package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
)

// --- node-integration Task 3: session-status callbacks -----------------------
//
// On Maker session START (backend connect success) and END (any close
// reason) the data plane POSTs to the configured callback URL. TDD: these
// tests were written BEFORE the implementation.

// callbackRecorder is the httptest backend: it records every callback
// attempt (path, headers, body) and optionally fails responses, for the
// retry tests. A mutex-guarded counter survives concurrent attempts; the
// tests use it to assert "exactly one retry then give-up" (total == 2).
type callbackRecorder struct {
	mu      sync.Mutex
	attempt int // incremented per HTTP attempt
	paths   []string
	headers []http.Header
	bodies  []string

	status int        // response status (0 = 200)
	block  bool       // block the handler until the client times out
	gate   chan error // optional write gate for transport-error tests
}

func (c *callbackRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.attempt++
	c.paths = append(c.paths, r.URL.Path)
	c.headers = append(c.headers, r.Header.Clone())
	c.bodies = append(c.bodies, string(body))
	c.mu.Unlock()
	if c.gate != nil {
		c.gate <- nil // first attempt: the test closes the server to break the transport
	}
	if c.status != 0 {
		w.WriteHeader(c.status)
	}
	w.Write([]byte(`{"session_id":"sid-x","action":"started","rows_updated":1}`))
}

func (c *callbackRecorder) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempt
}

func (c *callbackRecorder) snapshot(t *testing.T) (paths []string, headers []http.Header, bodies []string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.paths...), c.headers, c.bodies
}

// waitCount polls until the recorded attempt count reaches want or the
// deadline lapses (retry delivery is asynchronous — 2s after attempt 1).
func waitCount(t *testing.T, c *callbackRecorder, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c.count() >= want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("callback attempts = %d, want %d (deadline passed)", c.count(), want)
}

// waitCountStable asserts the count reaches want AND stays there for 500ms —
// the give-up assertion for the 500 test (one retry, no third attempt).
func waitCountStable(t *testing.T, c *callbackRecorder, want int) {
	t.Helper()
	waitCount(t, c, want)
	time.Sleep(500 * time.Millisecond)
	if got := c.count(); got != want {
		t.Fatalf("callback attempts = %d, want exactly %d (retry must stop after ONE retry)", got, want)
	}
}

// cbToken is the session the callbacks hang off; the id is what the callback
// path must carry (same id the mint response returned — 0ac5768).
func cbToken() *models.TokenPayload {
	return &models.TokenPayload{Username: "maker1", DBUser: "ro_user", DBType: "mysql", SessionID: "sid-cb01"}
}

// newCallbacks builds a SessionCallbacks wired to httptest's URL with a
// short timeout; the retry spacing stays at the production 2s (the tests
// assert the actual retry timing contract).
func newCallbacks(t *testing.T, rawURL, secret string) *SessionCallbacks {
	t.Helper()
	cb, err := NewSessionCallbacks(slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL, time.Second, secret, "127.0.0.1:9999")
	if err != nil {
		t.Fatalf("NewSessionCallbacks: %v", err)
	}
	if cb == nil {
		t.Fatal("NewSessionCallbacks returned nil for a non-empty url — feature unexpectedly disabled")
	}
	return cb
}

// cbTokenSession is a minimal sessionCommon stand-in: only the directory id
// fallback matters to the callback path.
func cbTokenSession(id string) sessionCommon {
	s := &mysqlSession{}
	s.id = id
	return s
}

// publishStarted/Ended drive the shared lifecycle funnel the way the
// proxies do (publishLifecycle for started, finishSession for ended).
func publishStarted(t *testing.T, cb *SessionCallbacks, tok *models.TokenPayload) {
	t.Helper()
	cb.NotifySession(cbTokenSession(tok.SessionID), tok, "started")
}

func publishEnded(t *testing.T, cb *SessionCallbacks, tok *models.TokenPayload) {
	t.Helper()
	cb.NotifySession(cbTokenSession(tok.SessionID), tok, "ended")
}

// TestSessionCallbackStartedEndedShape (brief test 1): started+ended received
// with the EXACT path, correct JSON body shape, and the shared-secret header
// present when configured.
func TestSessionCallbackStartedEndedShape(t *testing.T) {
	rec := &callbackRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	cb := newCallbacks(t, srv.URL, "topsecret")

	publishStarted(t, cb, cbToken())
	waitCount(t, rec, 1)
	publishEnded(t, cb, cbToken())
	waitCountStable(t, rec, 2)

	paths, headers, bodies := rec.snapshot(t)
	if paths[0] != "/dbpxy/session/sid-cb01/status" {
		t.Errorf("started path = %q, want /dbpxy/session/sid-cb01/status", paths[0])
	}
	if paths[1] != "/dbpxy/session/sid-cb01/status" {
		t.Errorf("ended path = %q, want /dbpxy/session/sid-cb01/status", paths[1])
	}
	if got := headers[0].Get("X-Session-Callback-Key"); got != "topsecret" {
		t.Errorf("started X-Session-Callback-Key = %q, want %q", got, "topsecret")
	}
	if got := headers[1].Get("X-Session-Callback-Key"); got != "topsecret" {
		t.Errorf("ended X-Session-Callback-Key = %q, want %q", got, "topsecret")
	}
	for i, want := range []string{"started", "ended"} {
		var body struct {
			Action    string `json:"action"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal([]byte(bodies[i]), &body); err != nil {
			t.Fatalf("body[%d] %q: unmarshal: %v", i, bodies[i], err)
		}
		if body.Action != want {
			t.Errorf("body[%d].action = %q, want %q", i, body.Action, want)
		}
		if body.Timestamp == "" {
			t.Errorf("body[%d].timestamp empty", i)
		}
		if _, err := time.Parse(time.RFC3339, body.Timestamp); err != nil {
			t.Errorf("body[%d].timestamp %q not RFC3339: %v", i, body.Timestamp, err)
		}
	}
}

// TestSessionCallbackNoSecretNoHeader (brief test 2): no secret configured →
// no X-Session-Callback-Key header at all.
func TestSessionCallbackNoSecretNoHeader(t *testing.T) {
	rec := &callbackRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	cb := newCallbacks(t, srv.URL, "")

	publishStarted(t, cb, cbToken())
	waitCount(t, rec, 1)

	_, headers, _ := rec.snapshot(t)
	if _, ok := headers[0]["X-Session-Callback-Key"]; ok {
		t.Errorf("X-Session-Callback-Key sent with empty shared_secret: %v", headers[0])
	}
}

// TestSessionCallbackDisabledByDefault (brief test 3): url empty (default) →
// the constructor returns nil and every notify is a no-op — zero HTTP calls.
func TestSessionCallbackDisabledByDefault(t *testing.T) {
	cb, err := NewSessionCallbacks(slog.New(slog.NewTextHandler(io.Discard, nil)), "", time.Second, "s", "")
	if err != nil {
		t.Fatalf("NewSessionCallbacks(\"\"): %v", err)
	}
	if cb != nil {
		t.Fatal("NewSessionCallbacks(\"\") = non-nil, want nil (disabled by default)")
	}
	// Notify on a nil receiver must be a safe no-op (the proxies call it
	// unconditionally through the embedded publisher).
	var none *SessionCallbacks
	none.NotifySession(cbTokenSession("sid-x"), cbToken(), "started")
}

// TestSessionCallback500OneRetryThenGiveUp (brief test 4): the endpoint
// answers 500 → exactly ONE retry after 2s, then give-up (total 2 attempts).
func TestSessionCallback500OneRetryThenGiveUp(t *testing.T) {
	rec := &callbackRecorder{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	cb := newCallbacks(t, srv.URL, "")

	publishStarted(t, cb, cbToken())
	// Attempt 1 lands immediately; the single retry lands ~2s later. The
	// stable wait then proves no third attempt follows.
	waitCountStable(t, rec, 2)
}

// TestSessionCallbackTransportErrorNoRetryStorm (brief test 5): the endpoint
// is unreachable (server closed) → transport errors logged, attempts stop
// after the one retry, and the notify call itself never blocks or errors.
func TestSessionCallbackTransportErrorNoRetryStorm(t *testing.T) {
	rec := &callbackRecorder{}
	srv := httptest.NewServer(rec)
	cb := newCallbacks(t, srv.URL, "")
	srv.Close() // unreachable from here on — every dial fails

	done := make(chan struct{})
	go func() {
		defer close(done)
		publishStarted(t, cb, cbToken())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("NotifySession blocked past the callback timeout — the relay must never wait on the callback")
	}
	// Closed server → attempt 1 fails on dial; the ONE retry also fails;
	// nothing further. No server means no counter — assert the attempts
	// stopped by checking the counter never moved past what landed before
	// Close (0) after the retry window: wait out 2.5s and confirm Notify
	// returned without blocking (the done select above) and that no panic
	// escaped. The count is informational here (0 or a pre-close race).
	time.Sleep(2500 * time.Millisecond)
	if got := rec.count(); got > 1 {
		t.Errorf("callback attempts on closed server = %d, want ≤ 1", got)
	}
}

// TestSessionCallbackTimestampRFC3339UTCMonotonic (brief test 6): timestamps
// are RFC3339 UTC strings and monotonic — started.ts < ended.ts.
func TestSessionCallbackTimestampRFC3339UTCMonotonic(t *testing.T) {
	rec := &callbackRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	cb := newCallbacks(t, srv.URL, "")

	publishStarted(t, cb, cbToken())
	waitCount(t, rec, 1)
	// A real gap: the ended event's timestamp must be strictly after the
	// started one (ACTUAL event times, not one shared stamp). RFC3339
	// renders whole seconds, so the gap must be ≥ 1.1s to be visible.
	time.Sleep(1100 * time.Millisecond)
	publishEnded(t, cb, cbToken())
	waitCount(t, rec, 2)

	_, _, bodies := rec.snapshot(t)
	var ts [2]time.Time
	for i, want := range []string{"started", "ended"} {
		var body struct {
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal([]byte(bodies[i]), &body); err != nil {
			t.Fatalf("body[%d]: %v", i, err)
		}
		var err error
		ts[i], err = time.Parse(time.RFC3339, body.Timestamp)
		if err != nil {
			t.Fatalf("body[%d].timestamp %q not RFC3339: %v", i, body.Timestamp, err)
		}
		if ts[i].Location() != time.UTC {
			t.Errorf("body[%d].timestamp %q not UTC (offset %v)", i, body.Timestamp, ts[i].Format("-07:00"))
		}
		if want == "started" {
			continue
		}
		if !ts[1].After(ts[0]) {
			t.Errorf("timestamps not monotonic: started %v ≥ ended %v", ts[0], ts[1])
		}
	}
	// The wire string itself must be the UTC 'Z' form, not an offset form
	// that merely parses to UTC.
	if !strings.Contains(bodies[0], "T") || !strings.HasSuffix(strings.TrimSuffix(strings.TrimSpace(bodies[0]), "}"), "Z\"") {
		t.Errorf("started timestamp not in RFC3339 UTC Z-form: %s", bodies[0])
	}
}

// TestSessionCallbackPanicIsolated (brief test 7): a panic in the callback
// path does not kill the session goroutine and never leaks past Notify.
func TestSessionCallbackPanicIsolated(t *testing.T) {
	calls := 0
	cb, err := NewSessionCallbacks(slog.New(slog.NewTextHandler(io.Discard, nil)), "http://127.0.0.1:1", time.Second, "", "")
	if err != nil {
		t.Fatalf("NewSessionCallbacks: %v", err)
	}
	cb.postFn = func(_ string, _ string, _ string) error { calls++; panic("boom: callback exploded") }

	// The dispatch goroutine's recover must swallow the panic — a crashing
	// callback goroutine must not take down the process. calls is
	// mutex-free here because the async goroutine is the only writer and
	// the final read happens after a settle sleep.
	cb.NotifySession(cbTokenSession("sid-panic"), cbToken(), "started")
	deadline := time.Now().Add(5 * time.Second)
	for calls == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls != 1 {
		t.Fatalf("postFn calls = %d, want 1 (and no process crash from the panic)", calls)
	}
	// A second event right after: the goroutine machinery still works
	// after the recovered panic.
	cb.NotifySession(cbTokenSession("sid-panic"), cbToken(), "ended")
	deadline = time.Now().Add(5 * time.Second)
	for calls < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls != 2 {
		t.Errorf("postFn calls = %d, want 2 (dispatch still functional after a recovered panic)", calls)
	}
}

// TestSessionCallbackSharedFunnelWiring pins the INTEGRATION POINT: the
// callback hangs off the SHARED lifecycle funnel (publishLifecycle /
// finishSession in session_common.go) — one wiring for all four protocols,
// started at connect-success, ended from finishSession's close path.
func TestSessionCallbackSharedFunnelWiring(t *testing.T) {
	rec := &callbackRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	cb := newCallbacks(t, srv.URL, "")

	pub := &sessionPublisher{
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		vs:        proxyTestStore(t),
		callbacks: cb,
	}
	tok := cbToken()
	s := cbTokenSession("sid-funnel")

	// Started: what every protocol's connect-success path does
	// (p.refreshSessionLive + p.publishLifecycle(s, tok, "started", addr)).
	pub.publishLifecycle(s, tok, "started", "127.0.0.1:50000")
	waitCount(t, rec, 1)
	// Ended: finishSession (DelSessionLive + ended lifecycle) — the single
	// deferred close path shared by every protocol.
	pub.finishSession(s, tok, "127.0.0.1:50000")
	waitCountStable(t, rec, 2)

	paths, _, bodies := rec.snapshot(t)
	// The TOKEN's session id is authoritative (the id the mint response
	// returned — 0ac5768); the directory record's id is only the fallback.
	// In production they are identical (each proxy adopts tok.SessionID at
	// connect), so the test's deliberately-divergent ids pin the
	// precedence: the wire path carries sid-cb01, never sid-funnel.
	for i, want := range []string{"/dbpxy/session/sid-cb01/status", "/dbpxy/session/sid-cb01/status"} {
		if paths[i] != want {
			t.Errorf("paths[%d] = %q, want %q (token SessionID is authoritative)", i, paths[i], want)
		}
	}
	var first struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &first); err != nil || first.Action != "started" {
		t.Errorf("first callback action = %q (err %v), want started", first.Action, err)
	}
	var second struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal([]byte(bodies[1]), &second); err != nil || second.Action != "ended" {
		t.Errorf("second callback action = %q (err %v), want ended", second.Action, err)
	}
}

// TestSessionCallbackLoopProtection: a callback whose target host equals the
// control plane's own address is SKIPPED — no HTTP call, no retry.
func TestSessionCallbackLoopProtection(t *testing.T) {
	rec := &callbackRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	// The control plane address resolves to this httptest server's host —
	// the notify must refuse to dial it.
	cb, err := NewSessionCallbacks(slog.New(slog.NewTextHandler(io.Discard, nil)), srv.URL, time.Second, "", srv.URL)
	if err != nil {
		t.Fatalf("NewSessionCallbacks: %v", err)
	}
	if cb == nil {
		t.Fatal("NewSessionCallbacks returned nil")
	}
	publishStarted(t, cb, cbToken())
	time.Sleep(300 * time.Millisecond)
	if got := rec.count(); got != 0 {
		t.Errorf("callback attempts to the control-plane host = %d, want 0 (loop protection)", got)
	}
}

// TestSessionCallbackRetryAfter2s pins the retry SPACING contract: with a
// first attempt at t0 that fails, the retry must land in [1.5s, 5s] — not
// immediately, not never.
func TestSessionCallbackRetryAfter2s(t *testing.T) {
	rec := &callbackRecorder{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	cb := newCallbacks(t, srv.URL, "")

	start := time.Now()
	publishStarted(t, cb, cbToken())
	waitCount(t, rec, 1)
	first := time.Since(start)
	deadline := time.Now().Add(10 * time.Second)
	for rec.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	retryIn := time.Since(start) - first
	if retryIn < 1500*time.Millisecond {
		t.Errorf("retry landed after %v, want ≥ 1.5s (one retry AFTER 2s)", retryIn)
	}
	if retryIn > 6*time.Second {
		t.Errorf("retry landed after %v, want ≈ 2s (never later than 6s)", retryIn)
	}
}
