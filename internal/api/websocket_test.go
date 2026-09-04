package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// --- Task 8.6: checker watch presence (WS hub → watch:<sid>) ----------------

// newWatchTestServer is newTestAPIServer with shortened watch presence
// parameters (2s lease, 200ms heartbeat instead of 30s/10s) so the heartbeat
// refresh is observable quickly. Returns the store too — tests inspect the
// watch keys it maintains.
func newWatchTestServer(t *testing.T) (*httptest.Server, *http.Client, *store.ValkeyStore, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "checker", // admin is the checker in the watch tests (SoD: maker ≠ checker)
		JWT:          testJWTBlock(),
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := NewAPI(log, cfg, vs, nil)
	a.watchTTL = 2 * time.Second
	a.watchHeartbeat = 200 * time.Millisecond
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, newJarClient(t), vs, cfg
}

// dialWSChecker opens a checker WebSocket with the given channel param.
// /ws/checker is requireJWT-guarded since Task 5: the dial presents the
// bearer token in the upgrade request's Authorization header.
func dialWSChecker(t *testing.T, srv *httptest.Server, token, channel string) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/checker?channel=" + url.QueryEscape(channel)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{authHeader(token)}},
	})
	if err != nil {
		t.Fatalf("ws dial %s: %v", u, err)
	}
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	return c
}

// pollWatch polls WatchActive until it reaches want (or fails after 5s).
func pollWatch(t *testing.T, vs *store.ValkeyStore, sid string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last := !want
	for time.Now().Before(deadline) {
		active, err := vs.WatchActive(context.Background(), sid)
		if err != nil {
			t.Fatalf("WatchActive(%s): %v", sid, err)
		}
		last = active
		if active == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("watch:%s active = %v, want %v (5s poll)", sid, last, want)
}

// TestWSCheckerWatchPresenceOnSubscribe (Task 8.6): a checker subscribing
// with channel=sess:<sid> sets watch:<sid> with a presence lease; closing
// the connection deletes it.
func TestWSCheckerWatchPresenceOnSubscribe(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	// admin = the checker (maker is the seeded session owner)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-ws-presence"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	// Separation of duties (2026-08-17): a sess: watch is only armed for a
	// real session whose maker differs from the checker (admin here).
	seedSessionRecord(t, vs, sid, "alice")

	c := dialWSChecker(t, srv, tok, "sess:"+sid)
	pollWatch(t, vs, sid, true) // subscribe → lease exists (gate probe sees the watch)

	// Lease TTL semantics are covered at the store level (watchLeaseTTL in
	// valkey_store_test.go); the API test proves the WIRING: subscribe arms
	// the presence and disconnect clears it.

	// Disconnect → key gone.
	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)
}

// TestWSCheckerWatchHeartbeatRefreshesTTL (Task 8.6, review 9.9): while the
// checker stays connected the hub refreshes its lease every heartbeat. With
// a 2s lease and a 200ms heartbeat the lease must SURVIVE past its own TTL —
// an un-refreshed key would expire ~2s after subscribe. So the connection
// stays up 2.5s (> lease TTL) and the gate probe must STILL see the watch:
// the heartbeat kept re-arming the key. (TTL introspection lives at the
// store level — watchLeaseTTL in valkey_store_test.go; this test proves the
// hub's refresh loop actually runs.)
func TestWSCheckerWatchHeartbeatRefreshesTTL(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	// admin = the checker (maker is the seeded session owner)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-ws-heartbeat"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice") // maker ≠ checker (admin)

	c := dialWSChecker(t, srv, tok, "sess:"+sid)
	pollWatch(t, vs, sid, true)

	time.Sleep(2500 * time.Millisecond) // ~12 heartbeat ticks, past the 2s lease TTL

	active, err := vs.WatchActive(context.Background(), sid)
	if err != nil {
		t.Fatalf("WatchActive: %v", err)
	}
	if !active {
		t.Error("watch lease expired while the checker stayed connected — heartbeat did not refresh it")
	}
	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)
}

// TestWSCheckerWatchChannelSwitchAway (Task 8.6): a checker that reconnects
// to a different channel (the UI switches channels by reconnecting with a
// new channel param) no longer holds the old session's watch — the old
// connection's disconnect clears exactly the key it held. A channel=*
// connection holds no key at all.
func TestWSCheckerWatchChannelSwitchAway(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	// admin = the checker (maker is the seeded session owner)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sidA := "sid-ws-switch-a"
	_ = vs.DelWatch(context.Background(), sidA)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sidA) })
	seedSessionRecord(t, vs, sidA, "alice") // maker ≠ checker (admin)

	// Checker watches session A.
	connA := dialWSChecker(t, srv, tok, "sess:"+sidA)
	pollWatch(t, vs, sidA, true)

	// "Switch away": a NEW connection on the live-all channel while the old
	// one closes. The new connection holds no key.
	connB := dialWSChecker(t, srv, tok, "*")
	_ = connA.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sidA, false) // old key cleared
	time.Sleep(300 * time.Millisecond)
	active, err := vs.WatchActive(context.Background(), "sid-ws-switch-b")
	if err != nil {
		t.Fatalf("WatchActive: %v", err)
	}
	if active {
		t.Error("channel=* connection holds a watch key, want none")
	}
	_ = connB.Close(websocket.StatusNormalClosure, "")
}

// TestWSCheckerWatchMalformedChannelHoldsNoKey (Task 8.6): a malformed
// session channel (empty sid) sets NO watch key; a non-session channel
// (live-all / user / ticket) neither.
func TestWSCheckerWatchMalformedChannelHoldsNoKey(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	// admin = the checker (maker is the seeded session owner)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	conn1 := dialWSChecker(t, srv, tok, "sess:") // empty sid — malformed
	conn2 := dialWSChecker(t, srv, tok, "*")     // live-all — not a session
	conn3 := dialWSChecker(t, srv, tok, "alice") // user channel — not a session

	time.Sleep(300 * time.Millisecond) // give a (wrong) set time to land
	for _, sid := range []string{"", "sid-ws-malformed", "sid-"} {
		active, err := vs.WatchActive(context.Background(), sid)
		if err != nil {
			t.Fatalf("WatchActive(%q): %v", sid, err)
		}
		if active {
			t.Errorf("malformed/non-session channel created watch key for %q", sid)
		}
	}
	for _, c := range []*websocket.Conn{conn1, conn2, conn3} {
		_ = c.Close(websocket.StatusNormalClosure, "")
	}
}

// TestWSCheckerWatchRefcountDisconnectSafety (review 9.9 CRITICAL b, hub
// wiring): presence is reference-counted per connection — with TWO checkers
// watching the same session, the FIRST disconnect must NOT close the gate
// while the second still watches; only the last disconnect clears presence.
// (The store-level lease math is covered by TestWatchPresenceRefcounted;
// this test proves the hub's SetWatchConn/WatchRemoveConn wiring end to end.)
func TestWSCheckerWatchRefcountDisconnectSafety(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	// admin = the checker (maker is the seeded session owner)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-ws-refcount"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice") // maker ≠ checker (admin)

	// Two checkers attach to the same session.
	connA := dialWSChecker(t, srv, tok, "sess:"+sid)
	connB := dialWSChecker(t, srv, tok, "sess:"+sid)
	pollWatch(t, vs, sid, true)

	// FIRST disconnect: the gate must stay OPEN (connB still watches).
	_ = connA.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, true)

	// LAST disconnect: presence gone.
	_ = connB.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)
}

// TestSubscribeLoopResubscribesWithBackoff (review 9.9 one-shot subscribe):
// a transient pubsub failure must not silently end the checker's stream —
// subscribeLoop resubscribes with exponential backoff until ctx is
// cancelled. The loop is driven against the real store: the first
// subscription is confirmed live (a message flows), then the store client
// is closed, forcing Subscribe to fail; the loop must retry (logged per
// attempt) and must return promptly once the context is cancelled.
func TestSubscribeLoopResubscribesWithBackoff(t *testing.T) {
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	var logBuf bytes.Buffer
	a := &api{log: slog.New(slog.NewTextHandler(&logBuf, nil)), vs: vs}

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan []byte, 8)
	done := make(chan struct{})
	go func() {
		a.subscribeLoop(ctx, "queries:test-resub", false, out)
		close(done)
	}()

	// First subscription live: publish until a message lands (a publish
	// that fires before the subscribe registers is lost by design, so the
	// publisher retries until the subscription is confirmed).
	deadline := time.Now().Add(5 * time.Second)
	got := false
	for time.Now().Before(deadline) && !got {
		_ = vs.Publish(context.Background(), "queries:test-resub", []byte(`{"n":1}`))
		select {
		case m := <-out:
			if string(m) != `{"n":1}` {
				t.Fatalf("message = %q, want the published payload", m)
			}
			got = true
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !got {
		t.Fatal("no message within 5s — first subscription never came up")
	}

	// Force the subscription to fail: the closed client makes every
	// subsequent Subscribe return immediately.
	vs.Close()
	time.Sleep(800 * time.Millisecond) // room for several backoff retries (100ms, 200ms, 400ms)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("subscribeLoop did not return within 5s of cancel")
	}

	retries := strings.Count(logBuf.String(), "resubscribing")
	if retries < 2 {
		t.Errorf("resubscribe log lines = %d, want >= 2 (the loop must retry after the failure)", retries)
	}
}
