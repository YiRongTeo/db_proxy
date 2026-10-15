package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"zerotrust-proxy/internal/models"
)

// Session-status callbacks to the main application: on session START
// (backend connect success) and END (any close reason) the data plane POSTs
// {url}/dbpxy/session/{sessionId}/status with body
// {"action":"started"|"ended","timestamp":<RFC3339 UTC string>} — the main
// app's contract, correlating by sessionId. Delivery is fire-and-forget
// with EXACTLY ONE retry after 2s; failures are logged WARN and NEVER
// affect the relay. A nil *SessionCallbacks (url empty = the committed
// default) makes every call a no-op. Integration point: the shared session
// lifecycle funnel (sessionPublisher.publishLifecycle).

// sessionCallbackRetryDelay is the fixed spacing between the first attempt
// and the single retry — bounded, no backoff schedule.
const sessionCallbackRetryDelay = 2 * time.Second

// SessionCallbacks delivers session-status callbacks. Constructed in
// cmd/data from the config session_callback block; a nil receiver is the
// disabled sentinel and every method is a safe no-op. Immutable after
// construction; safe for concurrent use (the http.Client is).
type SessionCallbacks struct {
	log     *slog.Logger
	baseURL string // trailing-slash-trimmed; non-empty = enabled
	hc      *http.Client
	secret  string // non-empty → X-Session-Callback-Key on every request
	// skipHosts is the loop-protection set (lowercased host:port, or bare
	// host for host-only keys): a matching callback target is NEVER
	// dialed. Seeded with the control plane's own address — a callback
	// pointed back at it would self-sustain a loop.
	skipHosts map[string]struct{}
	// postFn is the request-execution seam tests drive (nil in
	// production: post() runs).
	postFn func(target, payload, secret string) error
}

// NewSessionCallbacks validates the configured callback URL and builds the
// client. rawURL empty (the committed default) → (nil, nil): the disabled
// sentinel. A NON-empty url that cannot parse is a construction ERROR —
// a plane configured to report must never start silently broken.
// timeout <= 0 falls back to 5s. controlPlaneAddr seeds loop protection:
// callbacks targeting it are skipped entirely; empty = no skips.
func NewSessionCallbacks(log *slog.Logger, rawURL string, timeout time.Duration, secret, controlPlaneAddr string) (*SessionCallbacks, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("session_callback: parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("session_callback: url %q must be absolute (scheme + host)", rawURL)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	cb := &SessionCallbacks{
		log:       log,
		baseURL:   strings.TrimRight(rawURL, "/"),
		hc:        &http.Client{Timeout: timeout},
		secret:    secret,
		skipHosts: map[string]struct{}{},
	}
	if k := callbackSkipKey(controlPlaneAddr); k != "" {
		cb.skipHosts[k] = struct{}{}
	}
	return cb, nil
}

// callbackSkipKey normalizes the control plane's address into the skip-set
// key: host:port protects exactly that endpoint; a bare host protects the
// whole host. Lowercased; IPv6 brackets trimmed.
func callbackSkipKey(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if u, err := url.Parse(addr); err == nil && u.Host != "" {
		addr = u.Host // strips scheme/path; keeps host:port
	}
	return strings.ToLower(strings.Trim(addr, "[]"))
}

// NotifySession fires the session-status callback for one lifecycle event
// ("started" | "ended"). Fire-and-forget: the HTTP round trip runs on its
// own goroutine and this call returns immediately — the relay never waits
// on the main application. The timestamp is captured HERE (the actual
// event time). Safe on a nil receiver (disabled).
func (cb *SessionCallbacks) NotifySession(s sessionCommon, tok *models.TokenPayload, action string) {
	if cb == nil || cb.baseURL == "" {
		return
	}
	sid := sidOf(tok, s)
	if sid == "" {
		return // nothing to correlate — nothing to send
	}
	ts := time.Now().UTC()
	body, _ := json.Marshal(struct {
		Action    string `json:"action"`
		Timestamp string `json:"timestamp"`
	}{Action: action, Timestamp: ts.Format(time.RFC3339)})
	target := cb.baseURL + "/dbpxy/session/" + url.PathEscape(sid) + "/status"
	if cb.skipHost(target) {
		// Loop protection: the target host is the control plane's own —
		// skip entirely, no attempt and no retry.
		cb.log.Debug("session callback skipped — target host is the control plane", "url", target)
		return
	}
	cb.dispatch(action, sid, target, string(body))
}

// dispatch runs one delivery (attempt → ONE retry after 2s → give-up) on
// its own goroutine, panic-isolated: a panic recovers to a WARN and the
// goroutine dies quietly — the calling relay goroutine is untouched.
func (cb *SessionCallbacks) dispatch(action, sid, target, payload string) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				cb.log.Warn("session callback panicked (recovered)", "action", action, "session_id", sid, "panic", r)
			}
		}()
		if err := cb.exec(target, payload); err != nil {
			cb.log.Warn("session callback failed", "action", action, "session_id", sid, "error", err)
			// The retry sleep lives on this goroutine, never the relay.
			time.Sleep(sessionCallbackRetryDelay)
			if err2 := cb.exec(target, payload); err2 != nil {
				cb.log.Warn("session callback retry failed — giving up", "action", action, "session_id", sid, "error", err2)
			}
		}
	}()
}

// exec performs ONE callback attempt (postFn overrides it — test seam).
func (cb *SessionCallbacks) exec(target, payload string) error {
	if cb.postFn != nil {
		return cb.postFn(target, payload, cb.secret)
	}
	return cb.post(target, payload)
}

// post performs ONE real HTTP attempt. Transport errors and non-2xx both
// return an error; the response body is read and discarded (debug-logged
// only) and the shared secret never appears in any log.
func (cb *SessionCallbacks) post(target, payload string) error {
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("session callback: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cb.secret != "" {
		req.Header.Set("X-Session-Callback-Key", cb.secret)
	}
	resp, err := cb.hc.Do(req)
	if err != nil {
		return fmt.Errorf("session callback: %w", err)
	}
	defer resp.Body.Close()
	// Bounded read: a misbehaving endpoint cannot pin the goroutine.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("session callback: status %d", resp.StatusCode)
	}
	cb.log.Debug("session callback delivered",
		"status", resp.StatusCode,
		"body", strings.TrimSpace(string(raw)))
	return nil
}

// skipHost reports whether the target is in the loop-protection set
// (exact host:port, or host match for host-only keys).
func (cb *SessionCallbacks) skipHost(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	hostPort := strings.ToLower(u.Host)
	host := strings.ToLower(u.Hostname())
	if _, bad := cb.skipHosts[hostPort]; bad {
		return true
	}
	if _, bad := cb.skipHosts[host]; bad {
		return true
	}
	return false
}

// sidOf extracts the session id for the callback path: the token payload's
// SessionID (control-plane stamped, the id the mint response returned) is
// authoritative; the session's directory id is the fallback.
func sidOf(tok *models.TokenPayload, s sessionCommon) string {
	if tok != nil && tok.SessionID != "" {
		return tok.SessionID
	}
	if s != nil {
		id, _, _, _, _ := s.sessionMeta()
		return id
	}
	return ""
}
