package api

// Task 9 — checker WS auth transport. Browsers cannot set custom headers on
// a WebSocket upgrade (the WebSocket API takes no headers), so the SPA's
// live-query socket (Task 11) must carry its JWT another way: /ws/checker
// ALSO accepts the token via ?access_token= (requireJWTWS in jwt.go). The
// fallback is scoped to the WS route ONLY — REST routes keep requireJWT
// header-only, so tokens never ride URLs (logs/history/proxies) anywhere
// else. The upgrade additionally honors cfg auth.jwt.allowed_origins as the
// websocket.Accept OriginPatterns allowlist: EMPTY (the default) keeps
// today's same-origin-only behavior.
//
// The dials below present the token ONLY in the query string (no
// Authorization header) — a header-only middleware would 401 every one of
// the success cases.

import (
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

// newWSQueryTestServer is newWatchTestServer with the Task 9 origin
// allowlist injected: cfg.JWT.AllowedOrigins is set BEFORE the server
// starts. The fixture's primary account (admin) is a checker — checker role
// is allowed on the checker surface regardless of allow_maker_watch — and
// the watch-presence params are shortened so leases are observable fast.
func newWSQueryTestServer(t *testing.T, allowedOrigins []string) (*httptest.Server, *http.Client, *store.ValkeyStore, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "checker", // admin is the checker (SoD: maker ≠ checker)
		JWT:          testJWTBlock(),
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	cfg.JWT.AllowedOrigins = allowedOrigins
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := NewAPI(log, cfg, vs, nil)
	a.watchTTL = 2 * time.Second
	a.watchHeartbeat = 200 * time.Millisecond
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, vs, cfg
}

// wsQueryURL builds the /ws/checker URL with the channel param plus
// ?access_token= when token is non-empty — the Task 11 SPA socket shape.
func wsQueryURL(srv *httptest.Server, token, channel string) string {
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/checker?channel=" + url.QueryEscape(channel)
	if token != "" {
		u += "&access_token=" + url.QueryEscape(token)
	}
	return u
}

// dialWSQuery dials /ws/checker with the token ONLY in the query string and
// optionally a browser Origin header — NO Authorization header is attached,
// so a successful upgrade proves the query token was accepted (the
// header-only requireJWT would 401 here).
func dialWSQuery(t *testing.T, srv *httptest.Server, token, channel, origin string) *websocket.Conn {
	t.Helper()
	u := wsQueryURL(srv, token, channel)
	hdrs := http.Header{}
	if origin != "" {
		hdrs.Set("Origin", origin)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdrs})
	if err != nil {
		t.Fatalf("ws query-token dial %s: %v", u, err)
	}
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	return c
}

// dialWSQueryExpectStatus dials like dialWSQuery but requires the server to
// REFUSE the upgrade with the given HTTP status — 401 from the auth
// middleware (before any handshake) or 403 from the role gate or the
// websocket.Accept origin check. The coder client surfaces the non-101
// response on the dial error.
func dialWSQueryExpectStatus(t *testing.T, srv *httptest.Server, token, channel, origin string, wantStatus int) {
	t.Helper()
	u := wsQueryURL(srv, token, channel)
	hdrs := http.Header{}
	if origin != "" {
		hdrs.Set("Origin", origin)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdrs})
	if c != nil {
		_ = c.Close(websocket.StatusNormalClosure, "")
	}
	if err == nil {
		t.Fatalf("ws dial %s succeeded, want HTTP %d", u, wantStatus)
	}
	if resp == nil || resp.StatusCode != wantStatus {
		t.Fatalf("ws dial %s: err %v (http status %v), want %d", u, err, resp, wantStatus)
	}
}

// TestWSCheckerQueryTokenConnectsAndStreams (Task 9 requirement a): a valid
// checker token in ?access_token= with NO Authorization header connects and
// the hub runs. The suite's established end-to-end proof is the sess: watch
// presence: subscribing channel=sess:<sid> arms the per-connection lease
// (only reachable after auth passed AND websocket.Accept upgraded AND the
// hub's pub/sub path is live), and disconnect clears it again.
func TestWSCheckerQueryTokenConnectsAndStreams(t *testing.T) {
	srv, _, vs, cfg := newWSQueryTestServer(t, nil)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-ws-query-token"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice") // maker ≠ checker (admin)

	c := dialWSQuery(t, srv, tok, "sess:"+sid, "")
	pollWatch(t, vs, sid, true) // accepted + subscribed → lease armed

	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)
}

// TestWSCheckerNoTokenRejected (Task 9 requirement b): no Authorization
// header AND no access_token query param → 401 from requireJWTWS BEFORE any
// websocket handshake (pre-upgrade).
func TestWSCheckerNoTokenRejected(t *testing.T) {
	srv, _, _, _ := newWSQueryTestServer(t, nil)
	dialWSQueryExpectStatus(t, srv, "", "*", "", http.StatusUnauthorized)
}

// TestWSCheckerInvalidQueryTokenRejected (Task 9 requirement c): a garbage
// access_token is rejected 401 — the query value goes through the exact
// same parseJWT verification as the header value.
func TestWSCheckerInvalidQueryTokenRejected(t *testing.T) {
	srv, _, _, _ := newWSQueryTestServer(t, nil)
	dialWSQueryExpectStatus(t, srv, "not-a-jwt", "*", "", http.StatusUnauthorized)
}

// TestWSCheckerQueryTokenWrongSignatureRejected: a token SIGNED WITH THE
// WRONG SECRET is rejected over the query transport too — the query
// fallback does not skip signature verification (parseJWT enforces HS256 +
// cfg secret + exp + iss + aud regardless of how the raw token arrived).
func TestWSCheckerQueryTokenWrongSignatureRejected(t *testing.T) {
	srv, _, _, cfg := newWSQueryTestServer(t, nil)
	other := *cfg
	other.JWT.Secret = "a-different-secret-0123456789abcdef"
	tok := mintJWT(t, &other, testJWTUser, "checker")
	dialWSQueryExpectStatus(t, srv, tok, "*", "", http.StatusUnauthorized)
}

// TestRESTRejectsQueryToken (Task 9 requirement d — the scoping proof):
// REST routes stay header-only. The SAME checker token /ws/checker accepts
// via ?access_token= is 401 on GET /api/me and GET /api/sessions when
// carried ONLY in the query string. Query-param acceptance is scoped to the
// WS route so tokens never ride URLs on REST (URLs leak into logs, browser
// history and proxy access logs). The control at the end proves the 401s
// are about the TRANSPORT, not the token: the same token in the
// Authorization header is accepted on /api/sessions.
func TestRESTRejectsQueryToken(t *testing.T) {
	srv, client, _, cfg := newWSQueryTestServer(t, nil)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	for _, path := range []string{"/api/me", "/api/sessions"} {
		resp, err := client.Get(srv.URL + path + "?access_token=" + url.QueryEscape(tok))
		if err != nil {
			t.Fatalf("GET %s?access_token=...: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s with token only in query: status %d, want 401 (query tokens are WS-only)", path, resp.StatusCode)
		}
	}

	// Control: bearer header on the same token → 200 (checker role).
	authed := withBearer(client, tok)
	sessResp, err := authed.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions (bearer): %v", err)
	}
	sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/sessions with bearer: status %d, want 200 (control)", sessResp.StatusCode)
	}
}

// TestWSCheckerCrossOriginRejectedByDefault (Task 9 requirement e): with an
// EMPTY allowed_origins (the default) a cross-origin browser socket is
// refused 403 — the token is VALID (auth + role passed); websocket.Accept's
// origin check rejects the foreign Origin header after the middleware.
func TestWSCheckerCrossOriginRejectedByDefault(t *testing.T) {
	srv, _, _, cfg := newWSQueryTestServer(t, nil) // empty allowlist = same-origin only
	tok := mintJWT(t, cfg, testJWTUser, "checker")
	dialWSQueryExpectStatus(t, srv, tok, "*", "http://evil.example.com", http.StatusForbidden)
}

// TestWSCheckerCrossOriginAcceptedWhenAllowlisted (Task 9 requirement e):
// a host listed in auth.jwt.allowed_origins is accepted end to end (connect
// + watch lease arms); a host NOT listed stays refused 403 against the SAME
// allowlist.
func TestWSCheckerCrossOriginAcceptedWhenAllowlisted(t *testing.T) {
	allowed := []string{"http://checker.example.com"}
	srv, _, vs, cfg := newWSQueryTestServer(t, allowed)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	// Listed origin → accepted: the sess: watch lease arms (full pipeline).
	sid := "sid-ws-cross-origin"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice") // maker ≠ checker (admin)

	c := dialWSQuery(t, srv, tok, "sess:"+sid, "http://checker.example.com")
	pollWatch(t, vs, sid, true)
	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)

	// Same allowlist: an UNLISTED cross-origin host is still refused.
	dialWSQueryExpectStatus(t, srv, tok, "*", "http://other.example.com", http.StatusForbidden)
}

// TestWSCheckerSameOriginAcceptedWithEmptyAllowlist (Task 9 requirement e,
// default preservation): when the browser sends an explicit Origin header
// that EQUALS the control-plane host, the upgrade is accepted even with an
// EMPTY allowlist — vendor authenticateOrigin compares the Origin host to
// the request Host first, so the empty default keeps same-origin working
// exactly as before this task (dials here carry no Authorization header —
// the query token + same-origin header both clear).
func TestWSCheckerSameOriginAcceptedWithEmptyAllowlist(t *testing.T) {
	srv, _, _, cfg := newWSQueryTestServer(t, nil)
	tok := mintJWT(t, cfg, testJWTUser, "checker")
	c := dialWSQuery(t, srv, tok, "*", srv.URL) // Origin == the server's own host
	_ = c.Close(websocket.StatusNormalClosure, "")
}
