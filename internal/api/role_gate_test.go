package api

// Task 8 — role-gated checker endpoints. /ws/checker, POST /api/kill and
// GET /api/sessions sit behind requireChecker (composed after requireJWT in
// api.go): role=checker is ALWAYS allowed; role=maker is allowed ONLY when
// auth.allow_maker_watch is true — the single-account deployment escape
// hatch (a config-level choice, never a per-token grant). Separation of
// duties is untouched: checkerMayWatch still rejects a watcher who IS the
// watched session's maker, and a maker admitted by the flag still cannot
// watch their OWN session (pinned at the bottom of this file).

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// newRoleGateServer builds a control-plane server whose cfg carries the
// given allowMakerWatch value, with the watch presence parameters shortened
// (2s lease / 200ms heartbeat, mirroring newWatchTestServer) so watch
// tests observe presence quickly. Returns the store too — tests seed
// sess:live records and probe watch keys through it.
func newRoleGateServer(t *testing.T, allowMakerWatch bool) (*httptest.Server, *http.Client, *store.ValkeyStore, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:        testJWTUser,
		AuthPassword:    testJWTPassword,
		AuthRole:        "maker",
		AllowMakerWatch: allowMakerWatch,
		JWT:             testJWTBlock(),
		SessionTTL:      8,
		TokenTTL:        60,
		StaticDir:       t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := NewAPI(log, cfg, vs, nil)
	a.watchTTL = 2 * time.Second
	a.watchHeartbeat = 200 * time.Millisecond
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, vs, cfg
}

// killFor posts a ctl:kill request as the given client and returns the
// status code.
func killFor(t *testing.T, client *http.Client, base string) int {
	t.Helper()
	resp, err := client.Post(base+"/api/kill", "application/json",
		strings.NewReader(`{"session_id":"sid-gate"}`))
	if err != nil {
		t.Fatalf("POST /api/kill: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// dialWSForbidden dials /ws/checker with the token and requires the server
// to REFUSE the upgrade with HTTP 403 — the role gate answers before any
// websocket handshake (the coder/websocket client surfaces the non-101
// handshake as a dial error carrying the response).
func dialWSForbidden(t *testing.T, srv *httptest.Server, token string) {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/checker?channel=sess:sid-gate"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{authHeader(token)}},
	})
	if c != nil {
		_ = c.Close(websocket.StatusNormalClosure, "")
	}
	if err == nil {
		t.Fatal("ws dial succeeded, want a 403 rejection (role gate)")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ws dial err = %v (http status %v), want 403", err, resp)
	}
}

// TestRoleGateMakerForbiddenWhenFlagOff: with allow_maker_watch=false (the
// default — full SoD), a VALID maker-role bearer is refused 403 on all
// three checker endpoints. requireJWT has already authenticated it; the
// role gate is the only thing between a maker and the checker surface.
func TestRoleGateMakerForbiddenWhenFlagOff(t *testing.T) {
	srv, client, _, cfg := newRoleGateServer(t, false)
	maker := withBearer(client, mintJWT(t, cfg, "alice-maker", "maker"))

	if got := killFor(t, maker, srv.URL); got != http.StatusForbidden {
		t.Errorf("maker POST /api/kill: status %d, want 403", got)
	}

	sessResp, err := maker.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusForbidden {
		t.Errorf("maker GET /api/sessions: status %d, want 403", sessResp.StatusCode)
	}

	dialWSForbidden(t, srv, mintJWT(t, cfg, "alice-maker", "maker"))
}

// TestRoleGateMakerAllowedWhenFlagOn: allow_maker_watch=true admits a
// maker-role bearer to all three endpoints (the single-account deployment
// escape hatch): kill queues (202 — written only after the ctl:kill
// publish succeeds), the session directory lists (200, JSON array), and a
// sess:<sid> watch on ANOTHER user's session arms the write-gate presence
// (dial succeeds, lease appears, disconnect clears it).
func TestRoleGateMakerAllowedWhenFlagOn(t *testing.T) {
	srv, client, vs, cfg := newRoleGateServer(t, true)
	maker := withBearer(client, mintJWT(t, cfg, "alice-maker", "maker"))

	if got := killFor(t, maker, srv.URL); got != http.StatusAccepted {
		t.Errorf("maker POST /api/kill (flag on): status %d, want 202", got)
	}

	sessResp, err := maker.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	defer sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("maker GET /api/sessions (flag on): status %d, want 200", sessResp.StatusCode)
	}
	var arr []json.RawMessage // the body must be the directory's JSON array
	if err := json.NewDecoder(sessResp.Body).Decode(&arr); err != nil {
		t.Fatalf("decode /api/sessions body: %v", err)
	}

	// Watch presence: watcher alice-maker (role maker, flag on) on
	// alice-other's session — SoD passes (watcher != maker), the lease is
	// armed, and the disconnect clears it again.
	sid := "sid-rg-makerwatch"
	seedSessionRecord(t, vs, sid, "alice-other")
	c := dialWSChecker(t, srv, mintJWT(t, cfg, "alice-maker", "maker"), "sess:"+sid)
	pollWatch(t, vs, sid, true)
	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)
}

// TestRoleGateCheckerAlwaysAllowed: role=checker is allowed REGARDLESS of
// the flag — the checker surface belongs to the checker. (Flag-OFF server:
// the stricter deployment.)
func TestRoleGateCheckerAlwaysAllowed(t *testing.T) {
	srv, client, vs, cfg := newRoleGateServer(t, false)
	checker := withBearer(client, mintJWT(t, cfg, "carol-checker", "checker"))

	if got := killFor(t, checker, srv.URL); got != http.StatusAccepted {
		t.Errorf("checker POST /api/kill: status %d, want 202", got)
	}

	sessResp, err := checker.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusOK {
		t.Errorf("checker GET /api/sessions: status %d, want 200", sessResp.StatusCode)
	}

	// Watch presence arms for a checker watching another user's session.
	sid := "sid-rg-checkerwatch"
	seedSessionRecord(t, vs, sid, "bob-other")
	c := dialWSChecker(t, srv, mintJWT(t, cfg, "carol-checker", "checker"), "sess:"+sid)
	pollWatch(t, vs, sid, true)
	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)
}

// TestRoleGateMakerFlagOnStillCannotWatchOwnSession: the flag admits maker
// role to the checker surface, but separation of duties is NOT weakened —
// checkerMayWatch still rejects a watcher who IS the watched session's
// maker. A maker (flag on) watching their OWN session is closed with the
// 1008 policy violation and no presence lease is armed.
func TestRoleGateMakerFlagOnStillCannotWatchOwnSession(t *testing.T) {
	srv, _, vs, cfg := newRoleGateServer(t, true)
	tok := mintJWT(t, cfg, "alice-maker", "maker")

	sid := "sid-rg-makerown"
	seedSessionRecord(t, vs, sid, "alice-maker") // maker == watcher

	dialWSCheckerExpectRejected(t, srv, tok, "sess:"+sid)
	assertNoWatch(t, vs, sid)
}
