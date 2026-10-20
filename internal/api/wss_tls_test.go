package api

// Native control-plane TLS (http.tls) — WSS integration guard.
//
// The design goal: when the control plane serves TLS, the checker WebSocket
// must work UNCHANGED over wss — the ONLY change is the listener. Browsers
// force wss when the Angular SPA is served over https, so a real upgrade
// against a TLS listener, with requireJWTWS still enforcing auth, is the
// regression net for that surface. The repo pattern (httptest.NewTLSServer,
// as in internal/proxy/creds_test.go) hosts the REAL api mux on a TLS
// listener; the dial ignores the self-signed cert exactly like a browser
// after the user accepts it.

import (
	"context"
	"crypto/tls"
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

// newTLSWatchServer is newWatchTestServer over a TLS listener: the real api
// mux (requireJWTWS + hub included) served via httptest.NewTLSServer against
// the live Valkey, with the shortened watch presence knobs.
func newTLSWatchServer(t *testing.T) (*httptest.Server, *store.ValkeyStore, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "checker", // admin is the checker here (the WS role)
		JWT:          testJWTBlock(),
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := NewAPI(log, cfg, vs, nil)
	a.watchTTL = 2 * time.Second
	a.watchHeartbeat = 200 * time.Millisecond
	srv := httptest.NewTLSServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, vs, cfg
}

// tlsWSClient is a websocket dialer that trusts the httptest self-signed
// pair — the automation stand-in for the browser's "accept and continue".
func tlsWSClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-signed test pair
		},
	}
}

// tlsWSURL swaps https→ws (what a wss:// client URL looks like against the
// httptest TLS server) with the checker channel query set.
func tlsWSURL(srv *httptest.Server, channel string) string {
	return "wss" + strings.TrimPrefix(srv.URL, "https") + "/ws/checker?channel=" + url.QueryEscape(channel)
}

// dialWSSChecker opens a checker WebSocket over REAL TLS presenting the
// bearer token in the Authorization header (the Go-client path requireJWTWS
// reads first).
func dialWSSChecker(t *testing.T, srv *httptest.Server, token, channel string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, tlsWSURL(srv, channel), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{authHeader(token)}},
		HTTPClient: tlsWSClient(),
	})
	if err != nil {
		t.Fatalf("wss dial %s: %v", tlsWSURL(srv, channel), err)
	}
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	return c
}

// TestWSSCheckerUpgradeOverTLS proves the WSS contract end to end: a REAL
// WebSocket upgrade over TLS against the api mux succeeds, the connection
// CARRIES MESSAGES (an event published to the hub's channel reaches the
// wss client — not a half-open TLS tunnel), and the watch presence key is
// armed in Valkey (the hub ran).
func TestWSSCheckerUpgradeOverTLS(t *testing.T) {
	srv, vs, cfg := newTLSWatchServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-wss-presence"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice") // SoD: watcher (admin) ≠ maker (alice)

	c := dialWSSChecker(t, srv, tok, "sess:"+sid)
	pollWatch(t, vs, sid, true) // upgrade over TLS → hub subscribed → lease armed

	// The wss connection carries frames: publish a live-query event on the
	// hub's channel and read it back over the TLS websocket — a full
	// server→client frame through the wss transport.
	event := []byte(`{"kind":"query","db_type":"mysql","sql":"SELECT 1","status":"ok"}`)
	if err := vs.Publish(context.Background(), "queries:sess:"+sid, event); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read over wss: %v (published event never arrived)", err)
		}
		if strings.Contains(string(data), `"kind":"query"`) {
			break // the event crossed the TLS websocket end to end
		}
	}
}

// TestWSSRequireJWTEnforcedOverTLS pins that TLS does not relax auth: the
// same wss dial WITHOUT a bearer token is rejected by requireJWTWS (the
// upgrade fails — no 101).
func TestWSSRequireJWTEnforcedOverTLS(t *testing.T) {
	srv, _, cfg := newTLSWatchServer(t)
	_ = cfg

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := websocket.Dial(ctx, tlsWSURL(srv, "sess:any"), &websocket.DialOptions{
		HTTPClient: tlsWSClient(),
		// No HTTPHeader: no Authorization, no ?access_token= — the exact
		// unauthenticated upgrade requireJWTWS must 401.
	})
	if err == nil {
		t.Fatal("unauthenticated wss upgrade unexpectedly succeeded — requireJWTWS not enforced over TLS")
	}
}

// TestWSSQueryTokenFallbackOverTLS covers the browser path over wss: the
// ?access_token= query fallback (browsers cannot set upgrade headers) also
// authenticates over TLS — the checker SPA's wss URL shape.
func TestWSSQueryTokenFallbackOverTLS(t *testing.T) {
	srv, vs, cfg := newTLSWatchServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-wss-query"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice")

	u := "wss" + strings.TrimPrefix(srv.URL, "https") + "/ws/checker?channel=" +
		url.QueryEscape("sess:"+sid) + "&access_token=" + url.QueryEscape(tok)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: tlsWSClient()})
	if err != nil {
		t.Fatalf("wss dial with ?access_token=: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	pollWatch(t, vs, sid, true) // the query-fallback token authenticated over TLS too
}
