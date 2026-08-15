package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
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
func newWatchTestServer(t *testing.T) (*httptest.Server, *http.Client, *store.ValkeyStore) {
	t.Helper()
	vs, err := store.NewValkeyStoreDirect(context.Background(), "127.0.0.1:6379", "", 0)
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     "admin",
		AuthPassword: "s3cret",
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
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return srv, &http.Client{Jar: jar}, vs
}

// wsSessionCookie extracts the zt_session cookie header value after login
// (the WS dial must carry it — /ws/checker is session-required).
func wsSessionCookie(t *testing.T, srv *httptest.Server, client *http.Client) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == sessionCookie {
			return c.Name + "=" + c.Value
		}
	}
	t.Fatal("zt_session cookie not found after login")
	return ""
}

// dialWSChecker opens a checker WebSocket with the given channel param.
func dialWSChecker(t *testing.T, srv *httptest.Server, cookie, channel string) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/checker?channel=" + url.QueryEscape(channel)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{
		HTTPHeader: http.Header{"Cookie": []string{cookie}},
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
	srv, client, vs := newWatchTestServer(t)
	loginViaAPI(t, client, srv.URL)
	cookie := wsSessionCookie(t, srv, client)

	sid := "sid-ws-presence"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	c := dialWSChecker(t, srv, cookie, "sess:"+sid)
	pollWatch(t, vs, sid, true) // subscribe → key exists

	// The presence lease is live (TTL set, > 0).
	ttl, err := vs.WatchTTL(context.Background(), sid)
	if err != nil {
		t.Fatalf("WatchTTL: %v", err)
	}
	if ttl <= 0 || ttl > 2*time.Second {
		t.Errorf("WatchTTL = %v, want (0, 2s]", ttl)
	}

	// Disconnect → key gone.
	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)
}

// TestWSCheckerWatchHeartbeatRefreshesTTL (Task 8.6): while the checker
// stays connected the hub refreshes the lease every heartbeat. With a 2s
// lease and a 200ms heartbeat, the TTL must still be near-full after 1.2s —
// an un-refreshed key would have decayed to ~0.8s.
func TestWSCheckerWatchHeartbeatRefreshesTTL(t *testing.T) {
	srv, client, vs := newWatchTestServer(t)
	loginViaAPI(t, client, srv.URL)
	cookie := wsSessionCookie(t, srv, client)

	sid := "sid-ws-heartbeat"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	c := dialWSChecker(t, srv, cookie, "sess:"+sid)
	pollWatch(t, vs, sid, true)

	time.Sleep(1200 * time.Millisecond) // ~6 heartbeat ticks

	ttl, err := vs.WatchTTL(context.Background(), sid)
	if err != nil {
		t.Fatalf("WatchTTL: %v", err)
	}
	if ttl < 1500*time.Millisecond {
		t.Errorf("WatchTTL after 1.2s connected = %v, want >= 1.5s (heartbeat must refresh the lease)", ttl)
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
	srv, client, vs := newWatchTestServer(t)
	loginViaAPI(t, client, srv.URL)
	cookie := wsSessionCookie(t, srv, client)

	sidA := "sid-ws-switch-a"
	_ = vs.DelWatch(context.Background(), sidA)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sidA) })

	// Checker watches session A.
	connA := dialWSChecker(t, srv, cookie, "sess:"+sidA)
	pollWatch(t, vs, sidA, true)

	// "Switch away": a NEW connection on the live-all channel while the old
	// one closes. The new connection holds no key.
	connB := dialWSChecker(t, srv, cookie, "*")
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
	srv, client, vs := newWatchTestServer(t)
	loginViaAPI(t, client, srv.URL)
	cookie := wsSessionCookie(t, srv, client)

	conn1 := dialWSChecker(t, srv, cookie, "sess:") // empty sid — malformed
	conn2 := dialWSChecker(t, srv, cookie, "*")     // live-all — not a session
	conn3 := dialWSChecker(t, srv, cookie, "alice") // user channel — not a session

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
