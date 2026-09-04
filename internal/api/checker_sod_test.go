package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"zerotrust-proxy/internal/store"
)

// seedSessionRecord writes a sess:live:<sid> directory record naming the
// maker (the shape recordPendingSession writes at token issue) with a TTL
// long enough to outlive the test, and cleans it up on exit.
func seedSessionRecord(t *testing.T, vs *store.ValkeyStore, sid, maker string) {
	t.Helper()
	rec := []byte(`{"session_id":"` + sid + `","username":"` + maker +
		`","db_user":"ro_user","db_type":"mysql","status":"pending"}`)
	if err := vs.SetSessionLive(context.Background(), sid, rec, 10*time.Minute); err != nil {
		t.Fatalf("SetSessionLive(%s): %v", sid, err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), sid) })
}

// dialWSCheckerExpectRejected dials a checker WebSocket that MUST be
// closed by the server with a policy-violation close (1008) — the
// separation-of-duties rejection. The dial itself succeeds (HTTP 101
// upgrade); the rejection arrives as the first read's CloseError.
func dialWSCheckerExpectRejected(t *testing.T, srv *httptest.Server, token, channel string) {
	t.Helper()
	c := dialWSChecker(t, srv, token, channel)
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := c.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("watch on %q: read err = %v, want a 1008 policy-violation close", channel, err)
	}
	if ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("watch on %q: close code = %d, want %d (policy violation)", channel, ce.Code, websocket.StatusPolicyViolation)
	}
}

// assertNoWatch sleeps briefly (room for a WRONG lease to land) and fails
// if any watch:<sid>:* presence key exists.
func assertNoWatch(t *testing.T, vs *store.ValkeyStore, sid string) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	active, err := vs.WatchActive(context.Background(), sid)
	if err != nil {
		t.Fatalf("WatchActive(%s): %v", sid, err)
	}
	if active {
		t.Errorf("watch presence armed for %s — must stay closed", sid)
	}
}

// TestWSCheckerCannotWatchOwnSession (separation of duties, user directive
// 2026-08-17): a maker who tries to arm the write-gate presence for their
// OWN session (channel=sess:<sid>) is rejected with a 1008 policy-violation
// close and NO watch lease is ever created — the maker can never
// self-approve their own writes.
func TestWSCheckerCannotWatchOwnSession(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker") // admin = the checker

	sid := "sid-sod-self"
	seedSessionRecord(t, vs, sid, "admin") // maker = admin = the checker

	dialWSCheckerExpectRejected(t, srv, tok, "sess:"+sid)
	assertNoWatch(t, vs, sid)
}

// TestWSCheckerDifferentCheckerCanWatch: a DIFFERENT user than the maker
// may watch the session — the lease is armed, the gate opens, and the
// disconnect clears it again.
func TestWSCheckerDifferentCheckerCanWatch(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker") // admin = the checker

	sid := "sid-sod-other"
	seedSessionRecord(t, vs, sid, "alice") // maker = alice ≠ admin

	c := dialWSChecker(t, srv, tok, "sess:"+sid)
	pollWatch(t, vs, sid, true) // the gate probe sees the watch
	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false)
}

// TestWSCheckerUnknownSessionFailClosed: a sess: channel for a session
// with NO directory record is rejected (fail-closed) — a lease may only
// exist for a real session whose maker is known, so a ghost sid can never
// open a gate.
func TestWSCheckerUnknownSessionFailClosed(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker") // admin = the checker

	sid := "sid-sod-ghost"
	_ = vs.DelSessionLive(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), sid) })

	dialWSCheckerExpectRejected(t, srv, tok, "sess:"+sid)
	assertNoWatch(t, vs, sid)
}
