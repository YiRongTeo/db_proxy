package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"zerotrust-proxy/internal/store"
)

// --- Task 9 (node-integration): the hub's re-lock trigger --------------------
//
// In the watch disconnect defer, AFTER WatchRemoveConn, the hub checks
// WatchCount(sid): when the LAST lease is gone AND the sess:live record
// shows status "active" (an ADMITTED session — a pending one is still
// pre-hold and has nothing to re-lock), it publishes
// {"action":"relock","session_id":<sid>} on the ctl:relock channel. Brief
// test (b): published for an active rw session; NOT for non-rw/pending
// sessions; nothing published while another watcher remains.

// pollWatchCount polls WatchCount until it reaches want (or fails after 5s).
func pollWatchCount(t *testing.T, vs *store.ValkeyStore, sid string, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last int64 = -1
	for time.Now().Before(deadline) {
		n, err := vs.WatchCount(context.Background(), sid)
		if err != nil {
			t.Fatalf("WatchCount(%s): %v", sid, err)
		}
		last = n
		if n == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("watch count for %s = %d, want %d (5s poll)", sid, last, want)
}

// seedActiveSessionRecord is seedSessionRecord with status "active" — the
// shape the data plane writes at admission (the record the re-lock trigger
// must require before publishing).
func seedActiveSessionRecord(t *testing.T, vs *store.ValkeyStore, sid, maker string) {
	t.Helper()
	rec := []byte(`{"session_id":"` + sid + `","username":"` + maker +
		`","db_user":"rw_user","db_type":"mysql","status":"active"}`)
	if err := vs.SetSessionLive(context.Background(), sid, rec, 10*time.Minute); err != nil {
		t.Fatalf("SetSessionLive(%s): %v", sid, err)
	}
}

// TestHubPublishesRelockOnLastWatchLoss: disconnecting the LAST checker's
// watch connection from an ACTIVE session publishes exactly one relock
// command; an earlier disconnect (another watcher remains) publishes none.
func TestHubPublishesRelockOnLastWatchLoss(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-relock-hub"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedActiveSessionRecord(t, vs, sid, "alice") // maker ≠ checker (admin), status ACTIVE (admitted)

	// Subscribe ctl:relock BEFORE the WS connections (the data plane's
	// position on the channel).
	out := make(chan []byte, 8)
	subCtx, subCancel := context.WithCancel(context.Background())
	t.Cleanup(subCancel)
	go func() { _ = vs.Subscribe(subCtx, "ctl:relock", false, out) }()

	// Two checkers watch, then disconnect one at a time.
	c1 := dialWSChecker(t, srv, tok, "sess:"+sid)
	c2 := dialWSChecker(t, srv, tok, "sess:"+sid)
	pollWatch(t, vs, sid, true)

	_ = c1.Close(0, "")
	pollWatchCount(t, vs, sid, 1) // first lease gone, second remains

	// No relock while a watcher remains.
	select {
	case m := <-out:
		t.Fatalf("relock published while a watcher remained: %s", m)
	case <-time.After(500 * time.Millisecond):
	}

	_ = c2.Close(0, "")
	pollWatchCount(t, vs, sid, 0) // last lease gone

	// The relock command lands.
	select {
	case m := <-out:
		var payload struct {
			Action    string `json:"action"`
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(m, &payload); err != nil {
			t.Fatalf("relock payload unmarshal: %v (%s)", err, m)
		}
		if payload.Action != "relock" || payload.SessionID != sid {
			t.Errorf("relock payload = %s, want {action:relock, session_id:%s}", m, sid)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no relock published after the last watcher left an active session")
	}
}

// TestHubNoRelockForPendingOrNonRW (brief test b, negative side): the hub
// must NOT publish for a PENDING session (still pre-hold — nothing to
// re-lock) and must NOT publish when the session record is missing
// (fail-closed: no record = no proof of an admitted session).
func TestHubNoRelockForPendingOrMissingRecord(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	out := make(chan []byte, 8)
	subCtx, subCancel := context.WithCancel(context.Background())
	t.Cleanup(subCancel)
	go func() { _ = vs.Subscribe(subCtx, "ctl:relock", false, out) }()

	// PENDING record: a session still in the hold — no relock on watch loss.
	pendingSid := "sid-relock-pending"
	_ = vs.DelWatch(context.Background(), pendingSid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), pendingSid) })
	seedSessionRecord(t, vs, pendingSid, "alice") // status pending

	cp := dialWSChecker(t, srv, tok, "sess:"+pendingSid)
	pollWatch(t, vs, pendingSid, true)
	_ = cp.Close(0, "")
	pollWatchCount(t, vs, pendingSid, 0)

	select {
	case m := <-out:
		t.Fatalf("relock published for a PENDING session: %s", m)
	case <-time.After(500 * time.Millisecond):
	}

	// NO record at all: fail-closed — no relock either.
	missingSid := "sid-relock-missing"
	_ = vs.DelWatch(context.Background(), missingSid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), missingSid) })

	cm := dialWSChecker(t, srv, tok, "sess:"+missingSid)
	// The hub rejects the watch entirely (checkerMayWatch fail-closed on a
	// missing record), so no lease ever existed — poll the absence, then
	// give any (wrong) publish a chance to arrive.
	time.Sleep(300 * time.Millisecond)
	_ = cm.Close(0, "")
	pollWatchCount(t, vs, missingSid, 0)

	select {
	case m := <-out:
		t.Fatalf("relock published with NO session record: %s", m)
	case <-time.After(500 * time.Millisecond):
	}
}

// TestHubRelockNotFiredOnNoWatchConnection: a checker connection on a
// NON-session channel (channel=*) holds no lease, so closing it must not
// publish anything even for an active session.
func TestHubRelockNotFiredOnNoWatchConnection(t *testing.T) {
	srv, _, vs, cfg := newWatchTestServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-relock-nowatch"
	seedActiveSessionRecord(t, vs, sid, "alice")
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	out := make(chan []byte, 8)
	subCtx, subCancel := context.WithCancel(context.Background())
	t.Cleanup(subCancel)
	go func() { _ = vs.Subscribe(subCtx, "ctl:relock", false, out) }()

	c := dialWSChecker(t, srv, tok, "*") // live-all: no watch lease
	time.Sleep(200 * time.Millisecond)
	_ = c.Close(0, "")
	time.Sleep(300 * time.Millisecond)

	select {
	case m := <-out:
		t.Fatalf("relock published for a connection that never watched: %s", m)
	case <-time.After(500 * time.Millisecond):
	}
}
