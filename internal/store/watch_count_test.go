package store

import (
	"context"
	"testing"
	"time"
)

// --- Task 9 (node-integration): re-lock watch-loss detection -----------------
//
// The control-plane hub's disconnect defer must learn whether ITS connection
// was the LAST checker on the session (refcounted presence, Task 9.9). When
// the count drops to ZERO for an admitted rw session (sess:live status
// "active"), the hub publishes a re-lock command so the data plane freezes
// the session until a checker watches again. WatchCount is the hub-side
// probe: it counts the watch:<sid>:* leases.

// TestWatchCount (Task 9 re-lock): WatchCount reports the number of live
// watch:<sid>:* leases — 0 before any watcher, one per connected checker,
// decremented as each connection's lease is removed. This is the exact
// probe the hub's disconnect defer needs to detect "I was the last one".
func TestWatchCount(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "watch:"+sid)

	// No watcher → 0.
	n, err := s.WatchCount(ctx, sid)
	if err != nil {
		t.Fatalf("WatchCount(empty): %v", err)
	}
	if n != 0 {
		t.Errorf("WatchCount(no watchers) = %d, want 0", n)
	}

	// First checker connects → 1.
	if err := s.SetWatchConn(ctx, sid, "conn-1", 30*time.Second); err != nil {
		t.Fatalf("SetWatchConn conn-1: %v", err)
	}
	if n, err = s.WatchCount(ctx, sid); err != nil || n != 1 {
		t.Errorf("WatchCount(one watcher) = %d, %v; want 1, nil", n, err)
	}

	// Second checker on the same session → 2 (presence is per-connection).
	if err := s.SetWatchConn(ctx, sid, "conn-2", 30*time.Second); err != nil {
		t.Fatalf("SetWatchConn conn-2: %v", err)
	}
	if n, err = s.WatchCount(ctx, sid); err != nil || n != 2 {
		t.Errorf("WatchCount(two watchers) = %d, %v; want 2, nil", n, err)
	}

	// First disconnect → 1 (the OTHER watcher still holds its lease).
	if err := s.WatchRemoveConn(ctx, sid, "conn-1"); err != nil {
		t.Fatalf("WatchRemoveConn conn-1: %v", err)
	}
	if n, err = s.WatchCount(ctx, sid); err != nil || n != 1 {
		t.Errorf("WatchCount(after first disconnect) = %d, %v; want 1, nil", n, err)
	}

	// Last disconnect → 0 (the re-lock trigger condition).
	if err := s.WatchRemoveConn(ctx, sid, "conn-2"); err != nil {
		t.Fatalf("WatchRemoveConn conn-2: %v", err)
	}
	if n, err = s.WatchCount(ctx, sid); err != nil || n != 0 {
		t.Errorf("WatchCount(after last disconnect) = %d, %v; want 0, nil", n, err)
	}

	// Only the sid's OWN leases count: another session's watcher is invisible.
	if err := s.SetWatchConn(ctx, "other-"+sid, "conn-x", 30*time.Second); err != nil {
		t.Fatalf("SetWatchConn other: %v", err)
	}
	t.Cleanup(func() { _ = s.DelWatch(context.Background(), "other-"+sid) })
	if n, err = s.WatchCount(ctx, sid); err != nil || n != 0 {
		t.Errorf("WatchCount(other session watching) = %d, %v; want 0, nil", n, err)
	}
}
