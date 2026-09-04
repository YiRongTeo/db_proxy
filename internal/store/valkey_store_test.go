package store

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
)

// Integration tests against the LIVE Valkey at 127.0.0.1:6379 (no password).
// Each test uses a unique random key so parallel runs cannot collide, and
// registers a cleanup that deletes the key.

const testAddr = "127.0.0.1:6379"

func newTestStore(t *testing.T) *ValkeyStore {
	t.Helper()
	// Package-internal tests build the store directly (storetest would
	// create an import cycle: storetest imports store).
	s, err := NewValkeyStore(context.Background(), StoreOptions{Addrs: []string{testAddr}})
	if err != nil {
		t.Fatalf("NewValkeyStore(%q): %v", testAddr, err)
	}
	t.Cleanup(s.Close)
	return s
}

func uniqueToken(t *testing.T) string {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	return "test-tok-" + id
}

// cleanupKey removes the key when the test finishes (no-op if absent).
func cleanupKey(t *testing.T, s *ValkeyStore, key string) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		_ = s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error()
	})
}

// TestWatchPresence (Task 8.6): SetWatch makes WatchActive true with a TTL
// lease, a refresh re-arms the lease, DelWatch removes presence, and
// --- watch presence (Task 8.6 + Task 9.9 reference counting) ----------------

// watchLeaseTTL reads the TTL of a specific lease key (same-package test
// helper; the production surface deliberately exposes no TTL reader).
func watchLeaseTTL(t *testing.T, s *ValkeyStore, key string) time.Duration {
	t.Helper()
	secs, err := s.client.Do(context.Background(), s.client.B().Ttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatalf("TTL(%s): %v", key, err)
	}
	if secs < 0 {
		return 0 // -1 no expiry / -2 missing — neither is a valid lease
	}
	return time.Duration(secs) * time.Second
}

// TestWatchPresenceRefcounted (Task 9.9 CRITICAL b): presence is
// reference-counted PER CONNECTION — with two watchers on the same session,
// removing the FIRST connection's lease must NOT close the gate while the
// second watcher still holds a key; only the last disconnect clears
// presence.
func TestWatchPresenceRefcounted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "watch:"+sid)

	active, err := s.WatchActive(ctx, sid)
	if err != nil {
		t.Fatalf("WatchActive before set: %v", err)
	}
	if active {
		t.Error("WatchActive before set = true, want false")
	}

	// First checker connects.
	if err := s.SetWatchConn(ctx, sid, "conn-1", 30*time.Second); err != nil {
		t.Fatalf("SetWatchConn conn-1: %v", err)
	}
	active, err = s.WatchActive(ctx, sid)
	if err != nil {
		t.Fatalf("WatchActive after conn-1: %v", err)
	}
	if !active {
		t.Fatal("WatchActive after conn-1 = false, want true")
	}
	// The lease key is the per-connection form watch:<sid>:<connid>.
	if ttl := watchLeaseTTL(t, s, "watch:"+sid+":conn-1"); ttl <= 0 || ttl > 30*time.Second {
		t.Errorf("conn-1 lease TTL = %v, want (0, 30s]", ttl)
	}

	// Second checker connects (same session, different connection).
	if err := s.SetWatchConn(ctx, sid, "conn-2", 30*time.Second); err != nil {
		t.Fatalf("SetWatchConn conn-2: %v", err)
	}

	// FIRST disconnect: the gate must stay OPEN (conn-2 still watches).
	if err := s.WatchRemoveConn(ctx, sid, "conn-1"); err != nil {
		t.Fatalf("WatchRemoveConn conn-1: %v", err)
	}
	active, err = s.WatchActive(ctx, sid)
	if err != nil {
		t.Fatalf("WatchActive after conn-1 remove: %v", err)
	}
	if !active {
		t.Fatal("WatchActive after first disconnect = false, want true (second watcher still holds a key)")
	}

	// LAST disconnect: presence gone.
	if err := s.WatchRemoveConn(ctx, sid, "conn-2"); err != nil {
		t.Fatalf("WatchRemoveConn conn-2: %v", err)
	}
	active, err = s.WatchActive(ctx, sid)
	if err != nil {
		t.Fatalf("WatchActive after conn-2 remove: %v", err)
	}
	if active {
		t.Error("WatchActive after last disconnect = true, want false")
	}
}

// TestWatchLeaseRefreshExtendsTTL: refreshing a connection's lease re-arms
// its TTL — with a 1s lease, a refresh at 0.6s keeps presence alive past
// the original deadline (the heartbeat semantics the hub relies on).
func TestWatchLeaseRefreshExtendsTTL(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "watch:"+sid)

	if err := s.SetWatchConn(ctx, sid, "conn-1", time.Second); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	time.Sleep(600 * time.Millisecond)
	if err := s.SetWatchConn(ctx, sid, "conn-1", time.Second); err != nil { // heartbeat refresh
		t.Fatalf("SetWatchConn refresh: %v", err)
	}
	time.Sleep(600 * time.Millisecond) // 1.2s total > the 1s original lease
	active, err := s.WatchActive(ctx, sid)
	if err != nil {
		t.Fatalf("WatchActive: %v", err)
	}
	if !active {
		t.Error("WatchActive after refresh = false, want true (heartbeat must re-arm the lease)")
	}
}

// TestWatchLeaseTTLExpiry: an un-refreshed lease expires on its own — a
// crashed checker/hub cannot leave a stale "watched" state forever.
func TestWatchLeaseTTLExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "watch:"+sid)

	if err := s.SetWatchConn(ctx, sid, "conn-1", time.Second); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	active, err := s.WatchActive(ctx, sid)
	if err != nil {
		t.Fatalf("WatchActive: %v", err)
	}
	if !active {
		t.Fatal("WatchActive before expiry = false, want true")
	}

	time.Sleep(1200 * time.Millisecond)

	active, err = s.WatchActive(ctx, sid)
	if err != nil {
		t.Fatalf("WatchActive after expiry: %v", err)
	}
	if active {
		t.Error("WatchActive after TTL expiry = true, want false")
	}
}

// TestDelWatchClearsAllConnections: DelWatch (test/ops force-clear) removes
// EVERY connection's lease, closing the gate even with watchers attached.
func TestDelWatchClearsAllConnections(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "watch:"+sid)

	for _, conn := range []string{"conn-a", "conn-b", "conn-c"} {
		if err := s.SetWatchConn(ctx, sid, conn, 30*time.Second); err != nil {
			t.Fatalf("SetWatchConn %s: %v", conn, err)
		}
	}
	if err := s.DelWatch(ctx, sid); err != nil {
		t.Fatalf("DelWatch: %v", err)
	}
	active, err := s.WatchActive(ctx, sid)
	if err != nil {
		t.Fatalf("WatchActive after DelWatch: %v", err)
	}
	if active {
		t.Error("WatchActive after DelWatch = true, want false")
	}
	if ttl := watchLeaseTTL(t, s, "watch:"+sid+":conn-a"); ttl != 0 {
		t.Errorf("lease conn-a TTL after DelWatch = %v, want 0", ttl)
	}
}

func TestSetTokenGetDeleteTokenSingleUse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	token := uniqueToken(t)
	cleanupKey(t, s, "tok:"+token)

	want := models.TokenPayload{
		Username: "alice",
		DBUser:   "db_alice",
		DBIP:     "10.0.0.5",
		DBPort:   "3306",
		DBType:   "mysql",
		TicketID: "T-42",
	}
	if err := s.SetToken(ctx, token, want, 60*time.Second); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	got, err := s.GetDeleteToken(ctx, token)
	if err != nil {
		t.Fatalf("first GetDeleteToken: %v", err)
	}
	if got == nil {
		t.Fatal("first GetDeleteToken: expected payload, got nil")
	}
	if *got != want {
		t.Fatalf("first GetDeleteToken: got %+v, want %+v", *got, want)
	}

	// Second read must be nil: the token was atomically consumed by GETDEL.
	got2, err := s.GetDeleteToken(ctx, token)
	if err != nil {
		t.Fatalf("second GetDeleteToken: %v", err)
	}
	if got2 != nil {
		t.Fatalf("second GetDeleteToken: expected nil (single-use), got %+v", got2)
	}
}

// TestTokenMultiUseBudget (Task 9.12, option-2 multi-use): a token issued
// with max_uses=N survives N-1 consumes (payload returned, counter
// decremented atomically, TTL preserved) and dies on the Nth. A token with
// max_uses absent/0 stays single-use (covered above).
func TestTokenMultiUseBudget(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	token := uniqueToken(t)
	cleanupKey(t, s, "tok:"+token)

	const budget = 3
	want := models.TokenPayload{
		Username: "alice",
		DBUser:   "db_alice",
		DBIP:     "10.0.0.5",
		DBPort:   "1434",
		DBType:   "mssql",
		TicketID: "T-9-12",
		MaxUses:  budget,
	}
	if err := s.SetToken(ctx, token, want, 300*time.Second); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	// Budget-1 successful consumes; the returned payload matches the
	// original (MaxUses is the remaining count only inside the store).
	for i := 1; i < budget; i++ {
		got, err := s.GetDeleteToken(ctx, token)
		if err != nil {
			t.Fatalf("consume %d: %v", i, err)
		}
		if got == nil {
			t.Fatalf("consume %d: expected payload, got nil (budget %d)", i, budget)
		}
		if got.Username != want.Username || got.DBType != want.DBType {
			t.Fatalf("consume %d: payload %+v, want %+v", i, *got, want)
		}
	}

	// The token must still EXIST with a live TTL after the budget-1
	// consumes (the Lua decrement re-applies the remaining TTL — a bare
	// SET would have dropped it and the token would die instantly).
	ttl, err := s.client.Do(ctx, s.client.B().Ttl().Key("tok:"+token).Build()).AsInt64()
	if err != nil {
		t.Fatalf("TTL after consumes: %v", err)
	}
	if ttl <= 0 || ttl > 300 {
		t.Fatalf("TTL after %d consumes = %d, want (0, 300]", budget-1, ttl)
	}

	// Budget exhausted: the Nth consume deletes the token.
	got, err := s.GetDeleteToken(ctx, token)
	if err != nil {
		t.Fatalf("final consume: %v", err)
	}
	if got == nil {
		t.Fatal("final consume: expected payload (the Nth use is still allowed)")
	}
	got2, err := s.GetDeleteToken(ctx, token)
	if err != nil {
		t.Fatalf("post-budget consume: %v", err)
	}
	if got2 != nil {
		t.Fatalf("post-budget consume: expected nil (budget exhausted), got %+v", got2)
	}
}

// TestTokenMultiUseBudgetSurvivesExpiryBoundary: decrements re-apply the
// remaining TTL — verify the token still expires on schedule even after
// uses, and that a consume AFTER expiry returns nil.
func TestTokenMultiUseBudgetSurvivesExpiryBoundary(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	token := uniqueToken(t)
	cleanupKey(t, s, "tok:"+token)

	if err := s.SetToken(ctx, token, models.TokenPayload{Username: "bob", MaxUses: 4}, time.Second); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	// One consume to exercise the TTL-preserving rewrite path.
	if got, err := s.GetDeleteToken(ctx, token); err != nil || got == nil {
		t.Fatalf("consume: got=%v err=%v", got, err)
	}
	time.Sleep(1200 * time.Millisecond)
	got, err := s.GetDeleteToken(ctx, token)
	if err != nil {
		t.Fatalf("GetDeleteToken after expiry: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil after TTL expiry (post-decrement), got %+v", got)
	}
}

func TestTokenExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	token := uniqueToken(t)
	cleanupKey(t, s, "tok:"+token)

	if err := s.SetToken(ctx, token, models.TokenPayload{Username: "bob"}, time.Second); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	time.Sleep(1200 * time.Millisecond)

	got, err := s.GetDeleteToken(ctx, token)
	if err != nil {
		t.Fatalf("GetDeleteToken after expiry: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil after TTL expiry, got %+v", got)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	id, err := s.CreateSession(ctx, models.Session{Username: "carol"}, 60*time.Second)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if id == "" {
		t.Fatal("CreateSession: returned empty id")
	}
	cleanupKey(t, s, "sess:ui:"+id)

	sess, err := s.GetSession(ctx, id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess == nil {
		t.Fatal("GetSession: expected session, got nil")
	}
	if sess.Username != "carol" {
		t.Fatalf("GetSession: username = %q, want %q", sess.Username, "carol")
	}

	if err := s.DeleteSession(ctx, id); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	sess, err = s.GetSession(ctx, id)
	if err != nil {
		t.Fatalf("GetSession after delete: %v", err)
	}
	if sess != nil {
		t.Fatalf("GetSession after delete: expected nil, got %+v", sess)
	}
}

// --- Task 8.2: session directory (sess:live:* keys) -------------------------

func uniqueSid(t *testing.T) string {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	return "test-sid-" + id
}

// findLiveRecord returns the record for sid among ListSessions results.
func findLiveRecord(t *testing.T, recs [][]byte, sid string) []byte {
	t.Helper()
	for _, rec := range recs {
		if bytes.Contains(rec, []byte(`"session_id":"`+sid+`"`)) {
			return rec
		}
	}
	return nil
}

// countLiveRecords counts the records for sid among ListSessions results.
func countLiveRecords(recs [][]byte, sid string) int {
	n := 0
	for _, rec := range recs {
		if bytes.Contains(rec, []byte(`"session_id":"`+sid+`"`)) {
			n++
		}
	}
	return n
}

// TestGetSessionLiveRoundTrip: GetSessionLive reads back a stored record
// verbatim and returns (nil, nil) for a missing/expired one — the checker
// watch attach relies on the miss to fail closed (separation of duties,
// 2026-08-17).
func TestGetSessionLiveRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "sess:live:"+sid)

	// Missing → (nil, nil), no error.
	raw, err := s.GetSessionLive(ctx, sid)
	if err != nil {
		t.Fatalf("GetSessionLive(missing): %v", err)
	}
	if raw != nil {
		t.Fatalf("GetSessionLive(missing) = %q, want nil", raw)
	}

	// Stored → read back verbatim.
	rec := []byte(`{"session_id":"` + sid + `","username":"alice","db":"appdb","thread_id":42}`)
	if err := s.SetSessionLive(ctx, sid, rec, 60*time.Second); err != nil {
		t.Fatalf("SetSessionLive: %v", err)
	}
	raw, err = s.GetSessionLive(ctx, sid)
	if err != nil {
		t.Fatalf("GetSessionLive(stored): %v", err)
	}
	if string(raw) != string(rec) {
		t.Fatalf("GetSessionLive(stored) = %q, want %q", raw, rec)
	}

	// Deleted → (nil, nil) again.
	if err := s.DelSessionLive(ctx, sid); err != nil {
		t.Fatalf("DelSessionLive: %v", err)
	}
	raw, err = s.GetSessionLive(ctx, sid)
	if err != nil {
		t.Fatalf("GetSessionLive(after delete): %v", err)
	}
	if raw != nil {
		t.Fatalf("GetSessionLive(after delete) = %q, want nil", raw)
	}
}

// TestSessionLiveRoundTrip: SetSessionLive writes the record, ListSessions
// returns it (raw JSON), a refresh updates it in place (still one record),
// and DelSessionLive removes it — the full key lifecycle.
func TestSessionLiveRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "sess:live:"+sid)

	rec1 := []byte(`{"session_id":"` + sid + `","username":"alice","db":"appdb","thread_id":42}`)
	if err := s.SetSessionLive(ctx, sid, rec1, 60*time.Second); err != nil {
		t.Fatalf("SetSessionLive: %v", err)
	}
	recs, err := s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if got := findLiveRecord(t, recs, sid); got == nil {
		t.Fatalf("ListSessions after set: record for %s missing (got %d records)", sid, len(recs))
	} else if string(got) != string(rec1) {
		t.Fatalf("ListSessions record = %s, want %s", got, rec1)
	}

	// Refresh: same sid, newer record — still exactly one entry.
	rec2 := []byte(`{"session_id":"` + sid + `","username":"alice","db":"appdb","thread_id":42,"last_seen":"2026-08-13T00:00:00Z"}`)
	if err := s.SetSessionLive(ctx, sid, rec2, 60*time.Second); err != nil {
		t.Fatalf("SetSessionLive refresh: %v", err)
	}
	recs, err = s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions after refresh: %v", err)
	}
	if got := findLiveRecord(t, recs, sid); got == nil || string(got) != string(rec2) {
		t.Fatalf("ListSessions after refresh = %s, want %s", got, rec2)
	}
	// Refresh must not duplicate the key: exactly ONE record for this sid
	// (the list may legitimately hold other live sessions from packages
	// running concurrently on the shared dev Valkey).
	if n := countLiveRecords(recs, sid); n != 1 {
		t.Fatalf("ListSessions after refresh: %d records for %s, want 1", n, sid)
	}

	// Deletion: the key is gone.
	if err := s.DelSessionLive(ctx, sid); err != nil {
		t.Fatalf("DelSessionLive: %v", err)
	}
	recs, err = s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions after delete: %v", err)
	}
	if got := findLiveRecord(t, recs, sid); got != nil {
		t.Fatalf("ListSessions after delete: record for %s still present: %s", sid, got)
	}
}

// TestSessionLiveTTLExpiry: a short TTL record disappears from the
// directory once it expires (the heartbeat semantics — an idle session
// drops off when its heartbeats stop).
func TestSessionLiveTTLExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "sess:live:"+sid)

	if err := s.SetSessionLive(ctx, sid, []byte(`{"session_id":"`+sid+`"}`), time.Second); err != nil {
		t.Fatalf("SetSessionLive: %v", err)
	}
	recs, err := s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if findLiveRecord(t, recs, sid) == nil {
		t.Fatal("record missing before TTL expiry")
	}

	time.Sleep(1200 * time.Millisecond)

	recs, err = s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions after expiry: %v", err)
	}
	if got := findLiveRecord(t, recs, sid); got != nil {
		t.Fatalf("record still present after TTL expiry: %s", got)
	}
}

// TestListSessionsEmpty: a directory WITHOUT the test's own record reads
// back without it. The shared dev Valkey carries live-suite fixture records
// from other packages running in parallel (go test ./...), so global
// emptiness is not assertable — the previous version raced the proxy live
// suites (fix mirrors internal/api TestSessionsEmptyIsEmptyArray: seed →
// list → delete → gone).
func TestListSessionsEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "sess:live:"+sid)

	// Seed the test's own record, list (must contain it), delete, list
	// again (must be gone) — the deterministic per-test contract.
	rec := []byte(`{"session_id":"` + sid + `","username":"alice","status":"pending"}`)
	if err := s.SetSessionLive(ctx, sid, rec, 60*time.Second); err != nil {
		t.Fatalf("SetSessionLive: %v", err)
	}
	recs, err := s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions after seed: %v", err)
	}
	if got := findLiveRecord(t, recs, sid); got == nil {
		t.Fatalf("ListSessions after seed: record for %s missing", sid)
	}
	if err := s.DelSessionLive(ctx, sid); err != nil {
		t.Fatalf("DelSessionLive: %v", err)
	}
	recs, err = s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions after delete: %v", err)
	}
	if got := findLiveRecord(t, recs, sid); got != nil {
		t.Fatalf("ListSessions after delete still returns the record: %s", got)
	}
}

// TestListSessionsParsed (Task 8.4): ListSessionsParsed decodes the raw
// directory records into typed SessionInfo entries — checker-facing fields
// only, no thread_id — and returns an empty non-nil slice for an empty
// directory (so handlers encode [] rather than null).
func TestListSessionsParsed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "sess:live:"+sid)

	started := time.Now().UTC().Add(-3 * time.Minute).Truncate(time.Millisecond)
	last := time.Now().UTC().Truncate(time.Millisecond)
	rec := []byte(`{"session_id":"` + sid + `","username":"alice","db_user":"ro_user","db_type":"mysql","db":"appdb","thread_id":4242,"started_at":"` +
		started.Format(time.RFC3339Nano) + `","last_seen":"` + last.Format(time.RFC3339Nano) + `"}`)
	if err := s.SetSessionLive(ctx, sid, rec, 60*time.Second); err != nil {
		t.Fatalf("SetSessionLive: %v", err)
	}

	got, err := s.ListSessionsParsed(ctx)
	if err != nil {
		t.Fatalf("ListSessionsParsed: %v", err)
	}
	found := false
	for _, si := range got {
		if si.SessionID != sid {
			continue
		}
		found = true
		if si.Username != "alice" || si.DBUser != "ro_user" || si.DBType != "mysql" || si.DB != "appdb" {
			t.Errorf("parsed record = %+v, want username=alice db_user=ro_user db_type=mysql db=appdb", si)
		}
		if !si.StartedAt.Equal(started) || !si.LastSeen.Equal(last) {
			t.Errorf("parsed timestamps = %v/%v, want %v/%v", si.StartedAt, si.LastSeen, started, last)
		}
	}
	if !found {
		t.Fatalf("ListSessionsParsed: record for %s missing (got %d records)", sid, len(got))
	}

	// Empty directory: non-nil empty slice (encodes as [], never null).
	// After the test's OWN record is gone the result must be a NON-NIL
	// slice (encodes as [], never null) — foreign records from parallel
	// live suites may be present on the shared dev Valkey, so length is
	// not asserted (same race fix as TestListSessionsEmpty).
	if err := s.DelSessionLive(ctx, sid); err != nil {
		t.Fatalf("DelSessionLive: %v", err)
	}
	got, err = s.ListSessionsParsed(ctx)
	if err != nil {
		t.Fatalf("ListSessionsParsed after delete: %v", err)
	}
	if got == nil {
		t.Fatalf("ListSessionsParsed after delete = nil, want non-nil slice (encodes [] not null)")
	}
	for _, si := range got {
		if si.SessionID == sid {
			t.Fatalf("ListSessionsParsed after delete still returns the record: %+v", si)
		}
	}
}

// TestListSessionsParsedStatus (Task 8.11): the session-directory record's
// status field (pending|active) passes through ListSessionsParsed into
// SessionInfo — pending for the control plane's token-issue record, active
// for the data plane's established session. Records without the key
// (pre-8.11) decode with Status == "" (backward compat).
func TestListSessionsParsedStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	pendSid := uniqueSid(t)
	actSid := uniqueSid(t)
	legSid := uniqueSid(t)
	for _, k := range []string{"sess:live:" + pendSid, "sess:live:" + actSid, "sess:live:" + legSid} {
		cleanupKey(t, s, k)
	}

	pend := []byte(`{"session_id":"` + pendSid + `","username":"alice","db_user":"rw_user","db_type":"mysql","status":"pending","started_at":"` +
		now.Format(time.RFC3339Nano) + `","last_seen":"` + now.Format(time.RFC3339Nano) + `"}`)
	act := []byte(`{"session_id":"` + actSid + `","username":"bob","db_user":"ro_user","db_type":"postgres","db":"appdb","thread_id":42,"status":"active","started_at":"` +
		now.Format(time.RFC3339Nano) + `","last_seen":"` + now.Format(time.RFC3339Nano) + `"}`)
	leg := []byte(`{"session_id":"` + legSid + `","username":"carol","db_user":"ro_user","db_type":"mysql","db":"appdb","thread_id":7,"started_at":"` +
		now.Format(time.RFC3339Nano) + `","last_seen":"` + now.Format(time.RFC3339Nano) + `"}`)
	for _, rec := range [][]byte{pend, act, leg} {
		var r struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(rec, &r); err != nil {
			t.Fatalf("test record: %v", err)
		}
		if err := s.SetSessionLive(ctx, r.SessionID, rec, 60*time.Second); err != nil {
			t.Fatalf("SetSessionLive(%s): %v", r.SessionID, err)
		}
	}

	got, err := s.ListSessionsParsed(ctx)
	if err != nil {
		t.Fatalf("ListSessionsParsed: %v", err)
	}
	statusOf := map[string]string{}
	for _, si := range got {
		statusOf[si.SessionID] = si.Status
	}
	if statusOf[pendSid] != "pending" {
		t.Errorf("pending record status = %q, want pending (all: %v)", statusOf[pendSid], statusOf)
	}
	if statusOf[actSid] != "active" {
		t.Errorf("active record status = %q, want active (all: %v)", statusOf[actSid], statusOf)
	}
	if statusOf[legSid] != "" {
		t.Errorf("legacy record status = %q, want \"\" (backward compat)", statusOf[legSid])
	}
}

// TestSessionLivePendingExpiry (Task 8.11): a pending session record whose
// token never connects expires via its TTL — the production issue-time TTL
// is 60s; a 2s TTL here proves the mechanism without waiting.
func TestSessionLivePendingExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueSid(t)
	cleanupKey(t, s, "sess:live:"+sid)

	rec := []byte(`{"session_id":"` + sid + `","username":"alice","db_user":"rw_user","db_type":"mysql","status":"pending"}`)
	if err := s.SetSessionLive(ctx, sid, rec, 2*time.Second); err != nil {
		t.Fatalf("SetSessionLive: %v", err)
	}
	// Listed right after issue…
	recs, err := s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions right after issue: %v", err)
	}
	found := false
	for _, r := range recs {
		if bytes.Contains(r, []byte(`"session_id":"`+sid+`"`)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("pending record %s not listed right after issue (%d records)", sid, len(recs))
	}
	// …and gone after the TTL elapses (a token never connected).
	time.Sleep(2500 * time.Millisecond)
	recs, err = s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions after TTL: %v", err)
	}
	for _, r := range recs {
		if bytes.Contains(r, []byte(`"session_id":"`+sid+`"`)) {
			t.Fatalf("pending record %s still listed after TTL expiry", sid)
		}
	}
}

// TestSessionTokenNotConsumed (Task 9.13): a session-mode token survives
// ANY number of consumes — payload returned each time, key and max_uses
// untouched, TTL preserved. Revocation is external (DeleteToken) or expiry.
func TestSessionTokenNotConsumed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	token := uniqueToken(t)
	cleanupKey(t, s, "tok:"+token)

	payload := models.TokenPayload{
		Username: "alice", DBUser: "ro_user", DBType: "mssql",
		Mode: "session", IP: "127.0.0.1", IssuedAt: 1,
	}
	if err := s.SetToken(ctx, token, payload, 2*time.Second); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	for i := 0; i < 5; i++ {
		got, err := s.GetDeleteToken(ctx, token)
		if err != nil {
			t.Fatalf("consume %d: %v", i, err)
		}
		if got == nil || got.Mode != "session" || got.IP != "127.0.0.1" {
			t.Fatalf("consume %d: got %+v, want the session payload", i, got)
		}
	}
	// Key still alive with its budget untouched.
	alive, err := s.TokenAlive(ctx, token)
	if err != nil || !alive {
		t.Fatalf("TokenAlive after 5 consumes: %v %v", alive, err)
	}
	raw, err := s.client.Do(ctx, s.client.B().Get().Key("tok:"+token).Build()).ToString()
	if err != nil {
		t.Fatalf("get raw: %v", err)
	}
	if strings.Contains(raw, "max_uses") {
		t.Errorf("session token payload gained a max_uses field: %s", raw)
	}
}

// TestSessionTokenInfiniteTTL (Task 9.13): ttl <= 0 stores the token with
// NO expiry — it lives until DeleteToken removes it.
func TestSessionTokenInfiniteTTL(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	token := uniqueToken(t)
	cleanupKey(t, s, "tok:"+token)

	if err := s.SetToken(ctx, token, models.TokenPayload{Username: "bob", Mode: "session", IP: "127.0.0.1"}, 0); err != nil {
		t.Fatalf("SetToken(infinite): %v", err)
	}
	ttl, err := s.client.Do(ctx, s.client.B().Pttl().Key("tok:"+token).Build()).AsInt64()
	if err != nil {
		t.Fatalf("pttl: %v", err)
	}
	if ttl != -1 {
		t.Fatalf("PTTL = %d, want -1 (no expiry)", ttl)
	}
	// DeleteToken revokes it; a consume afterwards is nil.
	if err := s.DeleteToken(ctx, token); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	got, err := s.GetDeleteToken(ctx, token)
	if err != nil || got != nil {
		t.Fatalf("consume after DeleteToken: got=%v err=%v, want nil", got, err)
	}
}

// --- Task 6: bearer-JWT jti denylist (jwt:deny:<jti> keys) ------------------

func uniqueJTI(t *testing.T) string {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	return "test-jti-" + id
}

// TestJWTDenyLifecycle: a fresh jti is not denied; DenyJWT puts it on the
// list (JWTDenied true) with a bounded TTL; cleanupKey removes it for the
// next run.
func TestJWTDenyLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	jti := uniqueJTI(t)
	cleanupKey(t, s, "jwt:deny:"+jti)

	denied, err := s.JWTDenied(ctx, jti)
	if err != nil {
		t.Fatalf("JWTDenied(fresh): %v", err)
	}
	if denied {
		t.Error("JWTDenied(fresh) = true, want false")
	}

	if err := s.DenyJWT(ctx, jti, 60*time.Second); err != nil {
		t.Fatalf("DenyJWT: %v", err)
	}
	denied, err = s.JWTDenied(ctx, jti)
	if err != nil {
		t.Fatalf("JWTDenied(after deny): %v", err)
	}
	if !denied {
		t.Error("JWTDenied(after deny) = false, want true")
	}
	// The denylist key carries a TTL bounded by the caller's ttl — a
	// revoked jti must not outlive the token it denies.
	ttl, err := s.client.Do(ctx, s.client.B().Ttl().Key("jwt:deny:"+jti).Build()).AsInt64()
	if err != nil {
		t.Fatalf("TTL(jwt:deny:): %v", err)
	}
	if ttl <= 0 || ttl > 60 {
		t.Errorf("denylist TTL = %d, want (0, 60]", ttl)
	}
}

// TestJWTDenyExpires: the denylist entry self-expires with its TTL — after
// the token's natural lifetime nothing remembers the jti.
func TestJWTDenyExpires(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	jti := uniqueJTI(t)
	cleanupKey(t, s, "jwt:deny:"+jti)

	if err := s.DenyJWT(ctx, jti, time.Second); err != nil {
		t.Fatalf("DenyJWT: %v", err)
	}
	if denied, err := s.JWTDenied(ctx, jti); err != nil || !denied {
		t.Fatalf("JWTDenied right after deny = %v (err %v), want true", denied, err)
	}
	time.Sleep(1200 * time.Millisecond)
	denied, err := s.JWTDenied(ctx, jti)
	if err != nil {
		t.Fatalf("JWTDenied after expiry: %v", err)
	}
	if denied {
		t.Error("JWTDenied after TTL expiry = true, want false")
	}
}

// TestDenyJWTRejectsBadInput: an empty jti or non-positive TTL is a caller
// bug — the store refuses instead of writing a poisoned jwt:deny: key or a
// never-expiring denial.
func TestDenyJWTRejectsBadInput(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.DenyJWT(ctx, "", 60*time.Second); err == nil {
		t.Error("DenyJWT(empty jti) = nil error, want error")
	}
	if err := s.DenyJWT(ctx, "some-jti", 0); err == nil {
		t.Error("DenyJWT(ttl 0) = nil error, want error")
	}
	if err := s.DenyJWT(ctx, "some-jti", -time.Second); err == nil {
		t.Error("DenyJWT(negative ttl) = nil error, want error")
	}
}
