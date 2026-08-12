package store

import (
	"bytes"
	"context"
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
	s, err := NewValkeyStoreDirect(context.Background(), testAddr, "", 0)
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect(%q): %v", testAddr, err)
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

	id, err := s.CreateSession(ctx, models.Session{Username: "carol", Expires: time.Now().Add(time.Hour)}, 60*time.Second)
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

// clearLiveSessions deletes every sess:live:* key (keeps the empty-list
// assertion deterministic on the shared dev Valkey).
func clearLiveSessions(t *testing.T, s *ValkeyStore) {
	t.Helper()
	ctx := context.Background()
	cursor := uint64(0)
	for {
		res, err := s.client.Do(ctx, s.client.B().Scan().Cursor(cursor).Match("sess:live:*").Count(100).Build()).AsScanEntry()
		if err != nil {
			t.Fatalf("cleanup scan: %v", err)
		}
		if len(res.Elements) > 0 {
			_ = s.client.Do(ctx, s.client.B().Del().Key(res.Elements...).Build()).Error()
		}
		cursor = res.Cursor
		if cursor == 0 {
			return
		}
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

// TestListSessionsEmpty: an empty directory returns (nil, nil).
func TestListSessionsEmpty(t *testing.T) {
	s := newTestStore(t)
	clearLiveSessions(t, s) // deterministic on the shared dev Valkey

	recs, err := s.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions on empty directory: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("ListSessions on empty directory returned %d records: %s", len(recs), recs)
	}
}
