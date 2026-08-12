package store

import (
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
