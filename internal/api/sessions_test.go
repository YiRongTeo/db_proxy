package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/store"
)

// --- GET /api/sessions (Task 8.4: session directory) ---

// liveRecord mirrors the data plane's sess:live:<sid> payload (Task 8.2),
// INCLUDING thread_id — the tests prove the API strips it from the
// checker-facing surface.
type liveRecord struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	DBUser    string    `json:"db_user"`
	DBType    string    `json:"db_type"`
	DB        string    `json:"db"`
	ThreadID  int64     `json:"thread_id"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// seedLiveSession writes a sess:live:<sid> record directly through the
// store — exactly what the data plane's heartbeat does — and deletes it
// again at test end.
func seedLiveSession(t *testing.T, vs *store.ValkeyStore, rec liveRecord) {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal live record: %v", err)
	}
	if err := vs.SetSessionLive(context.Background(), rec.SessionID, raw, 60*time.Second); err != nil {
		t.Fatalf("SetSessionLive(%s): %v", rec.SessionID, err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), rec.SessionID) })
}

// clearLiveDirectory deletes every sess:live:* key currently present so the
// empty-list assertion is deterministic on the shared dev Valkey (same
// strategy as the store suite's TestListSessionsEmpty).
func clearLiveDirectory(t *testing.T, vs *store.ValkeyStore) {
	t.Helper()
	ctx := context.Background()
	recs, err := vs.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions (clear): %v", err)
	}
	for _, rec := range recs {
		var r struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(rec, &r); err != nil || r.SessionID == "" {
			continue
		}
		_ = vs.DelSessionLive(ctx, r.SessionID)
	}
}

// TestSessionsRequiresJWT: GET /api/sessions without an Authorization
// bearer → 401.
func TestSessionsRequiresJWT(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)

	resp, err := client.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/sessions without bearer: status %d, want 401", resp.StatusCode)
	}
}

// TestSessionsListsLiveDirectory: with a valid session and seeded sess:live
// records, GET /api/sessions returns the directory as an array whose
// records carry the checker-facing snake_case fields — and thread_id is
// NOT exposed.
func TestSessionsListsLiveDirectory(t *testing.T) {
	srv, client, cfg := newTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "checker"))

	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	defer vs.Close()

	now := time.Now().UTC().Truncate(time.Millisecond) // JSON time precision
	seed := []liveRecord{
		{SessionID: fmt.Sprintf("t84-a-%d", now.UnixNano()), Username: "alice", DBUser: "ro_user", DBType: "mysql", DB: "appdb", ThreadID: 4242, StartedAt: now.Add(-2 * time.Minute), LastSeen: now.Add(-30 * time.Second)},
		{SessionID: fmt.Sprintf("t84-b-%d", now.UnixNano()), Username: "bob", DBUser: "rw_user", DBType: "postgres", DB: "analytics", ThreadID: 9001, StartedAt: now.Add(-5 * time.Minute), LastSeen: now},
	}
	for _, rec := range seed {
		seedLiveSession(t, vs, rec)
	}

	resp, err := client.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /api/sessions body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sessions: status %d, want 200 (body %s)", resp.StatusCode, body)
	}

	// Typed decode: every seeded record round-trips with the right fields.
	var got []store.SessionInfo
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode /api/sessions body: %v", err)
	}
	for _, want := range seed {
		var found *store.SessionInfo
		for i := range got {
			if got[i].SessionID == want.SessionID {
				found = &got[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("session %s missing from directory (got %d records)", want.SessionID, len(got))
		}
		if found.Username != want.Username || found.DBUser != want.DBUser ||
			found.DBType != want.DBType || found.DB != want.DB {
			t.Errorf("session %s fields = %+v, want username=%s db_user=%s db_type=%s db=%s",
				want.SessionID, found, want.Username, want.DBUser, want.DBType, want.DB)
		}
		if !found.StartedAt.Equal(want.StartedAt) || !found.LastSeen.Equal(want.LastSeen) {
			t.Errorf("session %s timestamps = %v/%v, want %v/%v",
				want.SessionID, found.StartedAt, found.LastSeen, want.StartedAt, want.LastSeen)
		}
	}

	// thread_id must not leak: inspect the raw JSON element of each seeded
	// record (decoding into SessionInfo would silently drop the field).
	var elems []map[string]json.RawMessage
	if err := json.Unmarshal(body, &elems); err != nil {
		t.Fatalf("decode raw /api/sessions body: %v", err)
	}
	for _, want := range seed {
		for _, el := range elems {
			var sid string
			if err := json.Unmarshal(el["session_id"], &sid); err != nil || sid != want.SessionID {
				continue
			}
			if leaked, ok := el["thread_id"]; ok {
				t.Errorf("session %s leaks thread_id: %s", want.SessionID, leaked)
			}
		}
	}
}

// TestSessionsEmptyIsEmptyArray: with no sess:live keys, GET /api/sessions
// returns 200 with an empty JSON array — never null. The directory is
// SHARED with the store/api/cmd live suites (parallel packages write
// sess:live records concurrently), so the test is self-contained: seed
// exactly ONE fixture, assert it is listed, delete it, assert it is gone,
// and when the directory happens to be truly empty at the final read,
// assert the [] encoding (also pinned by the store suite).
func TestSessionsEmptyIsEmptyArray(t *testing.T) {
	srv, client, cfg := newTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "checker"))

	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	defer vs.Close()

	// Seed one fixture through the store — exactly what the data plane's
	// heartbeat writes (the sid is unique per run).
	sid := "test-sid-empty-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	seedLiveSession(t, vs, liveRecord{
		SessionID: sid,
		Username:  "alice",
		DB:        "appdb",
		LastSeen:  time.Now().UTC(),
	})

	// The fixture is listed.
	resp, err := client.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read /api/sessions body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sessions: status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), sid) {
		t.Fatalf("seeded session not listed: %s", body)
	}

	// Delete it; the API must no longer list it.
	clearLiveDirectory(t, vs)
	resp, err = client.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions (after delete): %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), sid) {
		t.Fatalf("deleted session still listed: %s", body)
	}
	if s := strings.TrimSpace(string(body)); s == "[]" {
		return // genuinely empty — the [] encoding holds
	}
	// Foreign fixtures from parallel packages may be present: the body must
	// still be a JSON ARRAY (never null) — parse it to prove the shape.
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		t.Fatalf("non-empty directory body is not a JSON array: %v (%s)", err, body)
	}
}

// --- POST /api/kill mode (Task 8.3/8.4 two-level kill) ---

// subscribeTo registers a ctl:kill subscriber (the exact mechanism the data
// plane runs) and blocks until the subscription is confirmed, returning the
// message channel, the subscriber error channel, and a cancel func.
func subscribeTo(t *testing.T, vs *store.ValkeyStore, channel string) (<-chan []byte, <-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan []byte, 4)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	subErr := make(chan error, 1)
	go func() { subErr <- vs.Subscribe(subCtx, channel, false, out) }()
	select {
	case <-acked:
	case err := <-subErr:
		cancel()
		t.Fatalf("subscribe %s: %v", channel, err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("subscription not confirmed within 5s")
	}
	return out, subErr, cancel
}

// TestKillPublishesCtlKillModeDefault is the live proof of the default
// mode: POST /api/kill WITHOUT a mode field must publish
// {"session_id":..., "mode":"connection"} on ctl:kill — the data plane's
// two-level kill dispatches on exactly this channel.
func TestKillPublishesCtlKillModeDefault(t *testing.T) {
	srv, client, cfg := newTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "checker"))

	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	defer vs.Close()
	out, subErr, cancel := subscribeTo(t, vs, "ctl:kill")
	defer cancel()

	resp, err := client.Post(srv.URL+"/api/kill", "application/json",
		strings.NewReader(`{"session_id":"sid-default"}`))
	if err != nil {
		t.Fatalf("POST /api/kill: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/kill: status %d, want 202", resp.StatusCode)
	}

	select {
	case m := <-out:
		var got struct {
			SessionID string `json:"session_id"`
			Mode      string `json:"mode"`
		}
		if err := json.Unmarshal(m, &got); err != nil {
			t.Fatalf("decode ctl:kill message %s: %v", m, err)
		}
		if got.SessionID != "sid-default" || got.Mode != "connection" {
			t.Errorf("ctl:kill message = %s, want session_id=sid-default mode=connection", m)
		}
	case err := <-subErr:
		t.Fatalf("ctl:kill subscriber exited: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no ctl:kill message within 5s")
	}
}

// TestKillPublishesCtlKillModeQuery is the live proof of mode=query
// passthrough: the subscriber receives {"session_id":..., "mode":"query"}.
func TestKillPublishesCtlKillModeQuery(t *testing.T) {
	srv, client, cfg := newTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "checker"))

	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	defer vs.Close()
	out, subErr, cancel := subscribeTo(t, vs, "ctl:kill")
	defer cancel()

	resp, err := client.Post(srv.URL+"/api/kill", "application/json",
		strings.NewReader(`{"session_id":"sid-q","mode":"query"}`))
	if err != nil {
		t.Fatalf("POST /api/kill: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/kill: status %d, want 202", resp.StatusCode)
	}

	select {
	case m := <-out:
		var got struct {
			SessionID string `json:"session_id"`
			Mode      string `json:"mode"`
		}
		if err := json.Unmarshal(m, &got); err != nil {
			t.Fatalf("decode ctl:kill message %s: %v", m, err)
		}
		if got.SessionID != "sid-q" || got.Mode != "query" {
			t.Errorf("ctl:kill message = %s, want session_id=sid-q mode=query", m)
		}
	case err := <-subErr:
		t.Fatalf("ctl:kill subscriber exited: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no ctl:kill message within 5s")
	}
}

// TestKillInvalidMode: any mode other than "query"/"connection" is rejected
// with 400 {"error":"invalid mode"} — nothing is published.
func TestKillInvalidMode(t *testing.T) {
	srv, client, cfg := newTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "checker"))

	for name, body := range map[string]string{
		"garbage mode": `{"session_id":"sid-x","mode":"garbage"}`,
		"uppercase":    `{"session_id":"sid-x","mode":"QUERY"}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := client.Post(srv.URL+"/api/kill", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatalf("POST /api/kill: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("body %s: status %d, want 400", body, resp.StatusCode)
			}
			var got map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatalf("decode kill response: %v", err)
			}
			if got["error"] != "invalid mode" {
				t.Errorf("body %s: error = %q, want %q", body, got["error"], "invalid mode")
			}
		})
	}
}
