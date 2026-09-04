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
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 8.11: token-time session listing (the gating-deadlock fix) --------
// The write-gate deadlock: a checker can only select a session AFTER the
// maker connects, but the maker's first query is blocked (1045) when nobody
// watches yet — the client breaks before the checker can attach. RESOLUTION:
// sessions become visible at TOKEN ISSUE time. These tests prove the control
// plane lists the session (status "pending") and publishes action=issued
// events BEFORE any connect.

// subscribeAPI opens a Valkey Pub/Sub subscription on one channel and blocks
// until it is confirmed; the returned channel receives raw event JSON.
func subscribeAPI(t *testing.T, vs *store.ValkeyStore, channel string) <-chan []byte {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan []byte, 16)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, channel, false, out)
	select {
	case <-acked:
	case <-time.After(5 * time.Second):
		t.Fatal("subscription not confirmed within 5s")
	}
	return out
}

// subscribePatternAPI is subscribeAPI for a PATTERN subscription (PSubscribe,
// e.g. queries:sess:*) — used to observe the per-session issued event before
// the sid is known (it is generated inside handleToken).
func subscribePatternAPI(t *testing.T, vs *store.ValkeyStore, pattern string) <-chan []byte {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan []byte, 32)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, pattern, true, out)
	select {
	case <-acked:
	case <-time.After(5 * time.Second):
		t.Fatal("pattern subscription not confirmed within 5s")
	}
	return out
}

// recvIssuedEvent returns the next event on a user channel — the first event
// there is the issued event because usernames are unique per test.
func recvIssuedEvent(t *testing.T, out <-chan []byte) models.QueryEvent {
	t.Helper()
	select {
	case m := <-out:
		var ev models.QueryEvent
		if err := json.Unmarshal(m, &ev); err != nil {
			t.Fatalf("unmarshal event %s: %v", m, err)
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the issued event")
		return models.QueryEvent{}
	}
}

// recvIssuedForSid drains the queries:sess:* pattern until the issued event
// for the given sid arrives (foreign sessions' events are skipped — the
// shared dev Valkey carries other tests' traffic).
func recvIssuedForSid(t *testing.T, out <-chan []byte, sid string) models.QueryEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-out:
			var ev models.QueryEvent
			if err := json.Unmarshal(m, &ev); err != nil {
				continue
			}
			if ev.Kind == "session" && ev.Action == "issued" && ev.SessionID == sid {
				return ev
			}
		case <-deadline:
			t.Fatalf("no issued event for %s within 5s", sid)
			return models.QueryEvent{}
		}
	}
}

// assertPendingListed GETs /api/sessions and asserts the issued token's
// session is listed with status "pending" and the exact known fields BEFORE
// any connect. Returns the listed session id.
func assertPendingListed(t *testing.T, client *http.Client, base, user, dbUser, dbType string) string {
	t.Helper()
	resp, err := client.Get(base + "/api/sessions")
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
	var got []store.SessionInfo
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode /api/sessions body: %v", err)
	}
	var found *store.SessionInfo
	for i := range got {
		if got[i].Username == user {
			found = &got[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("pending session for %s not listed in /api/sessions (got %d records)", user, len(got))
	}
	if !strings.HasPrefix(found.SessionID, "sid-") {
		t.Errorf("pending session_id = %q, want sid- prefix", found.SessionID)
	}
	if found.Status != "pending" {
		t.Errorf("pending session status = %q, want pending", found.Status)
	}
	if found.DBUser != dbUser || found.DBType != dbType {
		t.Errorf("pending session = %+v, want db_user=%s db_type=%s", found, dbUser, dbType)
	}
	if found.DB != "" {
		t.Errorf("pending session db = %q, want \"\" (unknown at issue time)", found.DB)
	}
	if found.StartedAt.IsZero() || found.LastSeen.IsZero() {
		t.Errorf("pending session timestamps: started_at=%v last_seen=%v, want non-zero", found.StartedAt, found.LastSeen)
	}
	// Raw JSON: the status key is present and thread_id is not exposed.
	var elems []map[string]json.RawMessage
	if err := json.Unmarshal(body, &elems); err != nil {
		t.Fatalf("decode raw /api/sessions body: %v", err)
	}
	for _, el := range elems {
		var sid string
		if err := json.Unmarshal(el["session_id"], &sid); err != nil || sid != found.SessionID {
			continue
		}
		var status string
		if err := json.Unmarshal(el["status"], &status); err != nil || status != "pending" {
			t.Errorf("raw record status = %q, want pending (%s)", status, el)
		}
		if _, leaked := el["thread_id"]; leaked {
			t.Errorf("pending record leaks thread_id: %s", el)
		}
	}
	return found.SessionID
}

// assertIssuedEvent checks the shared payload of an action=issued event.
func assertIssuedEvent(t *testing.T, ev models.QueryEvent, user, dbUser, dbType, sid string) {
	t.Helper()
	if ev.Kind != "session" || ev.Action != "issued" {
		t.Errorf("issued event kind/action = %q/%q, want session/issued", ev.Kind, ev.Action)
	}
	if ev.Username != user || ev.DBUser != dbUser || ev.DBType != dbType {
		t.Errorf("issued event context = user %q db_user %q db_type %q, want %q/%s/%s",
			ev.Username, ev.DBUser, ev.DBType, user, dbUser, dbType)
	}
	if ev.SessionID != sid {
		t.Errorf("issued event session_id = %q, want %q", ev.SessionID, sid)
	}
	if len(ev.ID) != 16 || ev.Ts.IsZero() {
		t.Errorf("issued event id=%q ts=%v, want 16-hex id and non-zero ts", ev.ID, ev.Ts)
	}
}

// TestTokenIssueListsPendingSession (Task 8.11 live): POST /api/token — for
// BOTH a write and a read token — (a) lists the session in GET /api/sessions
// with status "pending" and the exact known fields BEFORE any connect, (b)
// publishes the action=issued lifecycle event to queries:<user> AND
// queries:sess:<sid>, and (c) stamps the SAME sid into the stored token
// payload — the data plane adopts it when the maker connects.
func TestTokenIssueListsPendingSession(t *testing.T) {
	srv, client, vs := newPresetTestAPIServer(t)
	ctx := context.Background()
	// Review 9.9a: the token is issued for the SESSION user — each case
	// creates a session for its maker instead of the shared admin login.
	// The per-session channel must be subscribed BEFORE issuing — the sid
	// is generated inside handleToken.
	sessPat := subscribePatternAPI(t, vs, "queries:sess:*")

	cases := []struct {
		name, user, dbUser, dbType string
	}{
		{"write token (rw_user mysql)", fmt.Sprintf("pending-w-%d", time.Now().UnixNano()), "rw_user", "mysql"},
		{"read token (ro_user postgres)", fmt.Sprintf("pending-r-%d", time.Now().UnixNano()), "ro_user", "postgres"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessionAs(t, client, srv.URL, vs, tc.user)
			userCh := subscribeAPI(t, vs, "queries:"+tc.user)
			body := fmt.Sprintf(`{"username":%q,"db_user":%q,"db_ip":"127.0.0.1","db_port":"3307","db_type":%q,"ticket_id":"T-8-11"}`,
				tc.user, tc.dbUser, tc.dbType)
			token := issueToken(t, client, srv.URL, body)

			// (a) pending listing BEFORE any connect.
			sid := assertPendingListed(t, client, srv.URL, tc.user, tc.dbUser, tc.dbType)

			// (c) the stored payload carries the same sid.
			p, err := vs.GetDeleteToken(ctx, token)
			if err != nil {
				t.Fatalf("GetDeleteToken(%q): %v", token, err)
			}
			if p == nil {
				t.Fatalf("tok:%s missing", token)
			}
			if p.SessionID != sid {
				t.Errorf("stored payload session_id = %q, want the listed sid %q", p.SessionID, sid)
			}
			// Task 9.12: the stored payload carries the configured
			// connection budget (single-use default in this fixture).
			if p.MaxUses != 1 {
				t.Errorf("stored payload max_uses = %d, want 1 (config default)", p.MaxUses)
			}

			// (b) issued event on queries:<user> and queries:sess:<sid>.
			ev := recvIssuedEvent(t, userCh)
			assertIssuedEvent(t, ev, tc.user, tc.dbUser, tc.dbType, sid)
			evSess := recvIssuedForSid(t, sessPat, sid)
			if evSess.ID != ev.ID {
				t.Errorf("per-session issued event id %q != user-channel id %q", evSess.ID, ev.ID)
			}
		})
	}
}
