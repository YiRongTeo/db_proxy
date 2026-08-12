package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/store"
)

// --- POST /api/kill (Task 6.5, spec amendment 9e) ---

// TestKillRequiresSession: POST /api/kill without a zt_session cookie → 401.
func TestKillRequiresSession(t *testing.T) {
	srv, client := newTestAPIServer(t)

	resp, err := client.Post(srv.URL+"/api/kill", "application/json",
		strings.NewReader(`{"session_id":"sid-x"}`))
	if err != nil {
		t.Fatalf("POST /api/kill: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /api/kill without cookie: status %d, want 401", resp.StatusCode)
	}
}

// TestKillBadRequest: with a valid session, missing/empty/malformed
// session_id must all yield 400 {"error":"session_id required"}.
func TestKillBadRequest(t *testing.T) {
	srv, client := newTestAPIServer(t)
	loginViaAPI(t, client, srv.URL)

	for name, body := range map[string]string{
		"empty session_id":   `{"session_id":""}`,
		"missing session_id": `{}`,
		"malformed json":     `{not json`,
		"wrong type":         `{"session_id":42}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := client.Post(srv.URL+"/api/kill", "application/json",
				strings.NewReader(body))
			if err != nil {
				t.Fatalf("POST /api/kill: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("body %q: status %d, want 400", body, resp.StatusCode)
			}
			var got map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatalf("decode kill response: %v", err)
			}
			if got["error"] != "session_id required" {
				t.Errorf("body %q: error = %q, want %q", body, got["error"], "session_id required")
			}
		})
	}
}

// TestKillPublishesCtlKill is the live proof for the kill path: a Valkey
// subscriber on the ctl:kill channel (exactly what the data plane runs,
// Task 6.4) is registered BEFORE the POST, then POST /api/kill with
// {"session_id":"sid-x"} must return 202 {"killed":"queued"} and the
// subscriber must receive exactly {"session_id":"sid-x","mode":"connection"}
// — the mode field defaults to "connection" (Task 8.4).
func TestKillPublishesCtlKill(t *testing.T) {
	srv, client := newTestAPIServer(t)
	loginViaAPI(t, client, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vs, err := store.NewValkeyStoreDirect(ctx, "127.0.0.1:6379", "", 0)
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	defer vs.Close()

	out := make(chan []byte, 4)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	subErr := make(chan error, 1)
	go func() { subErr <- vs.Subscribe(subCtx, "ctl:kill", false, out) }()
	select {
	case <-acked:
	case err := <-subErr:
		t.Fatalf("ctl:kill subscribe failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ctl:kill subscription not confirmed within 5s")
	}

	resp, err := client.Post(srv.URL+"/api/kill", "application/json",
		strings.NewReader(`{"session_id":"sid-x"}`))
	if err != nil {
		t.Fatalf("POST /api/kill: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/kill: status %d, want 202", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode kill response: %v", err)
	}
	if got["killed"] != "queued" {
		t.Errorf("kill response = %q, want %q", got["killed"], "queued")
	}

	select {
	case m := <-out:
		if string(m) != `{"session_id":"sid-x","mode":"connection"}` {
			t.Fatalf("ctl:kill message = %s, want %s", m, `{"session_id":"sid-x","mode":"connection"}`)
		}
	case err := <-subErr:
		t.Fatalf("ctl:kill subscriber exited: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no ctl:kill message within 5s")
	}
}

// --- POST /api/token ticket requirement (Task 6.5, spec amendment 9b) ---

// TestTokenRequiresTicketID: with a valid UI session, a token request
// WITHOUT ticket_id → 400 {"error":"ticket_id required"}; WITH ticket_id →
// 200 and the issued tok:<token> key exists in Valkey with the ticket.
func TestTokenRequiresTicketID(t *testing.T) {
	srv, client := newTestAPIServer(t)
	loginViaAPI(t, client, srv.URL)

	noTicket := `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3306","db_type":"mysql"}`
	resp, err := client.Post(srv.URL+"/api/token", "application/json",
		strings.NewReader(noTicket))
	if err != nil {
		t.Fatalf("POST /api/token without ticket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/token without ticket_id: status %d, want 400", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode token error response: %v", err)
	}
	if got["error"] != "ticket_id required" {
		t.Errorf("error = %q, want %q", got["error"], "ticket_id required")
	}

	withTicket := `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3306","db_type":"mysql","ticket_id":"T-6.5"}`
	resp, err = client.Post(srv.URL+"/api/token", "application/json",
		strings.NewReader(withTicket))
	if err != nil {
		t.Fatalf("POST /api/token with ticket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/token with ticket_id: status %d, want 200", resp.StatusCode)
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if issued.Token == "" {
		t.Fatal("token response: empty token")
	}

	// The tok:<token> key must exist and carry the ticket_id round-trip.
	ctx := context.Background()
	vs, err := store.NewValkeyStoreDirect(ctx, "127.0.0.1:6379", "", 0)
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	defer vs.Close()
	p, err := vs.GetDeleteToken(ctx, issued.Token)
	if err != nil {
		t.Fatalf("GetDeleteToken(%q): %v", issued.Token, err)
	}
	if p == nil {
		t.Fatalf("tok:%s missing in Valkey — token was not issued", issued.Token)
	}
	if p.TicketID != "T-6.5" {
		t.Errorf("stored ticket_id = %q, want %q", p.TicketID, "T-6.5")
	}
	if p.DBUser != "ro_user" || p.DBType != "mysql" {
		t.Errorf("stored payload = %+v, want db_user=ro_user db_type=mysql", p)
	}
}
