package api

// Task 9.13 — session-mode token issuance (option A): request mode wins,
// then the target preset's token_mode, then api.token_mode. Session tokens
// are IP-stamped, non-consuming (no max_uses), with TTL 0 = INFINITE
// (expires_in -1) and the finite-TTL variant. Single-use minting is
// unchanged.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// newModeTestAPIServer is newTestAPIServer with the Task 9.13 knobs wired
// into the config (token_mode + session_token_ttl_seconds + one session-
// mode preset).
func newModeTestAPIServer(t *testing.T, tokenMode string, sessionTTL int) (*httptest.Server, *http.Client, *store.ValkeyStore) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:        "admin",
		AuthPassword:    "s3cret",
		SessionTTL:      8,
		TokenTTL:        60,
		TokenMaxUses:    1,
		TokenMode:       tokenMode,
		SessionTokenTTL: sessionTTL,
		StaticDir:       t.TempDir(),
		DBPresets: []config.DBPreset{
			{Name: "MSSQL read-only", DBType: "mssql", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "1434", Access: "read"},
			{Name: "MSSQL GUI session", DBType: "mssql", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "1434", Access: "write", TokenMode: "session"},
		},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return srv, &http.Client{Jar: jar}, vs
}

// issueTokenFull posts a token request (session-authenticated) and returns
// the decoded response + status.
func issueTokenFull(t *testing.T, client *http.Client, base, body string) (token string, expiresIn int, status int) {
	t.Helper()
	resp, err := client.Post(base+"/api/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	var issued struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
		Error     string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&issued)
	return issued.Token, issued.ExpiresIn, resp.StatusCode
}

// fetchPayload reads the stored token payload straight from valkey.
func fetchPayload(t *testing.T, vs *store.ValkeyStore, token string) map[string]any {
	t.Helper()
	raw, err := vs.GetDeleteToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetDeleteToken: %v", err)
	}
	if raw == nil {
		t.Fatalf("token %s not stored", token)
	}
	// GetDeleteToken CONSUMES single-use tokens — re-store the payload so
	// cleanup/assertions can still see the key state. (Session tokens are
	// not consumed; single-use tokens in this test are re-created.)
	data, _ := json.Marshal(raw)
	_ = vs.SetToken(context.Background(), token, *raw, 5*time.Minute)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return m
}

func TestTokenIssueSessionMode(t *testing.T) {
	srv, client, vs := newModeTestAPIServer(t, "single-use", 0)
	sessionAs(t, client, srv.URL, vs, "alice")
	token, expiresIn, status := issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13","mode":"session"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if expiresIn != -1 {
		t.Errorf("expires_in = %d, want -1 (infinite session token)", expiresIn)
	}
	p := fetchPayload(t, vs, token)
	if p["mode"] != "session" {
		t.Errorf("payload mode = %v, want session", p["mode"])
	}
	if p["ip"] != "127.0.0.1" {
		t.Errorf("payload ip = %v, want 127.0.0.1 (issue-time stamp)", p["ip"])
	}
	if _, ok := p["issued_at"]; !ok {
		t.Errorf("payload lacks issued_at")
	}
	if _, ok := p["max_uses"]; ok {
		t.Errorf("session token carries max_uses — it must not be consumed")
	}
}

func TestTokenIssueSessionModeFiniteTTL(t *testing.T) {
	srv, client, vs := newModeTestAPIServer(t, "single-use", 300)
	sessionAs(t, client, srv.URL, vs, "alice")
	_, expiresIn, status := issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13","mode":"session"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if expiresIn != 300 {
		t.Errorf("expires_in = %d, want 300", expiresIn)
	}
}

func TestTokenIssueInvalidMode(t *testing.T) {
	srv, client, vs := newModeTestAPIServer(t, "single-use", 0)
	sessionAs(t, client, srv.URL, vs, "alice")
	_, _, status := issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13","mode":"bogus"}`)
	if status != http.StatusBadRequest {
		t.Errorf("status %d, want 400 for invalid mode", status)
	}
}

func TestTokenIssuePresetTokenMode(t *testing.T) {
	srv, client, vs := newModeTestAPIServer(t, "single-use", 0)
	sessionAs(t, client, srv.URL, vs, "alice")

	// The rw_user preset declares token_mode: session → no request mode
	// needed.
	ptok, _, status := issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13"}`)
	if status != http.StatusOK {
		t.Fatalf("preset-session status %d, want 200", status)
	}
	if p := fetchPayload(t, vs, ptok); p["mode"] != "session" {
		t.Errorf("preset token_mode not honored: mode = %v", p["mode"])
	}

	// A preset without token_mode + config default single-use → single-use
	// (max_uses present, no mode).
	token2, _, status := issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13"}`)
	if status != http.StatusOK {
		t.Fatalf("default status %d, want 200", status)
	}
	p2 := fetchPayload(t, vs, token2)
	if m, _ := p2["mode"].(string); m != "" && m != "single-use" {
		t.Errorf("default mode = %v, want single-use", p2["mode"])
	}
	if mu, ok := p2["max_uses"]; !ok || fmt.Sprint(mu) != "1" {
		t.Errorf("single-use default payload max_uses = %v, want 1", p2["max_uses"])
	}
}

func TestTokenIssueConfigDefaultSession(t *testing.T) {
	// api.token_mode: session as the global default (GUI deployment).
	srv, client, vs := newModeTestAPIServer(t, "session", 0)
	sessionAs(t, client, srv.URL, vs, "alice")
	token, expiresIn, status := issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if expiresIn != -1 {
		t.Errorf("expires_in = %d, want -1", expiresIn)
	}
	if p := fetchPayload(t, vs, token); p["mode"] != "session" {
		t.Errorf("config default mode = %v, want session", p["mode"])
	}
}

func TestTokenIssueIdleOverride(t *testing.T) {
	srv, client, vs := newModeTestAPIServer(t, "single-use", 0)
	sessionAs(t, client, srv.URL, vs, "alice")

	// Per-token idle override lands in the stored payload (any mode).
	token, _, status := issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13","idle_seconds":600}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if p := fetchPayload(t, vs, token); fmt.Sprint(p["idle_seconds"]) != "600" {
		t.Errorf("payload idle_seconds = %v, want 600", p["idle_seconds"])
	}

	// Absent → 0 (follow the data-plane default).
	token2, _, status := issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if p := fetchPayload(t, vs, token2); p["idle_seconds"] != nil {
		t.Errorf("payload idle_seconds = %v, want absent (default)", p["idle_seconds"])
	}

	// Negative → 400.
	_, _, status = issueTokenFull(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-13","idle_seconds":-5}`)
	if status != http.StatusBadRequest {
		t.Errorf("status %d, want 400 for negative idle_seconds", status)
	}
}
