package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// --- Task 8.6: token access from the db_presets -----------------------------

// newPresetTestAPIServer is newTestAPIServer with the committed db_presets
// wired into the config, so handleToken can resolve access levels.
func newPresetTestAPIServer(t *testing.T) (*httptest.Server, *http.Client, *store.ValkeyStore, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "maker",
		JWT:          testJWTBlock(),
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
		DBPresets: []config.DBPreset{
			{Name: "MySQL read-only", DBType: "mysql", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "3307", Access: "read"},
			{Name: "MySQL read-write", DBType: "mysql", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "3307", Access: "write"},
			{Name: "PostgreSQL read-only", DBType: "postgres", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "5433", Access: "read"},
			// Task 9.3 review GAP 1: the committed mssql presets (mirror of the
			// mysql/pg pairs) so /api/token can stamp mssql access levels.
			{Name: "MSSQL read-only", DBType: "mssql", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "1434", Access: "read"},
			{Name: "MSSQL read-write", DBType: "mssql", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "1434", Access: "write"},
		},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	return srv, newJarClient(t), vs, cfg
}

// issueToken posts a token request through the real endpoint and returns the
// issued token string.
func issueToken(t *testing.T, client *http.Client, base, body string) string {
	t.Helper()
	resp, err := client.Post(base+"/api/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/token: status %d, want 200 (body %s)", resp.StatusCode, body)
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
	return issued.Token
}

// TestTokenAccessFromPreset (Task 8.6): POST /api/token stamps the stored
// payload with the matching preset's access level — write for the read-write
// preset, read for the read-only presets, "" for targets no preset matches
// (the data plane treats absent access as read).
func TestTokenAccessFromPreset(t *testing.T) {
	srv, client, vs, _ := newPresetTestAPIServer(t)
	loginViaAPI(t, client, srv.URL)
	ctx := context.Background()

	cases := []struct {
		name string
		body string
		want string
	}{
		{"read-write preset", `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-8-6"}`, "write"},
		{"mysql read-only preset", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-8-6"}`, "read"},
		{"pg read-only preset", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"5433","db_type":"postgres","ticket_id":"T-8-6"}`, "read"},
		{"no matching preset", `{"db_user":"some_user","db_ip":"10.1.2.3","db_port":"3306","db_type":"mysql","ticket_id":"T-8-6"}`, ""},
	}
	for _, tc := range cases {
		token := issueToken(t, client, srv.URL, tc.body)
		p, err := vs.GetDeleteToken(ctx, token)
		if err != nil {
			t.Fatalf("%s: GetDeleteToken(%q): %v", tc.name, token, err)
		}
		if p == nil {
			t.Fatalf("%s: tok:%s missing", tc.name, token)
		}
		if p.Access != tc.want {
			t.Errorf("%s: stored access = %q, want %q", tc.name, p.Access, tc.want)
		}
	}
}

// --- Task 9.3 review GAP 1: mssql token acceptance through /api/token ------

// TestTokenAccessMSSQLPresets: POST /api/token accepts db_type=mssql for
// BOTH committed mssql presets (read-only ro_user + read-write rw_user, both
// on 127.0.0.1:1434): 200, and the stored payload carries db_type=mssql with
// the full target fields (db_user/db_ip/db_port), the preset's access level
// and the issue-time session id + ticket.
func TestTokenAccessMSSQLPresets(t *testing.T) {
	srv, client, vs, _ := newPresetTestAPIServer(t)
	loginViaAPI(t, client, srv.URL)
	ctx := context.Background()

	cases := []struct {
		name string
		body string
		want string
	}{
		{"mssql read-only preset", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-3"}`, "read"},
		{"mssql read-write preset", `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-9-3"}`, "write"},
	}
	for _, tc := range cases {
		token := issueToken(t, client, srv.URL, tc.body)
		p, err := vs.GetDeleteToken(ctx, token)
		if err != nil {
			t.Fatalf("%s: GetDeleteToken(%q): %v", tc.name, token, err)
		}
		if p == nil {
			t.Fatalf("%s: tok:%s missing", tc.name, token)
		}
		if p.DBType != "mssql" {
			t.Errorf("%s: stored db_type = %q, want mssql", tc.name, p.DBType)
		}
		if p.DBUser == "" || p.DBIP != "127.0.0.1" || p.DBPort != "1434" {
			t.Errorf("%s: stored target = %s@%s:%s, want *@127.0.0.1:1434", tc.name, p.DBUser, p.DBIP, p.DBPort)
		}
		if p.Access != tc.want {
			t.Errorf("%s: stored access = %q, want %q", tc.name, p.Access, tc.want)
		}
		if p.TicketID != "T-9-3" || p.SessionID == "" || p.Username == "" {
			t.Errorf("%s: stored payload = %+v, want ticket T-9-3 + session id + username", tc.name, p)
		}
	}
}

// TestTokenRejectsInvalidDBType: the mssql/oracle acceptance must not have
// loosened the rejection — a db_type outside {mysql, postgres, mssql,
// oracle} still gets 422 with the canonical message.
func TestTokenRejectsInvalidDBType(t *testing.T) {
	srv, client, _, _ := newPresetTestAPIServer(t)
	loginViaAPI(t, client, srv.URL) // legacy cookie session for the /api/token leg (until Task 7)

	body := `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mongodb","ticket_id":"T-9-3"}`
	resp, err := client.Post(srv.URL+"/api/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("POST /api/token: status %d, want 422 (body %s)", resp.StatusCode, body)
	}
	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), "db_type must be mysql, postgres, mssql or oracle") {
		t.Errorf("error body = %s, want the canonical db_type message", got)
	}
}
