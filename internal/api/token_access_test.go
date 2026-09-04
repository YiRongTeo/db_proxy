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
// AllowMakerWatch is TRUE: this fixture models a single-account deployment
// whose maker drives both /api/token and the GET /api/sessions directory
// listing (the Task 8 role gate admits maker role only with the flag).
func newPresetTestAPIServer(t *testing.T) (*httptest.Server, *http.Client, *store.ValkeyStore, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:        testJWTUser,
		AuthPassword:    testJWTPassword,
		AuthRole:        "maker",
		AllowMakerWatch: true, // maker may list/watch in this fixture (Task 8)
		JWT:             testJWTBlock(),
		SessionTTL:      8,
		TokenTTL:        60,
		StaticDir:       t.TempDir(),
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
	return srv, &http.Client{}, vs, cfg
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
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	// The mint route is requireJWT-guarded (Task 7): authenticate as the
	// fixture user with a minted JWT.
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
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
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
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
	srv, client, _, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

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

// --- Task 7: JWT-only mint + checker read-only role gate --------------------

// postToken POSTs a token request and returns the status + raw body (for
// tests that must inspect rejections; 200-path callers use issueToken).
func postToken(t *testing.T, client *http.Client, base, body string) (int, string) {
	t.Helper()
	resp, err := client.Post(base+"/api/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read token response: %v", err)
	}
	return resp.StatusCode, string(raw)
}

// Task 7 request bodies: the mysql presets in newPresetTestAPIServer are
// ro_user (read, :3307) and rw_user (write, :3307); the ad-hoc target
// matches NO preset (access "" — the data plane treats absent access as
// read, so it stays ungated for both roles).
const (
	task7ReadBody  = `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-role"}`
	task7WriteBody = `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-role"}`
	task7AdhocBody = `{"db_user":"some_user","db_ip":"10.1.2.3","db_port":"3306","db_type":"mysql","ticket_id":"T-7-role"}`
)

// TestTokenRoleGate (Task 7 user directive): POST /api/token enforces the
// checker read-only rule — a checker-role principal requesting a WRITE-access
// preset is refused 403 BEFORE any token is stored; read-access presets and
// ungated ad-hoc targets stay available to BOTH roles.
func TestTokenRoleGate(t *testing.T) {
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	ctx := context.Background()

	cases := []struct {
		name, role, body string
		wantStatus       int
		wantAccess       string // stored payload access for the 200 rows
	}{
		{"checker + read preset", "checker", task7ReadBody, http.StatusOK, "read"},
		{"checker + write preset", "checker", task7WriteBody, http.StatusForbidden, ""},
		{"maker + write preset", "maker", task7WriteBody, http.StatusOK, "write"},
		{"maker + read preset", "maker", task7ReadBody, http.StatusOK, "read"},
		{"checker + ad-hoc target (no preset)", "checker", task7AdhocBody, http.StatusOK, ""},
		{"maker + ad-hoc target (no preset)", "maker", task7AdhocBody, http.StatusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authed := withBearer(client, mintJWT(t, cfg, testJWTUser, tc.role))
			status, body := postToken(t, authed, srv.URL, tc.body)
			if status != tc.wantStatus {
				t.Fatalf("status %d, want %d (body %s)", status, tc.wantStatus, body)
			}
			if status == http.StatusForbidden {
				if !strings.Contains(body, "checker role limited to read-only tokens") {
					t.Errorf("403 body = %s, want the checker read-only error", body)
				}
				return
			}
			// 200 rows: the stored payload carries the resolved access
			// level (the gate must not distort access resolution).
			var issued struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(strings.NewReader(body)).Decode(&issued); err != nil {
				t.Fatalf("decode 200 body %s: %v", body, err)
			}
			p, err := vs.GetDeleteToken(ctx, issued.Token)
			if err != nil || p == nil {
				t.Fatalf("GetDeleteToken: p=%v err=%v", p, err)
			}
			if p.Access != tc.wantAccess {
				t.Errorf("stored access = %q, want %q", p.Access, tc.wantAccess)
			}
		})
	}
}

// TestTokenMintRequiresJWT (Task 7): POST /api/token without a bearer JWT is
// 401 — no credential at all, AND the retired control-plane X-Api-Key header
// alone (the pre-Task-7 mint auth) must NOT authenticate a mint.
func TestTokenMintRequiresJWT(t *testing.T) {
	srv, client, _, _ := newPresetTestAPIServer(t)

	if status, body := postToken(t, client, srv.URL, task7ReadBody); status != http.StatusUnauthorized {
		t.Errorf("no auth: status %d, want 401 (body %s)", status, body)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/token", strings.NewReader(task7ReadBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Api-Key", "retired-key")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /api/token with X-Api-Key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("X-Api-Key mint: status %d, want 401 (control-plane API key retired)", resp.StatusCode)
	}
}

// TestTokenMintDenylistedJWT401 (Task 7 CARRY-FORWARD from the Task 4
// review): a logged-out (denylisted) bearer must NOT be able to mint — POST
// /api/token answers 401 even though the token's signature is still valid.
// The denylist consult lives in requireJWT (Task 6), which now guards the
// mint route, so revocation and mint share ONE auth path.
func TestTokenMintDenylistedJWT401(t *testing.T) {
	srv, client, _, _ := newPresetTestAPIServer(t)
	tok := loginJWT(t, client, srv.URL, testJWTUser, testJWTPassword)
	authed := withBearer(client, tok)

	// Sanity: the fresh token mints.
	if status, body := postToken(t, authed, srv.URL, task7ReadBody); status != http.StatusOK {
		t.Fatalf("pre-logout mint: status %d, want 200 (body %s)", status, body)
	}
	// Logout denylists the token's jti (Task 6 handleLogout).
	resp, err := authed.Post(srv.URL+"/api/logout", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/logout: status %d, want 200", resp.StatusCode)
	}
	// The SAME token, now denylisted → the mint route must refuse it.
	if status, body := postToken(t, authed, srv.URL, task7ReadBody); status != http.StatusUnauthorized {
		t.Errorf("denylisted mint: status %d, want 401 (body %s)", status, body)
	}
}
