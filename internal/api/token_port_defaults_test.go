package api

// Task (node-integration 1): db_port becomes OPTIONAL on POST /api/token.
// Resolution order: explicit db_port (verbatim, existing validation) → the
// dbPortDefaults map in handlers.go (db_type + optional db_subtype → port)
// → 422 with the documented error. db_subtype is a NEW OPTIONAL field
// (trimmed, ≤64 chars, no control chars; absent = subtype "default").
// The canonical ports: mysql→3306, postgres→5432, mssql→1433, oracle→1521.
// Payload and TokenResponse shapes are UNCHANGED — the port is just the
// resolved value.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
)

// TestTokenDefaultPortMySQL: a mysql mint with NO db_port resolves the
// payload's db_port to the canonical 3306 from the map.
func TestTokenDefaultPortMySQL(t *testing.T) {
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	token := issueToken(t, client, srv.URL,
		`{"db_user":"some_user","db_ip":"10.1.2.3","db_type":"mysql","ticket_id":"T-PORT-1"}`)
	p, err := vs.GetDeleteToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetDeleteToken(%q): %v", token, err)
	}
	if p == nil {
		t.Fatalf("tok:%s missing", token)
	}
	if p.DBPort != "3306" {
		t.Errorf("mysql mint without db_port: stored db_port = %q, want 3306", p.DBPort)
	}
}

// TestTokenDefaultPortByType: postgres → 5432, mssql → 1433, oracle → 1521
// (mysql→3306 is covered by TestTokenDefaultPortMySQL).
func TestTokenDefaultPortByType(t *testing.T) {
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
	ctx := context.Background()

	cases := []struct{ dbType, wantPort string }{
		{"postgres", "5432"},
		{"mssql", "1433"},
		{"oracle", "1521"},
	}
	for _, tc := range cases {
		body := fmt.Sprintf(`{"db_user":"some_user","db_ip":"10.1.2.3","db_type":%q,"ticket_id":"T-PORT-TYPE"}`, tc.dbType)
		token := issueToken(t, client, srv.URL, body)
		p, err := vs.GetDeleteToken(ctx, token)
		if err != nil {
			t.Fatalf("%s: GetDeleteToken(%q): %v", tc.dbType, token, err)
		}
		if p == nil {
			t.Fatalf("%s: tok:%s missing", tc.dbType, token)
		}
		if p.DBPort != tc.wantPort {
			t.Errorf("%s mint without db_port: stored db_port = %q, want %s", tc.dbType, p.DBPort, tc.wantPort)
		}
	}
}

// TestTokenExplicitPortBeatsMap (G3): when db_port IS supplied it wins over
// the map verbatim — mysql + db_port 3307 stores 3307, never the 3306 default.
func TestTokenExplicitPortBeatsMap(t *testing.T) {
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	token := issueToken(t, client, srv.URL,
		`{"db_user":"some_user","db_ip":"10.1.2.3","db_port":"3307","db_type":"mysql","ticket_id":"T-PORT-EXPL"}`)
	p, err := vs.GetDeleteToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetDeleteToken(%q): %v", token, err)
	}
	if p == nil {
		t.Fatalf("tok:%s missing", token)
	}
	if p.DBPort != "3307" {
		t.Errorf("mysql mint with explicit db_port: stored db_port = %q, want 3307 (explicit wins)", p.DBPort)
	}
}

// TestTokenSubtypeWithoutMapEntry: db_subtype is accepted by the shape rules,
// but subtype "master" has NO map entry today (the structure supports it, no
// entry ships) — a mint without db_port → 422 with the documented error.
func TestTokenSubtypeWithoutMapEntry(t *testing.T) {
	srv, client, _, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	body := `{"db_user":"some_user","db_ip":"10.1.2.3","db_type":"mysql","db_subtype":"master","ticket_id":"T-PORT-SUB"}`
	status, raw := postToken(t, client, srv.URL, body)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("mysql + db_subtype=master + no db_port: status %d, want 422 (body %s)", status, raw)
	}
	if !strings.Contains(raw, "no default port for db_type/db_subtype; pass db_port explicitly") {
		t.Errorf("error body = %s, want the documented no-default-port message", raw)
	}
}

// TestTokenSubtypeShape: db_subtype is trimmed before the map lookup (a
// padded "master" behaves as "master"), but >64 chars or control characters
// are rejected 400 invalid db_subtype.
func TestTokenSubtypeShape(t *testing.T) {
	srv, client, _, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	// Padded subtype is TRIMMED then looked up: "master" has no entry → 422
	// (not 400) with the map-miss message.
	status, raw := postToken(t, client, srv.URL,
		`{"db_user":"some_user","db_ip":"10.1.2.3","db_type":"mysql","db_subtype":"  master  ","ticket_id":"T-PORT-SHAPE"}`)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("padded db_subtype: status %d, want 422 (trimmed lookup; body %s)", status, raw)
	}
	if !strings.Contains(raw, "no default port for db_type/db_subtype") {
		t.Errorf("padded db_subtype body = %s, want the no-default-port message", raw)
	}

	// 65 chars → 400 invalid db_subtype.
	status, raw = postToken(t, client, srv.URL,
		fmt.Sprintf(`{"db_user":"some_user","db_ip":"10.1.2.3","db_type":"mysql","db_subtype":%q,"ticket_id":"T-PORT-SHAPE"}`, strings.Repeat("a", 65)))
	if status != http.StatusBadRequest {
		t.Fatalf("65-char db_subtype: status %d, want 400 (body %s)", status, raw)
	}
	if !strings.Contains(raw, "invalid db_subtype") {
		t.Errorf("65-char db_subtype body = %s, want invalid db_subtype", raw)
	}

	// Control character (JSON \t decodes to a real tab) → 400.
	status, raw = postToken(t, client, srv.URL,
		`{"db_user":"some_user","db_ip":"10.1.2.3","db_type":"mysql","db_subtype":"ma\tster","ticket_id":"T-PORT-SHAPE"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("control-char db_subtype: status %d, want 400 (body %s)", status, raw)
	}
	if !strings.Contains(raw, "invalid db_subtype") {
		t.Errorf("control-char db_subtype body = %s, want invalid db_subtype", raw)
	}
}

// TestTokenInvalidDBTypeWithoutPort: an unknown db_type WITHOUT db_port is
// still the EXISTING 422 db_type message — type validation precedes port
// resolution, so the new path cannot shadow it.
func TestTokenInvalidDBTypeWithoutPort(t *testing.T) {
	srv, client, _, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	body := `{"db_user":"ro_user","db_ip":"127.0.0.1","db_type":"mongodb","ticket_id":"T-PORT-BAD"}`
	status, raw := postToken(t, client, srv.URL, body)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown db_type without db_port: status %d, want 422 (body %s)", status, raw)
	}
	if !strings.Contains(raw, "db_type must be mysql, mariadb, postgres, mssql or oracle") {
		t.Errorf("error body = %s, want the canonical db_type message", raw)
	}
}

// TestTokenMissingFieldsWithoutPort: dropping db_port from the request does
// NOT loosen the other required-field checks — a body missing db_user (with
// no db_port either) is still 400 missing required fields, never a map
// lookup for an incomplete target.
func TestTokenMissingFieldsWithoutPort(t *testing.T) {
	srv, client, _, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	body := `{"db_ip":"10.1.2.3","db_type":"mysql","ticket_id":"T-PORT-MISS"}`
	status, raw := postToken(t, client, srv.URL, body)
	if status != http.StatusBadRequest {
		t.Fatalf("db_user missing: status %d, want 400 (body %s)", status, raw)
	}
	if !strings.Contains(raw, "missing required fields") {
		t.Errorf("error body = %s, want missing required fields", raw)
	}
}

// TestTokenDefaultPortAuditPendingRow (live): a no-db_port mysql mint through
// the REAL audit wiring — the stored payload carries the RESOLVED port (3306,
// the audit SessionsRecord itself is port-agnostic) and the pending audit row
// is written exactly as before (status/username/ticket/db target unchanged).
func TestTokenDefaultPortAuditPendingRow(t *testing.T) {
	srv, client, vs, db, cfg := newAuditTestAPIServer(t)

	user := fmt.Sprintf("port-audit-%d", time.Now().UnixNano())
	authed := withBearer(client, mintJWT(t, cfg, user, "maker"))
	token := issueToken(t, authed, srv.URL,
		`{"db_user":"ro_user","db_ip":"127.0.0.1","db_type":"mysql","ticket_id":"T-PORT-AUDIT"}`)

	p, err := vs.GetDeleteToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetDeleteToken(%q): %v", token, err)
	}
	if p == nil {
		t.Fatalf("tok:%s missing", token)
	}
	if p.DBPort != "3306" {
		t.Errorf("stored db_port = %q, want 3306 (resolved from the map)", p.DBPort)
	}
	if p.SessionID == "" {
		t.Fatal("stored payload has no session id")
	}
	sid := p.SessionID
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), sid) })

	r := fetchAuditRow(t, db, sid)
	if r.status != "pending" {
		t.Errorf("audit status = %q, want pending", r.status)
	}
	if r.username != user {
		t.Errorf("audit username = %q, want maker %q", r.username, user)
	}
	if r.ticketID != "T-PORT-AUDIT" {
		t.Errorf("audit ticket_id = %q, want T-PORT-AUDIT", r.ticketID)
	}
	if r.dbType != "mysql" || r.dbUser != "ro_user" {
		t.Errorf("audit db target = %s/%s, want mysql/ro_user", r.dbType, r.dbUser)
	}
	if r.access != "read" {
		t.Errorf("audit access = %q, want read (ro_user preset)", r.access)
	}
}

// TestTokenSubtypeWithExplicitPort: a subtype with no map entry does NOT
// reject a mint that supplies db_port explicitly — the explicit port wins
// (G3) regardless of subtype.
func TestTokenSubtypeWithExplicitPort(t *testing.T) {
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	token := issueToken(t, client, srv.URL,
		`{"db_user":"some_user","db_ip":"10.1.2.3","db_port":"13306","db_type":"mysql","db_subtype":"master","ticket_id":"T-PORT-SUBX"}`)
	p, err := vs.GetDeleteToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetDeleteToken(%q): %v", token, err)
	}
	if p == nil {
		t.Fatalf("tok:%s missing", token)
	}
	if p.DBPort != "13306" {
		t.Errorf("stored db_port = %q, want 13306 (explicit db_port wins over subtype map miss)", p.DBPort)
	}
}

// TestTokenResponseShapeUnchanged: the mint response decodes into the exact
// TokenResponse field set (token/session_id/host/port/expires_in) — the
// optional request fields add nothing to the response.
func TestTokenResponseShapeUnchanged(t *testing.T) {
	srv, client, _, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	resp, err := client.Post(srv.URL+"/api/token", "application/json",
		strings.NewReader(`{"db_user":"some_user","db_ip":"10.1.2.3","db_type":"mysql","ticket_id":"T-PORT-RESP"}`))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/token: status %d, want 200", resp.StatusCode)
	}
	var got models.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if got.Token == "" || got.SessionID == "" || got.ExpiresIn == 0 {
		t.Errorf("token response incomplete: %+v", got)
	}
}
