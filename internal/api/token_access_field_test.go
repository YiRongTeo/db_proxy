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

// --- Task 6 (node-integration): explicit access on POST /api/token ----------
//
// Owner-corrected semantics (2026-10-21): the request may carry an explicit
// `access` field — "read"/"ro" (case-insensitive) → canonical "ro" (TRUE
// read-only: every write SQL command rejected at the proxy), "write"/"rw" →
// canonical "rw" (connection HELD until a checker watches). Absent/null →
// the preset path unchanged. Invalid → 422 naming the field. Alias
// normalization happens BEFORE the checker SoD check (checker + rw → 403).
// Preset migration: a preset's access:"read" now resolves to "ro".

// newAccessFieldTestServer is a preset fixture with a read-only, a
// read-write and an ORACLE read-only preset (the oracle preset proves the
// ro-migration 422: oracle has no statement classification, so a ro mint
// for it is refused at the mint rather than silently unprotected).
func newAccessFieldTestServer(t *testing.T) (*httptest.Server, *http.Client, *store.ValkeyStore, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
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
			{Name: "Oracle read-only", DBType: "oracle", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "1521", Access: "read"},
		},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, vs, cfg
}

// TestTokenAccessFieldNormalization: the explicit access field normalizes
// case-insensitively to the canonical payload values — read/ro → "ro",
// write/rw → "rw" — and the explicit value WINS over the matching preset.
func TestTokenAccessFieldNormalization(t *testing.T) {
	srv, client, vs, cfg := newAccessFieldTestServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
	ctx := context.Background()

	cases := []struct {
		name, raw, want string
	}{
		{"ro alias", "ro", "ro"},
		{"read alias", "read", "ro"},
		{"uppercase RO", "RO", "ro"},
		{"mixed case Read", "Read", "ro"},
		{"rw alias", "rw", "rw"},
		{"write alias", "write", "rw"},
		{"uppercase RW", "RW", "rw"},
		{"mixed case Write", "wRiTe", "rw"},
		// Explicit access overrides the matched preset in BOTH directions.
		{"explicit rw over read preset", "rw", "rw"},
		{"explicit ro over write preset", "ro", "ro"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Odd rows hit the read preset (ro_user), even rows the write
			// preset (rw_user) — the override must win either way.
			target := "ro_user"
			if tc.raw == "rw" || tc.raw == "write" || tc.raw == "RW" || tc.raw == "wRiTe" || tc.raw == "ro" {
				target = "rw_user"
			}
			if tc.raw == "ro" || tc.raw == "RO" || tc.raw == "Read" || tc.raw == "read" {
				target = "ro_user"
			}
			body := `{"db_user":"` + target + `","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-6-access","access":"` + tc.raw + `"}`
			token := issueToken(t, client, srv.URL, body)
			p, err := vs.GetDeleteToken(ctx, token)
			if err != nil || p == nil {
				t.Fatalf("GetDeleteToken: p=%v err=%v", p, err)
			}
			if p.Access != tc.want {
				t.Errorf("access %q → stored %q, want %q", tc.raw, p.Access, tc.want)
			}
		})
	}
}

// TestTokenAccessFieldAbsentNullPresetPath: an ABSENT access field and an
// explicit null both take the preset path — byte-for-byte the pre-field
// behavior except for the deliberate read→ro preset migration.
func TestTokenAccessFieldAbsentNullPresetPath(t *testing.T) {
	srv, client, vs, cfg := newAccessFieldTestServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
	ctx := context.Background()

	cases := []struct {
		name, body, want string
	}{
		// No field: read preset migrates to ro enforcement.
		{"absent on read preset", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-6-access"}`, "ro"},
		// No field: write preset keeps legacy (no gate), verbatim "write".
		{"absent on write preset", `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-6-access"}`, "write"},
		// No field, no preset: ungated "" — byte-for-byte G3.
		{"absent no preset", `{"db_user":"some_user","db_ip":"10.1.2.3","db_port":"3306","db_type":"mysql","ticket_id":"T-6-access"}`, ""},
		// Explicit null = absent.
		{"null on read preset", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-6-access","access":null}`, "ro"},
		// Explicit empty string = no preference → preset path.
		{"empty string on read preset", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-6-access","access":""}`, "ro"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := issueToken(t, client, srv.URL, tc.body)
			p, err := vs.GetDeleteToken(ctx, token)
			if err != nil || p == nil {
				t.Fatalf("GetDeleteToken: p=%v err=%v", p, err)
			}
			if p.Access != tc.want {
				t.Errorf("stored access = %q, want %q", p.Access, tc.want)
			}
		})
	}
}

// TestTokenAccessFieldInvalid422: anything outside read/ro/write/rw is a
// 422 whose body NAMES the field.
func TestTokenAccessFieldInvalid422(t *testing.T) {
	srv, client, _, cfg := newAccessFieldTestServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	for _, raw := range []string{"admin", "readonly", "rw/", "ro rw", "none"} {
		body := `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-6-access","access":"` + raw + `"}`
		status, respBody := postToken(t, client, srv.URL, body)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("access %q: status %d, want 422 (body %s)", raw, status, respBody)
			continue
		}
		if !strings.Contains(respBody, "access") {
			t.Errorf("access %q: body %s does not name the field", raw, respBody)
		}
	}
}

// TestTokenAccessFieldCheckerSoDAfterNormalization: alias normalization
// happens BEFORE the checker SoD check — a checker sending "rw" (or the
// "write" alias) is 403'd on the CANONICAL value, while "ro"/"read" mints.
func TestTokenAccessFieldCheckerSoDAfterNormalization(t *testing.T) {
	srv, client, _, cfg := newAccessFieldTestServer(t)

	cases := []struct {
		name, role, raw string
		wantStatus      int
	}{
		{"checker rw", "checker", "rw", http.StatusForbidden},
		{"checker write alias", "checker", "write", http.StatusForbidden},
		{"checker uppercase RW", "checker", "RW", http.StatusForbidden},
		{"checker ro", "checker", "ro", http.StatusOK},
		{"checker read alias", "checker", "read", http.StatusOK},
		{"maker rw", "maker", "rw", http.StatusOK},
		{"maker ro", "maker", "ro", http.StatusOK},
		// Legacy preset path unchanged: checker + write preset still 403.
		{"checker write preset", "checker", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authed := withBearer(client, mintJWT(t, cfg, testJWTUser, tc.role))
			target := "rw_user" // write preset — the legacy 403 row needs it
			if tc.name == "checker ro" || tc.name == "checker read alias" || tc.name == "maker ro" {
				target = "ro_user"
			}
			body := `{"db_user":"` + target + `","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-6-access"`
			if tc.raw != "" {
				body += `,"access":"` + tc.raw + `"`
			}
			body += `}`
			status, respBody := postToken(t, authed, srv.URL, body)
			if status != tc.wantStatus {
				t.Fatalf("status %d, want %d (body %s)", status, tc.wantStatus, respBody)
			}
			if tc.wantStatus == http.StatusForbidden &&
				!strings.Contains(respBody, "checker role limited to read-only tokens") {
				t.Errorf("403 body = %s, want the canonical checker message", respBody)
			}
		})
	}
}

// TestTokenAccessFieldOracleRoRefused: oracle has NO statement
// classification (TNS capture is Phase 1) — a ro mint for db_type oracle is
// REFUSED at the mint with a named 422 (explicit ro AND the migrated
// read-only preset), never silently unprotected. rw stays available.
func TestTokenAccessFieldOracleRoRefused(t *testing.T) {
	srv, client, _, cfg := newAccessFieldTestServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	cases := []struct {
		name, body string
	}{
		{"explicit ro", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1521","db_type":"oracle","ticket_id":"T-6-access","access":"ro"}`},
		{"read alias", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1521","db_type":"oracle","ticket_id":"T-6-access","access":"read"}`},
		{"preset read migrates to ro → 422", `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1521","db_type":"oracle","ticket_id":"T-6-access"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, respBody := postToken(t, client, srv.URL, tc.body)
			if status != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422 (body %s)", status, respBody)
			}
			if !strings.Contains(respBody, "oracle") {
				t.Errorf("body %s does not name oracle", respBody)
			}
		})
	}
	// rw mints for oracle are FINE (the hold needs no classification) —
	// covered by TestTokenAccessFieldOracleRwAllowed below.
}

// TestTokenAccessFieldOracleRwAllowed: the rw hold needs no SQL
// classification, so an explicit rw mint for oracle succeeds.
func TestTokenAccessFieldOracleRwAllowed(t *testing.T) {
	srv, client, vs, cfg := newAccessFieldTestServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
	ctx := context.Background()

	token := issueToken(t, client, srv.URL, `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1521","db_type":"oracle","ticket_id":"T-6-access","access":"rw"}`)
	p, err := vs.GetDeleteToken(ctx, token)
	if err != nil || p == nil {
		t.Fatalf("GetDeleteToken: p=%v err=%v", p, err)
	}
	if p.Access != "rw" {
		t.Errorf("stored access = %q, want rw", p.Access)
	}
}

// TestTokenAccessFieldStoredPayloadShape: the stored payload's access stays
// within the canonical set {"", "ro", "rw", "write"(legacy presets)} — the
// raw alias never ships.
func TestTokenAccessFieldStoredPayloadShape(t *testing.T) {
	srv, client, vs, cfg := newAccessFieldTestServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
	ctx := context.Background()

	token := issueToken(t, client, srv.URL, `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-6-access","access":"READ"}`)
	p, err := vs.GetDeleteToken(ctx, token)
	if err != nil || p == nil {
		t.Fatalf("GetDeleteToken: p=%v err=%v", p, err)
	}
	if p.Access != "ro" {
		t.Errorf("stored access = %q, want canonical ro", p.Access)
	}
	// The wire payload JSON carries the canonical value.
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if !strings.Contains(string(raw), `"access":"ro"`) {
		t.Errorf("payload JSON %s lacks the canonical access value", raw)
	}
}
