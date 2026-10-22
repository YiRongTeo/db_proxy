package api

import (
	"net/http"
	"strings"
	"testing"
)

// --- Task 7 (node-integration): auth.allow_checker_write (mint SoD flag) -----
//
// Default FALSE: the mint 403 (handlers.go — "checker role limited to
// read-only tokens") stays byte-identical (G3). TRUE: a checker-role
// principal may mint write AND rw tokens — the UAT escape hatch where one
// person plays maker AND checker. The self-watch SoD (checkerMayWatch) is
// NOT touched by this flag and has its own tests (checker_sod_test.go).

// TestTokenCheckerWriteFlagDefaultRefuses: flag absent (default false) —
// the current 403s hold exactly as before.
func TestTokenCheckerWriteFlagDefaultRefuses(t *testing.T) {
	srv, client, _, cfg := newAccessFieldTestServer(t) // AllowCheckerWrite unset = false

	for _, role := range []string{"checker"} {
		authed := withBearer(client, mintJWT(t, cfg, testJWTUser, role))
		// Explicit rw…
		status, body := postToken(t, authed, srv.URL, `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-sod","access":"rw"}`)
		if status != http.StatusForbidden {
			t.Fatalf("checker rw (flag default): status %d, want 403 (body %s)", status, body)
		}
		if !strings.Contains(body, "checker role limited to read-only tokens") {
			t.Errorf("403 body = %s, want the canonical checker message", body)
		}
		// …and the legacy write preset path.
		status, body = postToken(t, authed, srv.URL, `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-sod"}`)
		if status != http.StatusForbidden {
			t.Fatalf("checker write preset (flag default): status %d, want 403 (body %s)", status, body)
		}
		// ro still mints for a checker under strict SoD.
		status, _ = postToken(t, authed, srv.URL, `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-sod","access":"ro"}`)
		if status != http.StatusOK {
			t.Fatalf("checker ro (flag default): status %d, want 200", status)
		}
	}
}

// TestTokenCheckerWriteFlagAllows: cfg.AllowCheckerWrite = true — the SAME
// requests that 403 above now mint (write AND rw; the 403 is skipped), ro is
// unaffected, and a MAKER is unchanged (the flag only lifts the CHECKER
// restriction).
func TestTokenCheckerWriteFlagAllows(t *testing.T) {
	srv, client, _, cfg := newAccessFieldTestServer(t)
	cfg.AllowCheckerWrite = true

	authed := withBearer(client, mintJWT(t, cfg, testJWTUser, "checker"))
	for _, raw := range []string{"rw", "write", "RW"} {
		status, body := postToken(t, authed, srv.URL, `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-sod","access":"`+raw+`"}`)
		if status != http.StatusOK {
			t.Fatalf("checker %q with allow_checker_write: status %d, want 200 (body %s)", raw, status, body)
		}
	}
	// Legacy preset path (no access field → write preset → canonical write):
	// the 403 must be skipped here too.
	status, body := postToken(t, authed, srv.URL, `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-sod"}`)
	if status != http.StatusOK {
		t.Fatalf("checker write preset with allow_checker_write: status %d, want 200 (body %s)", status, body)
	}
	// ro mints as before.
	status, _ = postToken(t, authed, srv.URL, `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-sod","access":"ro"}`)
	if status != http.StatusOK {
		t.Fatalf("checker ro with allow_checker_write: status %d, want 200", status)
	}
	// Maker: the flag changes nothing (already allowed).
	maker := withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
	status, _ = postToken(t, maker, srv.URL, `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-7-sod","access":"rw"}`)
	if status != http.StatusOK {
		t.Fatalf("maker rw with allow_checker_write: status %d, want 200", status)
	}
	// Oracle mint refusal is INDEPENDENT of the flag: even with the flag on,
	// a checker (or maker) rw-oracle mint stays 422 — the data plane has no
	// hold point for it (defense in depth; do not relax).
	status, body = postToken(t, authed, srv.URL, `{"db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1521","db_type":"oracle","ticket_id":"T-7-sod","access":"rw"}`)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("checker rw oracle with allow_checker_write: status %d, want 422 (oracle refusal is flag-independent) (body %s)", status, body)
	}
	if !strings.Contains(body, "oracle") {
		t.Errorf("422 body = %s, want it to name oracle", body)
	}
}
