// node-integration client-compat — POST /api/token contract fixes for the
// node main-app client (Ryan). Three live-verified failures:
//
//  1. JSON db_port: 3306 (NUMBER) → opaque 400 "bad request": the request
//     struct declared db_port string and DisallowUnknownFields' decode died
//     on a number-into-string with no field named. The client sends numbers.
//  2. JSON key endTime (camelCase, the client's contract spelling) →
//     unknown-field 400: the server only accepted end_time.
//  3. Decode failures surfaced the OPAQUE {"error":"bad request"} with no
//     indication of the offending field.
//
// Contract after the fix:
//   - db_port accepts a JSON integer OR numeric string, both normalized to
//     the canonical decimal string ("3306" == 3306); a fractional number or
//     non-numeric garbage → 400 naming db_port. Absent/null → the existing
//     dbPortDefaults resolution (unchanged).
//   - endTime is an exact alias of end_time (both accepted; BOTH set with
//     non-null, textually different values → 400 naming the conflict; null
//     counts as absent). No other field gains a camelCase alias.
//   - decodeJSON failures → 400 "bad request: <first json decode error>"
//     (the stdlib error names the field/type — no secrets in it).
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// compatIssue posts a RAW mint body (exact client bytes, no re-encoding)
// and returns status + body. It bypasses the endBody helper so the payload
// shape — a JSON number for db_port, camelCase endTime — is pinned
// verbatim.
func compatIssue(t *testing.T, client *http.Client, base, body string) (int, string) {
	t.Helper()
	resp, err := client.Post(base+"/api/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// TestTokenCompatClientExactPayload pins Ryan's EXACT live-verified
// payload: db_port as a JSON number, endTime in camelCase. Before the fix
// it 400'd opaquely ("bad request") on both counts; after, it mints 200
// with expires_at derived from the endTime and db_port stored as "3306"
// (the mint succeeds only if the preset resolves, which requires the port
// to have survived the decode as a string).
func TestTokenCompatClientExactPayload(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))

	status, raw := compatIssue(t, client, srv.URL,
		`{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":3306,"db_type":"mysql","ticket_id":"T-COMPAT-1","endTime":"2026-10-21 23:59:00"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %s)", status, raw)
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("decode response %s: %v", raw, err)
	}
	if out.ExpiresAt == 0 {
		t.Errorf("response lacks expires_at: %s", raw)
	}
	want := time.Date(2026, 10, 21, 23, 59, 0, 0, time.Local)
	if want.Before(time.Now()) {
		t.Skipf("client literal endTime %s already in the past", want)
	}
	if out.ExpiresAt != want.Unix() {
		t.Errorf("expires_at = %d, want exactly %d (gateway-local naive parse)", out.ExpiresAt, want.Unix())
	}
	// The port survived the decode: the mint resolved (200 above) against
	// the mysql/default preset, which needs an explicit db_port of "3306"
	// — the stored payload carries it verbatim.
	p := fetchPayload(t, vs, out.Token)
	if p["db_port"] != "3306" {
		t.Errorf("payload db_port = %v, want the string \"3306\"", p["db_port"])
	}
}

// TestTokenCompatDBPortNumberEqualsString: number vs string db_port are
// equivalent — same response TTL, same stored port — and a fractional
// number (3306.5) or non-numeric garbage is a 400 that NAMES the field.
func TestTokenCompatDBPortNumberEqualsString(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))

	mint := func(portJSON string) (int, string) {
		return compatIssue(t, client, srv.URL, fmt.Sprintf(
			`{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":%s,"db_type":"mysql","ticket_id":"T-COMPAT-PORT"}`, portJSON))
	}

	// Number, string, and whitespace-padded string all normalize to the
	// same canonical "3306".
	for _, tc := range []struct {
		name     string
		portJSON string
		wantPort string
	}{
		{"number", "3306", "3306"},
		{"string", `"3306"`, "3306"},
		{"padded string", `" 3306 "`, "3306"},
	} {
		status, raw := mint(tc.portJSON)
		if status != http.StatusOK {
			t.Fatalf("%s: status %d, want 200 (body %s)", tc.name, status, raw)
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatalf("%s: decode response %s: %v", tc.name, raw, err)
		}
		if p := fetchPayload(t, vs, out.Token); p["db_port"] != tc.wantPort {
			t.Errorf("%s: payload db_port = %v, want %q", tc.name, p["db_port"], tc.wantPort)
		}
	}

	// Fractional or non-numeric → 400 NAMING db_port.
	for _, tc := range []struct {
		name     string
		portJSON string
	}{
		{"float", "3306.5"},
		{"garbage string", `"db"`},
		{"empty string", `""`},
		{"bool", "true"},
	} {
		status, raw := mint(tc.portJSON)
		if status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", tc.name, status, raw)
		}
		if !strings.Contains(raw, "db_port") {
			t.Errorf("%s: body %q does not name db_port", tc.name, raw)
		}
	}
}

// TestTokenCompatEndTimeAlias: endTime alone works, end_time alone still
// works, both with IDENTICAL values → 200, both with DIFFERENT values →
// 400 naming the conflict, null on either side counts as absent.
func TestTokenCompatEndTimeAlias(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	end := time.Now().Unix() + 30

	mint := func(body string) (int, string) {
		return compatIssue(t, client, srv.URL, body)
	}
	head := `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":3306,"db_type":"mysql","ticket_id":"T-COMPAT-E"`

	// endTime alone → 200 with expires_at (same semantics as end_time).
	status, raw := mint(fmt.Sprintf(`%s,"endTime":%d}`, head, end))
	if status != http.StatusOK {
		t.Fatalf("endTime alone: status %d, want 200 (body %s)", status, raw)
	}
	var out struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	_ = json.Unmarshal([]byte(raw), &out)
	if out.ExpiresAt < end-2 || out.ExpiresAt > end+2 {
		t.Errorf("endTime alone: expires_at = %d, want %d (±2s)", out.ExpiresAt, end)
	}

	// Both keys, IDENTICAL values → fine.
	status, raw = mint(fmt.Sprintf(`%s,"end_time":%d,"endTime":%d}`, head, end, end))
	if status != http.StatusOK {
		t.Errorf("both identical: status %d, want 200 (body %s)", status, raw)
	}

	// Both keys, DIFFERENT values → 400 naming the conflict.
	status, raw = mint(fmt.Sprintf(`%s,"end_time":%d,"endTime":%d}`, head, end, end+10))
	if status != http.StatusBadRequest {
		t.Errorf("both different: status %d, want 400 (body %s)", status, raw)
	}
	for _, want := range []string{"end_time", "endTime"} {
		if !strings.Contains(raw, want) {
			t.Errorf("both different: body %q lacks %q", raw, want)
		}
	}

	// Null counts as absent: end_time + null endTime (and the reverse) →
	// 200, expiring at the present key.
	for _, tc := range []struct {
		name string
		tail string
	}{
		{"end_time + null endTime", fmt.Sprintf(`%s,"end_time":%d,"endTime":null}`, head, end)},
		{"null end_time + endTime", fmt.Sprintf(`%s,"end_time":null,"endTime":%d}`, head, end)},
	} {
		status, raw = mint(tc.tail + "}")
		if status != http.StatusOK {
			t.Errorf("%s: status %d, want 200 (body %s)", tc.name, status, raw)
		}
	}

	// endTime garbage still reports invalid end_time (alias, same error).
	status, raw = mint(head + `,"endTime":"next tuesday"}`)
	if status != http.StatusBadRequest || !strings.Contains(raw, "invalid end_time") {
		t.Errorf("endTime garbage: status %d body %s, want 400 invalid end_time", status, raw)
	}
}

// TestTokenCompatDecodeErrorsNameField: a decode failure returns 400 with
// the stdlib decode error passed through — it names the offending
// field/type instead of the opaque "bad request". Pins the exact client
// payloads that failed live (number db_port against a string field; an
// unknown field), plus the 1 MB cap.
func TestTokenCompatDecodeErrorsNameField(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))

	for _, tc := range []struct {
		name    string
		body    string
		wantSub []string
	}{
		{
			// A number into a string-typed field (db_type is still a
			// plain string): the stdlib error names field + types.
			// (The client's original db_port-number case now decodes
			// fine — pinned by TestTokenCompatClientExactPayload.)
			name:    "number into string field names the field",
			body:    `{"db_user":"ro_user","db_ip":"127.0.0.1","db_type":1,"ticket_id":"T"}`,
			wantSub: []string{"bad request:", "db_type"},
		},
		{
			name:    "unknown field named",
			body:    `{"db_user":"ro_user","db_ip":"127.0.0.1","db_type":"mysql","ticket_id":"T","bogus_field":1}`,
			wantSub: []string{"bad request:", "bogus_field"},
		},
		{
			name:    "not json at all",
			body:    `{`,
			wantSub: []string{"bad request:"},
		},
	} {
		status, raw := compatIssue(t, client, srv.URL, tc.body)
		if status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", tc.name, status, raw)
		}
		for _, sub := range tc.wantSub {
			if !strings.Contains(raw, sub) {
				t.Errorf("%s: body %q lacks %q", tc.name, raw, sub)
			}
		}
	}

	// The 1 MB cap still trips a 400 (MaxBytesError), now with the
	// field-naming prefix format.
	status, raw := compatIssue(t, client, srv.URL,
		`{"db_user":"`+strings.Repeat("a", maxBodyBytes+16)+`"}`)
	if status != http.StatusBadRequest {
		t.Errorf("oversized body: status %d, want 400 (body %s)", status, raw)
	}
	if !strings.Contains(raw, "bad request:") {
		t.Errorf("oversized body: body %q lacks the bad-request prefix", raw)
	}
}
