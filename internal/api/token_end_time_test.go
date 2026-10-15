package api

// node-integration Task 2 — end_time on POST /api/token: OPTIONAL expiry
// instant, RFC3339 UTC string OR integer epoch seconds. The mint resolves
// ttl = min(end_time − now, the existing TTL rules), stamps
// payload.expires_at and returns expires_at; end_time in the past is 422,
// beyond api.max_session_seconds is 422, garbage is 400. Absent end_time →
// byte-for-byte today's behavior (G3). The session-mode FORCE-CLOSE (the
// data plane closing a live session once the tok: key expires) is proven
// live in internal/proxy (zz_session_end_time_test.go) — this file pins the
// mint-side contract.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// endBody builds a mint body for the mssql ro_user preset with an end_time
// JSON value (already encoded: quoted string or integer) and an optional
// explicit mode.
func endBody(mode, endTimeJSON string) string {
	b := fmt.Sprintf(`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-NI-2","end_time":%s`, endTimeJSON)
	if mode != "" {
		b += fmt.Sprintf(`,"mode":%q`, mode)
	}
	return b + "}"
}

// issueEndTime posts the mint and returns the token, expires_in, expires_at,
// the status and the RAW body (for expires_at-absence checks).
func issueEndTime(t *testing.T, client *http.Client, base, body string) (token string, expiresIn int, expiresAt int64, status int, raw string) {
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
	raw = string(b)
	var out struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
		ExpiresAt int64  `json:"expires_at"`
		Error     string `json:"error"`
	}
	_ = json.Unmarshal(b, &out)
	return out.Token, out.ExpiresIn, out.ExpiresAt, resp.StatusCode, raw
}

// TestTokenEndTimeRFC3339 (brief test 1): an RFC3339 end_time yields
// expires_in == endTime−now (±2s), expires_at == epoch(endTime) (±2s), and
// the stored payload carries the same expires_at.
func TestTokenEndTimeRFC3339(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	end := time.Now().UTC().Add(30 * time.Second).Truncate(time.Second)

	token, expiresIn, expiresAt, status, _ := issueEndTime(t, client, srv.URL,
		endBody("", fmt.Sprintf("%q", end.Format(time.RFC3339))))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if expiresIn < 28 || expiresIn > 32 {
		t.Errorf("expires_in = %d, want 30 (±2s)", expiresIn)
	}
	if expiresAt < end.Unix()-2 || expiresAt > end.Unix()+2 {
		t.Errorf("expires_at = %d, want %d (±2s)", expiresAt, end.Unix())
	}
	p := fetchPayload(t, vs, token)
	if got, _ := p["expires_at"].(float64); int64(got) != end.Unix() {
		t.Errorf("payload expires_at = %v, want %d", p["expires_at"], end.Unix())
	}
}

// TestTokenEndTimeEpochSeconds (brief test 2): integer epoch seconds is the
// same contract.
func TestTokenEndTimeEpochSeconds(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	end := time.Now().Unix() + 30

	_, expiresIn, expiresAt, status, _ := issueEndTime(t, client, srv.URL,
		endBody("", fmt.Sprintf("%d", end)))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if expiresIn < 28 || expiresIn > 32 {
		t.Errorf("expires_in = %d, want 30 (±2s)", expiresIn)
	}
	if expiresAt < end-2 || expiresAt > end+2 {
		t.Errorf("expires_at = %d, want %d (±2s)", expiresAt, end)
	}
}

// TestTokenEndTimePast (brief test 3): end_time ≤ now → 422 "end_time is in
// the past" — both accepted shapes.
func TestTokenEndTimePast(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))

	pastRFC := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	for _, tc := range []struct {
		name string
		val  string
	}{
		{"rfc3339", fmt.Sprintf("%q", pastRFC.Format(time.RFC3339))},
		{"epoch", fmt.Sprintf("%d", time.Now().Unix()-10)},
		// The zero instant parses as valid RFC3339 but is infinitely in
		// the past — the 422 past-error is the right answer (an explicit
		// hasEndTime flag keeps it out of the absent-end_time path).
		{"zero rfc3339", `"0001-01-01T00:00:00Z"`},
	} {
		_, _, _, status, raw := issueEndTime(t, client, srv.URL, endBody("", tc.val))
		if status != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422 (body %s)", tc.name, status, raw)
		}
		if !strings.Contains(raw, "end_time is in the past") {
			t.Errorf("%s: body %q lacks the past-end_time error", tc.name, raw)
		}
	}
}

// TestTokenEndTimeBeyondMaxSession (brief test 4): api.max_session_seconds
// > 0 caps end_time − now; exceeding it → 422 "end_time exceeds max session
// duration". At the ceiling (inclusive) the mint succeeds; 0 = uncapped.
func TestTokenEndTimeBeyondMaxSession(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	cfg.MaxSessionSeconds = 120 // same *ControlConfig the api holds
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))

	_, _, _, status, raw := issueEndTime(t, client, srv.URL,
		endBody("", fmt.Sprintf("%d", time.Now().Unix()+300)))
	if status != http.StatusUnprocessableEntity {
		t.Errorf("status %d, want 422 for end_time beyond the ceiling (body %s)", status, raw)
	}
	if !strings.Contains(raw, "end_time exceeds max session duration") {
		t.Errorf("body %q lacks the ceiling error", raw)
	}

	// Exactly at the ceiling is NOT "exceeding" — mint succeeds.
	_, _, _, status, _ = issueEndTime(t, client, srv.URL,
		endBody("", fmt.Sprintf("%d", time.Now().Unix()+120)))
	if status != http.StatusOK {
		t.Errorf("status %d, want 200 for end_time at the ceiling", status)
	}
}

// TestTokenEndTimeShorterThanTTL (brief test 5): end_time shorter than the
// configured token TTL wins — expires_in is the SHORTER value, not the 60s
// fixture default.
func TestTokenEndTimeShorterThanTTL(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))

	_, expiresIn, _, status, _ := issueEndTime(t, client, srv.URL,
		endBody("", fmt.Sprintf("%d", time.Now().Unix()+10)))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if expiresIn < 8 || expiresIn > 12 {
		t.Errorf("expires_in = %d, want the end_time-derived 10 (±2s), not the 60s default", expiresIn)
	}
}

// TestTokenEndTimeSessionModeInfiniteTTL: a session token whose configured
// TTL is INFINITE (0 → expires_in −1) becomes finite when the mint carries
// end_time — the end_time-derived TTL governs, and the payload keeps the
// session stamps (mode/ip/issued_at) plus expires_at. The live force-close
// of such a token's session is asserted in internal/proxy.
func TestTokenEndTimeSessionModeInfiniteTTL(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	end := time.Now().Unix() + 30

	token, expiresIn, expiresAt, status, _ := issueEndTime(t, client, srv.URL,
		endBody("session", fmt.Sprintf("%d", end)))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if expiresIn == -1 || expiresIn < 28 || expiresIn > 32 {
		t.Errorf("expires_in = %d, want the end_time-derived 30 (±2s), not −1", expiresIn)
	}
	if expiresAt < end-2 || expiresAt > end+2 {
		t.Errorf("expires_at = %d, want %d (±2s)", expiresAt, end)
	}
	p := fetchPayload(t, vs, token)
	if p["mode"] != "session" || p["ip"] != "127.0.0.1" {
		t.Errorf("payload session stamps = mode %v ip %v, want session/127.0.0.1", p["mode"], p["ip"])
	}
	if _, ok := p["issued_at"]; !ok {
		t.Error("payload lacks issued_at")
	}
	if _, ok := p["expires_at"]; !ok {
		t.Error("payload lacks expires_at")
	}
}

// TestTokenEndTimeAbsentUnchanged (brief test 7, G3): NO end_time → exactly
// today's behavior — single-use expires_in = the configured TTL, session
// infinite = −1, and NEITHER the response NOR the payload carries
// expires_at. JSON null end_time counts as absent. Malformed end_time
// values are 400 "invalid end_time" (brief: parse failure).
func TestTokenEndTimeAbsentUnchanged(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))

	// Single-use, absent: expires_in == the 60s fixture TTL, no expires_at.
	_, expiresIn, _, status, raw := issueEndTime(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-NI-2"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if expiresIn != 60 {
		t.Errorf("expires_in = %d, want 60 (unchanged default TTL)", expiresIn)
	}
	if strings.Contains(raw, "expires_at") {
		t.Errorf("response leaks expires_at on an absent end_time: %s", raw)
	}

	// Session mode, absent: still infinite (−1).
	_, expiresIn, _, status, _ = issueEndTime(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-NI-2","mode":"session"}`)
	if status != http.StatusOK {
		t.Fatalf("session status %d, want 200", status)
	}
	if expiresIn != -1 {
		t.Errorf("session expires_in = %d, want −1 (infinite, unchanged)", expiresIn)
	}

	// JSON null → treated as absent.
	_, expiresIn, _, status, _ = issueEndTime(t, client, srv.URL, endBody("", `null`))
	if status != http.StatusOK {
		t.Fatalf("null end_time status %d, want 200", status)
	}
	if expiresIn != 60 {
		t.Errorf("null end_time expires_in = %d, want 60", expiresIn)
	}

	// Payload of an absent-end_time mint carries no expires_at.
	suTok, _, _, st, _ := issueEndTime(t, client, srv.URL,
		`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-NI-2"}`)
	if st != http.StatusOK {
		t.Fatalf("status %d, want 200", st)
	}
	if p := fetchPayload(t, vs, suTok); func() bool { _, ok := p["expires_at"]; return ok }() {
		t.Errorf("payload carries expires_at without end_time: %v", p["expires_at"])
	}

	// Malformed shapes → 400 "invalid end_time".
	for _, tc := range []struct {
		name string
		val  string
	}{
		{"garbage string", `"next tuesday"`},
		{"empty string", `""`},
		{"bad rfc3339", `"2026-13-45T99:00:00Z"`},
		{"float", `1.5`},
		{"bool", `true`},
		{"object", `{"epoch":123}`},
		{"overflow int", `99999999999999999999`},
	} {
		_, _, _, status, raw := issueEndTime(t, client, srv.URL, endBody("", tc.val))
		if status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", tc.name, status, raw)
		}
		if !strings.Contains(raw, "invalid end_time") {
			t.Errorf("%s: body %q lacks the invalid-end_time error", tc.name, raw)
		}
	}
}

// TestTokenEndTimeAcceptsUTCTOffsets: RFC3339 with a numeric UTC offset
// (e.g. "+02:00") denotes the same instant as its Z-spelling and is
// ACCEPTED — the mint resolves identically for both spellings.
func TestTokenEndTimeAcceptsUTCOffsets(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	want := time.Now().UTC().Add(30 * time.Second).Truncate(time.Second)

	_, expiresIn, _, status, raw := issueEndTime(t, client, srv.URL,
		endBody("", fmt.Sprintf("%q", want.In(time.FixedZone("UTC+2", 2*3600)).Format(time.RFC3339))))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %s)", status, raw)
	}
	if expiresIn < 28 || expiresIn > 32 {
		t.Errorf("expires_in = %d, want 30 (±2s) for the offset spelling", expiresIn)
	}
}

// TestTokenEndTimePayloadExpiryMatchesTTL sanity: the stored single-use
// token's key TTL is the end_time-derived value — assertable indirectly via
// the payload's expires_at + response expires_in coherence (already pinned
// above); this test keeps a direct model-level anchor on the wire shapes.
func TestTokenEndTimeResponseShape(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	end := time.Now().Unix() + 30

	_, _, _, status, raw := issueEndTime(t, client, srv.URL, endBody("", fmt.Sprintf("%d", end)))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &shape); err != nil {
		t.Fatalf("decode response %s: %v", raw, err)
	}
	for _, key := range []string{"token", "session_id", "host", "port", "expires_in", "expires_at"} {
		if _, ok := shape[key]; !ok {
			t.Errorf("response lacks %q: %s", key, raw)
		}
	}
}
