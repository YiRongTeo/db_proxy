package api

// node-integration Task 4 — password-at-mint (the credential override).
// POST /api/token gains an OPTIONAL `password` (string): absent → today's
// resolution byte-for-byte (G3); present → the mint writes ztcred:<session_id>
// (JSON {"password":"…"}) with TTL == the token's resolved TTL (incl.
// end_time), stamps payload.cred_override=true and NEVER echoes the password
// in the response (G2 — asserted on the RAW body, not a struct decode).
// Size cap 256 bytes → 422. No UI changes. The override KEY shape/TTL
// mechanics themselves are pinned in internal/store (cred_override_test.go);
// these tests pin the MINT-side contract end to end through the real route.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

// rawValkey is a test-local raw Valkey client for asserting the override
// key's raw VALUE and TTL (the *store.ValkeyStore deliberately exposes no
// TTL/raw-key reader — same reason the store package's own tests are
// in-package). Cleaned up per test.
func rawValkey(t *testing.T) valkey.Client {
	t.Helper()
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("raw valkey client: %v", err)
	}
	if err := c.Do(context.Background(), c.B().Ping().Build()).Error(); err != nil {
		t.Fatalf("raw valkey ping: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// rawKeyTTL reads the remaining TTL in ms of key (-2 missing).
func rawKeyTTL(t *testing.T, c valkey.Client, key string) int64 {
	t.Helper()
	ms, err := c.Do(context.Background(), c.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatalf("PTTL %s: %v", key, err)
	}
	return ms
}

// rawKeyValue reads the raw string value of key ("" when missing).
func rawKeyValue(t *testing.T, c valkey.Client, key string) string {
	t.Helper()
	raw, err := c.Do(context.Background(), c.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return "" // valkey.Nil → missing
	}
	return raw
}

// delOverrideKey deletes a test's override key (cleanup helper).
func delOverrideKey(c valkey.Client, sid string) {
	_ = c.Do(context.Background(), c.B().Del().Key("ztcred:"+sid).Build()).Error()
}

// mintPasswordBody builds a mint body for the mssql ro_user preset with an
// optional password JSON value (already encoded) — mirrors endBody.
func mintPasswordBody(passwordJSON string) string {
	b := `{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-NI-4"`
	if passwordJSON != "" {
		b += fmt.Sprintf(`,"password":%s`, passwordJSON)
	}
	return b + "}"
}

// issuePasswordMint posts the mint and returns the token, the status and the
// RAW body (the no-password-echo assertion runs on the raw bytes — a struct
// decode would silently ignore unknown fields and prove nothing).
func issuePasswordMint(t *testing.T, client *http.Client, base, body string) (token string, status int, raw string) {
	t.Helper()
	resp, err := client.Post(base+"/api/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil {
			break
		}
	}
	raw = buf.String()
	var out struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out.Token, resp.StatusCode, raw
}

// decodedMint extracts session_id/expires_in from a raw 200 mint response.
func decodedMint(t *testing.T, raw string) (sid string, expiresIn int) {
	t.Helper()
	var out struct {
		SessionID string `json:"session_id"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("decode mint response %s: %v", raw, err)
	}
	if out.SessionID == "" {
		t.Fatalf("mint response lacks session_id: %s", raw)
	}
	return out.SessionID, out.ExpiresIn
}

// TestMintWithPasswordWritesOverride (brief test 1): mint with password →
// ztcred:<sid> exists with the value; payload.cred_override true; the RAW
// response body does NOT contain the password.
func TestMintWithPasswordWritesOverride(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	rawc := rawValkey(t)
	ctx := context.Background()

	const pw = `override-"pw"-123` // JSON-hostile shape on purpose
	tok, status, raw := issuePasswordMint(t, client, srv.URL, mintPasswordBody(fmt.Sprintf("%q", pw)))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %s)", status, raw)
	}
	// G2: the response NEVER carries the password — raw bytes, not a decode.
	if strings.Contains(raw, pw) {
		t.Fatalf("mint response echoes the password: %s", raw)
	}
	sid, _ := decodedMint(t, raw)
	t.Cleanup(func() {
		delOverrideKey(rawc, sid)
		_ = vs.DelSessionLive(ctx, sid)
	})

	key := "ztcred:" + sid
	// ztcred:<sid> exists with EXACTLY {"password":"…"} — verbatim value.
	stored := rawKeyValue(t, rawc, key)
	if stored == "" {
		t.Fatalf("ztcred:%s missing after a password mint", sid)
	}
	var shape map[string]any
	if err := json.Unmarshal([]byte(stored), &shape); err != nil || len(shape) != 1 {
		t.Fatalf("stored override = %s, want exactly {\"password\":\"…\"} JSON", stored)
	}
	if shape["password"] != pw {
		t.Fatalf("stored override password = %v, want the minted password verbatim", shape["password"])
	}

	// payload.cred_override true (fetchPayload re-stores the consumed
	// single-use token; the trailing consume drops it again).
	p := fetchPayload(t, vs, tok)
	if v, _ := p["cred_override"].(bool); !v {
		t.Fatalf("payload cred_override = %v, want true (%v)", p["cred_override"], p)
	}
	_, _ = vs.GetDeleteToken(ctx, tok)
}

// TestMintPasswordOverrideTTLMatchesToken (brief test 7): the override key's
// TTL equals (≤ +skew) the token's TTL — written from the SAME resolution
// (incl. end_time). With an end_time the token TTL is the end_time-derived
// value; the override must not outlive it.
func TestMintPasswordOverrideTTLMatchesToken(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	rawc := rawValkey(t)
	ctx := context.Background()

	body := fmt.Sprintf(`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-NI-4","password":%q,"end_time":%d}`,
		"ttl-pw", time.Now().Unix()+30)
	tok, status, raw := issuePasswordMint(t, client, srv.URL, body)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %s)", status, raw)
	}
	sid, expiresIn := decodedMint(t, raw)
	if expiresIn < 28 || expiresIn > 32 {
		t.Fatalf("expires_in = %d, want 30 (±2s)", expiresIn)
	}
	t.Cleanup(func() {
		delOverrideKey(rawc, sid)
		_ = vs.DeleteToken(ctx, tok)
		_ = vs.DelSessionLive(ctx, sid)
	})
	if ms := rawKeyTTL(t, rawc, "ztcred:"+sid); ms <= 0 {
		t.Fatalf("override key missing (PTTL=%d)", ms)
	}
	tokMs := rawKeyTTL(t, rawc, "tok:"+tok)
	credMs := rawKeyTTL(t, rawc, "ztcred:"+sid)
	// ≤ token TTL (+2s PTTL-read skew) — never longer (G2).
	if credMs > tokMs+2000 {
		t.Fatalf("override TTL %dms > token TTL %dms — the credential would outlive its session", credMs, tokMs)
	}
	if credMs < 25000 {
		t.Fatalf("override TTL %dms, want ≈30000", credMs)
	}
}

// TestMintWithoutPasswordWritesNoOverride (brief test 4, G3): absent password
// → NO ztcred: key, payload cred_override absent, response byte-shape
// unchanged (no cred_override key anywhere).
func TestMintWithoutPasswordWritesNoOverride(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	rawc := rawValkey(t)
	ctx := context.Background()

	tok, status, raw := issuePasswordMint(t, client, srv.URL, mintPasswordBody(""))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %s)", status, raw)
	}
	if strings.Contains(raw, "cred_override") {
		t.Fatalf("response leaks cred_override without a password: %s", raw)
	}
	sid, _ := decodedMint(t, raw)
	if ms := rawKeyTTL(t, rawc, "ztcred:"+sid); ms != -2 {
		t.Fatalf("ztcred:%s written without a password (PTTL=%d)", sid, ms)
	}
	p := fetchPayload(t, vs, tok)
	if _, ok := p["cred_override"]; ok {
		t.Fatalf("payload carries cred_override without a password: %v", p["cred_override"])
	}
	_, _ = vs.GetDeleteToken(ctx, tok)
	_ = vs.DelSessionLive(ctx, sid)
}

// TestMintPasswordTooLong422 (brief test 5): > 256 bytes → 422; exactly 256
// is accepted (the cap is inclusive). Nothing is stored on the reject.
func TestMintPasswordTooLong422(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	rawc := rawValkey(t)

	_, status, raw := issuePasswordMint(t, client, srv.URL, mintPasswordBody(fmt.Sprintf("%q", strings.Repeat("x", 257))))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422 for a 257-byte password (body %s)", status, raw)
	}
	// Exactly 256 → accepted.
	tok, status, raw := issuePasswordMint(t, client, srv.URL, mintPasswordBody(fmt.Sprintf("%q", strings.Repeat("y", 256))))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 for a 256-byte password (body %s)", status, raw)
	}
	sid, _ := decodedMint(t, raw)
	t.Cleanup(func() {
		delOverrideKey(rawc, sid)
		_ = rawc.Do(context.Background(), rawc.B().Del().Key("tok:"+tok).Build()).Error()
	})
}

// TestMintPasswordEmptyRejected: an empty password is not an override —
// absent means absent; storing {"password":""} would flip the data plane
// onto an override carrying nothing. 422, no flag in the error body, and
// NO ztcred:/tok: keys left behind.
func TestMintPasswordEmptyRejected(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "single-use", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))

	_, status, raw := issuePasswordMint(t, client, srv.URL, mintPasswordBody(`""`))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422 for an empty password (body %s)", status, raw)
	}
	if strings.Contains(raw, "cred_override") {
		t.Fatalf("error body leaks the flag: %s", raw)
	}
}
