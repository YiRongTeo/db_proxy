package store

// node-integration Task 4 — the at-mint credential override (ztcred:<sid>):
// POST /api/token with `password` writes the override key with a TTL equal
// to the token's own TTL (same resolution, never longer); the data plane
// consults it FIRST (plain GET — session-mode reconnects may re-read; the
// key dies by TTL, not GETDEL) and falls back on miss. The value is JSON
// {"password":"…"}. HARD RULE (G2): the password never reaches a log line,
// an error string, or any response — the primitives here return fixed
// error strings precisely so a malformed/failed read can never embed the
// stored value.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
)

// uniqueCredKey builds a fresh sid for a per-test ztcred:<sid> key
// (parallel-run safety, same discipline as uniqueToken). The value is a
// full sid-<hex> session id exactly as the mint writes it.
func uniqueCredKey(t *testing.T) string {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	return "sid-" + id
}

// TestCredOverrideRoundTrip: SetCredOverride stores {"password":"…"} under
// ztcred:<sid>; GetCredOverride reads the SAME value back (plain GET — the
// key survives the read; session-mode reconnects depend on that).
func TestCredOverrideRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueCredKey(t)
	cleanupKey(t, s, "ztcred:"+sid)

	if err := s.SetCredOverride(ctx, sid, "override-pw-值", time.Minute); err != nil {
		t.Fatalf("SetCredOverride: %v", err)
	}
	pw, err := s.GetCredOverride(ctx, sid)
	if err != nil {
		t.Fatalf("GetCredOverride: %v", err)
	}
	if pw != "override-pw-值" {
		t.Fatalf("GetCredOverride = %q, want %q (verbatim, untrimmed)", pw, "override-pw-值")
	}
	// GET, not GETDEL: a second read must see the same value.
	pw2, err := s.GetCredOverride(ctx, sid)
	if err != nil || pw2 != pw {
		t.Fatalf("second GetCredOverride = %q, %v — the override must survive re-reads", pw2, err)
	}
}

// TestCredOverrideRawShape pins the stored VALUE shape: exactly
// {"password":"…"} — no extra fields (the contract the data plane decodes).
func TestCredOverrideRawShape(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueCredKey(t)
	key := "ztcred:" + sid
	cleanupKey(t, s, key)

	if err := s.SetCredOverride(ctx, sid, "pw-shape", time.Minute); err != nil {
		t.Fatalf("SetCredOverride: %v", err)
	}
	raw, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		t.Fatalf("raw GET %s: %v", key, err)
	}
	var shape map[string]any
	if err := json.Unmarshal([]byte(raw), &shape); err != nil {
		t.Fatalf("stored value is not JSON: %v (%s)", err, raw)
	}
	if len(shape) != 1 {
		t.Fatalf("stored value has %d fields, want exactly 1: %s", len(shape), raw)
	}
	if shape["password"] != "pw-shape" {
		t.Fatalf("stored value = %s, want {\"password\":\"pw-shape\"}", raw)
	}
}

// TestCredOverrideTTLOnKey: the written key carries a TTL within 2s of the
// requested one — the mint passes its token's resolved TTL, and this is the
// "never longer" half of the G2 rule.
func TestCredOverrideTTLOnKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueCredKey(t)
	key := "ztcred:" + sid
	cleanupKey(t, s, key)

	if err := s.SetCredOverride(ctx, sid, "pw", 30*time.Second); err != nil {
		t.Fatalf("SetCredOverride: %v", err)
	}
	ms, err := s.client.Do(ctx, s.client.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatalf("PTTL: %v", err)
	}
	if ms <= 0 {
		t.Fatalf("PTTL(%s) = %d — the override key must be TTL-bounded", key, ms)
	}
	got := time.Duration(ms) * time.Millisecond
	if got > 32*time.Second {
		t.Fatalf("override TTL = %v, want ≤ 30s (+2s skew) — never longer than the token TTL", got)
	}
	if got < 25*time.Second {
		t.Fatalf("override TTL = %v, want ≈30s (got suspiciously little)", got)
	}
}

// TestCredOverrideExpiry: after the TTL lapses the override is gone —
// GetCredOverride reports a miss (no value, no error) and the data plane's
// chain falls back. This is the "bounded by TTL" half of the design.
func TestCredOverrideExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueCredKey(t)
	key := "ztcred:" + sid
	cleanupKey(t, s, key)

	if err := s.SetCredOverride(ctx, sid, "pw", time.Second); err != nil {
		t.Fatalf("SetCredOverride: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		exists, _ := s.client.Do(ctx, s.client.B().Exists().Key(key).Build()).AsInt64()
		if exists == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("override key did not expire within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	pw, err := s.GetCredOverride(ctx, sid)
	if err != nil || pw != "" {
		t.Fatalf("GetCredOverride after expiry = %q, %v, want \"\"/nil (miss)", pw, err)
	}
}

// TestCredOverrideMissingKey: an absent key is a MISS (empty value, nil
// error) — the same contract as GetSessionLive, not an error.
func TestCredOverrideMissingKey(t *testing.T) {
	s := newTestStore(t)
	pw, err := s.GetCredOverride(context.Background(), "ztcred-nonexistent-sid")
	if err != nil {
		t.Fatalf("GetCredOverride(missing): %v, want nil error", err)
	}
	if pw != "" {
		t.Fatalf("GetCredOverride(missing) = %q, want \"\"", pw)
	}
}

// TestCredOverrideSetValidation: caller bugs are refused — an empty session
// id, an empty password (a mint never stores an empty override: absent means
// absent), and a non-positive TTL (an eternal credential must never be
// written — G2).
func TestCredOverrideSetValidation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.SetCredOverride(ctx, "", "pw", time.Minute); err == nil {
		t.Error("empty sid accepted")
	}
	if err := s.SetCredOverride(ctx, "sid-x", "", time.Minute); err == nil {
		t.Error("empty password accepted")
	}
	if err := s.SetCredOverride(ctx, "sid-x", "pw", 0); err == nil {
		t.Error("zero TTL accepted — an override must never outlive its token")
	}
	if err := s.SetCredOverride(ctx, "sid-x", "pw", -time.Second); err == nil {
		t.Error("negative TTL accepted")
	}
	// And nothing was written.
	n, err := s.client.Do(ctx, s.client.B().Exists().Key("ztcred:sid-x").Build()).AsInt64()
	if err != nil || n != 0 {
		t.Fatalf("ztcred:sid-x exists after refused writes: n=%d err=%v", n, err)
	}
}

// TestCredOverrideMalformedValueIsFixedError: a hand-corrupted value must
// surface as a FIXED error string — never one that embeds the stored bytes
// (a json decode error would happily quote the value fragment into the
// message, and the message would reach a WARN log line).
func TestCredOverrideMalformedValueIsFixedError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sid := uniqueCredKey(t)
	key := "ztcred:" + sid
	cleanupKey(t, s, key)
	secret := "super-secret-value-fragment"
	if err := s.client.Do(ctx, s.client.B().Set().Key(key).Value("not json "+secret).Build()).Error(); err != nil {
		t.Fatalf("plant corrupt value: %v", err)
	}
	_, err := s.GetCredOverride(ctx, sid)
	if err == nil {
		t.Fatal("corrupt value read: expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error string embeds the stored value: %q — value leakage", err.Error())
	}
}

// TestCredOverrideSurvivesValkeyNilSemantics: GetCredOverride maps valkey.Nil
// (absent key) to a clean miss — belt-and-braces that the errors.Is(valkey.Nil)
// path is the one taken (a plain err != nil mapping would log fallback WARNs
// for every merely-expired override).
func TestCredOverrideSurvivesValkeyNilSemantics(t *testing.T) {
	s := newTestStore(t)
	pw, gerr := s.GetCredOverride(context.Background(), "never-written")
	if gerr != nil || pw != "" {
		t.Fatalf("miss contract broken: pw=%q err=%v", pw, gerr)
	}
	_ = valkey.Nil            // referenced: the Nil mapping is the miss contract
	_ = models.TokenPayload{} // referenced: the payload flag lives in models
}
