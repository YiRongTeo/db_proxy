package api

// Final-review fix wave — the blocker: a session-mode mint carrying a
// password with api.session_token_ttl_seconds=0 (the committed default,
// configs/control.yaml:18) and no end_time resolves ttl=0, and
// SetCredOverride hard-refuses a non-positive TTL — so the mint 500s AFTER
// a tok: write + delete round-trip. The contract: an eternal password
// override is exactly what G2 forbids, so the request is a client error —
// 422, BEFORE any write. These tests pin the reject (no tok:/ztcred: keys)
// and the sanctioned escape hatch (end_time bounds the token, the override
// rides the same finite TTL — the existing happy path, byte-unchanged).

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

// TestMintPasswordSessionInfiniteTTL422: session mode + password +
// session_token_ttl_seconds=0 + no end_time → 422 with the exact message;
// NO tok: key and NO ztcred: key may exist — the guard fires before the
// first write, not after a write+delete round-trip.
func TestMintPasswordSessionInfiniteTTL422(t *testing.T) {
	srv, client, _, cfg := newModeTestAPIServer(t, "session", 0)
	if cfg.SessionTokenTTL != 0 {
		t.Fatalf("test wiring drift: SessionTokenTTL = %d, want 0 (the committed default)", cfg.SessionTokenTTL)
	}
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	rawc := rawValkey(t)

	tok, status, raw := issuePasswordMint(t, client, srv.URL, mintPasswordBody(fmt.Sprintf("%q", "eternal-pw")))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422 (body %s)", status, raw)
	}
	const wantMsg = "password requires a finite token ttl — supply end_time or set api.session_token_ttl_seconds"
	if !strings.Contains(raw, wantMsg) {
		t.Fatalf("body %q lacks the required message %q", raw, wantMsg)
	}
	if tok != "" {
		t.Fatalf("422 response unexpectedly carries a token: %s", tok)
	}

	// NO keys written — the guard fires BEFORE the first write, not after
	// a write+delete round-trip. The mint's session id lives only inside
	// the payload that was never stored, so the proof is keyspace-level:
	// snapshot the db, mint again (same reject), snapshot again — the
	// delta must be empty. (Other tests' keys are stable across the
	// window; tests in a package binary share the db but never run
	// concurrently without t.Parallel, which none of these use.)
	before := scanKeys(t, rawc)
	_, _, _ = issuePasswordMint(t, client, srv.URL, mintPasswordBody(fmt.Sprintf("%q", "eternal-pw-2")))
	after := scanKeys(t, rawc)
	if strays := keyDelta(before, after); len(strays) > 0 {
		t.Fatalf("422 mint wrote keys: %v (pre-write guard violated)", strays)
	}
}

// scanKeys returns every key in the database (SCAN, not KEYS).
func scanKeys(t *testing.T, c valkey.Client) []string {
	t.Helper()
	seen := map[string]bool{}
	var keys []string
	var cursor uint64
	for {
		entry, err := c.Do(context.Background(),
			c.B().Scan().Cursor(cursor).Count(1000).Build()).AsScanEntry()
		if err != nil {
			t.Fatalf("SCAN: %v", err)
		}
		for _, k := range entry.Elements {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
		cursor = entry.Cursor
		if cursor == 0 {
			break
		}
	}
	return keys
}

// keyDelta = after − before (set difference, order-insensitive).
func keyDelta(before, after []string) []string {
	b := make(map[string]bool, len(before))
	for _, k := range before {
		b[k] = true
	}
	var out []string
	for _, k := range after {
		if !b[k] {
			out = append(out, k)
		}
	}
	return out
}

// TestMintPasswordSessionWithEndTimeOK: the SAME request WITH end_time →
// 200; ztcred:<sid> written with a finite TTL bounded by the end_time
// (the existing happy path, unchanged by the guard).
func TestMintPasswordSessionWithEndTimeOK(t *testing.T) {
	srv, client, vs, cfg := newModeTestAPIServer(t, "session", 0)
	client = withBearer(client, mintJWT(t, cfg, "alice", "maker"))
	rawc := rawValkey(t)
	ctx := context.Background()

	end := time.Now().Unix() + 30
	body := fmt.Sprintf(`{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"T-NI-4","password":%q,"end_time":%d}`,
		"bounded-pw", end)
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

	// The override key exists with a finite TTL ≈ the end_time horizon.
	ms := rawKeyTTL(t, rawc, "ztcred:"+sid)
	if ms <= 0 {
		t.Fatalf("ztcred:%s missing (PTTL=%d) — end_time mint must still write the override", sid, ms)
	}
	if ms > 32000 || ms < 25000 {
		t.Fatalf("override PTTL = %dms, want ≈30000 (bounded by end_time)", ms)
	}
	// The token key itself is finite too (never −1/−2): the end_time made
	// the session token finite.
	tokMs := rawKeyTTL(t, rawc, "tok:"+tok)
	if tokMs <= 0 {
		t.Fatalf("tok:%s PTTL = %d, want finite >0 (end_time bounds the session token)", tok, tokMs)
	}
}
