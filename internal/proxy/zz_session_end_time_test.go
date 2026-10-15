package proxy

// node-integration Task 2 — end_time force-close. handleToken stores a mint
// with end_time as a session-mode tok: key whose TTL IS the end_time
// deadline (payload.expires_at is informational). This test proves the
// expiry half of the contract live: when the key lapses (server-side TTL
// expiry — no explicit delete), RunSessionSweeper force-closes the running
// session via the EXISTING revoke path. Same zz_ convention as the other
// live-session tests: run last in the proxy binary (sess:live records).

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// TestLiveSessionEndsAtTokenExpiry: hold a live session on a session-mode
// token stored with a 2s key TTL + payload ExpiresAt — the exact shape
// handleToken mints for end_time ≈ now+2s. Once the key expires on its own,
// the sweeper must close the session.
func TestLiveSessionEndsAtTokenExpiry(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-endtime-%d", time.Now().UnixNano())
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: username, DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "1434", DBType: "mssql", TicketID: "T-NI-2",
		SessionID: "sid-" + token[len("sess_"):],
		Mode:      "session", IP: "127.0.0.1", IssuedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(2 * time.Second).Unix()}
	if err := vs.SetToken(context.Background(), token, tok, 2*time.Second); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), tok.SessionID) })

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyLoopP(t, vs, &logBuf, nil)
	c := holdToken(t, token, ln)

	sweepCtx, sweepCancel := context.WithCancel(context.Background())
	defer sweepCancel()
	go RunSessionSweeper(sweepCtx, slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionPolicy{Poll: 300 * time.Millisecond}, p)

	// Simulated expiry: wait for the server-side TTL to lapse (no explicit
	// delete — the key dying by itself IS the endTime moment).
	deadline := time.Now().Add(5 * time.Second)
	for {
		alive, err := vs.TokenAlive(context.Background(), token)
		if err == nil && !alive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tok key did not expire within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	assertSessionClosesSoon(t, "end_time expiry", c.conn)
}
