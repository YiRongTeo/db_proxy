package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Alignment review I-3.3: flag-off live admission, mssql ------------------
//
// The review found TestMySQLRWFlagOffAdmitsWithoutWatch (zz_live_sod_flags_
// test.go) mirrored on NO other plane: "flag-off = byte-identical legacy
// path" (G3) was live-verified on one of three planes. This is the mssql
// mirror: rw + SetRWRequireCheckerWatch(false) → the rw token admits
// IMMEDIATELY on the normal connect path (no hold, no WatchActive polling)
// and a real backend round-trip completes with NO watch lease ever armed —
// asserted at the end as belt-and-braces. (Flag ON this sequence would sit
// silent — no login response at all — until the read deadline: the login-
// phase hold sends NOTHING before admission.)
//
// The pg mirror (TestPGRWFlagOffAdmitsWithoutWatch) lives in
// zz_live_pg_relock_test.go, which carries that plane's rw-hold helpers.

// TestMSSQLRWFlagOffAdmitsWithoutWatch: the mssql mirror — the rw LOGIN7
// completes INSTANTLY (no login-phase hold: the hold sends NOTHING before
// admission), a real batch round-trips, no lease ever armed.
func TestMSSQLRWFlagOffAdmitsWithoutWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	var logBuf bytes.Buffer
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	p := NewMSSQLProxy(logger, vs, &ConfigCredResolver{
		Creds: map[string]string{"mssql:rw_user@127.0.0.1:1434": "rw_pw"},
	}, nil)
	p.SetRWRequireCheckerWatch(false) // THE flag under test
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()

	sid := fmt.Sprintf("sid-ms-rw-flagoff-%d", time.Now().UnixNano())
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, token, models.TokenPayload{
		Username: "ms-rw-flagoff", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "1434",
		DBType: "mssql", TicketID: "T-I3-FLAGOFF", Access: "rw", SessionID: sid,
	}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), sid) })
	// NO SetWatchConn — no watch lease is ever armed.

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x, want ENCRYPT_NOT_SUP", enc)
	}
	start := time.Now()
	if _, done, ok := c.login(token, "appdb"); !done || !ok {
		t.Fatalf("flag-off rw mssql: login failed (done=%v ok=%v)", done, ok)
	}
	// Immediate: inside one hold poll tick (the hold would sit SILENT —
	// no response at all — through several ticks before admission).
	if d := time.Since(start); d > rwHoldPollInterval {
		t.Errorf("flag-off rw login took %v, want < one hold poll tick (%v) — hold leaked through?", d, rwHoldPollInterval)
	}
	// The session is REAL: a batch round-trips against the live backend.
	resp := c.sendBatchAllHeaders("SELECT 1")
	if mssqlResponseError(resp) {
		t.Fatalf("flag-off rw mssql: SELECT 1 errored: % x", resp)
	}
	if capSel := captureMSSQLResponse(resp); capSel.status != "ok" {
		t.Fatalf("flag-off rw mssql: SELECT 1 status = %q, want ok", capSel.status)
	}

	// Belt and braces: no lease leaked — admission came from the FLAG.
	active, werr := vs.WatchActive(ctx, sid)
	if werr != nil {
		t.Fatalf("WatchActive: %v", werr)
	}
	if active {
		t.Error("WatchActive = true with no watcher — a lease leaked; the test no longer proves flag-off admission")
	}
	c.close()
}
