package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 7 (node-integration): rw_require_checker_watch = false -------------
//
// Flag OFF: an access:"rw" token ADMITS IMMEDIATELY on the mysql plane —
// the normal post-auth backend connect (exactly what a legacy preset
// access:"write" token takes), NO hold, NO WatchActive polling. Proven LIVE:
// with NO watch lease ever armed, the rw client gets its OK and a real
// backend SELECT round-trips within the window the hold would need several
// poll ticks to even start.
//
// Flag ON (the proxy zero-value default): the Task 6 hold — covered by
// TestMySQLRWHoldLiveAdmitsOnWatch (zz_live_access_test.go), which doubles as
// the G3 byte-identical guard since it never calls the setter.

// TestMySQLRWFlagOffAdmitsWithoutWatch: rw + SetRWRequireCheckerWatch(false)
// → immediate backend connect, no hold, no watch needed.
func TestMySQLRWFlagOffAdmitsWithoutWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	creds := map[string]string{"mysql:rw_user@127.0.0.1:3307": "rw_pw"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := NewMySQLProxy(logger, vs, &ConfigCredResolver{Creds: creds}, nil)
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

	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	sid := fmt.Sprintf("sid-rw-flagoff-%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{
		Username: "rw-flagoff", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "3307",
		DBType: "mysql", TicketID: "T-7-FLAGOFF", Access: "rw", SessionID: sid,
	}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })
	// NO SetWatchConn — no watch lease is ever armed. WatchActive(sid) stays
	// false for the whole test; assert it at the end as a belt-and-braces.

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	cbr := bufio.NewReader(client)

	// Handshake: server greeting → client response → the login OK.
	if _, _, err := readMySQLPacket(cbr); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	seq, pkt, err := readMySQLPacket(cbr)
	if err != nil || len(pkt) == 0 || pkt[0] != 0x00 {
		t.Fatalf("flag-off rw: no OK after auth (pkt=% x seq=%d err=%v)", pkt, seq, err)
	}

	// ADMITTED, not held: a real backend SELECT round-trips with NO watch.
	// (Flag ON this exact sequence deadlocks until the read deadline: the
	// hold would park the SELECT waiting for a watcher that never comes.)
	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	_ = client.SetReadDeadline(time.Now().Add(4 * time.Second))
	if err := writeMySQLPacket(client, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	if _, _, err := readMySQLPacket(cbr); err != nil {
		t.Fatalf("flag-off rw: no backend response without a watch (hold leaked through?): %v", err)
	}
	_ = client.SetReadDeadline(time.Time{})

	// Belt and braces: the gate stayed closed the whole time — admission came
	// from the FLAG, never from a watch lease.
	active, werr := vs.WatchActive(ctx, sid)
	if werr != nil {
		t.Fatalf("WatchActive: %v", werr)
	}
	if active {
		t.Error("WatchActive = true with no watcher — a lease leaked; the test no longer proves flag-off admission")
	}
}
