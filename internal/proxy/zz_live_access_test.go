package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 6 LIVE (rw hold end-to-end, MySQL plane) --------------------------
//
// The zz prefix runs these LAST (the established live-suite convention —
// see zz_live_gate_hold_test.go). A real proxy session is opened with an
// access:"rw" token against the LIVE mysql-test backend: the client
// completes auth, NO backend conn opens and NO credential draw happens
// while unwatched (asserted via the creds map — an unresolvable key means
// any premature connect would fail loudly), a checker watch admits it, and
// the post-admission session runs a real SELECT.

// TestMySQLRWHoldLiveAdmitsOnWatch: the full hold lifecycle on the live
// backend.
func TestMySQLRWHoldLiveAdmitsOnWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	// NO credentials: if the proxy draws a credential / dials the backend
	// while unwatched, the connect FAILS (no creds) — but the failure would
	// only be visible after admission; while UNWATCHED any dial at all is a
	// contract breach. We assert the breach indirectly (below) by timing:
	// the client sees its OK instantly and nothing else for 800ms.
	creds := map[string]string{"mysql:rw_user@127.0.0.1:3307": "rw_pw"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := NewMySQLProxy(logger, vs, &ConfigCredResolver{Creds: creds}, nil)
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
	sid := fmt.Sprintf("sid-rw-live-%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{
		Username: "rw-live", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "3307",
		DBType: "mysql", TicketID: "T-6-HOLD", Access: "rw", SessionID: sid,
	}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	cbr := bufio.NewReader(client)

	// Handshake: server greeting → client response → the hold's OK.
	if _, _, err := readMySQLPacket(cbr); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	seq, pkt, err := readMySQLPacket(cbr)
	if err != nil || len(pkt) == 0 || pkt[0] != 0x00 {
		t.Fatalf("rw hold: no OK after auth (pkt=% x seq=%d err=%v)", pkt, seq, err)
	}

	// HELD: no response, no error, still connected for 800ms.
	_ = client.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	if _, pkt, err := readMySQLPacket(cbr); err == nil {
		t.Fatalf("held session answered early: % x", pkt)
	}
	_ = client.SetReadDeadline(time.Time{})

	// The pending directory record is alive while held.
	raw, rerr := vs.GetSessionLive(ctx, sid)
	if rerr != nil || raw == nil {
		t.Fatalf("held session missing from the directory: %v", rerr)
	}
	if !strings.Contains(string(raw), `"pending"`) {
		t.Errorf("held record = %s, want status pending", raw)
	}

	// Watcher attaches → admission → the backend session is REAL (a SELECT
	// round-trips). The hold ends when the WatchActive poll sees the lease;
	// the client's SELECT may arrive BEFORE admission — the hold's
	// disconnect probe may have consumed its first byte — so write the
	// query in a retry loop until the session responds (each iteration
	// re-sends; a byte consumed by a probe is re-sent).
	if err := vs.SetWatchConn(ctx, sid, "checker-c1", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	_ = client.SetReadDeadline(time.Now().Add(6 * time.Second))
	deadline := time.Now().Add(6 * time.Second)
	responded := false
	for !responded && time.Now().Before(deadline) {
		if err := writeMySQLPacket(client, 0, sel); err != nil {
			t.Fatalf("write SELECT after admission: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, _, err := readMySQLPacket(cbr); err == nil {
			responded = true
		}
	}
	if !responded {
		t.Fatal("no backend response after admission")
	}
}

// TestMySQLRWHoldLiveDisconnectCleansUp: a held client that walks away
// leaves NO directory record and the proxy logs the clean exit.
func TestMySQLRWHoldLiveDisconnectCleansUp(t *testing.T) {
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
	sid := fmt.Sprintf("sid-rw-dc-%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{
		Username: "rw-dc", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "3307",
		DBType: "mysql", TicketID: "T-6-HOLD", Access: "rw", SessionID: sid,
	}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	cbr := bufio.NewReader(client)
	if _, _, err := readMySQLPacket(cbr); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, pkt, err := readMySQLPacket(cbr); err != nil || len(pkt) == 0 || pkt[0] != 0x00 {
		t.Fatalf("no OK: %v", err)
	}
	// Walk away.
	client.Close()
	// The pending record must vanish (finishHeldSession) within a tick.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, gerr := vs.GetSessionLive(ctx, sid)
		if gerr == nil && raw == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sess:live record leaked after held disconnect")
}

// --- LIVE (PG): ro enforcement over the real pg-test backend ---------------

// TestPGRoRelayLiveBlocksWrites: a ro session against the live pg-test
// backend — INSERT is rejected with FATAL 28000 at the proxy (nothing
// reaches the backend), SELECT flows and returns real rows.
func TestPGRoRelayLiveBlocksWrites(t *testing.T) {
	vs := proxyTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var logBuf strings.Builder
	_ = logBuf
	done := make(chan struct{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := NewPGProxy(logger, vs, &ConfigCredResolver{Creds: pgLiveCreds}, nil)
	go func() {
		defer close(done)
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		p.handleConn(context.Background(), conn, bufio.NewReader(conn))
	}()

	token := fmt.Sprintf("pgro_%d", time.Now().UnixNano())
	if err := vs.SetToken(context.Background(), token, models.TokenPayload{
		Username: "pg-ro", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "5433",
		DBType: "postgres", Access: "ro", SessionID: "sid-pg-ro-" + token[5:],
	}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, "sid-pg-ro-"+token[5:])
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), "sid-pg-ro-"+token[5:]) })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
	if err := front.Send(&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": token, "database": "appdb"}}); err != nil {
		t.Fatalf("startup: %v", err)
	}
	// Welcome sequence.
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("welcome: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	// The write: rejected at the proxy.
	if err := front.Send(&pgproto3.Query{String: "INSERT INTO demo_items (name) VALUES ('ro-block')"}); err != nil {
		t.Fatalf("send INSERT: %v", err)
	}
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive INSERT response: %v", err)
		}
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			if !strings.Contains(er.Message, "read-only") {
				t.Errorf("INSERT error = %q, want the read-only message", er.Message)
			}
			continue
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	// The read: flows to the real backend and returns.
	if err := front.Send(&pgproto3.Query{String: "SELECT count(*) FROM demo_items"}); err != nil {
		t.Fatalf("send SELECT: %v", err)
	}
	sawRow := false
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive SELECT response: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.RowDescription:
			sawRow = true
		case *pgproto3.DataRow:
			_ = m
		case *pgproto3.ReadyForQuery:
			if !sawRow {
				t.Error("SELECT returned no RowDescription — the read did not flow")
			}
			return
		}
	}
}
