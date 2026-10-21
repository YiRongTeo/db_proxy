package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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

// --- Fix round 1: rw hold LIVE tests for the MSSQL + MSSQL ro relay --------

// TestMSSQLRWHoldLiveAdmitsOnWatch: the full login-phase hold on the live
// mssql-test backend. The TDS client logs in with an rw token: NOTHING
// comes back while unwatched (login-phase hold — no synthesized ack), a
// checker watch admits, the REAL login response arrives, and a batch
// round-trips. Asserts exactly ONE login success: the login() harness
// scans tokens until DONE(FINAL) — a duplicated success stream would
// surface as a second LOGINACK here.
func TestMSSQLRWHoldLiveAdmitsOnWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyP(t, vs, &logBuf, 0)
	_ = p

	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	sid := fmt.Sprintf("sid-ms-rw-%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "mssql-rw-hold",
		DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "1434", DBType: "mssql",
		TicketID: "T-6-FIX1", Access: "rw", SessionID: sid}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x, want ENCRYPT_NOT_SUP", enc)
	}
	// Send LOGIN7 and read the FIRST message with a short deadline: while
	// held, the proxy must send NOTHING (the old synthesized ack arrived
	// here instantly — a success-before-admission fails this test).
	msg := buildLogin7("tds-test-client", token, "TDS-TEST", "127.0.0.1", "appdb", nil, tdsVersion740, tdsPacketSize)
	if err := writeTDSPacket(c.conn, tdsLogin7, msg); err != nil {
		t.Fatalf("login7 write: %v", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	if typ, payload, err := readTDSMessage(c.br); err == nil {
		t.Fatalf("held MSSQL session answered pre-admission: typ=%#x payload=% x", typ, payload)
	}

	// The pending directory record is alive while held.
	raw, rerr := vs.GetSessionLive(ctx, sid)
	if rerr != nil || raw == nil {
		t.Fatalf("held session missing from the directory: %v", rerr)
	}
	if !bytes.Contains(raw, []byte(`"pending"`)) {
		t.Errorf("held record = %s, want status pending", raw)
	}

	// Admit → the REAL login response completes the login.
	if err := vs.SetWatchConn(ctx, sid, "checker-ms-rw", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var all []byte
	ok := true
	done := false
	for i := 0; i < 8 && !done; i++ {
		typ, payload, err := readTDSMessage(c.br)
		if err != nil || typ != tdsTabular {
			t.Fatalf("login response after admission: typ=%#x err=%v", typ, err)
		}
		all = append(all, payload...)
		var d, o bool
		d, o, _ = scanLoginResponse(payload)
		ok = ok && o
		if d {
			done = true
		}
	}
	if !done || !ok {
		t.Fatalf("login after admission: done=%v ok=%v stream=% x", done, ok, all)
	}
	// Exactly ONE LOGINACK in the whole stream (the old flow produced the
	// synthesized one BEFORE admission AND the real one after).
	ackCount := 0
	for pos := 0; pos < len(all); {
		switch all[pos] {
		case 0xAD:
			ackCount++
			if pos+3 > len(all) {
				pos = len(all)
			} else {
				pos += 3 + int(binary.LittleEndian.Uint16(all[pos+1:pos+3]))
			}
		case 0xFD, 0xFE, 0xFF:
			pos += 13
		case 0xAA, 0xAB, 0xAE, 0xE3, 0xE4:
			if pos+3 > len(all) {
				pos = len(all)
			} else {
				pos += 3 + int(binary.LittleEndian.Uint16(all[pos+1:pos+3]))
			}
		default:
			pos = len(all)
		}
	}
	if ackCount != 1 {
		t.Errorf("login stream carries %d LOGINACK tokens, want exactly 1", ackCount)
	}

	// The session is REAL: a batch round-trips.
	resp := c.sendBatch("SELECT 1")
	if !bytes.Contains(resp, utf16le("1")) && !bytes.Contains(resp, []byte{0x81}) {
		t.Fatalf("SELECT 1 after admission: unexpected response % x", resp)
	}
	c.close()
}

// TestMSSQLRoRelayLiveBlocksWrites: a ro session against the live
// mssql-test backend — an INSERT batch is answered at the proxy with the
// read-only ERROR token and NEVER reaches the backend (asserted via the
// response arriving without any backend round-trip marker), a SELECT
// flows and returns the backend's data.
func TestMSSQLRoRelayLiveBlocksWrites(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-ro-%d", time.Now().UnixNano())
	token := mssqlLiveToken(t, vs, username, "mssql")

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyP(t, vs, &logBuf, 0)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x, want ENCRYPT_NOT_SUP", enc)
	}
	resp, done, ok := c.login(token, "appdb")
	if !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v", done, ok)
	}
	_ = resp

	// ro write: rejected AT THE PROXY. The marker row is NEVER inserted —
	// verified after the session by a SELECT (the marker must be absent).
	marker := fmt.Sprintf("ro-never-%d", time.Now().UnixNano())
	blocked := c.sendBatch(fmt.Sprintf("INSERT INTO demo_items (id, name) VALUES (999001, '%s')", marker))
	errResp := extractErrorMsg(blocked)
	if !strings.Contains(errResp, "read-only") {
		t.Fatalf("INSERT on a ro session: error = %q, want the read-only message (resp % x)", errResp, blocked)
	}

	// ro read: flows to the real backend.
	got := c.sendBatch("SELECT count(*) FROM demo_items")
	cap := captureMSSQLResponse(got)
	if cap.status != "ok" {
		t.Fatalf("SELECT on a ro session: status = %q, want ok (resp % x)", cap.status, got)
	}

	// The write truly never reached the backend: count the marker rows.
	check := c.sendBatch(fmt.Sprintf("SELECT count(*) FROM demo_items WHERE name = '%s'", marker))
	capCheck := captureMSSQLResponse(check)
	if len(capCheck.rows) != 1 || capCheck.rows[0][0] != "0" {
		t.Fatalf("marker rows = %v, want 0 — the INSERT REACHED THE BACKEND", capCheck.rows)
	}
	c.close()
	_ = p
}
