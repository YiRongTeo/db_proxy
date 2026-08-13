package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
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

// --- Task 8.6: maker write-gating -------------------------------------------
// A read-WRITE maker cannot trigger ANY query unless a checker is watching
// their session (watch:<sid> present). Gate: MySQL COM_QUERY/COM_STMT_PREPARE/
// COM_STMT_EXECUTE, PG SimpleQuery/Parse/Execute on access=="write" sessions;
// unwatched (or store error — fail closed) → error to the CLIENT, nothing
// forwarded, audit event status=error. Checked per command, never cached.

// startGatingProxy is startKillTestProxy with caller-supplied credentials
// (multi-accept; every conn gets its own handleConn goroutine).
func startGatingProxy(t *testing.T, vs *store.ValkeyStore, creds map[string]string) (net.Listener, *MySQLProxy) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewMySQLProxy(logger, vs, &ConfigCredResolver{Creds: creds}, nil)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()
	return ln, p
}

// gatingCreds cover both MySQL backend users used by the live gating tests.
var gatingCreds = map[string]string{
	"mysql:rw_user@127.0.0.1:3307": "rw_pw",
	"mysql:ro_user@127.0.0.1:3307": "ro_pw",
}

// cleanupMarkerRow registers a deferred, best-effort DELETE of the marker row
// DIRECTLY against the live backend (127.0.0.1:3307 as rw_user), bypassing the
// proxy and its gate, so a test that fails after INSERTing its marker can
// never leave residue in demo_items. Leftover markers break
// TestMySQLSessionCaptureLive, which asserts the EXACT 3-row seed — this
// cleanup keeps that assertion stable even when a gating test Fatalfs
// mid-way (inline cleanups that run through the proxy cannot: the watcher
// may be gone and the DELETE itself gated).
func cleanupMarkerRow(t *testing.T, marker string) {
	t.Helper()
	t.Cleanup(func() {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:3307", 5*time.Second)
		if err != nil {
			t.Logf("cleanup: dial backend: %v", err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		_, hs, err := readMySQLPacket(conn)
		if err != nil {
			t.Logf("cleanup: read handshake: %v", err)
			return
		}
		salt, err := handshakeSalt(hs)
		if err != nil {
			t.Logf("cleanup: parse handshake: %v", err)
			return
		}
		// mysql_native_password scramble (rw_user is created with that
		// plugin — PLAN.md seed): SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw))).
		stage1 := sha1.Sum([]byte("rw_pw"))
		stage2 := sha1.Sum(stage1[:])
		h := sha1.New()
		h.Write(salt)
		h.Write(stage2[:])
		stage3 := h.Sum(nil)
		auth := make([]byte, 20)
		for i := range auth {
			auth[i] = stage1[i] ^ stage3[i]
		}
		caps := uint32(capProtocol41 | capSecureConnection | capConnectWithDB)
		resp := binary.LittleEndian.AppendUint32(nil, caps)
		resp = binary.LittleEndian.AppendUint32(resp, 1<<24)
		resp = append(resp, 33) // charset utf8_general_ci
		resp = append(resp, make([]byte, 23)...)
		resp = append(resp, "rw_user"...)
		resp = append(resp, 0x00)
		resp = append(resp, byte(len(auth)))
		resp = append(resp, auth...)
		resp = append(resp, "appdb"...)
		resp = append(resp, 0x00)
		if err := writeMySQLPacket(conn, 1, resp); err != nil {
			t.Logf("cleanup: write handshake response: %v", err)
			return
		}
		if _, pkt, err := readMySQLPacket(conn); err != nil || len(pkt) == 0 || pkt[0] != 0x00 {
			t.Logf("cleanup: backend auth failed: err=%v pkt=% x", err, pkt)
			return
		}
		q := append([]byte{cmdQuery}, "DELETE FROM demo_items WHERE name = '"+marker+"'"...)
		if err := writeMySQLPacket(conn, 0, q); err != nil {
			t.Logf("cleanup: write DELETE: %v", err)
			return
		}
		if _, pkt, err := readMySQLPacket(conn); err != nil || len(pkt) == 0 || pkt[0] != 0x00 {
			t.Logf("cleanup: DELETE failed: err=%v pkt=% x", err, pkt)
		}
	})
}

// handshakeSalt extracts the 20-byte auth-plugin-data (8-byte part1 +
// 12-byte part2) from a HandshakeV10 payload as sent by a real MySQL server.
func handshakeSalt(p []byte) ([]byte, error) {
	if len(p) < 34 || p[0] != 0x0a {
		return nil, errors.New("not a HandshakeV10 payload")
	}
	rest := p[1:]
	i := bytes.IndexByte(rest, 0) // server version terminator
	if i < 0 {
		return nil, errors.New("unterminated server version")
	}
	rest = rest[i+1:]
	if len(rest) < 4+8+1+2+1+2+2+1+10 {
		return nil, errors.New("handshake truncated before auth data")
	}
	salt := append([]byte{}, rest[4:12]...) // skip conn id (4); part1 (8)
	pos := 4 + 8 + 1 + 2 + 1 + 2 + 2        // filler, caps low, charset, status, caps high
	pluginLen := int(rest[pos])
	pos++
	pos += 10 // reserved
	part2Len := 13
	if pluginLen > 8 {
		part2Len = pluginLen - 8
	}
	if len(rest) < pos+part2Len {
		return nil, errors.New("handshake truncated in auth-plugin-data part2")
	}
	return append(salt, rest[pos:pos+part2Len-1]...), nil // drop trailing NUL
}

// readMySQLErrPacket reads one MySQL packet and asserts it is an ERR packet.
func readMySQLErrPacket(t *testing.T, r io.Reader) []byte {
	t.Helper()
	_, pkt, err := readMySQLPacket(r)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if len(pkt) == 0 || pkt[0] != 0xff {
		t.Fatalf("expected ERR packet, got % x", pkt)
	}
	return pkt
}

// readMySQLOKPacket reads one MySQL packet and asserts it is an OK packet.
func readMySQLOKPacket(t *testing.T, r io.Reader) {
	t.Helper()
	_, pkt, err := readMySQLPacket(r)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if len(pkt) == 0 || pkt[0] != 0x00 {
		t.Fatalf("expected OK packet, got % x", pkt)
	}
}

// assertMySQLGateErr asserts an ERR packet carries the gating code and the
// maker-gating message naming the session.
func assertMySQLGateErr(t *testing.T, pkt []byte, sid string) {
	t.Helper()
	if len(pkt) < 9 {
		t.Fatalf("ERR packet too short: % x", pkt)
	}
	if got := binary.LittleEndian.Uint16(pkt[1:3]); got != 1045 {
		t.Errorf("ERR code = %d, want 1045 (% x)", got, pkt)
	}
	msg := string(pkt[9:]) // 0xff + 2-byte code + '#' + 5-byte sqlstate
	if !strings.Contains(msg, "maker gating") || !strings.Contains(msg, sid) {
		t.Errorf("ERR message = %q, want maker-gating message naming %s", msg, sid)
	}
}

// assertBlockedEvent asserts the audit event for a gated block.
func assertBlockedEvent(t *testing.T, ev models.QueryEvent, sid, stmtType, sqlWant string) {
	t.Helper()
	if ev.Status != "error" {
		t.Errorf("blocked event status = %q, want error", ev.Status)
	}
	if !strings.Contains(ev.Error, "maker gating") || !strings.Contains(ev.Error, sid) {
		t.Errorf("blocked event error = %q, want maker-gating message naming %s", ev.Error, sid)
	}
	if ev.SessionID != sid {
		t.Errorf("blocked event session_id = %q, want %q", ev.SessionID, sid)
	}
	if ev.StmtType != stmtType {
		t.Errorf("blocked event stmt_type = %q, want %q", ev.StmtType, stmtType)
	}
	if !strings.Contains(ev.SQL, sqlWant) {
		t.Errorf("blocked event sql = %q, want it to contain %q", ev.SQL, sqlWant)
	}
}

// --- unit: gate decision helpers --------------------------------------------

// TestMySQLWriteGateDecision drives the gate helper directly: watched write
// sessions pass, unwatched write sessions block with the gating message,
// read/absent-access sessions are exempt, non-SQL commands are not gated,
// and a store error FAILS CLOSED (blocks).
func TestMySQLWriteGateDecision(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	watchedSid := "sid-gate-unit-watched"
	_ = vs.DelWatch(ctx, watchedSid)
	if err := vs.SetWatch(ctx, watchedSid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), watchedSid) })

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)

	// watched write session → allowed for every gated command.
	for _, cmd := range []byte{cmdQuery, cmdPrepare, cmdExecute} {
		s := &mysqlSession{id: watchedSid, access: "write"}
		if msg := p.checkWriteGate(s, cmd); msg != "" {
			t.Errorf("cmd %#x watched: blocked with %q, want allowed", cmd, msg)
		}
	}
	// unwatched write session → blocked, message names the session.
	s := &mysqlSession{id: "sid-gate-unit-unwatched", access: "write"}
	msg := p.checkWriteGate(s, cmdQuery)
	if !strings.Contains(msg, "maker gating") || !strings.Contains(msg, s.id) {
		t.Errorf("unwatched: got %q, want gating message naming %s", msg, s.id)
	}
	// read-access and absent-access sessions are exempt on the same command.
	for _, access := range []string{"read", ""} {
		s := &mysqlSession{id: "sid-gate-unit-ro", access: access}
		if msg := p.checkWriteGate(s, cmdQuery); msg != "" {
			t.Errorf("access %q: blocked with %q, want allowed (gate is write-only)", access, msg)
		}
	}
	// Non-SQL commands on a write session are not gated.
	s = &mysqlSession{id: "sid-gate-unit-unwatched", access: "write"}
	if msg := p.checkWriteGate(s, cmdInitDB); msg != "" {
		t.Errorf("COM_INIT_DB: blocked with %q, want allowed", msg)
	}
	if msg := p.checkWriteGate(s, cmdQuit); msg != "" {
		t.Errorf("COM_QUIT: blocked with %q, want allowed", msg)
	}
	// Store error → FAIL CLOSED: the command is blocked like an absent watcher.
	dead := newDeadStore(t)
	pe := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), dead, &ConfigCredResolver{}, nil)
	se := &mysqlSession{id: "sid-gate-unit-error", access: "write"}
	if msg := pe.checkWriteGate(se, cmdQuery); msg == "" {
		t.Error("store error: allowed, want fail-closed block")
	}
}

// newDeadStore returns a store whose client is already closed — every
// command errors (used to prove the gate fails closed).
func newDeadStore(t *testing.T) *store.ValkeyStore {
	t.Helper()
	vs, err := store.NewValkeyStoreDirect(context.Background(), "127.0.0.1:6379", "", 0)
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	vs.Close()
	return vs
}

// TestPGWriteGateDecision drives the PG gate helper over a pipe: watched
// write sessions pass; unwatched → ErrorResponse FATAL 28000 with the
// gating message + ReadyForQuery reaches the client; read-access sessions
// are exempt.
func TestPGWriteGateDecision(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	watchedSid := "sid-pg-gate-watched"
	_ = vs.DelWatch(ctx, watchedSid)
	if err := vs.SetWatch(ctx, watchedSid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), watchedSid) })

	// Drive the backend against an in-memory buffer instead of net.Pipe:
	// net.Pipe is UNBUFFERED, and gatePGMessage sends the block response
	// BEFORE the caller reads it, so be.Send would block forever waiting
	// for a reader that only appears after gatePGMessage returns. A
	// bytes.Buffer writer never blocks, and the frontend then reads the
	// exact bytes the backend wrote — sequentially, no goroutines. (The
	// production relays never hit this: pipePGBackendToClient reads the
	// client side concurrently with gatePGMessage's Send.)
	var out bytes.Buffer
	be := pgproto3.NewBackend(pgproto3.NewChunkReader(&out), &out)
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(&out), io.Discard)
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)

	// Watched write session → allowed (nothing sent to the client).
	s := &pgSession{id: watchedSid, access: "write"}
	if p.gatePGMessage(be, &pgproto3.Query{String: "SELECT 1"}, s) {
		t.Error("watched write session: blocked, want allowed")
	}

	// Unwatched write session → blocked with FATAL 28000 + ReadyForQuery.
	unw := &pgSession{id: "sid-pg-gate-unwatched", access: "write"}
	if !p.gatePGMessage(be, &pgproto3.Query{String: "SELECT 1"}, unw) {
		t.Fatal("unwatched write session: allowed, want blocked")
	}
	m1, err := front.Receive()
	if err != nil {
		t.Fatalf("receive ErrorResponse: %v", err)
	}
	er, ok := m1.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("first message = %T, want *pgproto3.ErrorResponse", m1)
	}
	if er.Code != "28000" || er.Severity != "FATAL" || !strings.Contains(er.Message, "maker gating") || !strings.Contains(er.Message, unw.id) {
		t.Errorf("ErrorResponse = code %q severity %q message %q, want FATAL 28000 maker-gating naming %s", er.Code, er.Severity, er.Message, unw.id)
	}
	m2, err := front.Receive()
	if err != nil {
		t.Fatalf("receive ReadyForQuery: %v", err)
	}
	if _, ok := m2.(*pgproto3.ReadyForQuery); !ok {
		t.Errorf("second message = %T, want *pgproto3.ReadyForQuery", m2)
	}

	// Read-access session → exempt.
	ro := &pgSession{id: "sid-pg-gate-unwatched", access: "read"}
	if p.gatePGMessage(be, &pgproto3.Query{String: "SELECT 1"}, ro) {
		t.Error("read-access session: blocked, want allowed")
	}
	// Non-gated message on a write session → not gated.
	if p.gatePGMessage(be, &pgproto3.Bind{}, unw) {
		t.Error("Bind on write session: blocked, want allowed")
	}
}

// --- LIVE (MySQL): blocked + row-absent + audit ------------------------------

// TestMySQLWriteGateBlocksUnwatched (Task 8.6 live, case a): a write-access
// token with NO checker watching → an INSERT is blocked: the client gets ERR
// 1045 with the gating message, the statement is NOT forwarded (the row does
// not land — verified through a read-access session), and the audit trail
// shows the block (event status=error with the gating message).
func TestMySQLWriteGateBlocksUnwatched(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	marker := fmt.Sprintf("gate-marker-%d", time.Now().UnixNano())
	cleanupMarkerRow(t, marker)

	rwToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, rwToken, models.TokenPayload{Username: "gate-writer", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-6", Access: "write"}, time.Minute); err != nil {
		t.Fatalf("SetToken(rw): %v", err)
	}
	roToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, roToken, models.TokenPayload{Username: "gate-reader", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-6"}, time.Minute); err != nil {
		t.Fatalf("SetToken(ro): %v", err)
	}

	userCh := subscribePG(t, vs, "queries:gate-writer")
	ln, _ := startGatingProxy(t, vs, gatingCreds)

	rwClient := dialTestMySQLSession(t, ln, rwToken)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID

	// No watcher: the INSERT must be blocked with ERR 1045.
	insert := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+marker+"')"...)
	if err := writeMySQLPacket(rwClient, 0, insert); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	assertMySQLGateErr(t, readMySQLErrPacket(t, rwClient), sid)

	// Audit event: status=error + gating message + classified stmt_type.
	ev := recvQueryEvent(t, userCh)
	assertBlockedEvent(t, ev, sid, "insert", marker)

	// Backend untouched: the marker row is absent — verified through a
	// read-access session (gate exempt).
	roClient := dialTestMySQLSession(t, ln, roToken)
	sel := append([]byte{cmdQuery}, "SELECT name FROM demo_items WHERE name = '"+marker+"'"...)
	if err := writeMySQLPacket(roClient, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	rows, err := readTextResultSet(roClient)
	if err != nil {
		t.Fatalf("read result set: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("blocked INSERT landed: %d row(s) found for %s", len(rows), marker)
	}
}

// TestMySQLWriteGateWatcherPass (Task 8.6 live, case b): with watch:<sid>
// present (exactly what the checker hub maintains), the write session's
// INSERT passes and the row actually lands.
func TestMySQLWriteGateWatcherPass(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	marker := fmt.Sprintf("gate-marker-%d", time.Now().UnixNano())
	cleanupMarkerRow(t, marker)

	rwToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, rwToken, models.TokenPayload{Username: "gate-pass", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-6", Access: "write"}, time.Minute); err != nil {
		t.Fatalf("SetToken(rw): %v", err)
	}
	roToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, roToken, models.TokenPayload{Username: "gate-pass-ro", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql"}, time.Minute); err != nil {
		t.Fatalf("SetToken(ro): %v", err)
	}

	userCh := subscribePG(t, vs, "queries:gate-pass")
	ln, _ := startGatingProxy(t, vs, gatingCreds)

	rwClient := dialTestMySQLSession(t, ln, rwToken)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	insert := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+marker+"')"...)
	if err := writeMySQLPacket(rwClient, 0, insert); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	readMySQLOKPacket(t, rwClient)
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "ok" || ev.StmtType != "insert" {
		t.Errorf("watched INSERT event = status %q stmt_type %q, want ok/insert", ev.Status, ev.StmtType)
	}

	// The row actually landed (watcher enabled the write).
	roClient := dialTestMySQLSession(t, ln, roToken)
	sel := append([]byte{cmdQuery}, "SELECT name FROM demo_items WHERE name = '"+marker+"'"...)
	if err := writeMySQLPacket(roClient, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	rows, err := readTextResultSet(roClient)
	if err != nil {
		t.Fatalf("read result set: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("watched INSERT did not land: %d row(s) for %s, want 1", len(rows), marker)
	}

	// Cleanup: delete the marker (watcher still present → allowed).
	del := append([]byte{cmdQuery}, "DELETE FROM demo_items WHERE name = '"+marker+"'"...)
	if err := writeMySQLPacket(rwClient, 0, del); err != nil {
		t.Fatalf("write DELETE: %v", err)
	}
	readMySQLOKPacket(t, rwClient)
}

// TestMySQLWriteGateReadOnlyExempt (Task 8.6 live, case c): a read-only
// token with NO watcher queries normally — the gate applies ONLY to
// write-access sessions.
func TestMySQLWriteGateReadOnlyExempt(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	roToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, roToken, models.TokenPayload{Username: "gate-ro-exempt", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-6", Access: "read"}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:gate-ro-exempt")
	ln, _ := startGatingProxy(t, vs, gatingCreds)

	client := dialTestMySQLSession(t, ln, roToken)
	recvSessionEvent(t, userCh) // started

	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	if err := writeMySQLPacket(client, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	if _, err := readTextResultSet(client); err != nil {
		t.Fatalf("read result set: %v", err)
	}
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "ok" {
		t.Errorf("read-only no-watcher SELECT event status = %q, want ok", ev.Status)
	}
}

// TestMySQLWriteGateWatcherRemovedMidSession (Task 8.6 live, case d): a
// watcher present at INSERT time enables it; REMOVING the watcher mid-session
// blocks the NEXT query (fail-closed per command); re-watching unblocks the
// same session — the block never kills the session.
func TestMySQLWriteGateWatcherRemovedMidSession(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	marker := fmt.Sprintf("gate-marker-%d", time.Now().UnixNano())
	cleanupMarkerRow(t, marker)

	rwToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, rwToken, models.TokenPayload{Username: "gate-remove", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-6", Access: "write"}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:gate-remove")
	ln, _ := startGatingProxy(t, vs, gatingCreds)

	client := dialTestMySQLSession(t, ln, rwToken)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID

	// Watched → INSERT passes.
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	insert := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+marker+"')"...)
	if err := writeMySQLPacket(client, 0, insert); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	readMySQLOKPacket(t, client)
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "ok" {
		t.Errorf("watched INSERT status = %q, want ok", ev.Status)
	}

	// Watcher removed → the NEXT query is blocked (per-command check).
	if err := vs.DelWatch(ctx, sid); err != nil {
		t.Fatalf("DelWatch: %v", err)
	}
	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	if err := writeMySQLPacket(client, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	assertMySQLGateErr(t, readMySQLErrPacket(t, client), sid)
	ev = recvQueryEvent(t, userCh)
	assertBlockedEvent(t, ev, sid, "select", "SELECT 1")

	// Re-watched → the SAME session works again.
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	if err := writeMySQLPacket(client, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	if _, err := readTextResultSet(client); err != nil {
		t.Fatalf("read result set after re-watch: %v", err)
	}
	ev = recvQueryEvent(t, userCh)
	if ev.Status != "ok" {
		t.Errorf("re-watched SELECT status = %q, want ok", ev.Status)
	}

	// Cleanup the marker row (watcher present).
	del := append([]byte{cmdQuery}, "DELETE FROM demo_items WHERE name = '"+marker+"'"...)
	if err := writeMySQLPacket(client, 0, del); err != nil {
		t.Fatalf("write DELETE: %v", err)
	}
	readMySQLOKPacket(t, client)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
}

// --- LIVE (PostgreSQL): mirror ----------------------------------------------

// pgSendQuery sends a SimpleQuery without consuming the response.
func pgSendQuery(t *testing.T, front *pgproto3.Frontend, sql string) {
	t.Helper()
	if err := front.Send(&pgproto3.Query{String: sql}); err != nil {
		t.Fatalf("send query %q: %v", sql, err)
	}
}

// pgExpectError reads until the next ErrorResponse and returns it.
func pgExpectError(t *testing.T, front *pgproto3.Frontend) *pgproto3.ErrorResponse {
	t.Helper()
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			return er
		}
	}
}

// pgExpectReady reads until the next ReadyForQuery.
func pgExpectReady(t *testing.T, front *pgproto3.Frontend) {
	t.Helper()
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return
		}
	}
}

// TestPGWriteGateBlocksUnwatched (Task 8.6 PG mirror of case a): a
// write-access token with NO watcher → a Simple Query is blocked: the client
// receives ErrorResponse FATAL 28000 with the gating message (plus
// ReadyForQuery), the query is NOT forwarded, and the audit event carries
// status=error. With a watcher the same session's query passes; removing the
// watcher blocks again.
func TestPGWriteGateBlocksUnwatched(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token := fmt.Sprintf("pggate_%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "pg-gate-writer", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "5433", DBType: "postgres", TicketID: "T-8-6", Access: "write"}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	userCh := subscribePG(t, vs, "queries:pg-gate-writer")
	ln, done := startTestPGProxyWithCreds(t, vs, &bytes.Buffer{}, pgLiveCreds, 1)
	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)

	started := recvSessionEvent(t, userCh)
	sid := started.SessionID

	// No watcher → blocked with FATAL 28000 + ReadyForQuery.
	pgSendQuery(t, front, "SELECT 1")
	er := pgExpectError(t, front)
	if er.Code != "28000" || er.Severity != "FATAL" {
		t.Errorf("blocked ErrorResponse = code %q severity %q, want 28000/FATAL", er.Code, er.Severity)
	}
	if !strings.Contains(er.Message, "maker gating") || !strings.Contains(er.Message, sid) {
		t.Errorf("blocked ErrorResponse message = %q, want maker-gating message naming %s", er.Message, sid)
	}
	pgExpectReady(t, front)

	ev := recvQueryEvent(t, userCh)
	assertBlockedEvent(t, ev, sid, "select", "SELECT 1")

	// Watcher present → the same session's query passes.
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	pgExecQuery(t, front, "SELECT 1")
	ev = recvQueryEvent(t, userCh)
	if ev.Status != "ok" {
		t.Errorf("watched SELECT event status = %q, want ok", ev.Status)
	}

	// Watcher removed → blocked again (per-command check, session survives).
	if err := vs.DelWatch(ctx, sid); err != nil {
		t.Fatalf("DelWatch: %v", err)
	}
	pgSendQuery(t, front, "SELECT 2")
	er = pgExpectError(t, front)
	if !strings.Contains(er.Message, "maker gating") {
		t.Errorf("second block message = %q, want maker gating", er.Message)
	}
	pgExpectReady(t, front)
	ev = recvQueryEvent(t, userCh)
	assertBlockedEvent(t, ev, sid, "select", "SELECT 2")

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}

// --- Task 8.11: token-time session listing (the gating-deadlock fix) --------
// The deadlock: a write maker's first query is blocked (1045) when no
// checker watches yet, but the checker can only select a session AFTER the
// maker connects — the client breaks before the checker can attach.
// RESOLUTION: the session id is stamped into the TOKEN at issue time, so
// the checker can watch sess:<sid> (from the pending listing) BEFORE the
// maker connects. These tests prove: the data plane adopts the token's sid,
// the FIRST command passes the gate when the watcher attached pre-connect,
// and the directory record flips to status=active under that sid.

// TestMySQLWriteGateFirstQueryPassesWithTokenSid (Task 8.11 live): a write
// token carrying its session id, watched BEFORE the maker connects → the
// maker's FIRST query passes (no 1045 — the deadlock is gone). Also asserts
// the started event's session_id equals the token's sid and the directory
// record flips to active.
func TestMySQLWriteGateFirstQueryPassesWithTokenSid(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	marker := fmt.Sprintf("gate-marker-%d", time.Now().UnixNano())
	cleanupMarkerRow(t, marker)

	sid := models.NewSessionID()
	rwToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, rwToken, models.TokenPayload{Username: "gate-811", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-11", Access: "write",
		SessionID: sid}, time.Minute); err != nil {
		t.Fatalf("SetToken(rw): %v", err)
	}
	userCh := subscribePG(t, vs, "queries:gate-811")
	ln, _ := startGatingProxy(t, vs, gatingCreds)

	// The checker attaches BEFORE the maker connects — exactly what the
	// token-time pending listing enables (watch:<sid> from the pending
	// entry, before the session exists).
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	rwClient := dialTestMySQLSession(t, ln, rwToken)
	started := recvSessionEvent(t, userCh)
	if started.SessionID != sid {
		t.Fatalf("started event session_id = %q, want the token's sid %q", started.SessionID, sid)
	}

	// FIRST query: the gate passes — no 1045 on the first command.
	insert := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+marker+"')"...)
	if err := writeMySQLPacket(rwClient, 0, insert); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	readMySQLOKPacket(t, rwClient)
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "ok" || ev.StmtType != "insert" || ev.SessionID != sid {
		t.Errorf("first-query event = status %q stmt_type %q session %q, want ok/insert/%s",
			ev.Status, ev.StmtType, ev.SessionID, sid)
	}

	// The directory record flipped to active under the token's sid.
	rec := findSessionRecord(t, vs, sid)
	if rec == nil {
		t.Fatalf("session %s not listed after connect", sid)
	}
	if rec.Status != "active" {
		t.Errorf("session record status = %q, want active", rec.Status)
	}
	if rec.ThreadID <= 0 {
		t.Errorf("thread_id = %d, want the backend CONNECTION_ID() (> 0)", rec.ThreadID)
	}

	// Cleanup the marker row (watcher still present → allowed).
	del := append([]byte{cmdQuery}, "DELETE FROM demo_items WHERE name = '"+marker+"'"...)
	if err := writeMySQLPacket(rwClient, 0, del); err != nil {
		t.Fatalf("write DELETE: %v", err)
	}
	readMySQLOKPacket(t, rwClient)
	rwClient.Close()
}

// TestPGWriteGateFirstQueryPassesWithTokenSid (Task 8.11 PG mirror): the
// same flow — token-sid session, watcher attached before connect, first
// query passes the gate, started event carries the token's sid, record
// status=active.
func TestPGWriteGateFirstQueryPassesWithTokenSid(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	sid := models.NewSessionID()
	token := fmt.Sprintf("pggate811_%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "pg-gate-811", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "5433", DBType: "postgres", TicketID: "T-8-11", Access: "write",
		SessionID: sid}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:pg-gate-811")
	ln, done := startTestPGProxyWithCreds(t, vs, &bytes.Buffer{}, pgLiveCreds, 1)

	// Checker attaches BEFORE the maker connects.
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)
	started := recvSessionEvent(t, userCh)
	if started.SessionID != sid {
		t.Fatalf("started event session_id = %q, want the token's sid %q", started.SessionID, sid)
	}

	// FIRST query passes the gate.
	pgExecQuery(t, front, "SELECT 1")
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "ok" || ev.SessionID != sid {
		t.Errorf("first-query event = status %q session %q, want ok/%s", ev.Status, ev.SessionID, sid)
	}

	// The directory record flipped to active under the token's sid.
	rec := findSessionRecord(t, vs, sid)
	if rec == nil {
		t.Fatalf("session %s not listed after connect", sid)
	}
	if rec.Status != "active" {
		t.Errorf("session record status = %q, want active", rec.Status)
	}

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}
