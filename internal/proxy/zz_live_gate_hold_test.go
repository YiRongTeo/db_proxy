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

// --- Task 8.13/8.17 LIVE gate-hold tests (moved here in 8.18) --------------
//
// The "zz" file prefix is deliberate: `go test` runs a package's tests in
// FILE ORDER, and these LIVE tests open real proxy sessions whose
// sess:live:<sid> directory records exist for the whole session. Because
// `go test ./...` runs package binaries in PARALLEL, any live session
// started early in the proxy binary races internal/store's
// TestListSessionsEmpty (clear-then-list on the shared dev Valkey), which
// runs in the store binary's first seconds. gate_hold_test.go sorts FIRST
// alphabetically, so before this move the 8.13/8.17 live sessions started
// ~5s into the proxy binary — inside the store binary's window (observed
// flake: TestListSessionsEmpty saw a gate-hold-run record mid-test). These
// tests now run LAST, restoring the pre-8.13 invariant: no proxy sess:live
// record is ever written during the store binary's window. Each test also
// registers cleanupLiveRecord so no record survives the test even if the
// real teardown's DelSessionLive is still in flight when the binary exits.
// --- LIVE (MySQL): the user's exact scenario -------------------------------

// TestMySQLWriteGateGraceHoldRunsAfterWatcher (Task 8.13 live, case a — the
// original breakage): the rw maker connects FIRST and runs a query; with no
// checker attached yet the command is HELD — the client stays connected
// with NO error and NO response. The checker attaches WITHIN the window →
// the held query RUNS and returns rows.
func TestMySQLWriteGateGraceHoldRunsAfterWatcher(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	marker := fmt.Sprintf("gate-hold-%d", time.Now().UnixNano())
	cleanupMarkerRow(t, marker)

	rwToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, rwToken, models.TokenPayload{Username: "gate-hold-run", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-13", Access: "write"}, time.Minute); err != nil {
		t.Fatalf("SetToken(rw): %v", err)
	}
	roToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, roToken, models.TokenPayload{Username: "gate-hold-run-ro", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql"}, time.Minute); err != nil {
		t.Fatalf("SetToken(ro): %v", err)
	}

	userCh := subscribePG(t, vs, "queries:gate-hold-run")
	ln, p := startGatingProxy(t, vs, gatingCreds)
	p.SetGateWaitSeconds(5)

	rwClient := dialTestMySQLSession(t, ln, rwToken)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID
	cleanupLiveRecord(t, vs, sid)

	// The maker's query arrives BEFORE any watcher: held — the client is
	// still connected, no error, no response yet.
	insert := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+marker+"')"...)
	if err := writeMySQLPacket(rwClient, 0, insert); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	_ = rwClient.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if _, pkt, err := readMySQLPacket(rwClient); err == nil {
		t.Fatalf("held INSERT answered early: % x", pkt)
	}
	_ = rwClient.SetReadDeadline(time.Time{})

	// Checker attaches WITHIN the window → the held query runs and returns.
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	readMySQLOKPacket(t, rwClient)
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "ok" || ev.StmtType != "insert" {
		t.Errorf("held-then-run INSERT event = status %q stmt_type %q, want ok/insert", ev.Status, ev.StmtType)
	}

	// The row actually landed.
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
		t.Fatalf("held-then-run INSERT did not land: %d row(s) for %s, want 1", len(rows), marker)
	}

	// Cleanup the marker (watcher still present → allowed).
	del := append([]byte{cmdQuery}, "DELETE FROM demo_items WHERE name = '"+marker+"'"...)
	if err := writeMySQLPacket(rwClient, 0, del); err != nil {
		t.Fatalf("write DELETE: %v", err)
	}
	readMySQLOKPacket(t, rwClient)
}

// TestMySQLWriteGateGraceHoldTimeout (Task 8.13 live, case b): no watcher
// within the window → the held command is drained with ERR 1045 + the
// timeout message + an audit event. Task 8.17: the drain does NOT latch —
// a watcher attaching LATER re-opens the gate and the next command runs.
func TestMySQLWriteGateGraceHoldTimeout(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	marker := fmt.Sprintf("gate-hold-tout-%d", time.Now().UnixNano())
	cleanupMarkerRow(t, marker)

	rwToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, rwToken, models.TokenPayload{Username: "gate-hold-timeout", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-13", Access: "write"}, time.Minute); err != nil {
		t.Fatalf("SetToken(rw): %v", err)
	}
	roToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, roToken, models.TokenPayload{Username: "gate-hold-timeout-ro", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql"}, time.Minute); err != nil {
		t.Fatalf("SetToken(ro): %v", err)
	}

	userCh := subscribePG(t, vs, "queries:gate-hold-timeout")
	ln, p := startGatingProxy(t, vs, gatingCreds)
	p.SetGateWaitSeconds(2)

	rwClient := dialTestMySQLSession(t, ln, rwToken)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID
	cleanupLiveRecord(t, vs, sid)

	// No watcher: the held INSERT is drained when the window expires —
	// ERR 1045 with the timeout message naming the window.
	insert := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+marker+"')"...)
	if err := writeMySQLPacket(rwClient, 0, insert); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	pkt := readMySQLErrPacket(t, rwClient)
	assertMySQLGateErr(t, pkt, sid)
	if !strings.Contains(string(pkt), "no checker connected within 2s") {
		t.Errorf("timeout ERR message = %q, want it to name the window (2s)", pkt)
	}

	// Audit: status=error + the timeout message.
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "error" || !strings.Contains(ev.Error, "no checker connected within 2s") {
		t.Errorf("timeout audit event = status %q error %q, want error + timeout message", ev.Status, ev.Error)
	}

	// Task 8.17 — the gate RE-OPENS: with a watcher attached NOW, the next
	// command FLOWS (same client connection, no reconnect) and runs.
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	if err := writeMySQLPacket(rwClient, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	rows, err := readTextResultSet(rwClient)
	if err != nil {
		t.Fatalf("re-attached SELECT errored: %v", err)
	}
	// readTextResultSet returns the RAW row packet: each cell is
	// length-prefixed, so the value is rows[0][1:].
	if len(rows) != 1 || string(rows[0][1:]) != "1" {
		t.Errorf("re-attached SELECT rows = %v, want [[1]]", rows)
	}
	ev = recvQueryEvent(t, userCh)
	if ev.Status != "ok" {
		t.Errorf("re-attached audit event = status %q, want ok", ev.Status)
	}

	// The blocked INSERT never landed.
	roClient := dialTestMySQLSession(t, ln, roToken)
	sel2 := append([]byte{cmdQuery}, "SELECT name FROM demo_items WHERE name = '"+marker+"'"...)
	if err := writeMySQLPacket(roClient, 0, sel2); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	rows, err = readTextResultSet(roClient)
	if err != nil {
		t.Fatalf("read result set: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("drained INSERT landed: %d row(s) for %s, want 0", len(rows), marker)
	}
}

// TestMySQLWriteGateReopensAfterWatchDrop (Task 8.17 live — the user's exact
// scenario): a write maker session WITH a watcher runs queries; the watcher
// is DELETED mid-session (the checker drops) → the maker's next query waits
// and is drained with ERR 1045 after the window (enforcement intact) + an
// audit event + the row never lands; the watcher RE-ATTACHES → the maker's
// next query RUNS and returns rows WITHOUT reconnecting.
func TestMySQLWriteGateReopensAfterWatchDrop(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	markerDrop := fmt.Sprintf("gate-reopen-drop-%d", time.Now().UnixNano())
	markerRun := fmt.Sprintf("gate-reopen-run-%d", time.Now().UnixNano())
	cleanupMarkerRow(t, markerDrop)
	cleanupMarkerRow(t, markerRun)

	rwToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, rwToken, models.TokenPayload{Username: "gate-reopen", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-17", Access: "write"}, time.Minute); err != nil {
		t.Fatalf("SetToken(rw): %v", err)
	}
	roToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, roToken, models.TokenPayload{Username: "gate-reopen-ro", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql"}, time.Minute); err != nil {
		t.Fatalf("SetToken(ro): %v", err)
	}

	userCh := subscribePG(t, vs, "queries:gate-reopen")
	ln, p := startGatingProxy(t, vs, gatingCreds)
	p.SetGateWaitSeconds(2)

	rwClient := dialTestMySQLSession(t, ln, rwToken)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID
	cleanupLiveRecord(t, vs, sid)

	// (a) Watcher present → queries run.
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	ins1 := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+markerDrop+"')"...)
	if err := writeMySQLPacket(rwClient, 0, ins1); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	readMySQLOKPacket(t, rwClient)
	if ev := recvQueryEvent(t, userCh); ev.Status != "ok" || ev.StmtType != "insert" {
		t.Errorf("watched INSERT event = status %q stmt_type %q, want ok/insert", ev.Status, ev.StmtType)
	}

	// (b) Watcher DELETED (checker drops) → the maker's next query waits
	// then gets ERR 1045 after the window + an audit event.
	if err := vs.DelWatch(ctx, sid); err != nil {
		t.Fatalf("DelWatch: %v", err)
	}
	ins2 := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+markerRun+"')"...)
	if err := writeMySQLPacket(rwClient, 0, ins2); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	pkt := readMySQLErrPacket(t, rwClient)
	assertMySQLGateErr(t, pkt, sid)
	if !strings.Contains(string(pkt), "no checker connected within 2s") {
		t.Errorf("blocked ERR message = %q, want it to name the window (2s)", pkt)
	}
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "error" || !strings.Contains(ev.Error, "no checker connected within 2s") {
		t.Errorf("blocked audit event = status %q error %q, want error + timeout message", ev.Status, ev.Error)
	}
	// Row-absent proof: the blocked INSERT never reached the backend.
	roClient := dialTestMySQLSession(t, ln, roToken)
	sel := append([]byte{cmdQuery}, "SELECT name FROM demo_items WHERE name IN ('"+markerDrop+"','"+markerRun+"')"...)
	if err := writeMySQLPacket(roClient, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	rows, err := readTextResultSet(roClient)
	if err != nil {
		t.Fatalf("read result set: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("rows for the markers = %d, want 1 (only the pre-drop INSERT landed)", len(rows))
	}

	// (c) Watcher RE-ATTACHES → the next query RUNS on the SAME client
	// connection (no reconnect) and the row lands.
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch re-attach: %v", err)
	}
	ins3 := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+markerRun+"')"...)
	if err := writeMySQLPacket(rwClient, 0, ins3); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	readMySQLOKPacket(t, rwClient)
	if ev := recvQueryEvent(t, userCh); ev.Status != "ok" || ev.StmtType != "insert" {
		t.Errorf("re-attached INSERT event = status %q stmt_type %q, want ok/insert", ev.Status, ev.StmtType)
	}
	sel2 := append([]byte{cmdQuery}, "SELECT name FROM demo_items WHERE name = '"+markerRun+"'"...)
	if err := writeMySQLPacket(rwClient, 0, sel2); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	rows, err = readTextResultSet(rwClient)
	if err != nil {
		t.Fatalf("read result set: %v", err)
	}
	// readTextResultSet returns the RAW row packet: each cell is
	// length-prefixed, so the value is rows[0][1:].
	if len(rows) != 1 || string(rows[0][1:]) != markerRun {
		t.Errorf("re-attached INSERT rows = %v, want 1 row [%s]", rows, markerRun)
	}
}

// TestMySQLWriteGateGraceHoldROExempt (Task 8.13 live, case d): read-only
// sessions are never held — with the grace window configured, an ro query
// returns immediately with no watcher.
func TestMySQLWriteGateGraceHoldROExempt(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	roToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, roToken, models.TokenPayload{Username: "gate-hold-ro", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-13", Access: "read"}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:gate-hold-ro")
	ln, p := startGatingProxy(t, vs, gatingCreds)
	p.SetGateWaitSeconds(30) // a long window: any hold would trip the deadline

	client := dialTestMySQLSession(t, ln, roToken)
	started := recvSessionEvent(t, userCh) // started
	cleanupLiveRecord(t, vs, started.SessionID)

	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	if err := writeMySQLPacket(client, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readTextResultSet(client); err != nil {
		t.Fatalf("ro query did not return immediately: %v", err)
	}
	_ = client.SetReadDeadline(time.Time{})
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "ok" {
		t.Errorf("ro no-watcher SELECT event status = %q, want ok (ro exempt from the gate)", ev.Status)
	}
}

// TestMySQLWriteGateGraceHoldZeroWait (Task 8.13 live, case e): with the
// grace window set to 0 (config ZT_GATE_WAIT_SECONDS=0 — the env override
// is pinned by the config tests), blocked commands reject immediately — the
// pre-8.13 behavior.
func TestMySQLWriteGateGraceHoldZeroWait(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	marker := fmt.Sprintf("gate-hold-zero-%d", time.Now().UnixNano())
	cleanupMarkerRow(t, marker)

	rwToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, rwToken, models.TokenPayload{Username: "gate-hold-zero", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-13", Access: "write"}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:gate-hold-zero")
	ln, p := startGatingProxy(t, vs, gatingCreds)
	p.SetGateWaitSeconds(0) // immediate reject (old behavior)

	rwClient := dialTestMySQLSession(t, ln, rwToken)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID
	cleanupLiveRecord(t, vs, sid)

	insert := append([]byte{cmdQuery}, "INSERT INTO demo_items (name) VALUES ('"+marker+"')"...)
	if err := writeMySQLPacket(rwClient, 0, insert); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	assertMySQLGateErr(t, readMySQLErrPacket(t, rwClient), sid)
	ev := recvQueryEvent(t, userCh)
	assertBlockedEvent(t, ev, sid, "insert", marker)
}

// --- LIVE (PostgreSQL): mirror ---------------------------------------------

// startHoldPGProxy is startTestPGProxyWithCreds with the grace window
// configured (the helper's proxy is otherwise unreachable). It accepts
// exactly ONE connection (the live grace-hold tests dial once): the accept
// loop exits when handleConn returns, so `done` closes when the session
// ends — the same done semantics waitPGDone relies on in every other PG
// live test. (An infinite accept loop would keep `done` open until the
// listener closes at cleanup — a waitPGDone hang.)
func startHoldPGProxy(t *testing.T, vs *store.ValkeyStore, seconds int) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewPGProxy(logger, vs, &ConfigCredResolver{Creds: pgLiveCreds}, nil)
	p.SetGateWaitSeconds(seconds)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(conn)
		p.handleConn(context.Background(), conn, br)
	}()
	return ln, done
}

// pgDialDBRaw is pgDialDB with the raw conn ALSO returned: the grace-hold
// live tests probe the held client with RAW bytes off the conn under a
// deadline (mirror of the MySQL probe) — never a concurrent
// front.Receive() goroutine, which pgproto3's Frontend does not support
// (its ChunkReader state is not safe for concurrent Receive). The conn's
// 10s dial-time deadline (read+write) is preserved.
func pgDialDBRaw(t *testing.T, ln net.Listener, token string, sslFirst bool, db string) (*pgproto3.Frontend, net.Conn) {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // no hanging tests
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
	if sslFirst {
		if err := front.Send(&pgproto3.SSLRequest{}); err != nil {
			t.Fatalf("send SSLRequest: %v", err)
		}
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read SSL response: %v", err)
		}
		if buf[0] != 'N' {
			t.Fatalf("SSLRequest response: got %q (0x%02x), want exactly 'N' (0x4e)", buf[0], buf[0])
		}
	}
	params := map[string]string{"user": token}
	if db != "" {
		params["database"] = db
	}
	if err := front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      params,
	}); err != nil {
		t.Fatalf("send StartupMessage: %v", err)
	}
	return front, conn
}

// pgReadRemainingResult consumes the response of an ALREADY-SENT Simple
// Query until ReadyForQuery. A backend ErrorResponse fails the test. (The
// held-response probe is a raw-conn deadline read that consumes nothing,
// so the Frontend's stream is intact here.)
func pgReadRemainingResult(t *testing.T, front *pgproto3.Frontend) pgExecResult {
	t.Helper()
	var res pgExecResult
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive held result: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.RowDescription:
			for _, f := range m.Fields {
				res.fields = append(res.fields, string(f.Name))
			}
		case *pgproto3.DataRow:
			row := make([]string, len(m.Values))
			for i, v := range m.Values {
				row[i] = string(v)
			}
			res.rows = append(res.rows, row)
		case *pgproto3.CommandComplete:
			res.tag = string(m.CommandTag)
		case *pgproto3.ReadyForQuery:
			res.ready = true
			return res
		case *pgproto3.ErrorResponse:
			t.Fatalf("held query errored: %s (%s)", m.Message, m.Code)
		}
	}
}

// TestPGWriteGateGraceHoldRunsAfterWatcher (Task 8.13 live, PG mirror of
// case a): the maker connects first and queries → held (no response yet) →
// checker attaches within the window → the held query runs and returns
// rows.
func TestPGWriteGateGraceHoldRunsAfterWatcher(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token := fmt.Sprintf("pggatehold_%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "pg-gate-hold", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "5433", DBType: "postgres", TicketID: "T-8-13", Access: "write"}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:pg-gate-hold")
	ln, done := startHoldPGProxy(t, vs, 5)

	front, conn := pgDialDBRaw(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID
	cleanupLiveRecord(t, vs, sid)

	// Maker's query arrives BEFORE any watcher: held — no response yet.
	// The probe reads RAW bytes off the conn under a 700ms deadline
	// (mirror of the MySQL probe). It NEVER runs a competing
	// front.Receive() goroutine: pgproto3's Frontend is not safe for
	// concurrent Receive, and a probe that consumed part of the stream
	// would corrupt the later result read ("negative body length"). On
	// timeout the probe consumes NOTHING — the stream stays intact for
	// pgReadRemainingResult after the watcher attaches.
	pgSendQuery(t, front, "SELECT 1")
	var b [1]byte
	_ = conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if n, err := io.ReadFull(conn, b[:]); err == nil {
		t.Fatalf("held PG query answered early: %d byte(s)", n)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second)) // restore the dial-time guard

	// Checker attaches WITHIN the window → the held query runs and returns.
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	res := pgReadRemainingResult(t, front)
	if !res.ready || len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Errorf("held-then-run result = ready %v rows %v, want ready with one row [1]", res.ready, res.rows)
	}
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "ok" || ev.StmtType != "select" {
		t.Errorf("held-then-run event = status %q stmt_type %q, want ok/select", ev.Status, ev.StmtType)
	}

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}

// TestPGWriteGateGraceHoldTimeout (Task 8.13 live, PG mirror of case b): no
// watcher within the window → the held query is drained with FATAL 28000 +
// the timeout message + an audit event. Task 8.17: the drain does NOT latch
// — a watcher attaching LATER re-opens the gate and the next query runs.
func TestPGWriteGateGraceHoldTimeout(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token := fmt.Sprintf("pggateholdtout_%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "pg-gate-hold-timeout", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "5433", DBType: "postgres", TicketID: "T-8-13", Access: "write"}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:pg-gate-hold-timeout")
	ln, done := startHoldPGProxy(t, vs, 2)

	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID
	cleanupLiveRecord(t, vs, sid)

	// No watcher: the held query is drained when the window expires.
	pgSendQuery(t, front, "SELECT 1")
	er := pgExpectError(t, front)
	if er.Code != "28000" || er.Severity != "FATAL" {
		t.Errorf("timeout ErrorResponse = code %q severity %q, want 28000/FATAL", er.Code, er.Severity)
	}
	if !strings.Contains(er.Message, "maker gating") || !strings.Contains(er.Message, "no checker connected within 2s") {
		t.Errorf("timeout ErrorResponse message = %q, want the timeout message naming the window", er.Message)
	}
	if !strings.Contains(er.Message, sid) {
		t.Errorf("timeout ErrorResponse message = %q, want it to name the session %s", er.Message, sid)
	}
	pgExpectReady(t, front)

	// Audit: status=error + the timeout message.
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "error" || !strings.Contains(ev.Error, "no checker connected within 2s") {
		t.Errorf("timeout audit event = status %q error %q, want error + timeout message", ev.Status, ev.Error)
	}

	// Task 8.17 — the gate RE-OPENS: with a watcher attached NOW, the next
	// query FLOWS (same session, no reconnect) and returns rows.
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	pgSendQuery(t, front, "SELECT 1")
	res := pgReadRemainingResult(t, front)
	if !res.ready || len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Errorf("re-attached SELECT = ready %v rows %v, want ready with one row [1]", res.ready, res.rows)
	}
	if ev := recvQueryEvent(t, userCh); ev.Status != "ok" || ev.StmtType != "select" {
		t.Errorf("re-attached audit event = status %q stmt_type %q, want ok/select", ev.Status, ev.StmtType)
	}

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}

// TestPGWriteGateReopensAfterWatchDrop (Task 8.17 live, PG mirror of the
// user's exact scenario): a write maker session WITH a watcher runs queries;
// the watcher is DELETED mid-session (the checker drops) → the maker's next
// query waits and is drained with FATAL 28000 after the window (enforcement
// intact) + an audit event; the watcher RE-ATTACHES → the maker's next query
// RUNS and returns rows WITHOUT reconnecting.
func TestPGWriteGateReopensAfterWatchDrop(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token := fmt.Sprintf("pggatereopen_%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "pg-gate-reopen", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "5433", DBType: "postgres", TicketID: "T-8-17", Access: "write"}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:pg-gate-reopen")
	ln, done := startHoldPGProxy(t, vs, 2)

	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)
	started := recvSessionEvent(t, userCh)
	sid := started.SessionID
	cleanupLiveRecord(t, vs, sid)

	// (a) Watcher present → queries run.
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	pgSendQuery(t, front, "SELECT 1")
	res := pgReadRemainingResult(t, front)
	if !res.ready || len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Errorf("watched SELECT = ready %v rows %v, want ready with one row [1]", res.ready, res.rows)
	}
	if ev := recvQueryEvent(t, userCh); ev.Status != "ok" || ev.StmtType != "select" {
		t.Errorf("watched SELECT event = status %q stmt_type %q, want ok/select", ev.Status, ev.StmtType)
	}

	// (b) Watcher DELETED (checker drops) → the maker's next query waits
	// then gets FATAL 28000 after the window + an audit event.
	if err := vs.DelWatch(ctx, sid); err != nil {
		t.Fatalf("DelWatch: %v", err)
	}
	pgSendQuery(t, front, "SELECT 2")
	er := pgExpectError(t, front)
	if er.Code != "28000" || er.Severity != "FATAL" {
		t.Errorf("blocked ErrorResponse = code %q severity %q, want 28000/FATAL", er.Code, er.Severity)
	}
	if !strings.Contains(er.Message, "no checker connected within 2s") {
		t.Errorf("blocked ErrorResponse message = %q, want the timeout message naming the window", er.Message)
	}
	pgExpectReady(t, front)
	ev := recvQueryEvent(t, userCh)
	if ev.Status != "error" || !strings.Contains(ev.Error, "no checker connected within 2s") {
		t.Errorf("blocked audit event = status %q error %q, want error + timeout message", ev.Status, ev.Error)
	}

	// (c) Watcher RE-ATTACHES → the next query RUNS (same session, no
	// reconnect).
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch re-attach: %v", err)
	}
	pgSendQuery(t, front, "SELECT 3")
	res = pgReadRemainingResult(t, front)
	if !res.ready || len(res.rows) != 1 || res.rows[0][0] != "3" {
		t.Errorf("re-attached SELECT = ready %v rows %v, want ready with one row [3]", res.ready, res.rows)
	}
	if ev := recvQueryEvent(t, userCh); ev.Status != "ok" || ev.StmtType != "select" {
		t.Errorf("re-attached SELECT event = status %q stmt_type %q, want ok/select", ev.Status, ev.StmtType)
	}

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}
