package proxy

import (
	"bufio"
	"bytes"
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

// --- Task 8.13: gate grace hold -------------------------------------------
// While a write session has NO watcher, blocked SQL commands WAIT up to
// gate_wait_seconds for a checker instead of failing instantly (maker-first
// connects no longer break): the watcher's arrival flushes the queue in
// order; the window's expiry drains it (1045/28000 + audit events) and
// LATCHES the session fail-closed (later watchers do not unblock; the maker
// must reconnect).

// holdMySQLProxy builds a MySQLProxy with the grace window configured.
func holdMySQLProxy(t *testing.T, vs *store.ValkeyStore, seconds int) *MySQLProxy {
	t.Helper()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	p.SetGateWaitSeconds(seconds)
	return p
}

// --- unit: queue bounds ----------------------------------------------------

// TestMySQLGateHoldQueueBounds: up to gateQueueMax commands queue while no
// watcher is attached; the NEXT command (overflow) is NOT queued — the
// caller rejects it immediately — and the queue keeps waiting (no latch).
func TestMySQLGateHoldQueueBounds(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMySQLProxy(t, vs, 60)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &mysqlSession{id: "sid-hold-bounds", access: "write", client: client, backend: backend}
	// Registered first → runs LAST: closeGateWait drains (best-effort
	// writes) only after the pipe peers are closed, so its replies error
	// out instead of blocking on the unread net.Pipe.
	defer p.closeGateWait(s)
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()

	for i := 0; i < gateQueueMax; i++ {
		s.mu.Lock()
		s.pending = &models.QueryEvent{SQL: fmt.Sprintf("SELECT %d", i), Username: "hold", SessionID: s.id}
		s.mu.Unlock()
		if !p.gateHold(s, 0, []byte{cmdQuery, '1'}) {
			t.Fatalf("command %d: not held, want queued", i+1)
		}
	}
	s.mu.Lock()
	s.pending = &models.QueryEvent{SQL: "SELECT overflow", Username: "hold", SessionID: s.id}
	s.mu.Unlock()
	if p.gateHold(s, 0, []byte{cmdQuery, '2'}) {
		t.Error("17th command: held, want immediate reject (queue overflow)")
	}
	s.gateMu.Lock()
	n, latched := len(s.gate.queue), s.gate.latched
	s.gateMu.Unlock()
	if n != gateQueueMax {
		t.Errorf("queue length = %d, want %d", n, gateQueueMax)
	}
	if latched {
		t.Error("overflow latched the session, want the queue to keep waiting")
	}
}

// --- unit: flush order -----------------------------------------------------

// TestMySQLGateHoldFlushOrder: queued commands flush IN ORDER — each
// forwarded exactly as the normal forward path writes it (stored client
// seq + byte-exact payload).
func TestMySQLGateHoldFlushOrder(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMySQLProxy(t, vs, 60)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &mysqlSession{id: "sid-hold-order", access: "write", client: client, backend: backend}
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	defer p.closeGateWait(s)

	sqls := []string{"SELECT 'first'", "SELECT 'second'", "SELECT 'third'"}
	payloads := make([][]byte, len(sqls))
	for i, sql := range sqls {
		s.mu.Lock()
		s.pending = &models.QueryEvent{SQL: sql, Username: "hold", SessionID: s.id}
		s.mu.Unlock()
		payloads[i] = append([]byte{cmdQuery}, sql...)
		if !p.gateHold(s, 0, payloads[i]) {
			t.Fatalf("command %d: not held, want queued", i+1)
		}
	}
	// Watcher arrives → flush (driven directly here; the ticker path is
	// proven end-to-end by the LIVE held-then-run test).
	go p.gateFlush(s)
	for i, want := range payloads {
		seq, payload, err := readMySQLPacket(bpeer)
		if err != nil {
			t.Fatalf("flush packet %d: %v", i+1, err)
		}
		if seq != 0 {
			t.Errorf("flush packet %d seq = %d, want 0 (client seq preserved)", i+1, seq)
		}
		if !bytes.Equal(payload, want) {
			t.Errorf("flush packet %d payload = % x, want % x (byte-exact)", i+1, payload, want)
		}
	}
	s.gateMu.Lock()
	active, n := s.gate.active, len(s.gate.queue)
	s.gateMu.Unlock()
	if active || n != 0 {
		t.Errorf("after flush: active=%v queue=%d, want false/0", active, n)
	}
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after flush")
	}
}

// --- unit: timeout drain ---------------------------------------------------

// TestMySQLGateHoldTimeoutDrain: no watcher within the window → every held
// command is drained with ERR 1045 + the timeout message, each gets an
// audit event (status=error, "no checker connected within <N>s"), and the
// session latches fail-closed.
func TestMySQLGateHoldTimeoutDrain(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMySQLProxy(t, vs, 1)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &mysqlSession{id: "sid-hold-timeout", access: "write", client: client, backend: backend}
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	defer p.closeGateWait(s)

	ev1 := &models.QueryEvent{SQL: "SELECT 1", Username: "hold", SessionID: s.id}
	ev2 := &models.QueryEvent{SQL: "SELECT 2", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev1
	s.mu.Unlock()
	if !p.gateHold(s, 0, []byte{cmdQuery, '1'}) {
		t.Fatal("command 1: not held, want queued")
	}
	s.mu.Lock()
	s.pending = ev2
	s.mu.Unlock()
	if !p.gateHold(s, 0, []byte{cmdQuery, '2'}) {
		t.Fatal("command 2: not held, want queued")
	}

	// The window expires with no watcher → both held commands drain.
	for i := 0; i < 2; i++ {
		pkt := readMySQLErrPacket(t, cpeer)
		if !strings.Contains(string(pkt), "no checker connected within 1s") {
			t.Errorf("drain ERR %d = %q, want timeout message naming the window", i+1, pkt)
		}
	}
	// The wait goroutine finishes the drain (replies → audit events) —
	// wait for it before asserting the events it stamps.
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after timeout drain")
	}
	s.gateMu.Lock()
	latched, active, n := s.gate.latched, s.gate.active, len(s.gate.queue)
	s.gateMu.Unlock()
	if !latched {
		t.Error("session not latched after timeout drain")
	}
	if active || n != 0 {
		t.Errorf("after drain: active=%v queue=%d, want false/0", active, n)
	}
	// Every held command got its own audit event.
	if ev1.Status != "error" || !strings.Contains(ev1.Error, "no checker connected within 1s") {
		t.Errorf("ev1 = status %q error %q, want error + timeout message", ev1.Status, ev1.Error)
	}
	if ev2.Status != "error" || !strings.Contains(ev2.Error, "no checker connected within 1s") {
		t.Errorf("ev2 = status %q error %q, want error + timeout message", ev2.Status, ev2.Error)
	}
}

// --- unit: fail-closed latch ----------------------------------------------

// TestMySQLGateHoldFailClosedLatch: after a timeout, subsequent commands
// are rejected immediately EVEN WHEN a watcher attaches later — the maker
// must reconnect.
func TestMySQLGateHoldFailClosedLatch(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMySQLProxy(t, vs, 1)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &mysqlSession{id: "sid-hold-latch", access: "write", client: client, backend: backend}
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	defer p.closeGateWait(s)

	s.mu.Lock()
	s.pending = &models.QueryEvent{SQL: "SELECT 1", Username: "hold", SessionID: s.id}
	s.mu.Unlock()
	if !p.gateHold(s, 0, []byte{cmdQuery, '1'}) {
		t.Fatal("command: not held, want queued")
	}
	readMySQLErrPacket(t, cpeer) // drain (window expired)

	// A watcher attaches LATER — the latch still rejects every command.
	if err := vs.SetWatch(context.Background(), s.id, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), s.id) })
	if msg := p.checkWriteGate(s, cmdQuery); !strings.Contains(msg, "no checker connected within 1s") {
		t.Errorf("latched checkWriteGate = %q, want the timeout message", msg)
	}
	if p.gateHold(s, 0, []byte{cmdQuery, '2'}) {
		t.Error("latched session: gateHold queued, want immediate reject")
	}
}

// --- unit: gate_wait_seconds=0 ---------------------------------------------

// TestMySQLGateHoldZeroWait: gate_wait_seconds=0 keeps the pre-8.13
// behavior — a blocked command is never queued; the caller rejects it
// immediately (the existing 8.6 matrix covers the reject path).
func TestMySQLGateHoldZeroWait(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMySQLProxy(t, vs, 0) // 0 = reject immediately (old behavior)
	s := &mysqlSession{id: "sid-hold-zero", access: "write"}
	if p.gateHold(s, 0, []byte{cmdQuery, '1'}) {
		t.Error("gate_wait_seconds=0: gateHold queued, want immediate reject")
	}
	s.gateMu.Lock()
	active := s.gate.active
	s.gateMu.Unlock()
	if active {
		t.Error("gate_wait_seconds=0 started a wait goroutine")
	}
}

// --- unit: session-close cleanup -------------------------------------------

// TestMySQLGateHoldCloseCleanup: closing the session while commands are
// held drains them with the same rejection (best-effort replies — the
// client is gone) and cleans up the wait goroutine and timers.
func TestMySQLGateHoldCloseCleanup(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMySQLProxy(t, vs, 60)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &mysqlSession{id: "sid-hold-close", access: "write", client: client, backend: backend}
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()

	ev := &models.QueryEvent{SQL: "SELECT 1", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev
	s.mu.Unlock()
	if !p.gateHold(s, 0, []byte{cmdQuery, '1'}) {
		t.Fatal("command: not held, want queued")
	}
	// The client is gone (peer closed) → the drain replies are best-effort.
	cpeer.Close()
	bpeer.Close()
	backend.Close()
	p.closeGateWait(s)

	s.gateMu.Lock()
	active, latched, n := s.gate.active, s.gate.latched, len(s.gate.queue)
	s.gateMu.Unlock()
	if active || n != 0 {
		t.Errorf("after close: active=%v queue=%d, want false/0", active, n)
	}
	if latched {
		t.Error("session-close drain must not latch the session")
	}
	if ev.Status != "error" || !strings.Contains(ev.Error, "no checker connected within 60s") {
		t.Errorf("held event = status %q error %q, want error + timeout message", ev.Status, ev.Error)
	}
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine still running after session close")
	}
}

// --- unit (PG mirror) ------------------------------------------------------

// pgHoldSession builds a PG session over net.Pipe pairs for gate unit
// tests. The client side carries the pgproto3 Backend (drain replies), the
// backend side the pgFrontend (flush forwards).
func pgHoldSession(t *testing.T, sid string) (*pgSession, net.Conn, net.Conn) {
	t.Helper()
	clientConn, clientPeer := net.Pipe()
	be := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)
	frontConn, frontPeer := net.Pipe()
	front := &pgFrontend{conn: frontConn, f: pgproto3.NewFrontend(pgproto3.NewChunkReader(frontConn), frontConn)}
	return &pgSession{id: sid, access: "write", be: be, front: front}, clientPeer, frontPeer
}

// TestPGGateHoldFlushOrder: PG mirror of the MySQL flush-order test — held
// messages flush in order, raw wire bytes byte-identical to the normal
// relay write.
func TestPGGateHoldFlushOrder(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	p.SetGateWaitSeconds(60)
	s, clientPeer, frontPeer := pgHoldSession(t, "sid-pg-hold-order")
	defer func() { clientPeer.Close(); frontPeer.Close() }()
	defer p.closePGGateWait(s)

	msgs := []pgproto3.FrontendMessage{
		&pgproto3.Query{String: "SELECT 'first'"},
		&pgproto3.Query{String: "SELECT 'second'"},
	}
	raws := make([][]byte, len(msgs))
	for i, m := range msgs {
		s.mu.Lock()
		s.pending = &models.QueryEvent{SQL: "SELECT " + fmt.Sprint(i), Username: "hold", SessionID: s.id}
		s.mu.Unlock()
		if !p.gatePGHold(m, s) {
			t.Fatalf("message %d: not held, want queued", i+1)
		}
		raws[i], _ = m.Encode(nil)
	}
	go p.gatePGFlush(s)
	for i, want := range raws {
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(frontPeer, buf); err != nil {
			t.Fatalf("flush message %d: %v", i+1, err)
		}
		if !bytes.Equal(buf, want) {
			t.Errorf("flush message %d = % x, want % x (byte-exact)", i+1, buf, want)
		}
	}
	s.gateMu.Lock()
	active, n := s.gate.active, len(s.gate.queue)
	s.gateMu.Unlock()
	if active || n != 0 {
		t.Errorf("after flush: active=%v queue=%d, want false/0", active, n)
	}
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after flush")
	}
}

// TestPGGateHoldTimeoutDrainAndLatch: PG mirror — no watcher within the
// window → every held message drains with FATAL 28000 + the timeout message
// (SimpleQuery also gets ReadyForQuery), each gets an audit event, and the
// session latches fail-closed (later watchers do not unblock).
func TestPGGateHoldTimeoutDrainAndLatch(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	p.SetGateWaitSeconds(1)
	s, clientPeer, frontPeer := pgHoldSession(t, "sid-pg-hold-timeout")
	defer func() { clientPeer.Close(); frontPeer.Close() }()
	defer p.closePGGateWait(s)

	ev1 := &models.QueryEvent{SQL: "SELECT 1", Username: "hold", SessionID: s.id}
	ev2 := &models.QueryEvent{SQL: "SELECT 2", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev1
	s.mu.Unlock()
	if !p.gatePGHold(&pgproto3.Query{String: "SELECT 1"}, s) {
		t.Fatal("message 1: not held, want queued")
	}
	s.mu.Lock()
	s.pending = ev2
	s.mu.Unlock()
	if !p.gatePGHold(&pgproto3.Query{String: "SELECT 2"}, s) {
		t.Fatal("message 2: not held, want queued")
	}

	// Window expires → drain: per held message ErrorResponse FATAL 28000 +
	// ReadyForQuery (SimpleQuery semantics).
	clFront := pgproto3.NewFrontend(pgproto3.NewChunkReader(clientPeer), io.Discard)
	for i := 0; i < 2; i++ {
		m1, err := clFront.Receive()
		if err != nil {
			t.Fatalf("drain ErrorResponse %d: %v", i+1, err)
		}
		er, ok := m1.(*pgproto3.ErrorResponse)
		if !ok {
			t.Fatalf("drain message %d = %T, want *pgproto3.ErrorResponse", i+1, m1)
		}
		if er.Code != "28000" || er.Severity != "FATAL" || !strings.Contains(er.Message, "no checker connected within 1s") {
			t.Errorf("drain ErrorResponse %d = code %q severity %q message %q, want FATAL 28000 timeout message", i+1, er.Code, er.Severity, er.Message)
		}
		m2, err := clFront.Receive()
		if err != nil {
			t.Fatalf("drain ReadyForQuery %d: %v", i+1, err)
		}
		if _, ok := m2.(*pgproto3.ReadyForQuery); !ok {
			t.Errorf("drain message %d = %T, want *pgproto3.ReadyForQuery", i+1, m2)
		}
	}
	s.gateMu.Lock()
	latched := s.gate.latched
	s.gateMu.Unlock()
	if !latched {
		t.Error("session not latched after PG timeout drain")
	}
	// The wait goroutine finishes the drain (replies → audit events) —
	// wait for it before asserting the events it stamps.
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after PG timeout drain")
	}
	if ev1.Status != "error" || !strings.Contains(ev1.Error, "no checker connected within 1s") {
		t.Errorf("ev1 = status %q error %q, want error + timeout message", ev1.Status, ev1.Error)
	}
	if ev2.Status != "error" || !strings.Contains(ev2.Error, "no checker connected within 1s") {
		t.Errorf("ev2 = status %q error %q, want error + timeout message", ev2.Status, ev2.Error)
	}

	// Fail-closed latch: a later watcher does not unblock.
	if err := vs.SetWatch(context.Background(), s.id, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), s.id) })
	if msg := p.gatePGBlockMsg(&pgproto3.Query{String: "SELECT 3"}, s); !strings.Contains(msg, "no checker connected within 1s") {
		t.Errorf("latched gatePGBlockMsg = %q, want the timeout message", msg)
	}
	if p.gatePGHold(&pgproto3.Query{String: "SELECT 3"}, s) {
		t.Error("latched session: gatePGHold queued, want immediate reject")
	}
}

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
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
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
// timeout message + an audit event, and the session latches fail-closed: a
// watcher attaching LATER does not unblock it.
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

	// FAIL-CLOSED LATCH: even with a watcher attached NOW, the next
	// command is rejected immediately — the maker must reconnect.
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	if err := writeMySQLPacket(rwClient, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	latchedPkt := readMySQLErrPacket(t, rwClient)
	assertMySQLGateErr(t, latchedPkt, sid)
	if !strings.Contains(string(latchedPkt), "no checker connected within 2s") {
		t.Errorf("latched ERR message = %q, want the timeout message", latchedPkt)
	}
	ev = recvQueryEvent(t, userCh)
	if ev.Status != "error" || !strings.Contains(ev.Error, "no checker connected within 2s") {
		t.Errorf("latched audit event = status %q error %q, want error + timeout message", ev.Status, ev.Error)
	}

	// The blocked INSERT never landed.
	roClient := dialTestMySQLSession(t, ln, roToken)
	sel2 := append([]byte{cmdQuery}, "SELECT name FROM demo_items WHERE name = '"+marker+"'"...)
	if err := writeMySQLPacket(roClient, 0, sel2); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	rows, err := readTextResultSet(roClient)
	if err != nil {
		t.Fatalf("read result set: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("drained INSERT landed: %d row(s) for %s, want 0", len(rows), marker)
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
	recvSessionEvent(t, userCh) // started

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
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
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
// the timeout message + an audit event.
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

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}
