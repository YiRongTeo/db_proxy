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

// --- Task 8.13/8.17: gate grace hold + re-open on watch -------------------
// While a write session has NO watcher, blocked SQL commands WAIT up to
// gate_wait_seconds for a checker instead of failing instantly (maker-first
// connects no longer break): the watcher's arrival flushes the queue in
// order; the window's expiry drains it (1045/28000 + audit events). A drain
// does NOT latch the session (Task 8.17): unwatched commands keep getting
// the grace wait + drain, and a re-attached watcher re-opens the gate — the
// maker's next command flows without reconnecting.

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
// caller rejects it immediately — and the queue keeps waiting.
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
	active, n := s.gate.active, len(s.gate.queue)
	s.gateMu.Unlock()
	if !active || n != gateQueueMax {
		t.Errorf("after overflow: active=%v queue=%d, want true/%d (queue keeps waiting)",
			active, n, gateQueueMax)
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
// audit event (status=error, "no checker connected within <N>s"). The drain
// does NOT latch the session (Task 8.17) — the reopen test below covers the
// re-attach path.
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
	active, n := s.gate.active, len(s.gate.queue)
	s.gateMu.Unlock()
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

// --- unit: gate re-opens on watcher re-attach ------------------------------

// TestMySQLGateHoldReopensAfterWatch (Task 8.17): a timeout drain does NOT
// latch the session. Post-drain, an unwatched command is blocked again and
// starts a FRESH grace wait (queued, then drained with ERR 1045 + its own
// audit event when the new window expires); when a watcher re-attaches, the
// gate re-opens — the next command's check passes and a held command flushes
// to the backend byte-exact (no reconnect).
func TestMySQLGateHoldReopensAfterWatch(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMySQLProxy(t, vs, 1)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &mysqlSession{id: "sid-hold-reopen", access: "write", client: client, backend: backend}
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	defer p.closeGateWait(s)

	// First cycle: unwatched command → held → drained when the window
	// expires (ERR 1045 + timeout message + audit event).
	ev1 := &models.QueryEvent{SQL: "SELECT 1", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev1
	s.mu.Unlock()
	if !p.gateHold(s, 0, []byte{cmdQuery, '1'}) {
		t.Fatal("command 1: not held, want queued")
	}
	if pkt := readMySQLErrPacket(t, cpeer); !strings.Contains(string(pkt), "no checker connected within 1s") {
		t.Errorf("drain ERR = %q, want the timeout message", pkt)
	}
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after the first drain")
	}

	// Post-drain, STILL unwatched: the next command is blocked again and
	// starts a FRESH grace wait (no latch) — drained when the new window
	// expires, with its own audit event.
	ev2 := &models.QueryEvent{SQL: "SELECT 2", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev2
	s.mu.Unlock()
	if msg := p.checkWriteGate(s, cmdQuery); msg == "" {
		t.Error("post-drain unwatched command passed the gate, want blocked")
	}
	if !p.gateHold(s, 0, []byte{cmdQuery, '2'}) {
		t.Fatal("post-drain command: not held, want a fresh grace wait (no latch)")
	}
	if pkt := readMySQLErrPacket(t, cpeer); !strings.Contains(string(pkt), "no checker connected within 1s") {
		t.Errorf("second drain ERR = %q, want the timeout message", pkt)
	}
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after the second drain")
	}
	if ev2.Status != "error" || !strings.Contains(ev2.Error, "no checker connected within 1s") {
		t.Errorf("ev2 = status %q error %q, want error + timeout message (audit published)", ev2.Status, ev2.Error)
	}

	// Watcher re-attaches → the gate re-opens: the next command's gate
	// check PASSES (same session, no reconnect) and a held command flushes
	// to the backend byte-exact. The window is widened to 60s first so the
	// flush phase cannot race the drain timer (the gate re-evaluates per
	// command — the widened window only affects NEW waits).
	p.SetGateWaitSeconds(60)
	if err := vs.SetWatch(context.Background(), s.id, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), s.id) })
	if msg := p.checkWriteGate(s, cmdQuery); msg != "" {
		t.Errorf("watched checkWriteGate = %q, want \"\" (gate re-opened)", msg)
	}
	payload := []byte{cmdQuery, '3'}
	s.mu.Lock()
	s.pending = &models.QueryEvent{SQL: "SELECT 3", Username: "hold", SessionID: s.id}
	s.mu.Unlock()
	// gateHold flushes synchronously when the watcher re-check hits (the
	// backend write blocks until the peer reads) — drive it in a goroutine,
	// then read the flushed bytes.
	held := make(chan bool, 1)
	go func() { held <- p.gateHold(s, 0, payload) }()
	seq, got, err := readMySQLPacket(bpeer)
	if err != nil {
		t.Fatalf("flush packet: %v", err)
	}
	if !<-held {
		t.Fatal("watched command: not held, want queued (flush path)")
	}
	if seq != 0 || !bytes.Equal(got, payload) {
		t.Errorf("flush packet seq=%d payload=% x, want seq 0 payload % x (byte-exact)", seq, got, payload)
	}
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after the re-attach flush")
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
	active, n := s.gate.active, len(s.gate.queue)
	s.gateMu.Unlock()
	if active || n != 0 {
		t.Errorf("after close: active=%v queue=%d, want false/0", active, n)
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

// TestPGGateHoldTimeoutDrainAndReopens (Task 8.17): PG mirror — no watcher
// within the window → every held message drains with FATAL 28000 + the
// timeout message (SimpleQuery also gets ReadyForQuery), each gets an audit
// event, and the session is NOT latched: a still-unwatched command starts a
// fresh grace wait (drained again with its own audit event), and a
// re-attached watcher makes the next message flow — no reconnect.
func TestPGGateHoldTimeoutDrainAndReopens(t *testing.T) {
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

	// expectDrain consumes one full drain response for each currently held
	// message: ErrorResponse FATAL 28000 + ReadyForQuery (SimpleQuery
	// semantics) per message.
	clFront := pgproto3.NewFrontend(pgproto3.NewChunkReader(clientPeer), io.Discard)
	expectDrain := func(held int) {
		t.Helper()
		for i := 0; i < held; i++ {
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
	}
	// Window expires → drain both held messages.
	expectDrain(2)
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

	// No latch: post-drain, an unwatched message is blocked again and
	// starts a FRESH grace wait (drained when its window expires).
	ev3 := &models.QueryEvent{SQL: "SELECT 3", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev3
	s.mu.Unlock()
	if msg := p.gatePGBlockMsg(&pgproto3.Query{String: "SELECT 3"}, s); msg == "" {
		t.Error("post-drain unwatched message passed the gate, want blocked")
	}
	if !p.gatePGHold(&pgproto3.Query{String: "SELECT 3"}, s) {
		t.Fatal("post-drain message: not held, want a fresh grace wait (no latch)")
	}
	expectDrain(1)
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after the second PG drain")
	}
	if ev3.Status != "error" || !strings.Contains(ev3.Error, "no checker connected within 1s") {
		t.Errorf("ev3 = status %q error %q, want error + timeout message (audit published)", ev3.Status, ev3.Error)
	}

	// Watcher re-attaches → the gate re-opens: the next message's gate
	// check PASSES (same session, no reconnect) and a held message flushes
	// to the backend byte-exact. The window is widened to 60s first so the
	// flush phase cannot race the drain timer (the gate re-evaluates per
	// message — the widened window only affects NEW waits).
	p.SetGateWaitSeconds(60)
	if err := vs.SetWatch(context.Background(), s.id, time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), s.id) })
	if msg := p.gatePGBlockMsg(&pgproto3.Query{String: "SELECT 4"}, s); msg != "" {
		t.Errorf("watched gatePGBlockMsg = %q, want \"\" (gate re-opened)", msg)
	}
	m5 := &pgproto3.Query{String: "SELECT 5"}
	s.mu.Lock()
	s.pending = &models.QueryEvent{SQL: "SELECT 5", Username: "hold", SessionID: s.id}
	s.mu.Unlock()
	want, _ := m5.Encode(nil)
	buf := make([]byte, len(want))
	// gatePGHold flushes synchronously when the watcher re-check hits (the
	// backend write blocks until the peer reads) — drive it in a goroutine,
	// then read the flushed bytes.
	held := make(chan bool, 1)
	go func() { held <- p.gatePGHold(m5, s) }()
	if _, err := io.ReadFull(frontPeer, buf); err != nil {
		t.Fatalf("flush message: %v", err)
	}
	if !<-held {
		t.Fatal("watched message: not held, want queued (flush path)")
	}
	if !bytes.Equal(buf, want) {
		t.Errorf("flush message = % x, want % x (byte-exact)", buf, want)
	}
	select {
	case <-s.gate.done:
	case <-time.After(2 * time.Second):
		t.Error("wait goroutine did not exit after the re-attach flush")
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
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
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

	// (a) Watcher present → queries run.
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
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
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
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
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
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

	// (a) Watcher present → queries run.
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
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
	if err := vs.SetWatch(ctx, sid, time.Minute); err != nil {
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
