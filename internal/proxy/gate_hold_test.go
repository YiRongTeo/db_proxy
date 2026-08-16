package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
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

// cleanupLiveRecord removes a fake gate session's sess:live directory entry
// at test end. The gate fakes never call finishSession — the real teardown
// that deletes the record — so every publishEvent they drive (drain audits
// re-arm the heartbeat via SetSessionLive, sessionLiveTTL=60s) leaves a
// sess:live:<sid> record behind for a full TTL. `go test ./...` runs
// package binaries in PARALLEL, so internal/store's TestListSessionsEmpty
// (clear-then-list on the shared dev Valkey) races those lingering records.
// Registered for EVERY fake session so no future gate test can leak one
// (DelSessionLive on an absent key is a no-op).
//
// Round-11 race fix: the DEL cannot be a single shot. For a REAL session
// whose handleConn goroutine is still tearing down when the cleanup runs
// (the conn-close cleanups registered before this one run AFTER it — LIFO),
// the teardown defers publish one final event — flushPendingOnClose re-arms
// sess:live:<sid> via SetSessionLive BEFORE finishSession deletes it — so
// the record can reappear moments after the first DEL. Settle past that
// teardown (the re-arm + finishSession DEL complete within milliseconds of
// the conn close), then DEL again: whatever the ordering, the key is gone by
// the time the next test — or a parallel package binary — scans the
// directory. For fake sessions the second DEL is a cheap no-op.
func cleanupLiveRecord(t *testing.T, vs *store.ValkeyStore, sid string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		_ = vs.DelSessionLive(ctx, sid)
		time.Sleep(200 * time.Millisecond)
		_ = vs.DelSessionLive(ctx, sid)
	})
}

// gateWaitJoined waits (with a 2s timeout) for the session's gate wait
// goroutine to exit — the Task 9.10 replacement for the removed done
// channel: the wait goroutine is joined via the gate state's WaitGroup
// (closeGateWait wg.Wait), so tests wait on the same join.
func gateWaitJoined(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("gate wait goroutine did not exit (2s timeout)")
	}
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
	cleanupLiveRecord(t, vs, s.id)
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
	cleanupLiveRecord(t, vs, s.id)
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
	gateWaitJoined(t, &s.gate.wg)
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
	cleanupLiveRecord(t, vs, s.id)
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
	gateWaitJoined(t, &s.gate.wg)
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
	cleanupLiveRecord(t, vs, s.id)
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
	gateWaitJoined(t, &s.gate.wg)

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
	gateWaitJoined(t, &s.gate.wg)
	if ev2.Status != "error" || !strings.Contains(ev2.Error, "no checker connected within 1s") {
		t.Errorf("ev2 = status %q error %q, want error + timeout message (audit published)", ev2.Status, ev2.Error)
	}

	// Watcher re-attaches → the gate re-opens: the next command's gate
	// check PASSES (same session, no reconnect) and a held command flushes
	// to the backend byte-exact. The window is widened to 60s first so the
	// flush phase cannot race the drain timer (the gate re-evaluates per
	// command — the widened window only affects NEW waits).
	p.SetGateWaitSeconds(60)
	if err := vs.SetWatchConn(context.Background(), s.id, "test-conn", time.Minute); err != nil {
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
	gateWaitJoined(t, &s.gate.wg)
}

// --- unit: gate_wait_seconds=0 ---------------------------------------------

// TestMySQLGateHoldZeroWait: gate_wait_seconds=0 keeps the pre-8.13
// behavior — a blocked command is never queued; the caller rejects it
// immediately (the existing 8.6 matrix covers the reject path).
func TestMySQLGateHoldZeroWait(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMySQLProxy(t, vs, 0) // 0 = reject immediately (old behavior)
	s := &mysqlSession{id: "sid-hold-zero", access: "write"}
	cleanupLiveRecord(t, vs, s.id)
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
	cleanupLiveRecord(t, vs, s.id)
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
	gateWaitJoined(t, &s.gate.wg)
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
	cleanupLiveRecord(t, vs, s.id)
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
	gateWaitJoined(t, &s.gate.wg)
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
	cleanupLiveRecord(t, vs, s.id)
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
	gateWaitJoined(t, &s.gate.wg)
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
	gateWaitJoined(t, &s.gate.wg)
	if ev3.Status != "error" || !strings.Contains(ev3.Error, "no checker connected within 1s") {
		t.Errorf("ev3 = status %q error %q, want error + timeout message (audit published)", ev3.Status, ev3.Error)
	}

	// Watcher re-attaches → the gate re-opens: the next message's gate
	// check PASSES (same session, no reconnect) and a held message flushes
	// to the backend byte-exact. The window is widened to 60s first so the
	// flush phase cannot race the drain timer (the gate re-evaluates per
	// message — the widened window only affects NEW waits).
	p.SetGateWaitSeconds(60)
	if err := vs.SetWatchConn(context.Background(), s.id, "test-conn", time.Minute); err != nil {
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
	gateWaitJoined(t, &s.gate.wg)
}
