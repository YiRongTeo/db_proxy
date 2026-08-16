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

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 9.4: ATTENTION kill-query ----------------------------------------

// TestMSSQLAttentionPacketShape pins the ATTENTION packet bytes: type 0x06,
// EOM status, length 8 (header only — no payload), SPID field (0 by default,
// caller-chosen via writeTDSPacketSPID), packet id 1, window 0. This is the
// shape ODBC/sqlcmd sends on cancel (MS-TDS 2.2.3.1: a single packet with
// no payload).
func TestMSSQLAttentionPacketShape(t *testing.T) {
	var buf bytes.Buffer
	if err := writeTDSPacket(&buf, tdsAttention, nil); err != nil {
		t.Fatalf("write attention: %v", err)
	}
	want := []byte{0x06, 0x01, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("attention packet = % x, want % x (type 0x06, EOM, len 8, no payload)", buf.Bytes(), want)
	}

	buf.Reset()
	if err := writeTDSPacketSPID(&buf, tdsAttention, tdsStatusEOM, 0x0A0B, nil); err != nil {
		t.Fatalf("write attention (spid): %v", err)
	}
	wantSpid := []byte{0x06, 0x01, 0x00, 0x08, 0x0A, 0x0B, 0x01, 0x00}
	if !bytes.Equal(buf.Bytes(), wantSpid) {
		t.Errorf("attention packet (spid) = % x, want % x", buf.Bytes(), wantSpid)
	}
}

// TestMSSQLKillQueryUnknownAndIdleRefusal: KillQuery on an unknown id
// returns false; on a registered but IDLE session (no command in flight) it
// refuses with a warn and writes NOTHING to the backend — the session is
// never touched.
func TestMSSQLKillQueryUnknownAndIdleRefusal(t *testing.T) {
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mssqlSession{id: "sid-attn-idle", client: client, backend: backend}
	bbr := bufio.NewReader(bpeer)
	p.registerSession(s)
	defer p.unregisterSession(s.id)

	if p.KillQuery("sid-no-such-session") {
		t.Fatal("KillQuery on an unknown id returned true")
	}
	if p.KillQuery(s.id) {
		t.Fatal("KillQuery on an idle session returned true")
	}
	_ = bpeer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := readTDSFrame(bbr); err == nil {
		t.Fatal("attention was written on an idle session")
	}
}

// TestMSSQLKillQuerySendsAttention: with a command in flight (the session's
// pending event set), KillQuery writes the ATTENTION packet — header-only,
// SPID from the login response, no payload — on the LIVE backend conn and
// reports true. The session itself is untouched (both conns stay open).
func TestMSSQLKillQuerySendsAttention(t *testing.T) {
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mssqlSession{id: "sid-attn-flight", client: client, backend: backend, spid: 0x1234}
	bbr := bufio.NewReader(bpeer)
	p.registerSession(s)
	defer p.unregisterSession(s.id)
	s.mu.Lock()
	s.pending = &models.QueryEvent{SQL: "WAITFOR DELAY '00:00:30'", SessionID: s.id}
	s.mu.Unlock()

	// The pipe write blocks until a reader consumes it (net.Pipe is
	// synchronous) — drive the kill in a goroutine, read the attention off
	// the backend peer, then assert the verdict.
	killed := make(chan bool, 1)
	go func() { killed <- p.KillQuery(s.id) }()
	hdr, payload, err := readTDSFrame(bbr)
	if err != nil {
		t.Fatalf("read attention off the backend conn: %v", err)
	}
	if !<-killed {
		t.Fatal("KillQuery on an in-flight session returned false")
	}
	want := [8]byte{tdsAttention, tdsStatusEOM, 0x00, 0x08, 0x12, 0x34, 0x01, 0x00}
	if hdr != want {
		t.Errorf("attention header = % x, want % x", hdr, want)
	}
	if len(payload) != 0 {
		t.Errorf("attention payload = % x, want empty", payload)
	}
	// The ack swallow is armed: the backend's DONE_ATTN acknowledgement
	// must be consumed proxy-side, not forwarded to the client.
	s.mu.Lock()
	attn := s.attnPending
	s.mu.Unlock()
	if !attn {
		t.Error("attnPending not armed after KillQuery")
	}
}

// TestMSSQLAttentionAckSwallowed: after a proxy-initiated ATTENTION, the
// backend answers with the aborted batch's DONE_ERROR and then a SEPARATE
// DONE_ATTN acknowledgement message (MS-TDS 2.2.7.10; live capture
// `fd 02 00 …` then `fd 20 00 …`). The relay forwards the DONE_ERROR —
// completing the pending capture as error — and SWALLOWS the ack: the
// client never asked to cancel, and a forwarded ack would corrupt its
// protocol state (its next batch would read the stale ack as its response).
// A client-initiated attention ack (attnPending unset) still passes
// through untouched.
func TestMSSQLAttentionAckSwallowed(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mssqlSession{id: "sid-attn-ack", client: client, backend: backend}
	bbr := bufio.NewReader(bpeer)
	cbr := bufio.NewReader(cpeer)
	// The kill already happened: the ack is outstanding, the aborted
	// batch's event is still pending (its response completes it). The
	// swallow-expiry clock (Task 9.10) starts when KillQuery arms the
	// flag — mirror that here or the expectation expires instantly.
	s.mu.Lock()
	s.attnPending = true
	s.attnAt = time.Now()
	s.pending = &models.QueryEvent{SQL: "WAITFOR DELAY '00:00:30'", SessionID: s.id}
	s.capture = &mssqlResultCapture{}
	s.mu.Unlock()

	relayed := make(chan struct{})
	go func() {
		p.pipeMSSQLBackendToClient(bbr, client, s)
		close(relayed)
	}()

	// Aborted batch response: a bare DONE_ERROR token stream (13 bytes).
	doneErr := make([]byte, 13)
	doneErr[0] = 0xFD
	binary.LittleEndian.PutUint16(doneErr[1:3], tdsDoneError)
	// Attention ack: a bare DONE_ATTN token stream (13 bytes).
	doneAttn := make([]byte, 13)
	doneAttn[0] = 0xFD
	binary.LittleEndian.PutUint16(doneAttn[1:3], tdsDoneAttn)
	// net.Pipe writes block until the relay consumes them — sequence each
	// backend message so the relay is always ready to read it.
	if err := writeTDSPacket(backend, tdsTabular, doneErr); err != nil {
		t.Fatalf("backend write: %v", err)
	}

	// The client sees ONLY the aborted batch's DONE_ERROR.
	typ, got, err := readTDSMessage(cbr)
	if err != nil || typ != tdsTabular {
		t.Fatalf("client read: typ=%#x err=%v", typ, err)
	}
	if !bytes.Equal(got, doneErr) {
		t.Fatalf("client got % x, want the DONE_ERROR stream % x", got, doneErr)
	}
	// Now the ack: the relay has looped back to its read.
	if err := writeTDSPacket(backend, tdsTabular, doneAttn); err != nil {
		t.Fatalf("backend write: %v", err)
	}
	// The ack must NOT reach the client: nothing further arrives.
	_ = cpeer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := readTDSMessage(cbr); err == nil {
		t.Fatal("client received a second message — the DONE_ATTN ack was not swallowed")
	}
	_ = cpeer.SetReadDeadline(time.Time{}) // clear the probe deadline
	// ...and the pending flag is cleared.
	s.mu.Lock()
	attn := s.attnPending
	s.mu.Unlock()
	if attn {
		t.Error("attnPending still set after the ack was swallowed")
	}

	// Client-initiated attention (flag unset): the ack passes through.
	s.mu.Lock()
	s.attnPending = false
	s.mu.Unlock()
	if err := writeTDSPacket(backend, tdsTabular, doneAttn); err != nil {
		t.Fatalf("backend write: %v", err)
	}
	typ, got, err = readTDSMessage(cbr)
	if err != nil || typ != tdsTabular {
		t.Fatalf("client read (client-initiated ack): typ=%#x err=%v", typ, err)
	}
	if !bytes.Equal(got, doneAttn) {
		t.Fatalf("client got % x, want the DONE_ATTN stream % x", got, doneAttn)
	}
	bpeer.Close() // unblock the relay's read so it can exit
	<-relayed
}

// --- Task 9.4: write-gate decision on the TDS plane ------------------------

// TestMSSQLGateDecision: the maker write-gate applies ONLY to SQL-executing
// TDS messages (SQL batch 0x01, RPC 0x03) on write-access sessions.
// Control types (ATTENTION, LOGOUT, prelogin, login7, tabular) never gate;
// read-access sessions are exempt; a present watch:<sid> passes; removing
// the watcher re-blocks the NEXT message (per-command decision, no latch).
func TestMSSQLGateDecision(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := &mssqlSession{id: "sid-gate-decision", access: "write"}
	cleanupLiveRecord(t, vs, s.id)
	ctx := context.Background()

	// Write access + SQL-executing types: blocked while unwatched.
	for _, typ := range []byte{tdsSQLBatch, tdsRPC} {
		if msg := p.gateMSSQLBlocked(s, typ); msg == "" {
			t.Errorf("typ 0x%02x unwatched: not blocked, want the gating message", typ)
		}
	}
	// Control types are never gated.
	for _, typ := range []byte{tdsAttention, tdsTabular, tdsLogin7, tdsPrelogin, 0x0E} {
		if msg := p.gateMSSQLBlocked(s, typ); msg != "" {
			t.Errorf("typ 0x%02x gated: %q, want pass", typ, msg)
		}
	}
	// Read-access session: exempt even for SQL batches.
	ro := &mssqlSession{id: "sid-gate-ro", access: "read"}
	if msg := p.gateMSSQLBlocked(ro, tdsSQLBatch); msg != "" {
		t.Errorf("read-access batch gated: %q, want pass", msg)
	}
	// Watcher present → pass.
	if err := vs.SetWatchConn(ctx, s.id, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(ctx, s.id) })
	if msg := p.gateMSSQLBlocked(s, tdsSQLBatch); msg != "" {
		t.Errorf("watched batch blocked: %q, want pass", msg)
	}
	// Watcher removed mid-session → the NEXT message is blocked again.
	_ = vs.DelWatch(ctx, s.id)
	if msg := p.gateMSSQLBlocked(s, tdsSQLBatch); msg == "" {
		t.Error("unwatched batch after watcher removal: not blocked, want fail-closed")
	}
}

// TestMSSQLGateRejectResponseShape: the immediate reject answers the client
// with a TABULAR stream whose ERROR token carries the gating message and
// whose DONE tail has the DONE_ERROR bit — the shape sqlcmd renders as
// "Msg 18456, Level 14, State 1: maker gating: ...".
func TestMSSQLGateRejectResponseShape(t *testing.T) {
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	defer func() { cpeer.Close(); client.Close() }()
	s := &mssqlSession{id: "sid-gate-shape", access: "write", client: client} // pending nil → no audit publish
	cbr := bufio.NewReader(cpeer)

	msg := gatingMessage(s.id)
	// The reject's client write blocks until a reader consumes it (net.Pipe
	// is synchronous) — drive it in a goroutine, then read the response.
	rejected := make(chan struct{})
	go func() { p.gateMSSQLReject(client, s, msg); close(rejected) }()

	typ, resp, err := readTDSMessage(cbr)
	if err != nil || typ != tdsTabular {
		t.Fatalf("reject response: typ=%#x err=%v", typ, err)
	}
	<-rejected
	if got := extractErrorMsg(resp); got != msg {
		t.Errorf("reject MsgText = %q, want %q", got, msg)
	}
	if !mssqlResponseError(resp) {
		t.Errorf("reject response has no ERROR/DONE_ERROR: % x", resp)
	}
}

// --- Task 9.4: message assembly ---------------------------------------------

// TestMSSQLReadTDSMessageFrames: a multi-packet message assembles into its
// raw frames in order (headers verbatim, EOM on the last) with the message
// type — the relay gates and forwards per MESSAGE without losing
// byte-exactness.
func TestMSSQLReadTDSMessageFrames(t *testing.T) {
	p1, p2 := []byte("first-fragment"), []byte("second-fragment")
	var wire bytes.Buffer
	if err := writeTDSPacketSPID(&wire, tdsSQLBatch, 0, 0, p1); err != nil {
		t.Fatalf("write frame 1: %v", err)
	}
	if err := writeTDSPacketSPID(&wire, tdsSQLBatch, tdsStatusEOM, 0, p2); err != nil {
		t.Fatalf("write frame 2: %v", err)
	}
	frames, typ, err := readTDSMessageFrames(bufio.NewReader(&wire))
	if err != nil {
		t.Fatalf("readTDSMessageFrames: %v", err)
	}
	if typ != tdsSQLBatch || len(frames) != 2 {
		t.Fatalf("typ=%#x frames=%d, want 0x01/2", typ, len(frames))
	}
	if frames[0].hdr[1]&tdsStatusEOM != 0 {
		t.Error("frame 1 carries EOM, want clear (more fragments follow)")
	}
	if frames[1].hdr[1]&tdsStatusEOM == 0 {
		t.Error("frame 2 lacks EOM, want set")
	}
	if !bytes.Equal(frames[0].payload, p1) || !bytes.Equal(frames[1].payload, p2) {
		t.Errorf("frame payloads = %q / %q, want %q / %q (byte-exact)", frames[0].payload, frames[1].payload, p1, p2)
	}
}

// --- Task 9.4: relay-level gate wiring --------------------------------------

// TestMSSQLRelayGateBlocksAndPassesControl: end-to-end through the relay
// pipe: an unwatched write-access INSERT batch is answered to the CLIENT
// with the gating ERROR and never reaches the backend; an ATTENTION packet
// passes through byte-exact.
func TestMSSQLRelayGateBlocksAndPassesControl(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	// net.Pipe ends: `client` is the proxy's conn (what handleConn would
	// hold), `cpeer` is the real client's end — the test writes commands on
	// cpeer and reads the proxy's replies from it (full duplex).
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	cbr := bufio.NewReader(cpeer)
	bbr := bufio.NewReader(bpeer)
	s := &mssqlSession{id: "sid-relay-gate", access: "write", client: client, backend: backend}
	cleanupLiveRecord(t, vs, s.id)
	// Registered FIRST → runs LAST: closeMSSQLGateWait drains (best-effort
	// writes) only after the pipe peers are closed, so its replies error
	// out instead of blocking on the unread net.Pipe.
	defer p.closeMSSQLGateWait(s)
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()

	done := make(chan struct{})
	go func() {
		p.pipeMSSQLClientToBackend(bufio.NewReader(client), backend, client, s,
			&models.TokenPayload{Username: "relay-gate"}, "unit")
		close(done)
	}()

	// Unwatched INSERT batch → gate ERROR to the client, silence to the backend.
	payload := append(append([]byte(nil), allHeaders22...), utf16le("INSERT INTO demo_items (id, name) VALUES (1, 'x')")...)
	if err := writeTDSPacket(cpeer, tdsSQLBatch, payload); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	typ, resp, err := readTDSMessage(cbr)
	if err != nil || typ != tdsTabular {
		t.Fatalf("gate response: typ=%#x err=%v", typ, err)
	}
	if msg := extractErrorMsg(resp); !strings.Contains(msg, "maker gating") {
		t.Errorf("gate error message = %q, want the gating message", msg)
	}
	_ = bpeer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := readTDSFrame(bbr); err == nil {
		t.Fatal("blocked batch reached the backend")
	}
	_ = bpeer.SetReadDeadline(time.Time{}) // the silence probe consumed its deadline

	// ATTENTION (0x06) is a control type: it passes through byte-exact.
	attn := []byte{0x06, 0x01, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00}
	if _, err := cpeer.Write(attn); err != nil {
		t.Fatalf("write attention: %v", err)
	}
	got, _, err := readTDSFrame(bbr)
	if err != nil {
		t.Fatalf("read attention off the backend: %v", err)
	}
	if !bytes.Equal(got[:], attn) {
		t.Errorf("relayed attention = % x, want % x (byte-exact)", got, attn)
	}

	cpeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit after the client closed")
	}
}

// --- Task 9.4: grace hold (8.13/8.17 semantics on the TDS plane) -----------

// holdMSSQLProxy builds an MSSQLProxy with the grace window configured.
func holdMSSQLProxy(t *testing.T, vs *store.ValkeyStore, seconds int) *MSSQLProxy {
	t.Helper()
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	p.SetGateWaitSeconds(seconds)
	return p
}

// mssqlTestFrames builds the raw frames of a SQL batch message carrying sql.
func mssqlTestFrames(sql string) []mssqlGateFrame {
	payload := append(append([]byte(nil), allHeaders22...), utf16le(sql)...)
	var hdr [8]byte
	hdr[0] = tdsSQLBatch
	hdr[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(hdr[2:4], uint16(tdsHeaderLen+len(payload)))
	hdr[6] = 1
	return []mssqlGateFrame{{hdr: hdr, payload: payload}}
}

// TestMSSQLGateHoldQueueBounds: up to gateQueueMax messages queue while no
// watcher is attached; the NEXT message (overflow) is NOT queued — the
// caller rejects it immediately — and the queue keeps waiting.
func TestMSSQLGateHoldQueueBounds(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMSSQLProxy(t, vs, 60)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &mssqlSession{id: "sid-hold-bounds", access: "write", client: client, backend: backend}
	cleanupLiveRecord(t, vs, s.id)
	defer p.closeMSSQLGateWait(s)
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()

	for i := 0; i < gateQueueMax; i++ {
		s.mu.Lock()
		s.pending = &models.QueryEvent{SQL: fmt.Sprintf("SELECT %d", i), Username: "hold", SessionID: s.id}
		s.mu.Unlock()
		if !p.gateMSSQLHold(s, mssqlTestFrames(fmt.Sprintf("SELECT %d", i)), false) {
			t.Fatalf("message %d: not held, want queued", i+1)
		}
	}
	s.mu.Lock()
	s.pending = &models.QueryEvent{SQL: "SELECT overflow", Username: "hold", SessionID: s.id}
	s.mu.Unlock()
	if p.gateMSSQLHold(s, mssqlTestFrames("SELECT overflow"), false) {
		t.Error("17th message: held, want immediate reject (queue overflow)")
	}
	s.gateMu.Lock()
	active, n := s.gate.active, len(s.gate.queue)
	s.gateMu.Unlock()
	if !active || n != gateQueueMax {
		t.Errorf("after overflow: active=%v queue=%d, want true/%d (queue keeps waiting)", active, n, gateQueueMax)
	}
}

// TestMSSQLGateHoldFlushOrder: held messages flush IN ORDER — each frame
// forwarded byte-exact (original header + payload) exactly as the normal
// forward path writes it.
func TestMSSQLGateHoldFlushOrder(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMSSQLProxy(t, vs, 60)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	bbr := bufio.NewReader(bpeer)
	s := &mssqlSession{id: "sid-hold-order", access: "write", client: client, backend: backend}
	cleanupLiveRecord(t, vs, s.id)
	defer p.closeMSSQLGateWait(s)
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()

	sqls := []string{"SELECT 'first'", "SELECT 'second'", "SELECT 'third'"}
	frames := make([][]mssqlGateFrame, len(sqls))
	for i, sql := range sqls {
		s.mu.Lock()
		s.pending = &models.QueryEvent{SQL: sql, Username: "hold", SessionID: s.id}
		s.mu.Unlock()
		frames[i] = mssqlTestFrames(sql)
		if !p.gateMSSQLHold(s, frames[i], false) {
			t.Fatalf("message %d: not held, want queued", i+1)
		}
	}
	// Watcher arrives → flush (driven directly here; the ticker path is
	// proven end-to-end by the LIVE held-then-run test).
	go p.gateMSSQLFlush(s)
	for i, want := range frames {
		hdr, payload, err := readTDSFrame(bbr)
		if err != nil {
			t.Fatalf("flush frame %d: %v", i+1, err)
		}
		if !bytes.Equal(hdr[:], want[0].hdr[:]) || !bytes.Equal(payload, want[0].payload) {
			t.Errorf("flush frame %d = hdr % x payload % x, want byte-exact % x / % x",
				i+1, hdr, payload, want[0].hdr, want[0].payload)
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

// TestMSSQLGateHoldTimeoutDrain: no watcher within the window → every held
// message is drained with the sqlcmd-readable ERROR token + the timeout
// message, each gets an audit event (status=error, "no checker connected
// within <N>s").
func TestMSSQLGateHoldTimeoutDrain(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMSSQLProxy(t, vs, 1)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	cbr := bufio.NewReader(cpeer)
	s := &mssqlSession{id: "sid-hold-timeout", access: "write", client: client, backend: backend}
	cleanupLiveRecord(t, vs, s.id)
	defer p.closeMSSQLGateWait(s)
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()

	ev1 := &models.QueryEvent{SQL: "SELECT 1", Username: "hold", SessionID: s.id}
	ev2 := &models.QueryEvent{SQL: "SELECT 2", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev1
	s.mu.Unlock()
	if !p.gateMSSQLHold(s, mssqlTestFrames("SELECT 1"), false) {
		t.Fatal("message 1: not held, want queued")
	}
	s.mu.Lock()
	s.pending = ev2
	s.mu.Unlock()
	if !p.gateMSSQLHold(s, mssqlTestFrames("SELECT 2"), false) {
		t.Fatal("message 2: not held, want queued")
	}

	// The window expires with no watcher → both held messages drain.
	for i := 0; i < 2; i++ {
		typ, payload, err := readTDSMessage(cbr)
		if err != nil || typ != tdsTabular {
			t.Fatalf("drain response %d: typ=%#x err=%v", i+1, typ, err)
		}
		if msg := extractErrorMsg(payload); !strings.Contains(msg, "no checker connected within 1s") {
			t.Errorf("drain ERROR %d = %q, want timeout message naming the window", i+1, msg)
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
	if ev1.Status != "error" || !strings.Contains(ev1.Error, "no checker connected within 1s") {
		t.Errorf("ev1 = status %q error %q, want error + timeout message", ev1.Status, ev1.Error)
	}
	if ev2.Status != "error" || !strings.Contains(ev2.Error, "no checker connected within 1s") {
		t.Errorf("ev2 = status %q error %q, want error + timeout message", ev2.Status, ev2.Error)
	}
}

// TestMSSQLGateHoldZeroWait: gate_wait_seconds=0 keeps the pre-8.13
// behavior — a blocked message is never queued; the caller rejects it
// immediately.
func TestMSSQLGateHoldZeroWait(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMSSQLProxy(t, vs, 0) // 0 = reject immediately (old behavior)
	s := &mssqlSession{id: "sid-hold-zero", access: "write"}
	cleanupLiveRecord(t, vs, s.id)
	defer p.closeMSSQLGateWait(s)

	if msg := p.gateMSSQLBlocked(s, tdsSQLBatch); msg == "" {
		t.Fatal("unwatched batch: not blocked, want the gating message")
	}
	if p.gateMSSQLHold(s, mssqlTestFrames("SELECT 1"), false) {
		t.Error("gate_wait_seconds=0: message held, want immediate reject")
	}
}

// TestMSSQLGateHoldReopensAfterWatch (Task 8.17 on the TDS plane): a
// timeout drain does NOT latch the session. Post-drain, an unwatched
// message is blocked again and starts a FRESH grace wait (drained when the
// new window expires); when a watcher re-attaches, the gate re-opens — the
// next message's check passes and a held message flushes to the backend
// byte-exact (no reconnect).
func TestMSSQLGateHoldReopensAfterWatch(t *testing.T) {
	vs := proxyTestStore(t)
	p := holdMSSQLProxy(t, vs, 1)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	cbr := bufio.NewReader(cpeer)
	bbr := bufio.NewReader(bpeer)
	s := &mssqlSession{id: "sid-hold-reopen", access: "write", client: client, backend: backend}
	cleanupLiveRecord(t, vs, s.id)
	defer p.closeMSSQLGateWait(s)
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()

	// First cycle: unwatched message → held → drained when the window
	// expires (ERROR token + timeout message + audit event).
	ev1 := &models.QueryEvent{SQL: "SELECT 1", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev1
	s.mu.Unlock()
	if !p.gateMSSQLHold(s, mssqlTestFrames("SELECT 1"), false) {
		t.Fatal("message 1: not held, want queued")
	}
	typ, payload, err := readTDSMessage(cbr)
	if err != nil || typ != tdsTabular {
		t.Fatalf("drain response: typ=%#x err=%v", typ, err)
	}
	if msg := extractErrorMsg(payload); !strings.Contains(msg, "no checker connected within 1s") {
		t.Errorf("drain ERROR = %q, want the timeout message", msg)
	}
	gateWaitJoined(t, &s.gate.wg)

	// Post-drain, STILL unwatched: the next message is blocked again and
	// starts a FRESH grace wait (no latch) — drained when the new window
	// expires, with its own audit event.
	ev2 := &models.QueryEvent{SQL: "SELECT 2", Username: "hold", SessionID: s.id}
	s.mu.Lock()
	s.pending = ev2
	s.mu.Unlock()
	if msg := p.gateMSSQLBlocked(s, tdsSQLBatch); msg == "" {
		t.Error("post-drain unwatched message passed the gate, want blocked")
	}
	if !p.gateMSSQLHold(s, mssqlTestFrames("SELECT 2"), false) {
		t.Fatal("post-drain message: not held, want a fresh grace wait (no latch)")
	}
	typ, payload, err = readTDSMessage(cbr)
	if err != nil || typ != tdsTabular {
		t.Fatalf("second drain response: typ=%#x err=%v", typ, err)
	}
	if msg := extractErrorMsg(payload); !strings.Contains(msg, "no checker connected within 1s") {
		t.Errorf("second drain ERROR = %q, want the timeout message", msg)
	}
	gateWaitJoined(t, &s.gate.wg)
	if ev2.Status != "error" || !strings.Contains(ev2.Error, "no checker connected within 1s") {
		t.Errorf("ev2 = status %q error %q, want error + timeout message (audit published)", ev2.Status, ev2.Error)
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
	if msg := p.gateMSSQLBlocked(s, tdsSQLBatch); msg != "" {
		t.Errorf("watched gateMSSQLBlocked = %q, want \"\" (gate re-opened)", msg)
	}
	frames := mssqlTestFrames("SELECT 3")
	s.mu.Lock()
	s.pending = &models.QueryEvent{SQL: "SELECT 3", Username: "hold", SessionID: s.id}
	s.mu.Unlock()
	// gateMSSQLHold flushes synchronously when the watcher re-check hits
	// (the backend write blocks until the peer reads) — drive it in a
	// goroutine, then read the flushed bytes.
	held := make(chan bool, 1)
	go func() { held <- p.gateMSSQLHold(s, frames, false) }()
	hdr, got, err := readTDSFrame(bbr)
	if err != nil {
		t.Fatalf("flush frame: %v", err)
	}
	if !<-held {
		t.Fatal("watched message: not held, want queued (flush path)")
	}
	if !bytes.Equal(hdr[:], frames[0].hdr[:]) || !bytes.Equal(got, frames[0].payload) {
		t.Errorf("flush frame = hdr % x payload % x, want byte-exact % x / % x", hdr, got, frames[0].hdr, frames[0].payload)
	}
	gateWaitJoined(t, &s.gate.wg)
}

// mssqlResponseError scans a TABULAR payload's token stream and reports
// whether it carries an error: an ERROR token (0xAA) or a DONE-family token
// with the DONE_ERROR status bit. Used by the kill-query and gating live
// tests to recognize abort/reject responses (the abort response is
// ERROR + DONE — no result-set tokens).
func mssqlResponseError(payload []byte) bool {
	pos := 0
	for pos < len(payload) {
		t := payload[pos]
		switch t {
		case 0xAA: // ERROR token
			return true
		case 0xAB, 0xAD, 0xAE, 0xE3, 0xE4: // other length-prefixed tokens
			if pos+3 > len(payload) {
				return false
			}
			l := int(binary.LittleEndian.Uint16(payload[pos+1 : pos+3]))
			if pos+3+l > len(payload) {
				return false
			}
			pos += 3 + l
		case 0xFD, 0xFE, 0xFF: // DONE family — 13-byte tail
			if pos+13 > len(payload) {
				return false
			}
			if binary.LittleEndian.Uint16(payload[pos+1:pos+3])&tdsDoneError != 0 {
				return true
			}
			pos += 13
		default: // result-set content (COLMETADATA/ROW/...) — not an error
			return false
		}
	}
	return false
}
