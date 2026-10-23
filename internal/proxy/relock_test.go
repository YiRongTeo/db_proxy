package proxy

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
)

// --- Task 9 (node-integration): the rw RE-LOCK -------------------------------
//
// An ADMITTED rw session re-freezes when the last checker leaves: the
// control-plane hub publishes {"action":"relock","session_id":...} on the
// ctl:relock channel; the data plane sets a per-session frozen flag (rw
// sessions only); while frozen EVERY client→backend message is answered with
// the dialect's gating error and NOT forwarded; on the next
// WatchActive(sid)==true the session unfreezes (the re-admission poll uses
// the hold's rwHoldPollInterval). Flag rw_relock_on_watch_loss (default
// TRUE) disables the whole feature. Oracle NEVER relocks (no hold point).

// TestMySQLRelockFreezesSession (Task 9 brief test c): HandleRelock on a
// live rw session freezes it — the NEXT query gets the well-formed gating
// ERR 1045 and the backend NEVER sees it.
func TestMySQLRelockFreezesSession(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	cbr := bufio.NewReader(cpeer)
	bbr := bufio.NewReader(bpeer)
	sid := "sid-relock-freeze"
	s := &mysqlSession{id: sid, access: "rw", holdAdmitted: true, client: client, backend: backend,
		tok: &models.TokenPayload{Username: "relock-maker", DBUser: "rw_user", DBType: "mysql", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(ctx, sid)
		cpeer.Close()
		bpeer.Close()
		client.Close()
		backend.Close()
	})
	p.registerSession(s)

	// Drive the REAL client→backend relay pipe (as the session would): the
	// freeze blocks inside the loop, so the pipe never deadlocks a lone
	// test goroutine.
	done := make(chan struct{})
	go func() {
		p.pipeClientToBackend(bufio.NewReader(client), backend, client, s, s.tok, "relock-test")
		close(done)
	}()

	// Freeze via the ctl:relock payload (exactly what the hub publishes).
	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Fatal("HandleRelock(relock rw session) = false, want true (frozen)")
	}

	// The client's next command is answered with the gating error...
	q := append([]byte{cmdQuery}, "SELECT 1"...)
	if err := writeMySQLPacket(cpeer, 0, q); err != nil {
		t.Fatalf("write query: %v", err)
	}
	_ = cpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, pkt, err := readMySQLPacket(cbr)
	if err != nil {
		t.Fatalf("read frozen reply: %v", err)
	}
	if len(pkt) == 0 || pkt[0] != 0xff {
		t.Fatalf("frozen reply % x is not an ERR packet", pkt)
	}
	if code := uint16(pkt[1]) | uint16(pkt[2])<<8; code != 1045 {
		t.Errorf("frozen ERR code = %d, want 1045 (the same gating error)", code)
	}
	if msg := string(pkt[9:]); !strings.Contains(msg, "maker gating") || !strings.Contains(msg, sid) {
		t.Errorf("frozen ERR message = %q, want the gating message naming %s", msg, sid)
	}

	// ...and the backend NEVER sees the command.
	_ = bpeer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := readTDSFrameMySQLTest(bbr); err == nil {
		t.Fatal("frozen query reached the backend")
	}
	_ = bpeer.SetReadDeadline(time.Time{})
}

// TestMySQLRelockUnfreezesOnWatch (brief test c): while frozen the session
// re-admits when a checker watches — the frozen poll sees WatchActive and
// unfreezes; a following query is FORWARDED to the backend byte-exact.
func TestMySQLRelockUnfreezesOnWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	bbr := bufio.NewReader(bpeer)
	sid := "sid-relock-unfreeze"
	s := &mysqlSession{id: sid, access: "rw", holdAdmitted: true, client: client, backend: backend,
		tok: &models.TokenPayload{Username: "relock-maker", DBUser: "rw_user", DBType: "mysql", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(ctx, sid)
		cpeer.Close()
		bpeer.Close()
		client.Close()
		backend.Close()
	})
	p.registerSession(s)

	// Drive the REAL relay pipe: freeze, then unfreeze on a watcher — the
	// next query must flow THROUGH the relay to the backend byte-exact.
	done := make(chan struct{})
	go func() {
		p.pipeClientToBackend(bufio.NewReader(client), backend, client, s, s.tok, "relock-test")
		close(done)
	}()

	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Fatal("HandleRelock = false, want true")
	}

	// A checker attaches — the SAME signal the initial hold polls.
	if err := vs.SetWatchConn(ctx, sid, "relock-checker", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	waitFor(t, "session unfreezes on watch", func() bool { return !p.sessionFrozen(sid) })

	// Now a query flows to the backend (forwarded, not blocked).
	q := append([]byte{cmdQuery}, "SELECT 1"...)
	if err := writeMySQLPacket(cpeer, 0, q); err != nil {
		t.Fatalf("write query: %v", err)
	}
	seq, pkt, err := readMySQLPacket(bbr)
	if err != nil {
		t.Fatalf("read forwarded query: %v", err)
	}
	if seq != 0 || string(pkt) != string(q) {
		t.Errorf("forwarded = seq %d % x, want seq 0 % x (byte-exact after unfreeze)", seq, pkt, q)
	}
	cpeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit after the client closed")
	}
}

// TestMySQLRelockIgnoresNonRWAndUnknown (brief test b parity): relock for a
// NON-rw session (legacy "write" preset) and for an unknown id is a no-op —
// the proxy reports false and the session state is untouched. A malformed
// payload never freezes anything.
func TestMySQLRelockIgnoresNonRWAndUnknown(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mysqlSession{id: "sid-relock-write", access: "write", client: client, backend: backend}
	p.registerSession(s)
	defer p.unregisterSession(s.id)

	if p.HandleRelock([]byte(`{"action":"relock","session_id":"sid-relock-write"}`)) {
		t.Error("HandleRelock on an access=write session = true, want false (legacy presets never relock)")
	}
	if p.HandleRelock([]byte(`{"action":"relock","session_id":"sid-never-registered"}`)) {
		t.Error("HandleRelock on an unknown id = true, want false")
	}
	if p.HandleRelock([]byte(`garbage`)) {
		t.Error("HandleRelock on a malformed payload = true, want false (dropped silently)")
	}
	if p.HandleRelock(nil) {
		t.Error("HandleRelock(nil) = true, want false")
	}
	if p.sessionFrozen("sid-relock-write") {
		t.Error("write session froze, want untouched")
	}
}

// TestRelockFlagOffNeverFreezes (brief test d): with the relock flag OFF the
// handler is a hard no-op — today's one-way admission, byte-identical (G3
// applies to the flag-off path only).
func TestRelockFlagOffNeverFreezes(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mysqlSession{id: "sid-relock-off", access: "rw", holdAdmitted: true, client: client, backend: backend}
	p.registerSession(s)
	defer p.unregisterSession(s.id)
	p.SetRWRelockOnWatchLoss(false)

	if p.HandleRelock([]byte(`{"action":"relock","session_id":"sid-relock-off"}`)) {
		t.Error("HandleRelock with the flag off = true, want false (no-op)")
	}
	if p.sessionFrozen("sid-relock-off") {
		t.Error("session froze with the flag off, want never")
	}
}

// TestMySQLRelockKillStillWorksWhileFrozen (brief requirement 6): an
// explicit kill during the frozen state must tear the session down — kill
// closes the conns regardless of the frozen flag.
func TestMySQLRelockKillStillWorksWhileFrozen(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mysqlSession{id: "sid-relock-kill", access: "rw", holdAdmitted: true, client: client, backend: backend,
		closer: func() { client.Close(); backend.Close() }}
	p.registerSession(s)
	defer p.unregisterSession(s.id)

	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"sid-relock-kill"}`)) {
		t.Fatal("HandleRelock = false, want true")
	}
	if !p.KillSession("sid-relock-kill") {
		t.Fatal("KillSession while frozen = false, want true")
	}
	// The kill closer closed the client conn: a write on the peer end now
	// fails (io.ErrClosedPipe) — proof the session really was torn down.
	if _, err := cpeer.Write([]byte{0}); err == nil {
		t.Error("write after kill succeeded — the frozen session's conns were not closed")
	}
}
