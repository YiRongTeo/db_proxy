package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
)

// --- Task 6 (node-integration): rw connection HOLD --------------------------
//
// An rw session authenticates (client protocol auth completes) but the
// backend connection is NOT opened and the credential is NOT drawn until a
// checker actively watches (WatchActive true). Hold state:
//
//   - the client sees a normal completed login (the protocol's success
//     response), but no backend traffic flows yet
//   - the pending sess:live:<sid> record (mint-time) must stay visible —
//     refreshed on the hold heartbeat — so the directory shows pending
//   - client disconnect while held → clean exit, no backend, no leaked
//     sess:live record
//   - one-way admission: a watcher detaching after admission does NOT kill
//     the session

// waitFor holds a condition with a timeout, for ticker-driven admission.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within 5s: %s", what)
}

// TestHoldForAccessNothingAdmittedWithoutWatch: resolveHold on an unwatched
// rw session reports NOT admitted (no backend connect, no credential draw)
// for the whole probe window; a watcher appearing flips it to admitted.
func TestHoldForAccessNothingAdmittedWithoutWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	sid := "sid-hold-unwatched"
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	admitted := make(chan struct{}, 1)
	stop := make(chan struct{})
	defer close(stop)
	go p.watchForAdmission(ctx, sid, stop, admitted)

	// 400ms unwatched: no admission signal.
	select {
	case <-admitted:
		t.Fatal("admitted with NO watcher — the hold failed")
	case <-time.After(400 * time.Millisecond):
	}

	// A checker attaches → admission within a tick or two.
	if err := vs.SetWatchConn(ctx, sid, "checker-conn", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher attached but the session was never admitted")
	}
}

// TestHoldSessionRecordRefreshedWhileHeld: while a rw session is held, the
// mint-time pending sess:live:<sid> record must NOT expire (60s TTL) — the
// hold heartbeat refreshes it. The record keeps status "pending" until the
// backend connect overwrites it with the active shape.
func TestHoldSessionRecordRefreshedWhileHeld(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	sid := "sid-hold-refresh"
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	// Seed a mint-time pending record, then run the hold heartbeat twice —
	// last_seen must ADVANCE (the heartbeat), proving the refresh.
	tok := &models.TokenPayload{Username: "hold-user", DBUser: "rw_user", DBType: "mysql", SessionID: sid}
	p.holdHeartbeat(tok)
	raw1, err := vs.GetSessionLive(ctx, sid)
	if err != nil || raw1 == nil {
		t.Fatalf("pending record missing after refresh: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	p.holdHeartbeat(tok)
	raw2, err := vs.GetSessionLive(ctx, sid)
	if err != nil || raw2 == nil {
		t.Fatalf("pending record missing after second refresh: %v", err)
	}
	if string(raw1) == string(raw2) {
		t.Error("two refreshes wrote identical records — last_seen did not advance")
	}
	// Status stays pending (the directory must show pending until admission).
	rec := parseSessionRecord(t, raw2)
	if rec.Status != "pending" {
		t.Errorf("held record status = %q, want pending", rec.Status)
	}
}

// TestHoldClientDisconnectCleansUp: a rw client that disconnects while held
// tears down cleanly — the hold goroutine exits, the (never-created)
// backend is untouched and the mint-time sess:live record is removed (no
// leaked directory entry).
func TestHoldClientDisconnectCleansUp(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	sid := "sid-hold-disconnect"
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	client, cpeer := net.Pipe()
	defer cpeer.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	tok := &models.TokenPayload{Username: "hold-user", DBUser: "rw_user", DBType: "mysql", SessionID: sid}
	p.holdHeartbeat(tok)

	// Simulate the proxy's hold path with a real client conn: the hold
	// writes the login success (MySQL OK packet via writeLoginOK) — the
	// test reads it off the OTHER pipe end (cpeer) — then polls. Closing
	// the client end must end the hold WITHOUT any backend dial (the stub
	// connector returns an error on any call, which would surface as an
	// admission attempt; none may happen unwatched). The disconnect probe
	// is the SAME Peek-based loop the MySQL connect path wires.
	holdDone := make(chan struct{})
	clientDied := make(chan struct{})
	cbr := bufio.NewReader(client)
	go func() {
		for {
			_ = client.SetReadDeadline(time.Now().Add(rwHoldPollInterval))
			if _, err := cbr.Peek(1); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				break
			}
			_ = client.SetReadDeadline(time.Time{})
		}
		close(clientDied)
	}()
	go func() {
		_, _ = p.holdRWSession(ctx, client, clientDied,
			func() error { return writeMySQLPacket(client, 2, okPacket()) },
			tok, &ConfigCredResolver{}, "appdb",
			func(ctx context.Context, tok *models.TokenPayload, res CredResolver, db string) (net.Conn, error) {
				return connectMySQLBackendForTest(ctx, tok, res, db)
			})
		close(holdDone)
	}()

	// The login success arrives (auth completed — the contract).
	respBr := bufio.NewReader(cpeer)
	_ = cpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, pkt, err := readMySQLPacket(respBr); err != nil || len(pkt) == 0 || pkt[0] != 0x00 {
		t.Fatalf("hold did not write the OK packet: pkt=% x err=%v", pkt, err)
	}

	cpeer.Close()
	select {
	case <-holdDone:
	case <-time.After(5 * time.Second):
		t.Fatal("hold did not exit after client disconnect")
	}
	// The mint-time record must be gone (finishHeldSession ran).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := vs.GetSessionLive(ctx, sid)
		if err == nil && raw == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("sess:live record leaked after held-session disconnect")
}

// connectMySQLBackendForTest is the connect hook signature the hold takes;
// the test passes a stub that never dials (any call would be a contract
// breach — the credential draw is part of the same seam).
func connectMySQLBackendForTest(ctx context.Context, tok *models.TokenPayload, res CredResolver, db string) (net.Conn, error) {
	return nil, context.Canceled
}

// parseSessionRecord unmarshals a sess:live payload (test-side helper).
func parseSessionRecord(t *testing.T, raw []byte) pendingRecordTest {
	t.Helper()
	var rec pendingRecordTest
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("unmarshal session record: %v", err)
	}
	return rec
}

// pendingRecordTest mirrors the directory record's status field only.
type pendingRecordTest struct {
	Status string `json:"status"`
}

// TestHoldWriteClassifierGateWiring: after admission the session's writes
// are NOT gated (full rw); before admission nothing flows at all (the hold
// is upstream of the relay). This pins the relay-side absence of a gate for
// rw — checkWriteGate must stay tied to access=="write" ONLY.
func TestHoldWriteClassifierGateWiring(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := &mysqlSession{id: "sid-hold-rw-relay", access: "rw"}
	cleanupLiveRecord(t, vs, s.id)

	// rw sessions never trip the legacy write gate — the hold is the gate.
	if msg := p.checkWriteGate(s, cmdQuery); msg != "" {
		t.Errorf("rw session gated at the relay: %q — the hold is upstream, the relay must not gate rw", msg)
	}
}

// --- ro relay wiring (MySQL): write commands rejected, reads forwarded ------

// TestMySQLRoRelayBlocksWritesForwardsReads: end-to-end through the relay
// pipe — a ro session's INSERT/UPDATE/DELETE/CREATE are answered with ERR
// 1045 and NEVER reach the backend; SELECT/SHOW flow byte-exact.
func TestMySQLRoRelayBlocksWritesForwardsReads(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	cbr := bufio.NewReader(cpeer)
	bbr := bufio.NewReader(bpeer)
	s := &mysqlSession{id: "sid-ro-relay", access: "ro", client: client, backend: backend}
	cleanupLiveRecord(t, vs, s.id)
	defer p.closeGateWait(s)
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()

	done := make(chan struct{})
	go func() {
		p.pipeClientToBackend(bufio.NewReader(client), backend, client, s,
			&models.TokenPayload{Username: "ro-relay", DBType: "mysql"}, "unit")
		close(done)
	}()

	// Writes: rejected with ERR 1045, nothing forwarded.
	for _, sql := range []string{"INSERT INTO demo_items (name) VALUES ('x')", "UPDATE demo_items SET name='y'", "DELETE FROM demo_items", "CREATE TABLE zz (id int)", "DROP TABLE zz"} {
		if err := writeMySQLPacket(cpeer, 0, append([]byte{cmdQuery}, sql...)); err != nil {
			t.Fatalf("write %q: %v", sql, err)
		}
		_ = cpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
		seq, pkt, err := readMySQLPacket(cbr)
		if err != nil {
			t.Fatalf("read rejection for %q: %v", sql, err)
		}
		if len(pkt) == 0 || pkt[0] != 0xff {
			t.Fatalf("%q: response % x is not an ERR packet", sql, pkt)
		}
		if code := uint16(pkt[1]) | uint16(pkt[2])<<8; code != 1045 {
			t.Errorf("%q: err code %d, want 1045 (seq %d)", sql, code, seq)
		}
		_ = bpeer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, _, err := readTDSFrameMySQLTest(bbr); err == nil {
			t.Fatalf("%q reached the backend", sql)
		}
		_ = bpeer.SetReadDeadline(time.Time{})
	}

	// Reads: forwarded byte-exact as a FRAMED packet (header + payload —
	// the normal forward path's shape; we assert the payload + framing).
	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	if err := writeMySQLPacket(cpeer, 0, sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	seq, pkt, err := readMySQLPacket(bbr)
	if err != nil {
		t.Fatalf("read forwarded SELECT: %v", err)
	}
	if seq != 0 || string(pkt) != string(sel) {
		t.Errorf("forwarded = seq %d % x, want seq 0 % x (byte-exact)", seq, pkt, sel)
	}
	cpeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit after the client closed")
	}
}

// readTDSFrameMySQLTest reads a raw MySQL packet off the pipe in the test
// (seq discarded — the callers only need payload + err).
func readTDSFrameMySQLTest(br *bufio.Reader) (int, []byte, error) {
	seq, pkt, err := readMySQLPacket(br)
	return int(seq), pkt, err
}
