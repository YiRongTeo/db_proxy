package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

// --- Task 8 (node-integration): the hold-start session-status callback ------
//
// A HELD rw session must POST action:"started" to the session-status
// callback at HOLD-START — the "session is available to join" signal for
// Ryan's checker UI — BEFORE any watcher attaches (long before the
// backend-open admission whose own started fires later; the DOUBLE
// started is the accepted contract: first = joinable now, second =
// backend live). The postFn seam (session_callback.go) captures the
// payloads WITHOUT HTTP, exactly like TestSessionCallbackPanicIsolated.

// cbRecord is the postFn-recording callback client: every dispatch is
// captured as an ordered (action, target) event so the test can assert
// exactly-one-started and the fire-order relative to admission.
type cbRecord struct {
	mu         sync.Mutex
	events     []string      // "callback:<action>" entries in dispatch order
	target     string        // wire path of the FIRST callback (sid check)
	startFired chan struct{} // closed on the FIRST recorded callback
}

func newCbRecord() *cbRecord {
	return &cbRecord{startFired: make(chan struct{})}
}

func (c *cbRecord) post(target, payload, _ string) error {
	var body struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal([]byte(payload), &body)
	c.mu.Lock()
	c.events = append(c.events, "callback:"+body.Action)
	if c.target == "" {
		c.target = target
	}
	first := len(c.events) == 1
	c.mu.Unlock()
	if first {
		close(c.startFired)
	}
	return nil
}

func (c *cbRecord) snapshot(t *testing.T) []string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.events...)
}

// holdCbCallbacks builds a REAL SessionCallbacks (non-empty baseURL =
// enabled) whose deliveries are captured by rec — zero HTTP.
func holdCbCallbacks(rec *cbRecord) *SessionCallbacks {
	cb, err := NewSessionCallbacks(slog.New(slog.NewTextHandler(io.Discard, nil)),
		"http://callback.test", time.Second, "", "")
	if err != nil {
		panic(err) // unreachable: absolute url
	}
	cb.postFn = rec.post
	return cb
}

// TestHoldStartFiresSessionCallbackBeforeWatch: a held rw session fires
// exactly ONE session-status callback, action "started", carrying the HELD
// sid — and it lands BEFORE any watcher attaches (the test attaches the
// watcher only after the callback was recorded) and before admission (the
// connector runs strictly after the callback event). This is the
// "joinable now" push signal the checker UI consumes.
func TestHoldStartFiresSessionCallbackBeforeWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	sid := "sid-hold-cb-start"
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	rec := newCbRecord()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	p.SetSessionCallbacks(holdCbCallbacks(rec))

	client, cpeer := net.Pipe()
	defer cpeer.Close()
	defer client.Close()

	tok := &models.TokenPayload{Username: "hold-cb", DBUser: "rw_user", DBType: "mysql", SessionID: sid}
	// NO watcher exists yet: admission would only fire the connector, so
	// any connector call recorded before the watch attach is a breach.
	admitted := make(chan struct{}, 1)
	events := struct {
		mu  sync.Mutex
		log []string
	}{}
	mark := func(e string) {
		events.mu.Lock()
		events.log = append(events.log, e)
		events.mu.Unlock()
	}

	holdDone := make(chan error, 1)
	go func() {
		_, err := p.holdRWSession(ctx, client, nil,
			func() error { return nil }, // login success: the hold contract, not under test here
			tok, &ConfigCredResolver{}, "appdb",
			func(ctx context.Context, tok *models.TokenPayload, res CredResolver, db string) (net.Conn, error) {
				mark("admitted")
				admitted <- struct{}{}
				return nil, nil
			})
		holdDone <- err
	}()

	// The hold-start callback must arrive WITHOUT any watcher attached.
	// (The dispatch goroutine delivers shortly after the hold arms.)
	select {
	case <-rec.startFired:
	case <-time.After(5 * time.Second):
		t.Fatal("held session fired NO session-status callback at hold-start — the joinable-now signal is missing")
	}
	got := rec.snapshot(t)
	if len(got) != 1 || got[0] != "callback:started" {
		t.Fatalf("hold-start callbacks = %v, want exactly [callback:started]", got)
	}
	mark("callback:started") // recorded BEFORE the watch attach below

	// Now attach the watcher → admission on the next tick.
	if err := vs.SetWatchConn(ctx, sid, "checker-cb", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher attached but the session was never admitted")
	}

	// Order: the hold-start callback strictly precedes admission.
	events.mu.Lock()
	log := append([]string{}, events.log...)
	events.mu.Unlock()
	if len(log) != 2 || log[0] != "callback:started" || log[1] != "admitted" {
		t.Fatalf("event order = %v, want [callback:started admitted] — the hold-start callback must precede admission", log)
	}
	// The wire target carries the HELD sid (the callback path key).
	snap := rec.snapshot(t)
	if len(snap) != 1 || snap[0] != "callback:started" {
		t.Fatalf("callbacks after admission = %v, want exactly one started (admission-time started is publishLifecycle's, not the hold's)", snap)
	}
}

// TestHoldStartCallbackCarriesHeldSidNoWatcherNoBackend: the walked-away
// shape — the hold-start callback fires with the held sid, and a client
// disconnect while still unwatched produces NO backend connect and NO
// further callbacks from the hold itself (held → started is all the hold
// emits; ended is the plane's finishSession business).
func TestHoldStartCallbackCarriesHeldSidNoWatcherNoBackend(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	sid := "sid-hold-cb-walkaway"
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	rec := newCbRecord()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	p.SetSessionCallbacks(holdCbCallbacks(rec))

	client, cpeer := net.Pipe()
	defer cpeer.Close()

	tok := &models.TokenPayload{Username: "hold-cb-walk", DBUser: "rw_user", DBType: "mysql", SessionID: sid}
	holdDone := make(chan struct{})
	clientDied := make(chan struct{})
	// The same Peek-probe the planes wire (net.Pipe ignores deadlines, so
	// mirror the DisconnectCleanup fixture's manual probe loop).
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
			func() error { return nil },
			tok, &ConfigCredResolver{}, "appdb",
			func(ctx context.Context, tok *models.TokenPayload, res CredResolver, db string) (net.Conn, error) {
				t.Error("connector ran with NO watcher — admission breach")
				return nil, context.Canceled
			})
		close(holdDone)
	}()

	// The hold-start callback carries the HELD sid on the wire.
	select {
	case <-rec.startFired:
	case <-time.After(5 * time.Second):
		t.Fatal("no hold-start callback")
	}
	// Wait for the delivery payload to be readable, then check the sid.
	deadline := time.Now().Add(5 * time.Second)
	var target string
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		if len(rec.events) >= 1 {
			target = rec.target
		}
		rec.mu.Unlock()
		if target != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if want := "http://callback.test/dbpxy/session/" + sid + "/status"; target != want {
		t.Fatalf("hold-start callback target = %q, want %q (the held sid)", target, want)
	}

	// Walk away: the hold exits cleanly, connector untouched.
	cpeer.Close()
	select {
	case <-holdDone:
	case <-time.After(5 * time.Second):
		t.Fatal("hold did not exit after client disconnect")
	}
	if got := rec.snapshot(t); len(got) != 1 || got[0] != "callback:started" {
		t.Fatalf("callbacks = %v, want exactly one started (the hold must not fire ended)", got)
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

// --- Fix round 1 (CRITICAL-2): the Peek probe must not kill the relay -------
//
// The probe re-arms a 500ms read deadline on the client conn; if that
// deadline survived admission, ANY rw client idle >500ms would lose its
// relay read. After admission the probe must be stopped, the goroutine
// fully off the conn, and the deadline cleared before the relay starts —
// then a client that idles >1s with no writes still receives data.

// TestHoldProbeDeadlineClearedOnAdmission: after admission the probe is
// stopped and the conn handed over deadline-free. A read with NO deadline
// on the (probe-surviving) client conn must survive a 1.1s idle — a stale
// 500ms probe deadline would kill it at ~500ms. Uses a REAL loopback TCP
// pair (net.Pipe ignores deadlines, which would park the probe's Peek and
// let it swallow relay bytes — unrepresentative of every production conn).
func TestHoldProbeDeadlineClearedOnAdmission(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	sid := "sid-hold-idle"
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	// Real loopback pair: client = the proxy's side (probe + relay),
	// cpeer = the remote peer that later delivers a byte after the idle.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	cpeer := <-accepted
	defer cpeer.Close()

	tok := &models.TokenPayload{Username: "hold-idle", DBUser: "rw_user", DBType: "mysql", SessionID: sid}
	// The buffered reader is created HERE and shared by the probe AND the
	// "relay" read below — exactly how the planes wire it (the probe peeks
	// through br; the relay inherits br after admission, so any byte the
	// probe's Peek pulled into the buffer is still delivered to the relay).
	br := bufio.NewReader(client)
	clientDied, probeStop, probeExited := startHoldClientProbe(client, br)

	holdDone := make(chan error, 1)
	go func() {
		_, err := p.holdRWSession(ctx, client, clientDied, func() error { return nil }, tok,
			&ConfigCredResolver{}, "appdb",
			func(ctx context.Context, tok *models.TokenPayload, res CredResolver, db string) (net.Conn, error) {
				return nil, context.Canceled
			})
		holdDone <- err
	}()

	// Watcher attaches → admission on the next tick.
	if err := vs.SetWatchConn(ctx, sid, "checker-idle", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	// The admission wiring: stop the probe, wait for it to leave the conn,
	// and hand the conn to the relay DEADLINE-FREE (exactly what the
	// planes run after holdRWSession).
	stopHoldClientProbe(client, probeStop, probeExited, clientDied)

	// A byte arrives after 1.1s of silence; the relay read (client.Read,
	// no deadline) must still be healthy.
	go func() {
		time.Sleep(1100 * time.Millisecond)
		_, _ = cpeer.Write([]byte{0x00})
	}()
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second)) // bounded test read only
	// Read through the SHARED br (the relay's reader): a byte the probe's
	// Peek already pulled into the buffer must still reach the relay.
	if _, err := br.Read(buf); err != nil {
		t.Fatalf("relay read dead after 1.1s idle — a stale probe deadline killed it: %v", err)
	}
	_ = client.SetReadDeadline(time.Time{})
	select {
	case err := <-holdDone:
		if err == nil {
			t.Fatal("stub connector unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hold did not finish")
	}
}

// --- Fix round 1 (CRITICAL-1): EXACTLY ONE login success per held session ---
//
// The old wiring sent the login success TWICE on the MySQL and PG planes
// (the hold's success packet at auth + the unconditional post-admission
// OK/welcome). These tests drive the REAL plane connect paths (fake edge
// backends, a watcher admits the held session) and count the client-visible
// success messages across admission: exactly ONE may arrive.

// TestMySQLRWHoldAdmissionSingleOK: full handshake against the mysql plane
// with an rw token: the hold's OK arrives while held; a watcher admits; the
// session comes up on a fake edge backend and a SELECT round-trips. The
// first frame after the SELECT must be the column-count, NOT a second OK.
func TestMySQLRWHoldAdmissionSingleOK(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	backendAddr, _, _ := startEdgeBackend(t)
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	port := backendAddr[strings.LastIndex(backendAddr, ":")+1:]
	sid := fmt.Sprintf("sid-hold-single-%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "hold-single",
		DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: port, DBType: "mysql",
		TicketID: "T-6-FIX1", Access: "rw", SessionID: sid}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	creds := map[string]string{"mysql:rw_user@" + backendAddr: "rw_pw"}
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{Creds: creds}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	cbr := bufio.NewReader(client)

	if _, _, err := readMySQLPacket(cbr); err != nil { // server greeting
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	// Success #1 — the hold's OK (auth completes while held).
	if _, pkt, err := readMySQLPacket(cbr); err != nil || len(pkt) == 0 || pkt[0] != 0x00 {
		t.Fatalf("hold did not deliver the OK: pkt=% x err=%v", pkt, err)
	}
	// HELD: nothing else arrives while unwatched.
	_ = client.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	if _, pkt, err := readMySQLPacket(cbr); err == nil {
		t.Fatalf("held session answered early: % x", pkt)
	}

	// Admit. The backend connect runs; the client must see NO second OK.
	if err := vs.SetWatchConn(ctx, sid, "checker-single", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	// Drive a SELECT (retrying — the admission window may consume the
	// first write) and require the response to start with the fake edge
	// backend's OK-echo — but distinguish it from a SECOND auth OK by
	// sequence: the SELECT response carries seq = 1 (the request was seq
	// 0); the old double-OK bug sent its stray at the AUTH reply seq (2),
	// payload-identical to this echo, so seq is the discriminator: a first
	// response frame at seq 2 (authReplySeq, unprompted) is the bug.
	_ = client.SetReadDeadline(time.Now().Add(6 * time.Second))
	deadline := time.Now().Add(6 * time.Second)
	sel := append([]byte{cmdQuery}, "SELECT 1"...)
	responded := false
	for !responded && time.Now().Before(deadline) {
		if err := writeMySQLPacket(client, 0, sel); err != nil {
			t.Fatalf("write SELECT: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		seq, pkt, err := readMySQLPacket(cbr)
		if err != nil {
			continue // probe may have eaten the first byte pre-admission
		}
		if len(pkt) > 0 && pkt[0] == 0x00 && seq == 2 { // 2 = authReplySeq (plaintext): the auth-phase reply slot
			t.Fatalf("SECOND OK packet after admission (seq %d, payload % x) — double login success", seq, pkt)
		}
		responded = true
	}
	if !responded {
		t.Fatal("no backend response after admission")
	}
	client.Close()
}

// TestPGRWHoldAdmissionSingleWelcome: full startup against the pg plane
// with an rw token: the hold's welcome arrives while held (exactly ONE
// AuthenticationOk); a watcher admits; the session comes up on a fake
// edge backend and a query round-trips with NO second AuthenticationOk.
func TestPGRWHoldAdmissionSingleWelcome(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	// The live pg-test backend: ro_user has SELECT (the hold→admission
	// flow is under test, not the account's privilege) — a rw token can
	// name ro_user as its db_user; access lives on the TOKEN.
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	sid := fmt.Sprintf("sid-pg-single-%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "pg-single",
		DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "5433", DBType: "postgres",
		TicketID: "T-6-FIX1", Access: "rw", SessionID: sid}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(ctx, sid) })

	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{Creds: pgLiveCreds}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr == nil {
			p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
	if err := front.Send(&pgproto3.StartupMessage{ProtocolVersion: 196608,
		Parameters: map[string]string{"user": token, "database": "appdb"}}); err != nil {
		t.Fatalf("startup: %v", err)
	}

	// The hold's welcome — count the AuthenticationOks while held.
	authOKs := 0
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("welcome read: %v", err)
		}
		if _, ok := msg.(*pgproto3.AuthenticationOk); ok {
			authOKs++
			continue
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	if authOKs != 1 {
		t.Fatalf("held welcome carried %d AuthenticationOk messages, want exactly 1", authOKs)
	}

	// HELD: silence.
	_ = client.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	if _, err := front.Receive(); err == nil {
		t.Fatal("held session answered early")
	}

	// Admit: the backend connect runs; the post-admission block must send
	// NOTHING (the old bug re-sent all seven messages). A query round-trips
	// and any second AuthenticationOk anywhere fails the count.
	if err := vs.SetWatchConn(ctx, sid, "checker-pg-single", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	deadline := time.Now().Add(6 * time.Second)
	responded := false
	for !responded && time.Now().Before(deadline) {
		if err := front.Send(&pgproto3.Query{String: "SELECT 1"}); err != nil {
			t.Fatalf("send query: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		for {
			msg, err := front.Receive()
			if err != nil {
				break // retry the query
			}
			if _, ok := msg.(*pgproto3.AuthenticationOk); ok {
				t.Fatal("SECOND AuthenticationOk after admission — double login success")
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				responded = true
				break
			}
		}
	}
	if !responded {
		t.Fatal("no backend response after admission")
	}
	client.Close()
}

// --- Fix round 1 (CRITICAL-3): the oracle rw bypass is CLOSED ---------------
//
// The oracle plane has no hold point (TNS Phase-1), so an rw-oracle token
// used to open a backend session with NO checker gate — a silent bypass of
// the maker-checker model. The plane now refuses rw tokens at the
// pre-connect point: no backend session, no credential draw.

// TestOracleRWDeniedPreConnect: an rw-oracle token reaching the oracle
// plane is refused BEFORE any backend work — the backend session count
// stays at zero (dialer seam never fires) and the client conn is dropped.
// The hand-rolled TNS client drives the full CONNECT/O5LOGON/server-data/
// data-type/AUTH sequence the plane replays from its captured mirrors.
func TestOracleRWDeniedPreConnect(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	var logBuf bytes.Buffer
	p := NewOracleProxy(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})), vs, &ConfigCredResolver{Creds: map[string]string{
		"oracle:rw_user@127.0.0.1:1521": "rw_pw",
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go p.HandleConn(conn)
		}
	}()

	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	sid := fmt.Sprintf("sid-o-rw-%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "oracle-rw",
		DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "1521", DBType: "oracle",
		TicketID: "T-6-FIX1", Access: "rw", SessionID: sid}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// Handshake: CONNECT (JDBC family shape — the descriptor carries the
	// service name and the dict-auth marker), then mirror-read the
	// ACCEPT/O5LOGON/server-data/data-type responses the plane replays.
	// The payload's first bytes ARE the TNS version field: 0x013d = go-ora
	// (JDBC family — the flow with the data-type exchange; see
	// detectOracleFamily).
	desc := "\x01\x3d\x08\x01(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=FREEPDB1)(CID=(PROGRAM=go-ora)(HOST=x)(USER=u)))" +
		"(ADDRESS=(PROTOCOL=tcp)(HOST=127.0.0.1)(PORT=1521)))"
	if err := writeTNSHandshakeFrame(client, 1, []byte(desc)); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	if _, _, err := readTNSHandshakeFrame(bufio.NewReader(client)); err != nil { // ACCEPT
		t.Fatalf("read accept: %v", err)
	}
	// O5LOGON request → mirrored response; server-data request → mirrored.
	br := bufio.NewReader(client)
	for i := 0; i < 2; i++ {
		if err := writeTNSFrame(client, 6, []byte{0x01, 0x00}); err != nil {
			t.Fatalf("write nego %d: %v", i, err)
		}
		if _, _, err := readTNSFrame(br); err != nil {
			t.Fatalf("read nego %d: %v", i, err)
		}
	}
	// JDBC data-type negotiation: one request → mirrored 2756B response.
	if err := writeTNSFrame(client, 6, []byte{0x02, 0x00}); err != nil {
		t.Fatalf("write data-type: %v", err)
	}
	if _, _, err := readTNSFrame(br); err != nil {
		t.Fatalf("read data-type resp: %v", err)
	}

	// AUTH packet carrying the token (the plane scans for sess_…).
	auth := append([]byte("AUTH_TERMINAL@"), 0)
	auth = append(auth, []byte(token)...)
	if err := writeTNSFrame(client, 6, auth); err != nil {
		t.Fatalf("write auth: %v", err)
	}

	// The refusal: the plane returns WITHOUT a mirrored auth response —
	// the conn is closed (handleConn's defer). A read must hit EOF/error
	// within a bounded window.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.Peek(1); err == nil {
		t.Fatal("oracle rw session was NOT refused — the client saw a response (bypass open)")
	}
	// The refusal must name its reason in the log.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logBuf.String(), "rw access refused") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("refusal not logged; log:\n%s", logBuf.String())
}

// TestOracleROTokenStillConnects shape-checks the sibling path: a
// NON-rw oracle token is not caught by the new gate (the gate must not
// over-refuse). The connect proceeds past the access check into the
// backend login (which fails against the closed backend port here — the
// assertion is that the failure is the BACKEND one, not the rw refusal).
func TestOracleROTokenNotCaughtByRWGate(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	var logBuf bytes.Buffer
	// Backend port deliberately dead: the login attempt fails, proving the
	// gate did not fire (an rw token would have been refused earlier).
	p := NewOracleProxy(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})), vs, &ConfigCredResolver{Creds: map[string]string{
		"oracle:ro_user@127.0.0.1:1": "ro_pw",
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr == nil {
			p.HandleConn(conn)
		}
	}()

	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "oracle-ro",
		DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "1", DBType: "oracle",
		TicketID: "T-6-FIX1"}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	desc := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=FREEPDB1)(CID=(PROGRAM=sqlplus)(HOST=x)(USER=u)))" +
		"(ADDRESS=(PROTOCOL=tcp)(HOST=127.0.0.1)(PORT=1)))"
	if err := writeTNSHandshakeFrame(client, 1, []byte(desc)); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	br := bufio.NewReader(client)
	if _, _, err := readTNSHandshakeFrame(br); err != nil {
		t.Fatalf("read accept: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := writeTNSFrame(client, 6, []byte{0x01, 0x00}); err != nil {
			t.Fatalf("write nego %d: %v", i, err)
		}
		if _, _, err := readTNSFrame(br); err != nil {
			t.Fatalf("read nego %d: %v", i, err)
		}
	}
	auth := append([]byte("AUTH_TERMINAL@"), 0)
	auth = append(auth, []byte(token)...)
	if err := writeTNSFrame(client, 6, auth); err != nil {
		t.Fatalf("write auth: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logBuf.String(), "backend login failed") {
			return // gate skipped, backend attempted: correct
		}
		if strings.Contains(logBuf.String(), "rw access refused") {
			t.Fatal("ro token was caught by the rw gate — over-refusal")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ro path never reached the backend login; log:\n%s", logBuf.String())
}
