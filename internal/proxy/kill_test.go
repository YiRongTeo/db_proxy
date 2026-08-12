package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 6.4: registry kill semantics — both conns close -------------------

// TestSessionRegistryKillClosesBothConns: KillSession must force-close BOTH
// the client and the backend conn of a registered session (the relay pipes
// then see EOF and handleConn tears the session down). Unknown ids return
// false. The 6.2 registry test asserts the closer is invoked; this one pins
// the closer semantics on real conns.
func TestSessionRegistryKillClosesBothConns(t *testing.T) {
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)

	client, clientPeer := net.Pipe()
	backend, backendPeer := net.Pipe()
	defer client.Close()
	defer backend.Close()

	// The exact closer handleConn installs (Task 6.4): close client + backend.
	s := &mysqlSession{id: "sid-kill-1", closer: func() { client.Close(); backend.Close() }}
	p.registerSession(s)

	if p.KillSession("sid-no-such") {
		t.Fatal("KillSession on an unknown id returned true")
	}

	if !p.KillSession("sid-kill-1") {
		t.Fatal("KillSession on a registered session returned false")
	}

	// Both peer ends must see the closed conn — a read returns immediately
	// with an error instead of blocking for data.
	for name, peer := range map[string]net.Conn{"client": clientPeer, "backend": backendPeer} {
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s conn still readable after KillSession", name)
		}
	}

	// The entry stays registered until handleConn's deferred unregister runs
	// (there is no handleConn in this unit test), so a repeat kill still
	// reports the session — closing already-closed conns is a no-op.
	if !p.KillSession("sid-kill-1") {
		t.Error("second KillSession on the still-registered session returned false")
	}
}

// TestPGProxySessionRegistryKillClosesBothConns mirrors the MySQL test for the
// PG registry (same closer semantics: client + backend).
func TestPGProxySessionRegistryKillClosesBothConns(t *testing.T) {
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)

	client, clientPeer := net.Pipe()
	backend, backendPeer := net.Pipe()
	defer client.Close()
	defer backend.Close()

	s := &pgSession{id: "sid-kill-pg", closer: func() { client.Close(); backend.Close() }}
	p.registerSession(s)

	if p.KillSession("sid-no-such") {
		t.Fatal("KillSession on an unknown id returned true")
	}
	if !p.KillSession("sid-kill-pg") {
		t.Fatal("KillSession on a registered session returned false")
	}
	for name, peer := range map[string]net.Conn{"client": clientPeer, "backend": backendPeer} {
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s conn still readable after KillSession", name)
		}
	}
}

// --- Task 6.4: combined killer fan-out --------------------------------------

// TestKillerKillsOnEitherPlane: the combined killer reaches a session on EITHER
// plane — the ctl:kill subscriber does not know which protocol a session id
// belongs to. Killing one plane's session must leave the other plane's
// sessions untouched.
func TestKillerKillsOnEitherPlane(t *testing.T) {
	mysql := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	pg := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	k := NewKiller(mysql, pg)

	mc, mcPeer := net.Pipe()
	mb, mbPeer := net.Pipe()
	defer mc.Close()
	defer mb.Close()
	mysql.registerSession(&mysqlSession{id: "sid-mysql", closer: func() { mc.Close(); mb.Close() }})

	pc, pcPeer := net.Pipe()
	pb, pbPeer := net.Pipe()
	defer pc.Close()
	defer pb.Close()
	pg.registerSession(&pgSession{id: "sid-pg", closer: func() { pc.Close(); pb.Close() }})

	// Kill the MySQL-side session: true, both its conns closed, PG untouched.
	if !k.KillSession("sid-mysql") {
		t.Fatal("kill of the mysql session returned false")
	}
	for name, peer := range map[string]net.Conn{"client": mcPeer, "backend": mbPeer} {
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Errorf("mysql %s conn still readable after kill", name)
		}
	}
	pg.mu.Lock()
	_, pgStillThere := pg.sessions["sid-pg"]
	pg.mu.Unlock()
	if !pgStillThere {
		t.Error("pg session was removed by a mysql-only kill")
	}

	// Kill the PG-side session: true, both its conns closed.
	if !k.KillSession("sid-pg") {
		t.Fatal("kill of the pg session returned false")
	}
	for name, peer := range map[string]net.Conn{"client": pcPeer, "backend": pbPeer} {
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Errorf("pg %s conn still readable after kill", name)
		}
	}

	// Unknown id: false on both planes.
	if k.KillSession("sid-neither") {
		t.Fatal("kill of an unknown id returned true")
	}
}

// --- Task 6.4: LIVE kill E2E against mysql-test -----------------------------

// startKillTestProxy runs a multi-connection proxy (like the Dispatcher):
// every accepted conn gets its own handleConn goroutine. The proxy itself is
// returned so the test can reach the kill registry.
func startKillTestProxy(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer) (net.Listener, *MySQLProxy) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewMySQLProxy(logger, vs, map[string]string{"127.0.0.1:3307:ro_user": "ro_pw"})
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

// dialTestMySQLSession performs the client side of the 6-step handshake
// against the proxy and returns the connected client once the session is
// established (OK seq 2 received).
func dialTestMySQLSession(t *testing.T, ln net.Listener, token string) net.Conn {
	t.Helper()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	if _, _, err := readMySQLPacket(client); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	seq, resp, err := readMySQLPacket(client)
	if err != nil {
		t.Fatalf("read OK: %v", err)
	}
	if seq != 2 || len(resp) == 0 || resp[0] != 0x00 {
		t.Fatalf("expected OK seq 2, got seq=%d resp=% x", seq, resp)
	}
	return client
}

// waitSessionUnregistered polls the kill registry until the killed session's
// id is gone (handleConn's deferred unregister ran after the relay pipes
// exited on the closed conns).
func waitSessionUnregistered(t *testing.T, p *MySQLProxy, sid string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		_, present := p.sessions[sid]
		p.mu.Unlock()
		if !present {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session %s still registered 5s after kill", sid)
}

// TestMySQLKillSessionLive is the Task 6.4 money shot: a full live session
// against mysql-test through the proxy, force-killed by the session id the
// checker sees (the published event's session_id). Asserts: unknown id → false
// and the session unaffected; the real kill closes the CLIENT conn (next read
// fails), handleConn unwinds and unregisters, and the BACKEND conn disappears
// from the MySQL server (processlist count drops by one) while a second
// session keeps working — the kill targets one session, not the plane.
func TestMySQLKillSessionLive(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	setToken := func(ticket string) string {
		token, err := store.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		tok := models.TokenPayload{Username: "test-user", DBUser: "ro_user",
			DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: ticket}
		if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		return token
	}
	tokenA := setToken("T-6-4")
	tokenB := setToken("T-6-4-b")

	// Subscribe to the user channel: the session id comes from the published
	// event — exactly the id the checker would kill with.
	subCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan []byte, 8)
	acked := make(chan struct{}, 1)
	subCtx = valkey.WithOnSubscriptionHook(subCtx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, "queries:test-user", false, out)
	waitSubAck(t, acked)

	var logBuf bytes.Buffer
	ln, p := startKillTestProxy(t, vs, &logBuf)

	// Session A — the kill victim. Live round trip: SELECT 1 → result set →
	// published event carrying the session id.
	clientA := dialTestMySQLSession(t, ln, tokenA)
	if err := writeMySQLPacket(clientA, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
		t.Fatalf("write SELECT 1: %v", err)
	}
	if _, err := readTextResultSet(clientA); err != nil {
		t.Fatalf("read result set: %v", err)
	}
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if !strings.HasPrefix(ev.SessionID, "sid-") {
		t.Fatalf("session_id = %q, want sid- prefix", ev.SessionID)
	}
	sid := ev.SessionID

	// Negative: unknown id → false, and the session is unaffected (the next
	// query still round-trips).
	if p.KillSession("sid-no-such-session") {
		t.Fatal("KillSession(unknown) returned true")
	}
	if err := writeMySQLPacket(clientA, 0, append([]byte{cmdQuery}, "SELECT 2"...)); err != nil {
		t.Fatalf("write SELECT 2: %v", err)
	}
	if _, err := readTextResultSet(clientA); err != nil {
		t.Fatalf("session affected by unknown-id kill: %v", err)
	}
	recvEvent(t, out) // drain A's SELECT 2 event

	// Session B — the observer. Count backend conns on the MySQL server
	// (excluding B's own): the victim's backend conn must be there.
	clientB := dialTestMySQLSession(t, ln, tokenB)
	count := func() int {
		t.Helper()
		q := "SELECT COUNT(*) FROM information_schema.processlist WHERE user='ro_user' AND id <> CONNECTION_ID()"
		if err := writeMySQLPacket(clientB, 0, append([]byte{cmdQuery}, q...)); err != nil {
			t.Fatalf("write count query: %v", err)
		}
		rows, err := readTextResultSet(clientB)
		if err != nil {
			t.Fatalf("read count result: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("count query returned %d rows, want 1", len(rows))
		}
		s, ok := decodeLenencString(rows[0])
		if !ok {
			t.Fatalf("decode count cell: % x", rows[0])
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("parse count %q: %v", s, err)
		}
		return n
	}
	before := count()
	if before < 1 {
		t.Fatalf("expected the victim backend conn on the server, count=%d", before)
	}

	// The kill: force-close session A by the id the checker would use.
	if !p.KillSession(sid) {
		t.Fatalf("KillSession(%q) on a live session returned false", sid)
	}

	// 1. The CLIENT conn is closed: the next read fails immediately.
	if _, _, err := readMySQLPacket(clientA); err == nil {
		t.Fatal("client read succeeded after kill — conn not closed")
	}
	// 2. handleConn unwinds: the deferred unregister removes the session id.
	waitSessionUnregistered(t, p, sid)
	// 3. The BACKEND conn is closed: the MySQL server drops the victim's
	// connection (processlist count falls by one; the server reaps the FIN
	// asynchronously, so poll up to 5s).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if after := count(); after == before-1 {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("backend conn count = %d after kill, want %d (victim backend still connected)", after, before-1)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// 4. The plane itself is healthy: the observer session still round-trips.
	if err := writeMySQLPacket(clientB, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
		t.Fatalf("write B SELECT 1: %v", err)
	}
	if _, err := readTextResultSet(clientB); err != nil {
		t.Fatalf("observer session broken after kill: %v", err)
	}
}
