package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
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
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil)

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
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil)

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
	mysql := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil)
	pg := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil)
	k := NewKiller(mysql, pg, nil)

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
	p := NewMySQLProxy(logger, vs, &ConfigCredResolver{Creds: map[string]string{"mysql:ro_user@127.0.0.1:3307": "ro_pw"}}, nil)
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
	// The started lifecycle event precedes the SELECT event on the user
	// channel — recvQueryEvent skips kind=session events.
	ev := recvQueryEvent(t, out)
	if !strings.HasPrefix(ev.SessionID, "sid-") {
		t.Fatalf("session_id = %q, want sid- prefix", ev.SessionID)
	}
	sid := ev.SessionID
	cleanupLiveRecord(t, vs, sid)

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
	sidB := recvSessionEvent(t, out).SessionID // B's started (first event after the dial)
	cleanupLiveRecord(t, vs, sidB)
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

// --- Task 6.8: session-scoped kill isolation (live, three sessions) ---------

// TestKillIsolationLive is the final-gate isolation regression: THREE live
// sessions against mysql-test through one proxy; killing the MIDDLE session
// (by the id the checker would use) must close exactly that client, leave the
// other in-flight session untouched (its long SLEEP completes with the correct
// result and it keeps round-tripping), let a THIRD fresh session connect and
// query afterwards, and report unknown ids as false without disturbing anyone.
func TestKillIsolationLive(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	setToken := func(user, ticket string) string {
		token, err := store.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		tok := models.TokenPayload{Username: user, DBUser: "ro_user",
			DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: ticket}
		if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		return token
	}
	tokenA := setToken("iso-a", "T-6-8-a")
	tokenB := setToken("iso-b", "T-6-8-b")
	tokenC := setToken("iso-c", "T-6-8-c")

	// One subscription per user → each client maps to exactly its session id
	// (the published event's session_id is what the checker would kill with).
	sub := func(channel string) <-chan []byte {
		subCtx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		out := make(chan []byte, 16)
		acked := make(chan struct{}, 1)
		subCtx = valkey.WithOnSubscriptionHook(subCtx, func(valkey.PubSubSubscription) {
			select {
			case acked <- struct{}{}:
			default:
			}
		})
		go vs.Subscribe(subCtx, channel, false, out)
		waitSubAck(t, acked)
		return out
	}
	outA := sub("queries:iso-a")
	outB := sub("queries:iso-b")

	var logBuf bytes.Buffer
	ln, p := startKillTestProxy(t, vs, &logBuf)

	// connect dials a session, runs a quick SELECT, and returns the client
	// plus the session id from the published event (the checker's view).
	connect := func(token string, out <-chan []byte) (net.Conn, string) {
		t.Helper()
		c := dialTestMySQLSession(t, ln, token)
		if err := writeMySQLPacket(c, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
			t.Fatalf("write SELECT 1: %v", err)
		}
		if _, err := readTextResultSet(c); err != nil {
			t.Fatalf("read result set: %v", err)
		}
		// Each channel's first event is the session's started lifecycle event;
		// recvQueryEvent skips it and returns the SELECT 1 query event.
		ev := recvQueryEvent(t, out)
		if !strings.HasPrefix(ev.SessionID, "sid-") {
			t.Fatalf("session_id = %q, want sid- prefix", ev.SessionID)
		}
		return c, ev.SessionID
	}
	clientA, sidA := connect(tokenA, outA)
	clientB, sidB := connect(tokenB, outB)
	cleanupLiveRecord(t, vs, sidA)
	cleanupLiveRecord(t, vs, sidB)

	// Both clients go into long server-side SLEEPs (SLEEP blocks in MySQL, so
	// each session is genuinely in-flight mid-query when the kill lands).
	for _, c := range []net.Conn{clientA, clientB} {
		if err := writeMySQLPacket(c, 0, append([]byte{cmdQuery}, "SELECT SLEEP(8)"...)); err != nil {
			t.Fatalf("write SLEEP: %v", err)
		}
	}
	// Give both SLEEPs time to reach the backend and start sleeping, and
	// confirm both sessions are registered in the kill registry.
	time.Sleep(1500 * time.Millisecond)
	for name, sid := range map[string]string{"A": sidA, "B": sidB} {
		p.mu.Lock()
		_, present := p.sessions[sid]
		p.mu.Unlock()
		if !present {
			t.Fatalf("session %s (%s) not registered while sleeping", name, sid)
		}
	}

	// The kill: exactly session A, by the id the checker would use.
	if !p.KillSession(sidA) {
		t.Fatalf("KillSession(%q) on a live session returned false", sidA)
	}

	// 1. Session A is gone: its client read fails immediately, and the session
	// unregisters as handleConn unwinds on the closed conns.
	if _, _, err := readMySQLPacket(clientA); err == nil {
		t.Fatal("client A read succeeded after kill — conn not closed")
	}
	waitSessionUnregistered(t, p, sidA)

	// 4. Unknown id → false; the still-sleeping session B is not disturbed.
	if p.KillSession("sid-no-such-iso") {
		t.Fatal("KillSession(unknown) returned true")
	}

	// 2. Session B is UNAFFECTED: its SLEEP completes with the correct result
	// (SLEEP returns one row whose value is 0) and it keeps round-tripping.
	rows, err := readTextResultSet(clientB)
	if err != nil {
		t.Fatalf("client B's SLEEP failed after A's kill: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("SLEEP result rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "0" {
		t.Fatalf("SLEEP result cell = %q (ok=%v), want \"0\"", v, ok)
	}
	if err := writeMySQLPacket(clientB, 0, append([]byte{cmdQuery}, "SELECT 42"...)); err != nil {
		t.Fatalf("write B SELECT 42: %v", err)
	}
	rows, err = readTextResultSet(clientB)
	if err != nil {
		t.Fatalf("client B's follow-up query failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("SELECT 42 rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "42" {
		t.Fatalf("SELECT 42 cell = %q (ok=%v), want \"42\"", v, ok)
	}

	// 3. A THIRD fresh session connects and queries fine after the kill.
	outC := sub("queries:iso-c")
	clientC := dialTestMySQLSession(t, ln, tokenC)
	if err := writeMySQLPacket(clientC, 0, append([]byte{cmdQuery}, "SELECT 'fresh-ok'"...)); err != nil {
		t.Fatalf("write C SELECT: %v", err)
	}
	rows, err = readTextResultSet(clientC)
	if err != nil {
		t.Fatalf("fresh session C failed after kill: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("C SELECT rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "fresh-ok" {
		t.Fatalf("C SELECT cell = %q (ok=%v), want \"fresh-ok\"", v, ok)
	}
	sidC := recvSessionEvent(t, outC).SessionID
	cleanupLiveRecord(t, vs, sidC)
}

// --- Task 8.3: two-level kill — ctl:kill mode parsing + dispatch ------------

// TestHandleKillPayloadParse pins the ctl:kill {session_id, mode} parsing
// rules: mode ABSENT defaults to connection (Task 6.4 backward compat — the
// old payload carried only session_id), explicit query/connection pass
// through, malformed JSON and empty session ids are dropped silently
// (("", "")), and an unknown mode is ignored ("kill: unknown mode"), never a
// crash. With nil planes every real dispatch reports the session unknown.
func TestHandleKillPayloadParse(t *testing.T) {
	k := NewKiller(nil, nil, nil)
	cases := []struct {
		name string
		msg  string
		line string
		sid  string
	}{
		{"mode absent defaults to connection", `{"session_id":"sid-1"}`, "kill: unknown session", "sid-1"},
		{"explicit connection", `{"session_id":"sid-1","mode":"connection"}`, "kill: unknown session", "sid-1"},
		{"explicit query", `{"session_id":"sid-1","mode":"query"}`, "kill: unknown session", "sid-1"},
		{"empty session id dropped", `{"session_id":""}`, "", ""},
		{"malformed json dropped", `not json`, "", ""},
		{"empty message dropped", ``, "", ""},
		{"unknown mode ignored not crash", `{"session_id":"sid-1","mode":"banana"}`, "kill: unknown mode", "sid-1"},
	}
	for _, tc := range cases {
		line, sid := k.HandleKill([]byte(tc.msg))
		if line != tc.line || sid != tc.sid {
			t.Errorf("%s: HandleKill(%q) = (%q,%q), want (%q,%q)", tc.name, tc.msg, line, sid, tc.line, tc.sid)
		}
	}
}

// TestMySQLKillQueryUnknownAndNoThreadID: KillQuery on an unknown id returns
// false; on a REGISTERED session with no captured thread id (threadID == 0,
// Task 8.2 degrade rule) it also returns false, logs the specific reason,
// and NEVER invokes the session closer — a failed kill-query must leave the
// session's conns untouched. A nil credential context is refused without
// panicking.
func TestMySQLKillQueryUnknownAndNoThreadID(t *testing.T) {
	var logBuf bytes.Buffer
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(&logBuf, nil)), nil, &ConfigCredResolver{}, nil)

	client, _ := net.Pipe()
	backend, _ := net.Pipe()
	defer client.Close()
	defer backend.Close()
	closed := false
	p.registerSession(&mysqlSession{id: "sid-kq-1", threadID: 0,
		closer: func() { closed = true; client.Close(); backend.Close() }})

	if p.KillQuery("sid-no-such") {
		t.Fatal("KillQuery(unknown) returned true")
	}
	if p.KillQuery("sid-kq-1") {
		t.Fatal("KillQuery with threadID 0 returned true")
	}
	if !strings.Contains(logBuf.String(), "kill query: no thread id") {
		t.Errorf("expected 'kill query: no thread id' warn, logs:\n%s", logBuf.String())
	}
	if closed {
		t.Fatal("session closer invoked by a failed kill-query — session must survive")
	}

	// A registered session WITHOUT the credential context (tok == nil) is
	// refused without a panic and without touching the conns.
	p.registerSession(&mysqlSession{id: "sid-kq-2", threadID: 42,
		closer: func() { closed = true; client.Close(); backend.Close() }})
	if p.KillQuery("sid-kq-2") {
		t.Fatal("KillQuery with nil token context returned true")
	}
	if closed {
		t.Fatal("session closer invoked by a nil-context kill-query")
	}

	// Registry intact — neither failed kill-query unregistered anything.
	p.mu.Lock()
	_, present := p.sessions["sid-kq-1"]
	_, present2 := p.sessions["sid-kq-2"]
	p.mu.Unlock()
	if !present || !present2 {
		t.Fatal("session unregistered by a failed kill-query")
	}
}

// TestPGKillQueryUnknownAndNoThreadID mirrors the MySQL unit test for the PG
// registry (same rules: unknown → false, no thread id → false + warn, closer
// never invoked).
func TestPGKillQueryUnknownAndNoThreadID(t *testing.T) {
	var logBuf bytes.Buffer
	p := NewPGProxy(slog.New(slog.NewTextHandler(&logBuf, nil)), nil, &ConfigCredResolver{}, nil)

	closed := false
	p.registerSession(&pgSession{id: "sid-kq-pg", threadID: 0, closer: func() { closed = true }})

	if p.KillQuery("sid-no-such") {
		t.Fatal("KillQuery(unknown) returned true")
	}
	if p.KillQuery("sid-kq-pg") {
		t.Fatal("KillQuery with threadID 0 returned true")
	}
	if !strings.Contains(logBuf.String(), "kill query: no thread id") {
		t.Errorf("expected 'kill query: no thread id' warn, logs:\n%s", logBuf.String())
	}
	if closed {
		t.Fatal("session closer invoked by a failed kill-query — session must survive")
	}
}

// TestKillerKillQueryFanOut: the combined killer's KillQuery reaches the
// plane holding the session. A registered session WITHOUT a thread id logs
// its specific warn on ITS plane — proof of which plane was consulted —
// while the other plane logs nothing; an unknown id logs nothing anywhere.
func TestKillerKillQueryFanOut(t *testing.T) {
	var mysqlLog, pgLog bytes.Buffer
	mysql := NewMySQLProxy(slog.New(slog.NewTextHandler(&mysqlLog, nil)), nil, &ConfigCredResolver{}, nil)
	pg := NewPGProxy(slog.New(slog.NewTextHandler(&pgLog, nil)), nil, &ConfigCredResolver{}, nil)
	k := NewKiller(mysql, pg, nil)

	pg.registerSession(&pgSession{id: "sid-pg", threadID: 0})

	if k.KillQuery("sid-pg") {
		t.Fatal("KillQuery of a no-thread-id session returned true")
	}
	if !strings.Contains(pgLog.String(), "kill query: no thread id") {
		t.Errorf("pg plane not consulted: %s", pgLog.String())
	}
	if mysqlLog.Len() != 0 {
		t.Errorf("mysql plane logged for a pg-only session: %s", mysqlLog.String())
	}
	if k.KillQuery("sid-neither") {
		t.Fatal("KillQuery(unknown) returned true")
	}
}

// --- Task 8.3 LIVE: kill-query vs kill-connection through the proxy --------

// startKillSwitch is the test-side ctl:kill subscriber: it subscribes to the
// REAL ctl:kill channel and applies each message through the REAL
// Killer.HandleKill — the exact function cmd/data's subscriber calls — so
// the live tests exercise the full control path (JSON payload → parse →
// mode dispatch → plane fan-out) over the real pub/sub transport. Outcome
// lines are reported on the returned channel.
func startKillSwitch(t *testing.T, vs *store.ValkeyStore, k *Killer) <-chan string {
	t.Helper()
	ch := subscribePG(t, vs, "ctl:kill")
	out := make(chan string, 16)
	go func() {
		for msg := range ch {
			if line, _ := k.HandleKill(msg); line != "" {
				out <- line
			}
		}
	}()
	return out
}

// recvKillOutcome waits for the next ctl:kill outcome line.
func recvKillOutcome(t *testing.T, out <-chan string) string {
	t.Helper()
	select {
	case line := <-out:
		return line
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ctl:kill outcome")
		return ""
	}
}

// killTestUserSub subscribes to queries:<user> — the session ids come from
// the published events, exactly the id the checker would kill with.
func killTestUserSub(t *testing.T, vs *store.ValkeyStore, user string) <-chan []byte {
	t.Helper()
	return subscribePG(t, vs, "queries:"+user)
}

// killTestConnect dials a MySQL session, round-trips SELECT 1, and returns
// the client plus the session id from the published event.
func killTestConnect(t *testing.T, ln net.Listener, token string, out <-chan []byte) (net.Conn, string) {
	t.Helper()
	c := dialTestMySQLSession(t, ln, token)
	if err := writeMySQLPacket(c, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
		t.Fatalf("write SELECT 1: %v", err)
	}
	if _, err := readTextResultSet(c); err != nil {
		t.Fatalf("read result set: %v", err)
	}
	ev := recvQueryEvent(t, out)
	if !strings.HasPrefix(ev.SessionID, "sid-") {
		t.Fatalf("session_id = %q, want sid- prefix", ev.SessionID)
	}
	return c, ev.SessionID
}

// killTestAddr normalizes a listener address for HOST-side clients: a
// wildcard-bound listener (":0") must be dialed via 127.0.0.1, not 0.0.0.0.
func killTestAddr(ln net.Listener) string {
	ta := ln.Addr().(*net.TCPAddr)
	ip := ta.IP.String()
	if ip == "0.0.0.0" || ip == "::" {
		ip = "127.0.0.1"
	}
	return net.JoinHostPort(ip, strconv.Itoa(ta.Port))
}

// dialTestMySQLSessionAt is dialTestMySQLSession with an explicit target
// address (the wildcard-bound kill-connection listener needs 127.0.0.1 for
// host-side clients).
func dialTestMySQLSessionAt(t *testing.T, addr, token string) net.Conn {
	t.Helper()
	client, err := net.Dial("tcp", addr)
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

// startKillTestProxyAny is startKillTestProxy with the listener bound on ALL
// interfaces (":0"): the mysql-test container reaches the test proxy via
// host.docker.internal, which only routes to host listeners that are not
// loopback-only (verified on this dev env).
func startKillTestProxyAny(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer) (net.Listener, *MySQLProxy) {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewMySQLProxy(logger, vs, &ConfigCredResolver{Creds: map[string]string{"mysql:ro_user@127.0.0.1:3307": "ro_pw"}}, nil)
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

// startPGKillTestProxy runs a single-connection PG proxy (like
// startTestPGProxyWithCreds) and returns the proxy itself so the test can
// build the combined killer and reach the kill registry.
func startPGKillTestProxy(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer) (net.Listener, *PGProxy, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewPGProxy(logger, vs, &ConfigCredResolver{Creds: pgLiveCreds}, nil)
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
	return ln, p, done
}

// TestMySQLKillQueryLive is the Task 8.3 money shot (dispatch scenario a +
// isolation): a maker session runs a genuinely kill-abortable blocking query
// — SELECT GET_LOCK('<name>', 60) while another proxy session holds the
// lock (VERIFIED bare-metal 2026-08-13: KILL QUERY aborts a GET_LOCK waiter
// with ERROR 1317 "Query execution was interrupted"; SELECT SLEEP(n) is NOT
// kill-abortable on MySQL 8.4 — the sleep completes with result 1 — so it
// is not a valid fixture). A ctl:kill {sid, mode:query} published on the
// REAL channel aborts ONLY the in-flight query: the maker's client receives
// an ERROR result for the blocked GET_LOCK (1317, NOT a lost connection),
// the SAME session immediately runs SELECT 1 → OK (the session survived and
// stays in the registry), the bystander's own in-flight SLEEP completes
// untouched, and the lock-holder session is undisturbed (it releases the
// lock afterwards and keeps round-tripping).
func TestMySQLKillQueryLive(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	setToken := func(user, ticket string) string {
		token, err := store.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		tok := models.TokenPayload{Username: user, DBUser: "ro_user",
			DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: ticket}
		if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		return token
	}
	tokenA := setToken("kq-a", "T-8-3-a")
	tokenB := setToken("kq-b", "T-8-3-b")
	tokenC := setToken("kq-c", "T-8-3-c")

	outA := killTestUserSub(t, vs, "kq-a")
	outB := killTestUserSub(t, vs, "kq-b")

	var logBuf bytes.Buffer
	ln, p := startKillTestProxy(t, vs, &logBuf)
	k := NewKiller(p, NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil), nil)
	killOut := startKillSwitch(t, vs, k)

	clientA, sidA := killTestConnect(t, ln, tokenA, outA)
	clientB, sidB := killTestConnect(t, ln, tokenB, outB)
	cleanupLiveRecord(t, vs, sidA)
	cleanupLiveRecord(t, vs, sidB)

	// Lock holder C: a THIRD proxy session (its sid is not needed). It
	// acquires the named lock first, so A's GET_LOCK below genuinely
	// blocks in the backend — a kill-abortable in-flight query. The lock
	// name is unique per run: a lock left behind by a crashed earlier run
	// must not poison this one.
	outC := killTestUserSub(t, vs, "kq-c")
	clientC := dialTestMySQLSession(t, ln, tokenC)
	lockName := fmt.Sprintf("kq8-%d", time.Now().UnixNano())
	if err := writeMySQLPacket(clientC, 0, append([]byte{cmdQuery}, "SELECT GET_LOCK('"+lockName+"', 60)"...)); err != nil {
		t.Fatalf("write C GET_LOCK: %v", err)
	}
	rows, err := readTextResultSet(clientC)
	if err != nil {
		t.Fatalf("holder C GET_LOCK failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("holder C GET_LOCK rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "1" {
		t.Fatalf("holder C GET_LOCK cell = %q (ok=%v), want \"1\"", v, ok)
	}
	sidC := recvSessionEvent(t, outC).SessionID
	cleanupLiveRecord(t, vs, sidC)

	// A: SELECT GET_LOCK('<lockName>', 60) — the kill-query victim: C owns
	// the lock, so A's statement blocks in the backend. B: SELECT SLEEP(8)
	// — the bystander, whose own in-flight query must NOT be aborted by
	// A's kill-query.
	if err := writeMySQLPacket(clientA, 0, append([]byte{cmdQuery}, "SELECT GET_LOCK('"+lockName+"', 60)"...)); err != nil {
		t.Fatalf("write A GET_LOCK: %v", err)
	}
	if err := writeMySQLPacket(clientB, 0, append([]byte{cmdQuery}, "SELECT SLEEP(8)"...)); err != nil {
		t.Fatalf("write B SLEEP: %v", err)
	}
	// Give A's GET_LOCK time to block (and B's SLEEP to start) on the
	// backend, and confirm both sessions are registered (genuinely
	// in-flight).
	time.Sleep(1500 * time.Millisecond)
	for name, sid := range map[string]string{"A": sidA, "B": sidB} {
		p.mu.Lock()
		_, present := p.sessions[sid]
		p.mu.Unlock()
		if !present {
			t.Fatalf("session %s (%s) not registered while blocking/sleeping", name, sid)
		}
	}

	// The kill-query, exactly as the control plane would publish it.
	if err := vs.Publish(ctx, "ctl:kill", []byte(`{"session_id":"`+sidA+`","mode":"query"}`)); err != nil {
		t.Fatalf("publish ctl:kill: %v", err)
	}
	if line := recvKillOutcome(t, killOut); line != "query killed" {
		t.Fatalf("kill outcome = %q, want %q", line, "query killed")
	}

	// 1. A's blocked GET_LOCK is ABORTED server-side: the client gets an
	//    ERROR result for it (1317 Query execution was interrupted) — the
	//    conn is NOT closed (that would be a 2013 lost connection). The
	//    statement never produced a result set, so the ERR is the first
	//    response packet (readResultSetErr handles both shapes).
	_ = clientA.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := readResultSetErr(clientA)
	if err != nil {
		t.Fatalf("client A's conn dropped instead of an error result: %v", err)
	}
	if msg := mysqlErrMessage(resp); !strings.Contains(msg, "interrupted") {
		t.Errorf("A: abort error = %q, want 1317 Query execution was interrupted", msg)
	}

	// 2. The SAME session survives: the same client conn round-trips
	//    SELECT 1 immediately after the aborted query.
	if err := writeMySQLPacket(clientA, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
		t.Fatalf("write A SELECT 1: %v", err)
	}
	rows, err = readTextResultSet(clientA)
	if err != nil {
		t.Fatalf("A's follow-up SELECT 1 failed (session died?): %v", err)
	}
	_ = clientA.SetReadDeadline(time.Time{})
	if len(rows) != 1 {
		t.Fatalf("A SELECT 1 rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "1" {
		t.Fatalf("A SELECT 1 cell = %q (ok=%v), want \"1\"", v, ok)
	}

	// 3. The registry still holds A — kill-query tears down nothing.
	p.mu.Lock()
	_, present := p.sessions[sidA]
	p.mu.Unlock()
	if !present {
		t.Fatal("kill-query removed the session from the registry")
	}

	// 4. Isolation: the bystander B's in-flight SLEEP was NOT aborted — it
	//    completes with the correct result (SLEEP returns 0) and B keeps
	//    round-tripping.
	rows, err = readTextResultSet(clientB)
	if err != nil {
		t.Fatalf("client B's SLEEP failed after A's kill-query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("B SLEEP rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "0" {
		t.Fatalf("B SLEEP cell = %q (ok=%v), want \"0\"", v, ok)
	}
	if err := writeMySQLPacket(clientB, 0, append([]byte{cmdQuery}, "SELECT 42"...)); err != nil {
		t.Fatalf("write B SELECT 42: %v", err)
	}
	rows, err = readTextResultSet(clientB)
	if err != nil {
		t.Fatalf("client B's follow-up query failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("B SELECT 42 rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "42" {
		t.Fatalf("B SELECT 42 cell = %q (ok=%v), want \"42\"", v, ok)
	}

	// 5. Isolation: the lock holder C is undisturbed — it still owns the
	//    lock, releases it (only the holder can), and keeps round-tripping.
	if err := writeMySQLPacket(clientC, 0, append([]byte{cmdQuery}, "SELECT RELEASE_LOCK('"+lockName+"')"...)); err != nil {
		t.Fatalf("write C RELEASE_LOCK: %v", err)
	}
	rows, err = readTextResultSet(clientC)
	if err != nil {
		t.Fatalf("holder C RELEASE_LOCK failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("C RELEASE_LOCK rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "1" {
		t.Fatalf("C RELEASE_LOCK cell = %q (ok=%v), want \"1\"", v, ok)
	}
	if err := writeMySQLPacket(clientC, 0, append([]byte{cmdQuery}, "SELECT 7"...)); err != nil {
		t.Fatalf("write C SELECT 7: %v", err)
	}
	rows, err = readTextResultSet(clientC)
	if err != nil {
		t.Fatalf("holder C's follow-up query failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("C SELECT 7 rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "7" {
		t.Fatalf("C SELECT 7 cell = %q (ok=%v), want \"7\"", v, ok)
	}
}

// TestMySQLKillConnectionLive is dispatch scenario (b) + connection-mode
// isolation: a maker session — the REAL mysql C client inside the
// mysql-test container, the exact client the house verification uses — runs
// SELECT SLEEP(60) through the proxy; a ctl:kill {sid, mode:connection}
// tears the session down. The maker's client reports Error 2013 (lost
// connection during query), the registry entry is gone, the sess:live
// directory entry is deleted, and a bystander session keeps working.
func TestMySQLKillConnectionLive(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	setToken := func(user, ticket string) string {
		token, err := store.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		tok := models.TokenPayload{Username: user, DBUser: "ro_user",
			DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: ticket}
		if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		return token
	}
	tokenA := setToken("kc-a", "T-8-3-ka")
	tokenB := setToken("kc-b", "T-8-3-kb")

	outA := killTestUserSub(t, vs, "kc-a")
	outB := killTestUserSub(t, vs, "kc-b")

	// Wildcard-bound listener: the docker mysql CLI reaches it via
	// host.docker.internal (host-side raw clients use 127.0.0.1).
	var logBuf bytes.Buffer
	ln, p := startKillTestProxyAny(t, vs, &logBuf)
	addr := killTestAddr(ln)
	k := NewKiller(p, NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil), nil)
	killOut := startKillSwitch(t, vs, k)

	// Bystander B: connects and round-trips BEFORE the kill.
	clientB := dialTestMySQLSessionAt(t, addr, tokenB)
	sidB := recvSessionEvent(t, outB).SessionID // B's started (published at dial)
	cleanupLiveRecord(t, vs, sidB)
	if err := writeMySQLPacket(clientB, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
		t.Fatalf("write B SELECT 1: %v", err)
	}
	if _, err := readTextResultSet(clientB); err != nil {
		t.Fatalf("read B result set: %v", err)
	}
	recvQueryEvent(t, outB) // B's SELECT 1 event (drain)

	// Victim A: the real mysql C client inside the mysql-test container,
	// running SELECT SLEEP(60) through the proxy.
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	cmd := exec.Command("docker", "exec", "mysql-test", "mysql",
		"-h", "host.docker.internal", "-P", port, "-u", tokenA, "-e", "SELECT SLEEP(60)")
	var cliOut, cliErr bytes.Buffer
	cmd.Stdout = &cliOut
	cmd.Stderr = &cliErr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mysql CLI: %v", err)
	}
	// The started lifecycle event proves the CLI's session is established;
	// its SLEEP query follows immediately.
	ev := recvSessionEvent(t, outA)
	if !strings.HasPrefix(ev.SessionID, "sid-") {
		t.Fatalf("CLI session_id = %q, want sid- prefix", ev.SessionID)
	}
	sidA := ev.SessionID
	time.Sleep(1500 * time.Millisecond) // SLEEP(60) now in-flight on the backend

	// The kill-connection, exactly as the control plane would publish it.
	if err := vs.Publish(ctx, "ctl:kill", []byte(`{"session_id":"`+sidA+`","mode":"connection"}`)); err != nil {
		t.Fatalf("publish ctl:kill: %v", err)
	}
	if line := recvKillOutcome(t, killOut); line != "session killed" {
		t.Fatalf("kill outcome = %q, want %q", line, "session killed")
	}

	// 1. The maker's query dies with Error 2013 (lost connection), exit 1.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("mysql CLI exited 0 after kill-connection (stderr=%q)", cliErr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("mysql CLI did not exit within 10s of the kill")
	}
	if !strings.Contains(cliErr.String(), "2013") {
		t.Errorf("mysql CLI stderr = %q, want Error 2013 (lost connection)", cliErr.String())
	}

	// 2. Registry empty: handleConn unwound and unregistered the session.
	waitSessionUnregistered(t, p, sidA)

	// 3. sess:live deleted: the session directory no longer lists A.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if findSessionRecord(t, vs, sidA) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sess:live record still present 5s after kill-connection")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 4. Isolation: the bystander session keeps working after the kill.
	if err := writeMySQLPacket(clientB, 0, append([]byte{cmdQuery}, "SELECT 42"...)); err != nil {
		t.Fatalf("write B SELECT 42: %v", err)
	}
	rows, err := readTextResultSet(clientB)
	if err != nil {
		t.Fatalf("client B's post-kill query failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("B SELECT 42 rows = %d, want 1", len(rows))
	}
	if v, ok := decodeLenencString(rows[0]); !ok || v != "42" {
		t.Fatalf("B SELECT 42 cell = %q (ok=%v), want \"42\"", v, ok)
	}
}

// TestPGKillQueryLive is the PG mirror of the kill-query money shot
// (dispatch scenario a): a maker session runs pg_sleep(60) through the
// proxy; a ctl:kill {sid, mode:query} published on the REAL channel makes
// the second backend conn run SELECT pg_cancel_backend(<pid>) — the maker's
// client receives the 57014 cancellation ErrorResponse for the sleep, and
// the SAME session immediately runs SELECT 1 → OK (session survived and
// stays in the registry).
func TestPGKillQueryLive(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	userCh := subscribePG(t, vs, "queries:alice")

	var logBuf bytes.Buffer
	ln, p, done := startPGKillTestProxy(t, vs, &logBuf)
	k := NewKiller(NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &ConfigCredResolver{}, nil), p, nil)
	killOut := startKillSwitch(t, vs, k)

	token := pgLiveToken(t, vs)
	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)

	res := pgExecQuery(t, front, "SELECT 1")
	if len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Fatalf("SELECT 1 = %v, want [[1]]", res.rows)
	}
	ev := recvQueryEvent(t, userCh)
	if !strings.HasPrefix(ev.SessionID, "sid-") {
		t.Fatalf("session_id = %q, want sid- prefix", ev.SessionID)
	}
	sid := ev.SessionID

	// pg_sleep(60) — the in-flight query to abort. Received manually (not
	// pgExecQuery, which fails the test on the expected cancellation).
	if err := front.Send(&pgproto3.Query{String: "SELECT pg_sleep(60)"}); err != nil {
		t.Fatalf("send pg_sleep: %v", err)
	}
	time.Sleep(1500 * time.Millisecond) // sleep now in-flight on the backend

	// The kill-query, exactly as the control plane would publish it.
	if err := vs.Publish(ctx, "ctl:kill", []byte(`{"session_id":"`+sid+`","mode":"query"}`)); err != nil {
		t.Fatalf("publish ctl:kill: %v", err)
	}
	if line := recvKillOutcome(t, killOut); line != "query killed" {
		t.Fatalf("kill outcome = %q, want %q", line, "query killed")
	}

	// The maker's client sees the 57014 cancellation for the sleep — the
	// conn stays up (ReadyForQuery follows).
	aborted := false
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive after kill-query: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			if m.Code != "57014" || !strings.Contains(m.Message, "canceling statement") {
				t.Errorf("abort error = %s (%s), want 57014 canceling statement", m.Code, m.Message)
			}
			aborted = true
		case *pgproto3.ReadyForQuery:
			if !aborted {
				t.Fatal("pg_sleep was not aborted by kill-query")
			}
			goto survived
		}
	}
survived:
	// The SAME session survives: SELECT 1 round-trips after the abort.
	res = pgExecQuery(t, front, "SELECT 1")
	if len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Fatalf("post-kill SELECT 1 = %v, want [[1]]", res.rows)
	}
	// The registry still holds the session — kill-query tears down nothing.
	p.mu.Lock()
	_, present := p.sessions[sid]
	p.mu.Unlock()
	if !present {
		t.Fatal("kill-query removed the PG session from the registry")
	}

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}
