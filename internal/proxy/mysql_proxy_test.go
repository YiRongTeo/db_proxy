package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// proxyTestStore connects to the live local Valkey (house rule: integration
// tests run against live infra — the valkey container is part of the dev env,
// exactly like the store package's own tests).
func proxyTestStore(t *testing.T) *store.ValkeyStore {
	t.Helper()
	vs, err := store.NewValkeyStoreDirect(context.Background(), "127.0.0.1:6379", "", 0)
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	return vs
}

func waitSubAck(t *testing.T, acked <-chan struct{}) {
	t.Helper()
	select {
	case <-acked:
	case <-time.After(5 * time.Second):
		t.Fatal("subscription not confirmed within 5s")
	}
}

func recvEvent(t *testing.T, out <-chan []byte) []byte {
	t.Helper()
	select {
	case m := <-out:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for published event")
		return nil
	}
}

// expectNoEvent asserts nothing arrives on the channel within the window
// (used for commands that must NOT be sniffed / channels that must NOT fire).
func expectNoEvent(t *testing.T, out <-chan []byte) {
	t.Helper()
	select {
	case m := <-out:
		t.Fatalf("unexpected event: %s", m)
	case <-time.After(300 * time.Millisecond):
	}
}

// buildTestHandshakeResponse builds a protocol-4.1 client handshake response
// with username = token, matching what parseHandshakeResponse expects.
func buildTestHandshakeResponse(token string) []byte {
	auth := make([]byte, 20)
	for i := range auth {
		auth[i] = byte(i + 1)
	}
	caps := uint32(capProtocol41 | capSecureConnection | capConnectWithDB)
	p := binary.LittleEndian.AppendUint32(nil, caps)
	p = binary.LittleEndian.AppendUint32(p, 1<<24) // max packet size
	p = append(p, 33)                              // charset
	p = append(p, make([]byte, 23)...)             // reserved
	p = append(p, []byte(token)...)
	p = append(p, 0x00)
	p = append(p, byte(len(auth)))
	p = append(p, auth...)
	p = append(p, []byte("appdb")...)
	p = append(p, 0x00)
	return p
}

// startTestProxy runs handleConn on a fresh listener for one connection and
// returns the listener plus a channel closed when the session ends. The
// Dispatcher (Task 3.5) is not wired yet, so the test acts as it: accept +
// bufio.Reader + handleConn.
func startTestProxy(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer) (net.Listener, <-chan struct{}) {
	t.Helper()
	return startTestProxyWithCreds(t, vs, logBuf, map[string]string{"mysql:ro_user@127.0.0.1:3307": "ro_pw"})
}

// startTestProxyWithCreds is startTestProxy with a caller-supplied credential
// map (used by tests that point the backend at a fake listener).
func startTestProxyWithCreds(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, creds map[string]string) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewMySQLProxy(logger, vs, &ConfigCredResolver{Creds: creds}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.handleConn(context.Background(), conn, bufio.NewReader(conn))
	}()
	return ln, done
}

// --- sniffing semantics (Task 6.2: publish on response completion) ----------

// TestSniffCommandPublishesQueryEventsOnResponse: every sniffed command
// stashes a pending QueryEvent with the correct kind/sql/stmt_type and full
// token context; NOTHING is published at sniff time — the event is published
// only when the backend's response completes (synthetic OK here), carrying
// status=ok. Non-sniffed commands (COM_QUIT, COM_PING) never publish.
func TestSniffCommandPublishesQueryEventsOnResponse(t *testing.T) {
	vs := proxyTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan []byte, 8)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, "queries:test-user", false, out)
	waitSubAck(t, acked)

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := newTestSession()
	tok := &models.TokenPayload{Username: "test-user", TicketID: "T-3-4",
		DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "3307"}

	cases := []struct {
		cmd  byte
		body []byte
		kind string
		sql  string
		stmt string
	}{
		{cmdQuery, []byte("SELECT * FROM users"), "query", "SELECT * FROM users", "select"},
		// Real clients NUL-terminate command payloads — the sniffed copy must
		// be trimmed (Task 3.7 deferred fix); the relayed bytes are untouched.
		{cmdQuery, []byte("SELECT * FROM users\x00"), "query", "SELECT * FROM users", "select"},
		{cmdInitDB, []byte("appdb"), "use", "USE appdb", "other"},
		{cmdInitDB, []byte("appdb\x00"), "use", "USE appdb", "other"},
		{cmdPrepare, []byte("SELECT id FROM t WHERE id = ?"), "prepare", "SELECT id FROM t WHERE id = ?", "select"},
		{cmdPrepare, []byte("SELECT id FROM t WHERE id = ?\x00"), "prepare", "SELECT id FROM t WHERE id = ?", "select"},
		{cmdExecute, []byte{42, 0, 0, 0, 1, 2, 3}, "execute", "EXECUTE stmt_id=42", "other"},
		{cmdExecute, []byte{1, 2}, "execute", "EXECUTE stmt_id=?", "other"}, // truncated stmt id
	}
	for _, tc := range cases {
		p.sniffCommand(s, tc.cmd, tc.body, tok, "127.0.0.1:55555")
		expectNoEvent(t, out) // not published at sniff time — waits for the response
		completePending(p, s)
		var ev models.QueryEvent
		if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if ev.Kind != tc.kind || ev.SQL != tc.sql {
			t.Errorf("cmd %#x: kind=%q sql=%q, want kind=%q sql=%q", tc.cmd, ev.Kind, ev.SQL, tc.kind, tc.sql)
		}
		if ev.StmtType != tc.stmt {
			t.Errorf("cmd %#x: stmt_type=%q, want %q", tc.cmd, ev.StmtType, tc.stmt)
		}
		if ev.Status != "ok" || ev.Error != "" {
			t.Errorf("cmd %#x: status=%q error=%q, want ok/empty", tc.cmd, ev.Status, ev.Error)
		}
		if ev.SessionID != s.id {
			t.Errorf("cmd %#x: session_id=%q, want %q", tc.cmd, ev.SessionID, s.id)
		}
		if ev.Username != "test-user" || ev.TicketID != "T-3-4" ||
			ev.DBUser != "ro_user" || ev.DBIP != "127.0.0.1" || ev.DBPort != "3307" ||
			ev.DBType != "mysql" || ev.ClientAddr != "127.0.0.1:55555" {
			t.Errorf("cmd %#x: event context mismatch: %+v", tc.cmd, ev)
		}
		if len(ev.ID) != 16 || ev.Ts.IsZero() {
			t.Errorf("cmd %#x: id=%q ts=%v, want 16-hex id and non-zero ts", tc.cmd, ev.ID, ev.Ts)
		}
	}

	// Non-sniffed commands (COM_QUIT, COM_PING) must publish nothing, even
	// after a response completes.
	p.sniffCommand(s, cmdQuit, nil, tok, "127.0.0.1:55555")
	p.sniffCommand(s, cmdPing, nil, tok, "127.0.0.1:55555")
	completePending(p, s)
	expectNoEvent(t, out)
}

// TestSniffCommandPublishesTicketChannel: events are also published to
// queries:ticket:<ticket_id> when the token carries one, and never when it
// does not.
func TestSniffCommandPublishesTicketChannel(t *testing.T) {
	vs := proxyTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan []byte, 4)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, "queries:ticket:T-3-4", false, out)
	waitSubAck(t, acked)

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := newTestSession()

	// With a ticket: event lands on the ticket channel once the response
	// completes.
	p.sniffCommand(s, cmdQuery, []byte("SELECT 1"), &models.TokenPayload{
		Username: "test-user", TicketID: "T-3-4", DBUser: "ro_user"}, "c")
	completePending(p, s)
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.TicketID != "T-3-4" || ev.SQL != "SELECT 1" {
		t.Errorf("ticket event: ticket_id=%q sql=%q, want T-3-4 / SELECT 1", ev.TicketID, ev.SQL)
	}

	// Without a ticket: nothing on the ticket channel.
	p.sniffCommand(s, cmdQuery, []byte("SELECT 2"), &models.TokenPayload{Username: "test-user"}, "c")
	completePending(p, s)
	expectNoEvent(t, out)
}

// --- session lifecycle (light; full integration is Task 3.7) ---------------

// TestMySQLSessionRelayAndTeardown runs the full 6-step session against the
// live mysql-test backend: handshake -> token response -> GETDEL validation ->
// backend connect -> OK -> byte-exact relay of a real result set -> teardown
// when the client disconnects. Verifies the done-channel teardown path and
// that the token is consumed atomically (single-use gate).
func TestMySQLSessionRelayAndTeardown(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "test-user", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-3-4"}
	if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	var logBuf bytes.Buffer
	ln, proxyDone := startTestProxy(t, vs, &logBuf)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	// 1. server handshake (seq 0)
	if _, _, err := readMySQLPacket(client); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	// 2. handshake response carrying the token
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	// 3+4+5. OK (seq 2) = token validated, backend connected, session up
	seq, resp, err := readMySQLPacket(client)
	if err != nil {
		t.Fatalf("read OK: %v", err)
	}
	if seq != 2 {
		t.Errorf("OK seq = %d, want 2", seq)
	}
	if len(resp) == 0 || resp[0] != 0x00 {
		t.Fatalf("expected OK packet, got % x", resp)
	}

	// 6. relay round trip: COM_QUERY "SELECT 1" -> real result set from MySQL.
	if err := writeMySQLPacket(client, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
		t.Fatalf("write COM_QUERY: %v", err)
	}
	seenEOF := false
	for i := 0; i < 20; i++ {
		_, pkt, err := readMySQLPacket(client)
		if err != nil {
			t.Fatalf("read result packet %d: %v", i, err)
		}
		if len(pkt) > 0 && pkt[0] == 0xfe { // EOF terminates the result set
			seenEOF = true
			break
		}
	}
	if !seenEOF {
		t.Fatal("result set did not terminate with an EOF packet")
	}

	// Teardown: client close must unblock both pipes; handleConn returns.
	client.Close()
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return within 5s of client close")
	}

	// Single-use gate: the token was consumed by GETDEL during the session.
	if got, err := vs.GetDeleteToken(ctx, token); err != nil || got != nil {
		t.Fatalf("token not consumed: got=%v err=%v", got, err)
	}

	// Session lifecycle logged with identity, never the token value.
	logs := logBuf.String()
	for _, want := range []string{"session established", "session closed", "test-user", "ro_user"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, token) {
		t.Errorf("logs must never contain the token value:\n%s", logs)
	}
}

// TestMySQLSessionTokenRejection: invalid/expired and wrong-protocol tokens
// are rejected with ERR 1045 (seq 2) and the session is torn down.
func TestMySQLSessionTokenRejection(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		present func(t *testing.T) string // token to present in the handshake
		wantMsg string
	}{
		{"invalid-or-expired", func(t *testing.T) string { return "sess_no_such_token" }, "invalid or expired token"},
		{"wrong-protocol", func(t *testing.T) string {
			token, err := store.NewToken()
			if err != nil {
				t.Fatalf("NewToken: %v", err)
			}
			if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "u", DBType: "postgres"}, time.Minute); err != nil {
				t.Fatalf("SetToken: %v", err)
			}
			return token
		}, "token not valid for this protocol"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			ln, _ := startTestProxy(t, vs, &logBuf)

			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer client.Close()

			if _, _, err := readMySQLPacket(client); err != nil {
				t.Fatalf("read handshake: %v", err)
			}
			if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(tc.present(t))); err != nil {
				t.Fatalf("write handshake response: %v", err)
			}
			seq, resp, err := readMySQLPacket(client)
			if err != nil {
				t.Fatalf("read ERR: %v", err)
			}
			if seq != 2 {
				t.Errorf("ERR seq = %d, want 2", seq)
			}
			if len(resp) == 0 || resp[0] != 0xff {
				t.Fatalf("expected ERR packet, got % x", resp)
			}
			if !bytes.Contains(resp, []byte(tc.wantMsg)) {
				t.Errorf("ERR packet missing %q: % x", tc.wantMsg, resp)
			}
		})
	}
}

// --- Task 3.7: sniffed-SQL NUL trim ----------------------------------------

// TestSniffCommandTrimsTrailingNUL: real COM_QUERY/COM_INIT_DB/COM_STMT_PREPARE
// payloads are NUL-terminated; the published event SQL must carry neither the
// NUL nor any whitespace after it, while a payload without a NUL is unchanged.
func TestSniffCommandTrimsTrailingNUL(t *testing.T) {
	vs := proxyTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan []byte, 8)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, "queries:test-user", false, out)
	waitSubAck(t, acked)

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	tok := &models.TokenPayload{Username: "test-user", DBUser: "ro_user"}
	s := newTestSession()

	cases := []struct {
		name string
		cmd  byte
		body []byte
		want string
	}{
		{"query-nul", cmdQuery, []byte("SELECT 1\x00"), "SELECT 1"},
		{"query-nul-spaces", cmdQuery, []byte("SELECT 1\x00  "), "SELECT 1"},
		{"query-nul-tab", cmdQuery, []byte("SELECT 1\x00	"), "SELECT 1"},
		{"query-no-nul", cmdQuery, []byte("SELECT 1"), "SELECT 1"},
		{"query-trailing-space-before-nul", cmdQuery, []byte("SELECT 1 \x00"), "SELECT 1"},
		{"initdb-nul", cmdInitDB, []byte("appdb\x00"), "USE appdb"},
		{"prepare-nul", cmdPrepare, []byte("SELECT ?\x00"), "SELECT ?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p.sniffCommand(s, tc.cmd, tc.body, tok, "127.0.0.1:55555")
			completePending(p, s)
			var ev models.QueryEvent
			if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
				t.Fatalf("unmarshal event: %v", err)
			}
			if ev.SQL != tc.want {
				t.Errorf("sql=%q, want %q (no trailing NUL)", ev.SQL, tc.want)
			}
			if strings.ContainsRune(ev.SQL, 0) {
				t.Errorf("sql=%q still contains a NUL byte", ev.SQL)
			}
		})
	}
}

// --- Task 3.7: byte/seq-exact relay assertion -------------------------------

// startFakeBackend speaks just enough server-side MySQL for connectMySQLBackend
// (go-mysql client) to complete auth, then records every subsequent packet it
// receives — raw 4-byte header + payload — on recv and answers each client
// command with an OK packet so the relay round-trips.
func startFakeBackend(t *testing.T) (addr string, recv chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake backend listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	recv = make(chan []byte, 16)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		authData, err := randomAuthData()
		if err != nil {
			return
		}
		hs, err := buildHandshakeV10("8.4.0-fake", 1, authData, advertisedCaps)
		if err != nil {
			return
		}
		if err := writeMySQLPacket(conn, 0, hs); err != nil {
			return
		}
		if _, _, err := readMySQLPacket(conn); err != nil { // client handshake response
			return
		}
		if err := writeMySQLPacket(conn, 2, okPacket()); err != nil {
			return
		}
		for {
			hdr := make([]byte, 4)
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
			payload := make([]byte, length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
			recv <- append(append([]byte{}, hdr...), payload...)
			// Answer with an OK packet (client commands restart at seq 0).
			if err := writeMySQLPacket(conn, hdr[3]+1, okPacket()); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), recv
}

func recvBackendPacket(t *testing.T, recv <-chan []byte) []byte {
	t.Helper()
	select {
	case p := <-recv:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for packet captured by the backend")
		return nil
	}
}

// TestMySQLSessionRelayByteExactToBackend proves the client→backend relay is
// byte-exact: the raw header bytes (3-byte LE length + sequence id) the test
// client writes are replayed unchanged to the backend — sniffing must never
// alter the stream. The COM_QUERY payload intentionally ends with a NUL byte
// (as real clients send); the backend must receive it untouched, and a second
// command at seq 1 proves the original sequence id passes through (no
// renumbering). Session lifecycle + single-use gate are re-asserted here too.
func TestMySQLSessionRelayByteExactToBackend(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	backendAddr, backendRecv := startFakeBackend(t)
	_, port, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("split backend addr: %v", err)
	}

	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "test-user", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: port, DBType: "mysql"}
	if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	var logBuf bytes.Buffer
	creds := map[string]string{fmt.Sprintf("mysql:ro_user@127.0.0.1:%s", port): "ro_pw"}
	ln, proxyDone := startTestProxyWithCreds(t, vs, &logBuf, creds)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	// Handshake + auth (steps 1-5).
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

	// Two client commands: COM_QUERY at seq 0 (NUL-terminated payload, as a
	// real client sends it) and COM_PING at seq 1 (empty payload).
	query := append([]byte{cmdQuery}, "SELECT 99\x00"...)
	if err := writeMySQLPacket(client, 0, query); err != nil {
		t.Fatalf("write COM_QUERY: %v", err)
	}
	if err := writeMySQLPacket(client, 1, []byte{cmdPing}); err != nil {
		t.Fatalf("write COM_PING: %v", err)
	}

	// The Task 8.2 thread-id capture runs FIRST on the raw backend conn
	// (before the OK packet): the fake backend must have received exactly
	// the capture's COM_QUERY, and the capture consumed its OK reply, so
	// the relay stream starts clean.
	want := func(seq byte, payload []byte) []byte {
		return append([]byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}, payload...)
	}
	capQ := append([]byte{cmdQuery}, "SELECT CONNECTION_ID()"...)
	if got := recvBackendPacket(t, backendRecv); !bytes.Equal(got, want(0, capQ)) {
		t.Errorf("backend received % x\nwant the thread-id capture query % x (seq 0)", got, want(0, capQ))
	}

	// Exact wire bytes the client wrote: 3-byte LE length + seq + payload.
	if got := recvBackendPacket(t, backendRecv); !bytes.Equal(got, want(0, query)) {
		t.Errorf("backend received % x\nwant byte-exact % x (seq 0, trailing NUL preserved)", got, want(0, query))
	}
	if got := recvBackendPacket(t, backendRecv); !bytes.Equal(got, want(1, []byte{cmdPing})) {
		t.Errorf("backend received % x\nwant byte-exact % x (seq 1 passed through, not renumbered)", got, want(1, []byte{cmdPing}))
	}

	// Both OK replies come back to the client through the relay.
	for i := 0; i < 2; i++ {
		if _, pkt, err := readMySQLPacket(client); err != nil || len(pkt) == 0 || pkt[0] != 0x00 {
			t.Fatalf("expected OK reply %d, got % x err=%v", i, pkt, err)
		}
	}

	// Teardown: client close must unblock both pipes; handleConn returns.
	client.Close()
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return within 5s of client close")
	}

	// Single-use gate: the token was consumed by GETDEL during the session.
	if got, err := vs.GetDeleteToken(ctx, token); err != nil || got != nil {
		t.Fatalf("token not consumed: got=%v err=%v", got, err)
	}
	// No token value in the logs.
	if logs := logBuf.String(); strings.Contains(logs, token) {
		t.Errorf("logs must never contain the token value:\n%s", logs)
	}
}

// --- Task 6.2: live response capture -----------------------------------------

// TestMySQLSessionCaptureLive runs a full session against the live mysql-test
// backend and asserts the PUBLISHED QueryEvents carry the classified stmt
// type and the captured backend response: a SELECT's result set (columns +
// rows, status ok, not truncated) and a failing query's server error message
// (status error). The user channel and the ticket channel both receive the
// same event.
func TestMySQLSessionCaptureLive(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "test-user", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-6-2"}
	if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	subCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	userOut := make(chan []byte, 8)
	userAcked := make(chan struct{}, 1)
	userSubCtx := valkey.WithOnSubscriptionHook(subCtx, func(valkey.PubSubSubscription) {
		select {
		case userAcked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(userSubCtx, "queries:test-user", false, userOut)
	waitSubAck(t, userAcked)
	ticketOut := make(chan []byte, 8)
	ticketAcked := make(chan struct{}, 1)
	ticketSubCtx := valkey.WithOnSubscriptionHook(subCtx, func(valkey.PubSubSubscription) {
		select {
		case ticketAcked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(ticketSubCtx, "queries:ticket:T-6-2", false, ticketOut)
	waitSubAck(t, ticketAcked)

	var logBuf bytes.Buffer
	ln, proxyDone := startTestProxy(t, vs, &logBuf)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	// Steps 1-5: server handshake, token response, OK.
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

	// SELECT with a real result set: the published event carries the stmt
	// type plus the captured columns/rows and status ok.
	sel := "SELECT id,name FROM demo_items"
	if err := writeMySQLPacket(client, 0, append([]byte{cmdQuery}, sel...)); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	if _, err := readTextResultSet(client); err != nil {
		t.Fatalf("read result set: %v", err)
	}
	// The started lifecycle event precedes the query event on the user
	// channel — recvQueryEvent skips kind=session events.
	ev := recvQueryEvent(t, userOut)
	if ev.Kind != "query" || ev.SQL != sel {
		t.Errorf("event kind/sql = %q/%q, want query/%q", ev.Kind, ev.SQL, sel)
	}
	if ev.StmtType != "select" {
		t.Errorf("stmt_type = %q, want select", ev.StmtType)
	}
	if ev.Status != "ok" || ev.Error != "" {
		t.Errorf("status/error = %q/%q, want ok/empty", ev.Status, ev.Error)
	}
	if !reflect.DeepEqual(ev.Columns, []string{"id", "name"}) {
		t.Errorf("columns = %q, want [id name]", ev.Columns)
	}
	// The live seed is (1,test),(2,bravo),(3,charlie) — row 1's name was
	// changed to 'test' by a prior task's UPDATE; alpha is only in the docs.
	wantRows := [][]string{{"1", "test"}, {"2", "bravo"}, {"3", "charlie"}}
	if !reflect.DeepEqual(ev.Rows, wantRows) {
		t.Errorf("rows = %q, want %q", ev.Rows, wantRows)
	}
	if ev.Truncated {
		t.Error("truncated = true, want false")
	}
	if !strings.HasPrefix(ev.SessionID, "sid-") {
		t.Errorf("session_id = %q, want sid- prefix", ev.SessionID)
	}
	if len(ev.ID) != 16 || ev.Ts.IsZero() {
		t.Errorf("id=%q ts=%v, want 16-hex id and non-zero ts", ev.ID, ev.Ts)
	}
	// The ticket channel receives the same event (same id).
	var tev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, ticketOut), &tev); err != nil {
		t.Fatalf("unmarshal ticket event: %v", err)
	}
	if tev.ID != ev.ID {
		t.Errorf("ticket event id %q != user event id %q", tev.ID, ev.ID)
	}

	// Failing query: status error with the server's message; no result set.
	if err := writeMySQLPacket(client, 0, append([]byte{cmdQuery}, "SELECT * FROM nope"...)); err != nil {
		t.Fatalf("write error query: %v", err)
	}
	if seq, resp, err := readMySQLPacket(client); err != nil || len(resp) == 0 || resp[0] != 0xff {
		t.Fatalf("expected ERR packet, got seq=%d resp=% x err=%v", seq, resp, err)
	}
	// Unmarshal into a FRESH struct: absent omitempty fields (columns/rows
	// on the error event) do NOT clear values left by the previous event.
	ev = recvQueryEvent(t, userOut)
	if ev.StmtType != "select" {
		t.Errorf("error event stmt_type = %q, want select", ev.StmtType)
	}
	if ev.Status != "error" {
		t.Errorf("error event status = %q, want error", ev.Status)
	}
	if !strings.Contains(ev.Error, "doesn't exist") {
		t.Errorf("error message = %q, want it to contain %q", ev.Error, "doesn't exist")
	}
	if len(ev.Columns) != 0 || len(ev.Rows) != 0 {
		t.Errorf("error event must carry no result set, got columns=%q rows=%q", ev.Columns, ev.Rows)
	}

	// Teardown: client close must unblock both pipes; handleConn returns.
	client.Close()
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return within 5s of client close")
	}
}

// --- Task 7.4: MySQL wire TLS -----------------------------------------------

// neverReadConn is a net.Conn stub whose Read is never exercised — used to
// prove bufferedConn drains its bufio.Reader (the wrapped conn must not be
// touched while buffered bytes remain).
type neverReadConn struct{ net.Conn }

func (neverReadConn) Read([]byte) (int, error) { return 0, io.EOF }

// TestBufferedConnPreservesBufferedBytes (Task 7.4): clients commonly
// coalesce the SSLRequest packet and the start of the TLS handshake into one
// TCP segment. readMySQLPacket consumes exactly the SSLRequest; the leftover
// bytes sit in br's buffer and MUST be visible to the TLS layer — otherwise
// the handshake hangs. bufferedConn reads through br first, so nothing is
// lost.
func TestBufferedConnPreservesBufferedBytes(t *testing.T) {
	sslReq := make([]byte, 32)
	binary.LittleEndian.PutUint32(sslReq[0:4], uint32(capSSL|capProtocol41))
	var seg bytes.Buffer
	seg.Write([]byte{32, 0, 0, 1}) // packet header: len=32, seq=1
	seg.Write(sslReq)
	clientHello := []byte{0x16, 0x03, 0x01, 0x02, 0x00} // TLS record header bytes
	seg.Write(clientHello)

	br := bufio.NewReader(bytes.NewReader(seg.Bytes()))
	seq, payload, err := readMySQLPacket(br)
	if err != nil {
		t.Fatalf("readMySQLPacket: %v", err)
	}
	if seq != 1 || !bytes.Equal(payload, sslReq) {
		t.Fatalf("seq=%d payload=% x, want seq=1 SSLRequest", seq, payload)
	}
	if br.Buffered() != len(clientHello) {
		t.Fatalf("buffered = %d bytes, want %d (the TLS bytes)", br.Buffered(), len(clientHello))
	}

	bc := &bufferedConn{Conn: neverReadConn{}, r: br}
	got := make([]byte, len(clientHello))
	if _, err := io.ReadFull(bc, got); err != nil {
		t.Fatalf("read through bufferedConn: %v", err)
	}
	if !bytes.Equal(got, clientHello) {
		t.Errorf("bufferedConn read = % x, want % x (buffered TLS bytes preserved)", got, clientHello)
	}
}

// loadTestTLS loads the self-signed data-plane cert from certs/ (committed
// dev certs generated by scripts/gen-certs.sh; skipped when absent so the
// suite stays green on a fresh clone without certs).
func loadTestTLS(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../certs/data.crt", "../../certs/data.key")
	if err != nil {
		t.Skipf("certs/data.{crt,key} not available (run scripts/gen-certs.sh): %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// startTestTLSProxy runs handleConn on a fresh TLS-enabled listener for one
// connection (Task 7.4): the proxy advertises CLIENT_SSL and answers an
// SSLRequest with a real TLS handshake before auth.
func startTestTLSProxy(t *testing.T, vs *store.ValkeyStore) (net.Listener, <-chan struct{}) {
	t.Helper()
	tlsCfg := loadTestTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs,
		&ConfigCredResolver{Creds: map[string]string{"mysql:ro_user@127.0.0.1:3307": "ro_pw"}}, tlsCfg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.handleConn(context.Background(), conn, bufio.NewReader(conn))
	}()
	return ln, done
}

// TestMySQLSessionOverTLS (Task 7.4): the full 6-step session with a TLS
// client — the handshake advertises CLIENT_SSL, the client answers with an
// SSLRequest, the proxy upgrades to TLS, and auth + relay run over the
// encrypted conn (real tls.Client, InsecureSkipVerify for the self-signed
// cert — REQUIRED semantics: encryption, no verification). Verifies the
// capture event still flows and the token is consumed (single-use).
func TestMySQLSessionOverTLS(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "tls-user", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-7-4"}
	if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	out := make(chan []byte, 4)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, "queries:tls-user", false, out)
	waitSubAck(t, acked)

	ln, done := startTestTLSProxy(t, vs)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	// 1. server handshake must advertise CLIENT_SSL (Task 7.4).
	_, hs, err := readMySQLPacket(client)
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if handshakeCapBits(t, hs)&capSSL == 0 {
		t.Fatalf("handshake caps %#x missing CLIENT_SSL 0x0800 on a TLS listener", handshakeCapBits(t, hs))
	}

	// 2. SSLRequest (seq 1) then a real TLS handshake over the same conn.
	sslReq := make([]byte, 32)
	binary.LittleEndian.PutUint32(sslReq[0:4], uint32(capSSL|capProtocol41|capSecureConnection|capConnectWithDB))
	if err := writeMySQLPacket(client, 1, sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if tlsClient.ConnectionState().Version == 0 {
		t.Fatal("TLS handshake completed without a negotiated version")
	}

	// 3. REAL handshake response (auth) over TLS. The C client's seq counter
	// is at 2 here (handshake=0 srv, SSLRequest=1 cli, auth=2 cli) — the
	// proxy's reply MUST therefore be seq 3 (regression: a seq-2 OK under
	// TLS is dropped by the mysql 8.4 C client's strict SSL_read validation,
	// ERROR 2013 'reading authorization packet').
	if err := writeMySQLPacket(tlsClient, 2, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response over TLS: %v", err)
	}

	// 4+5. OK (seq 3) over TLS = token validated, backend connected.
	seq, resp, err := readMySQLPacket(tlsClient)
	if err != nil {
		t.Fatalf("read OK over TLS: %v", err)
	}
	if seq != 3 || len(resp) == 0 || resp[0] != 0x00 {
		t.Fatalf("expected OK packet seq 3 over TLS, got seq=%d resp=% x", seq, resp)
	}

	// 6. relay round trip over TLS: COM_QUERY SELECT 1 → real result set.
	if err := writeMySQLPacket(tlsClient, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
		t.Fatalf("write COM_QUERY over TLS: %v", err)
	}
	seenEOF := false
	for i := 0; i < 20; i++ {
		_, pkt, err := readMySQLPacket(tlsClient)
		if err != nil {
			t.Fatalf("read result packet %d over TLS: %v", i, err)
		}
		if len(pkt) > 0 && pkt[0] == 0xfe {
			seenEOF = true
			break
		}
	}
	if !seenEOF {
		t.Fatal("result set over TLS did not terminate with an EOF packet")
	}

	// Capture event flows with the response status (same as plaintext).
	// The started lifecycle event precedes it on the channel — skip it.
	ev := recvQueryEvent(t, out)
	if ev.Status != "ok" || ev.StmtType != "select" || ev.SQL != "SELECT 1" {
		t.Errorf("event = status %q stmt_type %q sql %q, want ok/select/SELECT 1", ev.Status, ev.StmtType, ev.SQL)
	}

	// Teardown: closing the TLS conn must unblock both relay pipes.
	tlsClient.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return within 5s of TLS client close")
	}

	// Single-use gate: the token was consumed by GETDEL during the session.
	if got, err := vs.GetDeleteToken(ctx, token); err != nil || got != nil {
		t.Fatalf("token not consumed: got=%v err=%v", got, err)
	}
}

// TestMySQLSessionAuthErrorOverTLS (Task 7.4 round 2): every auth-phase
// rejection over TLS — invalid/expired token, wrong-protocol token, backend
// unavailable — must be answered with ERR 1045 at seq 3. The SSLRequest
// consumed seq 1 (handshake=0 srv, SSLRequest=1 cli, auth=2 cli), so the
// reply is one higher than the plaintext seq 2. The Go client tolerates
// wrong seq numbers; the mysql 8.4 C client's strict SSL_read validation
// does not (it drops a seq-2 ERR under TLS), so the seq byte is asserted
// explicitly.
func TestMySQLSessionAuthErrorOverTLS(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		present func(t *testing.T) string // token to present in the handshake
		wantMsg string
	}{
		{"invalid-or-expired", func(t *testing.T) string { return "sess_no_such_token" }, "invalid or expired token"},
		{"wrong-protocol", func(t *testing.T) string {
			token, err := store.NewToken()
			if err != nil {
				t.Fatalf("NewToken: %v", err)
			}
			if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "u", DBType: "postgres"}, time.Minute); err != nil {
				t.Fatalf("SetToken: %v", err)
			}
			return token
		}, "token not valid for this protocol"},
		{"backend-unavailable", func(t *testing.T) string {
			token, err := store.NewToken()
			if err != nil {
				t.Fatalf("NewToken: %v", err)
			}
			// DBUser "nobody" has no entry in the proxy's credential map →
			// connectMySQLBackend fails fast ("no credentials") → ERR.
			if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "u", DBUser: "nobody",
				DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql"}, time.Minute); err != nil {
				t.Fatalf("SetToken: %v", err)
			}
			return token
		}, "backend unavailable"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, _ := startTestTLSProxy(t, vs)

			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer client.Close()

			// 1. server handshake must advertise CLIENT_SSL.
			_, hs, err := readMySQLPacket(client)
			if err != nil {
				t.Fatalf("read handshake: %v", err)
			}
			if handshakeCapBits(t, hs)&capSSL == 0 {
				t.Fatalf("handshake caps %#x missing CLIENT_SSL 0x0800", handshakeCapBits(t, hs))
			}
			// 2. SSLRequest (seq 1) then a real TLS handshake.
			sslReq := make([]byte, 32)
			binary.LittleEndian.PutUint32(sslReq[0:4], uint32(capSSL|capProtocol41|capSecureConnection|capConnectWithDB))
			if err := writeMySQLPacket(client, 1, sslReq); err != nil {
				t.Fatalf("write SSLRequest: %v", err)
			}
			tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			if err := tlsClient.Handshake(); err != nil {
				t.Fatalf("client TLS handshake: %v", err)
			}
			// 3. auth response over TLS at seq 2 (the real C-client counter).
			if err := writeMySQLPacket(tlsClient, 2, buildTestHandshakeResponse(tc.present(t))); err != nil {
				t.Fatalf("write handshake response over TLS: %v", err)
			}
			// 4. ERR must come back at seq 3 under TLS (not 2).
			seq, resp, err := readMySQLPacket(tlsClient)
			if err != nil {
				t.Fatalf("read ERR over TLS: %v", err)
			}
			if seq != 3 {
				t.Errorf("ERR seq = %d, want 3 under TLS", seq)
			}
			if len(resp) == 0 || resp[0] != 0xff {
				t.Fatalf("expected ERR packet, got % x", resp)
			}
			if !bytes.Contains(resp, []byte(tc.wantMsg)) {
				t.Errorf("ERR packet missing %q: % x", tc.wantMsg, resp)
			}
		})
	}
}
