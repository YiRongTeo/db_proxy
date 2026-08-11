package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	vs, err := store.NewValkeyStore(context.Background(), "127.0.0.1:6379", "", 0)
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
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
	return startTestProxyWithCreds(t, vs, logBuf, map[string]string{"127.0.0.1:3307:ro_user": "ro_pw"})
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
	p := NewMySQLProxy(logger, vs, creds)
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

// --- sniffing semantics ---------------------------------------------------

// TestSniffCommandPublishesQueryEvents: every sniffed command publishes a
// QueryEvent with the correct kind/sql and full token context to
// queries:<username>.
func TestSniffCommandPublishesQueryEvents(t *testing.T) {
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

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, nil)
	tok := &models.TokenPayload{Username: "test-user", TicketID: "T-3-4",
		DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "3307"}

	cases := []struct {
		cmd  byte
		body []byte
		kind string
		sql  string
	}{
		{cmdQuery, []byte("SELECT * FROM users"), "query", "SELECT * FROM users"},
		// Real clients NUL-terminate command payloads — the sniffed copy must
		// be trimmed (Task 3.7 deferred fix); the relayed bytes are untouched.
		{cmdQuery, []byte("SELECT * FROM users\x00"), "query", "SELECT * FROM users"},
		{cmdInitDB, []byte("appdb"), "use", "USE appdb"},
		{cmdInitDB, []byte("appdb\x00"), "use", "USE appdb"},
		{cmdPrepare, []byte("SELECT id FROM t WHERE id = ?"), "prepare", "SELECT id FROM t WHERE id = ?"},
		{cmdPrepare, []byte("SELECT id FROM t WHERE id = ?\x00"), "prepare", "SELECT id FROM t WHERE id = ?"},
		{cmdExecute, []byte{42, 0, 0, 0, 1, 2, 3}, "execute", "EXECUTE stmt_id=42"},
		{cmdExecute, []byte{1, 2}, "execute", "EXECUTE stmt_id=?"}, // truncated stmt id
	}
	for _, tc := range cases {
		p.sniffCommand(tc.cmd, tc.body, tok, "127.0.0.1:55555")
		var ev models.QueryEvent
		if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if ev.Kind != tc.kind || ev.SQL != tc.sql {
			t.Errorf("cmd %#x: kind=%q sql=%q, want kind=%q sql=%q", tc.cmd, ev.Kind, ev.SQL, tc.kind, tc.sql)
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

	// Non-sniffed commands (COM_QUIT, COM_PING) must publish nothing.
	p.sniffCommand(cmdQuit, nil, tok, "127.0.0.1:55555")
	p.sniffCommand(cmdPing, nil, tok, "127.0.0.1:55555")
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

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, nil)

	// With a ticket: event lands on the ticket channel.
	p.sniffCommand(cmdQuery, []byte("SELECT 1"), &models.TokenPayload{
		Username: "test-user", TicketID: "T-3-4", DBUser: "ro_user"}, "c")
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.TicketID != "T-3-4" || ev.SQL != "SELECT 1" {
		t.Errorf("ticket event: ticket_id=%q sql=%q, want T-3-4 / SELECT 1", ev.TicketID, ev.SQL)
	}

	// Without a ticket: nothing on the ticket channel.
	p.sniffCommand(cmdQuery, []byte("SELECT 2"), &models.TokenPayload{Username: "test-user"}, "c")
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

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, nil)
	tok := &models.TokenPayload{Username: "test-user", DBUser: "ro_user"}

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
			p.sniffCommand(tc.cmd, tc.body, tok, "127.0.0.1:55555")
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
		hs, err := buildHandshakeV10("8.4.0-fake", 1, authData)
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
	creds := map[string]string{fmt.Sprintf("127.0.0.1:%s:ro_user", port): "ro_pw"}
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

	// Exact wire bytes the client wrote: 3-byte LE length + seq + payload.
	want := func(seq byte, payload []byte) []byte {
		return append([]byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}, payload...)
	}
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
