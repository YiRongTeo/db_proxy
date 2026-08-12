package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 3.8: edge-case robustness -----------------------------------------

// startEdgeBackend is a fake MySQL backend for the edge-case tests. It
// accepts ANY number of connections (edge tests need a backend that survives
// session teardowns and serves follow-up sessions), completes the go-mysql
// auth handshake per connection, records every post-auth packet it receives
// (raw 4-byte header + payload) on recv, replies OK to commands, and — like a
// real MySQL server — closes a connection after COM_QUIT without replying.
// closed fires when no connections remain (the session under test tore down).
func startEdgeBackend(t *testing.T) (addr string, recv chan []byte, closed chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("edge backend listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	recv = make(chan []byte, 64)
	closed = make(chan struct{})
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()
				authData, err := randomAuthData()
				if err != nil {
					return
				}
				hs, err := buildHandshakeV10("8.4.0-edge-fake", 1, authData, advertisedCaps)
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
					if len(payload) > 0 && payload[0] == cmdQuit {
						return // real servers close after COM_QUIT without replying
					}
					if err := writeMySQLPacket(conn, hdr[3]+1, okPacket()); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	go func() {
		wg.Wait()
		close(closed)
	}()
	return ln.Addr().String(), recv, closed
}

// startStallingBackend accepts TCP connections but never sends the server
// handshake — a backend that has accepted but is dead/black-holed.
func startStallingBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stalling backend listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(io.Discard, c) // hold the conn open, never speak
				c.Close()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startEdgeDispatcher runs the REAL Dispatcher (accept loop + shared-port
// protocol detection) on a fresh listener with a short detect delay, wired to
// the given backend credentials — the production entry path the edge-case
// tests must exercise: accept -> decide -> handleConn. Session logs go to
// logW (io.Discard unless a test needs them). The listener is closed at
// cleanup, which ends Serve.
func startEdgeDispatcher(t *testing.T, vs *store.ValkeyStore, creds map[string]string, logW io.Writer) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logW, nil))
	d := NewDispatcher(logger, NewMySQLProxy(logger, vs, creds, nil), &PGProxy{}, 100*time.Millisecond, 64)
	go d.Serve(ln, context.Background())
	return ln
}

// establishSession runs steps 1-5 of a MySQL session against the proxy:
// server handshake, token handshake response, OK (seq 2). Returns the client
// conn with the session up (relay active).
func establishSession(t *testing.T, addr, token string) net.Conn {
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

// issueToken stores a fresh single-use MySQL token for edge-user.
func issueToken(t *testing.T, vs *store.ValkeyStore, dbPort, ticket string) string {
	t.Helper()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "edge-user", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: dbPort, DBType: "mysql", TicketID: ticket}
	if err := vs.SetToken(context.Background(), token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	return token
}

// readTextResultSet reads a text-protocol result set (column count, column
// definitions, EOF, rows, EOF) and returns the row payloads. Used to prove
// each concurrent client receives exactly its own result.
func readTextResultSet(r io.Reader) ([][]byte, error) {
	if _, _, err := readMySQLPacket(r); err != nil { // column count
		return nil, err
	}
	for { // column definitions until first EOF
		_, pkt, err := readMySQLPacket(r)
		if err != nil {
			return nil, err
		}
		if len(pkt) > 0 && pkt[0] == 0xfe {
			break
		}
	}
	var rows [][]byte
	for { // rows until second EOF
		_, pkt, err := readMySQLPacket(r)
		if err != nil {
			return nil, err
		}
		if len(pkt) > 0 && pkt[0] == 0xfe {
			return rows, nil
		}
		if len(pkt) > 0 && pkt[0] == 0xff {
			return nil, fmt.Errorf("ERR packet inside result set: % x", pkt)
		}
		rows = append(rows, pkt)
	}
}

// decodeLenencString decodes a length-encoded string (text result format)
// from the start of b.
func decodeLenencString(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	switch first := b[0]; {
	case first < 0xfb:
		if len(b) < 1+int(first) {
			return "", false
		}
		return string(b[1 : 1+int(first)]), true
	case first == 0xfc:
		if len(b) < 3 {
			return "", false
		}
		l := int(b[1]) | int(b[2])<<8
		if len(b) < 3+l {
			return "", false
		}
		return string(b[3 : 3+l]), true
	}
	return "", false
}

// proxyGoroutines counts goroutines whose stack includes proxy-package
// function frames — the handler/pipe/accept goroutines the edge tests must
// prove are torn down. Persistent client internals (valkey-go pipe loops,
// go-mysql, net pollers) are deliberately excluded: they are library
// background loops that spawn lazily on first use, not leaks.
//
// Matching is on FUNCTION-NAME lines only, at most once per goroutine.
// runtime.Stack emits each stack as column-0 function lines
// ("zerotrust-proxy/internal/proxy.mysqlProxy.handleConn(...)") followed by
// tab-prefixed file lines ("	D:/AI/hermes/.../mysql_proxy.go:123"). The old
// pattern "	zerotrust-proxy/internal/proxy." matched NOTHING (function
// lines carry no leading tab) — the leak check was a guaranteed no-op.
// Counting bare "internal/proxy." occurrences would over-count: absolute
// file paths appear in every stack, and "created by" trailer lines are also
// column-0. This must never regress to a no-op (see
// TestProxyGoroutinesNonVacuous).
func proxyGoroutines() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	count := 0
	inGoroutine := false
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		switch {
		case strings.HasPrefix(line, "goroutine "):
			inGoroutine = true
		case inGoroutine && !strings.HasPrefix(line, "	") &&
			!strings.HasPrefix(line, "created by ") &&
			strings.Contains(line, "internal/proxy."):
			count++
			inGoroutine = false // count this goroutine at most once
		}
	}
	return count
}

// assertNoGoroutineLeak polls until the proxy goroutine count settles back to
// baseline — proves handler/pipe goroutines exit when sessions end.
func assertNoGoroutineLeak(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if proxyGoroutines() <= baseline {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	t.Errorf("goroutine leak: %d proxy goroutines remain, baseline %d\n%s", proxyGoroutines(), baseline, buf[:n])
}

// --- group 1: COM_QUIT mid-session -------------------------------------------

// TestEdgeCOMQuitClosesSessionCleanly: a client that sends COM_QUIT mid-session
// gets a clean teardown — the packet is relayed byte-exact, the backend closes
// (real-server semantics), the client sees EOF instead of an error packet (no
// 1045, no hang), the session logs no errors, the token is consumed, the
// backend conn is closed, and no goroutines leak.
func TestEdgeCOMQuitClosesSessionCleanly(t *testing.T) {
	vs := proxyTestStore(t)

	backendAddr, backendRecv, backendClosed := startEdgeBackend(t)
	_, port, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("split backend addr: %v", err)
	}
	creds := map[string]string{fmt.Sprintf("127.0.0.1:%s:ro_user", port): "ro_pw"}

	var logBuf bytes.Buffer
	ln := startEdgeDispatcher(t, vs, creds, &logBuf)
	baseline := proxyGoroutines()

	token := issueToken(t, vs, port, "")
	client := establishSession(t, ln.Addr().String(), token)

	// COM_QUIT, empty payload, seq 0 — as real clients send it.
	if err := writeMySQLPacket(client, 0, []byte{cmdQuit}); err != nil {
		t.Fatalf("write COM_QUIT: %v", err)
	}

	// The Task 8.2 thread-id capture (SELECT CONNECTION_ID() on the raw
	// backend conn, before the OK to the client) lands in the fake backend
	// first; drain it — the fake backend already OK'd it, so the capture
	// degrades to threadID 0 and the session proceeds.
	capQ := append([]byte{cmdQuery}, "SELECT CONNECTION_ID()"...)
	if pkt := recvBackendPacket(t, backendRecv); !bytes.Equal(pkt, append([]byte{byte(len(capQ)), byte(len(capQ) >> 8), byte(len(capQ) >> 16), 0}, capQ...)) {
		t.Fatalf("backend received % x, want the thread-id capture query % x (seq 0)", pkt, capQ)
	}

	// The backend received the COM_QUIT byte-exact, then closed without replying.
	if pkt := recvBackendPacket(t, backendRecv); !bytes.Equal(pkt, []byte{0x01, 0x00, 0x00, 0x00, cmdQuit}) {
		t.Fatalf("backend received % x, want byte-exact COM_QUIT header+payload", pkt)
	}
	select {
	case <-backendClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("backend conn not closed within 5s of COM_QUIT")
	}

	// Client side: clean EOF, promptly — no ERR/1045 packet, no hang.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := readMySQLPacket(client); !errors.Is(err, io.EOF) {
		t.Fatalf("after COM_QUIT: want clean EOF, got err=%v (ERR/1045 or hang)", err)
	}
	client.Close()

	// Single-use gate: token consumed.
	if got, err := vs.GetDeleteToken(context.Background(), token); err != nil || got != nil {
		t.Fatalf("token not consumed: got=%v err=%v", got, err)
	}

	// No error spam: session established + closed logged, no ERROR-level
	// lines, no rejection messages.
	logs := logBuf.String()
	for _, want := range []string{"session established", "session closed"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q:\n%s", want, logs)
		}
	}
	for _, bad := range []string{"level=ERROR", "invalid or expired", "not valid for this protocol"} {
		if strings.Contains(logs, bad) {
			t.Errorf("logs contain %q (error spam):\n%s", bad, logs)
		}
	}

	assertNoGoroutineLeak(t, baseline)
}

// --- group 2: oversized length claim -----------------------------------------

// TestEdgeOversizedLengthClaimFailsGracefully: a client packet whose 3-byte
// length field claims the protocol maximum 0xFFFFFF (~16 MiB − 1) but delivers
// only a few bytes must fail gracefully: no panic, no unbounded allocation
// (the 3-byte field itself caps any allocation at the protocol max — 0xFFFFFF
// is the MySQL max packet size), the relay never forwards a partial or giant
// packet to the backend, the session tears down promptly when the client
// disconnects, the Dispatcher keeps accepting, and no goroutines leak.
func TestEdgeOversizedLengthClaimFailsGracefully(t *testing.T) {
	vs := proxyTestStore(t)

	backendAddr, backendRecv, backendClosed := startEdgeBackend(t)
	_, port, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("split backend addr: %v", err)
	}
	creds := map[string]string{fmt.Sprintf("127.0.0.1:%s:ro_user", port): "ro_pw"}
	ln := startEdgeDispatcher(t, vs, creds, io.Discard)
	baseline := proxyGoroutines()

	token := issueToken(t, vs, port, "")
	client := establishSession(t, ln.Addr().String(), token)

	// Claim 0xFFFFFF (the 3-byte field's max) but deliver only 8 bytes, then
	// disconnect. The relay is blocked in the payload read; the disconnect
	// must unblock it and tear the session down.
	if _, err := client.Write(append([]byte{0xff, 0xff, 0xff, 0x00}, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)); err != nil {
		t.Fatalf("write oversized length claim: %v", err)
	}
	client.Close()

	select {
	case <-backendClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("backend conn not closed within 5s of oversized claim + disconnect (hang)")
	}

	// The Task 8.2 thread-id capture (SELECT CONNECTION_ID() on the raw
	// backend conn, before the OK to the client) is the ONE packet the
	// backend sees after auth; drain it — the fake backend already OK'd it,
	// so the capture degrades to threadID 0 and the session proceeds.
	capQ := append([]byte{cmdQuery}, "SELECT CONNECTION_ID()"...)
	if pkt := recvBackendPacket(t, backendRecv); !bytes.Equal(pkt, append([]byte{byte(len(capQ)), byte(len(capQ) >> 8), byte(len(capQ) >> 16), 0}, capQ...)) {
		t.Fatalf("backend received % x, want the thread-id capture query % x (seq 0)", pkt, capQ)
	}

	// The relay never forwarded anything else: the backend never received a
	// packet after the capture (the relay only writes complete packets).
	select {
	case p := <-backendRecv:
		t.Fatalf("backend received a packet it must never see (relay forwarded a partial/giant claim): % x", p)
	default:
	}

	// Token consumed.
	if got, err := vs.GetDeleteToken(context.Background(), token); err != nil || got != nil {
		t.Fatalf("token not consumed: got=%v err=%v", got, err)
	}

	// Dispatcher still live: a fresh session completes end to end.
	token2 := issueToken(t, vs, port, "")
	c2 := establishSession(t, ln.Addr().String(), token2)
	if err := writeMySQLPacket(c2, 0, []byte{cmdPing}); err != nil {
		t.Fatalf("second session write COM_PING: %v", err)
	}
	if seq, resp, err := readMySQLPacket(c2); err != nil || seq != 1 || len(resp) == 0 || resp[0] != 0x00 {
		t.Fatalf("second session: expected OK reply to COM_PING, got seq=%d resp=% x err=%v", seq, resp, err)
	}
	c2.Close()

	assertNoGoroutineLeak(t, baseline)
}

// TestEdgeStallingBackendConnectIsBounded: a backend that accepts the TCP
// connection but never sends its handshake must NOT pin the session forever.
// The backend connect is deadline-bounded (Task 3.8 fix — go-mysql's timeout
// covers only the dial, so the handshake read used to be unbounded): the
// client gets ERR 1045 "backend unavailable" within the bound, the session
// tears down, the token is consumed, and the Dispatcher keeps serving.
func TestEdgeStallingBackendConnectIsBounded(t *testing.T) {
	vs := proxyTestStore(t)

	// A healthy backend for the follow-up liveness session, and a stalling
	// one for the bounded-connect assertion. The dispatcher must know both.
	healthyAddr, _, _ := startEdgeBackend(t)
	_, healthyPort, err := net.SplitHostPort(healthyAddr)
	if err != nil {
		t.Fatalf("split healthy backend addr: %v", err)
	}
	stallAddr := startStallingBackend(t)
	_, stallPort, err := net.SplitHostPort(stallAddr)
	if err != nil {
		t.Fatalf("split stalling backend addr: %v", err)
	}
	creds := map[string]string{
		fmt.Sprintf("127.0.0.1:%s:ro_user", stallPort):   "ro_pw",
		fmt.Sprintf("127.0.0.1:%s:ro_user", healthyPort): "ro_pw",
	}
	ln := startEdgeDispatcher(t, vs, creds, io.Discard)
	baseline := proxyGoroutines()

	token := issueToken(t, vs, stallPort, "")
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second)) // fail fast if the bound regresses
	if _, _, err := readMySQLPacket(client); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}

	// The bounded connect fails: ERR 1045, not a hang.
	seq, resp, err := readMySQLPacket(client)
	if err != nil {
		t.Fatalf("expected ERR 1045 from bounded backend connect, got err=%v (hang?)", err)
	}
	if seq != 2 || len(resp) == 0 || resp[0] != 0xff {
		t.Fatalf("expected ERR packet seq 2, got seq=%d resp=% x", seq, resp)
	}
	if !bytes.Contains(resp, []byte("backend unavailable")) {
		t.Fatalf("ERR packet missing %q: % x", "backend unavailable", resp)
	}

	// Session torn down: next read is EOF; token consumed (single-use).
	if _, _, err := readMySQLPacket(client); !errors.Is(err, io.EOF) {
		t.Fatalf("after ERR: want EOF, got %v", err)
	}
	if got, err := vs.GetDeleteToken(context.Background(), token); err != nil || got != nil {
		t.Fatalf("token not consumed: got=%v err=%v", got, err)
	}

	// Dispatcher still live: a full session against a healthy backend completes.
	token2 := issueToken(t, vs, healthyPort, "")
	c2 := establishSession(t, ln.Addr().String(), token2)
	if err := writeMySQLPacket(c2, 0, []byte{cmdPing}); err != nil {
		t.Fatalf("healthy session write COM_PING: %v", err)
	}
	if seq, resp, err := readMySQLPacket(c2); err != nil || seq != 1 || len(resp) == 0 || resp[0] != 0x00 {
		t.Fatalf("healthy session: expected OK reply, got seq=%d resp=% x err=%v", seq, resp, err)
	}
	c2.Close()

	assertNoGoroutineLeak(t, baseline)
}

// --- group 3: garbage first packet on a fresh conn ----------------------------

// TestEdgeGarbageFirstPacketDoesNotKillDispatcher: a MySQL-classified conn
// (the client stays silent during protocol detection, then speaks) whose
// FIRST packet is random non-protocol bytes is dropped — parse error, conn
// closed, no panic, no reply — and the Dispatcher keeps accepting: two
// garbage conns followed by a full valid session that completes end to end.
func TestEdgeGarbageFirstPacketDoesNotKillDispatcher(t *testing.T) {
	vs := proxyTestStore(t)

	backendAddr, _, _ := startEdgeBackend(t)
	_, port, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("split backend addr: %v", err)
	}
	creds := map[string]string{fmt.Sprintf("127.0.0.1:%s:ro_user", port): "ro_pw"}
	ln := startEdgeDispatcher(t, vs, creds, io.Discard)
	baseline := proxyGoroutines()

	// Two garbage-first conns: each gets the server handshake (the conn was
	// classified MySQL by silence), then sends random non-protocol bytes as
	// its first packet and must be dropped with a clean EOF.
	for i := 0; i < 2; i++ {
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("garbage conn %d dial: %v", i, err)
		}
		if _, _, err := readMySQLPacket(client); err != nil {
			t.Fatalf("garbage conn %d: read handshake: %v", i, err)
		}
		if err := writeMySQLPacket(client, 1, []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02}); err != nil {
			t.Fatalf("garbage conn %d: write garbage: %v", i, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, err := readMySQLPacket(client); !errors.Is(err, io.EOF) {
			client.Close()
			t.Fatalf("garbage conn %d: want clean EOF after garbage first packet, got err=%v", i, err)
		}
		client.Close()
	}

	// Dispatcher still live: a valid session completes end to end (relay
	// round trip against the fake backend).
	token := issueToken(t, vs, port, "")
	c := establishSession(t, ln.Addr().String(), token)
	if err := writeMySQLPacket(c, 0, []byte{cmdPing}); err != nil {
		t.Fatalf("valid conn write COM_PING: %v", err)
	}
	if seq, resp, err := readMySQLPacket(c); err != nil || seq != 1 || len(resp) == 0 || resp[0] != 0x00 {
		t.Fatalf("valid conn: expected OK reply, got seq=%d resp=% x err=%v", seq, resp, err)
	}
	c.Close()

	assertNoGoroutineLeak(t, baseline)
}

// --- group 4: N=5 concurrent live sessions ------------------------------------

// TestEdgeConcurrentLiveSessions: 5 parallel sessions against the LIVE
// mysql-test backend, each with a distinct single-use token. Every session
// succeeds end to end (handshake -> auth -> OK -> real result set), each
// client sees exactly its own row (no cross-talk), all five tokens are
// consumed (single-use), and no goroutines leak.
func TestEdgeConcurrentLiveSessions(t *testing.T) {
	vs := proxyTestStore(t)

	// Live backend credentials (same as the Task 3.7 integration test).
	creds := map[string]string{"127.0.0.1:3307:ro_user": "ro_pw"}
	ln := startEdgeDispatcher(t, vs, creds, io.Discard)
	baseline := proxyGoroutines()

	const n = 5
	tokens := make([]string, n)
	values := make([]string, n)
	for i := 0; i < n; i++ {
		tokens[i] = issueToken(t, vs, "3307", fmt.Sprintf("T-EDGE-%d", i))
		values[i] = fmt.Sprintf("%d", 100+i) // 100..104 — distinct per session
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				errs <- fmt.Errorf("session %d: dial: %w", i, err)
				return
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(15 * time.Second)) // fail fast on hang
			if _, _, err := readMySQLPacket(client); err != nil {
				errs <- fmt.Errorf("session %d: handshake: %w", i, err)
				return
			}
			if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(tokens[i])); err != nil {
				errs <- fmt.Errorf("session %d: auth: %w", i, err)
				return
			}
			seq, resp, err := readMySQLPacket(client)
			if err != nil || seq != 2 || len(resp) == 0 || resp[0] != 0x00 {
				errs <- fmt.Errorf("session %d: expected OK seq 2, got seq=%d resp=% x err=%v", i, seq, resp, err)
				return
			}
			query := "SELECT " + values[i]
			if err := writeMySQLPacket(client, 0, append([]byte{cmdQuery}, query...)); err != nil {
				errs <- fmt.Errorf("session %d: query: %w", i, err)
				return
			}
			rows, err := readTextResultSet(client)
			if err != nil {
				errs <- fmt.Errorf("session %d: result set: %w", i, err)
				return
			}
			if len(rows) != 1 {
				// Length check BEFORE indexing rows[0]: an empty result set must
				// fail with the clean assertion message, not panic the session
				// goroutine.
				errs <- fmt.Errorf("session %d: rows=%q, want exactly [%q] (own result, no cross-talk)", i, rows, values[i])
				return
			}
			got, ok := decodeLenencString(rows[0])
			if !ok || got != values[i] {
				errs <- fmt.Errorf("session %d: decode rows[0]: ok=%v got=%q want %q (own result, no cross-talk)", i, ok, got, values[i])
				return
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Single-use: every token was consumed by its session.
	for i, token := range tokens {
		if got, err := vs.GetDeleteToken(context.Background(), token); err != nil || got != nil {
			t.Errorf("token %d not consumed: got=%v err=%v", i, got, err)
		}
	}

	assertNoGoroutineLeak(t, baseline)
}

// TestProxyGoroutinesNonVacuous guards proxyGoroutines() against regressing
// to a no-op: it spawns a goroutine parked inside a proxy-package closure and
// requires the observed count to increase by exactly 1. Before the fix,
// proxyGoroutines() matched "	zerotrust-proxy/internal/proxy." — a pattern
// that never occurs in runtime.Stack output (function-name lines carry NO
// leading tab; file lines are tab-prefixed absolute paths) — so it always
// returned 0 and every assertNoGoroutineLeak was a guaranteed no-op. This
// test fails against that implementation (base+1 is never reached), proving
// the leak check is non-vacuous.
func TestProxyGoroutinesNonVacuous(t *testing.T) {
	// Baseline BEFORE spawning: this test's own goroutine is always counted
	// (it is executing proxy-package test code), and no other proxy
	// goroutines exist here — the suite is sequential and every edge test
	// already asserted its own goroutines returned to baseline.
	base := proxyGoroutines()
	release := make(chan struct{})
	done := make(chan struct{})
	started := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		<-release // park inside a proxy-package goroutine
	}()
	<-started
	deadline := time.Now().Add(3 * time.Second)
	for {
		if n := proxyGoroutines(); n == base+1 {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("proxyGoroutines() did not observe the parked goroutine: base=%d, got=%d — leak check is vacuous or broken", base, n)
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
	close(release)
	<-done
}
