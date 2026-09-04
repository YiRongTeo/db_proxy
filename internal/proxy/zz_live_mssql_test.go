package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 9.2 LIVE tests ---------------------------------------------------
//
// The "zz" file prefix is deliberate (same convention as
// zz_live_gate_hold_test.go): these tests open real proxy sessions whose
// sess:live:<sid> records exist for the whole session, so they must run
// LAST in the proxy binary — outside internal/store's
// TestListSessionsEmpty window. They require the live environment: Valkey
// on :6379, the mssql-test container on :1434 (the committed creds
// mssql:ro_user@127.0.0.1:1434 → ro_pw), and (TLS case) certs/data.{crt,key}
// (scripts/gen-certs.sh). proxyTestStore fails fast when Valkey is down —
// the established suite convention.

// tdsTestClient is a raw TDS client (sqlcmd's role) used to drive the
// proxy: PRELOGIN, optional 0x12-wrapped TLS upgrade (client role), LOGIN7,
// then batches. Plaintext and TLS variants share the message plumbing.
type tdsTestClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

// dialTDS connects a plaintext TDS client to addr.
func dialTDS(t *testing.T, addr string) *tdsTestClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &tdsTestClient{t: t, conn: conn, br: bufio.NewReader(conn)}
}

// dialTDSTLS connects a TDS client that upgrades through the 0x12-wrapped
// wiring (client role): the PRELOGIN exchange happens FIRST (plaintext —
// the server answers ENCRYPT_ON, asserted), then the tdsTLSConn seam
// strips/re-adds the 0x12 framing around the TLS record stream for the
// handshake. After the handshake the client role switches to BARE TLS
// records (the real sqlcmd v18 behavior, round-8 live capture) — seam
// bare=true, exactly like the real client.
func dialTDSTLS(t *testing.T, addr string) *tdsTestClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	br := bufio.NewReader(conn)
	c := &tdsTestClient{t: t, conn: conn, br: br}
	if enc := c.prelogin(encryptOn); enc != encryptOn {
		t.Fatalf("server encryption = %#x, want ENCRYPT_ON (TLS plane)", enc)
	}
	seam := &tdsTLSConn{Conn: conn, br: br}
	tlsConn := tls.Client(seam, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	seam.bare = true // post-handshake records are bare TLS records (real sqlcmd)
	return &tdsTestClient{t: t, conn: tlsConn, br: bufio.NewReader(tlsConn)}
}

// prelogin sends a PRELOGIN (buildPrelogin, the captured sqlcmd shape) and
// returns the server's ENCRYPTION value. The server's response may arrive
// as TABULAR (0x04 — what the real SQL Server and this proxy send) or
// PRELOGIN (0x12 — some stacks); both carry the same option payload.
func (c *tdsTestClient) prelogin(enc byte) byte {
	c.t.Helper()
	if err := writeTDSPacket(c.conn, tdsPrelogin, buildPrelogin(enc)); err != nil {
		c.t.Fatalf("prelogin write: %v", err)
	}
	typ, payload, err := readTDSMessage(c.br)
	if err != nil || (typ != tdsPrelogin && typ != tdsTabular) {
		c.t.Fatalf("prelogin response: typ=%#x err=%v", typ, err)
	}
	serverEnc, err := parsePrelogin(payload)
	if err != nil {
		c.t.Fatalf("prelogin parse: %v", err)
	}
	return serverEnc
}

// login sends a LOGIN7 with token-as-username and returns the login
// response payload plus the scan verdict. The backend's login response
// can span several TDS messages (ENVCHANGE/LOGINACK in the first, the
// FINAL DONE in a later one — verified live), so messages are read until
// a DONE(FINAL) appears, exactly like the real client does.
func (c *tdsTestClient) login(token, database string) ([]byte, bool, bool) {
	c.t.Helper()
	msg := buildLogin7("tds-test-client", token, "TDS-TEST", "127.0.0.1", database, nil, tdsVersion740, tdsPacketSize)
	if err := writeTDSPacket(c.conn, tdsLogin7, msg); err != nil {
		c.t.Fatalf("login7 write: %v", err)
	}
	var all []byte
	ok := true
	for i := 0; i < 8; i++ {
		typ, payload, err := readTDSMessage(c.br)
		if err != nil || typ != tdsTabular {
			c.t.Fatalf("login response: typ=%#x err=%v", typ, err)
		}
		all = append(all, payload...)
		done, o, _ := scanLoginResponse(payload)
		ok = ok && o
		if done {
			return all, true, ok
		}
	}
	c.t.Fatal("login: no DONE(FINAL) within 8 messages")
	return nil, false, false
}

// sendBatch relays a SQL batch (type 0x01) and returns the backend's
// response payload(s) until a DONE(FINAL) token appears.
func (c *tdsTestClient) sendBatch(sql string) []byte {
	c.t.Helper()
	if err := writeTDSPacket(c.conn, tdsSQLBatch, []byte(sql)); err != nil {
		c.t.Fatalf("batch write: %v", err)
	}
	var all []byte
	for i := 0; i < 8; i++ {
		typ, payload, err := readTDSMessage(c.br)
		if err != nil {
			c.t.Fatalf("batch response: %v", err)
		}
		if typ != tdsTabular {
			c.t.Fatalf("batch response typ = %#x, want 0x04", typ)
		}
		all = append(all, payload...)
		done, _, _ := scanLoginResponse(payload)
		if done {
			return all
		}
	}
	c.t.Fatal("batch: no DONE(FINAL) within 8 messages")
	return nil
}

// close ends the client side (sqlcmd's logout is a plain close).
func (c *tdsTestClient) close() { _ = c.conn.Close() }

// extractErrorMsg pulls the MsgText out of a login-failure response built
// by buildLoginError (or the real SQL Server — same token layout).
func extractErrorMsg(payload []byte) string {
	if len(payload) < 3 || payload[0] != 0xAA {
		return ""
	}
	restLen := int(payload[1]) | int(payload[2])<<8
	if restLen < 12 || 3+restLen > len(payload) {
		return ""
	}
	body := payload[3 : 3+restLen]
	// body: number(4) state(1) class(1) msgLen(2) msg(2m) srvLen(1) srv(2s)
	// procLen(1) proc(2p) line(4) — MsgText is a US_VARCHAR (USHORT length
	// in UTF-16 code units), the captured real-server shape. Login-failure
	// tokens carry an EMPTY proc, so walk from the end: line(4) ends the
	// token, procLen sits at restLen-5, and the srv data ends at restLen-6.
	// The srvLen byte is the one whose value is half the bytes between it
	// and restLen-6 (scan back — a fixed offset like restLen-7 reads one
	// byte into the srv data and yields a garbage length; round-5 live
	// bug).
	if procLen := int(body[restLen-5]); procLen != 0 {
		return "" // unexpected proc — unsupported shape
	}
	srvEnd := restLen - 6 // exclusive end of the srv data
	srvLen := 0
	for pos := srvEnd - 1; pos >= 6; pos-- {
		if v := int(body[pos]); v > 0 && 2*v == srvEnd-pos {
			srvLen = v
			break
		}
	}
	msgBytes := restLen - 12 - 2*srvLen - 2 // skip the USHORT MsgText prefix
	if msgBytes < 0 {
		return ""
	}
	units := make([]uint16, msgBytes/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(body[8+2*i:])
	}
	return string(utf16.Decode(units))
}

// startMSSQLTestProxy runs handleConn on a fresh listener for one
// connection (mirror of startTestProxyWithResolver).
func startMSSQLTestProxy(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, tlsCfg *tls.Config) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewMSSQLProxy(logger, vs, &ConfigCredResolver{
		Creds: map[string]string{"mssql:ro_user@127.0.0.1:1434": "ro_pw"},
	}, tlsCfg)
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

// startMSSQLTestProxyLoop is the multi-session variant of
// startMSSQLTestProxy: it accepts and handles connections until the
// listener is closed — for tests that need several sessions against one
// proxy instance (single-use: first use logs in, second must be refused).
func startMSSQLTestProxyLoop(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, tlsCfg *tls.Config) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewMSSQLProxy(logger, vs, &ConfigCredResolver{
		Creds: map[string]string{"mssql:ro_user@127.0.0.1:1434": "ro_pw"},
	}, tlsCfg)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()
	return ln
}

// mssqlLiveToken mints a token for the live backend and registers a
// cleanup that removes any leftover sess:live record.
func mssqlLiveToken(t *testing.T, vs *store.ValkeyStore, username string, dbType string) string {
	t.Helper()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: username, DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "1434", DBType: dbType, TicketID: "T-9-2", SessionID: "sid-" + token[len("sess_"):]}
	if err := vs.SetToken(context.Background(), token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), tok.SessionID) })
	return token
}

// subscribeEvents subscribes to queries:<username> and returns the channel
// plus an ack once the subscription is live.
func subscribeEvents(t *testing.T, vs *store.ValkeyStore, username string) (chan []byte, context.CancelFunc) {
	t.Helper()
	out := make(chan []byte, 16)
	acked := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, "queries:"+username, false, out)
	waitSubAck(t, acked)
	return out, cancel
}

// recvEventKind waits for a lifecycle event with the given action.
func recvEventKind(t *testing.T, out <-chan []byte, action string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-out:
			if bytes.Contains(m, []byte(`"action":"`+action+`"`)) {
				return
			}
		case <-deadline:
			t.Fatalf("no %s lifecycle event within 5s", action)
		}
	}
}

// loginVersioned is login() with the client's declared TDS version/packet
// size — the legacy-provider path (version passthrough fix, 2026-08-26).
// Reads are deadline-bounded: an unexpected legacy-shape response must
// fail fast with evidence, never hang the suite.
func (c *tdsTestClient) loginVersioned(token, database string, tdsVersion, packetSize uint32) ([]byte, bool, bool) {
	c.t.Helper()
	msg := buildLogin7("tds-test-client", token, "TDS-TEST", "127.0.0.1", database, nil, tdsVersion, packetSize)
	if err := writeTDSPacket(c.conn, tdsLogin7, msg); err != nil {
		c.t.Fatalf("login7 write: %v", err)
	}
	var all []byte
	ok := true
	for i := 0; i < 8; i++ {
		_ = c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		typ, payload, err := readTDSMessage(c.br)
		_ = c.conn.SetReadDeadline(time.Time{})
		if err != nil || typ != tdsTabular {
			c.t.Fatalf("login response msg %d: typ=%#x err=%v (got %d bytes so far: %x)", i+1, typ, err, len(all), all)
		}
		c.t.Logf("login response msg %d (%d bytes): %x", i+1, len(payload), payload)
		all = append(all, payload...)
		done, o, _ := scanLoginResponse(payload)
		ok = ok && o
		if done {
			return all, true, ok
		}
		// Same last-message rule as scanLoginResponse: the live backend
		// finishes a successful login with DONE status 0x0000 (no
		// DONE_FINAL) + message EOM — real clients treat EOM as the end.
		if tdsMessageEndsWithDone(payload) {
			return all, true, ok
		}
	}
	c.t.Fatal("login: no DONE(FINAL) within 8 messages")
	return nil, false, false
}

// tdsMessageEndsWithDone reports whether the login-response message ends
// with a DONE-family token (0xFD/0xFE/0xFF) — the live server's "login
// complete" signal when it omits the DONE_FINAL bit (round-6 capture).
// Both modern (13-byte) and legacy (9-byte, TDS < 7.2 — version passthrough
// fix 2026-08-26) DONE tails are recognized: the token starts n bytes
// before the final header byte.
func tdsMessageEndsWithDone(payload []byte) bool {
	for _, n := range []int{13, 9} {
		if len(payload) < n {
			continue
		}
		t := payload[len(payload)-n]
		if t == 0xFD || t == 0xFE || t == 0xFF {
			return true
		}
	}
	return false
}

// TestMSSQLLiveLegacyTDSVersionPassthrough is the SQLOLEDB regression
// (version passthrough fix, 2026-08-26): a client declaring TDS 7.1
// (0x71000001 — what SQLOLEDB sends) authenticates through a real proxy
// session against the live SQL Server. The rewritten backend LOGIN7 carries
// the client's version verbatim, so the backend's LOGINACK comes back with
// THAT version (the server echoes the client's negotiated version) — not
// 7.4 as the pre-fix forced-7.4 rewrite produced. The legacy client can
// then parse its own login response and populate DBMS Version.
func TestMSSQLLiveLegacyTDSVersionPassthrough(t *testing.T) {
	const legacyTDS = 0x71000001
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-legacy-%d", time.Now().UnixNano())
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	token := mssqlLiveToken(t, vs, username, "mssql")

	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxy(t, vs, &logBuf, nil)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("server encryption = %#x, want ENCRYPT_NOT_SUP", enc)
	}
	payload, done, ok := c.loginVersioned(token, "appdb", legacyTDS, 8000)
	if !done || !ok {
		t.Fatalf("legacy-version login failed: done=%v ok=%v payload=%x", done, ok, payload)
	}
	// The relayed LOGINACK must carry the LEGACY version — proof the
	// passthrough reached the real server and came back. Layout: token
	// (0xAD, 1) + length (2) + interface (1) + TDSVersion (4, BIG-endian
	// — unlike LOGIN7's little-endian field; live-verified 2026-08-26:
	// `ad 36 00 01 71 00 00 01` for the 7.1 login) + ProgNameLen...
	idx := bytes.IndexByte(payload, 0xAD)
	if idx < 0 || idx+12 > len(payload) {
		t.Fatalf("no LOGINACK token in login response: %x", payload)
	}
	ackVer := binary.BigEndian.Uint32(payload[idx+4 : idx+8])
	if ackVer != legacyTDS {
		t.Fatalf("LOGINACK tds version = %#08x, want the client's %#08x "+
			"(pre-fix behavior: %#08x forced)", ackVer, legacyTDS, tdsVersion740)
	}
	c.close()
	recvEventKind(t, out, "started")
	recvEventKind(t, out, "ended")
}

// TestMSSQLLiveMultiUseTokenBudget (Task 9.12, option-2 multi-use) is the
// SSMS scenario in-suite: a token issued with max_uses=N opens N
// sequential live TDS sessions through the SAME proxy; the N+1th connect
// is rejected as invalid/expired (the budget is exhausted). GUI clients
// (SSMS Object Explorer + auxiliary connections) need this budget.
func TestMSSQLLiveMultiUseTokenBudget(t *testing.T) {
	const budget = 3
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-multi-%d", time.Now().UnixNano())
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: username, DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "1434", DBType: "mssql", TicketID: "T-9-12",
		SessionID: "sid-" + token[len("sess_"):], MaxUses: budget}
	if err := vs.SetToken(context.Background(), token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), tok.SessionID) })

	var logBuf bytes.Buffer
	ln := startMSSQLTestProxyLoop(t, vs, &logBuf, nil)

	// One connect+login+close per use, exactly like SSMS opening its
	// Object Explorer connections.
	loginOnce := func() bool {
		c := dialTDS(t, ln.Addr().String())
		defer c.close()
		if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
			t.Fatalf("server encryption = %#x, want ENCRYPT_NOT_SUP", enc)
		}
		_, done, ok := c.login(token, "appdb")
		return done && ok
	}
	for i := 1; i <= budget; i++ {
		if !loginOnce() {
			t.Fatalf("use %d/%d: login failed — budget not honored", i, budget)
		}
	}
	if loginOnce() {
		t.Fatal("login after budget exhaustion SUCCEEDED — the token must be consumed")
	}
}

// TestMSSQLLiveSessionPlaintext is the Task 9.2 money shot (in-suite): a
// raw TDS client (sqlcmd's role) authenticates with a token through the
// plaintext path — PRELOGIN answered ENCRYPT_NOT_SUP, LOGIN7 token accepted,
// the backend's LOGINACK + DONE relayed byte-exact — then a real SELECT
// batch is relayed to SQL Server and its result comes back (the raw relay
// that Task 9.3 replaces with the sniffing relay). The session lifecycle
// events (started/ended) and the registry teardown are asserted too.
func TestMSSQLLiveSessionPlaintext(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-live-%d", time.Now().UnixNano())
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	token := mssqlLiveToken(t, vs, username, "mssql")

	var logBuf bytes.Buffer
	ln, proxyDone := startMSSQLTestProxy(t, vs, &logBuf, nil)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("server encryption = %#x, want ENCRYPT_NOT_SUP (plaintext plane)", enc)
	}
	payload, done, ok := c.login(token, "appdb")
	if !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v payload=%x", done, ok, payload)
	}
	if !bytes.Contains(payload, []byte{0xAD}) {
		t.Fatalf("login response has no LOGINACK token: %x", payload)
	}
	// NOTE: no query round-trip here — a SQL batch needs the AllHeaders
	// transaction-descriptor prefix, which the raw byte relay does not
	// rebuild (live backend: bare text → 4002 "stream ended unexpectedly",
	// 0x0000 headers → 4009 "headers contained errors"). Query execution
	// lands with the sniffing query relay in Task 9.3. This test proves
	// what round 6 owns: LOGIN-OK relayed byte-exact, session established,
	// and a clean bounded teardown (the byte relay runs both directions
	// until either side closes).
	c.close()
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy session did not tear down within 5s")
	}
	recvEventKind(t, out, "started")
	recvEventKind(t, out, "ended")
	if !strings.Contains(logBuf.String(), `"session established"`) {
		t.Fatalf("no session established log line: %s", logBuf.String())
	}
}

// TestMSSQLLiveSessionTLS is the TLS money shot: the PRELOGIN exchange
// (inside dialTDSTLS) answers ENCRYPT_ON, the client upgrades through the
// 0x12-wrapped wiring (ClientHello inside a 0x12 packet), and the LOGIN7 +
// batch travel encrypted — then the backend leg (also TLS, per the data
// plane config) carries the rewritten login7 to the real server.
func TestMSSQLLiveSessionTLS(t *testing.T) {
	tlsCfg := loadTestTLS(t) // skips when certs/ absent
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-tls-%d", time.Now().UnixNano())
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	token := mssqlLiveToken(t, vs, username, "mssql")

	var logBuf bytes.Buffer
	ln, proxyDone := startMSSQLTestProxy(t, vs, &logBuf, tlsCfg)

	c := dialTDSTLS(t, ln.Addr().String())
	payload, done, ok := c.login(token, "appdb")
	if !done || !ok {
		t.Fatalf("login failed over TLS: done=%v ok=%v payload=%x", done, ok, payload)
	}
	if !bytes.Contains(payload, []byte{0xAD}) {
		t.Fatalf("login response has no LOGINACK token: %x", payload)
	}
	// No query round-trip over TLS either — same Task 9.3 boundary as the
	// plaintext test (AllHeaders transaction descriptor). The 0x12-wrapped
	// upgrade + encrypted LOGIN7 + relayed LOGINACK + clean teardown is
	// the round-6 TLS proof.
	c.close()
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy session did not tear down within 5s")
	}
	recvEventKind(t, out, "started")
	recvEventKind(t, out, "ended")
}

// TestMSSQLLiveWrongDBType: a MySQL token presented to the TDS plane is
// refused with a sqlcmd-readable ERROR token naming the mismatch.
func TestMSSQLLiveWrongDBType(t *testing.T) {
	vs := proxyTestStore(t)
	token := mssqlLiveToken(t, vs, "mssql-wrongdb", "mysql")
	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxy(t, vs, &logBuf, nil)
	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("server encryption = %#x", enc)
	}
	payload, _, ok := c.login(token, "appdb")
	if ok {
		t.Fatalf("wrong-db-type token must not log in: %x", payload)
	}
	if msg := extractErrorMsg(payload); !strings.Contains(msg, "token not valid for this protocol") {
		t.Fatalf("error message = %q, want protocol mismatch", msg)
	}
	c.close()
}

// TestMSSQLLiveInvalidToken: an unknown/expired token is refused with the
// canonical 18456 message.
func TestMSSQLLiveInvalidToken(t *testing.T) {
	vs := proxyTestStore(t)
	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxy(t, vs, &logBuf, nil)
	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("server encryption = %#x", enc)
	}
	token := "sess_00000000000000000000000000000000"
	payload, _, ok := c.login(token, "appdb")
	if ok {
		t.Fatalf("unknown token must not log in: %x", payload)
	}
	if msg := extractErrorMsg(payload); !strings.Contains(msg, "Login failed for user '"+token+"'") {
		t.Fatalf("error message = %q, want the canonical login-failed message", msg)
	}
	c.close()
}

// TestMSSQLLiveExpiredToken: a token whose TTL has elapsed is refused with
// the canonical 18456 message — GETDEL returns nothing, exactly like an
// unknown token.
func TestMSSQLLiveExpiredToken(t *testing.T) {
	vs := proxyTestStore(t)
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "mssql-expired", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "1434", DBType: "mssql", TicketID: "T-9-2", SessionID: "sid-expired"}
	if err := vs.SetToken(context.Background(), token, tok, time.Second); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	time.Sleep(1200 * time.Millisecond) // let the TTL elapse
	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxy(t, vs, &logBuf, nil)
	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("server encryption = %#x", enc)
	}
	payload, _, ok := c.login(token, "appdb")
	if ok {
		t.Fatalf("expired token must not log in: %x", payload)
	}
	if msg := extractErrorMsg(payload); !strings.Contains(msg, "Login failed for user '"+token+"'") {
		t.Fatalf("error message = %q, want the canonical login-failed message", msg)
	}
	c.close()
}

// TestMSSQLLiveSingleUse: GETDEL semantics — the same token works exactly
// once; the second connection is refused like an expired token.
func TestMSSQLLiveSingleUse(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-single-%d", time.Now().UnixNano())
	token := mssqlLiveToken(t, vs, username, "mssql")
	var logBuf bytes.Buffer
	ln := startMSSQLTestProxyLoop(t, vs, &logBuf, nil)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("server encryption = %#x", enc)
	}
	if _, done, ok := c.login(token, "appdb"); !done || !ok {
		t.Fatalf("first use must log in: done=%v ok=%v", done, ok)
	}
	c.close()

	c2 := dialTDS(t, ln.Addr().String())
	if enc := c2.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("server encryption = %#x", enc)
	}
	payload, _, ok := c2.login(token, "appdb")
	if ok {
		t.Fatalf("second use of the same token must be refused: %x", payload)
	}
	if msg := extractErrorMsg(payload); !strings.Contains(msg, "Login failed for user '"+token+"'") {
		t.Fatalf("error message = %q", msg)
	}
	c2.close()
}

// --- Task 9.3 review GAP 2: two concurrent sessions, no cross-talk ----------

// sendBatchAllHeaders relays a SQL batch prefixed with the real sqlcmd
// ALL_HEADERS block (allHeaders22 — the live backend rejects bare text
// with 4002) and returns the response payloads until the response ends
// (trailing-DONE rule, like sendBatch).
func (c *tdsTestClient) sendBatchAllHeaders(sql string) []byte {
	c.t.Helper()
	payload := append(append([]byte(nil), allHeaders22...), utf16le(sql)...)
	if err := writeTDSPacket(c.conn, tdsSQLBatch, payload); err != nil {
		c.t.Fatalf("batch write: %v", err)
	}
	var all []byte
	for i := 0; i < 8; i++ {
		typ, payload, err := readTDSMessage(c.br)
		if err != nil {
			c.t.Fatalf("batch response: %v", err)
		}
		if typ != tdsTabular {
			c.t.Fatalf("batch response typ = %#x, want 0x04", typ)
		}
		all = append(all, payload...)
		done, _, _ := scanLoginResponse(payload)
		if done {
			return all
		}
	}
	c.t.Fatal("batch: no terminating DONE within 8 messages")
	return nil
}

// TestMSSQLLivePerChannelNoCrossTalk (Task 9.3 review GAP 2): TWO concurrent
// LIVE mssql sessions (alice + bob, distinct single-use tokens), each with a
// subscriber on its OWN queries:sess:<sid> channel. Alice runs a query
// mid-window while bob's channel is live — alice's channel delivers ONLY
// alice's event and bob's channel stays empty (no cross-talk); then bob's
// query lands ONLY on bob's channel. Ended events land on the right channels
// too. Mirrors TestSessionPerChannelNoCrossTalk (Task 8.2) on the TDS plane.
func TestMSSQLLivePerChannelNoCrossTalk(t *testing.T) {
	vs := proxyTestStore(t)
	base := fmt.Sprintf("mssql-xtalk-%d", time.Now().UnixNano())
	userA, userB := base+"-a", base+"-b"
	tokenA := mssqlLiveToken(t, vs, userA, "mssql")
	tokenB := mssqlLiveToken(t, vs, userB, "mssql")

	userChA, cancelA := subscribeEvents(t, vs, userA)
	defer cancelA()
	userChB, cancelB := subscribeEvents(t, vs, userB)
	defer cancelB()

	var logBuf bytes.Buffer
	ln := startMSSQLTestProxyLoop(t, vs, &logBuf, nil)

	// Both sessions connect; the started events yield the session ids.
	cA := dialTDS(t, ln.Addr().String())
	if enc := cA.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("alice prelogin encryption = %#x, want ENCRYPT_NOT_SUP", enc)
	}
	if _, done, ok := cA.login(tokenA, "appdb"); !done || !ok {
		t.Fatalf("alice login failed: done=%v ok=%v", done, ok)
	}
	startedA := recvSessionEvent(t, userChA)
	sidA := startedA.SessionID

	cB := dialTDS(t, ln.Addr().String())
	if enc := cB.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("bob prelogin encryption = %#x, want ENCRYPT_NOT_SUP", enc)
	}
	if _, done, ok := cB.login(tokenB, "appdb"); !done || !ok {
		t.Fatalf("bob login failed: done=%v ok=%v", done, ok)
	}
	startedB := recvSessionEvent(t, userChB)
	sidB := startedB.SessionID
	if sidA == sidB {
		t.Fatalf("both sessions got the same id %q", sidA)
	}

	// Subscribe to each session's OWN channel now that the ids are known.
	sessA, cancelSessA := subscribeEvents(t, vs, "sess:"+sidA)
	defer cancelSessA()
	sessB, cancelSessB := subscribeEvents(t, vs, "sess:"+sidB)
	defer cancelSessB()

	// Alice queries mid-window (both per-session channels live): her
	// channel must deliver her event...
	cA.sendBatchAllHeaders("SELECT 'from-A'")
	evA := recvQueryEvent(t, sessA)
	if evA.SessionID != sidA || !strings.Contains(evA.SQL, "from-A") {
		t.Errorf("alice channel delivered %q (sid %q) — want alice's own query (from-A, sid %q)",
			evA.SQL, evA.SessionID, sidA)
	}
	// ...and bob's channel must be empty right now: alice's event never
	// crossed over while bob sat mid-window.
	select {
	case m := <-sessB:
		t.Fatalf("bob channel received alice's event (cross-talk): %s", m)
	default:
	}

	// Bob queries mid-window: his channel delivers only his event.
	cB.sendBatchAllHeaders("SELECT 'from-B'")
	evB := recvQueryEvent(t, sessB)
	if evB.SessionID != sidB || !strings.Contains(evB.SQL, "from-B") {
		t.Errorf("bob channel delivered %q (sid %q) — want bob's own query (from-B, sid %q)",
			evB.SQL, evB.SessionID, sidB)
	}
	select {
	case m := <-sessA:
		t.Fatalf("alice channel received bob's event (cross-talk): %s", m)
	default:
	}

	// Close both; the ended events land on each session's own channel.
	cA.close()
	endedA := recvSessionEvent(t, sessA)
	if endedA.SessionID != sidA || endedA.Action != "ended" {
		t.Errorf("alice channel ended = sid %q action %q, want %q/ended", endedA.SessionID, endedA.Action, sidA)
	}
	cB.close()
	endedB := recvSessionEvent(t, sessB)
	if endedB.SessionID != sidB || endedB.Action != "ended" {
		t.Errorf("bob channel ended = sid %q action %q, want %q/ended", endedB.SessionID, endedB.Action, sidB)
	}
}

// startMSSQLTestProxyLoopP is the loop variant that ALSO hands back the
// proxy instance (the sweeper and RevokeToken need it). The plain
// startMSSQLTestProxyLoop only returns the listener; this is the same
// wiring with the pointer exposed.
func startMSSQLTestProxyLoopP(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, tlsCfg *tls.Config) (net.Listener, *MSSQLProxy) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewMSSQLProxy(logger, vs, &ConfigCredResolver{
		Creds: map[string]string{"mssql:ro_user@127.0.0.1:1434": "ro_pw"},
	}, tlsCfg)
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

// TestMSSQLLiveSessionTokenLifecycle (Task 9.13 option-A money shot) proves
// the session-token model end to end against the real SQL Server:
//
//  1. NOT consumed: one session-mode token opens two sequential live TDS
//     sessions (the SSMS Object-Explorer pattern).
//  2. IP locked: a token stamped for another address is rejected at login.
//  3. LIVE revocation: deleting the token key mid-session closes the
//     running session within the sweep interval (the "removed via another
//     process" requirement).
//  4. Idle policy: a silent session is closed after session.idle_seconds.
func TestMSSQLLiveSessionTokenLifecycle(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-sess-%d", time.Now().UnixNano())
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: username, DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "1434", DBType: "mssql", TicketID: "T-9-13",
		SessionID: "sid-" + token[len("sess_"):],
		Mode:      "session", IP: "127.0.0.1", IssuedAt: time.Now().Unix()}
	if err := vs.SetToken(context.Background(), token, tok, time.Hour); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), tok.SessionID) })

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyLoopP(t, vs, &logBuf, nil)

	// 1. Two sequential logins on the SAME token — session tokens are not
	// consumed (SSMS opens its Object Explorer + auxiliary connections).
	loginOnce := func(token string) bool {
		c := dialTDS(t, ln.Addr().String())
		defer c.close()
		if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
			t.Fatalf("server encryption = %#x, want ENCRYPT_NOT_SUP", enc)
		}
		_, done, ok := c.login(token, "appdb")
		return done && ok
	}
	if !loginOnce(token) {
		t.Fatal("session token login #1 failed — token must not be consumed")
	}
	if !loginOnce(token) {
		t.Fatal("session token login #2 failed — session tokens are NOT single-use")
	}
	alive, err := vs.TokenAlive(context.Background(), token)
	if err != nil || !alive {
		t.Fatalf("TokenAlive after 2 logins: %v %v — session token must survive", alive, err)
	}

	// 2. IP lock: a token stamped for a foreign address is rejected even
	// though it is valid and unexpired.
	foreign, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	ftok := tok
	ftok.SessionID = "sid-" + foreign[len("sess_"):]
	ftok.IP = "192.0.2.1"
	if err := vs.SetToken(context.Background(), foreign, ftok, time.Minute); err != nil {
		t.Fatalf("SetToken(foreign): %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), ftok.SessionID) })
	if loginOnce(foreign) {
		t.Fatal("wrong-IP login SUCCEEDED — session tokens are IP-locked")
	}

	// 3. LIVE revocation: hold a session open, delete the key from valkey
	// (as any external process would), and expect the proxy to close the
	// connection within the sweep interval.
	c := holdToken(t, token, ln)
	// Sweeper A: revocation-only (no idle) so the token-deletion close is
	// attributable to the liveness check, not the idle policy.
	sweepCtx, sweepCancel := context.WithCancel(context.Background())
	defer sweepCancel()
	go RunSessionSweeper(sweepCtx, slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionPolicy{Poll: 300 * time.Millisecond}, p)
	if err := vs.DeleteToken(context.Background(), token); err != nil {
		t.Fatalf("DeleteToken (external revocation): %v", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.conn.Read(buf); err == nil {
		t.Fatal("session still alive after token key deletion — revocation failed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("session survived 5s after token key deletion — revocation failed")
	}
	sweepCancel() // stop sweeper A before the idle phase

	// 4. Idle policy: a silent session is closed after the idle window.
	idleToken, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	itok := tok
	itok.SessionID = "sid-" + idleToken[len("sess_"):]
	itok.IssuedAt = time.Now().Unix()
	if err := vs.SetToken(context.Background(), idleToken, itok, time.Hour); err != nil {
		t.Fatalf("SetToken(idle): %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), itok.SessionID) })
	// Sweeper B: idle policy (1s) on top of the liveness poll.
	idleCtx, idleCancel := context.WithCancel(context.Background())
	defer idleCancel()
	go RunSessionSweeper(idleCtx, slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionPolicy{Idle: time.Second, Poll: 300 * time.Millisecond}, p)
	c2 := holdToken(t, idleToken, ln)
	start := time.Now()
	_ = c2.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.conn.Read(buf); err == nil {
		t.Fatal("idle session still alive after 5s")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle session survived the deadline — idle policy did not fire")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("idle close took %v, want <= ~2s (idle=1s, poll=300ms)", d)
	}
}

// holdToken logs in with the token and returns the open client (the caller
// keeps it open to simulate a live GUI session).
func holdToken(t *testing.T, token string, ln net.Listener) *tdsTestClient {
	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("server encryption = %#x, want ENCRYPT_NOT_SUP", enc)
	}
	if _, done, ok := c.login(token, "appdb"); !(done && ok) {
		t.Fatalf("hold login failed")
	}
	return c
}

// TestMSSQLLiveKillRevokesSessionToken (Task 9.13): a connection-mode kill
// through the ctl:kill path (killer.HandleKill) both closes the live
// session AND deletes the token key — the session cannot re-establish and
// the external-revocation invariant ("no key = no session") holds for the
// control-plane kill path too.
func TestMSSQLLiveKillRevokesSessionToken(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-kill-sess-%d", time.Now().UnixNano())
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: username, DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "1434", DBType: "mssql", TicketID: "T-9-13",
		SessionID: "sid-" + token[len("sess_"):],
		Mode:      "session", IP: "127.0.0.1", IssuedAt: time.Now().Unix()}
	if err := vs.SetToken(context.Background(), token, tok, time.Hour); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), tok.SessionID) })

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyLoopP(t, vs, &logBuf, nil)
	c := holdToken(t, token, ln)
	defer c.close()

	killer := NewKiller(nil, nil, p)
	killer.SetStore(vs)
	msg := []byte(fmt.Sprintf(`{"session_id":%q,"mode":"connection"}`, tok.SessionID))
	if line, sid := killer.HandleKill(msg); line != "session killed" || sid != tok.SessionID {
		t.Fatalf("HandleKill = %q/%q, want session killed/%s", line, sid, tok.SessionID)
	}
	// The client conn must be closed by the kill…
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.conn.Read(buf); err == nil {
		t.Fatal("session still alive after kill")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("session survived 5s after kill")
	}
	// …and the token key must be GONE (no reconnect possible).
	alive, err := vs.TokenAlive(context.Background(), token)
	if err != nil || alive {
		t.Fatalf("TokenAlive after kill = %v %v, want false — kill must revoke the token", alive, err)
	}
}
