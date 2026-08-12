package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// startTestPGProxy runs PGProxy.handleConn on a fresh listener for n
// sequential sessions and returns the listener plus a channel closed when all
// sessions have ended. The test acts as the Dispatcher: accept + bufio.Reader
// + handleConn (real TCP — the 10s handshake deadline and 'N' write need a
// real conn, not net.Pipe). No backend credentials — sessions that pass the
// auth handshake hit the FATAL backend-unavailable path.
func startTestPGProxy(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, n int) (net.Listener, <-chan struct{}) {
	t.Helper()
	return startTestPGProxyWithCreds(t, vs, logBuf, map[string]string{}, n)
}

// pgTestToken registers a token directly in Valkey (single-use semantics live
// in GetDeleteToken). Tokens are unique per test so runs never collide on the
// shared dev Valkey.
func pgTestToken(t *testing.T, vs *store.ValkeyStore, dbType string) string {
	t.Helper()
	token := fmt.Sprintf("pgtest_%d_%s", time.Now().UnixNano(), dbType)
	err := vs.SetToken(context.Background(), token, models.TokenPayload{
		Username: "alice",
		DBUser:   "db_alice",
		DBIP:     "127.0.0.1",
		DBPort:   "5432",
		DBType:   dbType,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	return token
}

// pgDial connects to the listener and wraps the conn in a pgproto3.Frontend
// (raw PG wire protocol). If sslFirst, an SSLRequest is sent first and the
// single-byte response is asserted to be exactly 'N' (0x4E) — the proxy never
// advertises SSL (spec D10). Then a StartupMessage with user = token (and
// database appdb) is sent.
func pgDial(t *testing.T, ln net.Listener, token string, sslFirst bool) *pgproto3.Frontend {
	t.Helper()
	return pgDialDB(t, ln, token, sslFirst, "appdb")
}

// pgReadUntilReady consumes backend messages until ReadyForQuery and reports
// what was seen (AuthenticationOk flag, ParameterStatus values, BackendKeyData).
func pgReadUntilReady(t *testing.T, front *pgproto3.Frontend) (authOK bool, params map[string]string, bk *pgproto3.BackendKeyData, rq *pgproto3.ReadyForQuery) {
	t.Helper()
	params = map[string]string{}
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			authOK = true
		case *pgproto3.ParameterStatus:
			params[m.Name] = m.Value
		case *pgproto3.BackendKeyData:
			bk = m
		case *pgproto3.ReadyForQuery:
			rq = m
			return
		}
	}
}

// pgReadFatalError consumes messages until an ErrorResponse and asserts it is
// a FATAL 28000 error.
func pgReadFatalError(t *testing.T, front *pgproto3.Frontend) *pgproto3.ErrorResponse {
	t.Helper()
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		er, ok := msg.(*pgproto3.ErrorResponse)
		if !ok {
			t.Fatalf("expected ErrorResponse, got %T", msg)
		}
		if er.Severity != "FATAL" {
			t.Fatalf("severity: got %q, want FATAL", er.Severity)
		}
		if er.Code != "28000" {
			t.Fatalf("sqlstate: got %q, want 28000", er.Code)
		}
		return er
	}
}

// waitPGDone asserts the proxy session ended (handleConn returned) promptly.
func waitPGDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pg session did not end within 5s")
	}
}

// (a) SSLRequest → the response byte is exactly 'N'; a StartupMessage sent
// after the refusal still completes the full handshake.
func TestPGProxySSLRefused(t *testing.T) {
	vs := proxyTestStore(t)
	logBuf := &bytes.Buffer{}
	ln, done := startTestPGProxy(t, vs, logBuf, 1)
	token := pgTestToken(t, vs, "postgres")

	front := pgDial(t, ln, token, true) // asserts the exact 'N' byte

	authOK, params, bk, rq := pgReadUntilReady(t, front)
	if !authOK {
		t.Fatal("expected AuthenticationOk after SSL refusal")
	}
	if params["server_version"] != "17.0" {
		t.Fatalf("server_version: got %q, want 17.0", params["server_version"])
	}
	if params["client_encoding"] != "UTF8" {
		t.Fatalf("client_encoding: got %q, want UTF8", params["client_encoding"])
	}
	if bk == nil {
		t.Fatal("expected BackendKeyData")
	}
	if rq == nil || rq.TxStatus != 'I' {
		t.Fatalf("expected ReadyForQuery TxStatus 'I', got %+v", rq)
	}
	waitPGDone(t, done)
}

// (b) Valid token → full handshake: AuthenticationOk, ParameterStatus
// (server_version + client_encoding), BackendKeyData, ReadyForQuery 'I'.
// Also asserts the token value never appears in the proxy log.
func TestPGProxyValidTokenHandshake(t *testing.T) {
	vs := proxyTestStore(t)
	logBuf := &bytes.Buffer{}
	ln, done := startTestPGProxy(t, vs, logBuf, 1)
	token := pgTestToken(t, vs, "postgres")

	front := pgDial(t, ln, token, false)

	authOK, params, bk, rq := pgReadUntilReady(t, front)
	if !authOK {
		t.Fatal("expected AuthenticationOk")
	}
	if params["server_version"] != "17.0" {
		t.Fatalf("server_version: got %q, want 17.0", params["server_version"])
	}
	if params["client_encoding"] != "UTF8" {
		t.Fatalf("client_encoding: got %q, want UTF8", params["client_encoding"])
	}
	if bk == nil || bk.ProcessID == 0 {
		t.Fatalf("expected BackendKeyData, got %+v", bk)
	}
	if rq == nil || rq.TxStatus != 'I' {
		t.Fatalf("expected ReadyForQuery TxStatus 'I', got %+v", rq)
	}
	waitPGDone(t, done)

	if got := logBuf.String(); strings.Contains(got, token) {
		t.Fatalf("token value leaked into proxy log:\n%s", got)
	}
}

// (c) Unknown token → FATAL 28000 'invalid or expired token'.
func TestPGProxyInvalidToken(t *testing.T) {
	vs := proxyTestStore(t)
	ln, done := startTestPGProxy(t, vs, &bytes.Buffer{}, 1)

	front := pgDial(t, ln, "no_such_token", false)

	er := pgReadFatalError(t, front)
	if er.Message != "invalid or expired token" {
		t.Fatalf("message: got %q, want %q", er.Message, "invalid or expired token")
	}
	waitPGDone(t, done)
}

// (d) Token bound to the wrong DB type → FATAL 28000 'token not valid for
// this protocol' (and the token is still consumed — single-use gate).
func TestPGProxyWrongDBType(t *testing.T) {
	vs := proxyTestStore(t)
	ln, done := startTestPGProxy(t, vs, &bytes.Buffer{}, 1)
	token := pgTestToken(t, vs, "mysql") // wrong protocol

	front := pgDial(t, ln, token, false)

	er := pgReadFatalError(t, front)
	if er.Message != "token not valid for this protocol" {
		t.Fatalf("message: got %q, want %q", er.Message, "token not valid for this protocol")
	}
	waitPGDone(t, done)
}

// (e) Single-use: the same token accepted once; a second session with it is
// rejected with FATAL 28000 (GETDEL consumed it on the first handshake).
func TestPGProxyTokenSingleUse(t *testing.T) {
	vs := proxyTestStore(t)
	ln, done := startTestPGProxy(t, vs, &bytes.Buffer{}, 2)
	token := pgTestToken(t, vs, "postgres")

	// first session: full handshake (its ReadyForQuery proves the auth path
	// completed; done below closes only after BOTH sessions end)
	front := pgDial(t, ln, token, false)
	_, _, _, rq := pgReadUntilReady(t, front)
	if rq == nil || rq.TxStatus != 'I' {
		t.Fatalf("first session: expected ReadyForQuery 'I', got %+v", rq)
	}

	// second session with the same token: rejected
	front2 := pgDial(t, ln, token, false)
	er := pgReadFatalError(t, front2)
	if er.Message != "invalid or expired token" {
		t.Fatalf("message: got %q, want %q", er.Message, "invalid or expired token")
	}
	waitPGDone(t, done)
}

// --- Task 7.5: PostgreSQL wire TLS ------------------------------------------

// startTestPGProxyTLS runs handleConn on a fresh TLS-enabled listener for n
// sequential sessions (Task 7.5): SSLRequests are answered with 'S' and the
// session continues over TLS. Skips when the dev certs are absent (same
// policy as the MySQL TLS tests).
func startTestPGProxyTLS(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, creds map[string]string, n int) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewPGProxy(logger, vs, creds, loadTestTLS(t))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(conn)
			p.handleConn(context.Background(), conn, br)
		}
	}()
	return ln, done
}

// pgTLSDial connects to a TLS-enabled listener, sends an SSLRequest, asserts
// the single-byte response is exactly 'S' (0x53), performs the TLS handshake
// (InsecureSkipVerify — encryption without verification, REQUIRED semantics
// for the self-signed dev cert), and returns a pgproto3.Frontend speaking
// over the TLS conn plus the raw TLS conn for teardown.
func pgTLSDial(t *testing.T, ln net.Listener) (*pgproto3.Frontend, *tls.Conn) {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // no hanging tests

	rawFront := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
	if err := rawFront.Send(&pgproto3.SSLRequest{}); err != nil {
		t.Fatalf("send SSLRequest: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read SSL response: %v", err)
	}
	if buf[0] != 'S' {
		t.Fatalf("SSLRequest response: got %q (0x%02x), want exactly 'S' (0x53)", buf[0], buf[0])
	}

	tlsClient := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if tlsClient.ConnectionState().Version == 0 {
		t.Fatal("TLS handshake completed without a negotiated version")
	}
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(tlsClient), tlsClient)
	return front, tlsClient
}

// TestPGProxySessionOverTLS (Task 7.5): the full session with a TLS client —
// SSLRequest → exactly 'S' → TLS handshake → the REAL StartupMessage over
// TLS → welcome sequence in order (AuthenticationOk → 4x ParameterStatus →
// BackendKeyData → ReadyForQuery 'I') → a Simple Query relayed over TLS with
// a real result set → capture event still flows (stmt_type/status/columns/
// rows) → token consumed (single-use). Mirrors TestMySQLSessionOverTLS.
func TestPGProxySessionOverTLS(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token := fmt.Sprintf("pgtls_%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{
		Username: "tls-pg-user",
		DBUser:   "ro_user",
		DBIP:     "127.0.0.1",
		DBPort:   "5433",
		DBType:   "postgres",
		TicketID: "T-7-5",
	}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	userCh := subscribePG(t, vs, "queries:tls-pg-user")

	ln, done := startTestPGProxyTLS(t, vs, &bytes.Buffer{}, pgLiveCreds, 1)
	front, tlsClient := pgTLSDial(t, ln)

	// The REAL StartupMessage goes over TLS (token-as-username + appdb).
	if err := front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": token, "database": "appdb"},
	}); err != nil {
		t.Fatalf("send StartupMessage over TLS: %v", err)
	}

	// Welcome sequence ORDER (all over TLS): AuthenticationOk →
	// ParameterStatus x4 → BackendKeyData → ReadyForQuery 'I'.
	var order []string
	params := map[string]string{}
	var bk *pgproto3.BackendKeyData
	var rq *pgproto3.ReadyForQuery
	for rq == nil {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive over TLS: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			order = append(order, "AuthenticationOk")
		case *pgproto3.ParameterStatus:
			order = append(order, "ParameterStatus")
			params[m.Name] = m.Value
		case *pgproto3.BackendKeyData:
			order = append(order, "BackendKeyData")
			bk = m
		case *pgproto3.ReadyForQuery:
			order = append(order, "ReadyForQuery")
			rq = m
		}
	}
	wantOrder := []string{"AuthenticationOk", "ParameterStatus", "ParameterStatus",
		"ParameterStatus", "ParameterStatus", "BackendKeyData", "ReadyForQuery"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("welcome sequence = %v, want %v", order, wantOrder)
	}
	if params["server_version"] != "17.0" || params["client_encoding"] != "UTF8" {
		t.Errorf("ParameterStatus = %v, want server_version 17.0 + client_encoding UTF8", params)
	}
	if bk == nil || bk.ProcessID == 0 {
		t.Errorf("BackendKeyData = %+v, want non-zero ProcessID", bk)
	}
	if rq.TxStatus != 'I' {
		t.Fatalf("ReadyForQuery TxStatus = %q, want 'I'", rq.TxStatus)
	}

	// Relay round trip over TLS: Q 'SELECT 1' → real result set.
	res := pgExecQuery(t, front, "SELECT 1")
	if !res.ready || res.tag != "SELECT 1" {
		t.Errorf("result = %+v, want ready + tag SELECT 1", res)
	}
	if len(res.rows) != 1 || len(res.rows[0]) != 1 || res.rows[0][0] != "1" {
		t.Errorf("rows = %v, want [[1]]", res.rows)
	}

	// Capture event flows exactly as on the plaintext wire (sniffing and
	// response capture both run over the TLS session).
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, userCh), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.Kind != "query" || ev.SQL != "SELECT 1" || ev.StmtType != "select" || ev.Status != "ok" {
		t.Errorf("event = kind %q sql %q stmt_type %q status %q, want query/SELECT 1/select/ok",
			ev.Kind, ev.SQL, ev.StmtType, ev.Status)
	}
	if !reflect.DeepEqual(ev.Columns, []string{"?column?"}) {
		t.Errorf("columns = %q, want [?column?]", ev.Columns)
	}
	if !reflect.DeepEqual(ev.Rows, [][]string{{"1"}}) {
		t.Errorf("rows = %q, want [[1]]", ev.Rows)
	}
	if ev.TicketID != "T-7-5" || !strings.HasPrefix(ev.SessionID, "sid-") {
		t.Errorf("ticket_id/session_id = %q/%q, want T-7-5 / sid- prefix", ev.TicketID, ev.SessionID)
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

// TestPGProxyPlaintextOnTLSListener (Task 7.5): a client that skips the
// SSLRequest entirely still completes the handshake on a TLS-enabled
// listener — TLS is negotiated ONLY when the client asks; the plaintext
// path is byte-identical to the non-TLS listener.
func TestPGProxyPlaintextOnTLSListener(t *testing.T) {
	vs := proxyTestStore(t)
	ln, done := startTestPGProxyTLS(t, vs, &bytes.Buffer{}, map[string]string{}, 1)
	token := pgTestToken(t, vs, "postgres")

	front := pgDial(t, ln, token, false) // no SSLRequest → plaintext path
	authOK, _, _, rq := pgReadUntilReady(t, front)
	if !authOK {
		t.Fatal("expected AuthenticationOk on the plaintext path of a TLS listener")
	}
	if rq == nil || rq.TxStatus != 'I' {
		t.Fatalf("expected ReadyForQuery 'I', got %+v", rq)
	}
	waitPGDone(t, done)
}
