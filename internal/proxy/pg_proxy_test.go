package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
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
// real conn, not net.Pipe).
func startTestPGProxy(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, n int) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewPGProxy(logger, vs, map[string]string{})
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
// advertises SSL (spec D10). Then a StartupMessage with user = token is sent.
func pgDial(t *testing.T, ln net.Listener, token string, sslFirst bool) *pgproto3.Frontend {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second)) // no hanging tests
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
	if sslFirst {
		if err := front.Send(&pgproto3.SSLRequest{}); err != nil {
			t.Fatalf("send SSLRequest: %v", err)
		}
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read SSL response: %v", err)
		}
		if buf[0] != 'N' {
			t.Fatalf("SSLRequest response: got %q (0x%02x), want exactly 'N' (0x4e)", buf[0], buf[0])
		}
	}
	if err := front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": token, "database": "appdb"},
	}); err != nil {
		t.Fatalf("send StartupMessage: %v", err)
	}
	return front
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
