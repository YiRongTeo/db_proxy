package proxy

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 8.7 LIVE: api-mode data plane against a local vault stub --------
//
// The "money shot": the backend DB password comes from an HTTP credential
// API per connect — never from the config file. The vault stub below is a
// tiny in-process vault; the REAL ro_pw lives ONLY inside its handler, so a
// successful live session against the real backend proves the password
// travelled vault → resolver → backend connect, and the data-plane log is
// grepped to prove the password never appears in it.

// vaultStub is a tiny in-test credential vault: it records every request's
// query params and X-Api-Key and answers with a fixed status + body.
type vaultStub struct {
	mu       sync.Mutex
	queries  []string
	keys     []string
	status   int
	body     string
	apiKey   string // if non-empty, only answer requests carrying it
	requests int
}

func newVaultStub(status int, body, apiKey string) *vaultStub {
	return &vaultStub{status: status, body: body, apiKey: apiKey}
}

func (v *vaultStub) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.queries = append(v.queries, r.URL.RawQuery)
		v.keys = append(v.keys, r.Header.Get("X-Api-Key"))
		v.requests++
		badKey := v.apiKey != "" && r.Header.Get("X-Api-Key") != v.apiKey
		v.mu.Unlock()
		if badKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(v.status)
		_, _ = w.Write([]byte(v.body))
	}
}

func (v *vaultStub) query(i int) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if i >= len(v.queries) {
		return ""
	}
	return v.queries[i]
}

func (v *vaultStub) apiKeySeen(i int) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if i >= len(v.keys) {
		return ""
	}
	return v.keys[i]
}

func (v *vaultStub) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.requests
}

func (v *vaultStub) assertQueryParams(t *testing.T, i int, dbType, dbUser, dbIP, dbPort string) {
	t.Helper()
	q := v.query(i)
	for _, want := range []string{
		"db_type=" + dbType, "db_user=" + dbUser, "db_ip=" + dbIP, "db_port=" + dbPort,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("vault request %d query %q missing %s", i, q, want)
		}
	}
}

// startTestProxyWithResolver is startTestProxyWithCreds with a caller-
// supplied CredResolver (Task 8.7): the api-mode live tests point it at an
// APICredResolver backed by the vault stub.
func startTestProxyWithResolver(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, res CredResolver) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewMySQLProxy(logger, vs, res, nil)
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

// TestAPICredsLiveMySQLSession is the money shot: full live session
// (token → SELECT rows against the real mysql-test backend) with the
// password served ONLY by the vault stub. The data-plane log is grepped:
// the password value must appear nowhere.
func TestAPICredsLiveMySQLSession(t *testing.T) {
	const realPW = "ro_pw" // exists ONLY in the vault stub handler
	stub := newVaultStub(http.StatusOK, `{"password":"`+realPW+`"}`, "vault-key-1")
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	vs := proxyTestStore(t)
	ctx := context.Background()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "api-live-user", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-7"}
	if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	res, err := NewAPICredResolver(srv.URL, "vault-key-1", 5*time.Second)
	if err != nil {
		t.Fatalf("NewAPICredResolver: %v", err)
	}
	var logBuf bytes.Buffer
	ln, proxyDone := startTestProxyWithResolver(t, vs, &logBuf, res)

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

	// SELECT against the real backend — only possible with the REAL ro_pw,
	// which only the vault stub knows.
	sel := "SELECT id,name FROM demo_items"
	if err := writeMySQLPacket(client, 0, append([]byte{cmdQuery}, sel...)); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	if _, err := readTextResultSet(client); err != nil {
		t.Fatalf("read result set: %v", err)
	}

	client.Close()
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return within 5s of client close")
	}

	// The vault was consulted with the parsed key parts + api key.
	if stub.count() < 1 {
		t.Fatal("vault stub was never called")
	}
	stub.assertQueryParams(t, 0, "mysql", "ro_user", "127.0.0.1", "3307")
	if got := stub.apiKeySeen(0); got != "vault-key-1" {
		t.Errorf("vault X-Api-Key = %q, want vault-key-1", got)
	}

	// HARD hygiene: the password value is nowhere in the data-plane log.
	logs := logBuf.String()
	if strings.Contains(logs, realPW) {
		t.Errorf("data plane log MUST NEVER contain the password %q:\n%s", realPW, logs)
	}
}

// TestAPICredsLiveMySQLVault404 is the negative: the vault answers 404
// (with the real password in the BODY, to prove even the body never
// leaks). The session fails with a clean client error, the log carries the
// status code and the key, and neither the password nor the body appears
// anywhere.
func TestAPICredsLiveMySQLVault404(t *testing.T) {
	const realPW = "ro_pw" // planted in the 404 BODY — must never leak
	stub := newVaultStub(http.StatusNotFound, `{"password":"`+realPW+`"}`, "")
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	vs := proxyTestStore(t)
	ctx := context.Background()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "api-404-user", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql"}
	if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	res, err := NewAPICredResolver(srv.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewAPICredResolver: %v", err)
	}
	var logBuf bytes.Buffer
	ln, proxyDone := startTestProxyWithResolver(t, vs, &logBuf, res)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	if _, _, err := readMySQLPacket(client); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	seq, resp, err := readMySQLPacket(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(resp) == 0 || resp[0] != 0xff {
		t.Fatalf("expected ERR packet (vault 404), got seq=%d resp=% x err=%v", seq, resp, err)
	}
	if !bytes.Contains(resp, []byte("backend unavailable")) {
		t.Errorf("client error must be the clean 'backend unavailable', got % x", resp)
	}

	client.Close()
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return within 5s of client close")
	}

	// Clean, status-only failure in the log: status code + key name, no
	// password, no response body.
	logs := logBuf.String()
	if !strings.Contains(logs, "backend connect failed") {
		t.Errorf("log missing 'backend connect failed':\n%s", logs)
	}
	if !strings.Contains(logs, "404") {
		t.Errorf("log missing the vault status code 404:\n%s", logs)
	}
	if !strings.Contains(logs, "mysql:ro_user@127.0.0.1:3307") {
		t.Errorf("log missing the credential key name:\n%s", logs)
	}
	if strings.Contains(logs, realPW) {
		t.Errorf("data plane log MUST NEVER contain the password %q:\n%s", realPW, logs)
	}
	if strings.Contains(logs, `{"password"`) {
		t.Errorf("data plane log MUST NEVER contain the vault response body:\n%s", logs)
	}
}

// TestAPICredsLivePGConnect proves the PostgreSQL path through the API
// resolver end-to-end against the real pg-test backend: the password comes
// from the vault stub and the hijacked raw stream round-trips a query.
func TestAPICredsLivePGConnect(t *testing.T) {
	stub := newVaultStub(http.StatusOK, `{"password":"ro_pw"}`, "")
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	res, err := NewAPICredResolver(srv.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewAPICredResolver: %v", err)
	}
	tok := &models.TokenPayload{DBType: "postgres", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "5433"}
	f, err := connectPostgresBackend(context.Background(), tok, res, "appdb")
	if err != nil {
		t.Fatalf("connectPostgresBackend via vault: %v", err)
	}
	defer f.Close()

	writePGQuery(t, f.conn, "SELECT 1")
	resp := readPGQueryResponse(t, f.conn)
	if resp.errMsg != "" {
		t.Fatalf("backend error: %s", resp.errMsg)
	}
	if !resp.rowDesc || !resp.dataRow {
		t.Fatalf("SELECT 1 response missing RowDescription/DataRow: %+v", resp)
	}
	if !bytes.Contains(resp.dataRowPayload, []byte("1")) {
		t.Errorf("DataRow %q does not contain value 1", resp.dataRowPayload)
	}
	if stub.count() < 1 {
		t.Fatal("vault stub was never called")
	}
	stub.assertQueryParams(t, 0, "postgres", "ro_user", "127.0.0.1", "5433")
}
