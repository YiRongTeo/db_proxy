package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/store"
)

// --- unit: cancel registry semantics (review 2026-08-17) -------------------

func TestPGCancelRegistryLookup(t *testing.T) {
	p := NewPGProxy(testLogger(t), nil, &ConfigCredResolver{}, nil)
	s := &pgSession{id: "sid-cancel-1", threadID: 424242, cancelKey: 0xDEADBEEF}
	p.registerCancel(s)

	if got := p.cancelLookup(uint32(s.threadID), s.cancelKey); got != s {
		t.Fatalf("lookup with correct (pid, key) = %v, want session", got)
	}
	if got := p.cancelLookup(uint32(s.threadID), s.cancelKey^1); got != nil {
		t.Fatalf("lookup with wrong secret = %v, want nil (silent no-op)", got)
	}
	if got := p.cancelLookup(1, s.cancelKey); got != nil {
		t.Fatalf("lookup with unknown pid = %v, want nil", got)
	}

	// Unregister removes exactly this session; a reused pid for a NEWER
	// session must survive the old session's unregister (identity guard).
	s2 := &pgSession{id: "sid-cancel-2", threadID: 424242, cancelKey: 0x11111111}
	p.registerCancel(s2)
	p.unregisterCancel(s)
	if got := p.cancelLookup(uint32(s2.threadID), s2.cancelKey); got != s2 {
		t.Fatalf("identity guard: unregister of old session removed the new one")
	}
	p.unregisterCancel(s2)
	if got := p.cancelLookup(uint32(s2.threadID), s2.cancelKey); got != nil {
		t.Fatalf("lookup after unregister = %v, want nil", got)
	}
}

func TestPGCancelRegistrySkipsZeroPid(t *testing.T) {
	p := NewPGProxy(testLogger(t), nil, &ConfigCredResolver{}, nil)
	s := &pgSession{id: "sid-cancel-zero", threadID: 0, cancelKey: 1}
	p.registerCancel(s) // threadID 0 → degrade rule: not cancellable
	p.cancelMu.Lock()
	n := len(p.cancels)
	p.cancelMu.Unlock()
	if n != 0 {
		t.Fatalf("session with threadID 0 entered the cancel registry (%d entries)", n)
	}
}

func TestCancelKeyRandomness(t *testing.T) {
	seen := map[uint32]bool{}
	for i := 0; i < 50; i++ {
		k := newCancelKey()
		if k == 0 {
			t.Fatal("cancel key = 0")
		}
		if seen[k] {
			t.Fatalf("duplicate cancel key %#x in 50 draws", k)
		}
		seen[k] = true
	}
}

// --- live: CancelRequest over the wire against pg-test ----------------------

// startPGCancelTestProxy accepts ANY number of connections and runs each
// through the proxy (the kill-test harness accepts exactly one — too
// narrow for CancelRequest, which opens a SECOND connection). done closes
// when the listener closes; tests wait for session teardown via
// waitPGSessionsEmpty instead.
func startPGCancelTestProxy(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer) (net.Listener, *PGProxy, <-chan struct{}) {
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
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()
	return ln, p, done
}

// waitPGSessionsEmpty polls the session registry until teardown completes.
func waitPGSessionsEmpty(t *testing.T, p *PGProxy) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		n := len(p.sessions)
		p.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("PG sessions did not tear down within 5s")
}

// pgCancelSend opens a fresh connection to the proxy and sends one
// CancelRequest (the shape libpq's PQcancel sends), then closes it — the
// proxy must service it and close the connection WITHOUT any response.
func pgCancelSend(t *testing.T, ln net.Listener, pid, key uint32) {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("cancel dial: %v", err)
	}
	defer c.Close()
	f := pgproto3.NewFrontend(pgproto3.NewChunkReader(c), c)
	if err := f.Send(&pgproto3.CancelRequest{ProcessID: pid, SecretKey: key}); err != nil {
		t.Fatalf("send CancelRequest: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if b := make([]byte, 1); func() bool {
		_, err := c.Read(b)
		return err != nil // EOF/timeout = no response, per PG semantics
	}() == false {
		t.Fatal("cancel connection received data — the proxy must not respond to a CancelRequest")
	}
}

// pgReadUntilReadyErr reads backend messages until ReadyForQuery and
// reports whether an ErrorResponse arrived.
func pgReadUntilReadyErr(t *testing.T, front *pgproto3.Frontend) (errResp *pgproto3.ErrorResponse) {
	t.Helper()
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			errResp = m
		case *pgproto3.ReadyForQuery:
			return errResp
		}
	}
}

func TestPGCancelRequestLive(t *testing.T) {
	vs := proxyTestStore(t)
	var logBuf bytes.Buffer
	ln, p, _ := startPGCancelTestProxy(t, vs, &logBuf)
	userCh := subscribePG(t, vs, "queries:alice") // subscribe BEFORE the query publishes
	defer func() {
		if t.Failed() {
			t.Logf("PROXY LOG:\n%s", logBuf.String())
		}
	}()

	token := pgLiveToken(t, vs)
	front := pgDialDB(t, ln, token, false, "appdb")
	authOK, _, bk, _ := pgReadUntilReady(t, front)
	if !authOK {
		t.Fatal("auth not ok")
	}
	if bk == nil {
		t.Fatal("no BackendKeyData in the welcome sequence")
	}
	// Review 2026-08-17: the key must be the REAL per-session identity —
	// the fabricated {42, 4242} is gone.
	if bk.ProcessID == 42 && bk.SecretKey == 4242 {
		t.Fatal("BackendKeyData still carries the fabricated {42, 4242}")
	}

	res := pgExecQuery(t, front, "SELECT 1")
	if len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Fatalf("SELECT 1 = %v, want [[1]]", res.rows)
	}
	ev := recvQueryEvent(t, userCh)
	sid := ev.SessionID

	// The advertised (pid, key) must match the cancel registry entry.
	p.cancelMu.Lock()
	var registered *pgSession
	for _, s := range p.cancels {
		if s.id == sid {
			registered = s
		}
	}
	p.cancelMu.Unlock()
	if registered == nil {
		t.Fatal("session not in the cancel registry")
	}
	if bk.ProcessID != uint32(registered.threadID) || bk.SecretKey != registered.cancelKey {
		t.Fatalf("BackendKeyData (%d, %#x) != registry (%d, %#x)",
			bk.ProcessID, bk.SecretKey, registered.threadID, registered.cancelKey)
	}

	// In-flight pg_sleep(60), then a client-side CancelRequest — the exact
	// shape psql's Ctrl-C produces.
	if err := front.Send(&pgproto3.Query{String: "SELECT pg_sleep(60)"}); err != nil {
		t.Fatalf("send pg_sleep: %v", err)
	}
	time.Sleep(1500 * time.Millisecond) // sleep now in-flight on the backend
	pgCancelSend(t, ln, bk.ProcessID, bk.SecretKey)

	// The maker sees the 57014 cancellation; the session survives.
	aborted := false
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive after cancel: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			if m.Code != "57014" || !strings.Contains(m.Message, "canceling statement") {
				t.Errorf("abort error = %s (%s), want 57014 canceling statement", m.Code, m.Message)
			}
			aborted = true
		case *pgproto3.ReadyForQuery:
			if !aborted {
				t.Fatalf("pg_sleep was not aborted by the CancelRequest\nproxy log:\n%s", logBuf.String())
			}
			goto survived
		}
	}
survived:
	res = pgExecQuery(t, front, "SELECT 1")
	if len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Fatalf("post-cancel SELECT 1 = %v, want [[1]]", res.rows)
	}

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGSessionsEmpty(t, p)
}

func TestPGCancelRequestWrongSecretLive(t *testing.T) {
	vs := proxyTestStore(t)
	var logBuf bytes.Buffer
	ln, p, _ := startPGCancelTestProxy(t, vs, &logBuf)

	token := pgLiveToken(t, vs)
	front := pgDialDB(t, ln, token, false, "appdb")
	_, _, bk, _ := pgReadUntilReady(t, front)
	if bk == nil {
		t.Fatal("no BackendKeyData")
	}

	// Short sleep; a cancel with the WRONG secret must be a silent no-op —
	// the query runs to completion with no error (real-backend semantics).
	if err := front.Send(&pgproto3.Query{String: "SELECT pg_sleep(3)"}); err != nil {
		t.Fatalf("send pg_sleep: %v", err)
	}
	time.Sleep(700 * time.Millisecond) // sleep in-flight
	pgCancelSend(t, ln, bk.ProcessID, bk.SecretKey^0xFFFFFFFF)

	errResp := pgReadUntilReadyErr(t, front)
	if errResp != nil {
		t.Fatalf("wrong-secret cancel aborted the query: %s (%s)", errResp.Code, errResp.Message)
	}

	// Unknown pid is equally inert.
	if err := front.Send(&pgproto3.Query{String: "SELECT pg_sleep(3)"}); err != nil {
		t.Fatalf("send pg_sleep: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
	pgCancelSend(t, ln, bk.ProcessID+1, bk.SecretKey)
	if errResp := pgReadUntilReadyErr(t, front); errResp != nil {
		t.Fatalf("unknown-pid cancel aborted the query: %s (%s)", errResp.Code, errResp.Message)
	}

	// The registry entry is gone after session teardown.
	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGSessionsEmpty(t, p)
	p.cancelMu.Lock()
	left := len(p.cancels)
	p.cancelMu.Unlock()
	if left != 0 {
		t.Fatalf("cancel registry not cleaned up after teardown (%d entries)", left)
	}
}

// testLogger builds a discard logger for unit tests.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
