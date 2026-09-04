package proxy

// Task 9.13 consistency suite — the session-token behavior (IP lock, not
// consumed / unlimited connection attempts, TTL-until-revoked, idle kill)
// must hold IDENTICALLY for all three protocols. The mssql lifecycle test
// (zz_live_mssql_test.go) covers TDS; these two tests mirror the same
// assertions over the live MySQL and PostgreSQL backends:
//
//  1. one session token opens TWO sequential sessions (not consumed),
//  2. a token stamped for a foreign IP is rejected at login,
//  3. deleting the token key mid-session closes the running session
//     within the sweep interval (live revocation).
//
// Same zz_ convention as the mssql tests: live sessions whose sess:live
// records exist — run last in the proxy binary.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// startMySQLProxyLoopP is startTestProxyWithResolver with an accept loop
// AND the proxy pointer (the sweeper needs it).
func startMySQLProxyLoopP(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer) (net.Listener, *MySQLProxy) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(logBuf, nil)), vs, &ConfigCredResolver{
		Creds: map[string]string{"mysql:ro_user@127.0.0.1:3307": "ro_pw"},
	}, nil)
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

// startPGProxyLoopP is the PG mirror (same wiring as startHoldPGProxy but
// with an accept loop and the pointer).
func startPGProxyLoopP(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer) (net.Listener, *PGProxy) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := NewPGProxy(slog.New(slog.NewTextHandler(logBuf, nil)), vs, &ConfigCredResolver{
		Creds: map[string]string{"postgres:ro_user@127.0.0.1:5433": "ro_pw"},
	}, nil)
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

// sessionTokenFor mints a session-mode token payload bound to 127.0.0.1
// (the test clients connect from the loopback).
func sessionTokenFor(t *testing.T, vs *store.ValkeyStore, username, dbType, dbPort string) string {
	t.Helper()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: username, DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: dbPort, DBType: dbType, TicketID: "T-9-13",
		SessionID: "sid-" + token[len("sess_"):],
		Mode:      "session", IP: "127.0.0.1", IssuedAt: time.Now().Unix()}
	if err := vs.SetToken(context.Background(), token, tok, time.Hour); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), tok.SessionID) })
	return token
}

// mysqlLoginOnce does the full MySQL handshake with the token and reports
// whether the proxy accepted it (OK packet).
func mysqlLoginOnce(t *testing.T, ln net.Listener, token string) bool {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := readMySQLPacket(conn); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(conn, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	_, resp, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if len(resp) == 0 {
		return false
	}
	return resp[0] == 0x00 // OK
}

// pgLoginOnce does the PG startup with the token and reports whether the
// proxy accepted it (ReadyForQuery, no ErrorResponse).
func pgLoginOnce(t *testing.T, ln net.Listener, token string) bool {
	t.Helper()
	front, _ := pgDialDBRaw(t, ln, token, false, "appdb")
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("pg auth receive: %v", err)
		}
		switch msg.(type) {
		case *pgproto3.ErrorResponse:
			return false
		case *pgproto3.ReadyForQuery:
			return true
		}
	}
}

// assertSessionClosesSoon blocks reading the held connection until the
// proxy closes it (revocation), failing on a 5s timeout.
func assertSessionClosesSoon(t *testing.T, label string, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("%s: session still alive after revocation", label)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s: session survived 5s after revocation", label)
	}
}

func TestLiveSessionTokenMySQL(t *testing.T) {
	vs := proxyTestStore(t)
	token := sessionTokenFor(t, vs, fmt.Sprintf("mysql-sess-%d", time.Now().UnixNano()), "mysql", "3307")
	var logBuf bytes.Buffer
	ln, p := startMySQLProxyLoopP(t, vs, &logBuf)

	// 1. Not consumed: two sequential logins on the same token.
	if !mysqlLoginOnce(t, ln, token) {
		t.Fatal("session token login #1 failed")
	}
	if !mysqlLoginOnce(t, ln, token) {
		t.Fatal("session token login #2 failed — token must not be consumed")
	}
	alive, err := vs.TokenAlive(context.Background(), token)
	if err != nil || !alive {
		t.Fatalf("TokenAlive after 2 logins = %v %v, want true", alive, err)
	}

	// 2. IP lock: foreign-IP token rejected.
	foreign := sessionTokenFor(t, vs, fmt.Sprintf("mysql-ip-%d", time.Now().UnixNano()), "mysql", "3307")
	if err := vs.SetToken(context.Background(), foreign, models.TokenPayload{
		Username: "alice", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "3307",
		DBType: "mysql", SessionID: "sid-" + foreign[len("sess_"):],
		Mode: "session", IP: "192.0.2.1", IssuedAt: time.Now().Unix(),
	}, time.Hour); err != nil {
		t.Fatalf("SetToken(foreign): %v", err)
	}
	if mysqlLoginOnce(t, ln, foreign) {
		t.Fatal("wrong-IP login SUCCEEDED — session tokens are IP-locked")
	}

	// 3. Live revocation: hold a session, delete the key, expect close.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := readMySQLPacket(conn); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(conn, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	_, resp, err := readMySQLPacket(conn)
	if err != nil || len(resp) == 0 || resp[0] != 0x00 {
		t.Fatalf("hold login failed: %v % x", err, resp)
	}
	sweepCtx, sweepCancel := context.WithCancel(context.Background())
	defer sweepCancel()
	go RunSessionSweeper(sweepCtx, slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionPolicy{Poll: 300 * time.Millisecond}, p)
	if err := vs.DeleteToken(context.Background(), token); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	assertSessionClosesSoon(t, "mysql", conn)
}

func TestLiveSessionTokenPG(t *testing.T) {
	vs := proxyTestStore(t)
	token := sessionTokenFor(t, vs, fmt.Sprintf("pg-sess-%d", time.Now().UnixNano()), "postgres", "5433")
	var logBuf bytes.Buffer
	ln, p := startPGProxyLoopP(t, vs, &logBuf)

	// 1. Not consumed.
	if !pgLoginOnce(t, ln, token) {
		t.Fatal("session token login #1 failed")
	}
	if !pgLoginOnce(t, ln, token) {
		t.Fatal("session token login #2 failed — token must not be consumed")
	}
	alive, err := vs.TokenAlive(context.Background(), token)
	if err != nil || !alive {
		t.Fatalf("TokenAlive after 2 logins = %v %v, want true", alive, err)
	}

	// 2. IP lock.
	foreign := sessionTokenFor(t, vs, fmt.Sprintf("pg-ip-%d", time.Now().UnixNano()), "postgres", "5433")
	if err := vs.SetToken(context.Background(), foreign, models.TokenPayload{
		Username: "alice", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "5433",
		DBType: "postgres", SessionID: "sid-" + foreign[len("sess_"):],
		Mode: "session", IP: "192.0.2.1", IssuedAt: time.Now().Unix(),
	}, time.Hour); err != nil {
		t.Fatalf("SetToken(foreign): %v", err)
	}
	if pgLoginOnce(t, ln, foreign) {
		t.Fatal("wrong-IP login SUCCEEDED — session tokens are IP-locked")
	}

	// 3. Live revocation: hold a PG session open, delete the key.
	front, conn := pgDialDBRaw(t, ln, token, false, "appdb")
	// Consume the startup exchange until ReadyForQuery.
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("pg hold auth: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
		if _, isErr := msg.(*pgproto3.ErrorResponse); isErr {
			t.Fatal("pg hold login failed")
		}
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // unblock the read below
	sweepCtx, sweepCancel := context.WithCancel(context.Background())
	defer sweepCancel()
	go RunSessionSweeper(sweepCtx, slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionPolicy{Poll: 300 * time.Millisecond}, p)
	if err := vs.DeleteToken(context.Background(), token); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	// The proxy closes both conns — the Frontend's next read fails.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("pg: session still alive after revocation")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("pg: session survived 5s after revocation")
	}
}

// TestLiveIdleAppliesToSingleUse (Task 9.13 round-2): the configured idle
// default now sweeps EVERY token mode — a single-use session (whose token
// key is consumed at login, so no liveness check applies) is still closed
// after session.idle_seconds of silence.
func TestLiveIdleAppliesToSingleUse(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-idle-su-%d", time.Now().UnixNano())
	token := mssqlLiveToken(t, vs, username, "mssql") // single-use: no mode, no ip

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyLoopP(t, vs, &logBuf, nil)
	c := holdToken(t, token, ln)

	idleCtx, idleCancel := context.WithCancel(context.Background())
	defer idleCancel()
	go RunSessionSweeper(idleCtx, slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionPolicy{Idle: time.Second, Poll: 300 * time.Millisecond}, p)
	assertSessionClosesSoon(t, "single-use idle", c.conn)
}

// TestLiveIdlePerTokenOverride (Task 9.13 round-2): a token minted with
// idle_seconds=1 is closed after ~1s of silence even when the data plane's
// default idle is OFF — the per-token override wins.
func TestLiveIdlePerTokenOverride(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-idle-ovr-%d", time.Now().UnixNano())
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: username, DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "1434", DBType: "mssql", TicketID: "T-9-13",
		SessionID: "sid-" + token[len("sess_"):],
		Mode:      "session", IP: "127.0.0.1", IssuedAt: time.Now().Unix(),
		IdleSeconds: 1}
	if err := vs.SetToken(context.Background(), token, tok, time.Hour); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), tok.SessionID) })

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyLoopP(t, vs, &logBuf, nil)
	c := holdToken(t, token, ln)

	// Policy idle OFF — only the token's own override can close this.
	idleCtx, idleCancel := context.WithCancel(context.Background())
	defer idleCancel()
	go RunSessionSweeper(idleCtx, slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionPolicy{Poll: 300 * time.Millisecond}, p)
	assertSessionClosesSoon(t, "per-token idle override", c.conn)
}
