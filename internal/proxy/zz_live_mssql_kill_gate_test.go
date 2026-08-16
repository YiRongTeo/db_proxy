package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 9.4 LIVE tests: kill + write-gating on the TDS plane -------------
//
// The "zz" file prefix is deliberate (same convention as the other live
// files): these tests open real proxy sessions against the live backend
// (Valkey :6379, mssql-test :1434), so they run LAST in the proxy package
// binary. They require the live environment; proxyTestStore fails fast when
// Valkey is down.

// startMSSQLTestProxyP runs the multi-session proxy loop (like the
// Dispatcher) with BOTH backend credential entries (ro_user + rw_user —
// the gating tests need write access) and returns the listener PLUS the
// proxy, so tests can reach the kill registry and the gate window.
func startMSSQLTestProxyP(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, gateWaitSeconds int) (net.Listener, *MSSQLProxy) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewMSSQLProxy(logger, vs, &ConfigCredResolver{
		Creds: map[string]string{
			"mssql:ro_user@127.0.0.1:1434": "ro_pw",
			"mssql:rw_user@127.0.0.1:1434": "rw_pw",
		},
	}, nil)
	p.SetGateWaitSeconds(gateWaitSeconds)
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

// mssqlRwLiveToken mints a write-access token for the live backend
// (rw_user) and registers the sess:live cleanup, mirroring mssqlLiveToken.
func mssqlRwLiveToken(t *testing.T, vs *store.ValkeyStore, username string) string {
	t.Helper()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: username, DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "1434", DBType: "mssql", TicketID: "T-9-4",
		Access: "write", SessionID: "sid-" + token[len("sess_"):]}
	if err := vs.SetToken(context.Background(), token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), tok.SessionID) })
	return token
}

// mssqlMarker returns a unique (id, name) pair for a demo_items row.
func mssqlMarker() (int, string) {
	n := time.Now().UnixNano()
	return int(300000 + n%100000), fmt.Sprintf("g9.4-%d", n)
}

// captureMSSQLResponse feeds a full backend response payload into a fresh
// mssqlResultCapture (the same state machine the relay uses) and returns
// it — the tests assert on the captured status/rows.
func captureMSSQLResponse(payload []byte) *mssqlResultCapture {
	c := &mssqlResultCapture{}
	c.feed(payload, true)
	return c
}

// cleanupMSSQLRow deletes a marker row DIRECTLY from the live backend
// (rw_user, plaintext TDS) at test end — the belt-and-braces counterpart of
// the in-test DELETE. Best-effort: failures are logged, never fatal.
func cleanupMSSQLRow(t *testing.T, marker string) {
	t.Helper()
	t.Cleanup(func() {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:1434", 5*time.Second)
		if err != nil {
			t.Logf("cleanup: dial mssql backend: %v", err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		br := bufio.NewReader(conn)
		if err := writeTDSPacket(conn, tdsPrelogin, buildPrelogin(encryptNotSup)); err != nil {
			t.Logf("cleanup: prelogin: %v", err)
			return
		}
		if typ, _, err := readTDSMessage(br); err != nil || (typ != tdsPrelogin && typ != tdsTabular) {
			t.Logf("cleanup: prelogin response: %v", err)
			return
		}
		login := buildLogin7("zt-cleanup", "rw_user", "CLEANUP", "127.0.0.1", "appdb", obfuscatePassword("rw_pw"))
		if err := writeTDSPacket(conn, tdsLogin7, login); err != nil {
			t.Logf("cleanup: login7: %v", err)
			return
		}
		loginOK := false
		for i := 0; i < 8; i++ {
			typ, payload, err := readTDSMessage(br)
			if err != nil {
				return
			}
			if typ != tdsTabular {
				return
			}
			done, ok, _ := scanLoginResponse(payload)
			loginOK = loginOK || ok
			if done {
				break
			}
		}
		if !loginOK {
			t.Logf("cleanup: backend login failed")
			return
		}
		del := append(append([]byte(nil), allHeaders22...), utf16le("DELETE FROM demo_items WHERE name = '"+marker+"'")...)
		if err := writeTDSPacket(conn, tdsSQLBatch, del); err != nil {
			t.Logf("cleanup: delete batch: %v", err)
		}
	})
}

// TestMSSQLLiveKillQueryAbortsAndSessionSurvives is the Task 9.4 kill-query
// money shot: a real sqlcmd-style batch (WAITFOR DELAY '00:00:30' — a
// genuinely in-flight, attention-cancellable command) is aborted by the
// ATTENTION packet written on the LIVE backend conn. The client receives an
// ERROR/DONE_ERROR response for the batch, the audit event publishes as
// status=error, and the SAME session runs SELECT 1 afterwards — the session
// survives. An idle kill-query is refused.
func TestMSSQLLiveKillQueryAbortsAndSessionSurvives(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-kq-%d", time.Now().UnixNano())
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	token := mssqlLiveToken(t, vs, username, "mssql")

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyP(t, vs, &logBuf, 0)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x, want ENCRYPT_NOT_SUP", enc)
	}
	if _, done, ok := c.login(token, "appdb"); !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v", done, ok)
	}
	sid := recvSessionEvent(t, out).SessionID
	cleanupLiveRecord(t, vs, sid)

	// Sanity: the session round-trips before the kill.
	resp := c.sendBatchAllHeaders("SELECT 1")
	if cap1 := captureMSSQLResponse(resp); cap1.status != "ok" || len(cap1.rows) != 1 {
		t.Fatalf("sanity SELECT 1: status=%q rows=%d", cap1.status, len(cap1.rows))
	}
	recvQueryEvent(t, out) // drain the SELECT 1 event

	// The long, genuinely in-flight command — the kill victim. The client
	// blocks reading until the backend answers (abort) or the delay ends.
	respCh := make(chan []byte, 1)
	go func() { respCh <- c.sendBatchAllHeaders("WAITFOR DELAY '00:00:30'") }()
	time.Sleep(1500 * time.Millisecond) // let the batch reach the backend and start sleeping

	if !p.KillQuery(sid) {
		t.Fatal("KillQuery on the in-flight session returned false")
	}
	var aborted []byte
	select {
	case aborted = <-respCh:
	case <-time.After(10 * time.Second):
		t.Fatal("WAITFOR batch was not aborted within 10s of the attention")
	}
	if !mssqlResponseError(aborted) {
		t.Fatalf("aborted batch response carries no ERROR/DONE_ERROR: % x", aborted)
	}

	// Audit: the aborted query publishes as status=error.
	ev := recvQueryEvent(t, out)
	if !strings.Contains(ev.SQL, "WAITFOR") || ev.Status != "error" {
		t.Errorf("aborted event = sql %q status %q, want WAITFOR/error", ev.SQL, ev.Status)
	}
	if !strings.Contains(logBuf.String(), `"query killed"`) {
		t.Errorf("no 'query killed' log line: %s", logBuf.String())
	}

	// THE SAME SESSION SURVIVES: the next command round-trips normally.
	resp = c.sendBatchAllHeaders("SELECT 1")
	if cap2 := captureMSSQLResponse(resp); cap2.status != "ok" || len(cap2.rows) != 1 {
		t.Fatalf("SELECT 1 after kill-query: status=%q rows=%d — session did not survive", cap2.status, len(cap2.rows))
	}
	// Drain the SELECT 1 event BEFORE the idle check: its publish (which
	// clears the session's pending slot) runs in the relay goroutine a
	// beat after the client read completes — without the drain, the idle
	// KillQuery assertion below races the publish and intermittently sees
	// the still-pending slot (flake observed in the 2026-08-17 full suite).
	recvQueryEvent(t, out)

	// Now idle (the abort completed and cleared the pending slot): a second
	// kill-query is refused — nothing in flight to cancel.
	if p.KillQuery(sid) {
		t.Error("KillQuery on the now-idle session returned true")
	}
	c.close()
}

// TestMSSQLLiveKillConnection is the Task 9.4 kill-connection money shot:
// the registry closer force-closes both conns — the client's next read
// fails, the session unregisters, and the ended lifecycle event fires.
func TestMSSQLLiveKillConnection(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-kc-%d", time.Now().UnixNano())
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	token := mssqlLiveToken(t, vs, username, "mssql")

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyP(t, vs, &logBuf, 0)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x", enc)
	}
	if _, done, ok := c.login(token, "appdb"); !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v", done, ok)
	}
	sid := recvSessionEvent(t, out).SessionID
	cleanupLiveRecord(t, vs, sid)
	resp := c.sendBatchAllHeaders("SELECT 1")
	if cap1 := captureMSSQLResponse(resp); cap1.status != "ok" {
		t.Fatalf("sanity SELECT 1: status=%q", cap1.status)
	}
	recvQueryEvent(t, out)

	// Unknown id: false, session untouched.
	if p.KillSession("sid-no-such-kc") {
		t.Fatal("KillSession(unknown) returned true")
	}

	if !p.KillSession(sid) {
		t.Fatal("KillSession on the live session returned false")
	}
	// The CLIENT conn is closed: the next read fails immediately.
	_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := readTDSMessage(c.br); err == nil {
		t.Fatal("client read succeeded after kill-connection — conn not closed")
	}
	// handleConn unwinds: the registry entry goes away and the ended
	// lifecycle event fires (sess:live cleanup via finishSession).
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		_, present := p.sessions[sid]
		p.mu.Unlock()
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session still registered 5s after kill-connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
	recvEventKind(t, out, "ended")
}

// TestMSSQLLiveKillIsolation: a bystander session is unaffected by BOTH
// kill modes. While A's WAITFOR is in flight, B round-trips normally; the
// kill-query on A aborts only A; then the kill-connection on B closes only
// B — A keeps working afterwards.
func TestMSSQLLiveKillIsolation(t *testing.T) {
	vs := proxyTestStore(t)
	base := fmt.Sprintf("mssql-iso-%d", time.Now().UnixNano())
	userA, userB := base+"-a", base+"-b"
	tokenA := mssqlLiveToken(t, vs, userA, "mssql")
	tokenB := mssqlLiveToken(t, vs, userB, "mssql")
	chA, cancelA := subscribeEvents(t, vs, userA)
	defer cancelA()
	chB, cancelB := subscribeEvents(t, vs, userB)
	defer cancelB()

	var logBuf bytes.Buffer
	ln, p := startMSSQLTestProxyP(t, vs, &logBuf, 0)

	connect := func(token string, ch <-chan []byte) (*tdsTestClient, string) {
		t.Helper()
		c := dialTDS(t, ln.Addr().String())
		if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
			t.Fatalf("prelogin encryption = %#x", enc)
		}
		if _, done, ok := c.login(token, "appdb"); !done || !ok {
			t.Fatalf("login failed: done=%v ok=%v", done, ok)
		}
		sid := recvSessionEvent(t, ch).SessionID
		cleanupLiveRecord(t, vs, sid)
		return c, sid
	}
	cA, sidA := connect(tokenA, chA)
	cB, sidB := connect(tokenB, chB)

	// A goes in-flight; while A sleeps, B round-trips — A's in-flight
	// state does not touch B.
	respCh := make(chan []byte, 1)
	go func() { respCh <- cA.sendBatchAllHeaders("WAITFOR DELAY '00:00:30'") }()
	time.Sleep(1200 * time.Millisecond)
	resp := cB.sendBatchAllHeaders("SELECT 1")
	if capB := captureMSSQLResponse(resp); capB.status != "ok" || len(capB.rows) != 1 {
		t.Fatalf("bystander B SELECT 1 mid-A-wait: status=%q rows=%d", capB.status, len(capB.rows))
	}
	recvQueryEvent(t, chB)

	// Kill-query on A: only A aborts.
	if !p.KillQuery(sidA) {
		t.Fatal("KillQuery(A) returned false")
	}
	select {
	case aborted := <-respCh:
		if !mssqlResponseError(aborted) {
			t.Fatalf("A's aborted response carries no ERROR/DONE_ERROR: % x", aborted)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("A's WAITFOR was not aborted within 10s")
	}
	recvQueryEvent(t, chA) // A's abort audit event
	resp = cA.sendBatchAllHeaders("SELECT 1")
	if capA := captureMSSQLResponse(resp); capA.status != "ok" || len(capA.rows) != 1 {
		t.Fatalf("A SELECT 1 after its own kill-query: status=%q rows=%d", capA.status, len(capA.rows))
	}
	recvQueryEvent(t, chA)

	// Kill-connection on B: only B dies — A keeps working.
	if !p.KillSession(sidB) {
		t.Fatal("KillSession(B) returned false")
	}
	_ = cB.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := readTDSMessage(cB.br); err == nil {
		t.Fatal("B's client read succeeded after its kill-connection — conn not closed")
	}
	recvEventKind(t, chB, "ended")
	resp = cA.sendBatchAllHeaders("SELECT 42")
	if capA := captureMSSQLResponse(resp); capA.status != "ok" || len(capA.rows) != 1 {
		t.Fatalf("A SELECT 42 after B's kill-connection: status=%q rows=%d", capA.status, len(capA.rows))
	}
	cA.close()
}

// TestMSSQLLiveWriteGateBlocksUnwatched (Task 9.4 gating, case a): a
// write-access session with NO watcher gets its INSERT blocked with the
// sqlcmd-readable 18456 ERROR token ("maker gating: no checker connected to
// session <sid>"), the audit event publishes as status=error with
// stmt_type=insert, and the row does NOT land (verified through a
// read-access session, which is gate-exempt).
func TestMSSQLLiveWriteGateBlocksUnwatched(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-gate-block-%d", time.Now().UnixNano())
	roUser := username + "-ro"
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	rwToken := mssqlRwLiveToken(t, vs, username)
	roToken := mssqlLiveToken(t, vs, roUser, "mssql")
	id, marker := mssqlMarker()
	cleanupMSSQLRow(t, marker)

	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxyP(t, vs, &logBuf, 0)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x", enc)
	}
	if _, done, ok := c.login(rwToken, "appdb"); !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v", done, ok)
	}
	sid := recvSessionEvent(t, out).SessionID
	cleanupLiveRecord(t, vs, sid)

	// No watcher: the INSERT is blocked — sqlcmd-readable ERROR token.
	insert := fmt.Sprintf("INSERT INTO demo_items (id, name) VALUES (%d, '%s')", id, marker)
	resp := c.sendBatchAllHeaders(insert)
	if !mssqlResponseError(resp) {
		t.Fatalf("unwatched INSERT response has no ERROR/DONE_ERROR: % x", resp)
	}
	if msg := extractErrorMsg(resp); !strings.Contains(msg, "maker gating: no checker connected to session "+sid) {
		t.Errorf("gate error message = %q, want the gating message naming the session", msg)
	}

	// Audit: status=error + gating message + stmt_type.
	ev := recvQueryEvent(t, out)
	if ev.Status != "error" || ev.StmtType != "insert" || !strings.Contains(ev.Error, "maker gating") {
		t.Errorf("blocked event = status %q stmt_type %q error %q, want error/insert/gating message",
			ev.Status, ev.StmtType, ev.Error)
	}
	if !strings.Contains(ev.SQL, marker) {
		t.Errorf("blocked event SQL = %q, want the marker INSERT", ev.SQL)
	}

	// Row absent — verified through a read-access session (gate exempt).
	// The ro session's lifecycle/query events publish to queries:<roUser>
	// (its own channel — no cross-talk), so subscribe to that channel.
	roOut, roCancel := subscribeEvents(t, vs, roUser)
	defer roCancel()
	ro := dialTDS(t, ln.Addr().String())
	if enc := ro.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("ro prelogin encryption = %#x", enc)
	}
	if _, done, ok := ro.login(roToken, "appdb"); !done || !ok {
		t.Fatalf("ro login failed: done=%v ok=%v", done, ok)
	}
	roSid := recvSessionEvent(t, roOut).SessionID
	cleanupLiveRecord(t, vs, roSid)
	sel := "SELECT name FROM demo_items WHERE name = '" + marker + "'"
	if capRo := captureMSSQLResponse(ro.sendBatchAllHeaders(sel)); len(capRo.rows) != 0 {
		t.Fatalf("blocked INSERT landed: %d row(s) for %s", len(capRo.rows), marker)
	}
	ro.close()
	c.close()
}

// TestMSSQLLiveWriteGateWatcherPass (Task 9.4 gating, case b): with
// watch:<sid> present (what the checker hub maintains), the write session's
// INSERT passes and the row actually lands.
func TestMSSQLLiveWriteGateWatcherPass(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	username := fmt.Sprintf("mssql-gate-pass-%d", time.Now().UnixNano())
	roUser := username + "-ro"
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	rwToken := mssqlRwLiveToken(t, vs, username)
	roToken := mssqlLiveToken(t, vs, roUser, "mssql")
	id, marker := mssqlMarker()
	cleanupMSSQLRow(t, marker)

	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxyP(t, vs, &logBuf, 0)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x", enc)
	}
	if _, done, ok := c.login(rwToken, "appdb"); !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v", done, ok)
	}
	sid := recvSessionEvent(t, out).SessionID
	cleanupLiveRecord(t, vs, sid)
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(ctx, sid) })

	insert := fmt.Sprintf("INSERT INTO demo_items (id, name) VALUES (%d, '%s')", id, marker)
	resp := c.sendBatchAllHeaders(insert)
	if mssqlResponseError(resp) {
		t.Fatalf("watched INSERT response carries an error: % x", resp)
	}
	ev := recvQueryEvent(t, out)
	if ev.Status != "ok" || ev.StmtType != "insert" {
		t.Errorf("watched INSERT event = status %q stmt_type %q, want ok/insert", ev.Status, ev.StmtType)
	}

	// The row actually landed (watcher enabled the write).
	roOut, roCancel := subscribeEvents(t, vs, roUser)
	defer roCancel()
	ro := dialTDS(t, ln.Addr().String())
	if enc := ro.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("ro prelogin encryption = %#x", enc)
	}
	if _, done, ok := ro.login(roToken, "appdb"); !done || !ok {
		t.Fatalf("ro login failed: done=%v ok=%v", done, ok)
	}
	roSid := recvSessionEvent(t, roOut).SessionID
	cleanupLiveRecord(t, vs, roSid)
	sel := "SELECT name FROM demo_items WHERE name = '" + marker + "'"
	capRo := captureMSSQLResponse(ro.sendBatchAllHeaders(sel))
	if len(capRo.rows) != 1 || capRo.rows[0][0] != marker {
		t.Fatalf("watched INSERT did not land: rows=%v, want [%q]", capRo.rows, marker)
	}
	ro.close()

	// Cleanup the marker through the watched session (allowed) — and prove
	// the DELETE also passes the gate.
	del := "DELETE FROM demo_items WHERE name = '" + marker + "'"
	if resp := c.sendBatchAllHeaders(del); mssqlResponseError(resp) {
		t.Fatalf("watched DELETE response carries an error: % x", resp)
	}
	c.close()
}

// TestMSSQLLiveWriteGateReadOnlyExempt (Task 9.4 gating, case c): a
// read-access token with NO watcher queries normally — the gate applies
// ONLY to write-access sessions.
func TestMSSQLLiveWriteGateReadOnlyExempt(t *testing.T) {
	vs := proxyTestStore(t)
	username := fmt.Sprintf("mssql-gate-ro-%d", time.Now().UnixNano())
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	token := mssqlLiveToken(t, vs, username, "mssql") // Access absent = read

	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxyP(t, vs, &logBuf, 0)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x", enc)
	}
	if _, done, ok := c.login(token, "appdb"); !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v", done, ok)
	}
	sid := recvSessionEvent(t, out).SessionID
	cleanupLiveRecord(t, vs, sid)

	// No watcher, read access: the SELECT runs and returns rows.
	cap := captureMSSQLResponse(c.sendBatchAllHeaders("SELECT name FROM demo_items"))
	if cap.status != "ok" || len(cap.rows) == 0 {
		t.Fatalf("read-access no-watcher SELECT: status=%q rows=%d, want ok with rows", cap.status, len(cap.rows))
	}
	ev := recvQueryEvent(t, out)
	if ev.Status != "ok" {
		t.Errorf("read-only no-watcher SELECT event status = %q, want ok", ev.Status)
	}
	c.close()
}

// TestMSSQLLiveWriteGateGraceHoldRunsAfterWatcher (Task 9.4 gating, case d
// — maker-first with the grace window): the maker's INSERT arrives BEFORE
// any watcher; with gate_wait_seconds=5 it is HELD (no reply yet, verified
// with a short read deadline), then a checker attaches within the window →
// the held INSERT flushes and runs, the client gets the real backend
// response, and the row lands.
func TestMSSQLLiveWriteGateGraceHoldRunsAfterWatcher(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	username := fmt.Sprintf("mssql-gate-hold-%d", time.Now().UnixNano())
	roUser := username + "-ro"
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	rwToken := mssqlRwLiveToken(t, vs, username)
	roToken := mssqlLiveToken(t, vs, roUser, "mssql")
	id, marker := mssqlMarker()
	cleanupMSSQLRow(t, marker)

	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxyP(t, vs, &logBuf, 5)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x", enc)
	}
	if _, done, ok := c.login(rwToken, "appdb"); !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v", done, ok)
	}
	sid := recvSessionEvent(t, out).SessionID
	cleanupLiveRecord(t, vs, sid)

	// Maker-first: the INSERT arrives with NO watcher — held, no reply yet.
	insert := fmt.Sprintf("INSERT INTO demo_items (id, name) VALUES (%d, '%s')", id, marker)
	payload := append(append([]byte(nil), allHeaders22...), utf16le(insert)...)
	if err := writeTDSPacket(c.conn, tdsSQLBatch, payload); err != nil {
		t.Fatalf("write INSERT: %v", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if _, _, err := readTDSMessage(c.br); err == nil {
		t.Fatal("held INSERT answered early")
	}
	_ = c.conn.SetReadDeadline(time.Time{})

	// Checker attaches WITHIN the window → the held query runs and returns
	// the real backend response (no gate error).
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(ctx, sid) })
	typ, resp, err := readTDSMessage(c.br)
	if err != nil || typ != tdsTabular {
		t.Fatalf("held INSERT response: typ=%#x err=%v", typ, err)
	}
	if mssqlResponseError(resp) {
		t.Fatalf("held-then-run INSERT response carries an error: % x", resp)
	}
	ev := recvQueryEvent(t, out)
	if ev.Status != "ok" || ev.StmtType != "insert" {
		t.Errorf("held-then-run INSERT event = status %q stmt_type %q, want ok/insert", ev.Status, ev.StmtType)
	}

	// The row actually landed.
	roOut, roCancel := subscribeEvents(t, vs, roUser)
	defer roCancel()
	ro := dialTDS(t, ln.Addr().String())
	if enc := ro.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("ro prelogin encryption = %#x", enc)
	}
	if _, done, ok := ro.login(roToken, "appdb"); !done || !ok {
		t.Fatalf("ro login failed: done=%v ok=%v", done, ok)
	}
	roSid := recvSessionEvent(t, roOut).SessionID
	cleanupLiveRecord(t, vs, roSid)
	capRo := captureMSSQLResponse(ro.sendBatchAllHeaders("SELECT name FROM demo_items WHERE name = '" + marker + "'"))
	if len(capRo.rows) != 1 || capRo.rows[0][0] != marker {
		t.Fatalf("held-then-run INSERT did not land: rows=%v, want [%q]", capRo.rows, marker)
	}
	ro.close()

	// Cleanup the marker (watcher still present → allowed).
	del := "DELETE FROM demo_items WHERE name = '" + marker + "'"
	if resp := c.sendBatchAllHeaders(del); mssqlResponseError(resp) {
		t.Fatalf("watched DELETE response carries an error: % x", resp)
	}
	c.close()
}

// TestMSSQLLiveWriteGateGraceHoldTimeoutThenReopens (Task 9.4 gating, case
// e + Task 8.17 no-latch): no watcher within the window → the held INSERT
// is drained with the sqlcmd-readable timeout ERROR ("no checker connected
// within 2s") + audit event, and the row does NOT land. The drain does NOT
// latch: a watcher attaching LATER re-opens the gate — the next INSERT
// runs and the row lands.
func TestMSSQLLiveWriteGateGraceHoldTimeoutThenReopens(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	username := fmt.Sprintf("mssql-gate-tout-%d", time.Now().UnixNano())
	roUser := username + "-ro"
	out, cancel := subscribeEvents(t, vs, username)
	defer cancel()
	rwToken := mssqlRwLiveToken(t, vs, username)
	roToken := mssqlLiveToken(t, vs, roUser, "mssql")
	// ro2 needs its OWN single-use token — the first ro login already
	// consumed roToken (GETDEL).
	ro2Token := mssqlLiveToken(t, vs, roUser, "mssql")
	id1, marker1 := mssqlMarker()
	id2, marker2 := mssqlMarker()
	cleanupMSSQLRow(t, marker1)
	cleanupMSSQLRow(t, marker2)

	var logBuf bytes.Buffer
	ln, _ := startMSSQLTestProxyP(t, vs, &logBuf, 2)

	c := dialTDS(t, ln.Addr().String())
	if enc := c.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("prelogin encryption = %#x", enc)
	}
	if _, done, ok := c.login(rwToken, "appdb"); !done || !ok {
		t.Fatalf("login failed: done=%v ok=%v", done, ok)
	}
	sid := recvSessionEvent(t, out).SessionID
	cleanupLiveRecord(t, vs, sid)

	// No watcher: the held INSERT drains when the 2s window expires — an
	// sqlcmd-readable ERROR naming the window.
	insert1 := fmt.Sprintf("INSERT INTO demo_items (id, name) VALUES (%d, '%s')", id1, marker1)
	resp := c.sendBatchAllHeaders(insert1)
	if !mssqlResponseError(resp) {
		t.Fatalf("timeout-drained INSERT response has no ERROR/DONE_ERROR: % x", resp)
	}
	if msg := extractErrorMsg(resp); !strings.Contains(msg, "no checker connected within 2s") {
		t.Errorf("timeout ERROR message = %q, want it to name the window (2s)", msg)
	}
	ev := recvQueryEvent(t, out)
	if ev.Status != "error" || ev.StmtType != "insert" || !strings.Contains(ev.Error, "no checker connected within 2s") {
		t.Errorf("drained event = status %q stmt_type %q error %q, want error/insert/timeout message",
			ev.Status, ev.StmtType, ev.Error)
	}

	// Row absent after the drain.
	roOut, roCancel := subscribeEvents(t, vs, roUser)
	defer roCancel()
	ro := dialTDS(t, ln.Addr().String())
	if enc := ro.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("ro prelogin encryption = %#x", enc)
	}
	if _, done, ok := ro.login(roToken, "appdb"); !done || !ok {
		t.Fatalf("ro login failed: done=%v ok=%v", done, ok)
	}
	roSid := recvSessionEvent(t, roOut).SessionID
	cleanupLiveRecord(t, vs, roSid)
	capRo := captureMSSQLResponse(ro.sendBatchAllHeaders("SELECT name FROM demo_items WHERE name = '" + marker1 + "'"))
	if len(capRo.rows) != 0 {
		t.Fatalf("drained INSERT landed: %d row(s) for %s", len(capRo.rows), marker1)
	}
	ro.close()

	// Task 8.17: the drain did NOT latch. A watcher attaching AFTER the
	// drain re-opens the gate — the same session's next INSERT runs.
	if err := vs.SetWatchConn(ctx, sid, "test-conn", time.Minute); err != nil {
		t.Fatalf("SetWatch: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(ctx, sid) })
	insert2 := fmt.Sprintf("INSERT INTO demo_items (id, name) VALUES (%d, '%s')", id2, marker2)
	if resp := c.sendBatchAllHeaders(insert2); mssqlResponseError(resp) {
		t.Fatalf("post-reopen INSERT response carries an error: % x", resp)
	}
	ev2 := recvQueryEvent(t, out)
	if ev2.Status != "ok" || ev2.StmtType != "insert" {
		t.Errorf("post-reopen INSERT event = status %q stmt_type %q, want ok/insert", ev2.Status, ev2.StmtType)
	}
	ro2Out, ro2Cancel := subscribeEvents(t, vs, roUser)
	defer ro2Cancel()
	ro2 := dialTDS(t, ln.Addr().String())
	if enc := ro2.prelogin(encryptNotSup); enc != encryptNotSup {
		t.Fatalf("ro prelogin encryption = %#x", enc)
	}
	if _, done, ok := ro2.login(ro2Token, "appdb"); !done || !ok {
		t.Fatalf("ro login failed: done=%v ok=%v", done, ok)
	}
	ro2Sid := recvSessionEvent(t, ro2Out).SessionID
	cleanupLiveRecord(t, vs, ro2Sid)
	capRo2 := captureMSSQLResponse(ro2.sendBatchAllHeaders("SELECT name FROM demo_items WHERE name = '" + marker2 + "'"))
	if len(capRo2.rows) != 1 || capRo2.rows[0][0] != marker2 {
		t.Fatalf("post-reopen INSERT did not land: rows=%v, want [%q]", capRo2.rows, marker2)
	}
	ro2.close()

	// Cleanup the marker (watcher present → allowed).
	del := "DELETE FROM demo_items WHERE name = '" + marker2 + "'"
	if resp := c.sendBatchAllHeaders(del); mssqlResponseError(resp) {
		t.Fatalf("watched DELETE response carries an error: % x", resp)
	}
	c.close()
}
