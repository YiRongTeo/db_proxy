package proxy

import (
	"bufio"
	"bytes"
	"context"
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
	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// pgLiveCreds point the backend connect at the real pg-test container
// (Task 0.4: host port 5433, ro_user/ro_pw with SELECT on demo_items).
var pgLiveCreds = map[string]string{"postgres:ro_user@127.0.0.1:5433": "ro_pw"}

// startTestPGProxyWithCreds is startTestPGProxy with a caller-supplied
// credential map (used by relay tests that connect to the live backend).
func startTestPGProxyWithCreds(t *testing.T, vs *store.ValkeyStore, logBuf *bytes.Buffer, creds map[string]string, n int) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	p := NewPGProxy(logger, vs, &ConfigCredResolver{Creds: creds}, nil)
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

// pgLiveToken registers a token bound to the LIVE pg-test backend with a
// ticket id, so relay/sniffing tests exercise the full session path (real
// backend connect + both publish channels).
func pgLiveToken(t *testing.T, vs *store.ValkeyStore) string {
	t.Helper()
	token := fmt.Sprintf("pglive_%d", time.Now().UnixNano())
	err := vs.SetToken(context.Background(), token, models.TokenPayload{
		Username: "alice",
		DBUser:   "ro_user",
		DBIP:     "127.0.0.1",
		DBPort:   "5433",
		DBType:   "postgres",
		TicketID: "T-4-3",
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	return token
}

// pgDialDB is pgDial with an explicit database in the StartupMessage; an
// empty db omits the parameter entirely (the proxy falls back to its default).
func pgDialDB(t *testing.T, ln net.Listener, token string, sslFirst bool, db string) *pgproto3.Frontend {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // no hanging tests
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
	params := map[string]string{"user": token}
	if db != "" {
		params["database"] = db
	}
	if err := front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      params,
	}); err != nil {
		t.Fatalf("send StartupMessage: %v", err)
	}
	return front
}

// pgExecResult summarizes one Simple Query response. Values are COPIED out
// of the pgproto3 messages (their buffers are reused on the next Receive).
type pgExecResult struct {
	fields []string
	rows   [][]string
	tag    string
	ready  bool
}

// pgExecQuery sends a Simple Query and consumes the response until
// ReadyForQuery. A backend ErrorResponse fails the test.
func pgExecQuery(t *testing.T, front *pgproto3.Frontend, sql string) pgExecResult {
	t.Helper()
	if err := front.Send(&pgproto3.Query{String: sql}); err != nil {
		t.Fatalf("send query %q: %v", sql, err)
	}
	var res pgExecResult
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive response for %q: %v", sql, err)
		}
		switch m := msg.(type) {
		case *pgproto3.RowDescription:
			for _, f := range m.Fields {
				res.fields = append(res.fields, string(f.Name))
			}
		case *pgproto3.DataRow:
			row := make([]string, len(m.Values))
			for i, v := range m.Values {
				row[i] = string(v)
			}
			res.rows = append(res.rows, row)
		case *pgproto3.CommandComplete:
			res.tag = string(m.CommandTag)
		case *pgproto3.ReadyForQuery:
			res.ready = true
			return res
		case *pgproto3.ErrorResponse:
			t.Fatalf("backend error for %q: %s (%s)", sql, m.Message, m.Code)
		}
	}
}

// pgDrainUntilReady consumes backend messages until ReadyForQuery (used for
// extended-protocol exchanges where the result shape is not asserted).
func pgDrainUntilReady(t *testing.T, front *pgproto3.Frontend) {
	t.Helper()
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return
		}
	}
}

// subscribePG opens a Valkey Pub/Sub subscription and blocks until the
// subscription is confirmed; the returned channel receives raw event JSON.
func subscribePG(t *testing.T, vs *store.ValkeyStore, channel string) <-chan []byte {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan []byte, 16)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, channel, false, out)
	waitSubAck(t, acked)
	return out
}

// --- live relay + sniffing through the real pg-test backend ----------------

// TestPGProxyLiveRelaySession runs a FULL session through the proxy against
// the live pg-test container: token auth → backend connect → ReadyForQuery →
// Simple Query 'SELECT id, name FROM demo_items ORDER BY id' → RowDescription
// (id, name) + 3 DataRows (alpha/bravo/charlie) + CommandComplete "SELECT 3"
// + ReadyForQuery — all relayed through the proxy. Terminate ends the session
// cleanly through the done-channel teardown.
func TestPGProxyLiveRelaySession(t *testing.T) {
	vs := proxyTestStore(t)
	logBuf := &bytes.Buffer{}
	ln, done := startTestPGProxyWithCreds(t, vs, logBuf, pgLiveCreds, 1)
	token := pgLiveToken(t, vs)

	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)

	res := pgExecQuery(t, front, "SELECT id, name FROM demo_items ORDER BY id")
	if !res.ready {
		t.Fatal("query response missing ReadyForQuery")
	}
	if len(res.fields) != 2 || res.fields[0] != "id" || res.fields[1] != "name" {
		t.Fatalf("RowDescription fields = %v, want [id name]", res.fields)
	}
	if len(res.rows) != 3 {
		t.Fatalf("got %d DataRows, want 3 (alpha/bravo/charlie): %v", len(res.rows), res.rows)
	}
	want := [][]string{{"1", "alpha"}, {"2", "bravo"}, {"3", "charlie"}}
	for i := range want {
		if len(res.rows[i]) != 2 || res.rows[i][0] != want[i][0] || res.rows[i][1] != want[i][1] {
			t.Errorf("DataRow %d = %v, want %v", i, res.rows[i], want[i])
		}
	}
	if res.tag != "SELECT 3" {
		t.Errorf("CommandComplete tag = %q, want %q", res.tag, "SELECT 3")
	}

	// Graceful end: Terminate is relayed to the backend, which closes; the
	// backend→client pipe hits EOF and tears both sides down.
	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)

	logs := logBuf.String()
	for _, want := range []string{"session established", "session closed", "alice", "ro_user"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, token) {
		t.Errorf("token value leaked into proxy log:\n%s", logs)
	}
}

// TestPGProxySniffQueryAndTicketChannel: a Simple Query through the live
// relay publishes a kind=query event carrying the SQL (sniffed BEFORE
// forwarding) to BOTH queries:<username> and queries:ticket:<ticket_id>.
// Terminate publishes nothing.
func TestPGProxySniffQueryAndTicketChannel(t *testing.T) {
	vs := proxyTestStore(t)
	userCh := subscribePG(t, vs, "queries:alice")
	ticketCh := subscribePG(t, vs, "queries:ticket:T-4-3")

	ln, done := startTestPGProxyWithCreds(t, vs, &bytes.Buffer{}, pgLiveCreds, 1)
	token := pgLiveToken(t, vs)

	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)
	pgExecQuery(t, front, "SELECT id FROM demo_items") // drains to ReadyForQuery

	// The started lifecycle event precedes the query event — recvQueryEvent
	// skips kind=session events.
	ev := recvQueryEvent(t, userCh)
	if ev.Kind != "query" || ev.SQL != "SELECT id FROM demo_items" {
		t.Errorf("user event kind=%q sql=%q, want query / SELECT id FROM demo_items", ev.Kind, ev.SQL)
	}
	if ev.Username != "alice" || ev.TicketID != "T-4-3" || ev.DBUser != "ro_user" ||
		ev.DBIP != "127.0.0.1" || ev.DBPort != "5433" || ev.DBType != "postgres" {
		t.Errorf("user event context mismatch: %+v", ev)
	}
	if !strings.HasPrefix(ev.ClientAddr, "127.0.0.1:") {
		t.Errorf("ClientAddr = %q, want 127.0.0.1:...", ev.ClientAddr)
	}
	if len(ev.ID) != 16 || ev.Ts.IsZero() {
		t.Errorf("id=%q ts=%v, want 16-hex id and non-zero ts", ev.ID, ev.Ts)
	}

	var tick models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, ticketCh), &tick); err != nil {
		t.Fatalf("unmarshal ticket-channel event: %v", err)
	}
	if tick.Kind != "query" || tick.SQL != "SELECT id FROM demo_items" || tick.TicketID != "T-4-3" {
		t.Errorf("ticket event kind=%q sql=%q ticket=%q, want query / SELECT id FROM demo_items / T-4-3", tick.Kind, tick.SQL, tick.TicketID)
	}

	// Terminate ends the session and must NOT be sniffed; the teardown
	// publishes the ended lifecycle event on the user channel (never on the
	// ticket channel).
	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
	ended := recvSessionEvent(t, userCh)
	if ended.Action != "ended" || !strings.HasPrefix(ended.SessionID, "sid-") {
		t.Errorf("ended event action/session = %q/%q, want ended/sid-...", ended.Action, ended.SessionID)
	}
	expectNoEvent(t, ticketCh)
}

// TestPGProxySniffPrepareExecute: extended-protocol Parse+Bind+Execute+Sync
// follows the Task 6.3 pending semantics (mirroring MySQL): the response
// burst arrives as ONE unit, so the later Execute REPLACES the Parse's
// pending event — the published event is the execute, carrying the cached
// SQL and the captured backend response. Phase 1 executes the unnamed
// statement (status ok, result set captured); phase 2 executes a statement
// that was closed → the backend errors and the event carries status=error
// with the server message. Nothing else is published.
func TestPGProxySniffPrepareExecute(t *testing.T) {
	vs := proxyTestStore(t)
	userCh := subscribePG(t, vs, "queries:alice")

	ln, done := startTestPGProxyWithCreds(t, vs, &bytes.Buffer{}, pgLiveCreds, 1)
	token := pgLiveToken(t, vs)

	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)

	// Phase 1: unnamed statement (libpq/psql style).
	front.Send(&pgproto3.Parse{Name: "", Query: "SELECT 1"})
	front.Send(&pgproto3.Bind{}) // unnamed statement → unnamed portal
	front.Send(&pgproto3.Execute{Portal: ""})
	front.Send(&pgproto3.Sync{})
	pgDrainUntilReady(t, front)

	// The started lifecycle event precedes it — recvQueryEvent skips it.
	ev := recvQueryEvent(t, userCh)
	if ev.Kind != "execute" || ev.SQL != "EXECUTE SELECT 1" {
		t.Errorf("execute event kind=%q sql=%q, want execute / EXECUTE SELECT 1", ev.Kind, ev.SQL)
	}
	// Extended protocol WITHOUT a Describe message sends no RowDescription,
	// so column names may be unknown; the row values are always captured.
	if ev.Status != "ok" || !reflect.DeepEqual(ev.Rows, [][]string{{"1"}}) {
		t.Errorf("execute event capture: status=%q rows=%q, want ok/[[1]]", ev.Status, ev.Rows)
	}
	if len(ev.Columns) > 1 {
		t.Errorf("execute event columns = %q, want [] or [?column?]", ev.Columns)
	}
	// The Parse's prepare event was REPLACED by the Execute (one response
	// burst, single pending slot — MySQL-mirror semantics): nothing else.
	expectNoEvent(t, userCh)

	// Phase 2: named statement, closed before use → evicted from the cache.
	front.Send(&pgproto3.Parse{Name: "s1", Query: "SELECT 2"})
	front.Send(&pgproto3.Close{ObjectType: 'S', Name: "s1"})
	front.Send(&pgproto3.Execute{Portal: "s1"}) // backend errors: portal gone
	front.Send(&pgproto3.Sync{})
	pgDrainUntilReady(t, front)

	ev = recvQueryEvent(t, userCh)
	if ev.Kind != "execute" || ev.SQL != "EXECUTE portal=s1" {
		t.Errorf("evicted execute event kind=%q sql=%q, want execute / EXECUTE portal=s1", ev.Kind, ev.SQL)
	}
	if ev.Status != "error" || !strings.Contains(ev.Error, "does not exist") {
		t.Errorf("evicted execute event status=%q error=%q, want error containing 'does not exist'", ev.Status, ev.Error)
	}
	expectNoEvent(t, userCh)

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}

// TestPGProxyForwardsClientDatabase: the database from the client's STARTUP
// message reaches the backend session — a client requesting "postgres" gets
// current_database() == "postgres", and a client omitting the database falls
// back to the default appdb. Two sessions (each needs its own single-use
// token); done closes only after both end.
func TestPGProxyForwardsClientDatabase(t *testing.T) {
	vs := proxyTestStore(t)
	ln, done := startTestPGProxyWithCreds(t, vs, &bytes.Buffer{}, pgLiveCreds, 2)

	// Session 1: client-requested database "postgres" (different from the
	// default) — proves forwarding, not the fallback.
	token1 := pgLiveToken(t, vs)
	front1 := pgDialDB(t, ln, token1, false, "postgres")
	pgReadUntilReady(t, front1)
	res1 := pgExecQuery(t, front1, "SELECT current_database()")
	if len(res1.rows) != 1 || res1.rows[0][0] != "postgres" {
		t.Errorf("current_database() = %v, want [postgres] (client db not forwarded)", res1.rows)
	}
	if err := front1.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}

	// Session 2: no database in the startup message → default fallback.
	token2 := pgLiveToken(t, vs)
	front2 := pgDialDB(t, ln, token2, false, "")
	pgReadUntilReady(t, front2)
	res2 := pgExecQuery(t, front2, "SELECT current_database()")
	if len(res2.rows) != 1 || res2.rows[0][0] != "appdb" {
		t.Errorf("current_database() = %v, want [appdb] (default fallback)", res2.rows)
	}
	if err := front2.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
}

// TestPGProxyBackendUnavailable: when the backend connect fails (no
// credentials), the session ends with FATAL 28000 'backend unavailable' after
// the welcome sequence.
func TestPGProxyBackendUnavailable(t *testing.T) {
	vs := proxyTestStore(t)
	ln, done := startTestPGProxy(t, vs, &bytes.Buffer{}, 1) // empty creds
	token := pgLiveToken(t, vs)

	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)

	er := pgReadFatalError(t, front)
	if er.Message != "backend unavailable" {
		t.Fatalf("message: got %q, want %q", er.Message, "backend unavailable")
	}
	waitPGDone(t, done)
}

// TestPGProxyCaptureLive runs a FULL session through the proxy against the
// live pg-test container and asserts the PUBLISHED QueryEvents carry the
// classified stmt type and the captured backend response: the SELECT's real
// result set (seed verified 2026-08-12: 1|alpha 2|bravo 3|charlie) with
// status ok, and a failing query with status error + server message. The
// ticket channel receives the same event.
func TestPGProxyCaptureLive(t *testing.T) {
	vs := proxyTestStore(t)
	userCh := subscribePG(t, vs, "queries:pg63user")
	ticketCh := subscribePG(t, vs, "queries:ticket:T-6-3")

	ln, done := startTestPGProxyWithCreds(t, vs, &bytes.Buffer{}, pgLiveCreds, 1)
	token := fmt.Sprintf("pglive63_%d", time.Now().UnixNano())
	if err := vs.SetToken(context.Background(), token, models.TokenPayload{
		Username: "pg63user",
		DBUser:   "ro_user",
		DBIP:     "127.0.0.1",
		DBPort:   "5433",
		DBType:   "postgres",
		TicketID: "T-6-3",
	}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)

	// SELECT with a real result set: the published event carries the stmt
	// type plus the captured columns/rows and status ok.
	sel := "SELECT id,name FROM demo_items ORDER BY id"
	pgExecQuery(t, front, sel)
	// The started lifecycle event precedes it — recvQueryEvent skips it.
	ev := recvQueryEvent(t, userCh)
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
	// Live seed verified directly in the container: 1|alpha 2|bravo 3|charlie.
	wantRows := [][]string{{"1", "alpha"}, {"2", "bravo"}, {"3", "charlie"}}
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
	if err := json.Unmarshal(recvEvent(t, ticketCh), &tev); err != nil {
		t.Fatalf("unmarshal ticket event: %v", err)
	}
	if tev.ID != ev.ID {
		t.Errorf("ticket event id %q != user event id %q", tev.ID, ev.ID)
	}

	// Failing query: status error with the server's message; no result set
	// (fresh struct — absent omitempty fields must not leak).
	if err := front.Send(&pgproto3.Query{String: "SELECT * FROM nope"}); err != nil {
		t.Fatalf("send error query: %v", err)
	}
	var errMsg string
	for {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive error response: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			errMsg = m.Message
		case *pgproto3.ReadyForQuery:
			goto drained
		}
	}
drained:
	if errMsg == "" {
		t.Fatal("expected a backend error for SELECT * FROM nope")
	}
	ev = recvQueryEvent(t, userCh)
	if ev.Kind != "query" || ev.SQL != "SELECT * FROM nope" || ev.StmtType != "select" {
		t.Errorf("error event kind/sql/stmt = %q/%q/%q, want query/SELECT * FROM nope/select",
			ev.Kind, ev.SQL, ev.StmtType)
	}
	if ev.Status != "error" || !strings.Contains(ev.Error, "does not exist") {
		t.Errorf("status/error = %q/%q, want error containing 'does not exist'", ev.Status, ev.Error)
	}
	if len(ev.Columns) != 0 || len(ev.Rows) != 0 {
		t.Errorf("error event carries stale result set: cols=%q rows=%q", ev.Columns, ev.Rows)
	}
	if ev.SessionID == "" {
		t.Error("error event missing session_id")
	}
	// The ticket channel receives the error event too (same id).
	var tevErr models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, ticketCh), &tevErr); err != nil {
		t.Fatalf("unmarshal ticket error event: %v", err)
	}
	if tevErr.ID != ev.ID || tevErr.Status != "error" {
		t.Errorf("ticket error event id/status = %q/%q, want %q/error", tevErr.ID, tevErr.Status, ev.ID)
	}
	expectNoEvent(t, userCh)
	expectNoEvent(t, ticketCh)

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
	// Teardown publishes the ended lifecycle event on the user channel only.
	ended := recvSessionEvent(t, userCh)
	if ended.Action != "ended" || ended.SessionID == "" {
		t.Errorf("ended event action/session = %q/%q, want ended/<sid>", ended.Action, ended.SessionID)
	}
	expectNoEvent(t, ticketCh)
}
