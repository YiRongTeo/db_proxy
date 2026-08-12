package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgproto3/v2"
	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
)

// --- Task 6.3: pgResultCapture state machine --------------------------------

// pgMsg frames a raw backend→client message: 1-byte type + int32 length
// (big-endian, including itself) + payload — the exact wire framing the
// relay feeds into the capture.
func pgMsg(t byte, payload []byte) []byte {
	m := make([]byte, 0, 5+len(payload))
	m = append(m, t)
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(4+len(payload)))
	m = append(m, ln[:]...)
	return append(m, payload...)
}

// pgRowDescMsg crafts a RowDescription for the given column names (fixed
// 18-byte per-field descriptor of zeros — contents irrelevant to capture).
func pgRowDescMsg(names ...string) []byte {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(len(names)))
	for _, n := range names {
		p = append(p, n...)
		p = append(p, 0) // cstring terminator
		p = append(p, make([]byte, 18)...)
	}
	return pgMsg('T', p)
}

// pgDataRowMsg crafts a DataRow; a nil cell encodes SQL NULL (len -1).
func pgDataRowMsg(cells ...[]byte) []byte {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(len(cells)))
	for _, cell := range cells {
		if cell == nil {
			var ln [4]byte
			binary.BigEndian.PutUint32(ln[:], ^uint32(0)) // -1
			p = append(p, ln[:]...)
			continue
		}
		var ln [4]byte
		binary.BigEndian.PutUint32(ln[:], uint32(len(cell)))
		p = append(p, ln[:]...)
		p = append(p, cell...)
	}
	return pgMsg('D', p)
}

func pgCmdCompleteMsg(tag string) []byte { return pgMsg('C', append([]byte(tag), 0)) }

// pgErrMsg crafts an ErrorResponse with S/C/M fields (message capped like
// the capture does).
func pgErrMsg(message string) []byte {
	p := []byte{'S'}
	p = append(p, "ERROR"...)
	p = append(p, 0, 'C')
	p = append(p, "42P01"...)
	p = append(p, 0, 'M')
	p = append(p, message...)
	p = append(p, 0, 0)
	return pgMsg('E', p)
}

func pgEmptyQueryMsg() []byte    { return pgMsg('I', nil) }
func pgReadyMsg() []byte         { return pgMsg('Z', []byte{'I'}) }
func pgParseCompleteMsg() []byte { return pgMsg('1', nil) }
func pgBindCompleteMsg() []byte  { return pgMsg('2', nil) }

func TestPGResultCaptureFullResultSet(t *testing.T) {
	c := &pgResultCapture{}
	// Extended-protocol noise before the result set is ignored.
	c.feed(pgParseCompleteMsg())
	c.feed(pgBindCompleteMsg())
	c.feed(pgRowDescMsg("id", "name"))
	if c.done() {
		t.Fatal("capture done after RowDescription")
	}
	c.feed(pgDataRowMsg([]byte("1"), []byte("alpha")))
	c.feed(pgDataRowMsg(nil, []byte("bravo"))) // NULL cell → ""
	if c.done() {
		t.Fatal("capture done before CommandComplete")
	}
	c.feed(pgCmdCompleteMsg("SELECT 2"))
	if !c.done() {
		t.Fatal("capture not done after CommandComplete")
	}
	if c.status != "ok" || c.errorMsg != "" {
		t.Errorf("status=%q error=%q, want ok/empty", c.status, c.errorMsg)
	}
	if !reflect.DeepEqual(c.columns, []string{"id", "name"}) {
		t.Errorf("columns = %q, want [id name]", c.columns)
	}
	want := [][]string{{"1", "alpha"}, {"", "bravo"}}
	if !reflect.DeepEqual(c.rows, want) {
		t.Errorf("rows = %q, want %q", c.rows, want)
	}
	if c.truncated {
		t.Error("truncated = true, want false")
	}
	// Feeding after done is a no-op (trailing ReadyForQuery etc.).
	c.feed(pgReadyMsg())
	if c.status != "ok" {
		t.Errorf("status changed after done: %q", c.status)
	}
}

func TestPGResultCaptureError(t *testing.T) {
	msg := `relation "nope" does not exist`
	c := &pgResultCapture{}
	c.feed(pgErrMsg(msg))
	if !c.done() {
		t.Fatal("capture not done after ErrorResponse")
	}
	if c.status != "error" {
		t.Errorf("status = %q, want error", c.status)
	}
	if c.errorMsg != msg {
		t.Errorf("errorMsg = %q, want %q", c.errorMsg, msg)
	}
	if len(c.columns) != 0 || len(c.rows) != 0 {
		t.Errorf("unexpected capture content: cols=%q rows=%q", c.columns, c.rows)
	}

	// Messages are capped at 300 chars.
	long := strings.Repeat("m", 400)
	c2 := &pgResultCapture{}
	c2.feed(pgErrMsg(long))
	if len(c2.errorMsg) != 300 {
		t.Errorf("errorMsg length = %d, want 300 (capped)", len(c2.errorMsg))
	}
}

func TestPGResultCaptureEmptyQuery(t *testing.T) {
	c := &pgResultCapture{}
	c.feed(pgEmptyQueryMsg())
	if !c.done() {
		t.Fatal("capture not done after EmptyQueryResponse")
	}
	if c.status != "ok" || c.errorMsg != "" {
		t.Errorf("status=%q error=%q, want ok/empty", c.status, c.errorMsg)
	}
}

// ReadyForQuery is NOT a capture terminal — the relay uses it as a safety
// publish point, so the capture machine must leave it untouched.
func TestPGResultCaptureReadyForQueryNotTerminal(t *testing.T) {
	c := &pgResultCapture{}
	c.feed(pgReadyMsg())
	if c.done() {
		t.Fatal("capture done after ReadyForQuery — must be relay-level only")
	}
	if c.status != "" {
		t.Errorf("status = %q, want empty", c.status)
	}
}

func TestPGResultCaptureRowCap(t *testing.T) {
	c := &pgResultCapture{}
	c.feed(pgRowDescMsg("id", "name"))
	for i := 0; i < 105; i++ {
		c.feed(pgDataRowMsg([]byte{byte(i)}, []byte("v")))
	}
	c.feed(pgCmdCompleteMsg("SELECT 105"))
	if !c.done() {
		t.Fatal("capture not done after CommandComplete")
	}
	if len(c.rows) != capMaxRows {
		t.Errorf("rows = %d, want capMaxRows = %d", len(c.rows), capMaxRows)
	}
	if !c.truncated {
		t.Error("truncated = false, want true (row cap exceeded)")
	}
	if c.status != "ok" {
		t.Errorf("status = %q, want ok", c.status)
	}
	if !reflect.DeepEqual(c.columns, []string{"id", "name"}) {
		t.Errorf("columns = %q, want [id name]", c.columns)
	}
}

func TestPGResultCaptureCellCap(t *testing.T) {
	long := strings.Repeat("x", 600)
	c := &pgResultCapture{}
	c.feed(pgRowDescMsg("v"))
	c.feed(pgDataRowMsg([]byte(long)))
	c.feed(pgCmdCompleteMsg("SELECT 1"))
	wantCell := strings.Repeat("x", 512) + "…"
	if !reflect.DeepEqual(c.rows, [][]string{{wantCell}}) {
		t.Errorf("rows = %q, want [<512-char cell + ellipsis>]", c.rows)
	}
	if c.truncated {
		t.Error("truncated = true, want false (per-cell truncation does not set the flag)")
	}
}

// A DataRow whose column count mismatches the captured RowDescription is
// rejected, and a second RowDescription mid-stream is ignored — captures
// must never misparse.
func TestPGResultCaptureStrayDataRowIgnored(t *testing.T) {
	c := &pgResultCapture{}
	c.feed(pgRowDescMsg("a", "b"))
	c.feed(pgDataRowMsg([]byte("1"))) // 1 cell vs 2 columns: rejected
	if len(c.rows) != 0 {
		t.Fatalf("rows = %q, want none for mismatched row", c.rows)
	}
	c.feed(pgDataRowMsg([]byte("1"), []byte("2")))
	if len(c.rows) != 1 {
		t.Fatalf("rows = %q, want 1 row", c.rows)
	}
	// A second RowDescription mid-stream is ignored (first result set wins).
	c.feed(pgRowDescMsg("x"))
	c.feed(pgDataRowMsg([]byte("9")))
	if len(c.rows) != 1 || !reflect.DeepEqual(c.columns, []string{"a", "b"}) {
		t.Errorf("after stray RowDescription: cols=%q rows=%q", c.columns, c.rows)
	}
}

// Extended protocol without a Describe message sends DataRow with NO
// preceding RowDescription: rows are captured using their own column count
// and column names stay unknown (empty).
func TestPGResultCaptureDataRowWithoutRowDescription(t *testing.T) {
	c := &pgResultCapture{}
	c.feed(pgDataRowMsg([]byte("1")))
	if len(c.rows) != 1 || !reflect.DeepEqual(c.rows, [][]string{{"1"}}) {
		t.Fatalf("rows = %q, want [[1]]", c.rows)
	}
	if len(c.columns) != 0 {
		t.Errorf("columns = %q, want empty (no RowDescription seen)", c.columns)
	}
	c.feed(pgDataRowMsg([]byte("2")))
	if len(c.rows) != 2 {
		t.Fatalf("rows = %q, want 2", c.rows)
	}
	// A RowDescription after the rows phase began is ignored.
	c.feed(pgRowDescMsg("a", "b"))
	if len(c.columns) != 0 || len(c.rows) != 2 {
		t.Errorf("after late RowDescription: cols=%q rows=%q", c.columns, c.rows)
	}
	c.feed(pgCmdCompleteMsg("SELECT 2"))
	if !c.done() || c.status != "ok" {
		t.Fatalf("capture not done/ok after CommandComplete: done=%v status=%q", c.done(), c.status)
	}
	if !reflect.DeepEqual(c.rows, [][]string{{"1"}, {"2"}}) {
		t.Errorf("rows = %q, want [[1] [2]]", c.rows)
	}
}

// Malformed frames (bad length, truncated) are ignored — capture never
// crashes the relay.
func TestPGResultCaptureMalformedFrame(t *testing.T) {
	c := &pgResultCapture{}
	c.feed([]byte{'T', 0, 0, 0, 50, 'x'}) // declared length 50, actual 5
	if c.done() || c.stage != 0 {
		t.Fatalf("malformed frame advanced the capture: stage=%d done=%v", c.stage, c.done())
	}
	c.feed([]byte{'C'}) // too short
	if c.done() {
		t.Fatal("short frame completed the capture")
	}
	// Truncated RowDescription body is ignored.
	c.feed(pgMsg('T', []byte{0, 1, 'a'})) // declares 1 field, no descriptor
	if c.stage != 0 {
		t.Fatalf("truncated RowDescription advanced the capture: stage=%d", c.stage)
	}
	// And a clean result set still works afterwards.
	c.feed(pgRowDescMsg("id"))
	c.feed(pgDataRowMsg([]byte("1")))
	c.feed(pgCmdCompleteMsg("SELECT 1"))
	if !c.done() || c.status != "ok" || len(c.rows) != 1 {
		t.Fatalf("capture broken after malformed frames: done=%v status=%q rows=%q", c.done(), c.status, c.rows)
	}
}

// --- Task 6.3: session sniff → capture → publish pipeline -------------------

// newPGTestSession builds an unregistered session for driving the
// sniff → capture → publish flow directly.
func newPGTestSession() *pgSession {
	return &pgSession{id: "sid-" + newEventID(), closer: func() {}}
}

// pgCompletePending drives a session's capture to completion with a
// synthetic CommandComplete and publishes the pending event — the unit-test
// analogue of the backend answering a command.
func pgCompletePending(p *PGProxy, s *pgSession) {
	s.mu.Lock()
	s.capture.feed(pgCmdCompleteMsg("SELECT 1"))
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)
}

// TestPGSniffClassifiesSQL: SimpleQuery and Parse SQL are classified into
// the pending event's stmt_type (select/insert/update/delete/other).
func TestPGSniffClassifiesSQL(t *testing.T) {
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	s := newPGTestSession()
	tok := &models.TokenPayload{Username: "pg-user", DBUser: "ro_user"}
	cache := newStmtCache()

	cases := []struct {
		msg  pgproto3.FrontendMessage
		kind string
		want string
	}{
		{&pgproto3.Query{String: "SELECT id FROM demo_items"}, "query", "select"},
		{&pgproto3.Query{String: "INSERT INTO t VALUES (1)"}, "query", "insert"},
		{&pgproto3.Query{String: "  UPDATE t SET a=1"}, "query", "update"},
		{&pgproto3.Query{String: "DELETE FROM t"}, "query", "delete"},
		{&pgproto3.Query{String: "BEGIN"}, "query", "other"},
		{&pgproto3.Parse{Name: "s1", Query: "SELECT * FROM t"}, "prepare", "select"},
		{&pgproto3.Parse{Name: "s2", Query: "DELETE FROM t WHERE id=$1"}, "prepare", "delete"},
	}
	for _, tc := range cases {
		p.sniffPGMessage(tc.msg, cache, s, tok, "127.0.0.1:1")
		s.mu.Lock()
		ev := s.pending
		s.mu.Unlock()
		if ev == nil {
			t.Fatalf("sniff %T: no pending event", tc.msg)
		}
		if ev.Kind != tc.kind || ev.StmtType != tc.want {
			t.Errorf("sniff %T: kind=%q stmt_type=%q, want %q/%q", tc.msg, ev.Kind, ev.StmtType, tc.kind, tc.want)
		}
	}

	// Execute resolves SQL through the stmt cache (and classifies as
	// "other" like the MySQL EXECUTE fallback).
	p.sniffPGMessage(&pgproto3.Execute{Portal: "s1"}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev := s.pending
	s.mu.Unlock()
	if ev == nil || ev.Kind != "execute" || ev.SQL != "EXECUTE SELECT * FROM t" || ev.StmtType != "other" {
		t.Errorf("execute: kind=%q sql=%q stmt=%q, want execute/EXECUTE SELECT * FROM t/other", ev.Kind, ev.SQL, ev.StmtType)
	}

	// Terminate and Close are not sniffed — pending stays as-is.
	p.sniffPGMessage(&pgproto3.Terminate{}, cache, s, tok, "127.0.0.1:1")
	p.sniffPGMessage(&pgproto3.Close{ObjectType: 'S', Name: "s1"}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev = s.pending
	s.mu.Unlock()
	if ev == nil || ev.Kind != "execute" {
		t.Errorf("pending changed after Terminate/Close: %+v", ev)
	}
}

// TestPGSessionCapturePublish drives the full pending pipeline with
// synthetic backend messages: a result-set response publishes ok with
// captured columns/rows, an ErrorResponse publishes status=error with the
// server message — both carrying the classified stmt type and session id.
func TestPGSessionCapturePublish(t *testing.T) {
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
	go vs.Subscribe(subCtx, "queries:pg-user", false, out)
	waitSubAck(t, acked)

	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, nil)
	s := newPGTestSession()
	tok := &models.TokenPayload{Username: "pg-user", TicketID: "T-6-3", DBUser: "ro_user"}
	cache := newStmtCache()

	// Result-set response → ok with captured columns/rows.
	p.sniffPGMessage(&pgproto3.Query{String: "SELECT id FROM t"}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	s.capture.feed(pgRowDescMsg("id"))
	s.capture.feed(pgDataRowMsg([]byte("1")))
	s.capture.feed(pgCmdCompleteMsg("SELECT 1"))
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal ok event: %v", err)
	}
	if ev.Kind != "query" || ev.SQL != "SELECT id FROM t" || ev.StmtType != "select" {
		t.Errorf("ok event: kind=%q sql=%q stmt=%q", ev.Kind, ev.SQL, ev.StmtType)
	}
	if ev.Status != "ok" || ev.Error != "" {
		t.Errorf("ok event: status=%q error=%q, want ok/empty", ev.Status, ev.Error)
	}
	if !reflect.DeepEqual(ev.Columns, []string{"id"}) || !reflect.DeepEqual(ev.Rows, [][]string{{"1"}}) {
		t.Errorf("ok event: columns=%q rows=%q", ev.Columns, ev.Rows)
	}
	if ev.Truncated {
		t.Error("ok event: truncated = true, want false")
	}
	if ev.SessionID != s.id {
		t.Errorf("ok event: session_id = %q, want %q", ev.SessionID, s.id)
	}

	// Error response → status error + server message; no stale result set.
	p.sniffPGMessage(&pgproto3.Query{String: "SELECT * FROM nope"}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	s.capture.feed(pgErrMsg(`relation "nope" does not exist`))
	c = s.capture
	s.mu.Unlock()
	p.publishPending(s, c)
	ev = models.QueryEvent{} // fresh struct: absent omitempty fields must not leak
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal error event: %v", err)
	}
	if ev.StmtType != "select" || ev.Status != "error" || !strings.Contains(ev.Error, "does not exist") {
		t.Errorf("error event: stmt=%q status=%q error=%q", ev.StmtType, ev.Status, ev.Error)
	}
	if len(ev.Columns) != 0 || len(ev.Rows) != 0 {
		t.Errorf("error event carries stale result set: cols=%q rows=%q", ev.Columns, ev.Rows)
	}
	if ev.SessionID != s.id {
		t.Errorf("error event: session_id = %q, want %q", ev.SessionID, s.id)
	}
}

// TestPGSessionStaleCaptureGuard: a capture completed for a command that
// was replaced by a newer sniffed command publishes NOTHING (pointer
// identity); only the current capture's completion publishes.
func TestPGSessionStaleCaptureGuard(t *testing.T) {
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
	go vs.Subscribe(subCtx, "queries:pg-user", false, out)
	waitSubAck(t, acked)

	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, nil)
	s := newPGTestSession()
	tok := &models.TokenPayload{Username: "pg-user", TicketID: "T-6-3", DBUser: "ro_user"}
	cache := newStmtCache()

	p.sniffPGMessage(&pgproto3.Query{String: "SELECT 1"}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	stale := s.capture
	s.mu.Unlock()
	// A newer command replaces pending + capture before the first response.
	p.sniffPGMessage(&pgproto3.Query{String: "SELECT 2"}, cache, s, tok, "127.0.0.1:1")

	// The stale capture completing must not publish (it is no longer the
	// session's capture — and its data would describe the wrong command).
	stale.feed(pgCmdCompleteMsg("SELECT 1"))
	p.publishPending(s, stale)
	expectNoEvent(t, out)

	// The CURRENT capture's completion publishes the current pending event.
	s.mu.Lock()
	s.capture.feed(pgRowDescMsg("x"))
	s.capture.feed(pgDataRowMsg([]byte("2")))
	s.capture.feed(pgCmdCompleteMsg("SELECT 1"))
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.SQL != "SELECT 2" || !reflect.DeepEqual(ev.Rows, [][]string{{"2"}}) {
		t.Errorf("event: sql=%q rows=%q, want SELECT 2 / [[2]]", ev.SQL, ev.Rows)
	}
	expectNoEvent(t, out)
}

// TestPGSessionReadyForQuerySafetyPublish: a command still pending at
// ReadyForQuery (capture never completed — defensive) is finished as ok and
// published at the statement boundary.
func TestPGSessionReadyForQuerySafetyPublish(t *testing.T) {
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
	go vs.Subscribe(subCtx, "queries:pg-user", false, out)
	waitSubAck(t, acked)

	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, nil)
	s := newPGTestSession()
	tok := &models.TokenPayload{Username: "pg-user", TicketID: "T-6-3", DBUser: "ro_user"}
	cache := newStmtCache()

	p.sniffPGMessage(&pgproto3.Query{String: "SELECT 1"}, cache, s, tok, "127.0.0.1:1")
	p.publishPendingOnReady(s) // no completion message seen
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.SQL != "SELECT 1" || ev.Status != "ok" {
		t.Errorf("event: sql=%q status=%q, want SELECT 1 / ok", ev.SQL, ev.Status)
	}
	// Nothing pending afterwards: a later ReadyForQuery publishes nothing.
	p.publishPendingOnReady(s)
	expectNoEvent(t, out)
}

// TestPGSessionFlushOnClose: a command unanswered when the session dies is
// published as error "connection closed before response"; an idle session
// publishes nothing.
func TestPGSessionFlushOnClose(t *testing.T) {
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
	go vs.Subscribe(subCtx, "queries:pg-user", false, out)
	waitSubAck(t, acked)

	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, nil)
	s := newPGTestSession()
	tok := &models.TokenPayload{Username: "pg-user", TicketID: "T-6-3", DBUser: "ro_user"}
	cache := newStmtCache()

	p.sniffPGMessage(&pgproto3.Query{String: "SELECT pg_sleep(100)"}, cache, s, tok, "127.0.0.1:1")
	p.flushPendingOnClose(s)
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.Status != "error" || ev.Error != "connection closed before response" {
		t.Errorf("event: status=%q error=%q, want error / connection closed before response", ev.Status, ev.Error)
	}
	if ev.StmtType != "select" {
		t.Errorf("event: stmt_type=%q, want select", ev.StmtType)
	}

	// Idle session close: no event.
	s2 := newPGTestSession()
	p.flushPendingOnClose(s2)
	expectNoEvent(t, out)
}

// TestPGProxySessionRegistryKill mirrors the MySQL registry test:
// register/unregister + KillSession invokes the closer exactly for
// registered sessions.
func TestPGProxySessionRegistryKill(t *testing.T) {
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	killed := false
	s := &pgSession{id: "sid-test", closer: func() { killed = true }}
	p.registerSession(s)
	if !p.KillSession("sid-test") {
		t.Fatal("KillSession on a registered session returned false")
	}
	if !killed {
		t.Error("KillSession did not invoke the closer")
	}
	p.unregisterSession("sid-test")
	if p.KillSession("sid-test") {
		t.Error("KillSession after unregister returned true")
	}
}
