package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
)

// --- Task 6.2: statement classification --------------------------------------

func TestClassifyStmt(t *testing.T) {
	cases := []struct {
		sql  string
		want string
	}{
		{"SELECT * FROM users", "select"},
		{"select id from t", "select"},
		{"  \t\n  SELECT 1", "select"},
		{"INSERT INTO t VALUES (1)", "insert"},
		{"  UPDATE t SET a = 1", "update"},
		{"DELETE FROM t WHERE id = 1", "delete"},
		// Leading comments are skipped only when newline-terminated (the
		// stripper walks to the next line); a one-line comment without a
		// newline yields "other".
		{"/* leading comment */\nSELECT 1", "select"},
		{"/* c1 */\n/* c2 */\nSELECT 1", "select"},
		{"-- line comment\nSELECT 1", "select"},
		{"# hash comment\nselect 1", "select"},
		{"/* one-line comment */ SELECT 1", "other"},
		{"-- only a comment", "other"},
		{"BEGIN", "other"},
		{"COMMIT", "other"},
		{"SHOW TABLES", "other"},
		{"WITH x AS (SELECT 1) SELECT * FROM x", "other"},
		{"", "other"},
		{"   ", "other"},
	}
	for _, tc := range cases {
		if got := classifyStmt(tc.sql); got != tc.want {
			t.Errorf("classifyStmt(%q) = %q, want %q", tc.sql, got, tc.want)
		}
	}
}

// --- Task 6.2: resultCapture state machine -----------------------------------

func TestResultCaptureOK(t *testing.T) {
	c := &resultCapture{}
	c.feed(okPacket()) // 0x00 header, >= 7 bytes → OK packet ends the capture
	if !c.done() {
		t.Fatal("capture not done after OK")
	}
	if c.status != "ok" || c.errorMsg != "" {
		t.Errorf("status=%q error=%q, want ok/empty", c.status, c.errorMsg)
	}
	if len(c.columns) != 0 || len(c.rows) != 0 || c.truncated {
		t.Errorf("unexpected capture content: cols=%q rows=%q truncated=%v", c.columns, c.rows, c.truncated)
	}
	// Feeding after done is a no-op (e.g. trailing packets of a later reply).
	c.feed([]byte{0xff, 0x48, 0x04, '#', '4', '2', '0', '0', '0', 'x'})
	if c.status != "ok" {
		t.Errorf("status changed after done: %q", c.status)
	}
}

func TestResultCaptureErr(t *testing.T) {
	pkt := []byte{0xff, 0x48, 0x04, '#', '4', '2', '0', '0', '0'}
	pkt = append(pkt, "Table 'appdb.nope' doesn't exist"...)
	c := &resultCapture{}
	c.feed(pkt)
	if !c.done() {
		t.Fatal("capture not done after ERR")
	}
	if c.status != "error" {
		t.Errorf("status = %q, want error", c.status)
	}
	if c.errorMsg != "Table 'appdb.nope' doesn't exist" {
		t.Errorf("errorMsg = %q, want the server message", c.errorMsg)
	}

	// Messages are capped at 300 bytes.
	long := strings.Repeat("m", 400)
	pkt = []byte{0xff, 0x48, 0x04, '#', '4', '2', '0', '0', '0'}
	pkt = append(pkt, long...)
	c2 := &resultCapture{}
	c2.feed(pkt)
	if len(c2.errorMsg) != 300 {
		t.Errorf("errorMsg length = %d, want 300 (capped)", len(c2.errorMsg))
	}
}

func TestResultCaptureFullResultSet(t *testing.T) {
	c := &resultCapture{}
	c.feed([]byte{0x02}) // column count (2 columns: id, name)
	c.feed(colDefPacket("id"))
	c.feed(colDefPacket("name"))
	if c.done() {
		t.Fatal("capture done before the EOF that ends column definitions")
	}
	c.feed([]byte{0xfe}) // EOF ends column definitions
	// Row 1: NULL id (0xfb) + name; row 2: a >512-char cell (cell-truncated)
	// + name.
	long := strings.Repeat("x", 600)
	c.feed(dataRowPacket(nil, []byte("alpha")))
	c.feed(dataRowPacket([]byte(long), []byte("bravo")))
	if c.done() {
		t.Fatal("capture done before the final EOF")
	}
	c.feed([]byte{0xfe}) // EOF ends rows
	if !c.done() {
		t.Fatal("capture not done after the final EOF")
	}
	if c.status != "ok" || c.errorMsg != "" {
		t.Errorf("status=%q error=%q, want ok/empty", c.status, c.errorMsg)
	}
	if !reflect.DeepEqual(c.columns, []string{"id", "name"}) {
		t.Errorf("columns = %q, want [id name]", c.columns)
	}
	if len(c.rows) != 2 {
		t.Fatalf("rows = %q, want 2 rows", c.rows)
	}
	if !reflect.DeepEqual(c.rows[0], []string{"", "alpha"}) {
		t.Errorf("row0 = %q, want [\"\" alpha] (NULL cell)", c.rows[0])
	}
	wantCell := strings.Repeat("x", 512) + "…"
	if !reflect.DeepEqual(c.rows[1], []string{wantCell, "bravo"}) {
		t.Errorf("row1 = %q, want [<512-char cell + ellipsis> bravo]", c.rows[1])
	}
	if c.truncated {
		t.Error("truncated = true, want false (per-cell truncation does not set the flag)")
	}
}

func TestResultCaptureRowCap(t *testing.T) {
	c := &resultCapture{}
	c.feed([]byte{0x02})
	c.feed(colDefPacket("id"))
	c.feed(colDefPacket("name"))
	c.feed([]byte{0xfe})
	for i := 0; i < 105; i++ {
		c.feed(dataRowPacket([]byte{byte(i)}, []byte("v")))
	}
	c.feed([]byte{0xfe})
	if !c.done() {
		t.Fatal("capture not done after the final EOF")
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

// --- helpers: synthetic MySQL text-protocol packets --------------------------

// colDefPacket crafts a COLUMN_DEFINITION packet for one column: lenenc
// catalog/schema/table/org_table, then NAME + org_name, then the fixed 0x0c
// header (contents irrelevant to capture).
func colDefPacket(name string) []byte {
	p := make([]byte, 0, 64)
	for _, s := range []string{"def", "appdb", "demo_items", "demo_items"} {
		p = append(p, byte(len(s)))
		p = append(p, s...)
	}
	for i := 0; i < 2; i++ { // NAME + org_name
		p = append(p, byte(len(name)))
		p = append(p, name...)
	}
	p = append(p, 0x0c)                // length of fixed fields
	p = append(p, make([]byte, 12)...) // charset(2) length(4) type(1) flags(2) decimals(1) filler(2)
	return p
}

// dataRowPacket crafts a TEXT-protocol DataRow packet: a plain sequence of
// lenenc cells with NO leading field-count byte (a leading count is the
// BINARY protocol). A nil cell encodes SQL NULL (0xfb).
func dataRowPacket(cells ...[]byte) []byte {
	p := make([]byte, 0, 16)
	for _, cell := range cells {
		if cell == nil {
			p = append(p, 0xfb)
			continue
		}
		switch {
		case len(cell) < 251:
			p = append(p, byte(len(cell)))
		case len(cell) < 1<<16:
			p = append(p, 0xfc, byte(len(cell)), byte(len(cell)>>8))
		default:
			p = append(p, 0xfd, byte(len(cell)), byte(len(cell)>>8), byte(len(cell)>>16))
		}
		p = append(p, cell...)
	}
	return p
}

// newTestSession builds an unregistered session for driving the
// sniff → capture → publish flow directly.
func newTestSession() *mysqlSession {
	return &mysqlSession{id: "sid-" + newEventID(), closer: func() {}}
}

// completePending drives a session's capture to completion with a synthetic
// OK packet and publishes the pending event — the unit-test analogue of the
// backend answering a command.
func completePending(p *MySQLProxy, s *mysqlSession) {
	s.mu.Lock()
	s.capture.feed(okPacket())
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)
}

// --- Task 6.2: session sniff → capture → publish pipeline --------------------

// TestSessionCapturePublish drives the full pending pipeline with synthetic
// backend packets: an ERR response publishes status=error with the server
// message, a result-set response publishes ok with captured columns/rows, and
// both events carry the classified stmt type and the session id.
func TestSessionCapturePublish(t *testing.T) {
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
	go vs.Subscribe(subCtx, "queries:test-user", false, out)
	waitSubAck(t, acked)

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, nil, nil)
	s := newTestSession()
	tok := &models.TokenPayload{Username: "test-user", TicketID: "T-6-2", DBUser: "ro_user"}

	// ERR response → status error + server message, stmt classified.
	p.sniffCommand(s, cmdQuery, []byte("SELECT * FROM nope"), tok, "127.0.0.1:1")
	errPkt := []byte{0xff, 0x48, 0x04, '#', '4', '2', '0', '0', '0'}
	errPkt = append(errPkt, "Table 'appdb.nope' doesn't exist"...)
	s.mu.Lock()
	s.capture.feed(errPkt)
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)
	var ev models.QueryEvent
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal error event: %v", err)
	}
	if ev.StmtType != "select" || ev.Status != "error" || !strings.Contains(ev.Error, "doesn't exist") {
		t.Errorf("error event: stmt=%q status=%q error=%q", ev.StmtType, ev.Status, ev.Error)
	}
	if ev.SessionID != s.id {
		t.Errorf("error event session_id = %q, want %q", ev.SessionID, s.id)
	}

	// Result-set response → ok with captured columns/rows.
	p.sniffCommand(s, cmdQuery, []byte("SELECT id FROM t"), tok, "127.0.0.1:1")
	s.mu.Lock()
	s.capture.feed([]byte{0x01})
	s.capture.feed(colDefPacket("id"))
	s.capture.feed([]byte{0xfe})
	s.capture.feed(dataRowPacket([]byte("1")))
	s.capture.feed([]byte{0xfe})
	c = s.capture
	s.mu.Unlock()
	p.publishPending(s, c)
	ev = models.QueryEvent{} // fresh struct: absent omitempty fields must not leak from the error event above
	if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
		t.Fatalf("unmarshal ok event: %v", err)
	}
	if ev.Status != "ok" || !reflect.DeepEqual(ev.Columns, []string{"id"}) ||
		!reflect.DeepEqual(ev.Rows, [][]string{{"1"}}) {
		t.Errorf("ok event: status=%q columns=%q rows=%q", ev.Status, ev.Columns, ev.Rows)
	}
}

// TestSessionRegistryKill: register/unregister + KillSession invokes the
// closer (the Task 6.4 kill hook) exactly for registered sessions.
func TestSessionRegistryKill(t *testing.T) {
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil)
	killed := false
	s := &mysqlSession{id: "sid-test", closer: func() { killed = true }}
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
