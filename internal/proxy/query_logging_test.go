package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
)

// --- Task 8.8: query logging (buffer-handler logger assertions) ------------
//
// The proxies log every published query event with full context (username,
// ticket_id, db_user, db, db_type, stmt_type, status, session_id, sql) and —
// ONLY when log_query_output is on — the captured result payload
// (columns/row_count/rows/truncated). These tests capture the logger with a
// JSON buffer handler and assert on the decoded records, so attr PRESENCE is
// exact: flag off → the payload keys must not exist at all.

// logCapture collects slog records as decoded JSON objects.
type logCapture struct {
	buf bytes.Buffer
}

func newLogCapture() *logCapture { return &logCapture{} }

// logger returns a JSON slog logger writing into the capture buffer.
func (c *logCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&c.buf, nil))
}

// record returns the first record whose msg equals want, or nil.
func (c *logCapture) record(want string) map[string]any {
	for _, line := range strings.Split(c.buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["msg"] == want {
			return m
		}
	}
	return nil
}

func mustRecord(t *testing.T, c *logCapture, msg string) map[string]any {
	t.Helper()
	if r := c.record(msg); r != nil {
		return r
	}
	t.Fatalf("no %q log record in captured log:\n%s", msg, c.buf.String())
	return nil
}

// assertNoSensitiveKeys enforces the house rule: log records never carry
// credentials — no token values, no passwords, no secret material.
func assertNoSensitiveKeys(t *testing.T, c *logCapture) {
	t.Helper()
	for _, line := range strings.Split(c.buf.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		for _, bad := range []string{"token", "password", "secret"} {
			if strings.Contains(line, `"`+bad+`"`) {
				t.Errorf("log record contains sensitive key %q: %s", bad, line)
			}
		}
	}
}

// --- MySQL ------------------------------------------------------------------

// TestMySQLQueryLoggingContextAlways: with the flag OFF (default) a published
// query event still logs the full context line, and the captured result
// payload keys (columns/row_count/rows/truncated) are ABSENT.
func TestMySQLQueryLoggingContextAlways(t *testing.T) {
	cap := newLogCapture()
	vs := proxyTestStore(t)
	p := NewMySQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil) // flag off (default)
	s := &mysqlSession{id: "sid-" + newEventID(), db: "appdb", closer: func() {}}
	tok := &models.TokenPayload{Username: "alice", TicketID: "T-8-8", DBUser: "ro_user"}

	p.sniffCommand(s, cmdQuery, []byte("SELECT id FROM demo_items"), tok, "127.0.0.1:1")
	s.mu.Lock()
	s.capture.feed([]byte{0x01})
	s.capture.feed(colDefPacket("id"))
	s.capture.feed([]byte{0xfe})
	s.capture.feed(dataRowPacket([]byte("1")))
	s.capture.feed([]byte{0xfe})
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)

	r := mustRecord(t, cap, "query")
	assertQueryContext(t, r, "mysql", "SELECT id FROM demo_items", s.id, "alice", "T-8-8")
	for _, absent := range []string{"columns", "row_count", "rows", "truncated"} {
		if _, ok := r[absent]; ok {
			t.Errorf("flag off: record contains %q, want absent: %v", absent, r)
		}
	}
	assertNoSensitiveKeys(t, cap)
}

// TestMySQLQueryLoggingOutputFlag: with the flag ON the same line additionally
// carries columns, row_count, rows and truncated.
func TestMySQLQueryLoggingOutputFlag(t *testing.T) {
	cap := newLogCapture()
	vs := proxyTestStore(t)
	p := NewMySQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
	p.SetLogQueryOutput(true)
	s := &mysqlSession{id: "sid-" + newEventID(), db: "appdb", closer: func() {}}
	tok := &models.TokenPayload{Username: "alice", TicketID: "T-8-8", DBUser: "ro_user"}

	p.sniffCommand(s, cmdQuery, []byte("SELECT id FROM demo_items"), tok, "127.0.0.1:1")
	s.mu.Lock()
	s.capture.feed([]byte{0x01})
	s.capture.feed(colDefPacket("id"))
	s.capture.feed([]byte{0xfe})
	s.capture.feed(dataRowPacket([]byte("1")))
	s.capture.feed([]byte{0xfe})
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)

	r := mustRecord(t, cap, "query")
	assertQueryContext(t, r, "mysql", "SELECT id FROM demo_items", s.id, "alice", "T-8-8")
	if got := r["row_count"]; got != float64(1) {
		t.Errorf("row_count = %v, want 1", got)
	}
	if got, ok := r["columns"].([]any); !ok || len(got) != 1 || got[0] != "id" {
		t.Errorf("columns = %v, want [id]", r["columns"])
	}
	rows, ok := r["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %v, want 1 row", r["rows"])
	}
	row, ok := rows[0].([]any)
	if !ok || len(row) != 1 || row[0] != "1" {
		t.Errorf("rows[0] = %v, want [1]", rows[0])
	}
	if got := r["truncated"]; got != false {
		t.Errorf("truncated = %v, want false", got)
	}
	assertNoSensitiveKeys(t, cap)
}

// --- PostgreSQL -------------------------------------------------------------

// TestPGQueryLoggingContextAlways mirrors the MySQL flag-off case.
func TestPGQueryLoggingContextAlways(t *testing.T) {
	cap := newLogCapture()
	vs := proxyTestStore(t)
	p := NewPGProxy(cap.logger(), vs, &ConfigCredResolver{}, nil) // flag off (default)
	s := &pgSession{id: "sid-" + newEventID(), db: "appdb", closer: func() {}}
	tok := &models.TokenPayload{Username: "bob", TicketID: "T-8-8b", DBUser: "ro_user"}

	p.sniffPGMessage(&pgproto3.Query{String: "SELECT id FROM demo_items"}, newStmtCache(), s, tok, "127.0.0.1:1")
	s.mu.Lock()
	s.capture.feed(pgRowDescMsg("id"))
	s.capture.feed(pgDataRowMsg([]byte("7")))
	s.capture.feed(pgCmdCompleteMsg("SELECT 1"))
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)

	r := mustRecord(t, cap, "query")
	assertQueryContext(t, r, "postgres", "SELECT id FROM demo_items", s.id, "bob", "T-8-8b")
	for _, absent := range []string{"columns", "row_count", "rows", "truncated"} {
		if _, ok := r[absent]; ok {
			t.Errorf("flag off: record contains %q, want absent: %v", absent, r)
		}
	}
	assertNoSensitiveKeys(t, cap)
}

// TestPGQueryLoggingOutputFlag mirrors the MySQL flag-on case.
func TestPGQueryLoggingOutputFlag(t *testing.T) {
	cap := newLogCapture()
	vs := proxyTestStore(t)
	p := NewPGProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
	p.SetLogQueryOutput(true)
	s := &pgSession{id: "sid-" + newEventID(), db: "appdb", closer: func() {}}
	tok := &models.TokenPayload{Username: "bob", TicketID: "T-8-8b", DBUser: "ro_user"}

	p.sniffPGMessage(&pgproto3.Query{String: "SELECT id FROM demo_items"}, newStmtCache(), s, tok, "127.0.0.1:1")
	s.mu.Lock()
	s.capture.feed(pgRowDescMsg("id"))
	s.capture.feed(pgDataRowMsg([]byte("7")))
	s.capture.feed(pgCmdCompleteMsg("SELECT 1"))
	c := s.capture
	s.mu.Unlock()
	p.publishPending(s, c)

	r := mustRecord(t, cap, "query")
	assertQueryContext(t, r, "postgres", "SELECT id FROM demo_items", s.id, "bob", "T-8-8b")
	if got := r["row_count"]; got != float64(1) {
		t.Errorf("row_count = %v, want 1", got)
	}
	if got, ok := r["columns"].([]any); !ok || len(got) != 1 || got[0] != "id" {
		t.Errorf("columns = %v, want [id]", r["columns"])
	}
	rows, ok := r["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %v, want 1 row", r["rows"])
	}
	row, ok := rows[0].([]any)
	if !ok || len(row) != 1 || row[0] != "7" {
		t.Errorf("rows[0] = %v, want [7]", rows[0])
	}
	if got := r["truncated"]; got != false {
		t.Errorf("truncated = %v, want false", got)
	}
	assertNoSensitiveKeys(t, cap)
}

// --- lifecycle --------------------------------------------------------------

// TestLifecycleLogging: session started/ended events log the same context
// fields (minus sql) under "session started"/"session ended" messages.
func TestLifecycleLogging(t *testing.T) {
	vs := proxyTestStore(t)

	t.Run("mysql", func(t *testing.T) {
		cap := newLogCapture()
		p := NewMySQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
		s := &mysqlSession{id: "sid-" + newEventID(), db: "appdb", closer: func() {}}
		tok := &models.TokenPayload{Username: "alice", TicketID: "T-8-8", DBUser: "ro_user", DBType: "mysql"}

		p.publishLifecycle(s, tok, "started", "10.0.0.9:4444")
		r := mustRecord(t, cap, "session started")
		assertLifecycleContext(t, r, s.id, "alice")
		if _, ok := r["sql"]; ok {
			t.Errorf("lifecycle record must not carry sql: %v", r)
		}

		p.publishLifecycle(s, tok, "ended", "10.0.0.9:4444")
		r = mustRecord(t, cap, "session ended")
		assertLifecycleContext(t, r, s.id, "alice")
		if _, ok := r["sql"]; ok {
			t.Errorf("lifecycle record must not carry sql: %v", r)
		}
		assertNoSensitiveKeys(t, cap)
	})

	t.Run("postgres", func(t *testing.T) {
		cap := newLogCapture()
		p := NewPGProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
		s := &pgSession{id: "sid-" + newEventID(), db: "appdb", closer: func() {}}
		tok := &models.TokenPayload{Username: "bob", TicketID: "T-8-8b", DBUser: "ro_user", DBType: "postgres"}

		p.publishLifecycle(s, tok, "started", "10.0.0.9:4444")
		r := mustRecord(t, cap, "session started")
		assertLifecycleContext(t, r, s.id, "bob")
		if _, ok := r["sql"]; ok {
			t.Errorf("lifecycle record must not carry sql: %v", r)
		}

		p.publishLifecycle(s, tok, "ended", "10.0.0.9:4444")
		r = mustRecord(t, cap, "session ended")
		assertLifecycleContext(t, r, s.id, "bob")
		if _, ok := r["sql"]; ok {
			t.Errorf("lifecycle record must not carry sql: %v", r)
		}
		assertNoSensitiveKeys(t, cap)
	})
}

// --- shared assertions ------------------------------------------------------

// assertQueryContext checks the always-on context fields of a "query" record.
func assertQueryContext(t *testing.T, r map[string]any, dbType, sql, sid, username, ticketID string) {
	t.Helper()
	want := map[string]any{
		"username":   username,
		"ticket_id":  ticketID,
		"db_user":    "ro_user",
		"db":         "appdb",
		"db_type":    dbType,
		"stmt_type":  "select",
		"status":     "ok",
		"session_id": sid,
		"sql":        sql,
	}
	for k, v := range want {
		if got := r[k]; got != v {
			t.Errorf("record[%q] = %v, want %v (record: %v)", k, got, v, r)
		}
	}
}

// assertLifecycleContext checks the context fields of a lifecycle record.
func assertLifecycleContext(t *testing.T, r map[string]any, sid, username string) {
	t.Helper()
	if got := r["username"]; got != username {
		t.Errorf("username = %v, want %v", got, username)
	}
	if got := r["ticket_id"]; got == nil || got == "" {
		t.Errorf("ticket_id = %v, want the token's ticket id (lifecycle carries the same context as query lines, minus sql)", got)
	}
	if got := r["db_user"]; got != "ro_user" {
		t.Errorf("db_user = %v, want ro_user", got)
	}
	if got := r["db"]; got != "appdb" {
		t.Errorf("db = %v, want appdb", got)
	}
	if got := r["db_type"]; got == nil || got == "" {
		t.Errorf("db_type = %v, want mysql|postgres", got)
	}
	if got := r["session_id"]; got != sid {
		t.Errorf("session_id = %v, want %v", got, sid)
	}
}
