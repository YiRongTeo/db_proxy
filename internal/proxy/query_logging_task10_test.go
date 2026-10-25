package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
)

// --- Task 10 (node-integration): query-logging coverage gaps -----------------
//
// GAP 1 — mysql stmt cache: COM_STMT_PREPARE responses carry the stmt_id
// (backend→client OK packet); the relay stashes prepare→stmt_id so
// COM_STMT_EXECUTE logs the REAL SQL instead of "EXECUTE stmt_id=N".
// GAP 2 — pin the PG stmtCache incl. the UNNAMED portal "".
// GAP 3 — mssql RPC param extraction (best-effort; sp_executesql @stmt).
// GAP 4 — kind=control fire-and-forget logging on all three planes.
// GAP 5 — rejection-logging parity: ro/frozen/gate rejections publish
// status=error query lines on mysql + pg + mssql alike.

var task10Tok = func(dbType string) *models.TokenPayload {
	return &models.TokenPayload{Username: "task10", TicketID: "T-10", DBUser: "ro_user", DBType: dbType}
}

// mysqlPrepareOKPacket builds the COM_STMT_PREPARE response OK packet:
// 0x00 + stmt_id(4 LE) + num_columns(2) + num_params(2) + reserved(3)
// + warning_count(2) — 12 bytes total.
func mysqlPrepareOKPacket(stmtID uint32, cols, params uint16) []byte {
	p := make([]byte, 0, 12)
	p = append(p, 0x00)
	p = binary.LittleEndian.AppendUint32(p, stmtID)
	p = binary.LittleEndian.AppendUint16(p, cols)
	p = binary.LittleEndian.AppendUint16(p, params)
	p = append(p, 0x00, 0x00, 0x00) // reserved
	p = binary.LittleEndian.AppendUint16(p, 0)
	return p
}

// --- GAP 1: mysql stmt cache -------------------------------------------------

// TestMySQLStmtCacheExecuteWithSQL: prepare → (backend prepare-OK response
// hooks the stmt_id) → execute logs the REAL SQL, not stmt_id=N.
func TestMySQLStmtCacheExecuteWithSQL(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := &mysqlSession{id: "sid-task10-cache", db: "appdb", closer: func() {}}
	cleanupLiveRecord(t, vs, s.id)
	tok := task10Tok("mysql")

	p.sniffCommand(s, cmdPrepare, []byte("SELECT id FROM t WHERE id = ?\x00"), tok, "127.0.0.1:1")
	// The prepare's own pending event is untouched — publication still waits
	// for the backend response.
	if s.pendingEvent() == nil {
		t.Fatal("prepare sniff left no pending event")
	}
	p.notePrepareResponse(s, mysqlPrepareOKPacket(42, 1, 1))

	p.sniffCommand(s, cmdExecute, append([]byte{42, 0, 0, 0}, 0x01, 0), tok, "127.0.0.1:1")
	s.mu.Lock()
	ev := s.pending
	s.mu.Unlock()
	if ev == nil {
		t.Fatal("execute sniff left no pending event")
	}
	if ev.SQL != "EXECUTE SELECT id FROM t WHERE id = ?" {
		t.Errorf("execute event sql = %q, want the prepared text", ev.SQL)
	}
	if ev.Kind != "execute" {
		t.Errorf("execute event kind = %q, want execute", ev.Kind)
	}
}

// TestMySQLStmtCacheExecuteUnknownIDFallback: an execute for a stmt_id the
// relay never saw prepared falls back to stmt_id=N (fail-safe, never blank).
func TestMySQLStmtCacheExecuteUnknownIDFallback(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := &mysqlSession{id: "sid-task10-fallback", db: "appdb", closer: func() {}}
	cleanupLiveRecord(t, vs, s.id)
	tok := task10Tok("mysql")

	p.sniffCommand(s, cmdExecute, []byte{7, 0, 0, 0}, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev := s.pending
	s.mu.Unlock()
	if ev == nil || ev.SQL != "EXECUTE stmt_id=7" {
		t.Errorf("unknown stmt_id event = %+v, want sql EXECUTE stmt_id=7", ev)
	}
}

// TestMySQLStmtCloseEvictsCachedSQL: COM_STMT_CLOSE removes the mapping — a
// later execute of the same id cannot resurrect the old SQL.
func TestMySQLStmtCloseEvictsCachedSQL(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := &mysqlSession{id: "sid-task10-evict", db: "appdb", closer: func() {}}
	cleanupLiveRecord(t, vs, s.id)
	tok := task10Tok("mysql")

	p.sniffCommand(s, cmdPrepare, []byte("SELECT 1"), tok, "127.0.0.1:1")
	p.notePrepareResponse(s, mysqlPrepareOKPacket(9, 1, 0))
	p.sniffCommand(s, 0x19, []byte{9, 0, 0, 0}, tok, "127.0.0.1:1") // COM_STMT_CLOSE

	p.sniffCommand(s, cmdExecute, []byte{9, 0, 0, 0}, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev := s.pending
	s.mu.Unlock()
	if ev == nil || ev.SQL != "EXECUTE stmt_id=9" {
		t.Errorf("post-close execute event = %+v, want fallback stmt_id=9", ev)
	}
}

// TestMySQLPrepareErrorResponseNotCached: a FAILED prepare (backend ERR) must
// not cache its SQL — the slot is cleared either way.
func TestMySQLPrepareErrorResponseNotCached(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := &mysqlSession{id: "sid-task10-err", db: "appdb", closer: func() {}}
	cleanupLiveRecord(t, vs, s.id)
	tok := task10Tok("mysql")

	p.sniffCommand(s, cmdPrepare, []byte("SELECT no_such_table"), tok, "127.0.0.1:1")
	errPkt := append([]byte{0xff, 0x15, 0x2b}, append(append([]byte{}, "#42000"...), make([]byte, 6)...)...)
	p.notePrepareResponse(s, errPkt)

	p.sniffCommand(s, cmdExecute, []byte{3, 0, 0, 0}, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev := s.pending
	s.mu.Unlock()
	if ev == nil || ev.SQL != "EXECUTE stmt_id=3" {
		t.Errorf("post-ERR execute event = %+v, want fallback stmt_id=3", ev)
	}
}

// TestMySQLBackendPipePopulatesStmtCache: the hook is wired into the REAL
// backend→client relay pipe — the prepare-OK packet flowing through it
// populates the cache.
func TestMySQLBackendPipePopulatesStmtCache(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mysqlSession{id: "sid-task10-pipe", db: "appdb", closer: func() {}}
	cleanupLiveRecord(t, vs, s.id)

	go func() { // drain the relayed client side
		br := bufio.NewReader(cpeer)
		for {
			if _, _, err := readMySQLPacket(br); err != nil {
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		p.pipeBackendToClient(backend, client, s)
		close(done)
	}()

	p.sniffCommand(s, cmdPrepare, []byte("SELECT id FROM t WHERE id = ?"), task10Tok("mysql"), "127.0.0.1:1")
	if _, err := bpeer.Write(append([]byte{12, 0, 0, 1}, mysqlPrepareOKPacket(42, 1, 1)...)); err != nil {
		t.Fatalf("write prepare-OK: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		cached := s.stmtCache[42]
		s.mu.Unlock()
		if cached == "SELECT id FROM t WHERE id = ?" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cpeer.Close() // unblocks the client-drain goroutine
	client.Close()
	backend.Close() // EOF ends the relay's backend read loop
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("backend pipe did not exit")
	}
	s.mu.Lock()
	cached := s.stmtCache[42]
	s.mu.Unlock()
	if cached != "SELECT id FROM t WHERE id = ?" {
		t.Fatalf("stmt cache[42] = %q, want the prepared SQL", cached)
	}
}

// --- GAP 2: pin the PG stmtCache incl. the unnamed portal --------------------

func task10PGSession(t *testing.T) *pgSession {
	t.Helper()
	return &pgSession{id: "sid-task10-pg-" + newEventID(), db: "appdb", closer: func() {}}
}

// TestPGStmtCacheUnnamedPortalPin: Parse with the EMPTY statement name and
// Execute with the EMPTY portal resolve through the cache — the libpq/psql
// extended-protocol path logs the real SQL. Bind is neutral (no event), and
// a second unnamed Parse overwrites the mapping.
func TestPGStmtCacheUnnamedPortalPin(t *testing.T) {
	p := &PGProxy{}
	s := &pgSession{id: "sid-task10-pg-unnamed", db: "appdb", closer: func() {}}
	cache := newStmtCache()
	tok := task10Tok("postgres")

	p.sniffPGMessage(&pgproto3.Parse{Name: "", Query: "SELECT 1"}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev := s.pending
	s.mu.Unlock()
	if ev == nil || ev.Kind != "prepare" || ev.SQL != "SELECT 1" {
		t.Fatalf("unnamed Parse event = %+v, want prepare/SELECT 1", ev)
	}

	// Bind (unnamed) is relayed without an event — the pending stays the Parse's.
	p.sniffPGMessage(&pgproto3.Bind{}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev = s.pending
	s.mu.Unlock()
	if ev == nil || ev.Kind != "prepare" {
		t.Fatalf("Bind replaced the pending event: %+v", ev)
	}

	p.sniffPGMessage(&pgproto3.Execute{Portal: ""}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev = s.pending
	s.mu.Unlock()
	if ev == nil || ev.Kind != "execute" || ev.SQL != "EXECUTE SELECT 1" {
		t.Errorf("unnamed Execute event = %+v, want execute/EXECUTE SELECT 1", ev)
	}

	// A second unnamed Parse overwrites: the next unnamed Execute carries B.
	p.sniffPGMessage(&pgproto3.Parse{Name: "", Query: "SELECT 2"}, cache, s, tok, "127.0.0.1:1")
	p.sniffPGMessage(&pgproto3.Execute{Portal: ""}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev = s.pending
	s.mu.Unlock()
	if ev == nil || ev.SQL != "EXECUTE SELECT 2" {
		t.Errorf("second unnamed Execute event = %+v, want EXECUTE SELECT 2", ev)
	}
}

// TestPGStmtCacheNamedEvictPortalFallback: named statements cache and evict
// like named ones; an Execute for an evicted portal falls back to the
// portal name (never blank).
func TestPGStmtCacheNamedEvictPortalFallback(t *testing.T) {
	p := &PGProxy{}
	s := &pgSession{id: "sid-task10-pg-named", db: "appdb", closer: func() {}}
	cache := newStmtCache()
	tok := task10Tok("postgres")

	p.sniffPGMessage(&pgproto3.Parse{Name: "s1", Query: "SELECT 3"}, cache, s, tok, "127.0.0.1:1")
	p.sniffPGMessage(&pgproto3.Execute{Portal: "s1"}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev := s.pending
	s.mu.Unlock()
	if ev == nil || ev.SQL != "EXECUTE SELECT 3" {
		t.Fatalf("named Execute event = %+v, want EXECUTE SELECT 3", ev)
	}

	p.sniffPGMessage(&pgproto3.Close{ObjectType: 'S', Name: "s1"}, cache, s, tok, "127.0.0.1:1")
	p.sniffPGMessage(&pgproto3.Execute{Portal: "s1"}, cache, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev = s.pending
	s.mu.Unlock()
	if ev == nil || ev.SQL != "EXECUTE portal=s1" {
		t.Errorf("evicted Execute event = %+v, want EXECUTE portal=s1", ev)
	}
}

// --- GAP 3: mssql RPC parameter extraction (best-effort) ---------------------

// mssqlStringParam builds one RPC parameter carrying a string value:
// Name(B_VARCHAR) + Status(1) + UserType(4) + TYPE_INFO(0xE7 NVARCHAR:
// maxlen + collation(5)) + USHORT-length UTF-16LE value. maxlen 0xFFFF
// switches to the PLP (8-byte total + chunked) value encoding.
func mssqlStringParam(name, value string, plp bool) []byte {
	var b []byte
	b = append(b, byte(len(name)))
	b = append(b, utf16le(name)...)
	b = append(b, 0x00)                        // status
	b = binary.LittleEndian.AppendUint32(b, 0) // UserType
	b = append(b, 0xE7)                        // NVARCHAR
	if plp {
		b = binary.LittleEndian.AppendUint16(b, 0xFFFF)
	} else {
		b = binary.LittleEndian.AppendUint16(b, uint16(2*len(value)+2))
	}
	b = append(b, 0x09, 0x04, 0xd0, 0x00, 0x34) // collation
	if plp {
		total := uint64(2 * len(value))
		b = binary.LittleEndian.AppendUint64(b, total)
		b = binary.LittleEndian.AppendUint32(b, uint32(total))
		b = append(b, utf16le(value)...)
		b = binary.LittleEndian.AppendUint32(b, 0) // terminator
	} else {
		b = binary.LittleEndian.AppendUint16(b, uint16(2*len(value)))
		b = append(b, utf16le(value)...)
	}
	return b
}

func buildMSSQLRPCPayload(proc string, params ...[]byte) []byte {
	payload := append(append([]byte(nil), allHeaders22...), byte(len(proc)))
	payload = append(payload, utf16le(proc)...)
	payload = append(payload, 0x00, 0x00) // OptionFlags
	for _, p := range params {
		payload = append(payload, p...)
	}
	return payload
}

// TestDecodeMSSQLRPCParamsStmt: sp_executesql's first parameter (@stmt,
// NVARCHAR) is extracted alongside the proc name.
func TestDecodeMSSQLRPCParamsStmt(t *testing.T) {
	payload := buildMSSQLRPCPayload("sp_executesql", mssqlStringParam("@stmt", "SELECT 1", false))
	name, stmt, ok := decodeMSSQLRPCParams(payload)
	if !ok || name != "sp_executesql" {
		t.Fatalf("ok=%v name=%q, want sp_executesql", ok, name)
	}
	if stmt != "SELECT 1" {
		t.Errorf("stmt = %q, want SELECT 1", stmt)
	}
	// PLP (NVARCHAR(MAX)) values decode too.
	payload = buildMSSQLRPCPayload("sp_executesql", mssqlStringParam("@stmt", "UPDATE t SET x = 1", true))
	name, stmt, ok = decodeMSSQLRPCParams(payload)
	if !ok || name != "sp_executesql" || stmt != "UPDATE t SET x = 1" {
		t.Errorf("plp: ok=%v name=%q stmt=%q, want name+stmt", ok, name, stmt)
	}
	// The legacy name-only decoder still works (gate classification path).
	if name, ok := decodeMSSQLRPC(payload); !ok || name != "sp_executesql" {
		t.Errorf("decodeMSSQLRPC = %q/%v, want sp_executesql/true", name, ok)
	}
}

// TestDecodeMSSQLRPCParamsGarbageNameOnly: undecodable parameter streams
// degrade to the proc name only — never raw payload bytes, never a blank.
func TestDecodeMSSQLRPCParamsGarbageNameOnly(t *testing.T) {
	payload := buildMSSQLRPCPayload("sp_executesql", []byte{0x01, 0x02, 0x03})
	name, stmt, ok := decodeMSSQLRPCParams(payload)
	if !ok || name != "sp_executesql" || stmt != "" {
		t.Errorf("garbage params: ok=%v name=%q stmt=%q, want name-only", ok, name, stmt)
	}
	// Truncated parameter header → name only.
	payload = buildMSSQLRPCPayload("sp_executesql", []byte{0x05, 0x40, 0x00})
	_, stmt, ok = decodeMSSQLRPCParams(payload)
	if !ok || stmt != "" {
		t.Errorf("truncated params: ok=%v stmt=%q, want name-only", ok, stmt)
	}
}

// TestMSSQLSniffRPCLogsStatement: a sniffed sp_executesql RPC logs
// "EXEC sp_executesql <stmt>" (redacted); an undecodable RPC still logs
// "EXEC <name>".
func TestMSSQLSniffRPCLogsStatement(t *testing.T) {
	vs := proxyTestStore(t)
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	s := &mssqlSession{id: "sid-task10-rpc", db: "appdb", shortDone: false}
	tok := task10Tok("mssql")

	payload := buildMSSQLRPCPayload("sp_executesql", mssqlStringParam("@stmt", "CREATE USER bob IDENTIFIED BY 'sekret'", false))
	p.sniffMSSQLCommand(tdsRPC, payload, s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev := s.pending
	s.mu.Unlock()
	if ev == nil || ev.SQL != "EXEC sp_executesql CREATE USER bob '***'" {
		t.Errorf("rpc event = %+v, want redacted statement in the EXEC line", ev)
	}

	p.sniffMSSQLCommand(tdsRPC, buildMSSQLRPCPayload("sp_who"), s, tok, "127.0.0.1:1")
	s.mu.Lock()
	ev = s.pending
	s.mu.Unlock()
	if ev == nil || ev.SQL != "EXEC sp_who" {
		t.Errorf("paramless rpc event = %+v, want EXEC sp_who", ev)
	}
}

// --- GAP 4: kind=control fire-and-forget -------------------------------------

// TestMySQLControlCommandsLogged: PING/QUIT forwarded byte-exact AND logged
// immediately as kind=control status=ok — no pending event awaiting a
// backend response.
func TestMySQLControlCommandsLogged(t *testing.T) {
	cap := newLogCapture()
	vs := proxyTestStore(t)
	p := NewMySQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mysqlSession{id: "sid-task10-ctrl", db: "appdb", access: "ro", closer: func() {}}
	cleanupLiveRecord(t, vs, s.id)
	tok := task10Tok("mysql")

	done := make(chan struct{})
	go func() {
		p.pipeClientToBackend(bufio.NewReader(client), backend, client, s, tok, "127.0.0.1:2")
		close(done)
	}()

	for _, tc := range []struct {
		cmd  byte
		name string
	}{{0x0e, "PING"}, {0x01, "QUIT"}, {0x09, "STATISTICS"}} {
		if err := writeMySQLPacket(cpeer, 0, []byte{tc.cmd}); err != nil {
			t.Fatalf("write %#x: %v", tc.cmd, err)
		}
		bbr := bufio.NewReader(bpeer)
		_ = bpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, pkt, err := readMySQLPacket(bbr)
		_ = bpeer.SetReadDeadline(time.Time{})
		if err != nil || len(pkt) != 1 || pkt[0] != tc.cmd {
			t.Fatalf("command %#x forwarded = % x err=%v, want byte-exact", tc.cmd, pkt, err)
		}
		r := mustRecord(t, cap, "query")
		if r["sql"] != tc.name || r["kind"] != "control" || r["status"] != "ok" || r["stmt_type"] != "control" {
			t.Errorf("%#x record = %v, want control/ok/%s", tc.cmd, r, tc.name)
		}
		if ev := s.pendingEvent(); ev != nil {
			t.Fatalf("%#x left a pending event: %+v (control must be fire-and-forget)", tc.cmd, ev)
		}
		cap.buf.Reset()
	}
	cpeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit")
	}
	assertNoSensitiveKeys(t, cap)
}

// TestPGControlMessagesLogged: Sync/Flush/Terminate are logged kind=control
// (fire-and-forget) and forwarded byte-exact to the backend.
func TestPGControlMessagesLogged(t *testing.T) {
	cap := newLogCapture()
	vs := proxyTestStore(t)
	p := NewPGProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)

	var inBuf, backendBuf bytes.Buffer
	be := pgproto3.NewBackend(pgproto3.NewChunkReader(&inBuf), &inBuf)
	front := &pgFrontend{f: pgproto3.NewFrontend(pgproto3.NewChunkReader(bytes.NewReader(nil)), &backendBuf)}
	s := &pgSession{id: "sid-task10-pg-ctrl", db: "appdb", closer: func() {}}
	cleanupLiveRecord(t, vs, s.id)
	tok := task10Tok("postgres")

	for _, m := range []pgproto3.FrontendMessage{&pgproto3.Sync{}, &pgproto3.Flush{}, &pgproto3.Terminate{}} {
		raw, err := m.Encode(nil)
		if err != nil {
			t.Fatalf("encode %T: %v", m, err)
		}
		inBuf.Write(raw)
	}
	done := make(chan struct{})
	go func() {
		p.pipePGClientToBackend(be, front, s, tok, "127.0.0.1:3")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit")
	}

	forwarded := backendBuf.String()
	if !strings.Contains(forwarded, "S") || !strings.Contains(forwarded, "H") || !strings.Contains(forwarded, "X") {
		t.Errorf("forwarded buffer %q missing SYNC/FLUSH/TERMINATE frames", forwarded)
	}
	// The three records were written in one burst — collect all "query"
	// records and require exactly the SYNC/FLUSH/TERMINATE set.
	var saw []string
	for _, line := range strings.Split(cap.buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil || m["msg"] != "query" {
			continue
		}
		name, _ := m["sql"].(string)
		saw = append(saw, name)
		if m["kind"] != "control" || m["status"] != "ok" {
			t.Errorf("record %v: want kind=control status=ok", m)
		}
	}
	want := []string{"SYNC", "FLUSH", "TERMINATE"}
	if !reflect.DeepEqual(saw, want) {
		t.Errorf("control records = %v, want %v (in order)", saw, want)
	}
	if ev := s.pendingEvent(); ev != nil {
		t.Errorf("control message left a pending event: %+v", ev)
	}
	assertNoSensitiveKeys(t, cap)
}

// TestMSSQLControlMessagesLogged: ATTENTION (0x06) and transaction-manager
// (0x0E) messages are logged kind=control and forwarded byte-exact.
func TestMSSQLControlMessagesLogged(t *testing.T) {
	cap := newLogCapture()
	vs := proxyTestStore(t)
	p := NewMSSQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	s := &mssqlSession{id: "sid-task10-tds-ctrl", db: "appdb", client: client, backend: backend}
	cleanupLiveRecord(t, vs, s.id)
	tok := task10Tok("mssql")

	done := make(chan struct{})
	go func() {
		p.pipeMSSQLClientToBackend(bufio.NewReader(client), backend, client, s, tok, "127.0.0.1:4")
		close(done)
	}()

	for _, tc := range []struct {
		typ  byte
		name string
	}{{0x06, "ATTENTION"}, {0x0e, "TXMGR"}} {
		frame := []byte{tc.typ, tdsStatusEOM, 0x00, uint8(tdsHeaderLen), 0x00, 0x00, 0x01, 0x00}
		if _, err := cpeer.Write(frame); err != nil {
			t.Fatalf("write %#x frame: %v", tc.typ, err)
		}
		bbr := bufio.NewReader(bpeer)
		_ = bpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, _, err := readTDSFrame(bbr)
		_ = bpeer.SetReadDeadline(time.Time{})
		if err != nil || !bytes.Equal(got[:], frame) {
			t.Fatalf("%#x forwarded = % x err=%v, want byte-exact", tc.typ, got, err)
		}
		r := mustRecord(t, cap, "query")
		if r["sql"] != tc.name || r["kind"] != "control" || r["status"] != "ok" {
			t.Errorf("%#x record = %v, want control/ok/%s", tc.typ, r, tc.name)
		}
		cap.buf.Reset()
	}
	cpeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit")
	}
	assertNoSensitiveKeys(t, cap)
}

// --- GAP 5: rejection-logging parity (publishBlocked everywhere) -------------

// assertRejectedRecord asserts the "query" log record of a rejected command:
// status=error, the block message, and the classified SQL.
func assertRejectedRecord(t *testing.T, c *logCapture, wantSQL, wantErrSub string) {
	t.Helper()
	r := mustRecord(t, c, "query")
	if r["status"] != "error" {
		t.Errorf("rejection record status = %v, want error", r["status"])
	}
	if err, _ := r["error"].(string); !strings.Contains(err, wantErrSub) {
		t.Errorf("rejection record error = %v, want it to contain %q", r["error"], wantErrSub)
	}
	if sql, _ := r["sql"].(string); !strings.Contains(sql, wantSQL) {
		t.Errorf("rejection record sql = %v, want it to contain %q", r["sql"], wantSQL)
	}
}

// TestMySQLRelayRejectionsLogErrors: all THREE mysql rejection sites log a
// status=error query line through the real relay pipe — read-only, frozen
// (re-lock), and the maker write-gate.
func TestMySQLRelayRejectionsLogErrors(t *testing.T) {
	t.Run("read-only", func(t *testing.T) {
		cap := newLogCapture()
		vs := proxyTestStore(t)
		p := NewMySQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
		client, cpeer := net.Pipe()
		backend, bpeer := net.Pipe()
		defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
		s := &mysqlSession{id: "sid-task10-ro", db: "appdb", access: "ro", client: client, backend: backend, closer: func() {}}
		cleanupLiveRecord(t, vs, s.id)
		tok := task10Tok("mysql")

		done := make(chan struct{})
		go func() {
			p.pipeClientToBackend(bufio.NewReader(client), backend, client, s, tok, "127.0.0.1:5")
			close(done)
		}()
		q := append([]byte{cmdQuery}, []byte("INSERT INTO demo_items VALUES (1)")...)
		if err := writeMySQLPacket(cpeer, 0, q); err != nil {
			t.Fatalf("write INSERT: %v", err)
		}
		cbr := bufio.NewReader(cpeer)
		_ = cpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, pkt, err := readMySQLPacket(cbr)
		_ = cpeer.SetReadDeadline(time.Time{})
		if err != nil || len(pkt) == 0 || pkt[0] != 0xff {
			t.Fatalf("ro rejection reply = % x err=%v, want ERR packet", pkt, err)
		}
		cpeer.Close()
		<-done
		assertRejectedRecord(t, cap, "INSERT INTO demo_items", "read-only session")
		assertNoSensitiveKeys(t, cap)
	})

	t.Run("frozen", func(t *testing.T) {
		cap := newLogCapture()
		vs := proxyTestStore(t)
		ctx := context.Background()
		p := NewMySQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
		client, cpeer := net.Pipe()
		backend, bpeer := net.Pipe()
		defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
		sid := "sid-task10-frozen"
		s := &mysqlSession{id: sid, db: "appdb", access: "rw", holdAdmitted: true, client: client, backend: backend,
			tok:    &models.TokenPayload{Username: "task10", DBUser: "rw_user", DBType: "mysql", SessionID: sid, Access: "rw"},
			closer: func() {}}
		cleanupLiveRecord(t, vs, sid)
		t.Cleanup(func() {
			p.unregisterSession(sid)
			_ = vs.DelSessionLive(ctx, sid)
		})
		p.registerSession(s)

		if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
			t.Fatal("HandleRelock = false, want frozen")
		}
		done := make(chan struct{})
		go func() {
			p.pipeClientToBackend(bufio.NewReader(client), backend, client, s, s.tok, "127.0.0.1:6")
			close(done)
		}()
		q := append([]byte{cmdQuery}, []byte("DELETE FROM demo_items")...)
		if err := writeMySQLPacket(cpeer, 0, q); err != nil {
			t.Fatalf("write DELETE: %v", err)
		}
		cbr := bufio.NewReader(cpeer)
		_ = cpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, pkt, err := readMySQLPacket(cbr)
		_ = cpeer.SetReadDeadline(time.Time{})
		if err != nil || len(pkt) == 0 || pkt[0] != 0xff {
			t.Fatalf("frozen rejection reply = % x err=%v, want ERR packet", pkt, err)
		}
		cpeer.Close()
		<-done
		assertRejectedRecord(t, cap, "DELETE FROM demo_items", "maker gating")
		assertNoSensitiveKeys(t, cap)
	})

	t.Run("gate", func(t *testing.T) {
		cap := newLogCapture()
		vs := proxyTestStore(t)
		p := NewMySQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
		client, cpeer := net.Pipe()
		backend, bpeer := net.Pipe()
		defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
		s := &mysqlSession{id: "sid-task10-gate", db: "appdb", access: "write", client: client, backend: backend, closer: func() {}}
		cleanupLiveRecord(t, vs, s.id)
		tok := task10Tok("mysql")

		done := make(chan struct{})
		go func() {
			p.pipeClientToBackend(bufio.NewReader(client), backend, client, s, tok, "127.0.0.1:7")
			close(done)
		}()
		q := append([]byte{cmdQuery}, []byte("UPDATE demo_items SET name = 'x'")...)
		if err := writeMySQLPacket(cpeer, 0, q); err != nil {
			t.Fatalf("write UPDATE: %v", err)
		}
		cbr := bufio.NewReader(cpeer)
		_ = cpeer.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, pkt, err := readMySQLPacket(cbr)
		_ = cpeer.SetReadDeadline(time.Time{})
		if err != nil || len(pkt) == 0 || pkt[0] != 0xff {
			t.Fatalf("gate rejection reply = % x err=%v, want ERR packet", pkt, err)
		}
		cpeer.Close()
		<-done
		assertRejectedRecord(t, cap, "UPDATE demo_items", "maker gating")
		assertNoSensitiveKeys(t, cap)
	})
}

// TestPGRejectPublishesBlocked: every PG rejection site funnels through
// gatePGReject → publishBlocked — gate, read-only and frozen rejections all
// emit a status=error query line.
func TestPGRejectPublishesBlocked(t *testing.T) {
	cases := []struct {
		name       string
		access     string
		freeze     bool
		blockFn    func(p *PGProxy, s *pgSession) string
		wantErrSub string
	}{
		{"gate", "write", false, func(p *PGProxy, s *pgSession) string { return gatingMessage(s.id) }, "maker gating"},
		{"read-only", "ro", false, func(p *PGProxy, s *pgSession) string { return readOnlyMessage(s.id) }, "read-only session"},
		{"frozen", "rw", true, func(p *PGProxy, s *pgSession) string { return p.relockPGBlockMsg(s) }, "maker gating"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap := newLogCapture()
			vs := proxyTestStore(t)
			p := NewPGProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
			s := &pgSession{id: "sid-task10-pg-rej-" + tc.name, db: "appdb", access: tc.access, holdAdmitted: true,
				tok:    &models.TokenPayload{Username: "task10", DBUser: "rw_user", DBType: "postgres", SessionID: "sid-task10-pg-rej-" + tc.name, Access: tc.access},
				closer: func() {}}
			cleanupLiveRecord(t, vs, s.id)
			tok := task10Tok("postgres")
			cache := newStmtCache()
			if tc.freeze {
				p.registerSession(s) // HandleRelock freezes REGISTERED hold-admitted rw sessions
				t.Cleanup(func() { p.unregisterSession(s.id) })
			}

			var out bytes.Buffer
			be := pgproto3.NewBackend(pgproto3.NewChunkReader(&out), &out)
			p.sniffPGMessage(&pgproto3.Query{String: "INSERT INTO demo_items VALUES (1)"}, cache, s, tok, "127.0.0.1:8")
			if tc.freeze {
				if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + s.id + `"}`)) {
					t.Fatal("HandleRelock = false, want frozen")
				}
			}
			msg := tc.blockFn(p, s)
			if msg == "" {
				t.Fatal("block decision = empty, want a block message")
			}
			p.gatePGReject(be, &pgproto3.Query{String: "INSERT INTO demo_items VALUES (1)"}, s, msg)

			assertRejectedRecord(t, cap, "INSERT INTO demo_items", tc.wantErrSub)
			if ev := s.pendingEvent(); ev != nil {
				t.Errorf("rejection left a pending event: %+v", ev)
			}
			assertNoSensitiveKeys(t, cap)
		})
	}
}

// TestMSSQLRejectPublishesBlocked: every TDS rejection site funnels through
// gateMSSQLReject → publishBlocked — gate, read-only and frozen rejections
// all emit a status=error query line.
func TestMSSQLRejectPublishesBlocked(t *testing.T) {
	cases := []struct {
		name       string
		access     string
		freeze     bool
		blockFn    func(p *MSSQLProxy, s *mssqlSession) string
		wantErrSub string
	}{
		{"gate", "write", false, func(p *MSSQLProxy, s *mssqlSession) string { return gatingMessage(s.id) }, "maker gating"},
		{"read-only", "ro", false, func(p *MSSQLProxy, s *mssqlSession) string { return readOnlyMessage(s.id) }, "read-only session"},
		{"frozen", "rw", true, func(p *MSSQLProxy, s *mssqlSession) string { return p.relockMSSQLBlockMsg(s) }, "maker gating"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap := newLogCapture()
			vs := proxyTestStore(t)
			p := NewMSSQLProxy(cap.logger(), vs, &ConfigCredResolver{}, nil)
			client, cpeer := net.Pipe()
			sid := "sid-task10-mssql-rej-" + tc.name
			s := &mssqlSession{id: sid, db: "appdb", access: tc.access, holdAdmitted: true, client: client,
				tok: &models.TokenPayload{Username: "task10", DBUser: "rw_user", DBType: "mssql", SessionID: sid, Access: tc.access}}
			cleanupLiveRecord(t, vs, sid)
			t.Cleanup(func() { cpeer.Close(); client.Close() })
			tok := task10Tok("mssql")
			if tc.freeze {
				p.registerSession(s) // HandleRelock freezes REGISTERED hold-admitted rw sessions
				t.Cleanup(func() { p.unregisterSession(sid) })
			}

			payload := append(append([]byte(nil), allHeaders22...), utf16le("INSERT INTO demo_items VALUES (1)")...)
			p.sniffMSSQLCommand(tdsSQLBatch, payload, s, tok, "127.0.0.1:9")
			if tc.freeze {
				if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
					t.Fatal("HandleRelock = false, want frozen")
				}
			}
			msg := tc.blockFn(p, s)
			if msg == "" {
				t.Fatal("block decision = empty, want a block message")
			}
			// Drain the ERROR-token reply concurrently: gateMSSQLReject's
			// write blocks on the unbuffered net.Pipe until it is read.
			reply := make(chan []byte, 1)
			go func() {
				cbr := bufio.NewReader(cpeer)
				_, resp, err := readTDSMessage(cbr)
				if err == nil {
					reply <- resp
				}
				close(reply)
			}()
			p.gateMSSQLReject(client, s, msg)
			select {
			case resp := <-reply:
				if msgText := extractErrorMsg(resp); !strings.Contains(msgText, tc.wantErrSub) {
					t.Errorf("reject reply MsgText = %q, want it to contain %q", msgText, tc.wantErrSub)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no reject reply within 2s")
			}

			assertRejectedRecord(t, cap, "INSERT INTO demo_items", tc.wantErrSub)
			if ev := s.pendingEvent(); ev != nil {
				t.Errorf("rejection left a pending event: %+v", ev)
			}
			assertNoSensitiveKeys(t, cap)
		})
	}
}
