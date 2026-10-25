package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"zerotrust-proxy/internal/models"
)

// pipeClientToBackend: read client packets, sniff SQL, gate (Task 8.6),
// relay byte-exact. br must be the same buffered reader used during
// protocol detection. client is the session's client conn — the target for
// the maker write-gate's synthesized ERR replies.
func (p *MySQLProxy) pipeClientToBackend(br *bufio.Reader, backend, client net.Conn, s *mysqlSession, tok *models.TokenPayload, clientAddr string) {
	for {
		seq, payload, err := readMySQLPacket(br)
		if err != nil {
			return
		}
		if len(payload) > 0 {
			p.sniffCommand(s, payload[0], payload[1:], tok, clientAddr)
		}
		// Task 9 (node-integration) RE-LOCK freeze: a frozen (re-locked)
		// session rejects EVERY client command with the same gating error
		// and forwards NOTHING — checked before the write gate, since the
		// freeze applies to reads too (owner decision 1). The reply is the
		// well-formed ERR 1045 the pre-8.13 gated writer saw; the
		// backend→client direction keeps draining in its own pipe. The
		// freeze does NOT queue (no grace-hold semantics): the maker
		// re-sends after re-admission.
		if len(payload) > 0 {
			if msg := p.relockBlockMsg(s); msg != "" {
				s.writeMu.Lock() // serialize with drain replies (Task 9.10)
				_ = writeMySQLPacket(client, seq+1, errPacket(1045, "42000", msg))
				s.writeMu.Unlock()
				p.publishBlocked(s, msg)
				continue
			}
		}
		// Task 8.6 maker write-gate: check BEFORE forwarding, per command
		// (never cached), fail-closed. A blocked command is answered with
		// ERR 1045 to the CLIENT and NOT forwarded — the backend never sees
		// it — and the sniffed event is published immediately as status=error
		// so the audit trail shows the block. Task 8.13 grace hold: with
		// gate_wait_seconds > 0 a blocked command is QUEUED instead (no reply,
		// no forward) — the client keeps waiting for a watcher (the queue
		// flushes in order) or for the window to expire (drain). Task 8.17:
		// a drain does NOT latch — a re-attached watcher re-opens the gate.
		if len(payload) > 0 {
			if msg := p.checkWriteGate(s, payload[0]); msg != "" {
				if p.gateHold(s, seq, payload) {
					continue
				}
				s.writeMu.Lock() // serialize with drain replies (Task 9.10)
				_ = writeMySQLPacket(client, seq+1, errPacket(1045, "42000", msg))
				s.writeMu.Unlock()
				p.publishBlocked(s, msg)
				continue
			}
		}
		// Task 6 (node-integration) TRUE read-only: on a ro session EVERY write
		// SQL command is rejected AT THE PROXY — never forwarded, no checker
		// involvement. Text classification over the sniffed copy; the block
		// reply mirrors the write-gate's ERR shape. COM_INIT_DB (USE) is schema
		// flow control, not data — it flows.
		if len(payload) > 0 && s.access == "ro" {
			var sqlText string
			switch payload[0] {
			case cmdQuery, cmdPrepare:
				sqlText = trimSniffedSQL(payload[1:])
			case cmdExecute:
				sqlText = "EXECUTE" // prepared exec — fail-safe: blocked
			}
			if sqlText != "" && isWriteSQLMySQL(sqlText) {
				msg := readOnlyMessage(s.id)
				s.writeMu.Lock() // serialize with drain replies (Task 9.10)
				_ = writeMySQLPacket(client, seq+1, errPacket(1045, "42000", msg))
				s.writeMu.Unlock()
				p.publishBlocked(s, msg)
				p.metrics.GateBlocks("mysql")
				continue
			}
		}
		s.writeMu.Lock() // serialize with the gate flush (Task 9.10)
		err = writeMySQLPacket(backend, seq, payload)
		s.writeMu.Unlock()
		if err != nil {
			return
		}
	}
}

// pipeBackendToClient: relay backend packets byte-exact (original seq
// preserved), feeding each payload to the session's response capture BEFORE
// the write (bytes are only inspected, never modified). When the capture
// completes — OK/ERR packet or the EOF that ends a result set — the pending
// event is published with the response status and captured result.
//
// Task 10 (node-integration): each payload ALSO feeds notePrepareResponse —
// a COM_STMT_PREPARE's OK response carries the assigned stmt_id, hooking the
// sniffed prepare SQL to it so COM_STMT_EXECUTE can log the real statement.
func (p *MySQLProxy) pipeBackendToClient(backend, client net.Conn, s *mysqlSession) {
	for {
		seq, payload, err := readMySQLPacket(backend)
		if err != nil {
			return
		}
		p.notePrepareResponse(s, payload)
		s.mu.Lock()
		c := s.capture
		c.feed(payload)
		done := c.done()
		s.mu.Unlock()
		s.writeMu.Lock() // serialize with gate drain replies (Task 9.10)
		err = writeMySQLPacket(client, seq, payload)
		s.writeMu.Unlock()
		if err != nil {
			return
		}
		if done {
			p.publishPending(s, c)
		}
	}
}

// trimSniffedSQL strips the NUL terminator that real clients append to
// COM_QUERY/COM_INIT_DB/COM_STMT_PREPARE payloads (plus any whitespace after
// it) from the SNIFFED copy only. The relayed payload bytes are never touched
// — the relay is byte-exact; this affects solely the published event text.
func trimSniffedSQL(body []byte) string {
	s := string(body)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, " \t\r\n")
}

// sniffCommand extracts SQL text from command payloads and stashes the event
// as the session's pending event — publication happens when the backend's
// response completes (pipeBackendToClient → publishPending), carrying the
// response status and any captured result set.
//
// Task 10 (node-integration): COM_STMT_EXECUTE resolves its SQL through the
// session's stmt cache (prepared → stmt_id mapping), logging the REAL
// statement when known. Non-SQL control commands (COM_PING, COM_QUIT,
// COM_STATISTICS, …) are logged kind=control FIRE-AND-FORGET — published
// immediately with status=ok, no pending event awaiting the backend.
func (p *MySQLProxy) sniffCommand(s *mysqlSession, cmd byte, body []byte, tok *models.TokenPayload, clientAddr string) {
	var kind, sql string
	switch cmd {
	case cmdQuery:
		kind, sql = "query", redactSQL(trimSniffedSQL(body))
	case cmdInitDB:
		kind, sql = "use", redactSQL("USE "+trimSniffedSQL(body))
	case cmdPrepare:
		kind, sql = "prepare", redactSQL(trimSniffedSQL(body))
	case cmdExecute:
		kind = "execute"
		if len(body) >= 4 {
			stmtID := binary.LittleEndian.Uint32(body)
			if cached, ok := s.stmtCacheLookup(stmtID); ok {
				sql = "EXECUTE " + cached
			} else {
				sql = fmt.Sprintf("EXECUTE stmt_id=%d", stmtID)
			}
		} else {
			sql = "EXECUTE stmt_id=?"
		}
	case 0x19: // COM_STMT_CLOSE: drop the cached SQL (no event)
		if len(body) >= 4 {
			s.stmtCacheEvict(binary.LittleEndian.Uint32(body))
		}
		return
	case cmdPing, cmdQuit, cmdStatistics, 0x0a, 0x0c, 0x0d, 0x11, 0x12, 0x13, 0x14, 0x15, 0x1a:
		// COM_PING(0x0e) COM_QUIT(0x01) COM_STATISTICS(0x09) COM_PROCESS_INFO(0x0a)
		// COM_PROCESS_KILL(0x0c) COM_DEBUG(0x0d) COM_CHANGE_USER(0x11)
		// COM_BINLOG_DUMP(0x12) COM_TABLE_DUMP(0x13) COM_CONNECT_OUT(0x14)
		// COM_REGISTER_SLAVE(0x15) COM_STMT_FETCH(0x1a) — fixed names only,
		// never payload bytes (the map lookup guards unmapped codes).
		kind, sql = "control", mysqlCommandNames[cmd]
		if sql == "" {
			return
		}
		p.publishControl(s, tok, clientAddr, sql)
		return
	default:
		return
	}
	ev := models.QueryEvent{
		ID:         newEventID(),
		Ts:         time.Now().UTC(),
		Kind:       kind,
		Username:   tok.Username,
		TicketID:   tok.TicketID,
		DBUser:     tok.DBUser,
		DBIP:       tok.DBIP,
		DBPort:     tok.DBPort,
		DBType:     tok.DBType, // verbatim from the session's token: mysql OR mariadb
		DB:         s.db,
		SQL:        sql,
		ClientAddr: clientAddr,
		StmtType:   classifyStmt(sql),
		SessionID:  s.id,
	}
	s.mu.Lock()
	s.pending = &ev
	s.capture = &resultCapture{}
	s.mu.Unlock()
}

// mysqlCommandNames maps the non-SQL control commands to their fixed log
// names (Task 10): only fixed strings are logged — never payload bytes.
// COM_RESET_CONNECTION (0x1f) and COM_STMT_CLOSE (0x19) deliberately publish
// nothing (0x19 evicts the stmt cache instead).
var mysqlCommandNames = map[byte]string{
	0x01: "QUIT", 0x09: "STATISTICS", 0x0a: "PROCESS_INFO",
	0x0c: "PROCESS_KILL", 0x0d: "DEBUG", 0x0e: "PING",
	0x11: "CHANGE_USER", 0x12: "BINLOG_DUMP", 0x13: "TABLE_DUMP",
	0x14: "CONNECT_OUT", 0x15: "REGISTER_SLAVE", 0x1a: "STMT_FETCH",
}

const (
	cmdPing       = 0x0e
	cmdQuit       = 0x01
	cmdStatistics = 0x09
)

// stmtCacheLookup returns the redacted SQL prepared under stmt_id (Task 10).
func (s *mysqlSession) stmtCacheLookup(stmtID uint32) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sql, ok := s.stmtCache[stmtID]
	return sql, ok
}

// stmtCacheEvict drops the stmt_id mapping (COM_STMT_CLOSE).
func (s *mysqlSession) stmtCacheEvict(stmtID uint32) {
	s.mu.Lock()
	delete(s.stmtCache, stmtID)
	s.mu.Unlock()
}

// notePrepareResponse (Task 10) reads a backend→client packet and, when it
// is a COM_STMT_PREPARE response (12-byte OK carrying stmt_id/num_columns/
// num_params), binds the currently-sniffed prepare SQL to that stmt_id — so
// a later COM_STMT_EXECUTE logs the real statement. A FAILED prepare (ERR
// packet) clears the pending slot without caching anything. Called from the
// backend→client relay pipe; never alters the forwarded bytes (G3).
func (p *MySQLProxy) notePrepareResponse(s *mysqlSession, payload []byte) {
	if len(payload) < 12 || payload[0] != 0x00 {
		if len(payload) > 0 && payload[0] == 0xff {
			// Prepare rejected by the backend: drop the sniffed prepare so a
			// later stmt_id can never inherit its SQL.
			s.mu.Lock()
			if s.pending != nil && s.pending.Kind == "prepare" {
				s.pending = nil
				s.capture = nil
			}
			s.mu.Unlock()
		}
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.Kind != "prepare" {
		return
	}
	stmtID := binary.LittleEndian.Uint32(payload[1:5])
	if s.stmtCache == nil {
		s.stmtCache = make(map[uint32]string)
	}
	// The pending SQL is ALREADY redacted (sniffCommand ran redactSQL) —
	// G2 holds for the cache too.
	s.stmtCache[stmtID] = s.pending.SQL
}

// sqlExecCommands are the MySQL client commands that execute SQL on the
// backend — the maker write-gate's gated set (Task 8.6): COM_QUERY,
// COM_STMT_PREPARE, COM_STMT_EXECUTE. COM_INIT_DB (USE) changes only the
// default schema and is deliberately not gated.
func isSQLExecCommand(cmd byte) bool {
	return cmd == cmdQuery || cmd == cmdPrepare || cmd == cmdExecute
}

// gatingMessage is the maker write-gate block text shown to the client and
// recorded in the audit event.
func gatingMessage(sid string) string {
	return fmt.Sprintf("maker gating: no checker connected to session %s", sid)
}

// readOnlyMessage is the Task 6 TRUE-read-only block text: a ro session's
// write command is rejected with this message (no checker involvement).
func readOnlyMessage(sid string) string {
	return fmt.Sprintf("read-only session: write commands are rejected by the gateway (session %s)", sid)
}

// checkWriteGate implements the Task 8.6 maker write-gate decision: a
// SQL-executing command on a write-access session is allowed only while a
// checker watches the session (EXISTS watch:<sid>). Returns "" when the
// command may proceed; otherwise the block message. The check runs PER
// COMMAND — never cached — and FAILS CLOSED: a store error blocks the
// command exactly like an absent watcher (the error is logged).
func (p *MySQLProxy) checkWriteGate(s *mysqlSession, cmd byte) string {
	if s.access != "write" || !isSQLExecCommand(cmd) {
		return ""
	}
	// Bounded store call (review 2026-08-17): a hung valkey must not pin
	// the client→backend read loop — the command is blocked (fail closed)
	// after storeCallTimeout, exactly like an absent watcher.
	ctx, cancel := storeCallCtx()
	defer cancel()
	watched, err := p.vs.WatchActive(ctx, s.id)
	if err != nil {
		p.log.Error("watch check failed — fail closed", "session_id", s.id, "err", err)
		return gatingMessage(s.id)
	}
	if !watched {
		return gatingMessage(s.id)
	}
	return ""
}

// relockBlockMsg is the Task 9 re-lock freeze decision (checked BEFORE the
// write gate): a FROZEN session rejects EVERY client command — read or
// write, SQL-exec or not — with the SAME gating error the write gate uses
// (the pre-8.13 gated-writer failure mode, owner decision 1), and the relay
// must NOT forward it. Returns "" when the session may proceed. The flag is
// read under its own mutex — the freeze lands from the ctl:relock
// subscriber goroutine at any moment.
func (p *MySQLProxy) relockBlockMsg(s *mysqlSession) string {
	if s.relock.isFrozen() {
		return gatingMessage(s.id)
	}
	return ""
}
