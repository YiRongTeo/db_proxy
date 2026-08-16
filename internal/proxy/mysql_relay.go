package proxy

import (
	"bufio"
	"context"
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
func (p *MySQLProxy) pipeBackendToClient(backend, client net.Conn, s *mysqlSession) {
	for {
		seq, payload, err := readMySQLPacket(backend)
		if err != nil {
			return
		}
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
// response status and any captured result set. Non-sniffed commands
// (COM_PING, COM_QUIT, …) leave pending nil and publish nothing.
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
			sql = fmt.Sprintf("EXECUTE stmt_id=%d", binary.LittleEndian.Uint32(body))
		} else {
			sql = "EXECUTE stmt_id=?"
		}
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
		DBType:     "mysql",
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
	watched, err := p.vs.WatchActive(context.Background(), s.id)
	if err != nil {
		p.log.Error("watch check failed — fail closed", "session_id", s.id, "err", err)
		return gatingMessage(s.id)
	}
	if !watched {
		return gatingMessage(s.id)
	}
	return ""
}
