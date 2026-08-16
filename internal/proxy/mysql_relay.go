package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
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

// publishBlocked publishes the session's pending event immediately with
// status=error and the gating message (Task 8.6): a command blocked by the
// maker write-gate never reaches the backend, so no backend response will
// ever complete the pending capture — the audit trail must still show the
// block. The pending slot is cleared so the next command starts fresh.
func (p *MySQLProxy) publishBlocked(s *mysqlSession, msg string) {
	s.mu.Lock()
	ev := s.pending
	s.pending = nil
	s.capture = nil
	s.mu.Unlock()
	if ev == nil {
		return
	}
	ev.Status = "error"
	ev.Error = msg
	p.metrics.GateBlocks(ev.DBType)
	p.metrics.QueriesTotal(ev.DBType, ev.StmtType, ev.Status)
	p.publishEvent(s, ev)
}

// publishPending attaches the captured response (status/error/columns/rows/
// truncated) to the session's pending event, publishes it to
// queries:<username> and queries:ticket:<ticket_id> (when present), and
// clears the slot for the next command. capture must be the resultCapture
// whose completion triggered this publish; the data is attached ONLY when it
// is still the session's current capture (pointer identity) — never a stale
// capture from a previous command. When a newer command was sniffed in
// between (or nothing is pending at all), nothing is published — no-op for
// non-sniffed commands and stray packets after completion.
func (p *MySQLProxy) publishPending(s *mysqlSession, capture *resultCapture) {
	s.mu.Lock()
	ev := s.pending
	if ev != nil && capture != nil && s.capture == capture {
		ev.Status = capture.status
		ev.Error = capture.errorMsg
		ev.Columns = capture.columns
		ev.Rows = capture.rows
		ev.Truncated = capture.truncated
		s.pending = nil
		s.capture = nil
	} else {
		ev = nil // stale capture or nothing pending: publish nothing
	}
	s.mu.Unlock()
	if ev != nil {
		// Task 9.8: one query event = one queries.total increment, with
		// the command's latency (sniffed → response completed) recorded
		// on the query.duration histogram.
		p.metrics.QueriesTotal(ev.DBType, ev.StmtType, ev.Status)
		p.metrics.QueryDuration(ev.DBType, time.Since(ev.Ts))
		p.publishEvent(s, ev)
	}
}

// publishEvent publishes a QueryEvent to queries:<username>,
// queries:ticket:<ticket_id> (when present) AND — Task 8.2 — the session's
// own channel queries:sess:<session_id>. It also re-arms the session-directory
// heartbeat (SetSessionLive with a fresh last_seen), so an active session
// stays listed while its queries flow. Best-effort: failures are logged by
// the store, never fatal to the relay. Lifecycle events (started/ended) go
// through publishLifecycle instead — they must NOT re-create the record
// after DelSessionLive, and they deliberately skip the ticket channel.
func (p *MySQLProxy) publishEvent(s *mysqlSession, ev *models.QueryEvent) {
	raw, _ := json.Marshal(ev)
	ctx := context.Background()
	_ = p.vs.Publish(ctx, "queries:"+ev.Username, raw)
	if ev.TicketID != "" {
		_ = p.vs.Publish(ctx, "queries:ticket:"+ev.TicketID, raw)
	}
	_ = p.vs.Publish(ctx, "queries:sess:"+ev.SessionID, raw)
	s.mu.Lock()
	s.lastSeen = time.Now().UTC()
	rec := buildSessionRecord(s.id, ev.Username, ev.DBUser, ev.DBType, s.db, s.threadID, s.startedAt, s.lastSeen, "active")
	s.mu.Unlock()
	_ = p.vs.SetSessionLive(ctx, s.id, rec, sessionLiveTTL)
	// Task 8.8 query logging: every published query event is logged with
	// full context (never the token value — the event carries no token).
	// The captured result payload (columns/row_count/rows/truncated) is
	// added ONLY when log_query_output is on; rows are already capped by
	// the capture (100 rows/512 chars/64KB). Blocked write-gate events
	// (Task 8.6) flow through here too, carrying status=error + the gating
	// message — the audit trail shows the block in the log as well.
	attrs := []any{
		"username", ev.Username, "ticket_id", ev.TicketID,
		"db_user", ev.DBUser, "db", ev.DB, "db_type", ev.DBType,
		"stmt_type", ev.StmtType, "status", ev.Status,
		"session_id", ev.SessionID, "sql", ev.SQL,
	}
	if p.logQueryOutput {
		attrs = append(attrs,
			"columns", ev.Columns, "row_count", len(ev.Rows),
			"rows", ev.Rows, "truncated", ev.Truncated)
	}
	p.log.Info("query", attrs...)
}

// refreshSessionLive writes (or refreshes) the session's directory record —
// sess:live:<sid> with the heartbeat TTL — stamping a fresh last_seen. Called
// at session start and (via publishEvent) on every published query event.
// Best-effort: failures are logged by the store, never fatal to the session.
func (p *MySQLProxy) refreshSessionLive(s *mysqlSession, tok *models.TokenPayload) {
	s.mu.Lock()
	s.lastSeen = time.Now().UTC()
	rec := buildSessionRecord(s.id, tok.Username, tok.DBUser, tok.DBType, s.db, s.threadID, s.startedAt, s.lastSeen, "active")
	s.mu.Unlock()
	_ = p.vs.SetSessionLive(context.Background(), s.id, rec, sessionLiveTTL)
}

// publishLifecycle publishes a session lifecycle event (Kind=session,
// Action=started|ended) to queries:<username> AND queries:sess:<sid>. Lifecycle
// events deliberately do NOT go to the ticket channel — ticket grouping is
// about query activity, not connection presence.
func (p *MySQLProxy) publishLifecycle(s *mysqlSession, tok *models.TokenPayload, action, clientAddr string) {
	ev := models.QueryEvent{
		ID:         newEventID(),
		Ts:         time.Now().UTC(),
		Kind:       "session",
		Action:     action,
		Username:   tok.Username,
		DBUser:     tok.DBUser,
		DBType:     tok.DBType,
		DB:         s.db,
		SessionID:  s.id,
		ClientAddr: clientAddr,
	}
	raw, _ := json.Marshal(ev)
	ctx := context.Background()
	_ = p.vs.Publish(ctx, "queries:"+ev.Username, raw)
	_ = p.vs.Publish(ctx, "queries:sess:"+s.id, raw)
	// Task 8.8 lifecycle logging: same context fields as the query line,
	// minus sql (lifecycle events carry none). ticket_id comes from the
	// TOKEN directly — the lifecycle WIRE event deliberately carries no
	// ticket id (Task 8.2: ticket grouping is query activity only), but
	// the log line is part of the query-logging context. No credentials,
	// ever.
	p.log.Info("session "+action, "username", ev.Username, "ticket_id", tok.TicketID,
		"db_user", ev.DBUser, "db", ev.DB, "db_type", ev.DBType, "session_id", ev.SessionID)
}

// finishSession removes the session from the directory (DelSessionLive) and
// publishes the ended lifecycle event. Deferred in handleConn AFTER
// flushPendingOnClose so the ended event is always the session's last word on
// the wire — and the record is deleted only after any final query event
// re-armed the heartbeat.
func (p *MySQLProxy) finishSession(s *mysqlSession, tok *models.TokenPayload, clientAddr string) {
	_ = p.vs.DelSessionLive(context.Background(), s.id)
	p.publishLifecycle(s, tok, "ended", clientAddr)
}

// flushPendingOnClose publishes any still-pending event as failed when the
// session dies before the backend answered (both relay exit paths; invoked
// via defer in handleConn, and so also on a Task 6.4 kill).
func (p *MySQLProxy) flushPendingOnClose(s *mysqlSession) {
	s.mu.Lock()
	ev := s.pending
	s.pending = nil
	s.mu.Unlock()
	if ev == nil {
		return
	}
	ev.Status = "error"
	ev.Error = "connection closed before response"
	p.publishEvent(s, ev)
}
