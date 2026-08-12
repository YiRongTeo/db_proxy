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

// pipeClientToBackend: read client packets, sniff SQL, relay byte-exact.
// br must be the same buffered reader used during protocol detection.
func (p *MySQLProxy) pipeClientToBackend(br *bufio.Reader, backend net.Conn, s *mysqlSession, tok *models.TokenPayload, clientAddr string) {
	for {
		seq, payload, err := readMySQLPacket(br)
		if err != nil {
			return
		}
		if len(payload) > 0 {
			p.sniffCommand(s, payload[0], payload[1:], tok, clientAddr)
		}
		if err := writeMySQLPacket(backend, seq, payload); err != nil {
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
		if err := writeMySQLPacket(client, seq, payload); err != nil {
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
		kind, sql = "query", trimSniffedSQL(body)
	case cmdInitDB:
		kind, sql = "use", "USE "+trimSniffedSQL(body)
	case cmdPrepare:
		kind, sql = "prepare", trimSniffedSQL(body)
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
	rec := buildSessionRecord(s.id, ev.Username, ev.DBUser, ev.DBType, s.db, s.threadID, s.startedAt, s.lastSeen)
	s.mu.Unlock()
	if rec != nil {
		_ = p.vs.SetSessionLive(ctx, s.id, rec, sessionLiveTTL)
	}
}

// refreshSessionLive writes (or refreshes) the session's directory record —
// sess:live:<sid> with the heartbeat TTL — stamping a fresh last_seen. Called
// at session start and (via publishEvent) on every published query event.
// Best-effort: failures are logged by the store, never fatal to the session.
func (p *MySQLProxy) refreshSessionLive(s *mysqlSession, tok *models.TokenPayload) {
	s.mu.Lock()
	s.lastSeen = time.Now().UTC()
	rec := buildSessionRecord(s.id, tok.Username, tok.DBUser, tok.DBType, s.db, s.threadID, s.startedAt, s.lastSeen)
	s.mu.Unlock()
	if rec == nil {
		return
	}
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
