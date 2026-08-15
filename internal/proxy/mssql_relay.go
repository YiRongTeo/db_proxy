package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"zerotrust-proxy/internal/models"
)

// readTDSFrame reads one raw TDS packet: the 8-byte header VERBATIM plus
// its payload. The relay forwards header+payload byte-exact (original
// packet id, SPID and window preserved) — readTDSPacket is only for
// messages the proxy itself parses.
func readTDSFrame(br *bufio.Reader) (hdr [8]byte, payload []byte, err error) {
	if _, err = io.ReadFull(br, hdr[:]); err != nil {
		return hdr, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < tdsHeaderLen {
		return hdr, nil, fmt.Errorf("tds: bad packet length %d", length)
	}
	payload = make([]byte, length-tdsHeaderLen)
	if _, err = io.ReadFull(br, payload); err != nil {
		return hdr, nil, err
	}
	return hdr, payload, nil
}

// pipeMSSQLClientToBackend relays client packets byte-exact, sniffing SQL
// batches (0x01) and RPCs (0x03) into the session's pending event BEFORE
// the forward. ATTENTION (0x06), LOGOUT (0x0E) and every other packet type
// pass through untouched. The Task 9.4 maker write-gate slots in here
// (checkWriteGate before the forward, mirroring the MySQL/PG relays).
func (p *MSSQLProxy) pipeMSSQLClientToBackend(br *bufio.Reader, backend, client net.Conn, s *mssqlSession, tok *models.TokenPayload, clientAddr string) {
	for {
		hdr, payload, err := readTDSFrame(br)
		if err != nil {
			return
		}
		p.sniffMSSQLCommand(hdr[0], payload, s, tok, clientAddr)
		if _, err := backend.Write(append(hdr[:], payload...)); err != nil {
			return
		}
	}
}

// pipeMSSQLBackendToClient relays backend packets byte-exact (original
// header preserved), feeding each packet's payload to the session's
// response capture BEFORE the write — bytes are only inspected, never
// modified. When the capture completes (ERROR/DONE_ERROR token, DONE_FINAL,
// or message EOM after a DONE), the pending event is published with the
// response status and captured result.
func (p *MSSQLProxy) pipeMSSQLBackendToClient(backendBR *bufio.Reader, client net.Conn, s *mssqlSession) {
	for {
		hdr, payload, err := readTDSFrame(backendBR)
		if err != nil {
			return
		}
		s.mu.Lock()
		c := s.capture
		c.feed(payload, hdr[1]&tdsStatusEOM != 0)
		done := c.done()
		s.mu.Unlock()
		if _, err := client.Write(append(hdr[:], payload...)); err != nil {
			return
		}
		if done {
			p.publishPending(s, c)
		}
	}
}

// sniffMSSQLCommand extracts SQL text from SQL batch (0x01) and RPC (0x03)
// payloads and stashes the event as the session's pending event —
// publication happens when the backend's response completes
// (pipeMSSQLBackendToClient → publishPending), carrying the response status
// and any captured result set. Batches decode their UTF-16LE SQL text
// (ALL_HEADERS + optional empty client-procname stripped — see
// decodeMSSQLBatch); RPCs are classified by proc name (decodeMSSQLRPC).
// All other packet types (ATTENTION, LOGOUT, …) leave pending untouched.
func (p *MSSQLProxy) sniffMSSQLCommand(typ byte, payload []byte, s *mssqlSession, tok *models.TokenPayload, clientAddr string) {
	var kind, sql string
	switch typ {
	case tdsSQLBatch:
		text, ok := decodeMSSQLBatch(payload)
		if !ok {
			return
		}
		kind, sql = "query", text
	case tdsRPC:
		name, ok := decodeMSSQLRPC(payload)
		if !ok {
			return
		}
		kind, sql = "execute", "EXEC "+name
	default:
		return
	}
	if sql == "" {
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
		DBType:     "mssql",
		DB:         s.db,
		SQL:        sql,
		ClientAddr: clientAddr,
		StmtType:   classifyStmt(sql),
		SessionID:  s.id,
	}
	s.mu.Lock()
	s.pending = &ev
	s.capture = &mssqlResultCapture{}
	s.mu.Unlock()
}

// publishPending attaches the captured response (status/error/columns/rows/
// truncated) to the session's pending event, publishes it to
// queries:<username>, queries:ticket:<ticket_id> (when present) and
// queries:sess:<session_id>, and clears the slot for the next command.
// capture must be the mssqlResultCapture whose completion triggered this
// publish; the data is attached ONLY when it is still the session's current
// capture (pointer identity) — never a stale capture from a previous
// command. When a newer command was sniffed in between (or nothing is
// pending at all), nothing is published — no-op for non-sniffed packets and
// stray traffic after completion.
func (p *MSSQLProxy) publishPending(s *mssqlSession, capture *mssqlResultCapture) {
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
// own channel queries:sess:<session_id>. It also re-arms the
// session-directory heartbeat (SetSessionLive with a fresh last_seen), so
// an active session stays listed while its queries flow. Best-effort:
// failures are logged by the store, never fatal to the relay. Lifecycle
// events (started/ended) go through publishLifecycle instead — they must
// NOT re-create the record after DelSessionLive, and they deliberately skip
// the ticket channel.
func (p *MSSQLProxy) publishEvent(s *mssqlSession, ev *models.QueryEvent) {
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
	if rec != nil {
		_ = p.vs.SetSessionLive(ctx, s.id, rec, sessionLiveTTL)
	}
	// Task 8.8 query logging: every published query event is logged with
	// full context (never the token value — the event carries no token).
	// The captured result payload (columns/row_count/rows/truncated) is
	// added ONLY when log_query_output is on; rows are already capped by
	// the capture (100 rows/512 chars/64KB).
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

// flushPendingOnClose publishes any still-pending event as failed when the
// session dies before the backend answered (both relay exit paths; invoked
// via defer in handleConn, and so also on a Task 6.4 kill).
func (p *MSSQLProxy) flushPendingOnClose(s *mssqlSession) {
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
