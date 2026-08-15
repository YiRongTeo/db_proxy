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

// readTDSMessageFrames reads one logical TDS MESSAGE as its raw frames —
// packets of one type until the EOM status bit, each frame's original
// header + payload preserved. The relay decides per MESSAGE (sniff + Task
// 9.4 write-gate) and forwards the frames in order, so the stream the
// backend sees stays byte-exact for multi-packet messages too.
func readTDSMessageFrames(br *bufio.Reader) (frames []mssqlGateFrame, typ byte, err error) {
	for {
		hdr, payload, err := readTDSFrame(br)
		if err != nil {
			return nil, 0, err
		}
		if typ == 0 {
			typ = hdr[0]
		}
		frames = append(frames, mssqlGateFrame{hdr: hdr, payload: payload})
		if hdr[1]&tdsStatusEOM != 0 {
			return frames, typ, nil
		}
	}
}

// pipeMSSQLClientToBackend relays client messages byte-exact, sniffing SQL
// batches (0x01) and RPCs (0x03) into the session's pending event BEFORE
// the forward. The Task 9.4 maker write-gate slots in here (mirroring the
// MySQL/PG relays): a blocked SQL-executing message on a write-access
// session is answered to the CLIENT (ERROR token + DONE, sqlcmd-readable)
// and NOT forwarded — the backend never sees it — and the sniffed event is
// published immediately as status=error so the audit trail shows the block.
// With gate_wait_seconds > 0 a blocked message is QUEUED instead (no reply,
// no forward): the client keeps waiting for a checker (the queue flushes in
// order) or for the window to expire (drain). A drain does NOT latch (Task
// 8.17): a re-attached watcher re-opens the gate. ATTENTION (0x06), LOGOUT
// (0x0E) and every other packet type pass through untouched. Backend writes
// take the session's writeMu so a concurrent kill-query ATTENTION can never
// interleave mid-message.
func (p *MSSQLProxy) pipeMSSQLClientToBackend(br *bufio.Reader, backend, client net.Conn, s *mssqlSession, tok *models.TokenPayload, clientAddr string) {
	for {
		frames, typ, err := readTDSMessageFrames(br)
		if err != nil {
			return
		}
		// Assemble the message payload for the sniff (single-frame batches
		// — the common case — are unchanged; multi-frame messages parse
		// correctly instead of stalling at the first fragment).
		var payload []byte
		for _, f := range frames {
			payload = append(payload, f.payload...)
		}
		p.sniffMSSQLCommand(typ, payload, s, tok, clientAddr)
		if msg := p.gateMSSQLBlocked(s, typ); msg != "" {
			if p.gateMSSQLHold(s, frames) {
				continue
			}
			p.gateMSSQLReject(client, s, msg)
			continue
		}
		if err := p.forwardMSSQLFrames(s, frames); err != nil {
			return
		}
	}
}

// forwardMSSQLFrames writes a client message's raw frames to the backend in
// order, byte-exact (each frame's original header + payload), under the
// session's writeMu so a concurrent ATTENTION (kill-query) or gate flush
// serializes cleanly.
func (p *MSSQLProxy) forwardMSSQLFrames(s *mssqlSession, frames []mssqlGateFrame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for _, f := range frames {
		if _, err := s.backend.Write(append(f.hdr[:], f.payload...)); err != nil {
			return err
		}
	}
	return nil
}

// gateMSSQLBlocked implements the Task 8.6 maker write-gate DECISION on the
// TDS plane (Task 9.4): a SQL-executing message (SQL batch 0x01, RPC 0x03 —
// NOT the prelogin/login7/attention/logout control types) on a write-access
// session is allowed only while a checker watches the session (EXISTS
// watch:<sid>). Returns "" when the message may proceed; otherwise the
// block message. The check runs PER MESSAGE — never cached — and FAILS
// CLOSED: a store error blocks exactly like an absent watcher (the error is
// logged). A grace-wait drain does not latch (Task 8.17): a re-attached
// watcher re-opens the gate.
func (p *MSSQLProxy) gateMSSQLBlocked(s *mssqlSession, typ byte) string {
	if s.access != "write" || (typ != tdsSQLBatch && typ != tdsRPC) {
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

// gateMSSQLReject sends the Task 9.4 block response for an immediately
// rejected message: a TABULAR RESULT stream with an ERROR token (18456,
// class 14) carrying the block message plus a DONE_ERROR tail — the shape
// sqlcmd renders as "Msg 18456, Level 14, State 1: maker gating: ...". The
// sniffed event is published immediately as status=error (the command never
// reaches the backend, so no backend response will complete the capture).
func (p *MSSQLProxy) gateMSSQLReject(client net.Conn, s *mssqlSession, msg string) {
	_ = writeTDSMessage(client, tdsTabular, buildTDSErrorToken(msg, 18456, 1, 14))
	p.publishMSSQLBlocked(s, msg)
}

// publishMSSQLBlocked publishes the session's pending event immediately with
// status=error and the gating message (Task 9.4, mirroring the MySQL/PG
// publishBlocked): a command blocked by the maker write-gate never reaches
// the backend, so no backend response will ever complete the pending
// capture — the audit trail must still show the block. The pending slot is
// cleared so the next command starts fresh.
func (p *MSSQLProxy) publishMSSQLBlocked(s *mssqlSession, msg string) {
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
	p.publishEvent(s, ev)
}

// pipeMSSQLBackendToClient relays backend packets byte-exact (original
// header preserved), feeding each packet's payload to the session's
// response capture BEFORE the write — bytes are only inspected, never
// modified. When the capture completes (ERROR/DONE_ERROR token, DONE_FINAL,
// or message EOM after a DONE), the pending event is published with the
// response status and captured result.
//
// Task 9.4 round-1 fix — proxy-initiated attention ack swallow: a
// kill-query ATTENTION is answered by the backend with a SEPARATE DONE_ATTN
// acknowledgement message (a TABULAR message carrying ONLY a DONE token
// with the DONE_ATTN status bit — live capture `fd 20 00 …`) that follows
// the aborted batch's DONE_ERROR. The client never asked to cancel, so
// forwarding the ack would corrupt its protocol state: its NEXT batch would
// read the stale ack as its response. While the session's attnPending flag
// is set (KillQuery armed it), such a message is consumed proxy-side —
// never written to the client — and the flag is cleared. Client-initiated
// attentions (their acks arrive with attnPending unset) still pass through
// untouched. The aborted batch's own DONE_ERROR message is not a bare
// DONE_ATTN token stream, so it is relayed normally and completes the
// pending capture as status=error.
func (p *MSSQLProxy) pipeMSSQLBackendToClient(backendBR *bufio.Reader, client net.Conn, s *mssqlSession) {
	for {
		hdr, payload, err := readTDSFrame(backendBR)
		if err != nil {
			return
		}
		// Attention ack swallow: a single-packet TABULAR message that is
		// EXACTLY a DONE token carrying the DONE_ATTN bit (a 13-byte
		// token stream can never span packets). Guarded by attnPending so
		// only proxy-initiated attentions are consumed.
		s.mu.Lock()
		attn := s.attnPending
		s.mu.Unlock()
		if attn && hdr[0] == tdsTabular && hdr[1]&tdsStatusEOM != 0 &&
			len(payload) == 13 && payload[0] == 0xFD &&
			binary.LittleEndian.Uint16(payload[1:3])&tdsDoneAttn != 0 {
			s.mu.Lock()
			s.attnPending = false
			s.mu.Unlock()
			p.log.Info("attention ack swallowed", "session_id", s.id)
			continue
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
