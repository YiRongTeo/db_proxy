package proxy

import (
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
)

// stmtCache maps prepared-statement names to their SQL (Parse → Execute).
// The PG protocol splits prepared execution across three messages: Parse
// names a statement, Bind names a portal, Execute runs a portal. libpq and
// psql use the UNNAMED statement/portal (empty names), where the cache
// lookup is exact; the mapping is best-effort for named statements (the
// brief keeps it simple — a portal name rarely equals its statement name).
type stmtCache struct{ m map[string]string }

func newStmtCache() *stmtCache { return &stmtCache{m: map[string]string{}} }

func (c *stmtCache) evict(name string) { delete(c.m, name) }

// pipePGClientToBackend relays client messages, extracting SQL from
// SimpleQuery / Parse / Execute and stashing the session's pending event
// (publication happens when the backend's response completes). Messages are
// decoded by pgproto3 and re-encoded unchanged (Encode is byte-exact for
// every message type pgproto3 supports), so sniffing never alters the
// stream; the alternative — forwarding raw bytes — would fight pgproto3's
// ChunkReader buffering on the client side.
func (p *PGProxy) pipePGClientToBackend(be *pgproto3.Backend, front *pgFrontend,
	s *pgSession, tok *models.TokenPayload, clientAddr string) {
	cache := newStmtCache()
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		p.sniffPGMessage(msg, cache, s, tok, clientAddr)
		// Task 8.6 maker write-gate: check BEFORE forwarding, per message
		// (never cached), fail-closed. A blocked message is answered to the
		// CLIENT (FATAL 28000) and NOT forwarded; the sniffed event is
		// published immediately as status=error so the audit trail shows it.
		// Task 8.13 grace hold: with gate_wait_seconds > 0 a blocked message
		// is QUEUED instead (no reply, no forward) — the client keeps waiting
		// for a watcher (the queue flushes in order) or for the window to
		// expire (drain). Task 8.17: a drain does NOT latch — a re-attached
		// watcher re-opens the gate.
		if blockMsg := p.gatePGBlockMsg(msg, s); blockMsg != "" {
			if p.gatePGHold(msg, s) {
				continue
			}
			p.gatePGReject(be, msg, s, blockMsg)
			continue
		}
		// Task 9.10: while a grace wait is ACTIVE, EVERY message is
		// stalled — extended-protocol messages (Bind/Describe/Sync/Close/
		// Flush) must never overtake the held Parse/Execute messages, or
		// the prepared-statement ordering breaks on the success path. The
		// message is queued exactly like a blocked one; overflow (or a
		// mid-flight flush deactivation) rejects it to the client instead
		// of ever forwarding it past the held queue.
		if p.gatePGHolding(s) {
			if !p.gatePGHold(msg, s) {
				p.gatePGReject(be, msg, s, gatingMessage(s.id))
			}
			continue
		}
		s.writeMu.Lock() // serialize with the gate flush (Task 9.10)
		err = front.f.Send(msg)
		s.writeMu.Unlock()
		if err != nil { // relay unchanged
			return
		}
	}
}

// gatePGHolding reports whether a grace wait is currently active (Task
// 9.10): while it is, the relay stalls every subsequent client message so
// nothing can overtake the held queue.
func (p *PGProxy) gatePGHolding(s *pgSession) bool {
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	return s.gate.active
}

// gatePGBlockMsg implements the Task 8.6 maker write-gate DECISION: a
// SQL-executing message (SimpleQuery 'Q', Parse 'P', Execute 'E') on a
// write-access session is allowed only while a checker watches the session
// (EXISTS watch:<sid>). Returns "" when the message may proceed; otherwise
// the block message. Unwatched (or store error — fail closed) → the 8.6
// gating message. The decision re-evaluates PER MESSAGE (Task 8.17): a
// grace-wait drain does not latch — a re-attached watcher re-opens the gate.
func (p *PGProxy) gatePGBlockMsg(msg pgproto3.FrontendMessage, s *pgSession) string {
	if s.access != "write" {
		return ""
	}
	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.Parse, *pgproto3.Execute:
	default:
		return ""
	}
	// Bounded store call (review 2026-08-17): fail closed after
	// storeCallTimeout on a hung store, never pin the read loop.
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

// gatePGReject sends the Task 8.6 block response for an immediately
// rejected message: ErrorResponse FATAL 28000 with the block message is
// sent to the client; SimpleQuery also gets the trailing ReadyForQuery a
// simple-query response always ends with, and a rejected Sync draws the
// ReadyForQuery that completes an extended-protocol exchange (Task 9.10),
// while other extended-protocol messages (P/B/E) get the bare
// ErrorResponse — the client's Sync (relayed) draws the backend's
// ReadyForQuery. The sniffed event is published immediately as
// status=error. The replies take the session's writeMu (Task 9.10).
func (p *PGProxy) gatePGReject(be *pgproto3.Backend, msg pgproto3.FrontendMessage, s *pgSession, blockMsg string) {
	s.writeMu.Lock()
	_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000", Message: blockMsg})
	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.Sync:
		_ = be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	}
	s.writeMu.Unlock()
	p.publishBlocked(s, blockMsg)
}

// gatePGMessage is the full immediate-path gate (decision + client reply +
// audit): returns true when the message was BLOCKED — the caller must not
// forward it. Used by the relay when the message is NOT held, and by tests
// driving the 8.6 block behavior directly.
func (p *PGProxy) gatePGMessage(be *pgproto3.Backend, msg pgproto3.FrontendMessage, s *pgSession) bool {
	if blockMsg := p.gatePGBlockMsg(msg, s); blockMsg != "" {
		p.gatePGReject(be, msg, s, blockMsg)
		return true
	}
	return false
}

// pipePGBackendToClient relays backend messages back to the client, feeding
// each message's RAW wire bytes (type byte + int32 length including itself
// + payload; Encode is byte-exact) into the session's response capture
// BEFORE the relay write — inspected, never modified. When the capture
// completes (CommandComplete / ErrorResponse / EmptyQueryResponse), the
// pending event is published with the response status and captured result;
// ReadyForQuery is the safety publish point for a still-pending command.
func (p *PGProxy) pipePGBackendToClient(front *pgFrontend, be *pgproto3.Backend, s *pgSession) {
	for {
		msg, err := front.f.Receive()
		if err != nil {
			return
		}
		s.mu.Lock()
		c := s.capture
		if raw, err := msg.Encode(nil); err == nil {
			c.feed(raw)
		}
		done := c.done()
		s.mu.Unlock()
		s.writeMu.Lock() // serialize with gate drain replies (Task 9.10)
		err = be.Send(msg)
		s.writeMu.Unlock()
		if err != nil {
			return
		}
		if done {
			p.publishPending(s, c)
		} else if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			p.publishPendingOnReady(s)
		}
	}
}

// sniffPGMessage classifies one client message and stashes the session's
// pending QueryEvent (with its classified stmt type) for the kinds that
// carry SQL: SimpleQuery → "query", Parse → "prepare" (cached by statement
// name for Execute), Execute → "execute" (resolved through the cache,
// falling back to the portal name). Bind and Close are relayed without
// events (Close evicts the cached statement). Terminate publishes nothing —
// it ends the session through the normal relay teardown (the backend
// closes, the backend→client pipe hits EOF and tears both sides down).
//
// A later sniffed command REPLACES the pending event and starts a fresh
// capture (MySQL-mirror pending semantics — see publishPending).
func (p *PGProxy) sniffPGMessage(msg pgproto3.FrontendMessage, cache *stmtCache,
	s *pgSession, tok *models.TokenPayload, clientAddr string) {
	var kind, sql string
	switch m := msg.(type) {
	case *pgproto3.Query:
		kind, sql = "query", redactSQL(m.String)
	case *pgproto3.Parse:
		kind, sql = "prepare", redactSQL(m.Query)
		cache.m[m.Name] = sql
	case *pgproto3.Execute:
		kind = "execute"
		if s, ok := cache.m[m.Portal]; ok {
			sql = "EXECUTE " + s
		} else {
			sql = "EXECUTE portal=" + m.Portal
		}
	case *pgproto3.Close:
		if m.ObjectType == 'S' {
			cache.evict(m.Name)
		}
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
		DBType:     "postgres",
		DB:         s.db,
		SQL:        sql,
		ClientAddr: clientAddr,
		StmtType:   classifyStmt(sql),
		SessionID:  s.id,
	}
	s.mu.Lock()
	s.pending = &ev
	s.capture = &pgResultCapture{}
	s.mu.Unlock()
}
