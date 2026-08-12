package proxy

import (
	"context"
	"encoding/json"
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
		if err := front.f.Send(msg); err != nil { // relay unchanged
			return
		}
	}
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
		if err := be.Send(msg); err != nil {
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
		kind, sql = "query", m.String
	case *pgproto3.Parse:
		kind, sql = "prepare", m.Query
		cache.m[m.Name] = m.Query
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

// publishPending attaches the captured response (status/error/columns/rows/
// truncated) to the session's pending event, publishes it to
// queries:<username> and queries:ticket:<ticket_id> (when present), and
// clears the slot for the next command. capture must be the pgResultCapture
// whose completion triggered this publish; the data is attached ONLY when
// it is still the session's current capture (pointer identity) — never a
// stale capture from a previous command. When a newer command was sniffed
// in between (or nothing is pending at all), nothing is published — no-op
// for non-sniffed commands and stray packets after completion.
func (p *PGProxy) publishPending(s *pgSession, capture *pgResultCapture) {
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
		p.publishEvent(ev)
	}
}

// publishPendingOnReady is the ReadyForQuery safety net: a command still
// pending at a statement boundary (defensive — every real response ends in
// CommandComplete/ErrorResponse/EmptyQueryResponse, all of which complete
// the capture) is finished as ok and published, so no event is ever left
// dangling across statements.
func (p *PGProxy) publishPendingOnReady(s *pgSession) {
	s.mu.Lock()
	ev := s.pending
	if ev != nil {
		if c := s.capture; c != nil {
			if !c.done() {
				c.finish()
			}
			ev.Status = c.status
			ev.Error = c.errorMsg
			ev.Columns = c.columns
			ev.Rows = c.rows
			ev.Truncated = c.truncated
		}
		s.pending = nil
		s.capture = nil
	}
	s.mu.Unlock()
	if ev != nil {
		p.publishEvent(ev)
	}
}

// publishEvent publishes a QueryEvent to queries:<username> AND
// queries:ticket:<ticket_id> (when present). Best-effort: failures are
// logged by the store, never fatal to the relay.
func (p *PGProxy) publishEvent(ev *models.QueryEvent) {
	raw, _ := json.Marshal(ev)
	ctx := context.Background()
	_ = p.vs.Publish(ctx, "queries:"+ev.Username, raw)
	if ev.TicketID != "" {
		_ = p.vs.Publish(ctx, "queries:ticket:"+ev.TicketID, raw)
	}
}

// flushPendingOnClose publishes any still-pending event as failed when the
// session dies before the backend answered (both relay exit paths; invoked
// via defer in handleConn, and so also on a Task 6.4 kill).
func (p *PGProxy) flushPendingOnClose(s *pgSession) {
	s.mu.Lock()
	ev := s.pending
	s.pending = nil
	s.mu.Unlock()
	if ev == nil {
		return
	}
	ev.Status = "error"
	ev.Error = "connection closed before response"
	p.publishEvent(ev)
}
