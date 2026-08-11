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
// SimpleQuery / Parse / Execute, then publishes QueryEvents. Messages are
// decoded by pgproto3 and re-encoded unchanged (Encode is byte-exact for
// every message type pgproto3 supports), so sniffing never alters the
// stream; the alternative — forwarding raw bytes — would fight pgproto3's
// ChunkReader buffering on the client side.
func (p *PGProxy) pipePGClientToBackend(be *pgproto3.Backend, front *pgFrontend,
	tok *models.TokenPayload, clientAddr string) {
	cache := newStmtCache()
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		p.sniffPGMessage(msg, cache, tok, clientAddr)
		if err := front.f.Send(msg); err != nil { // relay unchanged
			return
		}
	}
}

// pipePGBackendToClient relays backend messages back to the client.
func (p *PGProxy) pipePGBackendToClient(front *pgFrontend, be *pgproto3.Backend) {
	for {
		msg, err := front.f.Receive()
		if err != nil {
			return
		}
		if err := be.Send(msg); err != nil {
			return
		}
	}
}

// sniffPGMessage classifies one client message and publishes a QueryEvent
// for the kinds that carry SQL: SimpleQuery → "query", Parse → "prepare"
// (cached by statement name for Execute), Execute → "execute" (resolved
// through the cache, falling back to the portal name). Bind and Close are
// relayed without events (Close evicts the cached statement). Terminate
// publishes nothing — it ends the session through the normal relay teardown
// (the backend closes, the backend→client pipe hits EOF and tears both sides
// down). Publishing is best-effort: failures are ignored, never fatal.
func (p *PGProxy) sniffPGMessage(msg pgproto3.FrontendMessage, cache *stmtCache,
	tok *models.TokenPayload, clientAddr string) {
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
	}
	raw, _ := json.Marshal(ev)
	ctx := context.Background()
	_ = p.vs.Publish(ctx, "queries:"+tok.Username, raw)
	if tok.TicketID != "" {
		_ = p.vs.Publish(ctx, "queries:ticket:"+tok.TicketID, raw)
	}
}
