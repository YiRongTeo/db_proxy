package proxy

import (
	"encoding/json"
	"time"

	"zerotrust-proxy/internal/metrics"
)

// The data-plane kill contract (two-level kill): force-close a live session
// by id, reporting whether a session was found, or abort ONLY its in-flight
// query, leaving the session alive. All four proxies implement KillSession
// through their per-session registries (the closer closes the client AND
// backend conns, so the relay pipes exit and handleConn tears the session
// down); KillQuery exists on the MySQL/PG/MSSQL planes (no Oracle in-flight
// query abort yet).

// Kill modes for the ctl:kill payload. The mode field is OPTIONAL — absent
// means KillModeConnection, so older publishers keep working unchanged.
const (
	KillModeConnection = "connection"
	KillModeQuery      = "query"
)

// killQueryTimeout bounds ONE kill-query operation: the second backend
// connect plus the KILL QUERY / pg_cancel_backend exchange and its response
// read. The ctl:kill subscriber must never block on a dead backend.
const killQueryTimeout = 10 * time.Second

// mssqlAttnTimeout bounds how long the proxy's ATTENTION ack expectation
// (attnPending) stays armed: the backend normally acks within
// the aborted batch's response, but a dead/hung backend must not poison the
// DONE_ATTN swallow for the rest of the session.
const mssqlAttnTimeout = 10 * time.Second

// Killer fans a ctl:kill request out to the MySQL, PostgreSQL, MSSQL and
// Oracle proxies' registries. Session ids are generated per proxy ("sid-" + random
// hex), so a live session lives on exactly one plane — but the ctl:kill
// subscriber does not know which protocol a session uses, so it
// asks all of them. All are always tried so an (astronomically unlikely) id
// collision on another plane cannot leave a session alive;
// KillSession/KillQuery are fast mutex-guarded map lookups on a miss.
type Killer struct {
	mysql  *MySQLProxy
	pg     *PGProxy
	mssql  *MSSQLProxy  // TDS sessions (kill-query N/A — no ATTENTION wiring)
	oracle *OracleProxy // TNS sessions (kill-query N/A)

	// vs is the store used to DELETE the session token's key
	// when a connection-mode kill lands — revocation converges on "no key
	// = no session": killing once both closes the live conns AND prevents
	// any reconnect (new connections fail the consume, the sweeper closes
	// stragglers). nil (tests) skips the deletion.
	vs Store

	// metrics: kills.total is recorded here — the ctl:kill handler —
	// per APPLIED kill (successful KillSession/KillQuery), by mode.
	// nil = metrics disabled (every call a no-op).
	metrics *metrics.Metrics
}

// SetStore wires the revocation store (the kill path deletes the session
// token's key; nil skips deletion — test-only proxies need not care).
func (k *Killer) SetStore(vs Store) { k.vs = vs }

// TokenForSession returns the raw session-mode token for a registered
// session on ANY plane ("" when unknown or single-use).
func (k *Killer) TokenForSession(id string) (string, bool) {
	if k.mysql != nil {
		if tok, ok := k.mysql.TokenForSession(id); ok && tok != "" {
			return tok, true
		}
	}
	if k.pg != nil {
		if tok, ok := k.pg.TokenForSession(id); ok && tok != "" {
			return tok, true
		}
	}
	if k.mssql != nil {
		if tok, ok := k.mssql.TokenForSession(id); ok && tok != "" {
			return tok, true
		}
	}
	if k.oracle != nil {
		if tok, ok := k.oracle.TokenForSession(id); ok && tok != "" {
			return tok, true
		}
	}
	return "", false
}

func NewKiller(mysql *MySQLProxy, pg *PGProxy, mssql *MSSQLProxy, oracle *OracleProxy) *Killer {
	return &Killer{mysql: mysql, pg: pg, mssql: mssql, oracle: oracle}
}

// SetMetrics wires the OTel instruments. nil (the default — config
// metrics.enabled=false) keeps every instrument call a no-op.
func (k *Killer) SetMetrics(m *metrics.Metrics) { k.metrics = m }

// KillSession tries the MySQL registry first, then the PostgreSQL registry,
// then the MSSQL registry, then the Oracle registry, and reports whether any
// plane had the session.
func (k *Killer) KillSession(id string) bool {
	killed := false
	if k.mysql != nil && k.mysql.KillSession(id) {
		killed = true
	}
	if k.pg != nil && k.pg.KillSession(id) {
		killed = true
	}
	if k.mssql != nil && k.mssql.KillSession(id) {
		killed = true
	}
	if k.oracle != nil && k.oracle.KillSession(id) {
		killed = true
	}
	return killed
}

// KillQuery tries to abort the in-flight query of the session on any plane,
// WITHOUT touching the session itself. Reports whether any plane accepted
// the kill-query — i.e. the session exists, has a captured thread id, and
// the backend acknowledged the abort. Failure reasons are logged by the
// plane's KillQuery (the MSSQL plane refuses — no ATTENTION wiring).
func (k *Killer) KillQuery(id string) bool {
	killed := false
	if k.mysql != nil && k.mysql.KillQuery(id) {
		killed = true
	}
	if k.pg != nil && k.pg.KillQuery(id) {
		killed = true
	}
	if k.mssql != nil && k.mssql.KillQuery(id) {
		killed = true
	}
	return killed
}

// killPayload is the ctl:kill message shape: {session_id, mode}. mode is
// optional — absent means KillModeConnection.
type killPayload struct {
	SessionID string `json:"session_id"`
	Mode      string `json:"mode"`
}

// parseKillPayload decodes a ctl:kill message. ok=false for malformed JSON
// or a missing/empty session_id (the subscriber drops those silently). An
// unknown mode string is NOT a parse error — it round-trips so the caller
// can log "kill: unknown mode" instead of crashing.
func parseKillPayload(msg []byte) (sid, mode string, ok bool) {
	var k killPayload
	if json.Unmarshal(msg, &k) != nil || k.SessionID == "" {
		return "", "", false
	}
	if k.Mode == "" {
		k.Mode = KillModeConnection
	}
	return k.SessionID, k.Mode, true
}

// HandleKill applies ONE ctl:kill message end to end: parse {session_id,
// mode} (mode absent → connection), fan out to
// whichever plane holds the session, and return the outcome log line plus
// the session id — the log vocabulary the ctl:kill subscriber uses:
// "session killed" / "query killed" / "kill: unknown session" / "kill:
// unknown mode". A malformed payload (no session id) returns ("", "") and
// is dropped silently; an unknown mode never crashes.
func (k *Killer) HandleKill(msg []byte) (line, sid string) {
	sid, mode, ok := parseKillPayload(msg)
	if !ok {
		return "", ""
	}
	switch mode {
	case KillModeQuery:
		if k.KillQuery(sid) {
			k.metrics.KillsTotal(KillModeQuery)
			return "query killed", sid
		}
		return "kill: unknown session", sid
	case KillModeConnection:
		// Revoke the token FIRST (idempotent) — no reconnect can
		// re-establish the session — then close the live conns. If
		// the session vanished between lookup and kill, the sweeper
		// closes the straggler within one poll interval anyway.
		if tok, ok := k.TokenForSession(sid); ok && k.vs != nil {
			ctx, cancel := storeCallCtx()
			_ = k.vs.DeleteToken(ctx, tok)
			cancel()
		}
		if k.KillSession(sid) {
			k.metrics.KillsTotal(KillModeConnection)
			return "session killed", sid
		}
		return "kill: unknown session", sid
	default:
		return "kill: unknown mode", sid
	}
}
