package proxy

import (
	"encoding/json"
	"time"
)

// SessionKiller is the data-plane kill interface: force-close a live session
// by id, reporting whether a session was found, or abort ONLY its in-flight
// query, leaving the session alive (Task 8.3 two-level kill). Both MySQLProxy
// and PGProxy implement it through their per-session registries (the closer
// closes the client AND backend conns, so the relay pipes exit and handleConn
// tears the session down). Compile-time assertions below pin both
// implementations.
type SessionKiller interface {
	KillSession(id string) bool
	KillQuery(id string) bool
}

var (
	_ SessionKiller = (*MySQLProxy)(nil)
	_ SessionKiller = (*PGProxy)(nil)
	_ SessionKiller = (*Killer)(nil)
)

// Kill modes for the ctl:kill payload (Task 8.3 two-level kill). The mode
// field is OPTIONAL — absent means KillModeConnection, preserving the Task
// 6.4 payload shape ({session_id} only), so older publishers keep working
// unchanged.
const (
	KillModeConnection = "connection"
	KillModeQuery      = "query"
)

// killQueryTimeout bounds ONE kill-query operation: the second backend
// connect plus the KILL QUERY / pg_cancel_backend exchange and its response
// read. The ctl:kill subscriber must never block on a dead backend.
const killQueryTimeout = 10 * time.Second

// Killer fans a ctl:kill request out to both proxies' registries. Session ids
// are generated per proxy ("sid-" + random hex), so a live session lives on
// exactly one plane — but the ctl:kill subscriber (Task 6.4) does not know
// which protocol a session uses, so it asks both. Both are always tried so an
// (astronomically unlikely) id collision on the other plane cannot leave a
// session alive; KillSession/KillQuery are fast mutex-guarded map lookups on
// a miss.
type Killer struct {
	mysql SessionKiller
	pg    SessionKiller
}

func NewKiller(mysql, pg SessionKiller) *Killer {
	return &Killer{mysql: mysql, pg: pg}
}

// KillSession tries the MySQL registry first, then the PostgreSQL registry,
// and reports whether either plane had the session.
func (k *Killer) KillSession(id string) bool {
	killed := false
	if k.mysql != nil && k.mysql.KillSession(id) {
		killed = true
	}
	if k.pg != nil && k.pg.KillSession(id) {
		killed = true
	}
	return killed
}

// KillQuery tries to abort the in-flight query of the session on either
// plane, WITHOUT touching the session itself (Task 8.3). Reports whether
// either plane accepted the kill-query — i.e. the session exists, has a
// captured thread id, and the backend acknowledged the abort. Failure
// reasons are logged by the plane's KillQuery.
func (k *Killer) KillQuery(id string) bool {
	killed := false
	if k.mysql != nil && k.mysql.KillQuery(id) {
		killed = true
	}
	if k.pg != nil && k.pg.KillQuery(id) {
		killed = true
	}
	return killed
}

// killPayload is the ctl:kill message shape: {session_id, mode}. mode is
// optional — absent means KillModeConnection (Task 6.4 backward compat).
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
// mode} (mode absent → connection, Task 6.4 backward compat), fan out to
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
			return "query killed", sid
		}
		return "kill: unknown session", sid
	case KillModeConnection:
		if k.KillSession(sid) {
			return "session killed", sid
		}
		return "kill: unknown session", sid
	default:
		return "kill: unknown mode", sid
	}
}
