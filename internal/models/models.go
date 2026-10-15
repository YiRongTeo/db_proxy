package models

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"time"
)

// TokenPayload is the routing payload bound to a single-use token.
// Stored in Valkey at tok:<token> with a 5-minute TTL.
type TokenPayload struct {
	Username string `json:"username"`            // AD user / requester (for auditing)
	DBUser   string `json:"db_user"`             // backend DB user
	DBIP     string `json:"db_ip"`               // backend DB host
	DBPort   string `json:"db_port"`             // backend DB port
	DBType   string `json:"db_type"`             // "mysql" | "postgres" | "mssql"
	TicketID string `json:"ticket_id,omitempty"` // optional maker-checker grouping
	Access   string `json:"access,omitempty"`    // "read" | "write"; absent = read
	// SessionID is the session directory id stamped by the CONTROL PLANE
	// at issue time, so the session is visible to checkers (status
	// "pending") BEFORE the maker ever connects. The data plane adopts it
	// as its session id; tokens without it (tests) fall back to generating
	// one.
	SessionID string `json:"session_id,omitempty"`
	// MaxUses is the number of REMAINING
	// connections this token may open before it is deleted. 0/absent = 1
	// (single-use — the historical zero-trust default; the data plane
	// treats any value < 1 as 1). The store decrements it atomically on
	// every consume; the final use deletes the token. Configured at issue
	// time via control.yaml api.token_max_uses (env ZT_TOKEN_MAX_USES) —
	// GUI clients (SSMS/DBeaver) open several connections per session and
	// need a small budget; the TTL still bounds the window.
	MaxUses int `json:"max_uses,omitempty"`
	// Mode is ""|"single-use" (the
	// historical behavior) or "session": a session token is NOT consumed
	// by connections — it stays valid until revoked (key deleted), its
	// TTL (infinite when the mint TTL is 0), or the data plane's
	// idle/max-lifetime enforcement. Session tokens are IP-locked:
	// every connection must come from IP (normalized) or the login is
	// rejected. Revocation is LIVE: deleting tok:<token> by ANY means
	// (control-plane kill, valkey-cli, expiry) closes running sessions
	// within the data plane's revoke poll interval (keyspace-notification
	// fast path when the server publishes them).
	Mode     string `json:"mode,omitempty"`
	IP       string `json:"ip,omitempty"`        // issue-time client IP (normalized), session mode only
	IssuedAt int64  `json:"issued_at,omitempty"` // unix seconds — max-lifetime anchor (session mode)
	// IdleSeconds is the session idle
	// timeout for THIS token, in seconds. 0/absent = follow the data
	// plane's session.idle_seconds default (which applies to EVERY token
	// mode). >0 overrides the default for sessions opened with this token.
	IdleSeconds int `json:"idle_seconds,omitempty"`
	// ExpiresAt is the end_time instant the mint was asked to honor, unix
	// seconds — informational only: enforcement is the tok: key TTL, and
	// when that key expires the revoke path closes running sessions.
	ExpiresAt int64 `json:"expires_at,omitempty"`
	// CredOverride marks a token minted with a `password`: the data plane
	// consults the ztcred:<sid> override key FIRST, falling back to the
	// normal chain on a missing/expired key (the WARN carries the reason
	// only — never a value). Absent/false: the store is never consulted.
	// The password NEVER rides the payload; it lives only in the ztcred:
	// key with the token's own TTL.
	CredOverride bool `json:"cred_override,omitempty"`
}

// NormalizeIP canonicalizes a client address host for session-token IP
// locking: strips brackets/port, maps the IPv6 loopback and the IPv4-mapped
// loopback onto 127.0.0.1 (a Windows box talking to localhost may present
// either form), and lowercases. Both planes must use it so the minted IP
// and the connecting IP compare equal.
func NormalizeIP(host string) string {
	// SplitHostPort strips [v6]:port / v4:port when present; bare hosts
	// pass through.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "::1", "::ffff:127.0.0.1", "::ffff:7f00:1":
		return "127.0.0.1"
	case "":
		return ""
	}
	return strings.ToLower(host)
}

// randomHex returns n random bytes hex-encoded (2*n hex chars). rand.Read
// cannot fail in practice on supported platforms; the zero fallback keeps
// the id well-formed in that pathological case. Shared by NewSessionID
// and NewEventID.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", 2*n)
	}
	return hex.EncodeToString(b)
}

// NewSessionID returns a random session id in the sid-<hex> form shared by
// the Control Plane (stamped into tokens at issue time) and the Data Plane
// (fallback when a token carries no sid). The form mirrors the data plane's
// generation so old and new ids are indistinguishable on the wire.
func NewSessionID() string {
	return "sid-" + randomHex(8)
}

// NewEventID returns a random 64-bit hex id for control-plane lifecycle
// events (kind=session issued events; mirrors the data plane's event id
// format), via randomHex.
func NewEventID() string {
	return randomHex(8)
}

// TokenResponse is returned by POST /api/token.
type TokenResponse struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	Host      string `json:"host"`
	Port      string `json:"port"`
	ExpiresIn int    `json:"expires_in"` // seconds
	// ExpiresAt is the absolute token expiry as unix seconds — present
	// only when the mint carried end_time; omitted otherwise.
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// QueryEvent is published to Valkey Pub/Sub by the Data Plane
// and streamed to the Checker dashboard by the Control Plane.
type QueryEvent struct {
	ID         string    `json:"id"`
	Ts         time.Time `json:"ts"`
	Kind       string    `json:"kind"` // query | prepare | execute | use
	Username   string    `json:"username"`
	TicketID   string    `json:"ticket_id,omitempty"`
	DBUser     string    `json:"db_user"`
	DBIP       string    `json:"db_ip"`
	DBPort     string    `json:"db_port"`
	DBType     string    `json:"db_type"` // mysql | postgres | mssql
	SQL        string    `json:"sql"`
	ClientAddr string    `json:"client_addr"`
	// Query-result fields — all omitempty for wire backward compatibility.
	StmtType  string     `json:"stmt_type,omitempty"`  // select|insert|update|delete|other
	SessionID string     `json:"session_id,omitempty"` // data-plane session id (kill target; NOT the token)
	Status    string     `json:"status,omitempty"`     // ok|error (from DB response)
	Error     string     `json:"error,omitempty"`
	Columns   []string   `json:"columns,omitempty"`
	Rows      [][]string `json:"rows,omitempty"`
	Truncated bool       `json:"truncated,omitempty"`
	// Session-lifecycle fields — all omitempty for wire backward compatibility.
	Action string `json:"action,omitempty"` // started|ended — session lifecycle events
	DB     string `json:"db,omitempty"`     // client-requested target database
}

// Session is the authenticated principal — username plus maker/checker
// role — carried in the request context: requireJWT parses a bearer JWT
// and builds this under sessionKey{}, where sessionFrom(r) consumers read.
type Session struct {
	Username string `json:"username"`
	Role     string `json:"role,omitempty"` // "maker" | "checker"
	// LoginSessionID is the IdP login session id from an
	// external issuer's session_id claim (default name "sessionId"),
	// carried on the principal so mint handlers can stamp it onto audit
	// rows (zt_audit.sessions.login_session_id) — the trace from a DB
	// session back to the login that requested it. It is NEVER a
	// revocation key (the denylist keys on jti only) and is empty for
	// local self-issued tokens (no IdP session in play).
	LoginSessionID string `json:"loginSessionId,omitempty"`
}
