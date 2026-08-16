package models

import (
	"crypto/rand"
	"encoding/hex"
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
	Access   string `json:"access,omitempty"`    // "read" | "write" (Task 8.6 maker write-gating); absent = read
	// SessionID (Task 8.11) is the session directory id stamped by the
	// CONTROL PLANE at issue time, so the session is visible to checkers
	// (status "pending") BEFORE the maker ever connects — the gating
	// deadlock fix. The data plane adopts it as its session id; tokens
	// without it (pre-8.11 / tests) fall back to generating one.
	SessionID string `json:"session_id,omitempty"`
}

// randomHex returns n random bytes hex-encoded (2*n hex chars). rand.Read
// cannot fail in practice on supported platforms; the zero fallback keeps
// the id well-formed in that pathological case. Shared by NewSessionID and
// NewEventID (Task 9.9: the control plane's duplicate event-id generator
// was deduplicated onto this).
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", 2*n)
	}
	return hex.EncodeToString(b)
}

// NewSessionID returns a random session id in the sid-<hex> form shared by
// the Control Plane (stamped into tokens at issue time — Task 8.11) and the
// Data Plane (fallback when a token carries no sid). The form mirrors the
// data plane's legacy "sid-" + 16-hex generation so old and new ids are
// indistinguishable on the wire.
func NewSessionID() string {
	return "sid-" + randomHex(8)
}

// NewEventID returns a random 64-bit hex id for control-plane lifecycle
// events (kind=session issued events; mirrors the data plane's event id
// format). Deduplicated with NewSessionID via randomHex (Task 9.9).
func NewEventID() string {
	return randomHex(8)
}

// TokenResponse is returned by POST /api/token.
type TokenResponse struct {
	Token     string `json:"token"`
	Host      string `json:"host"`
	Port      string `json:"port"`
	ExpiresIn int    `json:"expires_in"` // seconds
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
	// Phase 6 enhancement fields — all omitempty for wire backward compatibility.
	StmtType  string     `json:"stmt_type,omitempty"`  // select|insert|update|delete|other
	SessionID string     `json:"session_id,omitempty"` // data-plane session id (kill target; NOT the token)
	Status    string     `json:"status,omitempty"`     // ok|error (from DB response)
	Error     string     `json:"error,omitempty"`
	Columns   []string   `json:"columns,omitempty"`
	Rows      [][]string `json:"rows,omitempty"`
	Truncated bool       `json:"truncated,omitempty"`
	// Phase 8 enhancement fields — all omitempty for wire backward compatibility.
	Action string `json:"action,omitempty"` // started|ended — session lifecycle events
	DB     string `json:"db,omitempty"`     // client-requested target database
}

// Session is the UI session payload (stored at sess:ui:<id>). The TTL of
// the sess:ui:<id> key IS the expiry — the Expires field was dead weight
// and is gone (Task 9.9 review remediation).
type Session struct {
	Username string `json:"username"`
}
