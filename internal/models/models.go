package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// TokenPayload is the routing payload bound to a single-use token.
// Stored in Valkey at tok:<token> with a 5-minute TTL.
type TokenPayload struct {
	Username string `json:"username"`            // AD user / requester (for auditing)
	DBUser   string `json:"db_user"`             // backend DB user
	DBIP     string `json:"db_ip"`               // backend DB host
	DBPort   string `json:"db_port"`             // backend DB port
	DBType   string `json:"db_type"`             // "mysql" | "postgres"
	TicketID string `json:"ticket_id,omitempty"` // optional maker-checker grouping
	Access   string `json:"access,omitempty"`    // "read" | "write" (Task 8.6 maker write-gating); absent = read
	// SessionID (Task 8.11) is the session directory id stamped by the
	// CONTROL PLANE at issue time, so the session is visible to checkers
	// (status "pending") BEFORE the maker ever connects — the gating
	// deadlock fix. The data plane adopts it as its session id; tokens
	// without it (pre-8.11 / tests) fall back to generating one.
	SessionID string `json:"session_id,omitempty"`
}

// NewSessionID returns a random session id in the sid-<hex> form shared by
// the Control Plane (stamped into tokens at issue time — Task 8.11) and the
// Data Plane (fallback when a token carries no sid). The form mirrors the
// data plane's legacy "sid-" + 16-hex generation so old and new ids are
// indistinguishable on the wire. rand.Read cannot fail in practice on
// supported platforms; the zero fallback keeps the id well-formed in that
// pathological case.
func NewSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "sid-0000000000000000"
	}
	return "sid-" + hex.EncodeToString(b)
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
	DBType     string    `json:"db_type"` // mysql | postgres
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

// Session is the UI session payload (stored at sess:ui:<id>).
type Session struct {
	Username string    `json:"username"`
	Expires  time.Time `json:"expires"`
}
