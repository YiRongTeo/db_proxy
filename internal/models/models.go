package models

import "time"

// TokenPayload is the routing payload bound to a single-use token.
// Stored in Valkey at tok:<token> with a 5-minute TTL.
type TokenPayload struct {
	Username string `json:"username"`            // AD user / requester (for auditing)
	DBUser   string `json:"db_user"`             // backend DB user
	DBIP     string `json:"db_ip"`               // backend DB host
	DBPort   string `json:"db_port"`             // backend DB port
	DBType   string `json:"db_type"`             // "mysql" | "postgres"
	TicketID string `json:"ticket_id,omitempty"` // optional maker-checker grouping
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
