package proxy

import (
	"encoding/json"
	"time"
)

// sessionLiveTTL is the heartbeat TTL of sess:live:<sid> keys (Task 8.2):
// refreshed on every published event, so an idle-but-open session drops off
// the session directory ~60s after its last activity. Documented Phase 8
// design choice, not a leak to paper over.
const sessionLiveTTL = 60 * time.Second

// sessionRecord is the sess:live:<sid> JSON payload — the session directory
// entry the checker lists (username, session_id, db, db_user). ThreadID is
// the backend's connection identifier: MySQL CONNECTION_ID() for a mysql
// session, pg_backend_pid() for a postgres session. 0 means capture failed —
// the session still works; kill-query just has no query context. Status
// (Task 8.11) is "pending" for the CONTROL PLANE's token-issue record (the
// session is listed before the maker connects — the gating deadlock fix) or
// "active" once the data plane establishes the session and overwrites the
// record.
type sessionRecord struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	DBUser    string    `json:"db_user"`
	DBType    string    `json:"db_type"`
	DB        string    `json:"db"`
	ThreadID  int64     `json:"thread_id"`
	Status    string    `json:"status,omitempty"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// buildSessionRecord marshals a session directory record. status is
// "active" from the data plane (every write here is an established
// session); the control plane writes its own "pending" records at token
// issue (Task 8.11). Marshal cannot fail for these field types — the
// Task 9.10 cleanup removed the old nil guard branches at the call sites.
func buildSessionRecord(sid, username, dbUser, dbType, db string, threadID int64, startedAt, lastSeen time.Time, status string) []byte {
	raw, _ := json.Marshal(sessionRecord{
		SessionID: sid,
		Username:  username,
		DBUser:    dbUser,
		DBType:    dbType,
		DB:        db,
		ThreadID:  threadID,
		Status:    status,
		StartedAt: startedAt,
		LastSeen:  lastSeen,
	})
	return raw
}
