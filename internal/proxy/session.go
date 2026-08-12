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
// the session still works; kill-query just has no query context.
type sessionRecord struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	DBUser    string    `json:"db_user"`
	DBType    string    `json:"db_type"`
	DB        string    `json:"db"`
	ThreadID  int64     `json:"thread_id"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// buildSessionRecord marshals a session directory record; nil on failure
// (practically impossible for these field types).
func buildSessionRecord(sid, username, dbUser, dbType, db string, threadID int64, startedAt, lastSeen time.Time) []byte {
	raw, err := json.Marshal(sessionRecord{
		SessionID: sid,
		Username:  username,
		DBUser:    dbUser,
		DBType:    dbType,
		DB:        db,
		ThreadID:  threadID,
		StartedAt: startedAt,
		LastSeen:  lastSeen,
	})
	if err != nil {
		return nil
	}
	return raw
}
