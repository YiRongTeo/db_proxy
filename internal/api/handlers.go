package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// maxBodyBytes caps JSON request bodies at 1 MB.
const maxBodyBytes = 1 << 20

// sessionPendingTTL is the lifetime of a sess:live:<sid> record written at
// TOKEN ISSUE time (Task 8.11): a token whose maker never connects expires
// from the session directory on its own. Mirrors the data plane's
// sessionLiveTTL heartbeat so pending and active records share one cadence.
const sessionPendingTTL = 60 * time.Second

// handleHealth reports Control Plane + Valkey liveness.
func (a *api) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := a.vs.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "valkey": "down"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "valkey": "up"})
}

// handleDBPresets returns the configured database presets (session required).
func (a *api) handleDBPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.cfg.DBPresets)
}

// decodeJSON reads and decodes a JSON request body, capped at 1 MB. The
// MaxBytesReader is bound to the ResponseWriter so an oversized body aborts
// the connection instead of dribbling, and unknown fields are REJECTED —
// a misspelled field is a client bug, not a silently-ignored field (review
// 9.9 MINOR).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// writeJSON encodes v as a JSON response with the proper Content-Type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleToken issues a single-use DB token. Auth: valid API key OR UI session.
func (a *api) handleToken(w http.ResponseWriter, r *http.Request) {
	// Bare route (no requireSession wrapper): resolve the session cookie
	// ourselves to support the "API key OR session" auth model.
	if sess, err := a.auth.sessionFromRequest(r); err == nil && sess != nil {
		r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess))
	}
	if !a.auth.validAPIKey(r) && sessionFrom(r) == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Username string `json:"username"`
		DBUser   string `json:"db_user"`
		DBIP     string `json:"db_ip"`
		DBPort   string `json:"db_port"`
		DBType   string `json:"db_type"`
		TicketID string `json:"ticket_id,omitempty"`
		// Mode (Task 9.13) requests a token flavor: "single-use" (default)
		// or "session". Absent → the target preset's token_mode, then the
		// api.token_mode config default.
		Mode string `json:"mode,omitempty"`
		// IdleSeconds (Task 9.13 per-token idle override): the session
		// idle timeout for THIS token. 0/absent = the data plane's
		// session.idle_seconds default (applies to every token mode).
		IdleSeconds int `json:"idle_seconds,omitempty"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	// Review 9.9 CRITICAL (a): a session-authenticated requester's username
	// is BOUND to the session. The body username (if present) must match the
	// session's — otherwise the request is rejected — and the token is
	// ALWAYS issued for the session username. Only the API-key path (no
	// session) trusts the body.
	if sess := sessionFrom(r); sess != nil {
		if req.Username != "" && req.Username != sess.Username {
			http.Error(w, `{"error":"username does not match session"}`, http.StatusBadRequest)
			return
		}
		req.Username = sess.Username
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.DBUser == "" || req.DBIP == "" || req.DBPort == "" {
		http.Error(w, `{"error":"missing required fields"}`, http.StatusBadRequest)
		return
	}
	// Spec amendment 9b: every token must be traceable to a ticket.
	// Review 9.9 MINOR: ticket_id is also shape-validated — it lands in
	// audit rows and event payloads, so no whitespace/control characters and
	// a bounded length.
	if req.TicketID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket_id required"})
		return
	}
	tid := strings.TrimSpace(req.TicketID)
	if len(tid) > 128 || strings.ContainsAny(tid, " 	\r\n") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ticket_id"})
		return
	}
	req.TicketID = tid
	if req.DBType != "mysql" && req.DBType != "postgres" && req.DBType != "mssql" && req.DBType != "oracle" {
		http.Error(w, `{"error":"db_type must be mysql, postgres, mssql or oracle"}`, http.StatusUnprocessableEntity)
		return
	}
	// Task 9.13: token mode resolution — request mode wins, then the
	// target preset's token_mode, then the api.token_mode default.
	// Anything other than the two known flavors is a client error.
	mode := req.Mode
	if mode == "" {
		mode = a.modeForPreset(req.DBType, req.DBUser, req.DBIP, req.DBPort)
	}
	if mode == "" {
		mode = a.cfg.TokenMode
	}
	if mode == "" {
		mode = "single-use" // config default guard
	}
	if mode != "single-use" && mode != "session" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be single-use or session"})
		return
	}
	// Task 9.13 per-token idle override: non-negative only (0/absent =
	// follow the data-plane session.idle_seconds default).
	if req.IdleSeconds < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "idle_seconds must be >= 0"})
		return
	}
	// Review 9.9 MINOR: issuance throttle — bound token minting. Session
	// requests are keyed by the (bound) username; API-key requests by the
	// client IP (the key is shared, the IP is the only per-client signal).
	issueKey := req.Username
	if sessionFrom(r) == nil {
		issueKey = clientIP(r)
	}
	if a.issueLimiter.blocked(issueKey, time.Now()) {
		http.Error(w, `{"error":"token issuance rate limited"}`, http.StatusTooManyRequests)
		return
	}
	token, err := store.NewToken()
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	// Task 8.11: stamp the session id at ISSUE time so the session is
	// visible to checkers (status "pending") before the maker connects —
	// the gating-deadlock fix. The data plane adopts this id on connect.
	payload := models.TokenPayload{
		Username: req.Username, DBUser: req.DBUser, DBIP: req.DBIP,
		DBPort: req.DBPort, DBType: req.DBType, TicketID: req.TicketID,
		Access:    a.accessForPreset(req.DBType, req.DBUser, req.DBIP, req.DBPort),
		SessionID: models.NewSessionID(),
		Mode:      mode,
		// Task 9.13 per-token idle override: 0/absent = the data plane's
		// session.idle_seconds default (every token mode); >0 overrides it
		// for sessions opened with this token.
		IdleSeconds: req.IdleSeconds,
	}
	ttl := time.Duration(a.cfg.TokenTTL) * time.Second
	if mode == "session" {
		// Task 9.13 session tokens: TTL from api.session_token_ttl_seconds
		// (0 = INFINITE — the token lives until revoked), stamped issue IP
		// (every connection must come from it) and issued_at (max-lifetime
		// anchor). MaxUses is meaningless here — session tokens are not
		// consumed — so it stays absent.
		ttl = time.Duration(a.cfg.SessionTokenTTL) * time.Second
		payload.IP = models.NormalizeIP(clientIP(r))
		payload.IssuedAt = time.Now().UTC().Unix()
	} else {
		// Task 9.12: connection budget per token (1 = single-use default).
		// Clamped — a config of 0 or negative must never produce a token
		// that dies on its first use unexpectedly; the store also treats
		// < 1 as 1, so this is belt-and-braces.
		payload.MaxUses = a.cfg.TokenMaxUses
		if payload.MaxUses < 1 {
			payload.MaxUses = 1
		}
	}
	if err := a.vs.SetToken(r.Context(), token, payload, ttl); err != nil {
		a.log.Error("token store", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	// Task 9.13: -1 signals an infinite session token to the client (the
	// token never expires — revocation is explicit).
	expiresIn := int(ttl.Seconds())
	if mode == "session" && a.cfg.SessionTokenTTL <= 0 {
		expiresIn = -1
	}
	a.issueLimiter.hit(issueKey, time.Now())
	// The token is stored; now list the session at issue time (pending
	// directory record + action=issued lifecycle event). Best-effort — a
	// directory/pubsub hiccup must not fail an already-stored token, but
	// it IS logged.
	a.recordPendingSession(r.Context(), &payload)
	// Task 9.7 audit: persist the pending row (maker username, ticket, db
	// target, access). Best-effort like the directory record — an audit
	// write failure is logged, never fatal to the issue.
	a.auditUpsertPending(r.Context(), &payload)
	a.log.Info("token issued", "username", payload.Username, "db_user", payload.DBUser,
		"db_type", payload.DBType, "ticket", payload.TicketID, "access", payload.Access,
		"session_id", payload.SessionID)
	writeJSON(w, http.StatusOK, models.TokenResponse{
		Token:     token,
		Host:      a.cfg.DataPlaneHost,
		Port:      a.cfg.DataPlanePort,
		ExpiresIn: expiresIn,
	})
}

// modeForPreset resolves a db_preset's optional token_mode (Task 9.13) for
// the requested target; "" when no preset matches or the preset declares
// none (the api.token_mode default then applies). Mirrors accessForPreset.
func (a *api) modeForPreset(dbType, dbUser, dbIP, dbPort string) string {
	for _, p := range a.cfg.DBPresets {
		if p.DBType == dbType && p.DBUser == dbUser && p.DBIP == dbIP && p.DBPort == dbPort {
			return p.TokenMode
		}
	}
	return ""
}

// pendingSessionRecord is the CONTROL PLANE's sess:live:<sid> payload
// (Task 8.11): the session directory entry for a just-issued token, visible
// to checkers BEFORE the maker ever connects. DB is unknown at issue time
// (the client requests it in the handshake) and is therefore omitted; the
// data plane overwrites the record with the full active shape when the
// session starts.
type pendingSessionRecord struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	DBUser    string    `json:"db_user"`
	DBType    string    `json:"db_type"`
	DB        string    `json:"db,omitempty"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// recordPendingSession makes a just-issued token's session visible to
// checkers at TOKEN ISSUE time (Task 8.11): it writes the sess:live:<sid>
// directory entry with status "pending" (sessionPendingTTL — a token whose
// maker never connects expires on its own) and publishes the action=issued
// lifecycle event to queries:<user> AND queries:sess:<sid> (the same fan-out
// the data plane uses for started/ended; like them, it deliberately skips
// the ticket channel). Best-effort: the token itself is already stored — a
// directory/pubsub failure is logged, never fatal to the issue.
func (a *api) recordPendingSession(ctx context.Context, p *models.TokenPayload) {
	now := time.Now().UTC()
	rec, err := json.Marshal(pendingSessionRecord{
		SessionID: p.SessionID,
		Username:  p.Username,
		DBUser:    p.DBUser,
		DBType:    p.DBType,
		Status:    "pending",
		StartedAt: now,
		LastSeen:  now,
	})
	if err != nil {
		a.log.Error("pending session record marshal", "err", err)
		return
	}
	if err := a.vs.SetSessionLive(ctx, p.SessionID, rec, sessionPendingTTL); err != nil {
		a.log.Error("pending session record store", "err", err, "session_id", p.SessionID)
	}
	ev := models.QueryEvent{
		ID:        models.NewEventID(),
		Ts:        now,
		Kind:      "session",
		Action:    "issued",
		Username:  p.Username,
		DBUser:    p.DBUser,
		DBType:    p.DBType,
		SessionID: p.SessionID,
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		a.log.Error("issued event marshal", "err", err)
		return
	}
	if err := a.vs.Publish(ctx, "queries:"+ev.Username, raw); err != nil {
		a.log.Error("issued event publish", "err", err, "channel", "queries:"+ev.Username)
	}
	if err := a.vs.Publish(ctx, "queries:sess:"+ev.SessionID, raw); err != nil {
		a.log.Error("issued event publish", "err", err, "channel", "queries:sess:"+ev.SessionID)
	}
	a.log.Info("session issued", "username", ev.Username, "db_user", ev.DBUser,
		"db_type", ev.DBType, "session_id", ev.SessionID)
}

// accessForPreset resolves the token's access level from the db_preset that
// matches the requested target (Task 8.6 maker write-gating): a token issued
// for a read-write preset carries access="write" and is subject to the data
// plane's write gate (queries blocked unless a checker watches the session).
// No matching preset → "" — the data plane treats absent access as read (no
// gate), so tokens for ad-hoc targets stay ungated.
func (a *api) accessForPreset(dbType, dbUser, dbIP, dbPort string) string {
	for _, p := range a.cfg.DBPresets {
		if p.DBType == dbType && p.DBUser == dbUser && p.DBIP == dbIP && p.DBPort == dbPort {
			return p.Access
		}
	}
	return ""
}

// handleKill queues a data-plane session kill (session required). The kill
// is dispatched over the Valkey ctl:kill channel — no HTTP between planes
// (spec amendment 9e). Mode selects the kill scope (Task 8.3 two-level
// kill): "connection" (default) terminates the whole backend session;
// "query" aborts only the in-flight query. The published payload always
// carries the resolved mode so the data plane never has to guess.
func (a *api) handleKill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Mode      string `json:"mode"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
		return
	}
	// Review 9.9 MINOR: session_id shape validation — it becomes the ctl:kill
	// channel payload key, so no whitespace/control characters and a bounded
	// length.
	sid := strings.TrimSpace(req.SessionID)
	if len(sid) > 64 || strings.ContainsAny(sid, " 	\r\n") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session_id"})
		return
	}
	req.SessionID = sid
	mode := req.Mode
	if mode == "" {
		mode = "connection"
	}
	if mode != "connection" && mode != "query" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mode"})
		return
	}
	b, err := json.Marshal(struct {
		SessionID string `json:"session_id"`
		Mode      string `json:"mode"`
	}{SessionID: req.SessionID, Mode: mode})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if err := a.vs.Publish(r.Context(), "ctl:kill", b); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "kill dispatch failed"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"killed": "queued"})
}

// handleSessions lists the live data-plane session directory (session
// required). The directory is the sess:live:* keys the data plane
// heartbeats (Task 8.2); thread_id stays backend-internal and is not
// exposed to the checker. An empty directory is encoded as [] (never null).
func (a *api) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := a.vs.ListSessionsParsed(r.Context())
	if err != nil {
		a.log.Error("list sessions", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}
