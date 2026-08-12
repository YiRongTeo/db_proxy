package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// maxBodyBytes caps JSON request bodies at 1 MB.
const maxBodyBytes = 1 << 20

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

// decodeJSON reads and decodes a JSON request body, capped at 1 MB.
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodyBytes)
	return json.NewDecoder(r.Body).Decode(v)
}

// writeJSON encodes v as a JSON response with the proper Content-Type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// sessionFromCookie resolves the UI session from the zt_session cookie when
// present and valid, otherwise nil. handleToken is registered bare (no
// requireSession wrapper) so it must resolve the session itself to support
// the "API key OR session" auth model.
func (a *api) sessionFromCookie(r *http.Request) *models.Session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := a.vs.GetSession(r.Context(), c.Value)
	if err != nil || sess == nil {
		return nil
	}
	return sess
}

// handleToken issues a single-use DB token. Auth: valid API key OR UI session.
func (a *api) handleToken(w http.ResponseWriter, r *http.Request) {
	if sess := a.sessionFromCookie(r); sess != nil {
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
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if sess := sessionFrom(r); sess != nil && req.Username == "" {
		req.Username = sess.Username
	}
	if req.Username == "" || req.DBUser == "" || req.DBIP == "" || req.DBPort == "" {
		http.Error(w, `{"error":"missing required fields"}`, http.StatusBadRequest)
		return
	}
	// Spec amendment 9b: every token must be traceable to a ticket.
	if req.TicketID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket_id required"})
		return
	}
	if req.DBType != "mysql" && req.DBType != "postgres" {
		http.Error(w, `{"error":"db_type must be mysql or postgres"}`, http.StatusUnprocessableEntity)
		return
	}
	token, err := store.NewToken()
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	payload := models.TokenPayload{
		Username: req.Username, DBUser: req.DBUser, DBIP: req.DBIP,
		DBPort: req.DBPort, DBType: req.DBType, TicketID: req.TicketID,
	}
	ttl := time.Duration(a.cfg.TokenTTL) * time.Second
	if err := a.vs.SetToken(r.Context(), token, payload, ttl); err != nil {
		a.log.Error("token store", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	a.log.Info("token issued", "username", payload.Username, "db_user", payload.DBUser,
		"db_type", payload.DBType, "ticket", payload.TicketID)
	writeJSON(w, http.StatusOK, models.TokenResponse{
		Token:     token,
		Host:      a.cfg.DataPlaneHost,
		Port:      a.cfg.DataPlanePort,
		ExpiresIn: a.cfg.TokenTTL,
	})
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
	if err := decodeJSON(r, &req); err != nil || req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
		return
	}
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
