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
