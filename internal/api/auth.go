package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

const sessionCookie = "zt_session"

type authMiddleware struct {
	cfg *config.ControlConfig
	vs  *store.ValkeyStore
}

// requireSession rejects requests without a valid UI session cookie.
func (a *authMiddleware) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		sess, err := a.vs.GetSession(r.Context(), c.Value)
		if err != nil || sess == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, sess)
		next(w, r.WithContext(ctx))
	}
}

// validAPIKey reports whether the X-Api-Key header matches config.
func (a *authMiddleware) validAPIKey(r *http.Request) bool {
	k := a.cfg.APIKey
	return k != "" && strings.TrimSpace(r.Header.Get("X-Api-Key")) == k
}

type sessionKey struct{}

func sessionFrom(r *http.Request) *models.Session {
	if s, ok := r.Context().Value(sessionKey{}).(*models.Session); ok {
		return s
	}
	return nil
}

// handleLogin validates credentials and creates a Valkey-backed session.
func (a *authMiddleware) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if req.Username != a.cfg.AuthUser || req.Password != a.cfg.AuthPassword {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	id, err := a.vs.CreateSession(r.Context(), models.Session{
		Username: req.Username,
		Expires:  time.Now().Add(time.Duration(a.cfg.SessionTTL) * time.Hour),
	}, time.Duration(a.cfg.SessionTTL)*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: a.cfg.SessionTTL * 3600,
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": req.Username})
}

func (a *authMiddleware) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = a.vs.DeleteSession(r.Context(), c.Value)
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
