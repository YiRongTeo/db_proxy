// Package api holds the Control Plane HTTP API surface: handlers,
// middleware, and the WebSocket hub (wired up in Tasks 2.2/2.3).
package api

import (
	"log/slog"
	"net/http"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// api carries the Control Plane dependencies for all HTTP handlers.
type api struct {
	log  *slog.Logger
	cfg  *config.ControlConfig
	vs   *store.ValkeyStore
	auth *authMiddleware
}

// NewAPI builds the Control Plane API with its dependencies.
func NewAPI(log *slog.Logger, cfg *config.ControlConfig, vs *store.ValkeyStore) *api {
	return &api{log: log, cfg: cfg, vs: vs, auth: &authMiddleware{cfg: cfg, vs: vs}}
}

// Routes returns the Control Plane HTTP handler tree.
func (a *api) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", a.handleHealth)
	mux.HandleFunc("POST /api/login", a.auth.handleLogin)
	mux.HandleFunc("POST /api/logout", a.auth.handleLogout)
	mux.HandleFunc("GET /api/db-presets", a.auth.requireSession(a.handleDBPresets))
	mux.HandleFunc("POST /api/token", a.handleToken) // auth inside (key OR session)
	// Task 2.4: mux.HandleFunc("GET /ws/checker", a.auth.requireSession(a.handleWS))
	// Task 2.9: mux.Handle("/", http.FileServer(http.Dir(a.cfg.StaticDir)))
	return mux
}
