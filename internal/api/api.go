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
// Routes currently returns an empty mux; Task 2.2 replaces the stub internals.
type api struct {
	log *slog.Logger
	cfg *config.ControlConfig
	vs  *store.ValkeyStore
}

// NewAPI builds the Control Plane API with its dependencies.
func NewAPI(log *slog.Logger, cfg *config.ControlConfig, vs *store.ValkeyStore) *api {
	return &api{log: log, cfg: cfg, vs: vs}
}

// Routes returns the Control Plane HTTP handler tree.
func (a *api) Routes() http.Handler {
	return http.NewServeMux()
}
