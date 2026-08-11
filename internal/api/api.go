// Package api holds the Control Plane HTTP API surface: handlers,
// middleware, and the WebSocket hub (wired up in Tasks 2.2/2.3).
package api

import (
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"

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
	mux.HandleFunc("POST /api/token", a.handleToken)                     // auth inside (key OR session)
	mux.HandleFunc("GET /ws/checker", a.auth.requireSession(a.handleWS)) // Task 2.4
	// Task 2.9: SPA static serving — registered LAST so /api/* and /ws/* win.
	if _, err := os.Stat(a.cfg.StaticDir); err != nil {
		a.log.Warn("static dir missing; SPA will not be served", "static_dir", a.cfg.StaticDir)
	}
	mux.Handle("/", spaHandler{staticDir: a.cfg.StaticDir})
	return mux
}

// spaHandler serves the built Angular SPA from disk with a single-page-app
// fallback: any path that is not a real file (e.g. /maker, /checker, /login)
// gets index.html so client-side routing works. /api and /ws never reach it —
// Routes() registers those patterns before "/".
type spaHandler struct {
	staticDir string
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fs := http.Dir(h.staticDir)
	if f, err := fs.Open(path.Clean(r.URL.Path)); err != nil {
		http.ServeFile(w, r, filepath.Join(h.staticDir, "index.html")) // SPA fallback
		return
	} else {
		f.Close()
	}
	http.FileServer(fs).ServeHTTP(w, r)
}
