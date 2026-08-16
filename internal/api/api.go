// Package api holds the Control Plane HTTP API surface: handlers,
// middleware, and the WebSocket hub (wired up in Tasks 2.2/2.3).
package api

import (
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"zerotrust-proxy/internal/audit"
	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// api carries the Control Plane dependencies for all HTTP handlers.
type api struct {
	log  *slog.Logger
	cfg  *config.ControlConfig
	vs   *store.ValkeyStore
	auth *authMiddleware

	// Task 9.7 session audit: the MySQL writer, nil when audit.mysql.enabled
	// is false. Every hook checks nil first — zero overhead when disabled.
	// Write failures are logged by the hooks and NEVER fail the request.
	audit *audit.Writer

	// Task 8.6 maker write-gate: checker watch presence lease + heartbeat
	// period. Zero values fall back to watchPresenceTTL / watchHeartbeat —
	// tests shorten them via these fields so heartbeats are observable fast.
	watchTTL       time.Duration
	watchHeartbeat time.Duration

	// Review 9.9 pending-audit sweeper cadence; zero falls back to
	// auditSweepEvery (tests shorten it to observe sweeps quickly).
	auditSweepEvery time.Duration

	// Review 9.9: login brute-force backoff + token issuance throttle
	// (fixed-window per-key counters, wired in NewAPI).
	loginLimiter *rateLimiter
	issueLimiter *rateLimiter
}

// NewAPI builds the Control Plane API with its dependencies. aw is the
// session-audit writer (nil when audit is disabled — all hooks no-op).
func NewAPI(log *slog.Logger, cfg *config.ControlConfig, vs *store.ValkeyStore, aw *audit.Writer) *api {
	return &api{
		log: log, cfg: cfg, vs: vs,
		auth: &authMiddleware{
			cfg: cfg, vs: vs, log: log,
			loginLimiter: newRateLimiter(loginRateWindow, loginMaxFailures),
		},
		audit:        aw,
		issueLimiter: newRateLimiter(issueRateWindow, issueMaxTokens),
	}
}

// Routes returns the Control Plane HTTP handler tree.
func (a *api) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", a.handleHealth)
	mux.HandleFunc("POST /api/login", a.auth.handleLogin)
	mux.HandleFunc("POST /api/logout", a.auth.handleLogout)
	mux.HandleFunc("GET /api/me", a.auth.requireSession(a.auth.handleMe)) // Task 5.7: boot-time session restore
	mux.HandleFunc("GET /api/db-presets", a.auth.requireSession(a.handleDBPresets))
	mux.HandleFunc("POST /api/token", a.handleToken)                             // auth inside (key OR session)
	mux.HandleFunc("POST /api/kill", a.auth.requireSession(a.handleKill))        // Task 6.5: checker kill button
	mux.HandleFunc("GET /api/sessions", a.auth.requireSession(a.handleSessions)) // Task 8.4: session directory
	mux.HandleFunc("GET /ws/checker", a.auth.requireSession(a.handleWS))         // Task 2.4
	// Task 2.9: SPA static serving — registered LAST so /api/* and /ws/* win.
	if _, err := os.Stat(a.cfg.StaticDir); err != nil {
		a.log.Warn("static dir missing; SPA will not be served", "static_dir", a.cfg.StaticDir)
	}
	mux.Handle("/", spaHandler{staticDir: a.cfg.StaticDir})
	return mux
}

// spaHandler serves the built Angular SPA from disk with a single-page-app
// fallback: any path that is not a real file (e.g. /maker, /checker, /login)
// gets index.html so client-side routing works. The /api/ and /ws/ prefixes
// are guarded here (404) so unregistered API/WS paths never receive HTML —
// the guard makes the fallback self-contained instead of relying solely on
// mux registration order.
type spaHandler struct {
	staticDir string
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /api/* and /ws/* are API/WS territory; unknown paths under them must
	// 404 (JSON/WS clients would otherwise get index.html, masking bugs).
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
		http.NotFound(w, r)
		return
	}
	fs := http.Dir(h.staticDir)
	if f, err := fs.Open(path.Clean(r.URL.Path)); err != nil {
		http.ServeFile(w, r, filepath.Join(h.staticDir, "index.html")) // SPA fallback
		return
	} else {
		f.Close()
	}
	http.FileServer(fs).ServeHTTP(w, r)
}
