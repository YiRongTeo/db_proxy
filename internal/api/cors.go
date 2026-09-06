package api

// Phase 2 Task 3 — CORS for browser-direct REST: the other app's browser
// UI calls this Control Plane's bearer-JWT REST APIs cross-origin. This
// middleware is hand-rolled (no framework dependency) and wraps the ENTIRE
// Routes() mux — every route, the SPA static handler, and unknown paths
// included — so the browser-facing policy is uniform at the edge.
//
// It reuses auth.jwt.allowed_origins (cfg.JWT.AllowedOrigins) — the SAME
// list that already governs the checker WebSocket upgrade (websocket.Accept
// OriginPatterns, Task 9 Phase 1). One list = one mental model: "origins
// allowed to talk to this plane". To make that literally true the matching
// rule is byte-for-byte the vendor's (accept.go authenticateOrigin):
//
//   - the Origin header is parsed as a URL; a request whose Origin HOST
//     equals the request Host (EqualFold) is SAME-ORIGIN and passes through
//     untouched, no CORS headers — browsers send Origin on same-origin
//     POSTs, so this comparison (not header absence) is the fast path;
//   - each allowlist entry is a path.Match GLOB (case-insensitive) against
//     the origin's HOST only, unless the entry carries an explicit scheme
//     prefix ("https://..."), in which case the glob runs against
//     SCHEME://HOST — so "https://*.example.com" pins the scheme and
//     "*.example.com" is scheme-agnostic, exactly like the WS gate.
//
// Allow-list semantics that follow from that rule (and are locked by
// cors_test.go):
//
//   - EMPTY allowlist = same-origin only: any cross-origin Origin 403s
//     (today's behavior, preserved).
//   - Scheme-less entries are scheme-agnostic host globs; prefix
//     "https://" to pin a scheme. The ACAO echo is ALWAYS the exact Origin
//     the browser sent (never the pattern), so the response stays valid
//     CORS no matter which entry matched.
//
// Two deliberate non-goals (hard invariants, asserted in tests): this
// middleware NEVER emits Access-Control-Allow-Origin: * (bearer auth must
// stay origin-pinned) and NEVER sets Access-Control-Allow-Credentials —
// this system authenticates with an Authorization: Bearer header, not
// cookies, so the credentialed-mode flag would only widen the blast radius.
//
// Preflight (OPTIONS + Origin) from an allowed origin is answered HERE with
// a 204 + allow headers, before the mux — so an OPTIONS for an unknown /api
// path gets 204, never the spaHandler 404. Preflight from a disallowed
// origin is 403 (never 204 — a 204 would let the browser proceed). An
// OPTIONS with NO Origin header is not a browser preflight: it passes
// through and the mux decides (its "/" catch-all answers 404 for unknown
// /api paths, as before this task).

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// CORS allow-header values advertised on preflight. Only these methods and
// headers are ever needed by the REST surface (mux-level method patterns
// enforce the per-route method regardless — these are the browser-facing
// declarations). Max-Age 600 = 10 minutes of preflight caching.
const (
	corsAllowMethods = "GET, POST, OPTIONS"
	corsAllowHeaders = "Authorization, Content-Type"
	corsMaxAge       = "600"
)

// cors wraps next with the control-plane CORS policy driven by
// cfg.JWT.AllowedOrigins. Run it OUTSIDE everything else in Routes() so the
// origin check precedes auth (a disallowed cross-origin caller must be 403'd
// before it can even present a token).
func (a *api) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// No Origin header = not a browser cross-origin call (curl, server-
		// to-server, same-origin GETs...). Pass through untouched — the mux
		// decides, exactly as before this middleware existed.
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Same-origin (Origin host == request Host) passes through untouched
		// with NO CORS headers — checked before the allowlist so an empty
		// allowlist never locks out the plane's own SPA. Browsers send Origin
		// on same-origin POSTs, so this must be a host comparison, not an
		// "is Origin absent" check.
		if sameOrigin(origin, r.Host) {
			next.ServeHTTP(w, r)
			return
		}

		if !originAllowed(origin, a.cfg.JWT.AllowedOrigins) {
			// Fail closed: disallowed cross-origin origin — 403 for preflight
			// AND actual requests, before auth runs. Never echo the origin.
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}

		// Allowed cross-origin request.
		if r.Method == http.MethodOptions {
			// Preflight: answer it here (the browser only wants headers; the
			// actual request will carry the bearer token). 204 + Vary: Origin
			// so shared caches key preflight by origin.
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
			w.Header().Set("Access-Control-Max-Age", corsMaxAge)
			w.Header().Add("Vary", "Origin")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Actual request: echo the exact origin + Vary: Origin so caches key
		// the response on the Origin header, then run the route.
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether the Origin header's host matches the request
// Host (case-insensitive) — the browser's own same-origin definition.
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host != "" && strings.EqualFold(host, u.Host)
}

// originAllowed reports whether origin matches any auth.jwt.allowed_origins
// entry, using the vendored WS gate's rule verbatim (accept.go
// authenticateOrigin): glob the origin HOST, or SCHEME://HOST when the
// pattern pins a scheme. Unparseable origins (e.g. the literal "null" a
// sandboxed iframe sends) have no host and match nothing — fail closed.
func originAllowed(origin string, patterns []string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	for _, p := range patterns {
		target := u.Host
		if strings.Contains(p, "://") {
			target = u.Scheme + "://" + u.Host
		}
		if ok, _ := path.Match(strings.ToLower(p), strings.ToLower(target)); ok {
			return true
		}
	}
	return false
}
