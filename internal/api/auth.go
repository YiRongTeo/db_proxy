package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

const sessionCookie = "zt_session"

// loginRateWindow / loginMaxFailures bound the per-(IP, username)
// failed-login backoff (review 9.9): after loginMaxFailures failures within
// the window the key is blocked (429) until the window rolls over. A
// successful login clears the key.
const (
	loginRateWindow  = 60 * time.Second
	loginMaxFailures = 5
)

// issueRateWindow / issueMaxTokens bound token issuance per user (review
// 9.9 MINOR: issuance throttle): a single user cannot mint an unbounded
// number of tokens in a short window (every token is a session directory
// entry, a pub/sub event and an audit row).
const (
	issueRateWindow = 60 * time.Second
	issueMaxTokens  = 60
)

// rateLimiter is a fixed-window attempt counter keyed by a string (used for
// login failures per IP+username and token issuance per user). Thread-safe;
// zero value is NOT usable — build via newRateLimiter.
type rateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string][]time.Time
}

func newRateLimiter(window time.Duration, max int) *rateLimiter {
	return &rateLimiter{window: window, max: max, hits: make(map[string][]time.Time)}
}

// blocked reports whether key has reached max hits within the window
// (pruning expired hits on the way). now is injected for testability.
func (l *rateLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.hits[key] = kept
	return len(kept) >= l.max
}

// hit records one attempt for key (now injected for testability).
func (l *rateLimiter) hit(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.hits[key], now)
}

// clear forgets key (e.g. a successful login resets the failure counter).
func (l *rateLimiter) clear(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

// secureEqual compares two strings in constant time (review 9.9): both
// sides are hashed first so the comparison reveals nothing about the
// values' lengths, then subtle.ConstantTimeCompare runs in time
// proportional to the hash length regardless of where the values differ.
func secureEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// clientIP extracts the client's IP for rate limiting. The deployment is
// single-hop (no proxy), so RemoteAddr is authoritative; X-Forwarded-For is
// deliberately NOT trusted (spoofable).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// validCredentials accepts the primary auth.username/password pair OR any
// entry of the optional auth.users list (Task 9.13 — a dedicated checker
// account for SoD testing; every comparison is constant-time).
func (a *authMiddleware) validCredentials(username, password string) bool {
	if secureEqual(username, a.cfg.AuthUser) && secureEqual(password, a.cfg.AuthPassword) {
		return true
	}
	for _, u := range a.cfg.AuthUsers {
		if secureEqual(username, u.Username) && secureEqual(password, u.Password) {
			return true
		}
	}
	return false
}

// roleFor resolves a principal's maker|checker role from the config (Task 6
// JWT login): the primary auth.username maps to cfg.AuthRole, and each
// auth.users entry carries its own declared role. Callers have already
// passed validCredentials, so the user IS one of those identities — "" is
// returned only if the config changed between the two lookups (never in
// practice; handleLogin treats it as internal).
func (a *authMiddleware) roleFor(username string) string {
	if secureEqual(username, a.cfg.AuthUser) {
		return a.cfg.AuthRole
	}
	for _, u := range a.cfg.AuthUsers {
		if secureEqual(username, u.Username) {
			return u.Role
		}
	}
	return ""
}

type authMiddleware struct {
	cfg *config.ControlConfig
	vs  *store.ValkeyStore
	log *slog.Logger
	// Review 9.9: per-(IP, username) failed-login backoff (wired in NewAPI;
	// tests may inject a shortened limiter).
	loginLimiter *rateLimiter
}

// sessionFromRequest resolves the UI session from the zt_session cookie
// when present and valid, otherwise nil — the SINGLE cookie-resolution
// helper shared by requireSession and the bare /api/token route (review
// 9.9: the duplicated sessionFromCookie helper was removed).
func (a *authMiddleware) sessionFromRequest(r *http.Request) (*models.Session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	return a.vs.GetSession(r.Context(), c.Value)
}

// requireSession rejects requests without a valid UI session cookie.
func (a *authMiddleware) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := a.sessionFromRequest(r)
		if err != nil || sess == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, sess)
		next(w, r.WithContext(ctx))
	}
}

// validAPIKey reports whether the X-Api-Key header matches config, in
// constant time (review 9.9 — a plain == comparison leaks the comparison
// position through timing).
func (a *authMiddleware) validAPIKey(r *http.Request) bool {
	k := a.cfg.APIKey
	if k == "" {
		return false
	}
	return secureEqual(strings.TrimSpace(r.Header.Get("X-Api-Key")), k)
}

type sessionKey struct{}

func sessionFrom(r *http.Request) *models.Session {
	if s, ok := r.Context().Value(sessionKey{}).(*models.Session); ok {
		return s
	}
	return nil
}

// handleLogin (JWT since Task 6; registered only when
// auth.jwt.login_enabled) validates credentials (constant-time compares)
// and self-issues an HS256 bearer JWT: 200 {token, username, role,
// expires_in}. NO cookie and NO Valkey session — the token is the only
// credential handed to the SPA. The role comes from the config lookup
// (roleFor): primary auth.username → cfg.AuthRole, an auth.users match →
// that entry's role. Failed attempts are rate-limited per (IP, username)
// EXACTLY as before (review 9.9): after loginMaxFailures failures in
// loginRateWindow the key is blocked with 429 until the window rolls over,
// and a success clears the counter.
func (a *authMiddleware) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	// The key uses the REQUESTED username (the attacker's guess): rotating
	// usernames is bounded per-IP, and one user's typos never lock out
	// another user.
	key := clientIP(r) + "|" + req.Username
	if a.loginLimiter.blocked(key, time.Now()) {
		http.Error(w, `{"error":"too many attempts"}`, http.StatusTooManyRequests)
		return
	}
	if !a.validCredentials(req.Username, req.Password) {
		a.loginLimiter.hit(key, time.Now())
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	a.loginLimiter.clear(key)
	role := a.roleFor(req.Username)
	if role == "" {
		// Unreachable after validCredentials — config raced between the two
		// lookups. Never issue an un-role'd token (an accidental superuser).
		a.log.Error("login: no role for authenticated user", "username", req.Username)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	ttlSeconds := a.cfg.JWT.TTLSeconds
	if ttlSeconds <= 0 {
		// Config bug (auth.jwt.ttl_seconds default 28800): an instant-expiry
		// token would 401 on every guarded route — refuse to mint it.
		a.log.Error("login: auth.jwt.ttl_seconds must be > 0", "ttl_seconds", ttlSeconds)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	token, err := signJWT(a.cfg, req.Username, role, time.Duration(ttlSeconds)*time.Second, time.Now())
	if err != nil {
		a.log.Error("login: sign jwt", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"username":   req.Username,
		"role":       role,
		"expires_in": ttlSeconds,
	})
}

// handleMe reports the bearer-authenticated caller's username AND role
// (Task 5.7 route; role added Task 6 for the SPA's boot-time session
// restore). requireJWT already rejected unauthenticated requests with 401,
// so the session is always present.
func (a *authMiddleware) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	writeJSON(w, http.StatusOK, map[string]string{"username": sess.Username, "role": sess.Role})
}

// handleLogout (JWT since Task 6) revokes the PRESENTED bearer token: the
// token's jti is denylisted in Valkey for the token's remaining life
// (exp - now, floored at 1s) — replaying the same token on a guarded route
// then answers 401 until it would have expired anyway. No cookie, no
// session delete: the jwt:deny:<jti> key IS the revocation. A missing or
// unverifiable bearer is rejected 401 (nothing to revoke, nothing leaked);
// a denylist write failure answers 500 — silent logout would leave the
// token live while the SPA believes it is gone.
func (a *authMiddleware) handleLogout(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	sess, claims, err := a.parseJWT(raw)
	if err != nil || sess == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if claims.ID == "" {
		// A valid token without a jti cannot be revoked — fail loudly
		// instead of pretending the logout happened.
		a.log.Error("logout: token carries no jti — cannot revoke")
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	// Deny for the token's remaining life (floor 1s): parseJWT already
	// rejected expired tokens, so exp is in the future.
	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < time.Second {
		remaining = time.Second
	}
	if err := a.vs.DenyJWT(r.Context(), claims.ID, remaining); err != nil {
		a.log.Error("logout: deny jwt failed", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
