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

// sessionTLS reports whether the plane serves HTTPS — the zt_session cookie
// gets the Secure attribute only then (review 9.9: no Secure flag on
// plaintext dev deployments, where an HTTPS-only cookie would break login).
func (a *authMiddleware) sessionTLS() bool {
	return a.cfg.TLS != nil && a.cfg.TLS.Enabled
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

// handleLogin validates credentials (constant-time compares) and creates a
// Valkey-backed session. Failed attempts are rate-limited per (IP,
// username): after loginMaxFailures failures in loginRateWindow the key is
// blocked with 429 until the window rolls over (review 9.9 login rate
// limit).
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
	id, err := a.vs.CreateSession(r.Context(), models.Session{
		Username: req.Username,
	}, time.Duration(a.cfg.SessionTTL)*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: a.cfg.SessionTTL * 3600,
		Secure: a.sessionTLS(), // review 9.9: Secure cookie when the plane serves TLS
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": req.Username})
}

// handleMe reports the session-authenticated caller's username (Task 5.7).
// requireSession already rejected unauthenticated requests with 401, so the
// session is always present (review 9.9: the unreachable nil branch was
// dead code — removed).
func (a *authMiddleware) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"username": sessionFrom(r).Username})
}

func (a *authMiddleware) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		// Review 9.9 MINOR: a failed session delete is logged, not silent.
		if err := a.vs.DeleteSession(r.Context(), c.Value); err != nil {
			a.log.Warn("logout: session delete failed", "err", err)
		}
		// The clear cookie mirrors the set cookie's attributes (Secure in
		// particular) so browsers actually replace it.
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: a.sessionTLS(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
