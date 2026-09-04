package api

// JWT conversion (Task 5): self-issued HS256 bearer tokens are the Control
// Plane's request credential. requireJWT guards the session-required routes
// (/api/me, /api/db-presets, /api/kill, /api/sessions, /ws/checker),
// replacing the legacy zt_session cookie middleware on those routes (the
// cookie machinery itself is removed in Task 4; the Valkey jti denylist
// lands in Task 6).
//
// The token carries the principal in the sub claim plus an explicit
// maker|checker role claim. requireJWT verifies signature + exp + iss + aud
// and materializes *models.Session{Username: sub, Role: role} under the
// EXISTING sessionKey{} context key, so every downstream consumer
// (sessionFrom(r), SoD checkerMayWatch, audit, mint username-binding) keeps
// working unchanged.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
)

// jwtClaims is the self-issued token shape: registered claims
// (sub/iss/aud/exp/iat/jti) plus the maker|checker role claim. Role is
// REQUIRED — the plan decision is explicit over default: a token without a
// role claim is rejected (an un-role'd principal would be an accidental
// superuser). Role values are restricted to the two roles config validates
// (config.go Task 2), so a token minted with a bogus role is rejected
// rather than silently carried into SoD decisions.
type jwtClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// bearerPrefix is the only accepted Authorization scheme.
const bearerPrefix = "Bearer "

// newJTI returns a random 32-hex-char token id (the denylist key of
// Task 6). crypto/rand cannot fail in practice; the zero fallback keeps the
// token well-formed in that pathological case (mirrors models.randomHex).
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("jti: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// signJWT mints a self-issued HS256 token for username with the given role
// (maker|checker), bound to cfg's issuer/audience/secret. ttl bounds exp;
// now is injected so callers (and tests) control time. This is the sign
// side of the self-issuer — Task 6's handleLogin is its first production
// caller; today only the test helper mintJWT uses it.
func signJWT(cfg *config.ControlConfig, username, role string, ttl time.Duration, now time.Time) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := jwtClaims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			Issuer:    cfg.JWT.Issuer,
			Audience:  jwt.ClaimStrings{cfg.JWT.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(cfg.JWT.Secret))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// errUnauthorizedJWT is the single rejection reason the middleware needs —
// every failure (missing header, bad signature, expired, wrong iss/aud,
// missing role, malformed token) maps to the same 401 so the response leaks
// nothing about WHY a token was rejected.
var errUnauthorizedJWT = errors.New("unauthorized")

// parseJWT verifies a raw bearer token against the middleware's config and
// returns the principal session. Signature (HS256, cfg secret), exp, iss
// and aud are all enforced by jwt/v5 parser options; sub and role are
// checked afterwards (role ABSENT → reject, plan decision). When JWT auth
// is not configured (jwt.enabled=false or an empty secret/issuer/audience —
// the pre-JWT legacy cookie mode) the middleware fails CLOSED: no token can
// be trusted, so every request is rejected.
func (a *authMiddleware) parseJWT(raw string) (*models.Session, error) {
	j := a.cfg.JWT
	if !j.Enabled || j.Secret == "" || j.Issuer == "" || j.Audience == "" {
		return nil, errUnauthorizedJWT
	}
	claims := &jwtClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims,
		func(t *jwt.Token) (any, error) {
			// The method is pinned below via WithValidMethods; the keyfunc
			// must still refuse to hand the secret to a non-HS256 token.
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			return []byte(j.Secret), nil
		},
		jwt.WithIssuer(j.Issuer),
		jwt.WithAudience(j.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil || !tok.Valid {
		return nil, errUnauthorizedJWT
	}
	if claims.Subject == "" {
		return nil, errUnauthorizedJWT // no anonymous principals
	}
	if claims.Role != "maker" && claims.Role != "checker" {
		return nil, errUnauthorizedJWT // role absent or not a known role → reject
	}
	return &models.Session{Username: claims.Subject, Role: claims.Role}, nil
}

// requireJWT guards a route with a self-issued HS256 bearer token: it reads
// "Authorization: Bearer <token>", verifies signature + exp + iss + aud
// (parseJWT), and injects the principal session under sessionKey{} so
// sessionFrom(r) consumers keep working unchanged. Any failure answers 401
// with the standard unauthorized body — the exact contract requireSession
// had on these routes. (Valkey jti denylist consult: Task 6.)
func (a *authMiddleware) requireJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, bearerPrefix) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		sess, err := a.parseJWT(strings.TrimSpace(h[len(bearerPrefix):]))
		if err != nil || sess == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, sess)
		next(w, r.WithContext(ctx))
	}
}
