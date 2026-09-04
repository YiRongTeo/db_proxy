package api

// JWT conversion (Task 5): self-issued HS256 bearer tokens are the Control
// Plane's request credential. requireJWT guards the authenticated routes
// (/api/me, /api/db-presets, /api/token since Task 7, /api/kill,
// /api/sessions, /ws/checker), replacing the legacy UI-session middleware
// (removed in Task 4); the Valkey jti denylist (Task 6) revokes tokens.
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
// returns the principal session plus the verified claims (the jti the
// Task 6 denylist needs — requireJWT consults it, handleLogout denylists
// it). Signature (HS256, cfg secret), exp, iss and aud are all enforced by
// jwt/v5 parser options; sub and role are checked afterwards (role ABSENT →
// reject, plan decision). When JWT auth is not configured (jwt.enabled=false
// or an empty secret/issuer/audience) the middleware fails CLOSED: no token
// can be trusted, so every request is rejected.
func (a *authMiddleware) parseJWT(raw string) (*models.Session, jwtClaims, error) {
	j := a.cfg.JWT
	if !j.Enabled || j.Secret == "" || j.Issuer == "" || j.Audience == "" {
		return nil, jwtClaims{}, errUnauthorizedJWT
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
		return nil, jwtClaims{}, errUnauthorizedJWT
	}
	if claims.Subject == "" {
		return nil, jwtClaims{}, errUnauthorizedJWT // no anonymous principals
	}
	if claims.Role != "maker" && claims.Role != "checker" {
		return nil, jwtClaims{}, errUnauthorizedJWT // role absent or not a known role → reject
	}
	return &models.Session{Username: claims.Subject, Role: claims.Role}, *claims, nil
}

// requireJWT guards a route with a self-issued HS256 bearer token: it reads
// "Authorization: Bearer ***", verifies signature + exp + iss + aud
// (parseJWT), consults the Valkey jti denylist (Task 6: a logged-out token
// is rejected even though its signature is fine), and injects the principal
// session under sessionKey{} so sessionFrom(r) consumers keep working
// unchanged. Any failure answers 401 with the standard unauthorized body —
// the same 401 these routes answered under the legacy UI-session
// middleware. A denylist consult ERROR fails CLOSED (401): revocation state
// must never be skipped because the store hiccuped.
func (a *authMiddleware) requireJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		// Task 6: a token id on the denylist (handleLogout wrote it) is
		// revoked — 401. Tokens without a jti are skipped (never deniable);
		// self-issued tokens always carry one (signJWT/newJTI).
		if claims.ID != "" {
			denied, err := a.vs.JWTDenied(r.Context(), claims.ID)
			if err != nil {
				a.log.Warn("requireJWT: denylist consult failed", "err", err)
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if denied {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, sess)
		next(w, r.WithContext(ctx))
	}
}

// requireChecker role-gates the checker surface (Task 8): /ws/checker,
// POST /api/kill and GET /api/sessions are wrapped
// requireJWT(requireChecker(...)) — authentication first, authorization
// second. A checker-role principal is ALWAYS allowed (the checker surface
// is theirs); a maker-role principal is allowed ONLY when cfg's
// auth.allow_maker_watch is true — the single-account deployment escape
// hatch the operator chooses in config, never a grant the maker can claim
// from a token. Anything else answers 403; the body mirrors requireJWT's
// JSON error style and leaks nothing about the config. The session is
// always present (requireJWT ran first), but the middleware fails CLOSED
// if it is missing all the same.
//
// NOTE (Task 8.5 audit): this gate does NOT touch the SoD username check —
// checkerMayWatch still runs inside handleWS for channel=sess:<sid> and
// rejects watcher == session maker regardless of role or flag.
func (a *authMiddleware) requireChecker(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		if sess == nil {
			// Unreachable when composed after requireJWT — fail closed.
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		switch sess.Role {
		case "checker":
			next(w, r)
		case "maker":
			if a.cfg.AllowMakerWatch {
				next(w, r)
				return
			}
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		default:
			// parseJWT rejects unknown roles before this point; fail
			// closed rather than guess.
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		}
	}
}

// bearerToken extracts the raw token from "Authorization: Bearer ***"; ""
// when the header is absent or uses any other scheme. The strict prefix
// check keeps e.g. "Bearerish xyz" out — parseJWT must only ever see a real
// bearer value (or "").
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(h[len(bearerPrefix):])
}
