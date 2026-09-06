package api

// JWT conversion (Task 5): HS256 bearer tokens are the Control Plane's
// request credential. requireJWT guards the authenticated REST routes
// (/api/me, /api/db-presets, /api/token since Task 7, /api/kill,
// /api/sessions), replacing the legacy UI-session middleware (removed in
// Task 4); the Valkey jti denylist (Task 6) revokes tokens. /ws/checker is
// guarded by requireJWTWS (Task 9) — the same verification, but the token
// may ALSO arrive via ?access_token= because the browser WebSocket API
// cannot set the Authorization header.
//
// Verification is ISSUER-AWARE (Phase 2 Task 2): parseToken resolves a
// token's iss claim to a trust root — the LOCAL self-issued login tokens
// (auth.jwt.*, parseJWT) or a configured auth.jwt.external_issuers entry
// (parseExternalJWT, verified with the issuer's own HS256 shared secret +
// audience and mapped through the issuer's configurable claim mapping) —
// and unknown iss claims are rejected. The principal is always
// materialized as *models.Session{Username, Role} (role ∈ {maker, checker}
// enforced post-mapping) under the EXISTING sessionKey{} context key, so
// every downstream consumer (sessionFrom(r), SoD checkerMayWatch, audit,
// mint username-binding) keeps working unchanged.
//
// The token carries the principal in the sub claim (or the external
// issuer's mapped subject claim) plus an explicit maker|checker role claim.
// Local tokens always carry a jti (signJWT/newJTI); external tokens must
// too (require_jti, Task-1 default true), so the Task 6 denylist applies to
// every accepted token — logged-out external tokens replay as 401 like
// logged-out local ones.

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
// rather than silently carried into SoD decisions. Phase 2 Task 2: external
// tokens are verified via jwt.MapClaims (their claim NAMES are
// configurable), then the mapped principal + jti/exp are carried back in
// this same struct so the denylist and logout consumers stay unchanged.
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
// side of the self-issuer: Task 6's handleLogin mints every login JWT
// through it, and the test helper mintJWT shares the same path.
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

// parseJWT verifies a raw bearer token against the LOCAL issuer (the
// middleware's own auth.jwt.* config) and returns the principal session
// plus the verified claims (the jti the Task 6 denylist needs — requireJWT
// consults it, handleLogout denylists it). Signature (HS256, cfg secret),
// exp, iss and aud are all enforced by jwt/v5 parser options; sub and role
// are checked afterwards (role ABSENT → reject, plan decision). This is the
// LOCAL-issuer path: parseToken resolves a token's iss claim and reaches
// parseJWT ONLY for tokens claiming the local issuer, so self-issued login
// tokens verify here exactly as before. When JWT auth is not configured
// (jwt.enabled=false or an empty secret/issuer/audience) the middleware
// fails CLOSED: no token can be trusted, so every request is rejected.
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

// parseToken is the ISSUER-AWARE verification entry point (Phase 2 Task 2):
// every bearer token — self-issued or minted by a configured external
// issuer — is attributed to a trust root by its iss claim, verified against
// THAT issuer's HS256 secret + audience (with the issuer's claim mapping
// applied for external issuers), and materialized as
// *models.Session{Username, Role}. It is the shared core of authorizeJWT
// (requireJWT/requireJWTWS) and handleLogout, so external tokens are
// first-class principals: they authenticate guarded routes AND can be
// logged out (their jti denylisted — require_jti makes sure they carry
// one). Fail-closed semantics are unchanged: any resolution, verification
// or mapping failure → errUnauthorizedJWT → 401, never a different status
// and never a pass.
func (a *authMiddleware) parseToken(raw string) (*models.Session, jwtClaims, error) {
	j := a.cfg.JWT
	// Master switch: jwt.enabled=false → no token is trusted (fail closed,
	// exactly as parseJWT always did).
	if !j.Enabled {
		return nil, jwtClaims{}, errUnauthorizedJWT
	}
	// Phase 1 — read the iss claim WITHOUT verification so the token can be
	// attributed to a trust root (local issuer vs external list). MapClaims
	// is the probe because it tolerates any claim payload; only iss is
	// read, and a malformed token (unparseable, or iss not a string) fails
	// closed.
	probe := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, probe); err != nil {
		return nil, jwtClaims{}, errUnauthorizedJWT
	}
	iss, err := probe.GetIssuer()
	if err != nil {
		return nil, jwtClaims{}, errUnauthorizedJWT
	}
	if iss == "" {
		// No iss claim → the token names no trust root (the local parser
		// below also requires iss via WithIssuer, so nothing is lost).
		return nil, jwtClaims{}, errUnauthorizedJWT
	}
	// Phase 2 — resolve the issuer and verify with ITS key material.
	if iss == j.Issuer {
		// Local issuer: the historical single path, byte-for-byte (parseJWT
		// re-checks enabled/secret/issuer/audience and fails closed when the
		// local secret is not configured, e.g. external-only mode).
		return a.parseJWT(raw)
	}
	for i := range j.ExternalIssuers {
		e := &j.ExternalIssuers[i]
		if e.Iss == iss {
			return parseExternalJWT(raw, e)
		}
	}
	// Unknown iss: no configured trust root claims this token.
	return nil, jwtClaims{}, errUnauthorizedJWT
}

// parseExternalJWT verifies a raw token against ONE external issuer entry
// (Phase 2 Task 2): HS256 signature with the issuer's shared secret, iss ==
// e.Iss, aud containing e.Audience (Task-1 validation materialized the
// issuer-level audience — or the top-level inherit — into e.Audience at
// load), exp present. It then applies the issuer's CLAIM MAPPING — subject
// and role claim NAMES default to "sub"/"role" when zero, role_aliases
// translate raw role VALUES onto maker|checker (identity when unaliased) —
// and enforces the same post-verification rules as the local path: sub
// non-empty, canonical role ∈ {maker, checker}. require_jti (absent config
// field = TRUE, the Task-1 default; explicit false opts out) demands a
// non-empty jti claim so external tokens are deniable via the Task 6
// denylist. Any failure → errUnauthorizedJWT (fail closed).
func parseExternalJWT(raw string, e *config.ExternalIssuerConfig) (*models.Session, jwtClaims, error) {
	// Fail closed on a half-configured entry. config.Load guarantees
	// iss/secret non-empty and audience materialized; a hand-built cfg (in
	// tests, or a future caller) must not bypass the same bar.
	if e == nil || e.Iss == "" || e.Secret == "" || e.Audience == "" {
		return nil, jwtClaims{}, errUnauthorizedJWT
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims,
		func(t *jwt.Token) (any, error) {
			// Same method pin as the local path: never hand the shared
			// secret to a non-HS256 token.
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			return []byte(e.Secret), nil
		},
		jwt.WithIssuer(e.Iss),
		jwt.WithAudience(e.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil || !tok.Valid {
		return nil, jwtClaims{}, errUnauthorizedJWT
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, jwtClaims{}, errUnauthorizedJWT // defensive — WithExpirationRequired passed above
	}
	// jti: read verbatim (string claim). A malformed (non-string) jti is
	// treated as absent — with require_jti that is a rejection; without it
	// the denylist consult is skipped downstream (claims.ID == "").
	jti, jtiIsString := claims["jti"].(string)
	requireJTI := e.RequireJTI == nil || *e.RequireJTI // nil = absent = TRUE (Task-1 default)
	if requireJTI && (!jtiIsString || jti == "") {
		return nil, jwtClaims{}, errUnauthorizedJWT // no jti → nothing the logout denylist could revoke
	}
	if !jtiIsString {
		jti = ""
	}
	// Claim mapping: zero config values mean the defaults (sub/role claim
	// names; identity role translation). The issuer's JWT shape is adapted
	// HERE — a different claim vocabulary is a config edit, never code.
	m := e.Claims
	subName := m.Subject
	if subName == "" {
		subName = "sub"
	}
	roleName := m.Role
	if roleName == "" {
		roleName = "role"
	}
	username, _ := claims[subName].(string)
	if username == "" {
		return nil, jwtClaims{}, errUnauthorizedJWT // no anonymous principals
	}
	rawRole, _ := claims[roleName].(string)
	role, aliased := m.RoleAliases[rawRole]
	if !aliased {
		role = rawRole // identity translation for values the operator did not alias
	}
	if role != "maker" && role != "checker" {
		return nil, jwtClaims{}, errUnauthorizedJWT // role absent / unaliased non-canonical → reject (never a superuser)
	}
	return &models.Session{Username: username, Role: role}, jwtClaims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			Issuer:    e.Iss,
			ExpiresAt: exp,
			ID:        jti,
		},
	}, nil
}

// authorizeJWT is the shared core of requireJWT and requireJWTWS: it
// verifies a raw token — presence ("": errUnauthorizedJWT, no anonymous
// access), parseToken (issuer-aware resolution + signature + exp + iss +
// aud + role, claim-mapped for external issuers), the Valkey jti
// denylist (Task 6: a logged-out token is rejected even though its
// signature is fine) — and returns a request whose context carries the
// principal session under sessionKey{} so sessionFrom(r) consumers keep
// working unchanged. Any failure returns errUnauthorizedJWT, mapped by the
// caller to the standard 401. A denylist consult ERROR fails CLOSED (401):
// revocation state must never be skipped because the store hiccuped.
func (a *authMiddleware) authorizeJWT(r *http.Request, raw string) (*http.Request, error) {
	if raw == "" {
		return nil, errUnauthorizedJWT
	}
	sess, claims, err := a.parseToken(raw)
	if err != nil || sess == nil {
		return nil, errUnauthorizedJWT
	}
	// Task 6: a token id on the denylist (handleLogout wrote it) is
	// revoked — 401. Tokens without a jti are skipped (never deniable);
	// self-issued tokens always carry one (signJWT/newJTI) and require_jti
	// (Task 2) forces external tokens to carry one too, so the gap is
	// closed.
	if claims.ID != "" {
		denied, err := a.vs.JWTDenied(r.Context(), claims.ID)
		if err != nil {
			a.log.Warn("requireJWT: denylist consult failed", "err", err)
			return nil, errUnauthorizedJWT
		}
		if denied {
			return nil, errUnauthorizedJWT
		}
	}
	return r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)), nil
}

// requireJWT guards a route with a bearer token — local (self-issued HS256)
// or from a configured external issuer: it reads "Authorization: Bearer
// ***" ONLY (bearerToken), verifies signature + exp + iss + aud
// (issuer-aware parseToken via authorizeJWT, claim-mapped for external
// issuers), and injects the principal
// session under sessionKey{} so sessionFrom(r) consumers keep working
// unchanged. Any failure answers 401 with the standard unauthorized body —
// the same 401 these routes answered under the legacy UI-session
// middleware. REST routes stay header-only BY DESIGN: a token in a query
// string would leak into logs, browser history and proxy access logs, so
// the query-param fallback exists only on /ws/checker (requireJWTWS), where
// the browser WebSocket API makes the header impossible.
func (a *authMiddleware) requireJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authed, err := a.authorizeJWT(r, bearerToken(r))
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, authed)
	}
}

// requireJWTWS guards /ws/checker (Task 9): the browser WebSocket API
// cannot set custom headers, so the checker SPA's live-query socket (Task
// 11) must carry its JWT another way — the ?access_token= query parameter
// appended to the WS URL. The Authorization header is tried FIRST; the
// query parameter is consulted ONLY when the header is absent (the SPA
// never duplicates a header it could use into the URL). The raw value then
// goes through the EXACT same verification as requireJWT (authorizeJWT:
// signature + exp + iss + aud + role + denylist) BEFORE websocket.Accept
// runs, and the same 401 answers any failure. Scoping: the query fallback
// exists ONLY on this route — REST keeps requireJWT header-only above, so
// tokens never ride URLs (logs/history/proxies) anywhere but the one route
// where a browser WebSocket makes the header impossible.
func (a *authMiddleware) requireJWTWS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			raw = r.URL.Query().Get("access_token")
		}
		authed, err := a.authorizeJWT(r, raw)
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, authed)
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
			// Token verification (parseToken — local or external) rejects
			// unknown roles before this point; fail closed rather than guess.
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		}
	}
}

// bearerToken extracts the raw token from "Authorization: Bearer ***"; ""
// when the header is absent or uses any other scheme. The strict prefix
// check keeps e.g. "Bearerish xyz" out — parseToken must only ever see a
// real bearer value (or "").
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(h[len(bearerPrefix):])
}
