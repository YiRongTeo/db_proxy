package api

// Task 5 — requireJWT unit tests. The middleware is exercised directly (no
// Valkey needed): a requireJWT-wrapped handler captures the session
// requireJWT injects under sessionKey{}, exactly as sessionFrom(r)
// consumers see it. The full HTTP contract (401 bodies, route wiring) is
// covered by the migrated route tests (me/kill/sessions/ws).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// requireJWTCapture runs req through a requireJWT-wrapped handler that
// records the injected session, and returns (session, status).
func requireJWTCapture(t *testing.T, a *authMiddleware, req *http.Request) (*models.Session, int) {
	t.Helper()
	var got *models.Session
	h := a.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		got = sessionFrom(r)
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	h(rec, req)
	return got, rec.Code
}

// testJWTFixture returns a middleware whose cfg carries the shared test JWT
// block (jwt.enabled + secret + issuer + audience).
func testJWTFixture() *authMiddleware {
	return &authMiddleware{cfg: &config.ControlConfig{
		AuthUser: "admin",
		AuthRole: "maker",
		JWT:      testJWTBlock(),
	}}
}

// testJWTStoreFixture is testJWTFixture wired to the LIVE Valkey — the jti
// denylist consult in requireJWT (Task 6) needs a.vs. Only the
// acceptance-path tests need it: every rejection branch fails in parseJWT
// (or at the header) before the store is touched, so the plain cfg-only
// fixture stays sufficient for them.
func testJWTStoreFixture(t *testing.T) *authMiddleware {
	t.Helper()
	a := testJWTFixture()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	a.vs = vs
	return a
}

// jwtID parses a signed token with the config secret and returns its jti
// claim — test access to the denylist key of a minted token.
func jwtID(t *testing.T, cfg *config.ControlConfig, tok string) string {
	t.Helper()
	claims := &jwtClaims{}
	_, err := jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) {
		return []byte(cfg.JWT.Secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		t.Fatalf("parse token for jti: %v", err)
	}
	if claims.ID == "" {
		t.Fatal("token carries no jti")
	}
	return claims.ID
}

// bearerReq builds a GET request with the given Authorization header value
// ("" = no header at all).
func bearerReq(header string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	return req
}

// TestRequireJWTValidTokenInjectsSession: a token minted by signJWT for
// alice/checker is accepted and the middleware injects
// *models.Session{Username: alice, Role: checker} under sessionKey{} — the
// same shape the legacy cookie middleware provided, so sessionFrom(r)
// consumers (handleMe, SoD checkerMayWatch, audit, mint binding) are
// unchanged.
func TestRequireJWTValidTokenInjectsSession(t *testing.T) {
	a := testJWTStoreFixture(t)
	tok := mintJWT(t, a.cfg, "alice", "checker")

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(tok)))
	if status != http.StatusOK {
		t.Fatalf("valid token: status %d, want 200", status)
	}
	if sess == nil {
		t.Fatal("valid token: no session injected")
	}
	if sess.Username != "alice" || sess.Role != "checker" {
		t.Errorf("injected session = %+v, want Username=alice Role=checker", sess)
	}
}

// TestRequireJWTValidTokenMakerRole: the maker role round-trips too.
func TestRequireJWTValidTokenMakerRole(t *testing.T) {
	a := testJWTStoreFixture(t)
	tok := mintJWT(t, a.cfg, "bob", "maker")

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(tok)))
	if status != http.StatusOK {
		t.Fatalf("valid maker token: status %d, want 200", status)
	}
	if sess == nil || sess.Role != "maker" || sess.Username != "bob" {
		t.Errorf("injected session = %+v, want Username=bob Role=maker", sess)
	}
}

// TestRequireJWTDeniedToken: a token whose jti sits on the Valkey denylist
// (Task 6 — the state /api/logout writes) is rejected with 401 even though
// its signature/exp/iss/aud/role all verify. The consult runs AFTER
// signature validation, so only genuinely valid tokens reach it.
func TestRequireJWTDeniedToken(t *testing.T) {
	a := testJWTStoreFixture(t)
	tok := mintJWT(t, a.cfg, "alice", "checker")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusOK {
		t.Fatalf("pre-deny status %d, want 200", status)
	}
	if err := a.vs.DenyJWT(context.Background(), jwtID(t, a.cfg, tok), 5*time.Minute); err != nil {
		t.Fatalf("DenyJWT: %v", err)
	}
	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("denied token: status %d, want 401", status)
	}
}

// TestRequireJWTExpiredToken: a token whose exp is in the past → 401.
func TestRequireJWTExpiredToken(t *testing.T) {
	a := testJWTFixture()
	expired, err := signJWT(a.cfg, "alice", "maker", -1*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(expired))); status != http.StatusUnauthorized {
		t.Errorf("expired token: status %d, want 401", status)
	}
}

// TestRequireJWTBadSignature: a token signed with a DIFFERENT secret → 401.
func TestRequireJWTBadSignature(t *testing.T) {
	a := testJWTFixture()
	forged := &config.ControlConfig{JWT: testJWTBlock()}
	forged.JWT.Secret = "an-attacker-chosen-secret"
	tok := mintJWT(t, forged, "alice", "maker")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("bad-signature token: status %d, want 401", status)
	}
}

// TestRequireJWTWrongIssuer: a well-signed token from another issuer → 401.
func TestRequireJWTWrongIssuer(t *testing.T) {
	a := testJWTFixture()
	other := &config.ControlConfig{JWT: testJWTBlock()}
	other.JWT.Issuer = "some-other-issuer"
	tok := mintJWT(t, other, "alice", "maker")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("wrong-issuer token: status %d, want 401", status)
	}
}

// TestRequireJWTWrongAudience: a token aimed at another audience → 401.
func TestRequireJWTWrongAudience(t *testing.T) {
	a := testJWTFixture()
	other := &config.ControlConfig{JWT: testJWTBlock()}
	other.JWT.Audience = "some-other-api"
	tok := mintJWT(t, other, "alice", "maker")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("wrong-audience token: status %d, want 401", status)
	}
}

// TestRequireJWTMissingRoleClaim: a well-signed token WITHOUT the role
// claim is rejected — the plan decision is explicit over default: an
// un-role'd principal would be an accidental superuser.
func TestRequireJWTMissingRoleClaim(t *testing.T) {
	a := testJWTFixture()
	// Sign with ONLY registered claims (no role) using the trusted secret —
	// exactly what a self-issuer bug or an external issuer with no role
	// vocabulary would produce.
	now := time.Now()
	noRole := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "alice",
		Issuer:    testJWTIssuer,
		Audience:  jwt.ClaimStrings{testJWTAudience},
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        "no-role-jti",
	})
	tok, err := noRole.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign no-role token: %v", err)
	}

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("missing-role token: status %d, want 401", status)
	}
}

// TestRequireJWTUnknownRoleClaim: a role that is not maker|checker (e.g. a
// forged "superuser") is rejected like a missing role.
func TestRequireJWTUnknownRoleClaim(t *testing.T) {
	a := testJWTFixture()
	unknown := &config.ControlConfig{JWT: testJWTBlock()}
	tok, err := signJWT(unknown, "alice", "superuser", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("unknown-role token: status %d, want 401", status)
	}
}

// TestRequireJWTMissingOrMalformedHeader: absent header, wrong scheme and
// an empty token all → 401.
func TestRequireJWTMissingOrMalformedHeader(t *testing.T) {
	a := testJWTFixture()
	tok := mintJWT(t, a.cfg, "alice", "maker")

	cases := map[string]string{
		"no header":    "",
		"wrong scheme": "Basic " + tok,
		"empty bearer": "Bearer ",
		"bare token":   tok, // no "Bearer " prefix
		"garbage":      "Bearer not-a-jwt",
	}
	for name, h := range cases {
		if _, status := requireJWTCapture(t, a, bearerReq(h)); status != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, status)
		}
	}
}

// TestRequireJWTRejectsWhenJWTDisabled: with jwt.enabled=false (JWT
// verification disabled — there is NO legacy cookie mode; an explicitly
// disabled JWT trust is a misconfiguration) requireJWT fails CLOSED — even
// a correctly signed token is rejected because no JWT trust is configured.
// (Route tests run with jwt.enabled=true; this pins the fail-closed branch.)
func TestRequireJWTRejectsWhenJWTDisabled(t *testing.T) {
	disabled := &config.ControlConfig{JWT: config.JWTConfig{Enabled: false, LoginEnabled: true}}
	a := &authMiddleware{cfg: disabled}
	tok := mintJWT(t, testJWTFixture().cfg, "alice", "maker")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("jwt.disabled: status %d, want 401 (fail closed)", status)
	}
}
