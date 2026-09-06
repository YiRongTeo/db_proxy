package api

// Phase 2 Task 2 — issuer-aware JWT validation: tokens are resolved by
// their iss claim to the LOCAL issuer (self-issued login tokens) or a
// configured auth.jwt.external_issuers entry, then verified against THAT
// issuer's HS256 secret + audience, with the issuer's claim mapping
// (subject/role claim names + role_aliases) applied to build the principal.
// External tokens without a jti are rejected when require_jti (the
// Task-1 config default) so the logout denylist applies to them too.
//
// These tests exercise the middleware directly (requireJWTCapture) and one
// full-HTTP logout round-trip. The accept-path cases need the LIVE Valkey
// (the jti denylist consult runs for every token carrying a jti) — same
// dependency as the rest of the suite (127.0.0.1:6379).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// Fixed external-issuer identity for the Phase 2 Task 2 fixtures: a
// third-party app sharing an HS256 secret with the plane. The iss and
// audience are distinct from the LOCAL testJWTIssuer/testJWTAudience so the
// resolution and audience-override paths are exercised honestly.
const (
	testExtIssuer   = "https://other-app.example"
	testExtSecret   = "external-unit-test-secret-not-for-production"
	testExtAudience = "zt-ext-api"
)

// boolPtr is the require_jti *bool helper (config leaves absent = nil,
// meaning TRUE at the consumer; tests that want the EXPLICIT false build
// the pointer here).
func boolPtr(b bool) *bool { return &b }

// extIssuer builds one ExternalIssuerConfig the way config VALIDATION would
// have materialized it for the api test cfg structs (which bypass
// config.Load): audience empty inherits the top-level testJWTAudience,
// require_jti absent defaults TRUE. opts override per test.
func extIssuer(name, iss, secret string, opts ...func(*config.ExternalIssuerConfig)) config.ExternalIssuerConfig {
	e := config.ExternalIssuerConfig{
		Name:       name,
		Iss:        iss,
		Audience:   testJWTAudience, // empty at load inherits the top-level audience (Task 1)
		Secret:     secret,
		RequireJTI: boolPtr(true), // absent in yaml defaults true (Task 1)
	}
	for _, o := range opts {
		o(&e)
	}
	return e
}

func extWithAudience(aud string) func(*config.ExternalIssuerConfig) {
	return func(e *config.ExternalIssuerConfig) { e.Audience = aud }
}

func extWithRequireJTI(b bool) func(*config.ExternalIssuerConfig) {
	return func(e *config.ExternalIssuerConfig) { e.RequireJTI = boolPtr(b) }
}

func extWithClaims(c config.ClaimMappingConfig) func(*config.ExternalIssuerConfig) {
	return func(e *config.ExternalIssuerConfig) { e.Claims = c }
}

// testExtFixture returns a middleware whose cfg carries the shared test JWT
// block PLUS the given external issuer entries (a deployment trusting the
// other app alongside local login).
func testExtFixture(exts ...config.ExternalIssuerConfig) *authMiddleware {
	j := testJWTBlock()
	j.ExternalIssuers = exts
	return &authMiddleware{cfg: &config.ControlConfig{
		AuthUser: "admin",
		AuthRole: "maker",
		JWT:      j,
	}}
}

// testExtStoreFixture wires testExtFixture to the LIVE Valkey — every token
// carrying a jti (local or external) hits the denylist consult in
// authorizeJWT, so the accept-path tests need a.vs.
func testExtStoreFixture(t *testing.T, exts ...config.ExternalIssuerConfig) *authMiddleware {
	t.Helper()
	a := testExtFixture(exts...)
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	a.vs = vs
	return a
}

// randomJTI returns a fresh random token id for tests that DENY a jti: the
// shared live Valkey denylist would otherwise carry a fixed jti across test
// runs within the deny TTL and poison the next run's pre-deny assertion.
func randomJTI(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b)
}

// TestExternalIssuerTokenAccepted: a valid external token (correct HS256
// secret, matching iss + audience, role maker, jti present) is accepted and
// the middleware injects the principal under sessionKey{} like a local
// token would.
func TestExternalIssuerTokenAccepted(t *testing.T) {
	a := testExtStoreFixture(t, extIssuer("other-app", testExtIssuer, testExtSecret))
	tok := mintExternalJWT(t, testExtSecret, testExtIssuer, testJWTAudience, "alice", "maker", "ext-jti-accepted")

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(tok)))
	if status != http.StatusOK {
		t.Fatalf("valid external token: status %d, want 200", status)
	}
	if sess == nil {
		t.Fatal("valid external token: no session injected")
	}
	if sess.Username != "alice" || sess.Role != "maker" {
		t.Errorf("injected session = %+v, want Username=alice Role=maker", sess)
	}
}

// TestExternalIssuerUnknownIssuerRejected: a well-signed token whose iss is
// neither the local issuer nor any configured external issuer → 401 (the
// token cannot be attributed to any trust root).
func TestExternalIssuerUnknownIssuerRejected(t *testing.T) {
	a := testExtFixture(extIssuer("other-app", testExtIssuer, testExtSecret))
	// Signed with the EXTERNAL secret (so it is a real token) but claiming
	// an iss nobody configured.
	tok := mintExternalJWT(t, testExtSecret, "https://evil.example", testJWTAudience, "alice", "maker", "jti-1")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("unknown-iss token: status %d, want 401", status)
	}
}

// TestExternalIssuerWrongSecretRejected: a token claiming the configured
// external iss but signed with a DIFFERENT secret (forged by someone who
// does not hold the shared key) → 401.
func TestExternalIssuerWrongSecretRejected(t *testing.T) {
	a := testExtFixture(extIssuer("other-app", testExtIssuer, testExtSecret))
	tok := mintExternalJWT(t, "an-attacker-chosen-secret", testExtIssuer, testJWTAudience, "alice", "maker", "jti-2")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("wrong-secret external token: status %d, want 401", status)
	}
}

// TestExternalIssuerMissingJTIRejected: require_jti defaults TRUE — an
// otherwise-valid external token WITHOUT a jti claim is rejected (it could
// never be revoked via the logout denylist).
func TestExternalIssuerMissingJTIRejected(t *testing.T) {
	a := testExtStoreFixture(t, extIssuer("other-app", testExtIssuer, testExtSecret))
	tok := mintExternalJWT(t, testExtSecret, testExtIssuer, testJWTAudience, "alice", "maker", "")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("jti-less external token (require_jti default true): status %d, want 401", status)
	}
}

// TestExternalIssuerRequireJTIFalseAllowsJtiLess: an EXPLICIT
// require_jti: false accepts a jti-less external token (the issuer cannot
// mint jti claims; the operator opted out of deniability for it). The
// denylist consult is skipped — no jti to key on.
func TestExternalIssuerRequireJTIFalseAllowsJtiLess(t *testing.T) {
	a := testExtStoreFixture(t, extIssuer("other-app", testExtIssuer, testExtSecret, extWithRequireJTI(false)))
	tok := mintExternalJWT(t, testExtSecret, testExtIssuer, testJWTAudience, "alice", "maker", "")

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(tok)))
	if status != http.StatusOK {
		t.Fatalf("jti-less external token (require_jti false): status %d, want 200", status)
	}
	if sess == nil || sess.Username != "alice" || sess.Role != "maker" {
		t.Errorf("injected session = %+v, want Username=alice Role=maker", sess)
	}
}

// TestExternalIssuerDenylistRevokes: an external token with a jti consults
// the SAME denylist as local tokens — once its jti is denied (the state
// /api/logout writes) the token is rejected 401 despite a valid signature.
func TestExternalIssuerDenylistRevokes(t *testing.T) {
	a := testExtStoreFixture(t, extIssuer("other-app", testExtIssuer, testExtSecret))
	jti := randomJTI(t)
	tok := mintExternalJWT(t, testExtSecret, testExtIssuer, testJWTAudience, "alice", "maker", jti)

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusOK {
		t.Fatalf("pre-deny external token: status %d, want 200", status)
	}
	if err := a.vs.DenyJWT(context.Background(), jti, 5*time.Minute); err != nil {
		t.Fatalf("DenyJWT: %v", err)
	}
	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("denied external token: status %d, want 401", status)
	}
}

// TestExternalIssuerClaimMapping: an external issuer configured with a
// NON-default claim shape — subject claim "user_name", role claim
// "user_role", role_aliases {approver: checker} — is verified and mapped:
// the principal's Username comes from user_name, the raw user_role value
// passes through the alias table (approver → checker), and a raw value that
// is neither aliased nor a canonical role is rejected. Unmapped canonical
// values pass through (identity translation).
func TestExternalIssuerClaimMapping(t *testing.T) {
	mapping := config.ClaimMappingConfig{
		Subject: "user_name",
		Role:    "user_role",
		RoleAliases: map[string]string{
			"approver": "checker",
		},
	}
	a := testExtStoreFixture(t, extIssuer("other-app", testExtIssuer, testExtSecret, extWithClaims(mapping)))

	// Custom-claim-name token builder for this issuer's shape.
	mint := func(username, role string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_name": username,
			"user_role": role,
			"iss":       testExtIssuer,
			"aud":       testJWTAudience,
			"exp":       time.Now().Add(5 * time.Minute).Unix(),
			"iat":       time.Now().Unix(),
			"jti":       randomJTI(t),
		})
		signed, err := tok.SignedString([]byte(testExtSecret))
		if err != nil {
			t.Fatalf("sign mapped token: %v", err)
		}
		return signed
	}

	// Alias applied: user_role=approver maps onto checker.
	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(mint("alice", "approver"))))
	if status != http.StatusOK {
		t.Fatalf("aliased role token: status %d, want 200", status)
	}
	if sess == nil || sess.Username != "alice" || sess.Role != "checker" {
		t.Errorf("injected session = %+v, want Username=alice Role=checker (alias approver→checker)", sess)
	}

	// Unmapped canonical role passes through untouched.
	sess, status = requireJWTCapture(t, a, bearerReq(authHeader(mint("bob", "checker"))))
	if status != http.StatusOK {
		t.Fatalf("raw canonical role token: status %d, want 200", status)
	}
	if sess == nil || sess.Role != "checker" {
		t.Errorf("injected session = %+v, want Role=checker (identity translation)", sess)
	}

	// Unmapped NON-canonical role → 401 (never carried into SoD decisions).
	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(mint("mallory", "superuser")))); status != http.StatusUnauthorized {
		t.Errorf("unmapped non-canonical role token: status %d, want 401", status)
	}
}

// TestExternalIssuerAudienceOverride: an issuer pinning its OWN audience
// (different from the top-level) verifies tokens aimed at the issuer
// audience; a token aimed at the top-level audience fails against this
// issuer.
func TestExternalIssuerAudienceOverride(t *testing.T) {
	a := testExtStoreFixture(t, extIssuer("other-app", testExtIssuer, testExtSecret, extWithAudience(testExtAudience)))

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(
		mintExternalJWT(t, testExtSecret, testExtIssuer, testExtAudience, "alice", "maker", "jti-aud-ok"))))
	if status != http.StatusOK {
		t.Fatalf("issuer-audience token: status %d, want 200", status)
	}
	if sess == nil || sess.Username != "alice" {
		t.Errorf("injected session = %+v, want Username=alice", sess)
	}

	// Top-level audience token is NOT accepted from this issuer.
	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(
		mintExternalJWT(t, testExtSecret, testExtIssuer, testJWTAudience, "alice", "maker", "jti-aud-wrong")))); status != http.StatusUnauthorized {
		t.Errorf("top-level-audience token vs issuer override: status %d, want 401", status)
	}
}

// TestExternalIssuerLocalTokensStillAccepted: with external issuers
// configured ALONGSIDE local login, self-issued tokens keep working — the
// issuer resolution must not disturb the local path (regression).
func TestExternalIssuerLocalTokensStillAccepted(t *testing.T) {
	a := testExtStoreFixture(t, extIssuer("other-app", testExtIssuer, testExtSecret))
	tok := mintJWT(t, a.cfg, "admin", "maker")

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(tok)))
	if status != http.StatusOK {
		t.Fatalf("local token with external issuers configured: status %d, want 200", status)
	}
	if sess == nil || sess.Username != "admin" || sess.Role != "maker" {
		t.Errorf("injected session = %+v, want Username=admin Role=maker", sess)
	}
}

// TestExternalIssuerMalformedTokenRejected: garbage in → 401 (fail closed —
// the issuer resolution cannot even read a iss claim).
func TestExternalIssuerMalformedTokenRejected(t *testing.T) {
	a := testExtFixture(extIssuer("other-app", testExtIssuer, testExtSecret))
	if _, status := requireJWTCapture(t, a, bearerReq("Bearer not-a-jwt")); status != http.StatusUnauthorized {
		t.Errorf("garbage token: status %d, want 401", status)
	}
}

// newExtAPIServer builds the real Control Plane mux (login enabled, LIVE
// Valkey) with the given external issuers configured — the full HTTP path
// for the logout round-trip test.
func newExtAPIServer(t *testing.T, exts ...config.ExternalIssuerConfig) (*httptest.Server, *http.Client, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	jwt := testJWTBlock()
	jwt.ExternalIssuers = exts
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "maker",
		JWT:          jwt,
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, cfg
}

// TestExternalIssuerLogoutDenylists: handleLogout parses the presented
// token through the SAME issuer-aware path as requireJWT — an EXTERNAL
// token can be logged out: POST /api/logout denylists its jti (TTL = the
// token's remaining life) and replaying it on a guarded route answers 401.
func TestExternalIssuerLogoutDenylists(t *testing.T) {
	srv, client, _ := newExtAPIServer(t, extIssuer("other-app", testExtIssuer, testExtSecret))
	jti := randomJTI(t)
	tok := mintExternalJWT(t, testExtSecret, testExtIssuer, testJWTAudience, "alice", "checker", jti)

	// Pre-logout the external token authenticates a guarded route.
	authed := withBearer(client, tok)
	me, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me before logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me with external token: status %d, want 200", me.StatusCode)
	}

	// Logout accepts the external token (issuer-aware parse) and denies it.
	resp, _ := logoutBearer(t, authed, srv.URL, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout of external token: status %d, want 200", resp.StatusCode)
	}

	// Replay → 401: the external jti sits on the denylist.
	me, err = authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me after logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/me with logged-out external token: status %d, want 401", me.StatusCode)
	}
}

// --- Phase 2 Task 4b: /api/logout must exist in EXTERNAL-ONLY mode -------

// newExtOnlyAPIServer builds the real Control Plane mux in EXTERNAL-ONLY
// mode (auth.jwt.login_enabled=false): the local login machinery is gone —
// primary-account credentials and the local signing secret are deliberately
// unset, exactly as an external-only deployment loads (Task-1 validation:
// login_enabled=false requires >=1 external issuer, and the local secret is
// then NOT required). Configured external issuers are the ONLY trust roots.
func newExtOnlyAPIServer(t *testing.T, exts ...config.ExternalIssuerConfig) (*httptest.Server, *http.Client, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	jwt := config.JWTConfig{
		Enabled:         true,
		LoginEnabled:    false, // external-only: no self-issued tokens, no local login
		Issuer:          testJWTIssuer,
		Audience:        testJWTAudience,
		TTLSeconds:      testJWTTTL,
		ExternalIssuers: exts,
		// Secret left EMPTY — the local self-issuer does not exist in this mode.
	}
	cfg := &config.ControlConfig{
		JWT:       jwt,
		SessionTTL: 8,
		TokenTTL:   60,
		StaticDir:  t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, cfg
}

// TestExternalOnlyModeLogoutRegistered: Task 4b regression — with
// login_enabled=false POST /api/logout must STILL be registered, so
// external tokens are revocable server-side in the exact deployment Phase 2
// exists for (the Task-4 E2E finding: the route used to 404 with login
// disabled, leaving the jti denylist unreachable over HTTP). The endpoint
// is self-authenticating — it verifies the presented bearer via the
// issuer-aware parseToken path and denylists its jti — so it has no
// dependency on the local login machinery. POST /api/login stays
// conditional (404 here).
func TestExternalOnlyModeLogoutRegistered(t *testing.T) {
	srv, client, _ := newExtOnlyAPIServer(t, extIssuer("other-app", testExtIssuer, testExtSecret))
	jti := randomJTI(t)
	tok := mintExternalJWT(t, testExtSecret, testExtIssuer, testJWTAudience, "alice", "maker", jti)

	// login stays conditional: POST /api/login → 404 in external-only mode.
	if resp, _ := doLogin(t, client, srv.URL, testJWTUser, testJWTPassword); resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /api/login with login_enabled=false: status %d, want 404 (route must stay conditional)", resp.StatusCode)
	}

	// The external token authenticates a guarded route pre-logout.
	authed := withBearer(client, tok)
	me, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me before logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me with external token (login disabled): status %d, want 200", me.StatusCode)
	}

	// Logout must be LIVE in external-only mode: 200 means the route is
	// registered AND the external token verified + denylisted (a missing
	// route would answer 404 — the E2E bug this test guards).
	resp, body := logoutBearer(t, authed, srv.URL, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/logout with login_enabled=false: status %d, want 200 (route must be registered unconditionally; body %s)", resp.StatusCode, body)
	}

	// Replay → 401: the external jti sits on the denylist in external-only mode.
	me, err = authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me after logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/me with logged-out external token (login disabled): status %d, want 401", me.StatusCode)
	}
}

// TestExternalOnlyModeLogoutRejectsBadBearer: the unconditionally-registered
// logout is self-authenticating — a missing or unverifiable bearer answers
// 401 in external-only mode too (nothing to revoke, nothing leaked).
func TestExternalOnlyModeLogoutRejectsBadBearer(t *testing.T) {
	srv, client, _ := newExtOnlyAPIServer(t, extIssuer("other-app", testExtIssuer, testExtSecret))

	cases := map[string]string{
		"no bearer":    "",
		"garbage":      "Bearer not-a-jwt",
		"wrong secret": "Bearer " + mintExternalJWT(t, "not-the-shared-secret", testExtIssuer, testJWTAudience, "alice", "maker", "jti-wrong-secret"),
	}
	for name, hdr := range cases {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/logout", nil)
		if err != nil {
			t.Fatalf("%s: new logout request: %v", name, err)
		}
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: POST /api/logout: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s on logout (login disabled): status %d, want 401", name, resp.StatusCode)
		}
	}
}
