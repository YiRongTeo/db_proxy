package api

// Phase 2b Task 2 — relaxed external-issuer acceptance: the integrating
// app's real JWT carries NO iss/aud/jti claims, its principal rides
// "username", its role rides "role" with the app's OWN capitalization
// ("Maker"/"Checker"), and "sessionId" carries the IdP login session id
// (logs/tracing only). The per-issuer config relaxations built in Task 1
// (require_iss:false, require_aud:false) plus the existing
// require_jti:false and the claims mapping (subject/role names,
// session_id claim name, case-insensitive role_aliases) must accept this
// shape and map it onto the canonical principal.
//
// These tests exercise the middleware directly (requireJWTCapture) like
// the Phase 2 Task 2 suite. Accept-path cases carry no jti, so the
// denylist consult is skipped — but testExtStoreFixture is used anyway
// for consistency with the sibling tests where a store exists.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// extWithRequireISS / extWithRequireAud: *bool opts for the relaxed
// entries (absent = nil = TRUE strict default at the consumer, mirroring
// boolPtr for require_jti).
func extWithRequireISS(b bool) func(*config.ExternalIssuerConfig) {
	return func(e *config.ExternalIssuerConfig) { e.RequireISS = boolPtr(b) }
}

func extWithRequireAud(b bool) func(*config.ExternalIssuerConfig) {
	return func(e *config.ExternalIssuerConfig) { e.RequireAud = boolPtr(b) }
}

// otherAppIssuer builds the REAL integrating-app entry: no iss (relaxed),
// no aud (relaxed), no jti required, claims mapping username→sub,
// role→role, sessionId→session_id, aliases for the app's capitalized
// values. Issuer audience is left EMPTY — require_aud:false makes that a
// legal config (Task 1), and parseExternalJWT must not demand it.
func otherAppIssuer() config.ExternalIssuerConfig {
	return extIssuer("other-app-real", "", testExtSecret,
		extWithRequireISS(false),
		extWithRequireAud(false),
		extWithRequireJTI(false),
		extWithClaims(config.ClaimMappingConfig{
			Subject:   "username",
			Role:      "role",
			SessionID: "sessionId",
			RoleAliases: map[string]string{
				"maker":   "maker", // viper-lowercased form of "Maker"
				"checker": "checker",
			},
		}),
	)
}

// TestOtherAppRealShapeAccepted: the integrating app's actual token shape
// — no iss/aud/jti, username/role("Maker")/sessionId claims — is accepted
// and mapped onto the canonical principal (Username from "username", Role
// maker via the case-insensitive alias, LoginSessionID carried).
func TestOtherAppRealShapeAccepted(t *testing.T) {
	a := testExtStoreFixture(t, otherAppIssuer())
	tok := mintOtherAppJWT(t, testExtSecret, "alice", "Maker", "sess-login-123")

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(tok)))
	if status != http.StatusOK {
		t.Fatalf("other-app real-shape token: status %d, want 200", status)
	}
	if sess == nil {
		t.Fatal("other-app real-shape token: no session injected")
	}
	if sess.Username != "alice" || sess.Role != "maker" {
		t.Errorf("injected session = %+v, want Username=alice Role=maker (mapped via aliases)", sess)
	}
	if sess.LoginSessionID != "sess-login-123" {
		t.Errorf("LoginSessionID = %q, want sess-login-123 (parsed from the sessionId claim)", sess.LoginSessionID)
	}
}

// TestOtherAppRealShapeCheckerRole: the same shape with role "Checker"
// maps to the canonical checker — the alias translation is case-insensitive
// for BOTH capitalized values.
func TestOtherAppRealShapeCheckerRole(t *testing.T) {
	a := testExtFixture(otherAppIssuer())
	tok := mintOtherAppJWT(t, testExtSecret, "bob", "Checker", "sess-login-456")

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(tok)))
	if status != http.StatusOK {
		t.Fatalf("checker-role real-shape token: status %d, want 200", status)
	}
	if sess == nil || sess.Username != "bob" || sess.Role != "checker" {
		t.Errorf("injected session = %+v, want Username=bob Role=checker", sess)
	}
}

// TestOtherAppRealShapeUnknownRoleRejected: an unaliased non-canonical
// role value ("superuser") in the other app's shape still 401s — the
// case-insensitive alias lookup must NOT invent a mapping.
func TestOtherAppRealShapeUnknownRoleRejected(t *testing.T) {
	a := testExtFixture(otherAppIssuer())
	tok := mintOtherAppJWT(t, testExtSecret, "alice", "superuser", "sess-login-789")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("unaliased role value: status %d, want 401", status)
	}
}

// TestOtherAppRealShapeWrongSecretRejected: the relaxed shape signed with
// the WRONG secret (no configured trust root verifies it) → 401. The
// iss-less fallback must only ever accept a token some configured secret
// verifies.
func TestOtherAppRealShapeWrongSecretRejected(t *testing.T) {
	a := testExtFixture(otherAppIssuer())
	tok := mintOtherAppJWT(t, "an-attacker-chosen-secret", "alice", "Maker", "sess-evil")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("wrong-secret real-shape token: status %d, want 401", status)
	}
}

// TestIssLessResolutionTriesRelaxedEntriesInOrder: with TWO require_iss:
// false entries, an iss-less token signed with the SECOND entry's secret
// is accepted (resolution tries entry 1, fails, entry 2 verifies) — and a
// token no entry's secret verifies is rejected.
func TestIssLessResolutionTriesRelaxedEntriesInOrder(t *testing.T) {
	e1 := otherAppIssuer()
	e1.Name = "relaxed-a"
	e1.Secret = "relaxed-secret-a-0123456789abcdefghijklmnopqrstuv"
	e2 := otherAppIssuer()
	e2.Name = "relaxed-b"
	e2.Secret = "relaxed-secret-b-0123456789abcdefghijklmnopqrstuv"
	a := testExtStoreFixture(t, e1, e2)

	// Signed by entry B — entry A's secret fails first, B verifies.
	tok := mintOtherAppJWT(t, e2.Secret, "alice", "Maker", "sess-b")
	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(tok)))
	if status != http.StatusOK {
		t.Fatalf("iss-less token signed by 2nd relaxed entry: status %d, want 200", status)
	}
	if sess == nil || sess.Username != "alice" || sess.Role != "maker" {
		t.Errorf("injected session = %+v, want Username=alice Role=maker", sess)
	}

	// No entry's secret verifies → 401.
	bad := mintOtherAppJWT(t, "no-entry-holds-this-secret", "alice", "Maker", "sess-x")
	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(bad))); status != http.StatusUnauthorized {
		t.Errorf("iss-less token no entry verifies: status %d, want 401", status)
	}
}

// TestStrictEntryNeverTriedForIssLessToken: an iss-less token is NEVER
// tried against an entry with the strict default (RequireISS nil/true) —
// even one whose secret would verify. The relaxation is per-entry opt-in.
func TestStrictEntryNeverTriedForIssLessToken(t *testing.T) {
	// Strict entry: iss set, RequireISS absent (nil = TRUE).
	strict := extIssuer("strict-app", testExtIssuer, testExtSecret)
	a := testExtStoreFixture(t, strict)
	// Same secret as the strict entry, but NO iss claim — the strict entry
	// must not be consulted for an iss-less token.
	tok := mintExternalJWT(t, testExtSecret, "", testJWTAudience, "alice", "maker", "jti-strict")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusUnauthorized {
		t.Errorf("iss-less token vs strict entry: status %d, want 401 (relaxation is opt-in)", status)
	}
}

// TestAudRelaxedEntryAcceptsAudLessToken: require_aud:false accepts a
// token with no aud claim (the entry's audience may even be empty).
func TestAudRelaxedEntryAcceptsAudLessToken(t *testing.T) {
	a := testExtStoreFixture(t, otherAppIssuer()) // require_aud:false, empty audience
	tok := mintOtherAppJWT(t, testExtSecret, "alice", "Maker", "sess-audless")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(tok))); status != http.StatusOK {
		t.Errorf("aud-less token vs require_aud:false entry: status %d, want 200", status)
	}
}

// TestStrictAudStillEnforced: an entry WITHOUT require_aud:false still
// rejects a token whose aud is missing — the strict default survives
// alongside the relaxed entries.
func TestStrictAudStillEnforced(t *testing.T) {
	strict := extIssuer("strict-app", testExtIssuer, testExtSecret) // RequireAud nil = strict
	a := testExtFixture(strict)
	// Mint with the strict entry's secret + iss, but NO aud claim.
	claims := mapClaimsNoAud(t, testExtSecret, testExtIssuer, "alice", "maker", "jti-audless")

	if _, status := requireJWTCapture(t, a, bearerReq(authHeader(claims))); status != http.StatusUnauthorized {
		t.Errorf("aud-less token vs strict entry: status %d, want 401", status)
	}
}

// TestSessionIDClaimNameCustom: an issuer whose session-id claim is named
// differently (claims.session_id config) maps it onto LoginSessionID.
func TestSessionIDClaimNameCustom(t *testing.T) {
	e := otherAppIssuer()
	e.Claims.SessionID = "login" // the issuer calls it "login", not "sessionId"
	a := testExtStoreFixture(t, e)

	// Mint the other-app shape but rename sessionId → login.
	raw := mintOtherAppJWT(t, testExtSecret, "alice", "Maker", "sess-custom-name")
	// Re-sign with the claim renamed — build inline for the custom name.
	claims := reSignWithSessionIDName(t, raw, "login", testExtSecret)

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(claims)))
	if status != http.StatusOK {
		t.Fatalf("custom session-id claim name: status %d, want 200", status)
	}
	if sess == nil || sess.LoginSessionID != "sess-custom-name" {
		t.Errorf("LoginSessionID = %+v, want sess-custom-name (read from the 'login' claim)", sess)
	}
}

// TestSessionIDAbsentIsEmpty: a valid relaxed token WITHOUT any
// session-id claim is accepted; LoginSessionID is empty (tracing field is
// optional, never a gate).
func TestSessionIDAbsentIsEmpty(t *testing.T) {
	a := testExtStoreFixture(t, otherAppIssuer())
	claims := mapClaimsNoSessionID(t, testExtSecret, "alice", "Maker")

	sess, status := requireJWTCapture(t, a, bearerReq(authHeader(claims)))
	if status != http.StatusOK {
		t.Fatalf("no-sessionId token: status %d, want 200", status)
	}
	if sess == nil || sess.Username != "alice" || sess.Role != "maker" {
		t.Errorf("injected session = %+v, want Username=alice Role=maker", sess)
	}
	if sess.LoginSessionID != "" {
		t.Errorf("LoginSessionID = %q, want empty when the claim is absent", sess.LoginSessionID)
	}
}

// newPhase2bServer builds a full HTTP Control Plane mux whose JWT config
// trusts the REAL other-app issuer (relaxed: no iss/aud/jti required)
// alongside local login — the deployment the integration produces.
func newPhase2bServer(t *testing.T) (*httptest.Server, *http.Client, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	jwt := testJWTBlock()
	jwt.LoginEnabled = true
	jwt.ExternalIssuers = []config.ExternalIssuerConfig{otherAppIssuer()}
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

// TestLogoutJtiLessTokenRevokedFalse (Phase 2b Task 3): a VALID jti-less
// external token (the integrating app's real shape) logged out over HTTP →
// 200 {"ok":"true","revoked":false} — nothing server-side exists to
// revoke, and the token REMAINS usable until exp (client-side discard is
// the only revocation; the warn log records the un-revocable logout).
func TestLogoutJtiLessTokenRevokedFalse(t *testing.T) {
	srv, client, _ := newPhase2bServer(t)
	tok := mintOtherAppJWT(t, testExtSecret, "alice", "Maker", "sess-logout-1")
	authed := withBearer(client, tok)

	// Pre-logout: the token works.
	me, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me before logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me before logout: status %d, want 200", me.StatusCode)
	}

	resp, body := logoutBearer(t, authed, srv.URL, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout of jti-less token: status %d, want 200 (revoked:false contract)", resp.StatusCode)
	}
	if !strings.Contains(body, `"ok":"true"`) || !strings.Contains(body, `"revoked":false`) {
		t.Errorf("logout body = %s, want {\"ok\":\"true\",\"revoked\":false}", body)
	}

	// The token is NOT deniable — it still works (documented semantics:
	// no jti → nothing on the denylist; lives until exp).
	me, err = authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me after jti-less logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Errorf("GET /api/me after jti-less logout: status %d, want 200 (un-revocable token lives until exp)", me.StatusCode)
	}
}

// TestLogoutWithJtiStillRevokes (Phase 2b Task 3 regression): the WITH-jti
// path is unchanged — logout returns 200 {"ok":"true","revoked":true} and
// the token is denylisted (replay 401). Guards against the revoked:false
// branch widening to tokens that CAN be revoked. Uses a strict external
// entry (iss/aud/jti required) so the with-jti denylist path is exercised.
func TestLogoutWithJtiStillRevokes(t *testing.T) {
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	jwt := testJWTBlock()
	jwt.LoginEnabled = true
	jwt.ExternalIssuers = []config.ExternalIssuerConfig{
		extIssuer("strict-app", testExtIssuer, testExtSecret),
	}
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
	client := &http.Client{}

	jti := randomJTI(t)
	tok := mintExternalJWT(t, testExtSecret, testExtIssuer, testJWTAudience, "alice", "maker", jti)
	authed := withBearer(client, tok)

	resp, body := logoutBearer(t, authed, srv.URL, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout of jti-bearing token: status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, `"ok":"true"`) || !strings.Contains(body, `"revoked":true`) {
		t.Errorf("logout body = %s, want {\"ok\":\"true\",\"revoked\":true}", body)
	}
	// Replay → 401 (denylisted).
	me, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me after logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/me with revoked token: status %d, want 401", me.StatusCode)
	}
}
