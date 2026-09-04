package api

// Shared JWT test identity + auth helpers for the api test suite (Task 5 of
// the JWT conversion). Every test-server fixture builds cfg.JWT from
// testJWTBlock(), and mintJWT signs with a cfg built from the same fixed
// values — so a token minted in a test verifies in the server's requireJWT.
// The secret is a dev-only constant; production secrets come from
// ${ZT_JWT_SECRET} and are fail-fast non-empty (config.go Task 2).

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// Fixed identity for the fixtures' primary account.
const (
	testJWTUser     = "admin"
	testJWTPassword = "s3cret"
)

// The fixed JWT block every fixture shares: same secret/issuer/audience so
// mintJWT output verifies in requireJWT.
const (
	testJWTSecret   = "unit-test-jwt-secret-not-for-production"
	testJWTIssuer   = "zerotrust-proxy"
	testJWTAudience = "zt-api"
	testJWTTTL      = 28800 // seconds — mirrors the legacy 8h session TTL
)

// testJWTBlock returns the auth.jwt config every api test fixture must
// carry: jwt.enabled + login_enabled + a secret so mintJWT and requireJWT
// work (Task 5). requireJWT fails closed without it.
func testJWTBlock() config.JWTConfig {
	return config.JWTConfig{
		Enabled:      true,
		LoginEnabled: true,
		Issuer:       testJWTIssuer,
		Audience:     testJWTAudience,
		TTLSeconds:   testJWTTTL,
		Secret:       testJWTSecret,
	}
}

// mintJWT signs a VALID HS256 token for username with role, bound to cfg's
// JWT issuer/audience/secret: short exp (5 minutes), jti present. This is
// the direct replacement for the cookie-session test helpers: mint a token
// for the desired user+role and send requests with the Authorization header
// (authHeader/withBearer). login still issues COOKIES until Task 6 — tests
// must NOT expect /api/login to return a JWT yet.
func mintJWT(t *testing.T, cfg *config.ControlConfig, username, role string) string {
	t.Helper()
	tok, err := signJWT(cfg, username, role, 5*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("mintJWT(%s, %s): %v", username, role, err)
	}
	return tok
}

// authHeader returns the Authorization header value for a token.
func authHeader(token string) string {
	return "Bearer " + token
}

// bearerTransport is an http.RoundTripper that attaches the bearer token to
// every request it forwards — the test-side equivalent of the SPA attaching
// "Authorization: Bearer <jwt>" per call. The underlying request is cloned
// so the caller's headers are never mutated.
type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", authHeader(t.token))
	return t.base.RoundTrip(req)
}

// withBearer returns a shallow copy of client that sends the given bearer
// token on every request (cookie jar and other settings are preserved). Use
// it after mintJWT to drive requireJWT-guarded routes:
//
//	client = withBearer(client, mintJWT(t, cfg, "admin", "maker"))
func withBearer(client *http.Client, token string) *http.Client {
	clone := *client
	base := clone.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone.Transport = bearerTransport{base: base, token: token}
	return &clone
}

// newJarClient returns an http.Client with a fresh cookie jar — the shape
// every fixture historically returned (the jar still matters while the
// legacy zt_session cookie legs of /api/token and /api/login exist; Task 4
// retires the cookie machinery and the jars with it).
func newJarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar}
}

// loginViaAPI logs in through the real POST /api/login endpoint, letting
// the cookie jar capture the zt_session cookie. KEPT (cookie-based): it is
// the LEGACY session source for /api/token, whose bare route still resolves
// sessions from the cookie until Task 4/7 migrates it — and /api/login
// still issues cookies until Task 6. requireJWT-guarded routes do NOT
// accept the cookie: pair the cookie session with withBearer(mintJWT(...))
// when a flow hits both /api/token and a guarded route.
func loginViaAPI(t *testing.T, client *http.Client, base string) {
	t.Helper()
	resp, err := client.Post(base+"/api/login", "application/json",
		strings.NewReader(`{"username":"`+testJWTUser+`","password":"`+testJWTPassword+`"}`))
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/login: status %d, want 200", resp.StatusCode)
	}
}

// sessionAs creates a LEGACY UI session for user directly in Valkey and
// installs the zt_session cookie on the client — the session source for
// flows that mint tokens as a NON-configured user through /api/token (its
// bare route resolves sessions from the cookie until Task 4/7; the login
// endpoint only ever authenticates configured accounts). SessionAs itself
// is deleted with the cookie machinery in Task 4; until then, flows that
// ALSO hit requireJWT-guarded routes pair it with
// withBearer(mintJWT(...)) so those legs run on the bearer token.
func sessionAs(t *testing.T, client *http.Client, base string, vs *store.ValkeyStore, user string) {
	t.Helper()
	id, err := vs.CreateSession(context.Background(), models.Session{Username: user}, 8*time.Hour)
	if err != nil {
		t.Fatalf("CreateSession(%q): %v", user, err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base %q: %v", base, err)
	}
	client.Jar.SetCookies(u, []*http.Cookie{{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}})
}
