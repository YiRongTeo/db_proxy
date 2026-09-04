package api

// Shared JWT test identity + auth helpers for the api test suite (Task 5 of
// the JWT conversion). Every test-server fixture builds cfg.JWT from
// testJWTBlock(), and mintJWT signs with a cfg built from the same fixed
// values — so a token minted in a test verifies in the server's requireJWT.
// The secret is a dev-only constant; production secrets come from
// ${ZT_JWT_SECRET} and are fail-fast non-empty (config.go Task 2).
//
// The legacy session-planting helpers and the jar client were removed with
// the UI-session machinery in Task 4 — minted bearer tokens
// (mintJWT/withBearer) or the real /api/login endpoint (loginJWT) are the
// only auth paths left.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/config"
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
// the direct replacement for the legacy session-planting test helpers: mint
// a token for the desired user+role and send requests with the
// Authorization header (authHeader/withBearer). Since Task 6 the REAL login
// endpoint also returns such a token (see loginJWT); mintJWT stays for
// identities the login endpoint cannot authenticate (non-configured users —
// signJWT needs only the JWT config, so any sub+role can be minted).
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
// "Authorization: Bearer ***" per call. The underlying request is cloned
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
// token on every request. Use it after mintJWT to drive requireJWT-guarded
// routes (including the /api/token mint route since Task 7):
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

// loginJWT logs in through the real POST /api/login endpoint (Task 6
// contract: valid creds → 200 {token, username, role, expires_in}) and
// returns the issued bearer token.
func loginJWT(t *testing.T, client *http.Client, base, username, password string) string {
	t.Helper()
	resp, err := client.Post(base+"/api/login", "application/json",
		strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/login: status %d, want 200", resp.StatusCode)
	}
	var got struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode login body: %v", err)
	}
	if got.Token == "" {
		t.Fatal("POST /api/login: empty token")
	}
	return got.Token
}
