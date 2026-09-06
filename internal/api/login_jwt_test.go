package api

// Task 6 — /api/login + /api/logout JWT contract. login_enabled=true:
// POST /api/login validates credentials (constant-time, rate-limited) and
// answers 200 {token, username, role, expires_in} — the bearer token IS the
// credential; nothing is stored server-side. The issued token drives the
// requireJWT-guarded routes. POST /api/logout denylists the presented
// token's jti in Valkey (TTL = remaining token life), so replaying the same
// token on a guarded route → 401. login_enabled=false (Phase 2 Task 4b):
// POST /api/login is NOT registered → 404 via the spaHandler /api guard,
// while POST /api/logout IS registered unconditionally — it is
// self-authenticating (bearer → issuer-aware parse → jti denylist), so
// external-only deployments keep a server-side HTTP deny path; an
// unauthenticated logout answers 401, never 404.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// loginResponse is the Task 6 success payload of POST /api/login.
type loginResponse struct {
	Token     string `json:"token"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	ExpiresIn int    `json:"expires_in"`
}

// newJWTLoginServer builds the Control Plane mux with the shared test JWT
// block and optional extra auth.users. loginEnabled=false exercises the
// conditional /api/login registration (login falls through to the /api
// guard → 404) while /api/logout stays registered (Phase 2 Task 4b).
func newJWTLoginServer(t *testing.T, loginEnabled bool, users []config.AuthUserConfig) (*httptest.Server, *http.Client, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	jwt := testJWTBlock()
	jwt.LoginEnabled = loginEnabled
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "maker",
		JWT:          jwt,
		AuthUsers:    users,
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, cfg
}

// doLogin posts /api/login and returns the response plus the decoded body
// (zero loginResponse when the status is not 200).
func doLogin(t *testing.T, client *http.Client, base, username, password string) (*http.Response, loginResponse) {
	t.Helper()
	resp, err := client.Post(base+"/api/login", "application/json",
		strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	if err != nil {
		t.Fatalf("POST /api/login(%s): %v", username, err)
	}
	defer resp.Body.Close()
	var got loginResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode login body: %v", err)
		}
	}
	return resp, got
}

// logoutBearer posts /api/logout presenting token and returns the status.
func logoutBearer(t *testing.T, client *http.Client, base, token string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/logout", nil)
	if err != nil {
		t.Fatalf("new logout request: %v", err)
	}
	req.Header.Set("Authorization", authHeader(token))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /api/logout: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// TestLoginEnabledReturnsJWT: valid credentials → 200 {token, username,
// role, expires_in} with NO cookie; the issued token authenticates a
// requireJWT-guarded route (/api/me → 200 with the principal).
func TestLoginEnabledReturnsJWT(t *testing.T) {
	srv, client, _ := newJWTLoginServer(t, true, nil)

	resp, got := doLogin(t, client, srv.URL, testJWTUser, testJWTPassword)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d, want 200", resp.StatusCode)
	}
	if got.Token == "" {
		t.Fatal("login response: empty token")
	}
	if got.Username != testJWTUser {
		t.Errorf("login username = %q, want %q", got.Username, testJWTUser)
	}
	if got.Role != "maker" {
		t.Errorf("login role = %q, want maker (cfg.AuthRole)", got.Role)
	}
	if got.ExpiresIn != testJWTTTL {
		t.Errorf("login expires_in = %d, want %d (cfg.JWT.TTLSeconds)", got.ExpiresIn, testJWTTTL)
	}
	// NO legacy cookie: the JWT contract is bearer-only.
	if cookies := resp.Cookies(); len(cookies) != 0 {
		t.Errorf("login set %d cookies (%v), want none", len(cookies), cookies)
	}

	// The issued token must work on a requireJWT-guarded route.
	authed := withBearer(client, got.Token)
	me, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me with login token: status %d, want 200", me.StatusCode)
	}
	var principal map[string]string
	if err := json.NewDecoder(me.Body).Decode(&principal); err != nil {
		t.Fatalf("decode /api/me body: %v", err)
	}
	if principal["username"] != testJWTUser {
		t.Errorf("/api/me username = %q, want %q", principal["username"], testJWTUser)
	}
	if principal["role"] != "maker" {
		t.Errorf("/api/me role = %q, want maker", principal["role"])
	}
}

// TestLoginBadCredentials401AndRateLimit: wrong password → 401, and the
// per-(IP, username) failure limiter still blocks — after loginMaxFailures
// failures even CORRECT credentials answer 429.
func TestLoginBadCredentials401AndRateLimit(t *testing.T) {
	srv, client, _ := newJWTLoginServer(t, true, nil)

	for i := 0; i < loginMaxFailures; i++ {
		resp, _ := doLogin(t, client, srv.URL, testJWTUser, "wrong-pw")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bad creds attempt %d: status %d, want 401", i+1, resp.StatusCode)
		}
	}
	resp, _ := doLogin(t, client, srv.URL, testJWTUser, testJWTPassword)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("login after %d failures: status %d, want 429 (rate limiter preserved)", loginMaxFailures, resp.StatusCode)
	}
}

// TestLoginRoleFromAuthUsers: an auth.users entry authenticates and is
// issued a token carrying ITS declared role (checker), distinct from the
// primary account's maker role.
func TestLoginRoleFromAuthUsers(t *testing.T) {
	srv, client, _ := newJWTLoginServer(t, true, []config.AuthUserConfig{
		{Username: "checker", Password: "checker-pw", Role: "checker"},
	})

	resp, got := doLogin(t, client, srv.URL, "checker", "checker-pw")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("checker login status %d, want 200", resp.StatusCode)
	}
	if got.Username != "checker" || got.Role != "checker" {
		t.Errorf("checker login = %+v, want username=checker role=checker", got)
	}
	if got.Token == "" {
		t.Fatal("checker login: empty token")
	}
	// The checker token round-trips through a guarded route with its role.
	authed := withBearer(client, got.Token)
	me, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer me.Body.Close()
	var principal map[string]string
	if err := json.NewDecoder(me.Body).Decode(&principal); err != nil {
		t.Fatalf("decode /api/me body: %v", err)
	}
	if principal["username"] != "checker" || principal["role"] != "checker" {
		t.Errorf("/api/me = %+v, want username=checker role=checker", principal)
	}
}

// TestLoginRouteAbsentLogoutRegisteredWhenDisabled: with login_enabled=false
// POST /api/login is NOT registered — the spaHandler /api guard answers 404
// — while POST /api/logout IS (Phase 2 Task 4b: unconditional registration
// so external tokens stay revocable over HTTP); a logout with no bearer
// answers 401, never 404. JWT-guarded routes still work for presented
// tokens (requireJWT is independent of the login flag).
func TestLoginRouteAbsentLogoutRegisteredWhenDisabled(t *testing.T) {
	srv, client, cfg := newJWTLoginServer(t, false, nil)

	resp, _ := doLogin(t, client, srv.URL, testJWTUser, testJWTPassword)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /api/login with login_enabled=false: status %d, want 404", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatal("login_enabled=false: login succeeded — route must not be registered")
	}

	// Logout IS registered: no bearer → 401 (self-authenticating endpoint),
	// NOT 404 (the pre-Task-4b coupling bug).
	logoutReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/logout", nil)
	if err != nil {
		t.Fatalf("new logout request: %v", err)
	}
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("POST /api/logout: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /api/logout with login_enabled=false: status %d, want 401 (route registered unconditionally; no bearer rejected)", logoutResp.StatusCode)
	}

	// Guarded routes remain JWT-authenticated (external tokens work).
	authed := withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))
	me, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Errorf("GET /api/me (external token, login disabled): status %d, want 200", me.StatusCode)
	}
}

// TestLogoutDenylistsToken: logout with a valid bearer → 200 {ok:true};
// the SAME token replayed on a guarded route → 401 (jti denylist). A
// freshly logged-in token still works — denial is per-jti, not per-user.
func TestLogoutDenylistsToken(t *testing.T) {
	srv, client, _ := newJWTLoginServer(t, true, nil)

	_, first := doLogin(t, client, srv.URL, testJWTUser, testJWTPassword)
	authed := withBearer(client, first.Token)
	me, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me before logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me before logout: status %d, want 200", me.StatusCode)
	}

	resp, body := logoutBearer(t, authed, srv.URL, first.Token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, `"ok":"true"`) {
		t.Errorf("logout body = %s, want {\"ok\":\"true\"}", body)
	}

	// The logged-out token must now be rejected by requireJWT.
	me, err = authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me after logout: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/me with logged-out token: status %d, want 401 (denylist)", me.StatusCode)
	}

	// A brand-new login issues a fresh jti that is NOT denied.
	_, second := doLogin(t, client, srv.URL, testJWTUser, testJWTPassword)
	fresh := withBearer(client, second.Token)
	me, err = fresh.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me with fresh token: %v", err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Errorf("GET /api/me with fresh token after other token's logout: status %d, want 200", me.StatusCode)
	}
}

// TestLogoutRejectsInvalidBearer: logout without a bearer or with an
// unverifiable token → 401 — nothing is denied and nothing blows up.
func TestLogoutRejectsInvalidBearer(t *testing.T) {
	srv, client, _ := newJWTLoginServer(t, true, nil)

	noAuthReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/logout", nil)
	if err != nil {
		t.Fatalf("new logout request: %v", err)
	}
	resp, err := client.Do(noAuthReq)
	if err != nil {
		t.Fatalf("POST /api/logout (no header): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("logout without bearer: status %d, want 401", resp.StatusCode)
	}

	garbageReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/logout", nil)
	if err != nil {
		t.Fatalf("new logout request: %v", err)
	}
	garbageReq.Header.Set("Authorization", "Bearer not-a-jwt")
	resp, err = client.Do(garbageReq)
	if err != nil {
		t.Fatalf("POST /api/logout (garbage token): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("logout with garbage token: status %d, want 401", resp.StatusCode)
	}
}
