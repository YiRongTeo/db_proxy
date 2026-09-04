package api

// Task 5: GET /api/me is guarded by requireJWT — the bearer token the SPA
// will receive from /api/login (Task 6) replaces the zt_session cookie on
// this route. The legacy cookie login still exists (until Task 6/4) and is
// exercised where it still governs: /api/login itself and the /api/token
// session leg.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// newTestAPIServer builds the real Control Plane mux against the LIVE Valkey
// (127.0.0.1:6379, same as internal/store integration tests) with a
// throwaway config whose JWT block is enabled (jwt.enabled + login_enabled +
// fixed test secret) so requireJWT and mintJWT work. Returns the config so
// callers can mint bearer tokens for the identity under test.
func newTestAPIServer(t *testing.T) (*httptest.Server, *http.Client, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "maker",
		JWT:          testJWTBlock(),
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	return srv, newJarClient(t), cfg
}

// TestMeRequiresJWT: GET /api/me without an Authorization header → 401.
func TestMeRequiresJWT(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)

	resp, err := client.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/me without bearer: status %d, want 401", resp.StatusCode)
	}
}

// TestMeAfterLogin: log in through the real endpoint (still cookie-based
// until Task 6) and present a bearer token for the logged-in principal —
// GET /api/me → 200 with the session's username.
func TestMeAfterLogin(t *testing.T) {
	srv, client, cfg := newTestAPIServer(t)
	loginViaAPI(t, client, srv.URL)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	resp, err := client.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me after login: status %d, want 200", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode /api/me body: %v", err)
	}
	if got["username"] != testJWTUser {
		t.Errorf("GET /api/me username = %q, want %q", got["username"], testJWTUser)
	}
}

// TestMeAfterLogout: POST /api/logout still clears the legacy zt_session
// cookie (200). Bearer revocation is NOT wired yet — the jti denylist lands
// in Task 6 — so this test asserts the transitional contract: after logout
// the cookie is gone and a client with no bearer (and no cookie) is
// rejected by /api/me. Task 6 rewrites logout to denylist the presented
// token and adds the token-revocation assertions.
func TestMeAfterLogout(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)
	loginViaAPI(t, client, srv.URL)

	resp, err := client.Post(srv.URL+"/api/logout", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/logout: status %d, want 200", resp.StatusCode)
	}

	resp, err = client.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/me after logout (no bearer, no cookie): status %d, want 401", resp.StatusCode)
	}
}
