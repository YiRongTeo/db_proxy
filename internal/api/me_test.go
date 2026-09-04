package api

// Task 5/6: GET /api/me is guarded by requireJWT — the bearer token issued
// by /api/login (JWT since Task 6) replaces the legacy zt_session cookie on
// this route. /api/me reports {username, role} for the SPA's boot-time
// session restore; logout (Task 6) denylists the token so a replay is 401.

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

// TestMeAfterLogin: log in through the real endpoint and present the
// returned JWT — GET /api/me → 200 with the principal's username and role.
func TestMeAfterLogin(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)
	tok := loginJWT(t, client, srv.URL, testJWTUser, testJWTPassword)
	client = withBearer(client, tok)

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
	if got["role"] != "maker" {
		t.Errorf("GET /api/me role = %q, want maker", got["role"])
	}
}

// TestMeAfterLogout: POST /api/logout with the presented bearer token →
// 200; the logged-out token replayed on /api/me → 401 (the jti denylist of
// Task 6).
func TestMeAfterLogout(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)
	tok := loginJWT(t, client, srv.URL, testJWTUser, testJWTPassword)
	authed := withBearer(client, tok)

	resp, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me before logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me before logout: status %d, want 200", resp.StatusCode)
	}

	logoutReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/logout", nil)
	if err != nil {
		t.Fatalf("new logout request: %v", err)
	}
	logoutReq.Header.Set("Authorization", authHeader(tok))
	resp, err = authed.Do(logoutReq)
	if err != nil {
		t.Fatalf("POST /api/logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/logout: status %d, want 200", resp.StatusCode)
	}

	resp, err = authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/me with logged-out token: status %d, want 401", resp.StatusCode)
	}
}
