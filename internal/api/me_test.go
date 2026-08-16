package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// newTestAPIServer builds the real Control Plane mux against the LIVE Valkey
// (127.0.0.1:6379, same as internal/store integration tests) with a throwaway
// config, and returns a client whose cookie jar carries zt_session across
// requests exactly like a browser would.
func newTestAPIServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStoreDirect: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     "admin",
		AuthPassword: "s3cret",
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return srv, &http.Client{Jar: jar}
}

// loginViaAPI logs in through the real POST /api/login endpoint, letting the
// cookie jar capture the zt_session cookie.
func loginViaAPI(t *testing.T, client *http.Client, base string) {
	t.Helper()
	resp, err := client.Post(base+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/login: status %d, want 200", resp.StatusCode)
	}
}

// sessionAs creates a UI session for user directly in Valkey and installs
// the zt_session cookie on the client — the browser-equivalent of logging
// in as that user. Used by tests that issue tokens for a NON-admin maker:
// review 9.9a binds the token-request body username to the session (the
// body must match or be rejected), while the login endpoint only ever
// authenticates the configured admin — so a token for "audit-maker-…"
// requires a session created for that user.
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

// TestMeRequiresSession: GET /api/me without a zt_session cookie → 401.
func TestMeRequiresSession(t *testing.T) {
	srv, client := newTestAPIServer(t)

	resp, err := client.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/me without cookie: status %d, want 401", resp.StatusCode)
	}
}

// TestMeAfterLogin: login via the real endpoint, then GET /api/me → 200 with
// the session's username.
func TestMeAfterLogin(t *testing.T) {
	srv, client := newTestAPIServer(t)
	loginViaAPI(t, client, srv.URL)

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
	if got["username"] != "admin" {
		t.Errorf("GET /api/me username = %q, want %q", got["username"], "admin")
	}
}

// TestMeAfterLogout: the cookie jar drops zt_session on logout, so the same
// client is rejected afterwards → 401.
func TestMeAfterLogout(t *testing.T) {
	srv, client := newTestAPIServer(t)
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
		t.Errorf("GET /api/me after logout: status %d, want 401", resp.StatusCode)
	}
}
