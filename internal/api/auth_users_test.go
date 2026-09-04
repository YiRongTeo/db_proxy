package api

// Task 9.13 — optional extra UI users (auth.users): a dedicated checker
// account so maker and checker roles can use different identities (the SoD
// watch rejects checker == maker). The primary admin pair stays the
// primary; extra users authenticate through the same /api/login endpoint
// (which still issues the legacy cookie until Task 6, when it switches to
// returning a JWT — /api/me already demands the bearer, so the guarded-route
// leg below presents a minted checker token).

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

// loginAs posts /api/login and returns the status code.
func loginAs(t *testing.T, client *http.Client, base, username, password string) int {
	t.Helper()
	resp, err := client.Post(base+"/api/login", "application/json",
		strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestExtraUserLogin(t *testing.T) {
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "maker",
		JWT:          testJWTBlock(),
		AuthUsers: []config.AuthUserConfig{
			{Username: "checker", Password: "checker-pw", Role: "checker"},
		},
		SessionTTL: 8,
		TokenTTL:   60,
		StaticDir:  t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)

	client := newJarClient(t)

	if got := loginAs(t, client, srv.URL, "checker", "checker-pw"); got != http.StatusOK {
		t.Fatalf("checker login status %d, want 200", got)
	}
	// /api/me is bearer-guarded: present a token for the checker identity.
	authed := withBearer(client, mintJWT(t, cfg, "checker", "checker"))
	resp, err := authed.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), `"username":"checker"`) {
		t.Errorf("/api/me = %s, want username checker", string(body[:n]))
	}

	// Wrong password for the extra user → 401.
	if got := loginAs(t, client, srv.URL, "checker", "wrong"); got != http.StatusUnauthorized {
		t.Errorf("checker wrong-pw status %d, want 401", got)
	}
	// Unknown user → 401.
	if got := loginAs(t, client, srv.URL, "nobody", "x"); got != http.StatusUnauthorized {
		t.Errorf("unknown-user status %d, want 401", got)
	}
	// The primary pair still works alongside.
	if got := loginAs(t, client, srv.URL, "admin", "s3cret"); got != http.StatusOK {
		t.Errorf("admin login status %d, want 200", got)
	}
}
