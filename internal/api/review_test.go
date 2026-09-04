package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// --- Review 9.9 remediation unit tests --------------------------------------
// Constant-time credential compares, login rate limiting (429 backoff),
// session-authed /api/token username BINDING, and decodeJSON hardening
// (unknown fields rejected, oversized bodies capped). All live against the
// real mux + Valkey like the other api tests.

// TestSecureEqualConstantTime: secureEqual accepts exact matches and rejects
// everything else — including equal-length lookalikes and length-mismatched
// values (both sides are hashed first, so length leaks nothing either).
func TestSecureEqualConstantTime(t *testing.T) {
	if !secureEqual("admin", "admin") {
		t.Error("secureEqual(admin, admin) = false, want true")
	}
	if secureEqual("admin", "admiN") {
		t.Error("secureEqual(admin, admiN) = true, want false (case differs)")
	}
	if secureEqual("admin", "admin2") {
		t.Error("secureEqual(admin, admin2) = true, want false")
	}
	if secureEqual("", "admin") {
		t.Error("secureEqual(\"\", admin) = true, want false")
	}
	if secureEqual("admin", "") {
		t.Error("secureEqual(admin, \"\") = true, want false")
	}
	if !secureEqual("", "") {
		t.Error("secureEqual(\"\", \"\") = false, want true")
	}
	// Long values exercise the same path (hash-then-compare).
	longA := strings.Repeat("x", 4096)
	longB := strings.Repeat("x", 4095) + "y"
	if !secureEqual(longA, longA) {
		t.Error("secureEqual(long, long) = false, want true")
	}
	if secureEqual(longA, longB) {
		t.Error("secureEqual(long, long-1-char-diff) = true, want false")
	}
}

// TestLoginRateLimit429: after loginMaxFailures failed attempts the key is
// blocked — even CORRECT credentials answer 429 until the window rolls over.
func TestLoginRateLimit429(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)

	for i := 0; i < loginMaxFailures; i++ {
		resp, err := client.Post(srv.URL+"/api/login", "application/json",
			strings.NewReader(`{"username":"admin","password":"wrong"}`))
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, resp.StatusCode)
		}
	}
	// The (IP, username) key is now blocked: correct password still 429.
	resp, err := client.Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	if err != nil {
		t.Fatalf("blocked login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("blocked login: status %d, want 429", resp.StatusCode)
	}
}

// TestLoginSuccessClearsFailures: a successful login resets the failure
// counter — the key is not blocked by earlier typos.
func TestLoginSuccessClearsFailures(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)

	for i := 0; i < loginMaxFailures-1; i++ {
		resp, err := client.Post(srv.URL+"/api/login", "application/json",
			strings.NewReader(`{"username":"admin","password":"wrong"}`))
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, resp.StatusCode)
		}
	}
	// One short of the limit: the correct password must still succeed.
	resp, err := client.Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	if err != nil {
		t.Fatalf("login after 4 failures: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login after 4 failures: status %d, want 200 (success clears the counter)", resp.StatusCode)
	}
}

// tokenBody returns a valid /api/token request body for the given maker.
func tokenBody(username string) string {
	return `{"username":"` + username + `","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-9.9"}`
}

// TestTokenUsernameBindingAccept (review 9.9 CRITICAL a): a
// session-authenticated requester may send a body username that MATCHES the
// session — the token is issued for the session username.
func TestTokenUsernameBindingAccept(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)
	// /api/token's session leg still resolves the legacy cookie session
	// (the bare route is migrated to JWT in Task 7) — /api/login has issued
	// a JWT, no cookie, since Task 6, so the cookie session is planted
	// directly.
	cookieSessionAs(t, client, srv.URL, testJWTUser)

	resp, err := client.Post(srv.URL+"/api/token", "application/json",
		strings.NewReader(tokenBody("admin")))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("matching username: status %d, want 200 (body %s)", resp.StatusCode, tokenBody("admin"))
	}
}

// TestTokenUsernameBindingMismatch (review 9.9 CRITICAL a): a session
// authenticated as admin sending a body username for ANOTHER user is
// rejected — the body cannot forge a different maker identity.
func TestTokenUsernameBindingMismatch(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)
	cookieSessionAs(t, client, srv.URL, testJWTUser)

	resp, err := client.Post(srv.URL+"/api/token", "application/json",
		strings.NewReader(tokenBody("alice")))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched username: status %d, want 400", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body["error"] != "username does not match session" {
		t.Errorf("error body = %q, want username does not match session", body["error"])
	}
}

// TestTokenUsernameEmptyBindsSession (review 9.9 CRITICAL a): a session
// requester may OMIT the body username — the token is then issued for the
// SESSION username (the body is never trusted).
func TestTokenUsernameEmptyBindsSession(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)
	cookieSessionAs(t, client, srv.URL, testJWTUser)

	// Strip the username field entirely.
	body := `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-9.9"}`
	resp, err := client.Post(srv.URL+"/api/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("omitted username: status %d, want 200 (session binds the maker)", resp.StatusCode)
	}
}

// TestDecodeJSONRejectsUnknownFields (review 9.9 MINOR): a misspelled or
// unknown field is a client bug — decodeJSON rejects the request instead of
// silently ignoring the field.
func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	srv, client, cfg := newTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "checker"))

	body := `{"session_id":"sid-x","mode":"connection","bogus_field":true}`
	resp, err := client.Post(srv.URL+"/api/kill", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/kill: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field: status %d, want 400", resp.StatusCode)
	}
}

// TestDecodeJSONRejectsOversize (review 9.9 MINOR): a body larger than
// maxBodyBytes trips MaxBytesReader — the server answers 413 (the handler's
// 400 is superseded by the too-large response) and never decodes it.
func TestDecodeJSONRejectsOversize(t *testing.T) {
	srv, client, _ := newTestAPIServer(t)

	pad := strings.Repeat("a", maxBodyBytes) // valid JSON, oversized
	body := `{"username":"admin","password":"s3cret","pad":"` + pad + `"}`
	resp, err := client.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/login oversized: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body: status %d, want 413 (or 400)", resp.StatusCode)
	}
}

// newIssueRateLimitedAPI builds an api with a tiny issuance throttle so a
// burst of token issues trips it (review 9.9 MINOR: issuance throttle).
func newIssueRateLimitedAPI(t *testing.T) (*httptest.Server, *http.Client, *config.ControlConfig) {
	t.Helper()
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
		APIKey:       "dev-key",
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := NewAPI(log, cfg, vs, nil)
	a.issueLimiter = newRateLimiter(time.Minute, 2)
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, cfg
}

// TestTokenIssuanceThrottle (review 9.9 MINOR): token minting is bounded per
// user — after the (shortened) quota the next issue answers 429.
func TestTokenIssuanceThrottle(t *testing.T) {
	srv, client, _ := newIssueRateLimitedAPI(t)

	// API-key path (no session): keyed by client IP. The request body is a
	// one-shot reader — reuse would hit "ContentLength with Body length 0"
	// on the second Do, so each issue gets a fresh request.
	issue := func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/token", strings.NewReader(tokenBody("maker1")))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("X-Api-Key", "dev-key")
		return client.Do(req)
	}
	for i := 0; i < 2; i++ {
		resp, err := issue()
		if err != nil {
			t.Fatalf("issue %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("issue %d: status %d, want 200", i+1, resp.StatusCode)
		}
	}
	resp, err := issue()
	if err != nil {
		t.Fatalf("throttled issue: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third issue: status %d, want 429", resp.StatusCode)
	}
}
