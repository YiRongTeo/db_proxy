package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- Task 8.7: CredResolver unit tests --------------------------------

// TestConfigCredResolver pins the config-mode resolver to the pre-8.7 map
// semantics: key → password; a missing key is an error naming the key
// (never an empty-password success).
func TestConfigCredResolver(t *testing.T) {
	r := &ConfigCredResolver{Creds: map[string]string{"mysql:ro_user@127.0.0.1:3307": "ro_pw"}}
	pw, err := r.Password(context.Background(), "mysql:ro_user@127.0.0.1:3307")
	if err != nil {
		t.Fatalf("Password(found key) error: %v", err)
	}
	if pw != "ro_pw" {
		t.Fatalf("Password = %q, want %q", pw, "ro_pw")
	}

	// Missing key: error naming the key — the router turns it into a
	// failed connect ("backend unavailable" to the client).
	_, err = r.Password(context.Background(), "mysql:nobody@127.0.0.1:3307")
	if err == nil {
		t.Fatal("Password(missing key) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "no credentials for mysql:nobody@127.0.0.1:3307") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Nil map (the old `nil` creds argument) must fail gracefully, exactly
	// like a nil map lookup did before the resolver.
	if _, err := (&ConfigCredResolver{}).Password(context.Background(), "mysql:ro_user@127.0.0.1:3307"); err == nil {
		t.Fatal("Password(nil map) = nil error, want error")
	}
}

// TestAPICredResolverPassword200 is the happy path: a 200 {"password": "..."}
// response yields the password, and the vault request carries the query
// params built from the PARSED key parts (dbtype:user@ip:port →
// db_type/db_user/db_ip/db_port) plus the X-Api-Key header.
func TestAPICredResolverPassword200(t *testing.T) {
	var gotQuery, gotKey atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery.Store(r.URL.RawQuery)
		gotKey.Store(r.Header.Get("X-Api-Key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"password":"vault-pw-42"}`))
	}))
	defer srv.Close()

	r, err := NewAPICredResolver(srv.URL, "vault-key-1", 3*time.Second)
	if err != nil {
		t.Fatalf("NewAPICredResolver: %v", err)
	}
	pw, err := r.Password(context.Background(), "mysql:ro_user@127.0.0.1:3307")
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if pw != "vault-pw-42" {
		t.Fatalf("Password = %q, want %q", pw, "vault-pw-42")
	}
	q, _ := gotQuery.Load().(string)
	for _, want := range []string{"db_type=mysql", "db_user=ro_user", "db_ip=127.0.0.1", "db_port=3307"} {
		if !strings.Contains(q, want) {
			t.Errorf("vault request query %q missing %s", q, want)
		}
	}
	if key, _ := gotKey.Load().(string); key != "vault-key-1" {
		t.Errorf("X-Api-Key header = %q, want %q", key, "vault-key-1")
	}
}

// TestAPICredResolverStatusOnlyError is the non-200 contract: the error
// carries the STATUS CODE ONLY — never the response body (which could hold
// secrets the vault itself would never log). The body is drained for
// connection reuse but must not surface anywhere.
func TestAPICredResolverStatusOnlyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"password":"leaked-secret-body"}`))
	}))
	defer srv.Close()

	r, err := NewAPICredResolver(srv.URL, "", 3*time.Second)
	if err != nil {
		t.Fatalf("NewAPICredResolver: %v", err)
	}
	_, err = r.Password(context.Background(), "mysql:ro_user@127.0.0.1:3307")
	if err == nil {
		t.Fatal("Password(404) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error must mention the status code, got: %v", err)
	}
	if strings.Contains(err.Error(), "leaked-secret-body") {
		t.Errorf("error must NEVER carry the response body, got: %v", err)
	}
}

// TestAPICredResolverEmptyPassword: a 200 without a password field is a
// failure, not a silent empty-password connect.
func TestAPICredResolverEmptyPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	r, err := NewAPICredResolver(srv.URL, "", 3*time.Second)
	if err != nil {
		t.Fatalf("NewAPICredResolver: %v", err)
	}
	if _, err := r.Password(context.Background(), "mysql:ro_user@127.0.0.1:3307"); err == nil {
		t.Fatal("Password(empty) = nil error, want error")
	}
}

// TestAPICredResolverUnparseableKey: a malformed key must fail BEFORE any
// vault request — garbage keys never reach the vault.
func TestAPICredResolverUnparseableKey(t *testing.T) {
	r, err := NewAPICredResolver("http://127.0.0.1:1", "", 3*time.Second)
	if err != nil {
		t.Fatalf("NewAPICredResolver: %v", err)
	}
	for _, bad := range []string{"", "nocolon", ":u@h:p", "mysql:userip:port", "mysql:user@ip", "mysql:@127.0.0.1:3307"} {
		if _, err := r.Password(context.Background(), bad); err == nil {
			t.Errorf("Password(%q) = nil error, want unparseable-key error", bad)
		}
	}
}

// TestAPICredResolverNetworkError: transport failures surface as wrapped
// errors (the session fails cleanly; nothing is logged by the resolver).
func TestAPICredResolverNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // no listener anymore → connection refused

	r, err := NewAPICredResolver(url, "", 3*time.Second)
	if err != nil {
		t.Fatalf("NewAPICredResolver: %v", err)
	}
	if _, err := r.Password(context.Background(), "mysql:ro_user@127.0.0.1:3307"); err == nil {
		t.Fatal("Password(closed server) = nil error, want wrapped network error")
	}
}

// TestNewAPICredResolverFailFast: a missing/malformed vault URL is rejected
// at construction time (the data plane fails fast, never mid-session).
func TestNewAPICredResolverFailFast(t *testing.T) {
	for _, bad := range []string{"", "  ", "not-a-url", "vault:9000/creds"} {
		if _, err := NewAPICredResolver(bad, "", 3*time.Second); err == nil {
			t.Errorf("NewAPICredResolver(%q) = nil error, want error", bad)
		}
	}
	// timeout <= 0 falls back to the 5s default (never a broken client).
	r, err := NewAPICredResolver("http://127.0.0.1:1/creds", "", 0)
	if err != nil {
		t.Fatalf("NewAPICredResolver(timeout 0): %v", err)
	}
	if r.hc.Timeout != 5*time.Second {
		t.Errorf("default timeout = %v, want 5s", r.hc.Timeout)
	}
}
