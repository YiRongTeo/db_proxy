package main

import (
	"context"
	"testing"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/proxy"
)

// TestBuildCredResolverConfigMode pins the Task 8.7 wiring for
// credentials_source=config: buildCredResolver returns a ConfigCredResolver
// wrapping the committed credentials list (pre-8.7 behavior).
func TestBuildCredResolverConfigMode(t *testing.T) {
	cfg := &config.DataConfig{
		CredentialsSource: "config",
		Credentials:       map[string]string{"mysql:ro_user@127.0.0.1:3307": "ro_pw"},
	}
	res, err := buildCredResolver(cfg)
	if err != nil {
		t.Fatalf("buildCredResolver: %v", err)
	}
	cr, ok := res.(*proxy.ConfigCredResolver)
	if !ok {
		t.Fatalf("resolver type = %T, want *proxy.ConfigCredResolver", res)
	}
	pw, err := cr.Password(context.Background(), "mysql:ro_user@127.0.0.1:3307")
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if pw != "ro_pw" {
		t.Errorf("Password = %q, want %q", pw, "ro_pw")
	}
}

// TestBuildCredResolverAPIMode pins the api-mode wiring: buildCredResolver
// returns an APICredResolver built from the configured url/key/timeout.
func TestBuildCredResolverAPIMode(t *testing.T) {
	cfg := &config.DataConfig{
		CredentialsSource: "api",
		CredentialsAPI: &config.CredentialsAPIConfig{
			URL:            "http://127.0.0.1:9/creds",
			APIKey:         "k-1",
			TimeoutSeconds: 5,
		},
	}
	res, err := buildCredResolver(cfg)
	if err != nil {
		t.Fatalf("buildCredResolver: %v", err)
	}
	if _, ok := res.(*proxy.APICredResolver); !ok {
		t.Fatalf("resolver type = %T, want *proxy.APICredResolver", res)
	}
}

// TestBuildCredResolverAPIBadURL: a malformed vault URL fails fast at
// construction (never mid-session).
func TestBuildCredResolverAPIBadURL(t *testing.T) {
	cfg := &config.DataConfig{
		CredentialsSource: "api",
		CredentialsAPI:    &config.CredentialsAPIConfig{URL: "::bad::"},
	}
	if _, err := buildCredResolver(cfg); err == nil {
		t.Fatal("buildCredResolver: want error for malformed vault url, got nil")
	}
}

// TestStoreOptionsTLSServerName pins the review 2026-08-17 ServerName
// rule: DIRECT mode derives it from the configured address so TLS verifies
// the valkey hostname; SENTINEL mode leaves it unset because the master's
// host is unknown until discovery and the sentinel's hostname would be
// wrong for the master connections (BuildClientOption wires ONE TLS config
// to both sentinel and master conns).
func TestStoreOptionsTLSServerName(t *testing.T) {
	vc := config.ValkeyConfig{
		Mode: "direct",
		Addr: "127.0.0.1:6379",
		SSL: config.ValkeySSL{
			Enabled:  true,
			CertFile: "../../certs/control.crt",
			KeyFile:  "../../certs/control.key",
		},
	}
	opts, err := storeOptions(vc)
	if err != nil {
		t.Fatalf("storeOptions(direct): %v", err)
	}
	if opts.TLS == nil {
		t.Fatal("direct mode: TLS config not built")
	}
	if opts.TLS.ServerName != "127.0.0.1" {
		t.Errorf("direct mode ServerName = %q, want %q", opts.TLS.ServerName, "127.0.0.1")
	}

	vc.Mode = "sentinel"
	vc.SentinelAddrs = []string{"127.0.0.1:26379"}
	opts, err = storeOptions(vc)
	if err != nil {
		t.Fatalf("storeOptions(sentinel): %v", err)
	}
	if opts.TLS == nil {
		t.Fatal("sentinel mode: TLS config not built")
	}
	if opts.TLS.ServerName != "" {
		t.Errorf("sentinel mode ServerName = %q, want \"\" (master host unknown until discovery)", opts.TLS.ServerName)
	}
}
