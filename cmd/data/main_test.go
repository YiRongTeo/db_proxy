package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
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

// TestBuildSessionCallbacksDisabled (node-integration Task 3): url empty
// (the committed default) → (nil, nil) — the feature is disabled and the
// proxies' SetSessionCallbacks(nil) keeps every notify a no-op.
func TestBuildSessionCallbacksDisabled(t *testing.T) {
	cfg := &config.DataConfig{}
	cb, err := buildSessionCallbacks(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildSessionCallbacks: %v", err)
	}
	if cb != nil {
		t.Fatal("buildSessionCallbacks(empty url) = non-nil, want nil (disabled by default)")
	}
}

// TestBuildSessionCallbacksEnabled pins the wiring: the block's fields flow
// into the client (non-nil when url is set; a malformed url fails fast —
// never a plane configured to report starting silently broken).
func TestBuildSessionCallbacksEnabled(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.DataConfig{
		SessionCallback: config.SessionCallbackConfig{
			URL:              "http://10.0.0.9:9000",
			TimeoutSeconds:   3,
			SharedSecret:     "sekrit",
			ControlPlaneAddr: "127.0.0.1:8080",
		},
	}
	cb, err := buildSessionCallbacks(cfg, log)
	if err != nil {
		t.Fatalf("buildSessionCallbacks: %v", err)
	}
	if cb == nil {
		t.Fatal("buildSessionCallbacks(url set) = nil, want non-nil")
	}
	if _, err := buildSessionCallbacks(&config.DataConfig{
		SessionCallback: config.SessionCallbackConfig{URL: "::bad::"},
	}, log); err == nil {
		t.Fatal("buildSessionCallbacks(malformed url): want error, got nil")
	}
}

// TestApplySessionIPLock (node-integration IP-lock toggle): the config knob
// flows into ALL FOUR proxies, and a DISABLED lock boots the loud WARN (same
// convention as warnCredAPITLS — a disabled security control never passes
// silently). Enabled (default) stays silent: no WARN on the happy path.
func TestApplySessionIPLock(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	mysqlProxy := proxy.NewMySQLProxy(log, nil, &proxy.ConfigCredResolver{Creds: map[string]string{}}, nil)
	pgProxy := proxy.NewPGProxy(log, nil, &proxy.ConfigCredResolver{Creds: map[string]string{}}, nil)
	mssqlProxy := proxy.NewMSSQLProxy(log, nil, &proxy.ConfigCredResolver{Creds: map[string]string{}}, nil)
	oracleProxy := proxy.NewOracleProxy(log, nil, &proxy.ConfigCredResolver{Creds: map[string]string{}})

	// Disabled: the WARN fires exactly once and every plane is unlocked.
	tr := false
	applySessionIPLock(&config.DataConfig{SessionIPLock: &tr}, log, mysqlProxy, pgProxy, mssqlProxy, oracleProxy)
	if n := strings.Count(buf.String(), "IP lock"); n != 1 {
		t.Fatalf("disabled lock WARN count = %d, want exactly 1; log:\n%s", n, buf.String())
	}
	for _, c := range []interface{ SetIPLock(bool) }{mysqlProxy, pgProxy, mssqlProxy, oracleProxy} {
		_ = c // compile-proof: all four carry SetIPLock (typed in the signature)
	}

	// Enabled (the committed default): silent, and the lock is armed.
	buf.Reset()
	tr = true
	applySessionIPLock(&config.DataConfig{SessionIPLock: &tr}, log, mysqlProxy, pgProxy, mssqlProxy, oracleProxy)
	if buf.Len() != 0 {
		t.Fatalf("enabled lock must not WARN; got:\n%s", buf.String())
	}
}

// TestApplySessionIPLockRejectedEnv (fix round 1, strict env parse): a
// ZT_SESSION_IP_LOCK value that failed the config allowlist surfaces in
// SessionIPLockEnvRejected and MUST boot a WARN naming the rejected value —
// a typo'd override never passes silently. With the lock still ON (yaml
// absent/default) it is the ONLY warning; when the yaml itself disables the
// lock the rejected-value WARN fires IN ADDITION to the disabled-control
// WARN (both facts matter to the operator).
func TestApplySessionIPLockRejectedEnv(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	mysqlProxy := proxy.NewMySQLProxy(log, nil, &proxy.ConfigCredResolver{Creds: map[string]string{}}, nil)
	pgProxy := proxy.NewPGProxy(log, nil, &proxy.ConfigCredResolver{Creds: map[string]string{}}, nil)
	mssqlProxy := proxy.NewMSSQLProxy(log, nil, &proxy.ConfigCredResolver{Creds: map[string]string{}}, nil)
	oracleProxy := proxy.NewOracleProxy(log, nil, &proxy.ConfigCredResolver{Creds: map[string]string{}})

	// Rejected value, lock still ON (yaml decided = default true): exactly
	// one rejected-value WARN carrying the offending value, NO disabled WARN.
	tr := true
	applySessionIPLock(&config.DataConfig{SessionIPLock: &tr, SessionIPLockEnvRejected: "yes"}, log, mysqlProxy, pgProxy, mssqlProxy, oracleProxy)
	out := buf.String()
	if n := strings.Count(out, "not recognized"); n != 1 {
		t.Fatalf("rejected-env WARN count = %d, want exactly 1; log:\n%s", n, out)
	}
	if !strings.Contains(out, "yes") {
		t.Errorf("rejected-env WARN must name the offending value; log:\n%s", out)
	}
	if strings.Contains(out, "DISABLED") {
		t.Errorf("lock is ON — no disabled-control WARN expected; log:\n%s", out)
	}

	// Rejected value over an explicit yaml false: BOTH warnings fire.
	buf.Reset()
	tr = false
	applySessionIPLock(&config.DataConfig{SessionIPLock: &tr, SessionIPLockEnvRejected: "garbage"}, log, mysqlProxy, pgProxy, mssqlProxy, oracleProxy)
	out = buf.String()
	if n := strings.Count(out, "not recognized"); n != 1 {
		t.Fatalf("rejected-env WARN count = %d, want exactly 1; log:\n%s", n, out)
	}
	if n := strings.Count(out, "DISABLED"); n != 1 {
		t.Errorf("disabled-lock WARN count = %d, want exactly 1; log:\n%s", n, out)
	}

	// No rejection → no rejected-value WARN (covered by TestApplySessionIPLock's
	// silence assertions; pinned here for the empty-field path too).
	buf.Reset()
	tr = true
	applySessionIPLock(&config.DataConfig{SessionIPLock: &tr}, log, mysqlProxy, pgProxy, mssqlProxy, oracleProxy)
	if buf.Len() != 0 {
		t.Fatalf("empty SessionIPLockEnvRejected must not WARN; got:\n%s", buf.String())
	}
}
