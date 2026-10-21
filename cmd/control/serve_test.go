package main

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// newServeTestCfg builds the minimal ControlConfig the serve tests need:
// JWT login mode with the fixed test values (Routes()/requireJWT work), a
// throwaway static dir, and a LIVE Valkey store (returned too — serveControl
// takes it).
func newServeTestCfg(t *testing.T, tlsPair *config.CertConfig) (*config.ControlConfig, *store.ValkeyStore) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		HTTPAddr:  "127.0.0.1:0",
		StaticDir: t.TempDir(),
		AuthUser:  "admin",
		AuthRole:  "maker",
		JWT: config.JWTConfig{
			Enabled:      true,
			LoginEnabled: true,
			Issuer:       "zerotrust-proxy",
			Audience:     "zt-api",
			TTLSeconds:   28800,
			Secret:       "serve-test-jwt-secret-0123456789abcdef",
		},
		TLS:    tlsPair,
		Valkey: config.ValkeyConfig{Mode: "direct", Addr: "127.0.0.1:6379"},
	}
	return cfg, vs
}

// writeServeCertPair generates a REAL self-signed localhost pair (the
// ListenAndServeTLS path parses them, so the contents must be valid PEM):
// rsa:2048, SAN DNS:localhost + IP:127.0.0.1 + IP:::1, 10 years — the same
// shape scripts/gen-dev-cert.sh produces.
func writeServeCertPair(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "localhost.crt")
	keyPath := filepath.Join(dir, "localhost.key")
	// git-bash/MSYS: openssl is a native Windows binary — give it native
	// (forward-slash) paths, not MSYS /tmp-style ones.
	native := func(p string) string { return filepath.ToSlash(p) }
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", native(keyPath), "-out", native(certPath), "-days", "3650",
		"-subj", "/CN=localhost",
		"-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl dev pair: %v: %s", err, out)
	}
	return certPath, keyPath
}

// TestServeControlPlainHTTP pins the G3 contract: TLS nil → the SAME
// listener code path as before (plain http.Server.Serve), /api/health
// answers over PLAINTEXT.
func TestServeControlPlainHTTP(t *testing.T) {
	cfg, vs := newServeTestCfg(t, nil)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	addr, stop, err := serveControl(context.Background(), log, cfg, vs, nil, nil)
	if err != nil {
		t.Fatalf("serveControl: %v", err)
	}
	defer stop()
	waitServeReady(t, addr, false)
}

// TestServeControlHTTPS pins the native-TLS contract: both files set → the
// control answers TLS on the SAME addr; a plaintext GET on that port fails
// (the listener no longer speaks plain HTTP), and an https GET (TLS 1.2
// floor, self-signed accepted) reaches /api/health.
func TestServeControlHTTPS(t *testing.T) {
	certPath, keyPath := writeServeCertPair(t)
	cfg, vs := newServeTestCfg(t, &config.CertConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	addr, stop, err := serveControl(context.Background(), log, cfg, vs, nil, nil)
	if err != nil {
		t.Fatalf("serveControl: %v", err)
	}
	defer stop()
	hc := waitServeReady(t, addr, true)

	// Plaintext request against the TLS listener must FAIL at the HTTP
	// layer — Go's TLS listener answers a plaintext probe with a 400
	// ("Client sent an HTTP request to an HTTPS server"), never with the
	// route's own response (the control plane never serves both on one
	// addr). The health probe returning 200 over TLS above is the proof of
	// the real serving mode.
	plain := &http.Client{Timeout: 3 * time.Second}
	if resp, err := plain.Get("http://" + addr + "/api/health"); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("plaintext GET on the TLS listener returned 200 — the route answered over plain HTTP")
		}
	}

	// And the TLS-served endpoint works with the self-signed cert trusted.
	resp, err := hc.Get("https://" + addr + "/api/health")
	if err != nil {
		t.Fatalf("https GET /api/health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("https /api/health status = %d, want 200", resp.StatusCode)
	}
}

// TestServeControlTLSFloor pins the hardcoded TLS 1.2 minimum: a client
// offering only TLS 1.1 is rejected at the handshake.
func TestServeControlTLSFloor(t *testing.T) {
	certPath, keyPath := writeServeCertPair(t)
	cfg, vs := newServeTestCfg(t, &config.CertConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	addr, stop, err := serveControl(context.Background(), log, cfg, vs, nil, nil)
	if err != nil {
		t.Fatalf("serveControl: %v", err)
	}
	defer stop()
	waitServeReady(t, addr, true)

	old := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // dev self-signed pair
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS11, // force the legacy offer
			},
		},
	}
	if _, err := old.Get("https://" + addr + "/api/health"); err == nil {
		t.Error("TLS 1.1 handshake unexpectedly succeeded — the 1.2 floor is not enforced")
	}
}

// TestServeControlTLSSetupFailFast pins the fail-fast rule: TLS on with an
// UNREADABLE key file → serveControl returns an error (the boot fails),
// never a silent plaintext fallback.
func TestServeControlTLSSetupFailFast(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "localhost.crt")
	keyPath := filepath.Join(dir, "missing.key")
	if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	cfg, vs := newServeTestCfg(t, &config.CertConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, stop, err := serveControl(context.Background(), log, cfg, vs, nil, nil)
	if err == nil {
		stop()
		t.Fatal("serveControl: want error for unreadable key file, got nil (would fall back to plaintext)")
	}
}

// waitServeReady polls the control until /api/health answers over the given
// scheme and returns a client trusting the self-signed pair (insecure) for
// follow-up TLS requests.
func waitServeReady(t *testing.T, addr string, isTLS bool) *http.Client {
	t.Helper()
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	tr := &http.Transport{}
	if isTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // self-signed dev pair
	}
	hc := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := hc.Get(scheme + "://" + addr + "/api/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return hc
			}
			lastErr = err
		} else {
			lastErr = err
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("control %s://%s/api/health not ready: %v", scheme, addr, lastErr)
	return nil
}
