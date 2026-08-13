package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"zerotrust-proxy/internal/models"
)

// writeTestCert generates a self-signed cert+key in t.TempDir() and returns
// their paths (the cert PEM doubles as a CA file for RootCAs tests).
func writeTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "valkey-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

func TestTLSFromFiles(t *testing.T) {
	certFile, keyFile := writeTestCert(t)

	t.Run("all empty returns nil config (plaintext)", func(t *testing.T) {
		cfg, err := TLSFromFiles("", "", "", false, "")
		if err != nil {
			t.Fatalf("TLSFromFiles: %v", err)
		}
		if cfg != nil {
			t.Fatalf("expected nil config, got %+v", cfg)
		}
	})

	t.Run("bad ca path errors", func(t *testing.T) {
		if _, err := TLSFromFiles(filepath.Join(t.TempDir(), "missing.pem"), "", "", false, ""); err == nil {
			t.Fatal("expected error for missing ca file")
		}
	})

	t.Run("ca + server name", func(t *testing.T) {
		cfg, err := TLSFromFiles(certFile, "", "", false, "127.0.0.1")
		if err != nil {
			t.Fatalf("TLSFromFiles: %v", err)
		}
		if cfg.RootCAs == nil {
			t.Fatal("RootCAs not set")
		}
		if cfg.ServerName != "127.0.0.1" {
			t.Fatalf("ServerName = %q, want %q", cfg.ServerName, "127.0.0.1")
		}
		if cfg.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify should be false")
		}
		if len(cfg.Certificates) != 0 {
			t.Fatal("no client cert expected")
		}
	})

	t.Run("cert and key loaded", func(t *testing.T) {
		cfg, err := TLSFromFiles("", certFile, keyFile, false, "")
		if err != nil {
			t.Fatalf("TLSFromFiles: %v", err)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("Certificates = %d entries, want 1", len(cfg.Certificates))
		}
	})

	t.Run("cert without key errors", func(t *testing.T) {
		if _, err := TLSFromFiles("", certFile, "", false, ""); err == nil {
			t.Fatal("expected error for cert without key")
		}
	})

	t.Run("skip verify sets InsecureSkipVerify and drops server name", func(t *testing.T) {
		cfg, err := TLSFromFiles(certFile, "", "", true, "127.0.0.1")
		if err != nil {
			t.Fatalf("TLSFromFiles: %v", err)
		}
		if !cfg.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify should be true")
		}
		if cfg.ServerName != "" {
			t.Fatalf("ServerName = %q, want empty when skip_verify", cfg.ServerName)
		}
	})

	t.Run("bad key pem errors", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := TLSFromFiles("", certFile, bad, false, ""); err == nil {
			t.Fatal("expected error for unparseable key")
		}
	})
}

func TestBuildClientOptionDirect(t *testing.T) {
	tlsCfg := &tls.Config{ServerName: "127.0.0.1"} // test wiring only
	opt := BuildClientOption(StoreOptions{
		Addrs:    []string{"127.0.0.1:6379"},
		Password: "pw",
		DB:       3,
		TLS:      tlsCfg,
	})
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "127.0.0.1:6379" {
		t.Fatalf("InitAddress = %v, want [127.0.0.1:6379]", opt.InitAddress)
	}
	if opt.Password != "pw" {
		t.Fatalf("Password = %q, want %q", opt.Password, "pw")
	}
	if opt.SelectDB != 3 {
		t.Fatalf("SelectDB = %d, want 3", opt.SelectDB)
	}
	if opt.TLSConfig != tlsCfg {
		t.Fatal("TLSConfig not wired through")
	}
	if opt.Sentinel.MasterSet != "" {
		t.Fatalf("Sentinel.MasterSet = %q, want empty in direct mode", opt.Sentinel.MasterSet)
	}
	if opt.Sentinel.TLSConfig != nil {
		t.Fatal("Sentinel.TLSConfig should be nil in direct mode")
	}
}

func TestBuildClientOptionSentinel(t *testing.T) {
	tlsCfg := &tls.Config{ServerName: "127.0.0.1"} // test wiring only
	opt := BuildClientOption(StoreOptions{
		Addrs:            []string{"127.0.0.1:26379", "127.0.0.2:26379"},
		MasterName:       "mymaster",
		Password:         "datapw",
		SentinelUsername: "suser",
		SentinelPassword: "spw",
		TLS:              tlsCfg,
	})
	// InitAddress carries the SENTINEL addresses in sentinel mode.
	if len(opt.InitAddress) != 2 || opt.InitAddress[0] != "127.0.0.1:26379" {
		t.Fatalf("InitAddress = %v, want sentinel addrs", opt.InitAddress)
	}
	if opt.Sentinel.MasterSet != "mymaster" {
		t.Fatalf("Sentinel.MasterSet = %q, want %q", opt.Sentinel.MasterSet, "mymaster")
	}
	// Same TLS config covers sentinel conns (SentinelOption.TLSConfig) and
	// master/data conns (ClientOption.TLSConfig).
	if opt.Sentinel.TLSConfig != tlsCfg {
		t.Fatal("Sentinel.TLSConfig not wired through")
	}
	if opt.TLSConfig != tlsCfg {
		t.Fatal("TLSConfig not wired through")
	}
	// Task 7.7: sentinel credentials land in SentinelOption (sentinel conns
	// AUTH with these), while ClientOption.Password keeps serving the
	// master/data conns.
	if opt.Sentinel.Username != "suser" {
		t.Fatalf("Sentinel.Username = %q, want %q", opt.Sentinel.Username, "suser")
	}
	if opt.Sentinel.Password != "spw" {
		t.Fatalf("Sentinel.Password = %q, want %q", opt.Sentinel.Password, "spw")
	}
	if opt.Password != "datapw" {
		t.Fatalf("Password = %q, want %q (master/data conns)", opt.Password, "datapw")
	}
}

func TestNewValkeyStoreRejectsEmptyAddrs(t *testing.T) {
	if _, err := NewValkeyStore(context.Background(), StoreOptions{}); err == nil {
		t.Fatal("expected error for empty Addrs")
	}
	if _, err := NewValkeyStore(context.Background(), StoreOptions{MasterName: "mymaster"}); err == nil {
		t.Fatal("expected error for empty Addrs in sentinel mode")
	}
}

// reachable reports whether a TCP dial to addr succeeds within timeout.
func reachable(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// TestLiveTLSValkeyRoundTrip is a live proof of the direct TLS path against
// the TLS valkey the gate task 7.6 brings up (127.0.0.1:6380, self-signed
// CA = certs/data.crt). Skips with a clear message when that infra is not up
// yet.
func TestLiveTLSValkeyRoundTrip(t *testing.T) {
	const addr = "127.0.0.1:6380"
	if !reachable(addr, time.Second) {
		t.Skipf("live TLS valkey not reachable at %s (gate task 7.6 starts it); skipping", addr)
	}
	// Repo-root certs dir, relative to the package dir (tests run with cwd =
	// internal/store). Self-signed: ca file == server cert, verification real.
	tlsCfg, err := TLSFromFiles("../../certs/data.crt", "", "", false, "127.0.0.1")
	if err != nil {
		t.Skipf("TLSFromFiles(../../certs/data.crt): %v (certs generated by gate task 7.6); skipping", err)
	}
	s, err := NewValkeyStore(context.Background(), StoreOptions{Addrs: []string{addr}, TLS: tlsCfg})
	if err != nil {
		t.Fatalf("NewValkeyStore over TLS: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	token := uniqueToken(t)
	cleanupKey(t, s, "tok:"+token)
	want := models.TokenPayload{Username: "tls-user", DBType: "mysql"}
	if err := s.SetToken(ctx, token, want, 30*time.Second); err != nil {
		t.Fatalf("SetToken over TLS: %v", err)
	}
	got, err := s.GetDeleteToken(ctx, token)
	if err != nil {
		t.Fatalf("GetDeleteToken over TLS: %v", err)
	}
	if got == nil || *got != want {
		t.Fatalf("round trip over TLS: got %+v, want %+v", got, want)
	}
}

// TestLiveSentinelRoundTrip is a live proof of sentinel mode against the
// sentinel the gate task 7.6 brings up (127.0.0.1:26379, monitoring the
// plaintext master on 6379 under the "mymaster" set). Task 7.7: the
// sentinel runs requirepass sentinelpw, so the store must present
// SentinelPassword for its sentinel connections (the master itself stays
// passwordless). Skips with a clear message when that infra is not up yet.
func TestLiveSentinelRoundTrip(t *testing.T) {
	const sentinelAddr = "127.0.0.1:26379"
	if !reachable(sentinelAddr, time.Second) {
		t.Skipf("live sentinel not reachable at %s (gate task 7.6 starts it); skipping", sentinelAddr)
	}
	s, err := NewValkeyStore(context.Background(), StoreOptions{
		Addrs:            []string{sentinelAddr},
		MasterName:       "mymaster",
		SentinelPassword: "sentinelpw",
	})
	if err != nil {
		t.Fatalf("NewValkeyStore via sentinel: %v", err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	token := uniqueToken(t)
	cleanupKey(t, s, "tok:"+token)
	want := models.TokenPayload{Username: "sentinel-user", TicketID: "T-S1"}
	if err := s.SetToken(ctx, token, want, 30*time.Second); err != nil {
		t.Fatalf("SetToken via sentinel: %v", err)
	}
	got, err := s.GetDeleteToken(ctx, token)
	if err != nil {
		t.Fatalf("GetDeleteToken via sentinel: %v", err)
	}
	if got == nil || *got != want {
		t.Fatalf("round trip via sentinel: got %+v, want %+v", got, want)
	}

	// Pub/Sub through the sentinel path: subscribe to a fresh channel on the
	// discovered master, publish after the subscription is confirmed, and
	// expect the exact bytes back (gate 7.6 requires subscribe/publish via
	// the sentinel-discovered connection, not just key round trips).
	acked := make(chan struct{}, 1)
	channel := "queries:gate-sentinel-" + uniqueToken(t)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	out := make(chan []byte, 4)
	subErr := make(chan error, 1)
	go func() { subErr <- s.Subscribe(subCtx, channel, false, out) }()
	select {
	case <-acked:
	case <-time.After(5 * time.Second):
		t.Fatal("sentinel-path subscription not confirmed within 5s")
	}
	msg := []byte(`{"via":"sentinel","id":1}`)
	if err := s.Publish(ctx, channel, msg); err != nil {
		t.Fatalf("Publish via sentinel: %v", err)
	}
	select {
	case gotMsg := <-out:
		if string(gotMsg) != string(msg) {
			t.Fatalf("pubsub via sentinel: got %q, want %q", gotMsg, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pubsub message via sentinel")
	}
	cancel()
	select {
	case err := <-subErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Subscribe via sentinel returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe via sentinel did not return within 5s of cancel")
	}
}

// TestLiveSentinelRequiresPassword is the negative half of sentinel auth
// (Task 7.7): the dev sentinel runs requirepass sentinelpw, so connecting
// WITHOUT the sentinel password must fail — proving the password is
// enforced server-side and not merely accepted. The failure surface is the
// store constructor's fail-fast PING (the sentinel conn's HELLO 3 init is
// rejected with NOAUTH before any command runs).
func TestLiveSentinelRequiresPassword(t *testing.T) {
	const sentinelAddr = "127.0.0.1:26379"
	if !reachable(sentinelAddr, time.Second) {
		t.Skipf("live sentinel not reachable at %s (gate task 7.6 starts it); skipping", sentinelAddr)
	}
	_, err := NewValkeyStore(context.Background(), StoreOptions{
		Addrs:      []string{sentinelAddr},
		MasterName: "mymaster",
		// SentinelPassword intentionally omitted.
	})
	if err == nil {
		t.Fatal("expected error connecting to sentinel without SentinelPassword, got success")
	}
	if !strings.Contains(err.Error(), "NOAUTH") {
		t.Fatalf("expected NOAUTH error from sentinel, got: %v", err)
	}
	t.Logf("without sentinel password: %v", err)
}

// TestLiveSentinelDistinctPasswords (Task 8.10, user directive 2026-08-13:
// "config file only accepts one password for valkey, what if valkey password
// is different from sentinel password") proves the two-password model end to
// end against the auth-distinct dev infra: valkey-auth-master on :6390 runs
// requirepass masterpw, and the auth sentinel on :26390 runs requirepass
// sentinelpw while monitoring that master (RUN.md §6.3). valkey.password and
// valkey.sentinel_password are INDEPENDENT: sentinel conns present the
// sentinel password, master/data conns present the master password. Each
// misconfiguration must fail at the step that owns the wrong credential.
// Skips when the auth sentinel is not up yet.
func TestLiveSentinelDistinctPasswords(t *testing.T) {
	const sentinelAddr = "127.0.0.1:26390"
	if !reachable(sentinelAddr, time.Second) {
		t.Skipf("live auth-distinct sentinel not reachable at %s (RUN.md §6.3 starts it); skipping", sentinelAddr)
	}

	// roundTrip builds the store from opts and runs a SetToken /
	// GetDeleteToken round trip on a fresh token, returning the first error.
	roundTrip := func(t *testing.T, opts StoreOptions) error {
		t.Helper()
		s, err := NewValkeyStore(context.Background(), opts)
		if err != nil {
			return err
		}
		defer s.Close()
		token := uniqueToken(t)
		cleanupKey(t, s, "tok:"+token)
		want := models.TokenPayload{Username: "auth-distinct", DBType: "mysql"}
		if err := s.SetToken(context.Background(), token, want, 30*time.Second); err != nil {
			return err
		}
		got, err := s.GetDeleteToken(context.Background(), token)
		if err != nil {
			return err
		}
		if got == nil || *got != want {
			return fmt.Errorf("round trip: got %+v, want %+v", got, want)
		}
		return nil
	}

	t.Run("distinct master and sentinel passwords, both correct", func(t *testing.T) {
		if err := roundTrip(t, StoreOptions{
			Addrs:            []string{sentinelAddr},
			MasterName:       "mymaster",
			Password:         "masterpw",   // master/data conns
			SentinelPassword: "sentinelpw", // sentinel conns
		}); err != nil {
			t.Fatalf("round trip with distinct master/sentinel passwords: %v", err)
		}
	})

	t.Run("missing sentinel password fails at the sentinel", func(t *testing.T) {
		_, err := NewValkeyStore(context.Background(), StoreOptions{
			Addrs:      []string{sentinelAddr},
			MasterName: "mymaster",
			Password:   "masterpw",
			// SentinelPassword intentionally omitted.
		})
		if err == nil {
			t.Fatal("expected error without SentinelPassword, got success")
		}
		if !strings.Contains(err.Error(), "NOAUTH") {
			t.Fatalf("expected NOAUTH error from the sentinel, got: %v", err)
		}
		t.Logf("missing sentinel password: %v", err)
	})

	t.Run("wrong master password fails at the master", func(t *testing.T) {
		_, err := NewValkeyStore(context.Background(), StoreOptions{
			Addrs:            []string{sentinelAddr},
			MasterName:       "mymaster",
			Password:         "wrong-master-pw",
			SentinelPassword: "sentinelpw",
		})
		if err == nil {
			t.Fatal("expected error with wrong master password, got success")
		}
		if !strings.Contains(err.Error(), "WRONGPASS") {
			t.Fatalf("expected WRONGPASS error from the master, got: %v", err)
		}
		t.Logf("wrong master password: %v", err)
	})

	t.Run("swapped passwords fail at the sentinel", func(t *testing.T) {
		_, err := NewValkeyStore(context.Background(), StoreOptions{
			Addrs:            []string{sentinelAddr},
			MasterName:       "mymaster",
			Password:         "sentinelpw", // master conns wrongly get the sentinel password
			SentinelPassword: "masterpw",   // sentinel conns wrongly get the master password
		})
		if err == nil {
			t.Fatal("expected error with swapped passwords, got success")
		}
		if !strings.Contains(err.Error(), "WRONGPASS") {
			t.Fatalf("expected WRONGPASS error from the sentinel, got: %v", err)
		}
		t.Logf("swapped passwords: %v", err)
	})
}
