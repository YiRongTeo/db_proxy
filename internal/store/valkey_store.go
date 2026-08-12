package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
)

// StoreOptions configures the Valkey connection.
//
// Addrs carries the direct address(es) in direct mode, or the SENTINEL
// addresses in sentinel mode (when MasterName is non-empty). TLS nil means
// plaintext; when set, the same config covers data connections to the master
// (ClientOption.TLSConfig) and, in sentinel mode, the sentinel connections
// (SentinelOption.TLSConfig) — valkey-go v1.0.76 applies
// SentinelOption.TLSConfig to sentinel conns and ClientOption.TLSConfig to
// master/data conns.
type StoreOptions struct {
	Addrs      []string // direct: [addr]; sentinel: sentinel addrs
	MasterName string   // sentinel mode when non-empty
	Password   string
	DB         int
	TLS        *tls.Config // nil = plaintext
}

// TLSFromFiles builds a *tls.Config from PEM files:
//   - caFile (optional): parsed into RootCAs (server certificate verification);
//   - certFile+keyFile (optional, must be given together): client certificate;
//   - skipVerify: InsecureSkipVerify (disables chain AND hostname verification);
//   - serverName: set as ServerName when non-empty AND skipVerify is false
//     (caller passes the addr host; unused when verifying via IP SANs is not
//     wanted).
//
// Returns (nil, nil) when every file argument is empty — the plaintext case.
func TLSFromFiles(caFile, certFile, keyFile string, skipVerify bool, serverName string) (*tls.Config, error) {
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	cfg := &tls.Config{InsecureSkipVerify: skipVerify} // explicit opt-in via config
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca file %s: no certificates parsed", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("cert_file and key_file must be given together")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert/key pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if serverName != "" && !skipVerify {
		cfg.ServerName = serverName
	}
	return cfg, nil
}

// BuildClientOption maps StoreOptions onto the valkey-go ClientOption. In
// sentinel mode (MasterName non-empty) InitAddress carries the SENTINEL
// addresses and the same TLS config is wired for both the sentinel
// connections (SentinelOption.TLSConfig) and the master/data connections
// (ClientOption.TLSConfig). Exported so tests (and callers) can assert the
// wiring without constructing a client.
func BuildClientOption(opts StoreOptions) valkey.ClientOption {
	opt := valkey.ClientOption{
		InitAddress: opts.Addrs,
		Password:    opts.Password,
		SelectDB:    opts.DB,
		TLSConfig:   opts.TLS,
	}
	if opts.MasterName != "" {
		opt.Sentinel = valkey.SentinelOption{
			MasterSet: opts.MasterName,
			TLSConfig: opts.TLS,
		}
	}
	return opt
}

// ValkeyStore wraps valkey-go with the token/session primitives.
type ValkeyStore struct {
	client valkey.Client
	opts   StoreOptions // kept for future reconnect logic
}

// NewValkeyStore connects to Valkey (direct or via sentinel per opts) and
// verifies connectivity with a PING (3s timeout) — fail fast. The valkey-go
// client reconnects internally; opts is retained on the store for any later
// reconnect needs.
func NewValkeyStore(ctx context.Context, opts StoreOptions) (*ValkeyStore, error) {
	if len(opts.Addrs) == 0 {
		return nil, errors.New("valkey store: at least one address required")
	}
	client, err := valkey.NewClient(BuildClientOption(opts))
	if err != nil {
		return nil, fmt.Errorf("valkey client: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Do(pingCtx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("valkey ping: %w", err)
	}
	return &ValkeyStore{client: client, opts: opts}, nil
}

// NewValkeyStoreDirect is the plaintext direct-mode convenience wrapper
// (single address, no sentinel, no TLS) — used by tests and simple callers.
func NewValkeyStoreDirect(ctx context.Context, addr, password string, db int) (*ValkeyStore, error) {
	return NewValkeyStore(ctx, StoreOptions{Addrs: []string{addr}, Password: password, DB: db})
}

func (s *ValkeyStore) Close() { s.client.Close() }

// Ping checks Valkey connectivity (used by the health endpoint).
func (s *ValkeyStore) Ping(ctx context.Context) error {
	return s.client.Do(ctx, s.client.B().Ping().Build()).Error()
}

// SetToken stores a token payload with a TTL (single-use semantics enforced
// by the caller using GetDeleteToken).
func (s *ValkeyStore) SetToken(ctx context.Context, token string, p models.TokenPayload, ttl time.Duration) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.client.Do(ctx, s.client.B().Set().Key("tok:"+token).Value(string(data)).Ex(ttl).Build()).Error()
}

// GetDeleteToken atomically reads and deletes a token. Returns (nil, nil)
// when the token is absent or already consumed — this is the single-use gate.
func (s *ValkeyStore) GetDeleteToken(ctx context.Context, token string) (*models.TokenPayload, error) {
	raw, err := s.client.Do(ctx, s.client.B().Getdel().Key("tok:"+token).Build()).ToString()
	if errors.Is(err, valkey.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p models.TokenPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("token payload decode: %w", err)
	}
	return &p, nil
}

// CreateSession stores a UI session with a TTL and returns its id.
func (s *ValkeyStore) CreateSession(ctx context.Context, sess models.Session, ttl time.Duration) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	key := "sess:ui:" + id
	if err := s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Ex(ttl).Build()).Error(); err != nil {
		return "", err
	}
	return id, nil
}

// GetSession returns the session for an id, or nil if absent/expired.
func (s *ValkeyStore) GetSession(ctx context.Context, id string) (*models.Session, error) {
	raw, err := s.client.Do(ctx, s.client.B().Get().Key("sess:ui:"+id).Build()).ToString()
	if errors.Is(err, valkey.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sess models.Session
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *ValkeyStore) DeleteSession(ctx context.Context, id string) error {
	return s.client.Do(ctx, s.client.B().Del().Key("sess:ui:"+id).Build()).Error()
}
