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
	Addrs            []string // direct: [addr]; sentinel: sentinel addrs
	MasterName       string   // sentinel mode when non-empty
	Password         string   // master/data connections
	SentinelUsername string   // sentinel connections (sentinel mode only)
	SentinelPassword string   // sentinel connections (sentinel mode only)
	DB               int
	TLS              *tls.Config // nil = plaintext
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
// (ClientOption.TLSConfig). Sentinel credentials (SentinelUsername/
// SentinelPassword) are wired into SentinelOption.Username/Password —
// valkey-go v1.0.76's newSentinelOpt (sentinel.go) copies those onto the
// option used for sentinel connections, whose per-connection init sends
// HELLO 3 AUTH (pipe.go), so the sentinel itself is authenticated
// independently of the master. ClientOption.Password keeps serving the
// master/data connections. Exported so tests (and callers) can assert the
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
			Username:  opts.SentinelUsername,
			Password:  opts.SentinelPassword,
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

// sessionLivePrefix keys the session directory entries (Task 8.2):
// sess:live:<session_id> = JSON session record with a heartbeat TTL.
const sessionLivePrefix = "sess:live:"

// SetSessionLive stores (or refreshes) a live session record with a TTL
// (SETEX). rec is the raw JSON marshaled by the data plane; ttl is the
// heartbeat — an idle-but-open session drops off the directory when its
// heartbeats stop (documented Phase 8 behavior).
func (s *ValkeyStore) SetSessionLive(ctx context.Context, sid string, rec []byte, ttl time.Duration) error {
	return s.client.Do(ctx, s.client.B().Set().Key(sessionLivePrefix+sid).Value(string(rec)).Ex(ttl).Build()).Error()
}

// DelSessionLive removes a live session record (session close).
func (s *ValkeyStore) DelSessionLive(ctx context.Context, sid string) error {
	return s.client.Do(ctx, s.client.B().Del().Key(sessionLivePrefix+sid).Build()).Error()
}

// ListSessions returns the raw JSON records of all live sessions: a full
// SCAN of sess:live:* (cursor walk) followed by MGET. Records whose keys
// expired between the SCAN and the MGET are skipped. Errors are wrapped;
// an empty directory returns (nil, nil).
func (s *ValkeyStore) ListSessions(ctx context.Context) ([][]byte, error) {
	var keys []string
	cursor := uint64(0)
	for {
		res, err := s.client.Do(ctx, s.client.B().Scan().Cursor(cursor).Match(sessionLivePrefix+"*").Count(100).Build()).AsScanEntry()
		if err != nil {
			return nil, fmt.Errorf("list sessions scan: %w", err)
		}
		keys = append(keys, res.Elements...)
		cursor = res.Cursor
		if cursor == 0 {
			break
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	vals, err := s.client.Do(ctx, s.client.B().Mget().Key(keys...).Build()).AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("list sessions mget: %w", err)
	}
	recs := make([][]byte, 0, len(vals))
	for _, v := range vals {
		if v != "" { // key expired between SCAN and MGET → nil → skip
			recs = append(recs, []byte(v))
		}
	}
	return recs, nil
}

// watchPrefix keys the checker-presence records (Task 8.6): watch:<sid>
// exists while at least one checker is subscribed to the session's own
// channel (sess:<sid>). The Data Plane's maker write-gate probes it with
// WatchActive before relaying SQL on write-access sessions.
const watchPrefix = "watch:"

// SetWatch records checker presence on a session (watch:<sid>) with a
// presence lease ttl — the Control Plane WS hub sets it on subscribe to
// channel sess:<sid> and refreshes it on a heartbeat while the checker
// stays connected (SET … EX semantics).
func (s *ValkeyStore) SetWatch(ctx context.Context, sid string, ttl time.Duration) error {
	return s.client.Do(ctx, s.client.B().Set().Key(watchPrefix+sid).Value("1").Ex(ttl).Build()).Error()
}

// DelWatch removes checker presence for a session (checker disconnected or
// switched away from the session's channel).
func (s *ValkeyStore) DelWatch(ctx context.Context, sid string) error {
	return s.client.Do(ctx, s.client.B().Del().Key(watchPrefix+sid).Build()).Error()
}

// WatchActive reports whether a checker is currently watching the session
// (EXISTS watch:<sid>) — the Data Plane's maker write-gate probe. Callers
// treat an error as FAIL CLOSED (the gate blocks the command).
func (s *ValkeyStore) WatchActive(ctx context.Context, sid string) (bool, error) {
	n, err := s.client.Do(ctx, s.client.B().Exists().Key(watchPrefix+sid).Build()).AsInt64()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// WatchTTL returns the remaining presence lease of a watch key (0 when the
// key is absent or has no expiry) — used by tests to prove the hub's
// heartbeat refreshes the lease rather than merely setting the key once.
func (s *ValkeyStore) WatchTTL(ctx context.Context, sid string) (time.Duration, error) {
	secs, err := s.client.Do(ctx, s.client.B().Ttl().Key(watchPrefix+sid).Build()).AsInt64()
	if err != nil {
		return 0, err
	}
	if secs < 0 {
		return 0, nil // -1 no expiry / -2 missing — neither is a valid lease
	}
	return time.Duration(secs) * time.Second, nil
}

// SessionInfo is the checker-facing session directory entry (Task 8.4),
// decoded from the data plane's sess:live:<sid> records. ThreadID is
// intentionally NOT exposed: it is a backend-internal connection identifier
// (MySQL CONNECTION_ID / PG backend pid), not part of the control-plane
// surface. Status (Task 8.11) is "pending" for a token issued but not yet
// connected (control plane) or "active" once the data plane session is
// established; empty for records written before 8.11.
type SessionInfo struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	DBUser    string    `json:"db_user"`
	DBType    string    `json:"db_type"`
	DB        string    `json:"db"`
	Status    string    `json:"status,omitempty"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// ListSessionsParsed returns the live session directory as typed records,
// decoding each raw sess:live:<sid> payload into SessionInfo. Records that
// fail to decode are skipped — the data plane only ever writes valid JSON,
// and one malformed record must not hide the rest of the directory. An
// empty directory returns an empty non-nil slice so handlers encode it as
// [] rather than null.
func (s *ValkeyStore) ListSessionsParsed(ctx context.Context) ([]SessionInfo, error) {
	raw, err := s.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(raw))
	for _, rec := range raw {
		var si SessionInfo
		if err := json.Unmarshal(rec, &si); err != nil {
			continue // skip malformed record
		}
		out = append(out, si)
	}
	return out, nil
}
