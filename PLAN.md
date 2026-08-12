# Project-D — Zero-Trust JIT DB Access Gateway: Implementation Plan

> **For Hermes:** Use subagent-driven-development to implement this plan task-by-task. Fresh implementer subagent per task; spec-compliance review + code-quality review after each; progress ledger; no check-ins between tasks.

**Goal:** Build a zero-trust, JIT database access gateway — Control Plane (Go HTTP API + WebSocket + Angular 21 SPA) and Data Plane (Go TCP proxy parsing MySQL/PostgreSQL wire traffic), coupled only through Valkey. Users connect with single-use 5-minute tokens; every query is live-audited on the Checker dashboard.

**Architecture:** Control Plane (:8080) issues tokens into Valkey (`tok:<t>` TTL 300 s, atomic `GETDEL` = single-use) and bridges Valkey Pub/Sub to the Checker WebSocket. Data Plane (:3306/:5432) accepts thick-client connections with the token as username, validates via GETDEL, connects to the real backend with credentials from `data.yaml`, relays byte-exact, and passively sniffs SQL → publishes `QueryEvent` to `queries:*`.

**Tech Stack:** Go 1.24 (target 1.27), stdlib net/http, coder/websocket v2, valkey-io/valkey-go v1, spf13/viper, log/slog, go-mysql-org/go-mysql v1, jackc/pgx v5 + pgproto3/v2, Angular 21 standalone/zoneless/signals + NG-ZORRO v21. All deps Apache-2.0/MIT.

**Docs:** `hermes-agent-spec.md` (authoritative spec, §9 amendments), `hermes-rules.md` (house rules).

---

## Design Decisions (resolved — do not reopen without user approval)

| # | Decision | Rationale |
|---|---|---|
| D1 | **Valkey** (valkey/valkey:8 container) instead of Redis; `valkey-io/valkey-go` client | User directive 2026-08-11; RESP-compatible; RSAL-free |
| D2 | `/api/token` auth = `X-Api-Key` **or** UI session (cookie) | Spec allowed mTLS or API key; API key is simplest for ticketing integration |
| D3 | Checker is **monitor-only** (live feed). No approval/kill in v1 | Spec requires auditing only |
| D4 | Token payload includes `db_type` | Data Plane must know the protocol for routing/events |
| D5 | MySQL client-facing handshake **hand-rolled** (advertise `mysql_native_password`, ignore client password — token is the credential); backend auth via go-mysql (handles caching_sha2) | No third-party wire dep on the security boundary; battle-tested backend auth |
| D6 | PG client-facing via pgproto3 `Backend`; backend via pgx.Connect → `Hijack()` → pgproto3 `Frontend` | pgx handles SCRAM-SHA-256; pgproto3 handles framing both ways |
| D7 | Relay is **byte-exact** (original 4-byte headers replayed unchanged, both directions) | Sequence numbers stay consistent; no seq bookkeeping |
| D8 | UI tokens only against `db_presets` allowlist (control.yaml) | Zero-trust: UI can't target arbitrary hosts |
| D9 | Test DBs via Docker: mysql:8.4 (`--mysql-native-password=ON`), postgres:17 | Local env has Docker; native password keeps all auth paths classic |
| D10 | No TLS in v1 (no SSL cap advertised; PG answers SSLRequest 'N') | Hardening item v1.1 |
| D11 | **Single shared Data Plane port** (`:3306`) for MySQL AND PostgreSQL; protocol detected per connection (PG is client-first, MySQL is server-first) | One port to expose/firewall/document; `detect_delay_ms` grace (default 200 ms); peeked bytes preserved via bufio.Reader |

## Spec amendments vs agent.md
See hermes-agent-spec.md §9 (Valkey, db_type, API-key auth, monitor-only checker, db-presets allowlist, response port semantics, UI session, single shared Data Plane port).

## Environment map (ports)

| Service | Host port | Container | Notes |
|---|---|---|---|
| Control Plane | 8080 | — | Go `cmd/control` |
| Data Plane (MySQL + PostgreSQL, shared) | 3306 | — | Go `cmd/data`; ONE listener, protocol detected per connection; HeidiSQL + psql target |
| Valkey | 6379 | valkey/valkey:8-alpine | `tok:*`, `sess:ui:*`, Pub/Sub |
| MySQL backend | 3307 | mysql:8.4 | `appdb`; users ro_user/rw_user |
| PostgreSQL backend | 5433 | postgres:17 | `appdb`; users app_user/ro_user |

---

# Phase 0 — Environment & Scaffold

### Task 0.1: Start Docker Desktop and verify daemon
**Files:** none.
**Steps:**
1. `powershell.exe -Command "Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'"` (ignore error if already running)
2. Loop until ready (max ~180 s): `docker info --format '{{.ServerVersion}}'`
3. Expected: prints a version like `29.6.1`. If Docker Desktop is installed elsewhere, find it: `ls "/c/Program Files/Docker/Docker"` or `where docker`.
**Verify:** `docker ps` lists no containers, no error.

### Task 0.2: Valkey container
**Steps:**
1. `docker run -d --name valkey -p 6379:6379 -v valkey-data:/data valkey/valkey:8-alpine --save 60 1`
2. `docker exec valkey valkey-cli ping`
**Expected:** `PONG`.

### Task 0.3: MySQL 8.4 test backend
**Steps:**
1. `docker run -d --name mysql-test -p 3307:3306 -e MYSQL_ROOT_PASSWORD=root_pw -e MYSQL_DATABASE=appdb mysql:8.4 --mysql-native-password=ON`
2. Wait for ready (retry up to 60 s): `docker exec mysql-test mysqladmin -uroot -proot_pw ping`
3. Create users + seed data (password `ro_pw` / `rw_pw`):
```bash
docker exec mysql-test mysql -uroot -proot_pw appdb -e "
CREATE USER 'ro_user'@'%' IDENTIFIED WITH mysql_native_password BY 'ro_pw';
GRANT SELECT ON appdb.* TO 'ro_user'@'%';
CREATE USER 'rw_user'@'%' IDENTIFIED WITH mysql_native_password BY 'rw_pw';
GRANT ALL PRIVILEGES ON appdb.* TO 'rw_user'@'%';
CREATE TABLE IF NOT EXISTS demo_items (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100));
INSERT INTO demo_items (name) VALUES ('test'),('bravo'),('charlie');
FLUSH PRIVILEGES;"
```
**Verify:** `docker exec mysql-test mysql -uroot -proot_pw -e "SELECT COUNT(*) FROM appdb.demo_items;"` → 3.

### Task 0.4: PostgreSQL 17 test backend
**Steps:**
1. `docker run -d --name pg-test -p 5433:5432 -e POSTGRES_USER=app_user -e POSTGRES_PASSWORD=app_pw -e POSTGRES_DB=appdb postgres:17`
2. Retry up to 60 s: `docker exec pg-test pg_isready -U app_user -d appdb`
3. Users + seed:
```bash
docker exec pg-test psql -U app_user -d appdb -c "
CREATE ROLE ro_user LOGIN PASSWORD 'ro_pw';
GRANT CONNECT ON DATABASE appdb TO ro_user;
GRANT USAGE ON SCHEMA public TO ro_user;
CREATE TABLE IF NOT EXISTS demo_items (id SERIAL PRIMARY KEY, name TEXT);
INSERT INTO demo_items (name) VALUES ('alpha'),('bravo'),('charlie') ON CONFLICT DO NOTHING;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro_user;"   # NOTE: GRANT AFTER CREATE TABLE — otherwise a fresh seed grants on zero tables (fixed 2026-08-11, 4.3 gate)
```
**Verify:** `docker exec pg-test psql -U app_user -d appdb -tAc "SELECT COUNT(*) FROM demo_items;"` → 3.

### Task 0.5: Go module scaffold
**Files:** Create:
- `D:\AI\hermes\Project\Project-D\go.mod` (module `zerotrust-proxy`, go 1.24)
- `cmd/control/main.go` (stub: log "control plane stub")
- `cmd/data/main.go` (stub: log "data plane stub")
- `internal/models/models.go`, `internal/store/`, `internal/api/`, `internal/proxy/` (empty dirs via `.gitkeep`)
- `.gitignore` (bin/, web/node_modules/, web/dist/, configs/*.local.yaml, *.exe)

**Steps:**
1. `cd /d/AI/hermes/Project/Project-D && go mod init zerotrust-proxy`
2. Add deps:
```bash
go get github.com/valkey-io/valkey-go@latest github.com/coder/websocket@latest github.com/spf13/viper@latest github.com/go-mysql-org/go-mysql@latest github.com/jackc/pgx/v5@latest github.com/jackc/pgproto3/v2@latest
```
3. `git init && git add -A && git commit -m "chore: scaffold module and dirs"`
**Verify:** `go build ./...` succeeds; `git log --oneline` shows the commit.

### Task 0.6: Config files
**Files:** Create `configs/control.yaml`:
```yaml
http:
  addr: ":8080"
  static_dir: "./web/dist/project-d/browser"
api:
  api_key: ""                 # empty → external /api/token disabled; set via ZT_API_KEY
  token_ttl_seconds: 300
  data_plane_host: "127.0.0.1"
  data_plane_port: "3306"      # shared Data Plane listener (MySQL + PostgreSQL)
auth:
  username: "admin"
  password: "admin123"        # override via ZT_AUTH_PASSWORD
  session_ttl_hours: 8
db_presets:
  - name: "MySQL read-only"
    db_type: "mysql"
    db_user: "ro_user"
    db_ip: "127.0.0.1"
    db_port: "3307"
  - name: "MySQL read-write"
    db_type: "mysql"
    db_user: "rw_user"
    db_ip: "127.0.0.1"
    db_port: "3307"
  - name: "PostgreSQL read-only"
    db_type: "postgres"
    db_user: "ro_user"
    db_ip: "127.0.0.1"
    db_port: "5433"
valkey:
  addr: "127.0.0.1:6379"
  password: ""
  db: 0
```
Create `configs/data.yaml`:
```yaml
listen:
  addr: ":3306"            # shared port for MySQL + PostgreSQL (protocol detected)
  detect_delay_ms: 200     # grace period before assuming MySQL (server-first protocol)
valkey:
  addr: "127.0.0.1:6379"
  password: ""
  db: 0
credentials:                  # Data Plane owns DB credentials (zero-trust)
  - key: "127.0.0.1:3307:ro_user"
    password: "ro_pw"
  - key: "127.0.0.1:3307:rw_user"
    password: "rw_pw"
  - key: "127.0.0.1:5433:ro_user"
    password: "ro_pw"
```
**Verify:** YAML parses (`python -c "import yaml,sys; yaml.safe_load(open('configs/control.yaml'))"` and same for data.yaml).

**Phase 0 gate:** `docker ps` shows valkey, mysql-test, pg-test; `docker exec valkey valkey-cli ping` → PONG; `go build ./...` ok.

---

# Phase 1 — Shared Foundation (`internal/`)

### Task 1.1: Models
**Files:** Create `internal/models/models.go` + `internal/models/models_test.go`.
Complete code:
```go
package models

import "time"

// TokenPayload is the routing payload bound to a single-use token.
// Stored in Valkey at tok:<token> with a 5-minute TTL.
type TokenPayload struct {
	Username string `json:"username"`            // AD user / requester (for auditing)
	DBUser   string `json:"db_user"`             // backend DB user
	DBIP     string `json:"db_ip"`               // backend DB host
	DBPort   string `json:"db_port"`             // backend DB port
	DBType   string `json:"db_type"`             // "mysql" | "postgres"
	TicketID string `json:"ticket_id,omitempty"` // optional maker-checker grouping
}

// TokenResponse is returned by POST /api/token.
type TokenResponse struct {
	Token     string `json:"token"`
	Host      string `json:"host"`
	Port      string `json:"port"`
	ExpiresIn int    `json:"expires_in"` // seconds
}

// QueryEvent is published to Valkey Pub/Sub by the Data Plane
// and streamed to the Checker dashboard by the Control Plane.
type QueryEvent struct {
	ID         string    `json:"id"`
	Ts         time.Time `json:"ts"`
	Kind       string    `json:"kind"` // query | prepare | execute | use
	Username   string    `json:"username"`
	TicketID   string    `json:"ticket_id,omitempty"`
	DBUser     string    `json:"db_user"`
	DBIP       string    `json:"db_ip"`
	DBPort     string    `json:"db_port"`
	DBType     string    `json:"db_type"` // mysql | postgres
	SQL        string    `json:"sql"`
	ClientAddr string    `json:"client_addr"`
}

// Session is the UI session payload (stored at sess:ui:<id>).
type Session struct {
	Username string    `json:"username"`
	Expires  time.Time `json:"expires"`
}
```
**Test:** JSON round-trip for all three structs (marshal → unmarshal → DeepEqual). Include a test that `TokenPayload` with empty TicketID omits the field.
**Verify:** `go test ./internal/models/ -v` → PASS.

### Task 1.2: Valkey store (tokens + sessions)
**Files:** Create `internal/store/valkey_store.go` + `internal/store/valkey_store_test.go`.
Complete code:
```go
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
)

// ValkeyStore wraps valkey-go with the token/session primitives.
type ValkeyStore struct {
	client valkey.Client
}

func NewValkeyStore(ctx context.Context, addr, password string, db int) (*ValkeyStore, error) {
	// valkey-go v1: ClientOption uses InitAddress ([]string) — there is no Addr field.
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Password: password, SelectDB: db})
	if err != nil {
		return nil, fmt.Errorf("valkey client: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Do(pingCtx, client.B().Ping().Build()).Error(); err != nil {
		return nil, fmt.Errorf("valkey ping: %w", err)
	}
	return &ValkeyStore{client: client}, nil
}

func (s *ValkeyStore) Close() { s.client.Close() }

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
```
Add `internal/store/id.go` (used by store and api):
```go
package store

import (
	"crypto/rand"
	"encoding/hex"
)

// newID returns a random 128-bit hex id (used for tokens and session ids).
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewToken returns a token of the form sess_<32 hex chars>.
func NewToken() (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	return "sess_" + id, nil
}
```
**Tests (require Valkey running):**
1. SetToken → GetDeleteToken returns the payload; second GetDeleteToken returns nil (single-use proven).
2. SetToken with 1 s TTL → sleep 1.2 s → GetDeleteToken nil (expiry).
3. CreateSession → GetSession ok; DeleteSession → GetSession nil.
**Verify:** `go test ./internal/store/ -v` → all PASS.

### Task 1.3: Valkey Pub/Sub
**Files:** Create `internal/store/pubsub.go` + `internal/store/pubsub_test.go`.
Complete code (valkey-go v1.0.76 — VERIFIED: the handle-based `ps.Receive(ctx)` pattern does NOT exist in this version; the correct API is the callback form `Client.Receive(ctx, cmd, fn)` which registers the subscription and invokes fn per message until ctx is cancelled):
```go
package store

import (
	"context"
	"fmt"

	"github.com/valkey-io/valkey-go"
)

// Publish sends a raw JSON message to a channel.
func (s *ValkeyStore) Publish(ctx context.Context, channel string, message []byte) error {
	return s.client.Do(ctx, s.client.B().Publish().Channel(channel).Message(string(message)).Build()).Error()
}

// Subscribe streams messages from a channel (or pattern when pattern=true,
// e.g. "queries:*"). It blocks until ctx is cancelled or the connection
// fails, forwarding each message to out. It returns an error if the
// subscription itself fails; on ctx cancellation it returns ctx.Err().
func (s *ValkeyStore) Subscribe(ctx context.Context, channel string, pattern bool, out chan<- []byte) error {
	var cmd valkey.Completed
	if pattern {
		cmd = s.client.B().Psubscribe().Pattern(channel).Build()
	} else {
		cmd = s.client.B().Subscribe().Channel(channel).Build()
	}
	// Receive registers the subscription and invokes fn for every message
	// until ctx is cancelled (it then returns ctx.Err()). The send must also
	// unblock on ctx.Done() so a full out channel cannot deadlock cancel.
	err := s.client.Receive(ctx, cmd, func(msg valkey.PubSubMessage) {
		select {
		case out <- []byte(msg.Message):
		case <-ctx.Done():
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", channel, err)
	}
	return nil
}
```
**Tests:** subscriber goroutine on `queries:test` + pattern `queries:*`; publish 2 messages; assert both received with matching content; cancel ctx → subscriber returns.
**Verify:** `go test ./internal/store/ -run PubSub -v` → PASS.

### Task 1.4: Config loader
**Files:** Create `internal/config/config.go`:
```go
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

func load(v *viper.Viper, path string, defaults map[string]any) error {
	for k, val := range defaults {
		v.SetDefault(k, val)
	}
	v.SetConfigFile(path)
	v.SetEnvPrefix("ZT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	return nil
}

// ControlConfig mirrors configs/control.yaml.
type ControlConfig struct {
	HTTPAddr      string
	StaticDir     string
	APIKey        string
	TokenTTL      int
	DataPlaneHost string
	DataPlanePort string
	AuthUser      string
	AuthPassword  string
	SessionTTL    int // hours
	DBPresets     []DBPreset
	ValkeyAddr    string
	ValkeyPassword string
	ValkeyDB      int
}

type DBPreset struct {
	Name   string `mapstructure:"name"`
	DBType string `mapstructure:"db_type"`
	DBUser string `mapstructure:"db_user"`
	DBIP   string `mapstructure:"db_ip"`
	DBPort string `mapstructure:"db_port"`
}

func LoadControl(path string) (*ControlConfig, error) {
	v := viper.New()
	if err := load(v, path, map[string]any{
		"http.addr": ":8080", "api.token_ttl_seconds": 300,
		"auth.session_ttl_hours": 8, "valkey.addr": "127.0.0.1:6379",
	}); err != nil {
		return nil, err
	}
	return &ControlConfig{
		HTTPAddr: v.GetString("http.addr"), StaticDir: v.GetString("http.static_dir"),
		APIKey: v.GetString("api.api_key"), TokenTTL: v.GetInt("api.token_ttl_seconds"),
		DataPlaneHost: v.GetString("api.data_plane_host"),
		DataPlanePort: v.GetString("api.data_plane_port"),
		AuthUser: v.GetString("auth.username"), AuthPassword: v.GetString("auth.password"),
		SessionTTL: v.GetInt("auth.session_ttl_hours"),
		ValkeyAddr: v.GetString("valkey.addr"), ValkeyPassword: v.GetString("valkey.password"),
		ValkeyDB: v.GetInt("valkey.db"),
	}, v.UnmarshalKey("db_presets", &cfg.DBPresets) // see note
}
```
> Implementer note: `UnmarshalKey` needs the same viper instance — restructure `LoadControl` to hold `v` and unmarshal `db_presets` into `cfg.DBPresets` before returning (the snippet above is a sketch; the final function must compile and return all fields).

Also `DataConfig` for `configs/data.yaml` (`listen.addr`, `listen.detect_delay_ms`, `valkey.*`, `credentials` as `map[string]string` keyed by `key`). Test with the committed YAML files: `go test` in `internal/config` asserting `LoadControl("../../configs/control.yaml")` has 3 presets and TTL 300.
**Verify:** `go test ./internal/config/ -v` → PASS.

### Task 1.5: slog setup
**Files:** Create `internal/logging/logging.go`:
```go
package logging

import (
	"log/slog"
	"os"
)

func New(service string) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", service)
}
```
**Verify:** small `go run ./cmd/control` prints one JSON line to stdout; no secrets anywhere.

### Task 1.6: Phase 1 gate
- `go vet ./...` clean; `go test ./...` all PASS (Valkey must be running).
- Commit: `git add -A && git commit -m "feat(store): models, valkey store, pubsub, config, logging"`.

---

# Phase 2 — Control Plane

### Task 2.1: cmd/control/main.go
**Files:** Create `cmd/control/main.go`. Skeleton:
```go
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zerotrust-proxy/internal/api"
	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/logging"
	"zerotrust-proxy/internal/store"
)

func main() {
	log := logging.New("control")
	cfg, err := config.LoadControl("configs/control.yaml")
	if err != nil { log.Error("config", "err", err); os.Exit(1) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vs, err := store.NewValkeyStore(ctx, cfg.ValkeyAddr, cfg.ValkeyPassword, cfg.ValkeyDB)
	if err != nil { log.Error("valkey", "err", err); os.Exit(1) }
	defer vs.Close()

	apiSrv := api.NewAPI(log, cfg, vs) // Task 2.2/2.3
	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: apiSrv.Routes()}

	go func() {
		log.Info("control plane listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
			cancel() // unblocks the shutdown path via the stop channel below
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	// Fail fast on fatal server errors (e.g. port already bound): the goroutine
	// above cannot be the only unblocker — cancel() alone would hang the wait.
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.ListenAndServe() }()
	select {
	case err := <-srvErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
			os.Exit(1)
		}
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
		shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shCancel()
		_ = srv.Shutdown(shCtx)
	}
}
```
**Verify:** builds; `go run ./cmd/control` starts and logs a JSON line; Ctrl-C (or `process kill`) shuts down cleanly. (Static dir will 404 until Phase 2.9 — fine.)

### Task 2.2: Auth middleware + login/logout + health + db-presets
**Files:** Create `internal/api/api.go`, `internal/api/auth.go`, `internal/api/handlers.go` (package `api`).
Complete code (auth.go):
```go
package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

const sessionCookie = "zt_session"

type authMiddleware struct {
	cfg *config.ControlConfig
	vs  *store.ValkeyStore
}

// requireSession rejects requests without a valid UI session cookie.
func (a *authMiddleware) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		sess, err := a.vs.GetSession(r.Context(), c.Value)
		if err != nil || sess == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, sess)
		next(w, r.WithContext(ctx))
	}
}

// validAPIKey reports whether the X-Api-Key header matches config.
func (a *authMiddleware) validAPIKey(r *http.Request) bool {
	k := a.cfg.APIKey
	return k != "" && strings.TrimSpace(r.Header.Get("X-Api-Key")) == k
}

type sessionKey struct{}

func sessionFrom(r *http.Request) *models.Session {
	if s, ok := r.Context().Value(sessionKey{}).(*models.Session); ok {
		return s
	}
	return nil
}

// handleLogin validates credentials and creates a Valkey-backed session.
func (a *authMiddleware) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if req.Username != a.cfg.AuthUser || req.Password != a.cfg.AuthPassword {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	id, err := a.vs.CreateSession(r.Context(), models.Session{
		Username: req.Username,
		Expires:  time.Now().Add(time.Duration(a.cfg.SessionTTL) * time.Hour),
	}, time.Duration(a.cfg.SessionTTL)*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: a.cfg.SessionTTL * 3600,
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": req.Username})
}

func (a *authMiddleware) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = a.vs.DeleteSession(r.Context(), c.Value)
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
```
handlers.go: `handleHealth` (pings Valkey via `vs.Ping(ctx)` — add a `Ping` method returning `error`), `handleDBPresets` (session required; returns `cfg.DBPresets`), `handleToken` (below), `decodeJSON`/`writeJSON` helpers. Routes in `api.go`:
```go
mux := http.NewServeMux()
mux.HandleFunc("GET /api/health", a.handleHealth)
mux.HandleFunc("POST /api/login", a.auth.handleLogin)
mux.HandleFunc("POST /api/logout", a.auth.handleLogout)
mux.HandleFunc("GET /api/db-presets", a.auth.requireSession(a.handleDBPresets))
mux.HandleFunc("POST /api/token", a.handleToken) // auth inside (key OR session)
mux.HandleFunc("GET /ws/checker", a.auth.requireSession(a.handleWS)) // Task 2.3
mux.Handle("/", http.FileServer(http.Dir(cfg.StaticDir))) // Task 2.9
```
**Verify:** curl matrix (below) — but token endpoint comes in 2.3.

### Task 2.3: POST /api/token
**Files:** extend `internal/api/handlers.go`.
Complete code:
```go
func (a *api) handleToken(w http.ResponseWriter, r *http.Request) {
	if !a.auth.validAPIKey(r) && a.auth.sessionFromCookie(r) == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Username string `json:"username"`
		DBUser   string `json:"db_user"`
		DBIP     string `json:"db_ip"`
		DBPort   string `json:"db_port"`
		DBType   string `json:"db_type"`
		TicketID string `json:"ticket_id,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if sess := a.auth.sessionFromCookie(r); sess != nil && req.Username == "" {
		req.Username = sess.Username
	}
	if req.Username == "" || req.DBUser == "" || req.DBIP == "" || req.DBPort == "" {
		http.Error(w, `{"error":"missing required fields"}`, http.StatusBadRequest)
		return
	}
	if req.DBType != "mysql" && req.DBType != "postgres" {
		http.Error(w, `{"error":"db_type must be mysql or postgres"}`, http.StatusUnprocessableEntity)
		return
	}
	token, err := store.NewToken()
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	payload := models.TokenPayload{
		Username: req.Username, DBUser: req.DBUser, DBIP: req.DBIP,
		DBPort: req.DBPort, DBType: req.DBType, TicketID: req.TicketID,
	}
	ttl := time.Duration(a.cfg.TokenTTL) * time.Second
	if err := a.vs.SetToken(r.Context(), token, payload, ttl); err != nil {
		a.log.Error("token store", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	a.log.Info("token issued", "username", payload.Username, "db_user", payload.DBUser,
		"db_type", payload.DBType, "ticket", payload.TicketID)
	writeJSON(w, http.StatusOK, models.TokenResponse{
		Token:     token,
		Host:      a.cfg.DataPlaneHost,
		Port:      a.cfg.DataPlanePort, // single shared Data Plane port (spec amendment 8)
		ExpiresIn: a.cfg.TokenTTL,
	})
}
```
> VERIFIED DEVIATIONS (2026-08-11, Task 2.3): (1) `/api/token` is registered WITHOUT `requireSession`, so the context-based `sessionFrom()` is ALWAYS nil here — add `sessionFromCookie(r) *models.Session` to auth.go (read `zt_session` cookie → `GetSession` → return or nil); (2) `DataPlanePort` is a single string (shared port), not a map; (3) the env override for `api.api_key` is `ZT_API_API_KEY` (viper: dots→underscores + ZT_ prefix) — NOT `ZT_API_KEY`.
**Verify (curl):**
```bash
curl -s -X POST http://127.0.0.1:8080/api/token -H 'Content-Type: application/json' -d '{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"TICKET-1"}'
# → 401 (no key)
curl -s -X POST http://127.0.0.1:8080/api/token -H "X-Api-Key: $ZT_API_KEY" -H 'Content-Type: application/json' -d '{...same...}'
# → 200 {"token":"sess_...","host":"127.0.0.1","port":"3306","expires_in":300}
curl -s -c /tmp/zt.jar -X POST http://127.0.0.1:8080/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}'
curl -s -b /tmp/zt.jar http://127.0.0.1:8080/api/db-presets   # → 200 JSON array
```

### Task 2.4: WebSocket hub (/ws/checker)
**Files:** create `internal/api/websocket.go`.
Complete code:
```go
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// handleWS bridges Valkey Pub/Sub to a Checker's WebSocket.
// channel=alice → queries:alice ; channel=ticket:TICKET-1 → queries:ticket:TICKET-1 ;
// channel=* or empty → pattern queries:* (all queries).
func (a *api) handleWS(w http.ResponseWriter, r *http.Request) {
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		channel = "*"
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	key := "queries:" + channel
	pattern := channel == "*"
	out := make(chan []byte, 256)
	go func() {
		if err := a.vs.Subscribe(ctx, key, pattern, out); err != nil && ctx.Err() == nil {
			a.log.Warn("subscribe ended", "channel", key, "err", err)
		}
	}()

	// keepalive ping
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = c.Ping(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case m := <-out:
			if err := c.Write(ctx, websocket.MessageText, m); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
```
**Verify:** with control plane running and `channel=*`:
```bash
node -e '
const ws = new WebSocket("ws://127.0.0.1:8080/ws/checker?channel=*");
ws.onmessage = (e) => { console.log("EVENT:", e.data); ws.close(); process.exit(0); };
ws.onerror = (e) => { console.error("WS ERR"); process.exit(1); };
setTimeout(() => { console.error("TIMEOUT"); process.exit(2); }, 5000);
' &
sleep 1
curl -s -X POST http://127.0.0.1:8080/api/token -H "X-Api-Key: $ZT_API_KEY" -H 'Content-Type: application/json' -d '{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql"}'
# Control plane: publish a synthetic event so the WS test completes:
docker exec valkey valkey-cli publish queries:alice '{"id":"t1","ts":"2026-08-11T00:00:00Z","kind":"query","username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","sql":"SELECT 1","client_addr":"127.0.0.1:1"}'
# expect: EVENT: {...} from node (via pattern queries:*)
```
(WS is session-gated: run the node client with `-H 'Cookie: zt_session=...'` — fetch cookie via curl login jar; adjust command accordingly.)

### Task 2.5: Angular scaffold
**Files:** create under `web/`:
1. `cd /d/AI/hermes/Project/Project-D && npx -y @angular/cli@21 new web --directory web --standalone --zoneless --style=scss --skip-git --defaults`
2. `cd web && npx ng add ng-zorro-antd@21 --skip-confirmation` (choose default theme, enable icons)
3. `npm i ngx-clipboard`
4. Edit `web/src/styles.scss`: dark enterprise theme (dark zinc background `#0b0f19`-family, sky accent `#0ea5e9` — house style from B/C), `html,body{background:#0b0f19;color:#e2e8f0;}`.
5. `web/src/app/app.config.ts`: add `provideHttpClient()` and `provideAnimationsAsync()` (required by NG-ZORRO) if not present.
**Verify:** `npm run build` succeeds; `ng serve` renders the default page (browser check optional).

### Task 2.6: Core services
**Files:** `web/src/app/core/api.service.ts`, `core/auth.service.ts`, `core/live-query.service.ts`.
Key points:
- `ApiService`: `login(u,p)` POST /api/login (credentials: 'include'); `logout()`; `dbPresets()` GET /api/db-presets; `requestToken(payload)` POST /api/token; typed interfaces `DbPreset`, `TokenResponse`, `QueryEvent` (mirror Go JSON).
- `AuthService`: signal `user` (`signal<string|null>`), `isLoggedIn` computed; login/logout call ApiService and update signal.
- `LiveQueryService` (monitor-only):
```ts
import { Injectable, OnDestroy, signal } from '@angular/core';
import { webSocket, WebSocketSubject } from 'rxjs/webSocket';
import { toSignal } from '@angular/core/rxjs-interop';
import { QueryEvent } from './api.service';

@Injectable({ providedIn: 'root' })
export class LiveQueryService implements OnDestroy {
  private socket: WebSocketSubject<QueryEvent> | null = null;
  readonly events = signal<QueryEvent[]>([]);
  readonly connected = signal(false);
  private limit = 500; // ring-buffer cap

  connect(channel: string) {
    this.disconnect();
    const url = `${location.origin.replace(/^http/, 'ws')}/ws/checker?channel=${encodeURIComponent(channel)}`;
    this.socket = webSocket<QueryEvent>({ url, withCredentials: true });
    this.socket.subscribe({
      next: (e) => this.events.update((a) => [...a.slice(-this.limit + 1), e]),
      error: () => this.connected.set(false),
      complete: () => this.connected.set(false),
    });
    this.connected.set(true);
  }

  disconnect() {
    this.socket?.complete(); // spec: complete on navigation away (no leaks)
    this.socket = null;
  }

  ngOnDestroy() { this.disconnect(); }
}
```
**Verify:** `ng build` green; unit test for LiveQueryService event buffer (inject a fake WebSocketSubject via the `webSocketFactory` option) — 1 test.

### Task 2.7: Maker Portal
**Files:** `web/src/app/features/maker-portal/maker-portal.component.ts|html|scss` (standalone).
- `nz-form` with: preset `nz-select` (from ApiService.dbPresets()), ticket id optional `nz-input`, submit `nz-button` (type primary).
- Selecting a preset fills db_type/db_user/db_ip/db_port.
- On submit → `requestToken({username: auth.user(), ...preset, ticket_id})` → show `nz-result`-style card: token `nz-code`? — use a readonly `nz-input` + `nz-button` with `[cdkCopyToClipboard]` from `@angular/cdk/clipboard` (ngx-clipboard installed per spec; either works — prefer CDK clipboard, fewer deps at runtime).
- Show host/port/expires_in as `nz-descriptions`.
- Route `/maker` (lazy standalone, `canActivate` guard: redirect to /login if not logged in).
**Verify:** `ng build`; manual browser flow after Phase 2.10 (or `ng serve --proxy` optional — simplest is serving via Control Plane).

### Task 2.8: Checker Dashboard
**Files:** `web/src/app/features/checker-dashboard/checker-dashboard.component.ts|html|scss` (standalone).
- Channel input (`*` default) + "Connect"/"Stop" buttons.
- Connection status `nz-tag` (green "live" / red "disconnected").
- `nz-table` bound to `LiveQueryService.events` signal: columns Ts, Kind (`nz-tag` color: query=blue, prepare=purple, execute=orange, use=cyan), Username, DB (db_type), Target (db_user@db_ip:db_port), Ticket, SQL (monospace, `white-space: pre-wrap`).
- Auto-scroll toggle; ring buffer cap 500.
- `onDestroy` → `disconnect()`.
- Route `/checker` (lazy standalone, guard).
**Verify:** `ng build`.

### Task 2.9: Static serving + full control plane boot
**Files:** edit `cmd/control/main.go` — replace the file server line with:
```go
mux.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))
```
and mount it AFTER API routes (already in Task 2.2 sketch). Ensure `static_dir` exists before serving (log warning if missing).
**Verify:** `cd web && npm run build` then restart control plane; `curl -s http://127.0.0.1:8080/ | head -5` returns the Angular index.html.

### Task 2.10: Phase 2 gate
1. `ng build` clean.
2. Full curl matrix: login 200/401; db-presets 200 (with cookie) / 401 (without); token 401 without key; token 200 with key; token 200 with session cookie; health 200.
3. WS bridge test (Task 2.4 verify) passes with a real published event.
4. Browser smoke: `/login` → login as admin → `/maker` (form renders, presets load) → `/checker` (connect, status live).
5. Commit: `git add -A && git commit -m "feat(control): api, ws hub, angular maker/checker ui"`.

---

# Phase 3 — Data Plane: MySQL Proxy

### Task 3.1: MySQL packet IO
**Files:** `internal/proxy/mysql_packet.go` + test.
Complete code:
```go
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MySQL packet: 3-byte little-endian payload length + 1-byte sequence id.

func readMySQLPacket(r io.Reader) (seq byte, payload []byte, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read %d-byte payload: %w", length, err)
	}
	return hdr[3], payload, nil
}

// writeMySQLPacket replays the original header (same seq) — byte-exact relay.
func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
```
**Tests:** round-trip via `bytes.Buffer` (payload 0, 1, 255, 65535, 0xFFFFFF-1); assert header bytes: `[len&0xff, len>>8&0xff, len>>16&0xff, seq]`; truncated stream returns error. Use `binary.LittleEndian` in the test to build expected headers.
**Verify:** `go test ./internal/proxy/ -run Packet -v` → PASS.

### Task 3.2: MySQL handshake (client-facing server)
**Files:** `internal/proxy/mysql_handshake.go` + test.
Complete code:
```go
package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	capLongPassword     = 1 << 0
	capConnectWithDB    = 1 << 3  // CLIENT_CONNECT_WITH_DB 0x08 (NOT 0x10 = CLIENT_NO_SCHEMA)
	capProtocol41       = 1 << 9
	capTransactions     = 1 << 13
	capSecureConnection = 1 << 15
	capPluginAuth       = 1 << 19
	capPluginAuthData   = 1 << 21

	cmdQuit     = 0x01
	cmdInitDB   = 0x02
	cmdQuery    = 0x03
	cmdPing     = 0x0e
	cmdPrepare  = 0x16
	cmdExecute  = 0x17
)

var advertisedCaps = capLongPassword | capProtocol41 | capTransactions |
	capSecureConnection | capPluginAuth | capPluginAuthData

// buildHandshakeV10 builds the server's initial handshake payload.
// authData must be exactly 20 bytes (8-byte part1 + 12-byte part2).
func buildHandshakeV10(serverVersion string, connID uint32, authData []byte) ([]byte, error) {
	if len(authData) != 20 {
		return nil, fmt.Errorf("auth data must be 20 bytes, got %d", len(authData))
	}
	p := make([]byte, 0, 128)
	p = append(p, 0x0a) // protocol version 10
	p = append(p, []byte(serverVersion)...)
	p = append(p, 0x00)
	p = binary.LittleEndian.AppendUint32(p, connID)
	p = append(p, authData[:8]...)
	p = append(p, 0x00) // filler
	p = binary.LittleEndian.AppendUint16(p, uint16(advertisedCaps&0xffff))
	p = append(p, 33)                              // charset utf8_general_ci
	p = binary.LittleEndian.AppendUint16(p, 2)     // SERVER_STATUS_AUTOCOMMIT
	p = binary.LittleEndian.AppendUint16(p, uint16(advertisedCaps>>16))
	p = append(p, 21)                       // auth plugin data length
	p = append(p, make([]byte, 10)...)      // reserved
	p = append(p, authData[8:]...)          // 12-byte part2
	p = append(p, 0x00)
	p = append(p, []byte("mysql_native_password")...)
	p = append(p, 0x00)
	return p, nil
}

func randomAuthData() ([]byte, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	for i := range b {
		if b[i] == 0 {
			b[i] = 1 // avoid NUL bytes inside the scramble
		}
	}
	return b, nil
}

// parseHandshakeResponse extracts username (= token), database, auth response.
// Returns an error if the client does not speak protocol 4.1.
func parseHandshakeResponse(payload []byte) (username, database string, err error) {
	if len(payload) < 32 {
		return "", "", errors.New("handshake response too short")
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	if caps&capProtocol41 == 0 {
		return "", "", errors.New("client does not support protocol 4.1")
	}
	pos := 4 + 4 + 1 + 23 // max-packet(4) + charset(1) + reserved(23)
	end := bytes.IndexByte(payload[pos:], 0)
	if end < 0 {
		return "", "", errors.New("username not null-terminated")
	}
	username = string(payload[pos : pos+end])
	pos += end + 1
	if caps&capSecureConnection != 0 {
		if pos >= len(payload) {
			return "", "", errors.New("missing auth response length")
		}
		authLen := int(payload[pos])
		pos++
		if authLen > 0 {
			if pos+authLen > len(payload) {
				return "", "", errors.New("auth response truncated")
			}
			pos += authLen // password ignored — token is the credential
		}
	} else {
		if end := bytes.IndexByte(payload[pos:], 0); end >= 0 {
			pos += end + 1
		}
	}
	if caps&capConnectWithDB != 0 {
		if end := bytes.IndexByte(payload[pos:], 0); end >= 0 {
			database = string(payload[pos : pos+end])
		}
	}
	return username, database, nil
}

func okPacket() []byte {
	return []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00} // OK, autocommit
}

func errPacket(code uint16, sqlState, msg string) []byte {
	p := []byte{0xff, byte(code), byte(code >> 8), '#'}
	p = append(p, []byte(sqlState)...)
	return append(p, []byte(msg)...)
}
```
**Tests:**
1. `buildHandshakeV10` output: first byte 0x0a; contains "mysql_native_password"; plugin data length byte == 21 at the right offset; length equals expected layout.
2. `parseHandshakeResponse` on a constructed 4.1 response: caps + username "sess_abc" + db "appdb" + 20-byte auth; and an error case (truncated, no 4.1).
3. `errPacket(1045, "42000", "invalid or expired token")` starts `[0xff, 0x15, 0x04, '#', '4', '2', '0', '0', '0']` (1045 = 0x0415, little-endian 0x15 0x04 — corrected from an earlier typo 0x0d).
**Verify:** `go test ./internal/proxy/ -run Handshake -v` → PASS.

### Task 3.3: Backend connect + credential resolution
**Files:** `internal/proxy/mysql_router.go`.
Complete code:
```go
package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/go-mysql-org/go-mysql/client"
	"zerotrust-proxy/internal/models"
)

// backendKey identifies a credential entry: "<ip>:<port>:<db_user>".
func backendKey(t *models.TokenPayload) string {
	return fmt.Sprintf("%s:%s:%s", t.DBIP, t.DBPort, t.DBUser)
}

// connectMySQLBackend authenticates to the real MySQL with Data-Plane-owned
// credentials, then hands back the raw net.Conn for byte-exact relay.
// VERIFIED (v1.16.0, 2026-08-11): go-mysql negotiates CLIENT_QUERY_ATTRIBUTES
// and CLIENT_DEPRECATE_EOF by default — MySQL 8.4 then rejects naked COM_QUERY
// (ERR 1835 "Malformed communication packet") and EOF-less result-set framing
// mismatches classic clients. Both MUST be unset before Connect so the backend
// negotiates classic framing, matching what the relayed client produces.
func connectMySQLBackend(ctx context.Context, t *models.TokenPayload, creds map[string]string) (net.Conn, error) {
	pw, ok := creds[backendKey(t)]
	if !ok {
		return nil, fmt.Errorf("no credentials for %s", backendKey(t))
	}
	conn, err := client.ConnectWithContext(ctx, fmt.Sprintf("%s:%s", t.DBIP, t.DBPort), t.DBUser, pw, "",
		func(c *client.Conn) {
			c.UnsetCapability(client.CLIENT_QUERY_ATTRIBUTES)
			c.UnsetCapability(client.CLIENT_DEPRECATE_EOF)
		})
	if err != nil {
		return nil, fmt.Errorf("backend mysql connect: %w", err)
	}
	return conn.Conn, nil
}
```
(Verified against v1.16.0: `ConnectWithContext(ctx, addr, user, password, dbName, opts...)` — the plain `Connect` has no ctx arg. `conn.Conn` is the exported raw net.Conn. The UnsetCapability opts are LOAD-BEARING — do not remove them.)
**Verify:** unit test with `creds` map: unknown key → error; known key → no error *before* dial (use a fake: skip dial test here — covered in 3.6 integration).

### Task 3.4: MySQL proxy session
**Files:** `internal/proxy/mysql_proxy.go`.
Complete code:
```go
package proxy

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

type MySQLProxy struct {
	log      *slog.Logger
	vs       *store.ValkeyStore
	creds    map[string]string
	serverID atomic.Uint32
}

func NewMySQLProxy(log *slog.Logger, vs *store.ValkeyStore, creds map[string]string) *MySQLProxy {
	return &MySQLProxy{log: log, vs: vs, creds: creds}
}

// handleConn runs one MySQL session. The Dispatcher owns the accept loop and
// passes a buffered reader so any peeked client bytes are preserved.
func (p *MySQLProxy) handleConn(ctx context.Context, client net.Conn, br *bufio.Reader) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second)) // handshake deadline

	// 1. server handshake (seq 0)
	authData, err := randomAuthData()
	if err != nil {
		return
	}
	handshake, err := buildHandshakeV10("8.4.0-zerotrust-proxy", p.serverID.Add(1), authData)
	if err != nil {
		return
	}
	if err := writeMySQLPacket(client, 0, handshake); err != nil {
		return
	}

	// 2. handshake response (seq 1): username = token
	_, payload, err := readMySQLPacket(br)
	if err != nil {
		return
	}
	if len(payload) > 0 && payload[0] == 0xff {
		return // client refused
	}
	token, _, err := parseHandshakeResponse(payload)
	if err != nil {
		return
	}

	// 3. single-use token validation
	tok, err := p.vs.GetDeleteToken(ctx, token)
	if err != nil {
		p.log.Error("token lookup", "err", err)
		return
	}
	if tok == nil {
		p.log.Warn("invalid or expired token", "client", clientAddr)
		_ = writeMySQLPacket(client, 2, errPacket(1045, "42000", "invalid or expired token"))
		return
	}
	if tok.DBType != "mysql" {
		p.log.Warn("token for wrong protocol", "db_type", tok.DBType, "client", clientAddr)
		_ = writeMySQLPacket(client, 2, errPacket(1045, "42000", "token not valid for this listener"))
		return
	}

	// 4. backend connection (real credentials)
	backend, err := connectMySQLBackend(ctx, tok, p.creds)
	if err != nil {
		p.log.Error("backend connect failed", "err", err, "client", clientAddr)
		_ = writeMySQLPacket(client, 2, errPacket(1045, "42000", "backend unavailable"))
		return
	}
	defer backend.Close()

	// 5. OK (seq 2) — session established
	if err := writeMySQLPacket(client, 2, okPacket()); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	p.log.Info("session established", "username", tok.Username, "db_user", tok.DBUser,
		"db_type", tok.DBType, "client", clientAddr)

	// 6. bidirectional relay with passive sniffing
	done := make(chan struct{}, 2)
	go func() {
		p.pipeClientToBackend(br, backend, tok, clientAddr)
		done <- struct{}{}
	}()
	go func() {
		p.pipeBackendToClient(backend, client)
		done <- struct{}{}
	}()
	<-done
	client.Close()
	backend.Close()
	p.log.Info("session closed", "username", tok.Username, "client", clientAddr)
}
```
Add `mysql_relay.go`:
```go
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"zerotrust-proxy/internal/models"
)

// pipeClientToBackend: read client packets, sniff SQL, relay byte-exact.
// br must be the same buffered reader used during protocol detection.
func (p *MySQLProxy) pipeClientToBackend(br *bufio.Reader, backend net.Conn, tok *models.TokenPayload, clientAddr string) {
	for {
		seq, payload, err := readMySQLPacket(br)
		if err != nil {
			return
		}
		if len(payload) > 0 {
			p.sniffCommand(payload[0], payload[1:], tok, clientAddr)
		}
		if err := writeMySQLPacket(backend, seq, payload); err != nil {
			return
		}
	}
}

// pipeBackendToClient: relay backend packets byte-exact (original seq preserved).
func (p *MySQLProxy) pipeBackendToClient(backend, client net.Conn) {
	for {
		seq, payload, err := readMySQLPacket(backend)
		if err != nil {
			return
		}
		if err := writeMySQLPacket(client, seq, payload); err != nil {
			return
		}
	}
}

// sniffCommand extracts SQL text from command payloads and publishes a QueryEvent.
func (p *MySQLProxy) sniffCommand(cmd byte, body []byte, tok *models.TokenPayload, clientAddr string) {
	var kind, sql string
	switch cmd {
	case cmdQuery:
		kind, sql = "query", string(body)
	case cmdInitDB:
		kind, sql = "use", "USE "+string(body)
	case cmdPrepare:
		kind, sql = "prepare", string(body)
	case cmdExecute:
		kind = "execute"
		if len(body) >= 4 {
			sql = fmt.Sprintf("EXECUTE stmt_id=%d", binary.LittleEndian.Uint32(body))
		} else {
			sql = "EXECUTE stmt_id=?"
		}
	default:
		return
	}
	ev := models.QueryEvent{
		ID:         newEventID(),
		Ts:         time.Now().UTC(),
		Kind:       kind,
		Username:   tok.Username,
		TicketID:   tok.TicketID,
		DBUser:     tok.DBUser,
		DBIP:       tok.DBIP,
		DBPort:     tok.DBPort,
		DBType:     "mysql",
		SQL:        sql,
		ClientAddr: clientAddr,
	}
	raw, _ := json.Marshal(ev)
	ctx := context.Background()
	_ = p.vs.Publish(ctx, "queries:"+tok.Username, raw)
	if tok.TicketID != "" {
		_ = p.vs.Publish(ctx, "queries:ticket:"+tok.TicketID, raw)
	}
}
```
(`newEventID` — add to `internal/store/id.go` or a small `internal/proxy/id.go`: 8 random bytes hex. Import `encoding/json` in the relay file.)
**Verify:** builds; `go vet ./...`.

### Task 3.5: Protocol dispatcher (shared port)
**Files:** `internal/proxy/dispatcher.go` + `dispatcher_test.go`.
Complete code:
```go
package proxy

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// Dispatcher owns ONE TCP listener and routes each connection to the MySQL or
// PostgreSQL proxy based on which side speaks first:
//   - PostgreSQL is client-first: the client sends StartupMessage/SSLRequest
//     immediately after connect.
//   - MySQL is server-first: the client waits silently for the server handshake.
// So: client bytes within detectDelay → PostgreSQL; silence → MySQL.
type Dispatcher struct {
	log         *slog.Logger
	mysql       *MySQLProxy
	pg          *PGProxy
	detectDelay time.Duration
	conns       atomic.Int64
	maxConns    int64
}

func NewDispatcher(log *slog.Logger, mysql *MySQLProxy, pg *PGProxy, detectDelay time.Duration, maxConns int64) *Dispatcher {
	return &Dispatcher{log: log, mysql: mysql, pg: pg, detectDelay: detectDelay, maxConns: maxConns}
}

func (d *Dispatcher) Serve(l net.Listener, ctx context.Context) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if d.conns.Load() >= d.maxConns {
			d.log.Warn("connection limit reached, rejecting")
			c.Close()
			continue
		}
		d.conns.Add(1)
		go func() {
			defer d.conns.Add(-1)
			d.dispatch(ctx, c)
		}()
	}
}

func (d *Dispatcher) dispatch(ctx context.Context, c net.Conn) {
	br := bufio.NewReader(c)
	proto, err := decide(c, br, d.detectDelay)
	switch {
	case err == nil && proto == "pg":
		d.pg.handleConn(ctx, c, br)
	case err == nil:
		d.mysql.handleConn(ctx, c, br)
	default:
		d.log.Debug("dispatch drop", "err", err)
		c.Close()
	}
}

// decide peeks the first client byte: bytes → "pg" (client-first protocol),
// silence until delay → "mysql" (server-first protocol). Peeked bytes stay in
// br, so nothing is lost when the handler consumes the stream.
func decide(c net.Conn, br *bufio.Reader, delay time.Duration) (string, error) {
	_ = c.SetReadDeadline(time.Now().Add(delay))
	_, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err == nil {
		return "pg", nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "mysql", nil
	}
	return "", err
}
```
**Tests** (real TCP on `127.0.0.1:0`, since net.Pipe has no deadlines):
1. Write one byte from the client → `decide` returns `"pg"` and the byte remains readable through `br`.
2. Silent client → `"mysql"` after the delay (use 100 ms delay in test).
3. Closed connection → error.
**Verify:** `go test ./internal/proxy/ -run Decide -v` → PASS.

### Task 3.6: cmd/data/main.go (single shared listener)
**Files:** create `cmd/data/main.go`.
```go
package main

// loads configs/data.yaml (config.LoadData: listen.addr, detect_delay_ms,
// valkey, credentials), starts ValkeyStore, builds MySQLProxy and PGProxy
// (PG plugged in Task 4.4 — until then pass nil and have Dispatcher skip),
// net.Listen("tcp", cfg.ListenAddr), Dispatcher.Serve in a goroutine,
// graceful shutdown on SIGINT/SIGTERM. Logs JSON via slog.
```
**Verify:** `go run ./cmd/data` logs "dispatcher listening on :3306"; Ctrl-C clean shutdown.

### Task 3.7: MySQL integration gate (CLI through the proxy)
**Steps:**
1. Start control + data planes (background terminals or `pm2 start` — see RUN.md at end).
2. Issue a token (API key or login+session):
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/token -H "X-Api-Key: $ZT_API_KEY" -H 'Content-Type: application/json' \
  -d '{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"TICKET-1"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo $TOKEN
```
3. Connect through the proxy (from inside the mysql container so a mysql client exists):
```bash
docker exec mysql-test mysql -h host.docker.internal -P 3306 -u "$TOKEN" -proot_pw appdb -e "SELECT id,name FROM demo_items;"
```
> `host.docker.internal` reaches the Windows host where the Data Plane listens.
4. Expect: the 3 demo rows (proxied through the Data Plane to the same container's :3307 backend).
5. Check the Checker feed: with a WS listener on `channel=alice` (Task 2.4 node script with session cookie), run the query again → EVENT with kind=query, sql="SELECT id,name FROM demo_items;".
6. **Single-use:** run step 3 a second time with the SAME token → expect `ERROR 1045 (42000): invalid or expired token`.
7. Watch `docker exec valkey valkey-cli keys 'tok:*'` → empty (token consumed).
**Verify:** all of the above with real output; commit `feat(data): mysql proxy with single-use tokens and query sniffing`.

### Task 3.8: MySQL edge cases
- Wrong-protocol token: pg token (db_type=postgres) used with a mysql client on the shared port → 1045 "token not valid for this protocol".
- COM_INIT_DB / COM_STMT_PREPARE publish correct kind tags (test via mysql CLI: `mysql ... -e "PREPARE s FROM 'SELECT 1'; EXECUTE s; DEALLOCATE PREPARE s;"` → events kind=prepare/execute).
- Token expiry: set `api.token_ttl_seconds: 5` in a local override, issue token, wait 6 s, connect → 1045. (Restore TTL after.)
- Connection limit: `data.yaml` `max_conns: 2` (add to config structs) → 3rd concurrent connection rejected.
**Verify:** each case with real output.

---

# Phase 4 — Data Plane: PostgreSQL Proxy

### Task 4.1: PG client-facing session
**Files:** `internal/proxy/pg_proxy.go`.
Complete code:
```go
package proxy

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

type PGProxy struct {
	log   *slog.Logger
	vs    *store.ValkeyStore
	creds map[string]string
}

func NewPGProxy(log *slog.Logger, vs *store.ValkeyStore, creds map[string]string) *PGProxy {
	return &PGProxy{log: log, vs: vs, creds: creds}
}

// handleConn runs one PostgreSQL session. The Dispatcher owns the accept loop;
// br carries any bytes peeked during protocol detection.
func (p *PGProxy) handleConn(ctx context.Context, client net.Conn, br *bufio.Reader) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	// VERIFIED v2.3.3: NewBackend needs BOTH args — (ChunkReader, writer); nil writer panics on Send.
	// br carries the dispatcher's peeked bytes; client is the write side.
	be := pgproto3.NewBackend(pgproto3.NewChunkReader(br), client) // no SSL support
	startupMsg, err := be.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, isSSL := startupMsg.(*pgproto3.SSLRequest); isSSL {
		if _, err := client.Write([]byte{'N'}); err != nil { // refuse SSL
			return
		}
		startupMsg, err = be.ReceiveStartupMessage()
		if err != nil {
			return
		}
	}
	sm, ok := startupMsg.(*pgproto3.StartupMessage)
	if !ok {
		return
	}
	token := sm.Parameters["user"] // token-as-username

	tok, err := p.vs.GetDeleteToken(ctx, token)
	if err != nil || tok == nil {
		p.log.Warn("invalid or expired token", "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "invalid or expired token"})
		return
	}
	if tok.DBType != "postgres" {
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "token not valid for this listener"})
		return
	}

	// real backend session first (pgx handles SCRAM-SHA-256)
	front, err := connectPostgresBackend(ctx, tok, p.creds) // Task 4.2
	if err != nil {
		p.log.Error("backend pg connect failed", "err", err, "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "backend unavailable"})
		return
	}
	defer front.Close()

	// welcome the client
	_ = be.Send(&pgproto3.AuthenticationOk{})
	_ = be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"})
	_ = be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	_ = be.Send(&pgproto3.ParameterStatus{Name: "DateStyle", Value: "ISO, MDY"})
	_ = be.Send(&pgproto3.ParameterStatus{Name: "TimeZone", Value: "UTC"})
	_ = be.Send(&pgproto3.BackendKeyData{PID: 42, SecretKey: 4242})
	_ = be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	_ = client.SetDeadline(time.Time{})
	p.log.Info("pg session established", "username", tok.Username, "db_user", tok.DBUser,
		"client", clientAddr)

	done := make(chan struct{}, 2)
	go func() {
		p.pipePGClientToBackend(be, front, tok, clientAddr)
		done <- struct{}{}
	}()
	go func() {
		p.pipePGBackendToClient(front, be)
		done <- struct{}{}
	}()
	<-done
	client.Close()
	p.log.Info("pg session closed", "username", tok.Username, "client", clientAddr)
}
```
### Task 4.2: PG backend connect (pgx + hijack)
**Files:** `internal/proxy/pg_backend.go`:
```go
package proxy

import (
	"context"
	"fmt"

	"github.com/jackc/pgproto3/v2"
	"github.com/jackc/pgx/v5"
	"zerotrust-proxy/internal/models"
)

// pgFrontend wraps the hijacked backend connection with a pgproto3 Frontend
// (we act as the client toward the real PostgreSQL server).
type pgFrontend struct {
	conn net.Conn
	f    *pgproto3.Frontend
}

func connectPostgresBackend(ctx context.Context, t *models.TokenPayload, creds map[string]string) (*pgFrontend, error) {
	pw, ok := creds[backendKey(t)]
	if !ok {
		return nil, fmt.Errorf("no credentials for %s", backendKey(t))
	}
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=appdb sslmode=disable",
		t.DBIP, t.DBPort, t.DBUser, pw)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pgconn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("backend pg connect: %w", err)
	}
	// VERIFIED v5.10.0: Hijack() returns (*HijackedConn, error) — use hc.Conn as the raw net.Conn.
	// pgx consumes the FULL backend handshake (ReadyForQuery); hijacked stream is byte-clean
	// (bgReader stopped, chunkreader drained — verified against pgx source; proven by live test).
	hc, err := pgconn.PgConn().Hijack()
	if err != nil {
		return nil, fmt.Errorf("pg hijack: %w", err)
	}
	return &pgFrontend{conn: hc.Conn, f: pgproto3.NewFrontend(pgproto3.NewChunkReader(hc.Conn), hc.Conn)}, nil
}

func (f *pgFrontend) Send(msg pgproto3.BackendMessage) error { return f.f.Send(msg) } // see note
func (f *pgFrontend) Receive() (pgproto3.FrontendMessage, error) { return f.f.Receive() }
func (f *pgFrontend) Close() { _ = f.conn.Close() }
```
> Note: `pgproto3.Frontend.Send` accepts `FrontendMessage` (client→server messages) and `Receive` returns `BackendMessage` (server→client). Adjust the wrapper method signatures accordingly — the relay in Task 4.3 sends `pgproto3.FrontendMessage`s to the backend and `pgproto3.BackendMessage`s to the client. VERIFIED v5.10.0: `Hijack()` returns `(*HijackedConn, error)` (use `hc.Conn`); `NewFrontend(cr ChunkReader, w io.Writer)` — nil writer panics on Send, so pass `hc.Conn` as both. Also: set `cfg.Password = pw` AFTER `ParseConfig` (raw interpolation breaks passwords with space/quote/backslash).

### Task 4.3: PG relay + SQL extraction
**Files:** `internal/proxy/pg_relay.go`:
```go
package proxy

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
)

// stmtCache maps prepared-statement names to their SQL (Parse → Execute).
type stmtCache struct{ m map[string]string }

func newStmtCache() *stmtCache { return &stmtCache{m: map[string]string{}} }

func (c *stmtCache) evict(name string) { delete(c.m, name) }

// pipePGClientToBackend relays client messages, extracting SQL from
// SimpleQuery / Parse / Execute, then publishes QueryEvents.
func (p *PGProxy) pipePGClientToBackend(be *pgproto3.Backend, front *pgFrontend,
	tok *models.TokenPayload, clientAddr string) {
	cache := newStmtCache()
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		p.sniffPGMessage(msg, cache, tok, clientAddr)
		if err := front.f.Send(msg); err != nil { // relay unchanged
			return
		}
	}
}

func (p *PGProxy) pipePGBackendToClient(front *pgFrontend, be *pgproto3.Backend) {
	for {
		msg, err := front.f.Receive()
		if err != nil {
			return
		}
		if err := be.Send(msg); err != nil {
			return
		}
	}
}

func (p *PGProxy) sniffPGMessage(msg pgproto3.FrontendMessage, cache *stmtCache,
	tok *models.TokenPayload, clientAddr string) {
	var kind, sql string
	switch m := msg.(type) {
	case *pgproto3.Query:
		kind, sql = "query", m.String
	case *pgproto3.Parse:
		kind, sql = "prepare", m.Query
		cache.m[m.Name] = m.Query
	case *pgproto3.Execute:
		kind = "execute"
		if s, ok := cache.m[m.Portal]; ok {
			sql = "EXECUTE " + s
		} else {
			sql = "EXECUTE portal=" + m.Portal
		}
	case *pgproto3.Close:
		if m.ObjectType == 'S' {
			cache.evict(m.Name)
		}
		return
	default:
		return
	}
	ev := models.QueryEvent{
		ID: newEventID(), Ts: time.Now().UTC(), Kind: kind,
		Username: tok.Username, TicketID: tok.TicketID,
		DBUser: tok.DBUser, DBIP: tok.DBIP, DBPort: tok.DBPort,
		DBType: "postgres", SQL: sql, ClientAddr: clientAddr,
	}
	raw, _ := json.Marshal(ev)
	ctx := context.Background()
	_ = p.vs.Publish(ctx, "queries:"+tok.Username, raw)
	if tok.TicketID != "" {
		_ = p.vs.Publish(ctx, "queries:ticket:"+tok.TicketID, raw)
	}
}
```
> Note: `pgproto3.Backend.Send` takes `BackendMessage`; `Frontend.Send` takes `FrontendMessage`. In `pipePGClientToBackend` the messages from `be.Receive()` are `FrontendMessage`s — relay them with `front.f.Send(msg)` (typed appropriately; pgproto3 v2's `Frontend.Send` signature is `Send(msg FrontendMessage)`). If the v2 API differs (`Send` on interfaces), adapt using `go doc github.com/jackc/pgproto3/v2`.
**Verify:** `go vet ./...` + `go build ./...`.

### Task 4.4: PG integration gate (psql through the proxy)
**Steps:**
1. Plug the PG proxy into `cmd/data/main.go`: construct `NewPGProxy` and hand it to the `NewDispatcher` (it already routes per connection by protocol).
2. Token:
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/token -H "X-Api-Key: $ZT_API_KEY" -H 'Content-Type: application/json' \
  -d '{"username":"bob","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"5433","db_type":"postgres","ticket_id":"TICKET-2"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
```
3. `docker exec pg-test psql -h host.docker.internal -p 5432 -U "$TOKEN" -d appdb -c "SELECT id,name FROM demo_items;"` → 3 rows.
4. Checker feed on `channel=bob` shows kind=query with the SELECT.
5. Single-use: same token again → `FATAL: invalid or expired token`.
6. Prepared statement path: `psql ... -c "PREPARE s AS SELECT 1; EXECUTE s; DEALLOCATE s;"` → feed shows prepare/execute events.
**Verify:** all with real output; commit `feat(data): postgres proxy with sql extraction`.

### Task 4.5: Coexistence + mixed gate
- Both protocols served from the SAME port `:3306`; maker issues mysql token → mysql CLI connects (detected MySQL); pg token → psql connects (detected PG). Interleave connections; detection must be stable per connection.
- Wrong-protocol test: pg token used with a mysql client (silent → MySQL path) → 1045 "token not valid for this protocol"; mysql token used with psql (PG path) → FATAL 28000.
- Detection edge: connect and send nothing → MySQL handshake sent after `detect_delay_ms`; connect via psql → startup forwarded immediately.
- Checker dashboard `channel=*` shows both mysql and postgres events with correct `db_type` tags.
**Verify:** real output; commit.

---

# Phase 5 — Security, E2E, Docs

### Task 5.1: Security test matrix (scripted)
Create `scripts/security_checks.sh` (run from git-bash) covering:
1. `/api/token` no key no session → 401
2. `/api/token` bad key → 401
3. `/api/login` wrong password → 401
4. `/api/db-presets` no session → 401
5. `/ws/checker` no session → 401 (curl -i shows 401 before upgrade)
6. Token reuse → MySQL 1045 / PG FATAL 28000
7. Token TTL expiry (5 s TTL override) → rejected
8. Wrong-protocol token on the shared port: pg token via mysql client → 1045; mysql token via psql → FATAL 28000
9. `valkey keys 'tok:*'` empty after all connections
**Verify:** script exits 0 with each check printed; save output to `docs/security-matrix.txt`.

### Task 5.2: Concurrency + leak sanity
- 10 parallel `mysql` connections with 10 distinct tokens → all succeed.
- 2 parallel connects with the SAME token → exactly 1 succeeds, 1 gets 1045.
- After the test, `docker exec valkey valkey-cli dbsize` back to baseline; Data Plane log shows balanced open/close lines (no goroutine leak: run 5 min with `pprof` optional — skip if time-boxed).
**Verify:** real output.

### Task 5.3: Graceful shutdown + log hygiene
- Ctrl-C on both planes: logs show clean shutdown, listeners closed, no error spam.
- `grep -i "password\|token=" <data-plane-log>` → no secrets in logs (token *values* never logged — only usernames/db_user).
**Verify:** real output.

### Task 5.4: RUN.md + README
**Files:** create `RUN.md` (start order: Docker Desktop → `docker compose up -d`-style commands (or plain docker run lines from Phase 0) → `go run ./cmd/control` → `go run ./cmd/data`; how to issue a token via curl; HeidiSQL connection recipe: host 127.0.0.1, port 3306/5432, username = token, any password; checker URL `http://127.0.0.1:8080/checker`) and `README.md` (project overview, architecture diagram from spec §3, links to spec/rules/PLAN).
Also `ecosystem.config.cjs` (optional PM2) running `bin/control.exe` and `bin/data.exe` with `cwd` set — mirrors B/C ops pattern.
**Verify:** follow RUN.md from scratch on a fresh terminal: full stack up in < 2 min.

### Task 5.5: Two-browser Maker/Checker E2E gate
Recipe (house pattern from B/C — two-browser-hybrid verification):
1. Browser A: login admin → `/maker` → pick "MySQL read-only" preset → generate token → copy.
2. Browser B: login admin → `/checker` → channel `*` → connect (status live).
3. Terminal: mysql CLI through the proxy with the copied token; run SELECT + INSERT-as-ro (expect permission error from backend, still audited as an event).
4. Browser B: both events appear live (kind=query, sql text, ticket, user).
5. Repeat with a PG preset token; verify db_type tag = postgres.
6. Reuse the same token in a second connect → 1045, and Browser B shows nothing new for it (no event on failed auth).
7. Screenshot both browsers; save to `docs/e2e-YYYYMMDD/`.
**Verify:** screenshots + terminal output captured; gate PASSED recorded in the progress ledger.

### Task 5.6: Final review gates
- Spec-compliance review: every R1–R7 requirement mapped to a verified behavior (table in `docs/compliance.md`).
- Code-quality review: `go vet ./...`, `go test ./...`, `ng build`, no FIXME/TODO left, house rules respected.
- `git log --oneline` clean history; final commit `docs: compliance matrix and final review`.

---

## Risks & Mitigations
| Risk | Mitigation |
|---|---|
| HeidiSQL-specific handshake quirks | mysql CLI gate is the primary verification; HeidiSQL manual test documented in RUN.md (user can validate on Windows) |
| valkey-go API drift (v1) | Code pinned with `go doc` checks; Subscribe uses the documented Receive→Channel pattern; fallback: `redis/go-redis/v9` (RESP-compatible with Valkey) |
| go-mysql Connect signature drift | `go doc github.com/go-mysql-org/go-mysql/client Connect` before implementing Task 3.3 |
| pgproto3 v2 Send/Receive typing | Both relay directions typed via `go doc`; wrappers isolate the API surface |
| MySQL 8.4 auth | `--mysql-native-password=ON`; go-mysql also handles caching_sha2 if ever needed |
| PG SCRAM | pgx handles SCRAM-SHA-256 natively; hijack only after auth completes |
| >16 MB packets / multi-fragment | v1 relays raw, sniffs first fragment only; hardening v1.1 |
| Docker Desktop not running | Task 0.1 starts it and waits; RUN.md documents it |
| Protocol detection on the shared port | Deterministic in practice: PG clients send startup bytes immediately, MySQL clients always wait. A pathological slow PG client could be misdetected as MySQL → it fails with a protocol error (benign, retry works). `detect_delay_ms` is configurable; if per-protocol ports or firewalls are ever needed, split listeners again (dispatcher already isolates both paths) |

## Open Questions (defer to v2 unless user says otherwise)
- TLS termination for client TCP (stunnel/HAProxy)
- COM_STMT_EXECUTE → statement-id → SQL mapping (needs backend prepare-response parsing)
- Checker approval/kill-switch (B/C parity)
- RBAC / per-team tokens / quotas

## Definition of Done
- [ ] Phases 0–5 gates all PASSED with real tool output (no fabricated results)
- [ ] `go test ./...` green; `ng build` clean; security matrix script exits 0
- [ ] Two-browser Maker/Checker demo verified and screenshotted
- [ ] RUN.md reproducible from clean state
- [ ] Compliance table R1–R7 filled from verified behavior


# Phase 6: Checker enhancements (user directive 2026-08-11)

Amendment 9 in hermes-agent-spec.md. Supersedes: amendment 4 (kill only — checker stays monitor-only for approvals).
Design notes: capture is PASSIVE (relayed bytes byte-exact); one pending command per session; events publish on response completion (session close flushes pending with status=error); kill via Valkey `ctl:kill` channel — no HTTP between planes.

## Task 6.1: QueryEvent extension (models)
`internal/models/models.go` — ADD fields (all omitempty, backward-compatible; round-trip tests for old + new payloads):
```go
	StmtType  string     `json:"stmt_type,omitempty"`  // select|insert|update|delete|other
	SessionID string     `json:"session_id,omitempty"` // data-plane session id (kill target; NOT the token)
	Status    string     `json:"status,omitempty"`     // ok|error (from DB response)
	Error     string     `json:"error,omitempty"`
	Columns   []string   `json:"columns,omitempty"`
	Rows      [][]string `json:"rows,omitempty"`
	Truncated bool       `json:"truncated,omitempty"`
```
TS side (Task 6.7): same fields optional in `QueryEvent` interface (web/src/app/core/api.service.ts).

## Task 6.2: Statement classification + MySQL response capture
`internal/proxy/mysql_relay.go` — new file `internal/proxy/capture.go` (shared MySQL + classification):

```go
package proxy

import "strings"

// classifyStmt returns select|insert|update|delete|other from the leading keyword.
func classifyStmt(sql string) string {
	s := strings.TrimSpace(sql)
	for strings.HasPrefix(s, "--") || strings.HasPrefix(s, "/*") || strings.HasPrefix(s, "#") {
		if i := strings.IndexByte(s, '\n'); i >= 0 { s = strings.TrimSpace(s[i+1:]) } else { return "other" }
	}
	kw := s
	if i := strings.IndexAny(kw, " \t\r\n("); i >= 0 { kw = kw[:i] }
	switch strings.ToUpper(kw) {
	case "SELECT": return "select"
	case "INSERT": return "insert"
	case "UPDATE": return "update"
	case "DELETE": return "delete"
	default: return "other"
	}
}
```

Capture (complete code — protocol-critical, use verbatim):
```go
const (
	capMaxRows  = 100
	capMaxCell  = 512
	capMaxEvent = 64 << 10
)

// resultCapture is a passive state machine over backend→client packets.
// feed() is called AFTER readMySQLPacket, BEFORE the relay write — bytes are
// only inspected, never modified.
type resultCapture struct {
	status    string // "", "ok", "error"
	errorMsg  string
	columns   []string
	rows      [][]string
	truncated bool
	bytes     int
	colCount  int
	stage     int // 0=column-count, 1=column-defs, 2=rows
	doneFlag  bool
}

func (c *resultCapture) done() bool  { return c == nil || c.doneFlag }
func (c *resultCapture) ok() bool    { return c != nil && c.status == "ok" }

func (c *resultCapture) feed(payload []byte) {
	if c.done() || len(payload) == 0 { return }
	b := payload[0]
	switch {
	case b == 0xff: // ERR packet
		c.status, c.errorMsg = "error", mysqlErrMessage(payload)
		c.doneFlag = true
		return
	case b == 0x00 && len(payload) >= 7: // OK packet
		c.finish()
		return
	case b == 0xfb: // LOCAL INFILE — not captured
		return
	case b == 0xfe && len(payload) < 9: // EOF: ends col defs (stage1) or rows (stage2)
		if c.stage == 1 { c.stage = 2; return }
		if c.stage == 2 { c.finish(); return }
		return
	}
	switch c.stage {
	case 0: // column-count packet (lenenc int)
		n, _, ok := readLenencInt(payload, 0)
		if !ok || n == 0 { c.finish(); return }
		c.colCount = int(n)
		c.stage = 1
	case 1: // column definition
		if name, ok := mysqlColumnName(payload); ok {
			c.columns = append(c.columns, name)
		}
		if len(c.columns) >= c.colCount { c.stage = 2 }
	case 2: // data row (TEXT protocol: lenenc cells, no leading count)
		row, consumed := parseMySQLRow(payload, c.colCount)
		if consumed > 0 {
			if len(c.rows) < capMaxRows && c.bytes+len(payload) <= capMaxEvent {
				c.rows = append(c.rows, row)
				c.bytes += len(payload)
			} else {
				c.truncated = true
			}
		}
	}
}

func (c *resultCapture) finish() { if c.status == "" { c.status = "ok" }; c.doneFlag = true }

func mysqlErrMessage(p []byte) string {
	if len(p) < 9 { return "" }
	m := string(p[9:])
	if len(m) > 300 { m = m[:300] }
	return m
}

// mysqlColumnName extracts the column NAME from a COLUMN_DEFINITION packet
// (lenenc walk: catalog schema table org_table NAME org_name + fixed 0x0c header).
func mysqlColumnName(p []byte) (string, bool) {
	off := 0
	for i := 0; i < 4; i++ { // catalog, schema, table, org_table
		start, n, ok := readLenencString(p, off)
		if !ok { return "", false }
		off = start + n
	}
	start, n, ok := readLenencString(p, off) // NAME
	if !ok { return "", false }
	return string(p[start : start+n]), true
}

func readLenencInt(p []byte, off int) (uint64, int, bool) {
	if off >= len(p) { return 0, 0, false }
	switch b := p[off]; {
	case b < 0xfb:
		return uint64(b), 1, true
	case b == 0xfb: // NULL
		return 0, 1, false
	case b == 0xfc:
		if off+3 > len(p) { return 0, 0, false }
		return uint64(p[off+1]) | uint64(p[off+2])<<8, 3, true
	case b == 0xfd:
		if off+4 > len(p) { return 0, 0, false }
		return uint64(p[off+1]) | uint64(p[off+2])<<8 | uint64(p[off+3])<<16, 4, true
	default: // 0xfe — 8-byte
		if off+9 > len(p) { return 0, 0, false }
		var v uint64
		for i := 1; i <= 8; i++ { v |= uint64(p[off+i]) << (8 * (i - 1)) }
		return v, 9, true
	}
}

func readLenencString(p []byte, off int) (int, int, bool) {
	n, sz, ok := readLenencInt(p, off)
	if !ok || n > 1<<20 { return 0, 0, false }
	start := off + sz
	if start+int(n) > len(p) { return 0, 0, false }
	return start, int(n), true
}

// parseMySQLRow decodes a TEXT-protocol DataRow into cells. VERIFIED LIVE
// (2026-08-12, packet dump through the relay): text rows carry NO leading
// field-count byte — they are a plain sequence of lenenc strings (first byte
// is the first cell's length). Cells parse until the payload is exhausted;
// the count is validated against the captured column count when known.
// (A leading-count format is the BINARY protocol — not used here.)
func parseMySQLRow(p []byte, want int) ([]string, int) {
	if len(p) == 0 {
		return nil, 0
	}
	off := 0
	row := make([]string, 0, 8)
	for off < len(p) {
		if p[off] == 0xfb { // NULL cell
			row = append(row, "")
			off++
			continue
		}
		start, ln, ok := readLenencString(p, off)
		if !ok {
			return nil, 0
		}
		cell := string(p[start : start+ln])
		if len(cell) > capMaxCell {
			cell = cell[:capMaxCell] + "…"
		}
		row = append(row, cell)
		off = start + ln
	}
	if want > 0 && len(row) != want {
		return nil, 0
	}
	return row, off
}
```

Wiring (mysql_relay.go + mysql_proxy.go):
1. `mysqlSession` struct (mysql_proxy.go): `{ id string; mu sync.Mutex; pending *models.QueryEvent; capture *resultCapture }` — created at handshake OK (`id = "sid-" + newEventID()`), stored in a `map[string]*mysqlSession` on MySQLProxy (with mutex; also serves the kill registry — see 6.4).
2. `sniffCommand` (client→backend): set `ev.StmtType = classifyStmt(sql)`; do NOT publish yet — stash `s.pending = ev; s.capture = &resultCapture{}`.
3. `pipeBackendToClient`: after `readMySQLPacket`, `s.mu.Lock(); s.capture.feed(payload); done := s.capture.done(); s.mu.Unlock()`; after the relay write, if `done && s.pending != nil` → attach columns/rows/status/error/truncated → publish to `queries:<user>` + `queries:ticket:<t>` → clear pending. If `pending != nil && capture == nil` (non-query commands like PING): publish immediately after OK/ERR seen — i.e. a capture with no result-set still ends via OK/ERR feed.
4. On session close (both exits): if `s.pending != nil` → set `status="error", error="connection closed before response"` → publish → clear. Unregister session.
5. Session close also flushes — so `defer` in handleConn calls `s.flushPendingOnClose()`.

## Task 6.3 (folded into Task 4.3): PG relay + capture
PG relay uses RAW message framing (type byte + int32 length) — pgproto3 is used for the auth phase only (already committed). Capture by type byte on backend→client:
- 'T' RowDescription → column names (int16 count; per field: cstring name, then skip int32+int16+int32+int16+int32+int16)
- 'D' DataRow → cells (int16 count; per cell int32 len + bytes; NULL = len -1; caps as MySQL)
- 'C' CommandComplete → status ok (publish point when a query is pending)
- 'E' ErrorResponse → status error + message (walk fields: byte tag + cstring; take 'M')
- 'I' EmptyQueryResponse → ok
- 'Z' ReadyForQuery → also a publish point if pending (safety)
Client→backend: 'Q' SimpleQuery (sql), 'P' Parse (stmt name + sql — maintain per-session map stmtName→sql), 'E' Execute (kind execute; look up sql by portal/stmt name when possible), 'X' Terminate (session close). Same pending/flush semantics as MySQL.

## Task 6.4: Kill-switch (data plane)
1. `sessionRegistry` in proxy package: `register(id, closer func()) / unregister(id) / KillSession(id string) bool` (mutex + map). MySQLProxy + PGProxy each embed one; handleConn registers after auth OK (closer = close client + backend conns), defers unregister + flush.
2. cmd/data/main.go: after dispatcher start, subscribe `ctl:kill` (exact channel):
```go
killCh := make(chan []byte, 16)
go func() {
	if err := vs.Subscribe(ctx, "ctl:kill", false, killCh); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("kill subscriber", "err", err)
	}
}()
go func() {
	for msg := range killCh {
		var k struct{ SessionID string `json:"session_id"` }
		if json.Unmarshal(msg, &k) != nil || k.SessionID == "" { continue }
		if d.KillSession(k.SessionID) { log.Info("session killed", "session_id", k.SessionID) } else { log.Warn("kill: unknown session", "session_id", k.SessionID) }
	}
}()
```
(d = Dispatcher or a combined killer passed in — implement `KillSession` on a small struct holding both proxies' registries, or expose registry on each proxy and call both.)

## Task 6.5: Control plane — ticket required + POST /api/kill
1. `handlers.go handleToken`: after required-field checks, `if req.TicketID == "" { writeJSON(w, 400, map[string]string{"error": "ticket_id required"}); return }` (spec amendment 9b). Update curl tests (old 200-without-ticket → 400).
2. `handlers.go handleKill`:
```go
func (a *api) handleKill(w http.ResponseWriter, r *http.Request) {
	var req struct{ SessionID string `json:"session_id"` }
	if err := decodeJSON(w, r, &req); err != nil || req.SessionID == "" {
		writeJSON(w, 400, map[string]string{"error": "session_id required"}); return
	}
	b, err := json.Marshal(map[string]string{"session_id": req.SessionID})
	if err != nil { writeJSON(w, 500, map[string]string{"error": "internal"}); return }
	if err := a.vs.Publish(r.Context(), "ctl:kill", b); err != nil {
		writeJSON(w, 502, map[string]string{"error": "kill dispatch failed"}); return
	}
	writeJSON(w, 202, map[string]string{"killed": "queued"})
}
```
3. api.go: `mux.HandleFunc("POST /api/kill", a.auth.requireSession(a.handleKill))`.
4. Verify: curl with cookie + `{"session_id":"sid-x"}` → 202; no cookie → 401; bad body → 400. And a live kill E2E is Task 6.8.

## Task 6.6: Maker portal — ticket required
`web/src/app/features/maker-portal/`: ticket input gets `nzRequired` (label asterisk), submit button `[disabled]="!selectedPreset() || !ticketId()?.trim() || submitting()"`, and the submit() guard returns early with an error if ticket empty. Spec text "Ticket id (optional)" → "Ticket id".

## Task 6.7: Checker dashboard — stmt tags, status, output table, kill button
`web/src/app/features/checker-dashboard/`:
1. Kind column: render wire kind tag + stmt_type tag when present (SELECT=blue, INSERT=green, UPDATE=orange, DELETE=red, other=default; wire kinds keep existing colors).
2. New "Status" column: nz-tag ok=green/success, error=red (title = error message; tooltip nzTooltipTitle).
3. New "Output" column: nz-button "view" (disabled when no rows/columns) → expandable row (nzExpand) rendering a READ-ONLY nested nz-table: `[nzData]="row.cells"` with dynamic `[nzColumns]` from event.columns, cells as plain text (no inputs — read-only by construction). Truncated flag → nz-alert "results truncated".
4. New "Kill" column: nz-button danger "kill" (nz-popconfirm) → `ApiService.killSession(sessionId)` → POST /api/kill; on 202 → mark row killed (tag "killed"), disable button; on error → nz-message error. sessionId from `event.session_id` (button hidden when absent).
5. `ApiService.killSession(sessionId: string): Observable<{killed: string}>` → POST /api/kill.
6. Tests: update/extend checker-dashboard spec — stmt tag mapping, status tag, kill button calls service with session_id, output table renders columns/cells read-only (no input elements), truncated alert.

## Task 6.8: Enhancement integration gate
Full matrix (both planes up, containers up):
1. Ticket required: POST /api/token without ticket_id → 400; with → 200.
2. SELECT through proxy (mysql client): event arrives with stmt_type=select, status=ok, columns=[id,name], rows=[[1,test],[2,bravo],[3,charlie]], truncated=false; checker WS receives it.
3. INSERT through proxy (rw_user token): event status=ok, stmt_type=insert, no rows; row actually inserted (verify via direct container query).
4. Deliberate error (e.g. SELECT * FROM nonexistent): event status=error with message containing "doesn't exist"; query still relayed byte-exact.
5. UPDATE: stmt_type=update, status=ok.
6. PG side: psql SELECT through :3306 → event stmt_type=select, status=ok, columns/rows captured.
7. KILL E2E (the money shot): maker connects (mysql client, long sleep query or just open session) → checker clicks kill (API call with event's session_id) → maker's client sees connection closed/ERROR 2013; data plane logs "session killed"; backend conn verified closed (no orphaned process in container: `docker exec mysql-test mysqladmin -uroot -proot_pw processlist` shows no ro_user conn).
8. Teardown: both planes down, ports free; full Go suite + ng test + build green; commit.

## Phase 6 gate
Full suite (Go + Angular) green; ledger updated; amendment 9 verified end-to-end; security matrix gains kill-switch row.

# Phase 7: TLS everywhere + Valkey/Sentinel with SSL (user directive 2026-08-12)

Amendment 10 in hermes-agent-spec.md. Scope: (a) Control Plane HTTPS (HTTP+WS+SPA on :8080 via ListenAndServeTLS); (b) Data Plane TLS on the DB wire (MySQL: advertise CLIENT_SSL + SSLRequest→TLS handshake; PG: SSLRequest→'S' + TLS handshake); (c) Valkey direct AND Sentinel modes, both with optional SSL (TLS to data + sentinel conns). All TLS OPT-IN via config; plaintext remains the default (dev flows unchanged). Certificates from files; self-signed dev certs via scripts/gen-certs.sh (certs/ gitignored).

## Task 7.1: Config shapes (control.yaml + data.yaml + loaders)

```yaml
# control.yaml additions — EXPLICIT ENABLE SWITCH (user directive 2026-08-12):
# every TLS surface is on/off via config. enabled: true REQUIRES cert_file+key_file (fail fast); absent/false = plaintext.
tls:
  enabled: false          # ← explicit on/off; no implicit file-based toggles
  cert_file: "certs/control.crt"
  key_file:  "certs/control.key"

# data.yaml additions
tls:
  enabled: false
  cert_file: "certs/data.crt"
  key_file:  "certs/data.key"

# valkey block (BOTH configs) — backward compatible; ssl.enabled is the explicit switch:
valkey:
  mode: direct          # direct | sentinel
  addr: "127.0.0.1:6379"      # direct mode
  master_name: "mymaster"     # sentinel mode
  sentinel_addrs: ["127.0.0.1:26379"]
  password: ""
  db: 0
  ssl:
    enabled: false
    ca_file: ""
    cert_file: ""
    key_file: ""
    skip_verify: false
```
Go (internal/config/config.go): `CertConfig{Enabled bool, CertFile, KeyFile string}` (plane TLS — Enabled true + missing files → Load error), `ValkeySSL{Enabled, CAFile, CertFile, KeyFile, SkipVerify}`, `ValkeyConfig{Mode, Addr, MasterName, SentinelAddrs, Password, DB, SSL}` — LoadControl/LoadData gain `TLS *CertConfig` and `Valkey ValkeyConfig` (replacing the flat fields); mode=direct default; ssl.enabled default false.

## Task 7.2: Store — TLS + sentinel via valkey-go (verified v1.0.76 API)

```go
// internal/store/valkey_store.go
type StoreOptions struct {
    Addrs      []string     // direct: [addr]; sentinel: sentinel addrs
    MasterName string       // sentinel mode when non-empty
    Password   string
    DB         int
    TLS        *tls.Config  // nil = plaintext
}

// TLSFromFiles builds a *tls.Config (ca_file → RootCAs pool; cert/key → cert; skip_verify → InsecureSkipVerify).
// serverName: when non-empty and skip_verify false, set as ServerName (caller passes the addr host).
func TLSFromFiles(caFile, certFile, keyFile string, skipVerify bool, serverName string) (*tls.Config, error)

func NewValkeyStore(ctx context.Context, opts StoreOptions) (*ValkeyStore, error)
// builds ClientOption{InitAddress: opts.Addrs, Password, SelectDB, TLSConfig: opts.TLS}
// + when opts.MasterName != "": opt.Sentinel = valkey.SentinelOption{MasterSet: opts.MasterName, TLSConfig: opts.TLS}
// (VERIFIED: SentinelOption{TLSConfig, MasterSet, ...}; InitAddress carries the sentinel addrs; the SAME
// ClientOption.TLSConfig also covers data-plane conns to the master.)
```
Update ALL call sites (cmd/control/main.go, cmd/data/main.go, proxy tests' proxyTestStore helper, api tests) to the new constructor. Keep a tiny convenience `NewValkeyStoreDirect(ctx, addr, password, db)` for tests that want plaintext direct. Tests: TLSFromFiles cases (bad paths → error; ca only; skip_verify); option-building unit test (direct vs sentinel: assert InitAddress/MasterSet/TLSConfig wiring via a fake? — build options via an exported-for-test helper `buildClientOption(opts StoreOptions) valkey.ClientOption` and assert fields). LIVE TLS test: second valkey instance with TLS (see gate task; if not up yet, test skips with a clear message — gate 7.6 brings it up).

## Task 7.3: Control Plane HTTPS

1. cmd/control/main.go: when cfg.TLS has cert+key → `srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)` (log "control plane listening (https)"); else ListenAndServe as today.
2. Angular: verify LiveQueryService builds the WS URL from location (wss when https) — if it hardcodes ws://, fix to `(location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host`. All API calls are relative (already fine over https).
3. scripts/gen-certs.sh: openssl self-signed (SAN IP:127.0.0.1,DNS:localhost) → certs/control.{crt,key}, certs/data.{crt,key}. .gitignore += certs/.
4. Verify: start control with TLS config → curl -sk https://127.0.0.1:8080/api/health → 200; curl -sk https://127.0.0.1:8080/login → SPA html; WS handshake over wss via node (wss:// with rejectUnauthorized false) gets events; plaintext path still works when TLS config absent.

## Task 7.4: Data Plane MySQL TLS (wire-critical)

1. mysql_handshake.go: when TLS enabled, `advertisedCaps |= capSSL` (0x0800).
2. mysql_proxy.go handleConn: after writeHandshake, read the next packet via br:
   - if TLS enabled AND it's an SSLRequest (len(payload) >= 32 && LE32(payload[0:4])&capSSL != 0): tls.Server(client, tlsCfg).HandshakeContext(ctx) (handshake deadline already set); then `client = tlsConn; br = bufio.NewReader(tlsConn)` and read the REAL handshake response; continue auth flow unchanged (relay operates over tlsConn via client+br — the existing readMySQLPacket/writeMySQLPacket calls just work).
   - else: treat as the handshake response (today's path).
3. Load tls.Config in cmd/data/main.go from cfg.TLS; pass into NewMySQLProxy (new field or param — keep NewMySQLProxy(log, vs, creds) and add `SetTLS(*tls.Config)` or extend NewMySQLProxy(log, vs, creds, tlsCfg) — prefer extending the constructor; update call sites).
4. Tests: unit — SSLRequest detection (payload with/without SSL bit); LIVE — TLS-enabled data plane (or proxy in-process with tlsCfg), mysql client `--ssl-mode=REQUIRED` full session (SELECT returns rows, capture event flows, single-use works); `--ssl-mode=DISABLED` client against TLS-enabled listener still works (plaintext path preserved); TLS-disabled listener + REQUIRED client → fails cleanly (no SSL advertised → client errors).
5. Verify TLS certs for the live test: gen-certs.sh first; mysql client needs --ssl-mode=REQUIRED (skips verify? mysql client verifies CA by default in REQUIRED? REQUIRED = encryption without verification — perfect for self-signed).

## Task 7.5: Data Plane PG TLS (wire-critical)

pg_proxy.go: after ReceiveStartupMessage:
- if startup is *pgproto3.SSLRequest: TLS enabled → write 'S' (0x53), tls.Server(client, tlsCfg).HandshakeContext(ctx), rebuild `be = pgproto3.NewBackend(pgproto3.NewChunkReader(bufio.NewReader(tlsConn)), tlsConn)`, then ReceiveStartupMessage again (real startup over TLS); TLS disabled → write 'N' (existing path).
- else: normal path.
Tests: unit — SSLRequest → 'S' when enabled / 'N' when disabled (exact bytes); LIVE — psql `sslmode=require` through the TLS-enabled proxy full session (SELECT returns rows, event captured); sslmode=require against plaintext listener → client fails (server replied 'N').

## Task 7.6: TLS + Sentinel integration gate

1. scripts/gen-certs.sh run; certs in place.
2. TLS valkey: `docker run -d --name valkey-tls -p 6380:6380 -v <repo>/certs:/certs:ro valkey/valkey:8-alpine valkey-server --port 0 --tls-port 6380 --tls-cert-file /certs/data.crt --tls-key-file /certs/data.key --tls-ca-cert-file /certs/data.crt --tls-auth-clients no` (self-signed CA = the cert itself). Wait for readiness (valkey-cli -p 6380 --tls --cacert certs/data.crt ping — host has no valkey-cli; use `docker exec valkey-tls valkey-cli --tls --cacert /certs/data.crt -p 6380 ping`).
3. Sentinel: `docker run -d --name valkey-sentinel -p 26379:26379 -v <repo>/scripts/sentinel.conf:/etc/sentinel.conf:ro valkey/valkey:8-alpine valkey-sentinel /etc/sentinel.conf` — sentinel.conf: sentinel monitor mymaster 127.0.0.1 6379 1; sentinel down-after-milliseconds mymaster 5000. (Sentinel connects to the PLAINTEXT 6379 master — sentinel TLS is optional; the CLIENT→sentinel and client→master paths carry TLS.) scripts/sentinel.conf committed.
4. Store tests vs BOTH: direct TLS (port 6380, ssl enabled, skip_verify true for the self-signed cert OR ca_file=certs/data.crt — prefer ca_file so verification is real) — SetToken/GetDeleteToken round trip; sentinel mode (master_name mymaster, addrs [127.0.0.1:26379], ssl.enabled FALSE for the sentinel conn in this test, since the container's sentinel is plaintext; TLS-to-sentinel covered by config/unit test) — round trip + a PubSub subscribe/publish.
5. FULL STACK TLS matrix (both planes with TLS + valkey direct TLS): token via `curl -sk https://127.0.0.1:8080/api/token` (API key), mysql client `--ssl-mode=REQUIRED` through :3306 → SELECT + captured event; psql `sslmode=require` → SELECT + event; kill E2E over HTTPS; checker WS over wss receives events; log hygiene; teardown + ports free.
6. RUN.md: TLS + sentinel sections (config snippets, cert gen, client commands with ssl flags, docker run lines). Full suites: go test ./... + ng test + build.
7. Commit.

## Phase 7 gate
Both modes (plaintext default + TLS) verified; valkey direct + sentinel + SSL verified live; full suites green; RUN.md updated; amendment 10 compliance noted in ledger.

## Task 7.7: Sentinel authentication (user directive 2026-08-12)

Sentinel itself requires auth (sentinel.conf `requirepass`) — separate from the master's password. valkey-go v1.0.76 `SentinelOption{Username, Password, ClientName, ...}` carries sentinel-specific credentials; our current wiring sets only MasterSet + TLSConfig, and the single `opts.Password` goes to ClientOption.Password (data conns to the master). Add sentinel auth:

1. internal/config: ValkeyConfig gains `SentinelUsername string` (default "") + `SentinelPassword string` (default ""), yaml `valkey.sentinel_username` / `valkey.sentinel_password`, env `ZT_VALKEY_SENTINEL_USERNAME` / `ZT_VALKEY_SENTINEL_PASSWORD` (viper convention — verify names with the loader probe pattern).
2. internal/store: StoreOptions gains `SentinelUsername`, `SentinelPassword`; BuildClientOption wires them into `Sentinel: SentinelOption{MasterSet, TLSConfig, Username, Password}` (verify against v1.0.76 source that sentinel conns AUTH with these — sentinel.go). ClientOption.Password keeps serving the master/data conns.
3. Tests: BuildClientOption wiring assertion (sentinel username/password land in SentinelOption; data password stays in ClientOption); LIVE: scripts/sentinel.conf gains `requirepass sentinelpw`; TestLiveSentinelRoundTrip updated to pass SentinelPassword: "sentinelpw" (round trip + pub/sub still pass); NEW negative assertion: connecting WITHOUT the sentinel password → error (AUTH failed) — proves the password is actually required.
4. RUN.md §6: sentinel run line + config snippet show requirepass + sentinel_password; note master password stays under `password`.
5. Full suite + ng test + build; commit; report.
