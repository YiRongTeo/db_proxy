package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// load binds defaults, config file, and ZT_-prefixed env overrides (dots -> underscores)
// onto the given viper instance. All keys are read back from the SAME instance so that
// env overrides and file values resolve consistently (see LoadControl's UnmarshalKey).
func load(v *viper.Viper, path string, defaults map[string]any) error {
	for k, val := range defaults {
		v.SetDefault(k, val)
	}
	v.SetConfigFile(path)
	v.SetEnvPrefix("ZT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	// AllowEmptyEnv: an env var that is SET but empty (e.g. ZT_AUTH_PASSWORD="")
	// is a real override, not an absence — viper otherwise ignores empty env
	// vars and the guard below could never see the empty value. This is what
	// makes the auth fail-fast (review round 3) fire on empty env overrides.
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()
	// Explicit aliases (Task 9.12): the convention-derived name for
	// api.token_max_uses is ZT_API_TOKEN_MAX_USES; the short form
	// ZT_TOKEN_MAX_USES is accepted too (first set wins, both fall back to
	// the config file). Without BindEnv, ZT_TOKEN_MAX_USES would silently
	// not map and the budget would silently stay 1.
	v.BindEnv("api.token_max_uses", "ZT_API_TOKEN_MAX_USES", "ZT_TOKEN_MAX_USES")
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	return nil
}

// CertConfig carries the optional plane TLS certificate/key pair.
// TLS is EXPLICITLY opt-in via Enabled (binding user directive 2026-08-12):
// there is NO implicit file-based toggle. Enabled=false (or absent) keeps
// plaintext and the cert/key files are never touched; Enabled=true REQUIRES
// readable cert_file+key_file — load fails fast otherwise.
type CertConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// ValkeySSL is the optional TLS block for Valkey connections
// (data conns in direct mode; data + sentinel conns in sentinel mode).
type ValkeySSL struct {
	Enabled    bool   `mapstructure:"enabled"`
	CAFile     string `mapstructure:"ca_file"`
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	SkipVerify bool   `mapstructure:"skip_verify"`
}

// ValkeyConfig is the shared store block for both planes (control.yaml and
// data.yaml). Mode "direct" connects to Addr; mode "sentinel" discovers the
// master via SentinelAddrs/MasterName. The old flat shape
// (valkey: {addr, password, db}) still parses: mode defaults to "direct".
type ValkeyConfig struct {
	Mode          string   `mapstructure:"mode"`
	Addr          string   `mapstructure:"addr"`
	MasterName    string   `mapstructure:"master_name"`
	SentinelAddrs []string `mapstructure:"sentinel_addrs"`
	Password      string   `mapstructure:"password"`
	// SentinelPassword is the sentinel's OWN requirepass (AUTH <password>).
	// Sentinels have no ACL users — a username must never be sent (valkey-go
	// would emit AUTH <user> <pass>, which a requirepass-only sentinel
	// rejects). Distinct from valkey.password (the master/data password).
	SentinelPassword string    `mapstructure:"sentinel_password"`
	DB               int       `mapstructure:"db"`
	SSL              ValkeySSL `mapstructure:"ssl"`
}

// ControlConfig mirrors configs/control.yaml.
type ControlConfig struct {
	HTTPAddr  string
	StaticDir string
	TokenTTL  int
	// TokenMaxUses (Task 9.12): connection budget per issued token — 1 =
	// single-use (default); >1 lets GUI clients (SSMS/DBeaver) open their
	// several automatic connections. Env: ZT_TOKEN_MAX_USES.
	TokenMaxUses int
	// TokenMode (Task 9.13, option-A session tokens; yaml api.token_mode,
	// env ZT_API_TOKEN_MODE) is the DEFAULT issue mode when a mint request
	// carries no mode and the target preset declares none: "single-use"
	// (default — every token dies after its connection budget) or
	// "session" (IP-locked, non-consuming tokens with live revocation;
	// TTL from SessionTokenTTL — 0 = infinite).
	TokenMode string
	// SessionTokenTTL (yaml api.session_token_ttl_seconds, env
	// ZT_API_SESSION_TOKEN_TTL_SECONDS) is the lifetime of session-mode
	// tokens. 0 = infinite (default): the token lives until revoked
	// (key deleted) or the data plane's idle/max-lifetime enforcement.
	// Single-use tokens keep api.token_ttl_seconds.
	SessionTokenTTL int
	DataPlaneHost   string
	DataPlanePort   string
	AuthUser        string
	AuthPassword    string
	// AuthRole (yaml auth.role, env ZT_AUTH_ROLE; JWT conversion Task 2) is
	// the PRIMARY account's role: "maker" or "checker". REQUIRED whenever
	// auth.jwt.login_enabled is true — explicit over default, no silent
	// default (an un-role'd account would be an accidental superuser).
	AuthRole string
	// AllowMakerWatch (yaml auth.allow_maker_watch, env
	// ZT_AUTH_ALLOW_MAKER_WATCH; JWT conversion Task 2) gates the
	// checker-only endpoints (watch / kill / sessions): false (default)
	// keeps SoD — only checker-role principals may watch/kill; true lets
	// maker-role principals watch and kill too.
	AllowMakerWatch bool
	// AuthUsers (Task 9.13, SoD testing) are OPTIONAL additional UI
	// users beyond the primary auth.username/password pair — e.g. a
	// dedicated checker account so maker and checker roles use different
	// identities (the SoD watch rejects checker == maker). Passwords are
	// ${VAR} placeholders resolved from the environment (same fail-fast
	// rule as the primary pair: an empty password refuses to start).
	// Each entry carries its own role: "maker"|"checker" (Task 2).
	AuthUsers []AuthUserConfig
	// JWT (yaml auth.jwt.*, env ZT_AUTH_JWT_*; JWT conversion Task 2) is
	// the bearer-JWT auth block. jwt.ttl_seconds supersedes SessionTTL as
	// the auth expiry (default 28800 = 8h, mirroring the old session TTL).
	JWT JWTConfig
	// SessionTTL is INERT LEGACY RESIDUE of the cookie-session era: parsed
	// from auth.session_ttl_hours (default 8) for backward compatibility but
	// consumed by NOTHING — the live auth expiry is JWT.TTLSeconds (28800).
	// Safe to drop the yaml key; the parse goes away with this field.
	SessionTTL int
	DBPresets  []DBPreset
	TLS        *CertConfig
	Valkey     ValkeyConfig
	Audit      AuditConfig
}

// AuthUserConfig is one entry of the optional auth.users list.
type AuthUserConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	// Role (JWT conversion Task 2): this user's role — "maker" or
	// "checker". REQUIRED per entry when auth.jwt.login_enabled is true
	// (explicit over default: an un-role'd entry would silently become a
	// maker superuser). Declared role values are validated whenever JWT
	// mode is on, regardless of the login flag.
	Role string `mapstructure:"role"`
}

// JWTConfig is the bearer-JWT auth block (yaml auth.jwt.*, env
// ZT_AUTH_JWT_*; JWT conversion Task 2). Enabled is the master switch:
// ABSENT defaults to TRUE — JWT is the mode going forward, so an
// unmigrated config fails fast demanding roles + secret instead of
// booting with the old semantics. An EXPLICIT auth.jwt.enabled: false
// DISABLES JWT verification — every guarded route answers 401 (parseJWT
// fails closed); there is NO legacy cookie-session fallback (that
// machinery was removed in the conversion), so the only validations that
// still apply are the classic auth.username/auth.password requirement and
// the auth.users shape. Keep the default true.
// LoginEnabled registers /api/login + /api/logout and self-issues HS256
// JWTs; when false the plane may run external-JWT-only: auth.username /
// auth.password and the secret are then NOT required.
type JWTConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	LoginEnabled bool   `mapstructure:"login_enabled"`
	Issuer       string `mapstructure:"issuer"`
	Audience     string `mapstructure:"audience"`
	TTLSeconds   int    `mapstructure:"ttl_seconds"`
	// Secret is the HS256 signing secret — REQUIRED when login_enabled is
	// true. ${VAR}-expandable from the environment (same fail-fast rule as
	// the auth.users passwords: unset/empty = the plane refuses to start;
	// never a silent empty key).
	Secret string `mapstructure:"secret"`
	// AllowedOrigins (Task 9; yaml auth.jwt.allowed_origins) is the
	// cross-origin host allowlist for the CHECKER WebSocket upgrade ONLY
	// (/ws/checker websocket.Accept OriginPatterns). Browsers cannot set
	// headers on a WebSocket upgrade, so a checker SPA served from another
	// origin must be allow-listed here. EMPTY (default) = same-origin only
	// — an upgrade whose Origin host differs from the control-plane host is
	// rejected (the pre-Task-9 behavior). Patterns are lowercase host globs
	// ("checker.example.com", "*.example.com"); prefix the scheme
	// ("https://checker.example.com") to pin it. REST routes never read
	// this list — their JWTs ride the Authorization header only. No
	// dedicated env binding — AutomaticEnv still maps
	// ZT_AUTH_JWT_ALLOWED_ORIGINS (comma-separated) if set; set the list
	// in control.yaml for clarity.
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

// MySQLAuditConfig is the optional session-audit MySQL block (Task 9.7,
// user directive 2026-08-15): when audit.mysql.enabled is true the Control
// Plane — the writer that sees lifecycle events via the hub and knows the
// checker identity on watch attach/detach — persists every session (maker
// username, ticket, db target, checker username when present, status
// pending|active|ended, timestamps) to zt_audit.sessions. Disabled by
// default: NO database dependency unless enabled. Enabled REQUIRES
// host+port+user+password+database (fail-fast at load, naming the field).
type MySQLAuditConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Host     string `mapstructure:"host"`
	Port     string `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"`
}

// AuditConfig groups the Control Plane audit sinks (currently only MySQL).
type AuditConfig struct {
	MySQL MySQLAuditConfig `mapstructure:"mysql"`
}

// DBPreset is one selectable database target in the Maker portal.
// json tags keep the /api/db-presets wire contract snake_case (spec §5);
// mapstructure tags are used by viper when reading configs/control.yaml.
// Access (Task 8.6) is the maker write-gate level: "read" presets never
// gate, "write" presets require a checker watching the session.
type DBPreset struct {
	Name   string `mapstructure:"name" json:"name"`
	DBType string `mapstructure:"db_type" json:"db_type"`
	DBUser string `mapstructure:"db_user" json:"db_user"`
	DBIP   string `mapstructure:"db_ip" json:"db_ip"`
	DBPort string `mapstructure:"db_port" json:"db_port"`
	Access string `mapstructure:"access" json:"access"` // read | write (Task 8.6)
	// TokenMode (Task 9.13; optional): "session" marks a GUI-friendly
	// preset whose minted tokens are IP-locked, non-consuming session
	// tokens (live revocation). Absent = the api.token_mode default.
	TokenMode string `mapstructure:"token_mode,omitempty" json:"token_mode,omitempty"`
}

// readValkey reads the valkey block through the SAME viper instance that read
// the file (env overrides + defaults resolve consistently). Individual Get*
// calls (rather than UnmarshalKey) so nested defaults (mode=direct, ssl
// disabled) apply even when the file omits keys — the old flat shape
// valkey: {addr, password, db} therefore still parses unchanged.
// Review round 3: sentinel mode without master_name is a load error (fail
// fast naming the field) — a sentinel-mode plane that cannot discover its
// master must never start silently.
func readValkey(v *viper.Viper) (ValkeyConfig, error) {
	vc := ValkeyConfig{
		Mode:             v.GetString("valkey.mode"),
		Addr:             v.GetString("valkey.addr"),
		MasterName:       v.GetString("valkey.master_name"),
		SentinelAddrs:    v.GetStringSlice("valkey.sentinel_addrs"),
		Password:         v.GetString("valkey.password"),
		SentinelPassword: v.GetString("valkey.sentinel_password"),
		DB:               v.GetInt("valkey.db"),
		SSL: ValkeySSL{
			Enabled:    v.GetBool("valkey.ssl.enabled"),
			CAFile:     v.GetString("valkey.ssl.ca_file"),
			CertFile:   v.GetString("valkey.ssl.cert_file"),
			KeyFile:    v.GetString("valkey.ssl.key_file"),
			SkipVerify: v.GetBool("valkey.ssl.skip_verify"),
		},
	}
	if vc.Mode == "sentinel" && vc.MasterName == "" {
		return ValkeyConfig{}, fmt.Errorf("valkey.mode=sentinel requires valkey.master_name")
	}
	return vc, nil
}

// readTLS returns nil (plaintext) when tls.enabled is false or absent — the
// cert/key files are NOT accessed in that state (no implicit file-based
// toggle; a tls block with paths but enabled:false stays plaintext).
// When enabled, it fails fast with a load error if either file is
// missing/unreadable, so a misconfigured TLS plane never starts silently.
func readTLS(v *viper.Viper) (*CertConfig, error) {
	if !v.GetBool("tls.enabled") {
		return nil, nil
	}
	cert := v.GetString("tls.cert_file")
	key := v.GetString("tls.key_file")
	if cert == "" {
		return nil, fmt.Errorf("tls.enabled=true requires tls.cert_file")
	}
	if key == "" {
		return nil, fmt.Errorf("tls.enabled=true requires tls.key_file")
	}
	for _, f := range []string{cert, key} {
		h, err := os.Open(f)
		if err != nil {
			return nil, fmt.Errorf("tls enabled: %s: %w", f, err)
		}
		h.Close()
	}
	return &CertConfig{Enabled: true, CertFile: cert, KeyFile: key}, nil
}

// readAudit reads the audit block through the same viper instance that read
// the file (env overrides + defaults resolve consistently). When
// audit.mysql.enabled is true, ALL connection fields must be present —
// enabled without host/port/user/password/database is a load error naming
// the missing field, so an audit writer that cannot connect never starts
// silently (mirrors the credentials_source=api fail-fast).
func readAudit(v *viper.Viper) (AuditConfig, error) {
	a := AuditConfig{MySQL: MySQLAuditConfig{
		Enabled:  v.GetBool("audit.mysql.enabled"),
		Host:     v.GetString("audit.mysql.host"),
		Port:     v.GetString("audit.mysql.port"),
		User:     v.GetString("audit.mysql.user"),
		Password: v.GetString("audit.mysql.password"),
		Database: v.GetString("audit.mysql.database"),
	}}
	if a.MySQL.Enabled {
		for _, f := range []struct{ name, val string }{
			{"audit.mysql.host", a.MySQL.Host},
			{"audit.mysql.port", a.MySQL.Port},
			{"audit.mysql.user", a.MySQL.User},
			{"audit.mysql.password", a.MySQL.Password},
			{"audit.mysql.database", a.MySQL.Database},
		} {
			if f.val == "" {
				hint := ""
				if f.name == "audit.mysql.password" {
					hint = " (set ZT_AUDIT_MYSQL_PASSWORD in .env — see .env.example)"
				}
				return AuditConfig{}, fmt.Errorf("audit.mysql.enabled=true requires %s%s", f.name, hint)
			}
		}
	}
	return a, nil
}

// LoadControl reads the Control Plane config (configs/control.yaml).
// Secrets come from the environment (.env via LoadDotEnv or exported
// variables), never from the committed file — see dotenv.go.
func LoadControl(path string) (*ControlConfig, error) {
	if err := LoadDotEnv(dotenvPath()); err != nil {
		return nil, err
	}
	v := viper.New()
	if err := load(v, path, map[string]any{
		"http.addr": ":8080", "api.token_ttl_seconds": 300,
		"api.token_max_uses": 1,
		// Task 9.13 session tokens: default issue mode single-use; session
		// TTL 0 = infinite (revocation is explicit, never timer-based).
		"api.token_mode": "single-use", "api.session_token_ttl_seconds": 0,
		// JWT conversion (Task 2): the bearer-JWT block defaults ON —
		// auth.jwt.enabled ABSENT = true (JWT is the mode going forward; an
		// explicit false disables JWT verification — guarded routes fail
		// closed 401; the legacy cookie-session machinery was removed during
		// the conversion and no longer exists as a fallback), and
		// login_enabled ABSENT = true (today's behavior: the plane
		// authenticates UI users with username/password). jwt.ttl_seconds
		// (28800 = 8h) is the new auth expiry — it supersedes
		// auth.session_ttl_hours, which stays parsed (default 8) as INERT
		// backward-compatible residue (nothing consumes it).
		"auth.jwt.enabled":       true,
		"auth.jwt.login_enabled": true,
		"auth.jwt.ttl_seconds":   28800,
		"auth.session_ttl_hours": 8, "valkey.addr": "127.0.0.1:6379",
		"valkey.mode": "direct",
		// Task 9.7 session audit: OFF by default (no DB dependency unless
		// enabled); database defaults to zt_audit, host/port to the dev
		// mysql-test container. Env: ZT_AUDIT_MYSQL_ENABLED/_HOST/_PORT/
		// _USER/_PASSWORD/_DATABASE.
		"audit.mysql.enabled":  false,
		"audit.mysql.host":     "127.0.0.1",
		"audit.mysql.port":     "3307",
		"audit.mysql.database": "zt_audit",
	}); err != nil {
		return nil, err
	}
	tlsCfg, err := readTLS(v)
	if err != nil {
		return nil, err
	}
	auditCfg, err := readAudit(v)
	if err != nil {
		return nil, err
	}
	cfg := &ControlConfig{
		HTTPAddr:        v.GetString("http.addr"),
		StaticDir:       v.GetString("http.static_dir"),
		TokenTTL:        v.GetInt("api.token_ttl_seconds"),
		TokenMaxUses:    v.GetInt("api.token_max_uses"),
		TokenMode:       v.GetString("api.token_mode"),
		SessionTokenTTL: v.GetInt("api.session_token_ttl_seconds"),
		DataPlaneHost:   v.GetString("api.data_plane_host"),
		DataPlanePort:   v.GetString("api.data_plane_port"),
		AuthUser:        v.GetString("auth.username"),
		AuthPassword:    v.GetString("auth.password"),
		AuthRole:        v.GetString("auth.role"),
		AllowMakerWatch: v.GetBool("auth.allow_maker_watch"),
		JWT: JWTConfig{
			Enabled:        v.GetBool("auth.jwt.enabled"),
			LoginEnabled:   v.GetBool("auth.jwt.login_enabled"),
			Issuer:         v.GetString("auth.jwt.issuer"),
			Audience:       v.GetString("auth.jwt.audience"),
			TTLSeconds:     v.GetInt("auth.jwt.ttl_seconds"),
			Secret:         v.GetString("auth.jwt.secret"),
			AllowedOrigins: v.GetStringSlice("auth.jwt.allowed_origins"),
		},
		SessionTTL: v.GetInt("auth.session_ttl_hours"),
		TLS:        tlsCfg,
		Audit:      auditCfg,
	}
	// --- Auth validation (JWT conversion Task 2) ---
	// Review round 3 fail-fast retained: AutomaticEnv is set, so an empty
	// env override (e.g. ZT_AUTH_PASSWORD="") silently overrides the
	// defaults map and would produce a plane with an empty credential; a
	// plane with unguessable-empty credentials must never start. The
	// username/password requirement is now mode-dependent:
	//   - JWT disabled (auth.jwt.enabled: false): username/password still
	//     required (kept from the legacy config shape; no cookie mode
	//     exists — guarded routes simply fail closed 401, see JWTConfig).
	//   - JWT mode + login_enabled: required, unchanged.
	//   - JWT mode external-only (login_enabled: false): NOT required —
	//     the plane may run external-JWT-only (no UI login).
	// The signing secret follows the auth.users ${VAR}-expansion pattern:
	// a config placeholder resolves from the environment and an unset/
	// empty secret refuses to start — never a silent empty HS256 key.
	if cfg.JWT.Enabled {
		if cfg.JWT.LoginEnabled {
			secret, err := expandEnv(cfg.JWT.Secret)
			if err != nil {
				return nil, fmt.Errorf("auth.jwt.secret: %w", err)
			}
			if secret == "" {
				return nil, fmt.Errorf("auth.jwt.login_enabled=true requires auth.jwt.secret (set ZT_JWT_SECRET in .env — see .env.example)")
			}
			cfg.JWT.Secret = secret
			if cfg.AuthUser == "" {
				return nil, fmt.Errorf("auth.username is required (set auth.username or ZT_AUTH_USERNAME)")
			}
			if cfg.AuthPassword == "" {
				return nil, fmt.Errorf("auth.password is required (set ZT_AUTH_PASSWORD in .env — see .env.example)")
			}
			// Every principal role is EXPLICIT — no silent default (an
			// un-role'd account would be an accidental superuser).
			if cfg.AuthRole != "maker" && cfg.AuthRole != "checker" {
				if cfg.AuthRole == "" {
					return nil, fmt.Errorf("auth.role is required when auth.jwt.login_enabled=true (\"maker\" or \"checker\")")
				}
				return nil, fmt.Errorf("auth.role must be \"maker\" or \"checker\", got %q", cfg.AuthRole)
			}
		} else {
			// External-only: username/password + secret are NOT required,
			// but a role that IS declared must still be valid (role values
			// are validated for every principal regardless of login flag).
			if cfg.AuthRole != "" && cfg.AuthRole != "maker" && cfg.AuthRole != "checker" {
				return nil, fmt.Errorf("auth.role must be \"maker\" or \"checker\", got %q", cfg.AuthRole)
			}
		}
	} else {
		// JWT disabled (auth.jwt.enabled: false): the classic requirement is
		// kept so such a config still demands unguessable credentials (no
		// cookie-session mode exists anymore — guarded routes fail closed
		// 401 regardless, see JWTConfig).
		if cfg.AuthUser == "" {
			return nil, fmt.Errorf("auth.username is required (set auth.username or ZT_AUTH_USERNAME)")
		}
		if cfg.AuthPassword == "" {
			return nil, fmt.Errorf("auth.password is required (set ZT_AUTH_PASSWORD in .env — see .env.example)")
		}
	}
	// Task 9.13: extra users — ${VAR} password placeholders resolved from
	// the environment; empty username/password in ANY user is a load
	// error (same unguessable-credentials rule as the primary pair).
	if err := v.UnmarshalKey("auth.users", &cfg.AuthUsers); err != nil {
		return nil, fmt.Errorf("unmarshal auth.users: %w", err)
	}
	for i := range cfg.AuthUsers {
		u := &cfg.AuthUsers[i]
		if u.Username == "" {
			return nil, fmt.Errorf("auth.users[%d].username is required", i)
		}
		pw, err := expandEnv(u.Password)
		if err != nil {
			return nil, fmt.Errorf("auth.users[%d].password (%s): %w", i, u.Username, err)
		}
		if pw == "" {
			return nil, fmt.Errorf("auth.users[%d].password (%s) is required (set ZT_AUTH_<USER>_PASSWORD in .env — see .env.example)", i, u.Username)
		}
		u.Password = pw
	}
	// Task 2: role validation for the OPTIONAL users — every entry must
	// declare "maker"|"checker" when login_enabled (explicit over default:
	// an un-role'd entry would be an accidental superuser); in external-only
	// mode a declared role must still be valid. With JWT disabled
	// (jwt.enabled: false) there are no roles and this is skipped entirely.
	if cfg.JWT.Enabled {
		for i := range cfg.AuthUsers {
			u := &cfg.AuthUsers[i]
			if u.Role != "maker" && u.Role != "checker" {
				if cfg.JWT.LoginEnabled && u.Role == "" {
					return nil, fmt.Errorf("auth.users[%d].role (%s) is required when auth.jwt.login_enabled=true (\"maker\" or \"checker\")", i, u.Username)
				}
				if u.Role != "" {
					return nil, fmt.Errorf("auth.users[%d].role (%s) must be \"maker\" or \"checker\", got %q", i, u.Username, u.Role)
				}
			}
		}
	}
	if cfg.TokenTTL <= 0 {
		return nil, fmt.Errorf("api.token_ttl_seconds must be > 0, got %d", cfg.TokenTTL)
	}
	vc, err := readValkey(v)
	if err != nil {
		return nil, err
	}
	cfg.Valkey = vc
	// UnmarshalKey must run on the same viper instance that read the file,
	// otherwise it would unmarshal against a fresh, empty store.
	if err := v.UnmarshalKey("db_presets", &cfg.DBPresets); err != nil {
		return nil, fmt.Errorf("unmarshal db_presets: %w", err)
	}
	return cfg, nil
}

// CredentialsAPIConfig is the optional vault block for api-mode credential
// resolution (Task 8.7): the Data Plane fetches the backend DB password from
// this API per connect instead of the committed credentials list. The
// password is NEVER stored or logged — it exists in memory only for the
// in-flight connect call.
type CredentialsAPIConfig struct {
	URL            string `mapstructure:"url"`
	APIKey         string `mapstructure:"api_key"`
	TimeoutSeconds int    `mapstructure:"timeout_seconds"`
}

// MetricsConfig is the OTel/Prometheus scrape endpoint block (Task 9.8,
// user directive 2026-08-15). metrics.enabled (default false) turns on the
// data plane's OTel instruments and serves them at http://listen<path>
// (defaults 0.0.0.0:9464 and /metrics) in the Prometheus text format.
// Disabled = zero overhead: the proxies' metrics wrapper stays nil and every
// call site is a no-op. Env: ZT_METRICS_ENABLED / ZT_METRICS_LISTEN /
// ZT_METRICS_PATH.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`
	Path    string `mapstructure:"path"`
}

// DataConfig mirrors configs/data.yaml.
type DataConfig struct {
	ListenAddr string
	// ListenOracleAddr (yaml listen.oracle_addr, env ZT_ORACLE_ADDR; Task
	// 9.14) is the DEDICATED Oracle/TNS listener address. Empty (default)
	// = the Oracle listener is not started (it is wired together with the
	// OracleProxy).
	ListenOracleAddr string
	DetectDelayMS    int
	MaxConns         int
	TLS              *CertConfig
	Valkey           ValkeyConfig
	// LogQueryOutput (yaml log_query_output, env ZT_LOG_QUERY_OUTPUT; Task
	// 8.8) controls whether the data plane's query log lines carry the
	// CAPTURED RESULT PAYLOAD (columns/rows/row_count/truncated). Default
	// false: every query is still logged with full context (username,
	// ticket, db_user, db, db_type, stmt_type, status, session_id, sql) —
	// only the result payload is gated behind the flag.
	LogQueryOutput bool
	// GateWaitSeconds (yaml gate_wait_seconds, env ZT_GATE_WAIT_SECONDS;
	// Task 8.13) is the maker write-gate GRACE WINDOW: while a write
	// session has NO watcher, blocked SQL commands WAIT up to this many
	// seconds for a checker to attach instead of failing instantly (a maker
	// who connects BEFORE the checker no longer breaks). Default 20.
	// 0 = reject immediately (the pre-8.13 behavior). Negative values fall
	// back to the default.
	GateWaitSeconds int
	// CredentialsSource selects where the backend DB password comes from:
	// "config" (default — the committed credentials list below) or "api"
	// (per-connect fetch from CredentialsAPI; Task 8.7).
	CredentialsSource string
	// CredentialsAPI is the vault endpoint used when CredentialsSource is
	// "api". Load fails fast when source=api and URL is empty.
	CredentialsAPI *CredentialsAPIConfig
	// Credentials maps a backend identity key (e.g. "mysql:ro_user@127.0.0.1:3307")
	// to its password. Used only in config mode. The Data Plane owns DB
	// credentials (zero-trust).
	Credentials map[string]string
	// Metrics is the OTel/Prometheus scrape endpoint block (Task 9.8):
	// enabled=false (default) keeps the proxies' metrics wrapper nil (zero
	// overhead); enabled=true serves the instruments at listen+path and
	// fails fast at load on a malformed listen address.
	Metrics MetricsConfig
	// Session enforcement knobs (Task 9.13 option-A session tokens). These
	// are DATA-plane-side: session-mode sessions are checked on a ticker.
	// SessionIdleSeconds (yaml session.idle_seconds, env
	// ZT_SESSION_IDLE_SECONDS): close sessions idle this long (0 = off).
	// Default 1800 — the safety valve for infinite tokens: a forgotten
	// GUI window cannot pin a backend connection forever.
	SessionIdleSeconds int
	// SessionMaxLifetimeSeconds (yaml session.max_lifetime_seconds, env
	// ZT_SESSION_MAX_LIFETIME_SECONDS): hard cap on session duration from
	// token issue (payload issued_at); 0 = off (default).
	SessionMaxLifetimeSeconds int
	// RevokePollSeconds (yaml session.revoke_poll_seconds, env
	// ZT_SESSION_REVOKE_POLL_SECONDS): token-liveness poll interval for
	// live revocation — deleting tok:<token> by any means closes running
	// sessions within this many seconds (default 1). The valkey
	// keyspace-notification fast path (when the server publishes del/
	// expired events) revokes instantly regardless.
	RevokePollSeconds int
}

// LoadData reads the Data Plane config (configs/data.yaml). Secrets come
// from the environment (.env via LoadDotEnv or exported variables) — the
// committed credentials list carries ${VAR} placeholders, expanded here;
// an unset variable is a load error, never a silent empty password. See
// dotenv.go.
//
// Task 8.7: credentials_source defaults to "config" (committed credentials
// list); "api" switches to per-connect password fetches from
// credentials_api.url (vault contract: GET ?db_type&db_user&db_ip&db_port
// with X-Api-Key → {"password"}). Fail-fast: source=api with an empty URL is
// a load error — a data plane that cannot resolve passwords must never
// start silently.
func LoadData(path string) (*DataConfig, error) {
	if err := LoadDotEnv(dotenvPath()); err != nil {
		return nil, err
	}
	v := viper.New()
	if err := load(v, path, map[string]any{
		"listen.addr": ":3306", "listen.detect_delay_ms": 200,
		"listen.max_conns": 100,
		"valkey.addr":      "127.0.0.1:6379",
		"valkey.mode":      "direct",
		// Task 8.7 credential-source defaults: config mode, vault timeout 5s.
		"credentials_source":              "config",
		"credentials_api.timeout_seconds": 5,
		// Task 8.8: query log lines carry context only by default; the
		// captured result payload (rows) is opt-in via log_query_output.
		"log_query_output": false,
		// Task 9.13 session enforcement: idle 30 min default (the safety
		// valve for infinite session tokens), max-lifetime off, revoke
		// poll 1s (key deleted → sessions close within ~1s; keyspace
		// notifications make it instant when the server publishes them).
		"session.idle_seconds":         1800,
		"session.max_lifetime_seconds": 0,
		"session.revoke_poll_seconds":  1,
		// Task 8.13: the maker write-gate grace window — blocked SQL
		// commands on an unwatched write session wait this long for a
		// checker instead of failing instantly (default 20; 0 = reject
		// immediately, the pre-8.13 behavior; negative → default).
		"gate_wait_seconds": 20,
		// Task 9.8: OTel metrics for Prometheus scraping — DISABLED by
		// default (zero overhead; the proxies' metrics wrapper stays
		// nil). When enabled the data plane serves the instruments at
		// metrics.listen + metrics.path (defaults 0.0.0.0:9464 /metrics);
		// a malformed listen address is a load error (fail fast).
		"metrics.enabled": false,
		"metrics.listen":  "0.0.0.0:9464",
		"metrics.path":    "/metrics",
	}); err != nil {
		return nil, err
	}
	tlsCfg, err := readTLS(v)
	if err != nil {
		return nil, err
	}
	source := v.GetString("credentials_source")
	if source != "config" && source != "api" {
		return nil, fmt.Errorf("credentials_source must be \"config\" or \"api\", got %q", source)
	}
	var apiCfg *CredentialsAPIConfig
	if source == "api" {
		apiCfg = &CredentialsAPIConfig{
			URL:            v.GetString("credentials_api.url"),
			APIKey:         v.GetString("credentials_api.api_key"),
			TimeoutSeconds: v.GetInt("credentials_api.timeout_seconds"),
		}
		if apiCfg.URL == "" {
			return nil, fmt.Errorf("credentials_source=api requires credentials_api.url")
		}
	}
	// Task 8.13: negative gate_wait_seconds is a config error in spirit —
	// the window cannot be negative — so it falls back to the default (20)
	// rather than failing the plane's boot.
	gateWait := v.GetInt("gate_wait_seconds")
	if gateWait < 0 {
		gateWait = 20
	}
	// Task 9.8: metrics block — disabled by default. When enabled the
	// listen address must parse as host:port and the path must be
	// non-empty; both fail fast so a plane that cannot serve its scrape
	// endpoint never starts silently.
	mcfg := MetricsConfig{
		Enabled: v.GetBool("metrics.enabled"),
		Listen:  v.GetString("metrics.listen"),
		Path:    v.GetString("metrics.path"),
	}
	if mcfg.Enabled {
		if _, _, err := net.SplitHostPort(mcfg.Listen); err != nil {
			return nil, fmt.Errorf("metrics.enabled=true: bad metrics.listen %q: %w", mcfg.Listen, err)
		}
		if mcfg.Path == "" {
			return nil, fmt.Errorf("metrics.enabled=true requires metrics.path")
		}
	}
	cfg := &DataConfig{
		ListenAddr:                v.GetString("listen.addr"),
		ListenOracleAddr:          v.GetString("listen.oracle_addr"),
		DetectDelayMS:             v.GetInt("listen.detect_delay_ms"),
		MaxConns:                  v.GetInt("listen.max_conns"),
		TLS:                       tlsCfg,
		LogQueryOutput:            v.GetBool("log_query_output"),
		GateWaitSeconds:           gateWait,
		CredentialsSource:         source,
		CredentialsAPI:            apiCfg,
		Credentials:               map[string]string{},
		SessionIdleSeconds:        v.GetInt("session.idle_seconds"),
		SessionMaxLifetimeSeconds: v.GetInt("session.max_lifetime_seconds"),
		RevokePollSeconds:         v.GetInt("session.revoke_poll_seconds"),
		Metrics:                   mcfg,
	}
	vc, err := readValkey(v)
	if err != nil {
		return nil, err
	}
	cfg.Valkey = vc
	var creds []struct {
		Key      string `mapstructure:"key"`
		Password string `mapstructure:"password"`
	}
	if err := v.UnmarshalKey("credentials", &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}
	for _, c := range creds {
		// Passwords are ${VAR} placeholders resolved from the environment
		// (user directive 2026-08-17: no secrets in committed configs).
		pw, err := expandEnv(c.Password)
		if err != nil {
			return nil, fmt.Errorf("credentials %s: %w", c.Key, err)
		}
		cfg.Credentials[c.Key] = pw
	}
	return cfg, nil
}
