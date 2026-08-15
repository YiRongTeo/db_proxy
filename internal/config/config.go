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
	v.AutomaticEnv()
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
	Mode             string    `mapstructure:"mode"`
	Addr             string    `mapstructure:"addr"`
	MasterName       string    `mapstructure:"master_name"`
	SentinelAddrs    []string  `mapstructure:"sentinel_addrs"`
	Password         string    `mapstructure:"password"`
	SentinelUsername string    `mapstructure:"sentinel_username"`
	SentinelPassword string    `mapstructure:"sentinel_password"`
	DB               int       `mapstructure:"db"`
	SSL              ValkeySSL `mapstructure:"ssl"`
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
	TLS           *CertConfig
	Valkey        ValkeyConfig
	Audit         AuditConfig
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
}

// readValkey reads the valkey block through the SAME viper instance that read
// the file (env overrides + defaults resolve consistently). Individual Get*
// calls (rather than UnmarshalKey) so nested defaults (mode=direct, ssl
// disabled) apply even when the file omits keys — the old flat shape
// valkey: {addr, password, db} therefore still parses unchanged.
func readValkey(v *viper.Viper) ValkeyConfig {
	return ValkeyConfig{
		Mode:             v.GetString("valkey.mode"),
		Addr:             v.GetString("valkey.addr"),
		MasterName:       v.GetString("valkey.master_name"),
		SentinelAddrs:    v.GetStringSlice("valkey.sentinel_addrs"),
		Password:         v.GetString("valkey.password"),
		SentinelUsername: v.GetString("valkey.sentinel_username"),
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
				return AuditConfig{}, fmt.Errorf("audit.mysql.enabled=true requires %s", f.name)
			}
		}
	}
	return a, nil
}

// LoadControl reads the Control Plane config (configs/control.yaml).
func LoadControl(path string) (*ControlConfig, error) {
	v := viper.New()
	if err := load(v, path, map[string]any{
		"http.addr": ":8080", "api.token_ttl_seconds": 300,
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
		HTTPAddr:      v.GetString("http.addr"),
		StaticDir:     v.GetString("http.static_dir"),
		APIKey:        v.GetString("api.api_key"),
		TokenTTL:      v.GetInt("api.token_ttl_seconds"),
		DataPlaneHost: v.GetString("api.data_plane_host"),
		DataPlanePort: v.GetString("api.data_plane_port"),
		AuthUser:      v.GetString("auth.username"),
		AuthPassword:  v.GetString("auth.password"),
		SessionTTL:    v.GetInt("auth.session_ttl_hours"),
		TLS:           tlsCfg,
		Valkey:        readValkey(v),
		Audit:         auditCfg,
	}
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
	ListenAddr    string
	DetectDelayMS int
	MaxConns      int
	TLS           *CertConfig
	Valkey        ValkeyConfig
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
}

// LoadData reads the Data Plane config (configs/data.yaml).
//
// Task 8.7: credentials_source defaults to "config" (committed credentials
// list); "api" switches to per-connect password fetches from
// credentials_api.url (vault contract: GET ?db_type&db_user&db_ip&db_port
// with X-Api-Key → {"password"}). Fail-fast: source=api with an empty URL is
// a load error — a data plane that cannot resolve passwords must never
// start silently.
func LoadData(path string) (*DataConfig, error) {
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
		ListenAddr:        v.GetString("listen.addr"),
		DetectDelayMS:     v.GetInt("listen.detect_delay_ms"),
		MaxConns:          v.GetInt("listen.max_conns"),
		TLS:               tlsCfg,
		Valkey:            readValkey(v),
		LogQueryOutput:    v.GetBool("log_query_output"),
		GateWaitSeconds:   gateWait,
		CredentialsSource: source,
		CredentialsAPI:    apiCfg,
		Credentials:       map[string]string{},
		Metrics:           mcfg,
	}
	var creds []struct {
		Key      string `mapstructure:"key"`
		Password string `mapstructure:"password"`
	}
	if err := v.UnmarshalKey("credentials", &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}
	for _, c := range creds {
		cfg.Credentials[c.Key] = c.Password
	}
	return cfg, nil
}
