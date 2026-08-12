package config

import (
	"fmt"
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
	Mode          string    `mapstructure:"mode"`
	Addr          string    `mapstructure:"addr"`
	MasterName    string    `mapstructure:"master_name"`
	SentinelAddrs []string  `mapstructure:"sentinel_addrs"`
	Password      string    `mapstructure:"password"`
	DB            int       `mapstructure:"db"`
	SSL           ValkeySSL `mapstructure:"ssl"`
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
}

// DBPreset is one selectable database target in the Maker portal.
// json tags keep the /api/db-presets wire contract snake_case (spec §5);
// mapstructure tags are used by viper when reading configs/control.yaml.
type DBPreset struct {
	Name   string `mapstructure:"name" json:"name"`
	DBType string `mapstructure:"db_type" json:"db_type"`
	DBUser string `mapstructure:"db_user" json:"db_user"`
	DBIP   string `mapstructure:"db_ip" json:"db_ip"`
	DBPort string `mapstructure:"db_port" json:"db_port"`
}

// readValkey reads the valkey block through the SAME viper instance that read
// the file (env overrides + defaults resolve consistently). Individual Get*
// calls (rather than UnmarshalKey) so nested defaults (mode=direct, ssl
// disabled) apply even when the file omits keys — the old flat shape
// valkey: {addr, password, db} therefore still parses unchanged.
func readValkey(v *viper.Viper) ValkeyConfig {
	return ValkeyConfig{
		Mode:          v.GetString("valkey.mode"),
		Addr:          v.GetString("valkey.addr"),
		MasterName:    v.GetString("valkey.master_name"),
		SentinelAddrs: v.GetStringSlice("valkey.sentinel_addrs"),
		Password:      v.GetString("valkey.password"),
		DB:            v.GetInt("valkey.db"),
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

// LoadControl reads the Control Plane config (configs/control.yaml).
func LoadControl(path string) (*ControlConfig, error) {
	v := viper.New()
	if err := load(v, path, map[string]any{
		"http.addr": ":8080", "api.token_ttl_seconds": 300,
		"auth.session_ttl_hours": 8, "valkey.addr": "127.0.0.1:6379",
		"valkey.mode": "direct",
	}); err != nil {
		return nil, err
	}
	tlsCfg, err := readTLS(v)
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
	}
	// UnmarshalKey must run on the same viper instance that read the file,
	// otherwise it would unmarshal against a fresh, empty store.
	if err := v.UnmarshalKey("db_presets", &cfg.DBPresets); err != nil {
		return nil, fmt.Errorf("unmarshal db_presets: %w", err)
	}
	return cfg, nil
}

// DataConfig mirrors configs/data.yaml.
type DataConfig struct {
	ListenAddr    string
	DetectDelayMS int
	MaxConns      int
	TLS           *CertConfig
	Valkey        ValkeyConfig
	// Credentials maps a backend identity key (e.g. "127.0.0.1:3307:ro_user")
	// to its password. The Data Plane owns DB credentials (zero-trust).
	Credentials map[string]string
}

// LoadData reads the Data Plane config (configs/data.yaml).
func LoadData(path string) (*DataConfig, error) {
	v := viper.New()
	if err := load(v, path, map[string]any{
		"listen.addr": ":3306", "listen.detect_delay_ms": 200,
		"listen.max_conns": 100,
		"valkey.addr":      "127.0.0.1:6379",
		"valkey.mode":      "direct",
	}); err != nil {
		return nil, err
	}
	tlsCfg, err := readTLS(v)
	if err != nil {
		return nil, err
	}
	cfg := &DataConfig{
		ListenAddr:    v.GetString("listen.addr"),
		DetectDelayMS: v.GetInt("listen.detect_delay_ms"),
		MaxConns:      v.GetInt("listen.max_conns"),
		TLS:           tlsCfg,
		Valkey:        readValkey(v),
		Credentials:   map[string]string{},
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
