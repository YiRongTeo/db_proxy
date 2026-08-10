package config

import (
	"fmt"
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

// ControlConfig mirrors configs/control.yaml.
type ControlConfig struct {
	HTTPAddr       string
	StaticDir      string
	APIKey         string
	TokenTTL       int
	DataPlaneHost  string
	DataPlanePort  string
	AuthUser       string
	AuthPassword   string
	SessionTTL     int // hours
	DBPresets      []DBPreset
	ValkeyAddr     string
	ValkeyPassword string
	ValkeyDB       int
}

// DBPreset is one selectable database target in the Maker portal.
type DBPreset struct {
	Name   string `mapstructure:"name"`
	DBType string `mapstructure:"db_type"`
	DBUser string `mapstructure:"db_user"`
	DBIP   string `mapstructure:"db_ip"`
	DBPort string `mapstructure:"db_port"`
}

// LoadControl reads the Control Plane config (configs/control.yaml).
func LoadControl(path string) (*ControlConfig, error) {
	v := viper.New()
	if err := load(v, path, map[string]any{
		"http.addr": ":8080", "api.token_ttl_seconds": 300,
		"auth.session_ttl_hours": 8, "valkey.addr": "127.0.0.1:6379",
	}); err != nil {
		return nil, err
	}
	cfg := &ControlConfig{
		HTTPAddr:       v.GetString("http.addr"),
		StaticDir:      v.GetString("http.static_dir"),
		APIKey:         v.GetString("api.api_key"),
		TokenTTL:       v.GetInt("api.token_ttl_seconds"),
		DataPlaneHost:  v.GetString("api.data_plane_host"),
		DataPlanePort:  v.GetString("api.data_plane_port"),
		AuthUser:       v.GetString("auth.username"),
		AuthPassword:   v.GetString("auth.password"),
		SessionTTL:     v.GetInt("auth.session_ttl_hours"),
		ValkeyAddr:     v.GetString("valkey.addr"),
		ValkeyPassword: v.GetString("valkey.password"),
		ValkeyDB:       v.GetInt("valkey.db"),
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
	ListenAddr     string
	DetectDelayMS  int
	ValkeyAddr     string
	ValkeyPassword string
	ValkeyDB       int
	// Credentials maps a backend identity key (e.g. "127.0.0.1:3307:ro_user")
	// to its password. The Data Plane owns DB credentials (zero-trust).
	Credentials map[string]string
}

// LoadData reads the Data Plane config (configs/data.yaml).
func LoadData(path string) (*DataConfig, error) {
	v := viper.New()
	if err := load(v, path, map[string]any{
		"listen.addr": ":3306", "listen.detect_delay_ms": 200,
		"valkey.addr": "127.0.0.1:6379",
	}); err != nil {
		return nil, err
	}
	cfg := &DataConfig{
		ListenAddr:     v.GetString("listen.addr"),
		DetectDelayMS:  v.GetInt("listen.detect_delay_ms"),
		ValkeyAddr:     v.GetString("valkey.addr"),
		ValkeyPassword: v.GetString("valkey.password"),
		ValkeyDB:       v.GetInt("valkey.db"),
		Credentials:    map[string]string{},
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
