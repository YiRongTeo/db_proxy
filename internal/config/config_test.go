package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Paths are relative to this package; `go test ./internal/config/` runs with
// the package dir as CWD, so the committed configs live two levels up.
const (
	controlYAML = "../../configs/control.yaml"
	dataYAML    = "../../configs/data.yaml"
)

func TestLoadControl(t *testing.T) {
	cfg, err := LoadControl(controlYAML)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", controlYAML, err)
	}

	if got := cfg.HTTPAddr; got != ":8080" {
		t.Errorf("HTTPAddr = %q, want %q", got, ":8080")
	}
	if got := cfg.TokenTTL; got != 300 {
		t.Errorf("TokenTTL = %d, want 300", got)
	}
	if got := cfg.DataPlanePort; got != "3306" {
		t.Errorf("DataPlanePort = %q, want %q", got, "3306")
	}
	if got := cfg.DataPlaneHost; got != "127.0.0.1" {
		t.Errorf("DataPlaneHost = %q, want %q", got, "127.0.0.1")
	}
	if got := cfg.AuthUser; got != "admin" {
		t.Errorf("AuthUser = %q, want %q", got, "admin")
	}
	if got := cfg.SessionTTL; got != 8 {
		t.Errorf("SessionTTL = %d, want 8", got)
	}
	if got := cfg.Valkey.Mode; got != "direct" {
		t.Errorf("Valkey.Mode = %q, want %q", got, "direct")
	}
	if got := cfg.Valkey.Addr; got != "127.0.0.1:6379" {
		t.Errorf("Valkey.Addr = %q, want %q", got, "127.0.0.1:6379")
	}
	assertTLSDisabled(t, cfg.TLS)
	assertSSLDefaults(t, cfg.Valkey.SSL)

	if got := len(cfg.DBPresets); got != 3 {
		t.Fatalf("len(DBPresets) = %d, want 3", got)
	}

	wantPresets := []DBPreset{
		{Name: "MySQL read-only", DBType: "mysql", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "3307", Access: "read"},
		{Name: "MySQL read-write", DBType: "mysql", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "3307", Access: "write"},
		{Name: "PostgreSQL read-only", DBType: "postgres", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "5433", Access: "read"},
	}
	for i, want := range wantPresets {
		got := cfg.DBPresets[i]
		if got != want {
			t.Errorf("DBPresets[%d] = %+v, want %+v", i, got, want)
		}
	}
}

// TestDBPresetAccessValues (Task 8.6) pins the committed presets' access
// levels: the read-write preset is the ONLY write-gated target — the two
// read-only presets carry access "read" and never gate.
func TestDBPresetAccessValues(t *testing.T) {
	cfg, err := LoadControl(controlYAML)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", controlYAML, err)
	}
	wantAccess := map[string]string{
		"MySQL read-only":      "read",
		"MySQL read-write":     "write",
		"PostgreSQL read-only": "read",
	}
	for _, p := range cfg.DBPresets {
		want, ok := wantAccess[p.Name]
		if !ok {
			t.Errorf("unexpected preset %q", p.Name)
			continue
		}
		if p.Access != want {
			t.Errorf("preset %q access = %q, want %q", p.Name, p.Access, want)
		}
	}
}

// TestDBPresetJSONWireContract guards the /api/db-presets wire contract
// (spec §5 + TS DbPreset interface): keys MUST be snake_case. Without the
// json tags on DBPreset, encoding/json emits PascalCase keys and the
// Angular maker-portal select renders empty options.
func TestDBPresetJSONWireContract(t *testing.T) {
	cfg, err := LoadControl(controlYAML)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", controlYAML, err)
	}
	raw, err := json.Marshal(cfg.DBPresets)
	if err != nil {
		t.Fatalf("json.Marshal(DBPresets) error: %v", err)
	}
	s := string(raw)

	// Exactly the snake_case keys the TS DbPreset interface expects.
	for _, want := range []string{
		`"name":"MySQL read-only"`,
		`"db_type":"mysql"`,
		`"db_user":"ro_user"`,
		`"db_ip":"127.0.0.1"`,
		`"db_port":"3307"`,
		`"access":"read"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("marshaled JSON missing %s; got %s", want, s)
		}
	}

	// No PascalCase keys (the pre-fix bug).
	for _, bad := range []string{`"Name"`, `"DBType"`, `"DBUser"`, `"DBIP"`, `"DBPort"`, `"Access"`} {
		if strings.Contains(s, bad) {
			t.Errorf("marshaled JSON contains PascalCase key %s; got %s", bad, s)
		}
	}

	// Structural check: every element has exactly the 6 snake_case keys
	// (access joined the wire contract in Task 8.6).
	var got []map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error: %v", s, err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	wantKeys := []string{"name", "db_type", "db_user", "db_ip", "db_port", "access"}
	for i, m := range got {
		if len(m) != len(wantKeys) {
			t.Errorf("preset[%d] has %d keys, want %d: %v", i, len(m), len(wantKeys), m)
		}
		for _, k := range wantKeys {
			if _, ok := m[k]; !ok {
				t.Errorf("preset[%d] missing key %q; got %v", i, k, m)
			}
		}
	}
}

func TestLoadData(t *testing.T) {
	cfg, err := LoadData(dataYAML)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", dataYAML, err)
	}

	if got := cfg.ListenAddr; got != ":3306" {
		t.Errorf("ListenAddr = %q, want %q", got, ":3306")
	}
	if got := cfg.DetectDelayMS; got != 200 {
		t.Errorf("DetectDelayMS = %d, want 200", got)
	}
	if got := cfg.MaxConns; got != 100 {
		t.Errorf("MaxConns = %d, want 100", got)
	}
	if got := cfg.CredentialsSource; got != "config" {
		t.Errorf("CredentialsSource = %q, want %q (default)", got, "config")
	}
	if cfg.CredentialsAPI != nil {
		t.Errorf("CredentialsAPI = %+v, want nil (config mode)", cfg.CredentialsAPI)
	}
	if cfg.LogQueryOutput {
		t.Errorf("LogQueryOutput = true, want false (default: context-only query logs)")
	}
	if got := cfg.GateWaitSeconds; got != 20 {
		t.Errorf("GateWaitSeconds = %d, want 20 (Task 8.13 grace-window default)", got)
	}
	if got := cfg.Valkey.Mode; got != "direct" {
		t.Errorf("Valkey.Mode = %q, want %q", got, "direct")
	}
	if got := cfg.Valkey.Addr; got != "127.0.0.1:6379" {
		t.Errorf("Valkey.Addr = %q, want %q", got, "127.0.0.1:6379")
	}
	if got := cfg.Valkey.DB; got != 0 {
		t.Errorf("Valkey.DB = %d, want 0", got)
	}
	assertTLSDisabled(t, cfg.TLS)
	assertSSLDefaults(t, cfg.Valkey.SSL)

	wantCreds := map[string]string{
		"mysql:ro_user@127.0.0.1:3307":    "ro_pw",
		"mysql:rw_user@127.0.0.1:3307":    "rw_pw",
		"postgres:ro_user@127.0.0.1:5433": "ro_pw",
	}
	if got := len(cfg.Credentials); got != len(wantCreds) {
		t.Fatalf("len(Credentials) = %d, want %d", got, len(wantCreds))
	}
	for key, wantPw := range wantCreds {
		gotPw, ok := cfg.Credentials[key]
		if !ok {
			t.Errorf("Credentials missing key %q", key)
			continue
		}
		if gotPw != wantPw {
			t.Errorf("Credentials[%q] = %q, want %q", key, gotPw, wantPw)
		}
	}
}

// assertTLSDisabled checks the plane TLS block is OFF in the committed
// configs: tls.enabled: false → TLS stays nil and the cert/key paths are
// never touched (no implicit file-based toggle — certs/ does not even exist
// yet, which must not matter while disabled).
func assertTLSDisabled(t *testing.T, tls *CertConfig) {
	t.Helper()
	if tls != nil {
		t.Fatalf("TLS = %+v, want nil (committed configs set tls.enabled: false → plaintext)", tls)
	}
}

// assertSSLDefaults checks the valkey ssl block defaulted to disabled/empty.
func assertSSLDefaults(t *testing.T, ssl ValkeySSL) {
	t.Helper()
	if ssl.Enabled {
		t.Error("Valkey.SSL.Enabled = true, want false (TLS opt-in)")
	}
	if got := ssl.CAFile; got != "" {
		t.Errorf("Valkey.SSL.CAFile = %q, want empty", got)
	}
	if got := ssl.CertFile; got != "" {
		t.Errorf("Valkey.SSL.CertFile = %q, want empty", got)
	}
	if got := ssl.KeyFile; got != "" {
		t.Errorf("Valkey.SSL.KeyFile = %q, want empty", got)
	}
	if ssl.SkipVerify {
		t.Error("Valkey.SSL.SkipVerify = true, want false")
	}
}

// writeTempConfig writes yaml content to a fresh temp file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config %s: %v", path, err)
	}
	return path
}

// TestLoadControlSentinelShape guards the new sentinel-mode valkey block:
// mode/master_name/sentinel_addrs must all land on the struct, and the ssl
// block must parse when present.
func TestLoadControlSentinelShape(t *testing.T) {
	path := writeTempConfig(t, `
http:
  addr: ":8443"
valkey:
  mode: sentinel
  addr: "10.0.0.5:6379"
  master_name: "mymaster"
  sentinel_addrs: ["127.0.0.1:26379", "127.0.0.1:26380"]
  password: "s3cret"
  db: 2
  ssl:
    enabled: true
    ca_file: "/etc/ssl/valkey/ca.pem"
    cert_file: "/etc/ssl/valkey/client.pem"
    key_file: "/etc/ssl/valkey/client.key"
    skip_verify: false
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", path, err)
	}

	if got := cfg.Valkey.Mode; got != "sentinel" {
		t.Errorf("Valkey.Mode = %q, want %q", got, "sentinel")
	}
	if got := cfg.Valkey.MasterName; got != "mymaster" {
		t.Errorf("Valkey.MasterName = %q, want %q", got, "mymaster")
	}
	wantAddrs := []string{"127.0.0.1:26379", "127.0.0.1:26380"}
	if got := cfg.Valkey.SentinelAddrs; len(got) != len(wantAddrs) {
		t.Fatalf("len(SentinelAddrs) = %d, want %d (%v)", len(got), len(wantAddrs), got)
	}
	for i, want := range wantAddrs {
		if got := cfg.Valkey.SentinelAddrs[i]; got != want {
			t.Errorf("SentinelAddrs[%d] = %q, want %q", i, got, want)
		}
	}
	if got := cfg.Valkey.Addr; got != "10.0.0.5:6379" {
		t.Errorf("Valkey.Addr = %q, want %q", got, "10.0.0.5:6379")
	}
	if got := cfg.Valkey.Password; got != "s3cret" {
		t.Errorf("Valkey.Password = %q, want %q", got, "s3cret")
	}
	if got := cfg.Valkey.DB; got != 2 {
		t.Errorf("Valkey.DB = %d, want 2", got)
	}
	if !cfg.Valkey.SSL.Enabled {
		t.Error("Valkey.SSL.Enabled = false, want true")
	}
	if got := cfg.Valkey.SSL.CAFile; got != "/etc/ssl/valkey/ca.pem" {
		t.Errorf("Valkey.SSL.CAFile = %q, want %q", got, "/etc/ssl/valkey/ca.pem")
	}

	// No tls block in this file → plane TLS stays nil (plaintext default).
	if cfg.TLS != nil {
		t.Errorf("TLS = %+v, want nil (no tls block)", cfg.TLS)
	}
}

// TestValkeySentinelAuth is the Task 7.7 loader probe: sentinel
// credentials parse from yaml (valkey.sentinel_username /
// valkey.sentinel_password) and from the ZT_ env names (viper convention:
// prefix ZT_ + dots→underscores → ZT_VALKEY_SENTINEL_USERNAME /
// ZT_VALKEY_SENTINEL_PASSWORD), defaulting to "" when absent.
func TestValkeySentinelAuth(t *testing.T) {
	t.Run("defaults empty when absent", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
valkey:
  mode: sentinel
  master_name: "mymaster"
  sentinel_addrs: ["127.0.0.1:26379"]
`)
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if got := cfg.Valkey.SentinelUsername; got != "" {
			t.Errorf("SentinelUsername = %q, want \"\" (default)", got)
		}
		if got := cfg.Valkey.SentinelPassword; got != "" {
			t.Errorf("SentinelPassword = %q, want \"\" (default)", got)
		}
	})

	t.Run("yaml keys parse", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
valkey:
  mode: sentinel
  master_name: "mymaster"
  sentinel_addrs: ["127.0.0.1:26379"]
  sentinel_username: "sentuser"
  sentinel_password: "sentpw-yaml"
`)
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if got := cfg.Valkey.SentinelUsername; got != "sentuser" {
			t.Errorf("SentinelUsername = %q, want %q", got, "sentuser")
		}
		if got := cfg.Valkey.SentinelPassword; got != "sentpw-yaml" {
			t.Errorf("SentinelPassword = %q, want %q", got, "sentpw-yaml")
		}
	})

	t.Run("env overrides: ZT_VALKEY_SENTINEL_USERNAME / ZT_VALKEY_SENTINEL_PASSWORD", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
valkey:
  mode: sentinel
  master_name: "mymaster"
  sentinel_addrs: ["127.0.0.1:26379"]
`)
		t.Setenv("ZT_VALKEY_SENTINEL_USERNAME", "env-sentuser")
		t.Setenv("ZT_VALKEY_SENTINEL_PASSWORD", "env-sentpw")
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if got := cfg.Valkey.SentinelUsername; got != "env-sentuser" {
			t.Errorf("SentinelUsername = %q, want %q (ZT_VALKEY_SENTINEL_USERNAME)", got, "env-sentuser")
		}
		if got := cfg.Valkey.SentinelPassword; got != "env-sentpw" {
			t.Errorf("SentinelPassword = %q, want %q (ZT_VALKEY_SENTINEL_PASSWORD)", got, "env-sentpw")
		}
	})
}

// TestLoadDataOldShapeCompat guards backward compatibility: the pre-Phase-7
// flat valkey block (valkey: {addr, password, db}, no mode, no ssl) must still
// parse — mode defaults to "direct" and ssl defaults to disabled.
func TestLoadDataOldShapeCompat(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
valkey:
  addr: "127.0.0.1:6379"
  password: "oldpw"
  db: 3
`)
	cfg, err := LoadData(path)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", path, err)
	}

	if got := cfg.Valkey.Mode; got != "direct" {
		t.Errorf("Valkey.Mode = %q, want %q (default when mode absent)", got, "direct")
	}
	if got := cfg.Valkey.Addr; got != "127.0.0.1:6379" {
		t.Errorf("Valkey.Addr = %q, want %q", got, "127.0.0.1:6379")
	}
	if got := cfg.Valkey.Password; got != "oldpw" {
		t.Errorf("Valkey.Password = %q, want %q", got, "oldpw")
	}
	if got := cfg.Valkey.DB; got != 3 {
		t.Errorf("Valkey.DB = %d, want 3", got)
	}
	assertSSLDefaults(t, cfg.Valkey.SSL)
	if cfg.TLS != nil {
		t.Errorf("TLS = %+v, want nil (no tls block)", cfg.TLS)
	}
}

// TestTLSOffState guards TLS state (a): tls.enabled: false with NO cert/key
// files anywhere → Load succeeds and TLS is nil (plaintext). The cert/key
// files must never be touched while the switch is off.
func TestTLSOffState(t *testing.T) {
	path := writeTempConfig(t, `
http:
  addr: ":8080"
tls:
  enabled: false
  cert_file: "certs/does-not-exist.crt"
  key_file:  "certs/does-not-exist.key"
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v (enabled:false must not touch files)", path, err)
	}
	if cfg.TLS != nil {
		t.Fatalf("TLS = %+v, want nil (enabled: false → plaintext)", cfg.TLS)
	}
}

// TestTLSOnMissingFiles guards TLS state (b): tls.enabled: true with
// missing/unreadable cert or key → fail-fast Load ERROR naming the file.
func TestTLSOnMissingFiles(t *testing.T) {
	// (b1) cert missing.
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
tls:
  enabled: true
  cert_file: "certs/nope.crt"
  key_file:  "certs/nope.key"
`)
	_, err := LoadData(path)
	if err == nil {
		t.Fatal("LoadData: want error for enabled:true with missing cert/key, got nil")
	}
	if !strings.Contains(err.Error(), "certs/nope.crt") {
		t.Errorf("error %q missing the missing cert path", err.Error())
	}

	// (b2) key missing while cert exists on disk.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "plane.crt")
	if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
		t.Fatalf("write %s: %v", certPath, err)
	}
	path = writeTempConfig(t, fmt.Sprintf(`
listen:
  addr: ":3306"
tls:
  enabled: true
  cert_file: %q
  key_file:  "certs/nope.key"
`, filepath.ToSlash(certPath)))
	_, err = LoadData(path)
	if err == nil {
		t.Fatal("LoadData: want error for enabled:true with missing key, got nil")
	}
	if !strings.Contains(err.Error(), "certs/nope.key") {
		t.Errorf("error %q missing the missing key path", err.Error())
	}

	// (b3) enabled:true with no cert_file at all → shape error naming the key.
	path = writeTempConfig(t, `
http:
  addr: ":8080"
tls:
  enabled: true
`)
	_, err = LoadControl(path)
	if err == nil {
		t.Fatal("LoadControl: want error for enabled:true without cert_file, got nil")
	}
	if !strings.Contains(err.Error(), "tls.cert_file") {
		t.Errorf("error %q missing tls.cert_file hint", err.Error())
	}
}

// TestTLSOnWithFiles guards TLS state (c): tls.enabled: true with both files
// present → Load succeeds and TLS is populated with Enabled + both paths.
func TestTLSOnWithFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "plane.crt")
	keyPath := filepath.Join(dir, "plane.key")
	for _, f := range []string{certPath, keyPath} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	path := writeTempConfig(t, fmt.Sprintf(`
listen:
  addr: ":3306"
tls:
  enabled: true
  cert_file: %q
  key_file:  %q
`, filepath.ToSlash(certPath), filepath.ToSlash(keyPath)))
	cfg, err := LoadData(path)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", path, err)
	}
	if cfg.TLS == nil {
		t.Fatal("TLS = nil, want populated (enabled: true with files present)")
	}
	if !cfg.TLS.Enabled {
		t.Error("TLS.Enabled = false, want true")
	}
	if got := cfg.TLS.CertFile; got != filepath.ToSlash(certPath) {
		t.Errorf("TLS.CertFile = %q, want %q", got, filepath.ToSlash(certPath))
	}
	if got := cfg.TLS.KeyFile; got != filepath.ToSlash(keyPath) {
		t.Errorf("TLS.KeyFile = %q, want %q", got, filepath.ToSlash(keyPath))
	}
}

// --- Task 8.7: credential source (config vs api) ---------------------------

// TestCredentialsSourceAPIMode: credentials_source: api parses the
// credentials_api block (url/api_key/timeout_seconds) and the committed
// credentials list is untouched.
func TestCredentialsSourceAPIMode(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
credentials_source: api
credentials_api:
  url: "http://vault:9000/creds"
  api_key: "k-123"
  timeout_seconds: 7
`)
	cfg, err := LoadData(path)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", path, err)
	}
	if got := cfg.CredentialsSource; got != "api" {
		t.Errorf("CredentialsSource = %q, want %q", got, "api")
	}
	if cfg.CredentialsAPI == nil {
		t.Fatal("CredentialsAPI = nil, want populated block")
	}
	if got := cfg.CredentialsAPI.URL; got != "http://vault:9000/creds" {
		t.Errorf("CredentialsAPI.URL = %q, want %q", got, "http://vault:9000/creds")
	}
	if got := cfg.CredentialsAPI.APIKey; got != "k-123" {
		t.Errorf("CredentialsAPI.APIKey = %q, want %q", got, "k-123")
	}
	if got := cfg.CredentialsAPI.TimeoutSeconds; got != 7 {
		t.Errorf("CredentialsAPI.TimeoutSeconds = %d, want 7", got)
	}
}

// TestCredentialsSourceAPIDefaults: api mode with only a url gets the 5s
// timeout default and an empty api key.
func TestCredentialsSourceAPIDefaults(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
credentials_source: api
credentials_api:
  url: "http://vault:9000/creds"
`)
	cfg, err := LoadData(path)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", path, err)
	}
	if got := cfg.CredentialsAPI.TimeoutSeconds; got != 5 {
		t.Errorf("CredentialsAPI.TimeoutSeconds = %d, want default 5", got)
	}
	if got := cfg.CredentialsAPI.APIKey; got != "" {
		t.Errorf("CredentialsAPI.APIKey = %q, want empty default", got)
	}
}

// TestCredentialsSourceAPIMissingURLFailsFast: source=api with no URL is a
// load ERROR — a data plane that cannot resolve passwords must never start
// silently.
func TestCredentialsSourceAPIMissingURLFailsFast(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
credentials_source: api
`)
	_, err := LoadData(path)
	if err == nil {
		t.Fatal("LoadData: want error for source=api without credentials_api.url, got nil")
	}
	if !strings.Contains(err.Error(), "credentials_api.url") {
		t.Errorf("error %q missing the credentials_api.url hint", err.Error())
	}
}

// TestCredentialsSourceUnknownFailsFast: an unknown source value is a load
// error, not a silent fallback to config mode.
func TestCredentialsSourceUnknownFailsFast(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
credentials_source: bogus
`)
	_, err := LoadData(path)
	if err == nil {
		t.Fatal("LoadData: want error for unknown credentials_source, got nil")
	}
	if !strings.Contains(err.Error(), "credentials_source") {
		t.Errorf("error %q missing the credentials_source hint", err.Error())
	}
}

// TestCredentialsSourceEnvOverride: ZT_CREDENTIALS_SOURCE + the
// credentials_api.* env names override the file, per the viper convention
// (prefix ZT_, dots → underscores). Note the canonical viper mapping for
// credentials_api.api_key is ZT_CREDENTIALS_API_API_KEY (the dot becomes an
// underscore, so the key segment's own underscore survives).
func TestCredentialsSourceEnvOverride(t *testing.T) {
	t.Setenv("ZT_CREDENTIALS_SOURCE", "api")
	t.Setenv("ZT_CREDENTIALS_API_URL", "http://vault-env:9000/creds")
	t.Setenv("ZT_CREDENTIALS_API_API_KEY", "env-key")
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
`)
	cfg, err := LoadData(path)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", path, err)
	}
	if got := cfg.CredentialsSource; got != "api" {
		t.Errorf("CredentialsSource = %q, want %q (ZT_CREDENTIALS_SOURCE)", got, "api")
	}
	if got := cfg.CredentialsAPI.URL; got != "http://vault-env:9000/creds" {
		t.Errorf("CredentialsAPI.URL = %q, want %q (ZT_CREDENTIALS_API_URL)", got, "http://vault-env:9000/creds")
	}
	if got := cfg.CredentialsAPI.APIKey; got != "env-key" {
		t.Errorf("CredentialsAPI.APIKey = %q, want %q (ZT_CREDENTIALS_API_API_KEY)", got, "env-key")
	}
}

// --- Task 8.8: log_query_output flag ----------------------------------------

// TestLogQueryOutputFlag: log_query_output: true parses onto the struct;
// absent stays false (default — context-only query logging).
func TestLogQueryOutputFlag(t *testing.T) {
	t.Run("yaml true parses", func(t *testing.T) {
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
log_query_output: true
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if !cfg.LogQueryOutput {
			t.Error("LogQueryOutput = false, want true (log_query_output: true)")
		}
	})

	t.Run("absent defaults false", func(t *testing.T) {
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.LogQueryOutput {
			t.Error("LogQueryOutput = true, want false (default)")
		}
	})
}

// TestLogQueryOutputEnvOverride: ZT_LOG_QUERY_OUTPUT overrides the file value
// (viper convention: prefix ZT_, single key — no dots to replace).
func TestLogQueryOutputEnvOverride(t *testing.T) {
	t.Run("env true beats file false", func(t *testing.T) {
		t.Setenv("ZT_LOG_QUERY_OUTPUT", "true")
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
log_query_output: false
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if !cfg.LogQueryOutput {
			t.Error("LogQueryOutput = false, want true (ZT_LOG_QUERY_OUTPUT=true)")
		}
	})

	t.Run("env false beats file true", func(t *testing.T) {
		t.Setenv("ZT_LOG_QUERY_OUTPUT", "false")
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
log_query_output: true
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.LogQueryOutput {
			t.Error("LogQueryOutput = true, want false (ZT_LOG_QUERY_OUTPUT=false)")
		}
	})
}

// --- Task 8.13: gate_wait_seconds -----------------------------------------

// TestGateWaitSecondsConfig: gate_wait_seconds parses onto the struct;
// absent defaults to 20; 0 means reject-immediately; a negative value falls
// back to the default (the window cannot be negative).
func TestGateWaitSecondsConfig(t *testing.T) {
	t.Run("yaml value parses", func(t *testing.T) {
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
gate_wait_seconds: 7
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.GateWaitSeconds != 7 {
			t.Errorf("GateWaitSeconds = %d, want 7 (gate_wait_seconds: 7)", cfg.GateWaitSeconds)
		}
	})

	t.Run("absent defaults 20", func(t *testing.T) {
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.GateWaitSeconds != 20 {
			t.Errorf("GateWaitSeconds = %d, want 20 (default grace window)", cfg.GateWaitSeconds)
		}
	})

	t.Run("zero means reject immediately", func(t *testing.T) {
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
gate_wait_seconds: 0
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.GateWaitSeconds != 0 {
			t.Errorf("GateWaitSeconds = %d, want 0 (reject immediately)", cfg.GateWaitSeconds)
		}
	})

	t.Run("negative falls back to default", func(t *testing.T) {
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
gate_wait_seconds: -3
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.GateWaitSeconds != 20 {
			t.Errorf("GateWaitSeconds = %d, want 20 (negative clamped to default)", cfg.GateWaitSeconds)
		}
	})
}

// TestGateWaitSecondsEnvOverride: ZT_GATE_WAIT_SECONDS overrides the file
// value (viper convention: prefix ZT_, single key — no dots to replace).
func TestGateWaitSecondsEnvOverride(t *testing.T) {
	t.Run("env beats file", func(t *testing.T) {
		t.Setenv("ZT_GATE_WAIT_SECONDS", "5")
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
gate_wait_seconds: 20
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.GateWaitSeconds != 5 {
			t.Errorf("GateWaitSeconds = %d, want 5 (ZT_GATE_WAIT_SECONDS=5)", cfg.GateWaitSeconds)
		}
	})

	t.Run("env zero beats file", func(t *testing.T) {
		t.Setenv("ZT_GATE_WAIT_SECONDS", "0")
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
gate_wait_seconds: 20
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.GateWaitSeconds != 0 {
			t.Errorf("GateWaitSeconds = %d, want 0 (ZT_GATE_WAIT_SECONDS=0 → immediate reject)", cfg.GateWaitSeconds)
		}
	})

	t.Run("env negative falls back to default", func(t *testing.T) {
		t.Setenv("ZT_GATE_WAIT_SECONDS", "-1")
		path := writeTempConfig(t, `
listen:
  addr: ":3306"
gate_wait_seconds: 20
`)
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.GateWaitSeconds != 20 {
			t.Errorf("GateWaitSeconds = %d, want 20 (negative env clamped to default)", cfg.GateWaitSeconds)
		}
	})
}
