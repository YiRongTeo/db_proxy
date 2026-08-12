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
		{Name: "MySQL read-only", DBType: "mysql", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "3307"},
		{Name: "MySQL read-write", DBType: "mysql", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "3307"},
		{Name: "PostgreSQL read-only", DBType: "postgres", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "5433"},
	}
	for i, want := range wantPresets {
		got := cfg.DBPresets[i]
		if got != want {
			t.Errorf("DBPresets[%d] = %+v, want %+v", i, got, want)
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
	} {
		if !strings.Contains(s, want) {
			t.Errorf("marshaled JSON missing %s; got %s", want, s)
		}
	}

	// No PascalCase keys (the pre-fix bug).
	for _, bad := range []string{`"Name"`, `"DBType"`, `"DBUser"`, `"DBIP"`, `"DBPort"`} {
		if strings.Contains(s, bad) {
			t.Errorf("marshaled JSON contains PascalCase key %s; got %s", bad, s)
		}
	}

	// Structural check: every element has exactly the 5 snake_case keys.
	var got []map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error: %v", s, err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	wantKeys := []string{"name", "db_type", "db_user", "db_ip", "db_port"}
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
		"127.0.0.1:3307:ro_user": "ro_pw",
		"127.0.0.1:3307:rw_user": "rw_pw",
		"127.0.0.1:5433:ro_user": "ro_pw",
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
