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

// setSecretEnv fills the environment with the secrets the COMMITTED
// configs require (user directive 2026-08-17: no passwords in config
// files — tests emulate the git-ignored .env via t.Setenv, which restores
// the process env afterwards). Tests loading controlYAML/dataYAML call
// this first; the configs' ${VAR} placeholders + fail-fast checks resolve
// against it.
func setSecretEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ZT_AUTH_PASSWORD", "admin123")
	t.Setenv("ZT_AUTH_CHECKER_PASSWORD", "checker123")
	t.Setenv("ZT_JWT_SECRET", "jwt-dev-secret-0123456789abcdef0123456789")
	t.Setenv("ZT_CRED_MYSQL_RO_PASSWORD", "ro_pw")
	t.Setenv("ZT_CRED_MYSQL_RW_PASSWORD", "rw_pw")
	t.Setenv("ZT_CRED_PG_RO_PASSWORD", "ro_pw")
	t.Setenv("ZT_CRED_MSSQL_RO_PASSWORD", "ro_pw")
	t.Setenv("ZT_CRED_MSSQL_RW_PASSWORD", "rw_pw")
	t.Setenv("ZT_CRED_ORACLE_RO_PASSWORD", "ro_pw")
	t.Setenv("ZT_CRED_ORACLE_RW_PASSWORD", "rw_pw")
}

func TestLoadControl(t *testing.T) {
	setSecretEnv(t)
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
	// JWT conversion (Task 2): the committed auth block declares the
	// primary role, per-user roles, allow_maker_watch and the jwt block.
	if got := cfg.AuthRole; got != "maker" {
		t.Errorf("AuthRole = %q, want %q", got, "maker")
	}
	if cfg.AllowMakerWatch {
		t.Error("AllowMakerWatch = true, want false (committed default)")
	}
	if len(cfg.AuthUsers) != 1 || cfg.AuthUsers[0].Username != "checker" || cfg.AuthUsers[0].Role != "checker" {
		t.Errorf("AuthUsers = %+v, want [checker/checker]", cfg.AuthUsers)
	}
	j := cfg.JWT
	if !j.Enabled || !j.LoginEnabled {
		t.Errorf("JWT.Enabled/LoginEnabled = %v/%v, want true/true", j.Enabled, j.LoginEnabled)
	}
	if got := j.Issuer; got != "zerotrust-proxy" {
		t.Errorf("JWT.Issuer = %q, want %q", got, "zerotrust-proxy")
	}
	if got := j.Audience; got != "zt-api" {
		t.Errorf("JWT.Audience = %q, want %q", got, "zt-api")
	}
	if got := j.TTLSeconds; got != 28800 {
		t.Errorf("JWT.TTLSeconds = %d, want 28800", got)
	}
	if got := j.Secret; got != "jwt-dev-secret-0123456789abcdef0123456789" {
		t.Errorf("JWT.Secret = %q, want the expanded ZT_JWT_SECRET", got)
	}
	// Task 9: the committed control.yaml documents an EMPTY
	// auth.jwt.allowed_origins (same-origin-only default for the checker
	// WebSocket). Viper returns a non-nil empty slice for an explicit
	// `allowed_origins: []` — length is the contract.
	if got := len(j.AllowedOrigins); got != 0 {
		t.Errorf("len(JWT.AllowedOrigins) = %d, want 0 (committed default: same-origin only)", got)
	}
	if got := cfg.Valkey.Mode; got != "direct" {
		t.Errorf("Valkey.Mode = %q, want %q", got, "direct")
	}
	if got := cfg.Valkey.Addr; got != "127.0.0.1:6379" {
		t.Errorf("Valkey.Addr = %q, want %q", got, "127.0.0.1:6379")
	}
	assertTLSDisabled(t, cfg.TLS)
	assertSSLDefaults(t, cfg.Valkey.SSL)

	if got := len(cfg.DBPresets); got != 7 {
		t.Fatalf("len(DBPresets) = %d, want 7", got)
	}

	wantPresets := []DBPreset{
		{Name: "MySQL read-only", DBType: "mysql", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "3307", Access: "read"},
		{Name: "MySQL read-write", DBType: "mysql", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "3307", Access: "write"},
		{Name: "PostgreSQL read-only", DBType: "postgres", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "5433", Access: "read"},
		// Phase 9 (Task 9.1): MSSQL presets — port 1434, key format
		// <dbtype>:<db_user>@<db_ip>:<db_port> matches data.yaml credentials.
		{Name: "MSSQL read-only", DBType: "mssql", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "1434", Access: "read"},
		{Name: "MSSQL read-write", DBType: "mssql", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "1434", Access: "write"},
		// Task 9.14 Oracle — port 1521 matching the oracle-test container.
		{Name: "Oracle read-only", DBType: "oracle", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "1521", Access: "read"},
		{Name: "Oracle read-write", DBType: "oracle", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "1521", Access: "write"},
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
	setSecretEnv(t)
	cfg, err := LoadControl(controlYAML)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", controlYAML, err)
	}
	wantAccess := map[string]string{
		"MySQL read-only":      "read",
		"MySQL read-write":     "write",
		"PostgreSQL read-only": "read",
		"MSSQL read-only":      "read",
		"MSSQL read-write":     "write",
		// Task 9.14 Oracle (dedicated proxy port :1522, backend :1521).
		"Oracle read-only":  "read",
		"Oracle read-write": "write",
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
	setSecretEnv(t)
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
	if len(got) != 7 {
		t.Fatalf("len = %d, want 7", len(got))
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
	setSecretEnv(t)
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
		// Phase 9 (Task 9.1): MSSQL — key format <dbtype>:<db_user>@<db_ip>:<db_port>
		// (Task 8.7), port 1434 matching the mssql-test container + presets.
		"mssql:ro_user@127.0.0.1:1434": "ro_pw",
		"mssql:rw_user@127.0.0.1:1434": "rw_pw",
		// Task 9.14 Oracle — port 1521 matching the oracle-test container.
		"oracle:ro_user@127.0.0.1:1521": "ro_pw",
		"oracle:rw_user@127.0.0.1:1521": "rw_pw",
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
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): fixture exercises
  # valkey sentinel mode, not JWT.
  jwt:
    enabled: false
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

// TestValkeySentinelAuth is the Task 7.7 loader probe: the sentinel
// credential parses from yaml (valkey.sentinel_password) and from the ZT_
// env name (viper convention: prefix ZT_ + dots→underscores →
// ZT_VALKEY_SENTINEL_PASSWORD), defaulting to "" when absent. NOTE (review
// 2026-08-17): sentinels have no ACL users — there is deliberately NO
// sentinel_username key (valkey-go would send AUTH <user> <pass>, which a
// requirepass-only sentinel rejects).
func TestValkeySentinelAuth(t *testing.T) {
	t.Run("defaults empty when absent", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): this fixture exercises
  # valkey sentinel auth, not JWT — no roles/secret needed.
  jwt:
    enabled: false
valkey:
  mode: sentinel
  master_name: "mymaster"
  sentinel_addrs: ["127.0.0.1:26379"]
`)
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if got := cfg.Valkey.SentinelPassword; got != "" {
			t.Errorf("SentinelPassword = %q, want \"\" (default)", got)
		}
	})

	t.Run("yaml key parses", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): fixture exercises
  # valkey sentinel auth, not JWT.
  jwt:
    enabled: false
valkey:
  mode: sentinel
  master_name: "mymaster"
  sentinel_addrs: ["127.0.0.1:26379"]
  sentinel_password: "sentpw-yaml"
`)
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if got := cfg.Valkey.SentinelPassword; got != "sentpw-yaml" {
			t.Errorf("SentinelPassword = %q, want %q", got, "sentpw-yaml")
		}
	})

	t.Run("env override: ZT_VALKEY_SENTINEL_PASSWORD", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): this fixture exercises
  # valkey sentinel auth, not JWT — no roles/secret needed.
  jwt:
    enabled: false
valkey:
  mode: sentinel
  master_name: "mymaster"
  sentinel_addrs: ["127.0.0.1:26379"]
`)
		t.Setenv("ZT_VALKEY_SENTINEL_PASSWORD", "env-sentpw")
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if got := cfg.Valkey.SentinelPassword; got != "env-sentpw" {
			t.Errorf("SentinelPassword = %q, want %q (ZT_VALKEY_SENTINEL_PASSWORD)", got, "env-sentpw")
		}
	})
}

// TestTokenMaxUsesEnvBinding (Task 9.12): api.token_max_uses is settable via
// the config file (default 1 = single-use) AND via both env names —
// ZT_API_TOKEN_MAX_USES (convention-derived) and the short alias
// ZT_TOKEN_MAX_USES (first-set wins, long name preferred).
func TestTokenMaxUsesEnvBinding(t *testing.T) {
	base := `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): fixture exercises
  # api.token_max_uses env binding, not JWT.
  jwt:
    enabled: false
`
	path := writeTempConfig(t, base)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(default) error: %v", err)
	}
	if cfg.TokenMaxUses != 1 {
		t.Errorf("default TokenMaxUses = %d, want 1 (single-use)", cfg.TokenMaxUses)
	}

	t.Setenv("ZT_API_TOKEN_MAX_USES", "7")
	cfg, err = LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(long env) error: %v", err)
	}
	if cfg.TokenMaxUses != 7 {
		t.Errorf("TokenMaxUses = %d, want 7 (ZT_API_TOKEN_MAX_USES)", cfg.TokenMaxUses)
	}

	// Short alias alone (long name unset): must map to the same key.
	orig, hadOrig := os.LookupEnv("ZT_API_TOKEN_MAX_USES")
	if err := os.Unsetenv("ZT_API_TOKEN_MAX_USES"); err != nil {
		t.Fatalf("Unsetenv(long): %v", err)
	}
	if hadOrig {
		defer os.Setenv("ZT_API_TOKEN_MAX_USES", orig)
	}
	t.Setenv("ZT_TOKEN_MAX_USES", "9")
	cfg, err = LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(short env) error: %v", err)
	}
	if cfg.TokenMaxUses != 9 {
		t.Errorf("TokenMaxUses = %d, want 9 (ZT_TOKEN_MAX_USES alias)", cfg.TokenMaxUses)
	}

	// Both set: the convention-derived long name wins (BindEnv order).
	t.Setenv("ZT_API_TOKEN_MAX_USES", "7")
	cfg, err = LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(both env) error: %v", err)
	}
	if cfg.TokenMaxUses != 7 {
		t.Errorf("TokenMaxUses = %d, want 7 (long name precedence)", cfg.TokenMaxUses)
	}

	// Empty long name is an EXPLICIT override (allow-empty philosophy): it
	// shadows the alias and yields 0 → issue path falls back to single-use.
	t.Setenv("ZT_API_TOKEN_MAX_USES", "")
	cfg, err = LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(empty long env) error: %v", err)
	}
	if cfg.TokenMaxUses != 0 {
		t.Errorf("TokenMaxUses = %d, want 0 (empty long env = explicit override)", cfg.TokenMaxUses)
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
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): fixture exercises the
  # TLS off-state, not JWT.
  jwt:
    enabled: false
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

// --- Task 9.7: audit.mysql block --------------------------------------------

// TestAuditMySQLDefaultsOff: the committed control.yaml keeps session audit
// DISABLED — no DB dependency unless enabled — with the dev-target defaults
// (host/port = mysql-test container, database zt_audit).
func TestAuditMySQLDefaultsOff(t *testing.T) {
	setSecretEnv(t)
	cfg, err := LoadControl(controlYAML)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", controlYAML, err)
	}
	if cfg.Audit.MySQL.Enabled {
		t.Error("Audit.MySQL.Enabled = true, want false (disabled by default)")
	}
	if got := cfg.Audit.MySQL.Database; got != "zt_audit" {
		t.Errorf("Audit.MySQL.Database = %q, want %q", got, "zt_audit")
	}
	if got := cfg.Audit.MySQL.Host; got != "127.0.0.1" {
		t.Errorf("Audit.MySQL.Host = %q, want %q", got, "127.0.0.1")
	}
	if got := cfg.Audit.MySQL.Port; got != "3307" {
		t.Errorf("Audit.MySQL.Port = %q, want %q", got, "3307")
	}
}

// TestAuditMySQLParsesEnabled: an enabled audit.mysql block lands on the
// struct field for field.
func TestAuditMySQLParsesEnabled(t *testing.T) {
	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): fixture exercises the
  # audit.mysql block, not JWT.
  jwt:
    enabled: false
audit:
  mysql:
    enabled: true
    host: "10.0.0.9"
    port: "3306"
    user: "audit_w"
    password: "s3cret"
    database: "zt_audit_prod"
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", path, err)
	}
	m := cfg.Audit.MySQL
	if !m.Enabled || m.Host != "10.0.0.9" || m.Port != "3306" || m.User != "audit_w" ||
		m.Password != "s3cret" || m.Database != "zt_audit_prod" {
		t.Errorf("Audit.MySQL = %+v, want enabled host=10.0.0.9 port=3306 user=audit_w database=zt_audit_prod", m)
	}
}

// TestAuditMySQLFailFasts: enabled with ANY required connection field
// explicitly EMPTY is a load error naming the field — an audit writer that
// cannot connect must never start silently. (Absent keys fall back to the
// committed defaults — host/port/database — so only explicit empty values
// trip the guard, which is exactly the fail-fast the dispatch demands.)
func TestAuditMySQLFailFasts(t *testing.T) {
	fields := []string{"host", "port", "user", "password", "database"}
	for _, tc := range fields {
		t.Run(tc, func(t *testing.T) {
			lines := []string{
				"audit:",
				"  mysql:",
				"    enabled: true",
				`    host: "127.0.0.1"`,
				`    port: "3307"`,
				`    user: "root"`,
				`    password: "root_pw"`,
				`    database: "zt_audit"`,
			}
			for i, l := range lines {
				if strings.HasPrefix(strings.TrimSpace(l), tc+":") {
					lines[i] = "    " + tc + ": \"\""
				}
			}
			path := writeTempConfig(t, strings.Join(lines, "\n")+"\n")
			_, err := LoadControl(path)
			if err == nil {
				t.Fatalf("LoadControl: want error when audit.mysql.%s is empty, got nil", tc)
			}
			if !strings.Contains(err.Error(), "audit.mysql."+tc) {
				t.Errorf("error %q missing the audit.mysql.%s hint", err.Error(), tc)
			}
		})
	}
}

// TestAuditMySQLEnvOverride: the ZT_AUDIT_MYSQL_* env names override the file
// (viper convention: prefix ZT_, dots → underscores).
func TestAuditMySQLEnvOverride(t *testing.T) {
	t.Setenv("ZT_AUDIT_MYSQL_ENABLED", "true")
	t.Setenv("ZT_AUDIT_MYSQL_HOST", "env-host")
	t.Setenv("ZT_AUDIT_MYSQL_PORT", "3399")
	t.Setenv("ZT_AUDIT_MYSQL_USER", "env-user")
	t.Setenv("ZT_AUDIT_MYSQL_PASSWORD", "env-pw")
	t.Setenv("ZT_AUDIT_MYSQL_DATABASE", "env_audit")
	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): fixture exercises the
  # audit.mysql env override, not JWT.
  jwt:
    enabled: false
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", path, err)
	}
	m := cfg.Audit.MySQL
	if !m.Enabled || m.Host != "env-host" || m.Port != "3399" || m.User != "env-user" ||
		m.Password != "env-pw" || m.Database != "env_audit" {
		t.Errorf("Audit.MySQL = %+v, want env-overridden block", m)
	}
}

// TestAuditMySQLEnabledMissingEnvFailsFast: enabled via env alone (no file
// block) with the required fields unset is a load error, not a silent start.
func TestAuditMySQLEnabledMissingEnvFailsFast(t *testing.T) {
	t.Setenv("ZT_AUDIT_MYSQL_ENABLED", "true")
	path := writeTempConfig(t, `
http:
  addr: ":8080"
`)
	_, err := LoadControl(path)
	if err == nil {
		t.Fatal("LoadControl: want error for enabled audit without credentials, got nil")
	}
	if !strings.Contains(err.Error(), "audit.mysql.user") {
		t.Errorf("error %q missing the audit.mysql.user hint", err.Error())
	}
}

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

// --- Task 9.8 metrics block -------------------------------------------------

// TestMetricsDisabledByDefault: metrics.enabled defaults to false (zero
// overhead — the proxies' metrics wrapper stays nil); listen/path defaults
// are the committed 0.0.0.0:9464 /metrics.
func TestMetricsDisabledByDefault(t *testing.T) {
	setSecretEnv(t)
	cfg, err := LoadData(dataYAML)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", dataYAML, err)
	}
	if cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled = true, want false (disabled by default)")
	}
	if cfg.Metrics.Listen != "0.0.0.0:9464" {
		t.Errorf("Metrics.Listen = %q, want %q", cfg.Metrics.Listen, "0.0.0.0:9464")
	}
	if cfg.Metrics.Path != "/metrics" {
		t.Errorf("Metrics.Path = %q, want %q", cfg.Metrics.Path, "/metrics")
	}
}

// TestMetricsParsesEnabled: an enabled metrics block (file values, not
// defaults) lands on the struct field for field.
func TestMetricsParsesEnabled(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
metrics:
  enabled: true
  listen: "127.0.0.1:9464"
  path: "/prom"
`)
	cfg, err := LoadData(path)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", path, err)
	}
	m := cfg.Metrics
	if !m.Enabled || m.Listen != "127.0.0.1:9464" || m.Path != "/prom" {
		t.Errorf("Metrics = %+v, want enabled=true listen=127.0.0.1:9464 path=/prom", m)
	}
}

// TestMetricsEnvOverride: ZT_METRICS_ENABLED/_LISTEN/_PATH override the
// file (viper convention: prefix ZT_, dots → underscores).
func TestMetricsEnvOverride(t *testing.T) {
	t.Setenv("ZT_METRICS_ENABLED", "true")
	t.Setenv("ZT_METRICS_LISTEN", "10.1.2.3:9999")
	t.Setenv("ZT_METRICS_PATH", "/scrape")
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
`)
	cfg, err := LoadData(path)
	if err != nil {
		t.Fatalf("LoadData(%q) error: %v", path, err)
	}
	m := cfg.Metrics
	if !m.Enabled || m.Listen != "10.1.2.3:9999" || m.Path != "/scrape" {
		t.Errorf("Metrics = %+v, want enabled=true listen=10.1.2.3:9999 path=/scrape", m)
	}
}

// TestMetricsFailFastBadListen: enabled=true with a malformed metrics.listen
// is a load error naming the field — a plane that cannot serve its scrape
// endpoint must never start silently.
func TestMetricsFailFastBadListen(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
metrics:
  enabled: true
  listen: "not-a-host-port"
`)
	_, err := LoadData(path)
	if err == nil {
		t.Fatal("LoadData: want error for bad metrics.listen, got nil")
	}
	if !strings.Contains(err.Error(), "metrics.listen") {
		t.Errorf("error %q missing the metrics.listen hint", err.Error())
	}
}

// TestMetricsFailFastEmptyPath: enabled=true with an empty metrics.path is a
// load error.
func TestMetricsFailFastEmptyPath(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
metrics:
  enabled: true
  path: ""
`)
	_, err := LoadData(path)
	if err == nil {
		t.Fatal("LoadData: want error for empty metrics.path, got nil")
	}
	if !strings.Contains(err.Error(), "metrics.path") {
		t.Errorf("error %q missing the metrics.path hint", err.Error())
	}
}

// TestMetricsDisabledSkipsValidation: disabled (the default) tolerates a
// malformed listen — the block is inert until enabled.
func TestMetricsDisabledSkipsValidation(t *testing.T) {
	path := writeTempConfig(t, `
listen:
  addr: ":3306"
metrics:
  enabled: false
  listen: "garbage"
`)
	if _, err := LoadData(path); err != nil {
		t.Fatalf("LoadData(%q) error: %v, want nil (disabled block inert)", path, err)
	}
}

// TestLoadControlAuthFailFast (review round 3) guards the control-plane auth
// fail-fast: AutomaticEnv is set, so an EMPTY env override (e.g.
// ZT_AUTH_PASSWORD="") silently overrides the defaults map and would leave
// the plane with an empty password. An empty auth.username/auth.password or
// a non-positive api.token_ttl_seconds is a load error naming the field —
// a plane with unguessable-empty credentials or an instant-expiry token
// must never start silently.
func TestLoadControlAuthFailFast(t *testing.T) {
	const valid = `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    enabled: true
    login_enabled: true
    secret: "s3cret"
valkey:
  mode: direct
  addr: "127.0.0.1:6379"
`

	t.Run("valid config loads", func(t *testing.T) {
		cfg, err := LoadControl(writeTempConfig(t, valid))
		if err != nil {
			t.Fatalf("LoadControl(valid) error: %v", err)
		}
		if cfg.AuthUser != "admin" || cfg.AuthPassword != "secret" {
			t.Errorf("AuthUser/AuthPassword = %q/%q, want admin/secret", cfg.AuthUser, cfg.AuthPassword)
		}
		if cfg.TokenTTL != 300 {
			t.Errorf("TokenTTL = %d, want 300 (default)", cfg.TokenTTL)
		}
	})

	t.Run("empty env override fails fast", func(t *testing.T) {
		// The file has a good password; the empty env override wins (viper
		// AutomaticEnv) and must be rejected, not silently accepted.
		t.Setenv("ZT_AUTH_PASSWORD", "")
		_, err := LoadControl(writeTempConfig(t, valid))
		if err == nil {
			t.Fatal("LoadControl: want error when ZT_AUTH_PASSWORD is empty, got nil")
		}
		if !strings.Contains(err.Error(), "auth.password") {
			t.Errorf("error %q missing the auth.password hint", err.Error())
		}
	})

	t.Run("empty username env override fails fast", func(t *testing.T) {
		t.Setenv("ZT_AUTH_USERNAME", "")
		_, err := LoadControl(writeTempConfig(t, valid))
		if err == nil {
			t.Fatal("LoadControl: want error when ZT_AUTH_USERNAME is empty, got nil")
		}
		if !strings.Contains(err.Error(), "auth.username") {
			t.Errorf("error %q missing the auth.username hint", err.Error())
		}
	})

	t.Run("empty password in file fails fast", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: ""
  role: "maker"
  jwt:
    enabled: true
    login_enabled: true
    secret: "s3cret"
`)
		_, err := LoadControl(path)
		if err == nil {
			t.Fatal("LoadControl: want error for empty auth.password in file, got nil")
		}
		if !strings.Contains(err.Error(), "auth.password") {
			t.Errorf("error %q missing the auth.password hint", err.Error())
		}
	})

	t.Run("missing auth block fails fast", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
`)
		_, err := LoadControl(path)
		if err == nil {
			t.Fatal("LoadControl: want error when auth block is absent, got nil")
		}
	})

	t.Run("ttl zero fails fast", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
api:
  token_ttl_seconds: 0
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    enabled: true
    login_enabled: true
    secret: "s3cret"
`)
		_, err := LoadControl(path)
		if err == nil {
			t.Fatal("LoadControl: want error for token_ttl_seconds=0, got nil")
		}
		if !strings.Contains(err.Error(), "token_ttl_seconds") {
			t.Errorf("error %q missing the token_ttl_seconds hint", err.Error())
		}
	})

	t.Run("ttl negative fails fast", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
api:
  token_ttl_seconds: -5
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    enabled: true
    login_enabled: true
    secret: "s3cret"
`)
		_, err := LoadControl(path)
		if err == nil {
			t.Fatal("LoadControl: want error for token_ttl_seconds=-5, got nil")
		}
		if !strings.Contains(err.Error(), "token_ttl_seconds") {
			t.Errorf("error %q missing the token_ttl_seconds hint", err.Error())
		}
	})
}

// TestSessionKnobsDefaults (Task 9.13): the control defaults (single-use
// mode, infinite session TTL) and the data defaults (idle 1800, max-lifetime
// off, revoke poll 1s) must hold with a bare config file.
func TestSessionKnobsDefaults(t *testing.T) {
	ctlPath := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  # jwt disabled (legacy cookie mode, JWT Task 2): fixture exercises
  # session-token defaults, not JWT.
  jwt:
    enabled: false
`)
	cfg, err := LoadControl(ctlPath)
	if err != nil {
		t.Fatalf("LoadControl: %v", err)
	}
	if cfg.TokenMode != "single-use" {
		t.Errorf("default TokenMode = %q, want single-use", cfg.TokenMode)
	}
	if cfg.SessionTokenTTL != 0 {
		t.Errorf("default SessionTokenTTL = %d, want 0 (infinite)", cfg.SessionTokenTTL)
	}

	dataPath := writeTempConfig(t, `
listen:
  addr: ":3306"
`)
	dcfg, err := LoadData(dataPath)
	if err != nil {
		t.Fatalf("LoadData: %v", err)
	}
	if dcfg.SessionIdleSeconds != 1800 {
		t.Errorf("default SessionIdleSeconds = %d, want 1800", dcfg.SessionIdleSeconds)
	}
	if dcfg.SessionMaxLifetimeSeconds != 0 {
		t.Errorf("default SessionMaxLifetimeSeconds = %d, want 0 (off)", dcfg.SessionMaxLifetimeSeconds)
	}
	if dcfg.RevokePollSeconds != 1 {
		t.Errorf("default RevokePollSeconds = %d, want 1", dcfg.RevokePollSeconds)
	}
}

// TestAuthUsersParsing (Task 9.13 + JWT Task 2): the optional auth.users
// list parses, ${VAR} password placeholders resolve from the environment,
// and an empty password in ANY listed user fails fast (never a silently
// empty credential). Each entry carries its own role ("maker"|"checker"),
// required when auth.jwt.login_enabled is true.
func TestAuthUsersParsing(t *testing.T) {
	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
  users:
    - username: "checker"
      password: "${ZT_AUTH_CHECKER_PASSWORD}"
      role: "checker"
  jwt:
    enabled: true
    login_enabled: true
    secret: "s3cret"
`)
	t.Setenv("ZT_AUTH_CHECKER_PASSWORD", "checker-pw")
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl: %v", err)
	}
	if len(cfg.AuthUsers) != 1 || cfg.AuthUsers[0].Username != "checker" || cfg.AuthUsers[0].Password != "checker-pw" {
		t.Fatalf("AuthUsers = %+v, want [checker/checker-pw]", cfg.AuthUsers)
	}
	if got := cfg.AuthUsers[0].Role; got != "checker" {
		t.Errorf("AuthUsers[0].Role = %q, want %q", got, "checker")
	}
	// The primary pair is untouched by the list.
	if cfg.AuthUser != "admin" || cfg.AuthPassword != "secret" {
		t.Fatalf("primary auth = %q/%q, want admin/secret", cfg.AuthUser, cfg.AuthPassword)
	}
	if got := cfg.AuthRole; got != "maker" {
		t.Errorf("AuthRole = %q, want %q", got, "maker")
	}

	// Missing env for a listed user → load error, never an empty password.
	t.Setenv("ZT_AUTH_CHECKER_PASSWORD", "")
	if _, err := LoadControl(path); err == nil {
		t.Fatal("LoadControl with empty checker password succeeded, want fail-fast")
	}
	// Unset env → same fail-fast.
	if err := os.Unsetenv("ZT_AUTH_CHECKER_PASSWORD"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if _, err := LoadControl(path); err == nil {
		t.Fatal("LoadControl with unset checker password succeeded, want fail-fast")
	}
}

// TestJWTRolesValidation (JWT conversion Task 2) guards the new auth
// shape: the auth.jwt.* block, per-principal roles and allow_maker_watch.
// Rules under test:
//   - jwt.enabled ABSENT = true (JWT is the mode); an explicit false is
//     allowed and skips every new check (legacy cookie mode).
//   - login_enabled=true: jwt.secret REQUIRED (${VAR}-expandable),
//     username/password required (unchanged), EVERY principal (primary +
//     each auth.users entry) MUST declare role "maker"|"checker" — no
//     silent default (an un-role'd account would be a superuser).
//   - login_enabled=false (external-only): username/password + secret NOT
//     required; declared role VALUES are still validated.
func TestJWTRolesValidation(t *testing.T) {
	// header + primary are shared by every login-on case below; body
	// varies per case (the full yaml is assembled per entry).
	const header = `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
`
	secret := `    secret: "s3cret-0123456789abcdefghijklmnopqrstuv"`
	users := `  users:
    - username: "checker"
      password: "checker-pw"
      role: "checker"
`
	jwtOn := func(inner string) string {
		return "  jwt:\n    enabled: true\n    login_enabled: true\n" + inner + "\n"
	}

	tests := []struct {
		name    string
		yaml    string
		env     map[string]string
		wantErr string // substring the error must name; "" = must load
	}{
		{
			name: "login on: secret + roles load (maker/checker)",
			yaml: header + users + jwtOn(secret),
		},
		{
			name: "login on: ${ZT_JWT_SECRET} expands from env",
			yaml: header + users + jwtOn(`    secret: "${ZT_JWT_SECRET}"`),
			env:  map[string]string{"ZT_JWT_SECRET": "env-jwt-secret-0123456789abcdefghijklmnopqrstuv"},
		},
		{
			name:    "login on: secret placeholder with UNSET env fails fast",
			yaml:    header + users + jwtOn(`    secret: "${ZT_JWT_SECRET}"`),
			wantErr: "ZT_JWT_SECRET",
		},
		{
			name:    "login on: empty secret refuses to start",
			yaml:    header + users + jwtOn(`    secret: ""`),
			wantErr: "auth.jwt.secret",
		},
		{
			name:    "login on: missing secret key refuses to start",
			yaml:    header + users + jwtOn(""),
			wantErr: "auth.jwt.secret",
		},
		{
			name: "login on: primary role missing → error names auth.role",
			yaml: `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
` + users + jwtOn(secret),
			wantErr: "auth.role",
		},
		{
			name: "login on: primary role bad value → error names auth.role",
			yaml: `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "superuser"
` + users + jwtOn(secret),
			wantErr: "auth.role",
		},
		{
			name: "login on: users entry role missing → error names the entry",
			yaml: header + `  users:
    - username: "checker"
      password: "checker-pw"
` + jwtOn(secret),
			wantErr: "auth.users[0].role (checker)",
		},
		{
			name: "login on: users entry role bad value → error names the entry",
			yaml: header + `  users:
    - username: "checker"
      password: "checker-pw"
      role: "boss"
` + jwtOn(secret),
			wantErr: "auth.users[0].role (checker)",
		},
		{
			name: "login off: external-only without secret/username/password/roles loads",
			yaml: `
http:
  addr: ":8080"
auth:
  jwt:
    enabled: true
    login_enabled: false
    audience: "zt-api"
    # Phase 2 (Task 1): external-only mode REQUIRES >=1 external issuer
    # (else nothing can authenticate) — the fixture carries a valid one.
    external_issuers:
      - name: "other-app"
        iss: "https://other-app.example"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
`,
		},
		{
			name: "login off: declared bad primary role still rejected",
			yaml: `
http:
  addr: ":8080"
auth:
  role: "root"
  jwt:
    enabled: true
    login_enabled: false
    audience: "zt-api"
    external_issuers:
      - name: "other-app"
        iss: "https://other-app.example"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
`,
			wantErr: "auth.role",
		},
		{
			name: "login off: declared bad users role still rejected",
			yaml: `
http:
  addr: ":8080"
auth:
  users:
    - username: "checker"
      password: "checker-pw"
      role: "root"
  jwt:
    enabled: true
    login_enabled: false
    audience: "zt-api"
    external_issuers:
      - name: "other-app"
        iss: "https://other-app.example"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
`,
			wantErr: "auth.users[0].role (checker)",
		},
		{
			name: "login off: declared valid roles load",
			yaml: `
http:
  addr: ":8080"
auth:
  role: "maker"
  users:
    - username: "checker"
      password: "checker-pw"
      role: "checker"
  jwt:
    enabled: true
    login_enabled: false
    audience: "zt-api"
    external_issuers:
      - name: "other-app"
        iss: "https://other-app.example"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
`,
		},
		{
			name: "legacy: jwt.enabled false skips roles/secret (creds still required)",
			yaml: `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
`,
		},
		{
			name: "legacy: jwt.enabled false still requires the primary password",
			yaml: `
http:
  addr: ":8080"
auth:
  username: admin
  password: ""
  jwt:
    enabled: false
`,
			wantErr: "auth.password",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			path := writeTempConfig(t, tc.yaml)
			cfg, err := LoadControl(path)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadControl succeeded, want error naming %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not name %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadControl error: %v", err)
			}
			// Spot-check the parsed shape on login-on happy paths.
			if cfg.JWT.Enabled && cfg.JWT.LoginEnabled && cfg.AuthUser != "" {
				if cfg.AuthRole != "maker" {
					t.Errorf("AuthRole = %q, want maker", cfg.AuthRole)
				}
				if len(cfg.AuthUsers) == 1 && cfg.AuthUsers[0].Role != "checker" {
					t.Errorf("AuthUsers[0].Role = %q, want checker", cfg.AuthUsers[0].Role)
				}
			}
		})
	}
}

// TestJWTRolesDefaults (JWT conversion Task 2): with a jwt block present
// but enabled/ttl_seconds omitted, jwt.enabled defaults TRUE and
// jwt.ttl_seconds defaults 28800 (the new auth expiry). An entirely
// ABSENT jwt block also means JWT mode ON (login on by default) — an
// unmigrated config therefore fails fast demanding the secret instead of
// silently booting with the old cookie semantics.
func TestJWTRolesDefaults(t *testing.T) {
	t.Run("jwt block without enabled/ttl defaults to on + 28800", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    login_enabled: true
    secret: "s3cret-0123456789abcdefghijklmnopqrstuv"
`)
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl: %v", err)
		}
		if !cfg.JWT.Enabled {
			t.Error("JWT.Enabled = false, want true (absent defaults to true)")
		}
		if !cfg.JWT.LoginEnabled {
			t.Error("JWT.LoginEnabled = false, want true (absent defaults to true)")
		}
		if got := cfg.JWT.TTLSeconds; got != 28800 {
			t.Errorf("JWT.TTLSeconds = %d, want 28800 (default)", got)
		}
	})

	t.Run("absent jwt block = JWT mode on → unmigrated config fails fast", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
`)
		_, err := LoadControl(path)
		if err == nil {
			t.Fatal("LoadControl: want error for an unmigrated config (no jwt block), got nil")
		}
		if !strings.Contains(err.Error(), "auth.jwt.secret") {
			t.Errorf("error %q missing the auth.jwt.secret hint", err.Error())
		}
	})
}

// TestJWTAllowedOriginsLoad (Task 9): auth.jwt.allowed_origins is the
// cross-origin host allowlist for the checker WebSocket upgrade
// (websocket.Accept OriginPatterns). A yaml list must land on
// cfg.JWT.AllowedOrigins verbatim; an ABSENT key must load as EMPTY — the
// same-origin-only default (today's behavior), never nil-panicking
// consumers (websocket.Accept treats a nil/empty list identically). Phase 2
// Task 3 final review: every entry is a path.Match GLOB shared with REST
// CORS, so a MALFORMED glob (which cors.go would swallow as a silent
// never-match while the WS vendor 403s the request) is a load error naming
// the entry.
func TestJWTAllowedOriginsLoad(t *testing.T) {
	t.Run("yaml list populates the allowlist", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    login_enabled: true
    secret: "s3cret-0123456789abcdefghijklmnopqrstuv"
    allowed_origins:
      - "http://checker.example.com"
      - "https://*.zt-internal.example"
`)
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl: %v", err)
		}
		want := []string{"http://checker.example.com", "https://*.zt-internal.example"}
		got := cfg.JWT.AllowedOrigins
		if len(got) != len(want) {
			t.Fatalf("JWT.AllowedOrigins = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("JWT.AllowedOrigins[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("absent key loads empty (same-origin-only default)", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    login_enabled: true
    secret: "s3cret-0123456789abcdefghijklmnopqrstuv"
`)
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl: %v", err)
		}
		if len(cfg.JWT.AllowedOrigins) != 0 {
			t.Errorf("JWT.AllowedOrigins = %v, want empty (same-origin only)", cfg.JWT.AllowedOrigins)
		}
	})

	t.Run("malformed glob entry fails fast naming the entry", func(t *testing.T) {
		path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    login_enabled: true
    secret: "s3cret-0123456789abcdefghijklmnopqrstuv"
    allowed_origins:
      - "https://checker.example.com"
      - "https://[x"
`)
		_, err := LoadControl(path)
		if err == nil {
			t.Fatal("LoadControl succeeded, want an error for the malformed glob \"https://[x\"")
		}
		if !strings.Contains(err.Error(), "allowed_origins[1]") {
			t.Errorf("error %q does not name allowed_origins[1]", err.Error())
		}
	})
}

// TestJWTExternalIssuers (Phase 2 Task 1) guards the new
// auth.jwt.external_issuers schema: trusted THIRD-PARTY HS256 issuers, each
// with its own shared secret and an OPTIONAL claims mapping (subject/role
// claim names + role-value aliases). Rules under test:
//   - name non-empty + unique; iss non-empty + unique across the list (a
//     duplicated iss would resolve first-match, 401'ing the second issuer's
//     tokens forever) + must NOT equal the local auth.jwt.issuer
//     (shadowing); secret REQUIRED and ${VAR}-expandable (unset env = load
//     error, never an empty key).
//   - audience OPTIONAL per issuer — empty inherits the top-level
//     auth.jwt.audience at VALIDATION time; an entry that resolves EMPTY
//     (no pin AND no top-level audience) is a load error — its tokens could
//     never pass aud verification.
//   - require_jti ABSENT (nil) defaults TRUE; explicit false stays false.
//   - role_aliases VALUES must be "maker"|"checker"; keys non-empty.
//   - login_enabled=false (external-only) now REQUIRES >=1 external issuer
//     (with zero issuers NOTHING can authenticate).
//   - claims.subject/role zero values are LEFT zero (downstream applies the
//     "sub"/"role"/identity defaults) — only role_aliases are validated here.
func TestJWTExternalIssuers(t *testing.T) {
	// header: login-ON control config — local secret literal (no env
	// needed). Issuer-list blocks are spliced on below the jwt block.
	const header = `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    enabled: true
    login_enabled: true
    issuer: "zerotrust-proxy"
    audience: "zt-api"
    secret: "s3cret-0123456789abcdefghijklmnopqrstuv"
`
	// loginOffBase: external-only control config (no creds/secret needed).
	const loginOffBase = `
http:
  addr: ":8080"
auth:
  jwt:
    enabled: true
    login_enabled: false
    issuer: "zerotrust-proxy"
    audience: "zt-api"
`
	// noTopAudBase: login-ON base WITHOUT the top-level auth.jwt.audience —
	// an external entry that does not pin its own audience then resolves
	// EMPTY (the M2 fail-fast case).
	const noTopAudBase = `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  role: "maker"
  jwt:
    enabled: true
    login_enabled: true
    issuer: "zerotrust-proxy"
    secret: "s3cret-0123456789abcdefghijklmnopqrstuv"
`
	// ext wraps an entry list at the jwt-child indent (4 spaces).
	const ext = "\n    external_issuers:\n"

	one := `      - name: "other-app"
        iss: "https://other-app.example"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
`
	full := `      - name: "other-app"
        iss: "https://other-app.example"
        audience: "zt-other"
        secret: "${ZT_OTHERAPP_JWT_SECRET}"
        require_jti: false
        claims:
          subject: "preferred_username"
          role: "permission"
          role_aliases:
            "svc_maker": "maker"
            "svc_checker": "checker"
`
	two := `      - name: "app-a"
        iss: "https://app-a.example"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
      - name: "app-b"
        iss: "https://app-b.example"
        audience: "zt-b"
        secret: "b-secret-0123456789abcdefghijklmnopqrstuv"
`
	dupNames := `      - name: "other-app"
        iss: "https://app-a.example"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
      - name: "other-app"
        iss: "https://app-b.example"
        secret: "b-secret-0123456789abcdefghijklmnopqrstuv"
`
	dupIss := `      - name: "app-a"
        iss: "https://same-iss.example"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
      - name: "app-b"
        iss: "https://same-iss.example"
        secret: "b-secret-0123456789abcdefghijklmnopqrstuv"
`
	emptyName := `      - name: ""
        iss: "https://app-a.example"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
`
	emptyIss := `      - name: "other-app"
        iss: ""
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
`
	missingSecret := `      - name: "other-app"
        iss: "https://other-app.example"
`
	envSecret := `      - name: "other-app"
        iss: "https://other-app.example"
        secret: "${ZT_OTHERAPP_JWT_SECRET}"
`
	shadowIss := `      - name: "other-app"
        iss: "zerotrust-proxy"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
`
	aliasBadValue := `      - name: "other-app"
        iss: "https://other-app.example"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
        claims:
          role_aliases:
            "admin": "root"
`
	aliasEmptyKey := `      - name: "other-app"
        iss: "https://other-app.example"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
        claims:
          role_aliases:
            "": "maker"
`
	pinnedAud := `      - name: "other-app"
        iss: "https://other-app.example"
        audience: "zt-other"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
`
	// Phase 2b Task 1 relaxation fixtures (the other app's real JWT shape
	// has NO iss/aud/jti claims — require_iss/require_aud opt out per
	// issuer). noIssRelaxed omits the iss KEY entirely; emptyIssRelaxed
	// declares it empty — both must resolve identically.
	noIssRelaxed := `      - name: "other-app"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
        require_iss: false
`
	emptyIssRelaxed := `      - name: "other-app"
        iss: ""
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
        require_iss: false
`
	dupIssRelaxed := `      - name: "app-a"
        iss: "https://same-iss.example"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
      - name: "app-b"
        iss: "https://same-iss.example"
        secret: "b-secret-0123456789abcdefghijklmnopqrstuv"
        require_iss: false
`
	shadowIssRelaxed := `      - name: "other-app"
        iss: "zerotrust-proxy"
        secret: "a-secret-0123456789abcdefghijklmnopqrstuv"
        require_iss: false
`
	// noAudRelaxed: NO audience pin, NO top-level audience, aud not
	// enforced — the resolved-empty audience must NOT be a load error.
	noAudRelaxed := `      - name: "other-app"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
        require_iss: false
        require_aud: false
`
	audRelaxed := `      - name: "other-app"
        iss: "https://other-app.example"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
        require_aud: false
`
	// realShape: the other app's actual config — no iss/aud/jti lines,
	// claims map username/role(Maker|Checker)/sessionId.
	realShape := `      - name: "other-app-real"
        secret: "ext-secret-0123456789abcdefghijklmnopqrstuv"
        require_iss: false
        require_aud: false
        require_jti: false
        claims:
          subject: "username"
          role: "role"
          session_id: "sessionId"
          role_aliases:
            "Maker": "maker"
            "Checker": "checker"
`

	tests := []struct {
		name    string
		yaml    string
		env     map[string]string
		unset   string // env var to REMOVE before loading
		wantErr string // substring the error must name; "" = must load
	}{
		{
			name: "valid single external issuer (minimal) loads",
			yaml: header + ext + one,
		},
		{
			name: "valid single external issuer (full claims mapping) loads",
			yaml: header + ext + full,
			env:  map[string]string{"ZT_OTHERAPP_JWT_SECRET": "other-app-secret-0123456789abcdefghijklmnopqrstuv"},
		},
		{
			name: "two external issuers load",
			yaml: header + ext + two,
		},
		{
			name:    "empty name fails fast",
			yaml:    header + ext + emptyName,
			wantErr: "external_issuers[0].name",
		},
		{
			name:    "duplicate name fails fast naming both entries",
			yaml:    header + ext + dupNames,
			wantErr: "external_issuers[1].name",
		},
		{
			name:    "duplicate iss across entries fails fast naming the later entry",
			yaml:    header + ext + dupIss,
			wantErr: "external_issuers[1].iss",
		},
		{
			name:    "empty iss fails fast",
			yaml:    header + ext + emptyIss,
			wantErr: "external_issuers[0].iss",
		},
		{
			name:    "missing secret fails fast",
			yaml:    header + ext + missingSecret,
			wantErr: "external_issuers[0].secret",
		},
		{
			name:    "iss shadowing the local issuer fails fast",
			yaml:    header + ext + shadowIss,
			wantErr: "shadow",
		},
		{
			name:    "role alias to an invalid role fails fast",
			yaml:    header + ext + aliasBadValue,
			wantErr: `role_aliases["admin"]`,
		},
		{
			name:    "role alias with an empty key fails fast",
			yaml:    header + ext + aliasEmptyKey,
			wantErr: "empty key",
		},
		{
			name:    "secret placeholder with UNSET env fails fast",
			yaml:    header + ext + envSecret,
			unset:   "ZT_OTHERAPP_JWT_SECRET",
			wantErr: "ZT_OTHERAPP_JWT_SECRET",
		},
		{
			name:    "login off: ZERO external issuers fails fast",
			yaml:    loginOffBase,
			wantErr: "external_issuers",
		},
		{
			name:    "external issuer resolving to an EMPTY audience fails fast (no per-entry pin, no top-level audience)",
			yaml:    noTopAudBase + ext + one,
			wantErr: "external_issuers[0].audience",
		},
		{
			name: "external issuer with NO top-level audience but its OWN audience pin loads",
			yaml: noTopAudBase + ext + pinnedAud,
		},
		// Phase 2b relaxation cases (the other app's JWT has NO iss/aud/jti).
		{
			name: "require_iss absent + empty iss fails fast (strict default)",
			yaml: header + ext + emptyIss,
			// emptyIss fixture has NO require_iss → iss still required.
			wantErr: "external_issuers[0].iss",
		},
		{
			name: "require_iss false + iss KEY omitted loads (iss-less issuer)",
			yaml: header + ext + noIssRelaxed,
		},
		{
			name: "require_iss false + declared-empty iss loads identically",
			yaml: header + ext + emptyIssRelaxed,
		},
		{
			name:    "require_iss false entry carrying a DUPLICATE iss still fails fast",
			yaml:    header + ext + dupIssRelaxed,
			wantErr: "external_issuers[1].iss",
		},
		{
			name:    "require_iss false entry with iss == local issuer still fails fast",
			yaml:    header + ext + shadowIssRelaxed,
			wantErr: "shadow",
		},
		{
			name: "require_aud false + NO audience anywhere loads (aud not asserted)",
			yaml: noTopAudBase + ext + noAudRelaxed,
		},
		{
			name: "require_aud false + audience present loads",
			yaml: noTopAudBase + ext + audRelaxed,
		},
		{
			name: "REAL other-app shape loads (no iss/aud/jti; username role Maker/Checker sessionId)",
			yaml: header + ext + realShape,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if tc.unset != "" {
				if err := os.Unsetenv(tc.unset); err != nil {
					t.Fatalf("unsetenv %s: %v", tc.unset, err)
				}
			}
			_, err := LoadControl(writeTempConfig(t, tc.yaml))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadControl succeeded, want error naming %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not name %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadControl error: %v", err)
			}
		})
	}

	// Structural assertions on the RESOLVED config (defaults applied at
	// validation time, mutation on the loaded struct).
	t.Run("resolved: audience inherits top-level, require_jti defaults true, claims zero", func(t *testing.T) {
		cfg, err := LoadControl(writeTempConfig(t, header+ext+one))
		if err != nil {
			t.Fatalf("LoadControl: %v", err)
		}
		issuers := cfg.JWT.ExternalIssuers
		if len(issuers) != 1 {
			t.Fatalf("len(ExternalIssuers) = %d, want 1", len(issuers))
		}
		e := issuers[0]
		if e.Name != "other-app" || e.Iss != "https://other-app.example" {
			t.Errorf("Name/Iss = %q/%q, want other-app/https://other-app.example", e.Name, e.Iss)
		}
		if e.Audience != "zt-api" {
			t.Errorf("Audience = %q, want top-level \"zt-api\" (inherited)", e.Audience)
		}
		if e.Secret != "ext-secret-0123456789abcdefghijklmnopqrstuv" {
			t.Errorf("Secret = %q, want the literal secret (no placeholder to expand)", e.Secret)
		}
		if e.RequireJTI == nil {
			t.Error("RequireJTI = nil, want default true (absent field)")
		} else if !*e.RequireJTI {
			t.Error("RequireJTI = false, want default true when the field is absent")
		}
		if e.RequireISS == nil {
			t.Error("RequireISS = nil, want default true (absent field)")
		} else if !*e.RequireISS {
			t.Error("RequireISS = false, want default true when the field is absent")
		}
		if e.RequireAud == nil {
			t.Error("RequireAud = nil, want default true (absent field)")
		} else if !*e.RequireAud {
			t.Error("RequireAud = false, want default true when the field is absent")
		}
		if e.Claims.Subject != "" || e.Claims.Role != "" || len(e.Claims.RoleAliases) != 0 || e.Claims.SessionID != "" {
			t.Errorf("Claims = %+v, want zero values (downstream applies sub/role/identity defaults)", e.Claims)
		}
	})

	t.Run("resolved: explicit audience kept, require_jti false stays false, claims land", func(t *testing.T) {
		t.Setenv("ZT_OTHERAPP_JWT_SECRET", "other-app-secret-0123456789abcdefghijklmnopqrstuv")
		cfg, err := LoadControl(writeTempConfig(t, header+ext+full))
		if err != nil {
			t.Fatalf("LoadControl: %v", err)
		}
		e := cfg.JWT.ExternalIssuers[0]
		if e.Audience != "zt-other" {
			t.Errorf("Audience = %q, want explicit \"zt-other\" (not the top-level default)", e.Audience)
		}
		if e.RequireJTI == nil {
			t.Error("RequireJTI = nil, want explicit false")
		} else if *e.RequireJTI {
			t.Error("RequireJTI = true, want explicit false preserved")
		}
		if e.Secret != "other-app-secret-0123456789abcdefghijklmnopqrstuv" {
			t.Errorf("Secret = %q, want the expanded ZT_OTHERAPP_JWT_SECRET", e.Secret)
		}
		if e.Claims.Subject != "preferred_username" || e.Claims.Role != "permission" {
			t.Errorf("Claims.Subject/Role = %q/%q, want preferred_username/permission", e.Claims.Subject, e.Claims.Role)
		}
		if len(e.Claims.RoleAliases) != 2 || e.Claims.RoleAliases["svc_maker"] != "maker" || e.Claims.RoleAliases["svc_checker"] != "checker" {
			t.Errorf("RoleAliases = %v, want {svc_maker:maker svc_checker:checker}", e.Claims.RoleAliases)
		}
	})

	t.Run("resolved: relaxed flags false stay false, session_id claim lands", func(t *testing.T) {
		cfg, err := LoadControl(writeTempConfig(t, header+ext+realShape))
		if err != nil {
			t.Fatalf("LoadControl: %v", err)
		}
		e := cfg.JWT.ExternalIssuers[0]
		if e.Name != "other-app-real" {
			t.Errorf("Name = %q, want other-app-real", e.Name)
		}
		if e.RequireISS == nil || *e.RequireISS {
			t.Errorf("RequireISS = %v, want explicit false preserved", e.RequireISS)
		}
		if e.RequireAud == nil || *e.RequireAud {
			t.Errorf("RequireAud = %v, want explicit false preserved", e.RequireAud)
		}
		if e.RequireJTI == nil || *e.RequireJTI {
			t.Errorf("RequireJTI = %v, want explicit false preserved", e.RequireJTI)
		}
		if e.Claims.Subject != "username" || e.Claims.Role != "role" || e.Claims.SessionID != "sessionId" {
			t.Errorf("Claims = %+v, want subject=username role=role session_id=sessionId", e.Claims)
		}
		if e.Claims.RoleAliases["maker"] != "maker" || e.Claims.RoleAliases["checker"] != "checker" {
			// NOTE: viper lowercases config map keys — "Maker"/"Checker"
			// as written arrive here as "maker"/"checker". Runtime alias
			// matching must therefore be CASE-INSENSITIVE (Task 2) so a
			// token's literal "Maker"/"Checker" role values still map.
			t.Errorf("RoleAliases = %v, want {maker:maker checker:checker} (viper-lowercased keys)", e.Claims.RoleAliases)
		}
	})

	t.Run("resolved: login off + one external issuer loads (external-only)", func(t *testing.T) {
		cfg, err := LoadControl(writeTempConfig(t, loginOffBase+ext+one))
		if err != nil {
			t.Fatalf("LoadControl: %v", err)
		}
		if cfg.JWT.LoginEnabled {
			t.Error("JWT.LoginEnabled = true, want false (external-only fixture)")
		}
		if len(cfg.JWT.ExternalIssuers) != 1 {
			t.Errorf("len(ExternalIssuers) = %d, want 1", len(cfg.JWT.ExternalIssuers))
		}
	})

	t.Run("resolved: two issuers keep declaration order and independent audiences", func(t *testing.T) {
		cfg, err := LoadControl(writeTempConfig(t, header+ext+two))
		if err != nil {
			t.Fatalf("LoadControl: %v", err)
		}
		issuers := cfg.JWT.ExternalIssuers
		if len(issuers) != 2 {
			t.Fatalf("len(ExternalIssuers) = %d, want 2", len(issuers))
		}
		if issuers[0].Name != "app-a" || issuers[1].Name != "app-b" {
			t.Errorf("names = [%q %q], want [app-a app-b] (declaration order)", issuers[0].Name, issuers[1].Name)
		}
		// Issuer A omits audience → inherits top-level; issuer B declares one.
		if issuers[0].Audience != "zt-api" {
			t.Errorf("issuers[0].Audience = %q, want inherited \"zt-api\"", issuers[0].Audience)
		}
		if issuers[1].Audience != "zt-b" {
			t.Errorf("issuers[1].Audience = %q, want explicit \"zt-b\"", issuers[1].Audience)
		}
	})
}
