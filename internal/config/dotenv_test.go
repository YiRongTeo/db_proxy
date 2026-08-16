package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEnvFile writes an env-file fixture and returns its path (cleaned up
// with the test).
func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write env fixture: %v", err)
	}
	return p
}

// unsetEnv restores the environment after a test that set process vars.
func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	prev := map[string]string{}
	had := map[string]bool{}
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			prev[k], had[k] = v, true
		}
	}
	t.Cleanup(func() {
		for _, k := range keys {
			if had[k] {
				_ = os.Setenv(k, prev[k])
			} else {
				_ = os.Unsetenv(k)
			}
		}
	})
}

// TestLoadDotEnvBasics: KEY=VALUE lines, comments, blanks, export prefix,
// quoted values, CRLF — the godotenv-style subset the planes load.
func TestLoadDotEnvBasics(t *testing.T) {
	unsetEnv(t, "ZT_TEST_DOTENV_A", "ZT_TEST_DOTENV_B", "ZT_TEST_DOTENV_C", "ZT_TEST_DOTENV_D")
	p := writeEnvFile(t, "# comment\r\n"+
		"\r\n"+
		"ZT_TEST_DOTENV_A=alpha\r\n"+
		"export ZT_TEST_DOTENV_B=\"beta with spaces\"\r\n"+
		"ZT_TEST_DOTENV_C='gamma'\r\n"+
		"ZT_TEST_DOTENV_D=delta   \r\n")
	if err := LoadDotEnv(p); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if got := os.Getenv("ZT_TEST_DOTENV_A"); got != "alpha" {
		t.Errorf("A = %q, want %q", got, "alpha")
	}
	if got := os.Getenv("ZT_TEST_DOTENV_B"); got != "beta with spaces" {
		t.Errorf("B = %q, want %q", got, "beta with spaces")
	}
	if got := os.Getenv("ZT_TEST_DOTENV_C"); got != "gamma" {
		t.Errorf("C = %q, want %q", got, "gamma")
	}
	if got := os.Getenv("ZT_TEST_DOTENV_D"); got != "delta" {
		t.Errorf("D = %q, want %q", got, "delta")
	}
}

// TestLoadDotEnvMissingFile: an absent .env is a no-op (CI exports vars).
func TestLoadDotEnvMissingFile(t *testing.T) {
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "does-not-exist")); err != nil {
		t.Fatalf("missing env file: want nil error, got %v", err)
	}
}

// TestLoadDotEnvProcessEnvWins: variables already set in the environment
// are NOT overridden by the .env (process env is authoritative).
func TestLoadDotEnvProcessEnvWins(t *testing.T) {
	t.Setenv("ZT_TEST_DOTENV_WIN", "from-process")
	unsetEnv(t, "ZT_TEST_DOTENV_WIN")
	p := writeEnvFile(t, "ZT_TEST_DOTENV_WIN=from-file\n")
	if err := LoadDotEnv(p); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if got := os.Getenv("ZT_TEST_DOTENV_WIN"); got != "from-process" {
		t.Errorf("value = %q, want %q (process env must win)", got, "from-process")
	}
}

// TestLoadDotEnvMalformed: a line without '=' or with an empty name is a
// load error — a broken secrets file must not be silently ignored.
func TestLoadDotEnvMalformed(t *testing.T) {
	if err := LoadDotEnv(writeEnvFile(t, "ZT_TEST_DOTENV_X=ok\nno-equals-here\n")); err == nil {
		t.Error("malformed line: want error, got nil")
	}
	if err := LoadDotEnv(writeEnvFile(t, "=value\n")); err == nil {
		t.Error("empty variable name: want error, got nil")
	}
}

// TestExpandEnv: ${VAR} placeholders resolve from the process env; values
// without placeholders pass through; an UNSET variable is an error.
func TestExpandEnv(t *testing.T) {
	t.Setenv("ZT_TEST_EXPAND_A", "alpha")
	unsetEnv(t, "ZT_TEST_EXPAND_MISSING")

	got, err := expandEnv("${ZT_TEST_EXPAND_A}:${ZT_TEST_EXPAND_A}")
	if err != nil || got != "alpha:alpha" {
		t.Fatalf("expand = %q, %v; want %q", got, err, "alpha:alpha")
	}
	got, err = expandEnv("plain-value")
	if err != nil || got != "plain-value" {
		t.Fatalf("passthrough = %q, %v; want %q", got, err, "plain-value")
	}
	if _, err := expandEnv("${ZT_TEST_EXPAND_MISSING}"); err == nil ||
		!strings.Contains(err.Error(), "ZT_TEST_EXPAND_MISSING") {
		t.Fatalf("unset variable: want error naming the var, got %v", err)
	}
	// Explicitly-empty is a REAL override (AllowEmptyEnv philosophy).
	t.Setenv("ZT_TEST_EXPAND_EMPTY", "")
	if got, err := expandEnv("${ZT_TEST_EXPAND_EMPTY}"); err != nil || got != "" {
		t.Fatalf("explicitly-empty = %q, %v; want empty, nil", got, err)
	}
}

// TestLoadDataCredentialPlaceholders: the committed data.yaml credentials
// resolve their ${VAR} placeholders from the environment.
func TestLoadDataCredentialPlaceholders(t *testing.T) {
	setSecretEnv(t)
	cfg, err := LoadData(dataYAML)
	if err != nil {
		t.Fatalf("LoadData: %v", err)
	}
	want := map[string]string{
		"mysql:ro_user@127.0.0.1:3307":    "ro_pw",
		"mysql:rw_user@127.0.0.1:3307":    "rw_pw",
		"postgres:ro_user@127.0.0.1:5433": "ro_pw",
		"mssql:ro_user@127.0.0.1:1434":    "ro_pw",
		"mssql:rw_user@127.0.0.1:1434":    "rw_pw",
	}
	for key, wantPw := range want {
		if got := cfg.Credentials[key]; got != wantPw {
			t.Errorf("Credentials[%q] = %q, want %q", key, got, wantPw)
		}
	}
}

// TestLoadDataCredentialPlaceholderUnset: an UNSET credential variable is
// a LOAD ERROR naming it — never a silent empty password.
func TestLoadDataCredentialPlaceholderUnset(t *testing.T) {
	setSecretEnv(t)
	// Remove exactly one variable while the others stay set.
	prev, had := os.LookupEnv("ZT_CRED_MYSQL_RO_PASSWORD")
	_ = os.Unsetenv("ZT_CRED_MYSQL_RO_PASSWORD")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("ZT_CRED_MYSQL_RO_PASSWORD", prev)
		} else {
			_ = os.Unsetenv("ZT_CRED_MYSQL_RO_PASSWORD")
		}
	})
	_, err := LoadData(dataYAML)
	if err == nil || !strings.Contains(err.Error(), "ZT_CRED_MYSQL_RO_PASSWORD") {
		t.Fatalf("unset credential var: want load error naming it, got %v", err)
	}
}

// TestLoadControlFailsFastWithoutSecret: the committed control.yaml carries
// NO password — with ZT_AUTH_PASSWORD explicitly empty the plane refuses
// to start (fail-fast), pointing at .env.
func TestLoadControlFailsFastWithoutSecret(t *testing.T) {
	setSecretEnv(t)
	t.Setenv("ZT_AUTH_PASSWORD", "") // explicit empty AFTER — AllowEmptyEnv makes it a real override
	_, err := LoadControl(controlYAML)
	if err == nil || !strings.Contains(err.Error(), "auth.password") {
		t.Fatalf("empty auth password: want load error mentioning auth.password, got %v", err)
	}
	if !strings.Contains(err.Error(), ".env") {
		t.Errorf("error should point at .env: %v", err)
	}
}
