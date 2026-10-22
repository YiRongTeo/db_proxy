package config

import (
	"os"
	"testing"
)

// --- Task 7 (node-integration): configurable SoD flags -----------------------
//
// Two flags open the maker-checker separation for a UAT environment where one
// person plays both roles:
//
//   - auth.allow_checker_write (control plane, env
//     ZT_AUTH_ALLOW_CHECKER_WRITE, default FALSE): when true, the mint no
//     longer refuses write/rw tokens to checker-role principals (the 403 at
//     handlers.go). Default false = strict SoD (G3: byte-identical).
//   - rw_require_checker_watch (data plane, env ZT_RW_REQUIRE_CHECKER_WATCH,
//     default TRUE): when false, an access:"rw" token ADMITS IMMEDIATELY —
//     the normal backend connect, no hold, no WatchActive polling. Default
//     true = the Task 6 hold (G3: byte-identical).
//
// These tests pin BOTH flag states and the env bindings (viper AutomaticEnv
// maps the dot-paths; the parse test is the verification the brief asks for).

// TestAllowCheckerWriteConfig: auth.allow_checker_write parse matrix.
func TestAllowCheckerWriteConfig(t *testing.T) {
	t.Run("absent defaults false", func(t *testing.T) {
		path := writeTempControlConfig(t)
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if cfg.AllowCheckerWrite {
			t.Error("AllowCheckerWrite = true, want false (absent key = strict SoD, G3)")
		}
	})

	t.Run("yaml true parses", func(t *testing.T) {
		path := writeTempControlConfig(t)
		setControlTempField(t, path, "allow_checker_write: true")
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if !cfg.AllowCheckerWrite {
			t.Error("AllowCheckerWrite = false, want true (allow_checker_write: true)")
		}
	})

	t.Run("env true beats file false", func(t *testing.T) {
		t.Setenv("ZT_AUTH_ALLOW_CHECKER_WRITE", "true")
		path := writeTempControlConfig(t)
		setControlTempField(t, path, "allow_checker_write: false")
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if !cfg.AllowCheckerWrite {
			t.Error("AllowCheckerWrite = false, want true (ZT_AUTH_ALLOW_CHECKER_WRITE=true overrides the file)")
		}
	})

	t.Run("env false beats file true", func(t *testing.T) {
		t.Setenv("ZT_AUTH_ALLOW_CHECKER_WRITE", "false")
		path := writeTempControlConfig(t)
		setControlTempField(t, path, "allow_checker_write: true")
		cfg, err := LoadControl(path)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", path, err)
		}
		if cfg.AllowCheckerWrite {
			t.Error("AllowCheckerWrite = true, want false (ZT_AUTH_ALLOW_CHECKER_WRITE=false overrides the file)")
		}
	})

	t.Run("committed control.yaml default false", func(t *testing.T) {
		setSecretEnv(t)
		cfg, err := LoadControl(controlYAML)
		if err != nil {
			t.Fatalf("LoadControl(%q) error: %v", controlYAML, err)
		}
		if cfg.AllowCheckerWrite {
			t.Error("AllowCheckerWrite = true, want false (committed default = strict SoD)")
		}
	})
}

// TestRWRequireCheckerWatchConfig: rw_require_checker_watch parse matrix.
func TestRWRequireCheckerWatchConfig(t *testing.T) {
	t.Run("absent defaults true", func(t *testing.T) {
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if !cfg.RWRequireCheckerWatch {
			t.Error("RWRequireCheckerWatch = false, want true (absent key = the Task 6 hold, G3)")
		}
	})

	t.Run("yaml false parses", func(t *testing.T) {
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_require_checker_watch: false\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.RWRequireCheckerWatch {
			t.Error("RWRequireCheckerWatch = true, want false (rw_require_checker_watch: false)")
		}
	})

	t.Run("env false beats file true", func(t *testing.T) {
		t.Setenv("ZT_RW_REQUIRE_CHECKER_WATCH", "false")
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_require_checker_watch: true\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.RWRequireCheckerWatch {
			t.Error("RWRequireCheckerWatch = true, want false (ZT_RW_REQUIRE_CHECKER_WATCH=false overrides the file)")
		}
	})

	t.Run("env true beats file false", func(t *testing.T) {
		t.Setenv("ZT_RW_REQUIRE_CHECKER_WATCH", "true")
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_require_checker_watch: false\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if !cfg.RWRequireCheckerWatch {
			t.Error("RWRequireCheckerWatch = false, want true (ZT_RW_REQUIRE_CHECKER_WATCH=true overrides the file)")
		}
	})

	t.Run("committed data.yaml default true", func(t *testing.T) {
		setSecretEnv(t)
		cfg, err := LoadData(dataYAML)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", dataYAML, err)
		}
		if !cfg.RWRequireCheckerWatch {
			t.Error("RWRequireCheckerWatch = false, want true (committed default = the hold)")
		}
	})
}

// writeTempControlConfig writes the minimal control config every subtest
// starts from (the shape TestLoadControlSentinelShape proves loadable).
func writeTempControlConfig(t *testing.T) string {
	t.Helper()
	return writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
`)
}

// setControlTempField appends a key to the auth block of a temp control
// config (the temp files above are fixed-shape; this appends to the end of
// the file, where yaml nests the key under the auth block — the last block
// written — so each subtest controls exactly one flag).
func setControlTempField(t *testing.T, path, field string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("append %q to %s: %v", field, path, err)
	}
	defer f.Close()
	if _, err := f.WriteString("  " + field + "\n"); err != nil {
		t.Fatalf("append %q to %s: %v", field, path, err)
	}
}
