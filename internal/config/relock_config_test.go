package config

import (
	"testing"
)

// --- Task 9 (node-integration): rw_relock_on_watch_loss ----------------------
//
// The re-lock policy flag: when the LAST checker leaves an ADMITTED rw
// session, the session re-freezes (re-locks) until a checker watches again.
// Default TRUE (the owner-directed policy change — G3 applies only to the
// flag-OFF path, which must stay byte-identical to the old one-way
// admission). Env ZT_RW_RELOCK_ON_WATCH_LOSS uses the STRICT raw-string
// allowlist (true/1/false/0 only): false DISABLES a safety behavior, so a
// cast.ToBool typo ("yes"/"on" → false) would be a fail-open — a rejected
// value is UNSET (yaml/TRUE default decides) and surfaces for the boot WARN.

// TestRWRelockOnWatchLossConfig: parse matrix for the yaml + env resolution.
func TestRWRelockOnWatchLossConfig(t *testing.T) {
	t.Run("absent defaults true", func(t *testing.T) {
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if !cfg.RWRelockOnWatchLoss {
			t.Error("RWRelockOnWatchLoss = false, want true (absent key = re-lock ON, owner default)")
		}
		if cfg.RWRelockOnWatchLossEnvRejected != "" {
			t.Errorf("RWRelockOnWatchLossEnvRejected = %q, want empty", cfg.RWRelockOnWatchLossEnvRejected)
		}
	})

	t.Run("yaml false parses", func(t *testing.T) {
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_relock_on_watch_loss: false\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.RWRelockOnWatchLoss {
			t.Error("RWRelockOnWatchLoss = true, want false (rw_relock_on_watch_loss: false = the legacy one-way admission)")
		}
	})

	t.Run("env false beats file true", func(t *testing.T) {
		t.Setenv("ZT_RW_RELOCK_ON_WATCH_LOSS", "false")
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_relock_on_watch_loss: true\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if cfg.RWRelockOnWatchLoss {
			t.Error("RWRelockOnWatchLoss = true, want false (ZT_RW_RELOCK_ON_WATCH_LOSS=false overrides the file)")
		}
	})

	t.Run("env true beats file false", func(t *testing.T) {
		t.Setenv("ZT_RW_RELOCK_ON_WATCH_LOSS", "true")
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_relock_on_watch_loss: false\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", path, err)
		}
		if !cfg.RWRelockOnWatchLoss {
			t.Error("RWRelockOnWatchLoss = false, want true (ZT_RW_RELOCK_ON_WATCH_LOSS=true overrides the file)")
		}
	})

	t.Run("committed data.yaml default true", func(t *testing.T) {
		setSecretEnv(t)
		cfg, err := LoadData(dataYAML)
		if err != nil {
			t.Fatalf("LoadData(%q) error: %v", dataYAML, err)
		}
		if !cfg.RWRelockOnWatchLoss {
			t.Error("RWRelockOnWatchLoss = false, want true (committed default = re-lock ON)")
		}
	})
}

// TestRWRelockOnWatchLossEnvStrict: the strict allowlist — only
// true/1/false/0 (case-insensitive) count; anything else is UNSET (the yaml
// / TRUE default decides) and its raw value surfaces for the boot WARN.
// Mirrors TestRWRequireCheckerWatchEnvStrict (Task 7 follow-up).
func TestRWRelockOnWatchLossEnvStrict(t *testing.T) {
	// Accepted spellings work in both directions over any yaml.
	for _, tc := range []struct {
		env  string
		want bool
	}{
		{"true", true}, {"1", true}, {"false", false}, {"0", false},
	} {
		t.Run("accepted "+tc.env, func(t *testing.T) {
			t.Setenv("ZT_RW_RELOCK_ON_WATCH_LOSS", tc.env)
			path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_relock_on_watch_loss: "+map[bool]string{true: "false", false: "true"}[tc.want]+"\n")
			cfg, err := LoadData(path)
			if err != nil {
				t.Fatalf("LoadData: %v", err)
			}
			if cfg.RWRelockOnWatchLoss != tc.want {
				t.Errorf("env %q → RWRelockOnWatchLoss = %v, want %v", tc.env, cfg.RWRelockOnWatchLoss, tc.want)
			}
			if cfg.RWRelockOnWatchLossEnvRejected != "" {
				t.Errorf("env %q → RWRelockOnWatchLossEnvRejected = %q, want empty", tc.env, cfg.RWRelockOnWatchLossEnvRejected)
			}
		})
	}
	// Unrecognized spellings are rejected — the value is UNSET (the yaml
	// true / default TRUE applies — re-lock stays ON) and the raw value
	// surfaces for the boot WARN. "yes"/"on" are exactly the spellings
	// cast.ToBool silently mapped to false.
	for _, bad := range []string{"garbage", "yes", "on", "2"} {
		t.Run("rejected "+bad, func(t *testing.T) {
			t.Setenv("ZT_RW_RELOCK_ON_WATCH_LOSS", bad)
			// Over an explicit yaml false the rejection means UNSET → the
			// yaml (false) decides — rejection is not a forced lock.
			path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_relock_on_watch_loss: false\n")
			cfg, err := LoadData(path)
			if err != nil {
				t.Fatalf("LoadData: %v", err)
			}
			if cfg.RWRelockOnWatchLoss {
				t.Errorf("env %q over yaml false → RWRelockOnWatchLoss = true, want false (rejected = unset, yaml decides)", bad)
			}
			if cfg.RWRelockOnWatchLossEnvRejected != bad {
				t.Errorf("env %q → RWRelockOnWatchLossEnvRejected = %q, want %q (surfaces the boot WARN)", bad, cfg.RWRelockOnWatchLossEnvRejected, bad)
			}
		})
		t.Run("rejected "+bad+" default-locks", func(t *testing.T) {
			t.Setenv("ZT_RW_RELOCK_ON_WATCH_LOSS", bad)
			// With NO yaml key the true default applies — the typo can
			// never disable the re-lock (fail-locked).
			path := writeTempConfig(t, "listen:\n  addr: \":3306\"\n")
			cfg, err := LoadData(path)
			if err != nil {
				t.Fatalf("LoadData: %v", err)
			}
			if !cfg.RWRelockOnWatchLoss {
				t.Errorf("env %q with no yaml → RWRelockOnWatchLoss = false, want true (fail-locked default)", bad)
			}
		})
	}
	// Empty env = unset, yaml decides.
	t.Run("empty env unset", func(t *testing.T) {
		t.Setenv("ZT_RW_RELOCK_ON_WATCH_LOSS", "")
		path := writeTempConfig(t, "listen:\n  addr: \":3306\"\nrw_relock_on_watch_loss: false\n")
		cfg, err := LoadData(path)
		if err != nil {
			t.Fatalf("LoadData: %v", err)
		}
		if cfg.RWRelockOnWatchLoss {
			t.Error("empty env over yaml false → RWRelockOnWatchLoss = true, want false")
		}
		if cfg.RWRelockOnWatchLossEnvRejected != "" {
			t.Errorf("empty env → RWRelockOnWatchLossEnvRejected = %q, want empty", cfg.RWRelockOnWatchLossEnvRejected)
		}
	})
}
