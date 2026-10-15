package config

// node-integration Task 2 — api.max_session_seconds: the OPTIONAL mint
// ceiling on end_time. Committed config ships the default 0 (UNCAPPED);
// the env override ZT_API_MAX_SESSION_SECONDS resolves through the normal
// viper machinery.

import "testing"

func TestLoadControlMaxSessionSeconds(t *testing.T) {
	setSecretEnv(t)

	cfg, err := LoadControl(controlYAML)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", controlYAML, err)
	}
	if cfg.MaxSessionSeconds != 0 {
		t.Errorf("MaxSessionSeconds = %d, want 0 (uncapped default)", cfg.MaxSessionSeconds)
	}

	t.Setenv("ZT_API_MAX_SESSION_SECONDS", "3600")
	cfg2, err := LoadControl(controlYAML)
	if err != nil {
		t.Fatalf("LoadControl with env override: %v", err)
	}
	if cfg2.MaxSessionSeconds != 3600 {
		t.Errorf("MaxSessionSeconds = %d, want 3600 (ZT_API_MAX_SESSION_SECONDS override)", cfg2.MaxSessionSeconds)
	}
}
