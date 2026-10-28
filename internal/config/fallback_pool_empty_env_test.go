package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFallbackPoolEmptyEnvSurvives(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "control.yaml")
	yaml := "http:\n  addr: \":8080\"\nauth:\n  username: admin\n  password: pw123456\n  role: maker\n  jwt:\n    enabled: true\n    secret: test-secret-for-probe-0123456789abcdef\napi:\n  data_plane_hosts:\n    - \"10.0.0.1:3306\"\n    - \"10.0.0.2:3306\"\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadControl(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Logf("yaml list -> pool=%v rejected=%v", cfg.DataPlaneHosts, cfg.DataPlaneHostsRejected)
	t.Setenv("ZT_API_DATA_PLANE_HOSTS", "10.0.0.3:3306,10.0.0.4:3306")
	cfg2, err := LoadControl(p)
	if err != nil {
		t.Fatalf("load2: %v", err)
	}
	t.Logf("env over yaml -> pool=%v rejected=%v", cfg2.DataPlaneHosts, cfg2.DataPlaneHostsRejected)
	os.Unsetenv("ZT_API_DATA_PLANE_HOSTS")
	t.Setenv("ZT_API_DATA_PLANE_HOSTS", "")
	cfg3, err := LoadControl(p)
	if err != nil {
		t.Fatalf("load3: %v", err)
	}
	// Task 11 follow-up (the empty-env bug Ryan hit): a SET-BUT-EMPTY env
	// var poisons every env-aware accessor (IsSet true, GetStringSlice
	// empty) — the yaml pool must survive via the file-only read.
	if len(cfg3.DataPlaneHosts) != 2 {
		t.Errorf("env EMPTY over yaml list → DataPlaneHosts = %v, want the yaml pool of 2 (set-but-empty env must not wipe the pool)", cfg3.DataPlaneHosts)
	}
	if len(cfg3.DataPlaneHostsRejected) != 0 {
		t.Errorf("env EMPTY over yaml list → DataPlaneHostsRejected = %v, want empty", cfg3.DataPlaneHostsRejected)
	}
}
