package config

import (
	"encoding/json"
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
	if got := cfg.ValkeyAddr; got != "127.0.0.1:6379" {
		t.Errorf("ValkeyAddr = %q, want %q", got, "127.0.0.1:6379")
	}

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
	if got := cfg.ValkeyAddr; got != "127.0.0.1:6379" {
		t.Errorf("ValkeyAddr = %q, want %q", got, "127.0.0.1:6379")
	}
	if got := cfg.ValkeyDB; got != 0 {
		t.Errorf("ValkeyDB = %d, want 0", got)
	}

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
