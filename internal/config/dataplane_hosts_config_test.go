package config

// Task 11 (node-integration append): the data-plane FALLBACK POOL config —
// api.data_plane_hosts (yaml list of "host:port" strings; env
// ZT_API_DATA_PLANE_HOSTS comma-separated — AutomaticEnv hands a list key
// through as ONE string, so LoadControl parses it itself). Back-compat (G3):
// the legacy single api.data_plane_host + api.data_plane_port pair becomes a
// one-element pool when the new key is absent/empty; BOTH set → the new key
// wins; NEITHER → an empty pool (no config fallback — routing must be
// enabled or the mint warns with the pre-pool empty shape). Malformed
// entries (empty, no host, no/bad port) are dropped at load and surfaced in
// DataPlaneHostsRejected for the boot WARN — never a boot failure (the DB
// routing path is the primary).

import (
	"reflect"
	"testing"
)

// TestDataPlaneHostsOnly: the new yaml key parses as an ordered pool and
// leaves the legacy single-host fields empty.
func TestDataPlaneHostsOnly(t *testing.T) {
	setSecretEnv(t)

	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
api:
  data_plane_hosts:
    - "10.0.0.1:3306"
    - "10.0.0.2:3307"
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl error: %v", err)
	}
	want := []string{"10.0.0.1:3306", "10.0.0.2:3307"}
	if !reflect.DeepEqual(cfg.DataPlaneHosts, want) {
		t.Errorf("DataPlaneHosts = %v, want %v (order preserved)", cfg.DataPlaneHosts, want)
	}
	if len(cfg.DataPlaneHostsRejected) != 0 {
		t.Errorf("DataPlaneHostsRejected = %v, want empty", cfg.DataPlaneHostsRejected)
	}
	if cfg.DataPlaneHost != "" || cfg.DataPlanePort != "" {
		t.Errorf("legacy fields = %q/%q, want empty (only the new key set)", cfg.DataPlaneHost, cfg.DataPlanePort)
	}
}

// TestDataPlaneHostsLegacyOnlyBackCompat (G3): only the OLD single keys set →
// they become a ONE-ELEMENT pool (RR over one = always that plane —
// byte-identical to the pre-pool fallback).
func TestDataPlaneHostsLegacyOnlyBackCompat(t *testing.T) {
	setSecretEnv(t)

	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
api:
  data_plane_host: "10.0.0.9"
  data_plane_port: "3306"
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl error: %v", err)
	}
	want := []string{"10.0.0.9:3306"}
	if !reflect.DeepEqual(cfg.DataPlaneHosts, want) {
		t.Errorf("DataPlaneHosts = %v, want %v (legacy pair as one-element pool)", cfg.DataPlaneHosts, want)
	}
	if len(cfg.DataPlaneHostsRejected) != 0 {
		t.Errorf("DataPlaneHostsRejected = %v, want empty", cfg.DataPlaneHostsRejected)
	}
	if cfg.DataPlaneHost != "10.0.0.9" || cfg.DataPlanePort != "3306" {
		t.Errorf("legacy fields = %q/%q, want the yaml pair (fields stay populated)", cfg.DataPlaneHost, cfg.DataPlanePort)
	}
}

// TestDataPlaneHostsWinsOverLegacy: BOTH set → the new key is the pool; the
// legacy pair does NOT append to it.
func TestDataPlaneHostsWinsOverLegacy(t *testing.T) {
	setSecretEnv(t)

	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
api:
  data_plane_host: "10.0.0.9"
  data_plane_port: "3306"
  data_plane_hosts:
    - "10.0.0.1:3306"
    - "10.0.0.2:3307"
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl error: %v", err)
	}
	want := []string{"10.0.0.1:3306", "10.0.0.2:3307"}
	if !reflect.DeepEqual(cfg.DataPlaneHosts, want) {
		t.Errorf("DataPlaneHosts = %v, want %v (new key wins over legacy)", cfg.DataPlaneHosts, want)
	}
}

// TestDataPlaneHostsNeitherEmpty: NEITHER key set → an EMPTY pool (no config
// fallback; routing must be enabled) and nothing rejected.
func TestDataPlaneHostsNeitherEmpty(t *testing.T) {
	setSecretEnv(t)

	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl error: %v", err)
	}
	if len(cfg.DataPlaneHosts) != 0 {
		t.Errorf("DataPlaneHosts = %v, want empty (no fallback keys at all)", cfg.DataPlaneHosts)
	}
	if len(cfg.DataPlaneHostsRejected) != 0 {
		t.Errorf("DataPlaneHostsRejected = %v, want empty", cfg.DataPlaneHostsRejected)
	}
}

// TestDataPlaneHostsEnvCommaList: ZT_API_DATA_PLANE_HOSTS arrives through
// AutomaticEnv as ONE comma-separated string — parsed, trimmed, empties and
// malformed entries dropped into DataPlaneHostsRejected (in order), valid
// entries forming the pool. The env works with NO yaml key present.
func TestDataPlaneHostsEnvCommaList(t *testing.T) {
	setSecretEnv(t)

	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
`)
	t.Setenv("ZT_API_DATA_PLANE_HOSTS", "10.1.0.1:3306, 10.1.0.2:3307 , ,bogus, 10.1.0.3:65536")

	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl error: %v", err)
	}
	wantPool := []string{"10.1.0.1:3306", "10.1.0.2:3307"}
	if !reflect.DeepEqual(cfg.DataPlaneHosts, wantPool) {
		t.Errorf("DataPlaneHosts = %v, want %v (env comma-list parsed)", cfg.DataPlaneHosts, wantPool)
	}
	wantRej := []string{"", "bogus", "10.1.0.3:65536"}
	if !reflect.DeepEqual(cfg.DataPlaneHostsRejected, wantRej) {
		t.Errorf("DataPlaneHostsRejected = %q, want %q (empties + malformed, in order)", cfg.DataPlaneHostsRejected, wantRej)
	}
}

// TestDataPlaneHostsEnvOverridesYamlList: the env override beats a yaml list
// for the SAME key (viper AutomaticEnv precedence).
func TestDataPlaneHostsEnvOverridesYamlList(t *testing.T) {
	setSecretEnv(t)

	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
api:
  data_plane_hosts:
    - "10.9.9.9:1111"
`)
	t.Setenv("ZT_API_DATA_PLANE_HOSTS", "10.8.8.8:2222")

	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl error: %v", err)
	}
	want := []string{"10.8.8.8:2222"}
	if !reflect.DeepEqual(cfg.DataPlaneHosts, want) {
		t.Errorf("DataPlaneHosts = %v, want %v (env overrides yaml list)", cfg.DataPlaneHosts, want)
	}
}

// TestDataPlaneHostsMalformedDropped: every malformed shape (no port, empty
// port, no host, port 0, port too big, non-numeric port, empty, whitespace)
// is dropped at load into DataPlaneHostsRejected — the load NEVER fails and
// the valid entries (trimmed) still form the pool.
func TestDataPlaneHostsMalformedDropped(t *testing.T) {
	setSecretEnv(t)

	path := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
api:
  data_plane_hosts:
    - "10.2.0.1:3306"
    - "noport.host"
    - "host.only:"
    - ":3306"
    - "10.2.0.2:0"
    - "10.2.0.3:70000"
    - "10.2.0.4:notaport"
    - ""
    - "   "
    - " 10.2.0.5:3307 "
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl with malformed pool entries: %v (a malformed entry must NEVER fail the boot)", err)
	}
	wantPool := []string{"10.2.0.1:3306", "10.2.0.5:3307"}
	if !reflect.DeepEqual(cfg.DataPlaneHosts, wantPool) {
		t.Errorf("DataPlaneHosts = %v, want %v (valid entries kept, trimmed)", cfg.DataPlaneHosts, wantPool)
	}
	wantRej := []string{"noport.host", "host.only:", ":3306", "10.2.0.2:0", "10.2.0.3:70000", "10.2.0.4:notaport", "", ""}
	// Two empty strings: the empty literal and the whitespace entry — the
	// rejected list records the TRIMMED blank (the loader normalizes before
	// dropping), so both blanks look identical; len pins that BOTH dropped.
	if !reflect.DeepEqual(cfg.DataPlaneHostsRejected, wantRej) {
		t.Errorf("DataPlaneHostsRejected = %q, want %q", cfg.DataPlaneHostsRejected, wantRej)
	}
}
