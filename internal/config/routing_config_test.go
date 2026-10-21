package config

// Task 5 (node-integration append): DB-driven data-plane routing config —
// the `routing` block (color/env, enabled default FALSE = byte-identical
// single data_plane_host/port behavior, G3). Routing REQUIRES a usable
// MySQL DSN: audit.mysql is REUSED when audit.mysql.enabled is true;
// otherwise routing.mysql carries the same five fields (enabled implied by
// its presence). enabled=true with NO resolvable DSN is a load error.
// Env: ZT_ROUTING_ENABLED / ZT_ROUTING_COLOR / ZT_ROUTING_MYSQL_*.

import (
	"strings"
	"testing"
)

// TestRoutingDefaultsOff: the committed configs/control.yaml carries no
// routing block → Enabled=false (G3 byte-identical default), Color="blue"
// (spec default, relevant the moment routing is switched on).
func TestRoutingDefaultsOff(t *testing.T) {
	setSecretEnv(t)

	cfg, err := LoadControl(controlYAML)
	if err != nil {
		t.Fatalf("LoadControl(%q) error: %v", controlYAML, err)
	}
	if cfg.Routing.Enabled {
		t.Error("Routing.Enabled = true, want false (default off, G3)")
	}
	if cfg.Routing.Color != "blue" {
		t.Errorf("Routing.Color = %q, want %q (spec default)", cfg.Routing.Color, "blue")
	}
	if cfg.Routing.MySQL != nil {
		t.Error("Routing.MySQL set without a routing.mysql block, want nil")
	}
	// No routing block and audit disabled → no resolvable DSN.
	if _, ok := cfg.RoutingMySQL(); ok {
		t.Error("RoutingMySQL() resolved a DSN with no routing.mysql and audit disabled")
	}
}

// TestRoutingEnabledRequiresDSN: routing.enabled=true with neither
// audit.mysql.enabled nor a routing.mysql block → load error NAMING the
// requirement (fail fast — an operator who enabled routing must never boot
// silently into permanent fallback).
func TestRoutingEnabledRequiresDSN(t *testing.T) {
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
routing:
  enabled: true
`)
	_, err := LoadControl(path)
	if err == nil {
		t.Fatal("LoadControl with routing.enabled=true and no DSN: want error, got nil")
	}
	for _, want := range []string{"routing", "audit.mysql"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// TestRoutingReusesAuditDSN: routing.enabled=true + audit.mysql.enabled=true
// → the audit block IS the lookup DSN (RoutingMySQL() resolves to it; the
// five fields pass through verbatim).
func TestRoutingReusesAuditDSN(t *testing.T) {
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
audit:
  mysql:
    enabled: true
    host: "10.1.1.5"
    port: "6603"
    user: "routereader"
    password: "auditpw"
    database: "zt_audit"
routing:
  enabled: true
  color: "blue"
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl with audit-reuse: %v", err)
	}
	if cfg.Routing.MySQL != nil {
		t.Error("Routing.MySQL set while reusing audit DSN, want nil")
	}
	got, ok := cfg.RoutingMySQL()
	if !ok {
		t.Fatal("RoutingMySQL() did not resolve the audit block")
	}
	if got.Host != "10.1.1.5" || got.Port != "6603" || got.User != "routereader" ||
		got.Password != "auditpw" || got.Database != "zt_audit" {
		t.Errorf("RoutingMySQL() = %+v, want the audit.mysql fields verbatim", got)
	}
}

// TestRoutingOwnMySQLBlock: routing.mysql present (enabled implied by its
// presence) with audit disabled → the routing block wins; a PARTIAL block is
// a load error naming the missing field.
func TestRoutingOwnMySQLBlock(t *testing.T) {
	setSecretEnv(t)

	complete := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
routing:
  enabled: true
  mysql:
    host: "10.2.2.7"
    port: "3306"
    user: "router"
    password: "routepw"
    database: "zt_routes"
`)
	cfg, err := LoadControl(complete)
	if err != nil {
		t.Fatalf("LoadControl with routing.mysql: %v", err)
	}
	got, ok := cfg.RoutingMySQL()
	if !ok {
		t.Fatal("RoutingMySQL() did not resolve the routing.mysql block")
	}
	if got.Host != "10.2.2.7" || got.Port != "3306" || got.User != "router" ||
		got.Password != "routepw" || got.Database != "zt_routes" {
		t.Errorf("RoutingMySQL() = %+v, want the routing.mysql fields", got)
	}

	partial := writeTempConfig(t, `
http:
  addr: ":8080"
auth:
  username: admin
  password: secret
  jwt:
    enabled: false
valkey:
  addr: "127.0.0.1:6379"
routing:
  enabled: true
  mysql:
    host: "10.2.2.7"
    port: "3306"
    user: "router"
    database: "zt_routes"
`)
	_, err = LoadControl(partial)
	if err == nil {
		t.Fatal("LoadControl with partial routing.mysql: want error, got nil")
	}
	if !strings.Contains(err.Error(), "routing.mysql") {
		t.Errorf("error %q does not name routing.mysql", err.Error())
	}
}

// TestRoutingMySQLWithoutEnabledInert: a routing.mysql block with
// routing.enabled absent → routing stays OFF (default) and the block is NOT
// an error (it is parked config, enabled implied only when routing turns on).
func TestRoutingMySQLWithoutEnabledInert(t *testing.T) {
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
routing:
  mysql:
    host: "10.2.2.7"
    port: "3306"
    user: "router"
    password: "routepw"
    database: "zt_routes"
`)
	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl with parked routing.mysql: %v", err)
	}
	if cfg.Routing.Enabled {
		t.Error("Routing.Enabled = true with no routing.enabled key, want false")
	}
}

// TestRoutingEnvOverrides: ZT_ROUTING_ENABLED / ZT_ROUTING_COLOR resolve
// through the viper machinery (AutomaticEnv + registered defaults), so an
// operator flips routing/color without touching the committed yaml.
func TestRoutingEnvOverrides(t *testing.T) {
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
audit:
  mysql:
    enabled: true
    host: "10.1.1.5"
    port: "6603"
    user: "routereader"
    password: "auditpw"
    database: "zt_audit"
`)
	t.Setenv("ZT_ROUTING_ENABLED", "true")
	t.Setenv("ZT_ROUTING_COLOR", "green")

	cfg, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl with env overrides: %v", err)
	}
	if !cfg.Routing.Enabled {
		t.Error("Routing.Enabled = false, want true (ZT_ROUTING_ENABLED)")
	}
	if cfg.Routing.Color != "green" {
		t.Errorf("Routing.Color = %q, want green (ZT_ROUTING_COLOR)", cfg.Routing.Color)
	}
	if _, ok := cfg.RoutingMySQL(); !ok {
		t.Error("RoutingMySQL() did not resolve the audit block under env-enabled routing")
	}
}
