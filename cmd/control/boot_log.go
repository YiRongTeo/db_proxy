package main

// Task 11 (node-integration append): boot logging for the data-plane
// FALLBACK POOL (configs/control.yaml api.data_plane_hosts / env
// ZT_API_DATA_PLANE_HOSTS). A non-empty pool is announced once at boot so
// the operator sees the fallback surface; malformed entries that LoadControl
// dropped surface as a NAMED WARN (never a boot failure — the DB routing
// path is the primary). An empty pool stays quiet here: the per-mint WARN in
// internal/api chooseRoute names the misconfiguration where it bites.

import (
	"log/slog"
	"strings"

	"zerotrust-proxy/internal/config"
)

// logDataPlanePool logs the fallback pool at boot: a single INFO announce
// ("data plane fallback pool", hosts=N, comma-joined entries) when the pool
// is non-empty, plus — when LoadControl rejected malformed entries — one
// WARN naming each dropped entry verbatim alongside the entries that made it
// into the pool. Both lines are log-only: the pool is the fallback path and
// must never fail the boot.
func logDataPlanePool(log *slog.Logger, cfg *config.ControlConfig) {
	if len(cfg.DataPlaneHosts) > 0 {
		log.Info("data plane fallback pool",
			"hosts", len(cfg.DataPlaneHosts),
			"entries", strings.Join(cfg.DataPlaneHosts, ", "))
	}
	if len(cfg.DataPlaneHostsRejected) > 0 {
		log.Warn("data plane fallback pool entries rejected (malformed — no host, no/bad port); fix or remove them in api.data_plane_hosts / ZT_API_DATA_PLANE_HOSTS",
			"rejected", strings.Join(cfg.DataPlaneHostsRejected, ", "),
			"pool", strings.Join(cfg.DataPlaneHosts, ", "))
	}
}
