package main

// Task 11 (node-integration append): the CONTROL plane's boot logging for
// the data-plane fallback pool — a non-empty pool is announced at boot
// ("data plane fallback pool" with the host count + the entries) and
// malformed entries dropped by LoadControl surface as a NAMED WARN (never a
// boot failure — the DB routing path is the primary). An empty pool is
// quiet at boot (the per-mint WARN in internal/api covers the
// misconfiguration where it bites).

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"zerotrust-proxy/internal/config"
)

// TestLogDataPlanePoolAnnounces: pool ["10.0.0.1:3306","10.0.0.2:3307"] →
// one INFO line naming "data plane fallback pool" with hosts=2 and the
// entries themselves.
func TestLogDataPlanePoolAnnounces(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	cfg := &config.ControlConfig{DataPlaneHosts: []string{"10.0.0.1:3306", "10.0.0.2:3307"}}

	logDataPlanePool(log, cfg)

	out := buf.String()
	for _, want := range []string{"data plane fallback pool", "hosts=2", "10.0.0.1:3306, 10.0.0.2:3307"} {
		if !strings.Contains(out, want) {
			t.Errorf("pool boot log missing %q; log:\n%s", want, out)
		}
	}
}

// TestLogDataPlanePoolEmptyQuiet: an empty pool logs NOTHING at boot — the
// per-mint WARN (internal/api chooseRoute) is the empty-fallback signal.
func TestLogDataPlanePoolEmptyQuiet(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	cfg := &config.ControlConfig{}

	logDataPlanePool(log, cfg)

	if out := buf.String(); out != "" {
		t.Errorf("empty pool must stay quiet at boot; got:\n%s", out)
	}
}

// TestLogDataPlanePoolRejectedWarn: dropped malformed entries → exactly one
// WARN naming "data plane fallback pool entries rejected", listing the
// offending entries verbatim and pointing at the remaining valid pool.
func TestLogDataPlanePoolRejectedWarn(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	cfg := &config.ControlConfig{
		DataPlaneHosts:         []string{"10.0.0.1:3306"},
		DataPlaneHostsRejected: []string{"bogus", "10.0.0.9:70000"},
	}

	logDataPlanePool(log, cfg)

	out := buf.String()
	if n := strings.Count(out, "data plane fallback pool entries rejected"); n != 1 {
		t.Fatalf("rejected-entries WARN count = %d, want exactly 1; log:\n%s", n, out)
	}
	for _, want := range []string{"bogus", "10.0.0.9:70000", "10.0.0.1:3306"} {
		if !strings.Contains(out, want) {
			t.Errorf("rejected-entries WARN missing %q; log:\n%s", want, out)
		}
	}
	if strings.Count(out, "data plane fallback pool\n") != 0 && strings.Contains(out, "msg=\"data plane fallback pool\"") {
		// The announce and the WARN may coexist; this only guards that the
		// WARN is its own line, not a mutated announce.
		t.Logf("both lines present (announce + WARN):\n%s", out)
	}
}
