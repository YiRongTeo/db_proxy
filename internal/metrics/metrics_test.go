package metrics

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newTestMetrics builds the instrument wrapper over a MANUAL reader so
// tests can assert counter movement synchronously, without an HTTP
// endpoint or the default prometheus registerer.
func newTestMetrics(t *testing.T) (*Metrics, func() map[string]metricdata.Aggregation) {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	m, err := newMetrics(provider.Meter(MeterName))
	if err != nil {
		t.Fatalf("newMetrics: %v", err)
	}
	return m, func() map[string]metricdata.Aggregation {
		rm := &metricdata.ResourceMetrics{}
		if err := reader.Collect(context.Background(), rm); err != nil {
			t.Fatalf("collect: %v", err)
		}
		got := map[string]metricdata.Aggregation{}
		for _, sm := range rm.ScopeMetrics {
			for _, mm := range sm.Metrics {
				got[mm.Name] = mm.Data
			}
		}
		return got
	}
}

// TestNilGuard: every method on a nil *Metrics (the disabled state) is a
// no-op — the hot path must never panic or allocate.
func TestNilGuard(t *testing.T) {
	var m *Metrics
	m.TokensValidated()
	m.TokensRejected("invalid")
	m.ConnectionsTotal("mysql", "ok")
	m.ConnectionsActiveInc("mysql")
	m.ConnectionsActiveDec("mysql")
	m.QueriesTotal("mysql", "select", "ok")
	m.GateBlocks("mysql")
	m.KillsTotal("connection")
	m.SessionDuration("mysql", time.Second)
	m.QueryDuration("mysql", time.Second)
	if h := m.Handler(); h == nil {
		t.Fatal("nil Handler() returned nil")
	} else {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("nil Handler status = %d, want 404", rec.Code)
		}
	}
}

// TestNewDisabled: metrics disabled yields (nil, nil) — main wires that
// into the proxies, leaving every call site a no-op.
func TestNewDisabled(t *testing.T) {
	m, err := New(false)
	if err != nil {
		t.Fatalf("New(false) error: %v", err)
	}
	if m != nil {
		t.Fatalf("New(false) = %p, want nil", m)
	}
}

// TestInstrumentWiring: every instrument moves on the injected events.
// This pins the instrument names, attribute keys and value semantics the
// Prometheus scrape (and the live test) depends on.
func TestInstrumentWiring(t *testing.T) {
	m, collect := newTestMetrics(t)

	// Fire one event per instrument — exactly the call-site vocabulary.
	m.TokensValidated()
	m.TokensRejected("invalid")
	m.TokensRejected("wrong_db_type")
	m.ConnectionsTotal("mysql", "ok")
	m.ConnectionsTotal("mysql", "rejected")
	m.ConnectionsActiveInc("mysql")
	m.QueriesTotal("mysql", "select", "ok")
	m.GateBlocks("mysql")
	m.KillsTotal("connection")
	m.SessionDuration("mysql", 250*time.Millisecond)
	m.QueryDuration("mysql", 10*time.Millisecond)

	got := collect()

	sum := func(name string) metricdata.Sum[int64] {
		t.Helper()
		d, ok := got[name].(metricdata.Sum[int64])
		if !ok {
			t.Fatalf("%s data = %T, want Sum[int64]", name, got[name])
		}
		return d
	}

	if d := sum("tokens.validated"); len(d.DataPoints) != 1 || d.DataPoints[0].Value != 1 {
		t.Errorf("tokens.validated = %+v, want one point value 1", d.DataPoints)
	}
	d := sum("tokens.rejected")
	if len(d.DataPoints) != 2 {
		t.Fatalf("tokens.rejected points = %d, want 2 (invalid, wrong_db_type)", len(d.DataPoints))
	}
	reasons := map[string]int64{}
	for _, p := range d.DataPoints {
		reasons[attrString(p.Attributes, "reason")] = p.Value
	}
	if reasons["invalid"] != 1 || reasons["wrong_db_type"] != 1 {
		t.Errorf("tokens.rejected reasons = %v, want invalid=1 wrong_db_type=1", reasons)
	}

	d = sum("connections.total")
	if len(d.DataPoints) != 2 {
		t.Fatalf("connections.total points = %d, want 2 (ok, rejected)", len(d.DataPoints))
	}
	results := map[string]int64{}
	for _, p := range d.DataPoints {
		if attrString(p.Attributes, "db_type") != "mysql" {
			t.Errorf("connections.total db_type = %q, want mysql", attrString(p.Attributes, "db_type"))
		}
		results[attrString(p.Attributes, "result")] = p.Value
	}
	if results["ok"] != 1 || results["rejected"] != 1 {
		t.Errorf("connections.total results = %v, want ok=1 rejected=1", results)
	}

	// connections.active is an Int64UpDownCounter — the SDK reports it as
	// Sum[int64] with IsMonotonic=false (NOT a Gauge: Gauge is reserved for
	// observable gauges in metricdata; Sum carries both counter kinds,
	// monotonicity is the discriminator). The Prometheus exporter renders a
	// non-monotonic sum WITHOUT the _total suffix: connections_active.
	ud := sum("connections.active")
	if ud.IsMonotonic {
		t.Error("connections.active IsMonotonic = true, want false (updowncounter)")
	}
	if len(ud.DataPoints) != 1 || ud.DataPoints[0].Value != 1 {
		t.Errorf("connections.active = %+v, want one point value 1", ud.DataPoints)
	}
	if attrString(ud.DataPoints[0].Attributes, "db_type") != "mysql" {
		t.Errorf("connections.active db_type = %q, want mysql", attrString(ud.DataPoints[0].Attributes, "db_type"))
	}

	d = sum("queries.total")
	if len(d.DataPoints) != 1 || d.DataPoints[0].Value != 1 {
		t.Fatalf("queries.total = %+v, want one point value 1", d.DataPoints)
	}
	if attrString(d.DataPoints[0].Attributes, "stmt_type") != "select" || attrString(d.DataPoints[0].Attributes, "status") != "ok" {
		t.Errorf("queries.total attrs = %v, want stmt_type=select status=ok", d.DataPoints[0].Attributes)
	}

	d = sum("gate.blocks")
	if len(d.DataPoints) != 1 || d.DataPoints[0].Value != 1 {
		t.Errorf("gate.blocks = %+v, want one point value 1", d.DataPoints)
	}

	d = sum("kills.total")
	if len(d.DataPoints) != 1 || d.DataPoints[0].Value != 1 || attrString(d.DataPoints[0].Attributes, "mode") != "connection" {
		t.Errorf("kills.total = %+v, want one point value 1 mode=connection", d.DataPoints)
	}

	for name, wantCount := range map[string]uint64{"session.duration": 1, "query.duration": 1} {
		h, ok := got[name].(metricdata.Histogram[float64])
		if !ok {
			t.Fatalf("%s data = %T, want Histogram[float64]", name, got[name])
		}
		if len(h.DataPoints) != 1 || h.DataPoints[0].Count != wantCount {
			t.Errorf("%s = %+v, want one point count %d", name, h.DataPoints, wantCount)
		}
		if attrString(h.DataPoints[0].Attributes, "db_type") != "mysql" {
			t.Errorf("%s db_type = %q, want mysql", name, attrString(h.DataPoints[0].Attributes, "db_type"))
		}
	}

	// session.duration: 250ms recorded as seconds.
	h := got["session.duration"].(metricdata.Histogram[float64])
	if math.Abs(h.DataPoints[0].Sum-0.25) > 0.001 {
		t.Errorf("session.duration sum = %v, want ≈0.25s", h.DataPoints[0].Sum)
	}

	// UpDownCounter decrement returns the sum to zero (same Sum type).
	m.ConnectionsActiveDec("mysql")
	got = collect()
	ud = sum("connections.active")
	if len(ud.DataPoints) != 1 || ud.DataPoints[0].Value != 0 {
		t.Errorf("connections.active after dec = %+v, want value 0", ud.DataPoints)
	}
}

// attrString extracts one attribute value for the assertion helpers.
func attrString(attrs attribute.Set, key string) string {
	if v, ok := attrs.Value(attribute.Key(key)); ok {
		return v.AsString()
	}
	return ""
}
