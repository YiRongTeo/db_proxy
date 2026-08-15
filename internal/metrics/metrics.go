// Package metrics carries the data plane's OpenTelemetry instruments,
// exposed on an HTTP endpoint a Prometheus server can scrape (Task 9.8,
// user directive 2026-08-15). All instruments live on the Meter
// "zerotrust.proxy" and every family is emitted under the
// "zerotrust_proxy" namespace (prometheus.WithNamespace — the exporter
// does NOT derive a prefix from the Meter scope name; without the option
// the families surface bare, e.g. tokens_validated_total instead of
// zerotrust_proxy_tokens_validated_total). The Prometheus exporter
// (v0.67.0) registers its collector with the client_golang DEFAULT
// registerer at construction, so the scrape handler serves that same
// gatherer — the stock promhttp handler over prometheus.DefaultGatherer
// also serves the standard Go runtime and process collectors (go_*,
// process_*), exactly what a real Prometheus server scrapes.
//
// DISABLED-BY-DEFAULT design (mirrors the 8.7 nil-resolver pattern): when
// config metrics.enabled is false, main constructs no Metrics value and the
// proxies' metrics field stays nil — every method is a nil-safe no-op, so
// the disabled hot path costs exactly one nil pointer check per call site.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// MeterName is the OTel meter scope for every instrument.
const MeterName = "zerotrust.proxy"

// Metrics bundles the data plane's instruments. A nil *Metrics is the
// disabled state: every method guards on the receiver and returns
// immediately, so call sites never branch on configuration themselves.
type Metrics struct {
	tokensValidated   metric.Int64Counter
	tokensRejected    metric.Int64Counter
	connectionsTotal  metric.Int64Counter
	connectionsActive metric.Int64UpDownCounter
	queriesTotal      metric.Int64Counter
	gateBlocks        metric.Int64Counter
	killsTotal        metric.Int64Counter
	sessionDuration   metric.Float64Histogram
	queryDuration     metric.Float64Histogram
}

// New builds the meter wrapper backed by the Prometheus exporter. When
// enabled is false it returns (nil, nil) — the proxies' metrics field stays
// nil and every call site is a no-op. The exporter is constructed with the
// "zerotrust_proxy" namespace (every family surfaces as
// zerotrust_proxy_<name>; the exporter derives no prefix from the Meter
// scope name) and registers its collector with prometheus.DefaultRegisterer
// (exporters/prometheus v0.67.0 New()), so Handler() serves this meter's
// instruments AND the standard Go/process collectors from the same default
// gatherer.
func New(enabled bool) (*Metrics, error) {
	if !enabled {
		return nil, nil
	}
	exporter, err := otelprom.New(
		otelprom.WithNamespace("zerotrust_proxy"),
		// Single meter scope in this process; the otel_scope_* labels the
		// exporter would otherwise add to every series are pure noise.
		otelprom.WithoutScopeInfo(),
	)
	if err != nil {
		return nil, err
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(provider)
	return newMetrics(provider.Meter(MeterName))
}

// newMetrics wires the instruments on an arbitrary meter. The unit tests
// inject a manual-reader meter provider here to assert counter movement
// without an HTTP endpoint; New() passes the Prometheus-backed meter.
func newMetrics(meter metric.Meter) (*Metrics, error) {
	var firstErr error
	fail := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	tokensValidated, err := meter.Int64Counter("tokens.validated",
		metric.WithDescription("Tokens validated by GETDEL and accepted for the session's protocol."))
	fail(err)
	tokensRejected, err := meter.Int64Counter("tokens.rejected",
		metric.WithDescription("Token validation rejections, by reason (invalid|expired|consumed|wrong_db_type)."))
	fail(err)
	connectionsTotal, err := meter.Int64Counter("connections.total",
		metric.WithDescription("Connection attempts by outcome (ok|rejected), per database type."))
	fail(err)
	connectionsActive, err := meter.Int64UpDownCounter("connections.active",
		metric.WithDescription("Currently established sessions, per database type."))
	fail(err)
	queriesTotal, err := meter.Int64Counter("queries.total",
		metric.WithDescription("Queries published by the relay, per database type, statement type and status."))
	fail(err)
	gateBlocks, err := meter.Int64Counter("gate.blocks",
		metric.WithDescription("SQL commands blocked by the maker write-gate, per database type."))
	fail(err)
	killsTotal, err := meter.Int64Counter("kills.total",
		metric.WithDescription("Kill operations applied, by mode (query|connection)."))
	fail(err)
	sessionDuration, err := meter.Float64Histogram("session.duration",
		metric.WithDescription("Session lifetime: session established to teardown, seconds."),
		metric.WithUnit("s"))
	fail(err)
	queryDuration, err := meter.Float64Histogram("query.duration",
		metric.WithDescription("Query latency: command sniffed to response completed, seconds."),
		metric.WithUnit("s"))
	fail(err)
	if firstErr != nil {
		return nil, firstErr
	}
	return &Metrics{
		tokensValidated:   tokensValidated,
		tokensRejected:    tokensRejected,
		connectionsTotal:  connectionsTotal,
		connectionsActive: connectionsActive,
		queriesTotal:      queriesTotal,
		gateBlocks:        gateBlocks,
		killsTotal:        killsTotal,
		sessionDuration:   sessionDuration,
		queryDuration:     queryDuration,
	}, nil
}

// Handler returns the Prometheus scrape handler serving this meter's
// instruments plus the standard Go/process collectors. The exporter
// registered its collector with prometheus.DefaultRegisterer at New(), so
// the handler is built explicitly over prometheus.DefaultGatherer — the
// same gatherer a stock promhttp.Handler() would serve, written out so the
// wiring is self-documenting. A nil receiver (metrics disabled) yields a
// 404 so wiring mistakes stay loud instead of serving an empty scrape.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})
}

// TokensValidated records one accepted token (GETDEL hit + protocol match).
func (m *Metrics) TokensValidated() {
	if m == nil {
		return
	}
	m.tokensValidated.Add(context.Background(), 1)
}

// TokensRejected records one rejected token. reason is one of
// "invalid" (GETDEL nil — absent, expired, or already consumed; the store
// cannot distinguish these), "expired", "consumed" or "wrong_db_type".
func (m *Metrics) TokensRejected(reason string) {
	if m == nil {
		return
	}
	m.tokensRejected.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("reason", reason)))
}

// ConnectionsTotal records one connection attempt outcome: "ok" once a
// session is established, "rejected" for every attempt that failed before
// establishment (token rejection, backend unavailable).
func (m *Metrics) ConnectionsTotal(dbType, result string) {
	if m == nil {
		return
	}
	m.connectionsTotal.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("db_type", dbType),
			attribute.String("result", result),
		))
}

// ConnectionsActiveInc marks one session established.
func (m *Metrics) ConnectionsActiveInc(dbType string) {
	if m == nil {
		return
	}
	m.connectionsActive.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("db_type", dbType)))
}

// ConnectionsActiveDec marks one session torn down.
func (m *Metrics) ConnectionsActiveDec(dbType string) {
	if m == nil {
		return
	}
	m.connectionsActive.Add(context.Background(), -1,
		metric.WithAttributes(attribute.String("db_type", dbType)))
}

// QueriesTotal records one published query event (the relay's
// publishPending completion path).
func (m *Metrics) QueriesTotal(dbType, stmtType, status string) {
	if m == nil {
		return
	}
	m.queriesTotal.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("db_type", dbType),
			attribute.String("stmt_type", stmtType),
			attribute.String("status", status),
		))
}

// GateBlocks records one SQL command blocked by the maker write-gate
// (immediate reject or grace-wait drain; one per published blocked event).
func (m *Metrics) GateBlocks(dbType string) {
	if m == nil {
		return
	}
	m.gateBlocks.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("db_type", dbType)))
}

// KillsTotal records one applied kill operation.
func (m *Metrics) KillsTotal(mode string) {
	if m == nil {
		return
	}
	m.killsTotal.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("mode", mode)))
}

// SessionDuration records a session's lifetime (established to teardown).
func (m *Metrics) SessionDuration(dbType string, d time.Duration) {
	if m == nil {
		return
	}
	m.sessionDuration.Record(context.Background(), d.Seconds(),
		metric.WithAttributes(attribute.String("db_type", dbType)))
}

// QueryDuration records one command's latency (sniffed to response done).
func (m *Metrics) QueryDuration(dbType string, d time.Duration) {
	if m == nil {
		return
	}
	m.queryDuration.Record(context.Background(), d.Seconds(),
		metric.WithAttributes(attribute.String("db_type", dbType)))
}
