package api

// Task 11 (node-integration append): the config FALLBACK POOL at mint —
// chooseRoute round-robins over cfg.DataPlaneHosts (per-process atomic
// counter, pool[counter % len]) when DB routing is disabled or fails. These
// tests pin: RR distribution across N mints (routing disabled AND routing
// failure), the single-host pool equivalence (G3: RR over one = always that
// plane), and the empty pool (legacy neither-key shape: the mint still
// succeeds with NO host/port and a named WARN — byte-identical response
// fields to the pre-pool empty fallback).

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// newPoolTestServer builds the api mux with a cfg whose fallback POOL is
// exactly pool (the legacy single fields left empty — the pool IS the
// config shape under test) and injects src (nil = routing disabled).
func newPoolTestServer(t *testing.T, src RouteSource, color string, pool []string) (*httptest.Server, *http.Client, *store.ValkeyStore, *config.ControlConfig, *bytes.Buffer) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	if color == "" {
		color = "blue"
	}
	logBuf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logBuf, nil))
	cfg := &config.ControlConfig{
		AuthUser:       testJWTUser,
		AuthPassword:   testJWTPassword,
		AuthRole:       "maker",
		JWT:            testJWTBlock(),
		SessionTTL:     8,
		TokenTTL:       60,
		StaticDir:      t.TempDir(),
		DataPlaneHosts: pool,
		Routing: config.RoutingConfig{
			Enabled: src != nil,
			Color:   color,
		},
	}
	routingCache.reset() // the cache is package-level; never leak between fixtures
	a := NewAPI(log, cfg, vs, nil)
	a.routeSource = src
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, vs, cfg, logBuf
}

// mintPool posts one mint (bearer-bound username) and returns status + the
// decoded response.
func mintPool(t *testing.T, client *http.Client, base, bearer, body string) (int, models.TokenResponse) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/token", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	var out models.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp.StatusCode, out
}

// TestFallbackPoolRRRoutingDisabled: routing disabled + a 3-entry pool → six
// mints cycle host/port A,B,C,A,B,C (round-robin per mint), every response
// carries the entry's host AND port, and the payload keeps the legacy
// fallback shape (NO data_plane field — a config fallback is not a routing
// choice).
func TestFallbackPoolRRRoutingDisabled(t *testing.T) {
	pool := []string{"10.10.0.1:3306", "10.10.0.2:3307", "10.10.0.3:3308"}
	srv, client, vs, cfg, _ := newPoolTestServer(t, nil, "blue", pool)
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	want := []string{"10.10.0.1:3306", "10.10.0.2:3307", "10.10.0.3:3308",
		"10.10.0.1:3306", "10.10.0.2:3307", "10.10.0.3:3308"}
	for i, dp := range want {
		host, port, _ := strings.Cut(dp, ":")
		status, out := mintPool(t, client, srv.URL, bearer, mintBodyFor("alice"))
		if status != http.StatusOK {
			t.Fatalf("mint %d: status %d, want 200", i, status)
		}
		if out.Host != host || out.Port != port {
			t.Errorf("mint %d: host/port = %s/%s, want %s (round-robin order)", i, out.Host, out.Port, dp)
		}
		p := fetchPayload(t, vs, out.Token)
		if field, ok := p["data_plane"]; ok {
			t.Errorf("mint %d: payload carries data_plane %v on a config fallback, want absent", i, field)
		}
	}
}

// TestFallbackPoolRROnRoutingFailure: routing ENABLED but the source errors
// → every mint still succeeds 200 and the RR cycles the pool across the
// failure fallbacks (A, B, A).
func TestFallbackPoolRROnRoutingFailure(t *testing.T) {
	src := &stubRouteSource{err: context.DeadlineExceeded}
	pool := []string{"10.11.0.1:3306", "10.11.0.2:3307"}
	srv, client, _, cfg, _ := newPoolTestServer(t, src, "blue", pool)
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	want := []string{"10.11.0.1:3306", "10.11.0.2:3307", "10.11.0.1:3306"}
	for i, dp := range want {
		host, port, _ := strings.Cut(dp, ":")
		status, out := mintPool(t, client, srv.URL, bearer, mintBodyFor("alice"))
		if status != http.StatusOK {
			t.Fatalf("mint %d: status %d, want 200 (a routing failure must NEVER fail a mint)", i, status)
		}
		if out.Host != host || out.Port != port {
			t.Errorf("mint %d: host/port = %s/%s, want %s (RR over the failure fallback)", i, out.Host, out.Port, dp)
		}
	}
}

// TestFallbackSingleHostPoolEquivalence (G3): the legacy-promoted ONE-element
// pool behaves byte-identically to the old single-host fallback — three
// mints, always the same host/port.
func TestFallbackSingleHostPoolEquivalence(t *testing.T) {
	srv, client, _, cfg, _ := newPoolTestServer(t, nil, "blue", []string{"10.255.0.1:9999"})
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	for i := 0; i < 3; i++ {
		status, out := mintPool(t, client, srv.URL, bearer, mintBodyFor("alice"))
		if status != http.StatusOK {
			t.Fatalf("mint %d: status %d, want 200", i, status)
		}
		if out.Host != "10.255.0.1" || out.Port != "9999" {
			t.Errorf("mint %d: host/port = %s/%s, want 10.255.0.1/9999 (RR over one = constant)", i, out.Host, out.Port)
		}
	}
}

// TestFallbackEmptyPoolWarnsNoHost: the pool EMPTY (neither key configured —
// the legacy shape) + routing disabled → the mint STILL succeeds 200 with
// empty host/port (byte-identical to the pre-pool empty fallback) and a
// named WARN fires (once per mint) naming the misconfiguration.
func TestFallbackEmptyPoolWarnsNoHost(t *testing.T) {
	srv, client, vs, cfg, logBuf := newPoolTestServer(t, nil, "blue", nil)
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	status, out := mintPool(t, client, srv.URL, bearer, mintBodyFor("alice"))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (an empty fallback never fails a mint)", status)
	}
	if out.Host != "" || out.Port != "" {
		t.Errorf("host/port = %q/%q, want empty (no fallback configured)", out.Host, out.Port)
	}
	p := fetchPayload(t, vs, out.Token)
	if field, ok := p["data_plane"]; ok {
		t.Errorf("payload carries data_plane %v with an empty pool, want absent", field)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "no data plane fallback configured") {
		t.Errorf("empty-pool mint logged no named WARN; log:\n%s", logs)
	}
}
