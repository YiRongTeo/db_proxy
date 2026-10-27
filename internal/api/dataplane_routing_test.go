package api

// Task 5 (node-integration append): DB-driven data-plane routing at token
// mint — seam-level tests. RouteSource is the interface seam (the real
// implementation SELECTs from data_plane_routes on the audit MySQL); these
// tests pin: URL/number normalization (bad rows skipped, never trusted),
// fallback to config host/port on ANY failure (a mint NEVER fails because
// routing failed), the 5s per-color cache (two mints within TTL = one
// SELECT), color switching, and disabled = the config plane with zero
// source calls.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// stubRouteSource counts Select calls and serves canned rows/errors — the
// RouteSource seam so selection logic is tested without a MySQL server.
type stubRouteSource struct {
	calls int
	rows  []routeRow
	err   error
	delay time.Duration
}

func (s *stubRouteSource) Select(ctx context.Context, color string) ([]routeRow, error) {
	s.calls++
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.rows, nil
}

func (s *stubRouteSource) EnsureTable(ctx context.Context) error { return nil }

func (s *stubRouteSource) CountRows(ctx context.Context) (int, error) {
	return len(s.rows), nil
}

// mintBodyFor builds a valid mint payload whose username MATCHES the bearer
// principal under test (handleToken binds body username == JWT sub).
func mintBodyFor(username string) string {
	return `{"username":"` + username + `","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3306","db_type":"mysql","ticket_id":"T-RT"}`
}

// newRoutingTestServer builds the api mux with a cfg whose fallback plane is
// 10.255.0.1:9999 (distinct from every routed row) and injects src (nil =
// routing disabled, the G3 default shape).
func newRoutingTestServer(t *testing.T, src RouteSource, color string) (*httptest.Server, *http.Client, *store.ValkeyStore, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	if color == "" {
		color = "blue"
	}
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "maker",
		JWT:          testJWTBlock(),
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
		// The fallback plane: anything the response shows from here came
		// from config, not routing. The single pair mirrors LoadControl's
		// legacy promotion (Task 11): the pool field is what chooseRoute
		// consumes, the old fields stay populated for completeness.
		DataPlaneHost: "10.255.0.1",
		DataPlanePort: "9999",
		DataPlaneHosts: []string{
			cfgLegacyFallbackHost + ":" + cfgLegacyFallbackPort,
		},
		Routing: config.RoutingConfig{
			Enabled: src != nil,
			Color:   color,
		},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	routingCache.reset() // the cache is package-level; never leak between fixtures
	a := NewAPI(log, cfg, vs, nil)
	a.routeSource = src
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, vs, cfg
}

// mintRouting posts one mint and returns status + the decoded response.
func mintRouting(t *testing.T, client *http.Client, base, bearer, body string) (int, models.TokenResponse) {
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

// routeRowBlue/Green are valid rows on distinct planes.
var (
	routeRowBlue  = routeRow{Hostname: "db-blue1", URL: "https://db-blue1.internal:3307", ActiveSessions: 2, MaxSessions: 100}
	routeRowGreen = routeRow{Hostname: "db-green1", URL: "https://db-green1.internal:3307", ActiveSessions: 9, MaxSessions: 100}
)

// cfgLegacyFallbackHost/Port: the legacy single fallback plane every
// routing-suite fixture promotes to a one-element pool (the Task 11
// LoadControl rule: old keys → pool[field:field]).
const (
	cfgLegacyFallbackHost = "10.255.0.1"
	cfgLegacyFallbackPort = "9999"
)

// TestRoutingDisabledByteIdentical (G3): routing disabled → the response
// carries the config host/port, the payload carries NO data_plane field, and
// the route source is never consulted.
func TestRoutingDisabledByteIdentical(t *testing.T) {
	src := &stubRouteSource{rows: []routeRow{routeRowBlue}}
	srv, client, vs, cfg := newRoutingTestServer(t, nil, "blue")
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	status, out := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice"))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if out.Host != "10.255.0.1" || out.Port != "9999" {
		t.Errorf("host/port = %s/%s, want the config plane 10.255.0.1/9999", out.Host, out.Port)
	}
	if src.calls != 0 {
		t.Errorf("route source consulted %d times with routing disabled, want 0", src.calls)
	}
	p := fetchPayload(t, vs, out.Token)
	if dp, ok := p["data_plane"]; ok {
		t.Errorf("payload carries data_plane %v with routing disabled", dp)
	}
}

// TestRoutingChoosesRowAndStampsPayload: routing enabled + one valid row →
// the response host/port and the payload's data_plane carry the chosen plane.
func TestRoutingChoosesRowAndStampsPayload(t *testing.T) {
	src := &stubRouteSource{rows: []routeRow{routeRowBlue}}
	srv, client, vs, cfg := newRoutingTestServer(t, src, "blue")
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	status, out := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice"))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if out.Host != "db-blue1.internal" || out.Port != "3307" {
		t.Errorf("host/port = %s/%s, want db-blue1.internal/3307 (URL normalized)", out.Host, out.Port)
	}
	p := fetchPayload(t, vs, out.Token)
	if got, _ := p["data_plane"].(string); got != "db-blue1.internal:3307" {
		t.Errorf("payload data_plane = %v, want db-blue1.internal:3307", p["data_plane"])
	}
	if src.calls != 1 {
		t.Errorf("Select calls = %d, want 1", src.calls)
	}
}

// TestRoutingCacheOneSelectPerTTL: two mints within the 5s TTL → exactly one
// Select (per color).
func TestRoutingCacheOneSelectPerTTL(t *testing.T) {
	src := &stubRouteSource{rows: []routeRow{routeRowBlue}}
	srv, client, _, cfg := newRoutingTestServer(t, src, "blue")
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	for i := 0; i < 2; i++ {
		status, _ := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice"))
		if status != http.StatusOK {
			t.Fatalf("mint %d: status %d, want 200", i, status)
		}
	}
	if src.calls != 1 {
		t.Errorf("Select calls after two mints within TTL = %d, want 1 (cache)", src.calls)
	}
}

// TestRoutingCacheExpiry: after the TTL lapses the next mint queries again.
func TestRoutingCacheExpiry(t *testing.T) {
	src := &stubRouteSource{rows: []routeRow{routeRowBlue}}
	srv, client, _, cfg := newRoutingTestServer(t, src, "blue")
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	if status, _ := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice")); status != http.StatusOK {
		t.Fatalf("mint 1: status %d", status)
	}
	if src.calls != 1 {
		t.Fatalf("Select calls after mint 1 = %d, want 1", src.calls)
	}
	// Expire the cached entry: shrink the TTL AND drop the stamped entry
	// (its expiry was fixed at put() time with the old TTL).
	prev := routeCacheTTL
	routeCacheTTL = time.Nanosecond
	t.Cleanup(func() { routeCacheTTL = prev })
	routingCache.invalidate("blue")
	if status, _ := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice")); status != http.StatusOK {
		t.Fatalf("mint 2: status %d", status)
	}
	if src.calls != 2 {
		t.Errorf("Select calls after TTL expiry = %d, want 2", src.calls)
	}
}

// TestRoutingColorSwitch: color green selects the green row (the color is a
// query parameter, not config-implicit).
func TestRoutingColorSwitch(t *testing.T) {
	src := &stubRouteSource{rows: []routeRow{routeRowGreen}}
	srv, client, _, cfg := newRoutingTestServer(t, src, "green")
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	status, out := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice"))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if out.Host != "db-green1.internal" || out.Port != "3307" {
		t.Errorf("host/port = %s/%s, want db-green1.internal/3307", out.Host, out.Port)
	}
	if src.calls != 1 {
		t.Errorf("Select calls = %d, want 1", src.calls)
	}
}

// TestRoutingFallbackOnSourceError: the source errors (DB down) → the mint
// STILL succeeds 200 with the config plane + data_plane fallback marker.
func TestRoutingFallbackOnSourceError(t *testing.T) {
	src := &stubRouteSource{err: errors.New("dial tcp 10.9.9.9:3306: connection refused")}
	srv, client, vs, cfg := newRoutingTestServer(t, src, "blue")
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	status, out := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice"))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (a routing failure must NEVER fail a mint)", status)
	}
	if out.Host != "10.255.0.1" || out.Port != "9999" {
		t.Errorf("host/port = %s/%s, want the config fallback 10.255.0.1/9999", out.Host, out.Port)
	}
	// A routing FAILURE is not a routing CHOICE: the payload carries NO
	// data_plane (the config plane is implicit legacy behavior) while the
	// RESPONSE still hands the client the usable config host/port.
	p := fetchPayload(t, vs, out.Token)
	if dp, ok := p["data_plane"]; ok {
		t.Errorf("payload carries data_plane %v on a routing failure, want absent", dp)
	}
}

// TestRoutingFallbackOnNoValidRows: rows that all fail validation (bad URL
// scheme, missing port, port 0, insane numbers) → fallback to config.
func TestRoutingFallbackOnNoValidRows(t *testing.T) {
	bad := []routeRow{
		{Hostname: "ftp-row", URL: "ftp://db1:21", ActiveSessions: 1, MaxSessions: 10},              // scheme
		{Hostname: "noport", URL: "https://db2.internal", ActiveSessions: 1, MaxSessions: 10},       // no port
		{Hostname: "badport", URL: "https://db3.internal:0", ActiveSessions: 1, MaxSessions: 10},    // port 0
		{Hostname: "bignum", URL: "https://db4.internal:3306", ActiveSessions: -5, MaxSessions: 10}, // negative sessions
		{Hostname: "nocap", URL: "https://db5.internal:3306", ActiveSessions: 1, MaxSessions: 0},    // cap 0
	}
	for i, row := range bad {
		src := &stubRouteSource{rows: []routeRow{row}}
		srv, client, _, cfg := newRoutingTestServer(t, src, "blue")
		name := fmt.Sprintf("jack%d", i)
		bearer := mintJWT(t, cfg, name, "maker")
		client = withBearer(client, bearer)
		status, out := mintRouting(t, client, srv.URL, bearer, mintBodyFor(name))
		if status != http.StatusOK {
			t.Fatalf("row %d (%s): status %d, want 200", i, row.Hostname, status)
		}
		if out.Host != "10.255.0.1" || out.Port != "9999" {
			t.Errorf("row %d (%s): got %s/%s, want config fallback 10.255.0.1/9999",
				i, row.Hostname, out.Host, out.Port)
		}
	}
}

// TestRoutingSkipsBadRowPicksNext: one malformed row ahead of a valid one →
// the valid one is chosen (batched candidates, per-row skip).
func TestRoutingSkipsBadRowPicksNext(t *testing.T) {
	src := &stubRouteSource{rows: []routeRow{
		{Hostname: "broken", URL: "https://broken.internal", ActiveSessions: 1, MaxSessions: 10}, // no port
		routeRowBlue,
	}}
	srv, client, _, cfg := newRoutingTestServer(t, src, "blue")
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	status, out := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice"))
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if out.Host != "db-blue1.internal" || out.Port != "3307" {
		t.Errorf("host/port = %s/%s, want db-blue1.internal/3307 (bad row skipped)", out.Host, out.Port)
	}
}

// TestRoutingFallbackOnSlowSource: a source hanging beyond the bounded
// context → the mint falls back promptly, never wedging the request.
func TestRoutingFallbackOnSlowSource(t *testing.T) {
	src := &stubRouteSource{rows: []routeRow{routeRowBlue}, delay: 10 * time.Second}
	srv, client, _, cfg := newRoutingTestServer(t, src, "blue")
	bearer := mintJWT(t, cfg, "alice", "maker")
	client = withBearer(client, bearer)

	done := make(chan models.TokenResponse, 1)
	go func() {
		_, out := mintRouting(t, client, srv.URL, bearer, mintBodyFor("alice"))
		done <- out
	}()
	select {
	case out := <-done:
		if out.Host != "10.255.0.1" || out.Port != "9999" {
			t.Errorf("host/port = %s/%s, want config fallback after ctx timeout", out.Host, out.Port)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mint wedged on a slow route source — the lookup context must be bounded")
	}
}

// TestNormalizeDataURL pins the URL contract: https/http + explicit port →
// host/port; everything else (wrong scheme, missing port, port out of range,
// garbage) is rejected.
func TestNormalizeDataURL(t *testing.T) {
	ok := []struct{ raw, host, port string }{
		{"https://db1.internal:3307", "db1.internal", "3307"},
		{"http://db2.internal:3306", "db2.internal", "3306"},
		{"https://db3.internal:80", "db3.internal", "80"},
		{"https://db4.internal:65535", "db4.internal", "65535"},
	}
	for _, tc := range ok {
		host, port, err := normalizeDataURL(tc.raw)
		if err != nil || host != tc.host || port != tc.port {
			t.Errorf("normalizeDataURL(%q) = %q,%q,%v; want %q,%q,nil", tc.raw, host, port, err, tc.host, tc.port)
		}
	}
	bad := []string{
		"",                              // empty
		"https://",                      // no host
		"db1.internal:3307",             // no scheme
		"ftp://db1:21",                  // scheme not http/https
		"https://db1.internal",          // no port
		"https://db1.internal:0",        // port 0
		"https://db1.internal:65536",    // port too big
		"https://db1.internal:notaport", // not a port
		"://:",                          // garbage
	}
	for _, raw := range bad {
		if host, port, err := normalizeDataURL(raw); err == nil {
			t.Errorf("normalizeDataURL(%q) = %q,%q,nil; want error", raw, host, port)
		}
	}
}

// TestValidateRouteRow pins the numeric guards: activesessions/maxsessions
// must be sane or the row is skipped.
func TestValidateRouteRow(t *testing.T) {
	if err := validateRouteRow(routeRowBlue); err != nil {
		t.Errorf("valid row rejected: %v", err)
	}
	rows := []routeRow{
		{Hostname: "h", URL: "https://h:1", ActiveSessions: -1, MaxSessions: 10},
		{Hostname: "h", URL: "https://h:1", ActiveSessions: 5, MaxSessions: 0},
		{Hostname: "h", URL: "https://h:1", ActiveSessions: 5, MaxSessions: -2},
		{Hostname: "h", URL: "https://h:1", ActiveSessions: 10, MaxSessions: 5}, // over capacity
		{Hostname: "", URL: "https://h:1", ActiveSessions: 1, MaxSessions: 10},  // no hostname
		{Hostname: "h", URL: "", ActiveSessions: 1, MaxSessions: 10},            // no url
	}
	for i, row := range rows {
		if err := validateRouteRow(row); err == nil {
			t.Errorf("row %d (%+v) accepted, want error", i, row)
		}
	}
}
