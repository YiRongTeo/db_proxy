// Package api — DB-driven data-plane routing at token mint (Task 5,
// node-integration append, owner decisions 2026-10-21): when routing is
// enabled, every mint asks a MySQL table which data server to point the
// client at (color + least-loaded), instead of the single configured
// data_plane_host/port.
//
// TUNE THIS QUERY to change data-server selection: edit routeSelectQuery
// below. It is the ONLY tuning surface — no config key, no env var. The
// query MUST return exactly two columns in this order: hostname, url.
//
// Available columns of data_plane_routes:
//
//	hostname        VARCHAR(255)  — route key / display name
//	proxytype       VARCHAR(16)   — 'DB' (data servers)
//	url             VARCHAR(512)  — https://fqdn:port (normalized to host+port)
//	ipaddress       VARCHAR(64)
//	environment     VARCHAR(32)   — 'PROD'
//	country         VARCHAR(32)
//	lastheartbeat   DATETIME      — the plane's liveness stamp
//	deploymentcolor VARCHAR(16)   — 'blue' | 'green' (the query's 1 param)
//	maxsessions     INT           — capacity
//	activesessions  INT           — current load
//
// Parameter contract: exactly ONE parameter, the active color (?). Keep the
// SELECT list at (hostname, url) — internal/api scans exactly those two
// columns, validates the URL (http/https + port 1-65535) and the session
// numbers, and SKIPS rows that fail validation, falling back to the config
// data_plane_host/port when nothing eligible remains. A routing failure
// NEVER fails a mint.
package api

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"zerotrust-proxy/internal/config"
)

// routeSelectQuery is THE TUNING SURFACE (see the package comment above for
// columns + the one-color-parameter contract).
const routeSelectQuery = "SELECT `hostname`, `url` FROM `data_plane_routes` " +
	"WHERE `proxytype` = 'DB' AND `environment` = 'PROD' AND `deploymentcolor` = ? " +
	"AND `activesessions` < `maxsessions` AND `lastheartbeat` >= NOW() - INTERVAL 30 SECOND " +
	"ORDER BY `activesessions` ASC, RAND() LIMIT 1"

// routeSelectQueryDoc names the tuning surface in the boot log (exported —
// cmd/control prints it at boot so the operator knows where to tune).
const RouteSelectQueryDoc = "internal/api/dataplane_routing.go routeSelectQuery — TUNE THIS QUERY to change data-server selection"

// routeTableDDL is the OWNER'S schema, verbatim (auto-created idempotently).
const routeTableDDL = "(`hostname` VARCHAR(255) NOT NULL, " +
	"`proxytype` VARCHAR(16) NOT NULL, " +
	"`url` VARCHAR(512) NOT NULL, " +
	"`ipaddress` VARCHAR(64), " +
	"`environment` VARCHAR(32), " +
	"`country` VARCHAR(32), " +
	"`lastheartbeat` DATETIME, " +
	"`deploymentcolor` VARCHAR(16), " +
	"`maxsessions` INT, " +
	"`activesessions` INT, " +
	"PRIMARY KEY (`hostname`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"

// routeCacheTTL bounds the per-color lookup cache: mints within the TTL
// reuse one SELECT. A var (not const) so tests can shrink it.
var routeCacheTTL = 5 * time.Second

// routeLookupTimeout bounds one DB lookup: a hung routing DB must stall a
// mint for at most this long — the mint then falls back (storeCallCtx
// pattern: bounded context per logical store call).
const routeLookupTimeout = 3 * time.Second

// routeRow is one candidate data plane as the selection query returns it.
type routeRow struct {
	Hostname       string
	URL            string
	ActiveSessions int
	MaxSessions    int
}

// RouteSource abstracts the routing lookup: the live MySQL implementation
// (mySQLRouteSource) and the test stub both satisfy it. Select returns the
// eligible candidate rows for color, best candidate first. EnsureTable and
// CountRows serve the boot-time auto-create + boot log.
type RouteSource interface {
	Select(ctx context.Context, color string) ([]routeRow, error)
	EnsureTable(ctx context.Context) error
	CountRows(ctx context.Context) (int, error)
}

// mySQLRouteSource is the live RouteSource over the audit (or routing) MySQL
// database — one connection pool shared with nothing; all methods are safe
// for concurrent use.
type mySQLRouteSource struct {
	db *sql.DB
}

// NewMySQLRouteSource builds the live source over an open database handle
// (the caller owns the pool's lifecycle).
func NewMySQLRouteSource(db *sql.DB) RouteSource {
	return &mySQLRouteSource{db: db}
}

// EnsureTable auto-creates data_plane_routes with the OWNER'S schema
// (idempotent CREATE TABLE IF NOT EXISTS — the audit login_session_id
// migration pattern; a pre-existing table is left untouched).
func (m *mySQLRouteSource) EnsureTable(ctx context.Context) error {
	if _, err := m.db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS `data_plane_routes` "+routeTableDDL); err != nil {
		return fmt.Errorf("routing ensure table: %w", err)
	}
	return nil
}

// CountRows returns the row count for the boot log (routing table ready
// (N rows)). A failure is the caller's to log — never fatal.
func (m *mySQLRouteSource) CountRows(ctx context.Context) (int, error) {
	var n int
	if err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM `data_plane_routes`").Scan(&n); err != nil {
		return 0, fmt.Errorf("routing count rows: %w", err)
	}
	return n, nil
}

// Select runs the tunable query for color and returns the raw candidate
// rows; validation/normalization happens in the caller (chooseRoute) so a
// stub can feed malformed rows to the same code path the live DB does.
func (m *mySQLRouteSource) Select(ctx context.Context, color string) ([]routeRow, error) {
	rows, err := m.db.QueryContext(ctx, routeSelectQuery, color)
	if err != nil {
		return nil, fmt.Errorf("routing select: %w", err)
	}
	defer rows.Close()
	var out []routeRow
	for rows.Next() {
		var r routeRow
		if err := rows.Scan(&r.Hostname, &r.URL); err != nil {
			return nil, fmt.Errorf("routing scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// routeSelection is the per-plane mint decision: the chosen host/port and
// the data_plane string stamped into the payload + token-issued log line.
type routeSelection struct {
	Host      string
	Port      string
	DataPlane string
	Fallback  bool
}

// routeCacheEntry is one cached per-color lookup result.
type routeCacheEntry struct {
	sel     routeSelection
	expires time.Time
}

// routeCache is the 5s-TTL per-color cache. Guarded by mu; entries expire
// lazily on read.
type routeCache struct {
	mu      sync.Mutex
	entries map[string]routeCacheEntry
}

var routingCache = &routeCache{entries: map[string]routeCacheEntry{}}

// get returns the cached selection for color when fresh.
func (c *routeCache) get(color string) (routeSelection, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[color]
	if !ok || time.Now().After(e.expires) {
		return routeSelection{}, false
	}
	return e.sel, true
}

// put stores the selection for color under the (shrinkable) TTL.
func (c *routeCache) put(color string, sel routeSelection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[color] = routeCacheEntry{sel: sel, expires: time.Now().Add(routeCacheTTL)}
}

// invalidate drops one color's cached entry (tests).
func (c *routeCache) invalidate(color string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, color)
}

// reset drops every cached entry — the api test fixtures call it so the
// package-level cache never leaks one test's selection into the next.
func (c *routeCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]routeCacheEntry{}
}

// normalizeDataURL parses the owner's URL form (https://fqdn:port) into
// host + port. scheme MUST be http/https, the port MUST be present and in
// 1-65535; anything else is an error → the row is skipped. NEVER mint a
// token with an unvalidated host/port.
func normalizeDataURL(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("empty url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("scheme %q not http/https", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", "", fmt.Errorf("no host in url")
	}
	p := u.Port()
	if p == "" {
		return "", "", fmt.Errorf("no port in url")
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("port %q out of range", p)
	}
	return u.Hostname(), p, nil
}

// validateRouteRow enforces the shape + numeric guards on a candidate: a
// hostname, a URL, and sane non-negative session counters with the plane
// BELOW capacity (over-capacity rows are skipped — the drain mechanism).
func validateRouteRow(r routeRow) error {
	if strings.TrimSpace(r.Hostname) == "" {
		return fmt.Errorf("empty hostname")
	}
	if strings.TrimSpace(r.URL) == "" {
		return fmt.Errorf("empty url")
	}
	if r.ActiveSessions < 0 {
		return fmt.Errorf("negative activesessions %d", r.ActiveSessions)
	}
	if r.MaxSessions <= 0 {
		return fmt.Errorf("non-positive maxsessions %d", r.MaxSessions)
	}
	if r.ActiveSessions >= r.MaxSessions {
		return fmt.Errorf("at capacity (%d/%d)", r.ActiveSessions, r.MaxSessions)
	}
	return nil
}

// chooseRoute resolves the data plane for ONE mint. Order: the fresh cached
// selection for the color → the live lookup (bounded context) → the config
// fallback POOL (Task 11: round-robin over cfg.DataPlaneHosts via a
// per-process atomic counter; an empty pool = the legacy empty fallback).
// EVERY failure mode (DB unreachable, zero valid rows, slow query) lands on
// the config pool with a reason-only WARN — the lookup DB can NEVER fail a
// mint.
func (a *api) chooseRoute(ctx context.Context, src RouteSource, color string) routeSelection {
	// Task 11 fallback pool: round-robin over the config pool (one entry =
	// always that plane, byte-identical to the pre-pool single fallback).
	// EMPTY pool → the legacy shape (empty Host/Port/DataPlane, Fallback
	// still true — the mint proceeds, response fields blank) plus a named
	// WARN so the misconfiguration is visible per mint, never silent.
	pool := a.cfg.DataPlaneHosts
	if len(pool) == 0 {
		a.log.Warn("no data plane fallback configured — set api.data_plane_hosts (or the legacy api.data_plane_host/api.data_plane_port pair) or enable routing",
			"color", color)
		return routeSelection{Fallback: true}
	}
	entry := pool[(a.rrCounter.Add(1)-1)%uint64(len(pool))]
	host, port, err := net.SplitHostPort(entry)
	if err != nil {
		// Unreachable through LoadControl (malformed entries are dropped at
		// load) — guarded anyway so a programmatically-built cfg can never
		// mint an unvalidated host/port.
		a.log.Warn("data plane fallback pool entry invalid; skipped", "entry", entry, "reason", err.Error())
		return routeSelection{Fallback: true}
	}
	fallback := routeSelection{
		Host:      host,
		Port:      port,
		DataPlane: entry,
		Fallback:  true,
	}
	if src == nil || !a.cfg.Routing.Enabled {
		return fallback
	}
	if sel, ok := routingCache.get(color); ok {
		return sel
	}
	lctx, cancel := context.WithTimeout(ctx, routeLookupTimeout)
	defer cancel()
	rows, err := src.Select(lctx, color)
	if err != nil {
		a.log.Warn("routing lookup failed; falling back to configured data plane", "reason", err.Error())
		return fallback
	}
	for _, row := range rows {
		if err := validateRouteRow(row); err != nil {
			a.log.Warn("routing row invalid; skipped", "reason", err.Error())
			continue
		}
		host, port, err := normalizeDataURL(row.URL)
		if err != nil {
			a.log.Warn("routing row url invalid; skipped", "reason", err.Error())
			continue
		}
		sel := routeSelection{
			Host:      host,
			Port:      port,
			DataPlane: host + ":" + port,
			Fallback:  false,
		}
		routingCache.put(color, sel)
		return sel
	}
	a.log.Warn("routing lookup returned no eligible rows; falling back to configured data plane", "color", color)
	return fallback
}

// OpenRouteSource opens the routing MySQL pool from the resolved DSN (audit
// reuse or routing.mysql) and returns it with the live RouteSource. The
// caller owns the pool (defer Close). Exported for cmd/control's boot.
func OpenRouteSource(cfg *config.ControlConfig) (*sql.DB, RouteSource, error) {
	dsnCfg, ok := cfg.RoutingMySQL()
	if !ok {
		return nil, nil, fmt.Errorf("routing enabled but no MySQL DSN resolvable (audit.mysql disabled and no routing.mysql block)")
	}
	c := mysqlConfigFor(dsnCfg)
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		return nil, nil, fmt.Errorf("routing open: %w", err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("routing ping: %w", err)
	}
	return db, NewMySQLRouteSource(db), nil
}

// mysqlConfigFor builds the go-sql-driver config from a MySQLAuditConfig —
// the audit.NewWriter DSN pattern (ParseTime, UTC, bounded timeouts). The
// password never appears in logs or errors; FormatDSN output is only ever
// handed to sql.Open.
func mysqlConfigFor(cfg config.MySQLAuditConfig) *mysql.Config {
	c := mysql.NewConfig()
	c.User = cfg.User
	c.Passwd = cfg.Password
	c.Net = "tcp"
	c.Addr = cfg.Host + ":" + cfg.Port
	c.DBName = cfg.Database
	c.ParseTime = true
	c.Loc = time.UTC
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 5 * time.Second
	c.WriteTimeout = 5 * time.Second
	return c
}
