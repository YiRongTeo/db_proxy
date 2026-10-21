package api

// Task 5 (node-integration append): LIVE-MySQL integration test for the
// data-plane route source — gated on the dev mysql-test container
// (127.0.0.1:3307, root/root_pw, per RUN.md / .env.example). Skipped when
// the container is down so `go test ./...` stays green on bare laptops.
// Proves: the owner's exact data_plane_routes schema auto-creates, the
// TUNABLE query picks by color + least activesessions, heartbeat/capacity
// guards hold, and the query stays THE one tuning surface.

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// routeTestDSN builds a DSN for the throwaway route-test database.
func routeTestDSN(dbName string) string {
	c := mysql.NewConfig()
	c.User = "root"
	c.Passwd = "root_pw"
	c.Net = "tcp"
	c.Addr = "127.0.0.1:3307"
	c.DBName = dbName
	c.ParseTime = true
	c.Loc = time.UTC
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 5 * time.Second
	c.WriteTimeout = 5 * time.Second
	return c.FormatDSN()
}

// openRouteTestDB opens the mysql-test server, creating a THROWAWAY database
// (dropped on cleanup). Skips the test when the container is unreachable.
func openRouteTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Probe with no database first — the container may be up while the
	// default schema is absent.
	probe, err := sql.Open("mysql", routeTestDSN(""))
	if err != nil {
		t.Skipf("mysql-test container not reachable (open): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe.PingContext(ctx); err != nil {
		probe.Close()
		t.Skipf("mysql-test container not reachable (ping): %v", err)
	}
	probe.Close()

	dbName := fmt.Sprintf("zt_routes_test_%d", time.Now().UnixNano()%1_000_000_000)
	db, err := sql.Open("mysql", routeTestDSN(""))
	if err != nil {
		t.Skipf("open route test db: %v", err)
	}
	if _, err := db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS `"+dbName+"`"); err != nil {
		db.Close()
		t.Skipf("create route test db: %v", err)
	}
	if _, err := db.ExecContext(ctx, "USE `"+dbName+"`"); err != nil {
		db.Close()
		t.Skipf("use route test db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP DATABASE IF EXISTS `"+dbName+"`")
		db.Close()
	})
	return db
}

// seedRoute inserts one route row.
func seedRoute(t *testing.T, db *sql.DB, row routeRow, color string, active, max int, heartbeatAgo time.Duration) {
	t.Helper()
	// The lookup DSN uses Loc=UTC (audit pattern): heartbeat strings must be
	// written in UTC wall clock or the comparison silently shifts by the
	// local offset.
	hb := time.Now().UTC().Add(-heartbeatAgo).Format("2006-01-02 15:04:05")
	_, err := db.ExecContext(context.Background(),
		"INSERT INTO `data_plane_routes` (`hostname`,`proxytype`,`url`,`ipaddress`,`environment`,`country`,`lastheartbeat`,`deploymentcolor`,`maxsessions`,`activesessions`) "+
			"VALUES (?, 'DB', ?, '10.0.0.1', 'PROD', 'DE', ?, ?, ?, ?)",
		row.Hostname, row.URL, hb, color, max, active)
	if err != nil {
		t.Fatalf("seed route %s: %v", row.Hostname, err)
	}
}

// TestRouteSourceLiveIntegration is THE live gate: schema auto-create +
// tunable query semantics against the real MySQL server.
func TestRouteSourceLiveIntegration(t *testing.T) {
	db := openRouteTestDB(t)

	src := NewMySQLRouteSource(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. EnsureTable auto-creates the OWNER'S schema, idempotently.
	if err := src.EnsureTable(ctx); err != nil {
		t.Fatalf("EnsureTable: %v", err)
	}
	if err := src.EnsureTable(ctx); err != nil {
		t.Fatalf("EnsureTable (second run, must be idempotent): %v", err)
	}
	var colCount int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'data_plane_routes'").Scan(&colCount); err != nil {
		t.Fatalf("information_schema probe: %v", err)
	}
	if colCount != 10 {
		t.Fatalf("data_plane_routes has %d columns, want 10 (owner schema verbatim)", colCount)
	}

	// 2. Boot log contract: routing table ready (N rows).
	n, err := src.CountRows(ctx)
	if err != nil {
		t.Fatalf("CountRows: %v", err)
	}
	if n != 0 {
		t.Fatalf("fresh table has %d rows, want 0", n)
	}

	// 3. Selection: color blue, least activesessions wins; the stale-
	// heartbeat row and the at-capacity row are excluded; green rows are
	// invisible to a blue lookup.
	seedRoute(t, db, routeRow{Hostname: "b-heavy", URL: "https://b-heavy:3307"}, "blue", 50, 100, 2*time.Second)
	seedRoute(t, db, routeRow{Hostname: "b-light", URL: "https://b-light:3307"}, "blue", 3, 100, 2*time.Second)
	seedRoute(t, db, routeRow{Hostname: "b-stale", URL: "https://b-stale:3307"}, "blue", 1, 100, 45*time.Second) // heartbeat older than 30s
	seedRoute(t, db, routeRow{Hostname: "b-full", URL: "https://b-full:3307"}, "blue", 100, 100, 2*time.Second)  // at capacity
	seedRoute(t, db, routeRow{Hostname: "g-light", URL: "https://g-light:3307"}, "green", 0, 100, 2*time.Second) // wrong color

	rows, err := src.Select(ctx, "blue")
	if err != nil {
		t.Fatalf("Select(blue): %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("Select(blue) returned no rows, want b-light (least loaded, alive)")
	}
	if rows[0].Hostname != "b-light" {
		t.Errorf("Select(blue)[0] = %s, want b-light (least activesessions among eligible)", rows[0].Hostname)
	}
	host, port, err := normalizeDataURL(rows[0].URL)
	if err != nil || host != "b-light" || port != "3307" {
		t.Errorf("normalizeDataURL(%q) = %q,%q,%v; want b-light,3307,nil", rows[0].URL, host, port, err)
	}

	// 4. Color switch: green sees only the green row.
	gRows, err := src.Select(ctx, "green")
	if err != nil {
		t.Fatalf("Select(green): %v", err)
	}
	if len(gRows) != 1 || gRows[0].Hostname != "g-light" {
		t.Errorf("Select(green) = %+v, want exactly [g-light]", gRows)
	}

	// 5. Zero eligible rows for an unknown color → empty (caller falls
	// back), never an error that could fail a mint.
	if empty, err := src.Select(ctx, "purple"); err != nil || len(empty) != 0 {
		t.Errorf("Select(purple) = %+v, %v; want empty, nil", empty, err)
	}

	// 6. The tunable query must remain ONE named constant carrying the
	// tune-me doc contract.
	if routeSelectQuery == "" || RouteSelectQueryDoc == "" {
		t.Error("routeSelectQuery/RouteSelectQueryDoc must be non-empty (the tuning surface)")
	}
}
