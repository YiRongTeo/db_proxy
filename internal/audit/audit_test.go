package audit

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// Live-test targets: the shared dev mysql-test container (RUN.md §1.2) by
// default. ZT_AUDIT_TEST_HOST / ZT_AUDIT_TEST_PORT / ZT_AUDIT_TEST_USER /
// ZT_AUDIT_TEST_PASSWORD point the suite at any MySQL/MariaDB-compatible
// sink — the portable upsert syntax (review 2026-08-17) is verified against
// MariaDB by running the suite with ZT_AUDIT_TEST_PORT=<mariadb port>.
// The writer needs CREATE DATABASE, so the dev container root is used — the
// same class of committed dev credential as configs/data.yaml. Every test
// works on a THROWAWAY database (zt_audit_test_<n>) dropped on cleanup.
var (
	liveHost = envOr("ZT_AUDIT_TEST_HOST", "127.0.0.1")
	livePort = envOr("ZT_AUDIT_TEST_PORT", "3307")
	liveUser = envOr("ZT_AUDIT_TEST_USER", "root")
	livePass = envOr("ZT_AUDIT_TEST_PASSWORD", "root_pw")
)

// envOr returns the env var value or the default when unset.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// newLiveWriter opens a writer against a throwaway database on mysql-test
// and registers cleanup: close the pool + DROP DATABASE.
func newLiveWriter(t *testing.T) *Writer {
	t.Helper()
	name := fmt.Sprintf("zt_audit_test_%d", time.Now().UnixNano()%1_000_000_000)
	w, err := NewWriter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		Config{Host: liveHost, Port: livePort, User: liveUser, Password: livePass, Database: name})
	if err != nil {
		t.Fatalf("NewWriter(%s): %v", name, err)
	}
	t.Cleanup(func() {
		_ = w.Close()
		dropDatabase(t, name)
	})
	return w
}

// dropDatabase drops the throwaway database through a fresh root connection.
func dropDatabase(t *testing.T, name string) {
	t.Helper()
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/", liveUser, livePass, liveHost, livePort))
	if err != nil {
		return
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx, "DROP DATABASE IF EXISTS `"+name+"`")
}

// auditRow is a decoded sessions row for assertions.
type auditRow struct {
	sessionID      string
	username       string
	ticketID       string
	dbType         string
	dbUser         string
	db             string
	access         string
	checker        sql.NullString
	status         string
	startedAt      sql.NullTime
	endedAt        sql.NullTime
	loginSessionID sql.NullString // Phase 2b: IdP login session id (NULL for local logins)
	lastSeen       time.Time
	createdAt      time.Time
}

// fetchRow SELECTs the session row from the writer's table.
func fetchRow(t *testing.T, w *Writer, sid string) auditRow {
	t.Helper()
	q := "SELECT `session_id`, `username`, `ticket_id`, `db_type`, `db_user`, `db`, `access`, " +
		"`checker_username`, `status`, `started_at`, `ended_at`, `login_session_id`, `last_seen`, `created_at` FROM " +
		w.tbl + " WHERE `session_id` = ?"
	var r auditRow
	err := w.db.QueryRowContext(context.Background(), q, sid).Scan(
		&r.sessionID, &r.username, &r.ticketID, &r.dbType, &r.dbUser, &r.db, &r.access,
		&r.checker, &r.status, &r.startedAt, &r.endedAt, &r.loginSessionID, &r.lastSeen, &r.createdAt)
	if err != nil {
		t.Fatalf("SELECT audit row %s: %v", sid, err)
	}
	return r
}

// rowCount counts rows for a session_id (idempotency assertions).
func rowCount(t *testing.T, w *Writer, sid string) int {
	t.Helper()
	var n int
	err := w.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+w.tbl+" WHERE `session_id` = ?", sid).Scan(&n)
	if err != nil {
		t.Fatalf("COUNT audit rows %s: %v", sid, err)
	}
	return n
}

// ErrClosed reports whether the underlying pool is closed (review 9.9: the
// test-only helper moved OUT of the production file — tests use it to prove
// write failures surface as errors, never panics).
func (w *Writer) ErrClosed() error {
	if w == nil || w.db == nil {
		return fmt.Errorf("audit writer not initialized")
	}
	return w.db.Ping()
}

// TestNewWriterCreatesSchema: NewWriter auto-creates the database + sessions
// table on the live server (the throwaway DB name proves it).
func TestNewWriterCreatesSchema(t *testing.T) {
	w := newLiveWriter(t)
	if err := w.ErrClosed(); err != nil {
		t.Fatalf("writer ping: %v", err)
	}
	var n int
	err := w.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = 'sessions'",
		strings.TrimPrefix(strings.TrimSuffix(strings.Split(w.tbl, ".")[0], "`"), "`")).Scan(&n)
	if err != nil {
		t.Fatalf("information_schema query: %v", err)
	}
	if n != 1 {
		t.Errorf("sessions table in throwaway db: count = %d, want 1", n)
	}
}

// TestLoginSessionIDPersisted (Phase 2b Task 4): UpsertSession with a
// LoginSessionID writes it into the row (external JWT mint → the trace to
// the IdP login); an empty LoginSessionID lands NULL (local login).
func TestLoginSessionIDPersisted(t *testing.T) {
	w := newLiveWriter(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// External-issuer mint: session carries the IdP login session id.
	if err := w.UpsertSession(ctx, SessionRecord{
		SessionID:      "sid-ext-1",
		Username:       "alice",
		TicketID:       "T-EXT-1",
		DBType:         "mysql",
		DBUser:         "rw_user",
		Access:         "write",
		LoginSessionID: "sess-login-abc123",
		LastSeen:       now,
	}); err != nil {
		t.Fatalf("UpsertSession with login session id: %v", err)
	}
	r := fetchRow(t, w, "sid-ext-1")
	if !r.loginSessionID.Valid || r.loginSessionID.String != "sess-login-abc123" {
		t.Errorf("login_session_id = %+v, want sess-login-abc123", r.loginSessionID)
	}

	// Local login: no IdP session → NULL in the row.
	if err := w.UpsertSession(ctx, SessionRecord{
		SessionID: "sid-local-1",
		Username:  "admin",
		TicketID:  "T-LOCAL-1",
		DBType:    "postgres",
		DBUser:    "ro_user",
		Access:    "read",
		LastSeen:  now,
	}); err != nil {
		t.Fatalf("UpsertSession without login session id: %v", err)
	}
	r2 := fetchRow(t, w, "sid-local-1")
	if r2.loginSessionID.Valid {
		t.Errorf("login_session_id = %q, want NULL for a local login", r2.loginSessionID.String)
	}
}

// TestLoginSessionIDMigration (Phase 2b Task 4): NewWriter against a
// PRE-EXISTING table created WITHOUT the login_session_id column adds it
// (the ALTER path — CREATE TABLE IF NOT EXISTS alone would never touch a
// legacy table). Idempotent: a second NewWriter run sees the column and
// skips the ALTER.
func TestLoginSessionIDMigration(t *testing.T) {
	t.Helper()
	// Create a LEGACY-shape table (no login_session_id) in a throwaway db.
	name := fmt.Sprintf("zt_audit_legacy_%d", time.Now().UnixNano()%1_000_000_000)
	root, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/", liveUser, livePass, liveHost, livePort))
	if err != nil {
		t.Fatalf("root open: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := root.ExecContext(ctx, "CREATE DATABASE `"+name+"`"); err != nil {
		t.Fatalf("create legacy db: %v", err)
	}
	t.Cleanup(func() {
		dc, dcCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcCancel()
		_, _ = root.ExecContext(dc, "DROP DATABASE IF EXISTS `"+name+"`")
	})
	legacyCols := "(`id` BIGINT AUTO_INCREMENT PRIMARY KEY, `session_id` VARCHAR(64) NOT NULL UNIQUE, " +
		"`username` VARCHAR(128) NOT NULL, `ticket_id` VARCHAR(128) NOT NULL DEFAULT '', " +
		"`db_type` VARCHAR(16) NOT NULL DEFAULT '', `db_user` VARCHAR(128) NOT NULL DEFAULT '', " +
		"`db` VARCHAR(128) NOT NULL DEFAULT '', `access` VARCHAR(8) NOT NULL DEFAULT 'read', " +
		"`checker_username` VARCHAR(128) NULL, `status` VARCHAR(16) NOT NULL DEFAULT 'pending', " +
		"`started_at` DATETIME(3) NULL, `ended_at` DATETIME(3) NULL, " +
		"`last_seen` DATETIME(3) NOT NULL, `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), " +
		"INDEX `idx_status` (`status`), INDEX `idx_username` (`username`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
	if _, err := root.ExecContext(ctx, "CREATE TABLE `"+name+"`.`sessions` "+legacyCols); err != nil {
		t.Fatalf("create legacy sessions table: %v", err)
	}

	// NewWriter against the legacy table must ADD the column (migration).
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w, err := NewWriter(log, Config{Host: liveHost, Port: livePort, User: liveUser, Password: livePass, Database: name})
	if err != nil {
		t.Fatalf("NewWriter on legacy table: %v", err)
	}
	defer w.Close()

	var colCount int
	if err := w.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'sessions' AND COLUMN_NAME = 'login_session_id'",
		name).Scan(&colCount); err != nil {
		t.Fatalf("column probe after migration: %v", err)
	}
	if colCount != 1 {
		t.Fatalf("login_session_id column count after NewWriter = %d, want 1 (migration ran)", colCount)
	}

	// Idempotency: a second NewWriter run must not error on the ALTER.
	w2, err := NewWriter(log, Config{Host: liveHost, Port: livePort, User: liveUser, Password: livePass, Database: name})
	if err != nil {
		t.Fatalf("second NewWriter (idempotency): %v", err)
	}
	w2.Close()
}

// TestNewWriterFailFasts: missing fields, an unreachable host and a bad
// password are all construction errors (fail-fast, never a silent writer).
func TestNewWriterFailFasts(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewWriter(log, Config{Host: "127.0.0.1", Port: "3307", User: "root", Password: ""}); err == nil {
		t.Error("NewWriter with empty password: want error, got nil")
	}
	if _, err := NewWriter(log, Config{Host: "127.0.0.1", Port: "1", User: "root", Password: "root_pw", Database: "zt_audit_x"}); err == nil {
		t.Error("NewWriter with unreachable port: want error, got nil")
	}
	if _, err := NewWriter(log, Config{Host: "127.0.0.1", Port: "3307", User: "root", Password: "wrong", Database: "zt_audit_x"}); err == nil {
		t.Error("NewWriter with bad password: want error, got nil")
	}
	if _, err := NewWriter(log, Config{Host: "127.0.0.1", Port: "3307", User: "root", Password: "root_pw", Database: "bad name!"}); err == nil {
		t.Error("NewWriter with invalid database name: want error, got nil")
	}
}

// TestUpsertSessionIdempotent: two UpsertSession calls for the same sid land
// as ONE row, the second call's fields win, and lifecycle-owned columns
// (status/checker/timestamps) are never clobbered by the pending upsert.
func TestUpsertSessionIdempotent(t *testing.T) {
	w := newLiveWriter(t)
	ctx := context.Background()
	sid := "sid-upsert-test"
	now := time.Now().UTC()
	if err := w.UpsertSession(ctx, SessionRecord{
		SessionID: sid, Username: "alice", TicketID: "T-1", DBType: "mysql", DBUser: "ro_user",
		Access: "read", LastSeen: now,
	}); err != nil {
		t.Fatalf("UpsertSession #1: %v", err)
	}
	// Second upsert refreshes the maker/db fields only.
	if err := w.UpsertSession(ctx, SessionRecord{
		SessionID: sid, Username: "alice", TicketID: "T-1b", DBType: "postgres", DBUser: "ro_user",
		Access: "write", LastSeen: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("UpsertSession #2: %v", err)
	}
	if n := rowCount(t, w, sid); n != 1 {
		t.Fatalf("rows for %s = %d, want exactly 1 (idempotent)", sid, n)
	}
	r := fetchRow(t, w, sid)
	if r.ticketID != "T-1b" || r.dbType != "postgres" || r.access != "write" {
		t.Errorf("upsert refresh = ticket %q db_type %q access %q, want T-1b/postgres/write", r.ticketID, r.dbType, r.access)
	}
	if r.username != "alice" || r.status != "pending" {
		t.Errorf("pending row = username %q status %q, want alice/pending", r.username, r.status)
	}
	if r.checker.Valid {
		t.Errorf("pending row checker_username = %q, want NULL", r.checker.String)
	}
	if r.startedAt.Valid || r.endedAt.Valid {
		t.Errorf("pending row started_at=%v ended_at=%v, want both NULL", r.startedAt.Valid, r.endedAt.Valid)
	}
	if r.lastSeen.IsZero() || r.createdAt.IsZero() {
		t.Errorf("pending row last_seen=%v created_at=%v, want non-zero", r.lastSeen, r.createdAt)
	}
}

// TestLifecycleTransitions drives the full pending→active→ended lifecycle
// plus checker attach/detach against the real table and asserts every field
// the dispatch names, verbatim.
func TestLifecycleTransitions(t *testing.T) {
	w := newLiveWriter(t)
	ctx := context.Background()
	sid := "sid-lifecycle-test"
	started := time.Date(2026, 8, 15, 10, 30, 0, 123000000, time.UTC)
	ended := started.Add(42 * time.Second)

	if err := w.UpsertSession(ctx, SessionRecord{
		SessionID: sid, Username: "bob", TicketID: "T-9-7", DBType: "mysql", DBUser: "rw_user",
		Access: "write", LastSeen: started,
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}

	// started → active, db fields refreshed from the event.
	if err := w.SetActive(ctx, ActiveRecord{
		SessionID: sid, Username: "bob", DBType: "mysql", DBUser: "rw_user", DB: "appdb",
		StartedAt: started, LastSeen: started.Add(time.Second),
	}); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	r := fetchRow(t, w, sid)
	if r.status != "active" {
		t.Errorf("status = %q, want active", r.status)
	}
	if !r.startedAt.Valid || !r.startedAt.Time.Equal(started) {
		t.Errorf("started_at = %v, want %v", r.startedAt, started)
	}
	if r.db != "appdb" || r.dbUser != "rw_user" || r.dbType != "mysql" {
		t.Errorf("active db fields = db %q db_user %q db_type %q, want appdb/rw_user/mysql", r.db, r.dbUser, r.dbType)
	}

	// checker attaches → username set; detaches → NULL.
	if err := w.SetChecker(ctx, sid, "carol"); err != nil {
		t.Fatalf("SetChecker attach: %v", err)
	}
	r = fetchRow(t, w, sid)
	if !r.checker.Valid || r.checker.String != "carol" {
		t.Errorf("checker_username = %v, want carol", r.checker)
	}
	if r.status != "active" {
		t.Errorf("SetChecker clobbered status = %q, want active", r.status)
	}
	if err := w.SetChecker(ctx, sid, ""); err != nil {
		t.Fatalf("SetChecker detach: %v", err)
	}
	r = fetchRow(t, w, sid)
	if r.checker.Valid {
		t.Errorf("checker_username = %q, want NULL after detach", r.checker.String)
	}

	// ended → status ended + ended_at.
	if err := w.SetEnded(ctx, sid, ended); err != nil {
		t.Fatalf("SetEnded: %v", err)
	}
	r = fetchRow(t, w, sid)
	if r.status != "ended" {
		t.Errorf("status = %q, want ended", r.status)
	}
	if !r.endedAt.Valid || !r.endedAt.Time.Equal(ended) {
		t.Errorf("ended_at = %v, want %v", r.endedAt, ended)
	}
	if !r.startedAt.Valid {
		t.Error("ended row lost started_at")
	}
}

// TestSetActiveCreatesMissingRow: a started event whose pending row was
// never written (audit hiccup at issue time) still lands as an active row —
// the upsert is the safety net.
func TestSetActiveCreatesMissingRow(t *testing.T) {
	w := newLiveWriter(t)
	ctx := context.Background()
	sid := "sid-orphan-active"
	now := time.Now().UTC()
	if err := w.SetActive(ctx, ActiveRecord{
		SessionID: sid, Username: "dave", DBType: "mssql", DBUser: "ro_user", DB: "master",
		StartedAt: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("SetActive on missing row: %v", err)
	}
	r := fetchRow(t, w, sid)
	if r.status != "active" || r.username != "dave" || r.db != "master" {
		t.Errorf("orphan-active row = status %q user %q db %q, want active/dave/master", r.status, r.username, r.db)
	}
}

// TestWriteFailureIsErrorNotPanic: with the pool closed every write returns
// an error (the hooks log it and move on — the flow must never break).
func TestWriteFailureIsErrorNotPanic(t *testing.T) {
	w := newLiveWriter(t)
	_ = w.db.Close()
	ctx := context.Background()
	if err := w.UpsertSession(ctx, SessionRecord{SessionID: "sid-x", Username: "u", LastSeen: time.Now().UTC()}); err == nil {
		t.Error("UpsertSession after Close: want error, got nil")
	}
	if err := w.SetActive(ctx, ActiveRecord{SessionID: "sid-x", StartedAt: time.Now().UTC()}); err == nil {
		t.Error("SetActive after Close: want error, got nil")
	}
	if err := w.SetEnded(ctx, "sid-x", time.Now().UTC()); err == nil {
		t.Error("SetEnded after Close: want error, got nil")
	}
	if err := w.SetChecker(ctx, "sid-x", "carol"); err == nil {
		t.Error("SetChecker after Close: want error, got nil")
	}
}

// TestSweepStalePendingEndsStale (review 9.9 pending-audit sweeper): a
// pending row whose maker never connected (last_seen older than the cutoff)
// is flipped to ended with ended_at stamped, so the audit trail terminates
// instead of lingering 'pending' forever. FRESH pending rows and rows in
// other lifecycle states are left untouched; the sweep is idempotent (a
// second run sweeps nothing).
func TestSweepStalePendingEndsStale(t *testing.T) {
	w := newLiveWriter(t)
	ctx := context.Background()
	stale := "sid-sweep-stale"
	fresh := "sid-sweep-fresh"
	active := "sid-sweep-active"
	old := time.Now().UTC().Add(-2 * time.Hour)
	now := time.Now().UTC()

	// Two pending rows: one stale (maker never connected), one fresh.
	for _, sid := range []string{stale, fresh} {
		if err := w.UpsertSession(ctx, SessionRecord{SessionID: sid, Username: "eve", LastSeen: old}); err != nil {
			t.Fatalf("UpsertSession %s: %v", sid, err)
		}
	}
	if err := w.UpsertSession(ctx, SessionRecord{SessionID: fresh, Username: "eve", LastSeen: now}); err != nil {
		t.Fatalf("UpsertSession %s (fresh): %v", fresh, err)
	}
	// An ACTIVE row with an old last_seen must never be swept (the sweeper
	// targets status='pending' only — live sessions belong to the hub).
	if err := w.SetActive(ctx, ActiveRecord{
		SessionID: active, Username: "eve", StartedAt: old, LastSeen: old,
	}); err != nil {
		t.Fatalf("SetActive %s: %v", active, err)
	}

	cutoff := time.Now().UTC().Add(-time.Hour)
	n, err := w.SweepStalePending(ctx, cutoff)
	if err != nil {
		t.Fatalf("SweepStalePending: %v", err)
	}
	if n != 1 {
		t.Errorf("swept %d rows, want exactly 1 (the stale pending row)", n)
	}

	r := fetchRow(t, w, stale)
	if r.status != "ended" {
		t.Errorf("stale row status = %q, want ended", r.status)
	}
	if !r.endedAt.Valid {
		t.Error("stale row ended_at not stamped")
	}
	if r := fetchRow(t, w, fresh); r.status != "pending" {
		t.Errorf("fresh row status = %q, want pending (untouched)", r.status)
	}
	if r := fetchRow(t, w, active); r.status != "active" {
		t.Errorf("active row status = %q, want active (untouched)", r.status)
	}

	// Idempotent backstop: a second sweep has nothing left to do.
	if n, err := w.SweepStalePending(ctx, cutoff); err != nil || n != 0 {
		t.Errorf("second sweep = %d rows, err %v; want 0, nil", n, err)
	}
}
