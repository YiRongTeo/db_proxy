// Package audit persists the Control Plane's session audit trail to MySQL
// (Task 9.7, user directive 2026-08-15): every session's maker username,
// ticket, DB target, access level, checker username (when a checker watches
// the session), lifecycle status and timestamps land in zt_audit.sessions.
//
// The Control Plane is the writer by design: it sees the lifecycle events
// (issued/started/ended via the WS hub's pub/sub) and knows the checker
// identity on watch attach/detach — the Data Plane never learns the
// checker's username.
//
// All writes are idempotent INSERT ... ON DUPLICATE KEY UPDATE upserts keyed
// by session_id, and all methods return errors for the caller to log —
// an audit write failure must NEVER break the token/connect flow.
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Config carries the audit.mysql block (host/port/user/password/database).
// NewWriter validates it: every field must be non-empty.
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
}

// identRe validates database names before they are backtick-quoted into
// DDL/DML — config-driven identifiers must never reach SQL unvalidated.
var identRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// quoteIdent backtick-quotes a validated identifier (database or table).
func quoteIdent(name string) string {
	return "`" + name + "`"
}

// tableColumns is the sessions table column list (spec Task 9.7): maker
// username, ticket, db target, access, nullable checker_username, lifecycle
// status pending|active|ended and timestamps. created_at is server-side
// defaulted; last_seen is stamped by the writer on every write.
const tableColumns = "(" +
	"`id` BIGINT AUTO_INCREMENT PRIMARY KEY, " +
	"`session_id` VARCHAR(64) NOT NULL UNIQUE, " +
	"`username` VARCHAR(128) NOT NULL, " +
	"`ticket_id` VARCHAR(128) NOT NULL DEFAULT '', " +
	"`db_type` VARCHAR(16) NOT NULL DEFAULT '', " +
	"`db_user` VARCHAR(128) NOT NULL DEFAULT '', " +
	"`db` VARCHAR(128) NOT NULL DEFAULT '', " +
	"`access` VARCHAR(8) NOT NULL DEFAULT 'read', " +
	"`checker_username` VARCHAR(128) NULL, " +
	"`status` VARCHAR(16) NOT NULL DEFAULT 'pending', " +
	"`started_at` DATETIME(3) NULL, " +
	"`ended_at` DATETIME(3) NULL, " +
	"`last_seen` DATETIME(3) NOT NULL, " +
	"`created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), " +
	"INDEX `idx_status` (`status`), " +
	"INDEX `idx_username` (`username`)" +
	") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"

// Writer is the MySQL audit sink. Zero value is NOT usable — always build
// via NewWriter. All methods are safe for concurrent use (database/sql).
type Writer struct {
	db  *sql.DB
	log *slog.Logger
	tbl string // backtick-quoted `database`.`sessions`
}

// NewWriter opens the MySQL connection, ensures the audit schema exists
// (CREATE DATABASE IF NOT EXISTS + CREATE TABLE IF NOT EXISTS) and pings the
// server. Fail-fast: any error here means the plane must not start with
// audit enabled.
func NewWriter(log *slog.Logger, cfg Config) (*Writer, error) {
	if cfg.Host == "" || cfg.Port == "" || cfg.User == "" || cfg.Password == "" || cfg.Database == "" {
		return nil, fmt.Errorf("audit mysql: host, port, user, password and database are all required")
	}
	if !identRe.MatchString(cfg.Database) {
		return nil, fmt.Errorf("audit mysql: invalid database name %q", cfg.Database)
	}
	dsn := mysqlDSN(cfg, "") // no database selected yet — CREATE DATABASE first
	setup, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit mysql open: %w", err)
	}
	defer setup.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dbName := quoteIdent(cfg.Database)
	if _, err := setup.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS "+dbName); err != nil {
		return nil, fmt.Errorf("audit mysql create database %s: %w", cfg.Database, err)
	}
	if _, err := setup.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+dbName+".`sessions` "+tableColumns); err != nil {
		return nil, fmt.Errorf("audit mysql create table: %w", err)
	}
	if err := setup.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("audit mysql ping: %w", err)
	}
	db, err := sql.Open("mysql", mysqlDSN(cfg, cfg.Database))
	if err != nil {
		return nil, fmt.Errorf("audit mysql open %s: %w", cfg.Database, err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit mysql ping %s: %w", cfg.Database, err)
	}
	return &Writer{db: db, log: log, tbl: dbName + ".`sessions`"}, nil
}

// mysqlDSN builds a go-sql-driver DSN for the given database ("" = none).
func mysqlDSN(cfg Config, database string) string {
	c := mysql.NewConfig()
	c.User = cfg.User
	c.Passwd = cfg.Password
	c.Net = "tcp"
	c.Addr = net.JoinHostPort(cfg.Host, cfg.Port)
	c.DBName = database
	c.ParseTime = true
	c.Loc = time.UTC
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 5 * time.Second
	c.WriteTimeout = 5 * time.Second
	return c.FormatDSN()
}

// Close releases the connection pool.
func (w *Writer) Close() error {
	if w == nil || w.db == nil {
		return nil
	}
	return w.db.Close()
}

// SessionRecord is the pending/issued state of a session (written at token
// issue time). DB is unknown until the client requests it in the handshake.
type SessionRecord struct {
	SessionID string
	Username  string
	TicketID  string
	DBType    string
	DBUser    string
	Access    string
	LastSeen  time.Time
}

// ActiveRecord is the started-state refresh carried by the data plane's
// action=started lifecycle event.
type ActiveRecord struct {
	SessionID string
	Username  string
	DBType    string
	DBUser    string
	DB        string
	StartedAt time.Time
	LastSeen  time.Time
}

// UpsertSession inserts the pending row at token issue time. Idempotent: a
// re-issue for the same session_id refreshes the maker/db fields + last_seen
// but never touches status, checker_username, started_at or ended_at (the
// lifecycle owns those).
func (w *Writer) UpsertSession(ctx context.Context, rec SessionRecord) error {
	q := "INSERT INTO " + w.tbl +
		" (`session_id`, `username`, `ticket_id`, `db_type`, `db_user`, `access`, `last_seen`) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?) AS new_row ON DUPLICATE KEY UPDATE " +
		"`username` = new_row.`username`, `ticket_id` = new_row.`ticket_id`, " +
		"`db_type` = new_row.`db_type`, `db_user` = new_row.`db_user`, " +
		"`access` = new_row.`access`, `last_seen` = new_row.`last_seen`"
	_, err := w.db.ExecContext(ctx, q, rec.SessionID, rec.Username, rec.TicketID,
		rec.DBType, rec.DBUser, rec.Access, rec.LastSeen.UTC())
	return err
}

// SetActive flips a session to active on the data plane's action=started
// lifecycle event, stamping started_at and refreshing the db fields the
// event carries (the client-requested database is only known at connect).
// Idempotent upsert — a missing row (issued write failed earlier) is created
// in the active state rather than silently dropped.
func (w *Writer) SetActive(ctx context.Context, rec ActiveRecord) error {
	q := "INSERT INTO " + w.tbl +
		" (`session_id`, `username`, `db_type`, `db_user`, `db`, `status`, `started_at`, `last_seen`) " +
		"VALUES (?, ?, ?, ?, ?, 'active', ?, ?) AS new_row ON DUPLICATE KEY UPDATE " +
		"`username` = new_row.`username`, `db_type` = new_row.`db_type`, " +
		"`db_user` = new_row.`db_user`, `db` = new_row.`db`, " +
		"`status` = 'active', `started_at` = new_row.`started_at`, `last_seen` = new_row.`last_seen`"
	_, err := w.db.ExecContext(ctx, q, rec.SessionID, rec.Username, rec.DBType,
		rec.DBUser, rec.DB, rec.StartedAt.UTC(), rec.LastSeen.UTC())
	return err
}

// SetEnded flips a session to ended on the data plane's action=ended
// lifecycle event, stamping ended_at. Idempotent upsert. username is
// supplied as ” only to satisfy the NOT NULL insert row — the UPDATE
// clause excludes it, so an existing row's maker username is never
// clobbered; an orphan insert (pending+started hooks both failed) is a
// degraded-but-visible ended row.
func (w *Writer) SetEnded(ctx context.Context, sessionID string, endedAt time.Time) error {
	q := "INSERT INTO " + w.tbl +
		" (`session_id`, `username`, `status`, `ended_at`, `last_seen`) " +
		"VALUES (?, '', 'ended', ?, ?) AS new_row ON DUPLICATE KEY UPDATE " +
		"`status` = 'ended', `ended_at` = new_row.`ended_at`, `last_seen` = new_row.`last_seen`"
	_, err := w.db.ExecContext(ctx, q, sessionID, endedAt.UTC(), time.Now().UTC())
	return err
}

// SetChecker records checker presence on a session: checker != "" stores the
// username (watcher attached), checker == "" clears it to NULL (watcher
// disconnected). Idempotent upsert that never touches lifecycle fields; the
// maker username is excluded from the UPDATE clause for the same reason as
// SetEnded.
func (w *Writer) SetChecker(ctx context.Context, sessionID, checker string) error {
	var c any
	if checker != "" {
		c = checker
	}
	q := "INSERT INTO " + w.tbl +
		" (`session_id`, `username`, `checker_username`, `last_seen`) " +
		"VALUES (?, '', ?, ?) AS new_row ON DUPLICATE KEY UPDATE " +
		"`checker_username` = new_row.`checker_username`, `last_seen` = new_row.`last_seen`"
	_, err := w.db.ExecContext(ctx, q, sessionID, c, time.Now().UTC())
	return err
}

// SweepStalePending expires pending rows whose maker never connected: every
// status='pending' row with last_seen older than olderThan is flipped to
// 'ended' with ended_at = now, so the audit trail terminates instead of
// lingering 'pending' forever (review 9.9). Returns the number of rows
// swept. Idempotent backstop, not a lock: a late real lifecycle event
// simply re-upserts the row (SetActive/SetEnded win).
func (w *Writer) SweepStalePending(ctx context.Context, olderThan time.Time) (int64, error) {
	now := time.Now().UTC()
	res, err := w.db.ExecContext(ctx,
		"UPDATE "+w.tbl+" SET `status` = 'ended', `ended_at` = ?, `last_seen` = ? "+
			"WHERE `status` = 'pending' AND `last_seen` < ?",
		now, now, olderThan.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
