package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"zerotrust-proxy/internal/audit"
	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 9.7: session audit hooks (control plane = the writer) -------------
// Live tests against the real stack: a real api mux + real Valkey + a real
// MySQL audit writer on a THROWAWAY database (zt_audit_test_<n>, dropped on
// cleanup), with the queries:sess:* lifecycle consumer running exactly as
// cmd/control wires it. Events are published like the data plane publishes
// them (queries:sess:<sid>, kind=session).

// newAuditTestAPIServer is newPresetTestAPIServer with an audit writer wired
// in (mysql-test, throwaway database) AND the RunAuditLifecycle consumer
// started (the production wiring). Returns the server, client, store and a
// raw *sql.DB for row assertions. AllowMakerWatch is TRUE like
// newPresetTestAPIServer: the maker under test drives both /api/token and
// the GET /api/sessions listing that observes the pending row (Task 8).
func newAuditTestAPIServer(t *testing.T) (*httptest.Server, *http.Client, *store.ValkeyStore, *sql.DB, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:        testJWTUser,
		AuthPassword:    testJWTPassword,
		AuthRole:        "maker",
		AllowMakerWatch: true, // maker may list/watch in this fixture (Task 8)
		JWT:             testJWTBlock(),
		SessionTTL:      8,
		TokenTTL:        60,
		StaticDir:       t.TempDir(),
		DBPresets: []config.DBPreset{
			{Name: "MySQL read-only", DBType: "mysql", DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "3307", Access: "read"},
			{Name: "MySQL read-write", DBType: "mysql", DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "3307", Access: "write"},
		},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbName := fmt.Sprintf("zt_audit_test_%d", time.Now().UnixNano()%1_000_000_000)
	w, err := audit.NewWriter(log, audit.Config{
		Host: "127.0.0.1", Port: "3307", User: "root", Password: "root_pw", Database: dbName,
	})
	if err != nil {
		t.Fatalf("audit.NewWriter(%s): %v", dbName, err)
	}
	t.Cleanup(func() {
		_ = w.Close()
		dropAuditTestDB(t, dbName)
	})
	assertDB, err := sql.Open("mysql", auditDSN(dbName))
	if err != nil {
		t.Fatalf("open assert db: %v", err)
	}
	t.Cleanup(func() { _ = assertDB.Close() })
	a := NewAPI(log, cfg, vs, w)
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)

	// Production wiring: lifecycle consumer for the process lifetime.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.RunAuditLifecycle(ctx)

	return srv, &http.Client{}, vs, assertDB, cfg
}

// auditDSN builds the DSN for the throwaway audit database (root dev creds).
func auditDSN(dbName string) string {
	c := mysql.NewConfig()
	c.User = "root"
	c.Passwd = "root_pw"
	c.Net = "tcp"
	c.Addr = "127.0.0.1:3307"
	c.DBName = dbName
	c.ParseTime = true
	c.Loc = time.UTC
	return c.FormatDSN()
}

// dropAuditTestDB drops the throwaway database (cleanup discipline).
func dropAuditTestDB(t *testing.T, dbName string) {
	t.Helper()
	db, err := sql.Open("mysql", auditDSN(""))
	if err != nil {
		return
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx, "DROP DATABASE IF EXISTS `"+dbName+"`")
}

// auditRow mirrors the sessions row for assertions.
type auditRow struct {
	sessionID string
	username  string
	ticketID  string
	dbType    string
	dbUser    string
	db        string
	access    string
	checker   sql.NullString
	status    string
	startedAt sql.NullTime
	endedAt   sql.NullTime
}

// fetchAuditRow SELECTs the session row from the throwaway database.
func fetchAuditRow(t *testing.T, db *sql.DB, sid string) auditRow {
	t.Helper()
	var r auditRow
	err := db.QueryRowContext(context.Background(),
		"SELECT `session_id`, `username`, `ticket_id`, `db_type`, `db_user`, `db`, `access`, "+
			"`checker_username`, `status`, `started_at`, `ended_at` FROM `sessions` WHERE `session_id` = ?",
		sid).Scan(&r.sessionID, &r.username, &r.ticketID, &r.dbType, &r.dbUser, &r.db, &r.access,
		&r.checker, &r.status, &r.startedAt, &r.endedAt)
	if err != nil {
		t.Fatalf("SELECT audit row %s: %v", sid, err)
	}
	return r
}

// waitAudit polls the audit row until want returns true (or 5s elapse).
// onMiss is invoked after each failed poll — used to re-publish lifecycle
// events (upserts are idempotent, so re-publishing is harmless and removes
// the subscribe/publish race).
func waitAudit(t *testing.T, db *sql.DB, sid, desc string, want func(auditRow) bool, onMiss func()) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last auditRow
	for time.Now().Before(deadline) {
		last = fetchAuditRow(t, db, sid)
		if want(last) {
			return
		}
		if onMiss != nil {
			onMiss()
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("audit row %s: %s not reached within 5s (last: status=%s checker=%v started=%v ended=%v)",
		sid, desc, last.status, last.checker, last.startedAt.Valid, last.endedAt.Valid)
}

// withinMs reports whether got is within tol of want. MySQL DATETIME(3)
// ROUNDS fractional seconds (per MySQL 8.0 docs), so a stored timestamp may
// sit one millisecond past the Go value it was written from — comparisons
// must tolerate that, never require bit-equal times.
func withinMs(got, want time.Time, tol time.Duration) bool {
	return !got.Before(want.Add(-tol)) && !got.After(want.Add(tol))
}

// publishLifecycle publishes a kind=session event to queries:sess:<sid> the
// way the data plane does (MySQL proxy publishLifecycle).
func publishLifecycle(t *testing.T, vs *store.ValkeyStore, ev models.QueryEvent) {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal lifecycle event: %v", err)
	}
	if err := vs.Publish(context.Background(), "queries:sess:"+ev.SessionID, raw); err != nil {
		t.Fatalf("publish lifecycle: %v", err)
	}
}

// issueAuditToken issues a token for the given maker and returns the audit
// session id (from the pending directory listing).
func issueAuditToken(t *testing.T, client *http.Client, srv *httptest.Server, vs *store.ValkeyStore, user, dbUser, ticket string) string {
	t.Helper()
	ctx := context.Background()
	body := fmt.Sprintf(`{"username":%q,"db_user":%q,"db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":%q}`,
		user, dbUser, ticket)
	token := issueToken(t, client, srv.URL, body)
	_, _ = vs.GetDeleteToken(ctx, token) // consume the single-use token
	sid := assertPendingListed(t, client, srv.URL, user, dbUser, "mysql")
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), sid) })
	return sid
}

// TestTokenIssueWritesAuditPendingRow (Task 9.7 live): POST /api/token with
// audit enabled → the sessions row exists with status=pending, the maker
// username, the ticket and the db target BEFORE any connect. The pending
// upsert is synchronous inside handleToken, so the row is readable as soon
// as the issue returns 200.
func TestTokenIssueWritesAuditPendingRow(t *testing.T) {
	srv, client, vs, db, cfg := newAuditTestAPIServer(t)

	user := fmt.Sprintf("audit-maker-%d", time.Now().UnixNano())
	// Review 9.9a: the token is issued for the SESSION (bearer) user — the
	// maker under test authenticates with its own minted JWT (the login
	// endpoint only knows admin). The same bearer drives /api/token
	// (requireJWT-guarded since Task 7) and GET /api/sessions.
	authed := withBearer(client, mintJWT(t, cfg, user, "maker"))
	sid := issueAuditToken(t, authed, srv, vs, user, "ro_user", "T-9-7")

	r := fetchAuditRow(t, db, sid)
	if r.status != "pending" {
		t.Errorf("status = %q, want pending", r.status)
	}
	if r.username != user {
		t.Errorf("username = %q, want maker %q", r.username, user)
	}
	if r.ticketID != "T-9-7" {
		t.Errorf("ticket_id = %q, want T-9-7", r.ticketID)
	}
	if r.dbType != "mysql" || r.dbUser != "ro_user" {
		t.Errorf("db target = %s/%s, want mysql/ro_user", r.dbType, r.dbUser)
	}
	if r.access != "read" {
		t.Errorf("access = %q, want read (ro_user preset)", r.access)
	}
	if r.db != "" {
		t.Errorf("db = %q, want \"\" (unknown at issue time)", r.db)
	}
	if r.checker.Valid {
		t.Errorf("checker_username = %q, want NULL before any watcher", r.checker.String)
	}
	if r.startedAt.Valid || r.endedAt.Valid {
		t.Errorf("pending row started_at=%v ended_at=%v, want both NULL", r.startedAt.Valid, r.endedAt.Valid)
	}
}

// TestAuditLifecycleConsumer (Task 9.7 live): the queries:sess:* consumer
// mirrors the data plane's started/ended events into the audit row —
// started → status active + started_at + refreshed db fields; ended →
// status ended + ended_at.
func TestAuditLifecycleConsumer(t *testing.T) {
	srv, client, vs, db, cfg := newAuditTestAPIServer(t)

	user := fmt.Sprintf("audit-lc-%d", time.Now().UnixNano())
	// Review 9.9a: the token is issued for the SESSION user.
	authed := withBearer(client, mintJWT(t, cfg, user, "maker"))
	sid := issueAuditToken(t, authed, srv, vs, user, "rw_user", "T-LC")

	started := time.Now().UTC()
	ev := models.QueryEvent{Kind: "session", Action: "started", Ts: started,
		Username: user, DBUser: "rw_user", DBType: "mysql", DB: "appdb", SessionID: sid}
	publishLifecycle(t, vs, ev)
	waitAudit(t, db, sid, "active transition",
		func(r auditRow) bool { return r.status == "active" && r.db == "appdb" && r.startedAt.Valid },
		func() { publishLifecycle(t, vs, ev) })
	r := fetchAuditRow(t, db, sid)
	if r.username != user {
		t.Errorf("active username = %q, want %q", r.username, user)
	}
	if !withinMs(r.startedAt.Time, started, 2*time.Millisecond) {
		t.Errorf("started_at = %v, want ~%v (±2ms)", r.startedAt.Time, started)
	}

	ended := started.Add(30 * time.Second)
	evEnd := models.QueryEvent{Kind: "session", Action: "ended", Ts: ended, SessionID: sid}
	publishLifecycle(t, vs, evEnd)
	waitAudit(t, db, sid, "ended transition",
		func(r auditRow) bool { return r.status == "ended" && r.endedAt.Valid },
		func() { publishLifecycle(t, vs, evEnd) })
	r = fetchAuditRow(t, db, sid)
	if !withinMs(r.endedAt.Time, ended, 2*time.Millisecond) {
		t.Errorf("ended_at = %v, want ~%v (±2ms)", r.endedAt.Time, ended)
	}
	if !r.startedAt.Valid {
		t.Error("ended row lost started_at")
	}
}

// TestWSCheckerAuditAttachDetach (Task 9.7 live): a checker subscribing with
// channel=sess:<sid> writes checker_username=<checker>; disconnecting clears
// it to NULL. The checker identity comes from the WS session. Separation of
// duties (2026-08-17): the checker must be a DIFFERENT user than the
// session's maker — a maker watching their own session is rejected with a
// 1008 close and never reaches the audit attach.
func TestWSCheckerAuditAttachDetach(t *testing.T) {
	srv, client, vs, db, cfg := newAuditTestAPIServer(t)

	maker := fmt.Sprintf("audit-maker-%d", time.Now().UnixNano())
	checker := fmt.Sprintf("audit-checker-%d", time.Now().UnixNano())
	// Review 9.9a: the token is issued for the SESSION (bearer) user — the maker.
	authed := withBearer(client, mintJWT(t, cfg, maker, "maker"))
	sid := issueAuditToken(t, authed, srv, vs, maker, "ro_user", "T-WS")

	// Switch identity: the checker is a different user than the maker. The
	// WS upgrade is bearer-authed (requireJWT), so the dial presents the
	// checker's own minted token.
	c := dialWSChecker(t, srv, mintJWT(t, cfg, checker, "checker"), "sess:"+sid)

	waitAudit(t, db, sid, "checker attach",
		func(r auditRow) bool { return r.checker.Valid && r.checker.String == checker }, nil)
	r := fetchAuditRow(t, db, sid)
	if r.status != "pending" {
		t.Errorf("checker attach clobbered status = %q, want pending (no session yet)", r.status)
	}

	_ = c.Close(1000, "")
	waitAudit(t, db, sid, "checker detach",
		func(r auditRow) bool { return !r.checker.Valid }, nil)
}
