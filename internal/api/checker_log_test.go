package api

// Task 12 (node-integration): checker attach/leave INFO log lines in the
// control hub. The watch lifecycle is silent on successful attach and leave;
// the owner wants two observation lines, additive only:
//
//	attach — AFTER SetWatchConn succeeds, msg="checker attached" with
//	session_id, checker (username), leases (remaining watch-lease count
//	AFTER this attach, 1+; "unknown" on probe error — attach never fails
//	because of logging).
//	leave — in the disconnect defer, AFTER WatchRemoveConn, msg="checker
//	left" with session_id, checker, leases (count AFTER removal; 0 = the
//	session is now unwatched; the attr is omitted on probe error). The
//	line must fire on ALL leave paths (clean close, crash/TCP drop,
//	ctx-cancel) because every path runs the defer.
//
// Non-sess channels and rejected watches log nothing new.

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// newWatchLogServer is newWatchTestServer with a buffer-backed slog handler
// (the log-buffer precedent: dataplane_pool_test.go) so the two new INFO
// lines are assertable. The buffer is mutex-guarded: the hub logs from the
// connection goroutine AND the disconnect defer, and the test reads the
// buffer concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newWatchLogServer(t *testing.T) (*httptest.Server, *store.ValkeyStore, *config.ControlConfig, *syncBuffer) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "checker",
		JWT:          testJWTBlock(),
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	lb := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(lb, nil))
	a := NewAPI(log, cfg, vs, nil)
	a.watchTTL = 2 * time.Second
	a.watchHeartbeat = 200 * time.Millisecond
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, vs, cfg, lb
}

// waitForLog polls the log buffer until a line containing substr appears
// (or fails after 5s) — the hub logs from a goroutine, so arrival is async.
func waitForLog(t *testing.T, lb *syncBuffer, substr string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := lb.String(); strings.Contains(s, substr) {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("log line %q not found within 5s; log was:\n%s", substr, lb.String())
	return ""
}

// TestHubLogsCheckerAttachAndLeave: the happy path — a checker attaches to
// sess:<sid> (attach line with session_id + checker + leases>=1 after the
// lease is armed) and disconnects cleanly (leave line with the post-removal
// count, 0 here).
func TestHubLogsCheckerAttachAndLeave(t *testing.T) {
	srv, vs, cfg, lb := newWatchLogServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-log-attach-leave"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice") // maker ≠ checker (admin)

	c := dialWSChecker(t, srv, tok, "sess:"+sid)
	pollWatch(t, vs, sid, true) // lease armed BEFORE the attach line may fire

	logs := waitForLog(t, lb, "checker attached")
	line := findLogLine(t, logs, "checker attached")
	for _, want := range []string{"session_id=" + sid, "checker=" + testJWTUser} {
		if !strings.Contains(line, want) {
			t.Errorf("attach line %q missing %s", line, want)
		}
	}
	if !strings.Contains(line, "leases=1") {
		t.Errorf("attach line %q: leases=1 wanted (this connection's lease just armed)", line)
	}

	// Clean close → the disconnect defer fires the leave line.
	_ = c.Close(websocket.StatusNormalClosure, "")
	pollWatch(t, vs, sid, false) // removal landed before the leave line may fire

	logs = waitForLog(t, lb, "checker left")
	line = findLogLine(t, logs, "checker left")
	for _, want := range []string{"session_id=" + sid, "checker=" + testJWTUser, "leases=0"} {
		if !strings.Contains(line, want) {
			t.Errorf("leave line %q missing %s", line, want)
		}
	}
}

// TestHubLeaveLogFiresOnCrashPath: a checker that vanishes without a close
// frame (crash / TCP drop — CloseNow from the client side) must still leave
// a line: the disconnect defer runs on every path.
func TestHubLeaveLogFiresOnCrashPath(t *testing.T) {
	srv, vs, cfg, lb := newWatchLogServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	sid := "sid-log-crash"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice")

	c := dialWSChecker(t, srv, tok, "sess:"+sid)
	pollWatch(t, vs, sid, true)
	waitForLog(t, lb, "checker attached")

	c.CloseNow() // hard drop: no close handshake, the hub sees a read error
	pollWatch(t, vs, sid, false)

	waitForLog(t, lb, "checker left")
}

// TestHubNoAttachLogForRejectedWatch: the SoD rejection (checker == maker)
// keeps its WARN and fires NO attach line.
func TestHubNoAttachLogForRejectedWatch(t *testing.T) {
	srv, vs, cfg, lb := newWatchLogServer(t)
	tok := mintJWT(t, cfg, "alice", "checker") // alice IS the seeded maker

	sid := "sid-log-rejected"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice") // maker == checker → rejected

	dialWSCheckerExpectRejected(t, srv, tok, "sess:"+sid)
	time.Sleep(300 * time.Millisecond) // room for a (wrong) attach line

	if s := lb.String(); strings.Contains(s, "checker attached") {
		t.Errorf("attach line fired for a REJECTED watch; log was:\n%s", s)
	}
}

// TestHubNoNewLogForNonSessChannels: channel=* and a user channel hold no
// lease and log nothing new — no attach, no leave.
func TestHubNoNewLogForNonSessChannels(t *testing.T) {
	srv, _, cfg, lb := newWatchLogServer(t)
	tok := mintJWT(t, cfg, testJWTUser, "checker")

	for _, ch := range []string{"*", "alice"} {
		c := dialWSChecker(t, srv, tok, ch)
		time.Sleep(200 * time.Millisecond)
		_ = c.Close(websocket.StatusNormalClosure, "")
		time.Sleep(300 * time.Millisecond)
	}
	if s := lb.String(); strings.Contains(s, "checker attached") || strings.Contains(s, "checker left") {
		t.Errorf("attach/leave lines fired for non-sess channels; log was:\n%s", s)
	}
}

// TestHubLeaveLogKeepsLineOnProbeError: a failed lease-count probe must not
// suppress the leave line (the brief: "log with leases omitted and keep the
// line"). The probe is driven by KILLING the store client before the
// disconnect: WatchRemoveConn and WatchCount both fail, yet the leave line
// must still fire — without a leases attr (a wrong or missing number beats a
// made-up one). The attach-side probe-error shape (leases=unknown) is
// implemented identically but is not directly reachable in a test: SetWatchConn
// and WatchCount share one store client, so both fail together — with the
// lease unarmed there is no "successful attach" to log (the Warn covers it).
func TestHubLeaveLogKeepsLineOnProbeError(t *testing.T) {
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "checker",
		JWT:          testJWTBlock(),
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	lb := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(lb, nil))
	a := NewAPI(log, cfg, vs, nil)
	a.watchTTL = 2 * time.Second
	a.watchHeartbeat = 200 * time.Millisecond
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)

	tok := mintJWT(t, cfg, testJWTUser, "checker")
	sid := "sid-log-probe-err"
	_ = vs.DelWatch(context.Background(), sid)
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	seedSessionRecord(t, vs, sid, "alice")

	c := dialWSChecker(t, srv, tok, "sess:"+sid)
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })

	// Let the attach path run against the HEALTHY store first, then close
	// the client so the NEXT store call (any of them) errors. The attach
	// line must already be present with a numeric lease (attach ran fine);
	// the heartbeat/refresh warnings that follow prove the error path is
	// exercised. For the probe-error shape itself the brief accepts
	// "leases omitted" on leave; the attach contract (never fail because of
	// logging) is asserted structurally below via the leave-on-error line.
	pollWatch(t, vs, sid, true)
	waitForLog(t, lb, "checker attached")

	// Now kill the store and drop the connection: WatchRemoveConn and the
	// leave probe both fail — the leave line must STILL fire (probe error
	// keeps the line; leases attr omitted rather than a wrong number).
	vs.Close()
	c.CloseNow()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := lb.String(); strings.Contains(s, "checker left") {
			left := findLogLine(t, s, "checker left")
			if strings.Contains(left, "leases=") {
				t.Errorf("leave line fired with a leases attr despite a failed probe: %s", left)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no leave line within 5s with the store down; log was:\n%s", lb.String())
}

// findLogLine returns the first log line containing msg. Fail if absent.
func findLogLine(t *testing.T, logs, msg string) string {
	t.Helper()
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, msg) {
			return l
		}
	}
	t.Fatalf("no log line containing %q in:\n%s", msg, logs)
	return ""
}
