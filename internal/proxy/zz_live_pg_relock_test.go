package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Alignment review I-3.2: PG LIVE rw-hold parity --------------------------
//
// The review found pg missing BOTH live rw-hold tests the mysql and mssql
// planes have: admit-on-watch (mysql: TestMySQLRWHoldLiveAdmitsOnWatch,
// zz_live_access_test.go) and hold-disconnect-cleanup
// (TestMySQLRWHoldLiveDisconnectCleansUp — pg had NO equivalent at all).
// These are the pg mirrors against the LIVE pg-test backend through the
// plane's real accept loop (the pg hold's admission is covered only by the
// unit-level TestPGRWHoldAdmissionSingleWelcome — a driven handshake, not
// the accept loop — per the review).
//
// The "zz" prefix keeps the established live-suite convention (runs LAST;
// real sess:live records — see zz_live_gate_hold_test.go's header).

// startRWHoldPGProxy runs the multi-session pg proxy loop (the accept
// loop, like the Dispatcher) with the LIVE rw credential entry. The built
// proxy is also the package-local relock dispatch target (the test's
// HandleRelock arm — main.go fans ctl:relock into the planes).
func startRWHoldPGProxy(t *testing.T, vs *store.ValkeyStore) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewPGProxy(logger, vs, &ConfigCredResolver{
		Creds: map[string]string{"postgres:rw_user@127.0.0.1:5433": "rw_pw"},
	}, nil)
	lastRelockPGProxy = p
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()
	return ln
}

// pgRWLiveToken mints an access:"rw" token bound to the live pg-test
// backend (rw_user — real write access) and registers the cleanups.
func pgRWLiveToken(t *testing.T, vs *store.ValkeyStore, username, sid string) string {
	t.Helper()
	token := fmt.Sprintf("pgrw_%d", time.Now().UnixNano())
	if err := vs.SetToken(context.Background(), token, models.TokenPayload{
		Username: username, DBUser: "rw_user", DBIP: "127.0.0.1", DBPort: "5433",
		DBType: "postgres", TicketID: "T-I3-PG", Access: "rw", SessionID: sid,
	}, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() { _ = vs.DelSessionLive(context.Background(), sid) })
	return token
}

// TestPGRWHoldLiveAdmitsOnWatch: the full hold lifecycle on the LIVE
// pg-test backend through the accept loop — the client completes auth (the
// hold's welcome is THE welcome), NOTHING else comes back while unwatched,
// a checker watch admits, the backend session is real, and a SELECT
// round-trips against the live backend.
func TestPGRWHoldLiveAdmitsOnWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	ln := startRWHoldPGProxy(t, vs)

	sid := fmt.Sprintf("sid-pg-rw-live-%d", time.Now().UnixNano())
	token := pgRWLiveToken(t, vs, "pg-rw-live", sid)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
	if err := front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": token, "database": "appdb"},
	}); err != nil {
		t.Fatalf("startup: %v", err)
	}

	// The hold's welcome: auth completes for the client (exactly ONE
	// welcome — the unit test pins the count; here the real accept loop
	// must deliver it too).
	pgReadUntilReady(t, front)

	// HELD: no backend connect happened — the client's first query draws
	// NO response for a window no real backend round-trip could fit.
	pgSendQuery(t, front, "SELECT 1")
	var b [1]byte
	_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("held pg session answered pre-admission")
	}

	// The pending directory record is alive while held.
	raw, rerr := vs.GetSessionLive(ctx, sid)
	if rerr != nil || raw == nil {
		t.Fatalf("held session missing from the directory: %v", rerr)
	}
	if !strings.Contains(string(raw), `"pending"`) {
		t.Errorf("held record = %s, want status pending", raw)
	}

	// Watcher attaches → admission → the REAL backend session answers.
	if err := vs.SetWatchConn(ctx, sid, "checker-pg-rw", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	res := pgReadRemainingResult(t, front)
	if !res.ready || len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Errorf("post-admission SELECT 1 = ready %v rows %v, want ready [[1]] (live backend)",
			res.ready, res.rows)
	}
}

// TestPGRWHoldLiveDisconnectCleansUp: a held pg client that walks away
// leaves NO directory record (finishHeldSession) within a tick — the pg
// mirror of the mysql cleanup test (the review: pg had NO hold-disconnect-
// cleanup test at all).
func TestPGRWHoldLiveDisconnectCleansUp(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	ln := startRWHoldPGProxy(t, vs)

	sid := fmt.Sprintf("sid-pg-rw-dc-%d", time.Now().UnixNano())
	token := pgRWLiveToken(t, vs, "pg-rw-dc", sid)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
	if err := front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": token, "database": "appdb"},
	}); err != nil {
		t.Fatalf("startup: %v", err)
	}
	pgReadUntilReady(t, front)

	// The hold's liveness probe PEEKS (never consumes), and the hold only
	// just armed — the pending record writes on the hold goroutine. Wait
	// for the heartbeat to land (the record the mysql test asserts at the
	// same point) before the disconnect: a record checked too early can
	// race the heartbeat's first write.
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, gerr := vs.GetSessionLive(ctx, sid)
		if gerr == nil && raw != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("held session never appeared in the directory: %v", gerr)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// …the client walks away mid-hold.
	conn.Close()

	// The pending record must vanish (finishHeldSession) within a tick.
	goneDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(goneDeadline) {
		raw, gerr := vs.GetSessionLive(ctx, sid)
		if gerr == nil && raw == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sess:live record leaked after the held pg disconnect")
}

// --- Alignment review I-3.1: PG live relock E2E ------------------------------
//
// The review found NO live E2E relock test on ANY plane: the full chain
// (hold → admit → hub watch-loss → ctl:relock publish → subscriber →
// freeze → gated → checker re-attach → unfreeze → relay resumes) was
// exercised only through direct HandleRelock calls in unit tests. This test
// runs the WHOLE chain on the pg plane against the LIVE pg-test backend:
//
//  1. hold → attach the watch → admitted;
//  2. remove ALL watch:<sid>:* leases directly in the store (vs.DelWatch —
//     the wholesale teardown the hub's per-conn removals converge to),
//     mimicking the hub disconnect, and publish the hub's exact ctl:relock
//     payload; the REAL subscriber wiring (vs.Subscribe → bounded channel →
//     HandleRelock, the main.go loop shape, subscription acked first) picks
//     it up and freezes;
//  3. the next command is FROZEN-gated on the wire: FATAL 28000 + the
//     maker-gating message + ReadyForQuery (the freeze reuses gatePGReject);
//  4. re-arm the lease → the frozen poll unfreezes → the next SELECT flows
//     and returns real rows.

// TestPGRWRelockLiveE2EFreezeAndReAdmit: the full relock lifecycle, live.
func TestPGRWRelockLiveE2EFreezeAndReAdmit(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	ln := startRWHoldPGProxy(t, vs)

	sid := fmt.Sprintf("sid-pg-relock-e2e-%d", time.Now().UnixNano())
	token := pgRWLiveToken(t, vs, "pg-relock-e2e", sid)

	// (1) Connect, hold, admit on the checker's watch.
	front, conn := pgDialDBRaw(t, ln, token, false, "appdb")
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	pgReadUntilReady(t, front)
	if err := vs.SetWatchConn(ctx, sid, "checker-relock-e2e", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	pgSendQuery(t, front, "SELECT 1")
	res := pgReadRemainingResult(t, front)
	if !res.ready || len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Fatalf("post-admission SELECT 1 = ready %v rows %v, want ready [[1]]", res.ready, res.rows)
	}

	// (2) Hub watch-loss: remove ALL watch:<sid>:* leases directly, then
	// publish the hub's exact ctl:relock payload through the real
	// pubsub → subscriber → HandleRelock wiring (the main.go loop shape,
	// subscription acked BEFORE the publish or it races and drops).
	if err := vs.DelWatch(ctx, sid); err != nil {
		t.Fatalf("DelWatch (hub watch-loss): %v", err)
	}
	relockCh := make(chan []byte, 16)
	subCtx, cancelSub := context.WithCancel(context.Background())
	t.Cleanup(cancelSub)
	acked := make(chan struct{}, 1)
	hookCtx := valkey.WithOnSubscriptionHook(subCtx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go func() { _ = vs.Subscribe(hookCtx, "ctl:relock", false, relockCh) }()
	select {
	case <-acked:
	case <-time.After(5 * time.Second):
		t.Fatal("ctl:relock subscription not confirmed within 5s")
	}
	go func() {
		for msg := range relockCh {
			pgRelockDispatch(vs, msg) // the main.go loop body: freeze or drop
		}
	}()
	if err := vs.Publish(ctx, "ctl:relock", []byte(`{"action":"relock","session_id":"`+sid+`"}`)); err != nil {
		t.Fatalf("publish ctl:relock: %v", err)
	}

	// (3) The freeze lands asynchronously; on the wire the next command is
	// FROZEN-gated (FATAL 28000 + maker-gating message + ReadyForQuery).
	// The reply race (forwarded result vs frozen error) is decided with a
	// message-typed consumer: a result stream is drained and the SELECT
	// re-sent (idempotent) until the frozen error arrives — never a
	// hard-typed expectation that Fatalfs on the legitimate pre-freeze
	// result.
	var er *pgproto3.ErrorResponse
	wireDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(wireDeadline) {
		pgSendQuery(t, front, "SELECT 2")
		frozen := false
	drain:
		for {
			msg, err := front.Receive()
			if err != nil {
				t.Fatalf("receive during freeze wait: %v", err)
			}
			switch m := msg.(type) {
			case *pgproto3.ErrorResponse:
				if strings.Contains(m.Message, "maker gating") {
					er = m
					frozen = true
				} else {
					t.Fatalf("unexpected error during freeze wait: %s (%s)", m.Message, m.Code)
				}
			case *pgproto3.RowDescription, *pgproto3.DataRow, *pgproto3.CommandComplete:
				// pre-freeze forwarded result — keep draining
			case *pgproto3.ReadyForQuery:
				break drain
			}
		}
		if frozen {
			break
		}
	}
	if er == nil {
		t.Fatal("no frozen gating error within 8s of the ctl:relock publish")
	}
	if er.Code != "28000" || er.Severity != "FATAL" {
		t.Errorf("frozen ErrorResponse = code %q severity %q, want 28000/FATAL", er.Code, er.Severity)
	}
	if !strings.Contains(er.Message, sid) {
		t.Errorf("frozen message = %q, want it to name the session %s", er.Message, sid)
	}
	// The frozen ErrorResponse for a Query is followed by ReadyForQuery
	// (the drain loop above consumed it in the final iteration — the RFQ
	// after the frozen error is the loop's break; nothing left to expect).

	// (4) Checker re-attaches → the frozen poll unfreezes → the next
	// SELECT flows to the live backend and returns rows (no reconnect).
	// The unfreeze is also asynchronous (rwHoldPollInterval poll), and a
	// too-early SELECT draws another frozen error — retry with the same
	// typed consumer until a real result arrives.
	if err := vs.SetWatchConn(ctx, sid, "checker-relock-e2e-2", time.Minute); err != nil {
		t.Fatalf("SetWatchConn (re-attach): %v", err)
	}
	unfrozenDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(unfrozenDeadline) {
		pgSendQuery(t, front, "SELECT 3")
		var res pgExecResult
		resumed := false
	drain2:
		for {
			msg, err := front.Receive()
			if err != nil {
				t.Fatalf("receive during unfreeze wait: %v", err)
			}
			switch m := msg.(type) {
			case *pgproto3.ErrorResponse:
				if !strings.Contains(m.Message, "maker gating") {
					t.Fatalf("unexpected error during unfreeze wait: %s (%s)", m.Message, m.Code)
				}
				// still frozen — drain to RFQ, retry
			case *pgproto3.RowDescription:
				res.fields = append(res.fields, string(m.Fields[0].Name))
			case *pgproto3.DataRow:
				row := make([]string, len(m.Values))
				for i, v := range m.Values {
					row[i] = string(v)
				}
				res.rows = append(res.rows, row)
			case *pgproto3.CommandComplete:
				res.tag = string(m.CommandTag)
			case *pgproto3.ReadyForQuery:
				res.ready = true
				break drain2
			}
		}
		if res.ready && len(res.rows) == 1 && res.rows[0][0] == "3" {
			resumed = true
		}
		if resumed {
			return // the relay resumed — the lifecycle is complete
		}
	}
	t.Fatal("the session never resumed after the checker re-attached (still frozen)")
}

// pgRelockDispatch is the test's relock fanout arm (the main.go loop's
// relocker.HandleRelock body): a pg-plane relock dispatch. The pg registry
// register/unregister are unexported, so the dispatch goes through the
// proxy's own exported HandleRelock via a package-local PGProxy built here.
var lastRelockPGProxy *PGProxy

func pgRelockDispatch(vs *store.ValkeyStore, msg []byte) {
	if lastRelockPGProxy != nil {
		lastRelockPGProxy.HandleRelock(msg)
	}
	_ = vs
}

// --- Alignment review I-3.3: flag-off live admission, pg ---------------------
//
// The review found TestMySQLRWFlagOffAdmitsWithoutWatch (zz_live_sod_flags_
// test.go) mirrored on NO other plane: "flag-off = byte-identical legacy
// path" (G3) was live-verified on one of three planes. This is the pg
// mirror: rw + SetRWRequireCheckerWatch(false) → the rw token admits
// IMMEDIATELY on the normal connect path (no hold, no WatchActive polling)
// and a real backend round-trip completes with NO watch lease ever armed —
// asserted at the end as belt-and-braces. (Flag ON this exact sequence
// deadlocks until the read deadline: the hold would park the query waiting
// for a watcher that never comes.)

// TestPGRWFlagOffAdmitsWithoutWatch: the pg mirror — immediate admission,
// real SELECT round-trip, no lease.
func TestPGRWFlagOffAdmitsWithoutWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewPGProxy(logger, vs, &ConfigCredResolver{
		Creds: map[string]string{"postgres:rw_user@127.0.0.1:5433": "rw_pw"},
	}, nil)
	p.SetRWRequireCheckerWatch(false) // THE flag under test
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()

	sid := fmt.Sprintf("sid-pg-rw-flagoff-%d", time.Now().UnixNano())
	token := pgRWLiveToken(t, vs, "pg-rw-flagoff", sid)
	// NO SetWatchConn — no watch lease is ever armed.

	front, conn := pgDialDBRaw(t, ln, token, false, "appdb")
	_ = conn
	pgReadUntilReady(t, front) // the welcome — admitted, not held

	// ADMITTED, not held: a real backend SELECT round-trips with NO watch.
	pgSendQuery(t, front, "SELECT 1")
	res := pgReadRemainingResult(t, front)
	if !res.ready || len(res.rows) != 1 || res.rows[0][0] != "1" {
		t.Fatalf("flag-off rw pg: SELECT 1 = ready %v rows %v, want ready [[1]]", res.ready, res.rows)
	}

	// Belt and braces: no lease leaked — admission came from the FLAG.
	active, werr := vs.WatchActive(ctx, sid)
	if werr != nil {
		t.Fatalf("WatchActive: %v", werr)
	}
	if active {
		t.Error("WatchActive = true with no watcher — a lease leaked; the test no longer proves flag-off admission")
	}
}
