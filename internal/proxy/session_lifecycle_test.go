package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Task 8.2: session directory + lifecycle events -------------------------

// recvQueryEvent reads the next published event, SKIPPING session lifecycle
// events (kind=session). Every live-session test that subscribed to a
// queries:<user> channel sees the started event first (published when the
// session is established, before any query event) and the ended event last;
// this helper keeps query-focused assertions order-robust.
func recvQueryEvent(t *testing.T, out <-chan []byte) models.QueryEvent {
	t.Helper()
	for {
		var ev models.QueryEvent
		if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if ev.Kind == "session" {
			continue
		}
		return ev
	}
}

// recvSessionEvent is recvQueryEvent's counterpart: it skips query events and
// returns the next lifecycle event (kind=session) — used where a test that
// only consumed query events must also drain/assert the ended event that
// follows session teardown.
func recvSessionEvent(t *testing.T, out <-chan []byte) models.QueryEvent {
	t.Helper()
	for {
		var ev models.QueryEvent
		if err := json.Unmarshal(recvEvent(t, out), &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if ev.Kind == "session" {
			return ev
		}
	}
}

// subscribePattern opens a Valkey Pub/Sub PATTERN subscription (PSubscribe)
// and blocks until it is confirmed; the returned channel receives raw event
// JSON from every matching channel. Used to observe queries:sess:<sid> events
// before the session id is known (it is generated inside handleConn).
func subscribePattern(t *testing.T, vs *store.ValkeyStore, pattern string) <-chan []byte {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan []byte, 16)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, pattern, true, out)
	waitSubAck(t, acked)
	return out
}

// findSessionRecord returns the session-directory record for sid, or nil if
// the session is not listed. Records of other (possibly foreign) sessions on
// the shared dev Valkey are ignored.
func findSessionRecord(t *testing.T, vs *store.ValkeyStore, sid string) *sessionRecord {
	t.Helper()
	recs, err := vs.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	for _, raw := range recs {
		var r sessionRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("unmarshal session record: %v", err)
		}
		if r.SessionID == sid {
			return &r
		}
	}
	return nil
}

// assertLifecycleFields checks the shared payload of a started/ended event.
func assertLifecycleFields(t *testing.T, ev models.QueryEvent, wantUser, wantDB, wantType, action, sid string) {
	t.Helper()
	if ev.Kind != "session" || ev.Action != action {
		t.Errorf("lifecycle event kind/action = %q/%q, want session/%s", ev.Kind, ev.Action, action)
	}
	if ev.Username != wantUser || ev.DBUser != "ro_user" || ev.DBType != wantType {
		t.Errorf("lifecycle event context = user %q db_user %q db_type %q, want %q/ro_user/%s",
			ev.Username, ev.DBUser, ev.DBType, wantUser, wantType)
	}
	if ev.DB != wantDB {
		t.Errorf("lifecycle event db = %q, want %q", ev.DB, wantDB)
	}
	if ev.SessionID != sid {
		t.Errorf("lifecycle event session_id = %q, want %q", ev.SessionID, sid)
	}
	if !strings.HasPrefix(ev.ClientAddr, "127.0.0.1:") {
		t.Errorf("lifecycle event client_addr = %q, want 127.0.0.1:...", ev.ClientAddr)
	}
	if len(ev.ID) != 16 || ev.Ts.IsZero() {
		t.Errorf("lifecycle event id=%q ts=%v, want 16-hex id and non-zero ts", ev.ID, ev.Ts)
	}
}

// TestMySQLSessionLifecycleDirectory (Task 8.2): a live MySQL session through
// the proxy publishes a started lifecycle event on BOTH queries:<user> and
// queries:sess:<sid> (db=appdb from the handshake, full context), enters the
// session directory with the backend CONNECTION_ID() as thread_id; a query
// event also lands on the per-session channel; closing the client publishes
// the ended event and removes the session from the directory. Lifecycle
// events never hit the ticket channel.
func TestMySQLSessionLifecycleDirectory(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "sess-alice", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-8-2"}
	if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	userCh := subscribePG(t, vs, "queries:sess-alice")
	sessPat := subscribePattern(t, vs, "queries:sess:*")
	ticketCh := subscribePG(t, vs, "queries:ticket:T-8-2")

	var logBuf bytes.Buffer
	ln, proxyDone := startTestProxy(t, vs, &logBuf)
	client := dialTestMySQLSession(t, ln, token)

	// started on the user channel AND on the per-session channel (pattern).
	started := recvSessionEvent(t, userCh)
	startedSess := recvSessionEvent(t, sessPat)
	sid := started.SessionID
	if !strings.HasPrefix(sid, "sid-") {
		t.Fatalf("started event session_id = %q, want sid- prefix", sid)
	}
	assertLifecycleFields(t, started, "sess-alice", "appdb", "mysql", "started", sid)
	if startedSess.ID != started.ID || startedSess.SessionID != sid {
		t.Errorf("per-session started event id/sid = %q/%q, want %q/%q (same event)",
			startedSess.ID, startedSess.SessionID, started.ID, sid)
	}
	if started.TicketID != "" {
		t.Errorf("lifecycle event must not carry the ticket id, got %q", started.TicketID)
	}

	// The directory lists the session with the backend connection id.
	rec := findSessionRecord(t, vs, sid)
	if rec == nil {
		t.Fatalf("session %s not listed in the directory after started", sid)
	}
	if rec.ThreadID <= 0 {
		t.Errorf("thread_id = %d, want the backend CONNECTION_ID() (> 0)", rec.ThreadID)
	}
	if rec.DB != "appdb" || rec.Username != "sess-alice" || rec.DBUser != "ro_user" || rec.DBType != "mysql" {
		t.Errorf("session record = %+v, want db=appdb user=sess-alice db_user=ro_user db_type=mysql", rec)
	}
	if rec.StartedAt.IsZero() || rec.LastSeen.IsZero() {
		t.Errorf("session record timestamps: started_at=%v last_seen=%v, want non-zero", rec.StartedAt, rec.LastSeen)
	}

	// A query event lands on the user channel AND the per-session channel.
	if err := writeMySQLPacket(client, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
		t.Fatalf("write SELECT 1: %v", err)
	}
	if _, err := readTextResultSet(client); err != nil {
		t.Fatalf("read result set: %v", err)
	}
	ev := recvQueryEvent(t, userCh)
	evSess := recvQueryEvent(t, sessPat)
	if ev.SessionID != sid || ev.Kind != "query" || ev.Status != "ok" {
		t.Errorf("query event = session %q kind %q status %q, want %q/query/ok", ev.SessionID, ev.Kind, ev.Status, sid)
	}
	if evSess.ID != ev.ID {
		t.Errorf("per-session query event id %q != user-channel id %q", evSess.ID, ev.ID)
	}
	// The query event (a real query) DOES reach the ticket channel.
	tick := recvQueryEvent(t, ticketCh)
	if tick.ID != ev.ID {
		t.Errorf("ticket query event id %q != user-channel id %q", tick.ID, ev.ID)
	}

	// Close: ended event on both channels, directory entry removed.
	client.Close()
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return within 5s of client close")
	}
	ended := recvSessionEvent(t, userCh)
	endedSess := recvSessionEvent(t, sessPat)
	assertLifecycleFields(t, ended, "sess-alice", "appdb", "mysql", "ended", sid)
	if endedSess.ID != ended.ID {
		t.Errorf("per-session ended event id %q != user-channel id %q", endedSess.ID, ended.ID)
	}
	if findSessionRecord(t, vs, sid) != nil {
		t.Errorf("session %s still listed in the directory after close", sid)
	}
	// Lifecycle events never reach the ticket channel.
	expectNoEvent(t, ticketCh)
}

// TestPGSessionLifecycleDirectory (Task 8.2 PG mirror): same assertions as
// the MySQL lifecycle test against the live pg-test backend — the directory
// record carries the backend pid (pg_backend_pid()) as thread_id and the
// client-requested database from the StartupMessage.
func TestPGSessionLifecycleDirectory(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	token := fmt.Sprintf("pgsess_%d", time.Now().UnixNano())
	if err := vs.SetToken(ctx, token, models.TokenPayload{Username: "sess-pg-alice",
		DBUser: "ro_user", DBIP: "127.0.0.1", DBPort: "5433", DBType: "postgres"}, 5*time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	userCh := subscribePG(t, vs, "queries:sess-pg-alice")
	sessPat := subscribePattern(t, vs, "queries:sess:*")

	ln, done := startTestPGProxyWithCreds(t, vs, &bytes.Buffer{}, pgLiveCreds, 1)
	front := pgDialDB(t, ln, token, false, "appdb")
	pgReadUntilReady(t, front)

	started := recvSessionEvent(t, userCh)
	startedSess := recvSessionEvent(t, sessPat)
	sid := started.SessionID
	assertLifecycleFields(t, started, "sess-pg-alice", "appdb", "postgres", "started", sid)
	if startedSess.ID != started.ID || startedSess.SessionID != sid {
		t.Errorf("per-session started event id/sid = %q/%q, want %q/%q",
			startedSess.ID, startedSess.SessionID, started.ID, sid)
	}

	rec := findSessionRecord(t, vs, sid)
	if rec == nil {
		t.Fatalf("session %s not listed in the directory after started", sid)
	}
	if rec.ThreadID <= 0 {
		t.Errorf("thread_id = %d, want the backend pg_backend_pid() (> 0)", rec.ThreadID)
	}
	if rec.DB != "appdb" || rec.Username != "sess-pg-alice" || rec.DBUser != "ro_user" || rec.DBType != "postgres" {
		t.Errorf("session record = %+v, want db=appdb user=sess-pg-alice db_user=ro_user db_type=postgres", rec)
	}

	pgExecQuery(t, front, "SELECT 1")
	ev := recvQueryEvent(t, userCh)
	evSess := recvQueryEvent(t, sessPat)
	if ev.SessionID != sid || ev.Kind != "query" || ev.Status != "ok" {
		t.Errorf("query event = session %q kind %q status %q, want %q/query/ok", ev.SessionID, ev.Kind, ev.Status, sid)
	}
	if evSess.ID != ev.ID {
		t.Errorf("per-session query event id %q != user-channel id %q", evSess.ID, ev.ID)
	}

	if err := front.Send(&pgproto3.Terminate{}); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	waitPGDone(t, done)
	ended := recvSessionEvent(t, userCh)
	endedSess := recvSessionEvent(t, sessPat)
	assertLifecycleFields(t, ended, "sess-pg-alice", "appdb", "postgres", "ended", sid)
	if endedSess.ID != ended.ID {
		t.Errorf("per-session ended event id %q != user-channel id %q", endedSess.ID, ended.ID)
	}
	if findSessionRecord(t, vs, sid) != nil {
		t.Errorf("session %s still listed in the directory after close", sid)
	}
}

// TestSessionPerChannelNoCrossTalk (Task 8.2): two concurrent MySQL sessions;
// each session's own channel (queries:sess:<sid>) carries ONLY that session's
// events — the query event each channel delivers must be its own (matched by
// SQL and session id), the ended events land on the right channels, and after
// both close neither channel receives anything further. Both sessions also
// drop out of the directory.
func TestSessionPerChannelNoCrossTalk(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	setToken := func(user string) string {
		token, err := store.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if err := vs.SetToken(ctx, token, models.TokenPayload{Username: user, DBUser: "ro_user",
			DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql"}, time.Minute); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		return token
	}
	tokenA := setToken("xtalk-a")
	tokenB := setToken("xtalk-b")

	userA := subscribePG(t, vs, "queries:xtalk-a")
	userB := subscribePG(t, vs, "queries:xtalk-b")

	var logBuf bytes.Buffer
	ln, p := startKillTestProxy(t, vs, &logBuf)

	// Both sessions connect; the started events yield the session ids.
	clientA := dialTestMySQLSession(t, ln, tokenA)
	startedA := recvSessionEvent(t, userA)
	sidA := startedA.SessionID
	clientB := dialTestMySQLSession(t, ln, tokenB)
	startedB := recvSessionEvent(t, userB)
	sidB := startedB.SessionID
	if sidA == sidB {
		t.Fatalf("both sessions got the same id %q", sidA)
	}
	// Subscribe to each session's OWN channel now that the ids are known.
	sessA := subscribePG(t, vs, "queries:sess:"+sidA)
	sessB := subscribePG(t, vs, "queries:sess:"+sidB)

	// One query per session, then each per-session channel must deliver its
	// own session's query event — and never the other's.
	if err := writeMySQLPacket(clientA, 0, append([]byte{cmdQuery}, "SELECT 'from-A'"...)); err != nil {
		t.Fatalf("write A query: %v", err)
	}
	if _, err := readTextResultSet(clientA); err != nil {
		t.Fatalf("read A result: %v", err)
	}
	if err := writeMySQLPacket(clientB, 0, append([]byte{cmdQuery}, "SELECT 'from-B'"...)); err != nil {
		t.Fatalf("write B query: %v", err)
	}
	if _, err := readTextResultSet(clientB); err != nil {
		t.Fatalf("read B result: %v", err)
	}

	evA := recvQueryEvent(t, sessA)
	evB := recvQueryEvent(t, sessB)
	if evA.SessionID != sidA || !strings.Contains(evA.SQL, "from-A") {
		t.Errorf("session A channel delivered %q (sid %q) — want A's own query (from-A, sid %q)",
			evA.SQL, evA.SessionID, sidA)
	}
	if evB.SessionID != sidB || !strings.Contains(evB.SQL, "from-B") {
		t.Errorf("session B channel delivered %q (sid %q) — want B's own query (from-B, sid %q)",
			evB.SQL, evB.SessionID, sidB)
	}

	// Close both; the ended event must land on each session's own channel.
	clientA.Close()
	endedA := recvSessionEvent(t, sessA)
	if endedA.SessionID != sidA || endedA.Action != "ended" {
		t.Errorf("session A channel ended event = sid %q action %q, want %q/ended", endedA.SessionID, endedA.Action, sidA)
	}
	clientB.Close()
	endedB := recvSessionEvent(t, sessB)
	if endedB.SessionID != sidB || endedB.Action != "ended" {
		t.Errorf("session B channel ended event = sid %q action %q, want %q/ended", endedB.SessionID, endedB.Action, sidB)
	}

	// Nothing further on either per-session channel, and both sessions are
	// gone from the directory (p is unused beyond the registry sanity).
	if p == nil {
		t.Fatal("nil proxy")
	}
	expectNoEvent(t, sessA)
	expectNoEvent(t, sessB)
	if findSessionRecord(t, vs, sidA) != nil || findSessionRecord(t, vs, sidB) != nil {
		t.Errorf("sessions %s/%s still listed in the directory after close", sidA, sidB)
	}
}
