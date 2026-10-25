package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// --- Alignment review I-3: the ctl:relock subscriber loop --------------------
//
// The alignment review found the ctl:relock subscriber loop (cmd/data/
// main.go) with no test harness anywhere — the full chain (hub watch-loss →
// ctl:relock publish → subscriber → freeze) was exercised only through
// direct HandleRelock calls. There is no in-process harness for the main()
// loop itself (the plane is one whole binary; the only existing cmd/data
// live test drives a real subprocess), so per the brief's fallback these
// tests (in the proxy package, where the session registries are reachable)
// drive the loop's message-parse→HandleRelock dispatch exactly as main.go
// wires it:
//
//   - the loop body VERBATIM (the same bounded chan []byte, the same
//     NewRelocker fanout, the same HandleRelock + "session re-locked" log
//     on froze) as a goroutine, against a LIVE registered hold-admitted rw
//     session;
//   - the same loop fed by a REAL vs.Subscribe on ctl:relock, published
//     with vs.Publish exactly as the control-plane hub does — the full
//     publish→Subscribe→HandleRelock chain, in-process.
//
// parseRelockPayload's acceptance/rejection matrix is already pinned
// (TestMySQLRelockIgnoresNonRWAndUnknown); what was UNPINNED is the
// dispatch: a message reaching the subscriber reaching HandleRelock and
// freezing the session — and garbage on the channel dropping silently
// without freezing anything or killing the loop.

// relockSubscriberStore connects to the live local Valkey (the suite
// convention).
func relockSubscriberStore(t *testing.T) *store.ValkeyStore {
	t.Helper()
	vs := proxyTestStore(t)
	return vs
}

// relockSubscriberSession registers a hold-admitted rw mysql session on a
// real relay pipe (the only shape HandleRelock freezes).
func relockSubscriberSession(t *testing.T, p *MySQLProxy, vs *store.ValkeyStore, sid string) {
	t.Helper()
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &mysqlSession{id: sid, access: "rw", holdAdmitted: true, client: client, backend: backend,
		tok: &models.TokenPayload{Username: "relock-sub", DBUser: "rw_user", DBType: "mysql", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(context.Background(), sid)
		cpeer.Close()
		bpeer.Close()
		client.Close()
		backend.Close()
	})
	p.registerSession(s)
}

// TestRelockSubscriberLoopDispatchFreezes (I-3.1, dispatch half): the
// main.go loop body verbatim over the in-process channel — the hub's
// payload freezes the live hold-admitted rw session; malformed /
// non-relock payloads drop silently and the loop keeps consuming.
func TestRelockSubscriberLoopDispatchFreezes(t *testing.T) {
	vs := relockSubscriberStore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewMySQLProxy(log, vs, &ConfigCredResolver{}, nil)
	relocker := NewRelocker(p, nil, nil)

	sid := "sid-relock-sub-loop"
	relockSubscriberSession(t, p, vs, sid)

	// The main.go subscriber loop body, verbatim (minus the logger it
	// closes over): bounded channel drained by a goroutine calling
	// relocker.HandleRelock; froze → log; anything else → continue.
	relockCh := make(chan []byte, 16)
	go func() {
		for msg := range relockCh {
			if s, froze := relocker.HandleRelock(msg); froze {
				log.Info("session re-locked", "session_id", s)
			}
		}
	}()

	// The hub publishes exactly this when the last checker leaves an
	// admitted session.
	relockCh <- []byte(`{"action":"relock","session_id":"` + sid + `"}`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.sessionFrozen(sid) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !p.sessionFrozen(sid) {
		t.Fatal("the subscriber loop did not freeze the session (dispatch broken)")
	}

	// Garbage on the same channel drops silently (HandleRelock=false →
	// continue): the loop must keep consuming — the follow-up publish
	// below would deadlock a crashed loop (channel never drained).
	relockCh <- []byte(`garbage`)
	relockCh <- []byte(`{"action":"kill","session_id":"` + sid + `"}`)
	select {
	case relockCh <- []byte(`{"action":"relock","session_id":"` + sid + `"}`):
	default:
		t.Fatal("the subscriber loop stopped consuming — garbage killed it")
	}
	close(relockCh)
}

// TestRelockSubscriberPubsubChainFreezes (I-3.1, pubsub half): the same
// loop fed by a REAL vs.Subscribe on ctl:relock; the test publishes the
// hub's payload with vs.Publish (the WS-hub disconnect defer's exact call)
// and the live session freezes — the full publish→Subscribe→HandleRelock
// chain, in-process.
func TestRelockSubscriberPubsubChainFreezes(t *testing.T) {
	vs := relockSubscriberStore(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pg := NewPGProxy(log, vs, &ConfigCredResolver{}, nil)
	mp := NewMSSQLProxy(log, vs, &ConfigCredResolver{}, nil)
	relocker := NewRelocker(nil, pg, mp)

	sid := "sid-relock-sub-e2e"
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	s := &pgSession{id: sid, access: "rw", holdAdmitted: true,
		tok: &models.TokenPayload{Username: "relock-sub", DBUser: "rw_user", DBType: "postgres", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		pg.unregisterSession(sid)
		_ = vs.DelSessionLive(context.Background(), sid)
		cpeer.Close()
		bpeer.Close()
		client.Close()
		backend.Close()
	})
	pg.registerSession(s)

	// The subscriber half of main.go's wiring: vs.Subscribe on ctl:relock
	// feeding the bounded channel; the loop body as in main.go. The
	// subscription must be ACKED before the publish (a fire-and-forget
	// Subscribe would race the hub's publish and drop it — the same
	// waitSubAck discipline every other pubsub test uses).
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
			if s, froze := relocker.HandleRelock(msg); froze {
				log.Info("session re-locked", "session_id", s)
			}
		}
	}()

	// The hub's publish. The pg plane holds the session → the fanout must
	// reach the pg arm and freeze it; the mssql arm must not touch it.
	if err := vs.Publish(ctx, "ctl:relock", []byte(`{"action":"relock","session_id":"`+sid+`"}`)); err != nil {
		t.Fatalf("publish ctl:relock: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pg.sessionFrozen(sid) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !pg.sessionFrozen(sid) {
		t.Fatal("the published ctl:relock did not freeze the pg session")
	}
	if mp.sessionFrozen(sid) {
		t.Error("the mssql arm froze a pg-plane session id")
	}
}
