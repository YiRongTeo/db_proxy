package proxy

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// stallingStore wraps a real store and blocks every relay/gate store call
// (WatchActive / Publish / SetSessionLive) until the CALLER'S context
// expires, then returns ctx.Err() — the failure mode a timed-out call
// produces. Used to prove the relay/gate hot paths BOUND their store calls
// (review 2026-08-17): a hung valkey must stall a session for at most
// storeCallTimeout, never for the lifetime of the TCP retransmit.
type stallingStore struct {
	*store.ValkeyStore
}

func (s *stallingStore) WatchActive(ctx context.Context, _ string) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func (s *stallingStore) Publish(ctx context.Context, _ string, _ []byte) error {
	<-ctx.Done()
	return ctx.Err()
}

func (s *stallingStore) SetSessionLive(ctx context.Context, _ string, _ []byte, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

func newStallingStore(t *testing.T) *stallingStore {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	return &stallingStore{ValkeyStore: vs}
}

// shrinkStoreTimeout shortens storeCallTimeout for one test and restores it.
func shrinkStoreTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := storeCallTimeout
	storeCallTimeout = d
	t.Cleanup(func() { storeCallTimeout = old })
}

// TestGateCheckBoundedStoreTimeout proves the MySQL write-gate decision
// FAILS CLOSED within storeCallTimeout when the store hangs — the command
// is blocked exactly like an absent watcher, and the relay never hangs on
// a dead valkey.
func TestGateCheckBoundedStoreTimeout(t *testing.T) {
	shrinkStoreTimeout(t, 150*time.Millisecond)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), newStallingStore(t), &ConfigCredResolver{}, nil)
	s := &mysqlSession{id: "sid-gate-timeout", access: "write"}

	start := time.Now()
	msg := p.checkWriteGate(s, cmdQuery)
	elapsed := time.Since(start)

	if msg == "" || !strings.Contains(msg, "maker gating") {
		t.Fatalf("hung store: gate allowed the command (msg=%q), want fail-closed block", msg)
	}
	if elapsed < storeCallTimeout/2 {
		t.Errorf("gate check returned in %v — the store call was not bounded by the timeout", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("gate check took %v — bounded store call still hung", elapsed)
	}
}

// TestPGGateBlockBoundedStoreTimeout is the PG mirror of the MySQL test:
// gatePGBlockMsg must fail closed within storeCallTimeout on a hung store.
func TestPGGateBlockBoundedStoreTimeout(t *testing.T) {
	shrinkStoreTimeout(t, 150*time.Millisecond)
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), newStallingStore(t), &ConfigCredResolver{}, nil)
	s := &pgSession{id: "sid-pg-gate-timeout", access: "write"}

	start := time.Now()
	msg := p.gatePGBlockMsg(&pgproto3.Query{String: "SELECT 1"}, s)
	elapsed := time.Since(start)

	if msg == "" || !strings.Contains(msg, "maker gating") {
		t.Fatalf("hung store: PG gate allowed the message (msg=%q), want fail-closed block", msg)
	}
	if elapsed < storeCallTimeout/2 {
		t.Errorf("PG gate check returned in %v — store call not bounded by the timeout", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("PG gate check took %v — bounded store call still hung", elapsed)
	}
}

// TestMSSQLGateBlockBoundedStoreTimeout is the TDS mirror: gateMSSQLBlocked
// must fail closed within storeCallTimeout on a hung store.
func TestMSSQLGateBlockBoundedStoreTimeout(t *testing.T) {
	shrinkStoreTimeout(t, 150*time.Millisecond)
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), newStallingStore(t), &ConfigCredResolver{}, nil)
	s := &mssqlSession{id: "sid-mssql-gate-timeout", access: "write"}

	start := time.Now()
	msg := p.gateMSSQLBlocked(s, tdsSQLBatch)
	elapsed := time.Since(start)

	if msg == "" || !strings.Contains(msg, "maker gating") {
		t.Fatalf("hung store: MSSQL gate allowed the message (msg=%q), want fail-closed block", msg)
	}
	if elapsed < storeCallTimeout/2 {
		t.Errorf("MSSQL gate check returned in %v — store call not bounded by the timeout", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("MSSQL gate check took %v — bounded store call still hung", elapsed)
	}
}

// TestPublishEventBoundedStoreTimeout proves a hung store cannot stall the
// backend→client relay pipe beyond storeCallTimeout: publishEvent's
// publishes + heartbeat share ONE bounded context, so the total stall is
// the timeout, not N × timeout.
func TestPublishEventBoundedStoreTimeout(t *testing.T) {
	shrinkStoreTimeout(t, 150*time.Millisecond)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), newStallingStore(t), &ConfigCredResolver{}, nil)
	s := &mysqlSession{id: "sid-publish-timeout", db: "appdb"}
	ev := &models.QueryEvent{
		ID: "ev-1", Ts: time.Now().UTC(), Kind: "query",
		Username: "alice", DBUser: "rw_user", DBType: "mysql",
		SessionID: s.id, SQL: "SELECT 1",
	}

	start := time.Now()
	p.publishEvent(s, ev)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("publishEvent took %v on a hung store — relay pipe would stall", elapsed)
	}
}

// TestGateWaitLoopDrainsOnHungStore proves the grace-wait goroutine cannot
// be pinned by a hung store: the recheck's WatchActive is bounded, so the
// grace timer still fires and the wait ends with the drain (timeout)
// callback — never stuck waiting for a store that never answers.
func TestGateWaitLoopDrainsOnHungStore(t *testing.T) {
	shrinkStoreTimeout(t, 100*time.Millisecond)
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), newStallingStore(t), &ConfigCredResolver{}, nil)
	s := &mysqlSession{id: "sid-waitloop-timeout", access: "write"}

	var flushed, timedOut atomic.Bool
	s.gate.startWait(&p.sessionPublisher, s.id, 1,
		func() { flushed.Store(true) },
		func() { timedOut.Store(true) })

	done := make(chan struct{})
	go func() {
		s.gate.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("grace-wait goroutine never ended — a hung store pinned it")
	}
	if !timedOut.Load() {
		t.Error("grace timer did not drain the wait (timeout callback not called)")
	}
	if flushed.Load() {
		t.Error("flush fired without a watcher")
	}
}
