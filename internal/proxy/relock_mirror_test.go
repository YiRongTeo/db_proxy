package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
)

// --- Task 9 mirrors: PG + MSSQL re-lock (mysql first, these follow) ----------
//
// Same contract as the MySQL tests in relock_test.go, per dialect: the
// frozen session's reply must be the WELL-FORMED gating error for the
// protocol (PG FATAL 28000 + ReadyForQuery; MSSQL ERROR token 18456), the
// backend never sees frozen messages, and non-rw/unknown/flag-off are no-ops.

// TestPGRelockFreezeAndUnfreeze: freeze a hold-admitted rw pgSession — the
// client's SimpleQuery is answered with FATAL 28000 + the gating message +
// ReadyForQuery and never forwarded; a watcher attach unfreezes.
func TestPGRelockFreezeAndUnfreeze(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	sid := "sid-relock-pg"
	s := &pgSession{id: sid, access: "rw", holdAdmitted: true,
		tok: &models.TokenPayload{Username: "relock-maker", DBUser: "rw_user", DBType: "postgres", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(ctx, sid)
	})
	p.registerSession(s)

	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Fatal("PG HandleRelock = false, want true")
	}
	if !p.sessionFrozen(sid) {
		t.Fatal("pg session not frozen after HandleRelock")
	}

	// Frozen: the decision helper blocks EVERY message; the wire reply is
	// produced by the SAME gatePGReject machinery the relay calls (the
	// ErrorResponse shape is pinned by TestPGWriteGateDecision).
	var out bytes.Buffer
	be := pgproto3.NewBackend(pgproto3.NewChunkReader(&out), &out)
	if msg := p.relockPGBlockMsg(s); msg == "" || !strings.Contains(msg, "maker gating") {
		t.Errorf("relockPGBlockMsg = %q, want the gating message", msg)
	}
	p.gatePGReject(be, &pgproto3.Query{String: "SELECT 1"}, s, p.relockPGBlockMsg(s))
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(&out), io.Discard)
	m1, err := front.Receive()
	if err != nil {
		t.Fatalf("receive frozen ErrorResponse: %v", err)
	}
	er, ok := m1.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("frozen reply = %T, want *pgproto3.ErrorResponse", m1)
	}
	if er.Code != "28000" || er.Severity != "FATAL" || !strings.Contains(er.Message, "maker gating") || !strings.Contains(er.Message, sid) {
		t.Errorf("frozen ErrorResponse = code %q severity %q message %q, want FATAL 28000 maker-gating naming %s", er.Code, er.Severity, er.Message, sid)
	}
	if m2, err := front.Receive(); err != nil {
		t.Fatalf("receive frozen ReadyForQuery: %v", err)
	} else if _, ok := m2.(*pgproto3.ReadyForQuery); !ok {
		t.Errorf("frozen second message = %T, want *pgproto3.ReadyForQuery", m2)
	}

	// Watcher attaches → unfreeze on the poll.
	if err := vs.SetWatchConn(ctx, sid, "relock-checker-pg", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	waitFor(t, "pg session unfreezes on watch", func() bool { return !p.sessionFrozen(sid) })
	if msg := p.relockPGBlockMsg(s); msg != "" {
		t.Errorf("unfrozen pg session still blocks with %q", msg)
	}
}

// TestMSSQLRelockFreezeAndUnfreeze: freeze a hold-admitted rw mssqlSession —
// the decision helper blocks every message (the ERROR-token reply shape is
// the gateMSSQLReject machinery); a watcher attach unfreezes.
func TestMSSQLRelockFreezeAndUnfreeze(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	sid := "sid-relock-mssql"
	s := &mssqlSession{id: sid, access: "rw", holdAdmitted: true,
		tok: &models.TokenPayload{Username: "relock-maker", DBUser: "rw_user", DBType: "mssql", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(ctx, sid)
	})
	p.registerSession(s)

	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Fatal("MSSQL HandleRelock = false, want true")
	}
	if !p.sessionFrozen(sid) {
		t.Fatal("mssql session not frozen after HandleRelock")
	}
	if msg := p.relockMSSQLBlockMsg(s); msg == "" || !strings.Contains(msg, "maker gating") {
		t.Errorf("relockMSSQLBlockMsg = %q, want the gating message", msg)
	}

	if err := vs.SetWatchConn(ctx, sid, "relock-checker-mssql", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	waitFor(t, "mssql session unfreezes on watch", func() bool { return !p.sessionFrozen(sid) })
	if msg := p.relockMSSQLBlockMsg(s); msg != "" {
		t.Errorf("unfrozen mssql session still blocks with %q", msg)
	}
}

// TestPGMSSQLRelockIgnoresNonRW: the mirror's non-rw / unknown / flag-off
// refusals match the MySQL plane (legacy presets never relock; flag off =
// hard no-op).
func TestPGMSSQLRelockIgnoresNonRW(t *testing.T) {
	vs := proxyTestStore(t)
	pg := NewPGProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	mp := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	pg.SetRWRelockOnWatchLoss(false)
	mp.SetRWRelockOnWatchLoss(false)

	sW := &pgSession{id: "sid-relock-pg-write", access: "write"}
	pg.registerSession(sW)
	defer pg.unregisterSession(sW.id)
	if pg.HandleRelock([]byte(`{"action":"relock","session_id":"sid-relock-pg-write"}`)) {
		t.Error("PG HandleRelock with flag off = true, want false")
	}

	mW := &mssqlSession{id: "sid-relock-mssql-write", access: "write"}
	mp.registerSession(mW)
	defer mp.unregisterSession(mW.id)
	if mp.HandleRelock([]byte(`{"action":"relock","session_id":"sid-relock-mssql-write"}`)) {
		t.Error("MSSQL HandleRelock with flag off = true, want false")
	}
	if mp.sessionFrozen("sid-relock-mssql-write") || pg.sessionFrozen("sid-relock-pg-write") {
		t.Error("sessions froze with the flag off, want never")
	}
}
