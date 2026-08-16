package api

import (
	"context"
	"encoding/json"
	"time"

	"zerotrust-proxy/internal/audit"
	"zerotrust-proxy/internal/models"
)

// --- Task 9.7: session audit persistence to MySQL ---------------------------
// The Control Plane is the audit WRITER: it issues tokens (pending rows),
// consumes the data plane's lifecycle events via the hub's queries:sess:*
// pub/sub (started → active, ended → ended) and knows the checker identity
// on watch attach/detach (checker_username set/NULL). Every hook is a no-op
// when a.audit is nil (audit.mysql.enabled=false), and every write failure
// is logged but NEVER fatal to the token/connect flow.

// auditUpsertPending writes the pending row at token issue time (hook in
// handleToken). Access falls back to "read" for ungated presets (absent
// access means read per the token contract). Best-effort: the token is
// already stored — an audit hiccup must not fail the issue.
func (a *api) auditUpsertPending(ctx context.Context, p *models.TokenPayload) {
	if a.audit == nil {
		return
	}
	access := p.Access
	if access == "" {
		access = "read"
	}
	err := a.audit.UpsertSession(ctx, audit.SessionRecord{
		SessionID: p.SessionID,
		Username:  p.Username,
		TicketID:  p.TicketID,
		DBType:    p.DBType,
		DBUser:    p.DBUser,
		Access:    access,
		LastSeen:  time.Now().UTC(),
	})
	if err != nil {
		a.log.Error("audit upsert pending", "session_id", p.SessionID, "err", err)
	}
}

// auditChecker records checker presence on a session: checker != "" on
// attach, "" (NULL) on detach. Mirrors the watch:<sid> key lifecycle in
// handleWS — the hub knows the checker's username from the WS session.
func (a *api) auditChecker(ctx context.Context, sessionID, checker string) {
	if a.audit == nil {
		return
	}
	if err := a.audit.SetChecker(ctx, sessionID, checker); err != nil {
		a.log.Error("audit set checker", "session_id", sessionID, "checker", checker, "err", err)
	}
}

// auditLifecycleEvent feeds one consumed kind=session event into the audit
// writer. started → active (started_at + db fields from the event); ended →
// ended (ended_at). issued events are a no-op here — handleToken already
// wrote the pending row synchronously.
func (a *api) auditLifecycleEvent(ctx context.Context, ev models.QueryEvent) {
	if a.audit == nil {
		return
	}
	switch ev.Action {
	case "started":
		err := a.audit.SetActive(ctx, audit.ActiveRecord{
			SessionID: ev.SessionID,
			Username:  ev.Username,
			DBType:    ev.DBType,
			DBUser:    ev.DBUser,
			DB:        ev.DB,
			StartedAt: ev.Ts,
			LastSeen:  time.Now().UTC(),
		})
		if err != nil {
			a.log.Error("audit set active", "session_id", ev.SessionID, "err", err)
		}
	case "ended":
		if err := a.audit.SetEnded(ctx, ev.SessionID, ev.Ts); err != nil {
			a.log.Error("audit set ended", "session_id", ev.SessionID, "err", err)
		}
	}
}

// auditSweepEvery is the pending-row sweeper cadence (review 9.9): pending
// audit rows (token issued, maker never connected) are expired to 'ended'
// once their last_seen is older than sessionPendingTTL. Tests shorten the
// cadence via the api.auditSweepEvery field (zero → this default).
const auditSweepEvery = 30 * time.Second

// RunAuditSweeper periodically expires stale pending audit rows: rows whose
// maker never connected within sessionPendingTTL are flipped to 'ended' by
// the writer (SweepStalePending), keeping the audit trail terminated. It
// runs until ctx is cancelled; no-op when audit is disabled (no writer, no
// goroutine work). Events lost during a pub/sub gap are healed by the same
// sweep — a pending row that never became active is ended on the next pass.
func (a *api) RunAuditSweeper(ctx context.Context) {
	if a.audit == nil {
		return
	}
	every := a.auditSweepEvery
	if every <= 0 {
		every = auditSweepEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			n, err := a.audit.SweepStalePending(ctx, time.Now().Add(-sessionPendingTTL))
			if err != nil {
				a.log.Error("audit sweep stale pending", "err", err)
				continue
			}
			if n > 0 {
				a.log.Info("audit sweep expired stale pending rows", "rows", n)
			}
		case <-ctx.Done():
			return
		}
	}
}

// RunAuditLifecycle consumes the hub's per-session lifecycle channel pattern
// (queries:sess:*, where the Control Plane and Data Plane publish
// kind=session issued/started/ended events) and mirrors started/ended into
// the audit writer. Blocks until ctx is canceled; only meaningful when audit
// is enabled (no-op otherwise — no subscription, zero overhead). The
// subscription is resilient: subscribeLoop resubscribes with backoff on
// transient failures (review 9.9), and events lost during a gap are healed
// by the pending-audit sweeper.
func (a *api) RunAuditLifecycle(ctx context.Context) {
	if a.audit == nil {
		return
	}
	out := make(chan []byte, 256)
	go a.subscribeLoop(ctx, "queries:sess:*", true, out)
	for {
		select {
		case m := <-out:
			var ev models.QueryEvent
			if err := json.Unmarshal(m, &ev); err != nil || ev.Kind != "session" {
				continue
			}
			a.auditLifecycleEvent(ctx, ev)
		case <-ctx.Done():
			return
		}
	}
}
