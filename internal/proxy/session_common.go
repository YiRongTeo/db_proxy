package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"zerotrust-proxy/internal/metrics"
	"zerotrust-proxy/internal/models"
)

// Shared session/publish machinery: the session/publish helpers
// (publishEvent, publishLifecycle, refreshSessionLive, finishSession,
// flushPendingOnClose, publishPending, publishBlocked — plus PG's
// publishPendingOnReady safety net) live here ONCE, parameterized by the
// per-protocol bits: the session types (mysqlSession/pgSession/mssqlSession,
// via the sessionCommon surface below) and the result captures (via
// captureResult). The proxies embed sessionPublisher, so every call site
// (p.publishEvent(s, ev), p.publishPending(s, c), …) resolves to these
// shared methods unchanged.

// sessionPublisher is the shared session/publish state, embedded by every
// proxy: log/vs (session + lifecycle publishing), logQueryOutput (captured
// result payload on query log lines), metrics (OTel instruments; nil =
// disabled, every call a no-op) and callbacks (the session-status callback
// client; nil = disabled — every notify a no-op), wired once from cmd/data
// via SetSessionCallbacks and consumed by publishLifecycle below.
type sessionPublisher struct {
	log            *slog.Logger
	vs             Store
	logQueryOutput bool
	metrics        *metrics.Metrics
	callbacks      *SessionCallbacks

	// ipLockDisabled flips the session-token IP lock (checkSessionTokenIP
	// above) into a pass-through on every plane embedding this publisher.
	// The ZERO VALUE is false = LOCKED: constructors never set it and a
	// hand-built publisher keeps the secure default; only SetIPLock(false)
	// — wired from session.ip_lock / ZT_SESSION_IP_LOCK — disables the
	// check (the data plane boots a loud WARN when it does).
	ipLockDisabled bool
}

// SetIPLock enables/disables the session-token IP lock on this proxy (the
// publisher is embedded, so the setter is promoted onto all four planes and
// one config knob reaches every connect path). true (the default) enforces
// the check; false turns it into a pass-through.
func (pub *sessionPublisher) SetIPLock(on bool) { pub.ipLockDisabled = !on }

// storeCallTimeout bounds every store call made from the relay/gate hot
// paths: a hung valkey must stall a session for at
// most this long — gate checks fail closed (the command is blocked exactly
// like an absent watcher), publish paths log-and-continue — never for the
// lifetime of a TCP retransmit. A var (not const) so tests can shrink it.
var storeCallTimeout = 3 * time.Second

// storeCallCtx returns a context bounded by storeCallTimeout for one
// logical store operation. All store calls of one publish share the SAME
// ctx, so the total stall is bounded by the timeout, not N × timeout.
func storeCallCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), storeCallTimeout)
}

// sessionCommon is the per-protocol session surface the shared publisher
// needs — the session fields that feed the directory record, the heartbeat
// stamp and the pending/capture slots. Implemented by mysqlSession,
// pgSession and mssqlSession (one-liners in this file).
type sessionCommon interface {
	lockSession()
	unlockSession()
	sessionMeta() (id, db string, threadID int64, startedAt, lastSeen time.Time)
	setSessionLastSeen(t time.Time)
	pendingEvent() *models.QueryEvent
	clearPending()
	currentCapture() captureResult
	clearCapture()
}

// capturedResult is the response-capture payload shared by the three
// protocol captures (resultCapture / pgResultCapture / mssqlResultCapture
// all carry exactly these fields): status/errorMsg plus the captured result
// set (columns/rows/truncated, capped identically by each capture).
type capturedResult struct {
	status    string
	errorMsg  string
	columns   []string
	rows      [][]string
	truncated bool
}

// captureResult is the response-capture surface the shared publisher needs;
// every capture type carries one-liner implementations.
type captureResult interface {
	done() bool
	finish()
	snapshot() capturedResult
	isNil() bool
}

// --- sessionCommon implementations (per-protocol bits) --------------------

func (s *mysqlSession) lockSession()   { s.mu.Lock() }
func (s *mysqlSession) unlockSession() { s.mu.Unlock() }
func (s *mysqlSession) sessionMeta() (string, string, int64, time.Time, time.Time) {
	return s.id, s.db, s.threadID, s.startedAt, s.lastSeen
}
func (s *mysqlSession) setSessionLastSeen(t time.Time)   { s.lastSeen = t }
func (s *mysqlSession) pendingEvent() *models.QueryEvent { return s.pending }
func (s *mysqlSession) clearPending()                    { s.pending = nil }
func (s *mysqlSession) currentCapture() captureResult    { return s.capture }
func (s *mysqlSession) clearCapture()                    { s.capture = nil }

func (s *pgSession) lockSession()   { s.mu.Lock() }
func (s *pgSession) unlockSession() { s.mu.Unlock() }
func (s *pgSession) sessionMeta() (string, string, int64, time.Time, time.Time) {
	return s.id, s.db, s.threadID, s.startedAt, s.lastSeen
}

// relockStatePtr is the shared freeze step's per-plane surface.
func (s *pgSession) relockStatePtr() *relockState     { return &s.relock }
func (s *pgSession) setSessionLastSeen(t time.Time)   { s.lastSeen = t }
func (s *pgSession) pendingEvent() *models.QueryEvent { return s.pending }
func (s *pgSession) clearPending()                    { s.pending = nil }
func (s *pgSession) currentCapture() captureResult    { return s.capture }
func (s *pgSession) clearCapture()                    { s.capture = nil }

func (s *mssqlSession) lockSession()   { s.mu.Lock() }
func (s *mssqlSession) unlockSession() { s.mu.Unlock() }
func (s *mssqlSession) sessionMeta() (string, string, int64, time.Time, time.Time) {
	return s.id, s.db, s.threadID, s.startedAt, s.lastSeen
}

// relockStatePtr is the shared freeze step's per-plane surface.
func (s *mssqlSession) relockStatePtr() *relockState     { return &s.relock }
func (s *mssqlSession) setSessionLastSeen(t time.Time)   { s.lastSeen = t }
func (s *mssqlSession) pendingEvent() *models.QueryEvent { return s.pending }
func (s *mssqlSession) clearPending()                    { s.pending = nil }
func (s *mssqlSession) currentCapture() captureResult    { return s.capture }
func (s *mssqlSession) clearCapture()                    { s.capture = nil }

// --- captureResult implementations (per-protocol bits) ---------------------

func (c *resultCapture) snapshot() capturedResult {
	if c == nil {
		return capturedResult{}
	}
	return capturedResult{status: c.status, errorMsg: c.errorMsg, columns: c.columns, rows: c.rows, truncated: c.truncated}
}

func (c *resultCapture) isNil() bool { return c == nil }

func (c *pgResultCapture) snapshot() capturedResult {
	if c == nil {
		return capturedResult{}
	}
	return capturedResult{status: c.status, errorMsg: c.errorMsg, columns: c.columns, rows: c.rows, truncated: c.truncated}
}

func (c *pgResultCapture) isNil() bool { return c == nil }

func (c *mssqlResultCapture) snapshot() capturedResult {
	if c == nil {
		return capturedResult{}
	}
	return capturedResult{status: c.status, errorMsg: c.errorMsg, columns: c.columns, rows: c.rows, truncated: c.truncated}
}

func (c *mssqlResultCapture) isNil() bool { return c == nil }

// --- shared session/publish helpers ----------------------------------------

// publishEvent publishes a QueryEvent to queries:<username>,
// queries:ticket:<ticket_id> (when present) AND the session's own
// channel queries:sess:<session_id>. It also re-arms the session-directory
// heartbeat (SetSessionLive with a fresh last_seen), so an active session
// stays listed while its queries flow. Best-effort: failures are logged by
// the store, never fatal to the relay. Lifecycle events (started/ended) go
// through publishLifecycle instead — they must NOT re-create the record
// after DelSessionLive, and they deliberately skip the ticket channel.
func (pub *sessionPublisher) publishEvent(s sessionCommon, ev *models.QueryEvent) {
	raw, _ := json.Marshal(ev)
	// One bounded ctx for the WHOLE publish: a hung valkey stalls the
	// relay pipe at most storeCallTimeout, never per call.
	ctx, cancel := storeCallCtx()
	defer cancel()
	_ = pub.vs.Publish(ctx, "queries:"+ev.Username, raw)
	if ev.TicketID != "" {
		_ = pub.vs.Publish(ctx, "queries:ticket:"+ev.TicketID, raw)
	}
	_ = pub.vs.Publish(ctx, "queries:sess:"+ev.SessionID, raw)
	s.lockSession()
	s.setSessionLastSeen(time.Now().UTC())
	id, db, threadID, startedAt, lastSeen := s.sessionMeta()
	rec := buildSessionRecord(id, ev.Username, ev.DBUser, ev.DBType, db, threadID, startedAt, lastSeen, "active")
	s.unlockSession()
	_ = pub.vs.SetSessionLive(ctx, id, rec, sessionLiveTTL)
	// Query logging: every published query event is logged with full
	// context (never the token value — the event carries no token). The
	// captured result payload (columns/row_count/rows/truncated) is added
	// ONLY when log_query_output is on; rows are already capped by the
	// capture. Blocked write-gate events flow through here too, carrying
	// status=error + the gating message — the audit trail shows the block
	// in the log as well.
	attrs := []any{
		"username", ev.Username, "ticket_id", ev.TicketID,
		"db_user", ev.DBUser, "db", ev.DB, "db_type", ev.DBType,
		"stmt_type", ev.StmtType, "status", ev.Status,
		"session_id", ev.SessionID, "sql", ev.SQL,
	}
	if pub.logQueryOutput {
		attrs = append(attrs,
			"columns", ev.Columns, "row_count", len(ev.Rows),
			"rows", ev.Rows, "truncated", ev.Truncated)
	}
	pub.log.Info("query", attrs...)
}

// refreshSessionLive writes (or refreshes) the session's directory record —
// sess:live:<sid> with the heartbeat TTL — stamping a fresh last_seen. Called
// at session start and (via publishEvent) on every published query event.
// Best-effort: failures are logged by the store, never fatal to the session.
func (pub *sessionPublisher) refreshSessionLive(s sessionCommon, tok *models.TokenPayload) {
	s.lockSession()
	s.setSessionLastSeen(time.Now().UTC())
	id, db, threadID, startedAt, lastSeen := s.sessionMeta()
	rec := buildSessionRecord(id, tok.Username, tok.DBUser, tok.DBType, db, threadID, startedAt, lastSeen, "active")
	s.unlockSession()
	ctx, cancel := storeCallCtx() // bounded store call
	defer cancel()
	_ = pub.vs.SetSessionLive(ctx, id, rec, sessionLiveTTL)
}

// publishLifecycle publishes a session lifecycle event (Kind=session,
// Action=started|ended) to queries:<username> AND queries:sess:<sid>. Lifecycle
// events deliberately do NOT go to the ticket channel — ticket grouping is
// about query activity, not connection presence.
func (pub *sessionPublisher) publishLifecycle(s sessionCommon, tok *models.TokenPayload, action, clientAddr string) {
	id, db, _, _, _ := s.sessionMeta()
	ev := models.QueryEvent{
		ID:         newEventID(),
		Ts:         time.Now().UTC(),
		Kind:       "session",
		Action:     action,
		Username:   tok.Username,
		DBUser:     tok.DBUser,
		DBType:     tok.DBType,
		DB:         db,
		SessionID:  id,
		ClientAddr: clientAddr,
	}
	raw, _ := json.Marshal(ev)
	ctx, cancel := storeCallCtx() // bounded store calls
	defer cancel()
	_ = pub.vs.Publish(ctx, "queries:"+ev.Username, raw)
	_ = pub.vs.Publish(ctx, "queries:sess:"+id, raw)
	// Session-status callback to the main application — one funnel
	// serves all protocols; fire-and-forget (the HTTP round trip runs on
	// the callback client's own goroutine, never the relay). tok carries
	// the authoritative session id.
	pub.callbacks.NotifySession(s, tok, action)
	// Lifecycle logging: same context fields as the query line, minus
	// sql. ticket_id comes from the TOKEN directly — the wire event
	// deliberately carries none (ticket grouping is query activity only).
	// No credentials, ever.
	pub.log.Info("session "+action, "username", ev.Username, "ticket_id", tok.TicketID,
		"db_user", ev.DBUser, "db", ev.DB, "db_type", ev.DBType, "session_id", ev.SessionID)
}

// finishSession removes the session from the directory (DelSessionLive) and
// publishes the ended lifecycle event. Deferred in handleConn AFTER
// flushPendingOnClose so the ended event is always the session's last word on
// the wire — and the record is deleted only after any final query event
// re-armed the heartbeat.
func (pub *sessionPublisher) finishSession(s sessionCommon, tok *models.TokenPayload, clientAddr string) {
	id, _, _, _, _ := s.sessionMeta()
	ctx, cancel := storeCallCtx() // bounded store call
	defer cancel()
	_ = pub.vs.DelSessionLive(ctx, id)
	pub.publishLifecycle(s, tok, "ended", clientAddr)
}

// flushPendingOnClose publishes any still-pending event as failed when the
// session dies before the backend answered (invoked via defer in
// handleConn, and so also on a kill).
func (pub *sessionPublisher) flushPendingOnClose(s sessionCommon) {
	s.lockSession()
	ev := s.pendingEvent()
	s.clearPending()
	s.unlockSession()
	if ev == nil {
		return
	}
	ev.Status = "error"
	ev.Error = "connection closed before response"
	pub.publishEvent(s, ev)
}

// publishPending attaches the captured response (status/error/columns/rows/
// truncated) to the session's pending event, publishes it to
// queries:<username> and queries:ticket:<ticket_id> (when present), and
// clears the slot for the next command. capture must be the capture whose
// completion triggered this publish; the data is attached ONLY when it is
// still the session's current capture (pointer identity) — never a stale
// capture from a previous command. When a newer command was sniffed in
// between (or nothing is pending at all), nothing is published — no-op for
// non-sniffed commands and stray packets after completion.
func (pub *sessionPublisher) publishPending(s sessionCommon, capture captureResult) {
	s.lockSession()
	ev := s.pendingEvent()
	if ev != nil && capture != nil && !capture.isNil() && s.currentCapture() == capture {
		res := capture.snapshot()
		ev.Status = res.status
		ev.Error = res.errorMsg
		ev.Columns = res.columns
		ev.Rows = res.rows
		ev.Truncated = res.truncated
		s.clearPending()
		s.clearCapture()
	} else {
		ev = nil // stale capture or nothing pending: publish nothing
	}
	s.unlockSession()
	if ev != nil {
		// One query event = one queries.total increment, with the
		// command's latency (sniffed → response completed) recorded on
		// the query.duration histogram.
		pub.metrics.QueriesTotal(ev.DBType, ev.StmtType, ev.Status)
		pub.metrics.QueryDuration(ev.DBType, time.Since(ev.Ts))
		pub.publishEvent(s, ev)
	}
}

// publishPendingOnReady is the PG ReadyForQuery safety net — the one
// session/publish helper that is protocol-specific (only the PG relay
// calls it, at a statement boundary): a command still pending at a
// ReadyForQuery (defensive — every real response ends in CommandComplete /
// ErrorResponse / EmptyQueryResponse, all of which complete the capture) is
// finished as ok and published, so no event is ever left dangling across
// statements. Metrics parity with publishPending.
func (pub *sessionPublisher) publishPendingOnReady(s sessionCommon) {
	s.lockSession()
	ev := s.pendingEvent()
	if ev != nil {
		if c := s.currentCapture(); c != nil && !c.isNil() {
			if !c.done() {
				c.finish()
			}
			res := c.snapshot()
			ev.Status = res.status
			ev.Error = res.errorMsg
			ev.Columns = res.columns
			ev.Rows = res.rows
			ev.Truncated = res.truncated
		}
		s.clearPending()
		s.clearCapture()
	}
	s.unlockSession()
	if ev != nil {
		pub.metrics.QueriesTotal(ev.DBType, ev.StmtType, ev.Status)
		pub.metrics.QueryDuration(ev.DBType, time.Since(ev.Ts))
		pub.publishEvent(s, ev)
	}
}

// publishBlocked publishes the session's pending event immediately with
// status=error and the gating message: a command blocked by the
// maker write-gate never reaches the backend, so no backend response will
// ever complete the pending capture — the audit trail must still show the
// block. The pending slot is cleared so the next command starts fresh.
func (pub *sessionPublisher) publishBlocked(s sessionCommon, msg string) {
	s.lockSession()
	ev := s.pendingEvent()
	s.clearPending()
	s.clearCapture()
	s.unlockSession()
	if ev == nil {
		return
	}
	ev.Status = "error"
	ev.Error = msg
	pub.metrics.GateBlocks(ev.DBType)
	pub.metrics.QueriesTotal(ev.DBType, ev.StmtType, ev.Status)
	pub.publishEvent(s, ev)
}

// clearPendingCapture clears the session's pending/capture slots. The gate
// drain paths call it so the teardown path cannot publish a duplicate
// "connection closed" event.
func (pub *sessionPublisher) clearPendingCapture(s sessionCommon) {
	s.lockSession()
	s.clearPending()
	s.clearCapture()
	s.unlockSession()
}

// publishGateAudits publishes each held entry's audit event as status=error
// with the given drain message (the drain audit tail, shared by the gate
// reject paths). Entries without an event — and later
// packets/frames of the same multi-packet command (pointer-identity dedup,
// the pre-refactor loop semantics) — are skipped.
func (pub *sessionPublisher) publishGateAudits(s sessionCommon, evs []*models.QueryEvent, msg string) {
	var lastEv *models.QueryEvent
	for _, ev := range evs {
		if ev == nil || ev == lastEv {
			continue
		}
		lastEv = ev
		ev.Status = "error"
		ev.Error = msg
		pub.metrics.GateBlocks(ev.DBType)
		pub.metrics.QueriesTotal(ev.DBType, ev.StmtType, ev.Status)
		pub.publishEvent(s, ev)
	}
}
