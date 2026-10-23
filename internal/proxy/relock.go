package proxy

import (
	"encoding/json"
	"sync"
	"time"
)

// --- Task 9 (node-integration): the rw RE-LOCK -------------------------------
//
// Task 6 admitted a held rw session ONE-WAY: a watcher detaching after
// admission never affected the session. The owner now directs the opposite
// policy: when the LAST checker leaves an ADMITTED rw session, the session
// RE-LOCKS — it stays connected but FROZEN until a checker watches again.
//
// Control→data coupling (the same pubsub seam as ctl:kill): the control
// plane's hub, in its disconnect defer, removes its own watch:<sid>:<conn>
// lease and — when NO lease remains (WatchCount==0) and the sess:live record
// shows status "active" — publishes {"action":"relock","session_id":<sid>} on
// the "ctl:relock" channel. The data plane's Relocker (this file, wired in
// cmd/data next to the Killer) fans the message out to the MySQL/PG/MSSQL
// registries; the plane freezes the session when it holds it as a live
// hold-admitted rw session.
//
// Freeze semantics (owner-locked): from the freeze instant EVERY
// client→backend message is answered with the normal gating error
// (gatingMessage — the pre-8.13 gated-writer failure mode) and NOT
// forwarded; the backend→client direction keeps draining (an in-flight
// result set may finish arriving). No ROLLBACK, no COMMIT — in-flight
// transactions are left untouched; the freeze point is the detach. On the
// next WatchActive(sid)==true (a checker re-attaching) the session unfreezes
// and the relay continues. Each freeze fires the session-status callback
// action "started" (the hold-start signal: "joinable now" again) — with
// re-lock on, a session can emit started multiple times; ended exactly once.
//
// Scope: ONLY hold-admitted rw sessions (holdAdmitted is set in the planes'
// admitted branch). Legacy preset write sessions keep their per-command
// checkWriteGate; UAT flag-off (rw_require_checker_watch=false) sessions
// never held, so they are never hold-admitted and never relock; the config
// flag rw_relock_on_watch_loss (default TRUE) disables the whole feature —
// the flag-off path is byte-identical one-way admission (G3). Oracle NEVER
// relocks: no Relocker arm, no hold point (same asymmetry as Tasks 6/7).
//
// Kill interaction: kill closes the conns regardless of the frozen flag —
// KillSession never reads relock state.

// relockState is the per-session frozen flag, guarded by its own mutex (the
// session mu/gateMu guard the pending/capture/gate state; the freeze is set
// from the ctl:relock subscriber goroutine and read per-message by the
// relay). stop carries the re-admission poll's shutdown: armed at freeze,
// closed by unfreeze (watcher returned) or shutdown (session teardown) —
// the mu makes the close-once discipline total.
type relockState struct {
	mu     sync.Mutex
	frozen bool
	stop   chan struct{}
}

// isFrozen reports whether the session is currently re-locked (the relay's
// per-message check).
func (r *relockState) isFrozen() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.frozen
}

// freeze arms the flag and starts the re-admission poll (startWait receives
// the poll's stop channel). Idempotent: a duplicate relock command on an
// already-frozen session returns false and starts nothing. Returns true on
// the live→frozen transition (the caller fires the "started" callback).
func (r *relockState) freeze(startWait func(stop <-chan struct{})) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return false
	}
	r.frozen = true
	stop := make(chan struct{})
	r.stop = stop
	if startWait != nil {
		go startWait(stop)
	}
	return true
}

// unfreeze clears the flag and ends the poll (a checker re-attached).
func (r *relockState) unfreeze() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frozen = false
	if r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
}

// shutdown ends the poll at session teardown WITHOUT changing the flag —
// the session is going away either way; the poll goroutine must simply not
// outlive it. Safe against a concurrent unfreeze (mu serializes the
// close-once).
func (r *relockState) shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
}

// relockWait is the frozen session's re-admission poll — the SAME
// WatchActive probe and the SAME rwHoldPollInterval ticker the initial hold
// uses (watchForAdmission). A checker re-attaching unfreezes the session;
// stop (session teardown) ends the poll. Store errors log and retry — a
// hung valkey must never UNFREEZE a frozen session (fail frozen, exactly
// like the gate's fail-closed).
func (pub *sessionPublisher) relockWait(sid string, stop <-chan struct{}, unfroze func()) {
	ticker := time.NewTicker(rwHoldPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ctx, cancel := storeCallCtx()
			watched, err := pub.vs.WatchActive(ctx, sid)
			cancel()
			if err != nil {
				pub.log.Error("relock: watch recheck failed — still frozen", "session_id", sid, "err", err)
				continue
			}
			if watched {
				pub.log.Info("relock: checker watching — session re-admitted", "session_id", sid)
				unfroze()
				return
			}
		}
	}
}

// relockPayload is the ctl:relock message shape: {"action":"relock",
// "session_id":<sid>}. action is OPTIONAL (absent = relock — mirrors the
// kill payload's optional mode, so older publishers keep working); any other
// action is dropped.
type relockPayload struct {
	Action    string `json:"action"`
	SessionID string `json:"session_id"`
}

// parseRelockPayload decodes a ctl:relock message. ok=false for malformed
// JSON, a missing/empty session_id, or a non-relock action (the subscriber
// drops those silently).
func parseRelockPayload(msg []byte) (sid string, ok bool) {
	var r relockPayload
	if json.Unmarshal(msg, &r) != nil || r.SessionID == "" {
		return "", false
	}
	if r.Action != "" && r.Action != "relock" {
		return "", false
	}
	return r.SessionID, true
}

// relockTargetID extracts the session id a relock command targets ("" for a
// malformed payload — never matches a registry key).
func relockTargetID(msg []byte) string {
	sid, _ := parseRelockPayload(msg)
	return sid
}

// Relocker fans a ctl:relock request out to the MySQL, PostgreSQL and MSSQL
// proxies' registries — the re-lock counterpart of the Killer (kill.go),
// WITHOUT the Oracle arm: oracle sessions never relock (no hold point — the
// same fail-closed asymmetry as the Tasks 6/7 flags). Session ids are
// per-plane ("sid-" + random hex), so a live session sits on exactly one
// plane; all arms are always tried (fast mutex-guarded map lookups on a
// miss), mirroring KillSession. The Killer itself is deliberately NOT
// extended: kill means tear-down, relock means freeze — mixing the two would
// entangle the kill contract (and its metrics/log vocabulary) with the
// freeze policy.
type Relocker struct {
	mysql *MySQLProxy
	pg    *PGProxy
	mssql *MSSQLProxy
}

// NewRelocker wires the three relock-capable planes (oracle omitted by
// design — see the type comment).
func NewRelocker(mysql *MySQLProxy, pg *PGProxy, mssql *MSSQLProxy) *Relocker {
	return &Relocker{mysql: mysql, pg: pg, mssql: mssql}
}

// HandleRelock applies ONE ctl:relock message end to end: parse
// {"action":"relock","session_id"} and freeze the session on whichever plane
// holds it as a live hold-admitted rw session. Returns the session id and
// whether any plane froze it — the ctl:relock subscriber logs "session
// re-locked" for the true case and drops the rest. A malformed payload
// returns ("", false) and is dropped silently.
func (rl *Relocker) HandleRelock(msg []byte) (sid string, froze bool) {
	sid, ok := parseRelockPayload(msg)
	if !ok {
		return "", false
	}
	if rl.mysql != nil && rl.mysql.HandleRelock(msg) {
		return sid, true
	}
	if rl.pg != nil && rl.pg.HandleRelock(msg) {
		return sid, true
	}
	if rl.mssql != nil && rl.mssql.HandleRelock(msg) {
		return sid, true
	}
	return sid, false
}

// --- per-plane glue ----------------------------------------------------------
//
// Each plane gets: SetRWRelockOnWatchLoss (the config flag, constructors
// default TRUE), HandleRelock (freeze a registered hold-admitted rw session
// and fire the "started" callback), sessionFrozen (test/inspection seam) and
// closeRelockWait (the teardown defer that joins the re-admission poll).
// The per-message freeze REJECTS live in each relay (mysql_relay.go /
// pg_relay.go / mssql_relay.go), reusing the plane's own gating-reply
// machinery so the client always sees a well-formed dialect error.

// beginRelock is the shared freeze step: mark the session frozen and arm
// the re-admission poll. Returns true on the live→frozen transition.
func beginRelock(pub *sessionPublisher, s relockableSession) bool {
	return s.relockStatePtr().freeze(func(stop <-chan struct{}) {
		id := relockSessionID(s)
		pub.relockWait(id, stop, func() { s.relockStatePtr().unfreeze() })
	})
}

// relockSessionID pulls the directory id off a session via its sessionCommon
// surface (id, db, threadID, startedAt, lastSeen — the id is first).
func relockSessionID(s relockableSession) string {
	if sc, ok := s.(sessionCommon); ok {
		id, _, _, _, _ := sc.sessionMeta()
		return id
	}
	return ""
}

// endRelockWait is the teardown step (closeRelockWait): end the re-admission
// poll without touching the flag — the session is going away.
func endRelockWait(s relockableSession) {
	if s != nil {
		s.relockStatePtr().shutdown()
	}
}

// relockableSession is the per-plane surface the shared freeze step needs:
// the session's relockState pointer.
type relockableSession interface {
	relockStatePtr() *relockState
}
