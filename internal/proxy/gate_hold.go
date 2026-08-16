package proxy

import (
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/models"
)

// Task 8.13 — gate grace hold.
//
// While a write session has NO watcher, blocked SQL commands WAIT up to
// gate_wait_seconds for a checker to attach instead of failing instantly —
// a maker who connects BEFORE the checker no longer breaks. A watcher
// arriving within the window flushes the queued commands IN ORDER (each
// forwarded exactly as the normal forward path would); the window expiring
// DRAINS the queue — every held command is rejected to the client (MySQL
// ERR 1045 / PG FATAL 28000) with an audit event (status=error, "maker
// gating: no checker connected within <N>s").
//
// Task 8.17 — the gate RE-OPENS on watcher re-attach. The 8.13 permanent
// fail-closed latch is REMOVED: a drained session is NOT latched — the gate
// re-evaluates per command, exactly as it does before any timeout.
// Unwatched → a fresh grace wait (queue → drain/reject + audit); watched →
// forward immediately (a re-attached checker clears the wait state; the
// maker's next command flows without reconnecting). Enforcement is intact:
// no command ever reaches the backend without a watcher at execution time.
//
// Task 9.10 — ordering + locking hardening. While a grace wait is ACTIVE,
// the PG relay stalls EVERY subsequent client message (not just
// Query/Parse/Execute) and the MSSQL relay stalls every message too, so
// extended-protocol messages (Bind/Describe/Sync/Close) and ATTENTIONs can
// never overtake the held queue — the prepared-statement success path stays
// ordered. All gate I/O runs under the session's writeMu (snapshot the gate
// state under gateMu, RELEASE it, then write) — gateMu is never held across
// I/O — and the drain replies serialize with the relay's client writes. The
// wait goroutine is JOINED at session teardown (closeGateWait wg.Wait).
//
// gate_wait_seconds = 0 (the proxy default — the pre-8.13 config value)
// keeps the old behavior: blocked commands reject immediately.

const (
	// gateQueueMax bounds the per-session hold queue: on overflow the NEW
	// command is rejected immediately (that command only — the queue keeps
	// waiting for a watcher).
	gateQueueMax = 16
	// gateWatchRecheckInterval is how often the wait goroutine re-checks
	// for a watcher while commands are held. The watcher is ALSO re-checked
	// on every new command arrival, so the unblock latency is the tick
	// interval at worst.
	gateWatchRecheckInterval = 500 * time.Millisecond
	// defaultGateWaitSeconds is the grace window used when the configured
	// value is negative (clamped in LoadData and in SetGateWaitSeconds).
	defaultGateWaitSeconds = 20
)

// gateTimeoutMessage is the Task 8.13 drain block text, shown to the
// client and recorded in each audit event: the grace window expired with no
// checker attached.
func gateTimeoutMessage(sid string, seconds int) string {
	return fmt.Sprintf("maker gating: no checker connected within %ds (session %s)", seconds, sid)
}

// gateCore is the shared Task 8.13 grace-wait skeleton (Task 9.12
// de-triplication): the active/stop/waiting/wg state plus the wait goroutine
// body, embedded by the three per-protocol gate states (mysqlGateState,
// pgGateState, mssqlGateState — their queues and drain replies stay
// protocol-typed). The flush and timeout ACTIONS are the per-protocol bits,
// passed in as callbacks by the mirrors' Hold paths.
type gateCore struct {
	active  bool           // a grace wait is in progress (queue non-empty)
	stop    chan struct{}  // closed by whoever ends the wait (flush / drain / session close)
	waiting bool           // a wait goroutine is running (reset by every deactivation)
	wg      sync.WaitGroup // join the wait goroutine at session teardown (Task 9.10)
}

// startWait activates the grace wait and launches the shared wait goroutine
// (mirrors call it under the session's gateMu when the gate transitions
// inactive → active). flush/timeout are the mirror's protocol actions.
func (g *gateCore) startWait(pub *sessionPublisher, sid string, seconds int, flush, timeout func()) {
	g.active = true
	g.stop = make(chan struct{})
	if !g.waiting {
		g.waiting = true
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			g.waitLoop(pub, sid, seconds, flush, timeout)
		}()
	}
}

// waitLoop is the shared grace-wait goroutine body: it re-checks for a
// watcher on a short ticker (flushing the queue in order when one appears)
// and drains + rejects the queue when the grace window expires. It exits as
// soon as the wait is ended by any path (flush, drain, session close); the
// caller joins it via g.wg (Task 9.10).
func (g *gateCore) waitLoop(pub *sessionPublisher, sid string, seconds int, flush, timeout func()) {
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(gateWatchRecheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-timer.C:
			timeout()
			return
		case <-ticker.C:
			// Bounded store call (review 2026-08-17): a hung valkey must
			// not pin the wait goroutine — the recheck times out and the
			// grace timer still drains the queue on schedule.
			ctx, cancel := storeCallCtx()
			watched, err := pub.vs.WatchActive(ctx, sid)
			cancel()
			if err != nil {
				pub.log.Error("gate watch recheck failed — continuing the grace wait", "session_id", sid, "err", err)
				continue
			}
			if watched {
				flush()
				return
			}
		case <-g.stop:
			return
		}
	}
}

// deactivateLocked ends the wait: clears active/waiting and closes+nils the
// stop channel. Must be called with the session's gateMu held, right after
// the caller extracts its protocol-typed queue.
func (g *gateCore) deactivateLocked() {
	g.active = false
	g.waiting = false
	if g.stop != nil {
		close(g.stop)
		g.stop = nil
	}
}

// --- MySQL ----------------------------------------------------------------

// mysqlGateEntry is one held command: the exact bytes the normal forward
// path would relay (the client's seq + byte-exact payload) plus the audit
// event snapshot taken at queue time. The session's single pending slot is
// overwritten by each later sniffed command, so the queue preserves every
// held command's event for the drain audit.
type mysqlGateEntry struct {
	seq     byte
	payload []byte
	ev      *models.QueryEvent
}

// mysqlGateState is the per-session Task 8.13 grace-hold state, guarded by
// the session's gateMu (a dedicated mutex — the session mu guards the
// pending/capture slots and is never held across gate transitions).
// gateCore (Task 9.12) carries the shared active/stop/waiting/wg state and
// the wait goroutine; the queue stays protocol-typed here.
type mysqlGateState struct {
	gateCore
	queue []mysqlGateEntry // held commands, bounded (gateQueueMax)
}

// gateHold queues a gated (blocked) command for the grace window instead of
// rejecting it. Returns true when the command was QUEUED — the caller must
// NOT reply and must NOT forward: the client's response comes later, either
// the real backend result (watcher flush) or the drain ERR. Returns false
// when the caller must reject the command immediately: the grace window is
// disabled (gate_wait_seconds=0) or the queue is full (overflow rejects
// only the new command — the queue keeps waiting).
func (p *MySQLProxy) gateHold(s *mysqlSession, seq byte, payload []byte) bool {
	if p.gateWaitSeconds <= 0 {
		return false
	}
	s.gateMu.Lock()
	if !s.gate.active {
		// First held command: start the wait (grace timer + watch ticker).
		s.gate.startWait(&p.sessionPublisher, s.id, p.gateWaitSeconds,
			func() { p.gateFlush(s) }, func() { p.gateTimeout(s) })
	}
	if len(s.gate.queue) >= gateQueueMax {
		s.gateMu.Unlock()
		return false // overflow: reject THIS command only; the queue keeps waiting
	}
	s.mu.Lock()
	ev := s.pending // audit snapshot — sniffCommand ran before the gate check
	s.mu.Unlock()
	s.gate.queue = append(s.gate.queue, mysqlGateEntry{seq: seq, payload: payload, ev: ev})
	s.gateMu.Unlock()
	// A watcher that appeared since the gate check unblocks the queue
	// immediately — checked on every new command arrival, not only on the
	// ticker. Bounded (review 2026-08-17): a hung store must not stall the
	// relay — the wait simply continues until the grace timer drains.
	ctx, cancel := storeCallCtx()
	watched, werr := p.vs.WatchActive(ctx, s.id)
	cancel()
	if werr == nil && watched {
		p.gateFlush(s)
	}
	return true
}

// gateFlush forwards every held command to the backend IN ORDER — each
// exactly as the normal forward path writes it (the stored client seq +
// byte-exact payload, re-framed by writeMySQLPacket) — and clears the wait:
// subsequent commands flow normally. The held commands' sniffed events ride
// the normal pending/capture pipeline (the last one publishes with its
// backend response; earlier ones collapse like any pipelined commands).
// Task 9.10: the gate state is snapshotted under gateMu (NEVER held across
// I/O) and the forwards take the session's writeMu, so a concurrent relay
// forward can never interleave mid-packet or overtake the held queue.
func (p *MySQLProxy) gateFlush(s *mysqlSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	entries := s.gate.queue
	s.gate.queue = nil
	s.gate.deactivateLocked()
	s.gateMu.Unlock()
	s.writeMu.Lock()
	for _, e := range entries {
		if err := writeMySQLPacket(s.backend, e.seq, e.payload); err != nil {
			break
		}
	}
	s.writeMu.Unlock()
}

// gateTimeout drains the queue when the grace window expires: every held
// command is rejected to the client (ERR 1045 + the timeout message) with
// an audit event. The session is NOT latched (Task 8.17): a watcher that
// attaches later re-opens the gate — the maker's next command flows.
func (p *MySQLProxy) gateTimeout(s *mysqlSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	entries := s.gate.queue
	s.gate.queue = nil
	s.gate.deactivateLocked()
	s.gateMu.Unlock()
	p.gateRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
}

// closeGateWait ends a grace wait on session teardown: the held commands
// are drained with the same rejection as a timeout (the replies are
// best-effort — the client is going away anyway) and the wait goroutine is
// JOINED (Task 9.10) so it cannot outlive the session or publish after
// finishSession's DelSessionLive.
func (p *MySQLProxy) closeGateWait(s *mysqlSession) {
	s.gateMu.Lock()
	if s.gate.active {
		entries := s.gate.queue
		s.gate.queue = nil
		s.gate.deactivateLocked()
		s.gateMu.Unlock()
		p.gateRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
	} else {
		s.gateMu.Unlock()
	}
	// Join the wait goroutine (no-op when none was ever started — Wait on
	// a zero counter returns immediately).
	s.gate.wg.Wait()
}

// gateRejectEntries replies to the client for every held command (ERR 1045,
// best-effort) and publishes each one's audit event as status=error with
// the given message. The session's pending slot is cleared so the teardown
// path cannot publish a duplicate "connection closed" event. Task 9.10: the
// replies take the session's writeMu (serialized with the relay's client
// writes); the audit publishes run lock-free afterwards.
func (p *MySQLProxy) gateRejectEntries(s *mysqlSession, entries []mysqlGateEntry, msg string) {
	p.clearPendingCapture(s)
	s.writeMu.Lock()
	for _, e := range entries {
		_ = writeMySQLPacket(s.client, e.seq+1, errPacket(1045, "42000", msg))
	}
	s.writeMu.Unlock()
	evs := make([]*models.QueryEvent, len(entries))
	for i, e := range entries {
		evs[i] = e.ev
	}
	p.publishGateAudits(s, evs, msg)
}

// --- PostgreSQL -----------------------------------------------------------

// pgGateEntry is one held PG message: the RAW wire bytes (type byte + int32
// length + payload — from a byte-exact Encode at queue time; the decoded
// pgproto3 message cannot be stored because Backend.Receive reuses
// flyweight structs across calls), whether it was a SimpleQuery (its drain
// reply carries the trailing ReadyForQuery), whether it was a Sync (Task
// 9.10: a drained Sync must also draw the ReadyForQuery that completes an
// extended-protocol exchange), and the audit event snapshot.
type pgGateEntry struct {
	raw   []byte
	query bool
	sync  bool
	ev    *models.QueryEvent
}

// pgGateState is the per-session Task 8.13 grace-hold state for PG,
// guarded by the session's gateMu. Mirrors mysqlGateState; gateCore
// (Task 9.12) carries the shared state + wait goroutine.
type pgGateState struct {
	gateCore
	queue []pgGateEntry
}

// gatePGHold queues a gated (blocked) PG message for the grace window
// instead of rejecting it. Returns true when the message was QUEUED — the
// caller must NOT reply and must NOT forward. Returns false when the caller
// must reject immediately (gate_wait_seconds=0, queue overflow, or an
// Encode failure — the latter cannot happen in practice for messages just
// decoded by pgproto3). Task 9.10: also called for NON-SQL messages while a
// wait is active (the relay stall) — the queue preserves extended-protocol
// ordering.
func (p *PGProxy) gatePGHold(msg pgproto3.FrontendMessage, s *pgSession) bool {
	if p.gateWaitSeconds <= 0 {
		return false
	}
	s.gateMu.Lock()
	if !s.gate.active {
		// First held message: start the wait (grace timer + watch ticker).
		s.gate.startWait(&p.sessionPublisher, s.id, p.gateWaitSeconds,
			func() { p.gatePGFlush(s) }, func() { p.gatePGTimeout(s) })
	}
	if len(s.gate.queue) >= gateQueueMax {
		s.gateMu.Unlock()
		return false // overflow: reject THIS message only; the queue keeps waiting
	}
	raw, err := msg.Encode(nil) // byte-exact wire bytes (type + len + payload)
	if err != nil {
		s.gateMu.Unlock()
		return false
	}
	s.mu.Lock()
	ev := s.pending // audit snapshot — sniffPGMessage ran before the gate check
	s.mu.Unlock()
	_, isQuery := msg.(*pgproto3.Query)
	_, isSync := msg.(*pgproto3.Sync)
	s.gate.queue = append(s.gate.queue, pgGateEntry{raw: raw, query: isQuery, sync: isSync, ev: ev})
	s.gateMu.Unlock()
	// A watcher that appeared since the gate check unblocks the queue
	// immediately — checked on every new message arrival, not only on the
	// ticker. Bounded (review 2026-08-17): a hung store must not stall the
	// relay — the wait simply continues until the grace timer drains.
	ctx, cancel := storeCallCtx()
	watched, werr := p.vs.WatchActive(ctx, s.id)
	cancel()
	if werr == nil && watched {
		p.gatePGFlush(s)
	}
	return true
}

// gatePGFlush forwards every held message to the backend IN ORDER — the
// stored raw wire bytes written exactly as the normal relay write does
// (front.conn.Write; pgproto3's Send is an unbuffered Encode+Write, so this
// is byte-identical) — and clears the wait. Task 9.10: the state is
// snapshotted under gateMu (never held across I/O) and the writes take the
// session's writeMu, so a message arriving mid-flush cannot overtake the
// held queue or interleave with a relay forward.
func (p *PGProxy) gatePGFlush(s *pgSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	entries := s.gate.queue
	s.gate.queue = nil
	s.gate.deactivateLocked()
	s.gateMu.Unlock()
	s.writeMu.Lock()
	for _, e := range entries {
		if _, err := s.front.conn.Write(e.raw); err != nil {
			break
		}
	}
	s.writeMu.Unlock()
}

// gatePGTimeout is the PG mirror of gateTimeout: drain + reject the held
// queue with audit events. Not latched — a later watcher re-opens the gate.
func (p *PGProxy) gatePGTimeout(s *pgSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	entries := s.gate.queue
	s.gate.queue = nil
	s.gate.deactivateLocked()
	s.gateMu.Unlock()
	p.gatePGRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
}

// closePGGateWait is the PG mirror of closeGateWait (session teardown): the
// held messages are drained with the same rejection as a timeout and the
// wait goroutine is JOINED (Task 9.10).
func (p *PGProxy) closePGGateWait(s *pgSession) {
	s.gateMu.Lock()
	if s.gate.active {
		entries := s.gate.queue
		s.gate.queue = nil
		s.gate.deactivateLocked()
		s.gateMu.Unlock()
		p.gatePGRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
	} else {
		s.gateMu.Unlock()
	}
	s.gate.wg.Wait()
}

// gatePGRejectEntries replies to the client for every held message (FATAL
// 28000; SimpleQuery messages also get the trailing ReadyForQuery a
// simple-query response always ends with, mirroring gatePGReject — and a
// held Sync draws the ReadyForQuery that completes an extended-protocol
// exchange, Task 9.10) and publishes each one's audit event as
// status=error. The pending slot is cleared so the teardown path cannot
// publish a duplicate event. Replies run under the session's writeMu.
func (p *PGProxy) gatePGRejectEntries(s *pgSession, entries []pgGateEntry, msg string) {
	p.clearPendingCapture(s)
	s.writeMu.Lock()
	for _, e := range entries {
		_ = s.be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000", Message: msg})
		if e.query || e.sync {
			_ = s.be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		}
	}
	s.writeMu.Unlock()
	evs := make([]*models.QueryEvent, len(entries))
	for i, e := range entries {
		evs[i] = e.ev
	}
	p.publishGateAudits(s, evs, msg)
}

// --- MSSQL (Task 9.4) ------------------------------------------------------
//
// The TDS-plane mirror of the Task 8.13/8.17 grace hold, driven from
// pipeMSSQLClientToBackend (see mssql_relay.go). A held entry is one raw
// client MESSAGE — its frames (each frame's original header + payload,
// byte-exact) plus the audit event snapshot taken at queue time. A watcher
// arriving within gate_wait_seconds flushes the queue IN ORDER, each
// message forwarded exactly as the normal forward path writes it; the
// window expiring DRAINS the queue — every held message is rejected to the
// client with an sqlcmd-readable ERROR token (18456, class 14, the
// "maker gating: no checker connected within <N>s" text) and an audit event
// (status=error). gate_wait_seconds=0 rejects immediately (the caller's
// reject path). A drain does NOT latch (Task 8.17): the gate re-evaluates
// per message — a re-attached watcher re-opens it.
//
// Task 9.10: while a wait is ACTIVE every message is held (the relay stall)
// — an ATTENTION cannot overtake the held queue. A held ATTENTION entry is
// flagged; the drain answers it with the DONE_ATTN acknowledgement (never
// an ERROR token), and the flush forwards it byte-exact (the backend acks
// it — the client's cancel intent is preserved).

// mssqlGateFrame is one raw TDS packet of a held message: the 8-byte header
// VERBATIM plus its payload, forwarded byte-exact on flush.
type mssqlGateFrame struct {
	hdr     [8]byte
	payload []byte
}

// mssqlGateEntry is one held message: its raw frames plus the audit event
// snapshot taken at queue time. attn marks a held client ATTENTION (Task
// 9.10): its drain reply is the DONE_ATTN ack, not an ERROR token.
type mssqlGateEntry struct {
	frames []mssqlGateFrame
	attn   bool
	ev     *models.QueryEvent
}

// mssqlGateState is the per-session Task 8.13 grace-hold state for the TDS
// plane, guarded by the session's gateMu. Mirrors mysqlGateState; gateCore
// (Task 9.12) carries the shared state + wait goroutine.
type mssqlGateState struct {
	gateCore
	queue []mssqlGateEntry
}

// gateMSSQLHold queues a gated (blocked) TDS message for the grace window
// instead of rejecting it. Returns true when the message was QUEUED — the
// caller must NOT reply and must NOT forward: the client's response comes
// later, either the real backend result (watcher flush) or the drain ERROR
// (a held ATTENTION gets the DONE_ATTN ack). Returns false when the caller
// must reject immediately: gate_wait_seconds = 0 (pre-8.13 behavior) or the
// queue is full (overflow rejects only the new message — the queue keeps
// waiting). isAttn flags a client ATTENTION for the drain reply shape
// (Task 9.10).
func (p *MSSQLProxy) gateMSSQLHold(s *mssqlSession, frames []mssqlGateFrame, isAttn bool) bool {
	if p.gateWaitSeconds <= 0 {
		return false
	}
	s.gateMu.Lock()
	if !s.gate.active {
		// First held message: start the wait (grace timer + watch ticker).
		s.gate.startWait(&p.sessionPublisher, s.id, p.gateWaitSeconds,
			func() { p.gateMSSQLFlush(s) }, func() { p.gateMSSQLTimeout(s) })
	}
	if len(s.gate.queue) >= gateQueueMax {
		s.gateMu.Unlock()
		return false // overflow: reject THIS message only; the queue keeps waiting
	}
	s.mu.Lock()
	ev := s.pending // audit snapshot — sniffMSSQLCommand ran before the gate check
	s.mu.Unlock()
	s.gate.queue = append(s.gate.queue, mssqlGateEntry{frames: frames, attn: isAttn, ev: ev})
	s.gateMu.Unlock()
	// A watcher that appeared since the gate check unblocks the queue
	// immediately — checked on every new message arrival, not only on the
	// ticker. Bounded (review 2026-08-17): a hung store must not stall the
	// relay — the wait simply continues until the grace timer drains.
	ctx, cancel := storeCallCtx()
	watched, werr := p.vs.WatchActive(ctx, s.id)
	cancel()
	if werr == nil && watched {
		p.gateMSSQLFlush(s)
	}
	return true
}

// gateMSSQLFlush forwards every held message to the backend IN ORDER — each
// frame written byte-exact (original header + payload), exactly as the
// normal forward path writes it — and clears the wait: subsequent messages
// flow normally. Task 9.10: the state is snapshotted under gateMu (never
// held across I/O) and the writes take the session's writeMu, so a message
// arriving mid-flush cannot overtake the held queue or interleave with a
// relay forward or ATTENTION.
func (p *MSSQLProxy) gateMSSQLFlush(s *mssqlSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	entries := s.gate.queue
	s.gate.queue = nil
	s.gate.deactivateLocked()
	s.gateMu.Unlock()
	s.writeMu.Lock()
	for _, e := range entries {
		for _, f := range e.frames {
			if _, err := s.backend.Write(append(f.hdr[:], f.payload...)); err != nil {
				s.writeMu.Unlock()
				return
			}
		}
	}
	s.writeMu.Unlock()
}

// gateMSSQLTimeout drains the queue when the grace window expires: every
// held message is rejected to the client (ERROR token 18456 + the timeout
// message; a held ATTENTION gets its DONE_ATTN ack) with an audit event.
// The session is NOT latched (Task 8.17): a watcher that attaches later
// re-opens the gate — the maker's next message flows.
func (p *MSSQLProxy) gateMSSQLTimeout(s *mssqlSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	entries := s.gate.queue
	s.gate.queue = nil
	s.gate.deactivateLocked()
	s.gateMu.Unlock()
	p.gateMSSQLRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
}

// closeMSSQLGateWait ends a grace wait on session teardown: the held
// messages are drained with the same rejection as a timeout (the replies
// are best-effort — the client is going away anyway) and the wait goroutine
// is JOINED (Task 9.10).
func (p *MSSQLProxy) closeMSSQLGateWait(s *mssqlSession) {
	s.gateMu.Lock()
	if s.gate.active {
		entries := s.gate.queue
		s.gate.queue = nil
		s.gate.deactivateLocked()
		s.gateMu.Unlock()
		p.gateMSSQLRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
	} else {
		s.gateMu.Unlock()
	}
	s.gate.wg.Wait()
}

// buildTDSAttnAck builds the DONE_ATTN acknowledgement for a held client
// ATTENTION (Task 9.10): a single DONE token (0xFD) with the DONE_ATTN
// status bit (0x0020), curcmd 0, rowcount 0 — the 13-byte shape the real
// server sends for an attention ack (live capture `fd 20 00 …`).
func buildTDSAttnAck() []byte {
	out := make([]byte, 13)
	out[0] = 0xFD
	out[1] = tdsDoneAttn
	out[2] = 0x00
	return out
}

// gateMSSQLRejectEntries replies to the client for every held message (a
// TABULAR ERROR token + DONE_ERROR tail; a held ATTENTION gets the
// DONE_ATTN ack instead — Task 9.10) and publishes each one's audit event
// as status=error with the given message. The pending slot is cleared so
// the teardown path cannot publish a duplicate "connection closed" event.
// Replies run under the session's writeMu (Task 9.10).
func (p *MSSQLProxy) gateMSSQLRejectEntries(s *mssqlSession, entries []mssqlGateEntry, msg string) {
	p.clearPendingCapture(s)
	s.writeMu.Lock()
	for _, e := range entries {
		if e.attn {
			_ = writeTDSMessage(s.client, tdsTabular, buildTDSAttnAck())
		} else {
			_ = writeTDSMessage(s.client, tdsTabular, buildTDSErrorToken(msg, 18456, 1, 14))
		}
	}
	s.writeMu.Unlock()
	evs := make([]*models.QueryEvent, len(entries))
	for i, e := range entries {
		evs[i] = e.ev
	}
	p.publishGateAudits(s, evs, msg)
}
