package proxy

import (
	"context"
	"fmt"
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
// gating: no checker connected within <N>s") — and LATCHES the session
// fail-closed: every later gated command is rejected immediately with the
// same error even when a watcher attaches afterwards; the maker must
// reconnect.
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

// gateTimeoutMessage is the Task 8.13 drain/latch block text, shown to the
// client and recorded in each audit event: the grace window expired with no
// checker attached.
func gateTimeoutMessage(sid string, seconds int) string {
	return fmt.Sprintf("maker gating: no checker connected within %ds (session %s)", seconds, sid)
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
type mysqlGateState struct {
	active  bool             // a grace wait is in progress (queue non-empty)
	latched bool             // fail-closed latch: a wait timed out — every further gated command rejects
	queue   []mysqlGateEntry // held commands, bounded (gateQueueMax)
	stop    chan struct{}    // closed by whoever ends the wait (flush / drain / session close)
	done    chan struct{}    // closed when the wait goroutine exits
}

// gateHold queues a gated (blocked) command for the grace window instead of
// rejecting it. Returns true when the command was QUEUED — the caller must
// NOT reply and must NOT forward: the client's response comes later, either
// the real backend result (watcher flush) or the drain ERR. Returns false
// when the caller must reject the command immediately: the grace window is
// disabled (gate_wait_seconds=0), the session is fail-closed latched, or
// the queue is full (overflow rejects only the new command — the queue
// keeps waiting).
func (p *MySQLProxy) gateHold(s *mysqlSession, seq byte, payload []byte) bool {
	if p.gateWaitSeconds <= 0 {
		return false
	}
	s.gateMu.Lock()
	if s.gate.latched {
		s.gateMu.Unlock()
		return false
	}
	if !s.gate.active {
		// First held command: start the wait (grace timer + watch ticker).
		s.gate.active = true
		s.gate.stop = make(chan struct{})
		s.gate.done = make(chan struct{})
		go p.gateWaitLoop(s)
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
	// ticker.
	if watched, err := p.vs.WatchActive(context.Background(), s.id); err == nil && watched {
		p.gateFlush(s)
	}
	return true
}

// gateWaitLoop is the per-wait goroutine: it re-checks for a watcher on a
// short ticker (flushing the queue in order when one appears) and drains +
// latches the session when the grace window expires. It exits as soon as
// the wait is ended by any path (flush, drain, session close).
func (p *MySQLProxy) gateWaitLoop(s *mysqlSession) {
	defer close(s.gate.done)
	timer := time.NewTimer(time.Duration(p.gateWaitSeconds) * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(gateWatchRecheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-timer.C:
			p.gateTimeout(s)
			return
		case <-ticker.C:
			watched, err := p.vs.WatchActive(context.Background(), s.id)
			if err != nil {
				p.log.Error("gate watch recheck failed — continuing the grace wait", "session_id", s.id, "err", err)
				continue
			}
			if watched {
				p.gateFlush(s)
				return
			}
		case <-s.gate.stop:
			return
		}
	}
}

// gateFlush forwards every held command to the backend IN ORDER — each
// exactly as the normal forward path writes it (the stored client seq +
// byte-exact payload, re-framed by writeMySQLPacket) — and clears the wait:
// subsequent commands flow normally. The held commands' sniffed events ride
// the normal pending/capture pipeline (the last one publishes with its
// backend response; earlier ones collapse like any pipelined commands).
// The forwarding happens while still holding gateMu so a command arriving
// mid-flush cannot overtake the held queue.
func (p *MySQLProxy) gateFlush(s *mysqlSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	s.gate.active = false
	entries := s.gate.queue
	s.gate.queue = nil
	close(s.gate.stop)
	s.gate.stop = nil
	for _, e := range entries {
		if err := writeMySQLPacket(s.backend, e.seq, e.payload); err != nil {
			break
		}
	}
	s.gateMu.Unlock()
}

// gateTimeout drains the queue when the grace window expires: every held
// command is rejected to the client (ERR 1045 + the timeout message) with
// an audit event, and the session is LATCHED fail-closed — watchers that
// attach later do NOT unblock it; the maker must reconnect.
func (p *MySQLProxy) gateTimeout(s *mysqlSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	s.gate.active = false
	s.gate.latched = true
	entries := s.gate.queue
	s.gate.queue = nil
	close(s.gate.stop)
	s.gate.stop = nil
	s.gateMu.Unlock()
	p.gateRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
}

// closeGateWait ends a grace wait on session teardown: the held commands
// are drained with the same rejection as a timeout (the replies are
// best-effort — the client is going away anyway) and the wait goroutine and
// its timers are cleaned up.
func (p *MySQLProxy) closeGateWait(s *mysqlSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	s.gate.active = false
	entries := s.gate.queue
	s.gate.queue = nil
	close(s.gate.stop)
	s.gate.stop = nil
	s.gateMu.Unlock()
	p.gateRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
}

// gateRejectEntries replies to the client for every held command (ERR 1045,
// best-effort) and publishes each one's audit event as status=error with
// the given message. The session's pending slot is cleared so the teardown
// path cannot publish a duplicate "connection closed" event.
func (p *MySQLProxy) gateRejectEntries(s *mysqlSession, entries []mysqlGateEntry, msg string) {
	s.mu.Lock()
	s.pending = nil
	s.capture = nil
	s.mu.Unlock()
	var lastEv *models.QueryEvent
	for _, e := range entries {
		_ = writeMySQLPacket(s.client, e.seq+1, errPacket(1045, "42000", msg))
		if e.ev == nil || e.ev == lastEv {
			continue // no event, or a later packet of the same multi-packet command
		}
		lastEv = e.ev
		e.ev.Status = "error"
		e.ev.Error = msg
		p.publishEvent(s, e.ev)
	}
}

// --- PostgreSQL -----------------------------------------------------------

// pgGateEntry is one held PG message: the RAW wire bytes (type byte + int32
// length + payload — from a byte-exact Encode at queue time; the decoded
// pgproto3 message cannot be stored because Backend.Receive reuses
// flyweight structs across calls), whether it was a SimpleQuery (its drain
// reply carries the trailing ReadyForQuery), and the audit event snapshot.
type pgGateEntry struct {
	raw   []byte
	query bool
	ev    *models.QueryEvent
}

// pgGateState is the per-session Task 8.13 grace-hold state for PG,
// guarded by the session's gateMu. Mirrors mysqlGateState.
type pgGateState struct {
	active  bool
	latched bool
	queue   []pgGateEntry
	stop    chan struct{}
	done    chan struct{}
}

// gatePGHold queues a gated (blocked) PG message for the grace window
// instead of rejecting it. Returns true when the message was QUEUED — the
// caller must NOT reply and must NOT forward. Returns false when the caller
// must reject immediately (gate_wait_seconds=0, fail-closed latch, queue
// overflow, or an Encode failure — the latter cannot happen in practice for
// messages just decoded by pgproto3).
func (p *PGProxy) gatePGHold(msg pgproto3.FrontendMessage, s *pgSession) bool {
	if p.gateWaitSeconds <= 0 {
		return false
	}
	s.gateMu.Lock()
	if s.gate.latched {
		s.gateMu.Unlock()
		return false
	}
	if !s.gate.active {
		s.gate.active = true
		s.gate.stop = make(chan struct{})
		s.gate.done = make(chan struct{})
		go p.gatePGWaitLoop(s)
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
	s.gate.queue = append(s.gate.queue, pgGateEntry{raw: raw, query: isQuery, ev: ev})
	s.gateMu.Unlock()
	// A watcher that appeared since the gate check unblocks the queue
	// immediately — checked on every new message arrival, not only on the
	// ticker.
	if watched, err := p.vs.WatchActive(context.Background(), s.id); err == nil && watched {
		p.gatePGFlush(s)
	}
	return true
}

// gatePGWaitLoop is the PG mirror of gateWaitLoop.
func (p *PGProxy) gatePGWaitLoop(s *pgSession) {
	defer close(s.gate.done)
	timer := time.NewTimer(time.Duration(p.gateWaitSeconds) * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(gateWatchRecheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-timer.C:
			p.gatePGTimeout(s)
			return
		case <-ticker.C:
			watched, err := p.vs.WatchActive(context.Background(), s.id)
			if err != nil {
				p.log.Error("gate watch recheck failed — continuing the grace wait", "session_id", s.id, "err", err)
				continue
			}
			if watched {
				p.gatePGFlush(s)
				return
			}
		case <-s.gate.stop:
			return
		}
	}
}

// gatePGFlush forwards every held message to the backend IN ORDER — the
// stored raw wire bytes written exactly as the normal relay write does
// (front.conn.Write; pgproto3's Send is an unbuffered Encode+Write, so this
// is byte-identical) — and clears the wait. Holds gateMu across the writes
// so a message arriving mid-flush cannot overtake the held queue.
func (p *PGProxy) gatePGFlush(s *pgSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	s.gate.active = false
	entries := s.gate.queue
	s.gate.queue = nil
	close(s.gate.stop)
	s.gate.stop = nil
	for _, e := range entries {
		if _, err := s.front.conn.Write(e.raw); err != nil {
			break
		}
	}
	s.gateMu.Unlock()
}

// gatePGTimeout is the PG mirror of gateTimeout: drain + fail-closed latch.
func (p *PGProxy) gatePGTimeout(s *pgSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	s.gate.active = false
	s.gate.latched = true
	entries := s.gate.queue
	s.gate.queue = nil
	close(s.gate.stop)
	s.gate.stop = nil
	s.gateMu.Unlock()
	p.gatePGRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
}

// closePGGateWait is the PG mirror of closeGateWait (session teardown).
func (p *PGProxy) closePGGateWait(s *pgSession) {
	s.gateMu.Lock()
	if !s.gate.active {
		s.gateMu.Unlock()
		return
	}
	s.gate.active = false
	entries := s.gate.queue
	s.gate.queue = nil
	close(s.gate.stop)
	s.gate.stop = nil
	s.gateMu.Unlock()
	p.gatePGRejectEntries(s, entries, gateTimeoutMessage(s.id, p.gateWaitSeconds))
}

// gatePGRejectEntries replies to the client for every held message (FATAL
// 28000; SimpleQuery messages also get the trailing ReadyForQuery a
// simple-query response always ends with, mirroring gatePGReject) and
// publishes each one's audit event as status=error. The pending slot is
// cleared so the teardown path cannot publish a duplicate event.
func (p *PGProxy) gatePGRejectEntries(s *pgSession, entries []pgGateEntry, msg string) {
	s.mu.Lock()
	s.pending = nil
	s.capture = nil
	s.mu.Unlock()
	var lastEv *models.QueryEvent
	for _, e := range entries {
		_ = s.be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000", Message: msg})
		if e.query {
			_ = s.be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		}
		if e.ev == nil || e.ev == lastEv {
			continue
		}
		lastEv = e.ev
		e.ev.Status = "error"
		e.ev.Error = msg
		p.publishEvent(s, e.ev)
	}
}
