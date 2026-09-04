package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgproto3/v2"
	"zerotrust-proxy/internal/metrics"
	"zerotrust-proxy/internal/models"
)

// pgSession tracks one established PostgreSQL session: the pending (sniffed
// but not yet answered) QueryEvent plus the capture of the backend's
// response. It also serves as the Task 6.4 kill-registry entry: closer
// force-closes both conns to tear the session down. Mirrors mysqlSession.
// The Task 8.2 session-directory fields (db, threadID, startedAt, lastSeen)
// feed the sess:live:<sid> record.
type pgSession struct {
	id      string
	mu      sync.Mutex
	pending *models.QueryEvent
	capture *pgResultCapture
	closer  func()

	db        string               // client-requested database (raw startup value, may be "")
	threadID  int64                // backend pg_backend_pid(); 0 = capture failed
	startedAt time.Time            // session establishment (UTC)
	lastSeen  time.Time            // last activity — heartbeat stamp (UTC)
	tok       *models.TokenPayload // credential context for kill-query's second backend conn (Task 8.3)
	access    string               // token access level: "write" → maker write-gate applies (Task 8.6)
	// token (Task 9.13) is the raw token string for SESSION-mode sessions
	// (liveness/revocation handle). Empty for single-use sessions.
	token string
	// cancelKey (review 2026-08-17) is the per-session random secret the
	// proxy hands the client in BackendKeyData and validates on a
	// CancelRequest — the PG cancel model (pid + secret). Random per
	// session: the old fabricated {42, 4242} for every session is gone.
	cancelKey uint32

	// Task 8.13 grace hold: the client-side Backend (drain replies) and
	// the backend pgFrontend (flush forwards held messages), plus the
	// mutex-guarded gate state. writeMu (Task 9.10, MSSQL-style)
	// serializes ALL socket writes — relay forwards, gate flush, drain
	// replies — so extended-protocol messages cannot overtake the held
	// queue and packets never tear mid-write.
	be      *pgproto3.Backend
	front   *pgFrontend
	writeMu sync.Mutex
	gateMu  sync.Mutex
	gate    pgGateState
}

// PGProxy runs PostgreSQL sessions on the Data Plane. Task 4.1 implements the
// client-facing auth flow: SSLRequest → 'N' (spec D10 — no SSL advertised),
// token-as-username, single-use GETDEL validation, then the welcome sequence
// (AuthenticationOk + ParameterStatus + BackendKeyData + ReadyForQuery).
// Task 4.2 added the backend session (connectPostgresBackend + pgx Hijack);
// Task 4.3 completes the session with a bidirectional message-level relay
// and passive SQL sniffing, forwarding the CLIENT-requested database from
// its StartupMessage to the backend; Task 6.3 adds response capture
// (pending → publish-on-completion, flush-on-close) and the kill registry.
// Task 7.5 adds client-side TLS: with tlsCfg set, an SSLRequest is answered
// with 'S' (0x53) and the session continues over TLS; nil keeps the
// plaintext 'N' (0x4E) refusal — byte-identical to the pre-TLS wire path.
//
// NOTE (D11 redesign): like MySQLProxy, the Dispatcher owns the accept loop
// and connection limiting — one handleConn per accepted connection.
type PGProxy struct {
	// sessionPublisher (Task 9.12) carries the shared session/publish
	// machinery: log, vs (Store), logQueryOutput (Task 8.8) and metrics
	// (Task 9.8) — the fields were once duplicated across the three
	// protocol proxies. Its methods (publishEvent, publishPending, …) are
	// promoted onto PGProxy; the per-protocol bits (the session's
	// pending/capture slots) flow in via the sessionCommon surface.
	sessionPublisher

	creds  CredResolver // backend password source: config list or credential API (Task 8.7)
	tlsCfg *tls.Config  // non-nil → SSLRequest answered 'S' + TLS handshake (Task 7.5); nil = plaintext 'N'

	// gateWaitSeconds (Task 8.13) is the maker write-gate GRACE WINDOW:
	// blocked SQL messages on an unwatched write session wait up to this
	// many seconds for a checker instead of failing instantly. 0 (the
	// proxy default — tests construct proxies directly) = reject
	// immediately, the pre-8.13 behavior; the deployed plane is wired from
	// config gate_wait_seconds (ZT_GATE_WAIT_SECONDS, default 20) via
	// SetGateWaitSeconds.
	gateWaitSeconds int

	mu       sync.Mutex
	sessions map[string]*pgSession // active sessions — kill registry (Task 6.4)

	// Cancel registry (review 2026-08-17): sessions are keyed by their
	// backend pid once captured, so a client CancelRequest (pid + secret)
	// can be serviced instead of silently dropped.
	cancelMu sync.Mutex
	cancels  map[uint32]*pgSession
}

// NewPGProxy builds a PostgreSQL session handler. tlsCfg nil keeps the
// plaintext wire path (byte-identical to before TLS existed); non-nil makes
// the proxy answer an SSLRequest with 'S' and upgrade the connection to TLS
// before the real StartupMessage (client-side TLS, data plane listener).
// creds resolves the backend DB password per connect (Task 8.7: config list
// or credential API — the password is never stored or logged).
func NewPGProxy(log *slog.Logger, vs Store, creds CredResolver, tlsCfg *tls.Config) *PGProxy {
	return &PGProxy{
		sessionPublisher: sessionPublisher{log: log, vs: vs},
		creds:            creds,
		tlsCfg:           tlsCfg,
		sessions:         make(map[string]*pgSession),
		cancels:          make(map[uint32]*pgSession),
	}
}

// SetLogQueryOutput toggles whether query log lines carry the captured
// result payload (Task 8.8): true adds columns/row_count/rows/truncated to
// each "query" log line; false (default) keeps the lines context-only.
// The context fields (username, ticket_id, db_user, db, db_type, stmt_type,
// status, session_id, sql) are logged ALWAYS, regardless of the flag.
func (p *PGProxy) SetLogQueryOutput(on bool) { p.logQueryOutput = on }

// SetGateWaitSeconds configures the maker write-gate grace window (Task
// 8.13, seconds): while a write session has NO watcher, blocked SQL
// messages wait up to this long for a checker to attach instead of failing
// instantly. 0 = reject immediately (the pre-8.13 behavior). Negative
// values are clamped to the default (20). Wired from config
// gate_wait_seconds (ZT_GATE_WAIT_SECONDS).
func (p *PGProxy) SetGateWaitSeconds(seconds int) {
	if seconds < 0 {
		seconds = defaultGateWaitSeconds
	}
	p.gateWaitSeconds = seconds
}

// SetMetrics wires the OTel instruments (Task 9.8). nil (the default —
// config metrics.enabled=false) keeps every instrument call a no-op.
func (p *PGProxy) SetMetrics(m *metrics.Metrics) { p.metrics = m }

// registerSession adds a session to the registry so it can be killed by id
// (Task 6.4 wires the ctl:kill channel to KillSession; the registry itself
// lives here).
func (p *PGProxy) registerSession(s *pgSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions[s.id] = s
}

// unregisterSession removes a finished session from the registry.
func (p *PGProxy) unregisterSession(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, id)
}

// KillSession force-closes a registered session's client+backend conns.
// Returns false when no session with that id is registered.
func (p *PGProxy) KillSession(id string) bool {
	p.mu.Lock()
	s := p.sessions[id]
	p.mu.Unlock()
	if s == nil {
		return false
	}
	if s.closer != nil {
		s.closer()
	}
	return true
}

// KillQuery aborts the session's in-flight query only, leaving the session
// (its client and FIRST backend conns) untouched (Task 8.3 two-level kill,
// PG mirror of MySQLProxy.KillQuery). A SECOND backend connection with the
// SAME credentials runs "SELECT pg_cancel_backend(<pid>)" (PostgreSQL
// permits same-role cancel); the 't'/'f' result row is read and the second
// conn closed. The first conn — the maker's live session — is never
// touched: the backend aborts the query and the client sees an
// ErrorResponse (57014 "canceling statement due to user request"), then the
// session keeps working.
//
// Returns false (with the specific reason logged) when the session is
// unknown, its pid was never captured (threadID == 0 — Task 8.2 degrade
// rule), the credential context is missing, the second backend exchange
// fails, or pg_cancel_backend answered 'f' (backend already gone). The
// ctl:kill subscriber logs "kill: unknown session" for the false case; the
// proxy log carries the detail.
func (p *PGProxy) KillQuery(id string) bool {
	p.mu.Lock()
	s := p.sessions[id]
	p.mu.Unlock()
	if s == nil {
		return false
	}
	if s.threadID == 0 {
		p.log.Warn("kill query: no thread id", "session_id", id)
		return false
	}
	if s.tok == nil {
		p.log.Warn("kill query: no token context", "session_id", id)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), killQueryTimeout)
	defer cancel()
	ok, err := p.cancelBackendExchange(ctx, s) // shared with the CancelRequest path (review 2026-08-17)
	if err != nil {
		p.log.Warn("kill query: cancel exchange failed", "session_id", id, "err", err)
		return false
	}
	if !ok {
		p.log.Warn("kill query: pg_cancel_backend returned false", "session_id", id, "pid", s.threadID)
		return false
	}
	return true
}

// registerCancel enters the session in the cancel registry under its
// backend pid (review 2026-08-17). Sessions whose pid was never captured
// (threadID 0 — Task 8.2 degrade rule) are not cancellable via
// CancelRequest, mirroring KillQuery's degrade behavior.
func (p *PGProxy) registerCancel(s *pgSession) {
	if s.threadID == 0 {
		return
	}
	p.cancelMu.Lock()
	defer p.cancelMu.Unlock()
	p.cancels[uint32(s.threadID)] = s
}

// unregisterCancel removes the session from the cancel registry on
// teardown. The identity guard prevents a reused pid from clobbering a
// newer session's entry.
func (p *PGProxy) unregisterCancel(s *pgSession) {
	if s.threadID == 0 {
		return
	}
	p.cancelMu.Lock()
	defer p.cancelMu.Unlock()
	if p.cancels[uint32(s.threadID)] == s {
		delete(p.cancels, uint32(s.threadID))
	}
}

// cancelLookup resolves a CancelRequest's (pid, secret) to a live session,
// or nil when the pid is unknown or the secret does not match — a
// mismatched cancel is a silent no-op, exactly like the real backend.
func (p *PGProxy) cancelLookup(pid, key uint32) *pgSession {
	p.cancelMu.Lock()
	defer p.cancelMu.Unlock()
	s := p.cancels[pid]
	if s == nil || s.cancelKey != key {
		return nil
	}
	return s
}

// handleCancelRequest services one client CancelRequest (PQcancel / psql
// Ctrl-C — review 2026-08-17: previously dropped while a fabricated
// BackendKeyData was advertised). On a (pid, secret) match the session's
// in-flight query is aborted via pg_cancel_backend on a SECOND backend
// connection with the session's own credentials (same-role cancel,
// mirroring KillQuery). Per PG semantics the cancel connection is closed
// WITHOUT any response — the client learns the outcome from its original
// connection (ErrorResponse 57014).
func (p *PGProxy) handleCancelRequest(client net.Conn, startup pgproto3.FrontendMessage) {
	cr, ok := startup.(*pgproto3.CancelRequest)
	if !ok {
		return // unknown startup packet — nothing to service
	}
	s := p.cancelLookup(cr.ProcessID, cr.SecretKey)
	if s == nil {
		p.log.Debug("cancel request ignored", "pid", cr.ProcessID) // unknown/mismatched — silent no-op
		return
	}
	p.log.Info("cancel request", "session_id", s.id, "pid", cr.ProcessID)
	ctx, cancel := context.WithTimeout(context.Background(), killQueryTimeout)
	defer cancel()
	ok, err := p.cancelBackendExchange(ctx, s)
	if err != nil {
		p.log.Warn("cancel: exchange failed", "session_id", s.id, "err", err)
		return
	}
	if !ok {
		p.log.Warn("cancel: pg_cancel_backend returned false", "session_id", s.id, "pid", s.threadID)
	}
}

// handleConn runs one PostgreSQL session. The Dispatcher owns the accept loop;
// br carries any bytes peeked during protocol detection and ALL client reads
// go through it, writes through client. Token values are never logged.
func (p *PGProxy) handleConn(ctx context.Context, client net.Conn, br *bufio.Reader) {
	// Closure (not defer client.Close()): after the TLS upgrade client is
	// the tls.Conn, and closing IT closes the wrapped conn too — the
	// session closer below must tear down whichever layer is current.
	defer func() { _ = client.Close() }()
	clientAddr := client.RemoteAddr().String()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second)) // handshake deadline

	// client is the backend writer so be.Send() reaches the socket directly.
	// br is wrapped in pgproto3's ChunkReader so any bytes peeked during
	// protocol detection stay in the stream (br serves them first).
	be := pgproto3.NewBackend(pgproto3.NewChunkReader(br), client)
	startupMsg, err := be.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, isSSL := startupMsg.(*pgproto3.SSLRequest); isSSL {
		if p.tlsCfg == nil {
			// TLS not configured: refuse with 'N' (0x4E) — byte-identical
			// to the pre-TLS wire path. The client then resends the real
			// StartupMessage in plaintext.
			if _, err := client.Write([]byte{'N'}); err != nil { // refuse SSL
				return
			}
			startupMsg, err = be.ReceiveStartupMessage()
			if err != nil {
				return
			}
		} else {
			// TLS configured: accept with 'S' (0x53) and run the real
			// handshake — the 10s deadline set above still covers it, and
			// ctx cancellation aborts it too (HandshakeContext). A
			// conforming client waits for 'S' before sending its
			// ClientHello, but one that coalesces the two into a single
			// segment leaves those bytes in br: bufferedConn (the MySQL
			// 7.4 pattern) keeps them visible to the TLS layer, so the
			// handshake never hangs waiting for a retransmission.
			if _, err := client.Write([]byte{'S'}); err != nil { // accept SSL
				return
			}
			tlsConn := tls.Server(&bufferedConn{Conn: client, r: br}, p.tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				p.log.Warn("tls handshake failed", "client", clientAddr, "err", err)
				return
			}
			// Rebuild the pgproto3 backend over the TLS conn: the REAL
			// StartupMessage arrives encrypted. Everything downstream
			// (token GETDEL, FATAL sends, backend connect, relay,
			// sniffing, capture, kill-registry closer) is unchanged and
			// now flows over TLS — tls.Conn.Close closes the wrapped
			// conn, so the session closer tears down the wire either way.
			client = tlsConn
			br = bufio.NewReader(tlsConn)
			be = pgproto3.NewBackend(pgproto3.NewChunkReader(br), tlsConn)
			startupMsg, err = be.ReceiveStartupMessage()
			if err != nil {
				return
			}
		}
	}
	sm, ok := startupMsg.(*pgproto3.StartupMessage)
	if !ok {
		// CancelRequest (or an unknown startup packet): service PG
		// cancels (review 2026-08-17 — previously dropped silently while
		// a fabricated cancel key was advertised). The connection is
		// closed without a response either way, per PG semantics.
		p.handleCancelRequest(client, startupMsg)
		return
	}
	token := sm.Parameters["user"] // token-as-username

	// single-use token validation (GETDEL — atomic read+delete).
	// Bounded (review 2026-08-17): a hung store must not pin the session
	// goroutine at auth — the client gets the store-error rejection after
	// storeCallTimeout instead of hanging forever.
	sctx, scancel := storeCallCtx()
	tok, err := p.vs.GetDeleteToken(sctx, token)
	scancel()
	if err != nil {
		// Review 2026-08-16: a store failure must be REPORTED to the
		// client (FATAL 28000, mirroring the other rejection paths) and
		// funneled into connections.rejected{reason=store_error} —
		// previously the connection died silently.
		p.metrics.ConnectionsRejected("postgres", "store_error")
		p.log.Error("token lookup", "err", err, "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "token validation failed"})
		return
	}
	if tok == nil {
		// Task 9.8: GETDEL nil is ambiguous — absent, expired, or already
		// consumed (single-use) — so the reason collapses to "invalid"
		// (the store cannot distinguish; mirrors the log line below).
		p.metrics.TokensRejected("invalid")
		p.metrics.ConnectionsTotal("postgres", "rejected")
		p.log.Warn("invalid or expired token", "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "invalid or expired token"})
		return
	}
	if tok.DBType != "postgres" {
		p.metrics.TokensRejected("wrong_db_type")
		p.metrics.ConnectionsTotal("postgres", "rejected")
		p.log.Warn("token for wrong protocol", "db_type", tok.DBType, "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "token not valid for this protocol"})
		return
	}
	// Task 9.13 session tokens: IP lock (see checkSessionTokenIP).
	if reason := checkSessionTokenIP(tok, clientAddr); reason != "" {
		p.metrics.TokensRejected("ip_mismatch")
		p.metrics.ConnectionsTotal("postgres", "rejected")
		p.log.Warn("session token IP mismatch", "client", clientAddr, "token_ip", tok.IP)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: reason})
		return
	}
	p.metrics.TokensValidated()
	// The client has spoken — the handshake deadline has done its job. Clear
	// it now so the backend connect (which can take up to its own bounded
	// timeout) can still report the failure to the client afterwards; the
	// relay phase is deadline-free by design.
	_ = client.SetDeadline(time.Time{})

	// 4. backend session with the CLIENT-requested database (PG clients send
	// it in the STARTUP message — mirror of the MySQL CONNECT_WITH_DB flow);
	// an empty/missing value falls back to the default backend database.
	front, err := connectPostgresBackend(ctx, tok, p.creds, sm.Parameters["database"])
	if err != nil {
		p.metrics.ConnectionsTotal("postgres", "rejected")
		p.log.Error("backend connect failed", "err", err, "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "backend unavailable"})
		return
	}
	defer front.Close()

	// Task 8.11: the session id comes from the TOKEN when present — the
	// control plane stamps it at issue time so checkers can watch the
	// session BEFORE the maker connects (the gating-deadlock fix). Tokens
	// without one (pre-8.11 tokens / tests) fall back to generating it
	// here, preserving the old behavior.
	sid := tok.SessionID
	if sid == "" {
		sid = models.NewSessionID()
	}
	// Session established: create the per-session state (pending event +
	// response capture + kill-registry entry) before the relay starts. The
	// closer is the Task 6.4 kill hook — closing both conns forces both
	// relay pipes to exit and the defers below to run.
	//
	// Review round 3 (register-before-capture, capture-before-welcome): the
	// session is entered in the kill/checker registry BEFORE the pid probe,
	// and the probe runs BEFORE the welcome sequence — a kill or watcher
	// can find the session the moment it exists, and the client is only
	// told the session is up once the backend's pid is captured (backend
	// idle, no client traffic to interleave). The probe is deadline-bounded
	// (threadIDCaptureTimeout) and degrades to threadID 0 on any failure.
	s := &pgSession{
		id:        sid,
		be:        be,
		front:     front,
		db:        sm.Parameters["database"],
		startedAt: time.Now().UTC(),
		lastSeen:  time.Now().UTC(),
		tok:       tok,
		access:    tok.Access,
		closer:    func() { client.Close(); front.Close() },
	}
	if tok.Mode == "session" {
		s.token = token
	}
	p.registerSession(s)
	s.threadID = capturePGThreadID(front, p.log)
	// Review 2026-08-17: per-session random cancel secret + registry entry
	// under the backend pid — the BackendKeyData below now carries a real,
	// cancellable identity instead of the fabricated {42, 4242}.
	s.cancelKey = newCancelKey()
	p.registerCancel(s)

	// welcome the client — auth is complete. Sent only after register +
	// capture. Each Send is CHECKED (review 2026-08-16): a dead client
	// aborts the session at the first failed write instead of stranding it
	// in a half-welcomed state.
	if err := be.Send(&pgproto3.AuthenticationOk{}); err != nil {
		return
	}
	if err := be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"}); err != nil {
		return
	}
	if err := be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"}); err != nil {
		return
	}
	if err := be.Send(&pgproto3.ParameterStatus{Name: "DateStyle", Value: "ISO, MDY"}); err != nil {
		return
	}
	if err := be.Send(&pgproto3.ParameterStatus{Name: "TimeZone", Value: "UTC"}); err != nil {
		return
	}
	if err := be.Send(&pgproto3.BackendKeyData{ProcessID: uint32(s.threadID), SecretKey: s.cancelKey}); err != nil {
		return
	}
	if err := be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'}); err != nil {
		return
	}
	p.metrics.ConnectionsTotal("postgres", "ok")
	p.metrics.ConnectionsActiveInc("postgres")
	defer p.metrics.ConnectionsActiveDec("postgres")
	defer p.unregisterSession(s.id)
	defer p.unregisterCancel(s) // review 2026-08-17: cancel registry hygiene
	// Deferred in this order so teardown is: closePGGateWait (Task 8.13 —
	// any grace-held messages drain with the timeout rejection and the
	// wait goroutine is cleaned up) → flushPendingOnClose (any unanswered
	// query publishes first, re-arming the heartbeat) → finish session
	// (DelSessionLive + ended event) → unregister.
	defer p.finishSession(s, tok, clientAddr)
	defer p.flushPendingOnClose(s)
	defer p.closePGGateWait(s)
	p.refreshSessionLive(s, tok) // first sess:live:<sid> entry (heartbeat TTL)
	p.publishLifecycle(s, tok, "started", clientAddr)
	p.log.Info("session established", "username", tok.Username, "db_user", tok.DBUser,
		"db_type", tok.DBType, "client", clientAddr, "db", s.db, "thread_id", s.threadID)

	// 5. bidirectional relay with passive SQL sniffing and response
	// capture. Whichever direction ends first (client quit, backend close,
	// network error) tears down both sides; the second done-slot is
	// buffered so the survivor never blocks.
	done := make(chan struct{}, 2)
	go func() {
		p.pipePGClientToBackend(be, front, s, tok, clientAddr)
		done <- struct{}{}
	}()
	go func() {
		p.pipePGBackendToClient(front, be, s)
		done <- struct{}{}
	}()
	// Wait for BOTH relay pipes before teardown (Task 8.2 round-3 race fix,
	// PG mirror of the MySQL fix): the first done only means one direction
	// ended — the survivor may still be inside publishEvent, whose
	// SetSessionLive re-arms the session-directory heartbeat. Closing both
	// conns unblocks the survivor (it is normally blocked on a read of the
	// opposite conn); the second receive then guarantees its final publish —
	// and thus its SetSessionLive — completed BEFORE the teardown defers run
	// DelSessionLive. A literal `<-done; <-done` before the closes would
	// deadlock every dropped-client teardown: the survivor never exits on its
	// own while the opposite conn stays open.
	<-done
	client.Close()
	front.Close()
	<-done
	p.metrics.SessionDuration("postgres", time.Since(s.startedAt))
	p.log.Info("session closed", "username", tok.Username, "client", clientAddr)
}
