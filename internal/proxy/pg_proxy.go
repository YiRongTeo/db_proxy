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
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
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

	db        string    // client-requested database (raw startup value, may be "")
	threadID  int64     // backend pg_backend_pid(); 0 = capture failed
	startedAt time.Time // session establishment (UTC)
	lastSeen  time.Time // last activity — heartbeat stamp (UTC)
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
	log    *slog.Logger
	vs     *store.ValkeyStore
	creds  map[string]string
	tlsCfg *tls.Config // non-nil → SSLRequest answered 'S' + TLS handshake (Task 7.5); nil = plaintext 'N'

	mu       sync.Mutex
	sessions map[string]*pgSession // active sessions — kill registry (Task 6.4)
}

// NewPGProxy builds a PostgreSQL session handler. tlsCfg nil keeps the
// plaintext wire path (byte-identical to before TLS existed); non-nil makes
// the proxy answer an SSLRequest with 'S' and upgrade the connection to TLS
// before the real StartupMessage (client-side TLS, data plane listener).
func NewPGProxy(log *slog.Logger, vs *store.ValkeyStore, creds map[string]string, tlsCfg *tls.Config) *PGProxy {
	return &PGProxy{log: log, vs: vs, creds: creds, tlsCfg: tlsCfg, sessions: make(map[string]*pgSession)}
}

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
		return // CancelRequest or unknown startup packet
	}
	token := sm.Parameters["user"] // token-as-username

	// single-use token validation (GETDEL — atomic read+delete)
	tok, err := p.vs.GetDeleteToken(ctx, token)
	if err != nil {
		p.log.Error("token lookup", "err", err, "client", clientAddr)
		return
	}
	if tok == nil {
		p.log.Warn("invalid or expired token", "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "invalid or expired token"})
		return
	}
	if tok.DBType != "postgres" {
		p.log.Warn("token for wrong protocol", "db_type", tok.DBType, "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "token not valid for this protocol"})
		return
	}

	// welcome the client — auth is complete
	_ = be.Send(&pgproto3.AuthenticationOk{})
	_ = be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"})
	_ = be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	_ = be.Send(&pgproto3.ParameterStatus{Name: "DateStyle", Value: "ISO, MDY"})
	_ = be.Send(&pgproto3.ParameterStatus{Name: "TimeZone", Value: "UTC"})
	_ = be.Send(&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: 4242})
	_ = be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	_ = client.SetDeadline(time.Time{}) // handshake done — relay phase is deadline-free

	// 4. backend session with the CLIENT-requested database (PG clients send
	// it in the STARTUP message — mirror of the MySQL CONNECT_WITH_DB flow);
	// an empty/missing value falls back to the default backend database.
	front, err := connectPostgresBackend(ctx, tok, p.creds, sm.Parameters["database"])
	if err != nil {
		p.log.Error("backend connect failed", "err", err, "client", clientAddr)
		_ = be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000",
			Message: "backend unavailable"})
		return
	}
	defer front.Close()

	// Session established: create the per-session state (pending event +
	// response capture + kill-registry entry) before the relay starts. The
	// closer is the Task 6.4 kill hook — closing both conns forces both
	// relay pipes to exit and the defers below to run. Task 8.2: the
	// backend pid is captured NOW (backend idle) and the session is
	// entered in the directory with a started lifecycle event.
	s := &pgSession{
		id:        "sid-" + newEventID(),
		db:        sm.Parameters["database"],
		threadID:  capturePGThreadID(front, p.log),
		startedAt: time.Now().UTC(),
		lastSeen:  time.Now().UTC(),
		closer:    func() { client.Close(); front.Close() },
	}
	p.registerSession(s)
	defer p.unregisterSession(s.id)
	// Deferred in this order so teardown is: flushPendingOnClose (any
	// unanswered query publishes first, re-arming the heartbeat) → finish
	// session (DelSessionLive + ended event) → unregister.
	defer p.finishSession(s, tok, clientAddr)
	defer p.flushPendingOnClose(s)
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
	p.log.Info("session closed", "username", tok.Username, "client", clientAddr)
}
