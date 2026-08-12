package proxy

import (
	"bufio"
	"context"
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
type pgSession struct {
	id      string
	mu      sync.Mutex
	pending *models.QueryEvent
	capture *pgResultCapture
	closer  func()
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
//
// NOTE (D11 redesign): like MySQLProxy, the Dispatcher owns the accept loop
// and connection limiting — one handleConn per accepted connection.
type PGProxy struct {
	log   *slog.Logger
	vs    *store.ValkeyStore
	creds map[string]string

	mu       sync.Mutex
	sessions map[string]*pgSession // active sessions — kill registry (Task 6.4)
}

func NewPGProxy(log *slog.Logger, vs *store.ValkeyStore, creds map[string]string) *PGProxy {
	return &PGProxy{log: log, vs: vs, creds: creds, sessions: make(map[string]*pgSession)}
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
	defer client.Close()
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
		if _, err := client.Write([]byte{'N'}); err != nil { // refuse SSL
			return
		}
		startupMsg, err = be.ReceiveStartupMessage()
		if err != nil {
			return
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
	// relay pipes to exit and the defers below to run.
	s := &pgSession{
		id:     "sid-" + newEventID(),
		closer: func() { client.Close(); front.Close() },
	}
	p.registerSession(s)
	defer p.unregisterSession(s.id)
	defer p.flushPendingOnClose(s)
	p.log.Info("session established", "username", tok.Username, "db_user", tok.DBUser,
		"db_type", tok.DBType, "client", clientAddr)

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
	<-done
	client.Close()
	front.Close()
	p.log.Info("session closed", "username", tok.Username, "client", clientAddr)
}
