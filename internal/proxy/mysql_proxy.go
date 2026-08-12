package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// mysqlSession tracks one established MySQL session: the pending (sniffed but
// not yet answered) QueryEvent plus the capture of the backend's response.
// It also serves as the Task 6.4 kill-registry entry: closer force-closes
// both conns to tear the session down. The Task 8.2 session-directory fields
// (db, threadID, startedAt, lastSeen) feed the sess:live:<sid> record.
type mysqlSession struct {
	id      string
	mu      sync.Mutex
	pending *models.QueryEvent
	capture *resultCapture
	closer  func()

	db        string               // client-requested database (empty = no default schema)
	threadID  int64                // backend CONNECTION_ID(); 0 = capture failed
	startedAt time.Time            // session establishment (UTC)
	lastSeen  time.Time            // last activity — heartbeat stamp (UTC)
	tok       *models.TokenPayload // credential context for kill-query's second backend conn (Task 8.3)
	access    string               // token access level: "write" → maker write-gate applies (Task 8.6)
}

// MySQLProxy runs MySQL sessions on the Data Plane. It performs the 6-step
// session lifecycle: server handshake, client response, single-use token
// validation, backend connect, OK, then byte-exact bidirectional relay with
// passive SQL sniffing.
//
// NOTE (D11 redesign): the Dispatcher owns the accept loop and connection
// limiting (Task 3.5), so there is deliberately no connection counter, no
// maxConns, and no Serve loop here — one handleConn per accepted connection.
type MySQLProxy struct {
	log      *slog.Logger
	vs       *store.ValkeyStore
	creds    map[string]string
	tlsCfg   *tls.Config   // non-nil → CLIENT_SSL advertised + SSLRequest upgraded (Task 7.4); nil = plaintext
	serverID atomic.Uint32 // per-session connection id for the handshake

	mu       sync.Mutex
	sessions map[string]*mysqlSession // active sessions — kill registry (Task 6.4)
}

// NewMySQLProxy builds a MySQL session handler. tlsCfg nil keeps the
// plaintext wire path (byte-identical to before TLS existed); non-nil makes
// the server advertise CLIENT_SSL and answer an SSLRequest with a TLS
// handshake before auth (client-side TLS, data plane listener).
func NewMySQLProxy(log *slog.Logger, vs *store.ValkeyStore, creds map[string]string, tlsCfg *tls.Config) *MySQLProxy {
	return &MySQLProxy{
		log:      log,
		vs:       vs,
		creds:    creds,
		tlsCfg:   tlsCfg,
		sessions: make(map[string]*mysqlSession),
	}
}

// bufferedConn is a net.Conn whose reads drain a bufio.Reader before
// touching the underlying conn. The SSLRequest reader may buffer client
// bytes that belong to the TLS handshake (clients commonly coalesce the
// SSLRequest packet and the ClientHello into one TCP segment): handing the
// TLS layer a conn that reads through br preserves those bytes, so the
// handshake never loses them or hangs waiting for a retransmission.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// registerSession adds a session to the registry so it can be killed by id
// (Task 6.4 wires the ctl:kill channel to KillSession; the registry itself
// lives here).
func (p *MySQLProxy) registerSession(s *mysqlSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions[s.id] = s
}

// unregisterSession removes a finished session from the registry.
func (p *MySQLProxy) unregisterSession(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, id)
}

// KillSession force-closes a registered session's client+backend conns.
// Returns false when no session with that id is registered.
func (p *MySQLProxy) KillSession(id string) bool {
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

// KillQuery aborts the session's IN-FLIGHT query only, leaving the session
// (its client and FIRST backend conns) untouched (Task 8.3 two-level kill).
// It opens a SECOND backend connection with the SAME credentials (MySQL
// permits same-user KILL QUERY), sends "KILL QUERY <thread_id>", reads the
// OK/ERR response and closes the second conn. The first conn — the maker's
// live session — is never touched: the backend aborts the query and sends
// the client an error result for it (1317 "Query execution was
// interrupted"), and the session keeps working.
//
// Returns false (with the specific reason logged) when the session is
// unknown, its thread id was never captured (threadID == 0 — Task 8.2
// degrade rule; kill-query has no query context), the credential context is
// missing, or the second backend exchange fails. The ctl:kill subscriber
// logs "kill: unknown session" for the false case; the proxy log carries
// the detail.
func (p *MySQLProxy) KillQuery(id string) bool {
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
	backend, err := connectMySQLBackend(ctx, s.tok, p.creds, s.db)
	if err != nil {
		p.log.Warn("kill query: backend connect failed", "session_id", id, "err", err)
		return false
	}
	defer backend.Close()
	// Bound the exchange: connectMySQLBackend clears the deadline for the
	// relay, and a dead backend must not pin the ctl:kill subscriber.
	_ = backend.SetDeadline(time.Now().Add(killQueryTimeout))
	payload := append([]byte{cmdQuery}, "KILL QUERY "...)
	payload = strconv.AppendInt(payload, s.threadID, 10)
	if err := writeMySQLPacket(backend, 0, payload); err != nil {
		p.log.Warn("kill query: send failed", "session_id", id, "err", err)
		return false
	}
	_, resp, err := readMySQLPacket(backend)
	if err != nil {
		p.log.Warn("kill query: read failed", "session_id", id, "err", err)
		return false
	}
	if len(resp) > 0 && resp[0] == 0xff {
		p.log.Warn("kill query: backend error", "session_id", id, "thread_id", s.threadID, "err", mysqlErrMessage(resp))
		return false
	}
	return true
}

// handleConn runs one MySQL session. The Dispatcher owns the accept loop and
// passes a buffered reader so any peeked client bytes are preserved; ALL
// client-side reads go through br, writes through client.
func (p *MySQLProxy) handleConn(ctx context.Context, client net.Conn, br *bufio.Reader) {
	defer func() { _ = client.Close() }() // closes the (possibly TLS-wrapped) conn
	clientAddr := client.RemoteAddr().String()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second)) // handshake deadline

	// 1. server handshake (seq 0). CLIENT_SSL is advertised ONLY when TLS is
	// configured; otherwise the handshake is byte-identical to pre-TLS.
	caps := advertisedCaps
	if p.tlsCfg != nil {
		caps |= capSSL
	}
	authData, err := randomAuthData()
	if err != nil {
		return
	}
	handshake, err := buildHandshakeV10("8.4.0-zerotrust-proxy", p.serverID.Add(1), authData, caps)
	if err != nil {
		return
	}
	if err := writeMySQLPacket(client, 0, handshake); err != nil {
		return
	}

	// 2. handshake response (seq 1): username = token. When TLS is enabled
	// the client may answer with an SSLRequest instead (CLIENT_SSL set): run
	// the TLS handshake first — the 10s deadline set above still covers it,
	// and ctx cancellation aborts it too — then read the REAL handshake
	// response over TLS. Otherwise (plaintext listener, or a plaintext
	// client on a TLS listener) this packet IS the handshake response.
	//
	// authReplySeq is the seq id for the auth-phase reply (OK or ERR).
	// Plaintext: handshake (srv, seq 0), handshake response (cli, seq 1) →
	// reply is seq 2. With TLS the client first answers the handshake with
	// an SSLRequest (cli, seq 1) — the SSLRequest consumes seq 1 — then
	// sends the real auth response over TLS (cli, seq 2) → the reply MUST be
	// seq 3. The Go test client tolerates any seq; the mysql 8.4 C client's
	// strict SSL_read validation does not (ERROR 2013 'reading authorization
	// packet' on a seq-2 OK under TLS). Set to 3 below when the TLS path is
	// taken.
	authReplySeq := byte(2)
	_, payload, err := readMySQLPacket(br)
	if err != nil {
		return
	}
	if p.tlsCfg != nil && isSSLRequest(payload) {
		// bufferedConn: the SSLRequest read may have buffered the client's
		// ClientHello — the TLS layer must read through br, not the raw conn.
		tlsConn := tls.Server(&bufferedConn{Conn: client, r: br}, p.tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			p.log.Warn("tls handshake failed", "client", clientAddr, "err", err)
			return
		}
		client = tlsConn
		br = bufio.NewReader(tlsConn)
		if _, payload, err = readMySQLPacket(br); err != nil {
			return
		}
		// The SSLRequest consumed seq 1 (handshake=0 srv, SSLRequest=1 cli,
		// auth=2 cli) → the auth-phase reply must be seq 3, not 2.
		authReplySeq = 3
	}
	if len(payload) > 0 && payload[0] == 0xff {
		return // client refused
	}
	token, database, err := parseHandshakeResponse(payload)
	if err != nil {
		return
	}
	// The client has spoken — the handshake deadline has done its job. Clear it
	// now so the backend connect (which can take up to its own bounded timeout)
	// can still report ERR to the client afterwards; the relay phase is
	// deadline-free by design (long-running queries must never trip a deadline).
	_ = client.SetDeadline(time.Time{})

	// 3. single-use token validation (GETDEL — atomic read+delete)
	tok, err := p.vs.GetDeleteToken(ctx, token)
	if err != nil {
		p.log.Error("token lookup", "err", err)
		return
	}
	if tok == nil {
		p.log.Warn("invalid or expired token", "client", clientAddr)
		_ = writeMySQLPacket(client, authReplySeq, errPacket(1045, "42000", "invalid or expired token"))
		return
	}
	if tok.DBType != "mysql" {
		p.log.Warn("token for wrong protocol", "db_type", tok.DBType, "client", clientAddr)
		_ = writeMySQLPacket(client, authReplySeq, errPacket(1045, "42000", "token not valid for this protocol"))
		return
	}

	// 4. backend connection (real credentials, client-requested database)
	backend, err := connectMySQLBackend(ctx, tok, p.creds, database)
	if err != nil {
		p.log.Error("backend connect failed", "err", err, "client", clientAddr)
		_ = writeMySQLPacket(client, authReplySeq, errPacket(1045, "42000", "backend unavailable"))
		return
	}
	defer backend.Close()

	// 5. OK — session established (seq 2 plaintext / 3 under TLS)
	if err := writeMySQLPacket(client, authReplySeq, okPacket()); err != nil {
		return
	}
	// Session established: create the per-session state (pending event +
	// response capture + kill-registry entry) before the relay starts. The
	// closer is the Task 6.4 kill hook — closing both conns forces both
	// relay pipes to exit and the defers below to run. Task 8.2: the
	// backend thread id is captured NOW (backend idle, client not yet
	// told the session is up) and the session is entered in the directory
	// with a started lifecycle event.
	s := &mysqlSession{
		id:        "sid-" + newEventID(),
		db:        database,
		threadID:  captureMySQLThreadID(backend, p.log),
		startedAt: time.Now().UTC(),
		lastSeen:  time.Now().UTC(),
		tok:       tok,
		access:    tok.Access,
		closer:    func() { client.Close(); backend.Close() },
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
		"db_type", tok.DBType, "client", clientAddr, "db", database, "thread_id", s.threadID)

	// 6. bidirectional relay with passive sniffing. Whichever direction ends
	// first (client quit, backend close, network error) tears down both sides;
	// the second done-slot is buffered so the survivor never blocks.
	done := make(chan struct{}, 2)
	go func() {
		p.pipeClientToBackend(br, backend, client, s, tok, clientAddr)
		done <- struct{}{}
	}()
	go func() {
		p.pipeBackendToClient(backend, client, s)
		done <- struct{}{}
	}()
	// Wait for BOTH relay pipes before teardown (Task 8.2 round-3 race fix):
	// the first done only means one direction ended — the survivor may still
	// be inside publishEvent, whose SetSessionLive re-arms the
	// session-directory heartbeat. Closing both conns unblocks the survivor
	// (it is normally blocked on a read of the opposite conn); the second
	// receive then guarantees its final publish — and thus its SetSessionLive
	// — completed BEFORE the teardown defers run DelSessionLive. A literal
	// `<-done; <-done` before the closes would deadlock every dropped-client
	// teardown: the survivor never exits on its own while the opposite conn
	// stays open.
	<-done
	client.Close()
	backend.Close()
	<-done
	p.log.Info("session closed", "username", tok.Username, "client", clientAddr)
}
