package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
	"unicode/utf16"

	"zerotrust-proxy/internal/metrics"
	"zerotrust-proxy/internal/models"
)

// mssqlSession tracks one established TDS session. It serves as the kill
// registry entry (closer force-closes both conns to tear the session down)
// and carries the Task 8.2 session-directory fields. threadID is always 0:
// TDS has no client-visible connection id to capture — kill-query is the
// ATTENTION packet on the LIVE backend conn (Task 9.4).
type mssqlSession struct {
	id string
	mu sync.Mutex
	// Task 9.3 pending event + response capture: set by the client→backend
	// sniff, completed by the backend→client capture (see mssql_relay.go).
	pending     *models.QueryEvent
	capture     *mssqlResultCapture
	closer      func()
	db          string               // client-requested database (login7 field, envchange fallback)
	threadID    int64                // always 0 — see type comment
	startedAt   time.Time            // session establishment (UTC)
	lastSeen    time.Time            // last activity — heartbeat stamp (UTC)
	tok         *models.TokenPayload // credential context
	access      string               // token access level: "write" → maker write-gate applies (Task 9.4)
	spid        uint16               // backend SPID from the login-response ENVCHANGE token (ATTENTION header, Task 9.4)
	attnPending bool                 // a proxy-initiated ATTENTION is outstanding: the backend's DONE_ATTN ack must be swallowed (Task 9.4 round-1 fix)
	attnAt      time.Time            // when the proxy attention was sent — the swallow expectation expires after mssqlAttnTimeout (Task 9.10)
	writeMu     sync.Mutex           // serializes ALL socket writes: relay forward, gate flush, drain replies, ATTENTION (Task 9.4/9.10)
	gateMu      sync.Mutex           // Task 9.4 grace-hold state guard (mirrors mysqlSession.gateMu)
	gate        mssqlGateState       // Task 9.4 maker write-gate grace hold (mirrors mysqlGateState)
	client      net.Conn             // (possibly TLS-wrapped) client conn
	backend     net.Conn             // (possibly TLS-wrapped) backend conn
}

// MSSQLProxy runs TDS (SQL Server) sessions on the Data Plane (Task 9.2):
// client PRELOGIN (client-first), our PRELOGIN response (ENCRYPT_ON when
// client-side TLS is configured, ENCRYPT_NOT_SUP otherwise), optional TLS
// upgrade through the 0x12-wrapped wiring (TDS 8.0), LOGIN7 parse, single-use
// token validation (GETDEL, token-as-username), backend connect with a
// REWRITTEN login7 (real db_user + resolved password under the derived
// obfuscation), byte-exact relay of the backend login response, then session
// wiring (registry, lifecycle events, sess:live) and a raw byte relay until
// Task 9.3 replaces it with the sniffing query relay.
//
// NOTE (D11 redesign): like MySQLProxy/PGProxy, the Dispatcher owns the
// accept loop — one handleConn per accepted connection.
type MSSQLProxy struct {
	// sessionPublisher (Task 9.12) carries the shared session/publish
	// machinery: log, vs (Store), logQueryOutput (Task 8.8) and metrics
	// (Task 9.8) — the fields were once duplicated across the three
	// protocol proxies. Its methods (publishEvent, publishPending, …) are
	// promoted onto MSSQLProxy; the per-protocol bits (the session's
	// pending/capture slots) flow in via the sessionCommon surface.
	sessionPublisher

	creds  CredResolver // backend password source: config list or credential API (Task 8.7)
	tlsCfg *tls.Config  // non-nil → PRELOGIN answers ENCRYPT_ON + 0x12-wrapped TLS upgrade (Task 9.2); nil = plaintext

	// gateWaitSeconds (Task 8.13 parity) is the maker write-gate GRACE
	// WINDOW: blocked TDS messages on an unwatched write session wait up
	// to this many seconds for a checker instead of failing instantly. 0
	// (the proxy default) = reject immediately; the deployed plane is
	// wired from config gate_wait_seconds (ZT_GATE_WAIT_SECONDS, default
	// 20) via SetGateWaitSeconds.
	gateWaitSeconds int

	mu       sync.Mutex
	sessions map[string]*mssqlSession // active sessions — kill registry (Task 6.4 parity)
}

// NewMSSQLProxy builds a TDS session handler. tlsCfg nil keeps the
// plaintext wire path (PRELOGIN answers ENCRYPT_NOT_SUP — sqlcmd needs -N o);
// non-nil makes the proxy answer ENCRYPT_ON and upgrade to TLS before the
// LOGIN7 (client-side TLS, data plane listener). creds resolves the backend
// DB password per connect (Task 8.7: config list or credential API).
func NewMSSQLProxy(log *slog.Logger, vs Store, creds CredResolver, tlsCfg *tls.Config) *MSSQLProxy {
	return &MSSQLProxy{
		sessionPublisher: sessionPublisher{log: log, vs: vs},
		creds:            creds,
		tlsCfg:           tlsCfg,
		sessions:         make(map[string]*mssqlSession),
	}
}

// SetLogQueryOutput is the Task 8.8 parity setter; the TDS query pipeline
// (Task 9.3) consumes the flag. Wired from config log_query_output.
func (p *MSSQLProxy) SetLogQueryOutput(on bool) { p.logQueryOutput = on }

// SetGateWaitSeconds is the Task 8.13 parity setter; the TDS query pipeline
// (Task 9.3) consumes the value. Wired from config gate_wait_seconds.
func (p *MSSQLProxy) SetGateWaitSeconds(seconds int) {
	if seconds < 0 {
		seconds = defaultGateWaitSeconds
	}
	p.gateWaitSeconds = seconds
}

// SetMetrics wires the OTel instruments (Task 9.8). nil (the default —
// config metrics.enabled=false) keeps every instrument call a no-op.
func (p *MSSQLProxy) SetMetrics(m *metrics.Metrics) { p.metrics = m }

// tdsTLSConn is the 0x12-wrapping seam for the TDS 8.0 TLS upgrade. TLS
// handshake records travel inside PRELOGIN (0x12) TDS packets: the client
// wraps each TLS record it sends in a 0x12 header, and expects the server's
// TLS records the same way. This conn strips the 0x12 headers on Read (so
// tls.Conn sees a raw TLS record stream) and re-wraps on Write.
//
// Reads pull whole 0x12 payloads off br (which carries any bytes peeked by
// the dispatcher); a TLS record may span several 0x12 packets or several
// records may share one packet — the byte stream stays contiguous either
// way. Writes fragment at the 4096-byte TDS packet limit, EOM on the last
// fragment, packet id 0 — the id the real sqlcmd v18 and SQL Server 2022
// use for every 0x12-wrapped TLS packet (round-1 live capture).
//
// ASYMMETRY (round-7, fixed by live probe): the 0x12 wrapping applies ONLY
// to the TLS handshake. After the handshake the client sends the LOGIN7 as
// a BARE TLS record — the TLS record travels unwrapped (no 0x12 header) —
// and the server answers the login in PLAINTEXT TDS. bare=true switches
// Write to raw pass-through so the login7 record goes out unwrapped; the
// login response is then read plaintext from the raw conn (see
// connectMSSQLBackend).
//
// CLIENT-LEG symmetry (round-8, fixed by live capture): the same bare
// post-handshake rule holds on the proxy's own client leg — after the
// handshake the login7, the login response and the relay all travel as
// bare TLS records (real SQL Server 2022 client-leg capture, 2026-08-15).
// handleConn sets bare=true once HandshakeContext returns, and the hybrid
// Read (0x12-wrapped OR bare records) tolerates clients that switch
// framing mid-handshake under TLS 1.3.
type tdsTLSConn struct {
	net.Conn
	br      *bufio.Reader
	pending []byte // leftover payload of the current 0x12 packet
	bare    bool   // true → Write passes TLS records through unwrapped
}

func (c *tdsTLSConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		// Hybrid framing (round-8 live capture): during the handshake the
		// client wraps every TLS record in a 0x12 packet, but under TLS 1.3
		// ODBC 18 switches to BARE TLS records after the ServerHello, and
		// post-handshake records are ALWAYS bare (captured from the real
		// SQL Server 2022 client leg, 2026-08-15). Peek the first byte:
		// 0x12 → strip the TDS envelope; anything else → hand the raw
		// record stream through untouched (tls.Conn parses it).
		first, err := c.br.Peek(1)
		if err != nil {
			return 0, err
		}
		if first[0] != tdsPrelogin {
			return c.br.Read(p)
		}
		typ, _, payload, err := readTDSPacket(c.br)
		if err != nil {
			return 0, err
		}
		if typ != tdsPrelogin {
			// A client that answered ENCRYPT_ON with a plaintext LOGIN7
			// violates MS-TDS (the server's ENCRYPT_ON binds the client);
			// the tls.Conn sees garbage and the handshake fails — no
			// silent downgrade.
			return 0, fmt.Errorf("tds tls: expected 0x12 TLS packet, got 0x%02x", typ)
		}
		c.pending = payload
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *tdsTLSConn) Write(p []byte) (int, error) {
	// Post-handshake (bare=true): TLS records travel unwrapped — the
	// login7 record goes out as a raw TLS record with no 0x12 header
	// (round-7 probe: the real server 17832-rejects a 0x12-wrapped
	// login7 and accepts the bare record).
	if c.bare {
		return c.Conn.Write(p)
	}
	written := 0
	for id := byte(0); len(p) > 0; id++ {
		n := len(p)
		if n > tdsPacketSize-tdsHeaderLen {
			n = tdsPacketSize - tdsHeaderLen
		}
		hdr := make([]byte, tdsHeaderLen)
		hdr[0] = tdsPrelogin
		hdr[1] = tdsStatusEOM
		if n < len(p) {
			hdr[1] = 0 // more fragments follow — EOM on the last only
		}
		binary.BigEndian.PutUint16(hdr[2:4], uint16(tdsHeaderLen+n))
		hdr[6] = 0 // packet id 0 — what sqlcmd/SQL Server send on 0x12 TLS packets
		if _, err := c.Conn.Write(append(hdr, p[:n]...)); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// registerSession adds a session to the registry so it can be killed by id.
func (p *MSSQLProxy) registerSession(s *mssqlSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions[s.id] = s
}

// unregisterSession removes a finished session from the registry.
func (p *MSSQLProxy) unregisterSession(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, id)
}

// KillSession force-closes a registered session's client+backend conns.
// Returns false when no session with that id is registered.
func (p *MSSQLProxy) KillSession(id string) bool {
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
// alive (Task 9.4). TDS cancels via the ATTENTION (0x06) packet: a single
// header-only packet (type 0x06, EOM, length 8, no payload) written on the
// LIVE backend conn — connection-scoped cancel, no SPID lookup needed. The
// backend aborts the in-flight batch and answers with an ERROR/DONE_ERROR
// response, which the relay captures and forwards to the client naturally;
// the session itself is untouched and its next command flows normally.
//
// The attention is sent ONLY while a command is genuinely in flight (the
// session's pending event is set — the sniff ran and the response has not
// completed); an idle session is refused with a warn. Writes are serialized
// with the relay's forwards (writeMu) so the attention can never interleave
// mid-message. The header's SPID field carries the backend SPID captured at
// login (ENVCHANGE token) when the server announced one, else 0 — what the
// real ODBC driver sends.
//
// The backend acknowledges the attention with a SEPARATE DONE_ATTN message
// (after the aborted batch's DONE_ERROR). The client never asked to cancel,
// so the relay swallows that ack proxy-side (attnPending → see
// pipeMSSQLBackendToClient) — the client sees only the aborted batch's
// error and its next command flows normally on the same session.
func (p *MSSQLProxy) KillQuery(id string) bool {
	p.mu.Lock()
	s := p.sessions[id]
	p.mu.Unlock()
	if s == nil {
		return false
	}
	s.mu.Lock()
	inflight := s.pending != nil
	s.mu.Unlock()
	if !inflight {
		p.log.Warn("kill query: no command in flight", "session_id", id)
		return false
	}
	// Arm the ack swallow BEFORE the write: the backend answers the
	// attention with a separate DONE_ATTN acknowledgement message after
	// the aborted batch's DONE_ERROR (live capture: `fd 02 00` then
	// `fd 20 00`). The client never asked to cancel — forwarding that ack
	// would corrupt its protocol state (its next batch would read the
	// stale ack as its response). pipeMSSQLBackendToClient consumes it
	// proxy-side and clears this flag.
	s.mu.Lock()
	s.attnPending = true
	s.attnAt = time.Now() // Task 9.10: start the swallow-expiry clock
	s.mu.Unlock()
	s.writeMu.Lock()
	err := writeTDSPacketSPID(s.backend, tdsAttention, tdsStatusEOM, s.spid, nil)
	s.writeMu.Unlock()
	if err != nil {
		s.mu.Lock()
		s.attnPending = false
		s.mu.Unlock()
		p.log.Error("kill query: attention write failed", "session_id", id, "err", err)
		return false
	}
	p.log.Info("query killed", "session_id", id, "db_type", "mssql")
	return true
}

// handleConn runs one TDS session. The Dispatcher owns the accept loop and
// passes a buffered reader so any peeked client bytes are preserved; ALL
// client-side reads go through br, writes through client (which becomes the
// tls.Conn after a TLS upgrade).
func (p *MSSQLProxy) handleConn(ctx context.Context, client net.Conn, br *bufio.Reader) {
	// Closure (not defer client.Close()): after the TLS upgrade client is
	// the tls.Conn, and closing IT closes the wrapped conn too.
	defer func() { _ = client.Close() }()
	clientAddr := client.RemoteAddr().String()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second)) // handshake deadline

	// 1. client PRELOGIN (client-first). The dispatcher already peeked its
	// first byte (0x12) — br preserves it.
	typ, prePayload, err := readTDSMessage(br)
	if err != nil || typ != tdsPrelogin {
		return
	}
	if _, err := parsePrelogin(prePayload); err != nil {
		return
	}

	// 2. our PRELOGIN response: ENCRYPT_ON when client-side TLS is
	// configured (the client then MUST upgrade — the server's ENCRYPT_ON
	// binds it), ENCRYPT_NOT_SUP otherwise (an honest refusal — a
	// mandatory-encryption client like bare sqlcmd aborts cleanly, a -N o
	// client proceeds plaintext). The response travels as a TABULAR
	// RESULT (0x04) packet — the real SQL Server answers prelogin that
	// way (round-1 live capture), and ODBC 18 rejects a 0x12-typed
	// prelogin response with "Protocol error in TDS stream" (round-7
	// live capture: proxy 0x12 response vs real server 0x04).
	serverEnc := byte(encryptNotSup)
	if p.tlsCfg != nil {
		serverEnc = encryptOn
	}
	if err := writeTDSPacket(client, tdsTabular, buildPreloginResponse(serverEnc)); err != nil {
		return
	}

	// 3. TLS upgrade when offered: the client's next packet is a 0x12
	// header wrapping a raw TLS ClientHello record. The tdsTLSConn seam
	// strips/re-adds the 0x12 framing so tls.Server sees a plain TLS
	// record stream; after HandshakeContext the LOGIN7 arrives encrypted
	// (bare TLS record — post-handshake records are never 0x12-wrapped;
	// round-8 live capture of the real SQL Server client leg). The 10s
	// deadline set above still covers the handshake, and ctx cancellation
	// aborts it too.
	if serverEnc == encryptOn {
		// TLS 1.2 ONLY on the client leg (round-8 root cause, live
		// capture): ODBC 18 keeps every handshake record 0x12-wrapped as
		// long as the negotiated version is TLS 1.2 (the real SQL Server
		// 2022 answers with c02f), but under TLS 1.3 it switches to BARE
		// TLS records right after the ServerHello — a mixed stream the
		// strict 0x12 seam cannot follow. Forcing TLS 1.2 reproduces the
		// real server's byte-for-byte framing; the hybrid Read tolerates
		// bare records anyway.
		cfg := p.tlsCfg.Clone()
		cfg.MaxVersion = tls.VersionTLS12
		seam := &tdsTLSConn{Conn: client, br: br}
		tlsConn := tls.Server(seam, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			p.log.Warn("mssql tls handshake failed", "client", clientAddr, "err", err)
			return
		}
		// Post-handshake: bare TLS records both directions (login7 from
		// the client, our login response, the whole relay).
		seam.bare = true
		client = tlsConn
		br = bufio.NewReader(tlsConn)
	}

	// 4. LOGIN7 — token-as-username.
	typ, loginPayload, err := readTDSMessage(br)
	if err != nil || typ != tdsLogin7 {
		return
	}
	li, err := parseLogin7(loginPayload)
	if err != nil {
		return
	}
	token := li.username
	// The client has spoken — the handshake deadline has done its job.
	// Clear it now so the backend connect (bounded by its own timeout) can
	// still report the failure to the client afterwards; the relay phase
	// is deadline-free by design.
	_ = client.SetDeadline(time.Time{})

	// 5. single-use token validation (GETDEL — atomic read+delete).
	tok, err := p.vs.GetDeleteToken(ctx, token)
	if err != nil {
		p.log.Error("token lookup", "err", err, "client", clientAddr)
		p.metrics.ConnectionsTotal("mssql", "rejected")
		_ = writeTDSMessage(client, tdsTabular, buildLoginError(fmt.Sprintf("Login failed for user '%s': token validation failed.", token)))
		return
	}
	if tok == nil {
		// Task 9.8: GETDEL nil is ambiguous — absent, expired, or already
		// consumed (single-use) — so the reason collapses to "invalid"
		// (the store cannot distinguish; mirrors the log line below).
		p.metrics.TokensRejected("invalid")
		p.metrics.ConnectionsTotal("mssql", "rejected")
		p.log.Warn("invalid or expired token", "client", clientAddr)
		_ = writeTDSMessage(client, tdsTabular, buildLoginError(fmt.Sprintf("Login failed for user '%s'.", token)))
		return
	}
	if tok.DBType != "mssql" {
		p.metrics.TokensRejected("wrong_db_type")
		p.metrics.ConnectionsTotal("mssql", "rejected")
		p.log.Warn("token for wrong protocol", "db_type", tok.DBType, "client", clientAddr)
		_ = writeTDSMessage(client, tdsTabular, buildLoginError(fmt.Sprintf("Login failed for user '%s': token not valid for this protocol.", token)))
		return
	}
	p.metrics.TokensValidated()

	// 6. backend session: client-side TDS against the real SQL Server with
	// a REWRITTEN login7 (real db_user, resolver password under the
	// derived obfuscation, client-requested database kept). The backend
	// leg is TLS when the data plane is (the backend accepts both).
	backend, backendBR, loginResp, loginOK, envDB, err := connectMSSQLBackend(ctx, tok, p.creds, li, p.tlsCfg != nil)
	if err != nil {
		p.metrics.ConnectionsTotal("mssql", "rejected")
		p.log.Error("backend connect failed", "err", err, "client", clientAddr)
		_ = writeTDSMessage(client, tdsTabular, buildLoginError(fmt.Sprintf("Login failed for user '%s': backend unavailable.", token)))
		return
	}
	defer backend.Close()
	if len(loginResp) == 0 {
		p.log.Error("backend login: empty response", "client", clientAddr)
		_ = writeTDSMessage(client, tdsTabular, buildLoginError(fmt.Sprintf("Login failed for user '%s': backend unavailable.", token)))
		return
	}

	// 7. byte-exact relay of the backend login response — the full token
	// stream (LOGINACK/ENVCHANGE/DONE on success, ERROR/DONE when the
	// backend itself rejected the credentials). The payload bytes are
	// preserved verbatim; only the TDS envelope is rebuilt. A backend
	// rejection ends the attempt here: no session is established and the
	// backend closes the conn on its own.
	if !loginOK {
		p.metrics.ConnectionsTotal("mssql", "rejected") // Task 9.10: rejection funnel
		p.log.Warn("backend login rejected", "client", clientAddr, "db_user", tok.DBUser)
		_ = writeTDSMessage(client, tdsTabular, loginResp)
		return
	}
	if err := writeTDSMessage(client, tdsTabular, loginResp); err != nil {
		return
	}

	// 8. session wiring (mirror 8.2): Task 8.11 session id from the token
	// when present, else generated here. db from the login7 database
	// field, envchange fallback.
	sid := tok.SessionID
	if sid == "" {
		sid = models.NewSessionID()
	}
	db := li.database
	if db == "" {
		db = envDB
	}
	s := &mssqlSession{
		id:        sid,
		client:    client,
		backend:   backend,
		db:        db,
		startedAt: time.Now().UTC(),
		lastSeen:  time.Now().UTC(),
		tok:       tok,
		access:    tok.Access,
		spid:      scanLoginSPID(loginResp),
		closer:    func() { client.Close(); backend.Close() },
	}
	p.registerSession(s)
	p.metrics.ConnectionsTotal("mssql", "ok")
	p.metrics.ConnectionsActiveInc("mssql")
	defer p.metrics.ConnectionsActiveDec("mssql")
	defer p.unregisterSession(s.id)
	// Deferred in this order so teardown is: closeMSSQLGateWait (Task 9.4 —
	// any grace-held commands drain with the timeout rejection) → flush-
	// PendingOnClose (any unanswered query publishes first, re-arming the
	// heartbeat) → finish session (DelSessionLive + ended event) → unregister.
	defer p.finishSession(s, tok, clientAddr)
	defer p.flushPendingOnClose(s)
	defer p.closeMSSQLGateWait(s)
	p.refreshSessionLive(s, tok) // first sess:live:<sid> entry (heartbeat TTL)
	p.publishLifecycle(s, tok, "started", clientAddr)
	p.log.Info("session established", "username", tok.Username, "db_user", tok.DBUser,
		"db_type", tok.DBType, "client", clientAddr, "db", db)

	// 9. Task 9.3 sniffing query relay: client→backend packets are sniffed
	// for SQL (batch 0x01 / RPC 0x03) and forwarded byte-exact; backend→
	// client packets are forwarded byte-exact while their token stream
	// (COLMETADATA/ROW/DONE/ERROR) is passively captured, and each command
	// publishes its QueryEvent (status/columns/rows) to all three channels.
	// Whichever direction ends first (client quit, backend close, network
	// error, Task 6.4 kill) tears down both sides; the second done-slot is
	// buffered so the survivor never blocks.
	done := make(chan struct{}, 2)
	go func() {
		p.pipeMSSQLClientToBackend(br, backend, client, s, tok, clientAddr)
		done <- struct{}{}
	}()
	go func() {
		p.pipeMSSQLBackendToClient(backendBR, client, s)
		done <- struct{}{}
	}()
	// Wait for BOTH relay pipes before teardown (Task 8.2 round-3 race
	// fix, mirrored from MySQL/PG): the first done only means one direction
	// ended — the survivor may still be inside publishEvent, whose
	// SetSessionLive re-arms the session-directory heartbeat. Closing both
	// conns unblocks the survivor; the second receive then guarantees its
	// final publish completed BEFORE the teardown defers run DelSessionLive.
	<-done
	client.Close()
	backend.Close()
	<-done
	p.metrics.SessionDuration("mssql", time.Since(s.startedAt))
	p.log.Info("session closed", "username", tok.Username, "client", clientAddr)
}

// connectMSSQLBackend speaks the CLIENT side of TDS against the real SQL
// Server: PRELOGIN (ENCRYPT_ON when useTLS — the data plane's TLS config is
// on; ENCRYPT_NOT_SUP otherwise — the backend accepts both), optional
// 0x12-wrapped TLS upgrade, then the REWRITTEN LOGIN7 (username = the
// token's real db_user, password = the resolver password obfuscated with
// the derived transform, the client's database and connection metadata
// mirrored). Returns the (possibly TLS-wrapped) conn, the buffered reader
// the relay must keep reading through (it may hold bytes buffered past the
// login response), the backend's login response payload VERBATIM, whether
// the login succeeded, and any database announced by an ENVCHANGE token.
//
// TLS LEG FRAMING (probe-verified 2026-08-16 against the live mssql-test
// backend; task 9.10): with ENCRYPT_ON offered the server answers
// ENCRYPT_ON, the handshake travels 0x12-wrapped, the login7 goes out as a
// BARE TLS record (no 0x12 header — tdsTLSConn bare mode), and — unlike
// the ENCRYPT_OFF path, where the login response comes back in PLAINTEXT —
// the login response arrives as a BARE TLS RECORD too. The relay therefore
// runs entirely over the TLS conn (bare TLS records both directions). The
// old code returned the RAW conn after the login, so only the login7 was
// encrypted and every subsequent byte went out plaintext — nominal TLS.
func connectMSSQLBackend(ctx context.Context, t *models.TokenPayload, res CredResolver, li login7Info, useTLS bool) (net.Conn, *bufio.Reader, []byte, bool, string, error) {
	pw, err := res.Password(ctx, backendKey(t))
	if err != nil {
		return nil, nil, nil, false, "", err
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", t.DBIP, t.DBPort))
	if err != nil {
		return nil, nil, nil, false, "", fmt.Errorf("backend mssql dial: %w", err)
	}
	// Bounded handshake (Task 3.8 pattern): a backend that accepts but
	// never speaks must not pin the session goroutine and the consumed
	// token. Cleared before returning — the relay stays deadline-free.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	// client PRELOGIN. Task 9.10: when the data plane's TLS is enabled the
	// proxy offers ENCRYPT_ON — per MS-TDS the server MUST answer
	// ENCRYPT_ON and the TLS upgrade is then mandatory (probe: mssql-test
	// echoes 0x01 and everything after the handshake is encrypted). When
	// TLS is disabled the offer is the honest ENCRYPT_NOT_SUP and the
	// exchange stays plaintext end to end.
	enc := byte(encryptNotSup)
	if useTLS {
		enc = encryptOn
	}
	if err := writeTDSPacket(conn, tdsPrelogin, buildPrelogin(enc)); err != nil {
		conn.Close()
		return nil, nil, nil, false, "", err
	}
	typ, prePayload, err := readTDSMessage(br)
	// The real SQL Server sends its PRELOGIN response as a TABULAR RESULT
	// (0x04) packet — captured live from mssql-test (2026-08-15); some
	// stacks use 0x12. Accept both; the payload layout is identical.
	if err != nil || (typ != tdsPrelogin && typ != tdsTabular) {
		conn.Close()
		return nil, nil, nil, false, "", fmt.Errorf("backend mssql prelogin: %v", err)
	}
	serverEnc, err := parsePrelogin(prePayload)
	if err != nil {
		conn.Close()
		return nil, nil, nil, false, "", err
	}
	// TLS upgrade when offered AND accepted: a backend that answers
	// ENCRYPT_NOT_SUP (TLS disabled on its side) keeps the plaintext leg —
	// the login7 then travels as a regular 0x10 TDS packet.
	upgrade := useTLS && serverEnc != encryptNotSup
	if upgrade {
		// The backend's TLS records also travel 0x12-wrapped — the same
		// seam serves the client role. The backend's cert is the
		// container's self-signed dev certificate; production would pin
		// the CA via RootCAs instead of InsecureSkipVerify.
		//
		// ASYMMETRIC WIRING (round-7 root cause, live-probed 2026-08-15,
		// re-probed for ENCRYPT_ON 2026-08-16): the 0x12 wrapping covers
		// the handshake ONLY. After it, the login7 must go out as a BARE
		// TLS record — a raw TLS record whose payload is the full TDS
		// 0x10 packet (8-byte header + login7), with NO 0x12 header on
		// the wire. Under ENCRYPT_OFF the server answers the login in
		// PLAINTEXT TDS (and the relay stays plaintext); under ENCRYPT_ON
		// the login response and everything after travel as bare TLS
		// records — the returned conn is the TLS conn and the relay runs
		// over it (Task 9.10, probe-verified: `17 03 03 …` records both
		// directions, SELECT round-trip OK).
		tds := &tdsTLSConn{Conn: conn, br: br}
		tlsConn := tls.Client(tds, &tls.Config{
			InsecureSkipVerify: true, // dev: mssql-test self-signed cert
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, nil, nil, false, "", fmt.Errorf("backend mssql tls: %w", err)
		}
		// Post-handshake: login7 = bare TLS record (tdsTLSConn Write
		// switches to raw pass-through), login response = bare TLS record
		// read through the TLS conn.
		tds.bare = true
		login7 := buildLogin7(li.hostname, t.DBUser, li.appname, li.server, li.database, obfuscatePassword(pw))
		if err := writeTDSPacket(tlsConn, tdsLogin7, login7); err != nil {
			conn.Close()
			return nil, nil, nil, false, "", err
		}
		tlsBR := bufio.NewReader(tlsConn)
		typ, loginResp, err := readTDSMessage(tlsBR)
		if err != nil || typ != tdsTabular {
			conn.Close()
			return nil, nil, nil, false, "", fmt.Errorf("backend mssql login response: %v", err)
		}
		_, loginOK, envDB := scanLoginResponse(loginResp)
		_ = conn.SetDeadline(time.Time{}) // relay must be deadline-free
		return tlsConn, tlsBR, loginResp, loginOK, envDB, nil
	}

	// PLAINTEXT leg: REWRITTEN LOGIN7 as a regular 0x10 TDS packet.
	login7 := buildLogin7(li.hostname, t.DBUser, li.appname, li.server, li.database, obfuscatePassword(pw))
	if err := writeTDSPacket(conn, tdsLogin7, login7); err != nil {
		conn.Close()
		return nil, nil, nil, false, "", err
	}
	typ, loginResp, err := readTDSMessage(br)
	if err != nil || typ != tdsTabular {
		conn.Close()
		return nil, nil, nil, false, "", fmt.Errorf("backend mssql login response: %v", err)
	}
	_, loginOK, envDB := scanLoginResponse(loginResp)
	_ = conn.SetDeadline(time.Time{}) // relay must be deadline-free
	return conn, br, loginResp, loginOK, envDB, nil
}

// writeTDSMessage writes one logical TDS message (type typ), fragmenting
// the payload across packets at the 4096-byte TDS packet limit with the EOM
// status bit on the last fragment. The login response and the error
// responses all fit one packet in practice, but a message MUST be
// fragmentable per spec. Task 9.10: every fragment write is checked for
// short writes.
func writeTDSMessage(w io.Writer, typ byte, payload []byte) error {
	for id := byte(1); ; id++ {
		n := len(payload)
		if n > tdsPacketSize-tdsHeaderLen {
			n = tdsPacketSize - tdsHeaderLen
		}
		hdr := make([]byte, tdsHeaderLen)
		hdr[0] = typ
		hdr[1] = tdsStatusEOM
		if n < len(payload) {
			hdr[1] = 0
		}
		binary.BigEndian.PutUint16(hdr[2:4], uint16(tdsHeaderLen+n))
		hdr[6] = id
		wn, err := w.Write(append(hdr, payload[:n]...))
		if err != nil {
			return err
		}
		if wn != tdsHeaderLen+n {
			return io.ErrShortWrite
		}
		payload = payload[n:]
		if len(payload) == 0 {
			return nil
		}
	}
}

// buildLoginError builds the TABULAR RESULT token stream for a login
// failure: an ERROR token (0xAA — error 18456 "Login failed", class 14 user
// error, state 1) followed by a DONE token (0xFD). This is the byte-exact
// shape the real SQL Server sends for a rejected login (round-8 live capture
// of a backend rejection), and sqlcmd renders it as the canonical "Msg 18456
// ... Login failed for user 'x'." failure. The token value in the message is
// the client's OWN credential, echoed back only to the client that presented
// it.
func buildLoginError(msg string) []byte {
	return buildTDSErrorToken(msg, 18456, 1, 14)
}

// buildTDSErrorToken builds a TABULAR RESULT token stream carrying one
// sqlcmd-readable error: an ERROR token (0xAA — number/state/class + the
// UTF-16LE MsgText + empty server/proc + line 1) followed by a DONE token
// (0xFD) with the DONE_ERROR status bit (0x0002) — the exact shape the real
// SQL Server ends a failed command with, and what sqlcmd renders as
// "Msg <n>, Level <class>, State <s>: <msg>". Used for login failures
// (buildLoginError, 18456/1/14) and for the Task 9.4 maker write-gate
// rejections (18456/1/14 — the same access-denied family; the gating text
// names the session).
func buildTDSErrorToken(msg string, errNumber uint32, errState, errClass byte) []byte {
	const serverName = "zerotrust-proxy"
	utf16le := func(s string) []byte {
		units := utf16.Encode([]rune(s))
		b := make([]byte, len(units)*2)
		for i, u := range units {
			binary.LittleEndian.PutUint16(b[2*i:], u)
		}
		return b
	}
	msgB := utf16le(msg)
	srvB := utf16le(serverName)
	// ERROR token: type(1) + length(2) + Number(4) + State(1) + Class(1)
	// + MsgText(US_VARCHAR) + ServerName(B_VARCHAR) + ProcName(B_VARCHAR)
	// + Line(4). Captured layout of a real 18456 rejection:
	//   aa 66 00 18 48 00 00 01 0e 20 00 4c 00 6f ... 0c 37 00 ... 00 01 00 00 00
	// MsgText's length is a USHORT (0x0020 = 32) and ServerName's is a
	// single byte (0x0c = 12) — BOTH count UTF-16 CODE UNITS, not bytes.
	// Round-8 root cause: MsgText was written with NO length prefix, so
	// sqlcmd read the message's own first two bytes (0x4c 0x00 = 76) as
	// the length, swallowed the rest of the token as "text", and rendered
	// the failure garbled.
	msgChars := len(msgB) / 2
	restLen := 4 + 1 + 1 + 2 + len(msgB) + 1 + len(srvB) + 1 + 4
	out := []byte{0xAA, byte(restLen), byte(restLen >> 8)}
	var nb [4]byte
	binary.LittleEndian.PutUint32(nb[:], errNumber)
	out = append(out, nb[:]...)
	out = append(out, errState, errClass)
	out = append(out, byte(msgChars), byte(msgChars>>8)) // MsgText US_VARCHAR
	out = append(out, msgB...)
	out = append(out, byte(len(srvB)/2)) // ServerName B_VARCHAR (code units)
	out = append(out, srvB...)
	out = append(out, 0) // ProcName: empty
	var lb [4]byte
	binary.LittleEndian.PutUint32(lb[:], 1) // LineNumber
	out = append(out, lb[:]...)
	// DONE token: type(1) + status(2, LE) + curcmd(2) + rowcount(8). The
	// real server ends a failed command with status 0x0002 (DONE_ERROR
	// only — NO DONE_FINAL bit; captured `fd 02 00` tail) and the message
	// EOM is what ends the response.
	status := uint16(tdsDoneError) // 0x0002
	out = append(out, 0xFD)
	out = append(out, byte(status), byte(status>>8))
	out = append(out, 0x00, 0x00) // curcmd
	out = append(out, make([]byte, 8)...)
	return out
}

// scanLoginSPID walks the backend login response token stream and returns
// the SPID announced by an ENVCHANGE (0xE3) token of type 0x04 (SPID — the
// new value is a USHORT). Returns 0 when the server announced none. The
// ATTENTION packet's SPID header field mirrors it (Task 9.4) — the real
// ODBC driver fills the field from the same login response.
func scanLoginSPID(buf []byte) uint16 {
	for pos := 0; pos < len(buf); {
		t := buf[pos]
		switch t {
		case 0xFD, 0xFE, 0xFF: // DONE family — fixed 13-byte tail
			if pos+13 > len(buf) {
				return 0
			}
			pos += 13
		case 0xAA, 0xAB, 0xAD, 0xAE, 0xE3, 0xE4: // length-prefixed tokens
			if pos+3 > len(buf) {
				return 0
			}
			l := int(binary.LittleEndian.Uint16(buf[pos+1 : pos+3]))
			if pos+3+l > len(buf) {
				return 0
			}
			// ENVCHANGE: NewValueType(1) NewValue OldValueType(1) OldValue.
			// Type 0x04 = SPID, new value = USHORT (2 bytes).
			if t == 0xE3 && l >= 5 && buf[pos+3] == 0x04 {
				return binary.LittleEndian.Uint16(buf[pos+4 : pos+6])
			}
			pos += 3 + l
		default:
			return 0 // unknown token — post-login traffic
		}
	}
	return 0
}
