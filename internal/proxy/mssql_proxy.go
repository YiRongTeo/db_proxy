package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
	"unicode/utf16"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// mssqlSession tracks one established TDS session. It serves as the kill
// registry entry (closer force-closes both conns to tear the session down)
// and carries the Task 8.2 session-directory fields. threadID is always 0:
// TDS has no client-visible connection id to capture, and kill-query is N/A
// until Task 9.4 wires the ATTENTION packet — KillQuery returns false.
type mssqlSession struct {
	id string
	mu sync.Mutex
	// Task 9.3 pending event + response capture: set by the client→backend
	// sniff, completed by the backend→client capture (see mssql_relay.go).
	pending   *models.QueryEvent
	capture   *mssqlResultCapture
	closer    func()
	db        string               // client-requested database (login7 field, envchange fallback)
	threadID  int64                // always 0 — see type comment
	startedAt time.Time            // session establishment (UTC)
	lastSeen  time.Time            // last activity — heartbeat stamp (UTC)
	tok       *models.TokenPayload // credential context
	access    string               // token access level: "write" → maker write-gate applies (Task 9.4)
	client    net.Conn             // (possibly TLS-wrapped) client conn
	backend   net.Conn             // (possibly TLS-wrapped) backend conn
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
	log    *slog.Logger
	vs     *store.ValkeyStore
	creds  CredResolver // backend password source: config list or credential API (Task 8.7)
	tlsCfg *tls.Config  // non-nil → PRELOGIN answers ENCRYPT_ON + 0x12-wrapped TLS upgrade (Task 9.2); nil = plaintext

	// logQueryOutput (Task 8.8 parity) and gateWaitSeconds (Task 8.13
	// parity) mirror the MySQL/PG fields; the TDS query pipeline that
	// consumes them lands in Task 9.3. Wired from the same config keys.
	logQueryOutput  bool
	gateWaitSeconds int

	mu       sync.Mutex
	sessions map[string]*mssqlSession // active sessions — kill registry (Task 6.4 parity)
}

// NewMSSQLProxy builds a TDS session handler. tlsCfg nil keeps the
// plaintext wire path (PRELOGIN answers ENCRYPT_NOT_SUP — sqlcmd needs -N o);
// non-nil makes the proxy answer ENCRYPT_ON and upgrade to TLS before the
// LOGIN7 (client-side TLS, data plane listener). creds resolves the backend
// DB password per connect (Task 8.7: config list or credential API).
func NewMSSQLProxy(log *slog.Logger, vs *store.ValkeyStore, creds CredResolver, tlsCfg *tls.Config) *MSSQLProxy {
	return &MSSQLProxy{log: log, vs: vs, creds: creds, tlsCfg: tlsCfg, sessions: make(map[string]*mssqlSession)}
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

// KillQuery aborts the session's in-flight query only. TDS has no
// out-of-band query cancel: SQL Server cancels via the ATTENTION (0x06)
// packet, which Task 9.4 wires. Until then every kill-query request is
// refused with a warn — the session itself is never touched.
func (p *MSSQLProxy) KillQuery(id string) bool {
	p.mu.Lock()
	s := p.sessions[id]
	p.mu.Unlock()
	if s == nil {
		return false
	}
	p.log.Warn("kill query: not supported until task 9.4 (attention packet)", "session_id", id)
	return false
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
		return
	}
	if tok == nil {
		p.log.Warn("invalid or expired token", "client", clientAddr)
		_ = writeTDSMessage(client, tdsTabular, buildLoginError(fmt.Sprintf("Login failed for user '%s'.", token)))
		return
	}
	if tok.DBType != "mssql" {
		p.log.Warn("token for wrong protocol", "db_type", tok.DBType, "client", clientAddr)
		_ = writeTDSMessage(client, tdsTabular, buildLoginError(fmt.Sprintf("Login failed for user '%s': token not valid for this protocol.", token)))
		return
	}

	// 6. backend session: client-side TDS against the real SQL Server with
	// a REWRITTEN login7 (real db_user, resolver password under the
	// derived obfuscation, client-requested database kept). The backend
	// leg is TLS when the data plane is (the backend accepts both).
	backend, backendBR, loginResp, loginOK, envDB, err := connectMSSQLBackend(ctx, tok, p.creds, li, p.tlsCfg != nil)
	if err != nil {
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
	p.log.Info("session closed", "username", tok.Username, "client", clientAddr)
}

// connectMSSQLBackend speaks the CLIENT side of TDS against the real SQL
// Server: PRELOGIN (ENCRYPT_ON when useTLS, ENCRYPT_NOT_SUP otherwise — the
// backend accepts both), optional 0x12-wrapped TLS upgrade, then the
// REWRITTEN LOGIN7 (username = the token's real db_user, password = the
// resolver password obfuscated with the derived transform, the client's
// database and connection metadata mirrored). Returns the (possibly
// TLS-wrapped) conn, the buffered reader the relay must keep reading
// through (it may hold bytes buffered past the login response), the
// backend's login response payload VERBATIM, whether the login succeeded,
// and any database announced by an ENVCHANGE token.
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

	// client PRELOGIN. TDS 8.0 mirror (round-1 live capture, sqlcmd v18):
	// the prelogin ENCRYPTION value stays ENCRYPT_OFF even when the client
	// will upgrade — the TLS upgrade itself is the signal (the server
	// answers whatever we ask; the 0x12-wrapped handshake proceeds
	// regardless). useTLS=false keeps the honest ENCRYPT_NOT_SUP offer.
	enc := byte(encryptNotSup)
	if useTLS {
		enc = encryptOff
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
	_ = serverEnc // the negotiated value does not gate the upgrade — see below
	// TLS upgrade when useTLS. The backend's TLS records also travel
	// 0x12-wrapped — the same seam serves the client role. The backend's
	// cert is the container's self-signed dev certificate; production
	// would pin the CA via RootCAs instead of InsecureSkipVerify.
	//
	// ASYMMETRIC WIRING (round-7 root cause, live-probed 2026-08-15):
	// the 0x12 wrapping covers the handshake ONLY. After it, the login7
	// must go out as a BARE TLS record — a raw TLS record whose payload is
	// the full TDS 0x10 packet (8-byte header + login7), with NO 0x12
	// header on the wire — and the server answers the login in PLAINTEXT
	// TDS. The round-6 code kept 0x12-wrapping the login7 (like the
	// client leg) and SQL Server rejected it with 17832 "login packet
	// structurally invalid"; the round-7 probe matrix against the live
	// backend proved the accepted shape byte-for-byte (variants: wrapped
	// → close, bare-record-with-TDS-header → LOGIN-OK plaintext).
	if useTLS {
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
		// switches to raw pass-through), response = plaintext TDS read
		// straight off the raw conn (br below stays the raw reader).
		tds.bare = true
		login7 := buildLogin7(li.hostname, t.DBUser, li.appname, li.server, li.database, obfuscatePassword(pw))
		if err := writeTDSPacket(tlsConn, tdsLogin7, login7); err != nil {
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
// fragmentable per spec.
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
		if _, err := w.Write(append(hdr, payload[:n]...)); err != nil {
			return err
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
	const (
		errNumber  = 18456
		errState   = 1
		errClass   = 14
		serverName = "zerotrust-proxy"
	)
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
	// real server ends a rejected login with status 0x0002 (DONE_ERROR
	// only — NO DONE_FINAL bit; captured `fd 02 00` tail) and then drops
	// the connection — the close is what ends the response.
	status := uint16(tdsDoneError) // 0x0002
	out = append(out, 0xFD)
	out = append(out, byte(status), byte(status>>8))
	out = append(out, 0x00, 0x00) // curcmd
	out = append(out, make([]byte, 8)...)
	return out
}

// refreshSessionLive writes (or refreshes) the session's directory record —
// sess:live:<sid> with the heartbeat TTL — stamping a fresh last_seen.
// Best-effort: failures are logged by the store, never fatal to the session.
func (p *MSSQLProxy) refreshSessionLive(s *mssqlSession, tok *models.TokenPayload) {
	s.mu.Lock()
	s.lastSeen = time.Now().UTC()
	rec := buildSessionRecord(s.id, tok.Username, tok.DBUser, tok.DBType, s.db, s.threadID, s.startedAt, s.lastSeen, "active")
	s.mu.Unlock()
	if rec == nil {
		return
	}
	_ = p.vs.SetSessionLive(context.Background(), s.id, rec, sessionLiveTTL)
}

// publishLifecycle publishes a session lifecycle event (Kind=session,
// Action=started|ended) to queries:<username> AND queries:sess:<sid>.
// Lifecycle events deliberately do NOT go to the ticket channel — ticket
// grouping is about query activity, not connection presence.
func (p *MSSQLProxy) publishLifecycle(s *mssqlSession, tok *models.TokenPayload, action, clientAddr string) {
	ev := models.QueryEvent{
		ID:         newEventID(),
		Ts:         time.Now().UTC(),
		Kind:       "session",
		Action:     action,
		Username:   tok.Username,
		DBUser:     tok.DBUser,
		DBType:     tok.DBType,
		DB:         s.db,
		SessionID:  s.id,
		ClientAddr: clientAddr,
	}
	raw, _ := json.Marshal(ev)
	ctx := context.Background()
	_ = p.vs.Publish(ctx, "queries:"+ev.Username, raw)
	_ = p.vs.Publish(ctx, "queries:sess:"+s.id, raw)
	p.log.Info("session "+action, "username", ev.Username, "ticket_id", tok.TicketID,
		"db_user", ev.DBUser, "db", ev.DB, "db_type", ev.DBType, "session_id", ev.SessionID)
}

// finishSession removes the session from the directory (DelSessionLive) and
// publishes the ended lifecycle event. Deferred in handleConn so the ended
// event is always the session's last word on the wire.
func (p *MSSQLProxy) finishSession(s *mssqlSession, tok *models.TokenPayload, clientAddr string) {
	_ = p.vs.DelSessionLive(context.Background(), s.id)
	p.publishLifecycle(s, tok, "ended", clientAddr)
}
