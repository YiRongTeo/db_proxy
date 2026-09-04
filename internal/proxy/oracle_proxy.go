package proxy

// Task 9.14 — OracleProxy (Phase 1): client-leg login TERMINATION on a
// dedicated listener (listen.oracle_addr).
//
// The proxy answers the client's CONNECT/O5LOGON/server-data/AUTH with the
// REAL server's captured responses (mirrored verbatim — the token is the
// credential; the client's password is never verified), opens its OWN
// authenticated backend session with the resolved db_user/password, then
// relays post-auth TNS traffic byte-for-byte. This is the same
// terminate-then-relay model as the MSSQL proxy.

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"zerotrust-proxy/internal/metrics"
	"zerotrust-proxy/internal/models"
)

// OracleProxy is the TNS protocol proxy.
type OracleProxy struct {
	sessionPublisher

	creds CredResolver // backend password source (config list or credential API, Task 8.7)

	mu       sync.Mutex
	sessions map[string]*oracleSession
}

// NewOracleProxy wires the proxy to the shared store/resolver (the
// sessionPublisher is built inside, matching the other three proxies).
func NewOracleProxy(log *slog.Logger, vs Store, creds CredResolver) *OracleProxy {
	return &OracleProxy{
		sessionPublisher: sessionPublisher{log: log, vs: vs},
		creds:            creds,
		sessions:         map[string]*oracleSession{},
	}
}

// SetLogQueryOutput is the Task 8.8 parity setter (Phase 1: no query
// capture yet — accepted for wiring symmetry).
func (p *OracleProxy) SetLogQueryOutput(bool) {}

// SetMetrics wires the OTel instruments (Task 9.8); nil keeps no-ops.
func (p *OracleProxy) SetMetrics(m *metrics.Metrics) { p.metrics = m }

// oracleSession is the TNS session record (sessionCommon surface).
type oracleSession struct {
	id        string
	token     string // raw token, session-mode only ("" otherwise)
	tok       *models.TokenPayload
	client    net.Conn
	backend   net.Conn
	db        string // service name
	startedAt time.Time
	lastSeen  time.Time

	mu sync.Mutex
}

func (s *oracleSession) lockSession()   { s.mu.Lock() }
func (s *oracleSession) unlockSession() { s.mu.Unlock() }
func (s *oracleSession) sessionMeta() (id, db string, threadID int64, startedAt, lastSeen time.Time) {
	return s.id, s.db, 0, s.startedAt, s.lastSeen
}
func (s *oracleSession) setSessionLastSeen(t time.Time)   { s.lastSeen = t }
func (s *oracleSession) pendingEvent() *models.QueryEvent { return nil }
func (s *oracleSession) clearPending()                    {}
func (s *oracleSession) currentCapture() captureResult    { return nil }
func (s *oracleSession) clearCapture()                    {}

// extractOCIValue pulls a value from an OCI dict payload by key.
func extractOCIValue(payload []byte, key string, hasFlag bool) string {
	i := bytes.Index(payload, []byte(key))
	if i < 0 {
		return ""
	}
	v := i + len(key)
	if hasFlag {
		v++
	}
	if v+4 > len(payload) {
		return ""
	}
	vlen := int(binary.BigEndian.Uint32(payload[v : v+4]))
	if v+4+vlen > len(payload) {
		return ""
	}
	return string(payload[v+4 : v+4+vlen])
}

// HandleConn is the exported accept-loop entry (the dedicated oracle
// listener in cmd/data calls it per accepted conn).
func (p *OracleProxy) HandleConn(client net.Conn) {
	p.handleConn(client)
}

// handleConn runs the full TNS login + relay for one client connection.
func (p *OracleProxy) handleConn(client net.Conn) {
	defer client.Close()
	clientAddr := oracleConnAddr(client)

	// Handshake deadline (mirrors mysql_proxy.go:235): a client that
	// connects and stalls mid-login must not hold the accept goroutine,
	// a backend conn, and a session slot forever. It covers the client
	// handshake READS only (steps 1-4 below); it is cleared before the
	// backend login so backend latency never trips it (mysql_proxy.go:306),
	// re-armed for the JDBC verifier read (6b), and cleared again before
	// the relay — long queries must never see a deadline.
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. CONNECT (client-first; the descriptor carries the service name).
	//    Pre-handshake header format (2-byte length).
	typ, payload, err := readTNSHandshakeFrame(newBufReader(client))
	if err != nil {
		p.log.Debug("oracle connect read", "client", clientAddr, "err", err)
		return
	}
	if typ != 1 {
		p.log.Warn("oracle: expected CONNECT", "type", typ, "client", clientAddr)
		return
	}
	serviceName := parseServiceName(payload)
	if serviceName == "" {
		p.log.Warn("oracle: no service name in connect descriptor", "client", clientAddr)
		return
	}
	fam := detectOracleFamily(payload)
	if err := writeTNSHandshakeFrame(client, 2, acceptFor(fam)[8:]); err != nil {
		return
	}

	// 2. O5LOGON negotiation + 3. server-data request (mirrored replies).
	if err := p.negotiate(client, fam); err != nil {
		p.log.Warn("oracle negotiate", "client", clientAddr, "err", err)
		return
	}

	// 3b. JDBC-family clients (go-ora/ojdbc) run a data-type negotiation
	//     exchange right after the server-data (pinned from the 2026-09-01
	//     capture): one request packet + the 2756B mirrored response.
	if fam == oracleClientJDBC {
		if _, _, err := readTNSFrame(newBufReader(client)); err != nil {
			p.log.Warn("oracle data-type request", "client", clientAddr, "err", err)
			return
		}
		if err := writeTNSFrame(client, 6, authResp2756[8:]); err != nil {
			return
		}
	}

	// 4. AUTH: the token is the username; validate before any backend work.
	typ, payload, err = readTNSFrame(newBufReader(client))
	if err != nil {
		p.log.Warn("oracle auth read", "client", clientAddr, "err", err)
		return
	}
	if typ != 6 {
		p.log.Warn("oracle: expected AUTH DATA", "type", typ, "client", clientAddr)
		return
	}
	token := findToken(payload)
	if token == "" {
		p.log.Warn("oracle: no token in auth packet", "client", clientAddr)
		return
	}
	ctx, cancel := storeCallCtx()
	tok, err := p.vs.GetDeleteToken(ctx, token)
	cancel()
	if err != nil || tok == nil {
		p.log.Warn("oracle: invalid or expired token", "client", clientAddr)
		return
	}
	if tok.DBType != "oracle" {
		p.log.Warn("oracle: token for wrong protocol", "db_type", tok.DBType, "client", clientAddr)
		return
	}
	if msg := checkSessionTokenIP(tok, clientAddr); msg != "" {
		p.log.Warn("oracle: "+msg, "client", clientAddr)
		return
	}
	ctx, cancel = storeCallCtx()
	password, err := p.creds.Password(ctx, backendKey(tok))
	cancel()
	if err != nil {
		p.log.Warn("oracle: backend credential lookup failed", "db_user", tok.DBUser, "err", err)
		return
	}

	// The client has spoken — the handshake deadline has done its job for
	// the client READS. Clear it so the backend login (bounded by its own
	// dial/login timeout) can take as long as it needs without tripping a
	// client deadline (mysql_proxy.go:306-310); the 6b verifier read below
	// re-arms it briefly.
	_ = client.SetDeadline(time.Time{})

	// 5. Backend login (real creds, client's service name).
	var backend net.Conn
	if fam == oracleClientJDBC {
		backend, err = oracleBackendLoginGoORA(context.Background(), tok.DBIP, tok.DBPort, tok.DBUser, password, serviceName, 10*time.Second)
	} else {
		backend, err = oracleBackendLogin(context.Background(), tok.DBIP, tok.DBPort, tok.DBUser, password, serviceName, 10*time.Second)
	}
	if err != nil {
		p.log.Warn("oracle: backend login failed", "db_user", tok.DBUser, "err", err)
		return
	}

	// 6. Acknowledge the client's auth with the family-matched mirrored
	//    response (stored per its own framing convention — see
	//    TestOracleMirrorFraming). JDBC-family clients (SQL Developer,
	//    ojdbc, go-ora) do NOT verify AUTH_SVR_RESPONSE (pinned from
	//    go-ora + the capture); OCI clients do, and the mirror carries the
	//    CAPTURED session's identity rather than this backend's — so the
	//    OCI path is best-effort (the 23c mutual-auth wall, RUN.md).
	resp := append([]byte(nil), authRespFor(fam)[8:]...)
	if err := writeTNSFrame(client, 6, resp); err != nil {
		_ = backend.Close()
		return
	}
	// 6b. JDBC family: the client's authObject (the verifier dict — its
	//     username field carries the token) follows the doAuth response as
	//     a SEPARATE packet. The backend session is already authenticated,
	//     so swallow it and reply with the mirrored response (JDBC clients
	//     do NOT verify it). OCI clients send no such packet — their first
	//     post-auth packet is real traffic and is forwarded as-is.
	if fam == oracleClientJDBC {
		// Re-arm a short deadline for this one client read: a client that
		// sent its authObject and then stalled must not hold the goroutine
		// (the backend is already logged in at this point).
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))
		if typ, vp, err := readTNSFrame(newBufReader(client)); err == nil {
			hasTok := bytes.Contains(vp, []byte("sess_"))
			p.log.Debug("oracle verifier packet", "client", clientAddr, "size", len(vp), "has_token", hasTok)
			if hasTok {
				// authResp2172 is stored WITHOUT its 8-byte TNS header
				// (2164B blob = 2172B capture minus header — the one
				// exception among the mirrors; all others keep the
				// header and are sent with [8:]). writeTNSFrame adds
				// the header, so the blob goes out verbatim.
				if err := writeTNSFrame(client, 6, authResp2172); err != nil {
					_ = backend.Close()
					return
				}
			} else if err := writeTNSFrame(backend, typ, vp); err != nil {
				_ = backend.Close()
				return
			}
		}
	}
	s := &oracleSession{
		id:        tok.SessionID,
		tok:       tok,
		client:    client,
		backend:   backend,
		db:        serviceName,
		startedAt: time.Now().UTC(),
		lastSeen:  time.Now().UTC(),
	}
	if tok.Mode == "session" {
		s.token = token
	}
	sid := s.id
	p.mu.Lock()
	p.sessions[sid] = s
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.sessions, sid)
		p.mu.Unlock()
		p.finishSession(s, tok, clientAddr)
	}()
	p.refreshSessionLive(s, tok)
	p.publishLifecycle(s, tok, "started", clientAddr)
	p.log.Info("oracle session established", "username", tok.Username, "db_user", tok.DBUser, "service", serviceName, "client", clientAddr)

	// Relay: client <-> backend, byte-for-byte. Either side EOF closes both.
	// Handshake is done — clear the deadline so long-running queries are
	// never cut off mid-flight (mysql_proxy.go:310).
	_ = client.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(backend, client)
		_ = backend.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, backend)
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
}

// oracleClientFamily identifies the client's auth family from the CONNECT
// packet so the proxy can reply with the matching mirrored responses.
type oracleClientFamily int

const (
	oracleClientOCI  oracleClientFamily = iota // SQL*Plus / OCI (03 73 03 auth, 277B CONNECT)
	oracleClientJDBC                           // SQL Developer / go-ora / ojdbc (dict auth, 245B CONNECT)
)

// acceptFor picks the mirrored ACCEPT for the client family.
func acceptFor(fam oracleClientFamily) []byte {
	if fam == oracleClientJDBC {
		return accept41
	}
	return accept61
}

// authRespFor picks the mirrored auth response for the client family.
func authRespFor(fam oracleClientFamily) []byte {
	if fam == oracleClientJDBC {
		return authResp370
	}
	return authResp2200
}

// detectOracleFamily peeks the CONNECT payload's TNS version field
// (payload[0:2], big-endian). The version is the reliable family
// discriminator across JDBC-family clients — the mirrors the client leg
// replays are family-specific (type maps, AUTH dict framing):
//
//	go-ora           0x013d  (JDBC)
//	SQL Developer    0x013f  (ojdbc — same family, different version)
//	sqlplus / OCI    0x0140
//
// 2026-09-03 regression: the check matched only go-ora's exact signature
// (0x013d + options 0x0801), so SQL Developer (ojdbc, 0x013f) fell through
// to the OCI branch, received OCI-family mirrors and failed with
// ORA-17444 "TTC protocol version ... not supported". Any version BELOW
// the sqlplus 0x0140 marker is a JDBC-family client.
func detectOracleFamily(payload []byte) oracleClientFamily {
	if len(payload) >= 2 && payload[0] == 0x01 && payload[1] <= 0x3f {
		return oracleClientJDBC
	}
	return oracleClientOCI
}

// Each client packet gets its response BEFORE the client sends the next
// (sqlplus waits for the O5LOGON response before requesting server data).
func (p *OracleProxy) negotiate(client net.Conn, fam oracleClientFamily) error {
	br := newBufReader(client)
	typ, _, err := readTNSFrame(br)
	if err != nil {
		return err
	}
	if typ != 6 {
		return &oracleNegoError{typ}
	}
	if err := writeTNSFrame(client, 6, o5logonResp127[8:]); err != nil {
		return err
	}
	typ, _, err = readTNSFrame(br)
	if err != nil {
		return err
	}
	if typ != 6 {
		return &oracleNegoError{typ}
	}
	// Reply with the FAMILY-matched mirrored server-data response.
	// 2026-09-03 regression: this routed on go-ora's "OracleClientGo"
	// marker, so SQL Developer (ojdbc — JDBC family, no such marker) fell
	// through to the OCI server-data (797B) and failed with ORA-17444
	// "TTC protocol version ... not supported". The family — decided at
	// CONNECT time by detectOracleFamily — is the discriminator: JDBC
	// clients (go-ora AND ojdbc) get the JDBC server-data (260B), OCI
	// clients get the OCI one.
	if fam == oracleClientJDBC {
		return writeTNSFrame(client, 6, serverData260[8:])
	}
	return writeTNSFrame(client, 6, serverData797[8:])
}

type oracleNegoError struct{ typ byte }

func (e *oracleNegoError) Error() string {
	return "unexpected tns packet type " + string(rune(e.typ))
}

// ---- session-token parity (Task 9.13) ----

func (p *OracleProxy) sessionSnapshot() []sweepableSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sweepableSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		out = append(out, sweepableSession{id: s.id, token: s.token, issuedAt: s.tok.IssuedAt, lastSeen: s.lastSeen, idleSec: s.tok.IdleSeconds})
	}
	return out
}

func (p *OracleProxy) RevokeToken(token string) int {
	p.mu.Lock()
	var victims []string
	for _, s := range p.sessions {
		if s.token == token {
			victims = append(victims, s.id)
		}
	}
	p.mu.Unlock()
	for _, id := range victims {
		p.KillSession(id)
	}
	return len(victims)
}

func (p *OracleProxy) TokenForSession(id string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[id]
	if !ok {
		return "", false
	}
	return s.token, true
}

func (p *OracleProxy) SweepSessionTokens(policy SessionPolicy, now time.Time) []string {
	return sweepSnapshot(p.vs, p.sessionSnapshot(), policy, now)
}

func (p *OracleProxy) KillSession(id string) bool {
	p.mu.Lock()
	s, ok := p.sessions[id]
	p.mu.Unlock()
	if !ok {
		return false
	}
	_ = s.client.Close()
	_ = s.backend.Close()
	return true
}
