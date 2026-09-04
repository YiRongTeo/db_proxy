package proxy

// Task 9.14 — Oracle BACKEND leg (Phase 1): a minimal TNS client that
// completes CONNECT → O5LOGON negotiation → AUTH against the real Oracle
// backend with the resolved db_user/password, then hands the RAW conn to
// the relay. The session's buffered state is fully consumed by the login,
// so byte-relay after it is safe (no prefetch loss).
//
// Auth verification/negotiation logic is ported from go-ora v2.9.0
// (Apache-2.0); see oracle_auth.go.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
)

// oracleBackendSession is the minimal TNS inbound reader for the backend
// leg (framing mirror of go-ora's network.Session). The login consumes
// whole packets into s.in; byte-relay after it is safe (no prefetch loss).
type oracleBackendSession struct {
	conn net.Conn
	br   *bufio.Reader
	in   []byte
}

func newOracleBackendSession(conn net.Conn) *oracleBackendSession {
	return &oracleBackendSession{conn: conn, br: bufio.NewReader(conn)}
}

// ---- inbound framing ----

// readPacket reads one TNS packet into s.in (NULL/keepalive packets are
// transparently skipped). Post-handshake 4-byte length format.
func (s *oracleBackendSession) readPacket() (byte, error) {
	return s.readPacketFmt(false)
}

// readPacketHandshake reads the ACCEPT packet (2-byte length format).
func (s *oracleBackendSession) readPacketHandshake() (byte, error) {
	return s.readPacketFmt(true)
}

func (s *oracleBackendSession) readPacketFmt(handshake bool) (byte, error) {
	for {
		hdr := make([]byte, 8)
		if _, err := readFull(s.br, hdr); err != nil {
			return 0, fmt.Errorf("oracle read tns header: %w", err)
		}
		var n int
		if handshake {
			n = int(binary.BigEndian.Uint16(hdr[0:2]))
		} else {
			n = int(binary.BigEndian.Uint32(hdr[0:4]))
		}
		typ := hdr[4]
		if n < 8 || n > 1<<20 {
			return 0, fmt.Errorf("oracle bad tns length %d", n)
		}
		body := make([]byte, n-8)
		if _, err := readFull(s.br, body); err != nil {
			return 0, fmt.Errorf("oracle read tns body: %w", err)
		}
		if typ == 7 { // NULL keepalive
			continue
		}
		s.in = body
		return typ, nil
	}
}

func (s *oracleBackendSession) writePacket(payload []byte) error {
	return writeTNSFrame(s.conn, 6, payload)
}

// ---- login sequence ----

// parseDeadbeefNego extracts the two auth-relevant fields from the 23c
// O5LOGON response (the DEADBEEF stream): ServerCompileTimeCaps[4] (the
// logon-compatibility flag the verifier needs) and ServerCharset. The
// block layout is pinned from the 2026-09-01 capture:
//
//	00 00 DEADBEEF <u16 len> <u16 nBlocks> <blocks: u16 type, u16 len, data>
//
// Parsing is best-effort — the fields are also used cosmetically; the
// verifier type itself comes from the AUTH response dict.
func parseDeadbeefNego(payload []byte) *oracleTcpNego {
	nego := &oracleTcpNego{ServerCharset: 0}
	// Default: 23c negotiates the custom-hash logon (caps[4]&32 set).
	nego.ServerCompileTimeCaps[4] = 32
	idx := bytes.Index(payload, []byte{0xde, 0xad, 0xbe, 0xef})
	if idx < 0 || idx+9 > len(payload) {
		return nego
	}
	n := int(binary.BigEndian.Uint16(payload[idx+4 : idx+6]))
	end := idx + 6 + n
	if end > len(payload) {
		end = len(payload)
	}
	i := idx + 6
	for i+4 <= end {
		typ := binary.BigEndian.Uint16(payload[i : i+2])
		blen := int(binary.BigEndian.Uint16(payload[i+2 : i+4]))
		if i+4+blen > end {
			break
		}
		// ServerCharset appears as a 2-byte value in the type-4 block
		// (the charset entry); compile caps as a type-5 byte array.
		switch typ {
		case 4:
			if blen >= 2 {
				nego.ServerCharset = binary.BigEndian.Uint16(payload[i+4 : i+6])
			}
		case 5:
			if blen >= 8 {
				copy(nego.ServerCompileTimeCaps[:], payload[i+4:i+12])
			}
		}
		i += 4 + blen
	}
	return nego
}

// parseOCIChallenge parses the server's auth CHALLENGE (the OCI dict the
// 23c server sends inside the server-data response — pinned from the
// 2026-09-01 capture):
//
//	entries: u16 keylen, u32 keylen, key bytes, u8 flag, u32 vallen, value
//
// Flag convention (pinned from the capture): keys ending in '@'
// (AUTH_SESSKEY@, AUTH_PASSWORD@) carry their flag byte AS the '@'
// itself — hasFlag=false, the value length follows immediately. Keys
// without '@' (AUTH_VFR_DATA, AUTH_PBKDF2_*) carry a separate flag byte
// — hasFlag=true. The VFR_DATA flag byte is the verifier type (0x20 =
// PBKDF2-SPEEDY, the 23c default — mapped to the port's 18453 id).
// Returns the object with the challenge fields populated (tcpNego
// defaults: custom-hash on).
func parseOCIChallenge(payload []byte) (*oracleAuthObject, error) {
	ret := &oracleAuthObject{
		tcpNego: &oracleTcpNego{ServerCharset: 0},
	}
	ret.tcpNego.ServerCompileTimeCaps[4] = 32 // 23c custom-hash logon
	if v := extractOCIValue(payload, "AUTH_SESSKEY@", false); v != "" {
		ret.EServerSessKey = v
	}
	if v := extractOCIValue(payload, "AUTH_VFR_DATA", true); v != "" {
		ret.Salt = v
		ret.VerifierType = 18453 // OCI flag 0x20 → PBKDF2-SPEEDY (23c)
	}
	if v := extractOCIValue(payload, "AUTH_PBKDF2_CSK_SALT", true); v != "" {
		ret.pbkdf2ChkSalt = v
	}
	if v := extractOCIValue(payload, "AUTH_PBKDF2_VGEN_COUNT", true); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 4096 {
			ret.pbkdf2VgenCount = n
		} else {
			ret.pbkdf2VgenCount = 4096
		}
	}
	if v := extractOCIValue(payload, "AUTH_PBKDF2_SDER_COUNT", true); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 3 {
			ret.pbkdf2SderCount = n
		} else {
			ret.pbkdf2SderCount = 3
		}
	}
	if len(ret.EServerSessKey) != 64 && len(ret.EServerSessKey) != 96 {
		return nil, fmt.Errorf("oracle challenge: session key should be 64/96 hex chars, got %d", len(ret.EServerSessKey))
	}
	return ret, nil
}

// buildOCIAuth builds the AUTH DATA payload in OCI framing from the
// captured sqlplus AUTH template (a deadbeef/OCI negotiation REQUIRES the
// OCI auth family — go-ora's JDBC-style dict framing makes the server
// close the connection). All three verifier values have identical lengths
// to the template's (64/64/160 hex), so only the bytes inside change.
func buildOCIAuth(user string, auth *oracleAuthObject) []byte {
	tmpl := append([]byte(nil), ociAuthTemplate...)
	// 1. username (7 bytes at the 0x07 marker).
	ub := []byte(user)
	if len(ub) == 7 {
		if i := bytes.Index(tmpl, []byte("ro_user")); i >= 0 {
			copy(tmpl[i:], ub)
		}
	}
	// 2-4. verifier values (key + [flag] + u32 vallen + value).
	swap := func(key string, val string, hasFlag bool) {
		i := bytes.Index(tmpl, []byte(key))
		if i < 0 {
			return
		}
		v := i + len(key)
		if hasFlag {
			v++ // skip the flag byte
		}
		vlen := int(binary.BigEndian.Uint32(tmpl[v : v+4]))
		if v+4+vlen <= len(tmpl) && vlen == len(val) {
			copy(tmpl[v+4:], []byte(val))
		}
	}
	swap("AUTH_SESSKEY@", auth.EClientSessKey, false)
	swap("AUTH_PBKDF2_SPEEDY_KEY", auth.ESpeedyKey, true)
	swap("AUTH_PASSWORD@", auth.EPassword, false)
	return tmpl
}

// sanitizeOracleMsg keeps only printable runes of an ORA- message.
func sanitizeOracleMsg(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	return string(out)
}

// oracleBackendLogin completes the full login against the real backend and
// returns the raw conn (buffers empty) for the relay. The client leg
// acknowledges auth with the CAPTURED mirror (authResp2200), NOT a response
// built from this backend session — the captured session's identity is what
// the mirror carries, which is why the OCI client leg is best-effort (the
// 23c mutual-auth wall; see RUN.md). serviceName comes from the CLIENT's
// CONNECT descriptor (the token only carries host:port).
func oracleBackendLogin(ctx context.Context, host, port, user, password, serviceName string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("oracle backend dial %s:%s: %w", host, port, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	s := newOracleBackendSession(conn)

	// 1. CONNECT (client-first, service name in the descriptor). The
	//    CONNECT/ACCEPT exchange uses the pre-handshake 2-byte header.
	if err := writeTNSHandshakeFrame(conn, 1, buildConnectPacket(host, port, serviceName)); err != nil {
		return nil, fmt.Errorf("oracle connect: %w", err)
	}
	typ, err := s.readPacketHandshake()
	if err != nil {
		return nil, fmt.Errorf("oracle accept: %w", err)
	}
	if typ != 2 {
		if typ == 4 {
			return nil, fmt.Errorf("oracle backend refused the connection (REFUSE)")
		}
		return nil, fmt.Errorf("oracle backend: unexpected accept packet type %d", typ)
	}

	// 2. O5LOGON + server-data: REPLAY the captured sqlplus templates
	//    verbatim (headers included — the 23c server requires the
	//    DEADBEEF "advanced" negotiation, which go-ora's simple request
	//    shape cannot elicit; the response is deterministic per version).
	if _, err := s.conn.Write(cliO5logon150); err != nil {
		return nil, fmt.Errorf("oracle o5logon: %w", err)
	}
	if _, err := s.readPacket(); err != nil {
		return nil, fmt.Errorf("oracle o5logon response: %w", err)
	}
	nego := parseDeadbeefNego(s.in)
	_ = nego // caps are folded into the challenge defaults
	if _, err := s.conn.Write(cliServerDataReq384); err != nil {
		return nil, fmt.Errorf("oracle server-data request: %w", err)
	}
	if _, err := s.readPacket(); err != nil {
		return nil, fmt.Errorf("oracle server-data response: %w", err)
	}

	// 3. AUTH: the server-data response IS the challenge (salt, session
	//    key, PBKDF2 params in OCI dict framing). Compute the verifier
	//    keys with the ported crypto and send the OCI-framing AUTH (the
	//    captured sqlplus template with the three values swapped — a
	//    deadbeef/OCI negotiation requires the OCI auth family).
	auth, err := parseOCIChallenge(s.in)
	if err != nil {
		return nil, err
	}
	if err := auth.computeAuthKeys(user, password); err != nil {
		return nil, fmt.Errorf("oracle auth compute: %w", err)
	}
	if err := s.writePacket(buildOCIAuth(user, auth)); err != nil {
		return nil, fmt.Errorf("oracle auth write: %w", err)
	}

	// 4. The auth response: a dict with AUTH_VERSION_STRING on success
	//    (or an ORA- on failure), closed by the end marker. Read one
	//    packet and classify.
	if _, err := s.readPacket(); err != nil {
		return nil, fmt.Errorf("oracle auth response: %w", err)
	}
	if bytes.Contains(s.in, []byte("ORA-")) {
		msg := s.in
		if i := bytes.Index(msg, []byte("ORA-")); i >= 0 {
			end := i + 64
			if end > len(msg) {
				end = len(msg)
			}
			return nil, fmt.Errorf("oracle backend login rejected: %s", sanitizeOracleMsg(msg[i:end]))
		}
		return nil, fmt.Errorf("oracle backend login rejected")
	}
	if !bytes.Contains(s.in, []byte("AUTH_VERSION_STRING")) {
		return nil, fmt.Errorf("oracle backend login: unexpected auth response")
	}
	ok = true
	return conn, nil
}

// oracleBackendLoginGoORA is the JDBC-family backend leg driven by the
// vendored go-ora master (patched: descriptor cap 4096, RawConn accessor).
// go-ora completes the FULL login (deadbeef O5LOGON with fresh session
// randomness + the verifier auth as the real user) and its negotiated type
// maps match the JDBC client's dialect — the relay then carries the
// client's queries verbatim.
func oracleBackendLoginGoORA(ctx context.Context, host, port, user, password, serviceName string, dialTimeout time.Duration) (net.Conn, error) {
	url := fmt.Sprintf("oracle://%s:%s@%s:%s/%s", user, password, host, port, serviceName)
	// Parse the URL into a config so the caller's dial timeout and context
	// are actually honored (review 2026-09-02: NewConnection(url, nil)
	// applies go-ora's defaults — ConnectTimeout 60s, Timeout 0 = no read
	// deadline — and conn.Open() ignores ctx, so a black-holed backend
	// could pin the session goroutine for a minute).
	cfg, err := go_ora.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("oracle go-ora parse: %w", err)
	}
	if dialTimeout > 0 {
		cfg.SessionInfo.ConnectTimeout = dialTimeout // bounds the dial
		cfg.SessionInfo.Timeout = dialTimeout        // bounds login reads/writes
	}
	conn, err := go_ora.NewConnection("", cfg)
	if err != nil {
		return nil, fmt.Errorf("oracle go-ora open: %w", err)
	}
	// OpenWithContext: ctx cancels a hung dial/login (the caller's ctx is
	// the session lifetime anchor, e.g. storeCallCtx bounds).
	if err := conn.OpenWithContext(ctx); err != nil {
		return nil, fmt.Errorf("oracle go-ora login: %w", err)
	}
	raw := conn.RawConn()
	// go-ora armed per-op read/write deadlines (cfg.Timeout) during the
	// login; the byte relay must be deadline-free (long queries would
	// otherwise trip the lingering deadline mid-flight — mysql_proxy.go:310
	// clears its handshake deadline the same way).
	_ = raw.SetDeadline(time.Time{})
	return raw, nil
}
