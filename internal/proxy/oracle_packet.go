package proxy

// Task 9.14 — Oracle/TNS wire layer (Phase 1).
//
// Packet layout (pinned by the 2026-09-01 live captures of the real
// oracle-test backend):
//
//	TNS header (8 bytes): length (2 BE, whole packet), packet checksum (2,
//	usually 0), packet type (1), reserved (1, 0), header checksum (2, 0).
//	Type 1 = CONNECT, 2 = ACCEPT, 4 = REFUSE, 6 = DATA, 7 = NULL.
//
// The proxy TERMINATES the login on both legs (the MSSQL model): the client
// leg replays the captured real-server responses (oracle_responses.go — the
// token is the credential, the client's password is never verified), and
// the backend leg logs in with the real db_user/password using the
// go-ora-derived verifier crypto (oracle_auth.go). Post-login DATA packets
// are relayed byte-exact.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// TNS packet types.
const (
	tnsConnect = 0x01
	tnsAccept  = 0x02
	tnsRefuse  = 0x04
	tnsData    = 0x06
	tnsNull    = 0x07
)

// tnsHeaderLen is the fixed TNS packet header size.
const tnsHeaderLen = 8

// readTNSFrame reads one TNS packet (header + payload) from br. Uses the
// POST-handshake header format: 4-byte BE length at [0:4] (Oracle ≥ 12.1 /
// version 315+ after the CONNECT/ACCEPT exchange — pinned by the 2026-09-01
// captures; go-ora network/session.go readPacketData).
func readTNSFrame(br *bufio.Reader) (typ byte, payload []byte, err error) {
	hdr := make([]byte, tnsHeaderLen)
	if _, err = readFull(br, hdr); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint32(hdr[0:4]))
	if length < tnsHeaderLen || length > 1<<20 {
		return 0, nil, fmt.Errorf("tns: bad length %d", length)
	}
	typ = hdr[4]
	payload = make([]byte, length-tnsHeaderLen)
	if len(payload) > 0 {
		if _, err = readFull(br, payload); err != nil {
			return 0, nil, err
		}
	}
	return typ, payload, nil
}

// readTNSHandshakeFrame reads the CONNECT/ACCEPT exchange packet: 2-byte BE
// length at [0:2] (the pre-handshake format).
func readTNSHandshakeFrame(br *bufio.Reader) (typ byte, payload []byte, err error) {
	hdr := make([]byte, tnsHeaderLen)
	if _, err = readFull(br, hdr); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[0:2]))
	if length < tnsHeaderLen || length > 1<<20 {
		return 0, nil, fmt.Errorf("tns: bad length %d", length)
	}
	typ = hdr[4]
	payload = make([]byte, length-tnsHeaderLen)
	if len(payload) > 0 {
		if _, err = readFull(br, payload); err != nil {
			return 0, nil, err
		}
	}
	return typ, payload, nil
}

// writeTNSFrame writes one TNS packet with the given type and payload using
// the post-handshake header (4-byte length).
func writeTNSFrame(c net.Conn, typ byte, payload []byte) error {
	total := tnsHeaderLen + len(payload)
	if total > 1<<20 {
		return fmt.Errorf("tns: frame too large %d", total)
	}
	hdr := make([]byte, tnsHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(total))
	hdr[4] = typ
	_, err := c.Write(append(hdr, payload...))
	return err
}

// writeTNSFrameBytes is the writer-based variant of writeTNSFrame (used by
// tests to round-trip mirror blobs through the framing without a live conn).
func writeTNSFrameBytes(bw *bufio.Writer, typ byte, payload []byte) error {
	total := tnsHeaderLen + len(payload)
	if total > 1<<20 {
		return fmt.Errorf("tns: frame too large %d", total)
	}
	hdr := make([]byte, tnsHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(total))
	hdr[4] = typ
	if _, err := bw.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return bw.Flush()
}

// writeTNSHandshakeFrame writes the CONNECT/ACCEPT exchange packet (2-byte
// length at [0:2]).
func writeTNSHandshakeFrame(c net.Conn, typ byte, payload []byte) error {
	total := tnsHeaderLen + len(payload)
	if total > 0xFFFF {
		return fmt.Errorf("tns: frame too large %d", total)
	}
	hdr := make([]byte, tnsHeaderLen)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(total))
	hdr[4] = typ
	_, err := c.Write(append(hdr, payload...))
	return err
}

// readFull is io.ReadFull with a friendlier name (avoids shadowing).
func readFull(br *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := br.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// newBufReader wraps a conn in a fresh bufio.Reader (the client-leg frame
// reads each get their own, so packet boundaries never leak between reads).
func newBufReader(c net.Conn) *bufio.Reader {
	return bufio.NewReader(c)
}

// serviceNameRe extracts SERVICE_NAME=<x> from a TNS connect descriptor.
var serviceNameRe = regexp.MustCompile(`SERVICE_NAME\s*=\s*([^)\s]+)`)

// parseServiceName extracts the requested service name from a client
// CONNECT packet payload (the connect descriptor is an ASCII
// (DESCRIPTION=...SERVICE_NAME=... ) block inside the payload). "" when the
// descriptor carries none (e.g. SID= or SERVICE= variants) — the backend
// leg then uses the plain service form of the token's db name.
func parseServiceName(payload []byte) string {
	// The descriptor is the printable tail of the CONNECT payload; scan
	// for the (DESCRIPTION= marker and take everything after it.
	idx := strings.Index(string(payload), "(DESCRIPTION=")
	if idx < 0 {
		// Some clients send a bare service string; try the whole payload.
		idx = 0
	}
	m := serviceNameRe.FindSubmatch(payload[idx:])
	if len(m) == 2 {
		return string(m[1])
	}
	return ""
}

// tokenRe matches the Project-D token form (sess_ + 32 hex).
var tokenRe = regexp.MustCompile(`sess_[0-9a-f]{32}`)

// findToken scans a TNS payload for the token-as-username. Returns "" when
// absent. The token is the ONLY credential the proxy trusts — the client's
// password field is never read.
func findToken(payload []byte) string {
	m := tokenRe.Find(payload)
	if m == nil {
		return ""
	}
	return string(m)
}

// buildConnectPacket builds the backend-leg CONNECT packet payload (the
// go-ora layout, pinned against the captured sqlplus CONNECT): version,
// options, SDU/TDU, flags, then the connect descriptor at offset 70.
// buildConnectPacket builds the backend-leg CONNECT packet payload from the
// captured sqlplus CONNECT (byte-proven against the oracle-test listener):
// the 269-byte payload is a TEMPLATE (connectTemplate) whose descriptor we
// swap per session — same shape the listener accepted (CONNECT_DATA before
// ADDRESS, CID included, len-field +4 convention preserved).
func buildConnectPacket(host, port, serviceName string) []byte {
	tmpl := append([]byte(nil), connectTemplate...)
	// Replace SERVICE_NAME=<old> with the client's service name. The
	// template's value is 8 chars (FREEPDB1); longer names rebuild the
	// descriptor with the same shape and patch the length fields.
	oldVal := []byte("FREEPDB1")
	idx := bytes.Index(tmpl, append([]byte("SERVICE_NAME="), oldVal...))
	if idx >= 0 && len(serviceName) == len(oldVal) {
		copy(tmpl[idx+len("SERVICE_NAME="):], []byte(serviceName))
		return tmpl
	}
	// Rebuild: same structural shape, lengths recomputed. The capture's
	// desc-len field overcounts the descriptor by 4 — preserved here.
	desc := fmt.Sprintf("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=%s)(CID=(PROGRAM=zerotrust-proxy)(HOST=%s)(USER=proxy))(CONNECTION_ID=AA==))(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%s)))", serviceName, host, host, port)
	buf := make([]byte, 70+len(desc))
	copy(buf, tmpl[:70])
	binary.BigEndian.PutUint16(buf[16:18], uint16(len(desc)+4))
	copy(buf[70:], desc)
	return buf
}

// oracleConnAddr returns the normalized peer host of a conn (for the
// session-token IP check — shared with the other proxies via NormalizeIP).
func oracleConnAddr(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}
