package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// TDS packet types (MS-TDS 2.2.3.1). The login response and every query
// result stream are TABULAR RESULT packets (0x04); PRELOGIN (0x12) is also
// the envelope for the TDS 8.0 TLS upgrade — TLS records travel inside
// 0x12 packets.
const (
	tdsSQLBatch   = 0x01
	tdsRPC        = 0x03
	tdsTabular    = 0x04
	tdsAttention  = 0x06
	tdsLogin7     = 0x10
	tdsPrelogin   = 0x12
	tdsStatusEOM  = 0x01
	tdsHeaderLen  = 8
	tdsPacketSize = 4096
	tdsVersion740 = 0x74000004 // TDS 7.4 — what sqlcmd v18 sends
	// mssqlLegacyDoneMaxTDSVersion: clients declaring a TDS version BELOW
	// this negotiate the legacy wire shape — SQL Server answers them with
	// SHORT 9-byte DONE tokens (4-byte row count) instead of the modern
	// 13-byte form (live-verified 2026-08-26: SQLOLEDB declares
	// 0x71000001; the server echoed it and used 9-byte DONEs). Every
	// place the proxy BUILDS or PARSES a DONE token must branch on this.
	mssqlLegacyDoneMaxTDSVersion = 0x72000000
	tdsDoneFinal                 = 0x0200 // DONE token status bit: message complete
	tdsDoneError                 = 0x0002 // DONE token status bit: error occurred
	tdsDoneAttn                  = 0x0020 // DONE token status bit: attention acknowledged (MS-TDS 2.2.7.10)
)

// tdsMaxHandshakeMsg caps the assembled size of a PRE-AUTH TDS message
// (PRELOGIN / LOGIN7 — a few KB in practice): an endless multi-packet
// stream cannot grow the buffer without bound (review 2026-08-17 — the 10s
// handshake deadline bounds the stream in TIME only). A var (not const) so
// tests can shrink it.
var tdsMaxHandshakeMsg = 64 << 10

// tdsMaxRelayMsg caps one relayed client message (see
// readTDSMessageFrames): real SQL batches are far smaller, so the cap only
// ever trips on a broken or hostile client; it bounds per-session memory
// (review 2026-08-17). A var (not const) so tests can shrink it.
var tdsMaxRelayMsg = 16 << 20

// PreLogin option tokens (MS-TDS 2.2.6.3).
const (
	preloginVersion    = 0x00
	preloginEncryption = 0x01
	preloginInstOpt    = 0x02
	preloginThreadID   = 0x03
	preloginMARS       = 0x04
	preloginTraceID    = 0x05
)

// PreLogin ENCRYPTION values (MS-TDS 2.2.6.3).
const (
	encryptOff    = 0x00
	encryptOn     = 0x01
	encryptNotSup = 0x02
)

// readTDSPacket reads exactly one TDS packet: the 8-byte header plus its
// payload. NOTE: the TDS header Length and SPID fields are BIG-ENDIAN on
// the wire — verified empirically against SQL Server 2022 + ODBC 18
// (commit 0163a9b: `01 a2` = 418, `05 ea` = 1514; a little-endian write
// makes ODBC 18 reject the packet with "Protocol error in TDS stream").
// Token-level length fields inside payloads are little-endian as usual.
func readTDSPacket(br *bufio.Reader) (typ, status byte, payload []byte, err error) {
	hdr := make([]byte, tdsHeaderLen)
	if _, err = io.ReadFull(br, hdr); err != nil {
		return 0, 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < tdsHeaderLen {
		return 0, 0, nil, fmt.Errorf("tds: bad packet length %d", length)
	}
	payload = make([]byte, length-tdsHeaderLen)
	if _, err = io.ReadFull(br, payload); err != nil {
		return 0, 0, nil, err
	}
	return hdr[0], hdr[1], payload, nil
}

// writeTDSPacket writes one TDS packet (type typ) with the EOM status bit,
// SPID 0, packet id 1, window 0 — the shape every captured client/server
// packet in round 1 used. (The writeTDSPacketStatus wrapper is gone — Task
// 9.10 unnecessary-code removal; multi-fragment messages go through
// writeTDSMessage.)
func writeTDSPacket(w io.Writer, typ byte, payload []byte) error {
	return writeTDSPacketSPID(w, typ, tdsStatusEOM, 0, payload)
}

// writeTDSPacketSPID is writeTDSPacket with a caller-chosen SPID header
// field. The relay and the login path use SPID 0 (what every captured
// client/server packet in round 1 used); the ATTENTION packet (Task 9.4
// kill-query) carries the backend SPID captured at login — the real ODBC
// driver fills the field from the login response's ENVCHANGE SPID token.
// Task 9.10: the write is checked for short writes (n != len).
func writeTDSPacketSPID(w io.Writer, typ, status byte, spid uint16, payload []byte) error {
	hdr := make([]byte, tdsHeaderLen)
	hdr[0] = typ
	hdr[1] = status
	binary.BigEndian.PutUint16(hdr[2:4], uint16(tdsHeaderLen+len(payload)))
	binary.BigEndian.PutUint16(hdr[4:6], spid)
	hdr[6] = 1 // packet id
	hdr[7] = 0 // window
	n, err := w.Write(append(hdr, payload...))
	if err != nil {
		return err
	}
	if n != tdsHeaderLen+len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

// readTDSMessage reads TDS packets until the EOM status bit, assembling one
// logical message. PRELOGIN, LOGIN7 and the (small) login response each fit
// a single packet in practice, but a message MUST be assembled per spec —
// a client that fragments its login7 across packets must still be parsed.
func readTDSMessage(br *bufio.Reader) (typ byte, payload []byte, err error) {
	var buf []byte
	for {
		t, status, p, err := readTDSPacket(br)
		if err != nil {
			return 0, nil, err
		}
		if typ == 0 {
			typ = t
		}
		// Cap the assembled message (review 2026-08-17): an endless
		// multi-packet stream must not grow the buffer without bound —
		// the handshake deadline bounds it in TIME only.
		if len(buf)+len(p) > tdsMaxHandshakeMsg {
			return 0, nil, fmt.Errorf("tds: message too large (%d bytes)", len(buf)+len(p))
		}
		buf = append(buf, p...)
		if status&tdsStatusEOM != 0 {
			return typ, buf, nil
		}
	}
}

// parsePrelogin walks a PRELOGIN option map and returns the requested
// ENCRYPTION value (0x00 when absent). Option offsets/lengths are stored
// MOST-SIGNIFICANT-BYTE-FIRST — the round-1 capture parses perfectly under
// that reading (VERSION @31 len 6, ENCRYPTION @37 len 1, …) and the
// fakeserver response built the same way was accepted by ODBC 18.
func parsePrelogin(payload []byte) (encryption byte, err error) {
	for i := 0; i+5 <= len(payload); i += 5 {
		tok := payload[i]
		if tok == 0xff { // option-map terminator
			break
		}
		off := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
		l := int(binary.BigEndian.Uint16(payload[i+3 : i+5]))
		if tok == preloginEncryption {
			if off+l > len(payload) {
				return 0, fmt.Errorf("tds prelogin: encryption value out of bounds")
			}
			if l >= 1 {
				return payload[off], nil
			}
		}
	}
	return encryptOff, nil
}

// buildPrelogin builds the CLIENT prelogin the proxy sends to the real SQL
// Server backend — mirroring the sqlcmd v18 shape captured in round 1 (all
// six options, TRACEID present) byte-for-byte except the ENCRYPTION value,
// which is caller-chosen. The proxy always offers ENCRYPT_OFF on the
// backend leg: the login7 password is protected by the login-obfuscation
// transform and the channel needs no TLS.
func buildPrelogin(encryption byte) []byte {
	// Option map (offsets MSB-first, relative to the message body start):
	// VERSION(6)@31 ENCRYPTION(1)@37 INSTOPT(1)@38 THREADID(4)@39
	// MARS(1)@43 TRACEID(36)@44, terminator, then the value area.
	opt := []byte{
		0x00, 0x00, 0x1f, 0x00, 0x06, // VERSION
		0x01, 0x00, 0x25, 0x00, 0x01, // ENCRYPTION
		0x02, 0x00, 0x26, 0x00, 0x01, // INSTOPT
		0x03, 0x00, 0x27, 0x00, 0x04, // THREADID
		0x04, 0x00, 0x2b, 0x00, 0x01, // MARS
		0x05, 0x00, 0x2c, 0x00, 0x24, // TRACEID
		0xff,
	}
	data := []byte{0x12, 0x06, 0x00, 0x02, 0x00, 0x00} // VERSION value
	data = append(data, encryption)                    // ENCRYPTION
	data = append(data, 0x00)                          // INSTOPT
	data = append(data, 0x00, 0x00, 0x00, 0x00)        // THREADID
	data = append(data, 0x00)                          // MARS
	data = append(data, make([]byte, 36)...)           // TRACEID (zeros)
	return append(opt, data...)
}

// buildPreloginResponse builds the SERVER prelogin response, mirroring the
// real SQL Server 2022 response byte-for-byte (captured live via the round-1
// sniffer): VERSION(6) ENCRYPTION(1) INSTOPT(1) THREADID(0) MARS(1)
// TRACEID(0) + terminator; data area VERSION `10 00 10 a9 00 00` +
// ENCRYPTION byte + INSTOPT 00 + MARS 00. The TRACEID entry is REQUIRED —
// ODBC 18 rejects a response without it ("Protocol error in TDS stream").
func buildPreloginResponse(encryption byte) []byte {
	opt := []byte{
		0x00, 0x00, 0x1f, 0x00, 0x06, // VERSION
		0x01, 0x00, 0x25, 0x00, 0x01, // ENCRYPTION
		0x02, 0x00, 0x26, 0x00, 0x01, // INSTOPT
		0x03, 0x00, 0x27, 0x00, 0x00, // THREADID (len 0)
		0x04, 0x00, 0x27, 0x00, 0x01, // MARS
		0x05, 0x00, 0x28, 0x00, 0x00, // TRACEID (len 0)
		0xff,
	}
	data := []byte{0x10, 0x00, 0x10, 0xa9, 0x00, 0x00, encryption, 0x00, 0x00}
	return append(opt, data...)
}

// obfuscatePassword encodes a login password for the login7 Password field
// using the SQL Server 2022 / ODBC 18 "encrypt login" transform DERIVED
// from the round-1 plaintext captures (the derivation, byte math and golden
// vectors are in .superpowers/sdd/PLAN/task-9.2-report.md): each byte of
// the UTF-16LE encoding is nibble-swapped (rotate-left 4) and then XORed
// with 0xA5.
//
// Golden vectors (captured verbatim from sqlcmd v18.6.2.1 against a fake
// server that negotiated ENCRYPT_NOT_SUP):
//
//	obfuscatePassword("ro_pw") → 82 a5 53 a5 50 a5 a2 a5 d2 a5
//	obfuscatePassword("ZtProxyLongPass_2026!") →
//	  00 a5 e2 a5 a0 a5 82 a5 53 a5 22 a5 32 a5 61 a5 53 a5 43 a5
//	  d3 a5 a0 a5 b3 a5 92 a5 92 a5 50 a5 86 a5 a6 a5 86 a5 c6 a5 b7 a5
//
// The transform is per-character and position-independent — 'r' maps to
// 82 a5 in BOTH captures (offsets 0 and 3), '_' to 50 a5 (offsets 4 and
// 15), 's' to 92 a5 (offsets 13 and 14), 'P' to a0 a5 (offsets 2 and 11).
// Decoding (the server side, and our own parse path) is the same function
// applied again: rotl4 is its own inverse.
func obfuscatePassword(pw string) []byte {
	units := utf16.Encode([]rune(pw))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		for _, b := range [2]byte{byte(u), byte(u >> 8)} {
			out = append(out, ((b<<4)|(b>>4))^0xA5)
		}
	}
	return out
}

// login7Info is the parsed view of a LOGIN7 message the proxy needs:
// the token-as-username, the client-requested database (kept on the
// backend login), plus the client's connection metadata mirrored into the
// backend login7 so the session looks like the maker's own client. The
// client's raw password field is deliberately NOT parsed (Task 9.10
// unnecessary-code removal): the token IS the credential — the backend
// login7 always carries the RESOLVER password.
type login7Info struct {
	hostname string
	username string
	appname  string
	server   string
	database string
	// Fixed-header values declared by the CLIENT, preserved verbatim on
	// the backend login7 (version passthrough fix, 2026-08-26): the proxy
	// previously forced TDS 7.4 here, so a legacy provider (SQLOLEDB
	// declares 0x71000001) received a LOGINACK for a version it cannot
	// parse — its DBMS Version property came back empty/garbage and
	// HeidiSQL failed with "DBMS version is less than 7.0.0". Passing the
	// client's declaration through lets the REAL server negotiate exactly
	// as it would on a direct connection.
	tdsVersion uint32
	packetSize uint32
}

// login7 fixed header layout (MS-TDS 2.2.6.4): 36 bytes of fixed fields
// followed by the 60-byte offset/length table, then the variable-length
// data area. Lengths are in UTF-16 code units (characters). Table OFFSETS
// are relative to the start of the LOGIN7 PAYLOAD (after the 8-byte TDS
// header) — verified programmatically against the round-1 capture:
// hostname "79fc12acc361" @0x5e, username "ro_user" @0x76, password
// @0x84, appname "SQLCMD" @0x8e, servername "host.docker.internal,1504"
// @0x9a, extension @0xcc, cltintname "ODBC" @0xd0, database "appdb" @0xd8.
const (
	login7FixedLen = 36
	login7TableLen = 60
)

// parseLogin7 decodes the fixed header and the 16-entry offset/length
// table. The layout was validated field-by-field against the round-1
// capture (see the const comment above).
func parseLogin7(payload []byte) (login7Info, error) {
	var li login7Info
	if len(payload) < login7FixedLen+login7TableLen {
		return li, fmt.Errorf("tds login7: too short (%d bytes)", len(payload))
	}
	field := func(entry int) (int, int, error) {
		base := login7FixedLen + entry*4
		off := int(binary.LittleEndian.Uint16(payload[base : base+2]))
		l := int(binary.LittleEndian.Uint16(payload[base+2 : base+4]))
		if off+l*2 > len(payload) {
			return 0, 0, fmt.Errorf("tds login7: field %d out of bounds", entry)
		}
		return off, l, nil
	}
	text := func(entry int) (string, error) {
		off, l, err := field(entry)
		if err != nil || l == 0 {
			return "", err
		}
		units := make([]uint16, l)
		for i := 0; i < l; i++ {
			units[i] = binary.LittleEndian.Uint16(payload[off+2*i:])
		}
		return string(utf16.Decode(units)), nil
	}
	var err error
	if li.hostname, err = text(0); err != nil {
		return li, err
	}
	if li.username, err = text(1); err != nil {
		return li, err
	}
	if li.appname, err = text(3); err != nil {
		return li, err
	}
	if li.server, err = text(4); err != nil {
		return li, err
	}
	if li.database, err = text(8); err != nil {
		return li, err
	}
	li.tdsVersion = binary.LittleEndian.Uint32(payload[4:8])
	li.packetSize = binary.LittleEndian.Uint32(payload[8:12])
	return li, nil
}

// buildLogin7 builds the login7 the proxy sends to the real backend:
// username = the token's real db_user, password = the resolver password
// OBFUSCATED with the derived transform, database = the CLIENT-requested
// database (kept so the session has the maker's default schema). tdsVersion
// and packetSize are the CLIENT's declared fixed-header values, passed
// through verbatim (version passthrough fix, 2026-08-26): the server then
// negotiates the TDS version exactly as it would on a direct connection,
// so legacy providers (SQLOLEDB / TDS 7.1) get an ack they can parse while
// modern clients (which declare 7.4 themselves) see byte-identical behavior
// to the previous forced 7.4. The remaining fixed fields mirror the captured
// sqlcmd v18 login7 (option flags e0 03 00 10, LCID 0x0409); clientid is
// 0xFF like the capture; no feature extensions are requested.
func buildLogin7(hostname, username, appname, server, database string, obfuscatedPw []byte, tdsVersion, packetSize uint32) []byte {
	fields := []struct {
		val string
		raw []byte
	}{
		{val: hostname}, {val: username}, {raw: obfuscatedPw},
		{val: appname}, {val: server}, {val: ""}, {val: "ODBC"},
		{val: ""}, {val: database},
	}
	// UTF-16LE encode every field up front.
	for i := range fields {
		if fields[i].raw == nil {
			units := utf16.Encode([]rune(fields[i].val))
			fields[i].raw = make([]byte, len(units)*2)
			for j, u := range units {
				binary.LittleEndian.PutUint16(fields[i].raw[2*j:], u)
			}
		}
	}
	payload := make([]byte, login7FixedLen+login7TableLen)
	binary.LittleEndian.PutUint32(payload[4:8], tdsVersion)
	binary.LittleEndian.PutUint32(payload[8:12], packetSize)
	payload[24] = 0xE0 // OptionFlags1 (fUseDB | fSetLang | fByteOrder | fChar | fFloat | fDumpLoad)
	payload[25] = 0x03 // OptionFlags2 (fLanguage | fODBC)
	payload[26] = 0x00 // TypeFlags
	payload[27] = 0x10 // OptionFlags3 (fChangePassword is clear; 0x10 = unknown/captured)
	binary.LittleEndian.PutUint32(payload[32:36], 0x0409)
	// Offsets are relative to the payload start (the convention sqlcmd
	// uses and the server decodes — verified against the round-1 capture);
	// the data area follows the 60-byte table. Lengths are in UTF-16 code
	// units.
	off := login7FixedLen + login7TableLen
	set := func(entry int, raw []byte) {
		base := login7FixedLen + entry*4
		binary.LittleEndian.PutUint16(payload[base:base+2], uint16(off))
		binary.LittleEndian.PutUint16(payload[base+2:base+4], uint16(len(raw)/2))
		payload = append(payload, raw...)
		off += len(raw)
	}
	// Data area in the captured field order (extension value between
	// servername and cltintname).
	set(0, fields[0].raw) // hostname
	set(1, fields[1].raw) // username
	set(2, fields[2].raw) // password
	set(3, fields[3].raw) // appname
	set(4, fields[4].raw) // servername
	// Extension (entry 5): a 4-byte value (feature-data offset, 0) whose
	// LENGTH IS IN BYTES — unlike the text fields, whose table lengths are
	// UTF-16 code units. This is the round-5 root-caused fix: writing the
	// extension length in units (4/2 = 2) makes the real SQL Server reject
	// the login7 outright (live bisection: len=2 → server closes, len=4 →
	// LOGIN-OK), because it locates the following fields by walking the
	// extension bytes.
	extPos := off
	set(5, make([]byte, 4))
	binary.LittleEndian.PutUint16(payload[login7FixedLen+5*4+2:login7FixedLen+5*4+4], 4)
	set(6, fields[6].raw) // cltintname
	set(7, fields[7].raw) // language
	set(8, fields[8].raw) // database
	// The feature-data offset points at an explicit 0xff terminator: the
	// server walks feature blocks until 0xff, so an EMPTY extension is a
	// single terminator byte (no feature extensions are requested).
	feOff := off
	binary.LittleEndian.PutUint16(payload[extPos:extPos+2], uint16(feOff))
	payload = append(payload, 0xff)
	// clientid (6 bytes 0xFF), SSPI off 0xFFFF len 0, atchdbg/chgpassword
	// empty at end-of-data, 3 reserved entries.
	payload = append(payload, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
	payload = append(payload, 0xFF, 0xFF, 0x00, 0x00)
	for i := 0; i < 3; i++ {
		payload = append(payload, byte(off), byte(off>>8), 0x00, 0x00)
	}
	binary.LittleEndian.PutUint32(payload[0:4], uint32(len(payload)))
	return payload
}

// scanLoginResponse walks the token stream of the backend's login response
// (TABULAR RESULT payload) and reports whether the response has ENDED — a
// DONE token (0xFD) carrying the DONE_FINAL status bit — plus any database
// name announced by an ENVCHANGE (0xE3) type-0x01 token. ERROR tokens
// (0xAA) mark a failed login (loginOK=false). An unknown token type ends
// the scan conservatively: anything after it is post-login traffic.
func scanLoginResponse(buf []byte) (done, loginOK bool, db string) {
	loginOK = true
	for pos := 0; pos < len(buf); {
		t := buf[pos]
		switch t {
		case 0xFD, 0xFE, 0xFF: // DONE / DONEINPROC / DONEPROC
			// Modern (TDS >= 7.2) DONE is 13 bytes (8-byte rowcount);
			// legacy (TDS < 7.2 — SQLOLEDB/7.1) is 9 bytes (4-byte
			// rowcount). A live SQL Server answers a 7.1 client with
			// the legacy shape even in the login response (version
			// passthrough fix, 2026-08-26).
			doneLen := 13
			if pos+13 > len(buf) {
				if pos+9 > len(buf) {
					return false, loginOK, db
				}
				doneLen = 9
			}
			status := binary.LittleEndian.Uint16(buf[pos+1 : pos+3])
			if t == 0xFD && status&tdsDoneFinal != 0 {
				done = true
			}
			if t == 0xFD && status&tdsDoneError != 0 {
				loginOK = false
			}
			// A DONE token that is the LAST thing in the message ends the
			// response too: the live mssql-test backend (SQL Server 2022)
			// finishes a successful login with DONE status 0x0000 — no
			// DONE_FINAL bit — and the message EOM is what real clients
			// (sqlcmd/ODBC) treat as the end of the response. Round-6
			// live capture: 389-byte login response, trailing
			// `fd 00 00` (status 0x0000). Without this rule the harness
			// waits forever for a second message the server never sends.
			if t == 0xFD && pos+doneLen == len(buf) {
				done = true
			}
			pos += doneLen
		case 0xAA, 0xAB, 0xAD, 0xAE, 0xE3, 0xE4: // length-prefixed tokens
			if pos+3 > len(buf) {
				return false, loginOK, db
			}
			l := int(binary.LittleEndian.Uint16(buf[pos+1 : pos+3]))
			if pos+3+l > len(buf) {
				return false, loginOK, db
			}
			if t == 0xAA {
				loginOK = false
			}
			if t == 0xE3 && l >= 3 && buf[pos+3] == 0x01 { // ENVCHANGE database
				n := int(buf[pos+4])
				if pos+5+2*n <= len(buf) {
					units := make([]uint16, n)
					for i := 0; i < n; i++ {
						units[i] = binary.LittleEndian.Uint16(buf[pos+5+2*i:])
					}
					db = string(utf16.Decode(units))
				}
			}
			pos += 3 + l
		default:
			// Unknown token — the login response has ended.
			return true, loginOK, db
		}
	}
	return done, loginOK, db
}
