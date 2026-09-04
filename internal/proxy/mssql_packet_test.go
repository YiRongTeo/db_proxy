package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

// golden vectors captured VERBATIM from sqlcmd v18.6.2.1 (round 1): the
// plaintext login7 was captured by a fake server that negotiated
// ENCRYPT_NOT_SUP; the password field bytes below are what the client
// actually put on the wire.
var (
	goldenRoPW     = "82 a5 53 a5 50 a5 a2 a5 d2 a5"
	goldenLongPass = "00 a5 e2 a5 a0 a5 82 a5 53 a5 22 a5 32 a5 61 a5 53 a5 43 a5 d3 a5 a0 a5 b3 a5 92 a5 92 a5 50 a5 86 a5 a6 a5 86 a5 c6 a5 b7 a5"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestObfuscatePasswordGoldenVector(t *testing.T) {
	got := obfuscatePassword("ro_pw")
	want := mustHex(t, goldenRoPW)
	if !bytes.Equal(got, want) {
		t.Fatalf("obfuscatePassword(ro_pw) = %x, want %x", got, want)
	}
}

func TestObfuscatePasswordLongGoldenVector(t *testing.T) {
	got := obfuscatePassword("ZtProxyLongPass_2026!")
	want := mustHex(t, goldenLongPass)
	if !bytes.Equal(got, want) {
		t.Fatalf("obfuscatePassword(long) = %x, want %x", got, want)
	}
}

// The transform is per-character and position-independent: 'r' maps to
// 82 a5 at offset 0 in one capture and offset 3 in the other; '_' to
// 50 a5 at offsets 4 and 15; 's' to 92 a5 at offsets 13 and 14; 'P' to
// a0 a5 at offsets 2 and 11. Re-encoding any substring must reproduce
// the captured bytes.
func TestObfuscatePasswordPositionIndependent(t *testing.T) {
	sub := obfuscatePassword("o_pw")
	if !bytes.Equal(sub, mustHex(t, "53 a5 50 a5 a2 a5 d2 a5")) {
		t.Fatalf("o_pw re-encode mismatch: %x", sub)
	}
	sub = obfuscatePassword("ProxyLongPass_")
	want := mustHex(t, "a0 a5 82 a5 53 a5 22 a5 32 a5 61 a5 53 a5 43 a5 d3 a5 a0 a5 b3 a5 92 a5 92 a5 50 a5")
	if !bytes.Equal(sub, want) {
		t.Fatalf("ProxyLongPass_ re-encode mismatch: %x", sub)
	}
}

func TestObfuscatePasswordRoundTrip(t *testing.T) {
	for _, pw := range []string{"ro_pw", "rw_pw", "ZtProxyLongPass_2026!", "pässwörd", "a", ""} {
		enc := obfuscatePassword(pw)
		// Decode is the same transform applied again (rotl4 is its own inverse).
		dec := obfuscatePasswordBytes(enc)
		if dec != pw {
			t.Fatalf("round trip %q: got %q", pw, dec)
		}
	}
}

// obfuscatePasswordBytes decodes an obfuscated UTF-16LE password field
// (test helper mirroring the server-side decode: rotl4(out ^ 0xA5) per
// byte — the inverse of the encode transform — then UTF-16LE → string).
func obfuscatePasswordBytes(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		lo := ((b[i] ^ 0xA5) << 4) | ((b[i] ^ 0xA5) >> 4)
		hi := ((b[i+1] ^ 0xA5) << 4) | ((b[i+1] ^ 0xA5) >> 4)
		units = append(units, uint16(hi)<<8|uint16(lo))
	}
	return string(utf16.Decode(units))
}

func TestTDSPacketRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	if err := writeTDSPacket(&buf, tdsPrelogin, payload); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), buf.Bytes()...)
	br := bufio.NewReader(&buf)
	typ, status, got, err := readTDSPacket(br)
	if err != nil {
		t.Fatal(err)
	}
	if typ != tdsPrelogin || status != tdsStatusEOM || !bytes.Equal(got, payload) {
		t.Fatalf("round trip: typ=%#x status=%#x payload=%x", typ, status, got)
	}
	// Header length is BIG-ENDIAN: 8+4 = 12 → bytes 00 0c.
	if raw[2] != 0x00 || raw[3] != 0x0c {
		t.Fatalf("header length not big-endian: %02x %02x", raw[2], raw[3])
	}
}

func TestTDSMessageAssembly(t *testing.T) {
	var buf bytes.Buffer
	// First packet: no EOM (status 0), second: EOM.
	hdr1 := make([]byte, 8)
	hdr1[0] = tdsLogin7
	hdr1[1] = 0x00
	hdr1[2], hdr1[3] = 0x00, 0x0a // BE length 10
	hdr1[6] = 1
	buf.Write(hdr1)
	buf.Write([]byte("AB"))
	hdr2 := make([]byte, 8)
	hdr2[0] = tdsLogin7
	hdr2[1] = tdsStatusEOM
	hdr2[2], hdr2[3] = 0x00, 0x0a
	hdr2[6] = 2
	buf.Write(hdr2)
	buf.Write([]byte("CD"))
	typ, payload, err := readTDSMessage(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if typ != tdsLogin7 || string(payload) != "ABCD" {
		t.Fatalf("assembled: typ=%#x payload=%q", typ, payload)
	}
}

func TestPreloginParse(t *testing.T) {
	// The captured sqlcmd v18 prelogin: ENCRYPTION value byte is 0x00 at
	// offset 37 (client offered ENCRYPT_OFF with -N o).
	pre := mustHex(t, "120100580000010000001f000601002500010200260001030027000404002b000105002c0024ff1206000200000000000000000bc75a43c18424dfbf63d3b6ce6371e79fd6fefe908784c647c79a6a2b22d10b00000000")
	enc, err := parsePrelogin(pre[8:])
	if err != nil {
		t.Fatal(err)
	}
	if enc != encryptOff {
		t.Fatalf("client encryption = %#x, want 0x00", enc)
	}
	// A prelogin with no ENCRYPTION option defaults to off.
	enc, err = parsePrelogin([]byte{0xff})
	if err != nil || enc != encryptOff {
		t.Fatalf("empty map: enc=%#x err=%v", enc, err)
	}
}

func TestPreloginResponseShape(t *testing.T) {
	// The response must match the fake-server bytes that ODBC 18 accepted
	// (round 1) for the ENCRYPTION=0x02 case: 48 bytes total.
	resp := buildPreloginResponse(encryptNotSup)
	if len(resp) != 48-8 {
		t.Fatalf("response payload = %d bytes, want 40", len(resp))
	}
	// Data area starts at 31 (30-byte map + terminator): VERSION(6) then
	// the ENCRYPTION byte at index 37.
	if resp[37] != encryptNotSup {
		t.Fatalf("encryption byte misplaced: %x", resp[37])
	}
	// ENCRYPT_ON variant places 0x01 in the same slot.
	if buildPreloginResponse(encryptOn)[37] != encryptOn {
		t.Fatal("encrypt-on response byte misplaced")
	}
}

func TestLogin7ParseCaptured(t *testing.T) {
	// The FULL captured login7 packet (418 bytes, ro_user/ro_pw, appdb) —
	// extracted verbatim from build/fake-r1-enc02c.log. Field offsets were
	// validated against this capture; the table offsets are payload-relative.
	raw := mustHex(t,
		"100101a2000001009a0100000400007400100000000000077203000000000000"+
			"e00300100000000009040000"+
			"5e000c0076000700840005008e0006009a001900cc000400d0000400d8000000d8000500"+
			"ffffffffffff00000000e20000000000000000000000"+
			"370039006600630031003200610063006300330036003100"+
			"72006f005f007500730065007200"+
			"82a553a550a5a2a5d2a5"+
			"530051004c0043004d0044"+
			"0068006f00730074002e0064006f0063006b00650072002e0069006e007400650072006e0061006c002c003100350030003400"+
			"e2000000"+
			"4f00440042004300"+
			"61007000700064006200"+
			"109c00000031007c004d0053002d004f004400420043007c00310038002e0036002e0032002e0031007c007800380036005f00360034007c004c0069006e00750078007c004c0069006e0075007800200036002e0036002e00380037002e0032002d006d006900630072006f0073006f00660074002d007300740061006e0064006100720064002d00570053004c0032007c0055006e006b006e006f0077006e00"+
			"01000000000901000000010a01000000010b00000000ff")
	if len(raw) != 418 {
		t.Fatalf("captured packet = %d bytes, want 418", len(raw))
	}
	li, err := parseLogin7(raw[8:])
	if err != nil {
		t.Fatal(err)
	}
	if li.username != "ro_user" {
		t.Fatalf("username = %q", li.username)
	}
	if li.database != "appdb" {
		t.Fatalf("database = %q", li.database)
	}
	if li.hostname != "79fc12acc361" {
		t.Fatalf("hostname = %q", li.hostname)
	}
	if li.appname != "SQLCMD" {
		t.Fatalf("appname = %q", li.appname)
	}
	if li.server != "host.docker.internal,1504" {
		t.Fatalf("servername = %q", li.server)
	}
	// The client's password field is deliberately NOT parsed (Task 9.10):
	// the backend login7 always carries the RESOLVER password, so the
	// client's value is never inspected — only skipped.
}

// Version passthrough fix (2026-08-26): the proxy previously forced TDS 7.4
// into the backend login7 regardless of what the client declared. A legacy
// provider (SQLOLEDB declares 0x71000001) then received a LOGINACK for 7.4 —
// a version it cannot parse — surfacing as HeidiSQL's "DBMS version is less
// than 7.0.0". These tests pin the fix: the client's declared TDS version
// and packet size are parsed from LOGIN7 and rebuilt verbatim on the
// backend login.
func TestParseLogin7ClientFixedHeader(t *testing.T) {
	const legacyTDS = 0x71000001 // SQLOLEDB-era TDS 7.1
	const legacyPS = 8000
	pw := obfuscatePassword("ro_pw")
	msg := buildLogin7("legacy-host", "ro_user", "HeidiSQL", "mssql-test", "appdb", pw, legacyTDS, legacyPS)

	li, err := parseLogin7(msg)
	if err != nil {
		t.Fatal(err)
	}
	if li.tdsVersion != legacyTDS {
		t.Fatalf("tdsVersion = %#08x, want %#08x", li.tdsVersion, legacyTDS)
	}
	if li.packetSize != legacyPS {
		t.Fatalf("packetSize = %d, want %d", li.packetSize, legacyPS)
	}
}

func TestBuildLogin7VersionPassthroughBytes(t *testing.T) {
	// Legacy declaration survives verbatim...
	const legacyTDS = 0x71000001
	msg := buildLogin7("h", "u", "a", "s", "appdb", nil, legacyTDS, 8000)
	if got := binary.LittleEndian.Uint32(msg[4:8]); got != legacyTDS {
		t.Fatalf("backend login7 tdsVersion = %#08x, want %#08x (client's)", got, legacyTDS)
	}
	if got := binary.LittleEndian.Uint32(msg[8:12]); got != 8000 {
		t.Fatalf("backend login7 packetSize = %d, want 8000", got)
	}
	// ...and a modern client's declaration produces exactly the bytes the
	// pre-fix code hardcoded (7.4 / 4096) — modern providers are unaffected.
	modern := buildLogin7("h", "u", "a", "s", "appdb", nil, tdsVersion740, tdsPacketSize)
	if got := binary.LittleEndian.Uint32(modern[4:8]); got != tdsVersion740 {
		t.Fatalf("modern tdsVersion = %#08x, want %#08x", got, tdsVersion740)
	}
	if got := binary.LittleEndian.Uint32(modern[8:12]); got != tdsPacketSize {
		t.Fatalf("modern packetSize = %d, want %d", got, tdsPacketSize)
	}
}

func TestBuildLogin7RoundTrip(t *testing.T) {
	pw := obfuscatePassword("ro_pw")
	msg := buildLogin7("zerotrust-proxy", "ro_user", "zerotrust-proxy", "mssql-test", "appdb", pw, tdsVersion740, tdsPacketSize)
	li, err := parseLogin7(msg)
	if err != nil {
		t.Fatal(err)
	}
	if li.username != "ro_user" || li.database != "appdb" || li.hostname != "zerotrust-proxy" {
		t.Fatalf("round trip fields: %+v", li)
	}
	// Password round-trip is NOT asserted: the password field is
	// deliberately unparsed (Task 9.10 — resolver-password-only model).
	// Length field must equal the payload length.
	if int(msg[0])|int(msg[1])<<8 != len(msg) { // length field is LE here (login7)
		t.Fatalf("length field %d != payload %d", int(msg[0])|int(msg[1])<<8, len(msg))
	}
}

func TestScanLoginResponse(t *testing.T) {
	// ERROR + DONE(ERROR|FINAL): failed login.
	fail := []byte{0xAA, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	fail = append(fail, 0xFD, 0x02, 0x02, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0)
	done, ok, db := scanLoginResponse(fail)
	if !done || ok {
		t.Fatalf("error response: done=%v ok=%v", done, ok)
	}
	// LOGINACK + ENVCHANGE(db) + DONE(FINAL): success with database change.
	ack := []byte{0xAD, 0x0E, 0x00}
	ack = append(ack, make([]byte, 14)...)
	env := []byte{0xE3, 0x09, 0x00, 0x01, 0x05}
	for _, u := range []uint16{'a', 'p', 'p', 'd', 'b'} {
		env = append(env, byte(u), byte(u>>8))
	}
	env = append(env, 0x00) // old value: empty
	doneTok := []byte{0xFD, 0x00, 0x02, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	okResp := append(append(ack, env...), doneTok...)
	done, ok, db = scanLoginResponse(okResp)
	if !done || !ok || db != "appdb" {
		t.Fatalf("ok response: done=%v ok=%v db=%q", done, ok, db)
	}
	// Unknown token ends the scan.
	done, _, _ = scanLoginResponse([]byte{0x81, 0x00})
	if !done {
		t.Fatal("unknown token must end the scan")
	}
}
