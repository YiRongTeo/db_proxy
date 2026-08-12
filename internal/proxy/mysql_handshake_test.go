package proxy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildHandshakeV10(t *testing.T) {
	serverVersion := "8.0.36"
	connID := uint32(42)
	authData := []byte("0123456789abcdefghij") // exactly 20 bytes
	if len(authData) != 20 {
		t.Fatalf("test auth data must be 20 bytes, got %d", len(authData))
	}

	p, err := buildHandshakeV10(serverVersion, connID, authData, advertisedCaps)
	if err != nil {
		t.Fatalf("buildHandshakeV10: %v", err)
	}

	// 1. protocol version byte (v10)
	if p[0] != 0x0a {
		t.Errorf("first byte = %#x, want 0x0a (protocol v10)", p[0])
	}

	// 2. auth plugin name present, NUL-terminated, at the end of the payload
	if !bytes.Contains(p, []byte("mysql_native_password")) {
		t.Errorf("handshake payload missing plugin name %q", "mysql_native_password")
	}
	if !bytes.HasSuffix(p, []byte("mysql_native_password\x00")) {
		t.Errorf("plugin name must be NUL-terminated at the end of the payload")
	}

	// walk the wire layout to locate the auth-plugin-data length byte
	pos := 1 // protocol version
	end := bytes.IndexByte(p[pos:], 0)
	if end < 0 {
		t.Fatal("server version not NUL-terminated")
	}
	pos += end + 1 // skip version string + NUL

	// connection id (4 bytes LE)
	if got := binary.LittleEndian.Uint32(p[pos : pos+4]); got != connID {
		t.Errorf("connection id = %d, want %d", got, connID)
	}
	pos += 4

	// auth-data part1 (8 bytes)
	if !bytes.Equal(p[pos:pos+8], authData[:8]) {
		t.Errorf("auth-data part1 = % x, want % x", p[pos:pos+8], authData[:8])
	}
	pos += 8

	// filler
	if p[pos] != 0x00 {
		t.Errorf("filler byte = %#x, want 0x00", p[pos])
	}
	pos++

	// capability flags, low 16 bits
	if got := binary.LittleEndian.Uint16(p[pos : pos+2]); got != uint16(advertisedCaps&0xffff) {
		t.Errorf("capability low = %#x, want %#x", got, uint16(advertisedCaps&0xffff))
	}
	pos += 2

	// charset
	if p[pos] != 33 {
		t.Errorf("charset = %d, want 33 (utf8_general_ci)", p[pos])
	}
	pos++

	// status flags
	if got := binary.LittleEndian.Uint16(p[pos : pos+2]); got != 2 {
		t.Errorf("status flags = %d, want 2 (SERVER_STATUS_AUTOCOMMIT)", got)
	}
	pos += 2

	// capability flags, high 16 bits
	if got := binary.LittleEndian.Uint16(p[pos : pos+2]); got != uint16(advertisedCaps>>16) {
		t.Errorf("capability high = %#x, want %#x", got, uint16(advertisedCaps>>16))
	}
	pos += 2

	// 3. auth-plugin-data length byte == 21 at the correct offset
	if p[pos] != 21 {
		t.Errorf("auth-plugin-data length at offset %d = %d, want 21", pos, p[pos])
	}
	pos++

	// reserved (10 bytes, all zero)
	if !bytes.Equal(p[pos:pos+10], make([]byte, 10)) {
		t.Errorf("reserved 10 bytes must be zero")
	}
	pos += 10

	// auth-data part2 (12 bytes) + NUL terminator
	if !bytes.Equal(p[pos:pos+12], authData[8:]) {
		t.Errorf("auth-data part2 = % x, want % x", p[pos:pos+12], authData[8:])
	}
	pos += 12
	if p[pos] != 0x00 {
		t.Errorf("auth-data terminator = %#x, want 0x00", p[pos])
	}

	// 4. total layout length
	wantLen := 1 + // protocol version
		len(serverVersion) + 1 + // version + NUL
		4 + // connection id
		8 + // auth-data part1
		1 + // filler
		2 + // caps low
		1 + // charset
		2 + // status
		2 + // caps high
		1 + // auth-plugin-data length
		10 + // reserved
		12 + // auth-data part2
		1 + // NUL
		len("mysql_native_password") + 1 // plugin name + NUL
	if len(p) != wantLen {
		t.Errorf("payload length = %d, want %d", len(p), wantLen)
	}
}

// handshakeCapBits walks the fixed handshake layout (past the version string)
// and returns the advertised capability flags as a single uint32.
func handshakeCapBits(t *testing.T, p []byte) uint32 {
	t.Helper()
	pos := 1 // protocol version
	end := bytes.IndexByte(p[pos:], 0)
	if end < 0 {
		t.Fatal("server version not NUL-terminated")
	}
	pos += end + 1 + 4 + 8 + 1 // version+NUL + conn id + auth part1 + filler
	low := binary.LittleEndian.Uint16(p[pos : pos+2])
	high := binary.LittleEndian.Uint16(p[pos+5 : pos+7]) // +2 caps-low, +1 charset, +2 status
	return uint32(low) | uint32(high)<<16
}

// TestBuildHandshakeV10SSLCap (Task 7.4): the SSL cap (0x0800) is included in
// the advertised caps exactly when the caller ORs it in — and the plaintext
// handshake (advertisedCaps alone) stays byte-identical to pre-TLS, i.e. the
// SSL bit is NOT present.
func TestBuildHandshakeV10SSLCap(t *testing.T) {
	authData := []byte("0123456789abcdefghij")

	// Plaintext: advertisedCaps only → no CLIENT_SSL bit, exact set preserved.
	plain, err := buildHandshakeV10("8.4.0-zerotrust-proxy", 7, authData, advertisedCaps)
	if err != nil {
		t.Fatalf("buildHandshakeV10 (plaintext): %v", err)
	}
	if got := handshakeCapBits(t, plain); got != advertisedCaps {
		t.Errorf("plaintext caps = %#x, want exactly %#x (byte-identical to pre-TLS)", got, advertisedCaps)
	}
	if handshakeCapBits(t, plain)&capSSL != 0 {
		t.Errorf("plaintext caps %#x must NOT include CLIENT_SSL 0x0800", handshakeCapBits(t, plain))
	}

	// TLS enabled: advertisedCaps|capSSL → the SSL bit is advertised.
	tlsCaps := advertisedCaps | capSSL
	secured, err := buildHandshakeV10("8.4.0-zerotrust-proxy", 7, authData, tlsCaps)
	if err != nil {
		t.Fatalf("buildHandshakeV10 (tls): %v", err)
	}
	if got := handshakeCapBits(t, secured); got&capSSL == 0 {
		t.Errorf("tls caps = %#x, want CLIENT_SSL 0x0800 set", got)
	}
	if got := handshakeCapBits(t, secured); got != tlsCaps {
		t.Errorf("tls caps = %#x, want exactly %#x", got, tlsCaps)
	}
}

// TestIsSSLRequest (Task 7.4): an SSLRequest-shaped payload (>= 32 bytes,
// CLIENT_SSL set in the first 4 bytes) is detected; a real auth response
// (same shape but no SSL bit) and short payloads are not.
func TestIsSSLRequest(t *testing.T) {
	// SSLRequest-shaped: caps + max packet + charset + 23 reserved = 32 bytes.
	sslReq := make([]byte, 32)
	binary.LittleEndian.PutUint32(sslReq[0:4], uint32(capSSL|capProtocol41))
	if !isSSLRequest(sslReq) {
		t.Error("isSSLRequest = false for 32-byte payload with CLIENT_SSL, want true")
	}

	// Auth-response-shaped: same layout but WITHOUT the SSL bit.
	authResp := make([]byte, 32)
	binary.LittleEndian.PutUint32(authResp[0:4], uint32(capProtocol41|capSecureConnection|capConnectWithDB))
	if isSSLRequest(authResp) {
		t.Error("isSSLRequest = true for auth-response-shaped payload without CLIENT_SSL, want false")
	}

	// Full real handshake response (longer than 32, no SSL bit).
	full := buildTestHandshakeResponse("sess_abc")
	if isSSLRequest(full) {
		t.Error("isSSLRequest = true for full handshake response without CLIENT_SSL, want false")
	}

	// Short payloads can never be an SSLRequest.
	if isSSLRequest(nil) || isSSLRequest([]byte{0x01, 0x02, 0x03}) {
		t.Error("isSSLRequest = true for short payload, want false")
	}

	// SSL bit present but payload shorter than 32 → not an SSLRequest.
	short := make([]byte, 31)
	binary.LittleEndian.PutUint32(short[0:4], uint32(capSSL))
	if isSSLRequest(short) {
		t.Error("isSSLRequest = true for 31-byte payload with CLIENT_SSL, want false")
	}
}

func TestBuildHandshakeV10RejectsBadAuthData(t *testing.T) {
	if _, err := buildHandshakeV10("8.0.36", 1, []byte("short"), advertisedCaps); err == nil {
		t.Error("expected error for auth data shorter than 20 bytes")
	}
	if _, err := buildHandshakeV10("8.0.36", 1, nil, advertisedCaps); err == nil {
		t.Error("expected error for nil auth data")
	}
}

func TestRandomAuthData(t *testing.T) {
	b, err := randomAuthData()
	if err != nil {
		t.Fatalf("randomAuthData: %v", err)
	}
	if len(b) != 20 {
		t.Fatalf("auth data length = %d, want 20", len(b))
	}
	for i, c := range b {
		if c == 0 {
			t.Errorf("auth data byte %d is NUL — scramble must not contain NUL", i)
		}
	}
}

func TestParseHandshakeResponse(t *testing.T) {
	auth := make([]byte, 20)
	for i := range auth {
		auth[i] = byte(i + 1)
	}
	// Raw capability bits, pinned deliberately: CLIENT_CONNECT_WITH_DB is 0x08
	// per the MySQL protocol. Do NOT substitute the capConnectWithDB constant —
	// a regression there (e.g. back to 0x10 = CLIENT_NO_SCHEMA) must fail this test.
	caps := uint32(capProtocol41 | capSecureConnection | 0x08)
	payload := binary.LittleEndian.AppendUint32(nil, caps)
	payload = binary.LittleEndian.AppendUint32(payload, 1<<24) // max packet size
	payload = append(payload, 33)                              // charset
	payload = append(payload, make([]byte, 23)...)             // reserved
	payload = append(payload, []byte("sess_abc")...)           // username = token
	payload = append(payload, 0x00)
	payload = append(payload, byte(len(auth))) // auth response length
	payload = append(payload, auth...)         // 20-byte auth response
	payload = append(payload, []byte("appdb")...)
	payload = append(payload, 0x00)

	username, database, err := parseHandshakeResponse(payload)
	if err != nil {
		t.Fatalf("parseHandshakeResponse: %v", err)
	}
	if username != "sess_abc" {
		t.Errorf("username = %q, want %q", username, "sess_abc")
	}
	if database != "appdb" {
		t.Errorf("database = %q, want %q", database, "appdb")
	}
}

func TestParseHandshakeResponseTooShort(t *testing.T) {
	if _, _, err := parseHandshakeResponse([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Error("expected error for payload shorter than 32 bytes")
	}
}

func TestParseHandshakeResponseNoProtocol41(t *testing.T) {
	payload := make([]byte, 32) // all-zero caps: no CLIENT_PROTOCOL_41
	if _, _, err := parseHandshakeResponse(payload); err == nil {
		t.Error("expected error when client does not support protocol 4.1")
	}
}

func TestParseHandshakeResponseTruncatedAuth(t *testing.T) {
	// caps claim CLIENT_SECURE_CONNECTION but the auth response length overruns
	payload := binary.LittleEndian.AppendUint32(nil, uint32(capProtocol41|capSecureConnection))
	payload = append(payload, make([]byte, 4+1+23)...) // max packet, charset, reserved
	payload = append(payload, []byte("sess_abc")...)
	payload = append(payload, 0x00)
	payload = append(payload, 20)   // claims 20 bytes...
	payload = append(payload, 0x01) // ...but only 1 present
	if _, _, err := parseHandshakeResponse(payload); err == nil {
		t.Error("expected error for truncated auth response")
	}
}

func TestErrPacket(t *testing.T) {
	p := errPacket(1045, "42000", "invalid or expired token")
	// MySQL ERR packet: 0xff + error code (LE uint16) + '#' + 5-byte SQLSTATE.
	// 1045 = 0x0415 → little-endian bytes 0x15, 0x04.
	want := []byte{0xff, 0x15, 0x04, '#', '4', '2', '0', '0', '0'}
	if !bytes.HasPrefix(p, want) {
		t.Errorf("errPacket prefix = % x, want % x", p, want)
	}
	if !bytes.HasSuffix(p, []byte("invalid or expired token")) {
		t.Errorf("errPacket must carry the message, got %q", p)
	}
}

func TestOkPacket(t *testing.T) {
	want := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	if got := okPacket(); !bytes.Equal(got, want) {
		t.Errorf("okPacket = % x, want % x", got, want)
	}
}
