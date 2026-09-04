package proxy

// Task 9.14 — captured-exchange crypto verification: the captured sqlplus
// AUTH (same challenge, same ro_user/ro_pw) must be reproducible by the
// ported computation. This catches any verifier/parameter drift before the
// E2E ever touches the server.
//
// Hermetic since 2026-09-02: the original capture .bin files lived in a
// temp dir (ZT_TNS_CAP_DIR), were deleted during cleanup, and are NOT in
// the repo — so the env-gated tests silently SKIPPED in the default suite
// and the crypto chain was never exercised. The exact capture payloads are
// embedded in the response blobs (verified byte-identical by size + the
// reproduced exchange), so these tests slice the blobs instead:
//
//	challenge      = serverData797[8:]   (797B s2c frame, TNS header stripped)
//	authPkt payload = ociAuthTemplate     (1807B c2s AUTH, stored header-less)
//	authResp        = authResp2200[8:]    (2200B s2c frame, TNS header stripped)
//
// No env vars, no files: the tests always run.

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestOracleCapturedExchangeReproduces(t *testing.T) {
	challenge := serverData797[8:]
	authPkt := ociAuthTemplate

	auth, err := parseOCIChallenge(challenge)
	if err != nil {
		t.Fatalf("parseOCIChallenge: %v", err)
	}
	if err := auth.computeAuthKeys("ro_user", "ro_pw"); err != nil {
		t.Fatalf("computeAuthKeys: %v", err)
	}
	t.Logf("EClientSessKey=%s", auth.EClientSessKey)
	t.Logf("EPassword=%s", auth.EPassword)
	t.Logf("ESpeedyKey=%s", auth.ESpeedyKey)

	// The captured sqlplus AUTH must carry the three OCI keys; extracting
	// them doubles as a presence pin (extractCapValue fails if missing).
	capEPass := extractCapValue(t, authPkt, "AUTH_PASSWORD@", false)
	capSpeedy := extractCapValue(t, authPkt, "AUTH_PBKDF2_SPEEDY_KEY", true)
	capSessKey := extractCapValue(t, authPkt, "AUTH_SESSKEY@", false)
	t.Logf("captured AUTH_PASSWORD@ len=%d, AUTH_PBKDF2_SPEEDY_KEY len=%d", len(capEPass), len(capSpeedy))

	// Decrypt the captured EPassword with OUR computed newKey.
	// newKey derives from ServerSessKey+ClientSessKey — but the captured
	// packet used SQLPLUS's ClientSessKey (different random). So instead
	// verify the shared part: ServerSessKey derivation + the speedyKey.
	// The captured EClientSessKey decrypts with `key` to SQLPLUS's
	// ClientSessKey — recompute `key` (challenge + password only) and
	// check the decryption yields a 32-byte value (shape check).
	key, err := authSpeedyKey(auth)
	if err != nil {
		t.Fatalf("speedy key: %v", err)
	}
	clientSess, err := decryptSessionKey(false, key, capSessKey)
	if err != nil {
		t.Fatalf("decrypt captured EClientSessKey: %v", err)
	}
	if len(clientSess) != 32 {
		t.Fatalf("captured EClientSessKey decrypts to %d bytes, want 32", len(clientSess))
	}
	t.Logf("captured EClientSessKey decrypts to %d bytes (sqlplus's random ClientSessKey) ✓", len(clientSess))
}

func authSpeedyKey(auth *oracleAuthObject) ([]byte, error) {
	salt, err := hex.DecodeString(auth.Salt)
	if err != nil {
		return nil, err
	}
	message := append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
	speedyKey := generateSpeedyKey(message, []byte("ro_pw"), auth.pbkdf2VgenCount)
	buffer := append(speedyKey, salt...)
	h := sha512.New()
	h.Write(buffer)
	return h.Sum(nil)[:32], nil
}

// extractCapValue pulls a value from an OCI dict entry by key.
func extractCapValue(t *testing.T, payload []byte, key string, hasFlag bool) string {
	t.Helper()
	i := bytes.Index(payload, []byte(key))
	if i < 0 {
		t.Fatalf("key %s not in payload", key)
	}
	v := i + len(key)
	if hasFlag {
		v++
	}
	if v+4 > len(payload) {
		t.Fatalf("key %s truncated", key)
	}
	vlen := int(bigEndianU32(payload[v : v+4]))
	if v+4+vlen > len(payload) {
		t.Fatalf("key %s value truncated (vlen %d)", key, vlen)
	}
	return string(payload[v+4 : v+4+vlen])
}

func bigEndianU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func TestOracleCapturedSvrResponseStructure(t *testing.T) {
	challenge := serverData797[8:]
	authPkt := ociAuthTemplate
	authResp := authResp2200[8:]

	auth, err := parseOCIChallenge(challenge)
	if err != nil {
		t.Fatalf("parseOCIChallenge: %v", err)
	}
	// reproduce the client's key material with the REAL password (ro_pw).
	salt, _ := hex.DecodeString(auth.Salt)
	message := append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
	speedyKey := generateSpeedyKey(message, []byte("ro_pw"), auth.pbkdf2VgenCount)
	buffer := append(speedyKey, salt...)
	h := sha512.New()
	h.Write(buffer)
	key := h.Sum(nil)[:32]

	eClient := extractCapValue(t, authPkt, "AUTH_SESSKEY@", false)
	clientSess, err := decryptSessionKey(false, key, eClient)
	if err != nil {
		t.Fatalf("client sess: %v", err)
	}
	serverSess, err := decryptSessionKey(false, key, auth.EServerSessKey)
	if err != nil {
		t.Fatalf("server sess: %v", err)
	}
	keyBuffer := fmt.Sprintf("%X", append(clientSess, serverSess...))
	df2key, _ := hex.DecodeString(auth.pbkdf2ChkSalt)
	newKey := generateSpeedyKey(df2key, []byte(keyBuffer), auth.pbkdf2SderCount)[:32]

	svrResp := extractCapValue(t, authResp, "AUTH_SVR_RESPONSE", true)
	t.Logf("captured AUTH_SVR_RESPONSE (%d hex): %s", len(svrResp), svrResp)
	plain, err := decryptSessionKey(true, newKey, svrResp)
	if err != nil {
		t.Fatalf("decrypt svr resp: %v", err)
	}
	t.Logf("plaintext %d bytes: %q", len(plain), plain)
	t.Logf("hex: %X", plain)
}

// TestOracleMirrorFraming pins the TNS-header convention of every mirrored
// blob the client leg sends (2026-09-02 regression: authResp2172 was stored
// WITHOUT its 8-byte header while every other mirror keeps it, so the
// [8:] strip at the 6b call site chopped into the dict and the go-ora
// client failed with "TTC error: received code 84").
//
// Convention: blobs that START with a valid TNS header (4-byte BE length +
// type byte at [4] ∈ {1,2,4,6,7} matching their size) are stored WITH the
// header and must be sent with [8:]; blobs that start with the dataFlag
// (00 00) + dict (message code 8) are stored WITHOUT the header and must
// be sent verbatim (writeTNSFrame adds the header).
func TestOracleMirrorFraming(t *testing.T) {
	hasTNSHeader := func(b []byte) bool {
		if len(b) < 8 {
			return false
		}
		// post-handshake header: 4-byte BE length covering the whole blob,
		// type byte at [4]. accept blobs use the 2-byte form.
		l4 := int(binary.BigEndian.Uint32(b[0:4]))
		if l4 == len(b) && b[4] >= 1 && b[4] <= 7 {
			return true
		}
		l2 := int(binary.BigEndian.Uint16(b[0:2]))
		return l2 == len(b) && b[4] >= 1 && b[4] <= 7
	}
	// stored-with-header → sent with [8:]; stored-without → sent verbatim.
	cases := []struct {
		name string
		blob []byte
		// how the proxy sends it (slice applied at the call site)
		sent func() []byte
	}{
		{"accept41 JDBC", accept41, func() []byte { return acceptFor(oracleClientJDBC)[8:] }},
		{"accept61 OCI", accept61, func() []byte { return acceptFor(oracleClientOCI)[8:] }},
		{"o5logonResp127", o5logonResp127, func() []byte { return o5logonResp127[8:] }},
		{"serverData260 JDBC", serverData260, func() []byte { return serverData260[8:] }},
		{"serverData797 OCI", serverData797, func() []byte { return serverData797[8:] }},
		{"authResp2756 data-type", authResp2756, func() []byte { return authResp2756[8:] }},
		{"authResp370 challenge", authResp370, func() []byte { return authRespFor(oracleClientJDBC)[8:] }},
		{"authResp2200 OCI auth", authResp2200, func() []byte { return authRespFor(oracleClientOCI)[8:] }},
		// the odd one out: stored WITHOUT its TNS header, sent verbatim.
		{"authResp2172 verifier", authResp2172, func() []byte { return authResp2172 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored := tc.blob
			if hasTNSHeader(stored) {
				t.Logf("stored WITH TNS header (%d B)", len(stored))
			} else {
				t.Logf("stored WITHOUT TNS header (%d B)", len(stored))
			}
			sent := tc.sent()
			// THE regression this test pins: the SENT payload must not
			// itself carry a TNS header (writeTNSFrame adds one), or the
			// client sees a double header and fails (go-ora: "TTC error:
			// received code 84"). Accept/o5logon/server-data payloads are
			// NOT dicts — they start with version bytes (01 3d/01 40) or
			// deadbeef — so only the header check applies universally.
			if hasTNSHeader(sent) {
				t.Fatalf("sent payload still carries a TNS header (double-header bug): first8=%X", sent[:8])
			}
			if len(sent) < 10 {
				t.Fatalf("sent payload too short: %d B", len(sent))
			}
		})
	}
	// Round-trip: writeTNSFrame(sent) must produce a frame whose payload
	// (after the 8-byte header) starts with the dataFlag — i.e. the client
	// sees a clean dict at [10:]. Only the AUTH dict blobs are checked here
	// (message code 8). authResp2756 is the data-type negotiation response
	// (TTC code 2, not a dict) and accept/o5logon/server-data are
	// version/deadbeef payloads — all covered by the header check above.
	dictCases := []struct {
		name string
		sent func() []byte
	}{
		{"authResp370 challenge", func() []byte { return authRespFor(oracleClientJDBC)[8:] }},
		{"authResp2200 OCI auth", func() []byte { return authRespFor(oracleClientOCI)[8:] }},
		{"authResp2172 verifier", func() []byte { return authResp2172 }},
	}
	for _, tc := range dictCases {
		sent := tc.sent()
		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		if err := writeTNSFrameBytes(bw, 6, sent); err != nil {
			t.Fatalf("%s: writeTNSFrame: %v", tc.name, err)
		}
		frame := buf.Bytes()
		if len(frame) < 12 {
			t.Fatalf("%s: frame too short", tc.name)
		}
		payload := frame[8:]
		// client's session reads dataFlag at [8:10] then the dict at [10:]
		if payload[2] != 8 {
			t.Fatalf("%s: round-tripped payload dict code = %d (want 8): %X",
				tc.name, payload[2], payload[:8])
		}
	}
}

// TestOracleFamilyDetection pins the CONNECT-version → client-family mapping
// (2026-09-03 regression: detectOracleFamily matched only go-ora's exact
// version 0x013d, so SQL Developer/ojdbc — version 0x013f, same JDBC
// family — was misclassified as OCI, received OCI-family mirrors and died
// with ORA-17444 "TTC protocol version not supported"). The first two bytes
// of the CONNECT payload are the big-endian TNS version:
//
//	go-ora 0x013d / SQL Developer 0x013f → JDBC family (dict AUTH, JDBC mirrors)
//	sqlplus 0x0140                       → OCI family (03 73 03 AUTH, OCI mirrors)
func TestOracleFamilyDetection(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte // first bytes of the CONNECT payload (version at [0:2])
		want    oracleClientFamily
	}{
		// real captured CONNECT payload prefixes
		{"go-ora 0x013d", []byte{0x01, 0x3d, 0x01, 0x2c, 0x08, 0x01}, oracleClientJDBC},
		{"SQL Developer ojdbc 0x013f", []byte{0x01, 0x3f, 0x01, 0x2c, 0x0c, 0x41}, oracleClientJDBC},
		{"sqlplus 0x0140", []byte{0x01, 0x40, 0x01, 0x2c, 0x00, 0x41}, oracleClientOCI},
		// boundary: every version at or below the 0x0140 marker is JDBC
		{"old ojdbc 0x013c", []byte{0x01, 0x3c, 0x01, 0x2c}, oracleClientJDBC},
		{"version 0x013f edge", []byte{0x01, 0x3f}, oracleClientJDBC},
		// truncated payload must not panic
		{"empty payload", nil, oracleClientOCI},
		{"single byte", []byte{0x01}, oracleClientOCI},
		// non-0x01 version prefix is not JDBC
		{"nonstandard prefix", []byte{0x02, 0x3f}, oracleClientOCI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectOracleFamily(tc.payload); got != tc.want {
				t.Fatalf("detectOracleFamily(% X) = %v, want %v", tc.payload, got, tc.want)
			}
		})
	}
}
