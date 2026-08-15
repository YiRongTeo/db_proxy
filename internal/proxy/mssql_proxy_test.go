package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// --- Task 9.2 unit tests: error-token shape, the 0x12-wrapping TLS seam,
// message fragmentation, and the kill-registry hooks. The LIVE tests
// (real backend + sqlcmd-shaped raw clients) live in zz_live_mssql_test.go
// (they write sess:live records, so they must run LAST in the binary).

// TestBuildLoginErrorShape pins the ERROR-token login-failure response: the
// 0xAA ERROR token (number 18456, state 1, class 14, UTF-16LE message with
// the US_VARCHAR length prefix, B_VARCHAR server/proc names, line number)
// followed by a 0xFD DONE token with the DONE_ERROR status bit (0x0002) —
// the shape the real SQL Server sends for a rejected login, and the shape
// sqlcmd renders as the canonical "Msg 18456 ... Login failed for user 'x'."
// failure.
func TestBuildLoginErrorShape(t *testing.T) {
	msg := "Login failed for user 'sess_deadbeef'."
	payload := buildLoginError(msg)
	if len(payload) < 3+14+2+12 {
		t.Fatalf("error payload too small: %d bytes", len(payload))
	}
	if payload[0] != 0xAA {
		t.Fatalf("first token = %#x, want ERROR (0xAA)", payload[0])
	}
	restLen := int(payload[1]) | int(payload[2])<<8
	if restLen != len(payload)-3-13 {
		t.Fatalf("ERROR length field = %d, want %d (rest of token, DONE excluded)", restLen, len(payload)-3-13)
	}
	number := binary.LittleEndian.Uint32(payload[3:7])
	if number != 18456 {
		t.Fatalf("error number = %d, want 18456", number)
	}
	if payload[7] != 1 || payload[8] != 14 {
		t.Fatalf("state/class = %d/%d, want 1/14", payload[7], payload[8])
	}
	// MsgText(US_VARCHAR) + ServerName(B_VARCHAR) + ProcName(B_VARCHAR)
	// + LineNumber(4) must exactly fill the declared length. Both string
	// lengths count UTF-16 code units — the captured real-server shape
	// (`20 00` = 32 chars for "Login failed for user 'ro_user'.").
	tail := payload[9 : 3+restLen]
	msgChars := int(binary.LittleEndian.Uint16(tail[0:2]))
	if msgChars != len(msg) {
		t.Fatalf("MsgText US_VARCHAR length = %d, want %d (UTF-16 code units, not bytes)", msgChars, len(msg))
	}
	msgBytes := msgChars * 2
	if len(tail) < 2+msgBytes+1+1+4 {
		t.Fatalf("token tail too short: %d", len(tail))
	}
	units := make([]uint16, msgChars)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(tail[2+2*i:])
	}
	if got := string(utf16.Decode(units)); got != msg {
		t.Fatalf("message = %q, want %q", got, msg)
	}
	rest := tail[2+msgBytes:]
	if int(rest[0])*2 != len(rest)-1-1-4 {
		t.Fatalf("servername B_VARCHAR length %d inconsistent with tail %d", rest[0], len(rest))
	}
	if rest[1+int(rest[0])*2] != 0 { // ProcName empty
		t.Fatalf("procname not empty")
	}
	if line := binary.LittleEndian.Uint32(rest[len(rest)-4:]); line != 1 {
		t.Fatalf("line number = %d, want 1", line)
	}
	// DONE token: 0xFD + status 0x0002 (DONE_ERROR only — the real
	// server's own shape, captured `fd 02 00` tail; the connection close
	// that follows is what ends the response) + curcmd + rowcount.
	done := payload[len(payload)-13:]
	if done[0] != 0xFD {
		t.Fatalf("closing token = %#x, want DONE (0xFD)", done[0])
	}
	if status := binary.LittleEndian.Uint16(done[1:3]); status != tdsDoneError {
		t.Fatalf("DONE status = %#x, want %#x (DONE_ERROR only)", status, tdsDoneError)
	}
	// The scan agrees: a login response made of this payload is a FAILED
	// login that has ENDED.
	done2, ok, _ := scanLoginResponse(payload)
	if !done2 || ok {
		t.Fatalf("scan: done=%v loginOK=%v, want true/false", done2, ok)
	}
}

// TestTDSConnSeamRoundTrip drives the 0x12-wrapping seam both ways: reads
// must strip TDS headers and present the contiguous TLS-record byte stream
// (records may span packets — the seam returns what one packet carries and
// the caller's io.ReadFull-style loop reassembles, exactly how tls.Conn
// consumes the seam), writes must wrap raw TLS records in 0x12 packets with
// EOM on the last fragment.
func TestTDSConnSeamRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	// Server writes two wrapped packets that together carry one "TLS
	// record" split across them.
	part1 := []byte("hello ")
	part2 := []byte("world-TLS-record")
	_ = writeTDSPacketStatus(&wire, tdsPrelogin, 0, part1) // no EOM
	_ = writeTDSPacketStatus(&wire, tdsPrelogin, tdsStatusEOM, part2)

	seam := &tdsTLSConn{Conn: nopConn{&wire}, br: bufio.NewReader(&wire)}
	want := "hello world-TLS-record"
	var got []byte
	buf := make([]byte, 64)
	for len(got) < len(want) {
		n, err := seam.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != want {
		t.Fatalf("seam read = %q, want the reassembled record stream", got)
	}

	// Write side: a raw TLS record comes back wrapped in 0x12 packets.
	seam2 := &tdsTLSConn{Conn: nopConn{&wire}, br: bufio.NewReader(&wire)}
	rec := bytes.Repeat([]byte{0x17}, 9000) // > one TDS packet
	if _, err := seam2.Write(rec); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(&wire)
	var assembled []byte
	packets := 0
	eomCount := 0
	for {
		typ, status, payload, err := readTDSPacket(br)
		if err != nil {
			t.Fatalf("read packet: %v", err)
		}
		if typ != tdsPrelogin {
			t.Fatalf("wrapped packet type = %#x, want 0x12", typ)
		}
		packets++
		assembled = append(assembled, payload...)
		if status&tdsStatusEOM != 0 {
			eomCount++
			break
		}
	}
	if !bytes.Equal(assembled, rec) {
		t.Fatalf("wrapped payload differs (%d vs %d bytes)", len(assembled), len(rec))
	}
	if packets != 3 || eomCount != 1 {
		t.Fatalf("packets=%d eom=%d, want 3/1 (9000 bytes at 4088 payload each)", packets, eomCount)
	}
}

// TestTDSConnSeamBarePassThrough pins the hybrid framing: a stream that
// starts with a non-0x12 byte (a bare TLS record — the post-handshake
// shape, and the mid-handshake shape some clients use under TLS 1.3) is
// handed through byte-identically, NOT mistaken for a TDS packet. The
// fail-closed property (a plaintext LOGIN7 on an ENCRYPT_ON connection)
// now lives in tls.Conn: it sees garbage and the handshake fails instead
// of silently downgrading.
func TestTDSConnSeamBarePassThrough(t *testing.T) {
	raw := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00}
	var wire bytes.Buffer
	_, _ = wire.Write(raw)
	seam := &tdsTLSConn{Conn: nopConn{&wire}, br: bufio.NewReader(&wire)}
	got := make([]byte, len(raw))
	if _, err := io.ReadFull(seam, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("bare pass-through = %x, want %x (byte-identical)", got, raw)
	}
}

// TestWriteTDSMessageFragments: a large logical message must fragment
// across TDS packets with the EOM bit on the last fragment only, and
// reassemble byte-identically through readTDSMessage.
func TestWriteTDSMessageFragments(t *testing.T) {
	var wire bytes.Buffer
	payload := bytes.Repeat([]byte{0xAB}, 10000)
	if err := writeTDSMessage(&wire, tdsTabular, payload); err != nil {
		t.Fatal(err)
	}
	typ, got, err := readTDSMessage(bufio.NewReader(&wire))
	if err != nil {
		t.Fatal(err)
	}
	if typ != tdsTabular || !bytes.Equal(got, payload) {
		t.Fatalf("assembled: typ=%#x len=%d, want 0x04/%d", typ, len(got), len(payload))
	}
}

// TestMSSQLKillHooks pins the Task 9.2 kill-registry contract (Task 6.4
// parity, mirror of TestSessionRegistryKillClosesBothConns): KillSession
// force-closes a registered session's conns and stays registered until the
// session goroutine's deferred unregister runs (so a repeat kill still
// reports true); unknown ids report false. KillQuery is refused (TDS
// cancels via ATTENTION in Task 9.4) with a warn but never touches the
// session.
func TestMSSQLKillHooks(t *testing.T) {
	var logBuf bytes.Buffer
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(&logBuf, nil)), nil, &ConfigCredResolver{}, nil)
	if p.KillSession("sid-no-such") {
		t.Fatal("KillSession on an unknown id returned true")
	}
	closed := false
	p.registerSession(&mssqlSession{id: "sid-1", closer: func() { closed = true }})
	if !p.KillSession("sid-1") {
		t.Fatal("KillSession on a registered session must return true")
	}
	if !closed {
		t.Fatal("closer not invoked")
	}
	// The entry stays registered until handleConn's deferred unregister
	// runs (there is no handleConn in this unit test), so a repeat kill
	// still reports the session — closing already-closed conns is a no-op.
	if !p.KillSession("sid-1") {
		t.Fatal("second KillSession on the still-registered session must return true")
	}
	p.registerSession(&mssqlSession{id: "sid-2"})
	if p.KillQuery("sid-2") {
		t.Fatal("KillQuery must be refused before Task 9.4")
	}
	if !strings.Contains(logBuf.String(), "not supported until task 9.4") {
		t.Fatalf("kill query warn missing: %s", logBuf.String())
	}
	if p.KillQuery("nope") {
		t.Fatal("KillQuery on an unknown session must return false")
	}
}

// nopConn is a minimal net.Conn adapter for the seam unit tests: reads and
// writes go straight to the shared buffer. The WRITE side must actually
// capture the bytes — the seam's Write calls the wrapped conn's Write, and
// the write-side assertion re-reads the buffer to verify the 0x12 wrapping.
type nopConn struct {
	r *bytes.Buffer
}

func (nopConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }
func (nopConn) Close() error                     { return nil }
func (c nopConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (c nopConn) Write(p []byte) (int, error)    { return c.r.Write(p) }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

var _ io.ReadWriteCloser = nopConn{}
