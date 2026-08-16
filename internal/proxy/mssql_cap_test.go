package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// writeTDSTestPacket writes one raw TDS packet (header + payload) to w,
// mirroring the wire shape readTDSPacket/readTDSFrame expect: type byte,
// status byte, BIG-ENDIAN length, SPID 0, packet id 1, window 0.
func writeTDSTestPacket(w io.Writer, typ, status byte, payload []byte) {
	hdr := make([]byte, tdsHeaderLen)
	hdr[0] = typ
	hdr[1] = status
	binary.BigEndian.PutUint16(hdr[2:4], uint16(tdsHeaderLen+len(payload)))
	hdr[6] = 1
	_, _ = w.Write(append(hdr, payload...))
}

// TestReadTDSMessageRejectsOversized proves the pre-auth message assembly
// (PRELOGIN / LOGIN7) is capped: an endless multi-packet stream cannot grow
// the buffer past tdsMaxHandshakeMsg (review 2026-08-17 — the handshake
// deadline bounds it in time only, which is not enough). Bounded messages
// still assemble normally.
func TestReadTDSMessageRejectsOversized(t *testing.T) {
	old := tdsMaxHandshakeMsg
	tdsMaxHandshakeMsg = 1024
	defer func() { tdsMaxHandshakeMsg = old }()

	var buf bytes.Buffer
	// 800 + 800 = 1600 payload bytes across two packets, no EOM until the
	// second — total exceeds the cap before the message completes.
	writeTDSTestPacket(&buf, tdsPrelogin, 0, make([]byte, 800))
	writeTDSTestPacket(&buf, tdsPrelogin, tdsStatusEOM, make([]byte, 800))
	if _, _, err := readTDSMessage(bufio.NewReader(&buf)); err == nil {
		t.Fatal("oversized pre-auth message accepted, want error")
	}

	// Control: 800 + 100 = 900 payload ≤ cap assembles fine.
	buf.Reset()
	writeTDSTestPacket(&buf, tdsPrelogin, 0, make([]byte, 800))
	writeTDSTestPacket(&buf, tdsPrelogin, tdsStatusEOM, make([]byte, 100))
	if _, payload, err := readTDSMessage(bufio.NewReader(&buf)); err != nil {
		t.Fatalf("bounded pre-auth message rejected: %v", err)
	} else if len(payload) != 900 {
		t.Fatalf("assembled %d payload bytes, want 900", len(payload))
	}
}

// TestReadTDSMessageFramesRejectsOversized proves the relay-phase message
// assembly (readTDSMessageFrames) is capped too: an authenticated client
// streaming endless frames cannot grow the held message without bound
// (review 2026-08-17).
func TestReadTDSMessageFramesRejectsOversized(t *testing.T) {
	old := tdsMaxRelayMsg
	tdsMaxRelayMsg = 1024
	defer func() { tdsMaxRelayMsg = old }()

	var buf bytes.Buffer
	writeTDSTestPacket(&buf, tdsSQLBatch, 0, make([]byte, 800))
	writeTDSTestPacket(&buf, tdsSQLBatch, tdsStatusEOM, make([]byte, 800))
	if _, _, err := readTDSMessageFrames(bufio.NewReader(&buf)); err == nil {
		t.Fatal("oversized relay message accepted, want error")
	}

	// Control: a single EOM frame under the cap assembles as one message.
	buf.Reset()
	writeTDSTestPacket(&buf, tdsSQLBatch, tdsStatusEOM, make([]byte, 800))
	frames, typ, err := readTDSMessageFrames(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("bounded relay message rejected: %v", err)
	}
	if typ != tdsSQLBatch || len(frames) != 1 || len(frames[0].payload) != 800 {
		t.Fatalf("frames=%d typ=%#x payload=%d, want 1 frame / 0x01 / 800", len(frames), typ, len(frames[0].payload))
	}
}
