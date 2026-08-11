package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"testing"
)

func TestMySQLPacketRoundTrip(t *testing.T) {
	lengths := []int{0, 1, 255, 65535, 0xFFFFFF - 1}
	for _, length := range lengths {
		length := length
		name := "len_" + strconv.Itoa(length)
		t.Run(name, func(t *testing.T) {
			payload := make([]byte, length)
			for i := range payload {
				payload[i] = byte(i * 31)
			}
			const seq = byte(0xAB)

			var buf bytes.Buffer
			if err := writeMySQLPacket(&buf, seq, payload); err != nil {
				t.Fatalf("writeMySQLPacket: %v", err)
			}

			// Header: 3-byte little-endian length + 1-byte sequence id.
			raw := buf.Bytes()
			var wantHdr [4]byte
			binary.LittleEndian.PutUint32(wantHdr[:], uint32(length))
			wantHdr[3] = seq
			if !bytes.Equal(raw[:4], wantHdr[:]) {
				t.Fatalf("header = %v, want %v", raw[:4], wantHdr)
			}
			if !bytes.Equal(raw[4:], payload) {
				t.Fatal("payload bytes after header do not match")
			}

			gotSeq, gotPayload, err := readMySQLPacket(&buf)
			if err != nil {
				t.Fatalf("readMySQLPacket: %v", err)
			}
			if gotSeq != seq {
				t.Fatalf("seq = %#x, want %#x", gotSeq, seq)
			}
			if !bytes.Equal(gotPayload, payload) {
				t.Fatal("round-trip payload mismatch")
			}
		})
	}
}

func TestMySQLPacketTruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{10, 0, 0, 0x01}) // header claims 10-byte payload
	buf.Write([]byte{1, 2, 3})        // only 3 bytes follow
	if _, _, err := readMySQLPacket(&buf); err == nil {
		t.Fatal("want error for truncated payload")
	} else if !strings.Contains(err.Error(), "read 10-byte payload") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMySQLPacketTruncatedHeader(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{1, 2}) // fewer than 4 header bytes
	if _, _, err := readMySQLPacket(&buf); err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}
