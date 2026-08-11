package proxy

import (
	"fmt"
	"io"
)

// MySQL packet: 3-byte little-endian payload length + 1-byte sequence id.

func readMySQLPacket(r io.Reader) (seq byte, payload []byte, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read %d-byte payload: %w", length, err)
	}
	return hdr[3], payload, nil
}

// writeMySQLPacket replays the original header (same seq) — byte-exact relay.
func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
