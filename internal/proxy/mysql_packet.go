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
// The header and payload are written in a SINGLE Write call so that each MySQL
// packet lands in exactly one TCP segment / one TLS record. Splitting into two
// Write calls produces two TLS records for one MySQL packet (4-byte header +
// payload), which breaks the mysql C client's SSL_read path ('Lost connection
// at reading authorization packet'). Task 9.10: the write is checked for
// short writes (n != len).
func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	buf := make([]byte, 4+len(payload))
	buf[0] = byte(len(payload))
	buf[1] = byte(len(payload) >> 8)
	buf[2] = byte(len(payload) >> 16)
	buf[3] = seq
	copy(buf[4:], payload)
	n, err := w.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}
