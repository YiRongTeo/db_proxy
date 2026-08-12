package proxy

import (
	"bytes"
	"encoding/binary"
)

// pgResultCapture is the PostgreSQL analogue of resultCapture: a passive
// state machine over backend→client messages in RAW wire framing — 1 byte
// message type + int32 length (big-endian, INCLUDING itself) + payload.
// feed() is called with the exact bytes that are relayed to the client
// (pgproto3 re-encodes every message byte-exact), BEFORE the relay write —
// bytes are only inspected, never modified.
//
// Completion signals, mirroring the MySQL side: 'C' CommandComplete and
// 'I' EmptyQueryResponse finish as status ok; 'E' ErrorResponse finishes as
// status error with the server's message. 'Z' ReadyForQuery does NOT finish
// the capture here — the relay uses it as a safety publish point instead.
type pgResultCapture struct {
	status    string // "", "ok", "error"
	errorMsg  string
	columns   []string
	rows      [][]string
	truncated bool
	bytes     int
	colCount  int
	stage     int // 0 = awaiting RowDescription, 1 = capturing rows
	doneFlag  bool
}

func (c *pgResultCapture) done() bool { return c == nil || c.doneFlag }
func (c *pgResultCapture) ok() bool   { return c != nil && c.status == "ok" }

func (c *pgResultCapture) finish() {
	if c.status == "" {
		c.status = "ok"
	}
	c.doneFlag = true
}

// feed inspects one raw backend→client message. msg is the full framed
// message: msg[0] = type byte, msg[1:5] = int32 length (including itself),
// msg[5:] = payload. The declared length must match the buffer (total size
// is length+1); malformed frames are ignored — capture must never crash or
// stall the relay.
func (c *pgResultCapture) feed(msg []byte) {
	if c.done() || len(msg) < 5 {
		return
	}
	if n := int(binary.BigEndian.Uint32(msg[1:5])); n+1 != len(msg) {
		return // length includes itself: total = 1 + length
	}
	payload := msg[5:]
	switch msg[0] {
	case 'T': // RowDescription
		if c.stage != 0 {
			return
		}
		names, count := parsePGFieldNames(payload)
		if count == 0 {
			return
		}
		c.columns = names
		c.colCount = count
		c.stage = 1
	case 'D': // DataRow
		// Extended protocol without a Describe message sends DataRow with
		// NO preceding RowDescription (column names are then unknown):
		// rows are accepted using their own column count. When a
		// RowDescription was seen, the row is validated against it.
		want := c.colCount
		if c.stage == 0 {
			want = 0
		}
		row, ok := parsePGDataRow(payload, want)
		if ok {
			if len(c.rows) < capMaxRows && c.bytes+len(msg) <= capMaxEvent {
				c.rows = append(c.rows, row)
				c.bytes += len(msg)
			} else {
				c.truncated = true
			}
		}
		c.stage = 1 // a DataRow starts the rows phase
		return
	case 'C': // CommandComplete
		c.finish()
	case 'E': // ErrorResponse
		c.status, c.errorMsg = "error", pgErrorMessage(payload)
		c.doneFlag = true
	case 'I': // EmptyQueryResponse
		c.finish()
	}
}

// parsePGFieldNames decodes a RowDescription payload: int16 field count,
// then per field a cstring name followed by the fixed 18-byte descriptor
// (int32 tableOid + int16 attnum + int32 typeOid + int16 typlen + int32
// typmod + int16 format) which is skipped — only names are captured.
func parsePGFieldNames(p []byte) ([]string, int) {
	if len(p) < 2 {
		return nil, 0
	}
	count := int(binary.BigEndian.Uint16(p))
	if count == 0 || count > 4096 { // defensive bound
		return nil, 0
	}
	names := make([]string, 0, count)
	off := 2
	for i := 0; i < count; i++ {
		end := bytes.IndexByte(p[off:], 0) // cstring name
		if end < 0 {
			return nil, 0
		}
		names = append(names, string(p[off:off+end]))
		off += end + 1
		if off+18 > len(p) { // skip the fixed field descriptor
			return nil, 0
		}
		off += 18
	}
	return names, count
}

// parsePGDataRow decodes a DataRow payload: int16 column count, then per
// column int32 length (-1 = SQL NULL → ""), then that many bytes. Cells are
// capped at capMaxCell chars (per-cell truncation does NOT set the
// truncated flag, mirroring the MySQL side); a row whose cell count does
// not match the captured column count is rejected.
func parsePGDataRow(p []byte, want int) ([]string, bool) {
	if len(p) < 2 {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(p))
	if count == 0 || (want > 0 && count != want) {
		return nil, false
	}
	row := make([]string, 0, count)
	off := 2
	for i := 0; i < count; i++ {
		if off+4 > len(p) {
			return nil, false
		}
		ln := int32(binary.BigEndian.Uint32(p[off:]))
		off += 4
		if ln == -1 { // NULL cell
			row = append(row, "")
			continue
		}
		if ln < 0 || off+int(ln) > len(p) {
			return nil, false
		}
		cell := string(p[off : off+int(ln)])
		off += int(ln)
		if len(cell) > capMaxCell {
			cell = cell[:capMaxCell] + "…"
		}
		row = append(row, cell)
	}
	return row, true
}

// pgErrorMessage extracts the 'M' (message) field from an ErrorResponse
// payload: a sequence of 1-byte type tags each followed by a cstring value,
// terminated by a zero tag. Messages are capped at 300 chars like the MySQL
// side.
func pgErrorMessage(p []byte) string {
	off := 0
	for off < len(p) {
		tag := p[off]
		off++
		if tag == 0 {
			break
		}
		end := bytes.IndexByte(p[off:], 0)
		if end < 0 {
			return ""
		}
		val := string(p[off : off+end])
		off += end + 1
		if tag == 'M' {
			if len(val) > 300 {
				val = val[:300]
			}
			return val
		}
	}
	return ""
}
