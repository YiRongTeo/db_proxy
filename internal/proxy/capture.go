package proxy

import "strings"

// classifyStmt returns select|insert|update|delete|other from the leading keyword.
func classifyStmt(sql string) string {
	s := strings.TrimSpace(sql)
	for strings.HasPrefix(s, "--") || strings.HasPrefix(s, "/*") || strings.HasPrefix(s, "#") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = strings.TrimSpace(s[i+1:])
		} else {
			return "other"
		}
	}
	kw := s
	if i := strings.IndexAny(kw, " \t\r\n("); i >= 0 {
		kw = kw[:i]
	}
	switch strings.ToUpper(kw) {
	case "SELECT":
		return "select"
	case "INSERT":
		return "insert"
	case "UPDATE":
		return "update"
	case "DELETE":
		return "delete"
	default:
		return "other"
	}
}

const (
	capMaxRows  = 100
	capMaxCell  = 512
	capMaxEvent = 64 << 10
)

// resultCapture is a passive state machine over backend→client packets.
// feed() is called AFTER readMySQLPacket, BEFORE the relay write — bytes are
// only inspected, never modified.
type resultCapture struct {
	status    string // "", "ok", "error"
	errorMsg  string
	columns   []string
	rows      [][]string
	truncated bool
	bytes     int
	colCount  int
	stage     int  // 0=column-count, 1=column-defs, 2=rows
	defsEOF   bool // classic protocol: EOF after column defs seen; rows follow
	doneFlag  bool
}

func (c *resultCapture) done() bool { return c == nil || c.doneFlag }
func (c *resultCapture) ok() bool   { return c != nil && c.status == "ok" }

func (c *resultCapture) feed(payload []byte) {
	if c.done() || len(payload) == 0 {
		return
	}
	b := payload[0]
	switch {
	case b == 0xff: // ERR packet
		c.status, c.errorMsg = "error", mysqlErrMessage(payload)
		c.doneFlag = true
		return
	case b == 0x00 && len(payload) >= 7: // OK packet
		c.finish()
		return
	case b == 0xfe && len(payload) < 9: // EOF or OK-like: ends col defs or rows
		if c.stage == 1 {
			c.stage = 2
			return
		}
		if c.stage == 2 {
			// The column-count check already moved stage to 2 when the last
			// column definition arrived, so a CLASSIC-protocol EOF after the
			// defs (5 bytes) is distinguishable from the EOF ending the rows
			// only by position: the defs EOF always comes first. An OK-like
			// packet (0xfe header, >= 7 bytes) is the DEPRECATE_EOF end of a
			// result set and always finishes the capture.
			if len(payload) >= 7 {
				c.finish()
				return
			}
			if len(c.rows) > 0 || c.defsEOF {
				c.finish()
				return
			}
			c.defsEOF = true // classic EOF after column defs: rows follow
			return
		}
		return
	}
	switch c.stage {
	case 0: // column-count packet (lenenc int)
		if b == 0xfb { // LOCAL INFILE — not captured
			return
		}
		n, _, ok := readLenencInt(payload, 0)
		if !ok || n == 0 {
			c.finish()
			return
		}
		c.colCount = int(n)
		c.stage = 1
	case 1: // column definition
		if b == 0xfb { // LOCAL INFILE — not captured
			return
		}
		if name, ok := mysqlColumnName(payload); ok {
			c.columns = append(c.columns, name)
		}
		if len(c.columns) >= c.colCount {
			c.stage = 2
		}
	case 2: // data row (TEXT protocol: lenenc cells, no leading count)
		row, consumed := parseMySQLRow(payload, c.colCount)
		if consumed > 0 {
			if len(c.rows) < capMaxRows && c.bytes+len(payload) <= capMaxEvent {
				c.rows = append(c.rows, row)
				c.bytes += len(payload)
			} else {
				c.truncated = true
			}
		}
	}
}

func (c *resultCapture) finish() {
	if c.status == "" {
		c.status = "ok"
	}
	c.doneFlag = true
}

func mysqlErrMessage(p []byte) string {
	if len(p) < 9 {
		return ""
	}
	m := string(p[9:])
	if len(m) > 300 {
		m = m[:300]
	}
	return m
}

// mysqlColumnName extracts the column NAME from a COLUMN_DEFINITION packet
// (lenenc walk: catalog schema table org_table NAME org_name + fixed 0x0c header).
func mysqlColumnName(p []byte) (string, bool) {
	off := 0
	for i := 0; i < 4; i++ { // catalog, schema, table, org_table
		start, n, ok := readLenencString(p, off)
		if !ok {
			return "", false
		}
		off = start + n
	}
	start, n, ok := readLenencString(p, off) // NAME
	if !ok {
		return "", false
	}
	return string(p[start : start+n]), true
}

func readLenencInt(p []byte, off int) (uint64, int, bool) {
	if off >= len(p) {
		return 0, 0, false
	}
	switch b := p[off]; {
	case b < 0xfb:
		return uint64(b), 1, true
	case b == 0xfb: // NULL
		return 0, 1, false
	case b == 0xfc:
		if off+3 > len(p) {
			return 0, 0, false
		}
		return uint64(p[off+1]) | uint64(p[off+2])<<8, 3, true
	case b == 0xfd:
		if off+4 > len(p) {
			return 0, 0, false
		}
		return uint64(p[off+1]) | uint64(p[off+2])<<8 | uint64(p[off+3])<<16, 4, true
	default: // 0xfe — 8-byte
		if off+9 > len(p) {
			return 0, 0, false
		}
		var v uint64
		for i := 1; i <= 8; i++ {
			v |= uint64(p[off+i]) << (8 * (i - 1))
		}
		return v, 9, true
	}
}

func readLenencString(p []byte, off int) (int, int, bool) {
	n, sz, ok := readLenencInt(p, off)
	if !ok || n > 1<<20 {
		return 0, 0, false
	}
	start := off + sz
	if start+int(n) > len(p) {
		return 0, 0, false
	}
	return start, int(n), true
}

// parseMySQLRow decodes a TEXT-protocol DataRow into cells. VERIFIED LIVE
// (2026-08-12, packet dump through the relay): text rows carry NO leading
// field-count byte — they are a plain sequence of lenenc strings (first byte
// is the first cell's length). Cells parse until the payload is exhausted;
// the count is validated against the captured column count when known.
// (A leading-count format is the BINARY protocol — not used here.)
func parseMySQLRow(p []byte, want int) ([]string, int) {
	if len(p) == 0 {
		return nil, 0
	}
	off := 0
	row := make([]string, 0, 8)
	for off < len(p) {
		if p[off] == 0xfb { // NULL cell
			row = append(row, "")
			off++
			continue
		}
		start, ln, ok := readLenencString(p, off)
		if !ok {
			return nil, 0
		}
		cell := string(p[start : start+ln])
		if len(cell) > capMaxCell {
			cell = cell[:capMaxCell] + "…"
		}
		row = append(row, cell)
		off = start + ln
	}
	if want > 0 && len(row) != want {
		return nil, 0
	}
	return row, off
}
