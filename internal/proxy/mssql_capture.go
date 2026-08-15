package proxy

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"
	"unicode/utf16"
)

// mssqlResultCapture is the TDS analogue of resultCapture/pgResultCapture: a
// passive state machine over backend→client TABULAR RESULT token streams.
// feed() is called with each TDS packet's PAYLOAD (plus whether the packet
// carries the EOM status bit) BEFORE the relay write — bytes are only
// inspected, never modified.
//
// Token stream shape (MS-TDS 2.2.7, verified byte-for-byte against the live
// SQL Server 2022 backend — probes captured 2026-08-15):
//
//	COLMETADATA (0x81)  count + per column: UserType(4) Flags(2) TYPE_INFO
//	                    ColName(B_VARCHAR, UTF-16LE)
//	ROW (0xD1)          per column: NULL marker or type-encoded value
//	NBCROW (0xD2)       null-bitmap variant (bit set = NULL, no markers)
//	DONE (0xFD) / DONEPROC (0xFF) / DONEINPROC (0xFE)
//	                    status(2) curcmd(2) rowcount(8)
//	ERROR (0xAA)        number(4) state(1) class(1) MsgText(US_VARCHAR) …
//	INFO (0xAB)         informational message (ignored)
//	ROWCOUNT (0x7F)     affected-rows count (ignored)
//
// MULTI-RESULT BATCHES: one event is published per COMMAND (per SQL
// batch/RPC) carrying the LAST result set — a new COLMETADATA group while
// rows are already captured resets columns/rows (last-result-set-wins).
// This mirrors the MySQL/PG one-event-per-command semantics; the earlier
// result sets of a multi-statement batch are deliberately not published
// separately.
//
// COMPLETION (the live backend NEVER sets the DONE_FINAL bit on query
// responses — the final DONE carries DONE_COUNT only, and the message EOM
// is what real clients treat as the end of the response):
//   - ERROR token → status=error with the server message, capture done
//   - DONE-family with the DONE_ERROR (0x0002) or DONE_SRVERROR (0x0100)
//     status bit → status=error, capture done
//   - DONE with the DONE_FINAL bit (0x0200) → status=ok, capture done
//   - message EOM after at least one DONE-family token → status=ok (error
//     if an error was recorded), capture done
//
// TOKEN SPANNING PACKETS: feed() buffers partial tokens across packets and
// only consumes complete ones. A single token larger than capMaxEvent
// (a giant cell) stalls cell parsing — the capture still completes at
// message EOM with truncated=true (the published event shows what fit).
//
// CAPS (shared with the MySQL/PG captures): 100 rows, 512 chars per cell,
// 64 KB total captured row bytes; truncated flag set when any cap trips.
//
// BOUNDED TYPE TABLE (MS-TDS 2.2.5.1.1 — the nullable "-N" variants the
// live server sends for every nullable column; shapes captured live
// 2026-08-15):
//
//	fixed (bare value bytes; a nullable bare column encodes NULL as a
//	single 0x00 byte): INT1/INT2/INT4/INT8 (0x30/34/38/7F), BIT (0x32),
//	FLT4/FLT8 (0x3B/3E), MONEY/MONEY4 (0x3C/7A), DATETIME/DATETIME4
//	(0x3D/3A), GUID (0x24), DECIMAL/NUMERIC (0x37/3F — precision+scale;
//	value 4/8/12/16 bytes by precision), DATETIMEN (0x6F — the ONE
//	nullable variant whose value is bare)
//	fixed (1-byte LENGTH prefix, 0x00 = NULL): INTN (0x26), BITN (0x68),
//	FLTN (0x6D), MONEYN (0x6E), MONEY4N (0x6B), DECIMALN/NUMERICN
//	(0x6A/6C — maxlen+precision+scale), TIME/DATETIME2 (0x29/2A — scale;
//	value 3/4/5 bytes by scale), DATETIMEOFFSET (0x2B — scale+5)
//	var:     BIGVARCHAR/BIGCHAR/BIGVARBINARY/BIGBINARY (0xA7/AF/A5/AD —
//	          USHORT maxlen, char types + collation(5)), NVARCHAR/NCHAR
//	          (0xE7/EF — USHORT maxlen + collation(5)), legacy VARCHAR/
//	          VARBINARY (0x25/27 — ULONG maxlen)
//	plp:     TEXT/NTEXT/IMAGE (0x23/63/22 — ULONG maxlen), VARCHAR/CHAR/
//	          VARBINARY/BINARY/NVARCHAR/NCHAR with maxlen 0xFFFF, XML
//	          (0xF1 — schema byte + optional B_VARCHAR names), UDT (0xF0 —
//	          ULONG maxlen + B_VARCHAR names): 8-byte total length + chunks
//
// Row value encodings: fixed types — bare bytes or 1-byte length prefix
// (see above; NULL = 0x00 / length 0); var types — USHORT byte length,
// 0xFFFF = NULL; PLP — 8-byte total length (0xFFFF… = NULL) + 4-byte
// length-prefixed chunks terminated by a 0 chunk. NBCROW (0xD2) carries a
// null bitmap (one bit per column, LSB-first — bit i = column i, verified
// live: `d2 02 …` = column 1 NULL; NO column count) and omits NULL values
// entirely.
//
// Cell rendering: integers as signed decimals, BIT as 0/1, floats via
// strconv, UTF-16LE text types decoded to strings, everything else
// (binary, money, datetime, decimal-packed, GUID, UDT) as hex.
type mssqlResultCapture struct {
	status    string // "", "ok", "error"
	errorMsg  string
	columns   []string
	rows      [][]string
	truncated bool
	bytes     int
	cols      []tdsColType
	stage     int    // 0 = awaiting COLMETADATA, 1 = rows
	seenDone  bool   // ≥1 DONE-family token seen in the current message
	overflow  bool   // a token grew past capMaxEvent — parsing stalled
	buf       []byte // partial token bytes across packets
	doneFlag  bool
}

// tdsColType is the parsed TYPE_INFO of one result column — enough to walk
// ROW/NBCROW values and render cells.
type tdsColType struct {
	kind      byte // tdsFixed | tdsVar | tdsPlp
	size      int  // fixed byte size (0 = unknown)
	lenPrefix bool // fixed value carries a 1-byte length prefix (0x00 = NULL)
	utf16     bool // decode as UTF-16LE text
	ascii     bool // decode as raw string
	isInt     bool // render signed decimal
	isBit     bool // render 0/1
	isFloat   bool // render via strconv
}

const (
	tdsFixed = 1
	tdsVar   = 2
	tdsPlp   = 3
)

// TDS token type bytes (MS-TDS 2.2.7).
const (
	tdsTokenRow           = 0xD1
	tdsTokenNBCRow        = 0xD2
	tdsTokenColMetadata   = 0x81
	tdsTokenDone          = 0xFD
	tdsTokenDoneProc      = 0xFF
	tdsTokenDoneInProc    = 0xFE
	tdsTokenError         = 0xAA
	tdsTokenInfo          = 0xAB
	tdsTokenEnvChange     = 0xE3
	tdsTokenSessionState  = 0xE4
	tdsTokenRowCount      = 0x7F
	tdsTokenReturnStatus  = 0x79
	tdsTokenOffset        = 0x78
	tdsTokenReturnValue   = 0xAC
	tdsTokenLoginAck      = 0xAD
	tdsTokenFeatureExtAck = 0xAE
	tdsTokenOrder         = 0xA9
	tdsTokenColInfo       = 0xA1
	tdsTokenTabName       = 0xA4
	tdsTokenSSPI          = 0xED
)

// DONE status bits beyond the ones in mssql_packet.go (DONE_ERROR 0x0002,
// DONE_FINAL 0x0200).
const tdsDoneSRVError = 0x0100

func (c *mssqlResultCapture) done() bool { return c == nil || c.doneFlag }
func (c *mssqlResultCapture) ok() bool   { return c != nil && c.status == "ok" }

func (c *mssqlResultCapture) finish() {
	if c.status == "" {
		c.status = "ok"
	}
	c.doneFlag = true
}

// feed processes one packet payload; eom marks the EOM (last packet) of a
// logical message. Called with the exact bytes relayed to the client.
func (c *mssqlResultCapture) feed(payload []byte, eom bool) {
	if c.done() || len(payload) == 0 {
		return
	}
	if len(c.buf)+len(payload) > capMaxEvent {
		// A single token larger than the event cap: keep the bytes we
		// have, drop the rest, stall parsing. The capture still completes
		// at message EOM (overflow rule) with truncated=true.
		c.overflow = true
		c.truncated = true
		return
	}
	c.buf = append(c.buf, payload...)
	for !c.done() && !c.overflow && len(c.buf) > 0 {
		consumed, complete := c.parseToken()
		if !complete {
			break // need more bytes
		}
		c.buf = c.buf[consumed:]
	}
	if eom && (c.seenDone || c.overflow) {
		c.finish()
	}
}

// parseToken consumes one complete token from c.buf. Returns the consumed
// byte count and whether the token was complete (false = need more bytes or
// the token type is unknown — parsing stalls until EOM/flush).
func (c *mssqlResultCapture) parseToken() (int, bool) {
	b := c.buf[0]
	switch b {
	case tdsTokenColMetadata:
		return c.parseColMetadata()
	case tdsTokenRow:
		return c.parseRow(false)
	case tdsTokenNBCRow:
		return c.parseRow(true)
	case tdsTokenDone, tdsTokenDoneProc, tdsTokenDoneInProc:
		return c.parseDone()
	case tdsTokenError:
		return c.parseError()
	case tdsTokenRowCount, tdsTokenOffset: // fixed 9-byte tail (1 + 8)
		if len(c.buf) < 9 {
			return 0, false
		}
		return 9, true
	case tdsTokenReturnStatus: // fixed 5-byte tail (1 + 4)
		if len(c.buf) < 5 {
			return 0, false
		}
		return 5, true
	case tdsTokenInfo, tdsTokenEnvChange, tdsTokenSessionState,
		tdsTokenReturnValue, tdsTokenLoginAck, tdsTokenFeatureExtAck,
		tdsTokenOrder, tdsTokenColInfo, tdsTokenTabName, tdsTokenSSPI:
		// Length-prefixed tokens: type(1) + length(2, LE) + data.
		if len(c.buf) < 3 {
			return 0, false
		}
		l := int(binary.LittleEndian.Uint16(c.buf[1:3]))
		if len(c.buf) < 3+l {
			return 0, false
		}
		return 3 + l, true
	default:
		// Unknown token type — no safe skip. Stop parsing; completion
		// still happens at message EOM (seenDone) or flush-on-close.
		return 0, false
	}
}

// parseColMetadata walks a COLMETADATA token. A new metadata group resets
// the captured result set (last-result-set-wins for multi-result batches).
func (c *mssqlResultCapture) parseColMetadata() (int, bool) {
	if len(c.buf) < 3 {
		return 0, false
	}
	count := int(binary.LittleEndian.Uint16(c.buf[1:3]))
	off := 3
	if count == 0xFFFF { // no metadata sent
		c.cols, c.columns, c.stage = nil, nil, 1
		return off, true
	}
	if count == 0 || count > 4096 { // defensive bound
		return 0, false
	}
	cols := make([]tdsColType, 0, count)
	names := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if off+7 > len(c.buf) { // UserType(4) + Flags(2) + type(1)
			return 0, false
		}
		t := c.buf[off+6]
		off += 7
		ct, n, ok := parseTDSColType(t, c.buf, off)
		if !ok {
			return 0, false
		}
		off = n
		// ColName: B_VARCHAR — 1-byte length in UTF-16 code units + data.
		if off+1 > len(c.buf) {
			return 0, false
		}
		nl := int(c.buf[off])
		off++
		if nl > 0 {
			if off+2*nl > len(c.buf) {
				return 0, false
			}
			names = append(names, utf16String(c.buf[off:off+2*nl]))
			off += 2 * nl
		} else {
			names = append(names, "")
		}
		cols = append(cols, ct)
	}
	c.cols = cols
	c.columns = names
	c.rows = nil
	c.bytes = 0
	c.stage = 1
	return off, true
}

// parseTDSColType parses the TYPE_INFO of one column (the byte after the
// 7-byte UserType+Flags prefix) and returns the type plus the number of
// TYPE_INFO bytes consumed. ok=false aborts the metadata walk.
func parseTDSColType(t byte, buf []byte, off int) (tdsColType, int, bool) {
	need := func(n int) bool { return off+n <= len(buf) }
	ml1 := func() (int, bool) { // 1-byte maxlen
		if !need(1) {
			return 0, false
		}
		return int(buf[off]), true
	}
	ml2 := func() (int, bool) { // 2-byte maxlen
		if !need(2) {
			return 0, false
		}
		return int(binary.LittleEndian.Uint16(buf[off:])), true
	}
	ml4 := func() (int, bool) { // 4-byte maxlen
		if !need(4) {
			return 0, false
		}
		return int(binary.LittleEndian.Uint32(buf[off:])), true
	}
	collation := func() bool { // 5-byte collation
		if !need(5) {
			return false
		}
		return true
	}
	switch t {
	// Fixed-size non-nullable types (no TYPE_INFO data). ROW values are
	// bare bytes; a NULLABLE column of these types never appears on the
	// wire — the server promotes it to the -N variant below.
	case 0x30: // INT1
		return tdsColType{kind: tdsFixed, size: 1, isInt: true}, off, true
	case 0x32: // BIT
		return tdsColType{kind: tdsFixed, size: 1, isBit: true}, off, true
	case 0x34: // INT2
		return tdsColType{kind: tdsFixed, size: 2, isInt: true}, off, true
	case 0x38: // INT4
		return tdsColType{kind: tdsFixed, size: 4, isInt: true}, off, true
	case 0x7F: // INT8
		return tdsColType{kind: tdsFixed, size: 8, isInt: true}, off, true
	case 0x3A: // DATETIME4
		return tdsColType{kind: tdsFixed, size: 4}, off, true
	case 0x3B: // FLT4
		return tdsColType{kind: tdsFixed, size: 4, isFloat: true}, off, true
	case 0x3C: // MONEY
		return tdsColType{kind: tdsFixed, size: 8}, off, true
	case 0x3D: // DATETIME
		return tdsColType{kind: tdsFixed, size: 8}, off, true
	case 0x3E: // FLT8
		return tdsColType{kind: tdsFixed, size: 8, isFloat: true}, off, true
	case 0x7A: // MONEY4
		return tdsColType{kind: tdsFixed, size: 4}, off, true
	case 0x24: // GUID
		return tdsColType{kind: tdsFixed, size: 16}, off, true
	// NULLABLE fixed variants with a 1-byte maxlen. ROW values are
	// LENGTH-PREFIXED (1 byte; 0x00 = NULL) — verified live for every
	// variant below (2026-08-15 probes) EXCEPT DATETIMEN (0x6F), whose
	// value is bare 8 bytes with a single-0x00 NULL marker.
	case 0x26: // INTN
		ml, ok := ml1()
		if !ok {
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsFixed, size: ml, lenPrefix: true, isInt: true}, off + 1, true
	case 0x68: // BITN
		ml, ok := ml1()
		if !ok {
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsFixed, size: ml, lenPrefix: true, isBit: true}, off + 1, true
	case 0x6D: // FLTN
		ml, ok := ml1()
		if !ok {
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsFixed, size: ml, lenPrefix: true, isFloat: true}, off + 1, true
	case 0x6E: // MONEYN
		ml, ok := ml1()
		if !ok {
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsFixed, size: ml, lenPrefix: true}, off + 1, true
	case 0x6B: // MONEY4N
		ml, ok := ml1()
		if !ok {
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsFixed, size: ml, lenPrefix: true}, off + 1, true
	case 0x6F: // DATETIMEN — bare 8 bytes, single-0x00 NULL marker
		ml, ok := ml1()
		if !ok {
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsFixed, size: ml}, off + 1, true
	case 0x6A, 0x6C: // DECIMALN / NUMERICN: maxlen + precision + scale
		if !need(3) {
			return tdsColType{}, 0, false
		}
		ml := int(buf[off])
		return tdsColType{kind: tdsFixed, size: ml, lenPrefix: true}, off + 3, true
	case 0x37, 0x3F: // DECIMAL / NUMERIC (non-nullable): precision + scale
		if !need(2) {
			return tdsColType{}, 0, false
		}
		p := int(buf[off])
		size := 4
		switch {
		case p > 28:
			size = 16
		case p > 19:
			size = 12
		case p > 9:
			size = 8
		}
		return tdsColType{kind: tdsFixed, size: size}, off + 2, true
	case 0x29, 0x2A, 0x2B: // TIME / DATETIME2 / DATETIMEOFFSET: scale(1),
		// value 3/4/5 bytes (+5 offset bytes) — length-prefixed (live)
		if !need(1) {
			return tdsColType{}, 0, false
		}
		sc := int(buf[off])
		size := 3
		if sc > 2 {
			size++
		}
		if sc > 4 {
			size++
		}
		if t == 0x2B {
			size += 5
		}
		return tdsColType{kind: tdsFixed, size: size, lenPrefix: true}, off + 1, true
	// Variable-length types.
	case 0xA5, 0xAD: // BIGVARBINARY / BIGBINARY
		ml, ok := ml2()
		if !ok {
			return tdsColType{}, 0, false
		}
		if ml == 0xFFFF { // (max) → PLP encoding
			return tdsColType{kind: tdsPlp}, off + 2, true
		}
		return tdsColType{kind: tdsVar}, off + 2, true
	case 0xA7, 0xAF: // BIGVARCHAR / BIGCHAR
		ml, ok := ml2()
		if !ok || !collation() {
			return tdsColType{}, 0, false
		}
		if ml == 0xFFFF {
			return tdsColType{kind: tdsPlp, ascii: true}, off + 7, true
		}
		return tdsColType{kind: tdsVar, ascii: true}, off + 7, true
	case 0xE7, 0xEF: // NVARCHAR / NCHAR
		ml, ok := ml2()
		if !ok || !collation() {
			return tdsColType{}, 0, false
		}
		if ml == 0xFFFF {
			return tdsColType{kind: tdsPlp, utf16: true}, off + 7, true
		}
		return tdsColType{kind: tdsVar, utf16: true}, off + 7, true
	case 0x25, 0x27: // legacy VARCHAR / VARBINARY: ULONG maxlen
		ml, ok := ml4()
		if !ok {
			return tdsColType{}, 0, false
		}
		if t == 0x25 {
			if !collation() {
				return tdsColType{}, 0, false
			}
			return tdsColType{kind: tdsVar, ascii: true}, off + 9, true
		}
		_ = ml
		return tdsColType{kind: tdsVar}, off + 4, true
	// PLP types.
	case 0x22: // IMAGE
		if !need(4) {
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsPlp}, off + 4, true
	case 0x23: // TEXT
		if !need(9) { // ULONG maxlen + collation(5)
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsPlp, ascii: true}, off + 9, true
	case 0x63: // NTEXT
		if !need(9) {
			return tdsColType{}, 0, false
		}
		return tdsColType{kind: tdsPlp, utf16: true}, off + 9, true
	case 0xF1: // XML: schema-present byte + optional B_VARCHAR names
		if !need(1) {
			return tdsColType{}, 0, false
		}
		off++
		if buf[off-1] == 0x01 {
			for i := 0; i < 3; i++ { // db, schema, name
				if off+1 > len(buf) {
					return tdsColType{}, 0, false
				}
				nl := int(buf[off])
				off++
				if off+2*nl > len(buf) {
					return tdsColType{}, 0, false
				}
				off += 2 * nl
			}
		}
		return tdsColType{kind: tdsPlp, utf16: true}, off, true
	case 0xF0: // UDT: ULONG maxlen + db/schema/name B_VARCHARs
		if !need(4) {
			return tdsColType{}, 0, false
		}
		off += 4
		for i := 0; i < 3; i++ {
			if off+1 > len(buf) {
				return tdsColType{}, 0, false
			}
			nl := int(buf[off])
			off++
			if off+2*nl > len(buf) {
				return tdsColType{}, 0, false
			}
			off += 2 * nl
		}
		return tdsColType{kind: tdsPlp}, off, true
	default:
		return tdsColType{}, 0, false
	}
}

// parseRow consumes one ROW/NBCROW token and appends the rendered cells to
// the captured rows (subject to the caps). nbc selects the null-bitmap
// variant: NBCROW = type + null bitmap (one bit per column, LSB-first — bit
// i = column i; NO column count field — verified live) + values; a set bit
// means the column is NULL and carries no value bytes at all.
func (c *mssqlResultCapture) parseRow(nbc bool) (int, bool) {
	if c.stage == 0 {
		// A row before any metadata: the column types are unknown — skip
		// the token type byte; the walker will stall on the next unknown
		// byte and completion happens at EOM/flush.
		return 1, true
	}
	off := 1
	var bitmap []byte
	if nbc {
		nb := (len(c.cols) + 7) / 8
		if len(c.buf) < off+nb {
			return 0, false
		}
		bitmap = c.buf[off : off+nb]
		off += nb
	}
	row := make([]string, 0, len(c.cols))
	tokenLen := off
	for i, ct := range c.cols {
		// NULL markers: NBCROW → bitmap bit; ROW + fixed type → length
		// prefix 0x00 (lenPrefix types) or a single 0x00 byte (bare
		// types); var/PLP types carry their own NULL lengths.
		if nbc {
			if bitmap[i/8]&(1<<(i%8)) != 0 { // LSB-first: bit i = column i (live-captured d2 02 = col1 NULL)
				row = append(row, "")
				continue
			}
		} else if ct.kind == tdsFixed && !ct.lenPrefix {
			if len(c.buf) < off+1 {
				return 0, false
			}
			if c.buf[off] == 0x00 { // bare nullable fixed NULL marker
				off++
				row = append(row, "")
				continue
			}
		}
		var cell string
		switch ct.kind {
		case tdsFixed:
			if ct.lenPrefix {
				if len(c.buf) < off+1 {
					return 0, false
				}
				ln := int(c.buf[off])
				off++
				if ln == 0 { // NULL
					row = append(row, "")
					continue
				}
				if ln != ct.size {
					return 0, false // inconsistent stream — stall
				}
			}
			if len(c.buf) < off+ct.size {
				return 0, false
			}
			cell = renderTDSFixed(c.buf[off:off+ct.size], ct)
			off += ct.size
		case tdsVar:
			if len(c.buf) < off+2 {
				return 0, false
			}
			ln := int(binary.LittleEndian.Uint16(c.buf[off:]))
			off += 2
			if ln == 0xFFFF { // NULL
				row = append(row, "")
				continue
			}
			if len(c.buf) < off+ln {
				return 0, false
			}
			cell = renderTDSBytes(c.buf[off:off+ln], ct)
			off += ln
		case tdsPlp:
			if len(c.buf) < off+8 {
				return 0, false
			}
			total := binary.LittleEndian.Uint64(c.buf[off:])
			off += 8
			if total == 0xFFFFFFFFFFFFFFFF { // NULL
				row = append(row, "")
				continue
			}
			var data []byte
			for {
				if len(c.buf) < off+4 {
					return 0, false
				}
				cl := int(binary.LittleEndian.Uint32(c.buf[off:]))
				off += 4
				if cl == 0 {
					break
				}
				if len(c.buf) < off+cl {
					return 0, false
				}
				if len(data) < capMaxCell*4 { // bound accumulation; keep consuming
					data = append(data, c.buf[off:off+cl]...)
				}
				off += cl
			}
			cell = renderTDSBytes(data, ct)
		default:
			return 0, false
		}
		if len(cell) > capMaxCell {
			cell = cell[:capMaxCell] + "…"
		}
		row = append(row, cell)
	}
	tokenLen = off // all paths (incl. NULL continues) advance off
	if len(c.rows) < capMaxRows && c.bytes+tokenLen <= capMaxEvent {
		c.rows = append(c.rows, row)
		c.bytes += tokenLen
	} else {
		c.truncated = true
	}
	return tokenLen, true
}

// parseDone consumes a DONE-family token: status(2) curcmd(2) rowcount(8).
func (c *mssqlResultCapture) parseDone() (int, bool) {
	if len(c.buf) < 13 {
		return 0, false
	}
	status := binary.LittleEndian.Uint16(c.buf[1:3])
	c.seenDone = true
	if status&tdsDoneError != 0 || status&tdsDoneSRVError != 0 {
		if c.status == "" {
			c.status = "error"
		}
		if c.errorMsg == "" {
			c.errorMsg = "SQL Server reported an error"
		}
		c.doneFlag = true
	} else if status&tdsDoneFinal != 0 {
		c.finish()
	}
	return 13, true
}

// parseError consumes an ERROR token and completes the capture with
// status=error and the server's message (the first ERROR token wins).
// Layout: number(4) state(1) class(1) MsgText(US_VARCHAR — USHORT length in
// UTF-16 code units) ServerName(B_VARCHAR) ProcName(B_VARCHAR) Line(4).
func (c *mssqlResultCapture) parseError() (int, bool) {
	if len(c.buf) < 3 {
		return 0, false
	}
	l := int(binary.LittleEndian.Uint16(c.buf[1:3]))
	if len(c.buf) < 3+l {
		return 0, false
	}
	if c.status == "" {
		c.status = "error"
		if l >= 11 {
			mlen := int(binary.LittleEndian.Uint16(c.buf[9:11]))
			if 11+2*mlen <= 3+l {
				c.errorMsg = utf16String(c.buf[11 : 11+2*mlen])
				if len(c.errorMsg) > 300 {
					c.errorMsg = c.errorMsg[:300]
				}
			}
		}
	}
	c.doneFlag = true
	return 3 + l, true
}

// renderTDSFixed renders a fixed-size cell value.
func renderTDSFixed(b []byte, ct tdsColType) string {
	switch {
	case ct.isInt:
		var v uint64
		for i := len(b) - 1; i >= 0; i-- {
			v = v<<8 | uint64(b[i])
		}
		if len(b) < 8 && b[len(b)-1]&0x80 != 0 { // sign-extend
			v |= ^uint64(0) << (8 * uint(len(b)))
		}
		return strconv.FormatInt(int64(v), 10)
	case ct.isBit:
		if len(b) > 0 && b[0] != 0 {
			return "1"
		}
		return "0"
	case ct.isFloat:
		if len(b) == 4 {
			return strconv.FormatFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(b))), 'g', -1, 32)
		}
		if len(b) == 8 {
			return strconv.FormatFloat(math.Float64frombits(binary.LittleEndian.Uint64(b)), 'g', -1, 64)
		}
		return hex.EncodeToString(b)
	case ct.utf16:
		return utf16String(b)
	case ct.ascii:
		return string(b)
	default:
		return hex.EncodeToString(b)
	}
}

// renderTDSBytes renders a variable-length/PLP cell value.
func renderTDSBytes(b []byte, ct tdsColType) string {
	switch {
	case ct.utf16:
		return utf16String(b)
	case ct.ascii:
		return string(b)
	default:
		return hex.EncodeToString(b)
	}
}

// utf16String decodes a little-endian UTF-16 byte slice.
func utf16String(b []byte) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(units))
}

// decodeMSSQLBatch extracts the UTF-16LE SQL text from a SQL batch (0x01)
// payload. Layout (verified against the real sqlcmd v18 batch, captured
// 2026-08-15): ALL_HEADERS (self-describing — TotalLength bytes) followed
// by the optional empty client-procname (a single 0x00 B_VARCHAR length
// byte; the 9.2 capture shape) and the SQL text. Clients that send the
// text without ANY headers are handled too. The text may carry a trailing
// NUL terminator (stripped). A leading NUL byte after the headers is
// skipped as the empty-procname marker — real SQL text never starts with
// one. Non-empty client-procnames are NOT skipped (a capture limitation —
// the length byte is indistinguishable from text; ODBC sends these only
// for RPCs, which decodeMSSQLRPC handles).
func decodeMSSQLBatch(payload []byte) (string, bool) {
	off := 0
	if len(payload) >= 4 {
		if total := int(binary.LittleEndian.Uint32(payload)); total >= 8 && total <= len(payload) {
			off = total // ALL_HEADERS present — skip the whole block
			if off < len(payload) && payload[off] == 0x00 {
				off++ // empty client-procname (B_VARCHAR length 0)
			}
		}
	}
	text := payload[off:]
	// A second leading NUL (some clients pad the procname slot) is skipped
	// too; real SQL text never starts with a NUL character.
	for len(text) > 0 && text[0] == 0x00 {
		text = text[1:]
	}
	// Strip the trailing NUL terminator (00 00, or a lone trailing 00).
	for len(text) >= 2 && text[len(text)-2] == 0x00 && text[len(text)-1] == 0x00 {
		text = text[:len(text)-2]
	}
	if len(text) == 1 && text[0] == 0x00 {
		text = nil
	}
	if len(text) == 0 {
		return "", true
	}
	return utf16String(text), true
}

// decodeMSSQLRPC extracts the stored-procedure name from an RPC (0x03)
// payload: ALL_HEADERS, then the ProcName as a B_VARCHAR (1-byte length in
// UTF-16 code units + UTF-16LE name), then option flags and parameters
// (ignored). RPCs are classified by proc name (Task 9.3 brief); the
// parameter stream (e.g. sp_executesql's SQL text) is deliberately not
// parsed. A leading NUL after the headers (the empty-procname marker some
// clients pad, mirroring decodeMSSQLBatch) is skipped.
func decodeMSSQLRPC(payload []byte) (string, bool) {
	off := 0
	if len(payload) >= 4 {
		if total := int(binary.LittleEndian.Uint32(payload)); total >= 8 && total <= len(payload) {
			off = total
		}
	}
	if off < len(payload) && payload[off] == 0x00 {
		off++ // empty client-procname marker (B_VARCHAR length 0)
	}
	if off+1 > len(payload) {
		return "", false
	}
	nl := int(payload[off])
	off++
	if nl == 0 || off+2*nl > len(payload) {
		return "", false
	}
	name := utf16String(payload[off : off+2*nl])
	if name == "" {
		return "", false
	}
	return name, true
}
