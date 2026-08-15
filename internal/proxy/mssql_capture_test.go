package proxy

// Task 9.3 unit tests for the MSSQL sniffing relay + result capture.
// Golden fixtures are VERBATIM captures from the live SQL Server 2022
// backend (mssql-test, 2026-08-15) and from the real sqlcmd v18 client
// (see .superpowers/sdd/PLAN/task-9.3-report.md for the dump provenance).

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// --- AllHeaders strip + SQL text extraction (golden) -----------------------

// hexBytes decodes a hex string into bytes (test fixture helper).
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// putUint64LE writes v as 8 little-endian bytes into b.
func putUint64LE(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// putUint32LE writes v as 4 little-endian bytes into b.
func putUint32LE(b []byte, v uint32) {
	for i := 0; i < 4; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// utf16le encodes a string as UTF-16LE bytes (fixture builder).
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

// allHeaders22 is the ALL_HEADERS block the real sqlcmd v18 sends on every
// SQL batch (captured verbatim 2026-08-15): TotalLength=22, HeaderLength=18,
// HeaderType=2 (transaction descriptor), 8-byte descriptor, outstanding
// request count.
var allHeaders22 = hexBytesFixture("16000000120000000200000000000000000001000000")

func hexBytesFixture(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// goldenSQLCmdBatch is the FULL 72-byte SQL batch payload captured from the
// real sqlcmd v18.6.2.1 (probe replay 2026-08-15): AllHeaders + UTF-16LE
// "SET QUOTED_IDENTIFIER OFF" (sqlcmd's first batch), NO trailing NUL.
var goldenSQLCmdBatch = hexBytesFixture(
	"16000000120000000200000000000000000001000000" +
		"5300450054002000510055004f005400450044005f004900440045004e0054004900460049004500520020004f0046004600")

func TestDecodeMSSQLBatchGoldenSQLCmd(t *testing.T) {
	sql, ok := decodeMSSQLBatch(goldenSQLCmdBatch)
	if !ok {
		t.Fatal("decodeMSSQLBatch returned ok=false")
	}
	if sql != "SET QUOTED_IDENTIFIER OFF" {
		t.Fatalf("SQL = %q, want %q", sql, "SET QUOTED_IDENTIFIER OFF")
	}
}

func TestDecodeMSSQLBatchGolden9_2Capture(t *testing.T) {
	// The 9.2 capture shape (dispatch): the AllHeaders prefix
	// `16 00 00 00 12 00 00 00 02 00 00 00` + an EMPTY client-procname
	// (B_VARCHAR length 0 — a single 0x00 byte), then UTF-16LE SQL.
	payload := append(append([]byte(nil), allHeaders22...), 0x00)
	payload = append(payload, utf16le("SELECT id, name FROM demo_items")...)
	sql, ok := decodeMSSQLBatch(payload)
	if !ok || sql != "SELECT id, name FROM demo_items" {
		t.Fatalf("9.2-capture shape: ok=%v sql=%q", ok, sql)
	}
}

func TestDecodeMSSQLBatchNoHeaders(t *testing.T) {
	// Bare UTF-16LE text (no ALL_HEADERS at all) — accepted.
	if sql, ok := decodeMSSQLBatch(utf16le("SELECT 1")); !ok || sql != "SELECT 1" {
		t.Fatalf("bare text: ok=%v sql=%q", ok, sql)
	}
	// Trailing NUL terminator (sqlcmd appends 00 00 to some batches).
	payload := append(utf16le("SELECT 1"), 0x00, 0x00)
	if sql, ok := decodeMSSQLBatch(payload); !ok || sql != "SELECT 1" {
		t.Fatalf("trailing NUL: ok=%v sql=%q", ok, sql)
	}
}

func TestDecodeMSSQLRPC(t *testing.T) {
	// RPC: AllHeaders + procname B_VARCHAR ("sp_executesql").
	payload := append(append([]byte(nil), allHeaders22...), byte(len("sp_executesql")))
	payload = append(payload, utf16le("sp_executesql")...)
	name, ok := decodeMSSQLRPC(payload)
	if !ok || name != "sp_executesql" {
		t.Fatalf("rpc: ok=%v name=%q", ok, name)
	}
	// Garbage payload → ok=false.
	if _, ok := decodeMSSQLRPC([]byte{0x01, 0x02}); ok {
		t.Fatal("short rpc payload must fail")
	}
}

// --- COLMETADATA/ROW/DONE parsing (golden from the live backend) -----------

// goldenSelectResponse is the VERBATIM 104-byte response to
// "SELECT id, name FROM demo_items" (captured live 2026-08-15):
// COLMETADATA(2: INT4 id, NVARCHAR(200) name) + 3 ROWs + DONE(status
// 0x0010 DONE_COUNT, curcmd 0x00c1, rowcount 3). The DONE carries NO
// DONE_FINAL bit — completion relies on message EOM (the live server's
// behavior).
var goldenSelectResponse = hexBytesFixture(
	"810200000000000800380269006400000000000900e7c8000904d00034046e0061006d006500" +
		"d10100000008007400650073007400" +
		"d1020000000a0062007200610076006f00" +
		"d1030000000e0063006800610072006c0069006500" +
		"fd1000c1000300000000000000")

func TestMSSQLCaptureGoldenSelect(t *testing.T) {
	c := &mssqlResultCapture{}
	c.feed(goldenSelectResponse, true) // single packet, EOM
	if !c.done() {
		t.Fatal("capture not done after EOM")
	}
	if c.status != "ok" {
		t.Fatalf("status = %q, want ok", c.status)
	}
	if !reflect.DeepEqual(c.columns, []string{"id", "name"}) {
		t.Fatalf("columns = %v", c.columns)
	}
	want := [][]string{{"1", "test"}, {"2", "bravo"}, {"3", "charlie"}}
	if !reflect.DeepEqual(c.rows, want) {
		t.Fatalf("rows = %v, want %v", c.rows, want)
	}
	if c.truncated {
		t.Fatal("truncated must be false")
	}
}

func TestMSSQLCaptureNotDoneBeforeEOM(t *testing.T) {
	// Without EOM the capture must NOT complete (multi-packet messages).
	c := &mssqlResultCapture{}
	c.feed(goldenSelectResponse, false)
	if c.done() {
		t.Fatal("capture completed before EOM")
	}
	if len(c.rows) != 3 {
		t.Fatalf("rows = %d, want 3 (parsing must still make progress)", len(c.rows))
	}
}

func TestMSSQLCaptureTokenAcrossPackets(t *testing.T) {
	// Split the golden response mid-ROW-token across two packets: the
	// capture must buffer the partial token and complete at the second
	// packet's EOM.
	c := &mssqlResultCapture{}
	split := 60
	c.feed(goldenSelectResponse[:split], false)
	if c.done() {
		t.Fatal("completed early")
	}
	c.feed(goldenSelectResponse[split:], true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if !reflect.DeepEqual(c.rows, [][]string{{"1", "test"}, {"2", "bravo"}, {"3", "charlie"}}) {
		t.Fatalf("rows = %v", c.rows)
	}
}

// goldenErrorResponse is the VERBATIM 132-byte response to
// "SELECT * FROM no_such_table_zz" (captured live 2026-08-15): an ERROR
// token (208: Invalid object name 'no_such_table_zz'., class 16) followed
// by a DONE with status 0x0002 (DONE_ERROR).
var goldenErrorResponse = hexBytesFixture(
	"aa7400d00000000110270049006e00760061006c006900640020006f0062006a0065006300740020006e0061006d006500200027006e006f005f0073007500630068005f007400610062006c0065005f007a007a0027002e000c3700390066006300310032006100630063003300360031000001000000" +
		"fd0200fd000000000000000000")

func TestMSSQLCaptureGoldenError(t *testing.T) {
	c := &mssqlResultCapture{}
	c.feed(goldenErrorResponse, true)
	if !c.done() {
		t.Fatal("error capture not done")
	}
	if c.status != "error" {
		t.Fatalf("status = %q, want error", c.status)
	}
	if c.errorMsg != "Invalid object name 'no_such_table_zz'." {
		t.Fatalf("errorMsg = %q", c.errorMsg)
	}
}

// goldenMultiResult is the VERBATIM 146-byte response to
// "SELECT id, name FROM demo_items WHERE id = 1; SELECT name FROM demo_items"
// (captured live 2026-08-15): two COLMETADATA/ROW groups separated by a
// DONE(status 0x0011 COUNT|MORE). The published event carries the LAST
// result set (last-result-set-wins).
var goldenMultiResult = hexBytesFixture(
	"810200000000000800380269006400000000000900e7c8000904d00034046e0061006d006500" +
		"d10100000008007400650073007400" +
		"fd1100c1000100000000000000" +
		"810100000000000900e7c8000904d00034046e0061006d006500" +
		"d108007400650073007400" +
		"d10a0062007200610076006f00" +
		"d10e0063006800610072006c0069006500" +
		"fd1000c1000300000000000000")

func TestMSSQLCaptureGoldenMultiResult(t *testing.T) {
	c := &mssqlResultCapture{}
	c.feed(goldenMultiResult, true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	// Last result set wins: only [name] with 3 rows.
	if !reflect.DeepEqual(c.columns, []string{"name"}) {
		t.Fatalf("columns = %v, want [name]", c.columns)
	}
	if !reflect.DeepEqual(c.rows, [][]string{{"test"}, {"bravo"}, {"charlie"}}) {
		t.Fatalf("rows = %v", c.rows)
	}
}

// goldenInsertResponse is the VERBATIM 26-byte response to
// "INSERT INTO demo_items VALUES (77, 'zzprobe'); DELETE …" (captured live
// 2026-08-15): two DONE tokens (0x0011, 0x0010) with rowcounts — no
// COLMETADATA, no rows.
var goldenInsertResponse = hexBytesFixture(
	"fd1100c3000100000000000000fd1000c4000100000000000000")

func TestMSSQLCaptureGoldenInsert(t *testing.T) {
	c := &mssqlResultCapture{}
	c.feed(goldenInsertResponse, true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if len(c.columns) != 0 || len(c.rows) != 0 {
		t.Fatalf("insert must capture no result set: cols=%v rows=%v", c.columns, c.rows)
	}
}

// goldenCountResponse is the VERBATIM 33-byte response to
// "SELECT COUNT(*) AS n FROM demo_items": COLMETADATA(INTN maxlen=4 "n") +
// ROW (LENGTH-PREFIXED int value `04 03 00 00 00` = 3 — proving the INTN
// 1-byte-length encoding) + DONE.
var goldenCountResponse = hexBytesFixture(
	"8101000000000001002604016e00" +
		"d10403000000" +
		"fd1000c1000100000000000000")

func TestMSSQLCaptureGoldenINTN(t *testing.T) {
	c := &mssqlResultCapture{}
	c.feed(goldenCountResponse, true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if !reflect.DeepEqual(c.rows, [][]string{{"3"}}) {
		t.Fatalf("rows = %v, want [[3]]", c.rows)
	}
}

// --- constructed streams (type table, NBCROW, PLP, caps) --------------------

// buildMetadata builds a COLMETADATA token from type-byte + name pairs.
// typeInfo carries the TYPE_INFO bytes (maxlen/collation/scale…) that
// follow the type byte; the caller is responsible for correctness.
func buildMetadata(t *testing.T, cols ...struct {
	typ      byte
	typeInfo []byte
	name     string
}) []byte {
	t.Helper()
	out := []byte{tdsTokenColMetadata, byte(len(cols)), 0}
	for _, c := range cols {
		out = append(out, 0x00, 0x00, 0x00, 0x00) // UserType
		out = append(out, 0x00, 0x00)             // Flags
		out = append(out, c.typ)
		out = append(out, c.typeInfo...)
		out = append(out, byte(len(c.name)))
		out = append(out, utf16le(c.name)...)
	}
	return out
}

func TestMSSQLCaptureNBCRow(t *testing.T) {
	// The captured NBCROW shape (live): type + null bitmap + values —
	// bitmap 0x02 → column 1 NULL, columns 0/2 carry USHORT lengths.
	meta := buildMetadata(t,
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0xE7, []byte{0x14, 0x00, 0x09, 0x04, 0xd0, 0x00, 0x34}, "a"},
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0xE7, []byte{0x14, 0x00, 0x09, 0x04, 0xd0, 0x00, 0x34}, "b"},
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0xE7, []byte{0x14, 0x00, 0x09, 0x04, 0xd0, 0x00, 0x34}, "c"},
	)
	row := []byte{tdsTokenNBCRow, 0x02, // bitmap: col1 NULL
		0x04, 0x00, 'x', 0x00, 'y', 0x00, // col0: "xy"
		0x02, 0x00, 'z', 0x00, // col2: "z"
	}
	done := []byte{tdsTokenDone, 0x10, 0x00, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	c := &mssqlResultCapture{}
	c.feed(append(append(meta, row...), done...), true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if !reflect.DeepEqual(c.columns, []string{"a", "b", "c"}) {
		t.Fatalf("columns = %v", c.columns)
	}
	if !reflect.DeepEqual(c.rows, [][]string{{"xy", "", "z"}}) {
		t.Fatalf("rows = %v", c.rows)
	}
}

func TestMSSQLCaptureNullMarkers(t *testing.T) {
	// INTN (0x26, lenPrefix) NULL = length 0; DATETIMEN (0x6F, bare) NULL
	// = single 0x00; var NULL = 0xFFFF.
	meta := buildMetadata(t,
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0x26, []byte{0x04}, "i"},
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0x6F, []byte{0x08}, "d"},
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0xE7, []byte{0x14, 0x00, 0x09, 0x04, 0xd0, 0x00, 0x34}, "s"},
	)
	row := []byte{tdsTokenRow,
		0x00,       // INTN NULL (length 0)
		0x00,       // DATETIMEN NULL (single 0x00)
		0xFF, 0xFF, // NVARCHAR NULL (USHORT 0xFFFF)
	}
	done := []byte{tdsTokenDone, 0x10, 0x00, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	c := &mssqlResultCapture{}
	c.feed(append(append(meta, row...), done...), true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if !reflect.DeepEqual(c.rows, [][]string{{"", "", ""}}) {
		t.Fatalf("rows = %v", c.rows)
	}
}

func TestMSSQLCapturePLP(t *testing.T) {
	// NVARCHAR(MAX) PLP cell: 8-byte total + 4-byte chunk len + data +
	// 0 terminator (captured live shape).
	meta := buildMetadata(t,
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0xE7, []byte{0xFF, 0xFF, 0x09, 0x04, 0xd0, 0x00, 0x34}, "p"},
	)
	payload := utf16le("ababababab")
	row := []byte{tdsTokenRow}
	var total [8]byte
	putUint64LE(total[:], uint64(len(payload)))
	row = append(row, total[:]...)
	var cl [4]byte
	putUint32LE(cl[:], uint32(len(payload)))
	row = append(row, cl[:]...)
	row = append(row, payload...)
	row = append(row, 0, 0, 0, 0) // chunk terminator
	done := []byte{tdsTokenDone, 0x10, 0x00, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	c := &mssqlResultCapture{}
	c.feed(append(append(meta, row...), done...), true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if !reflect.DeepEqual(c.rows, [][]string{{"ababababab"}}) {
		t.Fatalf("rows = %v", c.rows)
	}
}

func TestMSSQLCaptureDoneFinal(t *testing.T) {
	// A DONE_FINAL bit completes the capture even without EOM.
	c := &mssqlResultCapture{}
	c.feed(goldenSelectResponse[:len(goldenSelectResponse)-13], false)
	if c.done() {
		t.Fatal("completed before final DONE")
	}
	c.feed([]byte{tdsTokenDone, 0x10, 0x02, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}, false) // DONE_FINAL, no EOM
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
}

func TestMSSQLCaptureDoneError(t *testing.T) {
	// DONE with DONE_ERROR (0x0002) → status=error + fallback message.
	payload := []byte{tdsTokenRowCount, 0, 0, 0, 0, 0, 0, 0, 0} // ROWCOUNT skipped
	payload = append(payload, tdsTokenDone, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	c := &mssqlResultCapture{}
	c.feed(payload, false)
	if !c.done() || c.status != "error" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if !strings.Contains(c.errorMsg, "SQL Server reported an error") {
		t.Fatalf("errorMsg = %q", c.errorMsg)
	}
}

func TestMSSQLCaptureInfoSkipped(t *testing.T) {
	// INFO (0xAB) length-prefixed tokens are skipped without derailing.
	info := []byte{tdsTokenInfo, 0x06, 0x00, 0x45, 0x16, 0x00, 0x00, 0x02, 0x00}
	c := &mssqlResultCapture{}
	c.feed(append(append([]byte(nil), info...), goldenSelectResponse...), true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if len(c.rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(c.rows))
	}
}

func TestMSSQLCaptureRowCap(t *testing.T) {
	// >100 rows → exactly 100 captured + truncated.
	meta := buildMetadata(t,
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0x26, []byte{0x04}, "i"},
	)
	var stream []byte
	stream = append(stream, meta...)
	for i := 0; i < 105; i++ {
		stream = append(stream, tdsTokenRow, 0x04, byte(i), 0, 0, 0)
	}
	stream = append(stream, tdsTokenDone, 0x10, 0x00, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0)
	c := &mssqlResultCapture{}
	c.feed(stream, true)
	if len(c.rows) != capMaxRows {
		t.Fatalf("rows = %d, want %d", len(c.rows), capMaxRows)
	}
	if !c.truncated {
		t.Fatal("truncated must be set")
	}
}

func TestMSSQLCaptureCellCap(t *testing.T) {
	// A cell longer than capMaxCell chars is cut with the … suffix (per
	// cell — does NOT set truncated, mirroring the MySQL/PG captures).
	long := strings.Repeat("x", capMaxCell+50)
	meta := buildMetadata(t,
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0xE7, []byte{0xFF, 0xFF, 0x09, 0x04, 0xd0, 0x00, 0x34}, "s"},
	)
	pl := utf16le(long)
	row := []byte{tdsTokenRow}
	var total [8]byte
	putUint64LE(total[:], uint64(len(pl)))
	row = append(row, total[:]...)
	var cl [4]byte
	putUint32LE(cl[:], uint32(len(pl)))
	row = append(row, cl[:]...)
	row = append(row, pl...)
	row = append(row, 0, 0, 0, 0)
	done := []byte{tdsTokenDone, 0x10, 0x00, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	c := &mssqlResultCapture{}
	c.feed(append(append(meta, row...), done...), true)
	if len(c.rows) != 1 {
		t.Fatalf("rows = %d", len(c.rows))
	}
	cell := c.rows[0][0]
	wantCell := strings.Repeat("x", capMaxCell) + "…"
	if cell != wantCell {
		t.Fatalf("cell = %q (len %d), want %q", cell, len(cell), wantCell)
	}
	if c.truncated {
		t.Fatal("per-cell truncation must not set truncated")
	}
}

func TestMSSQLCaptureOverflowStallsThenCompletes(t *testing.T) {
	// A single token larger than capMaxEvent: parsing stalls but the
	// capture still completes at EOM with truncated=true.
	meta := buildMetadata(t,
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0xE7, []byte{0xFF, 0xFF, 0x09, 0x04, 0xd0, 0x00, 0x34}, "s"},
	)
	pl := utf16le(strings.Repeat("y", capMaxEvent))
	row := []byte{tdsTokenRow}
	var total [8]byte
	putUint64LE(total[:], uint64(len(pl)))
	row = append(row, total[:]...)
	var cl [4]byte
	putUint32LE(cl[:], uint32(len(pl)))
	row = append(row, cl[:]...)
	row = append(row, pl...)
	c := &mssqlResultCapture{}
	c.feed(meta, false)
	c.feed(row, false) // pushes past capMaxEvent → overflow
	if c.done() {
		t.Fatal("overflow must not complete the capture")
	}
	c.feed([]byte{tdsTokenDone, 0x10, 0x00, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}, true)
	if !c.done() || c.status != "ok" {
		t.Fatalf("done=%v status=%q", c.done(), c.status)
	}
	if !c.truncated {
		t.Fatal("truncated must be set after overflow")
	}
}

func TestMSSQLCaptureFloatBitInt(t *testing.T) {
	// FLTN 1.25 → "1.25"; BITN 1 → "1"; INT2 -2 → "-2".
	meta := buildMetadata(t,
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0x6D, []byte{0x08}, "f"},
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0x68, []byte{0x01}, "b"},
		struct {
			typ      byte
			typeInfo []byte
			name     string
		}{0x34, []byte{}, "s"},
	)
	row := []byte{tdsTokenRow,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x3f, // FLTN len 8, 1.25
		0x01, 0x01, // BITN len 1, 1
		0xfe, 0xff, // INT2 -2 (bare)
	}
	done := []byte{tdsTokenDone, 0x10, 0x00, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	c := &mssqlResultCapture{}
	c.feed(append(append(meta, row...), done...), true)
	if !reflect.DeepEqual(c.rows, [][]string{{"1.25", "1", "-2"}}) {
		t.Fatalf("rows = %v", c.rows)
	}
}

func TestClassifyMSSQLStmt(t *testing.T) {
	// The shared classifier reused for decoded TDS SQL text.
	cases := map[string]string{
		"SELECT id FROM demo_items":         "select",
		"INSERT INTO demo_items VALUES (1)": "insert",
		"  UPDATE demo_items SET x=1":       "update",
		"DELETE FROM demo_items":            "delete",
		"SET QUOTED_IDENTIFIER OFF":         "other",
		"EXEC sp_executesql":                "other",
	}
	for sql, want := range cases {
		if got := classifyStmt(sql); got != want {
			t.Errorf("classifyStmt(%q) = %q, want %q", sql, got, want)
		}
	}
}
