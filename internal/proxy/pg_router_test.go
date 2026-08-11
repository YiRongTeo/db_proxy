package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"zerotrust-proxy/internal/models"
)

// The credential-key format ("<ip>:<port>:<db_user>") is shared with the
// MySQL backend and already covered by TestBackendKeyFormat
// (mysql_router_test.go); the PG missing-creds test below exercises the same
// backendKey lookup through the PG code path.

func TestConnectPostgresBackendMissingCreds(t *testing.T) {
	tok := &models.TokenPayload{DBIP: "127.0.0.1", DBPort: "5433", DBUser: "ro_user"}
	_, err := connectPostgresBackend(context.Background(), tok, map[string]string{}, "appdb")
	if err == nil {
		t.Fatal("expected error for missing credential key")
	}
	if !strings.Contains(err.Error(), "no credentials for 127.0.0.1:5433:ro_user") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestConnectPostgresBackendLiveRoundTrip is a skip-free LIVE integration
// test against the pg-test container (127.0.0.1:5433, ro_user/ro_pw, db
// appdb). It proves the hijacked raw byte stream is clean and usable
// end-to-end: pgx consumed the full auth handshake, SyncConn drained any
// internal read buffer, and the raw conn now carries a fresh client→server
// exchange byte-for-byte (any leftover buffered bytes would corrupt the very
// first frame read back).
func TestConnectPostgresBackendLiveRoundTrip(t *testing.T) {
	tok := &models.TokenPayload{DBIP: "127.0.0.1", DBPort: "5433", DBUser: "ro_user"}
	creds := map[string]string{"127.0.0.1:5433:ro_user": "ro_pw"}

	f, err := connectPostgresBackend(context.Background(), tok, creds, "appdb")
	if err != nil {
		t.Fatalf("connectPostgresBackend: %v", err)
	}
	defer f.Close()

	// Raw wire round-trip #1: Simple Query ('Q') "SELECT 1" written straight
	// to the hijacked conn, response read as raw frames.
	writePGQuery(t, f.conn, "SELECT 1")
	resp := readPGQueryResponse(t, f.conn)
	if resp.errMsg != "" {
		t.Fatalf("backend error: %s", resp.errMsg)
	}
	if !resp.rowDesc || !resp.dataRow {
		t.Fatalf("SELECT 1 response missing RowDescription/DataRow: %+v", resp)
	}
	if !bytes.Contains(resp.dataRowPayload, []byte("1")) {
		t.Errorf("DataRow %q does not contain value 1", resp.dataRowPayload)
	}
	if !strings.Contains(resp.cmdComplete, "SELECT 1") {
		t.Errorf("CommandComplete %q does not contain %q", resp.cmdComplete, "SELECT 1")
	}
	if !resp.ready {
		t.Fatalf("SELECT 1 response missing ReadyForQuery: %+v", resp)
	}

	// Raw wire round-trip #2: the caller-supplied database (here "appdb")
	// reached the backend — current_database() must report it.
	writePGQuery(t, f.conn, "SELECT current_database()")
	resp2 := readPGQueryResponse(t, f.conn)
	if resp2.errMsg != "" {
		t.Fatalf("backend error: %s", resp2.errMsg)
	}
	if !resp2.dataRow || !bytes.Contains(resp2.dataRowPayload, []byte("appdb")) {
		t.Errorf("current_database() DataRow %q does not contain %q", resp2.dataRowPayload, "appdb")
	}
	if !resp2.ready {
		t.Fatalf("current_database() response missing ReadyForQuery: %+v", resp2)
	}
}

// TestConnectPostgresBackendForwardsDatabase proves the CLIENT-requested
// database is forwarded to the backend connection (Task 4.3 — the interim
// 4.2 hardcode is gone): connecting with dbName "postgres" must yield a
// session whose current_database() is "postgres", not appdb.
func TestConnectPostgresBackendForwardsDatabase(t *testing.T) {
	tok := &models.TokenPayload{DBIP: "127.0.0.1", DBPort: "5433", DBUser: "ro_user"}
	creds := map[string]string{"127.0.0.1:5433:ro_user": "ro_pw"}

	f, err := connectPostgresBackend(context.Background(), tok, creds, "postgres")
	if err != nil {
		t.Fatalf("connectPostgresBackend: %v", err)
	}
	defer f.Close()

	writePGQuery(t, f.conn, "SELECT current_database()")
	resp := readPGQueryResponse(t, f.conn)
	if resp.errMsg != "" {
		t.Fatalf("backend error: %s", resp.errMsg)
	}
	if !resp.dataRow || !bytes.Contains(resp.dataRowPayload, []byte("postgres")) {
		t.Errorf("current_database() DataRow %q does not contain %q (client db not forwarded)", resp.dataRowPayload, "postgres")
	}
	if !resp.ready {
		t.Fatalf("current_database() response missing ReadyForQuery: %+v", resp)
	}
}

func TestConnectPostgresBackendWrongPassword(t *testing.T) {
	tok := &models.TokenPayload{DBIP: "127.0.0.1", DBPort: "5433", DBUser: "ro_user"}
	creds := map[string]string{"127.0.0.1:5433:ro_user": "definitely-wrong-pw"}
	if _, err := connectPostgresBackend(context.Background(), tok, creds, "appdb"); err == nil {
		t.Fatal("expected auth error for wrong password")
	}
}

// --- raw wire helpers (byte-exact, no pgproto3 involvement) ---

// writePGQuery sends a raw PostgreSQL Simple Query message over conn:
// [type 'Q'][int32 length incl. self][SQL\0]. Written as raw bytes so the
// test exercises the exact byte stream the 4.3 relay will forward.
func writePGQuery(t *testing.T, conn net.Conn, sql string) {
	t.Helper()
	payload := append([]byte(sql), 0)
	frame := make([]byte, 0, 1+4+len(payload))
	frame = append(frame, 'Q')
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(payload)+4))
	frame = append(frame, l[:]...)
	frame = append(frame, payload...)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write Q message: %v", err)
	}
}

// pgQueryResponse summarizes one Simple Query response sequence.
type pgQueryResponse struct {
	rowDesc        bool
	dataRow        bool
	dataRowPayload []byte
	cmdComplete    string
	ready          bool
	errMsg         string
}

// readPGQueryResponse reads backend frames ([type byte][int32 length]
// [payload]) until ReadyForQuery ('Z') or ErrorResponse ('E').
func readPGQueryResponse(t *testing.T, conn net.Conn) pgQueryResponse {
	t.Helper()
	var resp pgQueryResponse
	for i := 0; i < 20; i++ {
		typ, payload := readPGFrame(t, conn)
		switch typ {
		case 'T':
			resp.rowDesc = true
		case 'D':
			resp.dataRow = true
			resp.dataRowPayload = append([]byte(nil), payload...)
		case 'C':
			resp.cmdComplete = strings.TrimRight(string(payload), "\x00")
		case 'Z':
			resp.ready = true
			return resp
		case 'E':
			resp.errMsg = string(payload)
			return resp
		}
	}
	t.Fatal("backend response did not terminate with ReadyForQuery")
	return resp
}

// readPGFrame reads one backend message frame: 1-byte type + 4-byte
// big-endian length (including itself) + payload.
func readPGFrame(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	if length < 0 || length > 1<<24 {
		t.Fatalf("implausible frame length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read frame payload: %v", err)
	}
	return hdr[0], payload
}
