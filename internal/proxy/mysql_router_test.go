package proxy

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"zerotrust-proxy/internal/models"
)

func TestBackendKeyFormat(t *testing.T) {
	tok := &models.TokenPayload{DBIP: "127.0.0.1", DBPort: "3307", DBUser: "ro_user"}
	if got := backendKey(tok); got != "127.0.0.1:3307:ro_user" {
		t.Fatalf("backendKey() = %q, want %q", got, "127.0.0.1:3307:ro_user")
	}
}

func TestConnectMySQLBackendMissingCreds(t *testing.T) {
	tok := &models.TokenPayload{DBIP: "127.0.0.1", DBPort: "3307", DBUser: "ro_user"}
	_, err := connectMySQLBackend(context.Background(), tok, map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing credential key")
	}
	if !strings.Contains(err.Error(), "no credentials for 127.0.0.1:3307:ro_user") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestConnectMySQLBackendLiveRoundTrip is a skip-free LIVE integration test
// against the mysql-test container (127.0.0.1:3307, ro_user/ro_pw, db appdb).
func TestConnectMySQLBackendLiveRoundTrip(t *testing.T) {
	tok := &models.TokenPayload{DBIP: "127.0.0.1", DBPort: "3307", DBUser: "ro_user"}
	creds := map[string]string{"127.0.0.1:3307:ro_user": "ro_pw"}

	conn, err := connectMySQLBackend(context.Background(), tok, creds)
	if err != nil {
		t.Fatalf("connectMySQLBackend: %v", err)
	}
	defer conn.Close()

	// Real round-trip over the raw conn: COM_QUERY (0x03) "SELECT 1".
	payload := append([]byte{0x03}, []byte("SELECT 1")...)
	if err := writeMySQLPacket(conn, 0, payload); err != nil {
		t.Fatalf("write COM_QUERY: %v", err)
	}
	_, resp, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response packet")
	}
	// Valid result-set/OK packet: column-count header (0x01 for SELECT 1),
	// OK packet (0x00), or a payload carrying the result.
	if resp[0] != 0x00 && resp[0] != 0x01 && !bytes.Contains(resp, []byte("1")) {
		t.Fatalf("response is not a valid result-set/OK packet: % x", resp)
	}
	// Drain the rest of the result set (column defs, EOF, row, EOF/OK) so the
	// connection is provably usable end-to-end, not just for one packet.
	seenEOF := false
	for i := 0; i < 20; i++ {
		_, pkt, err := readMySQLPacket(conn)
		if err != nil {
			t.Fatalf("drain packet %d: %v", i, err)
		}
		if len(pkt) > 0 && pkt[0] == 0xfe { // EOF packet terminates result set
			seenEOF = true
			break
		}
	}
	if !seenEOF {
		t.Fatal("result set did not terminate with an EOF packet")
	}
}

func TestConnectMySQLBackendWrongPassword(t *testing.T) {
	tok := &models.TokenPayload{DBIP: "127.0.0.1", DBPort: "3307", DBUser: "ro_user"}
	creds := map[string]string{"127.0.0.1:3307:ro_user": "definitely-wrong-pw"}
	if _, err := connectMySQLBackend(context.Background(), tok, creds); err == nil {
		t.Fatal("expected auth error for wrong password")
	}
}
