package proxy

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"zerotrust-proxy/internal/models"
)

func TestBackendKeyFormat(t *testing.T) {
	tok := &models.TokenPayload{DBType: "mysql", DBIP: "127.0.0.1", DBPort: "3307", DBUser: "ro_user"}
	if got := backendKey(tok); got != "mysql:ro_user@127.0.0.1:3307" {
		t.Fatalf("backendKey() = %q, want %q", got, "mysql:ro_user@127.0.0.1:3307")
	}
}

func TestConnectMySQLBackendMissingCreds(t *testing.T) {
	tok := &models.TokenPayload{DBType: "mysql", DBIP: "127.0.0.1", DBPort: "3307", DBUser: "ro_user"}
	_, err := connectMySQLBackend(context.Background(), tok, &ConfigCredResolver{}, "")
	if err == nil {
		t.Fatal("expected error for missing credential key")
	}
	if !strings.Contains(err.Error(), "no credentials for mysql:ro_user@127.0.0.1:3307") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestConnectMySQLBackendLiveRoundTrip is a skip-free LIVE integration test
// against the mysql-test container (127.0.0.1:3307, ro_user/ro_pw, db appdb).
func TestConnectMySQLBackendLiveRoundTrip(t *testing.T) {
	tok := &models.TokenPayload{DBType: "mysql", DBIP: "127.0.0.1", DBPort: "3307", DBUser: "ro_user"}
	creds := map[string]string{"mysql:ro_user@127.0.0.1:3307": "ro_pw"}

	conn, err := connectMySQLBackend(context.Background(), tok, &ConfigCredResolver{Creds: creds}, "appdb")
	if err != nil {
		t.Fatalf("connectMySQLBackend: %v", err)
	}
	defer conn.Close()

	// Real round-trip over the raw conn: COM_QUERY (0x03) "SELECT DATABASE()"
	// proves the client-requested database was forwarded to the backend.
	payload := append([]byte{0x03}, []byte("SELECT DATABASE()")...)
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
	// Drain the rest of the result set (column defs, EOF, rows, EOF) so the
	// connection is provably usable end-to-end, not just for one packet.
	seenEOF := false
	var rows [][]byte
	for i := 0; i < 20; i++ {
		_, pkt, err := readMySQLPacket(conn)
		if err != nil {
			t.Fatalf("drain packet %d: %v", i, err)
		}
		if len(pkt) > 0 && pkt[0] == 0xfe { // EOF: first ends column defs, second ends rows
			if seenEOF {
				break
			}
			seenEOF = true
			continue
		}
		if seenEOF {
			rows = append(rows, pkt)
		}
	}
	if !seenEOF {
		t.Fatal("result set did not terminate with an EOF packet")
	}
	found := false
	for _, r := range rows {
		if bytes.Contains(r, []byte("appdb")) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("data rows %q do not contain the forwarded database %q", rows, "appdb")
	}
}

func TestConnectMySQLBackendWrongPassword(t *testing.T) {
	tok := &models.TokenPayload{DBType: "mysql", DBIP: "127.0.0.1", DBPort: "3307", DBUser: "ro_user"}
	creds := map[string]string{"mysql:ro_user@127.0.0.1:3307": "definitely-wrong-pw"}
	if _, err := connectMySQLBackend(context.Background(), tok, &ConfigCredResolver{Creds: creds}, ""); err == nil {
		t.Fatal("expected auth error for wrong password")
	}
}
