package api

// Node-integration, MariaDB: db_type "mariadb" is an EXPLICIT first-class
// type — never a silent alias of "mysql". The whitelist, the 422 message and
// the default-port map gain mariadb (default port 6603, the MariaDB-era
// convention); the minted payload keeps db_type VERBATIM "mariadb" so the
// data plane's credential keys (mariadb:<user>@<ip>:<port>) and audit
// records stay unambiguous.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestTokenMariaDBDefaultPort: a mariadb mint with NO db_port resolves the
// payload's db_port to the canonical 6603 from the map, and the stored
// payload's db_type is the verbatim string "mariadb" (no normalization to
// "mysql" anywhere in the mint path).
func TestTokenMariaDBDefaultPort(t *testing.T) {
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	token := issueToken(t, client, srv.URL,
		`{"db_user":"some_user","db_ip":"10.1.2.3","db_type":"mariadb","ticket_id":"T-MARIA-1"}`)
	p, err := vs.GetDeleteToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetDeleteToken(%q): %v", token, err)
	}
	if p == nil {
		t.Fatalf("tok:%s missing", token)
	}
	if p.DBPort != "6603" {
		t.Errorf("mariadb mint without db_port: stored db_port = %q, want 6603", p.DBPort)
	}
	if p.DBType != "mariadb" {
		t.Errorf("mariadb mint: stored db_type = %q, want verbatim \"mariadb\" (no aliasing)", p.DBType)
	}
}

// TestTokenMariaDBExplicitPortWins: an explicit db_port beats the map
// verbatim — mariadb + db_port 6604 stores 6604, never the 6603 default.
func TestTokenMariaDBExplicitPortWins(t *testing.T) {
	srv, client, vs, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	token := issueToken(t, client, srv.URL,
		`{"db_user":"some_user","db_ip":"10.1.2.3","db_port":"6604","db_type":"mariadb","ticket_id":"T-MARIA-2"}`)
	p, err := vs.GetDeleteToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetDeleteToken(%q): %v", token, err)
	}
	if p == nil {
		t.Fatalf("tok:%s missing", token)
	}
	if p.DBPort != "6604" {
		t.Errorf("mariadb mint with explicit db_port: stored db_port = %q, want 6604", p.DBPort)
	}
	if p.DBType != "mariadb" {
		t.Errorf("mariadb mint: stored db_type = %q, want verbatim \"mariadb\"", p.DBType)
	}
}

// TestTokenDBTypeMessageListsMariaDB: the 422 rejection message is the
// canonical enumeration and must name mariadb explicitly (the client team
// reads this message as the type contract).
func TestTokenDBTypeMessageListsMariaDB(t *testing.T) {
	srv, client, _, cfg := newPresetTestAPIServer(t)
	client = withBearer(client, mintJWT(t, cfg, testJWTUser, "maker"))

	body := `{"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mongodb","ticket_id":"T-MARIA-3"}`
	resp, err := client.Post(srv.URL+"/api/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("POST /api/token: status %d, want 422", resp.StatusCode)
	}
	buf := new(strings.Builder)
	if _, err := fmt.Fprint(buf, readAllForTest(t, resp)); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(buf.String(), "db_type must be mysql, mariadb, postgres, mssql or oracle") {
		t.Errorf("error body = %s, want the canonical db_type message listing mariadb", buf.String())
	}
}

// readAllForTest slurps a response body (helper kept local so this file does
// not reach into other tests' helpers).
func readAllForTest(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw := make([]byte, 4096)
	n, _ := resp.Body.Read(raw)
	return string(raw[:n])
}

// TestDocsNodeIntegrationListMariaDB (docs assertion): docs/11-node-integration.md
// must document mariadb in the db_type row and the 6603 default in the
// default-port map — the doc is the contract the client team codes against.
func TestDocsNodeIntegrationListMariaDB(t *testing.T) {
	raw, err := os.ReadFile("../../docs/11-node-integration.md")
	if err != nil {
		t.Fatalf("read docs/11-node-integration.md: %v", err)
	}
	doc := string(raw)
	if !strings.Contains(doc, "`mysql` \\| `mariadb` \\| `postgres` \\| `mssql` \\| `oracle`") {
		t.Errorf("docs/11 db_type row does not list mariadb")
	}
	if !strings.Contains(doc, "| `mariadb` | `6603` |") {
		t.Errorf("docs/11 default-port map has no mariadb → 6603 row")
	}
}
