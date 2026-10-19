package proxy

// Node-integration, MariaDB (plane acceptance): MariaDB speaks the MySQL
// wire protocol, so the mysql plane's wrong-db_type gate accepts tokens
// with db_type "mysql" OR "mariadb". Every other plane still rejects a
// mariadb token — db_type is served by exactly one plane.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// TestMySQLPlaneAcceptsMariaDBToken: a full handshake against the mysql
// plane with a db_type "mariadb" token — the type gate passes and the
// session proceeds to the backend connect (fake edge backend answers OK),
// proving the rejection path never fired.
func TestMySQLPlaneAcceptsMariaDBToken(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	backendAddr, _, backendClosed := startEdgeBackend(t)
	token, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tok := models.TokenPayload{Username: "test-user", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: backendAddr[strings.LastIndex(backendAddr, ":")+1:], DBType: "mariadb", TicketID: "T-MARIA-P1"}
	if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	var logBuf bytes.Buffer
	// Verbatim-key proof: the map holds ONLY the mariadb: credential key —
	// if the plane aliased to mysql: keys, the lookup would miss and the
	// session would die; success below therefore proves mariadb: keys are
	// consulted and never silently remapped.
	creds := map[string]string{
		"mariadb:ro_user@" + backendAddr: "ro_pw",
	}
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(&logBuf, nil)), vs, &ConfigCredResolver{Creds: creds}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.handleConn(context.Background(), conn, bufio.NewReader(conn))
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	if _, _, err := readMySQLPacket(client); err != nil { // 1. server handshake
		t.Fatalf("read handshake: %v", err)
	}
	if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	// 3. OK (seq 2) = type gate PASSED, backend connected, session up.
	seq, resp, err := readMySQLPacket(client)
	if err != nil {
		t.Fatalf("read post-auth reply: %v", err)
	}
	if len(resp) > 0 && resp[0] == 0xff {
		t.Fatalf("mysql plane rejected a mariadb token (seq %d): ERR packet % x", seq, resp)
	}
	if len(resp) == 0 || resp[0] != 0x00 {
		t.Fatalf("post-auth reply: seq=%d payload=% x, want OK packet", seq, resp)
	}
	client.Close() // COM_QUIT path tears the session down
	select {
	case <-backendClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("backend session did not close within 5s")
	}
	if bytes.Contains([]byte(logBuf.String()), []byte("token not valid for this protocol")) ||
		bytes.Contains([]byte(logBuf.String()), []byte("wrong_db_type")) {
		t.Errorf("logs show a wrong-db_type rejection:\n%s", logBuf.String())
	}
}

// TestPGPlaneRejectsMariaDBToken: the postgres plane must NOT accept a
// mariadb token — FATAL 28000 'token not valid for this protocol'.
func TestPGPlaneRejectsMariaDBToken(t *testing.T) {
	vs := proxyTestStore(t)
	ln, done := startTestPGProxy(t, vs, &bytes.Buffer{}, 1)
	token := pgTestToken(t, vs, "mariadb") // wrong protocol for the pg plane

	front := pgDial(t, ln, token, false)

	er := pgReadFatalError(t, front)
	if er.Message != "token not valid for this protocol" {
		t.Fatalf("message: got %q, want %q", er.Message, "token not valid for this protocol")
	}
	waitPGDone(t, done)
}

// TestMariaDBQueryEventsCarrySessionDBType (fix round 1): a session's
// published QueryEvent must carry the db_type the session's token presented —
// a mariadb session's query events are "mariadb", a mysql session's are
// "mysql". The event feeds pub/sub, the slog query line and the
// QueriesTotal/QueryDuration metric labels, so a hardcoded "mysql" mislabels
// every mariadb query (violates the verbatim-events criterion and docs/11
// §11.11). Driven end-to-end: full handshake, one COM_QUERY, the fake edge
// backend's OK completes the capture, the event is asserted off the wire.
func TestMariaDBQueryEventsCarrySessionDBType(t *testing.T) {
	for _, tc := range []struct {
		dbType string
		user   string
	}{
		{"mariadb", "maria-user"},
		{"mysql", "plain-user"}, // control: no regression for mysql sessions
	} {
		t.Run(tc.dbType, func(t *testing.T) {
			vs := proxyTestStore(t)
			ctx := context.Background()
			backendAddr, _, _ := startEdgeBackend(t)
			_, port, err := net.SplitHostPort(backendAddr)
			if err != nil {
				t.Fatalf("split backend addr: %v", err)
			}
			token, err := store.NewToken()
			if err != nil {
				t.Fatalf("NewToken: %v", err)
			}
			tok := models.TokenPayload{Username: tc.user, DBUser: "ro_user",
				DBIP: "127.0.0.1", DBPort: port, DBType: tc.dbType, TicketID: "T-MARIA-EV"}
			if err := vs.SetToken(ctx, token, tok, time.Minute); err != nil {
				t.Fatalf("SetToken: %v", err)
			}

			// Subscribe BEFORE the session comes up: the started lifecycle
			// event precedes the query event on the user channel.
			subCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			out := make(chan []byte, 8)
			acked := make(chan struct{}, 1)
			subCtx = valkey.WithOnSubscriptionHook(subCtx, func(valkey.PubSubSubscription) {
				select {
				case acked <- struct{}{}:
				default:
				}
			})
			go vs.Subscribe(subCtx, "queries:"+tc.user, false, out)
			waitSubAck(t, acked)

			// Verbatim cred key <db_type>:ro_user@addr — the same
			// no-aliasing rule the plane-acceptance test proves.
			var logBuf bytes.Buffer
			creds := map[string]string{
				fmt.Sprintf("%s:ro_user@%s", tc.dbType, backendAddr): "ro_pw",
			}
			ln, proxyDone := startTestProxyWithCreds(t, vs, &logBuf, creds)

			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer client.Close()

			// Handshake: server greeting, token response, OK (seq 2).
			if _, _, err := readMySQLPacket(client); err != nil {
				t.Fatalf("read handshake: %v", err)
			}
			if err := writeMySQLPacket(client, 1, buildTestHandshakeResponse(token)); err != nil {
				t.Fatalf("write handshake response: %v", err)
			}
			if seq, resp, err := readMySQLPacket(client); err != nil || seq != 2 || len(resp) == 0 || resp[0] != 0x00 {
				t.Fatalf("expected OK seq 2, got seq=%d resp=% x err=%v", seq, resp, err)
			}

			// One COM_QUERY; the edge backend answers OK, which completes the
			// capture and publishes the event.
			if err := writeMySQLPacket(client, 0, append([]byte{cmdQuery}, "SELECT 1"...)); err != nil {
				t.Fatalf("write COM_QUERY: %v", err)
			}
			if seq, resp, err := readMySQLPacket(client); err != nil || len(resp) == 0 || resp[0] != 0x00 {
				t.Fatalf("expected OK reply, got seq=%d resp=% x err=%v", seq, resp, err)
			}

			ev := recvQueryEvent(t, out) // skips the started lifecycle event
			if ev.Kind != "query" || ev.SQL != "SELECT 1" {
				t.Fatalf("event kind/sql = %q/%q, want query/SELECT 1", ev.Kind, ev.SQL)
			}
			if ev.DBType != tc.dbType {
				t.Errorf("query event db_type = %q, want %q (verbatim from the session's token)", ev.DBType, tc.dbType)
			}

			// Teardown: client close must end the session promptly.
			client.Close()
			select {
			case <-proxyDone:
			case <-time.After(5 * time.Second):
				t.Fatal("handleConn did not return within 5s of client close")
			}
		})
	}
}
