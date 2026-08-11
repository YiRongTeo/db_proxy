package proxy

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"zerotrust-proxy/internal/store"
)

// MySQLProxy runs MySQL sessions on the Data Plane. It performs the 6-step
// session lifecycle: server handshake, client response, single-use token
// validation, backend connect, OK, then byte-exact bidirectional relay with
// passive SQL sniffing.
//
// NOTE (D11 redesign): the Dispatcher owns the accept loop and connection
// limiting (Task 3.5), so there is deliberately no connection counter, no
// maxConns, and no Serve loop here — one handleConn per accepted connection.
type MySQLProxy struct {
	log      *slog.Logger
	vs       *store.ValkeyStore
	creds    map[string]string
	serverID atomic.Uint32 // per-session connection id for the handshake
}

func NewMySQLProxy(log *slog.Logger, vs *store.ValkeyStore, creds map[string]string) *MySQLProxy {
	return &MySQLProxy{log: log, vs: vs, creds: creds}
}

// handleConn runs one MySQL session. The Dispatcher owns the accept loop and
// passes a buffered reader so any peeked client bytes are preserved; ALL
// client-side reads go through br, writes through client.
func (p *MySQLProxy) handleConn(ctx context.Context, client net.Conn, br *bufio.Reader) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second)) // handshake deadline

	// 1. server handshake (seq 0)
	authData, err := randomAuthData()
	if err != nil {
		return
	}
	handshake, err := buildHandshakeV10("8.4.0-zerotrust-proxy", p.serverID.Add(1), authData)
	if err != nil {
		return
	}
	if err := writeMySQLPacket(client, 0, handshake); err != nil {
		return
	}

	// 2. handshake response (seq 1): username = token
	_, payload, err := readMySQLPacket(br)
	if err != nil {
		return
	}
	if len(payload) > 0 && payload[0] == 0xff {
		return // client refused
	}
	token, _, err := parseHandshakeResponse(payload)
	if err != nil {
		return
	}

	// 3. single-use token validation (GETDEL — atomic read+delete)
	tok, err := p.vs.GetDeleteToken(ctx, token)
	if err != nil {
		p.log.Error("token lookup", "err", err)
		return
	}
	if tok == nil {
		p.log.Warn("invalid or expired token", "client", clientAddr)
		_ = writeMySQLPacket(client, 2, errPacket(1045, "42000", "invalid or expired token"))
		return
	}
	if tok.DBType != "mysql" {
		p.log.Warn("token for wrong protocol", "db_type", tok.DBType, "client", clientAddr)
		_ = writeMySQLPacket(client, 2, errPacket(1045, "42000", "token not valid for this protocol"))
		return
	}

	// 4. backend connection (real credentials)
	backend, err := connectMySQLBackend(ctx, tok, p.creds)
	if err != nil {
		p.log.Error("backend connect failed", "err", err, "client", clientAddr)
		_ = writeMySQLPacket(client, 2, errPacket(1045, "42000", "backend unavailable"))
		return
	}
	defer backend.Close()

	// 5. OK (seq 2) — session established
	if err := writeMySQLPacket(client, 2, okPacket()); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	p.log.Info("session established", "username", tok.Username, "db_user", tok.DBUser,
		"db_type", tok.DBType, "client", clientAddr)

	// 6. bidirectional relay with passive sniffing. Whichever direction ends
	// first (client quit, backend close, network error) tears down both sides;
	// the second done-slot is buffered so the survivor never blocks.
	done := make(chan struct{}, 2)
	go func() {
		p.pipeClientToBackend(br, backend, tok, clientAddr)
		done <- struct{}{}
	}()
	go func() {
		p.pipeBackendToClient(backend, client)
		done <- struct{}{}
	}()
	<-done
	client.Close()
	backend.Close()
	p.log.Info("session closed", "username", tok.Username, "client", clientAddr)
}
