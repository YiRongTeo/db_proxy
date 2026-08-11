package proxy

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// PGProxy is the PostgreSQL proxy. Phase 4 (Task 4.4) defines the real
// implementation in pg_proxy.go (handshake, SCRAM, relay) with the same
// handleConn contract. This placeholder keeps the Dispatcher compiling until
// then; DELETE it (and this no-op method) when pg_proxy.go lands.
type PGProxy struct{}

// handleConn is a placeholder no-op matching the Phase 4 contract
// (ctx context.Context, client net.Conn, br *bufio.Reader).
func (p *PGProxy) handleConn(ctx context.Context, client net.Conn, br *bufio.Reader) {}

// Dispatcher owns ONE TCP listener and routes each connection to the MySQL or
// PostgreSQL proxy based on which side speaks first:
//   - PostgreSQL is client-first: the client sends StartupMessage/SSLRequest
//     immediately after connect.
//   - MySQL is server-first: the client waits silently for the server handshake.
//
// So: client bytes within detectDelay → PostgreSQL; silence → MySQL.
type Dispatcher struct {
	log         *slog.Logger
	mysql       *MySQLProxy
	pg          *PGProxy
	detectDelay time.Duration
	conns       atomic.Int64
	maxConns    int64
}

func NewDispatcher(log *slog.Logger, mysql *MySQLProxy, pg *PGProxy, detectDelay time.Duration, maxConns int64) *Dispatcher {
	return &Dispatcher{log: log, mysql: mysql, pg: pg, detectDelay: detectDelay, maxConns: maxConns}
}

func (d *Dispatcher) Serve(l net.Listener, ctx context.Context) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if d.conns.Load() >= d.maxConns {
			d.log.Warn("connection limit reached, rejecting")
			c.Close()
			continue
		}
		d.conns.Add(1)
		go func() {
			defer d.conns.Add(-1)
			d.dispatch(ctx, c)
		}()
	}
}

func (d *Dispatcher) dispatch(ctx context.Context, c net.Conn) {
	br := bufio.NewReader(c)
	proto, err := decide(c, br, d.detectDelay)
	switch {
	case err == nil && proto == "pg":
		if d.pg == nil {
			// PG proxy is wired in Phase 4 (Task 4.4); until then a detected
			// PG client cannot be served, so drop the connection explicitly
			// instead of panicking on a nil receiver.
			d.log.Warn("pg protocol detected but pg proxy not wired, closing",
				"client", c.RemoteAddr().String())
			c.Close()
			return
		}
		d.pg.handleConn(ctx, c, br)
	case err == nil:
		d.mysql.handleConn(ctx, c, br)
	default:
		d.log.Debug("dispatch drop", "err", err)
		c.Close()
	}
}

// decide peeks the first client byte: bytes → "pg" (client-first protocol),
// silence until delay → "mysql" (server-first protocol). Peeked bytes stay in
// br, so nothing is lost when the handler consumes the stream.
func decide(c net.Conn, br *bufio.Reader, delay time.Duration) (string, error) {
	_ = c.SetReadDeadline(time.Now().Add(delay))
	_, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err == nil {
		return "pg", nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "mysql", nil
	}
	return "", err
}
