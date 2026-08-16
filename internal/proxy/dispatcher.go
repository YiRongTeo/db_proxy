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

// Dispatcher owns ONE TCP listener and routes each connection to the MySQL,
// PostgreSQL, or MSSQL proxy based on which side speaks first:
//   - PostgreSQL is client-first: the client sends StartupMessage/SSLRequest
//     immediately after connect (first byte 0x00 — the 4-byte LE length of
//     the startup packet).
//   - MSSQL/TDS is client-first: the client sends a PRELOGIN packet whose
//     first byte is the packet type 0x12.
//   - MySQL is server-first: the client waits silently for the server
//     handshake.
//
// So: first byte 0x12 → MSSQL; any other client byte → PostgreSQL; silence
// within detectDelay → MySQL.
type Dispatcher struct {
	log         *slog.Logger
	mysql       *MySQLProxy
	pg          *PGProxy
	mssql       *MSSQLProxy // TDS plane (Task 9.2); nil only in tests — drop branch below stays nil-safe
	detectDelay time.Duration
	conns       atomic.Int64
	maxConns    int64
}

// NewDispatcher wires the three plane handlers. Review 2026-08-16: the
// one-method mssqlProxy interface was removed as unnecessary — the field
// is the concrete *MSSQLProxy (nil = TDS not wired; the drop branch below
// stays nil-safe on the concrete pointer).
func NewDispatcher(log *slog.Logger, mysql *MySQLProxy, pg *PGProxy, mssql *MSSQLProxy, detectDelay time.Duration, maxConns int64) *Dispatcher {
	return &Dispatcher{log: log, mysql: mysql, pg: pg, mssql: mssql, detectDelay: detectDelay, maxConns: maxConns}
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
	case err == nil && proto == "mssql":
		if d.mssql == nil {
			// The TDS proxy is wired in Phase 9 (Task 9.2); until then a
			// detected MSSQL client cannot be served, so drop the connection
			// explicitly instead of panicking on a nil receiver.
			d.log.Warn("mssql protocol detected but mssql proxy not wired, closing",
				"client", c.RemoteAddr().String())
			c.Close()
			return
		}
		d.mssql.handleConn(ctx, c, br)
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

// decide peeks the first client byte and classifies the protocol:
//   - 0x12 (TDS PRELOGIN packet type) → "mssql" (client-first; checked
//     BEFORE the PG branch — byte values are disjoint, but 0x12 is the more
//     specific signature).
//   - any other byte → "pg" (client-first startup message; the first byte
//     of a PG StartupMessage is 0x00 — the 4-byte BE length field).
//   - silence until delay → "mysql" (server-first protocol; the client
//     waits for the handshake).
//
// Peeked bytes stay in br, so nothing is lost when the handler consumes
// the stream.
func decide(c net.Conn, br *bufio.Reader, delay time.Duration) (string, error) {
	_ = c.SetReadDeadline(time.Now().Add(delay))
	b, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err == nil {
		if b[0] == 0x12 {
			return "mssql", nil
		}
		return "pg", nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "mysql", nil
	}
	return "", err
}
