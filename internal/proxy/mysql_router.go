package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"zerotrust-proxy/internal/models"
)

// threadIDCaptureTimeout bounds the thread-id probe on BOTH planes (review
// round 3): a backend that accepts the probe but never answers must degrade
// to 0 and never hang session setup. The deadline is set before the probe
// and cleared when the capture returns (defer), so the relay phase stays
// deadline-free. A var (not const) so tests can shrink it.
var threadIDCaptureTimeout = 5 * time.Second

// captureMySQLThreadID asks the freshly connected backend for its connection
// id — SELECT CONNECTION_ID() on the RAW conn while the backend session is
// still idle (before the OK packet is written to the client, so there is no
// client traffic to interleave). The FULL response is consumed (column
// count, column defs, EOF, row, terminating EOF) so the byte-exact relay
// starts from a clean stream with the backend's seq counter back at rest.
//
// Task 8.2 degrade-gracefully rule: ANY failure — write/read error, ERR
// packet, non-result-set reply (e.g. a stub backend answering OK), unparsable
// cell — logs and returns 0. The session proceeds with threadID 0; the
// session directory simply lacks connection context for kill-query.
// Review round 3: the probe runs under a read deadline (threadIDCaptureTimeout)
// so a stalled backend degrades to 0 instead of hanging the session setup.
func captureMySQLThreadID(backend net.Conn, log *slog.Logger) int64 {
	if err := backend.SetReadDeadline(time.Now().Add(threadIDCaptureTimeout)); err != nil {
		log.Warn("thread id capture: set read deadline failed", "err", err)
		return 0
	}
	defer backend.SetReadDeadline(time.Time{})
	if err := writeMySQLPacket(backend, 0, append([]byte{cmdQuery}, "SELECT CONNECTION_ID()"...)); err != nil {
		log.Warn("thread id capture: write failed", "err", err)
		return 0
	}
	var threadID int64
	stage := 0 // 0 = awaiting column count, 1 = column defs, 2 = rows
	for {
		_, payload, err := readMySQLPacket(backend)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				log.Warn("thread id capture: backend did not answer within deadline", "timeout", threadIDCaptureTimeout)
			} else {
				log.Warn("thread id capture: read failed", "err", err)
			}
			return 0
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case 0xff: // ERR packet — capture failed
			log.Warn("thread id capture: backend error", "err", mysqlErrMessage(payload))
			return 0
		case 0x00: // OK (no result set — non-SELECT/stub backend): nothing to read
			return 0
		case 0xfe: // EOF: ends the column defs (→ rows) or the rows (→ done)
			if stage == 1 {
				stage = 2
				continue
			}
			return threadID
		}
		switch stage {
		case 0:
			stage = 1 // column count packet
		case 1:
			// column definition — skipped
		case 2:
			// TEXT-protocol DataRow with exactly one cell (validated by
			// parseMySQLRow's want-count check).
			if row, consumed := parseMySQLRow(payload, 1); consumed > 0 {
				if v, err := strconv.ParseInt(row[0], 10, 64); err == nil {
					threadID = v
				}
			}
		}
	}
}

// backendKey identifies a credential entry: "<dbtype>:<db_user>@<db_ip>:<db_port>"
// (Task 8.7 format — carries the db type so the API resolver can build the
// vault query params db_type/db_user/db_ip/db_port).
func backendKey(t *models.TokenPayload) string {
	return fmt.Sprintf("%s:%s@%s:%s", t.DBType, t.DBUser, t.DBIP, t.DBPort)
}

// connectMySQLBackend authenticates to the real MySQL with Data-Plane-owned
// credentials resolved through res (config list or credential API — Task
// 8.7), then hands back the raw net.Conn for byte-exact relay. The password
// lives in memory only for this call; it is never logged or stored.
// dbName is the database the CLIENT requested in its handshake response
// (forwarded to the backend so the session has the right default schema);
// empty means no default database.
//
// API note (go-mysql v1.16.0): client.Connect's signature is
// Connect(addr, user, password, dbName string, options ...Option) — not
// context-aware. We use ConnectWithContext(ctx, addr, user, password, dbName,
// timeout, options ...Option), which honors ctx for the dial.
//
// Capability note: v1.16.0 always negotiates CLIENT_QUERY_ATTRIBUTES and
// CLIENT_DEPRECATE_EOF in its handshake. Both are incompatible with byte-exact
// relay: with QUERY_ATTRIBUTES set, MySQL 8.4 rejects every naked COM_QUERY
// packet with ER_MALFORMED_PACKET (1835), and DEPRECATE_EOF changes
// result-set framing (OK instead of EOF terminators). The proxy's own
// handshake (advertisedCaps) does not offer either flag to clients, so the
// backend connection must match — hence the explicit unsets below.
func connectMySQLBackend(ctx context.Context, t *models.TokenPayload, res CredResolver, dbName string) (net.Conn, error) {
	pw, err := res.Password(ctx, backendKey(t))
	if err != nil {
		return nil, err
	}
	// Bounded handshake (Task 3.8): go-mysql's timeout parameter covers the
	// TCP dial only — the initial-handshake read is otherwise unbounded, so a
	// backend that accepts but never speaks (dead/black-holed) would pin the
	// session goroutine, the client connection and the consumed token forever.
	// The custom dialer sets a deadline on the raw conn before go-mysql starts
	// the handshake; it is cleared once Connect returns so the byte-exact
	// relay stays deadline-free (long-running queries must never trip a stale
	// deadline).
	conn, err := client.ConnectWithDialer(ctx, "tcp",
		fmt.Sprintf("%s:%s", t.DBIP, t.DBPort), t.DBUser, pw, dbName,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			return c, nil
		},
		func(c *client.Conn) error {
			c.UnsetCapability(mysql.CLIENT_QUERY_ATTRIBUTES)
			c.UnsetCapability(mysql.CLIENT_DEPRECATE_EOF)
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("backend mysql connect: %w", err)
	}
	_ = conn.SetDeadline(time.Time{}) // relay must be deadline-free
	return conn, nil
}
