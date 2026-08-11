package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"zerotrust-proxy/internal/models"
)

// backendKey identifies a credential entry: "<ip>:<port>:<db_user>".
func backendKey(t *models.TokenPayload) string {
	return fmt.Sprintf("%s:%s:%s", t.DBIP, t.DBPort, t.DBUser)
}

// connectMySQLBackend authenticates to the real MySQL with Data-Plane-owned
// credentials, then hands back the raw net.Conn for byte-exact relay.
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
func connectMySQLBackend(ctx context.Context, t *models.TokenPayload, creds map[string]string) (net.Conn, error) {
	pw, ok := creds[backendKey(t)]
	if !ok {
		return nil, fmt.Errorf("no credentials for %s", backendKey(t))
	}
	conn, err := client.ConnectWithContext(ctx, fmt.Sprintf("%s:%s", t.DBIP, t.DBPort), t.DBUser, pw, "", 10*time.Second,
		func(c *client.Conn) error {
			c.UnsetCapability(mysql.CLIENT_QUERY_ATTRIBUTES)
			c.UnsetCapability(mysql.CLIENT_DEPRECATE_EOF)
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("backend mysql connect: %w", err)
	}
	return conn.Conn, nil
}
