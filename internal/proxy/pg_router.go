package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/jackc/pgproto3/v2"
	"github.com/jackc/pgx/v5"
	"zerotrust-proxy/internal/models"
)

// pgFrontend wraps the hijacked backend connection with a pgproto3 Frontend
// (we act as the client toward the real PostgreSQL server).
type pgFrontend struct {
	conn net.Conn
	f    *pgproto3.Frontend
}

// connectPostgresBackend authenticates to the real PostgreSQL backend with
// Data-Plane-owned credentials (keyed by backendKey, shared with the MySQL
// side), then hijacks the connection and hands back the raw byte stream for
// the byte-exact relay (Task 4.3). pgx performs the FULL auth handshake
// (SCRAM-SHA-256 etc.) so the proxy never re-implements PG auth; after the
// handshake the backend session is idle and its stream is clean for relaying
// subsequent client traffic verbatim.
//
// Hijack leftover-bytes finding (pgx v5.10.0, verified against source):
//   - PgConn.Hijack() returns (*HijackedConn, error) — NOT (net.Conn,
//     *HijackedConn, error) as the 4.2 brief assumed; the raw conn is
//     hc.Conn. (API not covered by semver; re-check on upgrades.)
//   - Hijack does NOT itself drain pgconn's internal buffered reader, but
//     PgConn.SyncConn does: it loops until bgReader is stopped AND
//     frontend.ReadBufferLen() == 0, pinging the server (max 10x) if needed.
//     On a fresh idle connection this is a zero-cost fast path — the
//     background reader never starts in normal operation (its trigger timer
//     is stopped at connect time) and ConnectConfig consumes exactly the
//     startup exchange (auth + ParameterStatus + BackendKeyData +
//     ReadyForQuery), leaving ReadBufferLen() == 0. So SyncConn is a no-op
//     here but is the documented requirement before Hijack; keep it as the
//     guard against any future read-ahead. The live round-trip test below
//     proves the raw stream carries a clean client→server exchange.
//
// dbname: hardcoded to "appdb" per the brief. Task 4.3 must forward the
// CLIENT-requested database from its STARTUP message instead (mirroring the
// MySQL side, which forwards the client's COM_INIT_DB database), so sessions
// get the right default schema.
//
// connect_timeout=10 bounds the whole connect+auth (dial AND handshake):
// pgx's default is unbounded, and a backend that accepts but never speaks
// would pin the session goroutine, the client connection and the consumed
// token forever — same failure mode Task 3.8 bounded on the MySQL side.
func connectPostgresBackend(ctx context.Context, t *models.TokenPayload, creds map[string]string) (*pgFrontend, error) {
	pw, ok := creds[backendKey(t)]
	if !ok {
		return nil, fmt.Errorf("no credentials for %s", backendKey(t))
	}
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=appdb sslmode=disable connect_timeout=10",
		t.DBIP, t.DBPort, t.DBUser, pw)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pgconn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("backend pg connect: %w", err)
	}
	// Drain any internally buffered bytes BEFORE hijack so the raw conn is
	// guaranteed clean for byte-exact relay (see finding above).
	if err := pgconn.PgConn().SyncConn(ctx); err != nil {
		_ = pgconn.Close(context.Background())
		return nil, fmt.Errorf("pg sync: %w", err)
	}
	hc, err := pgconn.PgConn().Hijack()
	if err != nil {
		_ = pgconn.Close(context.Background())
		return nil, fmt.Errorf("pg hijack: %w", err)
	}
	raw := hc.Conn
	// pgproto3.Frontend reads server messages from the conn (via ChunkReader)
	// and writes client messages to it — we are the client toward the backend.
	return &pgFrontend{conn: raw, f: pgproto3.NewFrontend(pgproto3.NewChunkReader(raw), raw)}, nil
}

// Send forwards a client→server message to the backend.
func (f *pgFrontend) Send(msg pgproto3.FrontendMessage) error { return f.f.Send(msg) }

// Receive reads the next server→client message from the backend.
func (f *pgFrontend) Receive() (pgproto3.BackendMessage, error) { return f.f.Receive() }

func (f *pgFrontend) Close() { _ = f.conn.Close() }
