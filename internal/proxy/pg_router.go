package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/jackc/pgproto3/v2"
	"github.com/jackc/pgx/v5"
	"zerotrust-proxy/internal/models"
)

// capturePGThreadID asks the freshly connected backend for its backend pid —
// a raw Q 'SELECT pg_backend_pid()' on the hijacked conn while the backend
// session is still idle (before the relay starts, so there is no client
// traffic to interleave). The FULL exchange is consumed (RowDescription,
// DataRow, CommandComplete, ReadyForQuery) so the message-level relay starts
// from a clean stream.
//
// Task 8.2 degrade-gracefully rule: ANY failure — send/receive error,
// ErrorResponse, unparsable cell — logs and returns 0. The session proceeds
// with pid 0; the session directory simply lacks connection context.
func capturePGThreadID(front *pgFrontend, log *slog.Logger) int64 {
	if err := front.f.Send(&pgproto3.Query{String: "SELECT pg_backend_pid()"}); err != nil {
		log.Warn("thread id capture: send failed", "err", err)
		return 0
	}
	var pid int64
	for {
		msg, err := front.f.Receive()
		if err != nil {
			log.Warn("thread id capture: receive failed", "err", err)
			return 0
		}
		switch m := msg.(type) {
		case *pgproto3.DataRow:
			// Re-encode to raw framing and decode the payload (int16 count +
			// per-cell int32 len + bytes) with the 1-column validation.
			raw, err := m.Encode(nil)
			if err != nil || len(raw) < 5 {
				continue
			}
			if row, ok := parsePGDataRow(raw[5:], 1); ok {
				if v, err := strconv.ParseInt(row[0], 10, 64); err == nil {
					pid = v
				}
			}
		case *pgproto3.ErrorResponse:
			log.Warn("thread id capture: backend error", "err", m.Message)
			return 0
		case *pgproto3.ReadyForQuery: // exchange fully consumed — stream is clean
			return pid
		}
	}
}

// pgFrontend wraps the hijacked backend connection with a pgproto3 Frontend
// (we act as the client toward the real PostgreSQL server).
type pgFrontend struct {
	conn net.Conn
	f    *pgproto3.Frontend
}

// defaultPGDatabase is the database used when the client's StartupMessage
// carries no database. PG clients normally always send one; the fallback
// keeps the 4.2-era default for bare clients.
const defaultPGDatabase = "appdb"

// connectPostgresBackend authenticates to the real PostgreSQL backend with
// Data-Plane-owned credentials (keyed by backendKey, shared with the MySQL
// side), then hijacks the connection and hands back the raw byte stream for
// the relay (Task 4.3). pgx performs the FULL auth handshake
// (SCRAM-SHA-256 etc.) so the proxy never re-implements PG auth; after the
// handshake the backend session is idle and its stream is clean for relaying
// subsequent client traffic verbatim.
//
// dbName is the database the CLIENT requested in its StartupMessage,
// forwarded so the session gets the right default schema (PG clients send
// the db in the startup message, mirroring MySQL's CONNECT_WITH_DB flow);
// an empty value falls back to defaultPGDatabase. It is applied via the
// parsed config (not DSN interpolation) so arbitrary database names cannot
// inject DSN parameters.
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
// connect_timeout=10 bounds the whole connect+auth (dial AND handshake):
// pgx's default is unbounded, and a backend that accepts but never speaks
// would pin the session goroutine, the client connection and the consumed
// token forever — same failure mode Task 3.8 bounded on the MySQL side.
func connectPostgresBackend(ctx context.Context, t *models.TokenPayload, res CredResolver, dbName string) (*pgFrontend, error) {
	pw, err := res.Password(ctx, backendKey(t))
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s sslmode=disable connect_timeout=10",
		t.DBIP, t.DBPort, t.DBUser, pw)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if dbName == "" {
		dbName = defaultPGDatabase
	}
	cfg.Database = dbName
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
