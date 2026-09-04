# Zero-Trust DB Proxy — Project Rules for Hermes

## Architecture
- `cmd/control/` — Control Plane: HTTP API + WebSocket hub + static Angular. Binds `:8080`.
- `cmd/data/` — Data Plane: TCP proxy. Binds `:3306` — ONE shared port; protocol detected per connection (PG client-first, MySQL server-first).
- `internal/store/` — Valkey client (tokens, sessions, Pub/Sub). The ONLY shared state between planes.
- `internal/proxy/` — wire protocol: `mysql_*.go` and `pg_*.go` (handshake, sniffing, relay).
- `internal/api/` — Control Plane HTTP handlers + WebSocket hub.
- `internal/models/` — `TokenPayload`, `QueryEvent`, shared DTOs.
- `web/` — Angular 21 standalone SPA (Maker portal + Checker dashboard).
- Data Plane NEVER makes HTTP calls to the Control Plane. All coupling via Valkey.

## Backend Standards (Go)
- Go 1.25.0 (local toolchain per go.mod; spec targets 1.27). stdlib `net/http` + ServeMux.
- `log/slog` (JSON) for all logging; `context.Context` for cancellation; no global state.
- `valkey-io/valkey-go` v1 for Valkey: tokens via `SET … EX` / `GETDEL` (atomic single-use); Pub/Sub via `Subscribe`/`PSubscribe`.
- `spf13/viper` for config: env prefix `ZT_`, dots → underscores; dev defaults committed in `configs/`.
- `coder/websocket` v1.8.15 for `/ws/checker` (installed version; brief code imports the non-/v2 path).
- `go-mysql-org/go-mysql` v1 for backend MySQL auth ONLY (then raw relay over `conn.Conn`).
- `jackc/pgx/v5` for backend PG auth (SCRAM), then `Hijack()` + `jackc/pgproto3/v2` for relay.
- Tokens: `crypto/rand`, `sess_` prefix; never log token values.
- Tests: stdlib `testing` only (no testify). Integration tests run against the live local Valkey/DBs.

## Wire Protocol Rules
- Shared port: wait up to `detect_delay_ms` for the first client byte → bytes = PostgreSQL, silence = MySQL; preserve peeked bytes via bufio.Reader (all client reads go through that reader).
- MySQL: username field = token; password ignored (token IS the credential); advertise `mysql_native_password`, no SSL cap in v1.
- Relay is byte-exact: read 4-byte header + payload, replay identical bytes (original seq) both directions.
- Sniff only: `COM_QUERY` 0x03, `COM_INIT_DB` 0x02, `COM_STMT_PREPARE` 0x16, `COM_STMT_EXECUTE` 0x17.
- PostgreSQL: user = token; `SSLRequest` → `'N'`; `AuthenticationOk` without challenge.
- PG SQL extraction: `SimpleQuery` (`Q`), `Parse` (`P`) name→SQL cache, `Execute` (`E`) lookup, `Close` evict.
- QueryEvent published to `queries:<username>` AND `queries:ticket:<ticket_id>` (when present).

## Frontend Standards (Angular 21)
- Standalone components only (NO NgModules); zoneless (Angular 21 default: no zone.js dep/polyfill, no provideZoneChangeDetection in app.config.ts); Signals for local state.
- NG-ZORRO v21 components (`nz-table`, `nz-form`, `nz-card`, `nz-tag`, `nz-select`); enterprise look.
- `rxjs/webSocket` for the live feed; `toSignal` bridge; `complete()` on destroy (no leaks).
- `ngx-clipboard` for token copy; lazy standalone routes; route guards require a stored bearer JWT (TokenStore; authGuard blocks until the boot-time /api/me restore resolves).
- Dark enterprise theme: dark zinc sidebar + sky accent (house style, consistent with B/C look).

## Verification
- Go: `go test ./...` — unit + integration (requires local Valkey running).
- Valkey: `docker exec valkey valkey-cli ping` → PONG.
- MySQL proxy: `docker exec mysql-test mysql -h host.docker.internal -P 3306 -u <token> -e "SELECT 1"`.
- PG proxy: `docker exec pg-test psql -h host.docker.internal -p 3306 -U <token> -d appdb -c "SELECT 1"` (shared port).
- Control API: curl matrix with/without bearer JWT → 200 vs 401 (login via `POST /api/login` first; role gates: checker-role JWT for kill/sessions, maker blocked unless `allow_maker_watch`; checker write-mint → 403). The old X-Api-Key/session-cookie matrix is GONE — never test with `X-Api-Key` on `/api/*`.
- WS: `node -e 'const ws=new WebSocket("ws://127.0.0.1:8080/ws/checker?access_token=<jwt>&channel=*");…'` (Node ≥22 global WebSocket; the token rides the URL query, not a cookie).
- E2E: two-browser Maker/Checker gate (recipe: PLAN.md Phase 5).
- All async operations must be verified with real tool output.
