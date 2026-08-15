# RUN.md — Project-D: Zero-Trust JIT DB Access Gateway

How to stand up the full stack (Valkey + MySQL + PostgreSQL backends + Control Plane + Data Plane)
from a clean state and connect a thick client (HeidiSQL / mysql CLI / psql) with a single-use token.

**Time budget:** ~5 min the first time (image pulls + seeds); **< 2 min** on a machine where the three
containers already exist (assumed up from Phase 0). The two `go run` boots + first token + first
`SELECT` are typically ~10–30 s total.

---

## 0. Prerequisites

| Requirement | Check |
|---|---|
| Docker Desktop running | `docker info --format '{{.ServerVersion}}'` prints a version |
| Go toolchain (1.25+) | `go version` |
| git-bash (or WSL) on Windows | this guide's commands are bash-flavored |
| Optional: PM2 (`npm i -g pm2`) | `pm2 --version` — only needed for the PM2 path (§7) |

The three containers (`valkey`, `mysql-test`, `pg-test`) are the **only** external services for the
default plaintext posture. Phase 7 (TLS/sentinel, §6) adds two optional ones: `valkey-tls` and
`valkey-sentinel`. All commands below run from the repo root:

```bash
cd /d/AI/hermes/Project/Project-D        # Windows: cd D:\AI\hermes\Project\Project-D
```

---

## 1. Backend containers (Phase 0 — one-time setup)

If a container already exists from a previous session, skip straight to the readiness checks
(or `docker start valkey mysql-test pg-test mssql-test`). Create missing ones with the exact commands below.

### 1.1 Valkey (shared store: tokens, sessions, Pub/Sub)

```bash
docker run -d --name valkey -p 6379:6379 -v valkey-data:/data valkey/valkey:8-alpine --save 60 1
docker exec valkey valkey-cli ping        # expect: PONG
```

### 1.2 MySQL 8.4 test backend (`mysql-test`, host port 3307)

```bash
docker run -d --name mysql-test -p 3307:3306 -e MYSQL_ROOT_PASSWORD=root_pw -e MYSQL_DATABASE=appdb mysql:8.4 --mysql-native-password=ON
```

Wait for readiness (retry up to 60 s):

```bash
docker exec mysql-test mysqladmin -uroot -proot_pw ping    # expect: mysqld is alive
```

Seed users + demo data (users `ro_user`/`ro_pw`, `rw_user`/`rw_pw`, 3 demo rows):

```bash
docker exec mysql-test mysql -uroot -proot_pw appdb -e "
CREATE USER 'ro_user'@'%' IDENTIFIED WITH mysql_native_password BY 'ro_pw';
GRANT SELECT ON appdb.* TO 'ro_user'@'%';
CREATE USER 'rw_user'@'%' IDENTIFIED WITH mysql_native_password BY 'rw_pw';
GRANT ALL PRIVILEGES ON appdb.* TO 'rw_user'@'%';
CREATE TABLE IF NOT EXISTS demo_items (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100));
INSERT INTO demo_items (name) VALUES ('test'),('bravo'),('charlie');
FLUSH PRIVILEGES;"
```

Verify: `docker exec mysql-test mysql -uroot -proot_pw -e "SELECT COUNT(*) FROM appdb.demo_items;"` → `3`.

### 1.3 PostgreSQL 17 test backend (`pg-test`, host port 5433)

```bash
docker run -d --name pg-test -p 5433:5432 -e POSTGRES_USER=app_user -e POSTGRES_PASSWORD=app_pw -e POSTGRES_DB=appdb postgres:17
```

Wait for readiness (retry up to 60 s):

```bash
docker exec pg-test pg_isready -U app_user -d appdb    # expect: accepting connections
```

Seed users + demo data. **Order matters: `CREATE TABLE` BEFORE `GRANT SELECT ON ALL TABLES`**
(otherwise a fresh seed grants on zero tables):

```bash
docker exec pg-test psql -U app_user -d appdb -c "
CREATE ROLE ro_user LOGIN PASSWORD 'ro_pw';
GRANT CONNECT ON DATABASE appdb TO ro_user;
GRANT USAGE ON SCHEMA public TO ro_user;
CREATE TABLE IF NOT EXISTS demo_items (id SERIAL PRIMARY KEY, name TEXT);
INSERT INTO demo_items (name) VALUES ('alpha'),('bravo'),('charlie') ON CONFLICT DO NOTHING;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro_user;"
```

Verify: `docker exec pg-test psql -U app_user -d appdb -tAc "SELECT COUNT(*) FROM demo_items;"` → `3`.

### 1.4 MSSQL 2022 test backend (`mssql-test`, host port 1434)

Phase 9 (Task 9.1): TDS test backend. SA password meets SQL Server policy
(8+ chars, 3 of 4 classes); dev app logins use CHECK_POLICY=OFF.

```bash
docker run -d --name mssql-test -p 1434:1433 -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD='SqlSrv_2022!' -e MSSQL_PID=Developer mcr.microsoft.com/mssql/server:2022-latest
```

Wait for readiness (retry up to 120 s — first boot initializes system DBs).
sqlcmd v18 (mssql-tools18, in-image) defaults to Encrypt=mandatory, so `-C`
trusts the container's self-signed cert; `-N o` (Encrypt=Optional) selects
plaintext instead:

```bash
for i in $(seq 1 24); do docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P 'SqlSrv_2022!' -C -Q "SELECT 1" >/dev/null 2>&1 && break; sleep 5; done
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P 'SqlSrv_2022!' -C -Q "SELECT @@VERSION"
```

Seed db + demo data + mixed-mode SQL logins. Idempotent; `GO` separates
batches; `CREATE DATABASE` must be its own batch; users/grants run in
`appdb` context (grants on objects in another database are rejected):

```bash
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P 'SqlSrv_2022!' -C -b -Q "
USE master;
GO
IF DB_ID('appdb') IS NULL CREATE DATABASE appdb;
GO
USE appdb;
GO
IF OBJECT_ID('dbo.demo_items') IS NOT NULL DROP TABLE dbo.demo_items;
CREATE TABLE dbo.demo_items (id INT PRIMARY KEY, name NVARCHAR(100));
INSERT INTO dbo.demo_items (id, name) VALUES (1, 'test'), (2, 'bravo'), (3, 'charlie');
GO
CREATE LOGIN ro_user WITH PASSWORD='ro_pw', CHECK_POLICY=OFF, CHECK_EXPIRATION=OFF;
CREATE USER ro_user FOR LOGIN ro_user;
GRANT SELECT ON dbo.demo_items TO ro_user;
GO
CREATE LOGIN rw_user WITH PASSWORD='rw_pw', CHECK_POLICY=OFF, CHECK_EXPIRATION=OFF;
CREATE USER rw_user FOR LOGIN rw_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.demo_items TO rw_user;
GO"
```

Verify (ro_user SELECT; ro_user INSERT denied — read-only proof; rw_user
exercises INSERT/UPDATE/DELETE then restores the 3-row seed):

```bash
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U ro_user -P ro_pw -d appdb -C -Q "SELECT COUNT(*) FROM demo_items"    # expect: 3
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U ro_user -P ro_pw -d appdb -C -b -Q "INSERT INTO demo_items VALUES (99, 'nope')"   # expect: Msg 229, INSERT permission denied
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U rw_user -P rw_pw -d appdb -C -b -Q "INSERT INTO demo_items VALUES (4, 'delta'); UPDATE demo_items SET name='delta2' WHERE id=4; DELETE FROM demo_items WHERE id=4; SELECT COUNT(*) FROM demo_items"   # expect: 3
```

Encryption flags (empirically verified on this image, sqlcmd v18):
- no flags → fails: Encrypt=mandatory rejects the self-signed cert
  (`certificate verify failed`).
- `-C` → TLS with the self-signed cert trusted (works).
- `-N o` (Encrypt=Optional) → plaintext (works).
Use `-C` for TLS mode or `-N o` for plaintext; the proxy side negotiates
per PLAN.md Phase 9 (Task 9.2).

#### TDS through the proxy (Task 9.2) — token as the username

The proxy answers the client PRELOGIN with `ENCRYPT_NOT_SUP` when the data
plane runs plaintext (`tls.enabled: false`) — a mandatory-encryption client
(bare sqlcmd, no `-N o`) aborts cleanly, `-N o` proceeds plaintext. With
`tls.enabled: true` it answers `ENCRYPT_ON` and the client MUST upgrade.
sqlcmd connects to the same shared port as MySQL/PostgreSQL — the
dispatcher detects TDS by the client-first PRELOGIN byte (0x12). The token
goes in the USERNAME field; the password is ignored (`-P x`). The token's
`db_ip`/`db_port` select the backend (mssql preset → `127.0.0.1:1434`):

```bash
# token for the mssql preset (Control Plane must be running):
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/token -H "X-Api-Key: dev-ke...-me" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# plaintext plane:  expect `1` / `(1 rows affected)`, exit 0
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$TOKEN" -P x -N o -Q "SELECT 1"
# TLS plane (ZT_TLS_ENABLED=true):  same result with -C (0x12-wrapped upgrade)
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$TOKEN" -P x -C -Q "SELECT 1"
# wrong/expired token → canonical 18456, exit 1 (renders EXACTLY like the
# real server's own rejection — round-9 verified byte-for-byte):
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U sess_badbadbadbadbadbadbadbadbadb -P x -N o -Q "SELECT 1"
# → Sqlcmd: Error: Microsoft ODBC Driver 18 for SQL Server : Login failed for user 'sess_badbad…'.  (exit 1)
```

TDS wiring notes (all pinned by live captures, rounds 6-9):
- **0x12-wrapped TLS upgrade**: the TLS handshake does NOT run raw — the
  client wraps every handshake record in a TDS packet type 0x12 (PRELOGIN);
  the server answers the same way. The proxy's `tdsTLSConn` seam
  strips/re-adds that framing for `tls.Conn`. Post-handshake the LOGIN7 and
  everything after travel as **bare TLS records** (no TDS header) — the
  seam switches to pass-through (`bare`) after `HandshakeContext`.
- **TLS 1.2 only on the client leg**: the real SQL Server 2022 negotiates
  TLS 1.2 (cipher c02f); the proxy pins `MaxVersion: TLS 1.2` so the
  client leg's framing stays 0x12-wrapped through the whole handshake (a
  TLS 1.3 ServerHello flips mid-handshake to bare records — a mixed stream
  real ODBC 18 clients cannot follow). The backend leg negotiates whatever
  the backend offers.
- **Derived obfuscation**: the backend LOGIN7 password is NOT sent in the
  clear — it is XOR-obfuscated with the per-login magic key derived from
  the client's own obfuscation fields (the `ClientProgVer`/`ClientPID`/…
  block), exactly like the real client does for its own password. The
  client leg's LOGIN7 is rewritten: token → real `db_user`, dummy password
  → resolver password (obfuscated), `database` field kept. The token value
  itself never leaves the data plane's valkey GETDEL.
- **Login failure shape**: `ERROR` token 18456 (class 14/state 1) with the
  `US_VARCHAR` message length in UTF-16 code units, `B_VARCHAR`
  server/proc names, then `DONE` status 0x0002 and connection close —
  byte-identical to the real server's rejection (round-8/9 captures).
- Login response relay is byte-exact; the backend's LOGINACK/ENVCHANGE/DONE
  are passed through verbatim (only the TDS envelope is rebuilt).

#### Relay capture + session events (Task 9.3) — mssql queries reach the checker

SQL batches (`0x01`) and RPCs (`0x03`) are sniffed client→backend; the
backend→client result stream (COLMETADATA → ROW/NBCROW → DONE/ERROR) is
captured pre-write while the relay stays byte-exact. Each command publishes
ONE QueryEvent — exactly like MySQL/PG — to `queries:<user>`,
`queries:ticket:<t>` and `queries:sess:<sid>`, with `stmt_type`, `status`,
`columns`/`rows` (caps: 100 rows, 512 chars/cell, 64 KB total, `truncated`
flag) and `db: appdb`. The Checker dashboard (`/ws/checker`) and
`/api/sessions` are protocol-agnostic, so mssql sessions and events appear
alongside MySQL/PG with no frontend changes:

```bash
# any mssql token (see the TDS-through-the-proxy block above) — then a real query:
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 \
  -U "$TOKEN" -P x -N o -d appdb -Q "SELECT id, name FROM demo_items ORDER BY id"
# → 3 rows; the checker feed carries one event:
#   {"kind":"query","db_type":"mssql","sql":"SELECT id, name FROM demo_items",
#    "stmt_type":"select","status":"ok","columns":["id","name"],
#    "rows":[["1","test"],["2","bravo"],["3","charlie"]],"db":"appdb"}
#   (INSERTs publish stmt_type=insert; failures publish status=error with the
#    server message, e.g. "Invalid object name 'no_such_table_zz'.")

# the session shows up in the checker directory with its database:
curl -b /tmp/zt.jar http://127.0.0.1:8080/api/sessions
# → 200 → [..., {"db_type":"mssql","db":"appdb", ...}, ...]
```

Wire notes pinned by live captures (2026-08-15): the live SQL Server 2022
NEVER sets the DONE_FINAL bit on query responses — completion is the message
EOM after a DONE-family token (documented in `mssql_capture.go`).
ATTENTION (`0x06`) / LOGOUT (`0x0E`) pass through untouched; the maker
write-gate slots into the client→backend sniff (Task 9.4).

---

## 2. Start the planes (control → data)

Both planes read `configs/*.yaml` **relative to the repo root** — always start them from there.

### 2.1 Control Plane (:8080 — REST + WS hub + Angular SPA)

```bash
cd /d/AI/hermes/Project/Project-D
go run ./cmd/control
```

Optional — enable external token issuance with an API key (recommended for ticketing integrations):

```bash
export ZT_API_API_KEY='dev-key-change-me'     # maps to configs/control.yaml api.api_key
go run ./cmd/control
```

Readiness (second terminal):

```bash
curl -s http://127.0.0.1:8080/api/health      # expect: {"status":"ok","valkey":"up"}
```

> The Angular SPA must already be built (`web/dist/web/browser/`). If the UI 404s, rebuild:
> `cd web && npm ci && npm run build && cd ..` then restart the control plane.

### 2.2 Data Plane (:3306 — ONE shared port, MySQL + PostgreSQL)

```bash
cd /d/AI/hermes/Project/Project-D
go run ./cmd/data
```

Readiness (second terminal): the log line `"dispatcher listening"` with `"addr":":3306"`, or

```bash
netstat -ano | grep ':3306' | grep -i listen
```

### 2.3 Credential source (Task 8.7): config list vs credential API

The Data Plane owns the backend DB passwords (zero-trust). Where they come from is
`credentials_source` in `configs/data.yaml` (env `ZT_CREDENTIALS_SOURCE`):

- **`config` (default)** — the committed `credentials:` list in `configs/data.yaml`.
  Key format: `<dbtype>:<db_user>@<db_ip>:<db_port>` (e.g. `mysql:ro_user@127.0.0.1:3307`).
- **`api`** — fetch the password per connect from a vault HTTP endpoint
  (`credentials_api.url`; env `ZT_CREDENTIALS_API_URL`; `api_key` → `X-Api-Key` header,
  env `ZT_CREDENTIALS_API_API_KEY`; `timeout_seconds` default 5, env
  `ZT_CREDENTIALS_API_TIMEOUT_SECONDS`). Load fails fast when `source=api` and the URL is
  empty, so a data plane that cannot resolve passwords never starts silently.

Vault contract (the only thing the endpoint must implement):

```
GET {url}?db_type=<mysql|postgres>&db_user=<user>&db_ip=<host>&db_port=<port>
X-Api-Key: <api_key>

200 → {"password": "<the backend db password>"}
anything else → the connect fails; the error carries the STATUS CODE ONLY
```

Password hygiene (HARD requirement, user directive 2026-08-13): the password is **never
stored and never logged** — it exists in memory only for the in-flight connect call. No
caching, no disk writes, no log field. Non-200 vault responses surface as status-only
errors; the response body is never read into an error or log line. Keys in the credential
list are plaintext in the committed file (as before); `api` mode removes even that.

Quick check (vault stub with `python`):

```bash
python -c "import http.server,socketserver; \
class H(http.server.BaseHTTPRequestHandler):
  def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'{\"password\":\"ro_pw\"}')
socketserver.TCPServer(('127.0.0.1',9000),H).serve_forever()" &
# configs/data.yaml: credentials_source: api, credentials_api.url: http://127.0.0.1:9000/creds
go run ./cmd/data   # then §4: token → SELECT works, password served by the stub
```

### 2.4 Query logging (Task 8.8)

Every query passing through the proxy is **always** logged at Info with full context:

```
msg=query  username ticket_id db_user db db_type stmt_type status session_id sql
```

(`ticket_id` present only when the token was issued with one.) Session lifecycle events are
logged the same way as `msg="session started"` / `msg="session ended"` — same context fields,
no SQL; their `ticket_id` comes from the token, matching the query lines.

`log_query_output` (`configs/data.yaml`, env `ZT_LOG_QUERY_OUTPUT`, default **false**) adds the
captured result payload to each query line: `columns`, `row_count`, `rows` (already capped by
capture: 100 rows / 512 chars / 64 KB) and the `truncated` flag:

```bash
ZT_LOG_QUERY_OUTPUT=true go run ./cmd/data
```

**Hygiene (HARD):** log lines never contain credentials or token values — only the context
fields above, and — with the flag on — the captured result rows. Lifecycle **wire** events
(`queries:*`) carry no ticket id at all (Task 8.2 contract); the ticket id appears only in
query events and log lines.

### 2.5 Session audit to MySQL (Task 9.7)

The Control Plane persists every session to MySQL — maker username, ticket, db target,
access level, **checker username when present**, lifecycle status and timestamps. The
Control Plane is the writer by design: it sees the lifecycle events (via the hub's
`queries:sess:*` pub/sub) and knows the checker identity on watch attach/detach — the Data
Plane never learns the checker's username.

**Config** (`configs/control.yaml`, env `ZT_AUDIT_MYSQL_*`):

```yaml
audit:
  mysql:
    enabled: false          # ZT_AUDIT_MYSQL_ENABLED — default OFF: no DB dependency
    host: "127.0.0.1"       # ZT_AUDIT_MYSQL_HOST
    port: "3307"            # ZT_AUDIT_MYSQL_PORT   (mysql-test, §1.2)
    user: "root"            # ZT_AUDIT_MYSQL_USER   (dev root; needs CREATE DATABASE — use a dedicated user in prod)
    password: "root_pw"     # ZT_AUDIT_MYSQL_PASSWORD
    database: "zt_audit"    # ZT_AUDIT_MYSQL_DATABASE
```

* **Fail-fast startup:** enabled + missing field, or enabled + unreachable DB → the Control
  Plane refuses to start (`os.Exit(1)` after logging). No silent audit-less operation.
* **Auto-schema:** on startup the writer runs `CREATE DATABASE IF NOT EXISTS` +
  `CREATE TABLE IF NOT EXISTS zt_audit.sessions` (id PK, `session_id` UNIQUE, username,
  ticket_id, db_type, db_user, db, access, `checker_username` NULL, status, started_at,
  ended_at, last_seen, created_at — all DATETIME(3), indexed on status/username).
* **Runtime failures are NON-fatal:** an audit write error is logged and never breaks the
  token/connect flow (the token is already stored; the session still works).

**Lifecycle mapping** (all idempotent `INSERT … ON DUPLICATE KEY UPDATE` upserts keyed by
`session_id`):

| Event | Row change |
|---|---|
| Token issued (`handleToken`) | status=`pending`, maker username, ticket_id, db_type/db_user, access |
| Client connects (data plane `started` on `queries:sess:<sid>`) | status=`active`, `started_at`, db (client-requested database) |
| Client disconnects (data plane `ended`) | status=`ended`, `ended_at` |
| Checker watches `channel=sess:<sid>` (WS attach) | `checker_username` = checker's username (e.g. `admin`) |
| Checker disconnects (WS detach) | `checker_username` = NULL |

**Verify** (audit enabled Control Plane running, §2.1):

```bash
docker exec mysql-test mysql -h127.0.0.1 -P3306 -uroot -proot_pw \
  -e "SELECT session_id, username, ticket_id, db, checker_username, status, started_at, ended_at \
      FROM zt_audit.sessions ORDER BY id DESC LIMIT 5\G"
```

Issue a token (§3), connect (§4), attach a checker WS (§5.2) — the row walks
pending → active → checker set → NULL on detach → ended when the client disconnects.

### 2.6 OTel metrics / Prometheus scrape endpoint (Task 9.8)

The Data Plane exposes OpenTelemetry instruments in the Prometheus text format on an
HTTP endpoint a Prometheus server can scrape. **Disabled by default** (`metrics.enabled:
false`) — the proxies' metrics wrapper stays nil and every call site is a no-op (zero
overhead). Enable it in `configs/data.yaml` or via env:

```yaml
# configs/data.yaml — Task 9.8 metrics block
metrics:
  enabled: false          # ZT_METRICS_ENABLED — false = zero overhead (no-op call sites)
  listen: "0.0.0.0:9464"  # ZT_METRICS_LISTEN — scrape endpoint bind
  path: "/metrics"        # ZT_METRICS_PATH   — scrape path
```

```bash
ZT_METRICS_ENABLED=true go run ./cmd/data    # logs: msg="metrics endpoint" addr="0.0.0.0:9464" path="/metrics"
```

The endpoint serves the meter's instruments **and** the standard Go runtime/process
collectors (`go_*`, `process_*`) from the same default gatherer — exactly what a real
Prometheus server scrapes. Point a job at it:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: zt-data
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

Scrape check (expect 200 + `zerotrust_proxy_*` families):

```bash
curl -s http://127.0.0.1:9464/metrics | grep -E "^(# HELP zerotrust_proxy|zerotrust_proxy_)" | head
```

Instruments (all under the `zerotrust_proxy` namespace, meter `zerotrust.proxy`):

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `tokens_validated_total` | counter | — | Tokens accepted by GETDEL + protocol match |
| `tokens_rejected_total` | counter | `reason` (invalid\|expired\|consumed\|wrong_db_type) | Token validation rejections |
| `connections_total` | counter | `db_type`, `result` (ok\|rejected) | Connection attempts by outcome |
| `connections_active` | updowncounter | `db_type` | Currently established sessions |
| `queries_total` | counter | `db_type`, `stmt_type`, `status` | Query events published by the relay — **including blocked commands** (see below) |
| `gate_blocks_total` | counter | `db_type` | SQL commands blocked by the maker write-gate |
| `kills_total` | counter | `mode` (query\|connection) | Kill operations applied |
| `session_duration_seconds` | histogram | `db_type` | Session lifetime (established → teardown) |
| `query_duration_seconds` | histogram | `db_type` | Query latency (sniffed → response completed) |

**Blocked-command semantics (Task 9.8 round 4):** a command blocked by the maker
write-gate never reaches the backend, but it IS a published query event with
`status="error"` — so every blocked-command path (immediate reject AND grace-wait drain,
all three protocols: MySQL `publishBlocked`/`gateRejectEntries`, PostgreSQL
`publishBlocked`/`gatePGRejectEntries`, MSSQL `publishBlocked`/`gateMSSQLRejectEntries`)
increments **both** `gate_blocks_total{db_type}` and
`queries_total{db_type, stmt_type, status="error"}`. A gated `INSERT` therefore shows up
as `queries_total{db_type="mysql",stmt_type="insert",status="error"} 1` alongside
`gate_blocks_total{db_type="mysql"} 1` — the audit view and the metrics view never
diverge.

Live-verified deltas (round 4, `cmd/data/zz_live_metrics_test.go`): one `SELECT 1` from
the go-mysql client → `tokens_validated_total +1`, `queries_total{select,ok} +1`,
`connections_total{ok} +1`, `connections_active 0→1→0`; `ctl:kill` → `kills_total{mode=connection}
+1`; gated `INSERT` → `gate_blocks_total{mysql} +1` AND `queries_total{insert,error} +1`;
bogus token → `tokens_rejected_total{reason=invalid} +1`, `connections_total{rejected} +1`.

---

## 3. Issue a token (curl)

Tokens are single-use, TTL 300 s, stored in Valkey (`tok:<token>`), consumed atomically on first
connection. **One token = one connection** — get a fresh token per connect.

### 3.1 API-key flavor (external systems)

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/token \
  -H "X-Api-Key: dev-key-change-me" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"TICKET-1"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "$TOKEN"
```

Response shape (token is always `sess_…`): `{"token":"sess_…","host":"127.0.0.1","port":"3306","expires_in":300}`.

### 3.2 Session-cookie flavor (UI session)

```bash
curl -s -c /tmp/zt.jar -X POST http://127.0.0.1:8080/api/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}'
TOKEN=$(curl -s -b /tmp/zt.jar -X POST http://127.0.0.1:8080/api/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"TICKET-1"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "$TOKEN"
```

For PostgreSQL swap `"db_type":"postgres"` and the backend port `"db_port":"5433"` (user `ro_user`).

> Token without key/session → `401`; unknown `db_type` → `422`; missing fields → `400`.

---

## 4. Connect with the token

### 4.1 MySQL CLI through the proxy (shared port 3306)

```bash
docker exec mysql-test mysql -h host.docker.internal -P 3306 -u "$TOKEN" -proot_pw appdb \
  -e "SELECT id,name FROM demo_items;"
# expect: 3 rows (test/bravo/charlie); password is ignored — the TOKEN is the credential
```

### 4.2 psql through the proxy (same shared port 3306!)

```bash
docker exec pg-test psql -h host.docker.internal -p 3306 -U "$TOKEN" -d appdb \
  -c "SELECT id,name FROM demo_items;"
```

### 4.3 HeidiSQL (Windows thick client) — connection recipe

| Field | Value |
|---|---|
| Host | `127.0.0.1` |
| Port | `3306` |
| Username | the token (`sess_…` — paste the whole value) |
| Password | anything (ignored; token is the credential) |
| Database | `appdb` |

**One shared port serves BOTH protocols.** The Data Plane detects the protocol per connection
(PostgreSQL clients send startup bytes first; MySQL clients wait for the server handshake).
HeidiSQL is a MySQL client → server-first path, so **every MySQL connect takes ~200 ms longer**
(`detect_delay_ms` grace, `configs/data.yaml`) before the handshake is sent — that is expected.
For PostgreSQL use psql or any PG client pointed at the same `127.0.0.1:3306`.

**Reusing a token** (second connect) → `ERROR 1045 (42000): invalid or expired token` (MySQL) /
`FATAL: invalid or expired token` (PG). Issue a new token.

---

## 5. Web UI (Maker + Checker)

| URL | Purpose |
|---|---|
| `http://127.0.0.1:8080/maker` | Maker Portal — pick a preset, generate + copy a token |
| `http://127.0.0.1:8080/checker` | Checker dashboard — live audit feed (`channel=*` = all queries) |
| `http://127.0.0.1:8080/login` | Login |

Login: **admin / admin123** — dev-only defaults, change via `configs/control.yaml`
(`auth.username` / `auth.password`) or env `ZT_AUTH_USERNAME` / `ZT_AUTH_PASSWORD`.

Checker is **monitor-only** for statements in v1 (live audit; no approval of queries). UI tokens
can only target the `db_presets` allowlist from `configs/control.yaml`. Phase 8 adds per-session
selection and two-level kill — see 5.2 below.

### 5.1 Maker write-gating (Task 8.6)

A **write-access** maker token (`db_presets[].access: write` — the MySQL read-write preset) cannot
run **ANY** SQL until a checker is watching the maker's session. Read-only tokens (`access: read` —
MySQL read-only and PG read-only presets) are **never** gated — the gate applies only to write-access
sessions.

How it works:

| Layer | Mechanism |
|---|---|
| Presence | A checker subscribed to the session's own channel (`sess:<sid>`) makes the WS hub keep `watch:<sid>` in Valkey: a 30 s lease refreshed every 10 s by the checker's heartbeat while connected, removed on disconnect or channel switch |
| Gate | Before relaying any SQL-executing command (`COM_QUERY` 0x03 / `COM_STMT_PREPARE` 0x16 / `COM_STMT_EXECUTE` 0x17; PG `Q` / `P` / `E`) on a write-access session, the data plane checks `EXISTS watch:<sid>` — **per command, never cached** |
| Blocked | No watcher (or store error — **fail closed**) → the client gets MySQL `ERR 1045` / PG `FATAL 28000` with the message **`maker gating: no checker connected to session <sid>`**; the statement is NOT forwarded, and the audit feed still shows the query with `status=error` + the gating message |
| Re-enable | A checker watching the session again (subscribe to `sess:<sid>`) unblocks the **same** session — a block never kills the connection |

Practical flow for a write-access maker: generate the token → a checker opens the session (Checker
dashboard session selector, or any WS client subscribing to `sess:<sid>`) → INSERT/UPDATE/DELETE
work. If the watcher is removed mid-session, the very next query is blocked until a checker watches
the session again.

**Grace window (Task 8.13 — maker-first no longer breaks).** When a write-access maker connects
BEFORE any checker, blocked SQL is not rejected instantly — it WAITS for a watcher:

| Aspect | Behavior |
|---|---|
| Config | `data.yaml` `gate_wait_seconds` (default **20**, env `ZT_GATE_WAIT_SECONDS`; **0 = reject immediately** = the pre-8.13 behavior above) |
| Wait | While a write session has NO watcher, SQL commands queue per session (bounded at **16** held commands; overflow rejects only the new command — the queue keeps waiting). The client stays connected with **no error and no response** |
| Watcher arrives | Within the window → the queued commands flush **in order** to the backend exactly as the normal relay would send them; each command runs and returns its real result |
| Window expires | No watcher → every held command is rejected to the client (MySQL `ERR 1045` / PG `FATAL 28000`) with **`maker gating: no checker connected within <N>s (session <sid>)`** and each gets an audit event (`status=error`) |
| Re-open on watch (Task 8.17) | A drain does **not** latch the session. Unwatched commands keep getting the grace wait + drain (1045/28000 + audit); the moment a checker **re-attaches** (`watch:<sid>` reappears), the gate re-opens and the maker's next command **flows** — no reconnect, the session survives |
| Watch re-check | The watcher is re-checked on a 500 ms ticker AND on every new command arrival, so the unblock latency is at most one tick |

Practical flow: issue the write token → the session shows up in `/api/sessions` and the Checker
selector immediately as **pending** (before any connect) → the checker selects the pending session
→ the maker connects → the first query passes (no deadlock, no wait). Maker-first still works too:
issue the write token → maker connects and runs a query (it WAITS, client alive) → checker selects
the pending session / subscribes to `sess:<sid>` within the window → the held query RUNS and
returns rows. If no checker appears within `gate_wait_seconds`, the maker gets the 1045/28000
rejection and stays blocked while unwatched — but when a checker re-attaches (e.g. the checker
dropped and rejoins by subscribing to `sess:<sid>` again), the maker's **next** query runs
immediately, on the **same connection**: the gate re-opens on watch, it never latches. Read-only
sessions are never held (ro is exempt from the gate).

### 5.2 Checker sessions + two-level kill (Phase 8)

**Session directory.** Every connection through the data plane is recorded in Valkey under
`sess:live:<sid>` (JSON: `session_id, username, db_user, db_type, db, started_at, last_seen,
thread_id|pid`), SETEX TTL 60 s — SET on start, REFRESH on every published event, DEL on end
(idle-but-open sessions drop off after 60 s, documented). The checker lists them with

```bash
curl -b /tmp/zt.jar http://127.0.0.1:8080/api/sessions   # session cookie required
# 200 → [{"session_id","username","db_user","db_type","db","started_at","last_seen"}, ...]
```

**Per-session feed.** Every query event is published to `queries:<user>` AND `queries:sess:<sid>`;
session start/end publish lifecycle events (`kind=session`, `action=started|ended`) to both.
Selecting a session in the Checker dashboard (or any WS client subscribing to
`ws://127.0.0.1:8080/ws/checker?channel=sess:<sid>`) switches the feed to ONLY that session's
events; `channel=*` remains the all-queries feed.

**Two-level kill.** `POST /api/kill` takes an optional `mode`:

| mode | behavior |
|---|---|
| `connection` (default) | full disconnect: client + backend conns closed, session removed from the directory (`sess:live` deleted, `ended` event published) — the maker sees MySQL `2013 Lost connection` |
| `query` | aborts only the in-flight query via a second backend connection (`KILL QUERY <thread_id>` MySQL / `pg_cancel_backend(<pid>)` PG); the session stays alive and the maker can keep running queries. No active query → idempotent ok |

```bash
curl -b /tmp/zt.jar -X POST http://127.0.0.1:8080/api/kill \
  -H 'Content-Type: application/json' -d '{"session_id":"sid-...","mode":"query"}'  # 202 {"killed":"queued"}
```

The Checker dashboard shows one row per session with two buttons: **Kill query** (mode=query,
session survives) and **Kill connection** (mode=connection, session removed).

### 5.3 MSSQL kill + write-gating (Task 9.4)

The same kill + write-gate machinery applies to the TDS plane; only the wire mechanism differs:

| Aspect | MySQL / PostgreSQL | MSSQL (TDS) |
|---|---|---|
| Kill query | second backend conn: `KILL QUERY <thread_id>` / `pg_cancel_backend(<pid>)` | **ATTENTION packet (type 0x06)** on the LIVE backend conn — header-only (length 8, no payload), SPID field from the login-response ENVCHANGE token (0 when the server announced none) |
| Kill connection | close both conns via the registry closer | identical (registry closer) |
| Gated messages | `COM_QUERY` 0x03 / `COM_STMT_PREPARE` 0x16 / `COM_STMT_EXECUTE` 0x17; PG `Q` / `P` / `E` | **SQL batch (0x01)** and **RPC (0x03)** messages on write-access sessions (control types — prelogin, login7, ATTENTION, logout, tabular — never gate) |
| Block response | MySQL `ERR 1045` / PG `FATAL 28000` | TABULAR stream with an **ERROR token (18456, class 14)** + DONE_ERROR tail — sqlcmd renders `Msg 18456, Level 14, State 1: maker gating: no checker connected to session <sid>` |

**ATTENTION / kill-query semantics.** `POST /api/kill` with `mode=query` on an mssql session
writes the ATTENTION packet on the live backend connection (writes are serialized with the
relay's forwards, so it can never interleave mid-message):

- The attention is sent **only while a command is genuinely in flight** (the sniff's pending
  event is set). An idle session is refused with a warn (`kill query: no command in flight`)
  and never touched; an unknown session reports false.
- The backend aborts the in-flight batch and answers with an **ERROR/DONE_ERROR** response
  (live capture `fd 02 00 …`) — the client sees that error, and the audit event publishes as
  `status=error`.
- The backend then sends a **separate DONE_ATTN acknowledgement** (live capture `fd 20 00 …`).
  The client never asked to cancel, so the proxy **swallows that ack proxy-side** (the
  `attnPending` flag is armed before the write and consumed by the backend→client pipe, logged
  `attention ack swallowed`): forwarding it would corrupt the client's protocol state — its
  next batch would read the stale ack as its response. The client sees only the aborted
  batch's error, and its **next command runs normally on the same session** — no reconnect.
  Client-initiated attentions (their acks arrive with the flag unset) still pass through
  untouched.

**Write-gating on TDS** — same rule as §5.1, applies to mssql write-access tokens: a
per-command `EXISTS watch:<sid>` check (never cached), **fail closed** on store error,
read-only sessions exempt, a block never kills the connection, and a re-attached watcher
re-opens the same session. The **grace window** (§5.1 Task 8.13) applies identically:
unwatched SQL batches queue per session (bounded at 16 held messages), flush in order when a
checker attaches, and drain with the 18456 rejection + audit event (`status=error`) when
`gate_wait_seconds` expires (`0` = reject immediately); a drain does not latch — re-watch
re-opens.

Practical flow: issue a write-access mssql token → connect with sqlcmd through the shared
port (3306; `-N o` plaintext or `-C` TLS) → run `WAITFOR DELAY '00:00:30'` → Checker
**Kill query** → the batch aborts with the attention error, `SELECT 1` on the SAME session
returns real rows → **Kill connection** → the client drops and the session leaves `sess:live`.
Without a checker, an INSERT is held/blocked per the gate rule above.

---

## 6. TLS mode & Valkey TLS / Sentinel (Phase 7 — optional)

Everything above is the **default plaintext** posture (`tls.enabled: false` in `configs/*.yaml`).
Phase 7 adds three independent TLS surfaces, each behind an explicit switch (absent/false =
plaintext, exactly the defaults committed in `configs/`):

| Surface | Switch (env / config key) | Default |
|---|---|---|
| Control Plane HTTPS (REST + WS + SPA) | `ZT_TLS_ENABLED` / `tls.enabled` (`configs/control.yaml`) | off |
| Data Plane wire TLS (MySQL SSL + PG SSLRequest handshakes) | `ZT_TLS_ENABLED` / `tls.enabled` (`configs/data.yaml`) | off |
| Valkey client TLS (tokens/sessions/PubSub) | `ZT_VALKEY_SSL_ENABLED` / `valkey.ssl.enabled` | off |

> Both planes read the same env names because both configs use the same key paths. Enabling TLS
> **requires** readable cert+key files — the plane fails fast at boot otherwise.

### 6.1 Certificates (one-time)

```bash
bash scripts/gen-certs.sh   # idempotent; writes certs/control.{crt,key} + certs/data.{crt,key}
```

Self-signed rsa:2048, 365 days, `CN=127.0.0.1`, SAN `IP:127.0.0.1,DNS:localhost` (the cert doubles as
its own CA). `configs/*.yaml` already point `tls.cert_file`/`tls.key_file` and `valkey.ssl.ca_file`
at these files. Production must use real CA-signed certs.

### 6.2 Valkey with TLS (`valkey-tls`, host port 6380)

```bash
docker run -d --name valkey-tls -p 6380:6380 \
  -v D:/AI/hermes/Project/Project-D/certs:/certs:ro \
  valkey/valkey:8-alpine valkey-server --port 0 --tls-port 6380 \
  --tls-cert-file /certs/data.crt --tls-key-file /certs/data.key \
  --tls-ca-cert-file /certs/data.crt --tls-auth-clients no
docker exec valkey-tls valkey-cli --tls --cacert /certs/data.crt -p 6380 ping   # expect: PONG
```

### 6.3 Sentinel (`valkey-sentinel`, host port 26379)

```bash
docker run -d --name valkey-sentinel -p 26379:26379 \
  -v D:/AI/hermes/Project/Project-D/scripts/sentinel.conf:/etc/sentinel.conf:ro \
  valkey/valkey:8-alpine sh -c 'cp /etc/sentinel.conf /tmp/sentinel.conf && exec valkey-sentinel /tmp/sentinel.conf'
docker exec valkey-sentinel valkey-cli -p 26379 -a sentinelpw --no-auth-warning \
  sentinel get-master-addr-by-name mymaster
# expect: 127.0.0.1 / 6379
```

> **Entrypoint workaround (verified 2026-08-12):** the valkey image's `valkey-sentinel` demands a
> **writable** config file, so a read-only `/etc/sentinel.conf` mount alone fails at boot. The
> `sh -c` wrapper copies it to `/tmp` first, then execs the real sentinel.
>
> **Sentinel auth (Task 7.7, verified 2026-08-12):** `scripts/sentinel.conf` sets
> `requirepass sentinelpw` — the sentinel itself is authenticated, SEPARATE from the master's
> password. The store/planes present it via `valkey.sentinel_password` (env
> `ZT_VALKEY_SENTINEL_PASSWORD`); `valkey.password` stays the master/data-connection password.
> Without it the sentinel answers `NOAUTH`. (The `-a` + `--no-auth-warning` flags on the
> verification line are the CLI equivalent.)
>
> `scripts/sentinel.conf` monitors the **plaintext** master `127.0.0.1:6379` (sentinel TLS is
> optional in dev; the client→sentinel and client→master paths carry TLS). Dev caveat: from inside
> the container that address is its own loopback, so the sentinel may report the master
> `s_down,o_down` — cosmetic here; `get-master-addr-by-name` still returns the configured
> `127.0.0.1:6379` (host-reachable) and the store's sentinel live tests pass.

Config snippet (both planes, sentinel mode):

```yaml
valkey:
  mode: sentinel
  master_name: mymaster
  sentinel_addrs: ["127.0.0.1:26379"]
  # sentinel's OWN auth (requirepass on the sentinel) — SEPARATE from
  # `password` below, which is the MASTER's (Task 8.10). Both can differ;
  # sentinel conns use these, master/data conns use `password`.
  sentinel_username: ""
  sentinel_password: sentinelpw   # env: ZT_VALKEY_SENTINEL_PASSWORD
  password: ""                     # master/data conns — unchanged by sentinel auth
```

> **Two-password model (Task 8.10, verified live 2026-08-13):** `valkey.password` and
> `valkey.sentinel_password` are INDEPENDENT credentials. `password` authenticates the
> master/data connections; `sentinel_password` authenticates the SENTINEL itself (its
> `requirepass`) — they can, and in the auth-distinct infra below do, differ. Each
> misconfiguration fails at the step that owns the credential: missing sentinel password
> → `NOAUTH` from the sentinel; wrong master password → `WRONGPASS` from the master;
> swapped → `WRONGPASS` from the sentinel. The durable live test
> `TestLiveSentinelDistinctPasswords` (internal/store, skips when :26390 is down) proves
> all four cases against the infra below.

### Auth-distinct infra (master and sentinel use DIFFERENT passwords)

Docker Desktop (WSL2) networking pitfall: the container default gateway **172.17.0.1 is
reachable from the container but NOT from the Windows host** — a sentinel monitoring
`172.17.0.1:6390` can ping the master itself, but the host-side store can never dial the
master address the sentinel returns. Use the WSL2 VM eth0 IP instead, which is reachable
from BOTH the sentinel container and the host:

```bash
VMIP=$(wsl -d docker-desktop -- ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+')
# authenticated master (requirepass masterpw)
docker run -d --name valkey-auth-master -p 6390:6390 \
  valkey/valkey:8-alpine valkey-server --port 6390 --requirepass masterpw
# sentinel conf: port 26390, monitors <VMIP>:6390, auth-pass masterpw, requirepass sentinelpw
TMPD=$(mktemp -d)
cat > "$TMPD/sentinel-auth.conf" <<EOF
port 26390
sentinel monitor mymaster $VMIP 6390 1
sentinel down-after-milliseconds mymaster 5000
sentinel failover-timeout mymaster 10000
sentinel auth-pass mymaster masterpw
requirepass sentinelpw
EOF
# auth-distinct sentinel — same cp-to-/tmp entrypoint workaround as above
docker run -d --name valkey-auth-sentinel -p 26390:26390 \
  -v "$TMPD/sentinel-auth.conf:/etc/sentinel.conf:ro" \
  valkey/valkey:8-alpine sh -c 'cp /etc/sentinel.conf /tmp/sentinel.conf && exec valkey-sentinel /tmp/sentinel.conf'
docker exec valkey-auth-master valkey-cli -p 6390 -a masterpw --no-auth-warning ping
# expect: PONG
docker exec valkey-auth-sentinel valkey-cli -p 26390 -a sentinelpw --no-auth-warning \
  sentinel get-master-addr-by-name mymaster
# expect: <VMIP> / 6390
```

> **host.docker.internal pitfall:** it does NOT resolve in the `valkey:8-alpine` image
> without `--add-host host.docker.internal:host-gateway` — and even with that flag the
> sentinel would hand the hostname back to host-side clients, which cannot resolve it.
> The VM eth0 IP is the one address reachable from both the sentinel container and the
> Windows host.

Planes against the auth-distinct infra (distinct passwords on both legs):

```bash
ZT_VALKEY_MODE=sentinel ZT_VALKEY_MASTER_NAME=mymaster \
ZT_VALKEY_SENTINEL_ADDRS='["127.0.0.1:26390"]' \
ZT_VALKEY_PASSWORD=masterpw ZT_VALKEY_SENTINEL_PASSWORD=sentinelpw go run ./cmd/control
```

### 6.4 Planes in TLS mode (HTTPS + wire TLS + TLS Valkey)

```bash
cd /d/AI/hermes/Project/Project-D
# control plane — HTTPS listener + TLS Valkey store + API key (optional)
ZT_TLS_ENABLED=true ZT_VALKEY_SSL_ENABLED=true ZT_VALKEY_ADDR=127.0.0.1:6380 \
ZT_VALKEY_SSL_CA_FILE=certs/data.crt ZT_API_API_KEY='dev-key-change-me' go run ./cmd/control
# data plane — wire TLS on :3306 + TLS Valkey store
ZT_TLS_ENABLED=true ZT_VALKEY_SSL_ENABLED=true ZT_VALKEY_ADDR=127.0.0.1:6380 \
ZT_VALKEY_SSL_CA_FILE=certs/data.crt go run ./cmd/data
```

Readiness is now **HTTPS** (`-k` = self-signed dev cert):

```bash
curl -sk https://127.0.0.1:8080/api/health      # expect: {"status":"ok","valkey":"up"}
```

Sentinel store mode instead of direct TLS Valkey (planes resolve the master through the sentinel;
`valkey.ssl.*` still applies to the client→master leg):

```bash
ZT_VALKEY_MODE=sentinel ZT_VALKEY_MASTER_NAME=mymaster \
ZT_VALKEY_SENTINEL_ADDRS='["127.0.0.1:26379"]' \
ZT_VALKEY_SENTINEL_PASSWORD=sentinelpw go run ./cmd/control
```

### 6.5 Clients with TLS flags (verified 2026-08-12 gate)

```bash
# token over HTTPS — same payloads as §3 (API-key or session-cookie flavor)
TOKEN=$(curl -sk -X POST https://127.0.0.1:8080/api/token \
  -H "X-Api-Key: $ZT_API_API_KEY" -H 'Content-Type: application/json' \
  -d '{"username":"alice","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"TICKET-1"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# MySQL wire TLS — REQUIRED hard-fails if the proxy did not negotiate TLS
docker exec mysql-test mysql -h host.docker.internal -P 3306 -u "$TOKEN" -pany \
  --ssl-mode=REQUIRED appdb -e "SELECT id,name FROM demo_items"

# PostgreSQL wire TLS — sslmode=require must be INSIDE the conninfo string;
# a bare trailing "sslmode=require" argument is IGNORED by psql (verified 2026-08-12)
docker exec pg-test psql "host=host.docker.internal port=3306 user=$TOKEN dbname=appdb sslmode=require" \
  -c "SELECT id,name FROM demo_items"

# kill E2E over HTTPS (session-cookie flavor; 202 = queued, data plane force-closes)
curl -sk -b /tmp/zt.jar -X POST https://127.0.0.1:8080/api/kill \
  -H 'Content-Type: application/json' -d '{"session_id":"sid-..."}'   # expect: 202 {"killed":"queued"}
```

Checker WS in TLS mode is `wss://127.0.0.1:8080/ws/checker?channel=*` — Node ≥ 22 global WebSocket
with `NODE_TLS_REJECT_UNAUTHORIZED=0` (self-signed cert) plus the session cookie header
(`new WebSocket(url, { headers: { Cookie: 'zt_session=...' } })`).

### 6.6 Env override notes (verified live, 2026-08-12)

- `api.api_key` maps to **`ZT_API_API_KEY`** (viper: `ZT_` prefix + dots→underscores) — **NOT**
  `ZT_API_KEY`. Setting only `ZT_API_KEY` is silently ignored and `/api/token` stays key-disabled
  (401); the stale `# set via ZT_API_KEY` comment in `configs/control.yaml` predates this finding.
- Sentinel mode overrides `valkey.addr` (direct mode); both modes share the `valkey.ssl.*` block.

---

## 7. Optional: PM2 (long-running ops)

```bash
cd /d/AI/hermes/Project/Project-D
go build -o bin/control.exe ./cmd/control && go build -o bin/data.exe ./cmd/data
pm2 start ecosystem.config.cjs     # apps: zt-control, zt-data
pm2 logs zt-control                # JSON slog output
pm2 restart zt-data                # e.g. after config change
```

---

## 8. Shutdown (reverse order) + port hygiene

```bash
# 1. stop the data plane first (Ctrl-C in its terminal), then the control plane (Ctrl-C)
#    PM2: pm2 stop zt-data && pm2 stop zt-control   (or: pm2 delete ecosystem.config.cjs)
# 2. optional: stop containers (data stays in the named volumes)
docker stop pg-test mysql-test valkey
#    Phase 7 containers (optional, TLS + sentinel): they may stay up between runs —
#    if you stop them: docker stop valkey-tls valkey-sentinel
# 3. verify the host ports are free:
netstat -ano | grep -E ':(8080|3306|6379|3307|5433)\s' | grep -i listen
#    expect: NO output (containers stopped) or only the container-mapped backend ports
#    (3307/5433/6379) if you left Docker running
```

If a plane won't start with `address already in use`, a previous instance is still bound — kill by
listener PID:

```bash
PID=$(netstat -ano | grep -E ':3306\s.*LISTEN' | awk '{print $NF}' | head -1)
[ -n "$PID" ] && powershell.exe -NoProfile -Command "Stop-Process -Id $PID -Force"
```

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `invalid or expired token` on first connect | Token reused (single-use) or > 300 s old — issue a fresh one |
| MySQL connect hangs ~200 ms then works | Expected — protocol-detection grace on the shared port |
| `token not valid for this protocol` | Token `db_type` doesn't match the client (mysql token + psql, or vice versa) |
| `backend unavailable` | Backend container down, or credentials missing in `configs/data.yaml` for that `db_ip:db_port:db_user` key |
| Control Plane exits at boot | Valkey not up (`valkey-cli ping` fails); port 8080 already bound |
| UI 404 / blank | Angular not built — see §2.1 |

---

## 10. Verified timings (Task 5.4 gate, 2026-08-11)

Measured from a fresh terminal with the three containers already up (Phase 0 state):

| Step | Time |
|---|---|
| Control Plane boot → `/api/health` 200 | **2.8 s** |
| Data Plane boot → `:3306` listening | **2.0 s** |
| Token issuance (curl, API key) | **79 ms** |
| `mysql … SELECT` through `:3306` (incl. ~200 ms detection grace) | **402 ms** |
| **Total, fresh terminal → first proxied SELECT** | **22.8 s — target < 120 s ✓** |

psql through the same `:3306` was also verified live (3 rows). Full suite
`go test -count=1 ./...` green at gate time. See `.superpowers/sdd/PLAN/task-5.4-report.md`.
