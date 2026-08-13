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
(or `docker start valkey mysql-test pg-test`). Create missing ones with the exact commands below.

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
