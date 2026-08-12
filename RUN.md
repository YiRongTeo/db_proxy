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
| Optional: PM2 (`npm i -g pm2`) | `pm2 --version` — only needed for the PM2 path (§5) |

The three containers (`valkey`, `mysql-test`, `pg-test`) are the **only** external services. All
commands below run from the repo root:

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

Checker is **monitor-only** in v1 (live audit; no approval/kill). UI tokens can only target the
`db_presets` allowlist from `configs/control.yaml`.

---

## 6. Optional: PM2 (long-running ops)

```bash
cd /d/AI/hermes/Project/Project-D
go build -o bin/control.exe ./cmd/control && go build -o bin/data.exe ./cmd/data
pm2 start ecosystem.config.cjs     # apps: zt-control, zt-data
pm2 logs zt-control                # JSON slog output
pm2 restart zt-data                # e.g. after config change
```

---

## 7. Shutdown (reverse order) + port hygiene

```bash
# 1. stop the data plane first (Ctrl-C in its terminal), then the control plane (Ctrl-C)
#    PM2: pm2 stop zt-data && pm2 stop zt-control   (or: pm2 delete ecosystem.config.cjs)
# 2. optional: stop containers (data stays in the named volumes)
docker stop pg-test mysql-test valkey
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

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `invalid or expired token` on first connect | Token reused (single-use) or > 300 s old — issue a fresh one |
| MySQL connect hangs ~200 ms then works | Expected — protocol-detection grace on the shared port |
| `token not valid for this protocol` | Token `db_type` doesn't match the client (mysql token + psql, or vice versa) |
| `backend unavailable` | Backend container down, or credentials missing in `configs/data.yaml` for that `db_ip:db_port:db_user` key |
| Control Plane exits at boot | Valkey not up (`valkey-cli ping` fails); port 8080 already bound |
| UI 404 / blank | Angular not built — see §2.1 |

---

## 9. Verified timings (Task 5.4 gate, 2026-08-11)

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
