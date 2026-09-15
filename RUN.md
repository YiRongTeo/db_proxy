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
`valkey-sentinel`. Phase 9 (Task 9.14, Oracle — **on a DEDICATED proxy port** `:1522`) adds
`oracle-test`. All commands below run from the repo root:

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
# bearer JWT via login (auth.jwt.login_enabled is on by default — §3):
JWT=$(curl -s -X POST http://127.0.0.1:8080/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
# mint the mssql token with that JWT (the body username must match the
# bearer principal — or omit it and it is bound to the JWT's sub, §3):
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/token -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"TICKET-1"}' \
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
curl -H "Authorization: Bearer $JWT" http://127.0.0.1:8080/api/sessions
# → 200 → [..., {"db_type":"mssql","db":"appdb", ...}, ...]
```

Wire notes pinned by live captures (2026-08-15): the live SQL Server 2022
NEVER sets the DONE_FINAL bit on query responses — completion is the message
EOM after a DONE-family token (documented in `mssql_capture.go`).
ATTENTION (`0x06`) / LOGOUT (`0x0E`) pass through untouched; the maker
write-gate slots into the client→backend sniff (Task 9.4).

### 1.5 Oracle 23c Free test backend (`oracle-test`, host port 1521)

Task 9.14: TNS test backend. The data plane serves Oracle on a **dedicated
proxy listener** (`listen.oracle_addr`, default `:1522`) — protocol-isolated
from the shared `:3306` classifier. Image `gvenzl/oracle-free:23-slim`
(~2–3 GB, free license, needs ~2 GB RAM). `ORACLE_PASSWORD` sets the SYS
password; the PDB is `FREEPDB1`; the DB service is `FREE`.

```bash
docker run -d --name oracle-test -p 1521:1521 -e ORACLE_PASSWORD='SysPassword123' gvenzl/oracle-free:23-slim
# readiness (first boot takes 2–5 min): the slim image has no HEALTHCHECK —
for i in $(seq 1 60); do docker exec oracle-test bash -lc "echo 'SELECT 1 FROM dual;' | sqlplus -S sys/SysPassword123@localhost:1521/FREEPDB1 as sysdba" >/dev/null 2>&1 && break; sleep 5; done
```

Seed users + demo table (idempotent; run the SQL from `tests/oracle-seed.sql`
— RO_USER/ro_pw = SELECT-only, RW_USER/rw_pw = write, table `DEMO_ITEMS`
owned by RW_USER with a public synonym so both users resolve it):

```bash
docker exec -i oracle-test bash -lc "sqlplus -S sys/SysPassword123@localhost:1521/FREEPDB1 as sysdba" < tests/oracle-seed.sql
docker exec oracle-test bash -lc "echo 'SELECT COUNT(*) FROM demo_items;' | sqlplus -S ro_user/ro_pw@localhost:1521/FREEPDB1"   # → 3
```

Wire note: Oracle clients negotiate native encryption (O5LOGON) — the
plaintext posture requires the client to disable it (recipes per client
land with the OracleProxy).

### 1.5.1 Through the proxy (JDBC-family clients — verified 2026-09-02)

The proxy terminates the TNS login on both legs (the token is the
credential; the client's password is never verified) and byte-relays
post-auth traffic. **JDBC-family clients** (go-ora, ojdbc, SQL Developer,
DBeaver Oracle) are fully supported — verified end-to-end with a go-ora
client through the proxy:

```bash
# mint a token, then point any JDBC client at the proxy:
#   host 127.0.0.1, port 1522 (listen.oracle_addr), service FREEPDB1
#   user = <token>, password = anything
# login → bearer JWT (admin = ZT_AUTH_PASSWORD from .env; §3), then mint:
JWT=$(curl -s -X POST http://127.0.0.1:8080/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/token \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" \
  -d '{"username":"admin","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"1521","db_type":"oracle","ticket_id":"E2E-1"}'
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
# go-ora DSN: oracle://<TOKEN>:x@127.0.0.1:1522/FREEPDB1
```

**OCI-family clients (sqlplus)**: the backend leg authenticates with the
real `db_user` credentials, but the client leg replays mirrored auth
responses — the 23c OCI mutual-auth handshake verifies `AUTH_SVR_RESPONSE`
on the client, so sqlplus fails at login (ORA-01017/ORA-28041). Use a
JDBC-family client (go-ora, DBeaver, SQL Developer) through the proxy, or
sqlplus directly against the backend (`:1521`) when the proxy isn't
required.

---

## 2. Start the planes (control → data)

Both planes read `configs/*.yaml` **relative to the repo root** — always start them from there.

### 2.0 Secrets bootstrap (one-time)

The committed configs carry **no passwords** — every secret (control-plane
login, audit sink, backend DB credentials, valkey) is resolved from the
git-ignored `.env` (or exported `ZT_*` variables) at plane startup. Create
it once from the template:

```bash
cd /d/AI/hermes/Project/Project-D
cp .env.example .env     # then edit .env to taste (dev defaults already match §1's container seeds)
```

Required (UI login on, the default): `ZT_AUTH_PASSWORD` AND `ZT_JWT_SECRET` (empty
→ the control plane refuses to start). `ZT_JWT_SECRET` is the HS256 signing
secret behind every LOCALLY issued bearer JWT (config `auth.jwt.secret`, §3);
`ZT_AUTH_PASSWORD` authenticates UI logins while `auth.jwt.login_enabled: true`
(the default) — set `login_enabled: false` for an external-JWT-only plane, in
which case the local password and secret are NOT required but at least one
`auth.jwt.external_issuers` entry (each with its OWN `${VAR}` secret, e.g.
`ZT_OTHERAPP_JWT_SECRET`) IS — see §2.1.1, the §2.1.2 cutover runbook and `docs/jwt-auth-conversion.md`.
`/api/logout` is registered regardless of `login_enabled` (Phase 2 Task 4b), so
external-only deployments can still revoke tokens server-side.
`ZT_CRED_*` entries feed the data plane's credentials list via `${VAR}`
placeholders in `configs/data.yaml`; an unset credential variable is a
**load error**, never a silent empty password. `ZT_ENV_FILE` overrides the
`.env` path (e.g. for CI). PM2 (§7) loads `.env` via `env_file` too.

### 2.1 Control Plane (:8080 — REST + WS hub + Angular SPA)

```bash
cd /d/AI/hermes/Project/Project-D
go run ./cmd/control
```

**SPA prerequisite (rebuild after ANY `web/src` change — a stale bundle fails
silently, it does not 404).** The control plane serves the Angular build from
`web/dist/web/browser/` (`static_dir`), and `web/dist/` is **gitignored**, so
nothing in git flags a bundle that predates a source change: the UI simply
keeps running the old code against the new API (e.g. a pre-JWT bundle still
speaks the retired cookie-session protocol, so **every browser login fails**
even though `POST /api/login` returns 200 via curl). Check the served bundle
age against the source, and rebuild when stale:

```bash
ls -la web/dist/web/browser/main-*.js     # bundle mtime
ls -lat web/src | head -3                 # newest source change
cd web && npm ci && npm run build && cd ..   # then restart the control plane
```

Auth model (JWT conversion — the old `ZT_API_API_KEY` / control-plane
`X-Api-Key` is GONE): every authenticated route takes a **Bearer JWT**
(`Authorization: Bearer <jwt>`); `/api/login` self-issues those JWTs when
`auth.jwt.login_enabled` is true (default). To mint DB tokens (§3) log in
first and reuse the returned JWT — the SPA does exactly this. Operators who
want ticketing integrations to mint tokens without a UI login can either
leave `login_enabled` on and treat the login response as the integration's
entry point, issue the integration JWTs signed with the local
`auth.jwt.secret` (they then verify as self-issued), or — the Phase 2 way —
register the integration as an **external issuer** (`auth.jwt.external_issuers`,
§2.1.1) trusted with its OWN shared secret, so its JWTs verify without ever
sharing the local login secret. `auth.jwt.allowed_origins` (control.yaml) is
ONE cross-origin allowlist for BOTH browser surfaces since Phase 2 Task 3:
REST CORS (the other app's UI calling `/api/*` with a bearer JWT from
another origin) AND the checker WebSocket upgrade (no dedicated env binding —
AutomaticEnv still maps `ZT_AUTH_JWT_ALLOWED_ORIGINS`, comma-separated, if
set). Empty (default) = same-origin only; entries are host globs — prefix
`https://` to pin the scheme, and spell out any non-default port (§2.1.1).

### 2.1.1 External JWT issuers (Phase 2 — `auth.jwt.external_issuers`)

Since Phase 2, the plane trusts **third-party HS256 issuers** in addition to
its own login: a JWT whose `iss` matches an `auth.jwt.external_issuers`
entry verifies against THAT entry's shared secret (not `auth.jwt.secret`),
is bound to the entry's audience, and is mapped onto the same
`{username, role ∈ maker|checker}` principal as a self-issued token — so
minting, the role gates, SoD and audit treat both kinds identically. An
unknown `iss` (no local match, no entry) → 401. Config (the committed
example is commented out until the other app is live):

```yaml
# configs/control.yaml — auth.jwt block
jwt:
  ...
  external_issuers:
    - name: "other-app"                  # label for logs; required + unique
      iss: "https://other-app.example"   # MUST equal the iss claim on their JWTs;
                                         # must NOT equal the local issuer (load error)
                                         # OMIT + set require_iss: false for issuers
                                         # whose JWT carries NO iss claim (below)
      audience: "zt-api"                 # optional — empty inherits auth.jwt.audience
      secret: "${ZT_OTHERAPP_JWT_SECRET}"  # their HS256 shared secret, via .env (see
                                         # .env.example) — NEVER committed to yaml
      require_iss: true                  # ABSENT = true: token without iss -> 401;
                                         # false = iss-less tokens tried against this
                                         # entry's secret (config order among relaxed
                                         # entries; first verify wins)
      require_aud: true                  # ABSENT = true: token aud must match the
                                         # resolved audience; false = aud NOT asserted
                                         # (an empty resolved audience is then legal)
      require_jti: true                  # ABSENT = true: token without jti -> 401
      claims:                            # optional — adapt to THEIR token shape (below)
        subject: "sub"                   #   claim carrying the username (default "sub")
        role: "role"                     #   claim carrying the role (default "role")
        session_id: "sessionId"          #   claim carrying the IdP login session id
                                         #   (default "sessionId") — parsed for
                                         #   logs/tracing + the audit
                                         #   login_session_id column; NEVER a
                                         #   revocation key
        role_aliases:                    #   raw role-claim VALUES -> maker|checker
          approver: checker              #     non-identity example: their role claim says
                                         #     "approver" where we say "checker". Canonical
                                         #     "maker"/"checker" values need NO alias — the
                                         #     default translation is identity. Matching
                                         #     is CASE-INSENSITIVE (viper lowercases
                                         #     yaml map keys, so "Maker" and "maker"
                                         #     both match a token's literal "Maker").
```

Every ACTIVE entry's secret is required at load (empty → the plane refuses
to start); `iss` collisions with the local issuer are a load error.
`iss` values must be UNIQUE across entries too — verification resolves a
token to its entry BY `iss`, so a duplicate would make the second issuer's
tokens 401 forever with no log clue — and an entry that resolves to an
EMPTY audience (no per-entry `audience`, no top-level `auth.jwt.audience`)
refuses to start: nothing it mints could ever pass `aud` verification.
**Relaxations (Phase 2b) are per-entry and EXPLICIT:** `require_iss: false`
permits an iss-less entry (the iss-required/unique/shadow checks then only
apply to entries that DO carry an iss — an iss-less token is resolved by
trying each relaxed entry's secret in config order, first verify wins);
`require_aud: false` skips the audience assertion entirely, making an empty
resolved audience legal for that entry. Entries with the strict defaults
are never consulted for tokens that omit the corresponding claim.

**Claim mapping — "their JWT differs" is a config edit, never code.** An
external token is verified as-is (HS256 with their secret, `iss` == the
entry's, `aud` contains the entry's audience, `exp` present) and then
adapted to the local principal model by the entry's `claims` map. Zero
`claims` = the defaults: username from `sub`, role from `role`, role values
taken verbatim (so a token that already carries `role: checker` works with
no mapping at all). Different claim vocabulary? Map it: e.g. their token
puts the username in `user_name`, the role in `access_level`, and uses the
raw value `admin` for what we call `checker` → set
`claims.subject: user_name`, `claims.role: access_level`,
`claims.role_aliases: {admin: checker}`. Only `role_aliases` VALUES are
validated (must be `maker`|`checker` — config load error otherwise); the
`subject`/`role` claim names are free strings (empty = default). Post-map
rules match the local path exactly: subject non-empty, canonical role ∈
{maker, checker} — anything else is the same bare 401.

**`require_jti`.** ABSENT defaults to **true**: an external token without a
non-empty string `jti` claim → 401. Rationale: revocation is the Valkey
**jti denylist** (logout writes `jwt:deny:<jti>`), so a jti-less token could
never be revoked — the Phase-1 "jti-less tokens bypass the denylist" gap is
closed for external tokens by this default (self-issued tokens always carry
a jti). Only an EXPLICIT `require_jti: false` relaxes it — do that only for
an issuer that cannot mint jti claims, accepting those tokens are
undeniably live until `exp`.

**Logout.** `POST /api/logout` is registered **unconditionally** (Phase 2
Task 4b), not just when `login_enabled` — it verifies the presented bearer
through the same issuer-aware path and denylists its `jti`, so an
external-only deployment (or an external token used alongside local logins)
keeps a server-side revocation route. A valid token WITH a jti → 200
`{"ok":"true","revoked":true}` (denylisted; replay 401). A valid token
WITHOUT a jti (`require_jti: false` issuers — e.g. the integrating app's
real shape) → 200 `{"ok":"true","revoked":false}` + a warn log (Phase 2b):
nothing server-side exists to revoke (their `sessionId` claim is a tracing
id, never a revocation key), the caller discards it client-side, and the
token lives until `exp` — keep their tokens short-lived; that is the only
revocation lever for jti-less issuers.

**Mint-for-self.** The mint endpoint binds every token to the authenticated
principal: the optional body `username` MUST equal the JWT's (mapped)
subject — or be omitted, and the token is issued for the subject anyway.
There is **no mint-for-others** anywhere: an external principal can only
mint DB tokens for its own mapped username, gated by its mapped role
(checker-role principals get 403 on write-access mints, §3/§5).

**CORS — one list, both surfaces.** `auth.jwt.allowed_origins` governs REST
CORS **and** the checker-WS origin gate (Phase 2 Task 3), because an
external issuer's browser UI calls this plane cross-origin. Matching rule
(identical to the WS vendor's): each entry is a case-insensitive glob over
the Origin **host**, unless the entry carries an explicit scheme prefix —
`"https://other-app.example"` globs `scheme://host` and therefore **pins
the scheme**, while a scheme-less entry (`"other-app.example"`) is
scheme-agnostic. The **port is part of the matched host**, so an origin
served on a non-default port must spell it in the entry
(`"https://other-app.example:8443"`). Each entry must be a **valid glob** —
a malformed pattern is a config-load error (naming the entry), never a
silent never-match. Same-origin requests pass untouched;
a disallowed cross-origin Origin is 403'd BEFORE auth (preflight 204 only
from allowed origins; responses never `Access-Control-Allow-Origin: *` and
never `Access-Control-Allow-Credentials`). CORS is not the security
boundary — the bearer JWT is; the allowlist only decides whether a browser
may read responses (§ "security notes" in `docs/jwt-auth-conversion.md`).

**External-only mode.** `auth.jwt.login_enabled: false` removes the
`/api/login` route and the local username/password + `auth.jwt.secret`
requirements; config validation then REQUIRES at least one
`external_issuers` entry — a plane nothing can authenticate must not boot.
Roles come entirely from the mapped claims.

**Recipe — integrate an external JWT issuer**

1. Add the issuer's secret to `.env` (`cp .env.example .env`; uncomment and
   set `ZT_OTHERAPP_JWT_SECRET` to their shared HS256 secret — 32+ random
   bytes, coordinated with them).
2. Add the `external_issuers` entry to `configs/control.yaml` as above
   (their `iss`, audience if it differs from `zt-api`, `require_jti` per
   their token shape, `claims` mapping if their claim names/values differ).
   Keep local `login_enabled: true` until the external path is proven.
3. Restart the control plane — validation fail-fasts on a bad entry
   (missing secret, duplicate name/`iss`, `iss` == local issuer, an entry
   that resolves to an empty audience, bad alias value).
4. Add their UI's origin to `auth.jwt.allowed_origins` (scheme-pinned,
   non-default port included, §above) so their browser can call the REST
   APIs and the checker WS cross-origin.
5. Verify: present one of their JWTs and confirm the mapped principal —
   `curl -H "Authorization: Bearer <their-jwt>" http://127.0.0.1:8080/api/me`
   → `200 {"username":"<their-sub>","role":"maker|checker"}` (401 = verify
   the entry: `iss`/`audience`/`secret`/`require_jti`/claim names — and if
   their JWT omits `iss` or `aud`, set `require_iss: false` /
   `require_aud: false`; if it omits `jti`, `require_jti: false` and accept
   un-revocable tokens, §logout above).
   Then mint through `POST /api/token` as usual (§3).

**Secret hygiene.** An external issuer's shared secret IS the trust root —
whoever holds it can mint any `sub`/role for that issuer. It lives in the
environment (`.env`), never in committed yaml; keep the list minimal
(absent entry = no trust); rotate by a coordinated secret swap (config
reload/restart) plus their token `exp` bounds.

### 2.1.2 Cutover to an external JWT issuer (integrated deployment)

Purpose: take the plane from **standalone** (its own `/api/login`, local
accounts) to **integrated external-issuer-only** — the OTHER app generates
the JWTs and this plane only CONSUMES them (the Phase 2 trust direction,
§2.1.1). The cutover is a config + deployment change, never a code change:
claim mapping, role vocabulary and trust all live in `configs/control.yaml`
and `.env`. Run it only after the §2.1.1 recipe's verification passed (their
JWT already answers `200` on `/api/me` while local login is still on).

```yaml
# configs/control.yaml — auth.jwt block, integrated (external-only) state
jwt:
  ...
  allowed_origins:
    - "https://other-app.example"   # their UI origin — ONE list for REST CORS +
                                    # checker WS; "https://" pins the scheme; a
                                    # non-default port must be spelled out
  external_issuers:
    - name: "other-app"             # §2.1.1 for the full key table
      # iss: "https://other-app.example"  # OMIT + require_iss: false if their
      #                               # JWT carries no iss (their real shape)
      # audience: "zt-api"          # optional — empty inherits auth.jwt.audience
      secret: "${ZT_OTHERAPP_JWT_SECRET}"   # the ONE shared HS256 secret
      # require_iss: false          # ABSENT = true (their real shape omits iss)
      # require_aud: false          # ABSENT = true (their real shape omits aud)
      # require_jti: false          # ABSENT = true (their real shape omits jti —
                                    #   tokens then un-revocable; keep them short)
      # claims: { subject: "username", role: "role", session_id: "sessionId",
      #           role_aliases: {Maker: maker, Checker: checker} }  # only if
                                    # their claim names/role VALUES differ
```

1. **Add the other app as an external issuer.** Set `ZT_OTHERAPP_JWT_SECRET`
   in `.env` to the shared secret (32+ random bytes, agreed with the other
   app — the SAME value on both sides; rotate only by a coordinated swap)
   and add the `external_issuers` entry above. Their JWTs then verify against
   THEIR secret, not `auth.jwt.secret`.
2. **Add the other app's UI origin to `auth.jwt.allowed_origins`.** Their
   browser must be allowed to call this plane's REST APIs AND upgrade the
   checker WebSocket cross-origin (one list, §2.1.1). Scheme-pin the entry
   (`https://`) and spell any non-default port. Then **restart the control
   plane** — validation fail-fasts on a bad entry (missing secret, duplicate
   name/`iss`, `iss` == local issuer, empty-resolving audience, bad alias).
3. **Verify while login is still enabled.** An external JWT must behave
   exactly like a self-issued one before the local path is removed:
   - identity — `curl -H "Authorization: Bearer <their-jwt>"
     http://127.0.0.1:8080/api/me` → `200 {"username":"<their-sub>",
     "role":"maker|checker"}` (401 = re-check `iss`/`audience`/`secret`/
     `require_jti`/claim names — or relax `require_iss`/`require_aud`/
     `require_jti` per their actual token shape, §2.1.1);
   - mint — `POST /api/token` with their JWT: maker principal → `200`
     (read AND write presets); checker principal → `200` on read-access
     mints, **403** on write-access mints (read-only, §3);
   - checker WS — from their origin: `ws://<host>:8080/ws/checker?channel=
     sess:<sid>&access_token=<their-jwt>` upgrades and streams QueryEvents.
4. **Flip `auth.jwt.login_enabled: false`.** `/api/login` is then NOT
   registered — the path falls through to the `/api` guard and answers 404
   (JSON, never HTML) — so nothing self-issues local tokens anymore. With
   login off, `auth.jwt.secret`, `auth.username/password` and `auth.users[]`
   are NOT required — but **at least one `external_issuers` entry IS** (an
   empty list is a load error: nothing could authenticate). Note the trust
   mechanism: a token claiming the LOCAL `iss` only verifies while a local
   secret is still configured (parseJWT fails closed on an empty secret) —
   removing `ZT_JWT_SECRET` (step 6) is what makes the local issuer
   untrusted in practice. `POST /api/logout` STAYS registered (Phase 2
   Task 4b): external-only deployments keep an HTTP jti-revocation route.
5. **Retire the Angular SPA.** Stop serving the built UI (drop/redirect
   `http.static_dir` in `configs/control.yaml`, then archive or delete the
   `web/` Angular source and its build output). The local `auth.users[]`
   entries become inert — nothing accepts local credentials anymore.
6. **`.env` cleanup.** Remove `ZT_AUTH_PASSWORD` (and
   `ZT_AUTH_CHECKER_PASSWORD` if set) and `ZT_JWT_SECRET` — with the local
   secret gone, any leftover token claiming the local `iss` fails closed —
   `ZT_OTHERAPP_JWT_SECRET` is now the only auth secret the plane reads.
   Confirm the end state:

   ```bash
   # /api/login is gone → 404
   curl -s -o /dev/null -w "%{http_code}" -X POST \
     http://127.0.0.1:8080/api/login -d '{"username":"x","password":"y"}'
   # logout still revokes a jti-bearing external token → 200 {"ok":"true",
   # "revoked":true}, replay → 401 (a jti-less token → 200 revoked:false)
   curl -X POST -H "Authorization: Bearer <their-jwt>" \
     http://127.0.0.1:8080/api/logout
   ```

**Rollback.** Local login comes back by flipping `auth.jwt.login_enabled`
back to `true` (plus restoring the local secrets to `.env` if step 6 already
removed them) and restarting — the local and external paths coexist until
the SPA is actually retired, so the flip alone is a complete rollback at any
point before step 5. After the SPA and `.env` cleanup are done, restoring
standalone mode means restoring those pieces too (`auth.users[]` etc.).
See also the interactive cutover diagram: `docs/archify/10-external-cutover.html`.

### 2.1.3 Login & authentication — current model

Since the JWT conversion (Phase 1, 2026-09-05) a **bearer JWT is the only
credential** this plane accepts — no cookie, no server-side UI session.

- **Local login** — `POST /api/login` is registered only while
  `auth.jwt.login_enabled: true` (the default). It validates
  `{username, password}` against the config accounts (`auth.username` +
  `auth.users[]`, constant-time compares, roles required — never silently
  defaulted) with a per-(IP, username) rate limiter, and answers
  `200 {token, username, role, expires_in}` — `token` is a self-issued HS256
  JWT (`iss zerotrust-proxy`, `aud zt-api`, claims `sub`/`role`/`exp`/`jti`,
  signed with `auth.jwt.secret` / `ZT_JWT_SECRET`, life
  `auth.jwt.ttl_seconds`, default 28800 s).
- **Every authenticated call** sends `Authorization: Bearer <jwt>` — REST
  only, tokens never ride URLs. `GET /api/me` → `200 {username, role}` of the
  token. The checker WebSocket is the one exception: browsers cannot set WS
  headers, so `GET /ws/checker?channel=<ch>&access_token=<jwt>`.
- **Minting** (`POST /api/token`) is mint-for-self: the optional body
  `username` must equal the JWT's `sub` (or be omitted → the subject is used);
  there is no mint-for-others. Checker-role principals are read-only —
  write-access mints → 403.
- **Logout is always available.** `POST /api/logout` is registered
  **unconditionally** (not gated by `login_enabled`): it verifies the
  presented bearer through the issuer-aware path and denylists its `jti`
  (`jwt:deny:<jti>` in Valkey) for the token's remaining life — replaying
  the same token anywhere → 401 (`{"ok":"true","revoked":true}`). A valid
  token without a `jti` (`require_jti: false` issuers) answers
  `{"ok":"true","revoked":false}` + a warn — nothing server-side exists to
  revoke, so the caller discards it client-side and it lives until `exp`.
- **External path (Phase 2/2b)** — the other app signs the JWT (their
  claims; the integrating app's real shape is `username`/`role`
  `Maker`|`Checker`/`sessionId` with NO `iss`/`aud`/`jti` — map the
  vocabulary + relax per entry with `require_iss`/`require_aud`/
  `require_jti: false`, §2.1.1) with the SHARED secret
  (`auth.jwt.external_issuers[].secret`, §2.1.1). This plane verifies it
  against that entry and maps claims onto the same
  `{username, role ∈ maker|checker}` principal — vocabulary differences are
  a config edit, never code. This plane never mints for others.
- `login_enabled: false` removes **only** `/api/login`; the local secret and
  credentials become optional, but ≥ 1 external issuer is required (else the
  plane refuses to start). Full cutover procedure: §2.1.2.

See also the interactive login-process diagram:
`docs/archify/09-auth-login.html`, and Page 9
(`docs/jwt-auth-conversion.md`) for the full role × capability matrix and
config key table.

Readiness (second terminal):

```bash
curl -s http://127.0.0.1:8080/api/health      # expect: {"status":"ok","valkey":"up"}
```

> The Angular SPA must already be built (`web/dist/web/browser/`). If the UI 404s, rebuild:
> `cd web && npm ci && npm run build && cd ..` then restart the control plane.

### 2.1.4 Debugging a rejected token (401)

The client always receives the SAME opaque body — `401 {"error":"unauthorized"}` — so a
rejection never tells the caller *why* (that is deliberate: the response must not
distinguish a bad signature from an expired token from an unknown issuer). The REASON is
therefore written to the **server-side log** instead, where an operator can see it.

Every rejection is a `WARN` line; an accepted request is a `DEBUG` line naming the
resolved trust root:

```bash
# stdout is the log sink; PM2 already writes it to files (ecosystem.config.cjs):
#   logs/control-out.log / logs/control-error.log
cd /d/AI/hermes/Project/Project-D
ZT_LOG_LEVEL=debug "$LOCALAPPDATA/Temp/zt-run/zt-control.exe" >> logs/control-out.log 2>&1

# then, after a failed call, read the reason:
grep '"requireJWT: token rejected"' logs/control-out.log | tail -5
```

| Logged reason (field `reason`) | What it means / what to fix |
|---|---|
| `requireJWT: no bearer token presented` (DEBUG) | No `Authorization: Bearer` header, or an empty token — REST is **header-only** |
| `token is not a parseable JWT` | Not three dot-separated base64url segments (truncated paste, wrong header) |
| `unknown issuer "X": not the local issuer and no external_issuers entry matches` | The token carries an `iss` that no `auth.jwt.external_issuers[]` entry declares — set that entry's `iss` to match, or have the IdP stop sending `iss` |
| `token has no iss claim; N require_iss:false issuer(s) tried, last rejection: …` | iss-less token (the integrating app's shape): the detail after the colon is the LAST issuer's specific failure — read that |
| `external issuer "name": token invalid: token is expired` | `exp` in the past — clock skew or a stale token |
| `external issuer "name": token invalid: token signature is invalid` | Signed with a **different secret** than the entry's `secret` (the classic integration bug: the two apps don't share the same value) |
| `external issuer "name": role "Vendor" maps to no canonical role (add a role_aliases entry)` | Role value not `maker`/`checker` after aliasing — add the raw value to `claims.role_aliases` |
| `external issuer "name": no "username" claim carrying a username` | The claim named by `claims.subject` is absent/empty in the token |
| `external issuer "name": token carries no jti while require_jti is in force` | `require_jti` is on (absent config = true) but the token has no `jti` — set `require_jti: false` if the IdP cannot emit one |
| `local token invalid: …` | A token claiming the LOCAL `iss` failed verification against `auth.jwt.secret` |
| `requireJWT: token rejected - jti denylisted` | The token was explicitly logged out (or its `jti` was revoked) |

Reasons never include the token, the secret or the signature — they are derived from the
token's own claims (iss/role/claim presence) and from config state, so the log is safe to
share with the integrating team.

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
  **This `X-Api-Key` is the DATA plane's key to its vault — unrelated to the retired
  control-plane `ZT_API_API_KEY` (removed in the JWT conversion; the Control Plane's
  `/api/token` now takes a Bearer JWT, §2.1).**

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

**Pairing rule (checker read-only gate — config hygiene).** The checker mint gate (403
on `access == "write"`, §3) resolves access from the `db_presets` entry in
`configs/control.yaml`, NOT from this credentials list. Every `credentials` key backed
by WRITE-capable backend creds MUST have a matching preset with `access: "write"` — a
write account with no matching preset resolves `access ""` (ungated, §5.1), so a
checker could mint a token over those creds that runs gate-free. The shipped configs
pair every rw key 1:1 (e.g. `mysql:rw_user@…` ↔ "MySQL read-write"); keep the pairing
when adding accounts.

Quick check (vault stub with `python`):

```bash
python -c "import http.server,socketserver; \
class H(http.server.BaseHTTPRequestHandler):
  def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'{\"password\":\"ro_pw\"}')
socketserver.TCPServer(('127.0.0.1',9000),H).serve_forever()" &
# configs/data.yaml: credentials_source: api, credentials_api.url: http://127.0.0.1:9000/creds
go run ./cmd/data   # then §4: token → SELECT works, password served by the stub
```

### 2.3.1 Vault TLS — internal CA / self-signed certificates

The credential-API client uses Go's default transport (the **system trust
store**), so a publicly-trusted HTTPS vault needs **no configuration**. An
internal CA or self-signed certificate needs its PEM anchor:

```yaml
# configs/data.yaml
credentials_source: api
credentials_api:
  url: "https://vault.internal.example/creds"
  api_key: "${ZT_CREDENTIALS_API_API_KEY}"
  tls:
    ca_file: "certs/vault-ca.pem"    # internal CA, or the self-signed cert itself
    min_version: "1.2"               # "1.2" (default) | "1.3"
    require_https: true              # optional: refuse a non-https url
```

`ca_file` is **appended to** the system pool (public and internal endpoints
keep working). Both of these refuse to **boot** rather than fail mid-session:

- `ca_file` missing, unreadable, or containing no parseable PEM CERTIFICATE;
- a `tls` block on a non-`https` URL (the options would be inert while the
  password travelled in plaintext) — or `require_https: true` alone on a
  plaintext URL.

Dev escape hatch: `insecure_skip_verify: true` disables verification — the
data plane logs a loud warning at boot and this **must not** be used with real
credentials. It exists so an internal-CA mismatch is debuggable without
disabling TLS entirely.

Diagnosing a trust failure (it fails closed — the maker sees
`ERROR 1045 ... backend unavailable`, never a password):

```bash
# the data plane's own log names the TLS cause, e.g.:
#   "credential api: Get \"https://vault…\": x509: certificate signed by unknown authority"
ZT_LOG_LEVEL=debug go run ./cmd/data 2>&1 | grep -i "credential api"

# capture the CA the vault actually serves (then point ca_file at this file):
openssl s_client -connect vault.internal.example:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > certs/vault-ca.pem

# confirm the trust anchor BEFORE connecting through the proxy:
curl --cacert certs/vault-ca.pem \
  -H "X-Api-Key: $ZT_CREDENTIALS_API_API_KEY" \
  "https://vault.internal.example/creds?db_type=mysql&db_user=ro_user&db_ip=127.0.0.1&db_port=3307"
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

**Sink compatibility (review 2026-08-17):** MariaDB or MySQL 5.7+ — the
upserts use the portable `VALUES()` syntax (the MySQL 8.0.19+ alias form
fails on MariaDB). The audit suite is verified against both sinks
(`ZT_AUDIT_TEST_PORT=<port>` points it at a MariaDB container).

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

Tokens are single-use by default, TTL 300 s, stored in Valkey (`tok:<token>`), consumed atomically on first
connection. **One token = one connection** — get a fresh token per connect.

**Multi-use budget (Task 9.12, option-2).** `api.token_max_uses` in
`configs/control.yaml` (env `ZT_TOKEN_MAX_USES`, default **1** = single-use)
sets how many connections one token may open before it dies. GUI clients
(SSMS / DBeaver / Azure Data Studio) open several connections per session
automatically (Object Explorer + auxiliary + query windows), so with the
default budget their second connection fails with `Login failed for user
'sess_…'` (18456) — set `token_max_uses: 4` (or `ZT_API_TOKEN_MAX_USES=4`;
the short alias `ZT_TOKEN_MAX_USES` also works) for
those clients. Each use is still atomic (a stolen token can open at most N
connections within the TTL), and the TTL still bounds the window.

**Session tokens (Task 9.13, option-A — the GUI-native flavor).** A
session-mode token (`"mode":"session"` on POST /api/token, a preset's
`token_mode: session`, or `api.token_mode: session` as the deployment
default) is:

- **Not consumed** — one token opens ANY number of connections (SSMS's
  connection churn is unbounded: Object Explorer, query windows, pooling).
- **IP-locked** — stamped with the issuer's address at mint; every
  connection must come from that address (loopback-normalized), else the
  login is rejected like an invalid token.
- **TTL 0 = INFINITE** (`api.session_token_ttl_seconds: 0`, the default) —
  the token lives until REVOKED. With a finite value it dies at the TTL.
- **Live-revocable** — deleting `tok:<token>` by ANY means (control-plane
  kill, `valkey-cli del`, an operator script) closes every running session
  bound to it: instantly via valkey keyspace notifications
  (`notify-keyspace-events KEx`) when the server publishes them, otherwise
  within `session.revoke_poll_seconds` (default 1 s, data.yaml). The kill
  endpoint also deletes the key, so kill == revoke.
- **Policed by the data plane** (data.yaml `session.*`): `idle_seconds`
  (default 1800 — the safety valve: a forgotten GUI window cannot pin a
  backend connection forever; **applies to every token mode**, single-use
  included), `max_lifetime_seconds` (0 = off), and `revoke_poll_seconds`
  (1). A mint request can carry `"idle_seconds": N` to override the
  default for that token (0/absent = follow the data-plane default).

Security posture: a stolen session token grants at most the maker's own
address and time window; revocation is explicit and converges on one
invariant — **no key = no session**. The checker gate, SoD watch and audit
are unchanged (the session id is stamped at mint as before).

### 3.1 Bearer-JWT flavor (login → mint — the ONLY flavor)

Every mint must present a valid bearer JWT (`Authorization: Bearer <jwt>`) —
the control-plane `X-Api-Key` was retired in the JWT conversion. The JWT comes
from `/api/login` (when `auth.jwt.login_enabled: true`, the default) or from a
configured external issuer (`auth.jwt.external_issuers` — verified against
THAT issuer's own shared secret, §2.1.1):

```bash
# 1) login → 200 {token, username, role, expires_in} — the token is the JWT
JWT=$(curl -s -X POST http://127.0.0.1:8080/api/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
# 2) mint with the JWT. The body username (optional) must match the JWT's
#    subject or be omitted — the token is always issued for the principal.
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/token \
  -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"TICKET-1"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "$TOKEN"
```

Logout revokes the JWT server-side (Valkey jti denylist for its remaining
life): `curl -X POST http://127.0.0.1:8080/api/logout -H "Authorization: Bearer $JWT"`
→ `200 {"ok":"true"}` — the same token then answers `401` on every guarded route.
Self-issued JWTs default to `auth.jwt.ttl_seconds: 28800` (8 h); on expiry the
SPA sends you back to `/login`.

Response shape (DB token is always `sess_…`): `{"token":"sess_…","host":"127.0.0.1","port":"3306","expires_in":300}`
(session-mode tokens report `expires_in: -1` = infinite, revoked by deletion).

For PostgreSQL swap `"db_type":"postgres"` and the backend port `"db_port":"5433"` (user `ro_user`).

> Mint without a bearer → `401`; unknown `db_type` → `422`; missing fields → `400`;
> a **checker**-role principal minting a write-access token → `403` (checkers are
> read-only minters — they cannot create a write session they could then watch, §5).

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

Login: **admin** with the password from `.env` (`ZT_AUTH_PASSWORD` — copy
`.env.example` to `.env` first; the committed configs carry NO secrets).
Override the username via `configs/control.yaml` (`auth.username`) or
`ZT_AUTH_USERNAME`. Every account declares a **role** (`auth.role` for the
primary pair, `auth.users[].role` for extras) and the SPA lands you on the
role's page — `/maker` for a maker, `/checker` for a checker. The committed
config ships two accounts for SoD testing: `admin` (maker) and `checker`
(checker, password `ZT_AUTH_CHECKER_PASSWORD` from `.env`) — use two
browsers/profiles, the checker must NOT be the maker.

| Role | Mint (`POST /api/token`) | Watch / kill / sessions (`/ws/checker`, `/api/kill`, `/api/sessions`) | Default account |
|---|---|---|---|
| `maker` | any `db_presets` access — read **and** write | **403** unless `auth.allow_maker_watch: true` (default false = strict SoD) | `admin` (`auth.username`, `auth.role: maker`) |
| `checker` | **read-only** presets only — a write-access mint → `403` | always (this is the checker surface) | `checker` (`auth.users[]`, `role: checker`) |

`allow_maker_watch: true` (control.yaml) is the single-account deployment
escape hatch: it lets maker-role principals watch/kill too. The **SoD
username check is independent of roles** — a checker can never watch their
OWN session (1008 policy-violation close, §5.1), and the data-plane write
gate still requires a watcher ≠ maker. Checker is **monitor-only** for
statements (live audit; no approval of queries — kill is the only action).
UI tokens can only target the `db_presets` allowlist from `configs/control.yaml`.

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

**Separation of duties (2026-08-17):** the checker who arms the gate for a session must be a
**different user** than the session's maker. The WS hub rejects a maker's attempt to watch their own
session with a **1008 policy-violation close** (no `watch:<sid>` lease is created), and also rejects
`sess:<sid>` channels whose session record is missing/expired (fail-closed). The checker dashboard
shows the server's reason in a banner. Only the session's maker identity is special — the live-all
feed (`channel=*`) and user/ticket channels are unaffected.

**Extra UI users (Task 9.13):** the control plane supports additional accounts beyond the primary
`auth.username/password` pair via the optional `auth.users` list in `configs/control.yaml`
(passwords are `${VAR}` placeholders from the environment, e.g.
`ZT_AUTH_CHECKER_PASSWORD` — same fail-fast rule as the primary pair). The committed config ships
a dedicated **`checker`** account for SoD testing: maker = `admin`, checker = `checker`
(two browsers/profiles — the checker must NOT be the maker).

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
curl -H "Authorization: Bearer $JWT" http://127.0.0.1:8080/api/sessions   # checker-role JWT (or maker with allow_maker_watch)
# 200 → [{"session_id","username","db_user","db_type","db","started_at","last_seen"}, ...]
```

**Per-session feed.** Every query event is published to `queries:<user>` AND `queries:sess:<sid>`;
session start/end publish lifecycle events (`kind=session`, `action=started|ended`) to both.
Selecting a session in the Checker dashboard (or any WS client subscribing to
`ws://127.0.0.1:8080/ws/checker?channel=sess:<sid>`) switches the feed to ONLY that session's
events; `channel=*` remains the all-queries feed.

**WS auth (JWT conversion):** `/ws/checker` accepts the bearer JWT via the
`Authorization` header **or**, because the browser WebSocket API cannot set
headers, as the `?access_token=<jwt>` query parameter on the WS URL — e.g.
`ws://127.0.0.1:8080/ws/checker?access_token=<jwt>&channel=sess:<sid>` (Node's
global WebSocket / rxjs `webSocket` both take the URL form). The header wins
when both are present; REST routes stay header-only by design. The route is
role-gated like the REST checker surface (checker always, maker only with
`allow_maker_watch`), and the SoD check still rejects watcher == maker.

**Two-level kill.** `POST /api/kill` takes an optional `mode`:

| mode | behavior |
|---|---|
| `connection` (default) | full disconnect: client + backend conns closed, session removed from the directory (`sess:live` deleted, `ended` event published) — the maker sees MySQL `2013 Lost connection` |
| `query` | aborts only the in-flight query via a second backend connection (`KILL QUERY <thread_id>` MySQL / `pg_cancel_backend(<pid>)` PG); the session stays alive and the maker can keep running queries. No active query → idempotent ok |

```bash
curl -H "Authorization: Bearer $JWT" -X POST http://127.0.0.1:8080/api/kill \
  -H 'Content-Type: application/json' -d '{"session_id":"sid-...","mode":"query"}'  # 202 {"killed":"queued"}
# ($JWT must be a checker-role JWT — or a maker with allow_maker_watch — else 403)
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
  # sentinel conns use this, master/data conns use `password`. Sentinels
  # have NO ACL users (review 2026-08-17): only the password is ever sent
  # (AUTH <password>) — there is deliberately no sentinel_username key.
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
# control plane — HTTPS listener + TLS Valkey store (auth secrets come from .env:
# ZT_AUTH_PASSWORD + ZT_JWT_SECRET; the retired ZT_API_API_KEY must NOT be set)
ZT_TLS_ENABLED=true ZT_VALKEY_SSL_ENABLED=true ZT_VALKEY_ADDR=127.0.0.1:6380 \
ZT_VALKEY_SSL_CA_FILE=certs/data.crt go run ./cmd/control
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
# token over HTTPS — bearer JWT (login over HTTPS first, §3; -k = self-signed dev cert)
JWT=$(curl -sk -X POST https://127.0.0.1:8080/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
TOKEN=$(curl -sk -X POST https://127.0.0.1:8080/api/token \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"username":"admin","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"TICKET-1"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# MySQL wire TLS — REQUIRED hard-fails if the proxy did not negotiate TLS
docker exec mysql-test mysql -h host.docker.internal -P 3306 -u "$TOKEN" -pany \
  --ssl-mode=REQUIRED appdb -e "SELECT id,name FROM demo_items"

# PostgreSQL wire TLS — sslmode=require must be INSIDE the conninfo string;
# a bare trailing "sslmode=require" argument is IGNORED by psql (verified 2026-08-12)
docker exec pg-test psql "host=host.docker.internal port=3306 user=$TOKEN dbname=appdb sslmode=require" \
  -c "SELECT id,name FROM demo_items"

# kill E2E over HTTPS (checker-role bearer JWT; 202 = queued, data plane force-closes)
curl -sk -H "Authorization: Bearer $JWT" -X POST https://127.0.0.1:8080/api/kill \
  -H 'Content-Type: application/json' -d '{"session_id":"sid-..."}'   # expect: 202 {"killed":"queued"}
```

Checker WS in TLS mode is
`wss://127.0.0.1:8080/ws/checker?access_token=<jwt>&channel=*` — Node ≥ 22 global
WebSocket with `NODE_TLS_REJECT_UNAUTHORIZED=0` (self-signed cert) plus the JWT
in the URL (`new WebSocket('wss://…/ws/checker?access_token=' + jwt +
'&channel=*')`); non-browser WS clients may instead send the
`Authorization: Bearer <jwt>` upgrade header.

### 6.6 Env override notes (verified live, 2026-08-12)

- Control-plane `api.api_key` / **`ZT_API_API_KEY`** were **retired in the JWT
  conversion** (Task 7): nothing parses them anymore, setting them has no
  effect, and `/api/token` auth is bearer-JWT only (§3). They are NOT the same
  key as the data plane's `credentials_api.api_key` → `ZT_CREDENTIALS_API_API_KEY`
  (§2.3), which is still live. The old `ZT_API_KEY` spelling was never valid.
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
| `401` on `/api/token` or any `/api/*` | Missing/invalid/expired/denylisted bearer JWT — log in again (§3) |
| `403` on `/api/kill`, `/api/sessions`, `/ws/checker` | Role gate: mint/watch needs a **checker**-role JWT (or `auth.allow_maker_watch: true`), §5 |
| `403` on a write-access mint | A **checker**-role JWT cannot mint write tokens (read-only minters), §3/§5 |
| `invalid or expired token` on first connect | Token reused (single-use) or > 300 s old — issue a fresh one |
| MySQL connect hangs ~200 ms then works | Expected — protocol-detection grace on the shared port |
| `token not valid for this protocol` | Token `db_type` doesn't match the client (mysql token + psql, or vice versa) |
| `backend unavailable` | Backend container down, or credentials missing in `configs/data.yaml` for that `db_ip:db_port:db_user` key |
| Control Plane exits at boot | Valkey not up (`valkey-cli ping` fails); port 8080 already bound; `ZT_JWT_SECRET`/`ZT_AUTH_PASSWORD` missing from `.env` |
| UI 404 / blank | Angular not built — see §2.1 |

---

## 10. Verified timings (Task 5.4 gate, 2026-08-11)

Measured from a fresh terminal with the three containers already up (Phase 0 state):

| Step | Time |
|---|---|
| Control Plane boot → `/api/health` 200 | **2.8 s** |
| Data Plane boot → `:3306` listening | **2.0 s** |
| Token issuance (curl, bearer JWT) | **79 ms** |
| `mysql … SELECT` through `:3306` (incl. ~200 ms detection grace) | **402 ms** |
| **Total, fresh terminal → first proxied SELECT** | **22.8 s — target < 120 s ✓** |

psql through the same `:3306` was also verified live (3 rows). Full suite
`go test -count=1 ./...` green at gate time. See `.superpowers/sdd/PLAN/task-5.4-report.md`.
