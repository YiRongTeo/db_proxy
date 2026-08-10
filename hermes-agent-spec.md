# Hermes Agent Specification
## Zero-Trust Just-in-Time Database Access Gateway

**Version:** 1.0
**Date:** 2026-08-11
**Status:** Ready for Implementation (plan awaiting approval)
**License Context:** Proprietary — avoid GPL-3.0 dependencies. All Go/Angular dependencies are Apache-2.0 or MIT. **Valkey** replaces Redis (RSAL license) per user directive 2026-08-11.
**Revisions:** v1.0 — initial release based on `agent.md`, with amendments listed in §9.

---

## 1. Executive Summary

Build a **zero-trust, just-in-time (JIT) database access gateway** that sits between end-users (thick clients such as HeidiSQL) and backend databases (MySQL/PostgreSQL). Static database credentials are replaced by **short-lived, single-use tokens** issued on demand by an external Ticketing/Orchestration system (or the UI). All SQL traffic is proxied through a protocol-aware Data Plane that extracts and **live-audits every query** (Maker-Checker principle) and streams it to a Checker dashboard.

The system is **distributed**: a **Control Plane** (web/API) and a **Data Plane** (TCP proxy) run as separate processes/servers, communicating **only** through a shared **Valkey** instance — enabling independent scaling and network isolation.

**Key directive:** the Data Plane MUST NEVER make HTTP calls to the Control Plane. All state sharing (tokens) and event streaming (queries) go through Valkey.

---

## 2. Core Requirements (Non-Negotiable)

| ID | Requirement | Enforcement |
|----|-------------|-------------|
| R1 | Users never see static DB credentials | Tokens issued JIT; real credentials live only in Data Plane config |
| R2 | Tokens are short-lived and single-use | 5-minute TTL; atomic `GETDEL` on first use |
| R3 | Every query is audited in real time | Wire-protocol parsing + Valkey Pub/Sub → Checker WebSocket dashboard |
| R4 | Control/Data planes fully decoupled | Valkey is the only shared infrastructure; Data Plane never calls Control Plane |
| R5 | Protocol-aware proxying | MySQL + PostgreSQL wire parsing (COM_QUERY, SimpleQuery, Parse, …) |
| R6 | Token issuance is secured | `X-Api-Key` (external systems) OR UI session; no anonymous issuance |
| R7 | Thick-client compatible | HeidiSQL connects with token as username; byte-exact relay |

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CONTROL PLANE (Go, :8080)                    │
│  ┌──────────────┐   ┌──────────────────┐   ┌─────────────────────┐  │
│  │ Angular SPA  │◄──┤ POST /api/token  │   │ /ws/checker WS hub  │  │
│  │ (maker+      │   │ POST /api/login  │   │ (Valkey Pub/Sub →   │  │
│  │  checker)    │   │ GET /api/db-     │   │  Checker dashboard) │  │
│  └──────────────┘   │ presets, health  │   └─────────────────────┘  │
│                     └────────┬─────────┘                            │
└──────────────────────────────┼──────────────────────────────────────┘
                               │  SET/GETDEL tokens · Pub/Sub queries
                               ▼
                    ┌──────────────────────┐
                    │   VALKEY (shared)     │   ← single source of truth
                    │ tok:<t> TTL 300s      │      tok:<t>, sess:ui:<id>,
                    │ sess:ui:<id> TTL 8h   │      Pub/Sub queries:*
                    └──────────────────────┘
                               ▲
        │        ┌──────────────────────┼──────────────────────────────────────┐
        │        │             DATA PLANE (Go, :3306 — MySQL+PG shared)         │
        │        │  protocol detect → token=username → GETDEL validate          │
        │  → backend connect (real creds from data.yaml)               │
        │  → byte-exact relay + passive SQL sniffing → Publish         │
        └──────────────────────┬──────────────────────────────────────┘
                               │
        ┌──────────────────────▼──────────────────────────────────────┐
        │        BACKEND DATABASES (MySQL 8.4, PostgreSQL 17)          │
        └─────────────────────────────────────────────────────────────┘
```

---

## 4. Components

### 4.1 Control Plane (Go, :8080)
- Serves the built Angular SPA from `web/dist/`
- `POST /api/token` — issues a single-use token (TTL 300 s) into Valkey; secured by `X-Api-Key` OR UI session cookie
- `POST /api/login` / `POST /api/logout` — single admin account (`control.yaml`), session stored in Valkey (TTL 8 h)
- `GET /api/db-presets` — allowlisted DB targets for the Maker UI (zero-trust: UI can only issue tokens against known targets)
- `GET /api/health` — liveness + Valkey status
- `GET /ws/checker?channel=<username | ticket:<id> | *>` — WebSocket bridge from Valkey Pub/Sub to the Checker dashboard

### 4.2 Data Plane (Go, :3306 — MySQL + PostgreSQL on one shared port)
- One shared TCP listener; **protocol detected per connection** (PostgreSQL is client-first, MySQL is server-first — see §6.0); grace period `listen.detect_delay_ms` (default 200 ms)
- Client handshake: **token-as-username**; token validated with atomic `GETDEL` (single-use); `OK`/`ERR` packets
- Backend connection with real credentials resolved from `data.yaml` (Data Plane owns credentials)
- Byte-exact relay both directions + **passive SQL sniffing**; every query published to Valkey Pub/Sub
- MySQL: go-mysql client for backend auth (handles caching_sha2_password), then raw packet relay
- PostgreSQL: pgx for backend auth (handles SCRAM-SHA-256), then `Hijack()` + pgproto3 relay

### 4.3 Valkey (shared infrastructure)
- `tok:<token>` → `TokenPayload` JSON, TTL 300 s — single source of truth for routing
- `sess:ui:<id>` → UI session, TTL 8 h
- Pub/Sub channels: `queries:<username>`, `queries:ticket:<ticket_id>` (pattern `queries:*` for "all")

---

## 5. API Contract

### `POST /api/token`
Auth: `X-Api-Key: <control.api_key>` **OR** valid UI session cookie.
```json
{ "username": "alice", "db_user": "ro_user", "db_ip": "10.0.0.5",
  "db_port": "3306", "db_type": "mysql", "ticket_id": "TICKET-1" }
```
- 200: `{ "token": "sess_…", "host": "<data-plane-host>", "port": "3306", "expires_in": 300 }`
  (`port` = the shared Data Plane public listener, from `control.yaml` — same port for both protocols)
- 401 unauthorized · 400 missing/invalid fields · 422 unknown `db_type`

### `POST /api/login` `{username,password}` → 200 + `Set-Cookie` (HttpOnly, SameSite=Lax) | 401
### `POST /api/logout` → 200 (session deleted from Valkey)
### `GET /api/db-presets` → `[{name, db_type, db_user, db_ip, db_port}]` (session required)
### `GET /api/health` → `{"status":"ok","valkey":"up"}`
### `GET /ws/checker?channel=<key>` (session required) → stream of `QueryEvent` JSON

---

## 6. Wire Protocol Notes (Data Plane)

### 6.0 Protocol detection (shared port)
Both protocols share one Data Plane port (`:3306`). Detection is deterministic because of a protocol asymmetry:
- **PostgreSQL is client-first** — the client sends `StartupMessage` (or `SSLRequest`) immediately after connect.
- **MySQL is server-first** — the client waits silently for the server handshake.

On accept, the Data Plane waits up to `listen.detect_delay_ms` (default 200 ms) for the first client byte: **bytes → PostgreSQL; silence → MySQL handshake**. The peeked bytes are preserved via a `bufio.Reader` (never lost). A pathological slow PG client could be misdetected as MySQL → it fails with a benign protocol error; raising `detect_delay_ms` covers that.

### 6.1 MySQL (client-facing)
- Handshake v10; advertise Protocol 4.1 + `mysql_native_password`; **no SSL capability** (v1)
- Username field = token; password and db fields ignored (the token is the credential)
- After OK, relay loop with passive sniffing:
  - `COM_QUERY` (0x03) → SQL
  - `COM_INIT_DB` (0x02) → `USE <db>`
  - `COM_STMT_PREPARE` (0x16) → SQL (prepare)
  - `COM_STMT_EXECUTE` (0x17) → statement id only (v1; param/statement mapping is hardening)
- Backend: `go-mysql` `client.Connect` (real creds), then raw relay over `conn.Conn`
- Relay is **byte-exact**: read 4-byte header + payload, replay identical bytes (header seq preserved) in both directions
- Packets > 16 MB (0xFFFFFF length): relayed; sniffing limited to first fragment (hardening item)

### 6.2 PostgreSQL (client-facing)
- `StartupMessage` (user = token); `SSLRequest` answered with `'N'`
- Auth: `AuthenticationOk` without challenge (token is the credential)
- `ParameterStatus` + `BackendKeyData` + `ReadyForQuery` sent after backend session is established
- Messages relayed with pgproto3; SQL extracted from:
  - `SimpleQuery` (`Q`) → `msg.SQL`
  - `Parse` (`P`) → cached by name (name → SQL); `Execute` (`E`) → lookup by portal/name; `Close` → evict
- Backend: `pgx.Connect` (SCRAM-SHA-256), `Hijack()` → raw conn, pgproto3 `Frontend` for relay

---

## 7. Tech Stack (Enterprise LTS, Aug 2026)

| Layer | Choice |
|---|---|
| Language | Go 1.24 local toolchain (spec targets Go 1.27) |
| HTTP | stdlib `net/http` ServeMux (method+path patterns) |
| WebSocket | `coder/websocket` v2 |
| Store/Bus | `valkey-io/valkey-go` v1 (official Valkey client) |
| Config | `spf13/viper` (env prefix `ZT_`) |
| Logging | `log/slog` (JSON) |
| MySQL wire | hand-rolled client-facing handshake/parse; `go-mysql-org/go-mysql` v1 for backend auth |
| PG wire | `jackc/pgproto3/v2` + `jackc/pgx/v5` |
| Frontend | Angular 21 (standalone, zoneless, signals), NG-ZORRO v21, ngx-clipboard, rxjs `webSocket` |

All dependencies Apache-2.0 or MIT — no GPL.

---

## 8. Phased Build & Verification Gates

| Phase | Scope | Gate |
|---|---|---|
| 0 | Environment (Docker, Valkey, MySQL 8.4, PG 17), scaffold, configs, git | 3 containers healthy; `valkey-cli ping` → PONG |
| 1 | Shared foundation: models, Valkey store (tokens/sessions), Pub/Sub, config | `go test ./...` green incl. single-use + Pub/Sub integration tests |
| 2 | Control Plane: API, WS hub, Angular SPA (maker portal + checker dashboard) | `ng build` ok; curl 401/200 matrix; WS stream via Node ≥22 WebSocket |
| 3 | Data Plane MySQL: handshake, token validation, relay, sniffing | mysql CLI through proxy; live feed in Checker dashboard; single-use enforced |
| 4 | Data Plane PostgreSQL: pgproto3 relay, SQL extraction | psql through proxy; both proxies coexist; live feed |
| 5 | Security tests, E2E two-browser gate, RUN.md/README, final review | Full matrix green; demo recorded |

---

## 9. Spec Amendments vs agent.md (2026-08-11)

1. **Redis → Valkey** (user directive; RSAL avoidance). Client: `valkey-io/valkey-go`.
2. **`TokenPayload` gains `db_type`** (`"mysql" | "postgres"`) — required for routing and `QueryEvent`.
3. **`POST /api/token` auth**: `X-Api-Key` or UI session (spec left open; API key chosen over mTLS for v1).
4. **Checker is monitor-only** (live audit feed). Approval/kill-switch NOT in scope for v1 — the spec requires auditing only.
5. **`GET /api/db-presets` allowlist** added so the UI only issues tokens against known targets.
6. **Response `port` = Data Plane public listener** for the requested `db_type` (not the backend port).
7. **UI auth**: single admin account from `control.yaml`; sessions in Valkey (TTL 8 h).
8. **Single shared Data Plane port** (`:3306`) for both protocols, with per-connection detection (`detect_delay_ms`, default 200 ms); `data_plane_ports` → single `data_plane_port` (2026-08-11, plan review).

---

## 10. Open Questions / Future Hardening

- TLS termination for client-facing TCP (stunnel/HAProxy) — v1.1
- COM_STMT_EXECUTE → statement-id → SQL mapping — v1.1
- Multi-packet (>16 MB) payload reassembly — v1.1
- RBAC, per-team tokens, token quotas — v2
- Checker approval/kill-switch (align with Project B/C) — v2 decision
