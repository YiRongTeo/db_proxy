# Project-D — Zero-Trust Just-in-Time (JIT) Database Access Gateway

A gateway that replaces **static database credentials** with **short-lived, single-use tokens**.
Users (thick clients such as HeidiSQL, mysql CLI, psql) connect to one shared Data Plane port with
the token as their username; the gateway validates the token, connects to the real backend with
credentials **only it** holds, relays traffic byte-exact, and **live-audits every query** on a
Checker dashboard (maker–checker principle).

- **Control Plane** (Go, `:8080`) — REST API + WebSocket hub + Angular 21 SPA (Maker portal / Checker dashboard).
- **Data Plane** (Go, `:3306`) — ONE shared TCP listener for **MySQL AND PostgreSQL**; protocol detected per connection.
- **Valkey** — the *only* coupling between the planes: tokens, UI sessions, and the query event bus.
  The Data Plane **never** makes HTTP calls to the Control Plane (R4).

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE (Go, :8080)                        │
│   Angular SPA (Maker+Checker) · POST /api/token · /ws/checker hub      │
└───────────────────────────────┬────────────────────────────────────────┘
                                │ SET/GETDEL tokens · Pub/Sub queries
                                ▼
                     ┌──────────────────────┐
                     │   VALKEY (shared)    │   tok:<t> TTL 300s (single-use, GETDEL)
                     │ tok:* · sess:ui:* ·  │   sess:ui:<id> TTL 8h
                     │ Pub/Sub queries:*    │   queries:<user>, queries:ticket:<id>
                     └──────────────────────┘
                                ▲
┌───────────────────────────────┴────────────────────────────────────────┐
│                     DATA PLANE (Go, :3306 — shared)                     │
│   protocol detect → token-as-username → GETDEL validate → backend       │
│   connect (real creds from data.yaml) → byte-exact relay + SQL sniff    │
└───────────────────────────────┬────────────────────────────────────────┘
                                ▼
              BACKEND DATABASES (MySQL 8.4 :3307 · PostgreSQL 17 :5433)
```

## Security model

- **Token-as-username** — the token *is* the credential; client passwords are ignored. No static DB
  credentials ever reach a client (R1).
- **Single-use, short-lived** — 5-minute TTL, consumed by atomic `GETDEL` on first connect; reuse →
  `1045` (MySQL) / `FATAL 28000` (PG) (R2).
- **Data Plane owns credentials** — real DB passwords live only in `configs/data.yaml`, resolved by
  `db_ip:db_port:db_user` key (R1).
- **Every query is audited** — passive wire-protocol sniffing (COM_QUERY/COM_INIT_DB/COM_STMT_PREPARE/
  EXECUTE; PG SimpleQuery/Parse/Execute) publishes `QueryEvent`s to Valkey Pub/Sub → Checker WebSocket
  (R3). Checker is **monitor-only** in v1 (D3).
- **No anonymous issuance** — `POST /api/token` requires `X-Api-Key` (external ticketing systems) **or**
  a UI session cookie (R6); UI tokens restricted to the `db_presets` allowlist (D8).
- **Decoupled planes** — Valkey is the only shared infrastructure; the Data Plane has zero HTTP calls
  to the Control Plane by construction (R4, verified in Task 5.1).

## Key behaviors

- One shared Data Plane port for both protocols: PG clients are client-first, MySQL clients
  server-first → detection grace `detect_delay_ms` (default 200 ms) adds ~200 ms to MySQL connects (D11).
- Tokens carry `db_type`; a MySQL token rejected by a PG client and vice versa (wrong-protocol = fail closed).
- Byte-exact relay (original packet headers/sequence preserved) — thick-client compatible (R7).
- UI session: single admin account (`configs/control.yaml`, env-overridable via `ZT_*`), 8 h TTL in Valkey.

## Tech stack

Go 1.24 (stdlib `net/http`, `log/slog` JSON, viper `ZT_` env config) · `valkey-io/valkey-go` v1 ·
`go-mysql` v1 (backend MySQL auth) · `pgx` v5 + `pgproto3` v2 (backend PG auth + relay) ·
`coder/websocket` v2 · Angular 21 standalone/zoneless/signals + NG-ZORRO v21. All deps Apache-2.0/MIT.

## Repo layout

```
cmd/control/     Control Plane entrypoint (:8080)
cmd/data/        Data Plane entrypoint (:3306 shared listener)
internal/api/    HTTP handlers + WebSocket hub
internal/proxy/  wire protocols: mysql_*.go, pg_*.go, dispatcher.go
internal/store/  Valkey client (tokens, sessions, Pub/Sub)
internal/models/ TokenPayload, QueryEvent, Session
web/             Angular 21 SPA (Maker portal + Checker dashboard)
configs/         control.yaml, data.yaml (dev defaults; ZT_ env overrides)
```

## Get started

See **[RUN.md](RUN.md)** — containers → `go run ./cmd/control` → `go run ./cmd/data` → curl a token →
connect HeidiSQL/mysql/psql → Checker at `http://127.0.0.1:8080/checker` (login `admin/admin123`, dev only).

## Docs

- [hermes-agent-spec.md](hermes-agent-spec.md) — authoritative spec (requirements R1–R7, §9 amendments)
- [hermes-rules.md](hermes-rules.md) — house rules / architecture invariants
- [PLAN.md](PLAN.md) — full implementation plan, per-task verification gates, design decisions D1–D11
- [RUN.md](RUN.md) — end-to-end run guide with exact commands and timings

**Status:** Phases 0–4 complete and reviewed (MySQL + PG proxies, shared-port dispatcher, coexistence
gate); Phase 5 gates in progress (security matrix, concurrency, shutdown hygiene passed; docs/E2E/review remaining).
