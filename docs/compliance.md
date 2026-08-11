# Compliance Matrix — Zero-Trust JIT Database Access Gateway

**Spec:** `hermes-agent-spec.md` v1.0 (§2 Core Requirements R1–R7; §9 Amendments 1–8)
**House rules:** `hermes-rules.md`
**Date:** 2026-08-11 (Task 5.6 — final review gates)
**Status:** **ALL R1–R7 VERIFIED** — 7/7 PASS (R4 PASS-with-annotation); **all 8 §9 amendments implemented**; Task 5.6 sweep green (vet / Go suite / ng test / ng build / FIXME grep).

**Method note:** every row cites the task report that captured real tool output (both planes from built binaries; containers `mysql-test` :3307, `pg-test` :5433, `valkey` :6379 live). All citations live in `.superpowers/sdd/PLAN/`. No fabricated results anywhere in the record.

---

## R1–R7 spec-compliance table

| ID | Requirement | Verdict | Verified behavior (evidence) |
|----|-------------|---------|------------------------------|
| R1 | Users never see static DB credentials | **PASS** | Token **is** the credential, used as the username, with **no password on the wire**: live `mysql` CLI connects with token only (task-5.1 claim 1; task-5.2 gates 1–2; task-3.4 session test). Handshake response skips the password field — `mysql_handshake.go:97` (`pos += authLen // password ignored — token is the credential`). Real credentials exist only in `configs/data.yaml` (data-plane config, never sent to clients). `DBPreset` has no password field; `GET /api/db-presets` response has `grep -ic password` → 0 (task-5.1 claim 10). Credential resolution lives in the data plane (task-3.3). |
| R2 | Tokens are short-lived and single-use | **PASS** | 5-minute TTL: `SET … EX 300` in the store (task-1.2); live expiry proven in task-5.1 claim 3 (`valkey-cli expire` → reconnect → `ERROR 1045 invalid or expired token`). Single-use via atomic `GETDEL` (`valkey_store.go:52`): consuming connect OK, same-token reconnect → 1045 (task-5.1 claim 2); **same-token parallel race → exactly 1 winner in 5/5 rounds** (task-5.2 Gate 2 — GETDEL atomicity under real concurrency); `tok:*` 0→0, no token leaks (task-5.2 Gate 3); balanced session open/close 17=17 (task-5.2 Gate 4). |
| R3 | Every query is audited in real time | **PASS** | Wire-level sniffing → `QueryEvent` → Valkey Pub/Sub → Checker WebSocket dashboard. MySQL: `COM_QUERY`/`COM_INIT_DB`/`COM_STMT_PREPARE`/`COM_STMT_EXECUTE` (task-3.4 tests `TestSniffCommandPublishesQueryEvents` / `TestSniffCommandPublishesTicketChannel`; NUL-trim fix task-3.7). PostgreSQL: `SimpleQuery`/`Parse`/`Execute`/`Close` extraction (task-4.3). Published to `queries:<username>` **and** `queries:ticket:<ticket_id>` (tasks 3.4, 4.3); WS hub bridges Valkey Pub/Sub → checker dashboard with no cross-channel leak (task-2.4 E2E 4/4); live two-browser feed with event dedupe verified (task-5.5, fix `edf42b1`). |
| R4 | Control/Data planes fully decoupled | **PASS** (with annotation) | Two separate binaries/processes (`cmd/control` :8080, `cmd/data` :3306). Valkey is the **only** shared infrastructure: token `GETDEL`, `sess:ui:*`, Pub/Sub `queries:*` (tasks 1.2, 1.3, 2.4). Data-plane **own code has zero `net/http` imports** and makes zero HTTP calls — coupling is exclusively Valkey tokens/PubSub, proven live (task-5.1 claim 6 full analysis). Annotation: `net/http` is linked into the data-plane binary only **transitively** via third-party deps (viper→afero, go-mysql→parser→zap) — inert, documented decision below. |
| R5 | Protocol-aware proxying | **PASS** | MySQL: hand-rolled handshake v10, OK/ERR packets, **byte-exact relay preserving original seq**, sniffing (tasks 3.1–3.5; byte-exactness asserted task-3.7). PostgreSQL: pgproto3/v2 relay, pgx SCRAM backend auth + `Hijack()`, SQL extraction (tasks 4.1–4.3). Shared-port protocol detection (PG client-first vs MySQL server-first, `detect_delay_ms` default 200 ms): dispatcher (tasks 3.5–3.6); live mixed-protocol matrix on :3306 — psql 3 rows + mysql regression + `FATAL 28000` + 1045 cross-checks (task-4.4); interleaved matrix + silent-connect edge (task-4.5). |
| R6 | Token issuance is secured | **PASS** | No anonymous issuance: `POST /api/token` requires `X-Api-Key` (env `ZT_API_API_KEY`) **OR** UI session cookie — live 401 / 401 / 200 matrix (task-5.1 claim 7; task-2.3). UI session cookie `HttpOnly; SameSite=Lax` (task-5.1 claim 8, `auth.go:76-79`); session required on `/api/db-presets` and `/ws/checker` — 401 returned before WS upgrade (task-5.1 claim 9). Initial curl matrix 6/6 (task-2.2). |
| R7 | Thick-client compatible | **PASS** | Standard clients connect with token-as-username: `mysql` CLI through proxy (task-3.4 live session; task-5.1 claim 1; task-5.2 10/10 parallel sessions), `psql` through proxy on the shared port (tasks 4.4–4.5). Relay is byte-exact (header+payload replayed with original seq, both directions). HeidiSQL: manual test recipe documented in `RUN.md` — Windows user-validatable; `mysql` CLI is the primary automated gate (task-5.6-brief risk table). |

---

## §9 Spec amendments — implementation status

| # | Amendment (spec v1.0 §9) | Status | Evidence |
|---|--------------------------|--------|----------|
| 1 | Redis → **Valkey** (RSAL avoidance) | **IMPLEMENTED** | `valkey-io/valkey-go` v1.0.76; every token/session/pubsub op on the `valkey` container (tasks 1.2, 1.3; live runs 5.1–5.5). |
| 2 | `TokenPayload` gains **`db_type`** | **IMPLEMENTED** | Token JSON carries `db_type`; routing and `QueryEvent` use it (task-5.1 claim 1 log `db_type=mysql`; task-4.4 `db_type=postgres` token routed on the shared port). |
| 3 | `POST /api/token` auth: **X-Api-Key or UI session** | **IMPLEMENTED** | `ZT_API_API_KEY` env (task-2.3 deviation); live 401/401/200 gate (task-5.1 claims 7–9). |
| 4 | **Checker is monitor-only** | **IMPLEMENTED** | `/ws/checker` is a read-only `QueryEvent` stream; no approval/kill-switch endpoints exist (tasks 2.4, 5.5; v2 open item). |
| 5 | **`GET /api/db-presets` allowlist** | **IMPLEMENTED** | Session-gated endpoint; UI issues tokens only against known targets (task-2.2; task-5.1 claim 10). |
| 6 | Response `port` = **shared Data Plane listener** | **IMPLEMENTED** | Token response returns the data-plane public port (3306) for both protocols (task-2.3 deviation "single-port response"). |
| 7 | **Single admin account** + Valkey sessions | **IMPLEMENTED** | `control.yaml` admin; `sess:ui:*` TTL 8 h (tasks 2.2; task-5.2 Gate 3 `dbsize`=15 baseline). |
| 8 | **Single shared Data Plane port** :3306 with per-connection detection | **IMPLEMENTED** | Dispatcher on :3306, `detect_delay_ms` default 200 ms (tasks 3.5–3.6, 4.4, 4.5). |

---

## Claim 6 annotation — decoupling invariant (from task-5.1-report)

The architectural invariant from `hermes-rules.md` ("Data Plane NEVER makes HTTP calls to the Control Plane. All coupling via Valkey") is **verified true at the code level**:

- Data-plane-owned packages (`cmd/data`, `internal/proxy`, `internal/store`, `internal/config`, `internal/logging`): `grep -rn "net/http"` → **0 hits**; `go vet ./...` clean.
- `go list -deps ./cmd/data | grep -i http` matches **8 packages**, all stdlib / `x/net`, pulled **transitively** by third-party deps:
  - `github.com/spf13/viper → github.com/spf13/afero → net/http` (afero's httpFs support)
  - `github.com/go-mysql-org/go-mysql → github.com/pingcap/tidb/pkg/parser → github.com/pingcap/log → go.uber.org/zap → net/http`
- Neither chain is exercised by data-plane code paths (afero httpFs and zap's http hook are dead code in this binary). Live session flow (task-5.1) shows coupling **exclusively** via Valkey token `GETDEL` + Pub/Sub — **zero HTTP calls by construction**.

**DECISION (2026-08-11, recorded in progress.md): keep `spf13/viper` — no replacement.** The literal dependency-graph FAIL from task-5.1 is therefore recorded as **R4 PASS-with-annotation**: the security property (no HTTP calls between planes) holds; the linkage is inert stdlib symbol linkage. Revisit only if the data-plane binary must be free of `net/http` symbols (e.g., regulatory/scanning requirements) — remediation path (a) from task-5.1 (stdlib config reader for the data plane) is documented and available.

---

## Task 5.6 final review gates (this run, 2026-08-11)

| Gate | Result |
|------|--------|
| `go vet ./...` | clean, exit 0 |
| `go test -count=1 ./...` | ALL PASS — `internal/api 1.470s`, `internal/config 1.640s`, `internal/models 1.033s`, `internal/proxy 12.840s`, `internal/store 2.844s` (61 tests, 0 fail; `cmd/control`, `cmd/data`, `internal/logging` no test files) |
| `cd web && npx ng test --watch=false` | 4 files / 17 tests PASS (vitest 4.1.10), exit 0 |
| `cd web && npm run build` | success → `web/dist/web/browser`, exit 0 (initial bundle 934 kB exceeds 500 kB *warning* budget — known cosmetic, deferred since task 2.5, exits 0) |
| FIXME/TODO/XXX grep in `cmd/` `internal/` `web/src` | **0 hits** |
| `git log --oneline` | clean linear history, 42 commits, no merge noise (reviewed in task-5.6-report) |

---

## Open items (v2 / hardening — spec §10, task-5.6-brief)

- TLS termination for client-facing TCP (stunnel/HAProxy) — v1.1
- `COM_STMT_EXECUTE` → statement-id → SQL mapping — v1.1
- Multi-packet (>16 MB) payload reassembly — v1.1
- RBAC / per-team tokens / quotas — v2
- Checker approval/kill-switch (B/C parity) — v2 decision
- (tracked) UI session restore on refresh; slow-WS-consumer Pub/Sub stall hardening; idle-session deadlines — v1.1 hardening list in progress.md

*Compliance record assembled by Task 5.6. Final project-state summary: see `.superpowers/sdd/PLAN/task-5.6-report.md`.*
