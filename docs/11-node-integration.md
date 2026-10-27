# Page 11 — Node Integration (Main-App Contract)

> **The integrating application's spec.** This page is the end-to-end contract for embedding the
> gateway behind another application ("the main app"): how it mints tokens (`POST /api/token` with
> the node-integration fields `db_subtype` / `end_time` / `password`), how the data plane resolves
> backend credentials (override-first), and how the data plane reports session start/end back to the
> main app (session callbacks). Operators: the config knobs and ops semantics live in
> [§11.9](#119-config-knobs) and [§11.10](#1110-operator-notes). Companion pages: [Page 2](02-creating-db-connections.md)
> (mint + wire connect basics), [Page 10](10-credential-api-contract.md) (external credential service).

## 11.1 The three integration points

| # | Surface | Direction | Contract |
|---|---|---|---|
| 1 | `POST /api/token` | Main app → Control Plane | Mint a DB token, optionally bounded by `end_time` and carrying an at-mint credential `password` override ([§11.2](#112-minting---post-apitoken)) |
| 2 | Token-as-username TCP connect | DB client → Data Plane | Unchanged wire contract ([Page 2 §2.3](02-creating-db-connections.md)); credential resolution is override-first when the mint carried a password ([§11.5](#115-credential-resolution---override-first)) |
| 3 | Session-status callback | Data Plane → Main app | `POST {url}/dbpxy/session/{sessionId}/status` on session start/end ([§11.6](#116-session-callbacks---data-plane--main-app)) |

## 11.2 Minting — `POST /api/token`

| Item | Value |
|---|---|
| Endpoint | `POST /api/token` (Control Plane, HTTPS `:8080`) |
| Authentication | `Authorization: Bearer <JWT>` — local login or external issuer ([Page 9](jwt-auth-conversion.md)); mint-for-self only (body `username` must equal the JWT subject or be omitted) |
| Content-Type | `application/json` |
| Body limit | 1 MB; **unknown fields are rejected** (`400`) — a misspelled field is a client bug, not a silently-ignored field |

### Request fields

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `username` | string | no | bearer subject | Must match the JWT's subject or be omitted — the token is always issued for the authenticated principal |
| `ticket_id` | string | **yes** | — | Approval/change ticket; trimmed, ≤ 128 chars, no whitespace/control chars |
| `db_type` | string | **yes** | — | `mysql` \| `mariadb` \| `postgres` \| `mssql` \| `oracle` — stored **verbatim** in the token payload (MariaDB is a first-class type, never normalized to `mysql`) |
| `db_user` | string | **yes** | — | Backend DB user |
| `db_ip` | string | **yes** | — | Backend DB host |
| `db_port` | integer \| string | no | resolved from `db_type` + `db_subtype` (table below) | **Node-integration change: now OPTIONAL, and accepts a JSON NUMBER or a numeric STRING** — `3306` and `"3306"` are the same port (normalized to the canonical decimal string; whitespace trimmed). A fractional number (`3306.5`) or non-numeric value → `400 db_port must be an integer or numeric string`. An explicit value is stored verbatim and always wins; when absent (or `null`), the port is looked up in the default-port map |
| `db_subtype` | string | no | `"default"` | **NEW.** Refines the default-port lookup (e.g. `master`/`slave`). Trimmed, ≤ 64 chars, no control characters; it never appears in the payload, the credentials key, or the response — it is consumed by the port lookup |
| `mode` | string | no | preset's `token_mode`, then `api.token_mode` | `single-use` \| `session` |
| `idle_seconds` | int | no | 0 = data-plane `session.idle_seconds` | Per-token idle override (≥ 0) |
| `end_time` | string \| int | no | absent = no deadline | **NEW.** Absolute kill time for the token and any session it opens — see [§11.3](#113-end_time---the-absolute-deadline) |
| `endTime` | string \| int | no | — | **ALIAS of `end_time`** (the node client's camelCase contract spelling). Both keys are accepted; setting **both** with different values → `400 end_time and endTime are both set with different values`; identical values (or `null` on one side) are fine. No other field has a camelCase alias |
| `password` | string | no | absent = unchanged | **NEW.** At-mint backend-credential override — see [§11.4](#114-password---the-at-mint-credential-override) |
| `access` | string | no | preset's `access` | **NEW — Task 6.** Explicit access level: `read` \\| `ro` \\| `write` \\| `rw` (case-insensitive) — see [§11.2.1](#1121-access---true-read-only-ro-and-held-read-write-rw) |

### 11.2.1 `access` — TRUE read-only (`ro`) and HELD read-write (`rw`)

The optional `access` field chooses the session's enforcement model. Values are
**case-insensitive** and normalized at mint: `read`/`ro` → **`ro`**,
`write`/`rw` → **`rw`**. Anything else → `422 access must be read, ro, write or rw`.
An absent (or `null`/empty) field takes the matching preset's `access` — that path is
byte-identical to the pre-field behavior apart from the preset migration below.

| Canonical value | Enforcement |
|---|---|
| `ro` | **TRUE read-only.** The session authenticates normally and every **write** SQL command is rejected AT THE PROXY (protocol-appropriate error, WARN log + `gate_blocks` metric, audit event) — it never reaches the backend. Reads flow. **No checker involvement.** A checker watching changes nothing; the gate is the classifier |
| `rw` | **HELD read-write.** The client's protocol auth COMPLETES (it sees a normal login success) but the backend connection is **NOT opened and the credential is NOT drawn** until a checker actively watches the session (`WatchActive(sid)`). The held session appears in the checker directory as `pending` (the mint-time record, refreshed while held). When watched: the backend connect proceeds and the session is full read/write **for its life** — a watcher detaching after admission does NOT kill the session. A client that disconnects while held exits cleanly: no backend, no leaked directory record |
| `write` (legacy presets only) | **Legacy no-gate.** Presets declaring `access: "write"` keep today's behavior (connect + write freely) for backward compatibility. **Flagged for future unification** — new integrations should use `rw` instead |

**Preset migration:** a preset with `access: "read"` now enforces `ro` (true
read-only). The stored payload carries the canonical value (`ro`) — the legacy
`read` value never ships.

**Checker separation of duties:** a checker-role principal may mint only `ro`
tokens — `rw` (and the legacy write presets) → `403 checker role limited to
read-only tokens`. Alias normalization happens BEFORE the SoD check, so a
checker sending `"rw"` is refused on the canonical value.

**Oracle limitation:** the Oracle relay has no statement classification yet
(TNS capture is Phase 1). A `ro` mint for `db_type: oracle` — explicit or via
a migrated read-only preset — is **refused at the mint** with
`422 access ro is not supported for db_type oracle — the gateway cannot
classify Oracle statements yet; use rw or a SELECT-only backend account`.
`rw` mints for oracle work (the hold needs no classification).

**Classification caveat (honest scope):** `ro` enforcement is TEXT
classification of the statement's leading keyword (comments skipped,
`WITH`-CTEs walked through — a data-modifying CTE is classified as a write).
It is a **strong first line, not a guarantee**: side effects through
`SELECT` (`SELECT ... INTO OUTFILE`, functions with side effects,
unparseable shapes) are the residual risk. **True read-only assurance comes
from provisioning SELECT-only backend accounts (`ro_user`) so even a
misclassified statement cannot mutate data.** Gateway `ro` + a SELECT-only
backend account is the defense-in-depth pairing. The classifier's verb list
lives in ONE place: `writeVerbsShared`/`writeVerbsMySQL` in
`internal/proxy/write_classify.go` (`EXTEND HERE`).

### Default-port map (used when `db_port` is omitted)

| `db_type` | `db_subtype` absent / `"default"` | Any other subtype without an entry |
|---|---|---|
| `mysql` | `3306` | `422` — no guessed port |
| `mariadb` | `6603` | `422` — no guessed port |
| `postgres` | `5432` | `422` |
| `mssql` | `1433` | `422` |
| `oracle` | `1521` | `422` |

> **Where the mapping lives (for the client team):** the default-port map — and any future
> `db_type`/`db_subtype` entry — is the `dbPortDefaults` map in `internal/api/handlers.go`. That is
> the only place a new subtype (e.g. `"slave" → 3307`) is added; nothing else in the codebase
> changes. Until an entry exists, a subtype-bearing mint must pass `db_port` explicitly or it is
> rejected `422 no default port for db_type/db_subtype; pass db_port explicitly` — never a guessed
> port.

### Response — `200 OK`

```json
{
  "token": "sess_3dbeca423e...",
  "session_id": "sid-1a2b3c4d5e6f7a8b",
  "host": "127.0.0.1",
  "port": "3306",
  "expires_in": 300,
  "expires_at": 1760512345
}
```

| Field | Present | Meaning |
|---|---|---|
| `token` | always | The DB token — the client uses it **as the DB username**. Format `sess_<32 hex>` |
| `session_id` | always | The session directory id (`sid-<16 hex>`), stamped at mint. **Correlate everything with this**: checker feeds, `/api/kill`, audit rows, and the callback path (`/dbpxy/session/{sessionId}/status`) all key on it |
| `host` / `port` | always | The data-plane listener to connect to |
| `expires_in` | always | Seconds until the token dies. `-1` **only** for a session-mode token with an infinite configured TTL *and* no `end_time`; when `end_time` is present the value is the end_time-derived TTL even in that infinite-TTL case |
| `expires_at` | **only when the mint carried `end_time`** | Absolute expiry, unix seconds (the `end_time` instant). Omitted otherwise — the response stays byte-identical to the pre-`end_time` shape for existing clients |

## 11.3 `end_time` — the absolute deadline

Optional per-mint field that turns the token (and any session it opens) off at a fixed instant.

| Aspect | Behavior |
|---|---|
| Accepted shapes | A string or integer epoch seconds (`1760512345`). String shapes, tried in order: **RFC3339** (UTC `Z` is the documented form, `"2026-10-15T18:00:00Z"`; numeric offsets `+02:00` are accepted and an offset, when present, is **authoritative** — never re-zoned) — then, when RFC3339 fails, the **naive (no-timezone) shapes**: `"2026-10-21 23:59:00"` (space-separated — the client main-app's shape), `"2026-10-21T23:59:00"` (naive ISO), `"2026-10-21"` (date-only → local midnight), `"2026-10-21 23:59"` (minute precision). Naive timestamps are interpreted in the **gateway's local timezone** (wall-clock intent) |
| Absent / `null` | Feature off — no `expires_at` in the payload or response (existing clients unaffected) |
| Malformed value | `400 invalid end_time` (a non-integer number, bool, object, array, or a string matching no accepted shape) |
| Past instant | `422 end_time is in the past` |
| Beyond the ceiling | `422 end_time exceeds max session duration` when `api.max_session_seconds` > 0 and `end_time − now` exceeds it; **exactly at the ceiling is accepted** (config: [§11.9](#119-config-knobs)) |
| Token TTL | `ttl = min(end_time − now, existing TTL rules)` — the end_time never *extends* a token past its mode's configured TTL; for session mode with an infinite configured TTL it becomes the finite key lifetime |
| Enforcement | The `tok:<token>` key TTL. When it expires, the **existing revoke path** closes running sessions — keyspace-notification fast path or within `session.revoke_poll_seconds` (default 1 s). Force-close and kill ride the same path; nothing new polls `end_time` |
| Visibility | `payload.expires_at` is **informational only** (logging/tracing); the TTL is the enforcement. The mint response reports the deadline as `expires_at` (unix seconds) |

## 11.4 `password` — the at-mint credential override

Optional per-mint field supplying the backend credential the data plane should use for sessions
opened with this token — instead of the configured credential chain.

| Aspect | Behavior |
|---|---|
| Absent / `null` | Unchanged resolution — no override key is written, the flag stays off (existing clients unaffected) |
| Empty string | `422 password must not be empty` (an override carrying nothing would flip the data plane onto a dead key) |
| Longer than 256 bytes | `422 password exceeds 256 bytes` (the cap is **inclusive** — 256 bytes is accepted; the value is never truncated) |
| Storage | Separate Valkey key **`ztcred:<session_id>`**, JSON `{"password":"…"}`, **TTL == the token's resolved TTL** (end_time- and mode-aware) — the override can never outlive the session it belongs to |
| Flag | `payload.cred_override = true`; the response **does not** change shape — no password or flag is ever echoed |
| Confidentiality | The value is **never** logged, never echoed in any response, never written to audit rows or lifecycle events |
| Infinite-TTL guard | `password` + a resolved `ttl ≤ 0` (session mode with `api.session_token_ttl_seconds: 0` and no `end_time`) → `422 password requires a finite token ttl — supply end_time or set api.session_token_ttl_seconds` — rejected **before any write** |
| Failed override write | Fails the **mint** (`500 internal`) and deletes the already-written `tok:` key — a `cred_override`-stamped token is never shipped without its credential |

## 11.5 Credential resolution — override-first

When a token was minted with `password` (`cred_override`), the data plane resolves the backend
credential **override-first** on every connect (including kill-query second connects):

1. `GET ztcred:<session_id>` — hit → that value authenticates the backend login.
2. Miss (expired key) or store error → fall through to the normal chain (config list / credential
   API, [Page 5](05-credential-retrieval-api.md)) with a **WARN carrying the reason only** — never a value.
3. Tokens without the flag never consult the override store — byte-identical to the pre-feature path.

Ops semantics of the `ztcred:` key (TTL skew, kill/revoke behavior, manual scrub): [§11.10](#1110-operator-notes).

## 11.6 Session callbacks — Data Plane → Main app

On Maker session **start** (rw hold-start **and** backend connect success) and **end** (every close
path: client close, backend close, idle timeout, kill, token expiry/`end_time`), the data plane POSTs
a status callback to the main app. **Disabled by default** — zero HTTP traffic until a callback URL
is configured ([§11.9](#119-config-knobs)).

| Aspect | Value |
|---|---|
| Method + path | `POST {url}/dbpxy/session/{sessionId}/status` (`sessionId` = the mint response's `session_id`, URL-path-escaped) |
| Body | `{"action":"started"\|"ended","timestamp":"<RFC3339 UTC>"}` |
| Header | `Content-Type: application/json`; plus **`X-Session-Callback-Key: <secret>`** on every request when a shared secret is configured (no header when empty) |
|| `started` | Sent at **rw hold-start** (the maker's rw connection authenticated and is HELD waiting for a checker — the **"session is available to join"** signal, fired before any watcher attaches) and **again at backend connect success**. An rw session therefore receives **TWO** `started` callbacks (accepted contract: first = *joinable now*, second = *backend live*); every non-rw session receives exactly one, at connect success |
| `ended` | Sent on **every** close path — client/backend disconnect, idle timeout, kill, token expiry (`end_time` or TTL), revoke |
| Delivery | **Fire-and-forget** on its own goroutine — the relay path never waits on the main app |
| Retries | **Exactly ONE** retry after **2 s** on failure — no backoff schedule, no buffering |
| Failure handling | Non-2xx and transport errors are **WARN-logged only** — they never affect the relay or the session |
| Response body | Read (bounded) and **discarded** — the data plane ignores any `session_id`/`action`/`rows_updated` the main app returns |
|| Correlation | The main app correlates by `sessionId` — the same id the mint response carried |

### `started` cadence — the rw hold (maker–checker)

An `access: "rw"` session under the checker hold (`rw_require_checker_watch: true`, the default)
produces this callback sequence — the **double `started` is the contract**:

| Session shape | Callbacks | Meaning |
|---|---|---|
| rw held → checker watches → admitted | `started` (hold-start) → `started` (backend live) → … → `ended` | First `started` = **joinable now** (push this to the checker UI); second = **backend live** |
| rw held → maker walks away | `started` (hold-start) → `ended` | Never admitted; the session existed only as pending in the directory |
| rw with `rw_require_checker_watch: false`, or any non-rw session | `started` (connect success) → `ended` | Unchanged single-`started` cadence |
| rw admitted → **last checker leaves** (Task 9 re-lock, `rw_relock_on_watch_loss: true` default) → checker watches again | `started` (hold-start) → `started` (backend live) → **`started` (re-lock)** → … → `ended` | With re-lock on, a session can emit `started` **MULTIPLE times** — once at hold-start and once per re-lock; **`ended` exactly once**. Each re-lock reuses the hold-start `started` (the "joinable now" signal — no new action value): the session is frozen with the gating error until a checker watches again |

Both `started` callbacks carry the same `sessionId`; the `timestamp` of each is the actual event
time (hold-start vs backend connect).

### Re-lock lifecycle (Task 9 — an admitted rw session re-freezes when the last checker leaves)

`rw_relock_on_watch_loss` (data.yaml, `ZT_RW_RELOCK_ON_WATCH_LOSS`, default `true`) reverses the
Task 6 ONE-WAY admission for hold-admitted rw sessions:

```
hold → started (hold-start) → started (admitted) → … → (last checker leaves)
     → relock → started (callback again) → re-admit → … → ended (exactly once)
```

- **Trigger** — the control plane's WS hub, in its disconnect defer, removes its own
  `watch:<sid>:<conn>` lease and counts the remaining leases (`WatchCount`). When the count is
  zero AND the `sess:live` record shows `status=active` (admitted — a pending record is still
  pre-hold and never re-locks), it publishes `{"action":"relock","session_id":<sid>}` on the
  `ctl:relock` channel (the same control→data pubsub coupling as `ctl:kill`).
- **Freeze** — the data plane's re-lock subscriber (a small `Relocker` next to the kill
  subscriber, no Oracle arm) sets a per-session frozen flag on the MySQL/PG/MSSQL plane that
  holds the session. While frozen, EVERY client→backend message is answered with the normal
  gating error (`maker gating: no checker connected to session <sid>` — MySQL `ERR 1045`,
  PG `FATAL 28000`, MSSQL `ERROR 18456`) and NOT forwarded; the backend→client direction keeps
  draining. In-flight transactions are left untouched (no ROLLBACK, no COMMIT — the freeze point
  is the detach).
- **Re-admission** — the frozen session polls `WatchActive` on the hold's 500 ms cadence; a
  checker re-attaching unfreezes it and the relay continues without a reconnect. An explicit kill
  works while frozen (kill tears down regardless).
- **Audit** — re-lock/free cycles do NOT change the sessions row status (it stays `active` from
  first admission; `ended` only at real close). No columns were added.
- **Scope** — hold-admitted rw sessions ONLY: legacy preset `write` sessions keep their
  per-command write gate; sessions admitted with `rw_require_checker_watch: false` never held and
  never relock; oracle NEVER relocks (no hold point). `rw_relock_on_watch_loss: false` (UAT)
  restores the one-way admission byte-identically. The env value uses the STRICT
  `true/1/false/0` parse — a typo is rejected at boot (re-lock stays ON, WARN names the value).

## 11.7 Full flow

```mermaid
sequenceDiagram
    autonumber
    participant App as Main App
    participant CP as Control Plane :8080
    participant V as Valkey
    participant DP as Data Plane :3306
    participant DB as Backend DB
    participant Cb as Main App (callback endpoint)

    App->>CP: POST /api/token (Bearer JWT) {db_type, db_subtype?, db_port?, end_time?, password?, ticket_id, ...}
    CP->>CP: validate; db_port explicit wins, else default-port map (422 if unknown type/subtype)
    CP->>CP: end_time → ttl = min(end_time - now, mode TTL rules); password shape-checked
    CP->>V: SET tok:<token> TTL=ttl (+ sess:live:<sid> status=pending, issued event)
    CP->>V: SET ztcred:<sid> {"password":...} TTL=ttl (only when password given)
    CP-->>App: 200 {token, session_id, host, port, expires_in, expires_at?}

    App->>DP: TCP connect — token as the DB username
    DP->>V: GETDEL tok:<token> (atomic; invalid/expired → clean auth failure)
    DP->>V: cred_override? GET ztcred:<sid> (hit = override) else fallback chain (config/credential API)
    DP->>DB: connect with resolved credentials (token never reaches the DB)
    DB-->>DP: login OK
    DP-->>App: session established (login response relayed byte-exact)

    DP-)Cb: POST /dbpxy/session/<sid>/status {"action":"started","timestamp":...} (+ X-Session-Callback-Key)
    Note over DP,Cb: fire-and-forget; ONE retry after 2 s; WARN-only on failure
    Note over DP,Cb: rw hold path: a FIRST started fires at hold-start (available to join), before any watcher
    App->>DP: queries (relay + audit feed unchanged)

    alt end_time reached (tok: TTL expiry) or kill/revoke (DEL tok:)
        V-)DP: keyspace event / revoke poll → close session
    else client/backend disconnect or idle timeout
        DP->>DP: teardown
    end
    DP-)Cb: POST /dbpxy/session/<sid>/status {"action":"ended","timestamp":...}
    Note over DP,V: kill/revoke deletes tok: only — ztcred:<sid> lingers ≤ TTL, unusable without the token
```

## 11.8 Error codes — `POST /api/token`

Node-integration messages are **verbatim** — match them exactly in the client.

| Status | Body | When |
|---|---|---|
| `400` | `{"error":"bad request: <first json decode error>"}` | Body not decodable JSON, an **unknown field**, or > 1 MB — the stdlib decode error is passed through and **names the offending field/type** (e.g. `bad request: json: unknown field "bogus_field"`). Replaces the old opaque `{"error":"bad request"}` |
| `400` | `{"error":"db_port must be an integer or numeric string"}` | **NEW** — `db_port` as a fractional number (`3306.5`) or a non-numeric value (`"db"`, `true`); `3306` / `"3306"` / `" 3306 "` all pass |
| `400` | `{"error":"end_time and endTime are both set with different values"}` | **NEW** — both the `end_time` key and its `endTime` alias set with non-null, textually different values; identical values (or `null` on one side) mint fine |
| `400` | `{"error":"missing required fields"}` | `username` / `db_user` / `db_ip` empty after binding |
| `400` | `{"error":"username does not match session"}` | Body `username` ≠ bearer subject |
| `400` | `{"error":"ticket_id required"}` | `ticket_id` absent/empty |
| `400` | `{"error":"invalid ticket_id"}` | > 128 chars, whitespace or control characters |
| `400` | `{"error":"invalid db_subtype"}` | **NEW** — > 64 chars or control characters (after trim) |
| `400` | `{"error":"invalid end_time"}` | **NEW** — a string matching no accepted shape (RFC3339 / naive datetime, ISO, date-only, minute-precision — naive = gateway-local), or a non-integer number (null/absent is fine) |
| `400` | `{"error":"mode must be single-use or session"}` | Unknown `mode` |
| `400` | `{"error":"idle_seconds must be >= 0"}` | Negative idle override |
| `422` | `{"error":"db_type must be mysql, mariadb, postgres, mssql or oracle"}` | Unknown `db_type` |
| `422` | `{"error":"no default port for db_type/db_subtype; pass db_port explicitly"}` | **NEW** — `db_port` omitted and the type+subtype pair has no map entry |
| `422` | `{"error":"end_time is in the past"}` | **NEW** — `end_time ≤ now` |
| `422` | `{"error":"end_time exceeds max session duration"}` | **NEW** — `end_time − now` > `api.max_session_seconds` (> 0 configured); exactly at the ceiling passes |
| `422` | `{"error":"password must not be empty"}` | **NEW** — explicit empty-string `password` |
| `422` | `{"error":"password exceeds 256 bytes"}` | **NEW** — > 256 bytes (256 accepted; never truncated) |
| `422` | `{"error":"password requires a finite token ttl — supply end_time or set api.session_token_ttl_seconds"}` | **NEW** — `password` on a mint that resolves an infinite TTL (session mode, `session_token_ttl_seconds: 0`, no `end_time`) |
| `422` | `{"error":"access must be read, ro, write or rw"}` | **NEW (Task 6)** — `access` outside the four accepted aliases (case-insensitive) |
| `422` | `{"error":"access ro is not supported for db_type oracle — the gateway cannot classify Oracle statements yet; use rw or a SELECT-only backend account"}` | **NEW (Task 6)** — a `ro` mint (explicit or migrated preset) for oracle: no statement classification exists, so the mint is refused rather than silently unprotected |
| `403` | `{"error":"checker role limited to read-only tokens"}` | Checker-role principal minting a write-access token — `access: "rw"` (or a legacy `write` preset); alias-normalized first, so `"rw"` is refused on the canonical value |
| `429` | `{"error":"token issuance rate limited"}` | Per-username issuance throttle |
| `500` | `{"error":"internal"}` | Store failure — including a failed `ztcred:` write (the mint is rolled back: `tok:` deleted) |

`401` (missing/invalid/expired/denylisted bearer JWT) answers the same opaque body on every
authenticated route — see RUN.md §2.1.4 for server-side diagnosis.

## 11.9 Config knobs

### Control Plane — `configs/control.yaml` mint knobs

| Key | Env | Default | Meaning |
|---|---|---|---|
| `api.max_session_seconds` | `ZT_API_MAX_SESSION_SECONDS` | `0` | Ceiling on a mint's `end_time` — `end_time − now` beyond it → `422`; **exactly at the ceiling is accepted**. `0` = uncapped. Negative = uncapped. Bounds **only** `end_time` mints — mints without `end_time` are unaffected |
| `api.data_plane_hosts` | `ZT_API_DATA_PLANE_HOSTS` | *(absent)* | Task 11 — the mint **fallback pool**: `"host:port"` entries (yaml list; the env var is one **comma-separated** string). When DB routing is disabled or fails, mints **round-robin** over the pool (per-process atomic counter, `pool[counter % len]`). Malformed entries (no host, no/bad port) are **dropped at load with a boot WARN** — never a boot failure. Absent/empty → the legacy `data_plane_host`+`data_plane_port` pair becomes a one-element pool; **both set → this key wins**; **neither** → no config fallback (enable routing, or every mint WARNs). One entry = the old single-host behavior exactly |
| `api.data_plane_host` / `api.data_plane_port` | — | `"127.0.0.1"` / `"3306"` | **LEGACY single-host fallback** (Task 11 back-compat, G3): still honored — promoted to a one-element pool when `data_plane_hosts` is absent/empty |

### Data Plane — `configs/data.yaml` `session_callback`

| Key | Env | Default | Meaning |
|---|---|---|---|
| `session_callback.url` | `ZT_SESSION_CALLBACK_URL` | `""` (empty = **DISABLED** — the committed default) | The main app's base URL; callbacks go to `{url}/dbpxy/session/{sessionId}/status`. Must be absolute (scheme + host) or the data plane refuses to boot |
| `session_callback.timeout_seconds` | `ZT_SESSION_CALLBACK_TIMEOUT_SECONDS` | `5` | Per-attempt HTTP timeout; ≤ 0 falls back to 5 |
| `session_callback.shared_secret` | `ZT_SESSION_CALLBACK_SHARED_SECRET` | `""` (no header) | Sent as `X-Session-Callback-Key` when set. **Deliberately no committed `${VAR}` placeholder** — an unset variable fails the boot, which would force every deployment to define the secret even with callbacks disabled; set it via env when enabling |
| `session_callback.control_plane_addr` | — | `127.0.0.1:8080` | The control plane's own address, seeded into the callback **loop-protection set** ([§11.10](#1110-operator-notes)) |

### Data Plane — `configs/data.yaml` `session.ip_lock`

| Key | Env | Default | Meaning |
|---|---|---|---|
| `session.ip_lock` | `ZT_SESSION_IP_LOCK` | `true` (the committed value) | Binds every session-mode token to the address it was minted for — a connection from any other address is rejected at login like an invalid token, on **all five planes** (mysql/mariadb/postgres/mssql/oracle). `false` **disables a security control**: session tokens open connections from ANY address, and the data plane boots a loud WARN. The env override is a **strict allowlist**: only `true`/`1`/`false`/`0` (case-insensitive); set-but-empty = the yaml decides; anything else (`yes`, `on`, `2`, a typo) is **ignored with a boot WARN** and the lock stays as the yaml/default — a typo'd env var can never disable the lock |

## 11.10 Operator notes


### Loop protection (`control_plane_addr`)

The data plane **never dials a callback target whose host:port equals `control_plane_addr`** — a
callback pointed back at the control plane would loop the planes into each other. Matching is
**exact host:port** (a bare host, or a URL without a port, protects the whole host). Note the
default `127.0.0.1:8080` protects the loopback endpoint while `control.yaml` `http.addr` is
`:8080` (all interfaces) — that is fine while the control plane is *reached* on loopback, but
**update `session_callback.control_plane_addr` whenever the control plane moves** or is reached on
a non-loopback address. A loop-protected target is **skipped with no attempt and no retry** (DEBUG
log only).

### IP-lock env spellings (`ZT_SESSION_IP_LOCK`)

The env override is parsed against a **strict allowlist** so a typo can never disable the lock
(fail-locked — only an accepted explicit `false`/`0` turns the control off):

| Value | Effect |
|---|---|
| `true` / `1` (case-insensitive) | Lock ON — re-arms over a yaml `ip_lock: false` |
| `false` / `0` (case-insensitive) | Lock OFF — disables a security control; boots a loud WARN |
| Set-but-empty (`ZT_SESSION_IP_LOCK=""`) | Not an override — `session.ip_lock` in `data.yaml` decides (default `true`) |
| Anything else (`yes`, `on`, `2`, typos) | **Ignored with a boot WARN naming the rejected value** — the yaml/default decides; the lock never silently opens |

`yes` and `on` are deliberately NOT accepted spellings.

### `ztcred:` key semantics

| Aspect | Behavior |
|---|---|
| Key space | `ztcred:<session_id>` — fully separate from `tok:<token>`; one token ↔ one `ztcred:` key |
| TTL | Identical to the token's resolved TTL. It may outlive `tok:` by **ms-scale write skew** (the token is stored first, the override second) — never the reverse |
| Kill / revoke | Deletes `tok:` **only** — `ztcred:` lingers until its own TTL expiry. It is **unusable** without the token: the override is read only during a connect that presented and validated the matching token. (Defense in depth, not a scrub mechanism.) |
| Manual scrub | `DEL ztcred:<sid>` (e.g. `valkey-cli`) — safe at any time; the data plane then falls back to the configured chain with a WARN |
| Fallback | Override-first with the normal chain on miss/error; the WARN carries the **reason only** (`cred override miss; falling back…` / `cred override read failed; falling back…`) — never a value |

## 11.11 MariaDB (`db_type: "mariadb"`)

MariaDB is a **first-class `db_type`** — accepted explicitly, never mapped to `mysql`.

- **Wire protocol:** MariaDB speaks the MySQL wire protocol, so a `mariadb` token is served by the
  **same data-plane listener as `mysql`** (the shared `:3306` plane; protocol detection is
  unchanged). The plane's type gate accepts both `mysql` and `mariadb` tokens; every other plane
  (postgres/mssql/oracle) still rejects a `mariadb` token.
- **Default port:** `6603` when `db_port` is omitted at mint (an explicit `db_port` always wins) —
  the MariaDB convention, deliberately distinct from MySQL's 3306.
- **Credential keys:** the backend credential key is **verbatim** `mariadb:<db_user>@<db_ip>:<db_port>`
  (e.g. `mariadb:ro_user@127.0.0.1:6603`). There is **no aliasing** to `mysql:` keys — a `mariadb`
  mint will not resolve a `mysql:` credentials entry, so every MariaDB backend needs its **own**
  `credentials:` entries (the payload's `db_type` and all audit/query events also carry the literal
  string `mariadb`).
- **Auth plugins:** the backend service accounts must use `mysql_native_password` or
  `caching_sha2_password` — **not `ed25519`** (MariaDB-specific; the proxy's MySQL client stack
  cannot perform its handshake). `caching_sha2_password` **full authentication** (first connect /
  after a server RSA-key rotation) requires a secure channel: connect over the **TLS plane**
  (`tls.enabled: true`); over plaintext the full-auth exchange cannot complete.
- **Live backend:** a dedicated MariaDB test container is an explicit follow-up — until it lands,
  MariaDB sessions are covered by the fake-backend acceptance tests.

## 11.12 WSS — native control-plane TLS (`http.tls`)

### When wss is required

Browsers **force `wss://` whenever the page itself is served over `https://`** — a mixed-content
`ws://` upgrade from an https origin is blocked outright. When the Angular SPA (or the main app's
UI) is served over https, the checker live-query socket can therefore only reach this control
plane as **wss**, which requires the control plane to speak TLS itself:

- **SPA served over http** (the dev default): `ws://` works — no TLS needed.
- **SPA served over https**: `wss://` is mandatory → enable `http.tls` below (or terminate TLS at
  a load balancer in front of the control plane — see "LB termination" at the end).

### Config — `http.tls` in `configs/control.yaml`

The **presence of the pair is the switch** — there is no `enabled` flag:

- BOTH `cert_file` and `key_file` set → the control plane serves **HTTPS/WSS via
  `ListenAndServeTLS` on the SAME `http.addr`** (health, SPA, REST, and the WS upgrade all move
  to TLS together; the port no longer answers plain HTTP).
- NEITHER set (or the whole block absent) → **plain HTTP**, byte-identical to the historical
  listener.
- EXACTLY ONE set → the plane **refuses to start** (load error naming the missing half).
- Files must be readable at boot — a broken pair is a load error (fail fast), and the TLS floor
  is **TLS 1.2** (hardcoded; no knob).
- **Migration guard:** a leftover legacy control `tls:` block (`tls.enabled` / `tls.cert_file` /
  `tls.key_file` — the shape this feature replaced) is a **load error naming the migration**,
  even when a valid `http.tls` pair is also present (no silent precedence). The guard inspects
  the config **FILE only**; environment variables like the data plane's `ZT_TLS_ENABLED` do not
  trip it. The DATA plane's own `tls:` block is unaffected — it still consumes its block for
  backend wire TLS.

```yaml
http:
  addr: ":8080"
  tls:
    cert_file: "scripts/dev-cert/localhost.crt"
    key_file:  "scripts/dev-cert/localhost.key"
```

The boot log states the mode: `control plane listening addr=:8080 tls=true|false`.

### Env overrides — `ZT_HTTP_TLS_CERT` / `ZT_HTTP_TLS_KEY`

These carry **paths, not secrets** (so unlike the `${VAR}` secret placeholders there is nothing
committed in `configs/` and no `.env` entry is required). They beat the yaml like every other
`ZT_` binding:

```bash
ZT_HTTP_TLS_CERT=scripts/dev-cert/localhost.crt
ZT_HTTP_TLS_KEY=scripts/dev-cert/localhost.key
```

### Development certificates

```bash
bash scripts/gen-dev-cert.sh     # idempotent; -f regenerates
```

Writes `scripts/dev-cert/localhost.crt` + `localhost.key` (**git-ignored**): self-signed
rsa:2048, **10-year** validity, SANs `DNS:localhost, IP:127.0.0.1, IP:::1`. The script prints the
post-generation steps itself; the short form:

1. Point `http.tls` (or the two env vars) at the pair.
2. **Browser trust** — visit `https://localhost:8080/` once and accept the warning (or import
   `localhost.crt` into your OS/browser trust store). After that the https-served SPA opens
   `wss://localhost:8080/ws/checker` directly against this process.
3. Smoke probe without the trust step: `curl -k https://localhost:8080/api/health`.

### LB termination — the 8-control production topology

In the production topology (eight control instances behind a load balancer) TLS **terminates at
the LB**: the LB owns the CA-signed certificate for the public hostname, speaks https/wss to
browsers, and forwards **plain HTTP to the controls** — the control plane keeps
`http.tls` unset (nil) and needs no certificates at all. Enable native `http.tls` only where the
browser reaches the Go process **directly** (single-node deployments, dev, or an LB pass-through
mode); between the LB and the controls, network-level isolation is the trust boundary, exactly
as for the existing plaintext data-plane hops.

## 11.13 DB-driven data-plane routing (blue/green at token mint)

By default every mint hands the client a plane from the **`api.data_plane_hosts` fallback
pool** (Task 11) — round-robin over the configured `host:port` entries; the legacy single
`api.data_plane_host` / `api.data_plane_port` pair still works as a one-element pool. With the
`routing` block **enabled**, each `POST /api/token`
instead asks a MySQL table **which data server to point at** and returns that plane in the mint
response (`host` / `port`) — selection by **deployment color + least-loaded**, evaluated at
mint time. Disabled (the default) the behavior is byte-identical to before.

### Selection semantics

- **Fallback pool (Task 11)**: when routing is disabled, the lookup DB fails, or zero eligible
  rows remain, the mint falls back to the `api.data_plane_hosts` pool — **round-robin**
  (per-process counter; no shared state, good enough for a fallback path). Selection order is
  unchanged: routing table → pool → empty-fallback WARN (`no data plane fallback configured`
  when neither the pool nor the legacy pair resolves).
- **One row wins**: the eligible row with the LOWEST `activesessions` (ties broken randomly)
  for the configured `routing.color`.
- **Eligibility guards**: `proxytype='DB'`, `environment='PROD'`, the row's
  `deploymentcolor` must equal the active color, `activesessions < maxsessions`
  (capacity), and `lastheartbeat` within the last 30 seconds (liveness).
- **URL normalization**: the row's `url` (`https://fqdn:port`) is parsed — scheme must be
  http/https and an explicit port 1–65535 must be present, or the row is **skipped**.
  Malformed `activesessions`/`maxsessions` (negative, zero cap, over capacity) also skip the
  row. A token is NEVER minted against an unvalidated host/port.
- **Failure isolation (load-bearing)**: lookup DB unreachable, zero eligible rows, or any
  error → the mint **still succeeds 200** with the configured `api.data_plane_host/port` and
  a WARN log naming the reason. The routing DB can never fail a mint.
- **Cache**: lookups are cached per color for 5 seconds (mints within the TTL share one
  SELECT; a color flip therefore takes effect within ~5s).
- **Audit trail**: the chosen plane is stamped into the stored token payload as
  `data_plane` ("host:port") and into the `token issued` log line — trace every mint to its
  plane with `grep '"data_plane"'` on the control log. (When routing falls back, the payload
  carries no `data_plane` — the configured plane is implicit.)

### Lookup database

The lookup runs on the **same MySQL server as session audit** when `audit.mysql.enabled: true`
(no second connection); otherwise give `routing.mysql` the same five fields. The
`data_plane_routes` table is auto-created at boot (idempotent) with the owner's schema:

```sql
CREATE TABLE IF NOT EXISTS data_plane_routes (
  hostname        VARCHAR(255) NOT NULL,
  proxytype       VARCHAR(16)  NOT NULL,
  url             VARCHAR(512) NOT NULL,
  ipaddress       VARCHAR(64),
  environment     VARCHAR(32),
  country         VARCHAR(32),
  lastheartbeat   DATETIME,
  deploymentcolor VARCHAR(16),
  maxsessions     INT,
  activesessions  INT,
  PRIMARY KEY (hostname)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

> **Pre-existing tables are left untouched** by the idempotent `CREATE TABLE IF NOT EXISTS` —
> e.g. a dev table extended with `port VARCHAR(8)` + `enabled TINYINT DEFAULT 1` and
> `PRIMARY KEY (hostname, port)` keeps those columns (the gateway reads only `hostname` and
> `url` via the selection query, so both variants work).

Boot log on success: `routing table ready rows=N color=blue tune=internal/api/dataplane_routing.go routeSelectQuery ...`

### Tuning the selection query

The selection is **one query string constant** — deliberately NOT a config key. Open
`internal/api/dataplane_routing.go` and edit `routeSelectQuery` at the top ("TUNE THIS QUERY
to change data-server selection"). The contract: exactly one `?` parameter (the active
color), returning exactly two columns — `hostname, url`. Everything else (extra WHERE
guards, different ORDER BY, maintenance windows, regional preferences) is fair game; the
Go-side URL/number validation and the fallback continue to apply whatever the query returns.

### Config

```yaml
routing:
  enabled: true        # ZT_ROUTING_ENABLED (default false)
  color: "blue"        # ZT_ROUTING_COLOR (default "blue")
  # mysql:             # optional dedicated lookup DB — omit to reuse audit.mysql
  #   host/port/user/password/database
```

`routing.enabled: true` with neither `audit.mysql.enabled` nor a `routing.mysql` block is a
**load error** — the plane refuses to start rather than silently routing everything to the
fallback forever.

### Ops: color flip / drain a plane

1. **Flip blue → green**: `UPDATE data_plane_routes SET deploymentcolor='green' WHERE hostname IN (...)`
   (or flip `ZT_ROUTING_COLOR=green` and restart, to move the whole plane). New mints pick the
   green rows within the 5s cache TTL; existing tokens keep the plane minted into their payload.
2. **Drain a plane (zero-downtime)**: set its rows' `activesessions = maxsessions` (capacity
   guard excludes them from selection) or stop the heartbeat (`lastheartbeat` ages past 30s).
   Restore by refreshing the heartbeat and resetting the counters.
3. **Verify**: watch the mint log — `data_plane` in every `token issued` line — or
   `SELECT hostname, activesessions, lastheartbeat FROM data_plane_routes WHERE deploymentcolor='green'`.
