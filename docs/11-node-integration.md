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

On Maker session **start** (backend connect success) and **end** (every close path: client close,
backend close, idle timeout, kill, token expiry/`end_time`), the data plane POSTs a status callback
to the main app. **Disabled by default** — zero HTTP traffic until a callback URL is configured
([§11.9](#119-config-knobs)).

| Aspect | Value |
|---|---|
| Method + path | `POST {url}/dbpxy/session/{sessionId}/status` (`sessionId` = the mint response's `session_id`, URL-path-escaped) |
| Body | `{"action":"started"\|"ended","timestamp":"<RFC3339 UTC>"}` |
| Header | `Content-Type: application/json`; plus **`X-Session-Callback-Key: <secret>`** on every request when a shared secret is configured (no header when empty) |
| `started` | Sent exactly once, when the backend connect succeeds |
| `ended` | Sent on **every** close path — client/backend disconnect, idle timeout, kill, token expiry (`end_time` or TTL), revoke |
| Delivery | **Fire-and-forget** on its own goroutine — the relay path never waits on the main app |
| Retries | **Exactly ONE** retry after **2 s** on failure — no backoff schedule, no buffering |
| Failure handling | Non-2xx and transport errors are **WARN-logged only** — they never affect the relay or the session |
| Response body | Read (bounded) and **discarded** — the data plane ignores any `session_id`/`action`/`rows_updated` the main app returns |
| Correlation | The main app correlates by `sessionId` — the same id the mint response carried |

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
| `403` | `{"error":"checker role limited to read-only tokens"}` | Checker-role principal minting a write-access token |
| `429` | `{"error":"token issuance rate limited"}` | Per-username issuance throttle |
| `500` | `{"error":"internal"}` | Store failure — including a failed `ztcred:` write (the mint is rolled back: `tok:` deleted) |

`401` (missing/invalid/expired/denylisted bearer JWT) answers the same opaque body on every
authenticated route — see RUN.md §2.1.4 for server-side diagnosis.

## 11.9 Config knobs

### Control Plane — `configs/control.yaml` `api.max_session_seconds`

| Key | Env | Default | Meaning |
|---|---|---|---|
| `api.max_session_seconds` | `ZT_API_MAX_SESSION_SECONDS` | `0` | Ceiling on a mint's `end_time` — `end_time − now` beyond it → `422`; **exactly at the ceiling is accepted**. `0` = uncapped. Negative = uncapped. Bounds **only** `end_time` mints — mints without `end_time` are unaffected |

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
