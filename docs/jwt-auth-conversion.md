# Page 9 — JWT & Roles Auth Conversion (Control-Plane Authentication)

> **What this page covers.** The Control Plane's authentication model changed on
> 2026-09-05 from **cookie sessions + a control-plane API key** to **self-issued
> HS256 bearer JWTs with maker/checker roles**. This page is the operator-facing
> summary: the flows before/after, the role × capability matrix, the config keys,
> and the end-to-end sequence (login → JWT → mint with role gate → checker WS
> watch). It supersedes the auth statements in [Page 1](01-architecture-overview.md),
> [Page 2](02-creating-db-connections.md) and the spec's R6 / §9-3 / §9-7 rows.

## Why it changed

The old model authenticated the UI with an HttpOnly `zt_session` cookie backed by
Valkey sessions (`sess:ui:<id>`, 8 h TTL) and authenticated `POST /api/token`
with either that cookie or a control-plane API key (`X-Api-Key` /
`ZT_API_API_KEY`). The conversion replaced both with one stateless credential —
a **bearer JWT** — so the Control Plane holds no server-side UI session state,
logout is an explicit per-token revocation, and every request carries the
caller's **role** (maker | checker) that authorization gates are built on.

**What was removed (code + config):** `zt_session` cookie, `sess:ui:*` Valkey
sessions, `CreateSession/GetSession/DeleteSession`, `sessionFromRequest`,
`requireSession`, `sessionCookie`, `auth.session_ttl_hours` (now inert), and the
control-plane API key (`api.api_key` / `ZT_API_API_KEY` / `X-Api-Key` on
`/api/*`). **What is NOT affected:** the Data Plane's own credential-retrieval
API key (`credentials_api.api_key` → `X-Api-Key` from the data plane to its
vault, [Page 5](05-credential-retrieval-api.md)) — that is a separate, still-live
credential.

## Auth flows — before vs after

| Aspect | Before (cookie era) | After (JWT conversion) |
|---|---|---|
| UI login | `POST /api/login` → `Set-Cookie: zt_session` (HttpOnly, SameSite=Lax) | `POST /api/login` → `200 {token, username, role, expires_in}` — the JWT, no cookie, no Valkey session |
| Authenticated REST calls | browser cookie on `/api/me`, `/api/db-presets`, `/api/kill`, `/api/sessions` | `Authorization: Bearer <jwt>` on every guarded route (header-only by design — tokens never ride URLs on REST) |
| Mint auth (`POST /api/token`) | `X-Api-Key` header **or** UI session cookie | bearer JWT only; body `username` (optional) must match the JWT's subject — the token is always issued for the authenticated principal (mint-for-others rejected) |
| Server-side session state | Valkey `sess:ui:<id>` TTL 8 h | none — stateless JWT (HS256, `sub`/`iss`/`aud`/`exp`/`iat`/`jti` + `role` claim); revocation is the Valkey **jti denylist** only |
| Logout | cookie cleared + Valkey session deleted | `POST /api/logout` denylists the presented token's `jti` (`jwt:deny:<jti>`) for its remaining life — replay of the same token → 401 |
| WS auth (`/ws/checker`) | same-origin cookie | bearer JWT via `Authorization` header **or** `?access_token=<jwt>` query param (browsers cannot set WS headers) |
| Authorization | any logged-in user could watch/kill/list | role gates (below): checker surface is checker-role-only unless `auth.allow_maker_watch: true`; checker-role minters are read-only |
| Control-plane API key | `ZT_API_API_KEY` / `configs/control.yaml` `api.api_key` | **removed** — setting it has no effect; do not re-add |
| Auth expiry config | `auth.session_ttl_hours: 8` (cookie TTL) | `auth.jwt.ttl_seconds: 28800` (JWT life; `session_ttl_hours` remains parsed but inert) |

## Role × capability matrix

Every account (the primary `auth.username/password` pair and each optional
`auth.users[]` entry) declares a role. Roles are **required** when
`auth.jwt.login_enabled: true` — never silently defaulted (an un-role'd account
would be an accidental superuser). A token without a `role` claim — or with a
role other than `maker`/`checker` — is rejected 401 at verification.

| Capability | `maker` | `checker` | Config |
|---|---|---|---|
| Login (`/api/login`), `/api/me`, `/api/db-presets` | ✅ | ✅ | — |
| Mint read-access tokens (`POST /api/token`) | ✅ | ✅ | — |
| Mint **write**-access tokens | ✅ | **403** (`checker role limited to read-only tokens`) — a checker must never be able to open a write session it could then watch itself | enforced in `handleToken` |
| Watch sessions / live feed (`/ws/checker`) | ❌ 403 | ✅ | `auth.allow_maker_watch: true` lets makers watch too |
| Kill (`POST /api/kill`) + session directory (`GET /api/sessions`) | ❌ 403 | ✅ | `auth.allow_maker_watch: true` lets makers kill too |
| Watch **own** session (`channel=sess:<sid>` where maker == watcher) | ❌ (1008 policy-violation close, regardless of role/flag) | ❌ | SoD username check in the WS hub — independent of the role gate |
| Default account | `admin` (`auth.role: maker`) | `checker` (`auth.users[]`, `role: checker`) | `configs/control.yaml` |

`allow_maker_watch` is the operator's single-account escape hatch, set in config
— it is never a grant a token can claim for itself.

## Config keys

| Key (`configs/control.yaml`) | Env | Meaning / defaults |
|---|---|---|
| `auth.jwt.enabled` | — (`true` default; `false` disables verification) | ABSENT = true (JWT is the mode; an unmigrated config fails fast). **Explicit `false` disables JWT verification entirely — guarded routes answer 401 (fail closed). There is no legacy cookie fallback.** Keep `true`. |
| `auth.jwt.login_enabled` | — (`true` default) | Registers `/api/login` + `/api/logout`. `false` = external-JWT-only: username/password and secret NOT required — mint JWTs yourself signed with the same `secret`. |
| `auth.jwt.issuer` / `auth.jwt.audience` | `ZT_AUTH_JWT_ISSUER` / `ZT_AUTH_JWT_AUDIENCE` | `zerotrust-proxy` / `zt-api` — enforced on every token (wrong iss/aud → 401). |
| `auth.jwt.ttl_seconds` | `ZT_AUTH_JWT_TTL_SECONDS` | `28800` (8 h) — the JWT life returned as `expires_in`; replaces `auth.session_ttl_hours` (now inert). |
| `auth.jwt.secret` | `ZT_JWT_SECRET` (also `ZT_AUTH_JWT_SECRET`) | HS256 signing secret. REQUIRED when `login_enabled` — empty = the control plane refuses to start. Use a long random value (32+ bytes). |
| `auth.jwt.allowed_origins` | **no env override** (set in yaml) | Cross-origin host allowlist for the checker WebSocket upgrade ONLY (`/ws/checker`). Empty = same-origin only (upgrade 403 before handshake). Patterns: `checker.example.com`, `*.example.com`; prefix the scheme to pin it. REST ignores the list (headers only). |
| `auth.username` / `auth.password` | `ZT_AUTH_USERNAME` / `ZT_AUTH_PASSWORD` | Primary account (maker in the committed config). Password REQUIRED when `login_enabled`; empty = refuses to start. |
| `auth.role` | `ZT_AUTH_ROLE` | Primary account's role: `maker` \| `checker` — REQUIRED when `login_enabled`. |
| `auth.allow_maker_watch` | `ZT_AUTH_ALLOW_MAKER_WATCH` | `false` (default, strict SoD) — maker-role principals may watch/kill only when `true`. |
| `auth.users[]` | passwords via `${VAR}` (e.g. `ZT_AUTH_CHECKER_PASSWORD`) | Optional extra accounts, each with its own `role` — the committed config ships `checker` (role `checker`). |
| *(removed)* `api.api_key` | *(removed)* `ZT_API_API_KEY` | Control-plane mint API key — retired. The data plane's `credentials_api.api_key` (`ZT_CREDENTIALS_API_API_KEY`) is unrelated and still live. |

## How a request is authenticated

1. **Guard** — `requireJWT` (REST) or `requireJWTWS` (`/ws/checker`) extracts
   `Authorization: Bearer <jwt>` (header) — or, on the WS route only,
   `?access_token=` when the header is absent.
2. **Verify** — signature (HS256, `auth.jwt.secret`), `exp`, `iss`, `aud`, then
   `sub` non-empty and `role` ∈ {maker, checker}. Any failure → the same bare
   401 (nothing leaks *why*). JWT disabled (`enabled: false`) or empty
   secret/issuer/audience → fail closed, every request 401.
3. **Denylist** — the token's `jti` is checked against `jwt:deny:<jti>`
   (logout revocation). A denylist consult error fails closed (401).
4. **Principal** — the verified `{username, role}` rides the request context;
   handlers see it via `sessionFrom(r)` (the same context contract as the old
   session middleware, so mint-binding, SoD, audit and kill consumers were
   unchanged).
5. **Role gate** — where the route needs it, `requireChecker` runs after
   authentication: `checker` always allowed; `maker` only when
   `auth.allow_maker_watch: true`; else 403. The SoD username check
   (watcher ≠ session maker) lives in the WS handler, independent of roles.

## End-to-end sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant S as Angular SPA
    participant C as Control Plane :8080
    participant V as Valkey
    participant D as Data Plane :3306

    U->>S: login as admin (maker) / checker
    S->>C: POST /api/login {username, password}
    C->>C: constant-time credential check + role lookup (auth.role / auth.users[].role)
    C-->>S: 200 {token: JWT(HS256, sub, role, iss, aud, exp, jti), username, role, expires_in: 28800}
    S->>S: JWT -> TokenStore (memory + sessionStorage)

    Note over S,C: Maker mints a WRITE token
    S->>C: POST /api/token with Authorization: Bearer <jwt>
    C->>C: requireJWT: signature + exp + iss + aud + role + jti denylist
    C->>C: bind mint to principal (body username must match or be absent)
    C->>C: resolve preset access=write; role gate: maker -> allowed (checker would get 403 here)
    C->>V: SET tok:<id> (TTL/max-uses) + sess:live:<sid> (status=pending)
    C-->>S: 200 {token: sess_…, host, port, expires_in}

    Note over D: DB client connects later with the sess_… token as username;<br/>write session queries are gated until a checker watches it

    U->>S: checker opens the session (different identity)
    S->>S: build WS URL: ?access_token=<jwt> (browser WS cannot set headers)
    S->>C: GET /ws/checker?access_token=<jwt>&channel=sess:<sid>
    C->>C: requireJWTWS: header absent -> access_token param, same verification
    C->>C: requireChecker: role=checker -> allowed; SoD: checker ≠ session maker
    C->>V: watch:<sid> lease (heartbeat-refreshed while connected)
    C-->>S: live QueryEvents for sess:<sid> (writer unblocked)

    Note over U,S: Logout
    S->>C: POST /api/logout with Authorization: Bearer <jwt>
    C->>V: SET jwt:deny:<jti> (TTL = remaining token life)
    C-->>S: 200 {"ok": true} — the same JWT now answers 401 everywhere
```

## Operator migration checklist

- **`.env`** — add `ZT_JWT_SECRET` (long random, 32+ bytes). **Delete
  `ZT_API_API_KEY`** if an old `.env` still has it (inert, but confusing).
  Keep `ZT_AUTH_PASSWORD` (and `ZT_AUTH_CHECKER_PASSWORD` for the checker
  account).
- **`configs/control.yaml`** — confirm `auth.role` on the primary account,
  `auth.users[].role` on every extra entry, and (if desired) flip
  `auth.jwt.login_enabled` to `false` for external-JWT-only, or set
  `auth.jwt.allowed_origins` for cross-origin checker dashboards.
- **Scripts / integrations** — replace `-H "X-Api-Key: …"` with a login
  (`POST /api/login`) then `-H "Authorization: Bearer $JWT"`; replace cookie
  jars (`curl -b/-c`, `Cookie: zt_session=…`) with the bearer header; for WS
  clients put the JWT in `?access_token=`.
- **Auth expiry** — the old `auth.session_ttl_hours` key can be deleted;
  `auth.jwt.ttl_seconds` is authoritative.
- Full run recipes: **RUN.md §2–§5**.

---

*Confluence page 9 of the Project-D set — see [docs/README.md](README.md) for the
full page list. Mermaid fences map 1:1 to the Confluence Mermaid macro.*
