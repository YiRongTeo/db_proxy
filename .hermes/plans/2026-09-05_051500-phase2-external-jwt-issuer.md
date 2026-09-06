# Phase 2 — External JWT Issuer Integration (Other App as IdP) Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make the control plane consume JWTs issued by the other Go app (external issuer, HS256 shared secret) as first-class principals — maker/checker roles, mint bound to `sub`, checker-WS over the browser with CORS — while keeping the local `login_enabled` self-issuer for standalone/dev, and make the claim mapping fully config-driven so it can be adapted to the other app's exact JWT shape without code changes.

**Architecture:** Extend the single-issuer `parseJWT` (internal/api/jwt.go:104-134) into an issuer-aware validator driven by a new `auth.jwt.external_issuers` config list. Each issuer entry declares its HS256 shared secret and an optional claim-mapping block (subject/role claim names + role-value aliases). The JWT principal injected under `sessionKey{}` stays `*models.Session{Username, Role}`, so every downstream consumer (SoD, mint binding, role gates, denylist) is untouched. Add a CORS middleware for browser-direct REST from the other app's origin (WS origin control already exists via `allowed_origins`, Task 9). `login_enabled` stays the master switch for the local login/logout endpoints.

**Tech Stack:** Go (existing), golang-jwt/jwt/v5 (already vendored), no new dependencies expected (CORS implemented by hand — small middleware, no framework).

---

## Decisions locked (2026-09-05, user-confirmed)

1. **Roles**: the other app's users are `maker` or `checker` — same vocabulary, no role-value translation needed for the primary path (but the mapping layer still supports value aliases defensively).
2. **Transport**: the other app's browser UI calls the control plane **directly** → CORS middleware for REST; the checker WS already accepts `?access_token=` + `auth.jwt.allowed_origins` (Task 9) — just configure the origin.
3. **Key type**: HS256 **shared secret** per external issuer (not JWKS). One secret for the integration; rotation = config change + coordinated secret swap.
4. **`jti`**: external tokens MUST carry `jti` — the denylist (Task 6) then works for external principals too (logout → server-side kill). External tokens without `jti` are REJECTED (this closes the ledger's parked finding #1 for the external path).
5. **Mint-for-self only**: the other app mints only for the authenticated user — body `username == sub` binding (Task 7, handlers.go:91-97) already enforces this. NO delegation rule, NO `requested_by` audit column. This is the strongest posture: no principal can mint for anyone but themselves.
6. **Claim mapping must be config-driven**: when the other app's JWT shape differs (claim names, extra claims), adapting = config edit, never code.

---

## Current state (verified at HEAD b4281de)

- `JWTConfig` (internal/config/config.go:165-190): `Enabled, LoginEnabled, Issuer, Audience, TTLSeconds, Secret, AllowedOrigins` — **no external_issuers**.
- `parseJWT` (internal/api/jwt.go:104-134): hardwired to one HS256 secret (`j.Secret`), one issuer, one audience; enforces exp/iss/aud, sub non-empty, role ∈ {maker,checker}; fail-closed when unconfigured.
- `authorizeJWT` (jwt.go:145-167): shared core of requireJWT/requireJWTWS; denylist consult skipped when `claims.ID == ""` (jwt.go:156) — the parked-finding gap this plan closes for external tokens.
- `jwtClaims` struct (jwt.go:~40): sub/role/iss/aud/exp/iat/jti — verify exact field set when implementing (mapstructure/json tags).
- `signJWT` (jwt.go:64-): mints self-issued tokens; used by handleLogin (auth.go:200) and the test helper.
- Routes (internal/api/api.go:62-82): mux built in `Routes()`; `cmd/control/main.go:110-112` wraps it in `http.Server{Handler: apiSrv.Routes()}` — CORS wraps here or in Routes().
- Role gates: requireChecker (jwt.go:232-255), mint role gate (handlers.go:171-174), SoD (websocket.go:265-285) — all consume the principal only; untouched by this plan.

---

## Task list

### Task 1: Config — external issuers + claim-mapping schema

**Objective:** `JWTConfig` gains `ExternalIssuers []ExternalIssuerConfig`; validation fail-fast.

**Files:** Modify `internal/config/config.go`; Test `internal/config/config_test.go`; doc `configs/control.yaml` + `.env.example`.

**Design** (yaml shape):
```yaml
auth:
  jwt:
    enabled: true
    login_enabled: true        # standalone/dev; false = external-only later
    issuer: zerotrust-proxy    # LOCAL issuer (self-issued login JWTs)
    audience: zt-api
    secret: ${ZT_JWT_SECRET}   # local signing secret (login_enabled only)
    external_issuers:
      - name: other-app
        iss: https://other-app.example    # MUST match the JWT iss claim
        audience: zt-api                  # optional; default = top-level audience
        secret: ${ZT_OTHERAPP_JWT_SECRET} # HS256 shared secret
        require_jti: true                 # external tokens without jti → 401
        claims:                           # OPTIONAL mapping — adapts to their JWT shape
          subject: sub                    # claim carrying the username (default "sub")
          role: role                      # claim carrying the role (default "role")
          role_aliases:                   # value translation, defensive (default: identity)
            maker: maker
            checker: checker
```

- `ExternalIssuerConfig{Name, Iss, Audience, Secret string, RequireJTI bool, Claims ClaimMappingConfig}`.
- `ClaimMappingConfig{Subject, Role string, RoleAliases map[string]string}` — zero values mean defaults (`sub`/`role`/identity).
- **Validation (fail-fast, naming the entry):**
  - Every issuer: `name` non-empty + unique; `iss` non-empty; `secret` non-empty (${VAR}-expandable, same pattern as `ZT_JWT_SECRET` — config.go:395-402 area); `audience` optional (defaults to top-level `auth.jwt.audience`).
  - `iss` must not collide with the LOCAL `auth.jwt.issuer` (an external issuer claiming the local iss would shadow it).
  - `role_aliases` values must be `maker|checker` only.
  - When `login_enabled: false`: local secret NOT required (external-only mode) — existing rule (config.go:417-424) — but then ≥1 external issuer IS required (else nothing can authenticate; fail-fast with a clear message).
  - `require_jti` default: true (external tokens must be deniable). Allow explicit false only with a warning-level doc note.

**TDD:** table tests — valid multi-issuer config; duplicate names; empty iss; missing secret; iss collision with local; alias to invalid role; login_enabled=false with zero external issuers → error; login_enabled=false with one external issuer → ok; audience defaulting.

**Verify:** `go build ./...`, `go test -count=1 ./internal/config/`.

**Commit:** `feat(config): external jwt issuers + configurable claim mapping`

### Task 2: Issuer-aware JWT validation

**Objective:** `parseJWT` resolves the token's `iss` claim to a trusted issuer (local or external) and validates with that issuer's secret/audience/claims mapping; external tokens without `jti` are rejected when `require_jti`.

**Files:** Modify `internal/api/jwt.go`; Test `internal/api/jwt_test.go` (+ new `external_issuer_test.go`).

**Step 1 — failing tests first** (use `mintJWT`-style helper extended to sign with an arbitrary secret/iss/aud — add `mintExternalJWT(t, secret, iss, aud, username, role string, jti string) string` to testhelpers_test.go):
- external issuer token (valid HS256, matching iss/aud/secret, role maker, jti present) → accepted; principal Username/Role correct.
- token from an UNKNOWN iss → 401.
- external token with a WRONG secret (signed by someone else) → 401.
- external token with jti MISSING + `require_jti: true` → 401.
- external token with jti present → denylist consult works (deny the jti → 401).
- local self-issued token still accepted when login_enabled (regression).
- claim-mapping: external issuer configured with `claims.subject: user_name` + `claims.role: user_role` + `claims.role_aliases: {approver: checker}` → token with those claim names/values → accepted with Role=checker.
- audience override: issuer-level audience differs from top-level → token with the issuer audience accepted, top-level audience token 401.

**Step 2 — implementation:**
- Refactor: keep `parseJWT(raw)` as the LOCAL-issuer path; add `parseExternalJWT(raw, iss)` OR restructure into one `parseToken(raw) (sess, claims, err)` that:
  1. parses header + claims unverified first (jwt.ParseUnverified or a two-phase parse) to read `iss`;
  2. looks up the issuer (local vs external list) — unknown → 401;
  3. verifies with the issuer's key material + options (iss/aud/exp/methods HS256);
  4. applies the issuer's claim mapping (subject/role claim names + aliases) → `*models.Session{Username, Role}`;
  5. enforces role ∈ {maker,checker} post-mapping;
  6. `require_jti` (external) → missing jti = 401.
- `authorizeJWT` (jwt.go:145-167): replace the `parseJWT` call with the issuer-aware path. Denylist consult now applies to every token WITH a jti (external tokens carry one by requirement; local always does). No other caller changes (`requireJWT`, `requireJWTWS`, `handleLogout` all go through authorizeJWT / parse paths — verify handleLogout's parse also uses the issuer-aware path so an external token can be logged out).
- Keep fail-closed semantics: any resolution/verify error → `errUnauthorizedJWT` → 401.

**Verify:** `go build ./...`, `go vet ./internal/api/`, `go test -count=1 ./internal/api/` (full api package — the local-path regression tests must stay green).

**Commit:** `feat(api): issuer-aware JWT validation with configurable claim mapping`

### Task 3: CORS for browser-direct REST

**Objective:** the other app's browser UI can call the control plane's REST APIs cross-origin with `Authorization: Bearer` (preflight + actual).

**Files:** Modify `internal/api/api.go` (Routes) or new `internal/api/cors.go`; config addition; Test new `internal/api/cors_test.go`.

**Design:**
- Config: reuse `auth.jwt.allowed_origins` as the CORS origin allowlist (it already exists for the WS; one list = one mental model) — confirm naming works for both (it does: "origins allowed to talk to this plane"). Add a note in the struct comment that it now covers REST CORS + WS origins.
- Middleware: hand-rolled, wraps the mux in `Routes()`:
  - Preflight OPTIONS: if `Origin` is allowed → 204 with `Access-Control-Allow-Origin: <origin>`, `Access-Control-Allow-Methods: GET, POST, OPTIONS`, `Access-Control-Allow-Headers: Authorization, Content-Type`, `Access-Control-Max-Age`. Disallowed → 403.
  - Actual requests: allowed origin → echo `Access-Control-Allow-Origin` + `Vary: Origin`. Never `*` (credentials/bearer must be origin-pinned).
  - Credentials mode: we do NOT use cookies anymore (Bearer header), so `Access-Control-Allow-Credentials` is NOT needed — do not set it.
- Same-origin requests (no Origin or matching host) pass through untouched.

**TDD:** preflight from allowed origin → 204 + correct headers; preflight from disallowed origin → 403; GET /api/me with Bearer from allowed origin → 200 + ACAO header; from disallowed → 403; same-origin (no Origin header) → 200 no ACAO; OPTIONS unknown path → handled by CORS (204) not spaHandler 404.

**Verify:** `go build ./...`, `go test -count=1 ./internal/api/`.

**Commit:** `feat(api): CORS allowlist for browser-direct REST (reuses auth.jwt.allowed_origins)`

### Task 4: Live E2E — external issuer end-to-end

**Objective:** prove a real external-issuer JWT (signed with the configured shared secret) drives the full flow: mint-for-self, checker 403 on write, checker WS watch, logout denylist. Plus the `login_enabled: false` external-only mode boots and rejects self-issued tokens.

**Files:** no prod code expected; scratch configs + a small Go signer helper (temp, not committed — or a committed `cmd/jwtsigner` if useful for ops; controller ruling: prefer a committed test-only helper under internal/api testhelpers + scratch configs under `$LOCALAPPDATA/Temp`).

**Steps:**
1. Add a scratch `external_issuers` entry to a copy of configs/control.yaml (secret = a test value) OR use test-fixture config — build the control plane with it.
2. Mint an external JWT with a scratch Go program (HS256, iss = external iss, aud = zt-api, sub = alice, role = maker, jti = uuid) — verify:
   - GET /api/me with it → `{username: alice, role: maker}`.
   - POST /api/token (username alice, write preset) → 200 token.
   - A checker-role external JWT (sub = bob, role = checker): same write-preset mint → 403; read preset → 200.
   - Body username ≠ sub → 400.
   - No jti → 401 (require_jti).
3. Checker WS: external checker JWT over `ws://127.0.0.1:8080/ws/checker?channel=*&access_token=<jwt>` → connects; watch a sess channel → watch lease appears; logout via `/api/logout` with the external JWT → 200, replay → 401 (denylist works on external tokens).
4. Browser-direct CORS: curl with `Origin: http://other-app.example` → ACAO header echoed; disallowed origin → 403.
5. `login_enabled: false` + one external issuer: plane boots; POST /api/login → 404; external JWT works; a LOCAL self-issued token (signed with the local secret — which is not configured) → 401.
6. Kill all background processes; report live curl outputs as evidence.

**Verify:** full accumulated suite `go test -count=1 -timeout 30m ./...` green (data plane stopped during the gate — the :1522 live-metrics test needs the port); SPA suite untouched but re-run once if any web/ file changed (not expected).

**Commit:** only if a real bug surfaced (then a clear fix commit); otherwise no commit — evidence goes in the report.

### Task 5: Docs — external issuer + claim mapping

**Objective:** RUN.md, docs/jwt-auth-conversion.md (or a new docs/external-issuer.md), control.yaml comments, .env.example document the external-issuer config, the claim-mapping adaptation path ("their JWT differs → edit claims map, not code"), the CORS allowlist, and the mint-for-self security posture.

**Files:** RUN.md, docs/*, configs/control.yaml (comments), .env.example (ZT_OTHERAPP_JWT_SECRET example line).

**Verify:** no suite needed; `go build ./...` once.

**Commit:** `docs: external jwt issuer integration (config, claim mapping, CORS)`

---

## Out of scope (explicitly NOT in Phase 2)

- **Delegation / mint-for-others** — the other app mints only for the authed user; body username MUST equal `sub`. No scope claims, no service-account minting.
- **`requested_by` audit column** — caller == maker, existing audit rows suffice.
- **JWKS/RS256** — HS256 shared secret per the locked decision; the `external_issuers` schema has no jwks_url field (keep it that way — YAGNI; adding RS256 later is a new field + verify path, isolated).
- **Re-implementing the checker hub/SoD/watch leases** in the other app — it calls `/ws/checker` and the REST APIs.
- **Retiring the Angular SPA / deleting web/** — that is the cutover step AFTER the other app is proven live; this phase only adds the external path alongside `login_enabled: true`.
- **JWT in DB wire usernames** — still no; the single-use `sess_` GETDEL token remains the only DB credential.

## Risks & notes

- **Shared-secret trust**: the external secret IS the trust root — a leak lets an attacker mint any `sub`/role. Mitigations: ${VAR} from env (never in control.yaml), short exp on their tokens, rotation = coordinated secret swap (config reload or restart).
- **iss collisions**: an external issuer configured with the local `iss` would let its secret sign "local" tokens — validation forbids it (Task 1).
- **CORS is not auth**: the allowlist only controls browser read/write of responses; the Bearer JWT is the actual gate. Keep `allowed_origins` restrictive.
- **Vendor discipline**: `go mod vendor` wipes the go-ora patches (RawConn ×2, connect_packet 230→4096 ×2) — re-apply after any vendor regen; vendor stays untracked.
- **Full-suite ritual**: stop the :1522 data plane before `go test ./...` (live-metrics test binds it); restart after.
- **Phase-1 ledger carry-forward**: parked finding #1 (jti-less tokens bypass denylist) is closed FOR EXTERNAL TOKENS by `require_jti: true` in this plan; the local self-issuer always mints jti (signJWT/newJTI) so the gap is fully closed.

## Execution handoff

Ready to execute via subagent-driven-development (fresh subagent per task, spec+quality review, full-suite gate at each review) — or wait until the other app's JWT shape is confirmed and only then adjust the claims-mapping fixtures in Task 2's tests.
