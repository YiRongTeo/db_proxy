# Project-D — Archify diagram set

Explorable, self-contained HTML diagrams generated with **Archify** (validated at the
`showcase` quality profile: 9/9 artifact checks, 0 composition errors, 0 warnings).
Each file opens standalone in any browser — no build step, no server. Features:
light/dark theme toggle, pan/zoom, search, focus views, relationship tracing, and
PNG/SVG/WebM export.

These complement the Confluence page set in `../` (which uses Mermaid). Use whichever
renders better in your target tool; the source facts are identical.

| # | File | Type | Covers | Source page |
|---|---|---|---|---|
| 1 | [01-architecture-overview.html](01-architecture-overview.html) | architecture | System topology, planes, Valkey coupling, zero-trust principles | [01-architecture-overview.md](../01-architecture-overview.md) |
| 2 | [02-creating-db-connections.html](02-creating-db-connections.html) | sequence | `/api/token` → wire connect → session lifecycle | [02-creating-db-connections.md](../02-creating-db-connections.md) |
| 3 | [03-checker-sessions-kill.html](03-checker-sessions-kill.html) | sequence | Session selection, live feed, kill-query vs kill-connection | [03-checker-sessions-kill.md](../03-checker-sessions-kill.md) |
| 4 | [04-write-gating.html](04-write-gating.html) | sequence | Grace window, re-open semantics, checker ≠ maker (SoD) | [04-write-gating.md](../04-write-gating.md) |
| 5 | [05-credential-retrieval-api.html](05-credential-retrieval-api.html) | sequence | External credential API: request/response contract, hygiene | [05-credential-retrieval-api.md](../05-credential-retrieval-api.md) |
| 6 | [06-protocols-tls-security.html](06-protocols-tls-security.html) | architecture | One listener, three wire protocols, byte-exact relay, capture caps | [06-protocols-tls-security.md](../06-protocols-tls-security.md) |
| 7 | [07-audit-persistence.html](07-audit-persistence.html) | dataflow | Lifecycle events → idempotent upserts in `zt_audit.sessions` | [07-audit-persistence.md](../07-audit-persistence.md) |
| 8 | [08-otel-metrics.html](08-otel-metrics.html) | dataflow | Instruments → `:9464/metrics` → Prometheus → Grafana | [08-otel-metrics.md](../08-otel-metrics.md) |
| 9 | [09-auth-login.html](09-auth-login.html) | sequence | Login & authentication: local `/api/login` self-issue, external pre-issued JWT, Bearer REST, mint-for-self, checker WS `?access_token=`, unconditional logout → jti denylist | [jwt-auth-conversion.md](../jwt-auth-conversion.md) |
| 10 | [10-external-cutover.html](10-external-cutover.html) | architecture | Cutover runbook: standalone local login → external-issuer-only (issuer entry, origin allowlist, verify, `login_enabled: false`, retire SPA, `.env` cleanup) with rollback branch | [jwt-auth-conversion.md](../jwt-auth-conversion.md) + RUN.md §2.1.2 |

## Authoring notes (keep diagrams honest)

- **Regenerate**: candidates live in [`candidates/`](candidates/). Render with
  `node archify/bin/archify.mjs deliver <type> <candidate>.json <output>.html --quality showcase`.
  Delivery snapshots the exact spec bytes (SHA-256 in the delivery receipt) and never
  edits the HTML afterwards.
- **Sequence diagrams** (2–5) are intentionally dense; on short desktop viewports
  (1440×900) they scroll vertically — same behavior as Archify's own reference
  example. Readability (≥6 px projected text) and no horizontal overflow hold at all
  checked sizes.
- **Visual evidence**: `*.visual-check.*.png` captures (light/dark at 1440×900 and
  2048×1320) and `*.visual-check.json` receipts sit beside each artifact. `visualReview`
  in those receipts is always `pending` — the screenshots are for human inspection.

## Change-prone surfaces

Pages 2 (token API) and 5 (credential API) describe the two wire contracts most likely
to change, and Page 9 (auth, `jwt-auth-conversion.md`) now mirrors its login process
and external-issuer cutover as diagrams 9–10. When editing them, update **both** the
Mermaid page and the Archify candidate (see `candidates/02-*`, `candidates/05-*`,
`candidates/09-*` and `candidates/10-*`), then re-deliver.
