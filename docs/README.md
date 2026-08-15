# Project-D — Zero-Trust JIT Database Access Gateway

**Confluence page set.** Each file in this folder is one Confluence page. Paste the Markdown into a Confluence page and render diagrams with the **Mermaid** macro (the fenced ```mermaid blocks map 1:1 to the macro content).

| Page | File | What it covers |
|---|---|---|
| 1. Architecture Overview | [01-architecture-overview.md](01-architecture-overview.md) | System topology, planes, Valkey coupling, zero-trust principles |
| 2. Creating DB Connections (API) | [02-creating-db-connections.md](02-creating-db-connections.md) | **How the gateway receives API calls that create DB connections** — `/api/token`, the wire connect, session lifecycle |
| 3. Checker Sessions & Kill | [03-checker-sessions-kill.md](03-checker-sessions-kill.md) | Session selection, live feed, kill-query vs kill-connection |
| 4. Write-Gating (Maker–Checker) | [04-write-gating.md](04-write-gating.md) | Read/write access, watch presence, grace window, re-open semantics |
| 5. Credential Retrieval API | [05-credential-retrieval-api.md](05-credential-retrieval-api.md) | **How the gateway calls an external API to withdraw DB passwords** — request/response contract, config, hygiene |
| 6. Protocols, TLS & Security | [06-protocols-tls-security.md](06-protocols-tls-security.md) | MySQL/PG/MSSQL wire handling, TLS surfaces, audit & logging |

> **Maintenance note:** pages 2 and 5 describe the two API surfaces most likely to change. Their contracts (headers, keys, status codes, payload fields) are spelled out in tables so edits can be made without re-deriving the wire behaviour.

## Quick orientation

- **Control plane** — HTTPS API + WebSocket hub + Angular SPA (`:8080`).
- **Data plane** — single TCP listener (`:3306`) that sniffs and speaks three wire protocols (MySQL, PostgreSQL, MSSQL/TDS).
- **Valkey** — the *only* coupling between the two planes: token store, session directory, watch keys, Pub/Sub event channels.
- **Makers** never see real DB credentials. They get a short-lived, single-use token from the ticketing UI and connect with it *as the username*.
- **Checkers** watch sessions live and can kill queries or whole connections.
