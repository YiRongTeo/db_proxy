# Page 4 — Write-Gating (Maker–Checker)

## The rule

A maker with **read-write** access (`access: write` on the token) **cannot execute any SQL unless a checker is connected to their session**. Read-only makers are never gated.

The gate is enforced **inside the data plane**, per command, before a single SQL byte is forwarded to the database.

```mermaid
sequenceDiagram
    autonumber
    participant M as Maker (rw, sqlcmd/mysql/psql)
    participant D as Data Plane
    participant V as Valkey
    participant K as Checker UI
    participant B as Target DB

    M->>D: connect with rw token
    D->>V: GETDEL token → access=write
    M->>D: INSERT ... (no checker yet)

    alt No checker watching (grace window)
        D->>D: wait up to gate_wait_seconds (default 20s)
        D->>V: watch:<sid>? → absent
        D-->>M: readable auth error (mysql 1045 / pg 28000 / mssql login-fail)
        D->>V: audit event status=error "maker gating: no checker connected"
    else Checker arrives within the window
        K->>V: watch:<sid> = 1
        D->>B: INSERT forwarded (the held query RUNS, in order)
        B-->>D: rows / OK
        D-->>M: result
        D->>V: audit event status=ok
    end

    Note over M, B: If the checker LEAVES and the gate rejects again,<br/>the gate RE-OPENS when a checker re-attaches —<br/>the maker resumes WITHOUT reconnecting (no permanent latch)
```

## How the gate works

1. **Watch presence** — while a checker is connected to a session, the checker hub keeps a heartbeat-refreshed `watch:<sid>` key in Valkey; it is deleted on disconnect.
2. **Per-command check** — for every SQL-executing command on a `access: write` session, the data plane checks `watch:<sid>` *before* forwarding. (MySQL/PG: query commands; MSSQL: TDS batch `0x01` / RPC `0x03` — control messages are never gated.)
3. **Grace window** — if unwatched, the command is **held**, not rejected instantly: `gate_wait_seconds` (default **20**, `0` = reject immediately; env `ZT_GATE_WAIT_SECONDS`). If a checker attaches within the window, the held command(s) flush in order.
4. **Timeout** — no watcher by the deadline → the client receives a readable auth-class error and an audit event (`status=error`, message `maker gating: no checker connected...`). Nothing was executed; no row can land.
5. **Re-open, no latch** — a later watcher **does** re-open the gate: the maker's next command runs, same connection, no reconnect required. (The permanent latch from an earlier design was removed — a returning checker unblocks the session.)

## Behaviour matrix

| Scenario | Outcome |
|---|---|
| rw maker, no checker ever | every SQL command → grace wait → readable error + audit `status=error`; **rows never land** |
| rw maker, checker attaches during grace | held command runs; subsequent commands flow while watched |
| rw maker, checker attaches after a rejection | next command runs (gate re-opened) |
| rw maker, checker disconnects mid-session | next command → grace wait → error again (enforcement is per-command) |
| ro maker | never gated — queries flow with no checker |

## Error surface per protocol

| Protocol | Blocked-command error |
|---|---|
| MySQL | `ERROR 1045 (42000): maker gating: no checker connected to session <sid>` |
| PostgreSQL | `FATAL 28000: maker gating: no checker connected to session <sid>` |
| MSSQL | sqlcmd-readable login-failure style error token with the same message |

## Configuration

| Key | Env | Default | Meaning |
|---|---|---|---|
| `gate_wait_seconds` | `ZT_GATE_WAIT_SECONDS` | `20` | Grace window for a watcher; `0` = immediate reject |

## The session-listing piece

Tokens carry a session id **stamped at issue time**; the session appears in the checker's list as `pending` (with a "waiting for maker" badge) **before the maker connects**. This lets a checker arm the watch *first* — the flow that originally deadlocked (checker couldn't select a session until the maker connected, but the maker's first query was blocked until a checker watched) now works in either order.
