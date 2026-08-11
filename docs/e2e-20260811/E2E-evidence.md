# Project-D E2E gate — 2026-08-11 (two-browser Maker/Checker demo)

Gate status: **PASSED** — all 7 steps verified live. (Screenshots are DOM captures — the harness has no screenshot tool; every claim below is real tool output.)

## Browser A — Maker Portal
- Login admin/admin123 → /maker
- Preset "MySQL read-only" selected (db_type=mysql, db_user=ro_user, db_ip=127.0.0.1, db_port=3307)
- Ticket E2E-1 → Issue token
- Result card: **token sess_817a88b8ecf34bc5cb8b841be8c039a3**, Host 127.0.0.1, Port 3306, Expires in 300 s, Copy button present

## Browser B — Checker Dashboard
- Login admin/admin123 → /checker (SPA-internal nav), channel `*` auto-connected, status tag **live** (ant-tag-success)

## Terminal — real DB connections through :3306
- mysql client with UI token: `SELECT id,name FROM demo_items` → **3 rows (alpha, bravo, charlie)**
- `INSERT INTO demo_items (name) VALUES ('sneaky')` → **ERROR 1142 (42000): INSERT command denied** (ro_user) — still audited as an event

## Browser B live table (5 rows, each event exactly ONCE — dedupe verified live)
```
2026-08-11T15:39:06.5006261Z | query | admin | mysql | ro_user@127.0.0.1:3307 | E2E-1 | select @@version_comment limit 1
2026-08-11T15:39:06.5022221Z | query | admin | mysql | ro_user@127.0.0.1:3307 | E2E-1 | select $$
2026-08-11T15:39:06.5037956Z | query | admin | mysql | ro_user@127.0.0.1:3307 | E2E-1 | SELECT id,name FROM demo_items
2026-08-11T15:39:06.505844Z | query | admin | mysql | ro_user@127.0.0.1:3307 | E2E-1 | INSERT INTO demo_items (name) VALUES ('sneaky')
2026-08-11T15:39:23.6469388Z | query | alice | postgres | ro_user@127.0.0.1:5433 | E2E-2 | SELECT id,name FROM demo_items
```

## PG repeat
- PG token issued via API (X-Api-Key: e2e-demo-key, db_type=postgres, ticket E2E-2): sess_d130fde53df5cb66f2a44f99c2d0db73
- psql through :3306 with PG token: `SELECT id,name FROM demo_items` → **3 rows**
- Browser B: postgres event with **db_type=postgres** tag, username=alice, ticket E2E-2

## Token reuse
- Same mysql token reconnected → **ERROR 1045 (42000): invalid or expired token**
- Browser B: still exactly 5 rows — **no event on failed auth**

## Teardown
- Both planes killed; :8080/:3306 verified free (netstat); tok:* empty in Valkey
