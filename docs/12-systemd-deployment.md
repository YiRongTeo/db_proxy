# systemd deployment (production topology)

Two services, one per host role. Both binaries resolve `configs/*.yaml` and the git-ignored
`.env` **relative to their working directory** — the units pin `WorkingDirectory=/opt/project-d`.

## Layout (`/opt/project-d/`)

```
/opt/project-d/
├── bin/control            # control-plane binary (GOOS target of cmd/control)
├── bin/data               # data-plane binary   (GOOS target of cmd/data)
├── configs/control.yaml   # committed config (secrets via ${VAR} → .env)
├── configs/data.yaml
├── .env                   # git-ignored — ALL secrets (ZT_AUTH_*, Valkey, audit MySQL, callbacks)
├── web/                   # SPA bundle served by the control plane
└── RUN.md
```

Run under a dedicated unprivileged account:

Build for the Linux target on the dev box (the committed tree builds on Windows; units reference the plain names):

```bash
GOOS=linux GOARCH=amd64 go build -o bin/control ./cmd/control
GOOS=linux GOARCH=amd64 go build -o bin/data    ./cmd/data
```

```bash
useradd -r -s /usr/sbin/nologin -d /opt/project-d projectd
chown -R projectd:projectd /opt/project-d
```

## Install

```bash
cp deploy/project-d-control.service /etc/systemd/system/   # control host
cp deploy/project-d-data.service    /etc/systemd/system/   # each data host (4 hosts)
systemctl daemon-reload
systemctl enable --now project-d-control                   # and/or project-d-data
systemctl status project-d-control
```

## Logs

The binaries write **JSON logs to stdout/stderr only** — journald is the sink and the
rotation layer (no own file handles, no third-party log shipper needed):

```bash
journalctl -u project-d-control -f          # control
journalctl -u project-d-data -f             # data
journalctl -u project-d-data --since today 'MSG~"query"'   # query lines only
```

Volume/retention is journald config (`/etc/systemd/journald.conf`: `SystemMaxUse=2G`,
`MaxRetentionSec=30day`, then `systemctl restart systemd-journald`). Query lines carry redacted
SQL (`sql=`), status, session id, ticket, username — with `log_query_output: true` they also
carry captured rows (volume grows fast; keep it off unless needed).

> **⚠ journald rate limiting will silently drop query lines.** The distro default
> `RateLimitIntervalSec=30s / RateLimitBurst=100` means a busy data plane (easily >100 log
> lines in 30 s) loses every message past the burst — lifecycle lines survive, queries vanish.
> For query logging to be trustworthy, relax it in `/etc/systemd/journald.conf`:
>
> ```ini
> [Journal]
> RateLimitIntervalSec=1s
> RateLimitBurst=10000
> Store=persistent
> ```
>
> then `systemctl restart systemd-journald`. (`Store=persistent` also makes logs survive
> reboots on hosts without `/var/log/journal`.) Verify with a quick burst test: run 200 queries
> through a session and confirm `journalctl -u project-d-data --since -1min | grep -c '"msg":"query"'`
> counts them all.

## File-mode logging (alternative to journald)

If you'd rather have plain files than journald, both units ship a ready **sink B**: comment the
two `StandardOutput/StandardError=journal` lines and un-comment the `append:/var/log/project-d/…`
pair (systemd ≥ 240), create `/var/log/project-d/` + the log files owned by `projectd`, add the
logrotate config from the unit's footer (`copytruncate` — required, since systemd keeps the
file descriptor open), and restart. Trade-offs vs journald:

| | journal (default) | file (append:) |
|---|---|---|
| Rotation | journald owns it | **you** must run logrotate (`copytruncate`) |
| Rate limits | journald drops bursts (see warning above) | no dropping — every line lands |
| Querying | `journalctl -u project-d-data -f` | `tail -f /var/log/project-d/data.log \| grep '"msg":"query"'` |
| Boot persistence | needs `Store=persistent` | files just persist |

Query lines are identical in both modes — same JSON, same fields.

## Environment / flags

All tuning is via `/opt/project-d/.env` (`ZT_*` variables — see docs/11 env tables) or the yaml
files; the units intentionally contain **no secrets**. Commonly set per role:

| Unit | Variable | Effect |
|---|---|---|
| data | `ZT_RW_REQUIRE_CHECKER_WATCH=false` | UAT: rw tokens admit without a checker hold |
| data | `ZT_RW_RELOCK_ON_WATCH_LOSS=false` | UAT: no re-lock when the last checker leaves |
| data | `ZT_SESSION_CALLBACK_URL=https://app…` | main-app status callbacks (`started` at hold-start + admission, `ended` at close) |
| control | `ZT_AUTH_ALLOW_CHECKER_WRITE=true` | UAT: checkers may mint rw tokens |

Both `false`-direction security flags use **strict env parsing** (`true/1/false/0` only): a typo
is rejected with a boot WARN and the strict default stays on.

## Topology notes (8 controls + 4 data)

- Controls sit behind the round-robin LB; each is stateless apart from Valkey + the audit MySQL,
  so N identical `project-d-control` units work unchanged.
- One data-plane instance **per host** — the oracle listener binds `:1522`; a second instance on
  the same host fails the bind and exits (also why `go test ./cmd/data` requires the service
  stopped on that host).
- Rolling restart of a data plane kills its in-flight DB sessions — drain first (checkers kill
  sessions or wait for idle), then `systemctl restart project-d-data`.
