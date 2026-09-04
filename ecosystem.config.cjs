/**
 * PM2 ecosystem — Project-D (Zero-Trust JIT DB Access Gateway)
 *
 * Two apps, mirroring the Project-B/C ops pattern (fork mode, cwd pinned to the
 * repo root, per-app log files):
 *
 *   zt-control → bin/control.exe   Control Plane (:8080 — REST + WS hub + Angular SPA)
 *   zt-data    → bin/data.exe      Data Plane   (:3306 — shared MySQL+PG listener)
 *
 * Build the binaries first (both planes read configs/*.yaml relative to the repo root,
 * which is why cwd: __dirname is load-bearing):
 *
 *   cd <repo root>
 *   go build -o bin/control.exe ./cmd/control
 *   go build -o bin/data.exe ./cmd/data
 *
 * Then:  pm2 start ecosystem.config.cjs
 *
 * No-binaries fallback (go run, requires Go in PATH) — swap script/args per app:
 *   script: 'go',
 *   args:   'run ./cmd/control',          // or './cmd/data'
 *
 * Secrets come from .env (git-ignored; cp .env.example .env) — each app
 * loads it via PM2's env_file AND the planes re-read it at startup, so
 * ZT_AUTH_PASSWORD / ZT_JWT_SECRET / ZT_AUTH_CHECKER_PASSWORD / ZT_CRED_* /
 * ZT_AUDIT_MYSQL_PASSWORD never live in committed files. Required env
 * (UI login on, the default): ZT_AUTH_PASSWORD + ZT_JWT_SECRET (empty =
 * the control plane refuses to start).
 * Dev-only default admin login: admin/<ZT_AUTH_PASSWORD from .env>.
 * NOTE: the legacy ZT_API_API_KEY injection was removed with the JWT
 * conversion — control-plane mint auth is bearer-JWT only (no env to set).
 */
module.exports = {
  apps: [
    {
      name: 'zt-control',
      script: 'bin/control.exe',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork', // single process — Valkey is the shared state, not process memory
      watch: false,
      autorestart: true,
      env_file: '.env', // git-ignored secrets (cp .env.example .env)
      env: {
        // Auth secrets (ZT_AUTH_PASSWORD, ZT_JWT_SECRET, …) come from .env
        // via env_file above — the retired ZT_API_API_KEY must NOT be set.
      },
      error_file: 'logs/control-error.log',
      out_file: 'logs/control-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      max_restarts: 10,
      min_uptime: '10s',
      max_memory_restart: '512M',
    },
    {
      name: 'zt-data',
      script: 'bin/data.exe',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      autorestart: true,
      env_file: '.env', // git-ignored secrets (cp .env.example .env)
      env: {},
      error_file: 'logs/data-error.log',
      out_file: 'logs/data-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      max_restarts: 10,
      min_uptime: '10s',
      max_memory_restart: '512M',
    },
  ],
};
