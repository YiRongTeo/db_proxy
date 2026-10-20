#!/usr/bin/env bash
# gen-dev-cert.sh — self-signed LOCALHOST certificate for the CONTROL plane's
# native TLS (http.tls) and browser WSS in development.
#
# Produces, under scripts/dev-cert/ (git-ignored):
#   localhost.crt + localhost.key
#
# Shape: rsa:2048, 10 YEARS (3650 days), CN=localhost,
# SANs DNS:localhost, IP:127.0.0.1, IP:::1 — exactly what a browser needs to
# trust https://localhost:<port>/ after one manual accept.
#
# DEVELOPMENT ONLY: production terminates TLS at the load balancer with real
# CA-signed certs (docs/11-node-integration.md §11.12 — the control plane
# stays HTTP behind the LB).
#
# IDEMPOTENT: an existing pair is left untouched (safe to re-run).
# Pass -f to force regeneration.
set -euo pipefail

FORCE=0
if [ "${1:-}" = "-f" ]; then
	FORCE=1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$HERE/dev-cert"
# git-bash/MSYS: openssl is a native Windows binary and cannot open MSYS
# /d/... paths — convert to a native path when cygpath is available
# (no-op on Linux/macOS, where cygpath does not exist).
if command -v cygpath >/dev/null 2>&1; then
	OUT_DIR="$(cygpath -w "$OUT_DIR")"
fi
mkdir -p "$OUT_DIR"

CRT="$OUT_DIR/localhost.crt"
KEY="$OUT_DIR/localhost.key"

if [ -f "$CRT" ] && [ -f "$KEY" ] && [ "$FORCE" -ne 1 ]; then
	echo "skip (pair exists; use -f to regenerate): $CRT"
else
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout "$KEY" -out "$CRT" \
		-days 3650 -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
		>/dev/null 2>&1
	echo "generated $CRT"
	echo "generated $KEY"
fi

cat <<EOF

── next steps ──────────────────────────────────────────────────────────────

1) Point the control plane at the pair — EITHER lines in configs/control.yaml:

     http:
       addr: ":8080"
       tls:
         cert_file: "scripts/dev-cert/localhost.crt"
         key_file:  "scripts/dev-cert/localhost.key"

   OR environment overrides (env beats the yaml; paths, not secrets):

     ZT_HTTP_TLS_CERT=scripts/dev-cert/localhost.crt
     ZT_HTTP_TLS_KEY=scripts/dev-cert/localhost.key

   The boot log then reads:  control plane listening  addr=:8080  tls=true

2) Browser trust (self-signed): visit https://localhost:8080/ once and
   accept the warning, or import localhost.crt into your OS/browser trust
   store. After that the Angular SPA (served over https) can open
   wss://localhost:8080/ws/checker directly against this process.

3) Smoke probe without the trust step:

     curl -k https://localhost:8080/api/health     # expect: {"status":"ok","valkey":"up"}

   (plain http:// to the same port now fails — the listener speaks TLS only)

────────────────────────────────────────────────────────────────────────────
EOF
