#!/usr/bin/env bash
# gen-certs.sh — generate self-signed development certificates for Project-D.
#
# Produces, under <repo>/certs/:
#   control.crt + control.key  (Control Plane HTTPS, Task 7.3)
#   data.crt    + data.key     (Data Plane TLS + Valkey TLS, Tasks 7.4-7.6)
#
# Certificates are self-signed (rsa:2048, 365 days) with
# SAN IP:127.0.0.1,DNS:localhost and CN=127.0.0.1 — sufficient for local
# development; production deployments MUST use real CA-signed certs.
#
# IDEMPOTENT: existing cert/key pairs are left untouched (safe to re-run).
# Pass -f to force regeneration of all pairs.
set -euo pipefail

FORCE=0
if [ "${1:-}" = "-f" ]; then
	FORCE=1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$(cd "$HERE/.." && pwd)/certs"
# git-bash/MSYS: openssl is a native Windows binary and cannot open MSYS
# /d/... paths — convert to a native path when cygpath is available
# (no-op on Linux/macOS, where cygpath does not exist).
if command -v cygpath >/dev/null 2>&1; then
	CERTS_DIR="$(cygpath -w "$CERTS_DIR")"
fi
mkdir -p "$CERTS_DIR"

DAYS=365
SUBJ="/CN=127.0.0.1"
SAN="subjectAltName=IP:127.0.0.1,DNS:localhost"

gen_pair() {
	local name="$1" crt="$2" key="$3"
	if [ -f "$crt" ] && [ -f "$key" ] && [ "$FORCE" -ne 1 ]; then
		echo "skip $name (certs exist; use -f to regenerate)"
		return
	fi
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout "$key" -out "$crt" \
		-days "$DAYS" -subj "$SUBJ" -addext "$SAN" \
		>/dev/null 2>&1
	echo "generated $name -> $crt"
}

gen_pair "control plane" "$CERTS_DIR/control.crt" "$CERTS_DIR/control.key"
gen_pair "data plane"    "$CERTS_DIR/data.crt"    "$CERTS_DIR/data.key"
