#!/usr/bin/env bash
# Generate self-signed TLS certificates for local development (Sprint 2+).
# Usage: bash scripts/gen-certs.sh
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/nginx/certs"
mkdir -p "$CERT_DIR"

if [[ -f "$CERT_DIR/server.crt" ]]; then
  echo "Certs already exist in $CERT_DIR — remove them first to regenerate."
  exit 0
fi

# MSYS_NO_PATHCONV stops Git Bash on Windows from mangling the -subj argument.
MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.crt" \
  -days 365 \
  -subj "/CN=honeyforge.local" \
  -addext "subjectAltName=DNS:localhost,DNS:honeyforge.local,DNS:nginx,IP:127.0.0.1"

chmod 600 "$CERT_DIR/server.key"
echo "Wrote server.crt / server.key to $CERT_DIR"
