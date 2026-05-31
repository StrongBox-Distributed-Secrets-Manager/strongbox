#!/bin/bash
# lib/crypto.sh — Crypto primitives

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# HMAC-SHA256 sign a message
# Usage: hmac_sign "message" "secret"
hmac_sign() {
  local message="$1"
  local secret="$2"
  echo -n "$message" | \
    openssl dgst -sha256 \
    -hmac "$secret" | \
    awk '{print $2}'
}

# Generate random hex string
# Usage: random_hex [bytes]
random_hex() {
  local bytes="${1:-32}"
  openssl rand -hex "$bytes"
}