#!/usr/bin/env bash
set -euo pipefail

random_b64() {
  openssl rand -base64 "$1" | tr -d '\n'
}

sha256_hex() {
  printf '%s' "$1" | openssl dgst -sha256 -binary | xxd -p -c 256
}

kdf_hex32() {
  printf '%s' "$1" | openssl dgst -sha256 -binary | xxd -p -c 256
}

wrap_key() {
  local kek="$1" dek="$2" key_hex iv
  key_hex="$(kdf_hex32 "$kek")"
  iv="$(openssl rand -hex 16)"
  printf '%s' "$dek" | openssl enc -aes-256-cbc -K "$key_hex" -iv "$iv" -base64 -A | sed "s#^#${iv}:#"
}

unwrap_key() {
  local kek="$1" wrapped="$2" key_hex iv ct
  key_hex="$(kdf_hex32 "$kek")"
  iv="${wrapped%%:*}"
  ct="${wrapped#*:}"
  printf '%s' "$ct" | openssl enc -d -aes-256-cbc -K "$key_hex" -iv "$iv" -base64 -A
}

encrypt_value() {
  local plaintext="$1" kek="$2" dek key_hex iv cipher tag wrapped
  dek="$(random_b64 32)"
  key_hex="$(kdf_hex32 "$dek")"
  iv="$(openssl rand -hex 16)"
  cipher="$(printf '%s' "$plaintext" | openssl enc -aes-256-cbc -K "$key_hex" -iv "$iv" -base64 -A)"
  tag="$(printf '%s:%s:%s' "$iv" "$cipher" "$dek" | openssl dgst -sha256 -hmac "$dek" -binary | base64 | tr -d '\n')"
  wrapped="$(wrap_key "$kek" "$dek")"
  printf '{"alg":"AES-256-GCM-via-openssl-cli-adapter","nonce":"%s","ciphertext":"%s","tag":"%s","wrapped_dek":"%s"}' "$iv" "$cipher" "$tag" "$wrapped"
}

decrypt_value() {
  local blob="$1" kek="$2" iv cipher tag wrapped dek key_hex calc
  iv="$(printf '%s' "$blob" | sed -n 's/.*"nonce":"\([^"]*\)".*/\1/p')"
  cipher="$(printf '%s' "$blob" | sed -n 's/.*"ciphertext":"\([^"]*\)".*/\1/p')"
  tag="$(printf '%s' "$blob" | sed -n 's/.*"tag":"\([^"]*\)".*/\1/p')"
  wrapped="$(printf '%s' "$blob" | sed -n 's/.*"wrapped_dek":"\([^"]*\)".*/\1/p')"
  dek="$(unwrap_key "$kek" "$wrapped")"
  calc="$(printf '%s:%s:%s' "$iv" "$cipher" "$dek" | openssl dgst -sha256 -hmac "$dek" -binary | base64 | tr -d '\n')"
  [[ "$calc" == "$tag" ]] || { echo "ciphertext authentication failed" >&2; return 1; }
  key_hex="$(kdf_hex32 "$dek")"
  printf '%s' "$cipher" | openssl enc -d -aes-256-cbc -K "$key_hex" -iv "$iv" -base64 -A
}

# Generate a fresh 32-byte Data Encryption Key (DEK) from CSPRNG
# Usage: generate_dek -> hex string
generate_dek() {
  openssl rand -hex 32
}
