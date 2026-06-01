#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=storage.sh
. "$SCRIPT_DIR/storage.sh"

: "${STRONGBOX_AUDIT_KEY:=dev-audit-key-change-me}"

audit_log_file() {
  storage_init
  printf '%s/audit/audit.log' "$STRONGBOX_DATA_DIR"
}

audit_hmac() {
  printf '%s' "$1" | openssl dgst -sha256 -hmac "$STRONGBOX_AUDIT_KEY" -binary | base64 | tr -d '\n'
}

audit_append() {
  local token="${1:-anonymous}" op="${2:-unknown}" path="${3:-/}" status="${4:-ok}" log prev idx ts body mac
  log="$(audit_log_file)"
  if [[ -s "$log" ]]; then
    prev="$(tail -n 1 "$log" | awk -F'|' '{print $8}')"
    idx="$(($(tail -n 1 "$log" | awk -F'|' '{print $1}') + 1))"
  else
    prev="GENESIS"
    idx=0
  fi
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  body="${idx}|${ts}|${token}|${op}|${path}|${status}|${prev}"
  mac="$(audit_hmac "$body")"
  printf '%s|%s\n' "$body" "$mac" >>"$log"
}

audit_verify() {
  local log="${1:-$(audit_log_file)}" prev="GENESIS" expected idx=0 line body mac entry_idx
  [[ -f "$log" ]] || { echo "audit log not found: $log" >&2; return 2; }
  while IFS= read -r line; do
    body="${line%|*}"
    mac="${line##*|}"
    entry_idx="$(printf '%s' "$body" | awk -F'|' '{print $1}')"
    expected="$(audit_hmac "$body")"
    if [[ "$entry_idx" != "$idx" || "$mac" != "$expected" ]]; then
      echo "corrupt audit entry index ${idx}" >&2
      return 1
    fi
    if [[ "$(printf '%s' "$body" | awk -F'|' '{print $7}')" != "$prev" ]]; then
      echo "corrupt audit entry index ${idx}: previous hash mismatch" >&2
      return 1
    fi
    prev="$mac"
    idx=$((idx + 1))
  done <"$log"
  echo "audit ok: ${idx} entries"
}

audit_query_json() {
  local token_filter="${1:-}"
  local log
  log="$(audit_log_file)"
  printf '['
  [[ -f "$log" ]] || { printf ']'; return 0; }
  awk -F'|' -v token="$token_filter" '
    BEGIN { first=1 }
    token == "" || $3 == token {
      if (!first) printf ",";
      first=0;
      printf "{\"ts\":\"%s\",\"token\":\"%s\",\"op\":\"%s\",\"path\":\"%s\",\"status\":\"%s\"}", $2, $3, $4, $5, $6
    }
  ' "$log"
  printf ']'
}
