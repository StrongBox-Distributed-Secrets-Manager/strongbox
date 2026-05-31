#!/bin/bash
# lib/audit.sh — Tamper-evident audit log (no jq required)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/crypto.sh"

AUDIT_LOG="${AUDIT_LOG_PATH:-/tmp/strongbox/audit.log}"
AUDIT_SECRET="${AUDIT_HMAC_SECRET:-changeme}"
LAST_HASH="0000000000000000000000000000000000000000000000000000000000000000"

# Initialize audit log
audit_init() {
  mkdir -p "$(dirname "$AUDIT_LOG")"

  if [[ -f "$AUDIT_LOG" ]] && \
     [[ -s "$AUDIT_LOG" ]]; then
    # Load last hash
    LAST_HASH=$(tail -1 "$AUDIT_LOG" | \
      grep -o '"hmac":"[^"]*"' | \
      sed 's/"hmac":"//;s/"//')
    local count
    count=$(wc -l < "$AUDIT_LOG")
    echo "Audit log loaded: $count entries"
  else
    # Write genesis entry
    _write_entry "GENESIS" "system" "/sys/init"
    echo "Audit log created: $AUDIT_LOG"
  fi
}

# Internal write function
_write_entry() {
  local operation="$1"
  local token_id="$2"
  local path="$3"

  local ts
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  local index=0
  if [[ -f "$AUDIT_LOG" ]]; then
    index=$(wc -l < "$AUDIT_LOG" | tr -d ' ')
  fi

  # Build entry as JSON string manually (no jq)
  local entry="{\"index\":${index},\"ts\":\"${ts}\",\"op\":\"${operation}\",\"path\":\"${path}\",\"token_id\":\"${token_id}\",\"prev_hash\":\"${LAST_HASH}\"}"

  # Sign entry
  local hmac
  hmac=$(hmac_sign "$entry" "$AUDIT_SECRET")

  # Full entry with hmac
  local full_entry="{\"index\":${index},\"ts\":\"${ts}\",\"op\":\"${operation}\",\"path\":\"${path}\",\"token_id\":\"${token_id}\",\"prev_hash\":\"${LAST_HASH}\",\"hmac\":\"${hmac}\"}"

  echo "$full_entry" >> "$AUDIT_LOG"
  LAST_HASH="$hmac"
}

# Public: append audit entry
# Usage: audit_log "token_id" "operation" "path"
audit_log() {
  local token_id="${1:-system}"
  local operation="${2:-UNKNOWN}"
  local path="${3:-/}"
  _write_entry "$operation" "$token_id" "$path"
}

# Read audit log
audit_read() {
  local filter="${1:-}"
  if [[ ! -f "$AUDIT_LOG" ]]; then
    echo "[]"
    return
  fi

  if [[ -n "$filter" ]]; then
    grep "\"token_id\":\"$filter\"" "$AUDIT_LOG"
  else
    cat "$AUDIT_LOG"
  fi
}