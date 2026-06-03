#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/storage.sh"
. "$SCRIPT_DIR/crypto.sh"

token_hash() {
  sha256_hex "$1"
}

policy_put() {
  local name="$1" rules="$2"
  printf '%s\n' "$rules" | storage_put policies "$name"
}

policy_get() {
  storage_get policies "$1"
}

token_create() {
  local policies="$1" ttl="${2:-3600}" token id expires
  token="$(random_b64 48)"
  id="$(token_hash "$token")"
  expires="$(($(date +%s) + ttl))"
  printf 'active|%s|%s\n' "$expires" "$policies" | storage_put tokens "$id"
  printf '%s' "$token"
}

token_revoke() {
  local token="$1" id
  id="$(token_hash "$token")"
  if storage_exists tokens "$id"; then
    awk -F'|' 'BEGIN{OFS="|"} {$1="revoked"; print}' "$(storage_path tokens "$id")" | storage_put tokens "$id"
  fi
}

token_record() {
  local token="$1" id
  id="$(token_hash "$token")"
  storage_get tokens "$id"
}

token_policies() {
  token_record "$1" | awk -F'|' '{print $3}'
}

auth_check() {
  local token="$1" path="$2" cap="$3" rec status expires policies p rule_prefix rule_caps match_prefix
  [[ -n "$token" ]] || return 1
  if [[ -f "$STRONGBOX_DATA_DIR/seal/root_token" ]] && [[ "$(cat "$STRONGBOX_DATA_DIR/seal/root_token")" == "$token" ]]; then
    return 0
  fi
  rec="$(token_record "$token" 2>/dev/null || true)"
  [[ -n "$rec" ]] || return 1
  IFS='|' read -r status expires policies <<<"$rec"
  [[ "$status" == "active" && "$expires" -gt "$(date +%s)" ]] || return 1
  IFS=',' read -ra p <<<"$policies"
  for policy in "${p[@]}"; do
    while IFS='|' read -r rule_prefix rule_caps; do
      [[ -z "$rule_prefix" ]] && continue
      match_prefix="${rule_prefix%\*}"
      if [[ "$rule_prefix" == "*" || "$path" == "$match_prefix"* ]] && [[ ",$rule_caps," == *",$cap,"* ]]; then
        return 0
      fi
    done < <(policy_get "$policy" 2>/dev/null || true)
  done
  return 2
}

user_put() {
  local username="$1" password="$2" policies="$3" salt hash
  salt="$(random_b64 16)"
  hash="$(printf '%s' "$password" | argon2 "$salt" -id -e)"
  printf '%s|%s|%s\n' "$hash" "$salt" "$policies" | storage_put users "$username"
}

user_login() {
  local username="$1" password="$2" rec hash salt policies current_hash
  rec="$(storage_get users "$username")"
  [[ -n "$rec" ]] || return 1
  IFS='|' read -r hash salt policies <<<"$rec"
  current_hash="$(printf '%s' "$password" | argon2 "$salt" -id -e)"
  if [[ "$current_hash" == "$hash" ]]; then
    token_create "$policies" 3600
  else
    return 1
  fi
}