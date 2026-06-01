#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/storage.sh"
. "$SCRIPT_DIR/crypto.sh"

: "${STRONGBOX_DEFAULT_TTL:=30}"
: "${STRONGBOX_MAX_TTL:=300}"

lease_create() {
  local path="$1" ttl="${2:-$STRONGBOX_DEFAULT_TTL}" kind="${3:-static}" meta="${4:-}" id now exp
  (( ttl > STRONGBOX_MAX_TTL )) && ttl="$STRONGBOX_MAX_TTL"
  id="$(random_b64 18 | tr '/+' '_-')"
  now="$(date +%s)"
  exp="$((now + ttl))"
  printf 'active|%s|%s|%s|%s|%s|0\n' "$path" "$kind" "$now" "$exp" "$meta" | storage_put leases "$id"
  printf '%s' "$id"
}

lease_json() {
  local id="$1" rec state path kind created expires meta
  rec="$(storage_get leases "$id")"
  IFS='|' read -r state path kind created expires meta _ <<<"$rec"
  printf '{"id":"%s","state":"%s","ttl":%s,"max_ttl":%s}' "$id" "$state" "$((expires - $(date +%s)))" "$STRONGBOX_MAX_TTL"
}

lease_renew() {
  local id="$1" rec state path kind created expires meta tries now new_exp
  rec="$(storage_get leases "$id")"
  IFS='|' read -r state path kind created expires meta tries <<<"$rec"
  now="$(date +%s)"
  [[ "$state" == "active" && "$expires" -gt "$now" ]] || return 1
  new_exp="$((now + STRONGBOX_DEFAULT_TTL))"
  (( new_exp > created + STRONGBOX_MAX_TTL )) && new_exp="$((created + STRONGBOX_MAX_TTL))"
  printf 'active|%s|%s|%s|%s|%s|%s\n' "$path" "$kind" "$created" "$new_exp" "$meta" "$tries" | storage_put leases "$id"
  printf '{"new_ttl":%s}' "$((new_exp - now))"
}

lease_revoke() {
  local id="$1" rec state path kind created expires meta tries
  rec="$(storage_get leases "$id")"
  IFS='|' read -r state path kind created expires meta tries <<<"$rec"
  printf 'revoked|%s|%s|%s|%s|%s|%s\n' "$path" "$kind" "$created" "$expires" "$meta" "$tries" | storage_put leases "$id"
}

lease_expire_due() {
  local now id rec state path kind created expires meta tries
  now="$(date +%s)"
  for id in $(storage_list leases); do
    rec="$(storage_get leases "$id")"
    IFS='|' read -r state path kind created expires meta tries <<<"$rec"
    if [[ "$state" == "active" && "$expires" -le "$now" ]]; then
      printf 'expired|%s|%s|%s|%s|%s|%s\n' "$path" "$kind" "$created" "$expires" "$meta" "$tries" | storage_put leases "$id"
    fi
  done
}
