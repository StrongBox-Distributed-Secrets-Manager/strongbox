#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/storage.sh"
. "$SCRIPT_DIR/crypto.sh"
. "$SCRIPT_DIR/lease.sh"

dynamic_pg_read() {
  local role="$1" username password lease_id
  username="sb_${role}_$(date +%s)_$RANDOM"
  password="$(random_b64 24)"
  if command -v psql >/dev/null 2>&1 && [[ -n "${POSTGRES_DSN:-}" ]]; then
    PGPASSWORD="${POSTGRES_ADMIN_PASSWORD:-}" psql "$POSTGRES_DSN" -v ON_ERROR_STOP=1 \
      -c "CREATE ROLE ${username} LOGIN PASSWORD '${password}'" \
      -c "GRANT CONNECT ON DATABASE ${POSTGRES_DB:-postgres} TO ${username}"
  fi
  printf '%s|%s|active\n' "$username" "$password" | storage_put dynamic "$username"
  lease_id="$(lease_create "dynamic-postgres/${role}" "$STRONGBOX_DEFAULT_TTL" "dynamic-postgres" "$username")"
  printf '{"username":"%s","password":"%s","lease":%s}' "$username" "$password" "$(lease_json "$lease_id")"
}

dynamic_pg_revoke_username() {
  local username="$1"
  if command -v psql >/dev/null 2>&1 && [[ -n "${POSTGRES_DSN:-}" ]]; then
    PGPASSWORD="${POSTGRES_ADMIN_PASSWORD:-}" psql "$POSTGRES_DSN" -v ON_ERROR_STOP=1 \
      -c "REVOKE ALL PRIVILEGES ON DATABASE ${POSTGRES_DB:-postgres} FROM ${username}" \
      -c "DROP ROLE IF EXISTS ${username}"
  fi
  storage_delete dynamic "$username"
}

dynamic_reap() {
  local id rec state path kind created expires meta tries now
  now="$(date +%s)"
  for id in $(storage_list leases); do
    rec="$(storage_get leases "$id")"
    IFS='|' read -r state path kind created expires meta tries <<<"$rec"
    [[ "$kind" == "dynamic-postgres" ]] || continue
    if [[ "$state" == "active" && "$expires" -le "$now" ]]; then
      if dynamic_pg_revoke_username "$meta"; then
        printf 'revoked|%s|%s|%s|%s|%s|%s\n' "$path" "$kind" "$created" "$expires" "$meta" "$tries" | storage_put leases "$id"
      else
        tries=$((tries + 1))
        printf 'revocation_pending|%s|%s|%s|%s|%s|%s\n' "$path" "$kind" "$created" "$expires" "$meta" "$tries" | storage_put leases "$id"
      fi
    fi
  done
}
