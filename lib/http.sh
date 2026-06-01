#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/storage.sh"
. "$SCRIPT_DIR/crypto.sh"
. "$SCRIPT_DIR/auth.sh"
. "$SCRIPT_DIR/lease.sh"
. "$SCRIPT_DIR/dynamic.sh"
. "$SCRIPT_DIR/consensus.sh"
. "$SCRIPT_DIR/audit.sh"

: "${STRONGBOX_THRESHOLD:=2}"
: "${STRONGBOX_SHARES:=3}"

json_field() {
  local json="$1" key="$2"
  printf '%s' "$json" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p"
}

json_data_object() {
  printf '%s' "$1" | sed -n 's/.*"data"[[:space:]]*:[[:space:]]*//p' | sed 's/}}$/}/'
}

sealed_file() { printf '%s/seal/sealed' "$STRONGBOX_DATA_DIR"; }
initialized_file() { printf '%s/seal/initialized' "$STRONGBOX_DATA_DIR"; }
kek_file() { printf '%s/seal/kek' "$STRONGBOX_DATA_DIR"; }
shares_file() { printf '%s/seal/submitted_shares' "$STRONGBOX_DATA_DIR"; }
root_token_file() { printf '%s/seal/root_token' "$STRONGBOX_DATA_DIR"; }

seal_bootstrap() {
  storage_init
  if [[ ! -f "$(initialized_file)" ]]; then
    touch "$(sealed_file)"
  fi
}

is_sealed() {
  seal_bootstrap
  [[ -f "$(sealed_file)" ]]
}

require_unsealed() {
  if is_sealed; then
    printf '{"error":"sealed"}'
    return 1
  fi
}

current_kek() {
  cat "$(kek_file)"
}

sys_init() {
  seal_bootstrap
  if [[ -f "$(initialized_file)" ]]; then
    printf '{"error":"already initialized"}'
    return 1
  fi
  local master_hex kek root_token shares_json
  master_hex="$(openssl rand -hex 32)"
  kek="$(openssl rand -base64 32 | tr -d '\n')"
  "$SCRIPT_DIR/shamir.py" split "$master_hex" "$STRONGBOX_THRESHOLD" "$STRONGBOX_SHARES" >"$STRONGBOX_DATA_DIR/seal/shares.tmp"
  printf '%s' "$kek" >"$(kek_file)"
  : >"$(shares_file)"
  touch "$(sealed_file)"
  touch "$(initialized_file)"
  policy_put root '*|read,write,delete'
  root_token="$(token_create root 86400)"
  printf '%s' "$root_token" >"$(root_token_file)"
  shares_json="$(awk 'BEGIN{printf "["} {if(NR>1)printf ","; printf "\"%s\"", $0} END{printf "]"}' "$STRONGBOX_DATA_DIR/seal/shares.tmp")"
  rm -f "$STRONGBOX_DATA_DIR/seal/shares.tmp"
  master_hex="$(printf '%064d' 0)"
  audit_append root init /v1/sys/init 201
  printf '{"shares":%s,"root_token":"%s"}' "$shares_json" "$root_token"
}

sys_unseal() {
  local body="$1" share progress recovered
  seal_bootstrap
  [[ -f "$(initialized_file)" ]] || { printf '{"error":"not initialized"}'; return 1; }
  share="$(json_field "$body" share)"
  [[ -n "$share" ]] || { printf '{"error":"missing share"}'; return 1; }
  grep -qxF "$share" "$(shares_file)" 2>/dev/null || printf '%s\n' "$share" >>"$(shares_file)"
  progress="$(wc -l <"$(shares_file)" | tr -d ' ')"
  if (( progress >= STRONGBOX_THRESHOLD )); then
    recovered="$("$SCRIPT_DIR/shamir.py" recover $(head -n "$STRONGBOX_THRESHOLD" "$(shares_file)"))"
    : >"$(shares_file)"
    rm -f "$(sealed_file)"
    recovered="$(printf '%064d' 0)"
    audit_append anonymous unseal /v1/sys/unseal 200
    printf '{"sealed":false,"progress":"%s/%s"}' "$STRONGBOX_THRESHOLD" "$STRONGBOX_THRESHOLD"
  else
    audit_append anonymous unseal /v1/sys/unseal 202
    printf '{"sealed":true,"progress":"%s/%s"}' "$progress" "$STRONGBOX_THRESHOLD"
  fi
}

sys_seal() {
  local token="$1"
  auth_check "$token" /v1/sys/seal write || { printf '{"error":"forbidden"}'; return 1; }
  touch "$(sealed_file)"
  rm -f "$(kek_file)"
  audit_append "$(token_hash "$token")" seal /v1/sys/seal 204
}

secret_latest_version() {
  local path="$1" p
  p="$(storage_path secrets "$path")"
  [[ -f "$p" ]] || { echo 0; return; }
  awk -F'|' 'END{print $1}' "$p"
}

secret_write() {
  local token="$1" path="$2" body="$3" data version blob
  require_unsealed || return 1
  cluster_require_leader >/dev/null || return 1
  auth_check "$token" "secret/${path}" write || { printf '{"error":"forbidden"}'; return 1; }
  data="$(json_data_object "$body")"
  [[ -n "$data" ]] || data="$body"
  version="$(($(secret_latest_version "$path") + 1))"
  blob="$(encrypt_value "$data" "$(current_kek)")"
  printf '%s|%s\n' "$version" "$blob" >>"$(storage_path secrets "$path")"
  audit_append "$(token_hash "$token")" write "secret/${path}" 201
  printf '{"version":%s}' "$version"
}

secret_read() {
  local token="$1" path="$2" version="${3:-}" rec blob lease_id
  require_unsealed || return 1
  auth_check "$token" "secret/${path}" read || { printf '{"error":"forbidden"}'; return 1; }
  if [[ -n "$version" ]]; then
    rec="$(awk -F'|' -v v="$version" '$1==v {print; exit}' "$(storage_path secrets "$path")")"
  else
    rec="$(tail -n 1 "$(storage_path secrets "$path")")"
  fi
  [[ -n "$rec" ]] || { printf '{"error":"not found"}'; return 1; }
  version="${rec%%|*}"
  blob="${rec#*|}"
  lease_id="$(lease_create "secret/${path}")"
  audit_append "$(token_hash "$token")" read "secret/${path}" 200
  printf '{"data":%s,"version":%s,"lease":%s}' "$(decrypt_value "$blob" "$(current_kek)")" "$version" "$(lease_json "$lease_id")"
}

route_request() {
  local method="$1" raw_path="$2" body="${3:-}" auth="${4:-}" token path query version role name lease_id
  seal_bootstrap
  cluster_bootstrap
  token="${auth#Bearer }"
  path="${raw_path%%\?*}"
  query=""
  [[ "$raw_path" == *\?* ]] && query="${raw_path#*\?}"
  case "${method} ${path}" in
    "POST /v1/sys/init") sys_init ;;
    "POST /v1/sys/unseal") sys_unseal "$body" ;;
    "POST /v1/sys/seal") sys_seal "$token" ;;
    "GET /v1/sys/health") printf '{"sealed":%s,"leader":"%s","term":%s,"node_id":"%s"}' "$(is_sealed && echo true || echo false)" "$(cluster_leader)" "$(cluster_term)" "$STRONGBOX_NODE_ID" ;;
    PUT\ /v1/secrets/*) secret_write "$token" "${path#/v1/secrets/}" "$body" ;;
    GET\ /v1/secrets/*) version="$(printf '%s' "$query" | sed -n 's/^version=\([0-9][0-9]*\)$/\1/p')"; secret_read "$token" "${path#/v1/secrets/}" "$version" ;;
    DELETE\ /v1/secrets/*) require_unsealed && auth_check "$token" "secret/${path#/v1/secrets/}" delete && storage_delete secrets "${path#/v1/secrets/}" && audit_append "$(token_hash "$token")" delete "secret/${path#/v1/secrets/}" 204 ;;
    GET\ /v1/dynamic-postgres/*) require_unsealed && auth_check "$token" "dynamic-postgres/${path#/v1/dynamic-postgres/}" read && dynamic_pg_read "${path#/v1/dynamic-postgres/}" ;;
    "POST /v1/auth/revoke") auth_check "$token" /v1/auth/revoke write || { printf '{"error":"forbidden"}'; return 1; }; token_revoke "$(json_field "$body" token)"; audit_append "$(token_hash "$token")" revoke /v1/auth/revoke 204 ;;
    "POST /v1/auth/login") printf '{"token":"%s","policies":"%s"}' "$(user_login "$(json_field "$body" username)" "$(json_field "$body" password)")" "$(json_field "$body" username)" ;;
    "GET /v1/auth/self") auth_check "$token" /v1/auth/self read || { printf '{"error":"unauthorized"}'; return 1; }; printf '{"token_id":"%s","policies":"%s","ttl":3600}' "$(token_hash "$token")" "$(token_policies "$token")" ;;
    PUT\ /v1/policies/*) name="${path#/v1/policies/}"; auth_check "$token" "policy/${name}" write || { printf '{"error":"forbidden"}'; return 1; }; policy_put "$name" "$(json_field "$body" rules)"; printf '{"created":true}' ;;
    GET\ /v1/policies/*) name="${path#/v1/policies/}"; auth_check "$token" "policy/${name}" read || { printf '{"error":"forbidden"}'; return 1; }; printf '{"rules":"%s"}' "$(policy_get "$name")" ;;
    POST\ /v1/leases/*/renew) lease_id="${path#/v1/leases/}"; lease_id="${lease_id%/renew}"; auth_check "$token" "lease/${lease_id}" write || { printf '{"error":"forbidden"}'; return 1; }; lease_renew "$lease_id" ;;
    POST\ /v1/leases/*/revoke) lease_id="${path#/v1/leases/}"; lease_id="${lease_id%/revoke}"; auth_check "$token" "lease/${lease_id}" write || { printf '{"error":"forbidden"}'; return 1; }; lease_revoke "$lease_id" ;;
    "GET /v1/audit") auth_check "$token" /v1/audit read || { printf '{"error":"forbidden"}'; return 1; }; audit_query_json "$(printf '%s' "$query" | sed -n 's/^token=\(.*\)$/\1/p')" ;;
    *) printf '{"error":"not found","path":"%s"}' "$raw_path"; return 1 ;;
  esac
}