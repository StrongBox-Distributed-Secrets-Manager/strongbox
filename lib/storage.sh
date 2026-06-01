#!/usr/bin/env bash
set -euo pipefail

: "${STRONGBOX_NODE_ID:=node1}"
: "${STRONGBOX_DATA_DIR:=/dev/shm/strongbox-${STRONGBOX_NODE_ID}}"

storage_init() {
  mkdir -p "$STRONGBOX_DATA_DIR"/{secrets,tokens,policies,leases,audit,cluster,dynamic,seal,users}
}

storage_path() {
  local bucket="$1" key="${2:-}"
  key="${key#/}"
  key="${key//\//__}"
  printf '%s/%s/%s' "$STRONGBOX_DATA_DIR" "$bucket" "$key"
}

storage_put() {
  local bucket="$1" key="$2" tmp
  storage_init
  tmp="$(mktemp "${STRONGBOX_DATA_DIR}/.${bucket}.XXXXXX")"
  cat >"$tmp"
  mv "$tmp" "$(storage_path "$bucket" "$key")"
}

storage_get() {
  local bucket="$1" key="$2" p
  p="$(storage_path "$bucket" "$key")"
  [[ -f "$p" ]] || return 1
  cat "$p"
}

storage_exists() {
  [[ -f "$(storage_path "$1" "$2")" ]]
}

storage_delete() {
  rm -f "$(storage_path "$1" "$2")"
}

storage_list() {
  local bucket="$1"
  storage_init
  find "$STRONGBOX_DATA_DIR/$bucket" -type f -maxdepth 1 -printf '%f\n' 2>/dev/null | sort
}
