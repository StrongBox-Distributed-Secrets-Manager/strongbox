#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/storage.sh"

: "${STRONGBOX_CLUSTER_NODES:=node1,node2,node3}"

cluster_majority() {
  local count
  IFS=',' read -ra nodes <<<"$STRONGBOX_CLUSTER_NODES"
  count="${#nodes[@]}"
  echo "$((count / 2 + 1))"
}

cluster_bootstrap() {
  storage_init
  [[ -f "$STRONGBOX_DATA_DIR/cluster/term" ]] || echo 1 >"$STRONGBOX_DATA_DIR/cluster/term"
  [[ -f "$STRONGBOX_DATA_DIR/cluster/leader" ]] || echo "${STRONGBOX_LEADER_ID:-node1}" >"$STRONGBOX_DATA_DIR/cluster/leader"
}

cluster_term() {
  cluster_bootstrap
  cat "$STRONGBOX_DATA_DIR/cluster/term"
}

cluster_leader() {
  cluster_bootstrap
  cat "$STRONGBOX_DATA_DIR/cluster/leader"
}

cluster_is_leader() {
  [[ "$(cluster_leader)" == "$STRONGBOX_NODE_ID" ]]
}

cluster_require_leader() {
  if cluster_is_leader; then
    return 0
  fi
  printf '{"error":"not leader","leader":"%s"}' "$(cluster_leader)"
  return 1
}

cluster_elect() {
  local new_leader="$1" term
  cluster_bootstrap
  term="$(($(cluster_term) + 1))"
  echo "$term" >"$STRONGBOX_DATA_DIR/cluster/term"
  echo "$new_leader" >"$STRONGBOX_DATA_DIR/cluster/leader"
}