#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export STRONGBOX_NODE_ID=node1
export STRONGBOX_DATA_DIR="${TMPDIR:-/tmp}/strongbox-test-$$"
export STRONGBOX_AUDIT_KEY="test-audit-key"
export STRONGBOX_DEFAULT_TTL=1
export STRONGBOX_MAX_TTL=4

. "$ROOT/lib/http.sh"

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
contains() { [[ "$1" == *"$2"* ]] || fail "$3: expected <$2> in <$1>"; pass "$3"; }

rm -rf "$STRONGBOX_DATA_DIR"
storage_init

health="$(route_request GET /v1/sys/health '{}' '')"
contains "$health" '"sealed":true' "cluster boots sealed before init"

init="$(route_request POST /v1/sys/init '{}' '')"
contains "$init" '"shares":' "init returns shares"
root="$(printf '%s' "$init" | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')"
share1="$(printf '%s' "$init" | sed -n 's/.*"shares":\["\([^"]*\)".*/\1/p')"
share2="$(printf '%s' "$init" | sed -n 's/.*"shares":\["[^"]*","\([^"]*\)".*/\1/p')"

sealed_read="$(route_request GET /v1/secrets/app/db '{}' "Bearer $root" || true)"
contains "$sealed_read" '"error":"sealed"' "sealed cluster rejects secret reads"

u1="$(route_request POST /v1/sys/unseal "{\"share\":\"$share1\"}" '')"
contains "$u1" '"sealed":true' "first share advances progress"
u2="$(route_request POST /v1/sys/unseal "{\"share\":\"$share2\"}" '')"
contains "$u2" '"sealed":false' "threshold share unseals"

w1="$(route_request PUT /v1/secrets/app/db '{"data":{"user":"app","pass":"one"}}' "Bearer $root")"
contains "$w1" '"version":1' "first write creates version 1"
w2="$(route_request PUT /v1/secrets/app/db '{"data":{"user":"app","pass":"two"}}' "Bearer $root")"
contains "$w2" '"version":2' "second write creates version 2"
r1="$(route_request GET '/v1/secrets/app/db?version=1' '{}' "Bearer $root")"
contains "$r1" '"pass":"one"' "version 1 remains retrievable"
r2="$(route_request GET /v1/secrets/app/db '{}' "Bearer $root")"
contains "$r2" '"pass":"two"' "latest version returns newest value"

policy_put appread 'secret/app/|read'
app_token="$(token_create appread 60)"
allowed="$(route_request GET /v1/secrets/app/db '{}' "Bearer $app_token")"
contains "$allowed" '"version":2' "read-only token can read allowed prefix"
denied_write="$(route_request PUT /v1/secrets/app/db '{"data":{"x":"y"}}' "Bearer $app_token" || true)"
contains "$denied_write" '"error":"forbidden"' "read-only token cannot write"
denied_path="$(route_request GET /v1/secrets/other/x '{}' "Bearer $app_token" || true)"
contains "$denied_path" '"error":"forbidden"' "read-only token cannot read other prefix"

token_revoke "$app_token"
revoked="$(route_request GET /v1/secrets/app/db '{}' "Bearer $app_token" || true)"
contains "$revoked" '"error":"forbidden"' "revoked token fails immediately"

policy_put dyn 'dynamic-postgres/|read'
dyn_token="$(token_create dyn 60)"
dyn="$(route_request GET /v1/dynamic-postgres/readonly '{}' "Bearer $dyn_token")"
contains "$dyn" '"username":"sb_readonly_' "dynamic postgres read mints role"
sleep 2
dynamic_reap
lease_state="$(grep -R '^revoked|' "$STRONGBOX_DATA_DIR/leases" || true)"
[[ -n "$lease_state" ]] || fail "expired dynamic lease is revoked by reaper"
pass "expired dynamic lease is revoked by reaper"

cluster_elect node2
not_leader="$(route_request PUT /v1/secrets/app/db '{"data":{"x":"lost"}}' "Bearer $root" || true)"
[[ -z "$not_leader" || "$not_leader" == *'not leader'* ]] || fail "old leader refuses writes after election"
pass "old leader refuses writes after election"
cluster_elect node1

"$ROOT/bin/strongbox-verify" >/dev/null
audit_file="$(audit_log_file)"
perl -0pi -e 's/write/wrIte/' "$audit_file"
if "$ROOT/bin/strongbox-verify" >/tmp/strongbox-verify.out 2>&1; then
  fail "audit verifier catches tampering"
fi
contains "$(cat /tmp/strongbox-verify.out)" 'corrupt audit entry index' "audit verifier catches tampering"

rm -rf "$STRONGBOX_DATA_DIR"
printf 'integration complete\n'
