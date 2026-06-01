#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8081}"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}

field() {
  sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"
}

need curl
need sed

request() {
  local method="$1" url="$2" body="${3:-}" token="${4:-}" tmp code
  tmp="$(mktemp)"
  if [[ -n "$token" && -n "$body" ]]; then
    code="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "Authorization: Bearer $token" -d "$body")"
  elif [[ -n "$token" ]]; then
    code="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "Authorization: Bearer $token")"
  elif [[ -n "$body" ]]; then
    code="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -d "$body")"
  else
    code="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url")"
  fi
  cat "$tmp"
  rm -f "$tmp"
  [[ "$code" =~ ^2 ]] || { echo; echo "request failed: $method $url -> HTTP $code" >&2; exit 1; }
}

echo "Health before init:"
HEALTH="$(request GET "$BASE_URL/v1/sys/health")"
printf '%s' "$HEALTH"
[[ "$HEALTH" == *'"sealed":true'* ]] || { echo; echo "expected fresh node to boot sealed before init" >&2; exit 1; }
echo

INIT="$(request POST "$BASE_URL/v1/sys/init")"
ROOT_TOKEN="$(printf '%s' "$INIT" | field root_token)"
SHARE1="$(printf '%s' "$INIT" | sed -n 's/.*"shares":\["\([^"]*\)".*/\1/p')"
SHARE2="$(printf '%s' "$INIT" | sed -n 's/.*"shares":\["[^"]*","\([^"]*\)".*/\1/p')"
[[ -n "$ROOT_TOKEN" && -n "$SHARE1" && -n "$SHARE2" ]] || { echo "init did not return root token and two shares: $INIT" >&2; exit 1; }

echo "Unsealing with two shares..."
request POST "$BASE_URL/v1/sys/unseal" "{\"share\":\"$SHARE1\"}"
echo
request POST "$BASE_URL/v1/sys/unseal" "{\"share\":\"$SHARE2\"}"
echo

echo "Writing secret version 1 and 2..."
request PUT "$BASE_URL/v1/secrets/app/db" '{"data":{"user":"app","password":"one"}}' "$ROOT_TOKEN"
echo
request PUT "$BASE_URL/v1/secrets/app/db" '{"data":{"user":"app","password":"two"}}' "$ROOT_TOKEN"
echo

echo "Reading latest secret..."
request GET "$BASE_URL/v1/secrets/app/db" "" "$ROOT_TOKEN"
echo

cat >root-token.txt <<EOF
$ROOT_TOKEN
EOF
chmod 600 root-token.txt
echo "Root token saved to root-token.txt. Scope it down before giving grader access."
