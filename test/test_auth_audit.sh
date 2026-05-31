#!/bin/bash

# ── Paths ─────────────────────────────
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/.." && pwd)"

# ── Environment ───────────────────────
export AUTH_DIR="/tmp/strongbox_test/auth"
export AUDIT_LOG_PATH="/tmp/strongbox_test/audit.log"
export AUDIT_HMAC_SECRET="test-hmac-secret"

# Clean slate
rm -rf /tmp/strongbox_test
mkdir -p /tmp/strongbox_test

# Load libraries
source "$ROOT_DIR/lib/crypto.sh"
source "$ROOT_DIR/lib/auth.sh"
source "$ROOT_DIR/lib/audit.sh"

# ── Helpers ───────────────────────────
PASS=0
FAIL=0

check() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    echo "✅ PASS: $desc"
    ((PASS++))
  else
    echo "❌ FAIL: $desc"
    echo "   Expected: $expected"
    echo "   Got:      $actual"
    ((FAIL++))
  fi
}

check_exit() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "✅ PASS: $desc (exit $actual)"
    ((PASS++))
  else
    echo "❌ FAIL: $desc"
    echo "   Expected exit: $expected | Got: $actual"
    ((FAIL++))
  fi
}

echo ""
echo "══════════════════════════════════"
echo "   STRONGBOX AUTH + AUDIT TESTS  "
echo "══════════════════════════════════"

# ── AUDIT INIT ────────────────────────
echo ""
echo "── Audit Log ──────────────────────"
audit_init

check "Audit log file created" \
  "" \
  "$(test -f "$AUDIT_LOG_PATH" && echo exists)"

check "Genesis entry written" \
  "GENESIS" \
  "$(cat "$AUDIT_LOG_PATH" 2>/dev/null)"

# ── TOKEN CREATION ────────────────────
echo ""
echo "── Token Creation ─────────────────"

TOKEN_JSON=$(create_token "default" 3600)
TOKEN=$(echo "$TOKEN_JSON" | \
  grep -o '"token":"[^"]*"' | \
  sed 's/"token":"//;s/"//')
TOKEN_ID=$(echo "$TOKEN_JSON" | \
  grep -o '"token_id":"[^"]*"' | \
  sed 's/"token_id":"//;s/"//')

check "Token is 64 chars" \
  "" "$([[ ${#TOKEN} -eq 64 ]] && echo OK)"

check "Token JSON has token field" \
  "token" "$TOKEN_JSON"

check "Token JSON has token_id" \
  "token_id" "$TOKEN_JSON"

check "Token JSON has policies" \
  "default" "$TOKEN_JSON"

# ── TOKEN VALIDATION ──────────────────
echo ""
echo "── Token Validation ───────────────"

VALID_ID=$(validate_token "$TOKEN" 2>/dev/null)
check_exit "Valid token returns exit 0" "0" "$?"

check "Returns correct token_id" "$TOKEN_ID" "$VALID_ID"

validate_token "fake-token-xyz" > /dev/null 2>&1
check_exit "Fake token returns exit 1" "1" "$?"

# ── TOKEN REVOCATION ──────────────────
echo ""
echo "── Token Revocation ───────────────"

REV_JSON=$(create_token "test" 3600)
REV_TOKEN=$(echo "$REV_JSON" | \
  grep -o '"token":"[^"]*"' | \
  sed 's/"token":"//;s/"//')

validate_token "$REV_TOKEN" > /dev/null 2>&1
check_exit "Token valid before revocation" "0" "$?"

revoke_token "$REV_TOKEN" > /dev/null

validate_token "$REV_TOKEN" > /dev/null 2>&1
check_exit "Token invalid immediately after revoke" "1" "$?"

# ── PASSWORD HASHING ──────────────────
echo ""
echo "── Password Hashing ───────────────"

HASH=$(hash_password "mysecretpassword")

check "Hash is not empty" "sha256" "$HASH"
check "Hash has salt" ":" "$HASH"
check "Hash not plaintext" \
  "" "$([[ "$HASH" != "mysecretpassword" ]] && echo OK)"

verify_password "mysecretpassword" "$HASH"
check_exit "Correct password verifies" "0" "$?"

verify_password "wrongpassword" "$HASH"
check_exit "Wrong password fails" "1" "$?"

# ── USER MANAGEMENT ───────────────────
echo ""
echo "── User Management ────────────────"

register_user "alice" "password123" "default"
check_exit "User registration succeeds" "0" "$?"

LOGIN_JSON=$(login_user "alice" "password123")
check_exit "Login correct password succeeds" "0" "$?"
check "Login returns token" "token" "$LOGIN_JSON"

login_user "alice" "wrongpassword" > /dev/null 2>&1
check_exit "Wrong password fails" "1" "$?"

login_user "nobody" "pass" > /dev/null 2>&1
check_exit "Unknown user fails" "1" "$?"

# ── POLICIES ──────────────────────────
echo ""
echo "── Policies ───────────────────────"

create_policy "readonly-app" \
  '[{"path":"secret/app/*","caps":["read"]}]'
check_exit "Create policy succeeds" "0" "$?"

POLICY_OUT=$(get_policy "readonly-app")
check "Policy retrieval works" "readonly-app" "$POLICY_OUT"

get_policy "nonexistent" > /dev/null 2>&1
check_exit "Nonexistent policy fails" "1" "$?"

# ── POLICY ENFORCEMENT ────────────────
echo ""
echo "── Policy Enforcement ─────────────"

create_policy "reader" \
  '[{"path":"secret/app/*","caps":["read"]}]' \
  > /dev/null

create_policy "writer" \
  '[{"path":"secret/app/*","caps":["read","write"]}]' \
  > /dev/null

create_policy "admin" \
  '[{"path":"secret/*","caps":["read","write","delete"]}]' \
  > /dev/null

READ_JSON=$(create_token "reader" 3600)
READ_ID=$(echo "$READ_JSON" | \
  grep -o '"token_id":"[^"]*"' | \
  sed 's/"token_id":"//;s/"//')

WRITE_JSON=$(create_token "writer" 3600)
WRITE_ID=$(echo "$WRITE_JSON" | \
  grep -o '"token_id":"[^"]*"' | \
  sed 's/"token_id":"//;s/"//')

ROOT_JSON=$(create_token "root" 0)
ROOT_ID=$(echo "$ROOT_JSON" | \
  grep -o '"token_id":"[^"]*"' | \
  sed 's/"token_id":"//;s/"//')

check_policy "$READ_ID" "secret/app/db" "read"
check_exit "Read token can READ secret/app/db" "0" "$?"

check_policy "$READ_ID" "secret/app/db" "write"
check_exit "Read token CANNOT write" "1" "$?"

check_policy "$READ_ID" "secret/other/x" "read"
check_exit "Read token CANNOT access other path" "1" "$?"

check_policy "$WRITE_ID" "secret/app/db" "write"
check_exit "Write token can WRITE" "0" "$?"

check_policy "$ROOT_ID" "secret/anything" "delete"
check_exit "Root can DELETE anything" "0" "$?"

# Wildcard tests
create_policy "wildtest" \
  '[{"path":"secret/prod/*","caps":["read"]}]' \
  > /dev/null
WILD_JSON=$(create_token "wildtest" 3600)
WILD_ID=$(echo "$WILD_JSON" | \
  grep -o '"token_id":"[^"]*"' | \
  sed 's/"token_id":"//;s/"//')

check_policy "$WILD_ID" "secret/prod/db" "read"
check_exit "Wildcard matches secret/prod/db" "0" "$?"

check_policy "$WILD_ID" "secret/staging/db" "read"
check_exit "Wildcard blocks secret/staging/db" "1" "$?"

# ── AUDIT ENTRIES ─────────────────────
echo ""
echo "── Audit Log Entries ──────────────"

audit_log "tok123" "WRITE" "secret/app/db"
audit_log "tok123" "READ" "secret/app/db"
audit_log "tok456" "REVOKE" "/auth/revoke"

LOG=$(cat "$AUDIT_LOG_PATH")

check "WRITE event logged" "WRITE" "$LOG"
check "READ event logged" "READ" "$LOG"
check "REVOKE event logged" "REVOKE" "$LOG"
check "Entries have prev_hash" "prev_hash" "$LOG"
check "Entries have hmac" "hmac" "$LOG"
check "Entries have timestamp" "ts" "$LOG"

# ── VERIFY CLEAN ──────────────────────
echo ""
echo "── Audit Verification ─────────────"

VERIFY_OUT=$(
  AUDIT_LOG_PATH="$AUDIT_LOG_PATH" \
  AUDIT_HMAC_SECRET="$AUDIT_HMAC_SECRET" \
  "$ROOT_DIR/bin/strongbox-verify" 2>&1
)
VERIFY_EXIT=$?

check_exit "Verify clean log exits 0" "0" "$VERIFY_EXIT"
check "Verify reports OK" "OK" "$VERIFY_OUT"

# ── TAMPER DETECTION ──────────────────
echo ""
echo "── Tamper Detection ───────────────"

TAMPERED="/tmp/strongbox_test/audit_tampered.log"
cp "$AUDIT_LOG_PATH" "$TAMPERED"

sed -i 's/"op":"READ"/"op":"REDD"/' "$TAMPERED"

TAMPER_OUT=$(
  AUDIT_LOG_PATH="$TAMPERED" \
  AUDIT_HMAC_SECRET="$AUDIT_HMAC_SECRET" \
  "$ROOT_DIR/bin/strongbox-verify" 2>&1
)
TAMPER_EXIT=$?

check_exit "Verify tampered log exits 1" "1" "$TAMPER_EXIT"
check "Verify names the bad entry" "TAMPERED" "$TAMPER_OUT"

# ── SUMMARY ───────────────────────────
echo ""
echo "══════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "══════════════════════════════════"
echo ""

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
