#!/bin/bash
# lib/auth.sh — Auth, tokens, policies (Windows/Git Bash compatible)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/crypto.sh"

# ─────────────────────────────────────
# STORAGE — flat files instead of
# associative arrays (Git Bash safe)
# ─────────────────────────────────────
AUTH_DIR="${AUTH_DIR:-/tmp/strongbox/auth}"

auth_init() {
  mkdir -p "$AUTH_DIR/tokens"
  mkdir -p "$AUTH_DIR/policies"
  mkdir -p "$AUTH_DIR/users"
}

auth_init

# ─────────────────────────────────────
# TOKEN FUNCTIONS
# ─────────────────────────────────────

# Create a new bearer token
# Usage: create_token "policies" [ttl]
create_token() {
  local policies="${1:-default}"
  local ttl="${2:-3600}"
  local now
  now=$(date +%s)

  # Generate token (>=32 bytes)
  local token
  token=$(openssl rand -hex 32)

  local token_id
  token_id=$(openssl rand -hex 8)

  # Calculate expiry
  local expiry
  if [[ "$ttl" -eq 0 ]]; then
    expiry=0
  else
    expiry=$(( now + ttl ))
  fi

  # Save token to file
  local token_file="$AUTH_DIR/tokens/${token}"
  cat > "$token_file" <<EOF
token_id=$token_id
policies=$policies
expiry=$expiry
created=$now
revoked=0
EOF

  echo "{\"token\":\"$token\",\"token_id\":\"$token_id\",\"ttl\":$ttl,\"policies\":\"$policies\"}"
}

# Validate a token
# Usage: validate_token "token"
validate_token() {
  local token="$1"
  local token_file="$AUTH_DIR/tokens/${token}"

  # Check file exists
  if [[ ! -f "$token_file" ]]; then
    echo "ERROR: token not found" >&2
    return 1
  fi

  # Read token data
  local token_id expiry revoked
  token_id=$(grep "^token_id=" "$token_file" | \
    cut -d= -f2)
  expiry=$(grep "^expiry=" "$token_file" | \
    cut -d= -f2)
  revoked=$(grep "^revoked=" "$token_file" | \
    cut -d= -f2)

  # Check revoked
  if [[ "$revoked" == "1" ]]; then
    echo "ERROR: token revoked" >&2
    return 1
  fi

  # Check TTL
  if [[ "$expiry" -ne 0 ]]; then
    local now
    now=$(date +%s)
    if [[ $now -gt $expiry ]]; then
      echo "ERROR: token expired" >&2
      return 1
    fi
  fi

  echo "$token_id"
}

# Revoke a token instantly
# Usage: revoke_token "token"
revoke_token() {
  local token="$1"
  local token_file="$AUTH_DIR/tokens/${token}"

  if [[ ! -f "$token_file" ]]; then
    echo "ERROR: token not found" >&2
    return 1
  fi

  # Mark as revoked
  sed -i 's/^revoked=.*/revoked=1/' "$token_file"
  echo "Token revoked"
}

# Get token info
# Usage: get_token_info "token"
get_token_info() {
  local token="$1"

  local token_id
  if ! token_id=$(validate_token "$token"); then
    return 1
  fi

  local token_file="$AUTH_DIR/tokens/${token}"
  local policies expiry created
  policies=$(grep "^policies=" "$token_file" | \
    cut -d= -f2)
  expiry=$(grep "^expiry=" "$token_file" | \
    cut -d= -f2)
  created=$(grep "^created=" "$token_file" | \
    cut -d= -f2)

  local now remaining
  now=$(date +%s)
  if [[ "$expiry" -eq 0 ]]; then
    remaining=0
  else
    remaining=$(( expiry - now ))
    [[ $remaining -lt 0 ]] && remaining=0
  fi

  echo "{\"token_id\":\"$token_id\",\"policies\":\"$policies\",\"ttl\":$remaining,\"created_at\":$created}"
}

# ─────────────────────────────────────
# PASSWORD FUNCTIONS
# ─────────────────────────────────────

# Hash password using openssl (argon2 fallback)
# Usage: hash_password "password"
hash_password() {
  local password="$1"
  local salt
  salt=$(openssl rand -hex 16)

  # Use openssl sha256 with salt as argon2 fallback
  # Format: sha256:salt:hash
  local hash
  hash=$(echo -n "${salt}${password}" | \
    openssl dgst -sha256 | \
    awk '{print $2}')

  echo "sha256:${salt}:${hash}"
}

# Verify password against stored hash
# Usage: verify_password "password" "stored_hash"
verify_password() {
  local password="$1"
  local stored="$2"

  # Parse stored hash
  local algo salt stored_hash
  algo=$(echo "$stored" | cut -d: -f1)
  salt=$(echo "$stored" | cut -d: -f2)
  stored_hash=$(echo "$stored" | cut -d: -f3)

  if [[ "$algo" == "sha256" ]]; then
    local computed
    computed=$(echo -n "${salt}${password}" | \
      openssl dgst -sha256 | \
      awk '{print $2}')

    if [[ "$computed" == "$stored_hash" ]]; then
      return 0
    fi
  fi

  return 1
}

# ─────────────────────────────────────
# USER MANAGEMENT
# ─────────────────────────────────────

# Register a user
# Usage: register_user "username" "password" "policies"
register_user() {
  local username="$1"
  local password="$2"
  local policies="${3:-default}"

  local hashed
  hashed=$(hash_password "$password")

  local user_file="$AUTH_DIR/users/${username}"
  cat > "$user_file" <<EOF
username=$username
password_hash=$hashed
policies=$policies
EOF

  echo "User $username registered"
}

# Login and return token
# Usage: login_user "username" "password"
login_user() {
  local username="$1"
  local password="$2"
  local user_file="$AUTH_DIR/users/${username}"

  if [[ ! -f "$user_file" ]]; then
    echo "ERROR: user not found" >&2
    return 1
  fi

  local stored_hash policies
  stored_hash=$(grep "^password_hash=" "$user_file" | \
    cut -d= -f2-)
  policies=$(grep "^policies=" "$user_file" | \
    cut -d= -f2)

  if ! verify_password "$password" "$stored_hash"; then
    echo "ERROR: invalid password" >&2
    return 1
  fi

  create_token "$policies" 3600
}

# ─────────────────────────────────────
# POLICY FUNCTIONS
# ─────────────────────────────────────

# Create a policy
# Usage: create_policy "name" 'rules_json'
create_policy() {
  local name="$1"
  local rules="$2"
  local policy_file="$AUTH_DIR/policies/${name}"

  # Save rules to file
  echo "$rules" > "$policy_file"
  echo "Policy $name created"
}

# Get a policy
# Usage: get_policy "name"
get_policy() {
  local name="$1"
  local policy_file="$AUTH_DIR/policies/${name}"

  if [[ ! -f "$policy_file" ]]; then
    echo "ERROR: policy not found" >&2
    return 1
  fi

  echo "{\"name\":\"$name\",\"rules\":$(cat "$policy_file")}"
}

# Check if token has permission
# Usage: check_policy "token_id" "path" "operation"
check_policy() {
  local token_id="$1"
  local request_path="$2"
  local operation="$3"

  # Find token file by token_id
  local token_file=""
  for f in "$AUTH_DIR/tokens/"*; do
    [[ -f "$f" ]] || continue
    local fid
    fid=$(grep "^token_id=" "$f" | cut -d= -f2)
    if [[ "$fid" == "$token_id" ]]; then
      token_file="$f"
      break
    fi
  done

  if [[ -z "$token_file" ]]; then
    return 1
  fi

  local policies
  policies=$(grep "^policies=" "$token_file" | \
    cut -d= -f2)

  # Root gets everything
  if [[ "$policies" == "root" || \
        "$policies" == *"root"* ]]; then
    return 0
  fi

  # Check each policy
  IFS=',' read -ra policy_list <<< "$policies"
  for policy_name in "${policy_list[@]}"; do
    local policy_file="$AUTH_DIR/policies/${policy_name}"
    [[ -f "$policy_file" ]] || continue

    local rules
    rules=$(cat "$policy_file")

    # Parse each rule manually
    # rules format:
    # [{"path":"secret/app/*","caps":["read"]}]
    # Extract path and caps pairs
    while IFS= read -r rule_path; do
      # Get caps for this rule
      local rule_caps
      rule_caps=$(echo "$rules" | \
        grep -o "\"caps\":\[[^]]*\]" | \
        head -1 | \
        grep -o '"[a-z]*"' | \
        tr -d '"')

      # Check path match
      local prefix="${rule_path/\*/}"
      local match=false

      if [[ "$rule_path" == *"*"* ]]; then
        [[ "$request_path" == "$prefix"* ]] && \
          match=true
      else
        [[ "$request_path" == "$rule_path" ]] && \
          match=true
      fi

      if [[ "$match" == true ]]; then
        while IFS= read -r cap; do
          if [[ "$cap" == "$operation" ]]; then
            return 0
          fi
        done <<< "$rule_caps"
      fi

    done < <(echo "$rules" | \
      grep -o '"path":"[^"]*"' | \
      sed 's/"path":"//;s/"//')
  done

  return 1
}