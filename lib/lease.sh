#!/usr/bin/env bash

# Source dynamic.sh for PG operations
source "$(dirname "${BASH_SOURCE[0]}")/dynamic.sh"

# Creates a lease in storage
# Returns lease JSON
lease_create() {
    local lease_id="$1"
    local type="$2"
    local path="$3"
    local ttl="$4"
    local max_ttl="$5"
    local extra_json="$6" # e.g. '{"username": "...", "role": "..."}'

    local now
    now=$(date +%s)
    local expires_at=$((now + ttl))

    # Base lease info
    local lease_json
    lease_json=$(jq -n \
        --arg id "$lease_id" \
        --arg type "$type" \
        --arg path "$path" \
        --argjson ttl "$ttl" \
        --argjson max_ttl "$max_ttl" \
        --argjson expires_at "$expires_at" \
        --argjson created_at "$now" \
        --argjson extra "$extra_json" \
        '{"id": $id, "type": $type, "path": $path, "ttl": $ttl, "max_ttl": $max_ttl, "expires_at": $expires_at, "created_at": $created_at, "renew_count": 0, "status": "active"} + $extra')

    # Save to storage
    storage_put "lease/$lease_id" "$lease_json"
    echo "$lease_json"
}

# Renews a lease up to its max_ttl
# Returns JSON with new_ttl or empty on failure
lease_renew() {
    local lease_id="$1"
    local increment="$2"

    local lease_json
    lease_json=$(storage_get "lease/$lease_id")
    if [[ -z "$lease_json" ]]; then
        return 1
    fi

    local status
    status=$(echo "$lease_json" | jq -r '.status')
    if [[ "$status" != "active" ]]; then
        return 1
    fi

    local now
    now=$(date +%s)
    local created_at
    created_at=$(echo "$lease_json" | jq -r '.created_at')
    local max_ttl
    max_ttl=$(echo "$lease_json" | jq -r '.max_ttl')
    local renew_count
    renew_count=$(echo "$lease_json" | jq -r '.renew_count')

    # Calculate new expires_at
    local new_expires_at=$((now + increment))
    local total_elapsed=$((new_expires_at - created_at))

    # Cap at max_ttl
    if (( total_elapsed > max_ttl )); then
        new_expires_at=$((created_at + max_ttl))
    fi

    local new_ttl=$((new_expires_at - now))
    if (( new_ttl <= 0 )); then
        return 1 # Expired and cannot be renewed
    fi

    # Update lease json
    local updated_json
    updated_json=$(echo "$lease_json" | jq \
        --argjson expires_at "$new_expires_at" \
        --argjson renew_count $((renew_count + 1)) \
        '.expires_at = $expires_at | .renew_count = $renew_count')

    storage_put "lease/$lease_id" "$updated_json"
    echo "$new_ttl"
}

# Internal function to execute revocation on a single lease
# Returns 0 on success, 1 on temporary failure (needs backoff)
execute_lease_revocation() {
    local lease_json="$1"
    local lease_id
    lease_id=$(echo "$lease_json" | jq -r '.id')
    local type
    type=$(echo "$lease_json" | jq -r '.type')

    if [[ "$type" == "static" ]]; then
        # Static leases don't have external assets to clean up
        return 0
    elif [[ "$type" == "dynamic" ]]; then
        local role
        role=$(echo "$lease_json" | jq -r '.role')
        local username
        username=$(echo "$lease_json" | jq -r '.username')
        
        # Try to revoke the Postgres role
        if dynamic_revoke "$role" "$username"; then
            return 0
        else
            return 1 # Postgres unreachable or query failed
        fi
    fi
    return 0
}

# Processes expired or pending leases on the leader
reap_leases() {
    local now
    now=$(date +%s)

    # Get all leases
    local leases
    leases=$(storage_list "lease/")
    for key in $leases; do
        local lease_json
        lease_json=$(storage_get "$key")
        if [[ -z "$lease_json" ]]; then continue; fi

        local status
        status=$(echo "$lease_json" | jq -r '.status')
        local expires_at
        expires_at=$(echo "$lease_json" | jq -r '.expires_at')

        # Check if active and expired
        if [[ "$status" == "active" ]] && (( now >= expires_at )); then
            # Mark status as expired
            lease_json=$(echo "$lease_json" | jq '.status = "expired"')
            storage_put "$key" "$lease_json"
            status="expired"
        fi

        # Process revocation for expired or pending leases
        if [[ "$status" == "expired" ]]; then
            if execute_lease_revocation "$lease_json"; then
                # Successfully revoked
                lease_json=$(echo "$lease_json" | jq '.status = "revoked"')
                storage_put "$key" "$lease_json"
                # Replicate the lease update to followers
                replicate_write "PUT" "$key" "$lease_json"
            else
                # Failed (DB unreachable) -> transition to revocation_pending
                local next_retry=$((now + 5)) # initial 5s backoff
                lease_json=$(echo "$lease_json" | jq \
                    --argjson next_retry "$next_retry" \
                    '.status = "revocation_pending" | .retry_count = 1 | .next_retry_at = $next_retry')
                storage_put "$key" "$lease_json"
                replicate_write "PUT" "$key" "$lease_json"
            fi
        elif [[ "$status" == "revocation_pending" ]]; then
            local next_retry_at
            next_retry_at=$(echo "$lease_json" | jq -r '.next_retry_at // 0')
            if (( now >= next_retry_at )); then
                # Time to retry!
                if execute_lease_revocation "$lease_json"; then
                    # Success!
                    lease_json=$(echo "$lease_json" | jq '.status = "revoked"')
                    storage_put "$key" "$lease_json"
                    replicate_write "PUT" "$key" "$lease_json"
                else
                    # Failed again -> calculate next exponential backoff
                    local retry_count
                    retry_count=$(echo "$lease_json" | jq -r '.retry_count // 0')
                    ((retry_count++))
                    # backoff = min(300, 5 * (2^retry_count))
                    local backoff=$(( 5 * (2 ** retry_count) ))
                    if (( backoff > 300 )); then
                        backoff=300
                    fi
                    local next_retry=$((now + backoff))
                    lease_json=$(echo "$lease_json" | jq \
                        --argjson next_retry "$next_retry" \
                        --argjson count "$retry_count" \
                        '.retry_count = $count | .next_retry_at = $next_retry')
                    storage_put "$key" "$lease_json"
                    replicate_write "PUT" "$key" "$lease_json"
                fi
            fi
        fi
    done
}
