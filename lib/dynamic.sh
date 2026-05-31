#!/usr/bin/env bash

# Helper to query the target PostgreSQL
pg_exec() {
    local query="$1"
    local db_host
    db_host=$(jq -r '.db.host // "localhost"' /dev/shm/config.json)
    local db_port
    db_port=$(jq -r '.db.port // 5432' /dev/shm/config.json)
    local db_user
    db_user=$(jq -r '.db.user // "postgres"' /dev/shm/config.json)
    local db_pass
    db_pass=$(jq -r '.db.password // ""' /dev/shm/config.json)
    local db_name
    db_name=$(jq -r '.db.dbname // "postgres"' /dev/shm/config.json)

    PGPASSWORD="$db_pass" psql -h "$db_host" -p "$db_port" -U "$db_user" -d "$db_name" -t -A -c "$query" 2>&1
}

# Mints a dynamic Postgres role based on config
dynamic_mint() {
    local role="$1"

    # Read configuration for the role
    # First check if role exists in config
    local role_exists
    role_exists=$(jq -r ".db.roles[\"$role\"] // empty" /dev/shm/config.json)
    if [[ -z "$role_exists" ]]; then
        echo "Role $role not configured" >&2
        return 1
    fi

    # Read creation statements
    local creation_statements
    creation_statements=$(jq -r ".db.roles[\"$role\"].creation_statements" /dev/shm/config.json)
    if [[ -z "$creation_statements" || "$creation_statements" == "null" ]]; then
        echo "No creation statements for role $role" >&2
        return 1
    fi

    local username="sb_user_$(openssl rand -hex 6)"
    local password
    password=$(openssl rand -hex 16)

    # Replace placeholders
    local sql="$creation_statements"
    sql="${sql//%username%/$username}"
    sql="${sql//%password%/$password}"

    # Execute SQL
    local output
    output=$(pg_exec "$sql")
    local status=$?
    if (( status != 0 )); then
        echo "Postgres error during minting: $output" >&2
        return 1
    fi

    echo "${username}:${password}"
}

# Revokes a dynamic Postgres role based on config
dynamic_revoke() {
    local role="$1"
    local username="$2"

    # Read revocation statements
    local revocation_statements
    revocation_statements=$(jq -r ".db.roles[\"$role\"].revocation_statements" /dev/shm/config.json)
    if [[ -z "$revocation_statements" || "$revocation_statements" == "null" ]]; then
        # Default fallback revocation
        revocation_statements="REVOKE ALL PRIVILEGES ON SCHEMA public FROM %username%; DROP ROLE %username%;"
    fi

    # Replace placeholders
    local sql="$revocation_statements"
    sql="${sql//%username%/$username}"

    # Execute SQL
    local output
    output=$(pg_exec "$sql")
    local status=$?
    if (( status != 0 )); then
        echo "Postgres error during revocation: $output" >&2
        return 1
    fi

    return 0
}
