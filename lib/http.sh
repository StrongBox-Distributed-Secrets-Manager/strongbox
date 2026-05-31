#!/usr/bin/env bash

# HTTP Router for StrongBox

# Send command to the daemon over IPC named pipe
send_ipc_cmd() {
    local cmd="$1"
    shift
    local ipc_payload="$$ $cmd"
    for arg in "$@"; do
        local arg_b64
        arg_b64=$(echo -n "$arg" | base64 -w0)
        ipc_payload+=" $arg_b64"
    done

    local reply_fifo="/dev/shm/reply_$$"
    mkdir -p /dev/shm
    mkfifo "$reply_fifo"
    
    # Send payload to daemon
    if ! echo "$ipc_payload" > /dev/shm/strongbox_ipc.fifo 2>/dev/null; then
        echo '{"error": "daemon offline"}' | base64 -w0
        rm -f "$reply_fifo"
        return 1
    fi
    
    local resp=""
    # 5 seconds timeout for daemon response
    if read -t 5 -r resp < "$reply_fifo"; then
        echo -n "$resp"
    else
        echo '{"error": "daemon timeout"}' | base64 -w0
    fi
    rm -f "$reply_fifo"
}

# Parse and route HTTP request
handle_http_request() {
    # Read request line
    read -r req_line
    req_line="${req_line%$'\r'}"
    if [[ -z "$req_line" ]]; then
        return 1
    fi

    local METHOD PATH HTTP_VERSION
    read -r METHOD PATH HTTP_VERSION <<< "$req_line"

    # Extract query parameters
    local QUERY_STRING=""
    if [[ "$PATH" == *"?"* ]]; then
        QUERY_STRING="${PATH#*\?}"
        PATH="${PATH%%\?*}"
    fi

    # Read headers
    local CONTENT_LENGTH=0
    local AUTH_HEADER=""
    while read -r header; do
        header="${header%$'\r'}"
        if [[ -z "$header" ]]; then
            break
        fi
        if [[ "$header" =~ ^[Cc]ontent-[Ll]ength:\ *(.*)$ ]]; then
            CONTENT_LENGTH="${BASH_REMATCH[1]}"
        elif [[ "$header" =~ ^[Aa]uthorization:\ *(.*)$ ]]; then
            AUTH_HEADER="${BASH_REMATCH[1]}"
        fi
    done

    # Read body if any
    local REQ_BODY=""
    if (( CONTENT_LENGTH > 0 )); then
        read -N "$CONTENT_LENGTH" -r REQ_BODY
    fi

    # Extract Bearer Token
    local TOKEN=""
    if [[ "$AUTH_HEADER" =~ ^[Bb]earer\ +(.*)$ ]]; then
        TOKEN="${BASH_REMATCH[1]}"
    fi

    # IPC request execution
    local ipc_resp_b64
    local http_status=200
    local http_body=""

    # ROUTING
    # 1. Sys Consensus internal endpoints (must not require token, but term checks)
    if [[ "$PATH" == "/v1/sys/consensus/request_vote" && "$METHOD" == "POST" ]]; then
        local term
        term=$(echo "$REQ_BODY" | jq -r '.term // 0')
        local candidate_id
        candidate_id=$(echo "$REQ_BODY" | jq -r '.candidate_id // ""')
        ipc_resp_b64=$(send_ipc_cmd "CON_REQUEST_VOTE" "$term" "$candidate_id")
        http_status=200

    elif [[ "$PATH" == "/v1/sys/consensus/heartbeat" && "$METHOD" == "POST" ]]; then
        local term
        term=$(echo "$REQ_BODY" | jq -r '.term // 0')
        local leader_id
        leader_id=$(echo "$REQ_BODY" | jq -r '.leader_id // ""')
        ipc_resp_b64=$(send_ipc_cmd "CON_HEARTBEAT" "$term" "$leader_id")
        http_status=200

    elif [[ "$PATH" == "/v1/sys/consensus/replicate" && "$METHOD" == "POST" ]]; then
        local op
        op=$(echo "$REQ_BODY" | jq -r '.op // ""')
        local key
        key=$(echo "$REQ_BODY" | jq -r '.key // ""')
        local val
        val=$(echo "$REQ_BODY" | jq -r '.value // ""')
        local term
        term=$(echo "$REQ_BODY" | jq -r '.term // 0')
        local leader_id
        leader_id=$(echo "$REQ_BODY" | jq -r '.leader_id // ""')
        ipc_resp_b64=$(send_ipc_cmd "CON_REPLICATE" "$op" "$key" "$val" "$term" "$leader_id")
        http_status=200

    # 2. Sys Standard Endpoints
    elif [[ "$PATH" == "/v1/sys/init" && "$METHOD" == "POST" ]]; then
        # Parse K and N from body if provided, otherwise default to 2-of-3
        local k
        k=$(echo "$REQ_BODY" | jq -r '.k // 2')
        local n
        n=$(echo "$REQ_BODY" | jq -r '.n // 3')
        ipc_resp_b64=$(send_ipc_cmd "INIT" "$k" "$n")
        http_status=200

    elif [[ "$PATH" == "/v1/sys/unseal" && "$METHOD" == "POST" ]]; then
        local share
        share=$(echo "$REQ_BODY" | jq -r '.share // ""')
        ipc_resp_b64=$(send_ipc_cmd "UNSEAL" "$share")
        http_status=200

    elif [[ "$PATH" == "/v1/sys/seal" && "$METHOD" == "POST" ]]; then
        ipc_resp_b64=$(send_ipc_cmd "SEAL" "$TOKEN")
        http_status=204

    elif [[ "$PATH" == "/v1/sys/health" && "$METHOD" == "GET" ]]; then
        ipc_resp_b64=$(send_ipc_cmd "HEALTH")
        http_status=200

    # 3. Auth Endpoints
    elif [[ "$PATH" == "/v1/auth/login" && "$METHOD" == "POST" ]]; then
        local username
        username=$(echo "$REQ_BODY" | jq -r '.username // ""')
        local password
        password=$(echo "$REQ_BODY" | jq -r '.password // ""')
        ipc_resp_b64=$(send_ipc_cmd "LOGIN" "$username" "$password")
        http_status=200

    elif [[ "$PATH" == "/v1/auth/revoke" && "$METHOD" == "POST" ]]; then
        local target_token
        target_token=$(echo "$REQ_BODY" | jq -r '.token // ""')
        ipc_resp_b64=$(send_ipc_cmd "REVOKE_TOKEN" "$target_token" "$TOKEN")
        http_status=204

    elif [[ "$PATH" == "/v1/auth/self" && "$METHOD" == "GET" ]]; then
        ipc_resp_b64=$(send_ipc_cmd "GET_TOKEN_SELF" "$TOKEN")
        http_status=200

    # 4. Policy Endpoints
    elif [[ "$PATH" =~ ^/v1/policies/(.+)$ ]]; then
        local name="${BASH_REMATCH[1]}"
        if [[ "$METHOD" == "PUT" ]]; then
            ipc_resp_b64=$(send_ipc_cmd "PUT_POLICY" "$name" "$REQ_BODY" "$TOKEN")
            http_status=201
        elif [[ "$METHOD" == "GET" ]]; then
            ipc_resp_b64=$(send_ipc_cmd "GET_POLICY" "$name" "$TOKEN")
            http_status=200
        else
            http_status=405
            ipc_resp_b64=$(echo '{"error": "method not allowed"}' | base64 -w0)
        fi

    # 5. Secrets Endpoints
    elif [[ "$PATH" =~ ^/v1/secrets/(.+)$ ]]; then
        local secret_path="${BASH_REMATCH[1]}"
        if [[ "$METHOD" == "PUT" ]]; then
            ipc_resp_b64=$(send_ipc_cmd "PUT_SECRET" "$secret_path" "$REQ_BODY" "$TOKEN")
            http_status=201
        elif [[ "$METHOD" == "GET" ]]; then
            # Parse version query param
            local version=""
            if [[ "$QUERY_STRING" =~ version=([0-9]+) ]]; then
                version="${BASH_REMATCH[1]}"
            fi
            ipc_resp_b64=$(send_ipc_cmd "GET_SECRET" "$secret_path" "$version" "$TOKEN")
            http_status=200
        elif [[ "$METHOD" == "DELETE" ]]; then
            ipc_resp_b64=$(send_ipc_cmd "DELETE_SECRET" "$secret_path" "$TOKEN")
            http_status=204
        else
            http_status=405
            ipc_resp_b64=$(echo '{"error": "method not allowed"}' | base64 -w0)
        fi

    # 6. Dynamic Secrets Endpoints
    elif [[ "$PATH" =~ ^/v1/dynamic-postgres/(.+)$ ]]; then
        local role="${BASH_REMATCH[1]}"
        if [[ "$METHOD" == "GET" ]]; then
            ipc_resp_b64=$(send_ipc_cmd "GET_DYNAMIC" "$role" "$TOKEN")
            http_status=200
        else
            http_status=405
            ipc_resp_b64=$(echo '{"error": "method not allowed"}' | base64 -w0)
        fi

    # 7. Lease Endpoints
    elif [[ "$PATH" =~ ^/v1/leases/(.+)/renew$ ]]; then
        local lease_id="${BASH_REMATCH[1]}"
        if [[ "$METHOD" == "POST" ]]; then
            # Get increment TTL from body if provided, else default 300
            local inc
            inc=$(echo "$REQ_BODY" | jq -r '.increment // 300')
            ipc_resp_b64=$(send_ipc_cmd "RENEW_LEASE" "$lease_id" "$inc" "$TOKEN")
            http_status=200
        else
            http_status=405
            ipc_resp_b64=$(echo '{"error": "method not allowed"}' | base64 -w0)
        fi

    elif [[ "$PATH" =~ ^/v1/leases/(.+)/revoke$ ]]; then
        local lease_id="${BASH_REMATCH[1]}"
        if [[ "$METHOD" == "POST" ]]; then
            ipc_resp_b64=$(send_ipc_cmd "REVOKE_LEASE" "$lease_id" "$TOKEN")
            http_status=204
        else
            http_status=405
            ipc_resp_b64=$(echo '{"error": "method not allowed"}' | base64 -w0)
        fi

    # 8. Audit Endpoints
    elif [[ "$PATH" == "/v1/audit" && "$METHOD" == "GET" ]]; then
        local filter_token=""
        if [[ "$QUERY_STRING" =~ token=([^&]+) ]]; then
            filter_token="${BASH_REMATCH[1]}"
        fi
        ipc_resp_b64=$(send_ipc_cmd "GET_AUDIT" "$filter_token" "$TOKEN")
        http_status=200

    else
        http_status=404
        ipc_resp_b64=$(echo '{"error": "endpoint not found"}' | base64 -w0)
    fi

    # Decode response
    http_body=$(echo -n "$ipc_resp_b64" | base64 -d)

    # If response has an error field, map to correct HTTP status codes
    if [[ -n "$http_body" ]]; then
        local err
        err=$(echo "$http_body" | jq -r '.error // empty')
        if [[ -n "$err" ]]; then
            case "$err" in
                "vault is sealed"|"daemon offline") http_status=503 ;;
                "not leader"|"not_leader")
                    http_status=307
                    # Extract leader address
                    local leader_url
                    leader_url=$(echo "$http_body" | jq -r '.leader // empty')
                    if [[ -n "$leader_url" ]]; then
                        export REDIRECT_LOCATION="${leader_url}${PATH}"
                        if [[ -n "$QUERY_STRING" ]]; then
                            REDIRECT_LOCATION+="?${QUERY_STRING}"
                        fi
                    fi
                    ;;
                "unauthorized"|"token invalid"|"token expired") http_status=401 ;;
                "forbidden"|"permission denied") http_status=403 ;;
                "not found"|"secret not found"|"lease not found") http_status=404 ;;
                "quorum lost"|"consensus write replication failed") http_status=503 ;;
                *) http_status=400 ;;
            esac
        fi
    fi

    # Send HTTP response
    http_respond "$http_status" "$http_body"
}

# HTTP status sender
http_respond() {
    local status="$1"
    local body="$2"
    local status_text="OK"
    case "$status" in
        200) status_text="OK" ;;
        201) status_text="Created" ;;
        204) status_text="No Content" ;;
        307) status_text="Temporary Redirect" ;;
        400) status_text="Bad Request" ;;
        401) status_text="Unauthorized" ;;
        403) status_text="Forbidden" ;;
        404) status_text="Not Found" ;;
        405) status_text="Method Not Allowed" ;;
        500) status_text="Internal Server Error" ;;
        503) status_text="Service Unavailable" ;;
    esac

    local len=0
    if [[ -n "$body" && "$status" != "204" ]]; then
        len=$(echo -ne "$body" | wc -c)
    fi

    echo -ne "HTTP/1.1 $status $status_text\r\n"
    echo -ne "Content-Type: application/json\r\n"
    echo -ne "Content-Length: $len\r\n"
    if [[ "$status" == "307" && -n "$REDIRECT_LOCATION" ]]; then
        echo -ne "Location: $REDIRECT_LOCATION\r\n"
    fi
    echo -ne "Connection: close\r\n\r\n"
    if [[ -n "$body" && "$status" != "204" ]]; then
        echo -ne "$body"
    fi
}

handle_http_request
