# Function to calculate HMAC-SHA256 in hex
hmac_sha256() {
    local key="$1"
    local data="$2"
    printf "%b" "$data" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$key" | awk '{print $2}'
}

# Initial Key derivation needs explicit string key
hmac_sha256_str_key() {
    local key="$1"
    local data="$2"
    printf "%b" "$data" | openssl dgst -sha256 -mac HMAC -macopt key:"$key" | awk '{print $2}'
}

s3_sign() {
    local method=$1
    local url=$2
    local access_key=$3
    local secret_key=$4
    local body=$5
    local region=${6:-"us-east-1"}
    local service=${7:-"s3"}

    # Time
    local date_iso=$(date -u +"%Y%m%dT%H%M%SZ")
    local date_short=$(date -u +"%Y%m%d")

    # Parse URL (simple parser)
    # We assume http://host:port/bucket/key?query
    local proto_removed="${url#*://}"
    local host_port="${proto_removed%%/*}"
    local uri_query="/${proto_removed#*/}"
    local uri_path="${uri_query%%\?*}"
    local query_string="${uri_query#*\?}"
    if [ "$query_string" == "$uri_query" ]; then query_string=""; fi
    
    # Canonical URI
    local canonical_uri="$uri_path"
    if [ -z "$canonical_uri" ]; then canonical_uri="/"; fi

    # Canonical Query String
    local canonical_querystring=""
    if [ -n "$query_string" ]; then
        # Sort query params
        local sorted_query=$(echo "$query_string" | tr '&' '\n' | sort | tr '\n' '&')
        # Remove trailing &
        sorted_query="${sorted_query%&}"
        
        # Normalize keys/values (append = if missing)
        local IFS='&'
        local buffer=""
        for part in $sorted_query; do
            if [[ "$part" != *"="* ]]; then
                part="$part="
            fi
            buffer="${buffer}&${part}"
        done
        canonical_querystring="${buffer#&}"
    fi

    # Payload Hash
    local payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if [ -n "$body" ]; then
        payload_hash=$(printf "%b" "$body" | openssl dgst -sha256 | awk '{print $2}')
    fi

    # Canonical Headers
    local canonical_headers="host:$host_port\nx-amz-content-sha256:$payload_hash\nx-amz-date:$date_iso\n"
    local signed_headers="host;x-amz-content-sha256;x-amz-date"

    # Canonical Request
    local canonical_request="$method\n$canonical_uri\n$canonical_querystring\n$canonical_headers\n$signed_headers\n$payload_hash"
    
    # String to Sign
    local algorithm="AWS4-HMAC-SHA256"
    local credential_scope="$date_short/$region/$service/aws4_request"
    local request_hash=$(printf "%b" "$canonical_request" | openssl dgst -sha256 | awk '{print $2}')
    local string_to_sign="$algorithm\n$date_iso\n$credential_scope\n$request_hash"

    # Signature Calculation
    local k_secret_str="AWS4$secret_key"
    local k_date=$(hmac_sha256_str_key "$k_secret_str" "$date_short")
    local k_region=$(hmac_sha256 "$k_date" "$region")
    local k_service=$(hmac_sha256 "$k_region" "$service")
    local k_signing=$(hmac_sha256 "$k_service" "aws4_request")
    local signature=$(hmac_sha256 "$k_signing" "$string_to_sign")

    # Authorization Header
    local auth_header="$algorithm Credential=$access_key/$credential_scope, SignedHeaders=$signed_headers, Signature=$signature"

    echo "Authorization: $auth_header"
    echo "x-amz-date: $date_iso"
    echo "x-amz-content-sha256: $payload_hash"
}
