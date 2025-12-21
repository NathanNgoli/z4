#!/bin/bash
set -e

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    # Wait for port to close
    sleep 0.5
}
trap cleanup EXIT

# 1. Build z4
echo "Building z4..."
zig build

# 2. Setup data dir
DATA_DIR=$(pwd)/data_debug
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

# 3. Start Server
echo "Starting z4 server..."
./zig-out/bin/z4 server --port 9099 --data "$DATA_DIR" > server_log.txt 2>&1 &
SERVER_PID=$!

# Wait for server
echo "Waiting for server..."
for i in {1..10}; do
    if curl -s http://localhost:9099/ > /dev/null; then
        echo "Server is up!"
        break
    fi
    sleep 0.5
done

# 4. Create Key
echo "Creating API key..."
KEY_OUTPUT=$(./zig-out/bin/z4 key create mykey --data "$DATA_DIR" 2>&1)
echo "$KEY_OUTPUT"
ACCESS_KEY=$(echo "$KEY_OUTPUT" | grep "Key ID:" | awk '{print $3}' | tr -d '\r')
SECRET_KEY=$(echo "$KEY_OUTPUT" | grep "Secret key:" | awk '{print $3}' | tr -d '\r')

echo "Access Key: $ACCESS_KEY"
echo "Secret Key: $SECRET_KEY"

# 5. Source signer
source tests/sign_s3.sh

# Helper
sign_and_curl() {
    local method=$1
    local url=$2
    local access=$3
    local secret=$4
    local body=$5
    local extra=$6
    
    # Extract path and query from url for signing
    # url is http://localhost:9099/path?query
    # we want /path?query
    # but s3_sign expects url to be passed? No, s3_sign expects full url or path?
    # Let's check sign_s3.sh usage.
    # It takes: method, url, access_key, secret_key, body
    # It seems to handle the parsing.
    
    local headers=$(s3_sign "$method" "$url" "$access" "$secret" "$body")
    
    local auth=$(echo "$headers" | grep "Authorization:" | sed 's/Authorization: //')
    local date=$(echo "$headers" | grep "x-amz-date:" | sed 's/x-amz-date: //')
    local hash=$(echo "$headers" | grep "x-amz-content-sha256:" | sed 's/x-amz-content-sha256: //')
    
    if [ -n "$body" ]; then
        curl -v -X "$method" \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             -H "$extra" \
             -d "$body" \
             "$url"
    else
        curl -v -X "$method" \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             -H "$extra" \
             "$url"
    fi
}

# 6. Create Bucket
echo "Creating bucket..."
sign_and_curl "PUT" "http://localhost:9099/ps-bucket" "$ACCESS_KEY" "$SECRET_KEY" "" ""

# 7. Set ACL Private
echo "Setting bucket private..."
ACL_BODY="owner=$ACCESS_KEY"
sign_and_curl "PUT" "http://localhost:9099/ps-bucket?acl" "$ACCESS_KEY" "$SECRET_KEY" "$ACL_BODY" ""

# 8. Put Object
echo "Putting object..."
DATA="Secret Data"
sign_and_curl "PUT" "http://localhost:9099/ps-bucket/secret.txt" "$ACCESS_KEY" "$SECRET_KEY" "$DATA" ""

# 9. Verify No Auth fails
echo "Testing No Auth..."
HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" http://localhost:9099/ps-bucket/secret.txt)
echo "No Auth Code: $HTTP_CODE"
if [ "$HTTP_CODE" != "403" ]; then
    echo "FAILURE: No Auth should rely 403, got $HTTP_CODE"
    cat server_log.txt
    exit 1
fi

# 10. Test Presigned URL
echo "Testing Presigned URL..."
generate_presigned_url() {
    local method="GET"
    local bucket="ps-bucket"
    local key="secret.txt"
    local region="us-east-1"
    local service="s3"
    
    local date_iso=$(date -u +"%Y%m%dT%H%M%SZ")
    local date_short=$(date -u +"%Y%m%d")
    local credential_scope="$date_short/$region/$service/aws4_request"
    
    # We MUST encode the credential slash in the param value but NOT double encode it?
    # server.zig expects query_args.
    # The credential string is "KEY/date/region/service/aws4_request".
    # When putting it in URL query param, we urlencode it.
    # bash/curl will handle it?
    
    # Wait, sign_s3.sh helper is for headers.
    # We need to manually construct the presigned URL logic in bash as per test_docker_presigned.sh
    
    # Reuse logic from test_docker_presigned.sh
    local canonical_uri="/$bucket/$key"
    local canonical_querystring="X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=$ACCESS_KEY%2F$date_short%2F$region%2F$service%2Faws4_request&X-Amz-Date=$date_iso&X-Amz-Expires=300&X-Amz-SignedHeaders=host"
    local canonical_headers="host:localhost:9099\n"
    local signed_headers="host"
    local payload_hash="UNSIGNED-PAYLOAD"
    local canonical_request="$method\n$canonical_uri\n$canonical_querystring\n$canonical_headers\n$signed_headers\n$payload_hash"
    
    local algorithm="AWS4-HMAC-SHA256"
    # Use buffer print for correct newlines
    local request_hash=$(printf "%b" "$canonical_request" | openssl dgst -sha256 | awk '{print $2}')
    local string_to_sign="$algorithm\n$date_iso\n$credential_scope\n$request_hash"
    
    local k_secret_str="AWS4$SECRET_KEY"
    local k_date=$(printf "%b" "$date_short" | openssl dgst -sha256 -mac HMAC -macopt key:"$k_secret_str" | awk '{print $2}')
    local k_region=$(printf "%b" "$region" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$k_date" | awk '{print $2}')
    local k_service=$(printf "%b" "$service" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$k_region" | awk '{print $2}')
    local k_signing=$(printf "%b" "aws4_request" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$k_service" | awk '{print $2}')
    local signature=$(printf "%b" "$string_to_sign" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$k_signing" | awk '{print $2}')
    
    echo "http://localhost:9099$canonical_uri?$canonical_querystring&X-Amz-Signature=$signature"
}

URL=$(generate_presigned_url)
echo "Trying: $URL"

FAIL=0
curl -f -v "$URL" || FAIL=1

if [ $FAIL -eq 1 ]; then
    echo "FAILURE: Presigned URL failed"
    echo "--- SERVER LOG ---"
    cat server_log.txt
    exit 1
fi

echo "SUCCESS"
