#!/bin/bash
set -e

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    pkill -f "z4 server --port 9097" 2>/dev/null || true
    sleep 0.5
}
trap cleanup EXIT

echo "Building z4..."
zig build

# Setup data dir
DATA_DIR=$(pwd)/data_expiry_test
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Starting z4 server..."
./zig-out/bin/z4 server --port 9097 --gossip-port 9096 --data "$DATA_DIR" > server_expiry_log.txt 2>&1 &

echo "Waiting for server..."
for i in {1..10}; do
    if curl -s http://localhost:9097/ > /dev/null 2>&1; then
        echo "Server is up!"
        break
    fi
    sleep 0.5
done

# Create key
echo "Creating API key..."
KEY_OUTPUT=$(./zig-out/bin/z4 key create expirytest --data "$DATA_DIR" 2>&1)
echo "$KEY_OUTPUT"

ACCESS_KEY=$(echo "$KEY_OUTPUT" | grep "Key ID:" | awk '{print $3}' | tr -d '\r')
SECRET_KEY=$(echo "$KEY_OUTPUT" | grep "Secret key:" | awk '{print $3}' | tr -d '\r')

echo "Access Key: $ACCESS_KEY"
echo "Secret Key: $SECRET_KEY"

source tests/sign_s3.sh

# Create bucket and object using signed requests
sign_and_curl() {
    local method=$1
    local url=$2
    local access=$3
    local secret=$4
    local body=$5
    
    local headers=$(s3_sign "$method" "$url" "$access" "$secret" "$body")
    local auth=$(echo "$headers" | grep "Authorization:" | sed 's/Authorization: //')
    local date=$(echo "$headers" | grep "x-amz-date:" | sed 's/x-amz-date: //')
    local hash=$(echo "$headers" | grep "x-amz-content-sha256:" | sed 's/x-amz-content-sha256: //')
    
    if [ -n "$body" ]; then
        curl -s -X $method \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             -d "$body" \
             "$url"
    else
        curl -s -X $method \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             "$url"
    fi
}

echo "Creating bucket..."
sign_and_curl "PUT" "http://localhost:9097/expiry-bucket" "$ACCESS_KEY" "$SECRET_KEY" ""

echo "Putting object..."
sign_and_curl "PUT" "http://localhost:9097/expiry-bucket/test.txt" "$ACCESS_KEY" "$SECRET_KEY" "test data"

# Generate an EXPIRED presigned URL (date in the past + 1 second expiry)
echo "Testing expired presigned URL..."
generate_expired_presigned_url() {
    local method="GET"
    local bucket="expiry-bucket"
    local key="test.txt"
    local region="us-east-1"
    local service="s3"
    
    # Use a date from 1 hour ago
    local date_iso=$(date -u -v-1H +"%Y%m%dT%H%M%SZ")
    local date_short=$(date -u -v-1H +"%Y%m%d")
    local credential_scope="$date_short/$region/$service/aws4_request"
    
    local canonical_uri="/$bucket/$key"
    local canonical_querystring="X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=$ACCESS_KEY%2F$date_short%2F$region%2F$service%2Faws4_request&X-Amz-Date=$date_iso&X-Amz-Expires=1&X-Amz-SignedHeaders=host"
    local canonical_headers="host:localhost:9097\n"
    local signed_headers="host"
    local payload_hash="UNSIGNED-PAYLOAD"
    local canonical_request="$method\n$canonical_uri\n$canonical_querystring\n$canonical_headers\n$signed_headers\n$payload_hash"
    
    local algorithm="AWS4-HMAC-SHA256"
    local request_hash=$(printf "%b" "$canonical_request" | openssl dgst -sha256 | awk '{print $2}')
    local string_to_sign="$algorithm\n$date_iso\n$credential_scope\n$request_hash"
    
    local k_secret_str="AWS4$SECRET_KEY"
    local k_date=$(printf "%b" "$date_short" | openssl dgst -sha256 -mac HMAC -macopt key:"$k_secret_str" | awk '{print $2}')
    local k_region=$(printf "%b" "$region" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$k_date" | awk '{print $2}')
    local k_service=$(printf "%b" "$service" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$k_region" | awk '{print $2}')
    local k_signing=$(printf "%b" "aws4_request" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$k_service" | awk '{print $2}')
    local signature=$(printf "%b" "$string_to_sign" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$k_signing" | awk '{print $2}')
    
    echo "http://localhost:9097$canonical_uri?$canonical_querystring&X-Amz-Signature=$signature"
}

EXPIRED_URL=$(generate_expired_presigned_url)
echo "Expired URL: $EXPIRED_URL"

HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" "$EXPIRED_URL")
echo "Response code: $HTTP_CODE"

if [ "$HTTP_CODE" == "403" ]; then
    echo "SUCCESS: Expired presigned URL correctly rejected with 403"
else
    echo "FAILURE: Expected 403 for expired URL, got $HTTP_CODE"
    echo "--- SERVER LOG ---"
    tail -20 server_expiry_log.txt
    exit 1
fi

echo ""
echo "=== EXPIRATION TEST PASSED ==="
