#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container WITH AUTH..."
docker build -t z4:latest .

# Run without keys (we will create them)
docker rm -f z4-auth >/dev/null 2>&1 || true
# Ensure data dir is clean for fresh keys
rm -rf $(pwd)/data 2>/dev/null || true
mkdir -p $(pwd)/data
docker run -d --name z4-auth -p 9670:9670 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service to be healthy..."
for i in {1..30}; do
    if curl -s http://localhost:9670/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

# Create key and parse output
echo "Creating API key..."
KEY_OUTPUT=$(docker exec z4-auth /app/z4 key create mykey 2>&1)

# Verify key list works
echo "Verifying key list..."
docker exec z4-auth /app/z4 key list 2>&1 || echo "Key list failed"
ACCESS_KEY=$(echo "$KEY_OUTPUT" | grep "Key ID:" | awk '{print $3}' | tr -d '\r')
SECRET_KEY=$(echo "$KEY_OUTPUT" | grep "Secret key:" | awk '{print $3}' | tr -d '\r')

echo "Created Key: $ACCESS_KEY"

cleanup() {
    echo "Cleaning up..."
    docker rm -f z4-auth || true
}
trap cleanup EXIT

# Source the shared bash signer
source tests/sign_s3.sh

# Helper to capture headers from s3_sign and curl
sign_and_curl() {
    local method=$1
    local url=$2
    local access=$3
    local secret=$4
    local body=$5
    local extra=$6
    
    local headers=$(s3_sign "$method" "$url" "$access" "$secret" "$body")
    
    local auth=$(echo "$headers" | grep "Authorization:" | sed 's/Authorization: //')
    local date=$(echo "$headers" | grep "x-amz-date:" | sed 's/x-amz-date: //')
    local hash=$(echo "$headers" | grep "x-amz-content-sha256:" | sed 's/x-amz-content-sha256: //')
    
    local curl_opts="-v -X $method"
    
    if [ -n "$body" ]; then
        curl $curl_opts \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             -H "$extra" \
             -d "$body" \
             "$url"
    else
        curl $curl_opts \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             -H "$extra" \
             "$url"
    fi
}

# 1. Create Bucket
echo "Creating bucket..."
sign_and_curl "PUT" "http://localhost:9670/ps-bucket" "$ACCESS_KEY" "$SECRET_KEY" "" ""

# 1b. Set Bucket ACL to Private (Owner only)
echo "Setting bucket private..."
ACL_BODY="owner=$ACCESS_KEY"
sign_and_curl "PUT" "http://localhost:9670/ps-bucket?acl" "$ACCESS_KEY" "$SECRET_KEY" "$ACL_BODY" ""

# 2. Put Object
echo "Putting object..."
DATA="Secret Data"
sign_and_curl "PUT" "http://localhost:9670/ps-bucket/secret.txt" "$ACCESS_KEY" "$SECRET_KEY" "$DATA" ""

# 3. Test No Auth (Should Fail)
echo "Testing No Auth..."
HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" http://localhost:9670/ps-bucket/secret.txt)
if [ "$HTTP_CODE" == "403" ]; then
    echo "SUCCESS: Rejected no auth (403)"
else
    echo "FAILURE: Expected 403, got $HTTP_CODE"
    exit 1
fi

# 4. Test Presigned (Query Auth)
echo "Testing Presigned URL..."
generate_presigned_url() {
    local method="GET"
    local bucket="ps-bucket"
    local key="secret.txt"
    # Assuming us-east-1, s3
    
    local date_iso=$(date -u +"%Y%m%dT%H%M%SZ")
    local date_short=$(date -u +"%Y%m%d")
    local region="us-east-1"
    local service="s3"
    local expiration="300"
    
    local canonical_uri="/$bucket/$key"
    local credential_scope="$date_short/$region/$service/aws4_request"
    local signed_headers="host"
    
    # Query Params must be sorted
    local q_algo="X-Amz-Algorithm=AWS4-HMAC-SHA256"
    # Encode slash %2F in credential scope for query param
    local cred_scope_enc=$(echo "$credential_scope" | sed 's/\//%2F/g')
    local q_cred="X-Amz-Credential=$ACCESS_KEY%2F$cred_scope_enc"
    
    local q_date="X-Amz-Date=$date_iso"
    local q_exp="X-Amz-Expires=$expiration"
    local q_head="X-Amz-SignedHeaders=$signed_headers"
    
    # Canonical Querystring uses RAW values (no double encoding generally, but S3 requires specific encoding)
    # Actually, for the canonical request, we use the decoded values?
    # No, S3 canonical querystring is strict.
    # Let's trust our bash signer's logic or replicate it here carefully.
    
    # To simplify: We construct the query string manually in correct sorted order.
    # X-Amz-Credential must be URL encoded in the request URL.
    
    local canonical_querystring="X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=$ACCESS_KEY%2F$cred_scope_enc&X-Amz-Date=$date_iso&X-Amz-Expires=$expiration&X-Amz-SignedHeaders=$signed_headers"
    
    local canonical_headers="host:localhost:9670\n"
    local payload_hash="UNSIGNED-PAYLOAD"
    local canonical_request="$method\n$canonical_uri\n$canonical_querystring\n$canonical_headers\n$signed_headers\n$payload_hash"
    
    local algorithm="AWS4-HMAC-SHA256"
    local request_hash=$(printf "%b" "$canonical_request" | openssl dgst -sha256 | awk '{print $2}')
    local string_to_sign="$algorithm\n$date_iso\n$credential_scope\n$request_hash"
    
    local k_secret_str="AWS4$SECRET_KEY"
    local k_date=$(hmac_sha256_str_key "$k_secret_str" "$date_short")
    local k_region=$(hmac_sha256 "$k_date" "$region")
    local k_service=$(hmac_sha256 "$k_region" "$service")
    local k_signing=$(hmac_sha256 "$k_service" "aws4_request")
    local signature=$(hmac_sha256 "$k_signing" "$string_to_sign")
    
    echo "http://localhost:9670$canonical_uri?$canonical_querystring&X-Amz-Signature=$signature"
}

URL=$(generate_presigned_url)
echo "Trying: $URL"
CONTENT=$(curl -s "$URL")
if [ "$CONTENT" == "Secret Data" ]; then
    echo "SUCCESS: Presigned URL worked."
else
    echo "FAILURE: Presigned URL failed. Got '$CONTENT'"
    exit 1
fi

# 5. Test Bad Presigned
echo "Testing Bad Presigned..."
URL_BAD="http://localhost:9670/ps-bucket/secret.txt?X-Amz-Credential=wrongkey&X-Amz-Signature=dummy"
HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" "$URL_BAD")
if [ "$HTTP_CODE" == "403" ]; then
    echo "SUCCESS: Rejected bad presigned (403)"
else
    echo "FAILURE: Expected 403, got $HTTP_CODE"
    exit 1
fi

echo "ALL TESTS PASSED"
    echo "FAILURE: Presigned URL failed. Got '$RESPONSE'"
    docker logs z4-auth
    cleanup
    exit 1
fi

echo "SUCCESS: Presigned URL worked"
cleanup
