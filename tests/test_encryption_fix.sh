#!/bin/bash
set -e

echo "Building z4 for encryption test..."
zig build

echo "Stopping any existing containers..."
docker rm -f z4-enc >/dev/null 2>&1 || true
rm -rf $(pwd)/data_enc 2>/dev/null || true
mkdir -p $(pwd)/data_enc

# Generate a 32-byte key (hex is 64 chars)
ENC_KEY="0123456789012345678901234567890101234567890123456789012345678901"

echo "Starting z4 with encryption..."
# We run the binary directly if possible, or use docker. 
# Docker is cleaner for env vars.
docker run -d --name z4-enc -p 9090:9670 -v $(pwd)/data_enc:/app/data -e Z4_ENCRYPTION_KEY=$ENC_KEY z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..10}; do
    if curl -s http://localhost:9090/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

echo "Creating key..."
docker exec z4-enc /app/z4 key create admin
KEY_OUT=$(docker exec z4-enc /app/z4 key list)
ACCESS_KEY=$(echo "$KEY_OUT" | grep "GK" | awk '{print $1}')
echo "Access Key: $ACCESS_KEY"

# We need the secret key to sign requests... this is annoying in bash without `s3_sign`.
# Let's trust the CLI `key create` output if we can capture it, but `key list` doesn't show secret?
# `key info` does.

INFO=$(docker exec z4-enc /app/z4 key info $ACCESS_KEY)
SECRET_KEY=$(echo "$INFO" | grep "Secret key:" | awk '{print $3}' | tr -d '\r')
echo "Secret Key: $SECRET_KEY"

# Source signer
source tests/sign_s3.sh

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
        curl -s -v -X $method \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             -d "$body" \
             "$url"
    else
        curl -s -v -X $method \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             "$url"
    fi
}

echo "Creating bucket 'enc-bucket'..."
sign_and_curl "PUT" "http://localhost:9090/enc-bucket" "$ACCESS_KEY" "$SECRET_KEY" ""

echo "Putting object 'secret.txt'..."
DATA="This is a secret message that should be encrypted on disk."
sign_and_curl "PUT" "http://localhost:9090/enc-bucket/secret.txt" "$ACCESS_KEY" "$SECRET_KEY" "$DATA"

echo "Verifying retrieval (decryption)..."
GET_URL="http://localhost:9090/enc-bucket/secret.txt"
headers=$(s3_sign "GET" "$GET_URL" "$ACCESS_KEY" "$SECRET_KEY" "")
auth=$(echo "$headers" | grep "Authorization:" | sed 's/Authorization: //')
date=$(echo "$headers" | grep "x-amz-date:" | sed 's/x-amz-date: //')
hash=$(echo "$headers" | grep "x-amz-content-sha256:" | sed 's/x-amz-content-sha256: //')

RETRIEVED=$(curl -s -H "Authorization: $auth" -H "x-amz-date: $date" -H "x-amz-content-sha256: $hash" "$GET_URL")

if [ "$RETRIEVED" == "$DATA" ]; then
    echo "SUCCESS: Retrieved data matches original."
else
    echo "FAILURE: Retrieved '$RETRIEVED', expected '$DATA'"
    exit 1
fi

echo "Verifying encryption on disk..."
# Find the file in data_enc
# Directory structure: data_enc/enc-bucket/hash/hash/secret.txt
FILE=$(find data_enc/enc-bucket -type f -name "secret.txt")
echo "Inspecting file: $FILE"
CONTENT=$(cat "$FILE")

if [[ "$CONTENT" == *"$DATA"* ]]; then
    echo "FAILURE: Found plaintext data in file!"
    exit 1
else
    echo "SUCCESS: File content on disk does not match plaintext."
fi

docker rm -f z4-enc
echo "Test Passed!"
