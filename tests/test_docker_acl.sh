#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
# Run without keys (we will create them)
docker rm -f z4-acl >/dev/null 2>&1 || true
rm -rf $(pwd)/data/_z4meta/keys/* 2>/dev/null || true
docker run -d --name z4-acl -p 8080:8080 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:8080/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

# Create key and parse output
echo "Creating API key..."
KEY_OUTPUT=$(docker exec z4-acl /app/z4 key create mykey 2>&1)
ACCESS_KEY=$(echo "$KEY_OUTPUT" | grep "Key ID:" | awk '{print $3}' | tr -d '\r')
SECRET_KEY=$(echo "$KEY_OUTPUT" | grep "Secret key:" | awk '{print $3}' | tr -d '\r')
echo "Created Key: $ACCESS_KEY"

cleanup() {
    docker rm -f z4-acl || true
}
trap cleanup EXIT

# Source shared signer
source tests/sign_s3.sh

# Helper function to sign and curl
do_curl() {
    local method=$1
    local url=$2
    local body=$3
    local extra_headers=$4

    local headers=$(s3_sign "$method" "$url" "$ACCESS_KEY" "$SECRET_KEY" "$body")
    local auth=$(echo "$headers" | grep "Authorization:" | sed 's/Authorization: //')
    local date=$(echo "$headers" | grep "x-amz-date:" | sed 's/x-amz-date: //')
    local hash=$(echo "$headers" | grep "x-amz-content-sha256:" | sed 's/x-amz-content-sha256: //')
    
    local curl_opts="-v"
    
    if [ "$method" == "HEAD" ]; then
        curl_opts="$curl_opts -I"
    else
        curl_opts="$curl_opts -X $method"
    fi

    if [ -n "$body" ]; then
        curl $curl_opts \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             -H "$extra_headers" \
             -d "$body" \
             "$url"
    else
        curl $curl_opts \
             -H "Authorization: $auth" \
             -H "x-amz-date: $date" \
             -H "x-amz-content-sha256: $hash" \
             -H "$extra_headers" \
             "$url"
    fi
}

echo "Creating bucket..."
AUTH_URL="http://localhost:8080/acl-bucket"
do_curl "PUT" "$AUTH_URL" "" ""

echo "Putting object..."
OBJ_URL="http://localhost:8080/acl-bucket/test.txt"
BODY="ACL Test Content"
do_curl "PUT" "$OBJ_URL" "$BODY" ""

echo "Setting bucket ACL..."
# Query param in URL
ACL_URL="http://localhost:8080/acl-bucket?acl="
ACL_BODY="owner=admin&grant=user1:READ&grant=user2:WRITE"
do_curl "PUT" "$ACL_URL" "$ACL_BODY" ""

echo "Getting bucket ACL..."
# We need body output only. do_curl prints verbose to stderr.
BACL=$(do_curl "GET" "$ACL_URL" "" "")
echo "Bucket ACL: $BACL"

if echo "$BACL" | grep -q "admin"; then
    echo "SUCCESS: Found owner in bucket ACL"
else
    echo "FAILURE: Missing owner in bucket ACL"
    exit 1
fi

if echo "$BACL" | grep -q "READ"; then
    echo "SUCCESS: Found READ permission"
else
    echo "FAILURE: Missing READ permission"
    exit 1
fi

echo "Setting object ACL..."
OBJ_ACL_URL="http://localhost:8080/acl-bucket/test.txt?acl="
OBJ_ACL_BODY="owner=fileowner&grant=reader:READ"
do_curl "PUT" "$OBJ_ACL_URL" "$OBJ_ACL_BODY" ""

echo "Getting object ACL..."
OACL=$(do_curl "GET" "$OBJ_ACL_URL" "" "")
echo "Object ACL: $OACL"

if echo "$OACL" | grep -q "fileowner"; then
    echo "SUCCESS: Found owner in object ACL"
else
    echo "FAILURE: Missing owner in object ACL"
    exit 1
fi

echo "ALL ACL TESTS PASSED"
