#!/bin/bash
set -e

# Start server in background
rm -rf data
echo "Building z4 for host..."
zig build
./zig-out/bin/z4 server --port 8080 --data data --debug > server.log 2>&1 &
PID=$!
sleep 1

cleanup() {
    kill $PID
    wait $PID || true
}
trap cleanup EXIT

# Source shared signer
source tests/sign_s3.sh

# Create key
echo "Creating key..."
./zig-out/bin/z4 key create metakey --data data > key_output.txt 2>&1
ACCESS_KEY=$(grep "Key ID:" key_output.txt | awk '{print $3}' | tr -d '\r')
SECRET_KEY=$(grep "Secret key:" key_output.txt | awk '{print $3}' | tr -d '\r')
rm key_output.txt

echo "Access Key: $ACCESS_KEY"

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

# 1. Create Bucket
echo "Creating bucket..."
AUTH_URL="http://localhost:8080/meta-bucket"
do_curl "PUT" "$AUTH_URL" "" ""

# 2. Put Object with Content-Type
echo "Putting object with Content-Type..."
OBJ_URL="http://localhost:8080/meta-bucket/hello.txt"
BODY="Hello Metadata"
do_curl "PUT" "$OBJ_URL" "$BODY" "Content-Type: text/plain"

# 3. Head Object verify
echo "Heading object..."
HEADERS=$(do_curl "HEAD" "$OBJ_URL" "" "" 2>&1)
echo "$HEADERS"

if echo "$HEADERS" | grep -q "Content-Type: text/plain"; then
    echo "SUCCESS: Content-Type is text/plain"
else
    echo "FAILURE: Content-Type mismatch"
    exit 1
fi

if echo "$HEADERS" | grep -q "Content-Length: 14"; then
    echo "SUCCESS: Content-Length is 14"
else
    echo "FAILURE: Content-Length mismatch"
    exit 1
fi

# 4. Get Object verify
echo "Getting object..."
GET_HEADERS=$(do_curl "GET" "$OBJ_URL" "" "" 2>&1)
if echo "$GET_HEADERS" | grep -q "Content-Type: text/plain"; then
    echo "SUCCESS: GET returned correct Content-Type"
else
    echo "FAILURE: GET returned wrong Content-Type"
    exit 1
fi

# 5. Multipart Abort Test (Basic)
echo "Testing Multipart Abort..."
# Init
MP_URL="http://localhost:8080/meta-bucket/mp?uploads="
UPLOAD_ID=$(do_curl "POST" "$MP_URL" "" "" | sed -n 's/.*<UploadId>\(.*\)<\/UploadId>.*/\1/p')
echo "Upload ID: $UPLOAD_ID"

# Check dir exists
if [ -d "data/meta-bucket/_multipart/$UPLOAD_ID" ]; then
    echo "Multipart dir exists."
else
    echo "Multipart dir missing!"
    exit 1
fi

# Abort
ABORT_URL="http://localhost:8080/meta-bucket/mp?uploadId=$UPLOAD_ID"
do_curl "DELETE" "$ABORT_URL" "" ""

# Check dir gone
if [ ! -d "data/meta-bucket/_multipart/$UPLOAD_ID" ]; then
    echo "SUCCESS: Multipart dir deleted."
else
    echo "FAILURE: Multipart dir still exists."
    ls -R data/meta-bucket/_multipart
    exit 1
fi

echo "ALL TESTS PASSED"
