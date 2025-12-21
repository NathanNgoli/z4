#!/bin/bash
set -e

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    pkill -f "z4 server --port 9096" 2>/dev/null || true
    sleep 0.5
}
trap cleanup EXIT

echo "Building z4..."
zig build

# Setup data dir
DATA_DIR=$(pwd)/data_keyenc_test
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

# Generate a 64-char hex key (32 bytes)
ENC_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
export Z4_ENCRYPTION_KEY=$ENC_KEY

echo "Creating API key with encryption enabled..."
KEY_OUTPUT=$(./zig-out/bin/z4 key create testkey --data "$DATA_DIR" 2>&1)
echo "$KEY_OUTPUT"

ACCESS_KEY=$(echo "$KEY_OUTPUT" | grep "Key ID:" | awk '{print $3}' | tr -d '\r')
SECRET_KEY=$(echo "$KEY_OUTPUT" | grep "Secret key:" | awk '{print $3}' | tr -d '\r')

echo ""
echo "Access Key: $ACCESS_KEY"
echo "Secret Key (returned to user): $SECRET_KEY"

echo ""
echo "Checking key file on disk..."
KEY_FILE="$DATA_DIR/_z4meta/keys/testkey.key"
cat "$KEY_FILE"

echo ""
echo "Verifying secret is encrypted on disk..."
if grep -q "^secret_key=ENC:" "$KEY_FILE"; then
    echo "SUCCESS: Secret key is stored encrypted (ENC: prefix found)"
else
    echo "FAILURE: Secret key is NOT encrypted on disk"
    exit 1
fi

echo ""
echo "Verifying key retrieval decrypts correctly..."
KEY_INFO=$(./zig-out/bin/z4 key info testkey --data "$DATA_DIR" 2>&1)
echo "$KEY_INFO"

RETRIEVED_SECRET=$(echo "$KEY_INFO" | grep "Secret key:" | awk '{print $3}' | tr -d '\r')

if [ "$RETRIEVED_SECRET" == "$SECRET_KEY" ]; then
    echo ""
    echo "SUCCESS: Retrieved secret key matches original"
else
    echo ""
    echo "FAILURE: Retrieved secret '$RETRIEVED_SECRET' does not match original '$SECRET_KEY'"
    exit 1
fi

echo ""
echo "Testing server authentication with encrypted key..."
./zig-out/bin/z4 server --port 9096 --gossip-port 9095 --data "$DATA_DIR" > server_keyenc_log.txt 2>&1 &
SERVER_PID=$!

echo "Waiting for server..."
for i in {1..10}; do
    if curl -s http://localhost:9096/ > /dev/null 2>&1; then
        echo "Server is up!"
        break
    fi
    sleep 0.5
done

source tests/sign_s3.sh

echo "Creating bucket with signed request..."
headers=$(s3_sign "PUT" "http://localhost:9096/enc-key-bucket" "$ACCESS_KEY" "$SECRET_KEY" "")
auth=$(echo "$headers" | grep "Authorization:" | sed 's/Authorization: //')
date=$(echo "$headers" | grep "x-amz-date:" | sed 's/x-amz-date: //')
hash=$(echo "$headers" | grep "x-amz-content-sha256:" | sed 's/x-amz-content-sha256: //')

RESULT=$(curl -s -X PUT \
     -H "Authorization: $auth" \
     -H "x-amz-date: $date" \
     -H "x-amz-content-sha256: $hash" \
     "http://localhost:9096/enc-key-bucket")
     
echo "$RESULT"

# Check if bucket was created (no error in response)
if echo "$RESULT" | grep -q "AccessDenied\|error"; then
    echo "FAILURE: Could not authenticate with encrypted key"
    cat server_keyenc_log.txt
    exit 1
else
    echo "SUCCESS: Authenticated successfully with encrypted key!"
fi

echo ""
echo "=== ALL API KEY ENCRYPTION TESTS PASSED ==="
