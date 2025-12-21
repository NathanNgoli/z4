#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
docker run -d --name z4-encryption -p 9670:9670 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:9670/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-encryption || true
}
trap cleanup EXIT

echo "Creating bucket..."
curl -X PUT http://localhost:9670/enc-bucket

echo "Checking encryption (should be 404 - not configured)..."
ENC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:9670/enc-bucket?encryption")
if [ "$ENC_STATUS" = "404" ]; then
    echo "SUCCESS: No encryption configured (404)"
else
    echo "FAILURE: Unexpected status $ENC_STATUS"
    exit 1
fi

echo "Setting bucket encryption..."
curl -X PUT "http://localhost:9670/enc-bucket?encryption" -d '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

echo "Getting bucket encryption..."
ENC_CONFIG=$(curl -s "http://localhost:9670/enc-bucket?encryption")
echo "Encryption Config: $ENC_CONFIG"

if echo "$ENC_CONFIG" | grep -q "AES256"; then
    echo "SUCCESS: Found AES256 algorithm"
else
    echo "FAILURE: Missing AES256 algorithm"
    exit 1
fi

echo "Deleting bucket encryption..."
DELETE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:9670/enc-bucket?encryption")
if [ "$DELETE_STATUS" = "204" ]; then
    echo "SUCCESS: Encryption deleted (204)"
else
    echo "FAILURE: Unexpected status $DELETE_STATUS"
    exit 1
fi

echo "Verifying encryption deleted (should get 404)..."
GET_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:9670/enc-bucket?encryption")
if [ "$GET_STATUS" = "404" ]; then
    echo "SUCCESS: Encryption not found (404)"
else
    echo "FAILURE: Unexpected status $GET_STATUS"
    exit 1
fi

echo "ALL ENCRYPTION TESTS PASSED"
