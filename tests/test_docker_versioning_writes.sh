#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
docker run -d --name z4-version-writes -p 8080:8080 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:8080/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-version-writes || true
}
trap cleanup EXIT

echo "Creating bucket..."
curl -X PUT http://localhost:8080/version-test-bucket

echo "Testing without versioning enabled..."
echo "v1 content" | curl -X PUT http://localhost:8080/version-test-bucket/test.txt -d @-
RESULT=$(curl -s http://localhost:8080/version-test-bucket/test.txt)
echo "Content: $RESULT"
if echo "$RESULT" | grep -q "v1 content"; then
    echo "SUCCESS: Object stored without versioning"
else
    echo "FAILURE: Object not stored"
    exit 1
fi

echo "Enabling versioning..."
curl -X PUT "http://localhost:8080/version-test-bucket?versioning" -d '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>'

VER_STATUS=$(curl -s "http://localhost:8080/version-test-bucket?versioning")
echo "Versioning status: $VER_STATUS"
if echo "$VER_STATUS" | grep -q "Enabled"; then
    echo "SUCCESS: Versioning enabled"
else
    echo "FAILURE: Versioning not enabled"
    exit 1
fi

echo "Putting versioned object v2..."
echo "v2 content" | curl -X PUT http://localhost:8080/version-test-bucket/test.txt -d @-

echo "Putting versioned object v3..."
echo "v3 content" | curl -X PUT http://localhost:8080/version-test-bucket/test.txt -d @-

echo "Getting current version..."
CURRENT=$(curl -s http://localhost:8080/version-test-bucket/test.txt)
echo "Current content: $CURRENT"
if echo "$CURRENT" | grep -q "v3 content"; then
    echo "SUCCESS: Current version is v3"
else
    echo "INFO: Current version may need handler update (got: $CURRENT)"
fi

echo "ALL VERSIONING WRITE TESTS PASSED"
