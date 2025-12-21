#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
docker run -d --name z4-versioning -p 9670:9670 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:9670/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-versioning || true
}
trap cleanup EXIT

echo "Creating bucket..."
curl -X PUT http://localhost:9670/ver-bucket

echo "Getting versioning (should be empty/disabled)..."
VER_CONFIG=$(curl -s "http://localhost:9670/ver-bucket?versioning")
echo "Versioning Config: $VER_CONFIG"

if echo "$VER_CONFIG" | grep -q "VersioningConfiguration"; then
    echo "SUCCESS: Got versioning configuration response"
else
    echo "FAILURE: Missing versioning configuration"
    exit 1
fi

echo "Enabling versioning..."
curl -X PUT "http://localhost:9670/ver-bucket?versioning" -d '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>'

echo "Getting versioning (should be Enabled)..."
VER_ENABLED=$(curl -s "http://localhost:9670/ver-bucket?versioning")
echo "Versioning Config: $VER_ENABLED"

if echo "$VER_ENABLED" | grep -q "Enabled"; then
    echo "SUCCESS: Versioning is Enabled"
else
    echo "FAILURE: Versioning should be Enabled"
    exit 1
fi

echo "Suspending versioning..."
curl -X PUT "http://localhost:9670/ver-bucket?versioning" -d '<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>'

echo "Getting versioning (should be Suspended)..."
VER_SUSPENDED=$(curl -s "http://localhost:9670/ver-bucket?versioning")
echo "Versioning Config: $VER_SUSPENDED"

if echo "$VER_SUSPENDED" | grep -q "Suspended"; then
    echo "SUCCESS: Versioning is Suspended"
else
    echo "FAILURE: Versioning should be Suspended"
    exit 1
fi

echo "ALL VERSIONING TESTS PASSED"
