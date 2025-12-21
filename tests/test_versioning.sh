#!/bin/bash
set -e

# Use unique port
PORT=9081
GOSSIP_PORT=9082

cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Building z4..."
zig build

DATA_DIR=$(pwd)/data_versioning_test
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Starting z4 server..."
./zig-out/bin/z4 server --port $PORT --gossip-port $GOSSIP_PORT --data "$DATA_DIR" --no-auth > versioning_server.log 2>&1 &
SERVER_PID=$!

echo "Waiting for server (PID: $SERVER_PID)..."
for i in {1..15}; do
    if curl -s http://localhost:$PORT/health > /dev/null 2>&1; then
        echo "Server is up!"
        break
    fi
    sleep 0.5
done

echo "Creating bucket..."
curl -s -X PUT http://localhost:$PORT/ver-bucket

echo ""
echo "Checking versioning status (should be 200 with no status)..."
VER_STATUS=$(curl -s "http://localhost:$PORT/ver-bucket?versioning")
echo "Initial status: $VER_STATUS"

VERSIONING_ON='<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration>
  <Status>Enabled</Status>
</VersioningConfiguration>'

echo ""
echo "Enabling versioning..."
curl -s -X PUT "http://localhost:$PORT/ver-bucket?versioning" -H "Content-Type: application/xml" -d "$VERSIONING_ON"

echo ""
echo "Checking versioning is enabled..."
VER_STATUS=$(curl -s "http://localhost:$PORT/ver-bucket?versioning")
echo "Versioning status: $VER_STATUS"

if echo "$VER_STATUS" | grep -q "Enabled"; then
    echo "SUCCESS: Versioning is Enabled"
else
    echo "FAILURE: Versioning not enabled"
    exit 1
fi

echo ""
echo "Uploading first version..."
echo "Version 1 Content" | curl -s -X PUT -d @- "http://localhost:$PORT/ver-bucket/test.txt"

echo ""
echo "Uploading second version..."
echo "Version 2 Content" | curl -s -X PUT -d @- "http://localhost:$PORT/ver-bucket/test.txt"

echo ""
echo "Getting current version..."
CURRENT=$(curl -s "http://localhost:$PORT/ver-bucket/test.txt")
echo "Current: $CURRENT"

if echo "$CURRENT" | grep -q "Version 2"; then
    echo "SUCCESS: Current version is Version 2"
else
    echo "FAILURE: Unexpected current version"
    exit 1
fi

echo ""
echo "Suspending versioning..."
VERSIONING_OFF='<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration>
  <Status>Suspended</Status>
</VersioningConfiguration>'

curl -s -X PUT "http://localhost:$PORT/ver-bucket?versioning" -H "Content-Type: application/xml" -d "$VERSIONING_OFF"

echo ""
echo "Checking versioning is suspended..."
VER_STATUS=$(curl -s "http://localhost:$PORT/ver-bucket?versioning")
echo "Versioning status: $VER_STATUS"

if echo "$VER_STATUS" | grep -q "Suspended"; then
    echo "SUCCESS: Versioning is Suspended"
else
    echo "FAILURE: Versioning not suspended"
    exit 1
fi

echo ""
echo "=== ALL VERSIONING TESTS PASSED ==="
