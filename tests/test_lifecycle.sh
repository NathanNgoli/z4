#!/bin/bash
set -e

# Use unique port
PORT=9079
GOSSIP_PORT=9080

cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Building z4..."
zig build

DATA_DIR=$(pwd)/data_lifecycle_test
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Starting z4 server..."
./zig-out/bin/z4 server --port $PORT --gossip-port $GOSSIP_PORT --data "$DATA_DIR" --no-auth > lifecycle_server.log 2>&1 &
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
curl -s -X PUT http://localhost:$PORT/lc-bucket

echo ""
echo "Checking lifecycle (should be 404 - not configured)..."
LC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT/lc-bucket?lifecycle")
if [ "$LC_STATUS" = "404" ]; then
    echo "SUCCESS: No lifecycle configured (404)"
else
    echo "FAILURE: Unexpected status $LC_STATUS"
    exit 1
fi

LIFECYCLE='<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration>
  <Rule>
    <ID>expire-old-objects</ID>
    <Status>Enabled</Status>
    <Expiration>
      <Days>90</Days>
    </Expiration>
  </Rule>
</LifecycleConfiguration>'

echo ""
echo "Setting lifecycle configuration..."
curl -s -X PUT "http://localhost:$PORT/lc-bucket?lifecycle" -H "Content-Type: application/xml" -d "$LIFECYCLE"

echo ""
echo "Getting lifecycle configuration..."
RETURNED_LC=$(curl -s "http://localhost:$PORT/lc-bucket?lifecycle")
echo "Lifecycle: $RETURNED_LC"

if echo "$RETURNED_LC" | grep -q "expire-old-objects"; then
    echo "SUCCESS: Found rule ID in lifecycle"
else
    echo "FAILURE: Missing rule ID in lifecycle"
    exit 1
fi

if echo "$RETURNED_LC" | grep -q "90"; then
    echo "SUCCESS: Found expiration days"
else
    echo "FAILURE: Missing expiration days"
    exit 1
fi

echo ""
echo "Deleting lifecycle configuration..."
DELETE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:$PORT/lc-bucket?lifecycle")
if [ "$DELETE_STATUS" = "204" ]; then
    echo "SUCCESS: Lifecycle deleted (204)"
else
    echo "FAILURE: Unexpected status $DELETE_STATUS"
    exit 1
fi

echo ""
echo "Verifying lifecycle deleted (should get 404)..."
GET_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT/lc-bucket?lifecycle")
if [ "$GET_STATUS" = "404" ]; then
    echo "SUCCESS: Lifecycle not found (404)"
else
    echo "FAILURE: Unexpected status $GET_STATUS"
    exit 1
fi

echo ""
echo "=== ALL LIFECYCLE TESTS PASSED ==="
