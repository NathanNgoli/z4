#!/bin/bash
set -e

# Use unique port
PORT=9077
GOSSIP_PORT=9078

cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Building z4..."
zig build

DATA_DIR=$(pwd)/data_health_test
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Starting z4 server..."
./zig-out/bin/z4 server --port $PORT --gossip-port $GOSSIP_PORT --data "$DATA_DIR" --no-auth > health_server.log 2>&1 &
SERVER_PID=$!

echo "Waiting for server (PID: $SERVER_PID)..."
for i in {1..15}; do
    if curl -s http://localhost:$PORT/ > /dev/null 2>&1; then
        echo "Server is up!"
        break
    fi
    sleep 0.5
done

echo ""
echo "Testing /health endpoint..."
HEALTH=$(curl -s http://localhost:$PORT/health)
echo "Health response: $HEALTH"

if echo "$HEALTH" | grep -q "healthy"; then
    echo "SUCCESS: Health check returns healthy"
else
    echo "FAILURE: Health check did not return healthy"
    echo "Got: $HEALTH"
    cat health_server.log
    exit 1
fi

if echo "$HEALTH" | grep -q "z4"; then
    echo "SUCCESS: Health check returns service name"
else
    echo "FAILURE: Health check did not return service name"
    exit 1
fi

echo ""
echo "Testing /health/ endpoint (with trailing slash)..."
HEALTH2=$(curl -s http://localhost:$PORT/health/)
echo "Health/ response: $HEALTH2"

if echo "$HEALTH2" | grep -q "healthy"; then
    echo "SUCCESS: /health/ also returns healthy"
else
    echo "FAILURE: /health/ did not return healthy"
    exit 1
fi

echo ""
echo "Verifying health check HTTP status code..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$PORT/health)
if [ "$STATUS" = "200" ]; then
    echo "SUCCESS: Health check returns 200 OK"
else
    echo "FAILURE: Health check returned $STATUS"
    exit 1
fi

echo ""
echo "=== ALL HEALTH CHECK TESTS PASSED ==="
