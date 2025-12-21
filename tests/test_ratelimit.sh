#!/bin/bash
set -e

# Configuration
PORT=9100
GOSSIP_PORT=9101
DATA_DIR="data_ratelimit_test"
SERVER_PID=""

# Cleanup function
cleanup() {
    echo "Stopping server..."
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

# Setup
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

# Start Server
echo "Building z4..."
zig build

echo "Starting z4 server..."
./zig-out/bin/z4 --port $PORT --gossip-port $GOSSIP_PORT --storage "$DATA_DIR" --no-auth > "$DATA_DIR/server.log" 2>&1 &
SERVER_PID=$!

# Wait for server
echo "Waiting for server (PID: $SERVER_PID)..."
for i in {1..30}; do
    if curl -s "http://localhost:$PORT/health" > /dev/null; then
        echo "Server is up!"
        break
    fi
    sleep 0.1
done

# Test Rate Limiting (IP)
echo "Testing IP Rate Limiting..."
echo "Sending 300 requests rapidly..."

# We expect burst of 200. Sending 300 rapid requests should trigger limit.
# Use Apache Bench for flooding
echo "Flooding server with 300 requests (concurrency 10)..."
set +e
ab -r -n 300 -c 10 "http://127.0.0.1:$PORT/health" > "$DATA_DIR/ab_output.txt" 2>&1
AB_EXIT=$?
set -e
echo "AB Exit Code: $AB_EXIT"

cat "$DATA_DIR/ab_output.txt"

# Analyze Results
NON_2XX=$(grep "Non-2xx responses:" "$DATA_DIR/ab_output.txt" | awk '{print $3}')

if [ -z "$NON_2XX" ]; then
    NON_2XX=0 # If line missing, might be all 200 OK (0 non-2xx is usually omitted by ab?) 
    # check Complete requests vs Failed requests
fi

echo "Non-2xx responses: $NON_2XX"

if [ "$NON_2XX" -eq 0 ]; then
    # Maybe ab output format differs.
    # If all 200, "Non-2xx responses" line is NOT present.
    # So we must verify if we expected failures.
    echo "FAILURE: IP Rate limiting did not trigger (0 Non-2xx)"
    # Double check if any failed request
    grep "Failed requests" "$DATA_DIR/ab_output.txt"
    exit 1
fi

echo "SUCCESS: IP Rate limiting triggered ($NON_2XX rejected)"



# Test Recovery
echo "Waiting 1 second for refill..."
sleep 1.1

code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT/health")
if [ "$code" != "200" ]; then
    echo "FAILURE: Rate limit did not recover (got $code)"
    exit 1
fi

echo "SUCCESS: Rate limit recovered"
echo "=== ALL RATE LIMIT TESTS PASSED ==="
