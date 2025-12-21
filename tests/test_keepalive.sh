#!/bin/bash
set -e

PORT=9301
DATA_DIR="data_keepalive_test"
LOG_FILE="$DATA_DIR/server.log"

cleanup() {
    echo "Stopping server..."
    pkill -P $$ || true
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Building z4..."
zig build

echo "Starting z4 server..."
./zig-out/bin/z4 --port $PORT --storage "$DATA_DIR" --no-auth > "$LOG_FILE" 2>&1 &
SERVER_PID=$!

echo "Waiting for server..."
sleep 2

echo "Testing Keep-Alive..."
# Send two requests in one connection using nc (or curl sequential)
# We expect two XML responses.

# Use curl to request two URLs sequentially. Curl reuses connections by default.
curl -v "http://localhost:$PORT/" "http://localhost:$PORT/health" > "$DATA_DIR/curl_out.txt" 2>&1

echo "Curl Output:"
cat "$DATA_DIR/curl_out.txt"

# Check for connection reuse indicators
# "Re-using existing connection" or "Connection #0 to host" staying open.
# If connection is closed, curl says "Closing connection 0".
# If reused, it says "Re-using existing connection".

if grep -q "Re-using existing connection" "$DATA_DIR/curl_out.txt"; then
    echo "SUCCESS: Connection reused."
elif grep -c "Connected to localhost" "$DATA_DIR/curl_out.txt" | grep -q "1"; then
    # Alternative check: strict count of "Connected to localhost" should be 1 if reused.
    echo "SUCCESS: Connection established only once."
else
    echo "FAILURE: Connection NOT reused."
    exit 1
fi


echo "=== KEEP-ALIVE VERIFIED ==="
