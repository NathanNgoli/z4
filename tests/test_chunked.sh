#!/bin/bash
set -e

# Configuration
PORT=9300
DATA_DIR="data_chunked_test"
LOG_FILE="$DATA_DIR/server.log"

# Cleanup
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

echo "Creating bucket 'chunked-bucket'..."
curl -v -X PUT "http://localhost:$PORT/chunked-bucket"

echo "Uploading chunked data (2 chunks of ~1KB)..."
# Create 1KB of data
printf 'a%.0s' {1..1024} > "$DATA_DIR/chunk1.txt"
printf 'b%.0s' {1..1024} > "$DATA_DIR/chunk2.txt"

# Use curl to send chunked upload (curl uses Transfer-Encoding: chunked automatically when reading from stdin or using specific flags, 
# but simply sending -T file sends with Content-Length if known. 
# To force chunked, we can use -H "Transfer-Encoding: chunked" and read from pipe/stdin where length is unknown to curl, 
# OR use --data-binary @file with explicit header?
# Curl splits into chunks for us if we use -H "Transfer-Encoding: chunked" and correct input.
# Simple way: explicit chunked header with @- (stdin).
echo "Creating input stream..."
cat "$DATA_DIR/chunk1.txt" "$DATA_DIR/chunk2.txt" | curl -v -X PUT -H "Transfer-Encoding: chunked" -T - "http://localhost:$PORT/chunked-bucket/chunked-object"

echo "Verifying object size..."
# Head request or Get
SIZE=$(curl -sI "http://localhost:$PORT/chunked-bucket/chunked-object" | grep -i "Content-Length" | awk '{print $2}' | tr -d '\r')
EXPECTED=2048

if [ "$SIZE" == "$EXPECTED" ]; then
    echo "SUCCESS: Object size matches ($SIZE bytes)"
else
    echo "FAILURE: Object size mismatch. Expected $EXPECTED, got $SIZE"
    exit 1
fi

echo "Verifying content..."
curl -s "http://localhost:$PORT/chunked-bucket/chunked-object" > "$DATA_DIR/downloaded.txt"
cat "$DATA_DIR/chunk1.txt" "$DATA_DIR/chunk2.txt" > "$DATA_DIR/original.txt"

if diff "$DATA_DIR/original.txt" "$DATA_DIR/downloaded.txt"; then
    echo "SUCCESS: Content matches"
else
    echo "FAILURE: Content mismatch"
    exit 1
fi

echo "=== CHUNKED ENCODING VERIFIED ==="
