#!/bin/bash
set -e

# Configuration
PORT=9300
GOSSIP_PORT=9301
DATA_DIR="data_audit_test"
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
# Using --no-auth for simplicity, logs will show "anonymous"
./zig-out/bin/z4 --port $PORT --gossip-port $GOSSIP_PORT --storage "$DATA_DIR" --no-auth > "$LOG_FILE" 2>&1 &
SERVER_PID=$!

echo "Waiting for server..."
sleep 2

echo "Creating bucket 'audit-bucket'..."
curl -v -X PUT "http://localhost:$PORT/audit-bucket"

echo "Putting object 'audit-object'..."
curl -v -X PUT -d "test data" "http://localhost:$PORT/audit-bucket/audit-object"

echo "Deleting object 'audit-object'..."
curl -v -X DELETE "http://localhost:$PORT/audit-bucket/audit-object"

echo "Deleting bucket 'audit-bucket'..."
curl -v -X DELETE "http://localhost:$PORT/audit-bucket"

echo "Verifying audit logs..."

# Check PutBucket
if grep -q "\[AUDIT\] .*PutBucket" "$LOG_FILE"; then
    echo "SUCCESS: Found PutBucket audit log"
else
    echo "FAILURE: PutBucket audit log missing"
    exit 1
fi

# Check PutObject
if grep -q "\[AUDIT\] .*PutObject" "$LOG_FILE"; then
    echo "SUCCESS: Found PutObject audit log"
else
    echo "FAILURE: PutObject audit log missing"
    exit 1
fi

# Check DeleteObject
if grep -q "\[AUDIT\] .*DeleteObject" "$LOG_FILE"; then
    echo "SUCCESS: Found DeleteObject audit log"
else
    echo "FAILURE: DeleteObject audit log missing"
    exit 1
fi

# Check DeleteBucket
if grep -q "\[AUDIT\] .*DeleteBucket" "$LOG_FILE"; then
    echo "SUCCESS: Found DeleteBucket audit log"
else
    echo "FAILURE: DeleteBucket audit log missing"
    exit 1
fi

echo "=== AUDIT LOGGING VERIFIED ==="
cat "$LOG_FILE" | grep "\[AUDIT\]"
