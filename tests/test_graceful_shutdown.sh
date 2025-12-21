#!/bin/bash
set -e

# Use unique port
PORT=9070
GOSSIP_PORT=9071

echo "Building z4..."
zig build

DATA_DIR=$(pwd)/data_shutdown_test
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Starting z4 server..."
./zig-out/bin/z4 server --port $PORT --gossip-port $GOSSIP_PORT --data "$DATA_DIR" --no-auth > shutdown_server.log 2>&1 &
SERVER_PID=$!

echo "Waiting for server (PID: $SERVER_PID)..."
for i in {1..15}; do
    if curl -s http://localhost:$PORT/health > /dev/null 2>&1; then
        echo "Server is up!"
        break
    fi
    sleep 0.5
done

echo ""
echo "Testing graceful shutdown with SIGTERM..."
kill -TERM $SERVER_PID

# Wait for graceful shutdown
sleep 2

echo ""
echo "Checking server log for graceful shutdown message..."
if grep -q "Shutting down gracefully" shutdown_server.log; then
    echo "SUCCESS: Graceful shutdown message found"
else
    echo "FAILURE: Graceful shutdown message not found"
    cat shutdown_server.log
    # Check if we should kill it
    kill -9 $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Check that process is no longer running (wait up to 10s)
for i in {1..20}; do
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "SUCCESS: Server process has exited"
        exit 0
    fi
    sleep 0.5
done

echo "FAILURE: Server process still running after 10s"
kill -9 $SERVER_PID 2>/dev/null || true
exit 1

echo ""
echo "=== ALL GRACEFUL SHUTDOWN TESTS PASSED ==="
