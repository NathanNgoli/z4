#!/bin/bash
set -e

# Build the main server
echo "Building Z4..."
zig build

# Build the stress test tool
echo "Building stress test..."
zig build-exe tests/stress_memory.zig --name stress_tool

# Start the server
echo "Starting Z4 server..."
./zig-out/bin/z4 server --port 8080 --data perf_data --debug > server.log 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
sleep 2

# Create bucket via CLI
echo "Creating bucket..."
./zig-out/bin/z4 bucket create stress-bucket --data perf_data

# Start memory monitor in background
echo "Monitoring memory usage..."
(
    while kill -0 $SERVER_PID 2>/dev/null; do
        RSS=$(ps -p $SERVER_PID -o rss= | tr -d ' ')
        if [ -n "$RSS" ]; then
            # Convert KB to MB
            MB=$((RSS / 1024))
            echo "Memory: ${MB}MB"
        fi
        sleep 1
    done
) > memory_log.txt &
MONITOR_PID=$!

# Run the stress test (20 concurrent uploads of 100MB each)
echo "Running stress test (20 concurrent 100MB uploads, total 2GB)..."
./stress_tool --endpoint http://127.0.0.1:8080 --concurrency 20 --size-mb 100

# Stop server and monitor
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
kill $MONITOR_PID 2>/dev/null || true

# Report Peak Memory
MAX_MEM=$(grep "Memory:" memory_log.txt | awk '{print $2}' | sed 's/MB//' | sort -rn | head -n 1)
echo "------------------------------------------------"
echo "Peak RAM Usage: ${MAX_MEM}MB"
echo "------------------------------------------------"

# Clean up
rm stress_tool stress_tool.o 2>/dev/null || true
rm memory_log.txt
rm server.log 2>/dev/null || true
rm -rf perf_data
