#!/bin/bash
set -e

# Configuration
PORT1=9200
GOSSIP1=9201
PORT2=9202
GOSSIP2=9203
PORT3=9204
GOSSIP3=9205
DATA_DIR="data_secure_gossip"

NON_AUTH_FLAG="--no-auth"

# Cleanup
cleanup() {
    echo "Stopping nodes..."
    pkill -P $$ || true
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Building z4..."
zig build

# Start Node 1 (Secret A)
echo "Starting Node 1 (Secret A)..."
export Z4_GOSSIP_SECRET="SECRET_A"
./zig-out/bin/z4 --port $PORT1 --gossip-port $GOSSIP1 --storage "$DATA_DIR/node1" $NON_AUTH_FLAG > "$DATA_DIR/node1.log" 2>&1 &
PID1=$!

sleep 2

# Start Node 2 (Secret A) - Should Join
echo "Starting Node 2 (Secret A, Join Node 1)..."
export Z4_GOSSIP_SECRET="SECRET_A"
./zig-out/bin/z4 --port $PORT2 --gossip-port $GOSSIP2 --storage "$DATA_DIR/node2" $NON_AUTH_FLAG --join "127.0.0.1:$GOSSIP1" > "$DATA_DIR/node2.log" 2>&1 &
PID2=$!

sleep 2

# Check Node 1 logs for Node 2 join
if grep -q "z4 node joined" "$DATA_DIR/node1.log"; then
    echo "SUCCESS: Node 2 joined Node 1 (Matching Secrets)"
else
    echo "FAILURE: Node 2 failed to join Node 1"
    exit 1
fi

# Start Node 3 (Secret B) - Should Fail to Join
echo "Starting Node 3 (Secret B, Join Node 1)..."
export Z4_GOSSIP_SECRET="SECRET_B"
./zig-out/bin/z4 --port $PORT3 --gossip-port $GOSSIP3 --storage "$DATA_DIR/node3" $NON_AUTH_FLAG --join "127.0.0.1:$GOSSIP1" > "$DATA_DIR/node3.log" 2>&1 &
PID3=$!

sleep 2

# Check Node 1 logs for HMAC mismatch
if grep -q "HMAC mismatch" "$DATA_DIR/node1.log"; then
    echo "SUCCESS: Node 1 rejected Node 3 (HMAC mismatch)"
else
    echo "FAILURE: Node 1 did not report HMAC mismatch for Node 3"
    # Dump log for debugging
    cat "$DATA_DIR/node1.log"
    exit 1
fi

echo "=== SECURE GOSSIP VERIFIED ==="
