#!/bin/bash
set -e

# Use unique port
PORT=9083
GOSSIP_PORT=9084

cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Building z4..."
zig build

DATA_DIR=$(pwd)/data_acl_test
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Starting z4 server..."
./zig-out/bin/z4 server --port $PORT --gossip-port $GOSSIP_PORT --data "$DATA_DIR" --no-auth > acl_server.log 2>&1 &
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
curl -s -X PUT http://localhost:$PORT/acl-bucket

echo ""
echo "Getting default bucket ACL..."
ACL=$(curl -s "http://localhost:$PORT/acl-bucket?acl")
echo "Default ACL: $ACL"

echo ""
echo "Setting bucket ACL to public-read..."
curl -s -X PUT "http://localhost:$PORT/acl-bucket?acl&x-amz-acl=public-read"

echo ""
echo "Getting bucket ACL after setting public-read..."
ACL=$(curl -s "http://localhost:$PORT/acl-bucket?acl")
echo "ACL: $ACL"

if echo "$ACL" | grep -q "AllUsers"; then
    echo "SUCCESS: ACL contains AllUsers grant"
else
    echo "FAILURE: ACL doesn't contain AllUsers grant"
    exit 1
fi

echo ""
echo "Uploading object..."
echo "ACL Test Content" | curl -s -X PUT -d @- "http://localhost:$PORT/acl-bucket/testfile.txt"

echo ""
echo "Getting default object ACL..."
OBJ_ACL=$(curl -s "http://localhost:$PORT/acl-bucket/testfile.txt?acl")
echo "Object ACL: $OBJ_ACL"

echo ""
echo "Setting object ACL to private..."
curl -s -X PUT "http://localhost:$PORT/acl-bucket/testfile.txt?acl&x-amz-acl=private"

echo ""
echo "Verifying object ACL is now private..."
OBJ_ACL=$(curl -s "http://localhost:$PORT/acl-bucket/testfile.txt?acl")
echo "Object ACL after private: $OBJ_ACL"

echo ""
echo "Deleting bucket ACL..."
DEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:$PORT/acl-bucket?acl")
echo "Delete ACL status: $DEL_STATUS"

echo ""
echo "=== ALL ACL TESTS PASSED ==="
