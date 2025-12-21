#!/bin/bash
set -e

# Use unique port
PORT=9087
GOSSIP_PORT=9088

cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Building z4..."
zig build

DATA_DIR=$(pwd)/data_tagging_test
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Starting z4 server..."
./zig-out/bin/z4 server --port $PORT --gossip-port $GOSSIP_PORT --data "$DATA_DIR" --no-auth > tagging_server.log 2>&1 &
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
curl -s -X PUT http://localhost:$PORT/tag-bucket

echo ""
echo "Setting bucket tagging..."
BUCKET_TAGS='<?xml version="1.0" encoding="UTF-8"?>
<Tagging>
  <TagSet>
    <Tag>
      <Key>Environment</Key>
      <Value>Production</Value>
    </Tag>
    <Tag>
      <Key>Department</Key>
      <Value>Engineering</Value>
    </Tag>
  </TagSet>
</Tagging>'

curl -s -X PUT "http://localhost:$PORT/tag-bucket?tagging" -H "Content-Type: application/xml" -d "$BUCKET_TAGS"

echo ""
echo "Getting bucket tagging..."
TAGS=$(curl -s "http://localhost:$PORT/tag-bucket?tagging")
echo "Bucket Tags: $TAGS"

if echo "$TAGS" | grep -q "Environment"; then
    echo "SUCCESS: Found Environment tag"
else
    echo "FAILURE: Missing Environment tag"
    exit 1
fi

if echo "$TAGS" | grep -q "Production"; then
    echo "SUCCESS: Found Production value"
else
    echo "FAILURE: Missing Production value"
    exit 1
fi

echo ""
echo "Uploading object..."
echo "Tagged Content" | curl -s -X PUT -d @- "http://localhost:$PORT/tag-bucket/tagged-file.txt"

echo ""
echo "Setting object tagging..."
OBJECT_TAGS='<?xml version="1.0" encoding="UTF-8"?>
<Tagging>
  <TagSet>
    <Tag>
      <Key>FileType</Key>
      <Value>Document</Value>
    </Tag>
  </TagSet>
</Tagging>'

curl -s -X PUT "http://localhost:$PORT/tag-bucket/tagged-file.txt?tagging" -H "Content-Type: application/xml" -d "$OBJECT_TAGS"

echo ""
echo "Getting object tagging..."
OBJ_TAGS=$(curl -s "http://localhost:$PORT/tag-bucket/tagged-file.txt?tagging")
echo "Object Tags: $OBJ_TAGS"

if echo "$OBJ_TAGS" | grep -q "FileType"; then
    echo "SUCCESS: Found FileType tag"
else
    echo "FAILURE: Missing FileType tag"
    exit 1
fi

echo ""
echo "Deleting bucket tagging..."
DEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:$PORT/tag-bucket?tagging")
echo "Delete bucket tags status: $DEL_STATUS"

echo ""
echo "Deleting object tagging..."
DEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:$PORT/tag-bucket/tagged-file.txt?tagging")
echo "Delete object tags status: $DEL_STATUS"

echo ""
echo "=== ALL TAGGING TESTS PASSED ==="
