#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
docker run -d --name z4-meta -p 9670:9670 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:9670/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-meta || true
}
trap cleanup EXIT

echo "Creating bucket..."
curl -v -X PUT http://localhost:9670/meta-bucket

echo "Putting object with Metadata..."
curl -v -X PUT \
  -H "Content-Type: text/plain" \
  -H "x-amz-meta-author: carsen" \
  -H "x-amz-meta-version: 1.0" \
  -d "Metadata Test" \
  http://localhost:9670/meta-bucket/meta.txt

echo "Verifying HEAD metadata..."
HEAD_OUTPUT=$(curl -I -s http://localhost:9670/meta-bucket/meta.txt)
echo "$HEAD_OUTPUT"

if echo "$HEAD_OUTPUT" | grep -i "x-amz-meta-author: carsen"; then
    echo "SUCCESS: Found author metadata in HEAD"
else
    echo "FAILURE: Missing author metadata in HEAD"
    exit 1
fi

if echo "$HEAD_OUTPUT" | grep -i "x-amz-meta-version: 1.0"; then
    echo "SUCCESS: Found version metadata in HEAD"
else
    echo "FAILURE: Missing version metadata in HEAD"
    exit 1
fi

echo "Verifying GET metadata..."
GET_OUTPUT=$(curl -i -s http://localhost:9670/meta-bucket/meta.txt)
if echo "$GET_OUTPUT" | grep -i "x-amz-meta-author: carsen"; then
    echo "SUCCESS: Found author metadata in GET"
else
    echo "FAILURE: Missing author metadata in GET"
    exit 1
fi

echo "ALL METADATA TESTS PASSED"
