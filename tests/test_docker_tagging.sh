#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
docker run -d --name z4-tagging -p 8080:8080 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:8080/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-tagging || true
}
trap cleanup EXIT

echo "Creating bucket..."
curl -X PUT http://localhost:8080/tag-bucket

echo "Putting object..."
curl -X PUT -d "Test Content" http://localhost:8080/tag-bucket/test.txt

echo "Putting object tags..."
curl -X PUT "http://localhost:8080/tag-bucket/test.txt?tagging" -d "env=prod&team=platform&version=1.0"

echo "Getting object tags..."
TAGS=$(curl -s "http://localhost:8080/tag-bucket/test.txt?tagging")
echo "Tags: $TAGS"

if echo "$TAGS" | grep -q "env"; then
    echo "SUCCESS: Found env tag"
else
    echo "FAILURE: Missing env tag"
    exit 1
fi

if echo "$TAGS" | grep -q "team"; then
    echo "SUCCESS: Found team tag"
else
    echo "FAILURE: Missing team tag"
    exit 1
fi

echo "Putting bucket tags..."
curl -X PUT "http://localhost:8080/tag-bucket?tagging" -d "purpose=testing&owner=ci"

echo "Getting bucket tags..."
BTAGS=$(curl -s "http://localhost:8080/tag-bucket?tagging")
echo "Bucket Tags: $BTAGS"

if echo "$BTAGS" | grep -q "purpose"; then
    echo "SUCCESS: Found bucket purpose tag"
else
    echo "FAILURE: Missing bucket purpose tag"
    exit 1
fi

echo "Deleting object tags..."
curl -X DELETE "http://localhost:8080/tag-bucket/test.txt?tagging"

echo "Verifying tags deleted..."
TAGS_AFTER=$(curl -s "http://localhost:8080/tag-bucket/test.txt?tagging")
if echo "$TAGS_AFTER" | grep -q "<TagSet></TagSet>"; then
    echo "SUCCESS: Tags deleted (empty TagSet)"
else
    echo "FAILURE: Tags should be empty, got: $TAGS_AFTER"
    exit 1
fi

echo "ALL TAGGING TESTS PASSED"
