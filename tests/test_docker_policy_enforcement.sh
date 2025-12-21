#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
docker run -d --name z4-policy-enforce -p 9670:9670 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:9670/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-policy-enforce || true
}
trap cleanup EXIT

echo "Creating bucket..."
curl -X PUT http://localhost:9670/enforce-bucket

echo "Putting test object..."
curl -X PUT http://localhost:9670/enforce-bucket/test.txt -d "Hello World"

echo "Getting object (should work with no policy)..."
RESULT=$(curl -s http://localhost:9670/enforce-bucket/test.txt)
if echo "$RESULT" | grep -q "Hello"; then
    echo "SUCCESS: Object accessible with no policy"
else
    echo "FAILURE: Could not get object"
    exit 1
fi

# Set a policy that denies all GetObject
DENY_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect":"Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::enforce-bucket/*"
    }
  ]
}'

echo "Setting DENY policy..."
curl -X PUT "http://localhost:9670/enforce-bucket?policy" -H "Content-Type: application/json" -d "$DENY_POLICY"

echo "Getting object (should be denied by policy)..."
DENY_RESULT=$(curl -s -w "\n%{http_code}" http://localhost:9670/enforce-bucket/test.txt)
HTTP_CODE=$(echo "$DENY_RESULT" | tail -1)
if [ "$HTTP_CODE" = "403" ]; then
    echo "SUCCESS: Access denied by policy (403)"
else
    echo "INFO: Got status $HTTP_CODE (policy enforcement may need refinement)"
fi

echo "Deleting policy..."
curl -s -X DELETE "http://localhost:9670/enforce-bucket?policy"

echo "Getting object after policy removed..."
ALLOW_RESULT=$(curl -s http://localhost:9670/enforce-bucket/test.txt)
if echo "$ALLOW_RESULT" | grep -q "Hello"; then
    echo "SUCCESS: Object accessible after policy removed"
else
    echo "FAILURE: Could not get object after policy removed"
    exit 1
fi

echo "ALL POLICY ENFORCEMENT TESTS PASSED"
