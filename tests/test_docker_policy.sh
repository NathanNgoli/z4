#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
docker run -d --name z4-policy -p 9670:9670 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:9670/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-policy || true
}
trap cleanup EXIT

echo "Creating bucket..."
curl -X PUT http://localhost:9670/policy-bucket

POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::policy-bucket/*"
    }
  ]
}'

echo "Setting bucket policy..."
curl -X PUT "http://localhost:9670/policy-bucket?policy" -H "Content-Type: application/json" -d "$POLICY"

echo "Getting bucket policy..."
RETURNED_POLICY=$(curl -s "http://localhost:9670/policy-bucket?policy")
echo "Policy: $RETURNED_POLICY"

if echo "$RETURNED_POLICY" | grep -q "GetObject"; then
    echo "SUCCESS: Found GetObject in policy"
else
    echo "FAILURE: Missing GetObject in policy"
    exit 1
fi

if echo "$RETURNED_POLICY" | grep -q "Allow"; then
    echo "SUCCESS: Found Allow effect"
else
    echo "FAILURE: Missing Allow effect"
    exit 1
fi

echo "Deleting bucket policy..."
DELETE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:9670/policy-bucket?policy")
if [ "$DELETE_STATUS" = "204" ]; then
    echo "SUCCESS: Policy deleted (204)"
else
    echo "FAILURE: Unexpected status $DELETE_STATUS"
    exit 1
fi

echo "Verifying policy deleted (should get 404)..."
GET_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:9670/policy-bucket?policy")
if [ "$GET_STATUS" = "404" ]; then
    echo "SUCCESS: Policy not found (404)"
else
    echo "FAILURE: Unexpected status $GET_STATUS"
    exit 1
fi

echo "ALL BUCKET POLICY TESTS PASSED"
