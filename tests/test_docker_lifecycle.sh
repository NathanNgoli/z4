#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker compose down || true

echo "Starting Docker container..."
docker build -t z4:latest .
docker run -d --name z4-lifecycle -p 8080:8080 -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:8080/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-lifecycle || true
}
trap cleanup EXIT

echo "Creating bucket..."
curl -X PUT http://localhost:8080/lc-bucket

echo "Checking lifecycle (should be 404 - not configured)..."
LC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/lc-bucket?lifecycle")
if [ "$LC_STATUS" = "404" ]; then
    echo "SUCCESS: No lifecycle configured (404)"
else
    echo "FAILURE: Unexpected status $LC_STATUS"
    exit 1
fi

LIFECYCLE='<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration>
  <Rule>
    <ID>expire-old-objects</ID>
    <Status>Enabled</Status>
    <Expiration>
      <Days>90</Days>
    </Expiration>
  </Rule>
</LifecycleConfiguration>'

echo "Setting lifecycle configuration..."
curl -X PUT "http://localhost:8080/lc-bucket?lifecycle" -H "Content-Type: application/xml" -d "$LIFECYCLE"

echo "Getting lifecycle configuration..."
RETURNED_LC=$(curl -s "http://localhost:8080/lc-bucket?lifecycle")
echo "Lifecycle: $RETURNED_LC"

if echo "$RETURNED_LC" | grep -q "expire-old-objects"; then
    echo "SUCCESS: Found rule ID in lifecycle"
else
    echo "FAILURE: Missing rule ID in lifecycle"
    exit 1
fi

if echo "$RETURNED_LC" | grep -q "90"; then
    echo "SUCCESS: Found expiration days"
else
    echo "FAILURE: Missing expiration days"
    exit 1
fi

echo "Deleting lifecycle configuration..."
DELETE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:8080/lc-bucket?lifecycle")
if [ "$DELETE_STATUS" = "204" ]; then
    echo "SUCCESS: Lifecycle deleted (204)"
else
    echo "FAILURE: Unexpected status $DELETE_STATUS"
    exit 1
fi

echo "Verifying lifecycle deleted (should get 404)..."
GET_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/lc-bucket?lifecycle")
if [ "$GET_STATUS" = "404" ]; then
    echo "SUCCESS: Lifecycle not found (404)"
else
    echo "FAILURE: Unexpected status $GET_STATUS"
    exit 1
fi

echo "ALL LIFECYCLE TESTS PASSED"
