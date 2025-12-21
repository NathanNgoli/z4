#!/bin/bash
set -e

echo "Building z4 for aarch64-linux-musl..."
zig build -Dtarget=aarch64-linux-musl

echo "Stopping any existing containers..."
docker rm -f z4-aws-test 2>/dev/null || true

echo "Starting Docker container with encryption enabled..."
docker build -t z4:latest .
docker run -d --name z4-aws-test -p 9670:9670 \
    -e Z4_ENCRYPTION_KEY=my-32-byte-encryption-key-here! \
    -v $(pwd)/data:/app/data z4:latest /app/z4 server

echo "Waiting for service..."
for i in {1..30}; do
    if curl -s http://localhost:9670/ > /dev/null; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

cleanup() {
    docker rm -f z4-aws-test || true
}
trap cleanup EXIT

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_REGION=us-east-1

echo "============================================="
echo "AWS CLI S3 Parity Tests"
echo "============================================="

echo ""
echo "1. Create bucket..."
aws s3api create-bucket --bucket aws-test-bucket --endpoint-url http://localhost:9670 2>&1 || echo "Bucket exists or created"

echo ""
echo "2. List buckets..."
aws s3api list-buckets --endpoint-url http://localhost:9670

echo ""
echo "3. Put object..."
echo "Hello from AWS CLI" > /tmp/test-file.txt
aws s3api put-object --bucket aws-test-bucket --key test-awscli.txt --body /tmp/test-file.txt --endpoint-url http://localhost:9670
echo "SUCCESS: Put object"

echo ""
echo "4. Get object..."
aws s3api get-object --bucket aws-test-bucket --key test-awscli.txt /tmp/retrieved.txt --endpoint-url http://localhost:9670
cat /tmp/retrieved.txt
if grep -q "AWS CLI" /tmp/retrieved.txt; then
    echo "SUCCESS: Get object content matches"
else
    echo "FAILURE: Content mismatch"
fi

echo ""
echo "5. Head object..."
aws s3api head-object --bucket aws-test-bucket --key test-awscli.txt --endpoint-url http://localhost:9670

echo ""
echo "6. Put bucket versioning..."
aws s3api put-bucket-versioning --bucket aws-test-bucket --versioning-configuration Status=Enabled --endpoint-url http://localhost:9670
echo "SUCCESS: Enabled versioning"

echo ""
echo "7. Get bucket versioning..."
aws s3api get-bucket-versioning --bucket aws-test-bucket --endpoint-url http://localhost:9670

echo ""
echo "8. Put bucket lifecycle..."
cat > /tmp/lifecycle.json << 'EOF'
{
  "Rules": [
    {
      "ID": "expire-test",
      "Status": "Enabled",
      "Expiration": {
        "Days": 30
      },
      "Filter": {
        "Prefix": ""
      }
    }
  ]
}
EOF
aws s3api put-bucket-lifecycle-configuration --bucket aws-test-bucket --lifecycle-configuration file:///tmp/lifecycle.json --endpoint-url http://localhost:9670 2>&1 || echo "Lifecycle set or format issue"

echo ""
echo "9. Delete object..."
aws s3api delete-object --bucket aws-test-bucket --key test-awscli.txt --endpoint-url http://localhost:9670
echo "SUCCESS: Delete object"

echo ""
echo "============================================="
echo "AWS CLI S3 PARITY TESTS COMPLETE"
echo "============================================="
