# Getting Started with Z4

Z4 is a high-performance, S3-compatible object storage server written in Zig.

## Features
- **S3 Protocol Support**: GET, PUT, DELETE, Multipart Uploads, and basic Bucket operations.
- **Clustering**: Gossip-based cluster membership and consistent hashing for data distribution.
- **Security**: AES-256-GCM at rest, API Key authentication, presigned URLs.
- **Performance**: Epoll-based event loop, thread pool processing, zero-allocation parsing where possible.

## Prerequisites
- **Zig**: Version 0.15.2 or later.
- **Linux** (primary) or **macOS** (supported). Windows is currently experimental.

## Quick Start

### 1. Build
```bash
git clone https://github.com/metaspartan/z4.git
cd z4
zig build -Doptimize=ReleaseSafe
```

### 2. Run
```bash
# Start a standalone node on port 9000
./zig-out/bin/z4 --port 9000 --storage ./data
```

### 3. Usage
You can use `curl` or any S3-compatible client (AWS CLI, MinIO Client).

**With curl:**
```bash
# Create bucket
curl -X PUT http://localhost:9000/my-bucket

# Upload object
echo "Hello Z4" | curl -X PUT -d @- http://localhost:9000/my-bucket/hello.txt

# Download object
curl http://localhost:9000/my-bucket/hello.txt
```

**With AWS CLI:**
```bash
# Configure profile (dummy keys for no-auth mode, or valid keys if authenticated)
aws configure set aws_access_key_id "z4-owner" --profile z4
aws configure set aws_secret_access_key "z4-secret-key" --profile z4
aws configure set region "us-east-1" --profile z4

# Commands
aws --endpoint-url http://localhost:9000 s3 mb s3://test-bucket --profile z4
aws --endpoint-url http://localhost:9000 s3 cp README.md s3://test-bucket/README.md --profile z4
```

## Security Note
By default, Z4 runs in authenticated mode if `auth.json` is present or environment variables are set. Use `--no-auth` for development testing only.

See [Deployment Guide](deployment.md) for production setup.
