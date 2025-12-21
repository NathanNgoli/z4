# Z4

A high-performance, self-hosted distributed S3-compatible object storage system written in Zig Lang.

**Author:** [Carsen Klock](https://x.com/carsenklock) ([@metaspartan](https://github.com/metaspartan))

## ✨ Key Features

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🚀 S3-Compatible API</h3>
      <p>Seamlessly integrates with the <strong>AWS CLI, SDKs, and standard S3 clients</strong>. A drop-in replacement for Cloudflare R2, Garage, MinIO, or AWS S3.</p>
    </td>
    <td width="50%" valign="top">
      <h3>🌐 Distributed & Scalable</h3>
      <p>Built on a <strong>consistent hashing ring</strong> with a gossip protocol. Storage capacity and throughput scale linearly as you add nodes.</p>
    </td>
  </tr>
  <tr>
    <td valign="top">
      <h3>🛠️ Admin CLI</h3>
      <p>Built-in <code>z4</code> CLI for managing API keys, buckets, and access permissions without complex configuration files or external dependencies.</p>
    </td>
    <td valign="top">
      <h3>🔐 Enterprise Security</h3>
      <p>
        <strong>Encryption at Rest:</strong> AES-256-GCM encryption.<br>
        <strong>Granular Access:</strong> Policy-based access control (Allow/Deny) and standardized ACLs.
      </p>
    </td>
  </tr>
  <tr>
    <td valign="top">
      <h3>📦 Advanced Data Management</h3>
      <p>
        <strong>Versioning:</strong> Protect against accidental deletes with object versioning.<br>
        <strong>Lifecycle Rules:</strong> Automate data expiration and cleanup.
      </p>
    </td>
    <td valign="top">
      <h3>⚡ Efficiency & Performance</h3>
      <p>
        <strong>Zero Dependencies:</strong> Single static binary (Linux/macOS).<br>
        <strong>Low Footprint:</strong> Runs on as little as 128MB RAM.<br>
        <strong>High Throughput:</strong> Optimized streaming I/O for large files.
      </p>
    </td>
  </tr>
</table>

## 📚 Documentation
- [Getting Started](docs/getting_started.md)
- [Deployment Guide](docs/deployment.md) - Cloudflare Tunnel, Nginx, Systemd
- [Backup & Restore](docs/backup_restore.md)

## System Requirements

- **RAM**: Minimum 128MB, Recommended 512MB+
- **CPU**: 1 core minimum
- **Disk**: Dependent on data size (Standard SSD/HDD)
- **OS**: Linux or macOS

## Quick Start

### Docker Compose (Recommended)

```bash
docker compose up -d
```

### CLI Administration

Z4 now uses a robust key management system. You must generate API keys using the CLI to access the S3 API.

**Generate an API key:**
```bash
# Create a key named 'admin'
docker exec z4-node1 /app/z4 key create admin
```

**Create a bucket and grant access:**
```bash
# Create a bucket
docker exec z4-node1 /app/z4 bucket create mybucket

# Grant 'admin' key full access to 'mybucket'
docker exec z4-node1 /app/z4 bucket allow mybucket --key admin --read --write --owner
```

### docker-compose.yml Example

```yaml
services:
  z4:
    build: .
    ports:
      - "9670:9670"   # S3 API
      - "9671:9671"   # Gossip protocol
    volumes:
      - ./data:/app/data
    environment:
      - Z4_ENCRYPTION_KEY=${Z4_ENCRYPTION_KEY:-}
    command: ["/app/z4", "server", "--vnodes", "150"]
    restart: always
```

## CLI Commands

Z4 includes a built-in CLI for administration.

### Key Management

| Command | Description |
|---------|-------------|
| `z4 key create <name>` | Generate a new API key (Access Key ID + Secret) |
| `z4 key list` | List all API keys |
| `z4 key info <name>` | Show key details and permissions |
| `z4 key delete <name>` | Delete an API key |

### Bucket Management

| Command | Description |
|---------|-------------|
| `z4 bucket create <name>` | Create a new bucket |
| `z4 bucket list` | List all buckets |
| `z4 bucket allow <bucket> --key <name> ...` | Grant permissions (flags below) |
| `z4 bucket deny <bucket> --key <name>` | Revoke access to a bucket |

**Permission Flags:**
- `--read`: Allow GetObject, ListObjects, etc.
- `--write`: Allow PutObject, DeleteObject, etc.
- `--owner`: Full control (ACLs, Policy, etc.)

## Configuration

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 9670 | HTTP API port |
| `--gossip-port` | 9671 | Cluster gossip port (UDP) |
| `--data` | data | Storage directory |
| `--id` | node1 | Unique node identifier |
| `--join` | - | Seed node address (host:port) |
| `--threads` | auto | Worker thread count |
| `--vnodes` | 150 | Virtual nodes per physical node |
| `--debug` | false | Enable debug logging |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `Z4_ENCRYPTION_KEY` | 32-byte AES-256-GCM encryption key |

## Usage Examples

### AWS CLI

After creating a key via CLI:

```bash
aws configure set aws_access_key_id <YOUR_ACCESS_KEY_ID>
aws configure set aws_secret_access_key <YOUR_SECRET_KEY>

aws --endpoint-url http://localhost:9670 s3 cp file.txt s3://mybucket/
aws --endpoint-url http://localhost:9670 s3 ls s3://mybucket/
```

## Architecture

### Storage Layout

```
data/
├── _z4meta/           # Secure metadata (not S3-accessible)
│   ├── keys/          # API keys and permissions
│   ├── buckets/       # ACLs, policies, encryption config
│   └── objects/       # Object tags
└── mybucket/
    └── a3/7f/         # Wyhash-sharded directories
        └── file.txt
```

### Clustering

- **Consistent hashing** with configurable virtual nodes (default: 150)
- **Replication factor 3** for fault tolerance
- **HTTP 307 redirects** route requests to responsible nodes
- **UDP gossip** for node discovery and health checks

## Build from Source

```bash
zig build                         # Debug
zig build -Doptimize=ReleaseFast  # Release
./scripts/build-all.sh v1.0.0     # Cross-compile all platforms
```

## ✅ S3 Compatibility

| Feature | Endpoint | Status | Notes |
|---------|----------|:------:|-------|
| **Buckets** | | | |
| CreateBucket | `PUT /{bucket}` | ✅ | |
| DeleteBucket | `DELETE /{bucket}` | ✅ | |
| ListBuckets | `GET /` | ✅ | |
| GetBucketLocation | `GET /{bucket}?location` | ✅ | Default: us-east-1 |
| **Objects** | | | |
| PutObject | `PUT /{bucket}/{key}` | ✅ | Streaming & Large files supported |
| GetObject | `GET /{bucket}/{key}` | ✅ | Range requests supported |
| DeleteObject | `DELETE /{bucket}/{key}` | ✅ | |
| HeadObject | `HEAD /{bucket}/{key}` | ✅ | |
| CopyObject | `PUT /{bucket}/{key}` | ✅ | Header: `x-amz-copy-source` |
| **Multipart Upload** | | | |
| CreateMultipartUpload | `POST /{bucket}/{key}?uploads` | ✅ | |
| UploadPart | `PUT /{bucket}/{key}?partNumber=...` | ✅ | |
| CompleteMultipartUpload | `POST /{bucket}/{key}?uploadId=...` | ✅ | |
| AbortMultipartUpload | `DELETE /{bucket}/{key}?uploadId=...` | ✅ | |
| **Advanced** | | | |
| Bucket Policies | `PUT/GET/DELETE /{bucket}?policy` | ✅ | Allow/Deny support |
| Bucket ACLs | `PUT/GET /{bucket}?acl` | ✅ | |
| Object ACLs | `PUT/GET /{bucket}/{key}?acl` | ✅ | |
| Versioning | `PUT/GET /{bucket}?versioning` | ✅ | |
| Encryption | `PUT/GET/DELETE /{bucket}?encryption` | ✅ | AES-256-GCM (Server-Side) |
| Lifecycle | `PUT/GET/DELETE /{bucket}?lifecycle` | ✅ | Expiration rules |
| Tagging | `PUT/GET/DELETE /{bucket}/{key}?tagging` | ✅ | Bucket & Object tagging |

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License. Copyright (c) 2025-2026 Carsen Klock
