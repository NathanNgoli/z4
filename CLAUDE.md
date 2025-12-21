# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
zig build              # Build the project
zig build run          # Run the server
zig build test         # Run all tests
zig build -Doptimize=ReleaseFast  # Optimized release build
```

## Running the Server

```bash
zig build run -- --port 9670 --data ./data --debug
zig build run -- --join 192.168.1.10:9671 --id node2  # Join existing cluster
```

Key flags: `--port`, `--gossip-port`, `--data`, `--id`, `--join`, `--threads`, `--vnodes`, `--debug`

## CLI Administration

The binary doubles as both server and CLI. Key/bucket management commands:

```bash
./zig-out/bin/z4 key create <name>              # Generate API key
./zig-out/bin/z4 key list                       # List all keys
./zig-out/bin/z4 bucket create <name>           # Create bucket
./zig-out/bin/z4 bucket allow <bucket> --key <name> --read --write --owner
```

## Testing

Integration tests use Docker:
```bash
./tests/test_docker_*.sh    # Various Docker-based integration tests
```

## Architecture

Z4 is a distributed S3-compatible object storage system with clustering and gossip-based node discovery.

### Core Components

- **main.zig** - Entry point. Routes to server mode or CLI subcommands (key/bucket management).
- **server.zig** - HTTP server with custom thread pool (auto-detects CPU cores). Handles S3-compatible REST API including multipart uploads.
- **storage.zig** - Filesystem-based object storage with 2-level directory sharding using Wyhash. Objects stored at `{bucket}/{d1:02x}/{d2:02x}/{key}`.
- **cluster.zig** - Consistent hashing ring with configurable virtual nodes (default 150). Replication factor of 3.
- **gossip.zig** - UDP-based cluster discovery protocol. Runs on separate thread with PING/PONG/JOIN messages.
- **keys.zig** - API key management. Keys stored in `_z4meta/keys/` with per-bucket permissions.
- **auth.zig** - AWS4-HMAC-SHA256 signature verification using keys from KeyManager.
- **lifecycle.zig** - Background worker for automatic object expiration (60s interval).

### Data Flow

1. HTTP request arrives at server thread pool
2. Auth verification (if configured)
3. Cluster ring determines node responsibility for key
4. Storage layer handles read/write with sharded directory structure
5. Non-local requests get HTTP 307 redirect to responsible node
6. Multipart uploads stored in `{bucket}/_multipart/{uploadId}/`

### Storage Layout

```
data/
├── _z4meta/           # Secure metadata (not S3-accessible)
│   ├── keys/          # API keys and permissions
│   ├── buckets/       # ACLs, policies, encryption config, versioning
│   └── objects/       # Object tags
└── mybucket/
    └── a3/7f/         # Wyhash-sharded directories
        └── file.txt
        └── file.txt.meta  # Object metadata
```

## Code Style

- **No comments in code** - code must be self-explanatory
- Use Zig 0.15.2+ with unmanaged ArrayLists and explicit allocators
- Handle all errors explicitly - no discarding errors with `_ = err`
- Avoid allocations in hot paths
- Use standard `zig fmt` formatting
