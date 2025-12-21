# Z4 Deployment Guide

This guide covers deployment strategies for Z4 in production environments.

## 1. Reverse Proxy (Recommended)

Since Z4 defaults to HTTP (plaintext), it is strongly recommended to run it behind a reverse proxy that handles TLS termination (HTTPS).

### Cloudflare Tunnel (Zero Truster)
Cloudflare Tunnel is the easiest way to expose Z4 securely.

1.  **Install cloudflared**: Follow Cloudflare's instructions.
2.  **Configure Tunnel**:
    ```yaml
    ingress:
      - hostname: s3.yourdomain.com
        service: http://localhost:9000
      - service: http_status:404
    ```
3.  **Run Z4**: `./z4 --port 9000 --storage /mnt/data`

### Nginx
Standard Nginx configuration for S3 compatibility.

```nginx
server {
    listen 443 ssl http2;
    server_name s3.yourdomain.com;

    # SSL Certs
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Allow large uploads
    client_max_body_size 0;

    location / {
        proxy_pass http://localhost:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Support chunked encoding
        proxy_request_buffering off;
        proxy_buffering off;
    }
}
```

## 2. Cluster Setup

Z4 supports clustering via a gossip protocol.

### Shared Secret
All nodes must share the same gossip secret for security.
Set `GOSSIP_SECRET` environment variable on all nodes.
```bash
export GOSSIP_SECRET="your-secure-random-secret"
```

### Starting Nodes

**Node 1 (Seed Node):**
```bash
./z4 --port 9001 --gossip-port 8001 --storage ./data1 --id node1
```

**Node 2:**
```bash
./z4 --port 9002 --gossip-port 8002 --storage ./data2 --id node2 --peer 127.0.0.1:8001
```

**Node 3:**
```bash
./z4 --port 9003 --gossip-port 8003 --storage ./data3 --id node3 --peer 127.0.0.1:8001
```

The nodes will discover each other via the seed node (Node 1). Data is distributed using consistent hashing.

## 3. Systemd Service

Create `/etc/systemd/system/z4.service`:

```ini
[Unit]
Description=Z4 Object Storage
After=network.target

[Service]
Type=simple
User=z4
Group=z4
ExecStart=/opt/z4/bin/z4 --port 9000 --storage /mnt/data
Restart=always
LimitNOFILE=65535
Environment="GOSSIP_SECRET=xxx"

[Install]
WantedBy=multi-user.target
```
