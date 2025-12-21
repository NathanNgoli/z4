# Backup and Restore

Z4 stores objects as standard files on disk. This makes backup and recovery straightforward using standard system tools.

## Data Structure
Z4 stores data in the directory specified by `--storage`.
- **Buckets**: Directories under the root storage path.
- **Objects**: Files within bucket directories.
- **Metadata**: `.meta` directory storing ACLs and object metadata.
- **Encryption**: If enabled, files are stored encrypted (AES-256-GCM).

## Backup Strategies

### 1. Filesystem Snapshots (Recommended)
If using ZFS, Btrfs, or LVM, atomic snapshots are the best method.
```bash
# Example (ZFS)
zfs snapshot pool/z4data@backup_2024
zfs send pool/z4data@backup_2024 | ssh backup_server zfs recv pool/backup
```

### 2. Rsync
For standard filesystems (ext4, xfs), use `rsync`.
```bash
# Stop Z4 (recommended for consistency)
systemctl stop z4

# Sync data
rsync -avz /data/z4/ /backup/z4/

# Restart Z4
systemctl start z4
```

### 3. Hot Backup (Experimental)
If you cannot stop the server, `rsync` can be run live, but you risk inconsistency if an object is being written during the copy.
- Run `rsync` twice to minimize difference window.

## Restore

To restore, simply stop the server and copy the data back to the storage directory.

```bash
systemctl stop z4
rsync -avz /backup/z4/ /data/z4/
systemctl start z4
```

## encryption Key Management
> [!IMPORTANT]
> If using server-side encryption, you **MUST** back up your encryption keys/environment variables. Losing the `Z4_SECRET_KEY` renders all encrypted data permanently unreadable.
