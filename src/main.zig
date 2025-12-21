const std = @import("std");
const Server = @import("server.zig").Server;
const Storage = @import("storage.zig").Storage;
const Cluster = @import("cluster.zig").Cluster;
const Gossip = @import("gossip.zig").Gossip;
const LifecycleWorker = @import("lifecycle.zig").LifecycleWorker;
const KeyManager = @import("keys.zig").KeyManager;
const log = @import("log.zig");
const constants = @import("constants.zig");

const Command = enum {
    server,
    key_create,
    key_list,
    key_info,
    key_delete,
    bucket_create,
    bucket_list,
    bucket_allow,
    bucket_deny,
    help,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try runServer(allocator, args);
        return;
    }

    const cmd_str = args[1];

    if (std.mem.eql(u8, cmd_str, "server") or std.mem.startsWith(u8, cmd_str, "--")) {
        try runServer(allocator, args);
        return;
    }

    if (std.mem.eql(u8, cmd_str, "help") or std.mem.eql(u8, cmd_str, "--help") or std.mem.eql(u8, cmd_str, "-h")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, cmd_str, "key")) {
        if (args.len < 3) {
            std.debug.print("Usage: z4 key <create|list|info|delete> ...\n", .{});
            return;
        }
        const subcmd = args[2];
        if (std.mem.eql(u8, subcmd, "create")) {
            try cmdKeyCreate(allocator, args);
        } else if (std.mem.eql(u8, subcmd, "list")) {
            try cmdKeyList(allocator, args);
        } else if (std.mem.eql(u8, subcmd, "info")) {
            try cmdKeyInfo(allocator, args);
        } else if (std.mem.eql(u8, subcmd, "delete")) {
            try cmdKeyDelete(allocator, args);
        } else {
            std.debug.print("Unknown key command: {s}\n", .{subcmd});
        }
        return;
    }

    if (std.mem.eql(u8, cmd_str, "bucket")) {
        if (args.len < 3) {
            std.debug.print("Usage: z4 bucket <create|list|allow|deny> ...\n", .{});
            return;
        }
        const subcmd = args[2];
        if (std.mem.eql(u8, subcmd, "create")) {
            try cmdBucketCreate(allocator, args);
        } else if (std.mem.eql(u8, subcmd, "list")) {
            try cmdBucketList(allocator, args);
        } else if (std.mem.eql(u8, subcmd, "allow")) {
            try cmdBucketAllow(allocator, args);
        } else if (std.mem.eql(u8, subcmd, "deny")) {
            try cmdBucketDeny(allocator, args);
        } else {
            std.debug.print("Unknown bucket command: {s}\n", .{subcmd});
        }
        return;
    }

    printHelp();
}

fn getDataPath(args: []const []const u8) []const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--data") and i + 1 < args.len) {
            return args[i + 1];
        }
    }
    return constants.DEFAULT_DATA_PATH;
}

fn getEncryptionKey() ?[32]u8 {
    const env_key = std.posix.getenv("Z4_ENCRYPTION_KEY") orelse return null;
    if (env_key.len != 64) return null;

    var key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, env_key) catch return null;
    return key;
}

fn cmdKeyCreate(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4 or !std.mem.eql(u8, args[2], "create")) {
        std.debug.print("Usage: z4 key create <name> [--data <path>]\n", .{});
        return;
    }

    const name = args[3];
    const data_path = getDataPath(args);

    var key_mgr = try KeyManager.init(allocator, data_path, getEncryptionKey());
    defer key_mgr.deinit();

    const key = key_mgr.createKey(name) catch |err| {
        if (err == error.KeyAlreadyExists) {
            std.debug.print("Error: Key '{s}' already exists\n", .{name});
        } else {
            std.debug.print("Error creating key: {}\n", .{err});
        }
        return;
    };
    defer key_mgr.freeKey(key);

    std.debug.print("Key created successfully!\n", .{});
    std.debug.print("Key name: {s}\n", .{key.name});
    std.debug.print("Key ID: {s}\n", .{key.access_key_id});
    std.debug.print("Secret key: {s}\n", .{key.secret_key});
}

fn cmdKeyList(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 3 or !std.mem.eql(u8, args[2], "list")) {
        std.debug.print("Usage: z4 key list [--data <path>]\n", .{});
        return;
    }

    const data_path = getDataPath(args);

    var key_mgr = try KeyManager.init(allocator, data_path, getEncryptionKey());
    defer key_mgr.deinit();

    const keys = try key_mgr.listKeys();
    defer {
        for (keys) |k| allocator.free(k);
        allocator.free(keys);
    }

    if (keys.len == 0) {
        std.debug.print("No keys found\n", .{});
        return;
    }

    std.debug.print("Keys:\n", .{});
    for (keys) |k| {
        std.debug.print("  {s}\n", .{k});
    }
}

fn cmdKeyInfo(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4 or !std.mem.eql(u8, args[2], "info")) {
        std.debug.print("Usage: z4 key info <name> [--data <path>]\n", .{});
        return;
    }

    const name = args[3];
    const data_path = getDataPath(args);

    var key_mgr = try KeyManager.init(allocator, data_path, getEncryptionKey());
    defer key_mgr.deinit();

    const key = key_mgr.getKey(name) catch {
        std.debug.print("Error: Key '{s}' not found\n", .{name});
        return;
    };
    defer key_mgr.freeKey(key);

    const perms = key_mgr.getPermissions(name) catch &[_]@import("keys.zig").Permission{};
    defer {
        for (perms) |p| allocator.free(p.bucket);
        allocator.free(perms);
    }

    std.debug.print("Key name: {s}\n", .{key.name});
    std.debug.print("Key ID: {s}\n", .{key.access_key_id});
    std.debug.print("Secret key: {s}\n", .{key.secret_key});
    std.debug.print("Created: {}\n", .{key.created_at});
    std.debug.print("Authorized buckets:\n", .{});

    if (perms.len == 0) {
        std.debug.print("  (none)\n", .{});
    } else {
        for (perms) |p| {
            std.debug.print("  {s}: ", .{p.bucket});
            if (p.read) std.debug.print("read ", .{});
            if (p.write) std.debug.print("write ", .{});
            if (p.owner) std.debug.print("owner", .{});
            std.debug.print("\n", .{});
        }
    }
}

fn cmdKeyDelete(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4 or !std.mem.eql(u8, args[2], "delete")) {
        std.debug.print("Usage: z4 key delete <name> [--data <path>]\n", .{});
        return;
    }

    const name = args[3];
    const data_path = getDataPath(args);

    var key_mgr = try KeyManager.init(allocator, data_path, getEncryptionKey());
    defer key_mgr.deinit();

    key_mgr.deleteKey(name) catch {
        std.debug.print("Error: Key '{s}' not found\n", .{name});
        return;
    };

    std.debug.print("Key '{s}' deleted\n", .{name});
}

fn cmdBucketCreate(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4 or !std.mem.eql(u8, args[2], "create")) {
        std.debug.print("Usage: z4 bucket create <name> [--data <path>]\n", .{});
        return;
    }

    const name = args[3];
    const data_path = getDataPath(args);

    var storage = try Storage.init(allocator, data_path);
    defer storage.deinit();

    storage.createBucket(name, null) catch |err| {
        if (err == error.BucketAlreadyExists) {
            std.debug.print("Error: Bucket '{s}' already exists\n", .{name});
        } else {
            std.debug.print("Error creating bucket: {}\n", .{err});
        }
        return;
    };

    std.debug.print("Bucket '{s}' created\n", .{name});
}

fn cmdBucketList(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 3 or !std.mem.eql(u8, args[2], "list")) {
        std.debug.print("Usage: z4 bucket list [--data <path>]\n", .{});
        return;
    }

    const data_path = getDataPath(args);

    var storage = try Storage.init(allocator, data_path);
    defer storage.deinit();

    const buckets = try storage.listBuckets();
    defer {
        for (buckets) |b| allocator.free(b);
        allocator.free(buckets);
    }

    if (buckets.len == 0) {
        std.debug.print("No buckets found\n", .{});
        return;
    }

    std.debug.print("Buckets:\n", .{});
    for (buckets) |b| {
        std.debug.print("  {s}\n", .{b});
    }
}

fn cmdBucketAllow(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4 or !std.mem.eql(u8, args[2], "allow")) {
        std.debug.print("Usage: z4 bucket allow <bucket> --key <key> [--read] [--write] [--owner] [--data <path>]\n", .{});
        return;
    }

    const bucket = args[3];
    var key_name: ?[]const u8 = null;
    var read = false;
    var write = false;
    var owner = false;
    var data_path: []const u8 = constants.DEFAULT_DATA_PATH;

    var i: usize = 4;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
            key_name = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--read")) {
            read = true;
        } else if (std.mem.eql(u8, args[i], "--write")) {
            write = true;
        } else if (std.mem.eql(u8, args[i], "--owner")) {
            owner = true;
        } else if (std.mem.eql(u8, args[i], "--data") and i + 1 < args.len) {
            data_path = args[i + 1];
            i += 1;
        }
    }

    if (key_name == null) {
        std.debug.print("Error: --key is required\n", .{});
        return;
    }

    if (!read and !write and !owner) {
        read = true;
        write = true;
    }

    var key_mgr = try KeyManager.init(allocator, data_path, getEncryptionKey());
    defer key_mgr.deinit();

    key_mgr.allowBucket(key_name.?, bucket, read, write, owner) catch |err| {
        std.debug.print("Error setting permissions: {}\n", .{err});
        return;
    };

    std.debug.print("Key '{s}' now has access to bucket '{s}': ", .{ key_name.?, bucket });
    if (read) std.debug.print("read ", .{});
    if (write) std.debug.print("write ", .{});
    if (owner) std.debug.print("owner", .{});
    std.debug.print("\n", .{});
}

fn cmdBucketDeny(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4 or !std.mem.eql(u8, args[2], "deny")) {
        std.debug.print("Usage: z4 bucket deny <bucket> --key <key> [--data <path>]\n", .{});
        return;
    }

    const bucket = args[3];
    var key_name: ?[]const u8 = null;
    var data_path: []const u8 = constants.DEFAULT_DATA_PATH;

    var i: usize = 4;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
            key_name = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--data") and i + 1 < args.len) {
            data_path = args[i + 1];
            i += 1;
        }
    }

    if (key_name == null) {
        std.debug.print("Error: --key is required\n", .{});
        return;
    }

    var key_mgr = try KeyManager.init(allocator, data_path, getEncryptionKey());
    defer key_mgr.deinit();

    key_mgr.denyBucket(key_name.?, bucket) catch |err| {
        std.debug.print("Error removing permissions: {}\n", .{err});
        return;
    };

    std.debug.print("Key '{s}' no longer has access to bucket '{s}'\n", .{ key_name.?, bucket });
}

fn printHelp() void {
    std.debug.print(
        \\Z4 - Distributed S3-Compatible Object Storage
        \\
        \\USAGE:
        \\  z4 [command] [options]
        \\
        \\COMMANDS:
        \\  server              Start the Z4 server (default)
        \\  key create <name>   Create a new API key
        \\  key list            List all API keys
        \\  key info <name>     Show key details and permissions
        \\  key delete <name>   Delete an API key
        \\  bucket create <name>   Create a new bucket
        \\  bucket list            List all buckets
        \\  bucket allow <bucket>  Grant key access to bucket
        \\  bucket deny <bucket>   Revoke key access to bucket
        \\  help                Show this help message
        \\
        \\SERVER OPTIONS:
        \\  --port <port>       HTTP port (default: 9670)
        \\  --gossip-port <port>  Gossip port (default: 9671)
        \\  --data <path>       Data directory (default: data)
        \\  --id <id>           Node ID (default: node1)
        \\  --join <host:port>  Join existing cluster
        \\  --vnodes <n>        Virtual nodes (default: 150)
        \\  --threads <n>       Worker threads (default: auto)
        \\  --debug             Enable debug logging
        \\
        \\BUCKET ALLOW OPTIONS:
        \\  --key <name>        Key name (required)
        \\  --read              Grant read access
        \\  --write             Grant write access
        \\  --owner             Grant owner access (full control)
        \\
        \\EXAMPLES:
        \\  z4 server --port 9670 --data ./data
        \\  z4 key create admin
        \\  z4 bucket create mybucket
        \\  z4 bucket allow mybucket --key admin --read --write
        \\  z4 bucket deny mybucket --key admin
        \\
    , .{});
}

fn runServer(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var port: u16 = constants.DEFAULT_HTTP_PORT;
    var gossip_port: u16 = constants.DEFAULT_GOSSIP_PORT;
    var storage_path: []const u8 = constants.DEFAULT_DATA_PATH;
    var self_id: []const u8 = constants.DEFAULT_NODE_ID;
    var join_addr: ?[]const u8 = null;
    var threads: ?usize = null;
    var debug: bool = false;
    var vnodes: usize = constants.DEFAULT_VIRTUAL_NODES;
    var no_auth: bool = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "server")) {
            continue;
        } else if (std.mem.eql(u8, arg, "--port") and i + 1 < args.len) {
            i += 1;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--gossip-port") and i + 1 < args.len) {
            i += 1;
            gossip_port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--data") and i + 1 < args.len) {
            i += 1;
            storage_path = args[i];
        } else if (std.mem.eql(u8, arg, "--id") and i + 1 < args.len) {
            i += 1;
            self_id = args[i];
        } else if (std.mem.eql(u8, arg, "--join") and i + 1 < args.len) {
            i += 1;
            join_addr = args[i];
        } else if (std.mem.eql(u8, arg, "--threads") and i + 1 < args.len) {
            i += 1;
            threads = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--debug")) {
            debug = true;
        } else if (std.mem.eql(u8, arg, "--vnodes") and i + 1 < args.len) {
            i += 1;
            vnodes = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--no-auth")) {
            no_auth = true;
        }
    }

    log.initGlobal(allocator);
    defer log.deinitGlobal();
    log.setDebug(debug);

    log.info("Starting z4 node '{s}'", .{self_id});
    log.info("HTTP Port: {}, Gossip Port: {}", .{ port, gossip_port });
    log.info("Storage: {s}", .{storage_path});
    log.info("Virtual Nodes: {}", .{vnodes});
    if (threads) |t| log.info("Threads: {}", .{t}) else log.info("Threads: Auto", .{});

    const gossip_secret = std.posix.getenv("Z4_GOSSIP_SECRET") orelse std.posix.getenv("Z4_SECRET_KEY") orelse "z4-default-gossip-secret";
    if (std.posix.getenv("Z4_GOSSIP_SECRET") == null and std.posix.getenv("Z4_SECRET_KEY") == null) {
        log.warn("WARNING: No Z4_GOSSIP_SECRET set. Using default insecure secret. Connects will fail if secrets mismatch.", .{});
    }

    var cluster = Cluster.initWithVnodes(allocator, self_id, gossip_secret, vnodes);
    defer cluster.deinit();

    try cluster.addNode(self_id, "127.0.0.1", port);

    var gossip = Gossip.init(allocator, &cluster, gossip_port);
    try gossip.start();
    defer gossip.stop();

    if (join_addr) |addr| {
        var iter = std.mem.splitScalar(u8, addr, ':');
        const host = iter.next() orelse "127.0.0.1";
        const p_str = iter.next() orelse "9671";
        const p = try std.fmt.parseInt(u16, p_str, 10);
        try gossip.joinCluster(host, p);
    }

    var storage = try Storage.init(allocator, storage_path);
    defer storage.deinit();

    if (std.posix.getenv("Z4_ENCRYPTION_KEY")) |enc_key| {
        storage.setEncryptionKey(enc_key) catch |err| {
            log.err("Invalid encryption key: {}", .{err});
            return err;
        };
        log.info("Encryption at rest: ENABLED", .{});
    }

    var key_mgr = try KeyManager.init(allocator, storage_path, getEncryptionKey());
    defer key_mgr.deinit();

    var lifecycle = LifecycleWorker.init(allocator, &storage);
    lifecycle.interval_ms = constants.LIFECYCLE_INTERVAL_MS;
    try lifecycle.start();
    defer lifecycle.stop();

    var server = try Server.init(allocator, storage, port, &cluster, threads, &key_mgr, no_auth);
    defer server.deinit();
    try server.start();
}
