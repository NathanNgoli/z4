const std = @import("std");
const fs = std.fs;
const utils = @import("utils.zig");
const constants = @import("constants.zig");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const c = @cImport({
    @cInclude("sys/statvfs.h");
});

pub const Storage = struct {
    root_dir: fs.Dir,
    meta_dir: fs.Dir,
    allocator: std.mem.Allocator,
    encryption_key: ?[32]u8 = null,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !Storage {
        var dir = fs.cwd().openDir(path, .{}) catch |err| switch (err) {
            error.FileNotFound => try fs.cwd().makeOpenPath(path, .{}),
            else => return err,
        };
        dir = try fs.cwd().openDir(path, .{ .iterate = true });

        dir.makeDir("_z4meta") catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
        dir.makeDir("_z4meta/buckets") catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
        dir.makeDir("_z4meta/objects") catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        const meta_dir = try dir.openDir("_z4meta", .{});

        return Storage{
            .root_dir = dir,
            .meta_dir = meta_dir,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Storage) void {
        self.meta_dir.close();
        self.root_dir.close();
    }

    fn checkDiskSpace(self: *Storage, required_bytes: u64) !void {
        var stat: c.struct_statvfs = undefined;
        if (c.fstatvfs(self.root_dir.fd, &stat) != 0) {
            return error.DiskCheckFailed;
        }
        const available = @as(u64, stat.f_bavail) * @as(u64, stat.f_frsize);

        if (required_bytes == std.math.maxInt(u64)) {
            if (available < constants.MIN_DISK_FREE_SPACE) return error.DiskFull;
            return;
        }

        const total_needed = std.math.add(u64, required_bytes, constants.MIN_DISK_FREE_SPACE) catch return error.DiskFull;
        if (available < total_needed) {
            return error.DiskFull;
        }
    }

    pub fn createBucket(self: *Storage, bucket_name: []const u8, owner: ?[]const u8) !void {
        try self.checkDiskSpace(4096);
        if (!utils.checkBucketName(bucket_name)) return error.InvalidBucketName;
        self.root_dir.makeDir(bucket_name) catch |err| switch (err) {
            error.PathAlreadyExists => return error.BucketAlreadyExists,
            else => return err,
        };

        if (owner) |o| {
            var grants = [_]AclGrant{.{ .grantee = o, .permission = .FULL_CONTROL }};
            try self.putBucketAcl(bucket_name, o, &grants);
        }
    }

    pub fn deleteBucket(self: *Storage, bucket_name: []const u8) !void {
        if (!utils.checkBucketName(bucket_name)) return error.InvalidBucketName;

        var bucket_dir = self.root_dir.openDir(bucket_name, .{ .iterate = true }) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        var iter = bucket_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory and !std.mem.eql(u8, entry.name, "_multipart")) {
                return error.BucketNotEmpty;
            }
            if (entry.kind == .file) {
                return error.BucketNotEmpty;
            }
        }

        self.root_dir.deleteTree(bucket_name) catch return error.InternalError;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return;
        defer buckets_meta.close();

        const acl_path = std.fmt.allocPrint(self.allocator, "{s}.acl", .{bucket_name}) catch return;
        defer self.allocator.free(acl_path);
        buckets_meta.deleteFile(acl_path) catch {};

        const policy_path = std.fmt.allocPrint(self.allocator, "{s}.policy", .{bucket_name}) catch return;
        defer self.allocator.free(policy_path);
        buckets_meta.deleteFile(policy_path) catch {};

        const enc_path = std.fmt.allocPrint(self.allocator, "{s}.encryption", .{bucket_name}) catch return;
        defer self.allocator.free(enc_path);
        buckets_meta.deleteFile(enc_path) catch {};

        const ver_path = std.fmt.allocPrint(self.allocator, "{s}.versioning", .{bucket_name}) catch return;
        defer self.allocator.free(ver_path);
        buckets_meta.deleteFile(ver_path) catch {};

        const lc_path = std.fmt.allocPrint(self.allocator, "{s}.lifecycle", .{bucket_name}) catch return;
        defer self.allocator.free(lc_path);
        buckets_meta.deleteFile(lc_path) catch {};
    }

    pub fn copyObject(self: *Storage, src_bucket: []const u8, src_key: []const u8, dest_bucket: []const u8, dest_key: []const u8) !void {
        try utils.checkKeyName(src_key);
        try utils.checkKeyName(dest_key);

        var src_bucket_dir = self.root_dir.openDir(src_bucket, .{}) catch return error.NoSuchBucket;
        defer src_bucket_dir.close();

        const src_path = try getShardedPath(self.allocator, src_key);
        defer self.allocator.free(src_path);

        const src_file = src_bucket_dir.openFile(src_path, .{}) catch return error.NoSuchKey;
        defer src_file.close();

        const src_meta_path = try std.fmt.allocPrint(self.allocator, "{s}.meta", .{src_path});
        defer self.allocator.free(src_meta_path);

        var src_meta_content: []u8 = &.{};
        var has_meta = false;

        if (src_bucket_dir.openFile(src_meta_path, .{})) |f| {
            defer f.close();
            const size = (try f.stat()).size;
            src_meta_content = try self.allocator.alloc(u8, size);
            _ = try f.readAll(src_meta_content);
            has_meta = true;
        } else |_| {}
        defer if (has_meta) self.allocator.free(src_meta_content);

        var dest_bucket_dir = self.root_dir.openDir(dest_bucket, .{}) catch return error.NoSuchBucket;
        defer dest_bucket_dir.close();

        const dest_path = try getShardedPath(self.allocator, dest_key);
        defer self.allocator.free(dest_path);

        if (std.fs.path.dirname(dest_path)) |dir| {
            try dest_bucket_dir.makePath(dir);
        }

        const dest_file = try dest_bucket_dir.createFile(dest_path, .{});
        defer dest_file.close();

        try src_file.seekTo(0);

        var buffer: [constants.COPY_BUFFER_SIZE]u8 = undefined;
        while (true) {
            const n = try src_file.read(&buffer);
            if (n == 0) break;
            try dest_file.writeAll(buffer[0..n]);
        }

        if (has_meta) {
            const dest_meta_path = try std.fmt.allocPrint(self.allocator, "{s}.meta", .{dest_path});
            defer self.allocator.free(dest_meta_path);

            const dest_meta_file = try dest_bucket_dir.createFile(dest_meta_path, .{});
            defer dest_meta_file.close();

            try dest_meta_file.writeAll(src_meta_content);
        }
    }

    pub fn listBuckets(self: *Storage) ![][]u8 {
        var buckets = try std.ArrayList([]u8).initCapacity(self.allocator, 16);
        defer buckets.deinit(self.allocator);

        var iter = self.root_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory and !std.mem.startsWith(u8, entry.name, "_")) {
                try buckets.append(self.allocator, try self.allocator.dupe(u8, entry.name));
            }
        }
        return buckets.toOwnedSlice(self.allocator);
    }

    pub const ListObjectsOptions = struct {
        prefix: []const u8 = "",
        delimiter: []const u8 = "",
        max_keys: usize = constants.LIST_OBJECTS_MAX_KEYS,
        continuation_token: ?[]const u8 = null,
        start_after: ?[]const u8 = null,
    };

    pub const ListObjectsResult = struct {
        objects: []ObjectInfo,
        common_prefixes: [][]const u8,
        is_truncated: bool,
        next_continuation_token: ?[]const u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *ListObjectsResult) void {
            for (self.objects) |obj| {
                self.allocator.free(obj.key);
                self.allocator.free(obj.etag);
            }
            self.allocator.free(self.objects);

            for (self.common_prefixes) |prefix| {
                self.allocator.free(prefix);
            }
            self.allocator.free(self.common_prefixes);

            if (self.next_continuation_token) |token| {
                self.allocator.free(token);
            }
        }
    };

    pub const ObjectInfo = struct {
        key: []const u8,
        size: u64,
        etag: []const u8,
        last_modified: i64,
    };

    pub fn listObjects(self: *Storage, bucket: []const u8, options: ListObjectsOptions) !ListObjectsResult {
        var bucket_dir = self.root_dir.openDir(bucket, .{ .iterate = true }) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        var objects = std.ArrayList(ObjectInfo){};
        errdefer {
            for (objects.items) |obj| {
                self.allocator.free(obj.key);
                self.allocator.free(obj.etag);
            }
            objects.deinit(self.allocator);
        }

        var prefixes = std.StringHashMap(void).init(self.allocator);
        defer prefixes.deinit();

        try self.scanDirectory(bucket_dir, "", options, &objects, &prefixes);

        std.mem.sort(ObjectInfo, objects.items, {}, struct {
            fn lessThan(_: void, a: ObjectInfo, b: ObjectInfo) bool {
                return std.mem.lessThan(u8, a.key, b.key);
            }
        }.lessThan);

        var start_idx: usize = 0;
        if (options.start_after) |start_after| {
            for (objects.items, 0..) |obj, i| {
                if (std.mem.order(u8, obj.key, start_after) == .gt) {
                    start_idx = i;
                    break;
                }
            }
        }
        if (options.continuation_token) |token| {
            for (objects.items, 0..) |obj, i| {
                if (std.mem.order(u8, obj.key, token) == .gt) {
                    start_idx = i;
                    break;
                }
            }
        }

        const is_truncated = (objects.items.len - start_idx) > options.max_keys;
        const end_idx = @min(start_idx + options.max_keys, objects.items.len);

        var result_objects = try std.ArrayList(ObjectInfo).initCapacity(self.allocator, end_idx - start_idx);
        errdefer result_objects.deinit(self.allocator);

        for (objects.items[start_idx..end_idx]) |obj| {
            try result_objects.append(self.allocator, obj);
        }

        for (objects.items[0..start_idx]) |obj| {
            self.allocator.free(obj.key);
            self.allocator.free(obj.etag);
        }
        for (objects.items[end_idx..]) |obj| {
            self.allocator.free(obj.key);
            self.allocator.free(obj.etag);
        }
        objects.deinit(self.allocator);

        var common_prefixes = try std.ArrayList([]const u8).initCapacity(self.allocator, prefixes.count());
        errdefer common_prefixes.deinit(self.allocator);

        var prefix_iter = prefixes.iterator();
        while (prefix_iter.next()) |entry| {
            try common_prefixes.append(self.allocator, try self.allocator.dupe(u8, entry.key_ptr.*));
        }

        var next_token: ?[]const u8 = null;
        if (is_truncated and end_idx < objects.items.len) {
            next_token = try self.allocator.dupe(u8, result_objects.items[result_objects.items.len - 1].key);
        }

        return ListObjectsResult{
            .objects = try result_objects.toOwnedSlice(self.allocator),
            .common_prefixes = try common_prefixes.toOwnedSlice(self.allocator),
            .is_truncated = is_truncated,
            .next_continuation_token = next_token,
            .allocator = self.allocator,
        };
    }

    fn scanDirectory(self: *Storage, dir: fs.Dir, current_path: []const u8, options: ListObjectsOptions, objects: *std.ArrayList(ObjectInfo), prefixes: *std.StringHashMap(void)) !void {
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (std.mem.startsWith(u8, entry.name, "_")) continue;

            const full_path = if (current_path.len > 0)
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ current_path, entry.name })
            else
                try self.allocator.dupe(u8, entry.name);
            defer self.allocator.free(full_path);

            if (entry.kind == .directory) {
                if (dir.openDir(entry.name, .{ .iterate = true })) |sub_dir| {
                    var sub = sub_dir;
                    defer sub.close();
                    try self.scanDirectory(sub, full_path, options, objects, prefixes);
                } else |_| {}
            } else if (entry.kind == .file) {
                if (std.mem.endsWith(u8, entry.name, ".meta")) continue;
                if (std.mem.endsWith(u8, entry.name, ".tags")) continue;
                if (std.mem.endsWith(u8, entry.name, ".acl")) continue;
                if (std.mem.endsWith(u8, entry.name, ".current")) continue;
                if (std.mem.endsWith(u8, entry.name, ".deleted")) continue;
                if (std.mem.indexOf(u8, entry.name, ".v") != null) continue;

                const key = try self.reverseShardedPath(full_path);
                defer self.allocator.free(key);

                if (options.prefix.len > 0 and !std.mem.startsWith(u8, key, options.prefix)) continue;

                if (options.delimiter.len > 0) {
                    const after_prefix = key[options.prefix.len..];
                    if (std.mem.indexOf(u8, after_prefix, options.delimiter)) |delim_pos| {
                        const prefix = try std.fmt.allocPrint(self.allocator, "{s}{s}{s}", .{
                            options.prefix,
                            after_prefix[0 .. delim_pos + options.delimiter.len],
                            "",
                        });
                        defer self.allocator.free(prefix);
                        try prefixes.put(prefix, {});
                        continue;
                    }
                }

                const stat = dir.statFile(entry.name) catch continue;
                const etag = try self.computeEtagFromFile(dir, entry.name);

                try objects.append(self.allocator, .{
                    .key = try self.allocator.dupe(u8, key),
                    .size = stat.size,
                    .etag = etag,
                    .last_modified = @as(i64, @intCast(@divTrunc(stat.mtime, std.time.ns_per_ms))),
                });
            }
        }
    }

    fn reverseShardedPath(self: *Storage, path: []const u8) ![]const u8 {
        var parts = std.mem.splitScalar(u8, path, '/');
        _ = parts.next();
        _ = parts.next();
        const rest = parts.rest();
        return self.allocator.dupe(u8, rest);
    }

    fn computeEtagFromFile(self: *Storage, dir: fs.Dir, filename: []const u8) ![]const u8 {
        const file = dir.openFile(filename, .{}) catch {
            return self.allocator.dupe(u8, "\"d41d8cd98f00b204e9800998ecf8427e\"");
        };
        defer file.close();

        var hasher = std.crypto.hash.Md5.init(.{});
        var buffer: [constants.COPY_BUFFER_SIZE]u8 = undefined;

        while (true) {
            const n = try file.read(&buffer);
            if (n == 0) break;
            hasher.update(buffer[0..n]);
        }

        var hash: [16]u8 = undefined;
        hasher.final(&hash);
        return std.fmt.allocPrint(self.allocator, "\"{x}\"", .{hash});
    }

    fn getShardedPath(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
        const hash = std.hash.Wyhash.hash(0, key);
        const d1 = @as(u8, @intCast(hash & 0xFF));
        const d2 = @as(u8, @intCast((hash >> 8) & 0xFF));
        return std.fmt.allocPrint(allocator, "{x:0>2}/{x:0>2}/{s}", .{ d1, d2, key });
    }

    pub const ObjectMetadata = struct {
        content_type: []const u8 = "application/octet-stream",
        etag: []const u8 = "",
        size: u64 = 0,
        last_modified: i64 = 0,
        encrypted: bool = false,
        user_metadata: std.StringHashMap([]const u8),

        pub fn deinit(self: *ObjectMetadata, allocator: std.mem.Allocator) void {
            allocator.free(self.content_type);
            allocator.free(self.etag);

            var iter = self.user_metadata.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            self.user_metadata.deinit();
        }
    };

    fn writeEncryptedChunk(self: *Storage, file: fs.File, data: []const u8) !void {
        if (self.encryption_key) |key| {
            var nonce: [12]u8 = undefined;
            std.crypto.random.bytes(&nonce);
            var tag: [16]u8 = undefined;

            const ciphertext = try self.allocator.alloc(u8, data.len);
            defer self.allocator.free(ciphertext);

            Aes256Gcm.encrypt(ciphertext, &tag, data, "", nonce, key);

            try file.writeAll(&nonce);
            try file.writeAll(ciphertext);
            try file.writeAll(&tag);
        }
    }

    fn readEncryptedFile(self: *Storage, file: fs.File, file_size: u64) ![]u8 {
        const key = self.encryption_key orelse return error.InternalError;
        var out = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        errdefer out.deinit(self.allocator);

        var pos: u64 = 0;

        while (pos < file_size) {
            var nonce: [12]u8 = undefined;
            const n_read = try file.read(&nonce);
            if (n_read == 0) break;
            if (n_read != 12) return error.InternalError;
            pos += 12;

            const remaining = file_size - pos;
            const chunk_overhead = 16;
            if (remaining < chunk_overhead) return error.InternalError;

            const full_chunk_size = constants.COPY_BUFFER_SIZE;
            const cipher_len = if (remaining > full_chunk_size + chunk_overhead)
                full_chunk_size
            else
                (remaining - chunk_overhead);

            const cipher = try self.allocator.alloc(u8, cipher_len);
            defer self.allocator.free(cipher);

            const n_cipher = try file.readAll(cipher);
            if (n_cipher != cipher_len) return error.InternalError;
            pos += cipher_len;

            var tag: [16]u8 = undefined;
            const n_tag = try file.readAll(&tag);
            if (n_tag != 16) return error.InternalError;
            pos += 16;

            const plaintext = try self.allocator.alloc(u8, cipher_len);
            defer self.allocator.free(plaintext);

            try Aes256Gcm.decrypt(plaintext, cipher, tag, "", nonce, key);
            try out.appendSlice(self.allocator, plaintext);
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn putObject(self: *Storage, bucket: []const u8, key: []const u8, data: []const u8, content_type: []const u8, user_metadata: std.StringHashMap([]const u8)) !void {
        try self.checkDiskSpace(data.len);
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        if (fs.path.dirname(sharded_path)) |dirname| {
            bucket_dir.makePath(dirname) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        const file = try bucket_dir.createFile(sharded_path, .{});
        defer file.close();

        var is_encrypted = false;
        if (self.encryption_key) |_| {
            try self.writeEncryptedChunk(file, data);
            is_encrypted = true;
        } else {
            try file.writeAll(data);
        }

        const etag = utils.computeMd5(data);
        const etag_str = try utils.formatMd5Etag(self.allocator, etag);
        defer self.allocator.free(etag_str);

        const meta_path = try std.fmt.allocPrint(self.allocator, "{s}.meta", .{sharded_path});
        defer self.allocator.free(meta_path);

        const meta_file = try bucket_dir.createFile(meta_path, .{});
        defer meta_file.close();

        const timestamp = std.time.milliTimestamp();

        const enc_str = if (is_encrypted) "true" else "false";
        const meta_content = try std.fmt.allocPrint(self.allocator, "content_type={s}\netag={s}\nsize={}\nlast_modified={}\nencrypted={s}\n", .{ content_type, etag_str, data.len, timestamp, enc_str });
        defer self.allocator.free(meta_content);

        try meta_file.writeAll(meta_content);

        var iter = user_metadata.iterator();
        while (iter.next()) |entry| {
            const line = try std.fmt.allocPrint(self.allocator, "{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            defer self.allocator.free(line);
            try meta_file.writeAll(line);
        }
    }

    pub fn putObjectStreaming(self: *Storage, bucket: []const u8, key: []const u8, reader: anytype, content_length: u64, content_type: []const u8, user_metadata: std.StringHashMap([]const u8), initial_data: []const u8) ![]const u8 {
        try self.checkDiskSpace(content_length);
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        if (std.fs.path.dirname(sharded_path)) |dirname| {
            bucket_dir.makePath(dirname) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        const file = try bucket_dir.createFile(sharded_path, .{});
        defer file.close();

        var hasher = std.crypto.hash.Md5.init(.{});
        var buffer: [constants.COPY_BUFFER_SIZE]u8 = undefined;
        var total_written: u64 = 0;
        var is_encrypted = false;

        if (self.encryption_key) |_| {
            is_encrypted = true;
            if (initial_data.len > 0) {
                hasher.update(initial_data);
                try self.writeEncryptedChunk(file, initial_data);
                total_written += initial_data.len;
            }

            while (total_written < content_length) {
                const to_read = @min(buffer.len, content_length - total_written);
                const n = try reader.read(buffer[0..to_read]);
                if (n == 0) break;

                hasher.update(buffer[0..n]);
                try self.writeEncryptedChunk(file, buffer[0..n]);
                total_written += n;
            }
        } else {
            if (initial_data.len > 0) {
                hasher.update(initial_data);
                try file.writeAll(initial_data);
                total_written += initial_data.len;
            }

            while (total_written < content_length) {
                const to_read = @min(buffer.len, content_length - total_written);
                const n = try reader.read(buffer[0..to_read]);
                if (n == 0) break;

                hasher.update(buffer[0..n]);
                try file.writeAll(buffer[0..n]);
                total_written += n;
            }
        }

        var hash: [16]u8 = undefined;
        hasher.final(&hash);
        const etag_str = try utils.formatMd5Etag(self.allocator, hash);

        const meta_path = try std.fmt.allocPrint(self.allocator, "{s}.meta", .{sharded_path});
        defer self.allocator.free(meta_path);

        const meta_file = try bucket_dir.createFile(meta_path, .{});
        defer meta_file.close();

        const timestamp = std.time.milliTimestamp();

        const enc_str = if (is_encrypted) "true" else "false";
        const meta_content = try std.fmt.allocPrint(self.allocator, "content_type={s}\netag={s}\nsize={}\nlast_modified={}\nencrypted={s}\n", .{ content_type, etag_str, total_written, timestamp, enc_str });
        defer self.allocator.free(meta_content);

        try meta_file.writeAll(meta_content);

        var iter = user_metadata.iterator();
        while (iter.next()) |entry| {
            const line = try std.fmt.allocPrint(self.allocator, "{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            defer self.allocator.free(line);
            try meta_file.writeAll(line);
        }

        return etag_str;
    }

    pub fn headObject(self: *Storage, bucket: []const u8, key: []const u8) !ObjectMetadata {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        const meta_path = try std.fmt.allocPrint(self.allocator, "{s}.meta", .{sharded_path});
        defer self.allocator.free(meta_path);

        const file = bucket_dir.openFile(meta_path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                if (bucket_dir.openFile(sharded_path, .{})) |f| {
                    defer f.close();
                    const stat = try f.stat();

                    var hasher = std.crypto.hash.Md5.init(.{});
                    var buffer: [constants.COPY_BUFFER_SIZE]u8 = undefined;
                    while (true) {
                        const n = try f.read(&buffer);
                        if (n == 0) break;
                        hasher.update(buffer[0..n]);
                    }
                    var hash: [16]u8 = undefined;
                    hasher.final(&hash);

                    return ObjectMetadata{
                        .size = stat.size,
                        .last_modified = @as(i64, @intCast(@divTrunc(stat.mtime, std.time.ns_per_ms))),
                        .content_type = try self.allocator.dupe(u8, "application/octet-stream"),
                        .etag = try utils.formatMd5Etag(self.allocator, hash),
                        .user_metadata = std.StringHashMap([]const u8).init(self.allocator),
                        .encrypted = false,
                    };
                } else |_| {
                    return error.NoSuchKey;
                }
            }
            return err;
        };
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);

        _ = try file.readAll(buffer);

        var meta = ObjectMetadata{
            .user_metadata = std.StringHashMap([]const u8).init(self.allocator),
        };

        meta.content_type = try self.allocator.dupe(u8, "application/octet-stream");
        meta.etag = try self.allocator.dupe(u8, "");

        var iter = std.mem.splitScalar(u8, buffer, '\n');
        while (iter.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.indexOfScalar(u8, line, '=')) |eq_idx| {
                const k = line[0..eq_idx];
                const v = line[eq_idx + 1 ..];

                if (std.mem.eql(u8, k, "content_type")) {
                    self.allocator.free(meta.content_type);
                    meta.content_type = try self.allocator.dupe(u8, std.mem.trim(u8, v, "\r"));
                } else if (std.mem.eql(u8, k, "etag")) {
                    self.allocator.free(meta.etag);
                    meta.etag = try self.allocator.dupe(u8, std.mem.trim(u8, v, "\r"));
                } else if (std.mem.eql(u8, k, "size")) {
                    meta.size = std.fmt.parseInt(u64, std.mem.trim(u8, v, "\r"), 10) catch 0;
                } else if (std.mem.eql(u8, k, "last_modified")) {
                    meta.last_modified = std.fmt.parseInt(i64, std.mem.trim(u8, v, "\r"), 10) catch 0;
                } else if (std.mem.eql(u8, k, "encrypted")) {
                    meta.encrypted = std.mem.eql(u8, std.mem.trim(u8, v, "\r"), "true");
                } else if (std.mem.startsWith(u8, k, "x-amz-meta-")) {
                    const k_dup = try self.allocator.dupe(u8, k);
                    const v_dup = try self.allocator.dupe(u8, std.mem.trim(u8, v, "\r"));
                    try meta.user_metadata.put(k_dup, v_dup);
                }
            }
        }

        return meta;
    }

    pub fn deleteObject(self: *Storage, bucket: []const u8, key: []const u8) !void {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        bucket_dir.deleteFile(sharded_path) catch |err| {
            if (err == error.FileNotFound) return error.NoSuchKey;
            return err;
        };

        const meta_path = try std.fmt.allocPrint(self.allocator, "{s}.meta", .{sharded_path});
        defer self.allocator.free(meta_path);
        bucket_dir.deleteFile(meta_path) catch {};

        const tags_path = try std.fmt.allocPrint(self.allocator, "{s}.tags", .{sharded_path});
        defer self.allocator.free(tags_path);
        bucket_dir.deleteFile(tags_path) catch {};

        const acl_path = try std.fmt.allocPrint(self.allocator, "{s}.acl", .{sharded_path});
        defer self.allocator.free(acl_path);
        bucket_dir.deleteFile(acl_path) catch {};
    }

    pub fn deleteMultipartUpload(self: *Storage, bucket: []const u8, upload_id: []const u8) !void {
        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        var mp_dir = bucket_dir.openDir("_multipart", .{}) catch return error.NoSuchUpload;
        defer mp_dir.close();

        mp_dir.deleteTree(upload_id) catch |err| {
            if (err == error.FileNotFound) return error.NoSuchUpload;
            return err;
        };
    }

    pub fn getObject(self: *Storage, bucket: []const u8, key: []const u8) ![]u8 {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        const current_path = try std.fmt.allocPrint(self.allocator, "{s}.current", .{sharded_path});
        defer self.allocator.free(current_path);

        var actual_path: []const u8 = sharded_path;
        var versioned_path_alloc: ?[]u8 = null;
        defer if (versioned_path_alloc) |vp| self.allocator.free(vp);

        if (bucket_dir.openFile(current_path, .{})) |current_file| {
            defer current_file.close();
            var version_buf: [64]u8 = undefined;
            const version_len = current_file.readAll(&version_buf) catch 0;
            if (version_len > 0) {
                const version_id = std.mem.trim(u8, version_buf[0..version_len], " \t\r\n");
                versioned_path_alloc = std.fmt.allocPrint(self.allocator, "{s}.v{s}", .{ sharded_path, version_id }) catch null;
                if (versioned_path_alloc) |vp| {
                    actual_path = vp;
                }
            }
        } else |_| {}

        const file = bucket_dir.openFile(actual_path, .{}) catch return error.NoSuchKey;
        defer file.close();

        var is_encrypted = false;
        if (self.headObject(bucket, key)) |meta| {
            is_encrypted = meta.encrypted;
            var m = meta;
            defer m.deinit(self.allocator);
        } else |_| {}

        if (is_encrypted) {
            const stat = try file.stat();
            return self.readEncryptedFile(file, stat.size);
        }

        return try file.readToEndAlloc(self.allocator, constants.MAX_OBJECT_SIZE);
    }

    pub fn getObjectRange(self: *Storage, bucket: []const u8, key: []const u8, start: u64, size: u64) ![]u8 {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        const file = bucket_dir.openFile(sharded_path, .{}) catch return error.NoSuchKey;
        defer file.close();

        var is_encrypted = false;
        if (self.headObject(bucket, key)) |meta| {
            is_encrypted = meta.encrypted;
            var m = meta;
            defer m.deinit(self.allocator);
        } else |_| {}

        if (is_encrypted) {
            const stat = try file.stat();
            const full_plaintext = try self.readEncryptedFile(file, stat.size);
            defer self.allocator.free(full_plaintext);

            if (start >= full_plaintext.len) return &.{};
            const end = @min(start + size, full_plaintext.len);

            const slice = full_plaintext[start..end];
            return self.allocator.dupe(u8, slice);
        }

        try file.seekTo(start);

        const buffer = try self.allocator.alloc(u8, size);
        errdefer self.allocator.free(buffer);

        const bytes_read = try file.readAll(buffer);

        if (bytes_read < size) {
            const result = try self.allocator.alloc(u8, bytes_read);
            @memcpy(result, buffer[0..bytes_read]);
            self.allocator.free(buffer);
            return result;
        }

        return buffer;
    }

    pub fn getObjectSize(self: *Storage, bucket: []const u8, key: []const u8) !u64 {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        const file = bucket_dir.openFile(sharded_path, .{}) catch return error.NoSuchKey;
        defer file.close();

        const stat = try file.stat();
        return stat.size;
    }

    pub fn initMultipartUpload(self: *Storage, bucket: []const u8, key: []const u8) ![]const u8 {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        bucket_dir.makeDir("_multipart") catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        var mp_root = bucket_dir.openDir("_multipart", .{}) catch return error.IOError;
        defer mp_root.close();

        const upload_id = try self.generateVersionId();

        mp_root.makeDir(upload_id) catch |err| {
            self.allocator.free(upload_id);
            return err;
        };

        const key_file = try mp_root.createFile(try std.fmt.allocPrint(self.allocator, "{s}/.key", .{upload_id}), .{});
        defer key_file.close();
        try key_file.writeAll(key);

        return upload_id;
    }

    pub fn putPart(self: *Storage, bucket: []const u8, upload_id: []const u8, part_number: u32, data: []const u8) ![]const u8 {
        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        var mp_dir = bucket_dir.openDir("_multipart", .{}) catch return error.NoSuchUpload;
        defer mp_dir.close();

        var upload_dir = mp_dir.openDir(upload_id, .{}) catch return error.NoSuchUpload;
        defer upload_dir.close();

        const part_name = try std.fmt.allocPrint(self.allocator, "{}", .{part_number});
        defer self.allocator.free(part_name);

        const file = try upload_dir.createFile(part_name, .{});
        defer file.close();
        try file.writeAll(data);

        const hash = utils.computeMd5(data);
        return utils.formatMd5Etag(self.allocator, hash);
    }

    pub fn putPartStreaming(self: *Storage, bucket: []const u8, upload_id: []const u8, part_number: u32, reader: anytype, content_length: u64, initial_data: []const u8) ![]const u8 {
        try utils.checkKeyName(upload_id);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        var mp_dir = bucket_dir.openDir("_multipart", .{}) catch return error.NoSuchUpload;
        defer mp_dir.close();

        var upload_dir = mp_dir.openDir(upload_id, .{}) catch return error.NoSuchUpload;
        defer upload_dir.close();

        const part_name = try std.fmt.allocPrint(self.allocator, "{}", .{part_number});
        defer self.allocator.free(part_name);

        const file = try upload_dir.createFile(part_name, .{});
        defer file.close();

        var hasher = std.crypto.hash.Md5.init(.{});
        var buffer: [constants.COPY_BUFFER_SIZE]u8 = undefined;
        var total_written: u64 = 0;

        if (initial_data.len > 0) {
            hasher.update(initial_data);
            try file.writeAll(initial_data);
            total_written += initial_data.len;
        }

        while (total_written < content_length) {
            const to_read = @min(buffer.len, content_length - total_written);
            const n = try reader.read(buffer[0..to_read]);
            if (n == 0) break;

            hasher.update(buffer[0..n]);
            try file.writeAll(buffer[0..n]);
            total_written += n;
        }

        var hash: [16]u8 = undefined;
        hasher.final(&hash);
        return utils.formatMd5Etag(self.allocator, hash);
    }

    pub fn completeMultipartUpload(self: *Storage, bucket: []const u8, key: []const u8, upload_id: []const u8) ![]const u8 {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        var mp_dir = bucket_dir.openDir("_multipart", .{}) catch return error.NoSuchUpload;
        defer mp_dir.close();

        var upload_dir = mp_dir.openDir(upload_id, .{ .iterate = true }) catch return error.NoSuchUpload;
        defer upload_dir.close();

        var parts = try std.ArrayList(u32).initCapacity(self.allocator, 32);
        defer parts.deinit(self.allocator);

        var iter = upload_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file and !std.mem.eql(u8, entry.name, ".key")) {
                const p = std.fmt.parseInt(u32, entry.name, 10) catch continue;
                try parts.append(self.allocator, p);
            }
        }

        std.mem.sort(u32, parts.items, {}, std.sort.asc(u32));

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        if (fs.path.dirname(sharded_path)) |dirname| {
            bucket_dir.makePath(dirname) catch {};
        }

        const dest_file = try bucket_dir.createFile(sharded_path, .{});
        defer dest_file.close();

        var hasher = std.crypto.hash.Md5.init(.{});

        for (parts.items) |p_num| {
            const part_name = try std.fmt.allocPrint(self.allocator, "{}", .{p_num});
            defer self.allocator.free(part_name);

            const part_file = try upload_dir.openFile(part_name, .{});
            defer part_file.close();

            var buffer: [constants.COPY_BUFFER_SIZE]u8 = undefined;
            while (true) {
                const n = try part_file.read(&buffer);
                if (n == 0) break;
                hasher.update(buffer[0..n]);
                try dest_file.writeAll(buffer[0..n]);
            }
        }

        mp_dir.deleteTree(upload_id) catch {};

        var hash: [16]u8 = undefined;
        hasher.final(&hash);
        const part_count = parts.items.len;
        return std.fmt.allocPrint(self.allocator, "\"{x}-{}\"", .{ hash, part_count });
    }

    pub fn putObjectTagging(self: *Storage, bucket: []const u8, key: []const u8, tags: std.StringHashMap([]const u8)) !void {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        bucket_dir.access(sharded_path, .{}) catch return error.NoSuchKey;

        const tags_path = try std.fmt.allocPrint(self.allocator, "{s}.tags", .{sharded_path});
        defer self.allocator.free(tags_path);

        const tags_file = try bucket_dir.createFile(tags_path, .{});
        defer tags_file.close();

        var iter = tags.iterator();
        while (iter.next()) |entry| {
            const line = try std.fmt.allocPrint(self.allocator, "{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            defer self.allocator.free(line);
            try tags_file.writeAll(line);
        }
    }

    pub fn getObjectTagging(self: *Storage, bucket: []const u8, key: []const u8) !std.StringHashMap([]const u8) {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        bucket_dir.access(sharded_path, .{}) catch return error.NoSuchKey;

        const tags_path = try std.fmt.allocPrint(self.allocator, "{s}.tags", .{sharded_path});
        defer self.allocator.free(tags_path);

        var tags = std.StringHashMap([]const u8).init(self.allocator);

        const file = bucket_dir.openFile(tags_path, .{}) catch {
            return tags;
        };
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);

        _ = try file.readAll(buffer);

        var iter = std.mem.splitScalar(u8, buffer, '\n');
        while (iter.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.indexOfScalar(u8, line, '=')) |eq_idx| {
                const k = try self.allocator.dupe(u8, line[0..eq_idx]);
                const v = try self.allocator.dupe(u8, std.mem.trim(u8, line[eq_idx + 1 ..], "\r"));
                try tags.put(k, v);
            }
        }

        return tags;
    }

    pub fn deleteObjectTagging(self: *Storage, bucket: []const u8, key: []const u8) !void {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        bucket_dir.access(sharded_path, .{}) catch return error.NoSuchKey;

        const tags_path = try std.fmt.allocPrint(self.allocator, "{s}.tags", .{sharded_path});
        defer self.allocator.free(tags_path);

        bucket_dir.deleteFile(tags_path) catch |err| {
            if (err != error.FileNotFound) return err;
        };
    }

    pub fn putBucketTagging(self: *Storage, bucket: []const u8, tags: std.StringHashMap([]const u8)) !void {
        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const tags_file = try bucket_dir.createFile("_bucket.tags", .{});
        defer tags_file.close();

        var iter = tags.iterator();
        while (iter.next()) |entry| {
            const line = try std.fmt.allocPrint(self.allocator, "{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            defer self.allocator.free(line);
            try tags_file.writeAll(line);
        }
    }

    pub fn getBucketTagging(self: *Storage, bucket: []const u8) !std.StringHashMap([]const u8) {
        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        var tags = std.StringHashMap([]const u8).init(self.allocator);

        const file = bucket_dir.openFile("_bucket.tags", .{}) catch {
            return tags;
        };
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);

        _ = try file.readAll(buffer);

        var iter = std.mem.splitScalar(u8, buffer, '\n');
        while (iter.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.indexOfScalar(u8, line, '=')) |eq_idx| {
                const k = try self.allocator.dupe(u8, line[0..eq_idx]);
                const v = try self.allocator.dupe(u8, std.mem.trim(u8, line[eq_idx + 1 ..], "\r"));
                try tags.put(k, v);
            }
        }

        return tags;
    }

    pub fn deleteBucketTagging(self: *Storage, bucket: []const u8) !void {
        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        bucket_dir.deleteFile("_bucket.tags") catch |err| {
            if (err != error.FileNotFound) return err;
        };
    }

    pub const AclPermission = enum {
        FULL_CONTROL,
        READ,
        WRITE,
        READ_ACP,
        WRITE_ACP,
    };

    pub fn putBucketAcl(self: *Storage, bucket: []const u8, owner: []const u8, grants: []const AclGrant) !void {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const acl_path = try std.fmt.allocPrint(self.allocator, "{s}.acl", .{bucket});
        defer self.allocator.free(acl_path);

        const acl_file = try buckets_meta.createFile(acl_path, .{});
        defer acl_file.close();

        const owner_line = try std.fmt.allocPrint(self.allocator, "owner={s}\n", .{owner});
        defer self.allocator.free(owner_line);
        try acl_file.writeAll(owner_line);

        for (grants) |grant| {
            const perm_str = switch (grant.permission) {
                .FULL_CONTROL => "FULL_CONTROL",
                .READ => "READ",
                .WRITE => "WRITE",
                .READ_ACP => "READ_ACP",
                .WRITE_ACP => "WRITE_ACP",
            };
            const line = try std.fmt.allocPrint(self.allocator, "grant={s}|{s}\n", .{ grant.grantee, perm_str });
            defer self.allocator.free(line);
            try acl_file.writeAll(line);
        }
    }

    pub const AclGrant = struct {
        grantee: []const u8,
        permission: AclPermission,
    };

    pub const AclInfo = struct {
        owner: []const u8,
        grants: []AclGrant,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *AclInfo) void {
            self.allocator.free(self.owner);
            for (self.grants) |g| {
                self.allocator.free(g.grantee);
            }
            self.allocator.free(self.grants);
        }
    };

    pub fn getBucketAcl(self: *Storage, bucket: []const u8) !AclInfo {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const acl_path = try std.fmt.allocPrint(self.allocator, "{s}.acl", .{bucket});
        defer self.allocator.free(acl_path);

        const file = buckets_meta.openFile(acl_path, .{}) catch {
            return AclInfo{
                .owner = try self.allocator.dupe(u8, "default"),
                .grants = try self.allocator.alloc(AclGrant, 0),
                .allocator = self.allocator,
            };
        };
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);
        _ = try file.readAll(buffer);

        var owner: []const u8 = try self.allocator.dupe(u8, "default");
        var grants_list = try std.ArrayList(AclGrant).initCapacity(self.allocator, 8);

        var iter = std.mem.splitScalar(u8, buffer, '\n');
        while (iter.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "owner=")) {
                self.allocator.free(owner);
                owner = try self.allocator.dupe(u8, line[6..]);
            } else if (std.mem.startsWith(u8, line, "grant=")) {
                const grant_str = line[6..];
                if (std.mem.lastIndexOfScalar(u8, grant_str, '|')) |pipe_idx| {
                    const grantee = try self.allocator.dupe(u8, grant_str[0..pipe_idx]);
                    const perm_str = grant_str[pipe_idx + 1 ..];
                    const permission: AclPermission = if (std.mem.eql(u8, perm_str, "FULL_CONTROL"))
                        .FULL_CONTROL
                    else if (std.mem.eql(u8, perm_str, "READ"))
                        .READ
                    else if (std.mem.eql(u8, perm_str, "WRITE"))
                        .WRITE
                    else if (std.mem.eql(u8, perm_str, "READ_ACP"))
                        .READ_ACP
                    else
                        .WRITE_ACP;
                    try grants_list.append(self.allocator, .{ .grantee = grantee, .permission = permission });
                }
            }
        }

        return AclInfo{
            .owner = owner,
            .grants = try grants_list.toOwnedSlice(self.allocator),
            .allocator = self.allocator,
        };
    }

    pub fn putObjectAcl(self: *Storage, bucket: []const u8, key: []const u8, owner: []const u8, grants: []const AclGrant) !void {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        bucket_dir.access(sharded_path, .{}) catch return error.NoSuchKey;

        const acl_path = try std.fmt.allocPrint(self.allocator, "{s}.acl", .{sharded_path});
        defer self.allocator.free(acl_path);

        const acl_file = try bucket_dir.createFile(acl_path, .{});
        defer acl_file.close();

        const owner_line = try std.fmt.allocPrint(self.allocator, "owner={s}\n", .{owner});
        defer self.allocator.free(owner_line);
        try acl_file.writeAll(owner_line);

        for (grants) |grant| {
            const perm_str = switch (grant.permission) {
                .FULL_CONTROL => "FULL_CONTROL",
                .READ => "READ",
                .WRITE => "WRITE",
                .READ_ACP => "READ_ACP",
                .WRITE_ACP => "WRITE_ACP",
            };
            const line = try std.fmt.allocPrint(self.allocator, "grant={s}|{s}\n", .{ grant.grantee, perm_str });
            defer self.allocator.free(line);
            try acl_file.writeAll(line);
        }
    }

    pub fn getObjectAcl(self: *Storage, bucket: []const u8, key: []const u8) !AclInfo {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        bucket_dir.access(sharded_path, .{}) catch return error.NoSuchKey;

        const acl_path = try std.fmt.allocPrint(self.allocator, "{s}.acl", .{sharded_path});
        defer self.allocator.free(acl_path);

        const file = bucket_dir.openFile(acl_path, .{}) catch {
            return error.NoSuchAcl;
        };
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);
        _ = try file.readAll(buffer);

        var owner: []const u8 = try self.allocator.dupe(u8, "default");
        var grants_list = try std.ArrayList(AclGrant).initCapacity(self.allocator, 8);

        var iter = std.mem.splitScalar(u8, buffer, '\n');
        while (iter.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "owner=")) {
                self.allocator.free(owner);
                owner = try self.allocator.dupe(u8, line[6..]);
            } else if (std.mem.startsWith(u8, line, "grant=")) {
                const grant_str = line[6..];
                if (std.mem.lastIndexOfScalar(u8, grant_str, '|')) |pipe_idx| {
                    const grantee = try self.allocator.dupe(u8, grant_str[0..pipe_idx]);
                    const perm_str = grant_str[pipe_idx + 1 ..];
                    const permission: AclPermission = if (std.mem.eql(u8, perm_str, "FULL_CONTROL"))
                        .FULL_CONTROL
                    else if (std.mem.eql(u8, perm_str, "READ"))
                        .READ
                    else if (std.mem.eql(u8, perm_str, "WRITE"))
                        .WRITE
                    else if (std.mem.eql(u8, perm_str, "READ_ACP"))
                        .READ_ACP
                    else
                        .WRITE_ACP;
                    try grants_list.append(self.allocator, .{ .grantee = grantee, .permission = permission });
                }
            }
        }

        return AclInfo{
            .owner = owner,
            .grants = try grants_list.toOwnedSlice(self.allocator),
            .allocator = self.allocator,
        };
    }

    pub fn putBucketPolicy(self: *Storage, bucket: []const u8, policy_json: []const u8) !void {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const policy_path = try std.fmt.allocPrint(self.allocator, "{s}.policy", .{bucket});
        defer self.allocator.free(policy_path);

        const policy_file = try buckets_meta.createFile(policy_path, .{});
        defer policy_file.close();

        try policy_file.writeAll(policy_json);
    }

    pub fn getBucketPolicy(self: *Storage, bucket: []const u8) ![]u8 {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const policy_path = try std.fmt.allocPrint(self.allocator, "{s}.policy", .{bucket});
        defer self.allocator.free(policy_path);

        const file = buckets_meta.openFile(policy_path, .{}) catch return error.NoSuchBucketPolicy;
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        _ = try file.readAll(buffer);

        return buffer;
    }

    pub fn deleteBucketPolicy(self: *Storage, bucket: []const u8) !void {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const policy_path = try std.fmt.allocPrint(self.allocator, "{s}.policy", .{bucket});
        defer self.allocator.free(policy_path);

        buckets_meta.deleteFile(policy_path) catch |err| {
            if (err == error.FileNotFound) return error.NoSuchBucketPolicy;
            return err;
        };
    }

    pub const PolicyAction = enum {
        GetObject,
        PutObject,
        DeleteObject,
        ListBucket,
        GetBucketAcl,
        PutBucketAcl,
        CreateBucket,
        DeleteBucket,
        GetBucketLocation,
    };

    pub fn evaluatePolicy(self: *Storage, bucket: []const u8, action: PolicyAction, principal: []const u8, resource: []const u8) bool {
        _ = principal;
        _ = resource;

        const policy = self.getBucketPolicy(bucket) catch {
            return true;
        };
        defer self.allocator.free(policy);

        const action_str = switch (action) {
            .GetObject => "s3:GetObject",
            .PutObject => "s3:PutObject",
            .DeleteObject => "s3:DeleteObject",
            .ListBucket => "s3:ListBucket",
            .GetBucketAcl => "s3:GetBucketAcl",
            .PutBucketAcl => "s3:PutBucketAcl",
            .CreateBucket => "s3:CreateBucket",
            .DeleteBucket => "s3:DeleteBucket",
            .GetBucketLocation => "s3:GetBucketLocation",
        };

        if (std.mem.indexOf(u8, policy, action_str) == null) {
            return true;
        }

        if (std.mem.indexOf(u8, policy, "\"Effect\":\"Deny\"") != null or
            std.mem.indexOf(u8, policy, "\"Effect\": \"Deny\"") != null)
        {
            if (std.mem.indexOf(u8, policy, action_str)) |action_pos| {
                const search_start = if (action_pos > 500) action_pos - 500 else 0;
                const search_slice = policy[search_start..action_pos];
                if (std.mem.indexOf(u8, search_slice, "\"Effect\":\"Deny\"") != null or
                    std.mem.indexOf(u8, search_slice, "\"Effect\": \"Deny\"") != null)
                {
                    return false;
                }
            }
        }

        return true;
    }

    pub const EncryptionAlgorithm = enum {
        AES256,
        AWSKMS,

        pub fn toString(self: EncryptionAlgorithm) []const u8 {
            return switch (self) {
                .AES256 => "AES256",
                .AWSKMS => "aws:kms",
            };
        }
    };

    pub const EncryptionConfig = struct {
        enabled: bool = false,
        algorithm: EncryptionAlgorithm = .AES256,
    };

    pub fn putBucketEncryption(self: *Storage, bucket: []const u8, algorithm: []const u8) !void {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const enc_path = try std.fmt.allocPrint(self.allocator, "{s}.encryption", .{bucket});
        defer self.allocator.free(enc_path);

        const enc_file = try buckets_meta.createFile(enc_path, .{});
        defer enc_file.close();

        const alg_enum: EncryptionAlgorithm = if (std.mem.indexOf(u8, algorithm, "kms") != null) .AWSKMS else .AES256;
        const line = try std.fmt.allocPrint(self.allocator, "enabled=true\nalgorithm={s}\n", .{alg_enum.toString()});
        defer self.allocator.free(line);
        try enc_file.writeAll(line);
    }

    pub fn getBucketEncryption(self: *Storage, bucket: []const u8) !EncryptionConfig {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const enc_path = try std.fmt.allocPrint(self.allocator, "{s}.encryption", .{bucket});
        defer self.allocator.free(enc_path);

        const file = buckets_meta.openFile(enc_path, .{}) catch {
            return EncryptionConfig{ .enabled = false };
        };
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);
        _ = try file.readAll(buffer);

        var enabled = false;
        var algorithm: EncryptionAlgorithm = .AES256;

        var iter = std.mem.splitScalar(u8, buffer, '\n');
        while (iter.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "enabled=")) {
                enabled = std.mem.eql(u8, line[8..], "true");
            } else if (std.mem.startsWith(u8, line, "algorithm=")) {
                const alg_str = line[10..];
                if (std.mem.indexOf(u8, alg_str, "kms") != null) {
                    algorithm = .AWSKMS;
                } else {
                    algorithm = .AES256;
                }
            }
        }

        return EncryptionConfig{
            .enabled = enabled,
            .algorithm = algorithm,
        };
    }

    pub fn deleteBucketEncryption(self: *Storage, bucket: []const u8) !void {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const enc_path = try std.fmt.allocPrint(self.allocator, "{s}.encryption", .{bucket});
        defer self.allocator.free(enc_path);

        buckets_meta.deleteFile(enc_path) catch |err| {
            if (err != error.FileNotFound) return err;
        };
    }

    pub const VersioningStatus = enum {
        Enabled,
        Suspended,
        Disabled,

        pub fn toString(self: VersioningStatus) []const u8 {
            return switch (self) {
                .Enabled => "Enabled",
                .Suspended => "Suspended",
                .Disabled => "",
            };
        }
    };

    pub fn putBucketVersioning(self: *Storage, bucket: []const u8, status: VersioningStatus) !void {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const ver_path = try std.fmt.allocPrint(self.allocator, "{s}.versioning", .{bucket});
        defer self.allocator.free(ver_path);

        const ver_file = try buckets_meta.createFile(ver_path, .{});
        defer ver_file.close();

        const line = try std.fmt.allocPrint(self.allocator, "status={s}\n", .{status.toString()});
        defer self.allocator.free(line);
        try ver_file.writeAll(line);
    }

    pub fn getBucketVersioning(self: *Storage, bucket: []const u8) !VersioningStatus {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const ver_path = try std.fmt.allocPrint(self.allocator, "{s}.versioning", .{bucket});
        defer self.allocator.free(ver_path);

        const file = buckets_meta.openFile(ver_path, .{}) catch {
            return .Disabled;
        };
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);
        _ = try file.readAll(buffer);

        var iter = std.mem.splitScalar(u8, buffer, '\n');
        while (iter.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "status=")) {
                const status_str = line[7..];
                if (std.mem.eql(u8, status_str, "Enabled")) {
                    return .Enabled;
                } else if (std.mem.eql(u8, status_str, "Suspended")) {
                    return .Suspended;
                }
            }
        }

        return .Disabled;
    }

    pub fn putBucketLifecycle(self: *Storage, bucket: []const u8, lifecycle_xml: []const u8) !void {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const lc_path = try std.fmt.allocPrint(self.allocator, "{s}.lifecycle", .{bucket});
        defer self.allocator.free(lc_path);

        const lifecycle_file = try buckets_meta.createFile(lc_path, .{});
        defer lifecycle_file.close();

        try lifecycle_file.writeAll(lifecycle_xml);
    }

    pub fn getBucketLifecycle(self: *Storage, bucket: []const u8) ![]u8 {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const lc_path = try std.fmt.allocPrint(self.allocator, "{s}.lifecycle", .{bucket});
        defer self.allocator.free(lc_path);

        const file = buckets_meta.openFile(lc_path, .{}) catch return error.NoSuchLifecycleConfiguration;
        defer file.close();

        const file_size = (try file.stat()).size;
        const buffer = try self.allocator.alloc(u8, file_size);
        _ = try file.readAll(buffer);

        return buffer;
    }

    pub fn deleteBucketLifecycle(self: *Storage, bucket: []const u8) !void {
        self.root_dir.access(bucket, .{}) catch return error.NoSuchBucket;

        var buckets_meta = self.meta_dir.openDir("buckets", .{}) catch return error.InternalError;
        defer buckets_meta.close();

        const lc_path = try std.fmt.allocPrint(self.allocator, "{s}.lifecycle", .{bucket});
        defer self.allocator.free(lc_path);

        buckets_meta.deleteFile(lc_path) catch |err| {
            if (err != error.FileNotFound) return err;
        };
    }

    pub fn generateVersionId(self: *Storage) ![]u8 {
        var rand_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&rand_bytes);
        const timestamp = std.time.nanoTimestamp();
        const ts_bytes: [8]u8 = @bitCast(@as(u64, @intCast(timestamp)));
        var combined: [24]u8 = undefined;
        @memcpy(combined[0..8], &ts_bytes);
        @memcpy(combined[8..24], &rand_bytes);
        return std.fmt.allocPrint(self.allocator, "{x}", .{combined});
    }

    pub fn putObjectVersionedStreaming(self: *Storage, bucket: []const u8, key: []const u8, reader: anytype, content_length: u64, content_type: []const u8, user_metadata: std.StringHashMap([]const u8), initial_data: []const u8) ![]const u8 {
        try utils.checkKeyName(key);

        const versioning = try self.getBucketVersioning(bucket);
        if (versioning != .Enabled) {
            _ = try self.putObjectStreaming(bucket, key, reader, content_length, content_type, user_metadata, initial_data);
            return self.allocator.dupe(u8, "null");
        }

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        if (std.fs.path.dirname(sharded_path)) |dir| {
            try bucket_dir.makePath(dir);
        }

        const version_id = try self.generateVersionId();
        const versioned_path = try std.fmt.allocPrint(self.allocator, "{s}.v{s}", .{ sharded_path, version_id });
        defer self.allocator.free(versioned_path);

        const file = try bucket_dir.createFile(versioned_path, .{});
        defer file.close();

        var hasher = std.crypto.hash.Md5.init(.{});
        var buffer: [constants.COPY_BUFFER_SIZE]u8 = undefined;
        var total_written: u64 = 0;

        if (initial_data.len > 0) {
            hasher.update(initial_data);
            try file.writeAll(initial_data);
            total_written += initial_data.len;
        }

        while (total_written < content_length) {
            const to_read = @min(buffer.len, content_length - total_written);
            const n = try reader.read(buffer[0..to_read]);
            if (n == 0) break;

            hasher.update(buffer[0..n]);
            try file.writeAll(buffer[0..n]);
            total_written += n;
        }

        var hash: [16]u8 = undefined;
        hasher.final(&hash);
        const etag_str = try utils.formatMd5Etag(self.allocator, hash);
        defer self.allocator.free(etag_str);

        const meta_path = try std.fmt.allocPrint(self.allocator, "{s}.meta", .{versioned_path});
        defer self.allocator.free(meta_path);

        const meta_file = try bucket_dir.createFile(meta_path, .{});
        defer meta_file.close();

        const timestamp = std.time.milliTimestamp();
        const meta_content = try std.fmt.allocPrint(self.allocator, "content_type={s}\netag={s}\nsize={}\nlast_modified={}\nversion_id={s}\n", .{ content_type, etag_str, total_written, timestamp, version_id });
        defer self.allocator.free(meta_content);
        try meta_file.writeAll(meta_content);

        var iter = user_metadata.iterator();
        while (iter.next()) |entry| {
            const line = try std.fmt.allocPrint(self.allocator, "{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            defer self.allocator.free(line);
            try meta_file.writeAll(line);
        }

        const current_path = try std.fmt.allocPrint(self.allocator, "{s}.current", .{sharded_path});
        defer self.allocator.free(current_path);
        const current_file = try bucket_dir.createFile(current_path, .{});
        defer current_file.close();
        try current_file.writeAll(version_id);

        return version_id;
    }

    pub fn putObjectVersioned(self: *Storage, bucket: []const u8, key: []const u8, data: []const u8, content_type: []const u8, user_metadata: std.StringHashMap([]const u8)) ![]u8 {
        try utils.checkKeyName(key);

        const versioning = try self.getBucketVersioning(bucket);
        if (versioning != .Enabled) {
            try self.putObject(bucket, key, data, content_type, user_metadata);
            return self.allocator.dupe(u8, "null");
        }

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        if (std.fs.path.dirname(sharded_path)) |dir| {
            try bucket_dir.makePath(dir);
        }

        const version_id = try self.generateVersionId();

        const versioned_path = try std.fmt.allocPrint(self.allocator, "{s}.v{s}", .{ sharded_path, version_id });
        defer self.allocator.free(versioned_path);

        const file = try bucket_dir.createFile(versioned_path, .{});
        defer file.close();
        try file.writeAll(data);

        const etag = utils.computeMd5(data);
        const etag_str = try utils.formatMd5Etag(self.allocator, etag);
        defer self.allocator.free(etag_str);

        const meta_path = try std.fmt.allocPrint(self.allocator, "{s}.meta", .{versioned_path});
        defer self.allocator.free(meta_path);

        const meta_file = try bucket_dir.createFile(meta_path, .{});
        defer meta_file.close();

        const timestamp = std.time.milliTimestamp();
        const meta_content = try std.fmt.allocPrint(self.allocator, "content_type={s}\netag={s}\nsize={}\nlast_modified={}\nversion_id={s}\n", .{ content_type, etag_str, data.len, timestamp, version_id });
        defer self.allocator.free(meta_content);
        try meta_file.writeAll(meta_content);

        var iter = user_metadata.iterator();
        while (iter.next()) |entry| {
            const line = try std.fmt.allocPrint(self.allocator, "{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            defer self.allocator.free(line);
            try meta_file.writeAll(line);
        }

        const current_path = try std.fmt.allocPrint(self.allocator, "{s}.current", .{sharded_path});
        defer self.allocator.free(current_path);

        const current_file = try bucket_dir.createFile(current_path, .{});
        defer current_file.close();
        try current_file.writeAll(version_id);

        return version_id;
    }

    pub fn getObjectVersioned(self: *Storage, bucket: []const u8, key: []const u8, version_id: ?[]const u8) ![]u8 {
        try utils.checkKeyName(key);

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        if (version_id) |vid| {
            const versioned_path = try std.fmt.allocPrint(self.allocator, "{s}.v{s}", .{ sharded_path, vid });
            defer self.allocator.free(versioned_path);

            const file = bucket_dir.openFile(versioned_path, .{}) catch return error.NoSuchKey;
            defer file.close();
            return try file.readToEndAlloc(self.allocator, constants.MAX_OBJECT_SIZE);
        }

        const current_path = try std.fmt.allocPrint(self.allocator, "{s}.current", .{sharded_path});
        defer self.allocator.free(current_path);

        if (bucket_dir.openFile(current_path, .{})) |f| {
            defer f.close();
            const current_vid = try f.readToEndAlloc(self.allocator, 256);
            defer self.allocator.free(current_vid);

            const versioned_path = try std.fmt.allocPrint(self.allocator, "{s}.v{s}", .{ sharded_path, current_vid });
            defer self.allocator.free(versioned_path);

            const file = bucket_dir.openFile(versioned_path, .{}) catch return error.NoSuchKey;
            defer file.close();
            return try file.readToEndAlloc(self.allocator, constants.MAX_OBJECT_SIZE);
        } else |_| {
            return self.getObject(bucket, key);
        }
    }

    pub fn deleteObjectVersioned(self: *Storage, bucket: []const u8, key: []const u8) ![]u8 {
        try utils.checkKeyName(key);

        const versioning = try self.getBucketVersioning(bucket);
        if (versioning != .Enabled) {
            try self.deleteObject(bucket, key);
            return self.allocator.dupe(u8, "null");
        }

        var bucket_dir = self.root_dir.openDir(bucket, .{}) catch return error.NoSuchBucket;
        defer bucket_dir.close();

        const sharded_path = try getShardedPath(self.allocator, key);
        defer self.allocator.free(sharded_path);

        const version_id = try self.generateVersionId();

        const marker_path = try std.fmt.allocPrint(self.allocator, "{s}.v{s}.deleted", .{ sharded_path, version_id });
        defer self.allocator.free(marker_path);

        if (std.fs.path.dirname(sharded_path)) |dir| {
            try bucket_dir.makePath(dir);
        }

        const marker_file = try bucket_dir.createFile(marker_path, .{});
        defer marker_file.close();
        try marker_file.writeAll("DELETE_MARKER");

        const current_path = try std.fmt.allocPrint(self.allocator, "{s}.current", .{sharded_path});
        defer self.allocator.free(current_path);

        bucket_dir.deleteFile(current_path) catch {};

        return version_id;
    }

    pub fn setEncryptionKey(self: *Storage, key: []const u8) !void {
        if (key.len < constants.MIN_ENCRYPTION_KEY_LENGTH) {
            return error.KeyTooShort;
        }
        var k: [32]u8 = undefined;
        @memcpy(&k, key[0..32]);
        self.encryption_key = k;
    }

    pub fn encrypt(self: *Storage, plaintext: []const u8) ![]u8 {
        const key = self.encryption_key orelse return self.allocator.dupe(u8, plaintext);

        var nonce: [12]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        const ciphertext_len = plaintext.len + Aes256Gcm.tag_length;
        const result = try self.allocator.alloc(u8, 12 + ciphertext_len);

        @memcpy(result[0..12], &nonce);

        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        Aes256Gcm.encrypt(result[12 .. 12 + plaintext.len], &tag, plaintext, &.{}, nonce, key);
        @memcpy(result[12 + plaintext.len ..], &tag);

        return result;
    }

    pub fn decrypt(self: *Storage, ciphertext: []const u8) ![]u8 {
        const key = self.encryption_key orelse return self.allocator.dupe(u8, ciphertext);

        if (ciphertext.len < 12 + Aes256Gcm.tag_length) {
            return error.InvalidCiphertext;
        }

        const nonce: [12]u8 = ciphertext[0..12].*;
        const data_len = ciphertext.len - 12 - Aes256Gcm.tag_length;
        const encrypted = ciphertext[12 .. 12 + data_len];
        const tag: [Aes256Gcm.tag_length]u8 = ciphertext[12 + data_len ..][0..Aes256Gcm.tag_length].*;

        const plaintext = try self.allocator.alloc(u8, data_len);
        Aes256Gcm.decrypt(plaintext, encrypted, tag, &.{}, nonce, key) catch {
            self.allocator.free(plaintext);
            return error.DecryptionFailed;
        };

        return plaintext;
    }
};
