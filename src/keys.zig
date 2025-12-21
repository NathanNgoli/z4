const std = @import("std");
const fs = std.fs;
const constants = @import("constants.zig");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const Permission = struct {
    bucket: []const u8,
    read: bool,
    write: bool,
    owner: bool,
};

pub const ApiKey = struct {
    name: []const u8,
    access_key_id: []const u8,
    secret_key: []const u8,
    created_at: i64,
};

pub const KeyManager = struct {
    allocator: std.mem.Allocator,
    keys_dir: fs.Dir,
    encryption_key: ?[32]u8,

    pub fn init(allocator: std.mem.Allocator, data_path: []const u8, encryption_key: ?[32]u8) !KeyManager {
        const meta_path = try std.fmt.allocPrint(allocator, "{s}/_z4meta/keys", .{data_path});
        defer allocator.free(meta_path);

        fs.cwd().makePath(meta_path) catch {};

        const keys_dir = try fs.cwd().openDir(meta_path, .{ .iterate = true });
        return KeyManager{
            .allocator = allocator,
            .keys_dir = keys_dir,
            .encryption_key = encryption_key,
        };
    }

    pub fn deinit(self: *KeyManager) void {
        self.keys_dir.close();
    }

    pub fn createKey(self: *KeyManager, name: []const u8) !ApiKey {
        const key_filename = try std.fmt.allocPrint(self.allocator, "{s}.key", .{name});
        defer self.allocator.free(key_filename);

        if (self.keys_dir.statFile(key_filename)) |_| {
            return error.KeyAlreadyExists;
        } else |_| {}

        var access_key_buf: [20]u8 = undefined;
        std.crypto.random.bytes(&access_key_buf);
        const access_key_id = try std.fmt.allocPrint(self.allocator, "GK{x}", .{access_key_buf});

        var secret_buf: [32]u8 = undefined;
        std.crypto.random.bytes(&secret_buf);
        const secret_key = try std.fmt.allocPrint(self.allocator, "{x}", .{secret_buf});

        const created_at = std.time.milliTimestamp();

        const file = try self.keys_dir.createFile(key_filename, .{});
        defer file.close();

        var stored_secret: []const u8 = undefined;
        var encrypted_hex: []u8 = undefined;
        defer if (self.encryption_key != null) self.allocator.free(encrypted_hex);

        if (self.encryption_key) |enc_key| {
            var nonce: [12]u8 = undefined;
            std.crypto.random.bytes(&nonce);
            var tag: [16]u8 = undefined;
            var ciphertext: [64]u8 = undefined;

            Aes256Gcm.encrypt(&ciphertext, &tag, secret_key, "", nonce, enc_key);

            encrypted_hex = try std.fmt.allocPrint(self.allocator, "ENC:{x}:{x}:{x}", .{ nonce, ciphertext, tag });
            stored_secret = encrypted_hex;
        } else {
            stored_secret = secret_key;
        }

        const content = try std.fmt.allocPrint(self.allocator, "name={s}\naccess_key_id={s}\nsecret_key={s}\ncreated_at={}\n", .{ name, access_key_id, stored_secret, created_at });
        defer self.allocator.free(content);
        try file.writeAll(content);

        const perms_filename = try std.fmt.allocPrint(self.allocator, "{s}.perms", .{name});
        defer self.allocator.free(perms_filename);
        const perms_file = try self.keys_dir.createFile(perms_filename, .{});
        perms_file.close();

        return ApiKey{
            .name = try self.allocator.dupe(u8, name),
            .access_key_id = access_key_id,
            .secret_key = secret_key,
            .created_at = created_at,
        };
    }

    pub fn getKey(self: *KeyManager, name: []const u8) !ApiKey {
        const key_filename = try std.fmt.allocPrint(self.allocator, "{s}.key", .{name});
        defer self.allocator.free(key_filename);

        const file = self.keys_dir.openFile(key_filename, .{}) catch return error.KeyNotFound;
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, constants.MAX_KEY_FILE_SIZE);
        defer self.allocator.free(content);

        var key = ApiKey{
            .name = "",
            .access_key_id = "",
            .secret_key = "",
            .created_at = 0,
        };

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.indexOfScalar(u8, line, '=')) |eq| {
                const k = line[0..eq];
                const v = line[eq + 1 ..];
                if (std.mem.eql(u8, k, "name")) {
                    key.name = try self.allocator.dupe(u8, v);
                } else if (std.mem.eql(u8, k, "access_key_id")) {
                    key.access_key_id = try self.allocator.dupe(u8, v);
                } else if (std.mem.eql(u8, k, "secret_key")) {
                    if (std.mem.startsWith(u8, v, "ENC:")) {
                        key.secret_key = try self.decryptSecretKey(v);
                    } else {
                        key.secret_key = try self.allocator.dupe(u8, v);
                    }
                } else if (std.mem.eql(u8, k, "created_at")) {
                    key.created_at = std.fmt.parseInt(i64, v, 10) catch 0;
                }
            }
        }

        return key;
    }

    fn decryptSecretKey(self: *KeyManager, encrypted: []const u8) ![]u8 {
        const enc_key = self.encryption_key orelse return error.EncryptionKeyRequired;

        if (!std.mem.startsWith(u8, encrypted, "ENC:")) return error.InvalidEncryptedFormat;
        const rest = encrypted[4..];

        var parts = std.mem.splitScalar(u8, rest, ':');
        const nonce_hex = parts.next() orelse return error.InvalidEncryptedFormat;
        const cipher_hex = parts.next() orelse return error.InvalidEncryptedFormat;
        const tag_hex = parts.next() orelse return error.InvalidEncryptedFormat;

        var nonce: [12]u8 = undefined;
        _ = std.fmt.hexToBytes(&nonce, nonce_hex) catch return error.InvalidEncryptedFormat;

        var tag: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&tag, tag_hex) catch return error.InvalidEncryptedFormat;

        var ciphertext: [64]u8 = undefined;
        _ = std.fmt.hexToBytes(&ciphertext, cipher_hex) catch return error.InvalidEncryptedFormat;

        var plaintext: [64]u8 = undefined;
        Aes256Gcm.decrypt(&plaintext, &ciphertext, tag, "", nonce, enc_key) catch return error.DecryptionFailed;

        return try self.allocator.dupe(u8, &plaintext);
    }

    pub fn getKeyByAccessId(self: *KeyManager, access_key_id: []const u8) !ApiKey {
        var iter = self.keys_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".key")) continue;

            const name = entry.name[0 .. entry.name.len - 4];
            const key = self.getKey(name) catch continue;

            if (std.mem.eql(u8, key.access_key_id, access_key_id)) {
                return key;
            }

            self.allocator.free(key.name);
            self.allocator.free(key.access_key_id);
            self.allocator.free(key.secret_key);
        }
        return error.KeyNotFound;
    }

    pub fn deleteKey(self: *KeyManager, name: []const u8) !void {
        const key_filename = try std.fmt.allocPrint(self.allocator, "{s}.key", .{name});
        defer self.allocator.free(key_filename);

        self.keys_dir.deleteFile(key_filename) catch return error.KeyNotFound;

        const perms_filename = try std.fmt.allocPrint(self.allocator, "{s}.perms", .{name});
        defer self.allocator.free(perms_filename);
        self.keys_dir.deleteFile(perms_filename) catch {};
    }

    pub fn listKeys(self: *KeyManager) ![][]const u8 {
        var names = std.ArrayList([]const u8){};

        var iter = self.keys_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".key")) continue;

            const name = entry.name[0 .. entry.name.len - 4];
            try names.append(self.allocator, try self.allocator.dupe(u8, name));
        }

        return try names.toOwnedSlice(self.allocator);
    }

    pub fn allowBucket(self: *KeyManager, key_name: []const u8, bucket: []const u8, read: bool, write: bool, owner: bool) !void {
        const perms_filename = try std.fmt.allocPrint(self.allocator, "{s}.perms", .{key_name});
        defer self.allocator.free(perms_filename);

        var existing_perms = std.ArrayList(u8){};
        defer existing_perms.deinit(self.allocator);

        if (self.keys_dir.openFile(perms_filename, .{})) |file| {
            defer file.close();
            const content = try file.readToEndAlloc(self.allocator, constants.MAX_PERMISSIONS_FILE_SIZE);
            defer self.allocator.free(content);

            var lines = std.mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
                    const line_bucket = line[0..colon];
                    if (!std.mem.eql(u8, line_bucket, bucket)) {
                        try existing_perms.appendSlice(self.allocator, line);
                        try existing_perms.append(self.allocator, '\n');
                    }
                }
            }
        } else |_| {}

        var perms_str = std.ArrayList(u8){};
        defer perms_str.deinit(self.allocator);

        try perms_str.appendSlice(self.allocator, bucket);
        try perms_str.append(self.allocator, ':');

        var first = true;
        if (read) {
            try perms_str.appendSlice(self.allocator, "read");
            first = false;
        }
        if (write) {
            if (!first) try perms_str.append(self.allocator, ',');
            try perms_str.appendSlice(self.allocator, "write");
            first = false;
        }
        if (owner) {
            if (!first) try perms_str.append(self.allocator, ',');
            try perms_str.appendSlice(self.allocator, "owner");
        }
        try perms_str.append(self.allocator, '\n');

        try existing_perms.appendSlice(self.allocator, perms_str.items);

        const file = try self.keys_dir.createFile(perms_filename, .{});
        defer file.close();
        try file.writeAll(existing_perms.items);
    }

    pub fn denyBucket(self: *KeyManager, key_name: []const u8, bucket: []const u8) !void {
        const perms_filename = try std.fmt.allocPrint(self.allocator, "{s}.perms", .{key_name});
        defer self.allocator.free(perms_filename);

        const file = self.keys_dir.openFile(perms_filename, .{}) catch return error.KeyNotFound;
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, constants.MAX_PERMISSIONS_FILE_SIZE);
        defer self.allocator.free(content);

        var new_perms = std.ArrayList(u8){};
        defer new_perms.deinit(self.allocator);

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
                const line_bucket = line[0..colon];
                if (!std.mem.eql(u8, line_bucket, bucket)) {
                    try new_perms.appendSlice(self.allocator, line);
                    try new_perms.append(self.allocator, '\n');
                }
            }
        }

        const out_file = try self.keys_dir.createFile(perms_filename, .{});
        defer out_file.close();
        try out_file.writeAll(new_perms.items);
    }

    pub fn getPermissions(self: *KeyManager, key_name: []const u8) ![]Permission {
        const perms_filename = try std.fmt.allocPrint(self.allocator, "{s}.perms", .{key_name});
        defer self.allocator.free(perms_filename);

        const file = self.keys_dir.openFile(perms_filename, .{}) catch return &[_]Permission{};
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, constants.MAX_PERMISSIONS_FILE_SIZE);
        defer self.allocator.free(content);

        var perms = std.ArrayList(Permission){};

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
                const bucket = line[0..colon];
                const perm_str = line[colon + 1 ..];

                try perms.append(self.allocator, .{
                    .bucket = try self.allocator.dupe(u8, bucket),
                    .read = std.mem.indexOf(u8, perm_str, "read") != null,
                    .write = std.mem.indexOf(u8, perm_str, "write") != null,
                    .owner = std.mem.indexOf(u8, perm_str, "owner") != null,
                });
            }
        }

        return try perms.toOwnedSlice(self.allocator);
    }

    pub fn hasPermission(self: *KeyManager, key_name: []const u8, bucket: []const u8, need_read: bool, need_write: bool) bool {
        const perms = self.getPermissions(key_name) catch return false;
        defer {
            for (perms) |p| self.allocator.free(p.bucket);
            self.allocator.free(perms);
        }

        for (perms) |p| {
            if (std.mem.eql(u8, p.bucket, bucket) or std.mem.eql(u8, p.bucket, "*")) {
                if (p.owner) return true;
                if (need_read and !p.read) continue;
                if (need_write and !p.write) continue;
                return true;
            }
        }

        return false;
    }

    pub fn freeKey(self: *KeyManager, key: ApiKey) void {
        self.allocator.free(key.name);
        self.allocator.free(key.access_key_id);
        self.allocator.free(key.secret_key);
    }
};
