const std = @import("std");
const constants = @import("constants.zig");

pub const StorageError = error{
    NoSuchBucket,
    NoSuchKey,
    InternalError,
    InvalidBucketName,
    InvalidKeyName,
    BucketAlreadyExists,
    KeyTooLong,
    PathTraversal,
};

pub fn checkBucketName(name: []const u8) bool {
    if (name.len < constants.MIN_BUCKET_NAME_LENGTH or name.len > constants.MAX_BUCKET_NAME_LENGTH) return false;
    if (name[0] == '-' or name[0] == '.') return false;
    if (name[name.len - 1] == '-' or name[name.len - 1] == '.') return false;
    if (std.mem.startsWith(u8, name, "_")) return false;
    for (name) |c| {
        switch (c) {
            'a'...'z', '0'...'9', '-', '.' => {},
            else => return false,
        }
    }
    if (std.mem.indexOf(u8, name, "..") != null) return false;
    return true;
}

pub fn checkKeyName(key: []const u8) StorageError!void {
    if (key.len == 0) return StorageError.InvalidKeyName;
    if (key.len > constants.MAX_KEY_LENGTH) return StorageError.KeyTooLong;

    if (std.mem.indexOf(u8, key, "..") != null) return StorageError.PathTraversal;
    if (key[0] == '/') return StorageError.PathTraversal;

    var i: usize = 0;
    while (i < key.len) {
        if (key[i] == '.' and i + 1 < key.len and key[i + 1] == '.') {
            return StorageError.PathTraversal;
        }
        i += 1;
    }

    const segments = std.mem.splitScalar(u8, key, '/');
    var iter = segments;
    while (iter.next()) |segment| {
        if (std.mem.eql(u8, segment, "..")) return StorageError.PathTraversal;
        if (std.mem.eql(u8, segment, ".")) continue;
    }

    return;
}

pub fn escapeXml(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var count: usize = 0;
    for (input) |c| {
        count += switch (c) {
            '<' => 4,
            '>' => 4,
            '&' => 5,
            '"' => 6,
            '\'' => 6,
            else => 1,
        };
    }

    if (count == input.len) {
        return allocator.dupe(u8, input);
    }

    var result = try allocator.alloc(u8, count);
    var idx: usize = 0;

    for (input) |c| {
        switch (c) {
            '<' => {
                @memcpy(result[idx..][0..4], "&lt;");
                idx += 4;
            },
            '>' => {
                @memcpy(result[idx..][0..4], "&gt;");
                idx += 4;
            },
            '&' => {
                @memcpy(result[idx..][0..5], "&amp;");
                idx += 5;
            },
            '"' => {
                @memcpy(result[idx..][0..6], "&quot;");
                idx += 6;
            },
            '\'' => {
                @memcpy(result[idx..][0..6], "&apos;");
                idx += 6;
            },
            else => {
                result[idx] = c;
                idx += 1;
            },
        }
    }

    return result;
}

pub fn urlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = try std.ArrayList(u8).initCapacity(allocator, input.len);
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hex = input[i + 1 .. i + 3];
            const byte = std.fmt.parseInt(u8, hex, 16) catch {
                try result.append(allocator, input[i]);
                i += 1;
                continue;
            };
            try result.append(allocator, byte);
            i += 3;
        } else if (input[i] == '+') {
            try result.append(allocator, ' ');
            i += 1;
        } else {
            try result.append(allocator, input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

pub fn computeMd5(data: []const u8) [16]u8 {
    var hasher = std.crypto.hash.Md5.init(.{});
    hasher.update(data);
    var result: [16]u8 = undefined;
    hasher.final(&result);
    return result;
}

pub fn formatMd5Etag(allocator: std.mem.Allocator, hash: [16]u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "\"{x}\"", .{hash});
}

pub fn parseContentLength(headers: std.StringHashMap([]const u8)) ?u64 {
    const value = headers.get("content-length") orelse return null;
    return std.fmt.parseInt(u64, value, 10) catch null;
}

pub fn formatTimestamp(timestamp: i64) [24]u8 {
    var buf: [24]u8 = undefined;
    const epoch_seconds: u64 = @intCast(@divTrunc(timestamp, 1000));
    const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();

    _ = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.000Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch {};

    return buf;
}
