const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const KeyManager = @import("keys.zig").KeyManager;

pub const AuthError = error{
    MissingAuthHeader,
    InvalidAuthHeader,
    SignatureMismatch,
    ExpiredRequest,
    InvalidAccessKey,
    MalformedCredential,
    AccessDenied,
    KeyNotFound,
};

pub const SignatureComponents = struct {
    access_key: []const u8,
    date: []const u8,
    region: []const u8,
    service: []const u8,
    signed_headers: []const u8,
    signature: []const u8,
};

pub fn verifyRequest(
    allocator: std.mem.Allocator,
    headers: std.StringHashMap([]const u8),
    query_args: std.StringHashMap([]const u8),
    method: []const u8,
    uri: []const u8,
    key_mgr: *KeyManager,
) !?[]const u8 {
    const auth_header = headers.get("authorization") orelse {
        if (query_args.get("X-Amz-Algorithm")) |_| {
            return verifyPresignedUrl(allocator, headers, query_args, method, uri, key_mgr);
        }
        return null;
    };

    if (!std.mem.startsWith(u8, auth_header, "AWS4-HMAC-SHA256")) {
        return AuthError.InvalidAuthHeader;
    }

    const components = try parseAuthHeader(auth_header);

    const key = key_mgr.getKeyByAccessId(components.access_key) catch return AuthError.InvalidAccessKey;
    defer key_mgr.freeKey(key);

    const amz_date = headers.get("x-amz-date") orelse headers.get("date") orelse return AuthError.InvalidAuthHeader;

    const canonical_request = try buildCanonicalRequest(allocator, method, uri, query_args, headers, components.signed_headers);
    defer allocator.free(canonical_request);

    const string_to_sign = try buildStringToSign(allocator, amz_date, components.region, components.service, canonical_request);
    defer allocator.free(string_to_sign);

    const signing_key = deriveSigningKey(key.secret_key, components.date, components.region, components.service);

    var expected_sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected_sig, string_to_sign, &signing_key);

    var expected_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&expected_hex, "{x}", .{expected_sig}) catch return AuthError.SignatureMismatch;

    if (!std.mem.eql(u8, &expected_hex, components.signature)) {
        return AuthError.SignatureMismatch;
    }
    return components.access_key;
}

fn verifyPresignedUrl(
    allocator: std.mem.Allocator,
    headers: std.StringHashMap([]const u8),
    query_args: std.StringHashMap([]const u8),
    method: []const u8,
    uri: []const u8,
    key_mgr: *KeyManager,
) !?[]const u8 {
    const credential = query_args.get("X-Amz-Credential") orelse return AuthError.InvalidAuthHeader;
    const amz_date = query_args.get("X-Amz-Date") orelse return AuthError.InvalidAuthHeader;
    const signed_headers_str = query_args.get("X-Amz-SignedHeaders") orelse return AuthError.InvalidAuthHeader;
    const signature = query_args.get("X-Amz-Signature") orelse return AuthError.InvalidAuthHeader;
    const expires = query_args.get("X-Amz-Expires") orelse "300";

    var cred_parts = std.mem.splitSequence(u8, credential, "%2F");
    if (cred_parts.peek() == null or cred_parts.peek().?.len == credential.len) {
        cred_parts = std.mem.splitSequence(u8, credential, "/");
    }
    const access_key_id = cred_parts.next() orelse return AuthError.MalformedCredential;
    const date = cred_parts.next() orelse return AuthError.MalformedCredential;
    const region = cred_parts.next() orelse return AuthError.MalformedCredential;
    const service = cred_parts.next() orelse return AuthError.MalformedCredential;

    const key = key_mgr.getKeyByAccessId(access_key_id) catch return AuthError.InvalidAccessKey;
    defer key_mgr.freeKey(key);

    const expires_secs = std.fmt.parseInt(i64, expires, 10) catch 300;

    const req_time = parseIso8601(amz_date) catch return AuthError.InvalidAuthHeader;
    const now = std.time.timestamp();
    if (now > req_time + expires_secs) {
        return AuthError.ExpiredRequest;
    }

    var filtered_query = std.StringHashMap([]const u8).init(allocator);
    defer filtered_query.deinit();

    var q_iter = query_args.iterator();
    while (q_iter.next()) |entry| {
        if (!std.mem.eql(u8, entry.key_ptr.*, "X-Amz-Signature")) {
            try filtered_query.put(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    const canonical_request = try buildCanonicalRequest(allocator, method, uri, filtered_query, headers, signed_headers_str);
    defer allocator.free(canonical_request);

    const string_to_sign = try buildStringToSign(allocator, amz_date, region, service, canonical_request);
    defer allocator.free(string_to_sign);

    const signing_key = deriveSigningKey(key.secret_key, date, region, service);

    var expected_sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected_sig, string_to_sign, &signing_key);

    var expected_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&expected_hex, "{x}", .{expected_sig}) catch return AuthError.SignatureMismatch;

    if (!std.mem.eql(u8, &expected_hex, signature)) {
        return AuthError.SignatureMismatch;
    }
    return access_key_id;
}

pub fn parseAuthHeader(header: []const u8) !SignatureComponents {
    var result: SignatureComponents = undefined;

    const credential_start = std.mem.indexOf(u8, header, "Credential=") orelse return AuthError.InvalidAuthHeader;
    const credential_end = std.mem.indexOfPos(u8, header, credential_start, ",") orelse header.len;
    const credential = header[credential_start + 11 .. credential_end];

    var cred_parts = std.mem.splitSequence(u8, credential, "%2F");
    if (cred_parts.peek() == null or cred_parts.peek().?.len == credential.len) {
        cred_parts = std.mem.splitSequence(u8, credential, "/");
    }

    result.access_key = cred_parts.next() orelse return AuthError.MalformedCredential;
    result.date = cred_parts.next() orelse return AuthError.MalformedCredential;
    result.region = cred_parts.next() orelse return AuthError.MalformedCredential;
    result.service = cred_parts.next() orelse return AuthError.MalformedCredential;

    const sh_start = std.mem.indexOf(u8, header, "SignedHeaders=") orelse return AuthError.InvalidAuthHeader;
    const sh_end = std.mem.indexOfPos(u8, header, sh_start, ",") orelse header.len;
    result.signed_headers = header[sh_start + 14 .. sh_end];

    const sig_start = std.mem.indexOf(u8, header, "Signature=") orelse return AuthError.InvalidAuthHeader;
    result.signature = std.mem.trim(u8, header[sig_start + 10 ..], " ,");

    return result;
}

pub fn getUserId(headers: std.StringHashMap([]const u8), query_args: std.StringHashMap([]const u8)) ?[]const u8 {
    if (headers.get("authorization")) |h| {
        if (parseAuthHeader(h)) |c| return c.access_key else |_| {}
    }
    if (query_args.get("X-Amz-Credential")) |c| {
        var it = std.mem.splitSequence(u8, c, "%2F");
        const part1 = it.next() orelse return null;
        if (part1.len == c.len) {
            var it2 = std.mem.splitScalar(u8, c, '/');
            return it2.next();
        }
        return part1;
    }
    return null;
}

fn buildCanonicalRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    uri: []const u8,
    query_args: std.StringHashMap([]const u8),
    headers: std.StringHashMap([]const u8),
    signed_headers_str: []const u8,
) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    const writer = result.writer(allocator);

    try writer.print("{s}\n", .{method});

    const path_end = std.mem.indexOfScalar(u8, uri, '?') orelse uri.len;
    const path = if (uri.len > 0 and uri[0] == '/') uri[0..path_end] else "/";
    try writer.print("{s}\n", .{path});

    var sorted_keys: std.ArrayList([]const u8) = .empty;
    defer sorted_keys.deinit(allocator);

    var q_iter = query_args.iterator();
    while (q_iter.next()) |entry| {
        try sorted_keys.append(allocator, entry.key_ptr.*);
    }

    std.mem.sort([]const u8, sorted_keys.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    for (sorted_keys.items, 0..) |key, i| {
        if (i > 0) try writer.writeByte('&');
        try writer.print("{s}={s}", .{ key, query_args.get(key) orelse "" });
    }
    try writer.writeByte('\n');

    var signed_headers = std.mem.splitScalar(u8, signed_headers_str, ';');
    while (signed_headers.next()) |header_name| {
        const value = headers.get(header_name) orelse "";
        try writer.print("{s}:{s}\n", .{ header_name, std.mem.trim(u8, value, " ") });
    }
    try writer.writeByte('\n');

    try writer.print("{s}\n", .{signed_headers_str});

    const payload_hash = headers.get("x-amz-content-sha256") orelse "UNSIGNED-PAYLOAD";
    try writer.print("{s}", .{payload_hash});

    return result.toOwnedSlice(allocator);
}

fn buildStringToSign(
    allocator: std.mem.Allocator,
    amz_date: []const u8,
    region: []const u8,
    service: []const u8,
    canonical_request: []const u8,
) ![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(canonical_request);
    var canonical_hash: [32]u8 = undefined;
    hasher.final(&canonical_hash);

    const date_stamp = if (amz_date.len >= 8) amz_date[0..8] else amz_date;

    return std.fmt.allocPrint(allocator, "AWS4-HMAC-SHA256\n{s}\n{s}/{s}/{s}/aws4_request\n{x}", .{
        amz_date,
        date_stamp,
        region,
        service,
        canonical_hash,
    });
}

fn deriveSigningKey(secret_key: []const u8, date_stamp: []const u8, region: []const u8, service: []const u8) [32]u8 {
    var k_secret_buf: [256]u8 = undefined;
    const k_secret_len = 4 + secret_key.len;
    @memcpy(k_secret_buf[0..4], "AWS4");
    @memcpy(k_secret_buf[4..k_secret_len], secret_key);
    const k_secret = k_secret_buf[0..k_secret_len];

    var k_date: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&k_date, date_stamp, k_secret);

    var k_region: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&k_region, region, &k_date);

    var k_service: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&k_service, service, &k_region);

    var signing_key: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&signing_key, "aws4_request", &k_service);

    return signing_key;
}

pub fn verifyGossipMessage(message: []const u8, secret: []const u8) bool {
    if (secret.len == 0) return true;
    if (message.len < 64) return false;

    const sig_hex = message[message.len - 64 ..];
    const payload = message[0 .. message.len - 65];

    var expected: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected, payload, secret);

    var expected_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&expected_hex, "{x}", .{expected}) catch return false;

    return std.mem.eql(u8, &expected_hex, sig_hex);
}

pub fn signGossipMessage(allocator: std.mem.Allocator, payload: []const u8, secret: []const u8) ![]u8 {
    if (secret.len == 0) {
        return allocator.dupe(u8, payload);
    }

    var sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&sig, payload, secret);

    return std.fmt.allocPrint(allocator, "{s} {x}", .{ payload, sig });
}

fn parseIso8601(date: []const u8) !i64 {
    if (date.len != 16 or date[8] != 'T' or date[15] != 'Z') return error.InvalidDateFormat;

    const year = try std.fmt.parseInt(u16, date[0..4], 10);
    const month = try std.fmt.parseInt(u8, date[4..6], 10);
    const day = try std.fmt.parseInt(u8, date[6..8], 10);
    const hour = try std.fmt.parseInt(u8, date[9..11], 10);
    const minute = try std.fmt.parseInt(u8, date[11..13], 10);
    const second = try std.fmt.parseInt(u8, date[13..15], 10);

    var days: u64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) {
        days += if (isLeap(y)) 366 else 365;
    }

    const days_in_month = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        days += days_in_month[m - 1];
        if (m == 2 and isLeap(year)) days += 1;
    }
    days += (day - 1);

    const total_secs = days * 86400 + @as(u64, hour) * 3600 + @as(u64, minute) * 60 + second;
    return @intCast(total_secs);
}

fn isLeap(y: u16) bool {
    return (y % 4 == 0) and ((y % 100 != 0) or (y % 400 == 0));
}
