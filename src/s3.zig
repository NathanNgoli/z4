const std = @import("std");
const utils = @import("utils.zig");
const constants = @import("constants.zig");

pub const S3Error = struct {
    code: []const u8,
    message: []const u8,
    resource: []const u8,
    request_id: []const u8,
};

pub fn writeErrorXml(allocator: std.mem.Allocator, writer: anytype, err: S3Error) !void {
    const escaped_message = try utils.escapeXml(allocator, err.message);
    defer allocator.free(escaped_message);
    const escaped_resource = try utils.escapeXml(allocator, err.resource);
    defer allocator.free(escaped_resource);

    try writer.print(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Error>
        \\  <Code>{s}</Code>
        \\  <Message>{s}</Message>
        \\  <Resource>{s}</Resource>
        \\  <RequestId>{s}</RequestId>
        \\</Error>
    , .{ err.code, escaped_message, escaped_resource, err.request_id });
}

pub fn writeListBucketsXml(allocator: std.mem.Allocator, writer: anytype, buckets: anytype, timestamps: ?[]const i64) !void {
    const owner_id = std.posix.getenv("Z4_OWNER_ID") orelse constants.DEFAULT_OWNER_ID;

    try writer.print(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\  <Owner>
        \\    <ID>{s}</ID>
        \\    <DisplayName>{s}</DisplayName>
        \\  </Owner>
        \\  <Buckets>
    , .{ owner_id, owner_id });

    for (buckets, 0..) |bucket, i| {
        const escaped_name = try utils.escapeXml(allocator, bucket);
        defer allocator.free(escaped_name);

        const ts = if (timestamps != null and i < timestamps.?.len) timestamps.?[i] else std.time.milliTimestamp();
        const formatted_ts = utils.formatTimestamp(ts);

        try writer.print(
            \\    <Bucket>
            \\      <Name>{s}</Name>
            \\      <CreationDate>{s}</CreationDate>
            \\    </Bucket>
        , .{ escaped_name, formatted_ts });
    }

    try writer.writeAll(
        \\  </Buckets>
        \\</ListAllMyBucketsResult>
    );
}

pub const ListObjectsV2Result = struct {
    name: []const u8,
    prefix: []const u8,
    key_count: usize,
    max_keys: usize,
    is_truncated: bool,
    continuation_token: ?[]const u8 = null,
    next_continuation_token: ?[]const u8 = null,
};

pub const ObjectInfo = struct {
    key: []const u8,
    size: u64,
    etag: []const u8,
    last_modified: i64,
    storage_class: []const u8 = "STANDARD",
};

pub fn writeListObjectsV2Xml(allocator: std.mem.Allocator, writer: anytype, result: ListObjectsV2Result, objects: []const ObjectInfo, common_prefixes: []const []const u8) !void {
    const escaped_name = try utils.escapeXml(allocator, result.name);
    defer allocator.free(escaped_name);
    const escaped_prefix = try utils.escapeXml(allocator, result.prefix);
    defer allocator.free(escaped_prefix);

    try writer.print(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\  <Name>{s}</Name>
        \\  <Prefix>{s}</Prefix>
        \\  <KeyCount>{}</KeyCount>
        \\  <MaxKeys>{}</MaxKeys>
        \\  <IsTruncated>{}</IsTruncated>
    , .{ escaped_name, escaped_prefix, result.key_count, result.max_keys, result.is_truncated });

    if (result.continuation_token) |token| {
        try writer.print("  <ContinuationToken>{s}</ContinuationToken>\n", .{token});
    }
    if (result.next_continuation_token) |token| {
        try writer.print("  <NextContinuationToken>{s}</NextContinuationToken>\n", .{token});
    }

    for (objects) |obj| {
        const escaped_key = try utils.escapeXml(allocator, obj.key);
        defer allocator.free(escaped_key);
        const formatted_ts = utils.formatTimestamp(obj.last_modified);

        try writer.print(
            \\  <Contents>
            \\    <Key>{s}</Key>
            \\    <LastModified>{s}</LastModified>
            \\    <ETag>{s}</ETag>
            \\    <Size>{}</Size>
            \\    <StorageClass>{s}</StorageClass>
            \\  </Contents>
        , .{ escaped_key, formatted_ts, obj.etag, obj.size, obj.storage_class });
    }

    for (common_prefixes) |prefix| {
        const escaped_cp = try utils.escapeXml(allocator, prefix);
        defer allocator.free(escaped_cp);
        try writer.print(
            \\  <CommonPrefixes>
            \\    <Prefix>{s}</Prefix>
            \\  </CommonPrefixes>
        , .{escaped_cp});
    }

    try writer.writeAll("</ListBucketResult>");
}

pub fn writeCopyObjectResult(allocator: std.mem.Allocator, writer: anytype, etag: []const u8, last_modified: i64) !void {
    _ = allocator;
    const formatted_ts = utils.formatTimestamp(last_modified);
    try writer.print(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<CopyObjectResult>
        \\  <ETag>{s}</ETag>
        \\  <LastModified>{s}</LastModified>
        \\</CopyObjectResult>
    , .{ etag, formatted_ts });
}

pub fn writeInitiateMultipartUploadResult(allocator: std.mem.Allocator, writer: anytype, bucket: []const u8, key: []const u8, upload_id: []const u8) !void {
    const escaped_bucket = try utils.escapeXml(allocator, bucket);
    defer allocator.free(escaped_bucket);
    const escaped_key = try utils.escapeXml(allocator, key);
    defer allocator.free(escaped_key);

    try writer.print(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\  <Bucket>{s}</Bucket>
        \\  <Key>{s}</Key>
        \\  <UploadId>{s}</UploadId>
        \\</InitiateMultipartUploadResult>
    , .{ escaped_bucket, escaped_key, upload_id });
}

pub fn writeCompleteMultipartUploadResult(allocator: std.mem.Allocator, writer: anytype, location: []const u8, bucket: []const u8, key: []const u8, etag: []const u8) !void {
    const escaped_bucket = try utils.escapeXml(allocator, bucket);
    defer allocator.free(escaped_bucket);
    const escaped_key = try utils.escapeXml(allocator, key);
    defer allocator.free(escaped_key);
    const escaped_location = try utils.escapeXml(allocator, location);
    defer allocator.free(escaped_location);

    try writer.print(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\  <Location>{s}</Location>
        \\  <Bucket>{s}</Bucket>
        \\  <Key>{s}</Key>
        \\  <ETag>{s}</ETag>
        \\</CompleteMultipartUploadResult>
    , .{ escaped_location, escaped_bucket, escaped_key, etag });
}

pub fn writeDeleteResult(writer: anytype, deleted_keys: []const []const u8, errors: []const struct { key: []const u8, code: []const u8, message: []const u8 }) !void {
    try writer.writeAll(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    );

    for (deleted_keys) |key| {
        try writer.print("  <Deleted><Key>{s}</Key></Deleted>\n", .{key});
    }

    for (errors) |e| {
        try writer.print(
            \\  <Error>
            \\    <Key>{s}</Key>
            \\    <Code>{s}</Code>
            \\    <Message>{s}</Message>
            \\  </Error>
        , .{ e.key, e.code, e.message });
    }

    try writer.writeAll("</DeleteResult>");
}
