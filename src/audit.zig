const std = @import("std");
const log = @import("log.zig");

pub const Action = enum {
    PutObject,
    DeleteObject,
    GetObject,
    PutBucket,
    DeleteBucket,
    PutAcl,
    AccessDenied,
    AuthenticationFailed,
    Login,
};

pub const AuditEntry = struct {
    timestamp: i64,
    action: []const u8,
    user_id: []const u8,
    ip: []const u8,
    resource: []const u8,
    status: u16,
    details: ?[]const u8 = null,
};

pub fn logAudit(
    allocator: std.mem.Allocator,
    action: Action,
    user_id: []const u8,
    ip: []const u8,
    resource: []const u8,
    status: u16,
    details: ?[]const u8,
) void {
    const entry = AuditEntry{
        .timestamp = std.time.timestamp(),
        .action = @tagName(action),
        .user_id = if (user_id.len == 0) "anonymous" else user_id,
        .ip = ip,
        .resource = resource,
        .status = status,
        .details = details,
    };

    _ = allocator;
    log.info("[AUDIT] {f}", .{std.json.fmt(entry, .{})});
}
