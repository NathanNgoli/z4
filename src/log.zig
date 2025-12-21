const std = @import("std");
const constants = @import("constants.zig");

pub const Level = enum {
    DEBUG,
    INFO,
    WARN,
    ERROR,
};

pub const Logger = struct {
    mutex: std.Thread.Mutex,
    buffer: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    debug_mode: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator) !Logger {
        return Logger{
            .mutex = .{},
            .buffer = try std.ArrayList(u8).initCapacity(allocator, constants.LOG_BUFFER_SIZE),
            .allocator = allocator,
            .debug_mode = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *Logger) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn setDebug(self: *Logger, enabled: bool) void {
        self.debug_mode.store(enabled, .release);
    }

    pub fn debug(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        if (!self.debug_mode.load(.acquire)) return;
        self.log(.DEBUG, fmt, args);
    }

    pub fn log(self: *Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const level_str = switch (level) {
            .DEBUG => "DEBUG",
            .INFO => "INFO",
            .WARN => "WARN",
            .ERROR => "ERROR",
        };

        const timestamp = std.time.milliTimestamp();

        self.buffer.writer(self.allocator).print("[{d}] [{s}] ", .{ timestamp, level_str }) catch return;
        self.buffer.writer(self.allocator).print(fmt, args) catch return;
        self.buffer.writer(self.allocator).writeByte('\n') catch return;

        const stderr_file = std.fs.File{ .handle = std.posix.STDERR_FILENO };
        stderr_file.writeAll(self.buffer.items) catch {};
        self.buffer.clearRetainingCapacity();
    }
};

var global_logger: ?Logger = null;
var init_mutex: std.Thread.Mutex = .{};

pub fn initGlobal(allocator: std.mem.Allocator) void {
    init_mutex.lock();
    defer init_mutex.unlock();

    if (global_logger == null) {
        global_logger = Logger.init(allocator) catch return;
    }
}

pub fn deinitGlobal() void {
    init_mutex.lock();
    defer init_mutex.unlock();

    if (global_logger) |*l| {
        l.deinit();
        global_logger = null;
    }
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |*l| l.log(.WARN, fmt, args);
}

pub fn setDebug(enabled: bool) void {
    if (global_logger) |*l| l.setDebug(enabled);
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |*l| l.debug(fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |*l| l.log(.INFO, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |*l| l.log(.ERROR, fmt, args);
}
