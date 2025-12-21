const std = @import("std");

pub fn main() !void {
    const meta = struct { x: i32 = 1 };
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try std.json.stringify(meta, .{}, fbs.writer());
    std.debug.print("{s}\n", .{fbs.getWritten()});
}
