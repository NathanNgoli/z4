const std = @import("std");
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var list = std.ArrayList(u8){};

    defer list.deinit(allocator);
    try list.append(allocator, 'a');
    std.debug.print("List: {s}\n", .{list.items});
}
