const std = @import("std");
const http = std.http;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var endpoint: []const u8 = "http://127.0.0.1:9670";
    var concurrency: usize = 20;
    var size_mb: u64 = 100;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--endpoint")) {
            i += 1;
            endpoint = args[i];
        } else if (std.mem.eql(u8, arg, "--concurrency")) {
            i += 1;
            concurrency = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--size-mb")) {
            i += 1;
            size_mb = try std.fmt.parseInt(u64, args[i], 10);
        }
    }

    std.debug.print("Starting stress test: {s}, Concurrency: {}, Size: {}MB\n", .{ endpoint, concurrency, size_mb });

    {
        var client = http.Client{ .allocator = allocator };
        defer client.deinit();
        const bucket_url = try std.fmt.allocPrint(allocator, "{s}/stress-bucket", .{endpoint});
        defer allocator.free(bucket_url);
        const uri = try std.Uri.parse(bucket_url);
        _ = try client.fetch(.{ .location = .{ .uri = uri }, .method = .PUT, .payload = "" });
    }

    const threads = try allocator.alloc(std.Thread, concurrency);
    defer allocator.free(threads);
    const errors = try allocator.alloc(usize, concurrency);
    defer allocator.free(errors);
    @memset(errors, 0);

    const start_time = std.time.milliTimestamp();

    for (0..concurrency) |idx| {
        threads[idx] = try std.Thread.spawn(.{}, worker, .{ allocator, endpoint, size_mb, &errors[idx] });
    }

    for (threads) |t| t.join();

    const duration_ms = std.time.milliTimestamp() - start_time;
    var total_errors: usize = 0;
    for (errors) |e| total_errors += e;

    std.debug.print("\n--- Test Finished ---\n", .{});
    std.debug.print("Duration: {}ms\n", .{duration_ms});
    std.debug.print("Total Errors: {}\n", .{total_errors});
}

fn worker(allocator: std.mem.Allocator, endpoint_str: []const u8, size_mb: u64, error_count: *usize) void {
    const total_bytes = size_mb * 1024 * 1024;
    const chunk_size = 64 * 1024;

    const uri = std.Uri.parse(endpoint_str) catch |e| {
        std.debug.print("URI Parse Error: {}\n", .{e});
        error_count.* += 1;
        return;
    };
    const hostname = if (uri.host) |h| h.percent_encoded else "localhost";
    const port = uri.port orelse 9670;

    const peer = std.net.Address.parseIp(hostname, port) catch |e| {
        std.debug.print("IP Parse Error (host={s}): {}\n", .{ hostname, e });
        error_count.* += 1;
        return;
    };
    const stream = std.net.tcpConnectToAddress(peer) catch |e| {
        std.debug.print("Connect Error: {}\n", .{e});
        error_count.* += 1;
        return;
    };
    defer stream.close();

    var buf: [1024]u8 = undefined;
    const key = std.fmt.bufPrint(&buf, "/stress-bucket/obj-{}-{}", .{ std.time.milliTimestamp(), std.crypto.random.int(u32) }) catch return;

    var header_buf: [4096]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "PUT {s} HTTP/1.1\r\nHost: {s}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n", .{ key, hostname, total_bytes }) catch |e| {
        std.debug.print("Header Fmt Error: {}\n", .{e});
        error_count.* += 1;
        return;
    };
    stream.writeAll(header) catch |e| {
        std.debug.print("Header Write Error: {}\n", .{e});
        error_count.* += 1;
        return;
    };

    var remaining = total_bytes;
    const dummy_data = allocator.alloc(u8, chunk_size) catch return;
    defer allocator.free(dummy_data);
    @memset(dummy_data, 'X');

    while (remaining > 0) {
        const to_send = @min(remaining, chunk_size);
        stream.writeAll(dummy_data[0..to_send]) catch |e| {
            var resp_buf: [1024]u8 = undefined;
            const res_n = stream.read(&resp_buf) catch 0;
            if (res_n > 0) {
                std.debug.print("Write Failed: {}. Server Sent: {s}\n", .{ e, resp_buf[0..res_n] });
            } else {
                std.debug.print("Body Write Error: {}\n", .{e});
            }
            error_count.* += 1;
            return;
        };
        remaining -= to_send;
    }

    var resp_buf: [1024]u8 = undefined;
    const n = stream.read(&resp_buf) catch 0;
    if (n > 0) {
        const response = resp_buf[0..n];
        if (!std.mem.containsAtLeast(u8, response, 1, "200 OK")) {
            std.debug.print("Server Error: {s}\n", .{response});
            error_count.* += 1;
        }
    } else {
        error_count.* += 1;
    }
}
