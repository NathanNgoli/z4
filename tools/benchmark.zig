const std = @import("std");
const http = std.http;
const net = std.net;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var endpoint: []const u8 = "http://localhost:9670";
    var concurrency: usize = 10;
    var duration_s: u64 = 10;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--endpoint")) {
            i += 1;
            endpoint = args[i];
        } else if (std.mem.eql(u8, arg, "--concurrency")) {
            i += 1;
            concurrency = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--duration")) {
            i += 1;
            duration_s = try std.fmt.parseInt(u64, args[i], 10);
        }
    }

    std.debug.print("Benchmark: {s}, Concurrency: {}, Duration: {}s\n", .{ endpoint, concurrency, duration_s });

    const thread_pool = try allocator.alloc(std.Thread, concurrency);
    defer allocator.free(thread_pool);
    const results = try allocator.alloc(Result, concurrency);
    defer allocator.free(results);
    for (results) |*r| r.* = .{};

    // Create bucket first
    try createBucket(allocator, endpoint, "bench");

    const start_time = std.time.milliTimestamp();
    var should_stop = std.atomic.Value(bool).init(false);

    // Using atomic boolean to signal stop isn't great for precise duration, but simple.
    // Better: each thread checks time? No, atomic bool is strictly controlled by main.

    for (0..concurrency) |idx| {
        thread_pool[idx] = try std.Thread.spawn(.{}, worker, .{ allocator, endpoint, &results[idx], &should_stop });
    }

    std.Thread.sleep(duration_s * 1000 * 1000 * 1000);
    should_stop.store(true, .seq_cst);

    var total_reqs: usize = 0;
    var total_errors: usize = 0;

    for (0..concurrency) |idx| {
        thread_pool[idx].join();
        total_reqs += results[idx].requests;
        total_errors += results[idx].errors;
    }

    const total_time_ms = std.time.milliTimestamp() - start_time;
    const rps = @as(f64, @floatFromInt(total_reqs)) / (@as(f64, @floatFromInt(total_time_ms)) / 1000.0);

    std.debug.print("Results:\n", .{});
    std.debug.print("  Total Requests: {}\n", .{total_reqs});
    std.debug.print("  Total Errors:   {}\n", .{total_errors});
    std.debug.print("  RPS:            {d:.2}\n", .{rps});
}

const Result = struct {
    requests: usize = 0,
    errors: usize = 0,
};

fn worker(allocator: std.mem.Allocator, endpoint: []const u8, result: *Result, should_stop: *std.atomic.Value(bool)) void {
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();

    var buf: [1024]u8 = undefined;
    const body = "benchmark_data";

    while (!should_stop.load(.seq_cst)) {
        // PUT object
        const key = std.fmt.bufPrint(&buf, "{s}/bench/obj-{}", .{ endpoint, std.crypto.random.int(u64) }) catch continue;
        const uri = std.Uri.parse(key) catch continue;

        const res = client.fetch(.{
            .location = .{ .uri = uri },
            .method = .PUT,
            .payload = body,
            .extra_headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        }) catch {
            result.errors += 1;
            continue;
        };

        if (res.status != .ok) {
            result.errors += 1;
        } else {
            result.requests += 1;
        }
    }
}

fn createBucket(allocator: std.mem.Allocator, endpoint: []const u8, bucket: []const u8) !void {
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ endpoint, bucket });
    defer allocator.free(url);

    const uri = try std.Uri.parse(url);
    const res = try client.fetch(.{
        .location = .{ .uri = uri },
        .method = .PUT,
        .payload = "",
    });

    if (res.status != .ok and res.status != .conflict) {
        std.debug.print("Failed to create bucket: {}\n", .{res.status});
    }
}
