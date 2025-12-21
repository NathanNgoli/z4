const std = @import("std");
const log = @import("log.zig");

pub const TokenBucket = struct {
    tokens: f64,
    last_refill_ns: i128,
    capacity: f64,
    rate_per_sec: f64,

    pub fn init(capacity: f64, rate: f64) TokenBucket {
        return TokenBucket{
            .tokens = capacity,
            .last_refill_ns = std.time.nanoTimestamp(),
            .capacity = capacity,
            .rate_per_sec = rate,
        };
    }

    pub fn consume(self: *TokenBucket, amount: f64) bool {
        const now = std.time.nanoTimestamp();
        const elapsed_ns = now - self.last_refill_ns;

        if (elapsed_ns > 0) {
            const elapsed_sec = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
            self.tokens = @min(self.capacity, self.tokens + (elapsed_sec * self.rate_per_sec));
            self.last_refill_ns = now;
        }

        if (self.tokens >= amount) {
            self.tokens -= amount;
            return true;
        }
        return false;
    }

    pub fn remaining(self: *TokenBucket) f64 {
        const now = std.time.nanoTimestamp();
        const elapsed_ns = now - self.last_refill_ns;
        if (elapsed_ns > 0) {
            const elapsed_sec = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
            return @min(self.capacity, self.tokens + (elapsed_sec * self.rate_per_sec));
        }
        return self.tokens;
    }
};

pub const RateLimiter = struct {
    mutex: std.Thread.Mutex,
    ip_buckets: std.AutoHashMap(u32, TokenBucket),
    key_buckets: std.StringHashMap(TokenBucket),
    allocator: std.mem.Allocator,

    ip_limit: f64,
    ip_burst: f64,
    key_limit: f64,
    key_burst: f64,

    pub fn init(allocator: std.mem.Allocator, ip_limit: f64, ip_burst: f64, key_limit: f64, key_burst: f64) RateLimiter {
        return RateLimiter{
            .mutex = .{},
            .ip_buckets = std.AutoHashMap(u32, TokenBucket).init(allocator),
            .key_buckets = std.StringHashMap(TokenBucket).init(allocator),
            .allocator = allocator,
            .ip_limit = ip_limit,
            .ip_burst = ip_burst,
            .key_limit = key_limit,
            .key_burst = key_burst,
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.ip_buckets.deinit();
        var it = self.key_buckets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.key_buckets.deinit();
    }

    pub fn checkIp(self: *RateLimiter, ip: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const result = self.ip_buckets.getOrPut(ip) catch {
            return true;
        };

        if (!result.found_existing) {
            result.value_ptr.* = TokenBucket.init(self.ip_burst, self.ip_limit);
        }

        return result.value_ptr.consume(1.0);
    }

    pub fn checkKey(self: *RateLimiter, key: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.key_buckets.getPtr(key)) |bucket| {
            return bucket.consume(1.0);
        } else {
            const key_dup = self.allocator.dupe(u8, key) catch return true;
            self.key_buckets.put(key_dup, TokenBucket.init(self.key_burst, self.key_limit)) catch return true;

            if (self.key_buckets.getPtr(key)) |bucket| {
                return bucket.consume(1.0);
            }
            return true;
        }
    }
};

test "TokenBucket basic usage" {
    var bucket = TokenBucket.init(10.0, 1.0);
    try std.testing.expect(bucket.tokens == 10.0);

    try std.testing.expect(bucket.consume(1.0));
    try std.testing.expect(bucket.tokens <= 9.0);

    try std.testing.expect(bucket.consume(8.0));
    try std.testing.expect(bucket.consume(1.0));

    try std.testing.expect(!bucket.consume(1.0));
}

test "TokenBucket refill" {
    var bucket = TokenBucket.init(1.0, 100.0);
    try std.testing.expect(bucket.consume(1.0));
    try std.testing.expect(!bucket.consume(1.0));

    std.time.sleep(20 * std.time.ns_per_ms);

    try std.testing.expect(bucket.consume(1.0));
}

test "RateLimiter IP check" {
    var limiter = RateLimiter.init(std.testing.allocator, 10.0, 1.0, 10.0, 1.0);
    defer limiter.deinit();

    try std.testing.expect(limiter.checkIp(1));
    try std.testing.expect(!limiter.checkIp(1));

    try std.testing.expect(limiter.checkIp(2));
}

test "RateLimiter Key check" {
    var limiter = RateLimiter.init(std.testing.allocator, 10.0, 1.0, 10.0, 2.0);
    defer limiter.deinit();

    try std.testing.expect(limiter.checkKey("apikey1"));
    try std.testing.expect(limiter.checkKey("apikey1"));
    try std.testing.expect(!limiter.checkKey("apikey1"));

    try std.testing.expect(limiter.checkKey("apikey2"));
}
