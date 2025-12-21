const std = @import("std");
const Storage = @import("storage.zig").Storage;
const log = @import("log.zig");

pub const LifecycleWorker = struct {
    storage: *Storage,
    allocator: std.mem.Allocator,
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    interval_ms: u64 = 3600000,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},

    pub fn init(allocator: std.mem.Allocator, storage: *Storage) LifecycleWorker {
        return LifecycleWorker{
            .allocator = allocator,
            .storage = storage,
        };
    }

    pub fn start(self: *LifecycleWorker) !void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn stop(self: *LifecycleWorker) void {
        self.running.store(false, .release);
        self.mutex.lock();
        self.cond.signal();
        self.mutex.unlock();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn run(self: *LifecycleWorker) void {
        log.info("Lifecycle worker started", .{});
        while (self.running.load(.acquire)) {
            self.processAllBuckets();

            self.mutex.lock();
            self.cond.timedWait(&self.mutex, self.interval_ms * std.time.ns_per_ms) catch {};
            self.mutex.unlock();
        }
        log.info("Lifecycle worker stopped", .{});
    }

    fn processAllBuckets(self: *LifecycleWorker) void {
        const buckets = self.storage.listBuckets() catch return;
        defer {
            for (buckets) |b| self.allocator.free(b);
            self.allocator.free(buckets);
        }

        for (buckets) |bucket| {
            if (std.mem.startsWith(u8, bucket, "_")) continue;
            self.processBucket(bucket);
        }
    }

    fn processBucket(self: *LifecycleWorker, bucket: []const u8) void {
        const lifecycle_xml = self.storage.getBucketLifecycle(bucket) catch return;
        defer self.allocator.free(lifecycle_xml);

        var rules_list = std.ArrayList(LifecycleRule).initCapacity(self.allocator, 8) catch return;
        defer rules_list.deinit(self.allocator);

        parseLifecycleRules(lifecycle_xml, &rules_list, self.allocator) catch return;

        for (rules_list.items) |rule| {
            if (!rule.enabled) continue;
            self.applyRule(bucket, rule);
        }
    }

    fn applyRule(self: *LifecycleWorker, bucket: []const u8, rule: LifecycleRule) void {
        if (rule.expiration_days == null) return;

        const exp_days = rule.expiration_days.?;
        const now = std.time.milliTimestamp();
        const exp_threshold = now - (@as(i64, @intCast(exp_days)) * 24 * 60 * 60 * 1000);

        var bucket_dir = self.storage.root_dir.openDir(bucket, .{ .iterate = true }) catch return;
        defer bucket_dir.close();

        self.scanAndExpire(bucket_dir, bucket, rule.prefix, exp_threshold, 0);
    }

    fn scanAndExpire(self: *LifecycleWorker, dir: std.fs.Dir, bucket: []const u8, prefix: []const u8, threshold: i64, depth: u32) void {
        if (depth > 10) return;

        var iter = dir.iterate();
        while (iter.next() catch return) |entry| {
            if (entry.kind == .directory) {
                if (dir.openDir(entry.name, .{ .iterate = true })) |subdir| {
                    var sub = subdir;
                    defer sub.close();
                    self.scanAndExpire(sub, bucket, prefix, threshold, depth + 1);
                } else |_| {}
            } else if (entry.kind == .file) {
                if (std.mem.endsWith(u8, entry.name, ".meta")) continue;
                if (std.mem.endsWith(u8, entry.name, ".current")) continue;
                if (std.mem.endsWith(u8, entry.name, ".deleted")) continue;

                if (prefix.len > 0 and !std.mem.startsWith(u8, entry.name, prefix)) continue;

                const stat = dir.statFile(entry.name) catch continue;
                const mtime = @divFloor(stat.mtime, std.time.ns_per_ms);

                if (mtime < threshold) {
                    log.info("Lifecycle: expiring {s}/{s}", .{ bucket, entry.name });
                    dir.deleteFile(entry.name) catch {};

                    const meta_name = std.fmt.allocPrint(self.allocator, "{s}.meta", .{entry.name}) catch continue;
                    defer self.allocator.free(meta_name);
                    dir.deleteFile(meta_name) catch {};
                }
            }
        }
    }

    pub const LifecycleRule = struct {
        id: []const u8 = "",
        enabled: bool = false,
        prefix: []const u8 = "",
        expiration_days: ?u32 = null,
    };

    fn parseLifecycleRules(xml: []const u8, rules: *std.ArrayList(LifecycleRule), allocator: std.mem.Allocator) !void {
        var pos: usize = 0;

        while (pos < xml.len) {
            const rule_start = std.mem.indexOf(u8, xml[pos..], "<Rule>") orelse break;
            const rule_end = std.mem.indexOf(u8, xml[pos + rule_start ..], "</Rule>") orelse break;

            const rule_xml = xml[pos + rule_start .. pos + rule_start + rule_end + 7];
            pos = pos + rule_start + rule_end + 7;

            var rule = LifecycleRule{};

            if (extractTagContent(rule_xml, "ID")) |id| {
                rule.id = id;
            }

            if (extractTagContent(rule_xml, "Status")) |status| {
                rule.enabled = std.ascii.eqlIgnoreCase(status, "Enabled");
            }

            if (std.mem.indexOf(u8, rule_xml, "<Filter>")) |filter_idx| {
                const filter_end = std.mem.indexOf(u8, rule_xml[filter_idx..], "</Filter>") orelse rule_xml.len - filter_idx;
                const filter_xml = rule_xml[filter_idx .. filter_idx + filter_end];
                if (extractTagContent(filter_xml, "Prefix")) |prefix| {
                    rule.prefix = prefix;
                }
            } else if (extractTagContent(rule_xml, "Prefix")) |prefix| {
                rule.prefix = prefix;
            }

            if (std.mem.indexOf(u8, rule_xml, "<Expiration>")) |exp_idx| {
                const exp_end = std.mem.indexOf(u8, rule_xml[exp_idx..], "</Expiration>") orelse rule_xml.len - exp_idx;
                const exp_xml = rule_xml[exp_idx .. exp_idx + exp_end];
                if (extractTagContent(exp_xml, "Days")) |days_str| {
                    rule.expiration_days = std.fmt.parseInt(u32, days_str, 10) catch null;
                }
            } else if (extractTagContent(rule_xml, "Days")) |days_str| {
                rule.expiration_days = std.fmt.parseInt(u32, days_str, 10) catch null;
            }

            try rules.append(allocator, rule);
        }

        if (rules.items.len == 0) {
            var rule = LifecycleRule{};

            if (std.mem.indexOf(u8, xml, "<Status>Enabled</Status>") != null) {
                rule.enabled = true;
            }

            if (extractTagContent(xml, "Days")) |days_str| {
                rule.expiration_days = std.fmt.parseInt(u32, days_str, 10) catch null;
            }

            if (extractTagContent(xml, "Prefix")) |prefix| {
                rule.prefix = prefix;
            }

            if (rule.enabled or rule.expiration_days != null) {
                try rules.append(allocator, rule);
            }
        }
    }

    fn extractTagContent(xml: []const u8, tag: []const u8) ?[]const u8 {
        var open_buf: [64]u8 = undefined;
        var close_buf: [64]u8 = undefined;

        const open_tag = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return null;
        const close_tag = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;

        const tag_start = std.mem.indexOf(u8, xml, open_tag) orelse return null;
        const content_start = tag_start + open_tag.len;
        const end = std.mem.indexOf(u8, xml[content_start..], close_tag) orelse return null;

        return xml[content_start .. content_start + end];
    }
};
