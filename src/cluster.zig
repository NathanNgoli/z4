const std = @import("std");
const net = std.net;
const constants = @import("constants.zig");

pub const Node = struct {
    id: []const u8,
    address: []const u8,
    port: u16,
};

const RingPoint = struct {
    hash: u64,
    node_index: usize,
};

pub const Cluster = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(Node),
    ring: std.ArrayList(RingPoint),
    self_id: []const u8,
    mutex: std.Thread.Mutex,
    virtual_nodes: usize,
    secret_key: []const u8,

    pub fn init(allocator: std.mem.Allocator, self_id: []const u8, secret_key: []const u8) Cluster {
        return initWithVnodes(allocator, self_id, secret_key, constants.DEFAULT_VIRTUAL_NODES);
    }

    pub fn initWithVnodes(allocator: std.mem.Allocator, self_id: []const u8, secret_key: []const u8, vnodes: usize) Cluster {
        return Cluster{
            .allocator = allocator,
            .nodes = std.ArrayList(Node){},
            .ring = std.ArrayList(RingPoint){},
            .self_id = allocator.dupe(u8, self_id) catch self_id,
            .secret_key = allocator.dupe(u8, secret_key) catch secret_key,
            .mutex = .{},
            .virtual_nodes = vnodes,
        };
    }

    pub fn deinit(self: *Cluster) void {
        for (self.nodes.items) |node| {
            self.allocator.free(node.id);
            self.allocator.free(node.address);
        }
        self.nodes.deinit(self.allocator);
        self.ring.deinit(self.allocator);
        self.allocator.free(self.self_id);
        self.allocator.free(self.secret_key);
    }

    pub fn addNode(self: *Cluster, id: []const u8, address: []const u8, port: u16) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const node_idx = self.nodes.items.len;
        const node = Node{
            .id = try self.allocator.dupe(u8, id),
            .address = try self.allocator.dupe(u8, address),
            .port = port,
        };
        try self.nodes.append(self.allocator, node);

        var buf: [256]u8 = undefined;
        var i: usize = 0;
        while (i < self.virtual_nodes) : (i += 1) {
            const label = std.fmt.bufPrint(&buf, "{s}-{}", .{ id, i }) catch continue;
            const hash = std.hash.Wyhash.hash(0, label);
            try self.ring.append(self.allocator, .{ .hash = hash, .node_index = node_idx });
        }

        std.mem.sort(RingPoint, self.ring.items, {}, compareRingPoints);
    }

    fn compareRingPoints(_: void, a: RingPoint, b: RingPoint) bool {
        return a.hash < b.hash;
    }

    pub fn getNodesFor(self: *Cluster, key: []const u8, out_nodes: []Node) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.ring.items.len == 0) return 0;
        if (self.nodes.items.len == 0) return 0;

        const hash = std.hash.Wyhash.hash(0, key);

        var left: usize = 0;
        var right: usize = self.ring.items.len;

        while (left < right) {
            const mid = left + (right - left) / 2;
            if (self.ring.items[mid].hash < hash) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        if (left == self.ring.items.len) left = 0;

        var count: usize = 0;
        var r_idx = left;
        var seen_node_indices: [constants.REPLICATION_FACTOR]usize = undefined;

        var looped_once = false;
        const start_idx = r_idx;

        while (count < out_nodes.len) {
            const node_idx = self.ring.items[r_idx].node_index;

            var already_seen = false;
            for (0..count) |i| {
                if (seen_node_indices[i] == node_idx) {
                    already_seen = true;
                    break;
                }
            }

            if (!already_seen) {
                seen_node_indices[count] = node_idx;
                out_nodes[count] = self.nodes.items[node_idx];
                count += 1;
            }

            r_idx += 1;
            if (r_idx >= self.ring.items.len) {
                r_idx = 0;
                looped_once = true;
            }

            if (looped_once and r_idx == start_idx) break;

            if (count >= self.nodes.items.len) break;
        }

        return count;
    }

    pub fn getNodeFor(self: *Cluster, key: []const u8) Node {
        var nodes: [1]Node = undefined;
        if (self.getNodesFor(key, &nodes) > 0) {
            return nodes[0];
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.nodes.items[0];
    }

    pub fn isLocal(self: *Cluster, key: []const u8) bool {
        if (self.nodes.items.len == 0) return true;
        const node = self.getNodeFor(key);
        return std.mem.eql(u8, node.id, self.self_id);
    }
};
