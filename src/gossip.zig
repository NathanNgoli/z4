const std = @import("std");
const Cluster = @import("cluster.zig").Cluster;
const log = @import("log.zig");
const net = std.net;
const posix = std.posix;
const constants = @import("constants.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Gossip = struct {
    cluster: *Cluster,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),
    thread: ?std.Thread = null,
    gossip_port: u16,
    socket: ?posix.socket_t = null,

    const MessageType = enum(u8) {
        PING = 1,
        PONG = 2,
        JOIN = 3,
    };

    pub fn init(allocator: std.mem.Allocator, cluster: *Cluster, port: u16) Gossip {
        return Gossip{
            .cluster = cluster,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
            .gossip_port = port,
        };
    }

    pub fn start(self: *Gossip) !void {
        const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        self.socket = sockfd;

        const addr = try net.Address.parseIp4("0.0.0.0", self.gossip_port);
        try posix.bind(sockfd, &addr.any, addr.getOsSockLen());

        self.running.store(true, .seq_cst);
        self.thread = try std.Thread.spawn(.{}, run, .{self});
        log.info("Gossip started on 0.0.0.0:{}", .{self.gossip_port});
    }

    pub fn stop(self: *Gossip) void {
        self.running.store(false, .seq_cst);
        if (self.socket) |fd| {
            posix.shutdown(fd, .both) catch {};
            posix.close(fd);
        }
        if (self.thread) |t| t.join();
    }

    pub fn joinCluster(self: *Gossip, seed_host: []const u8, seed_port: u16) !void {
        log.info("Joining cluster via seed {s}:{}", .{ seed_host, seed_port });
        var buf: [constants.GOSSIP_PACKET_SIZE]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "JOIN {} {s}", .{ self.gossip_port, self.cluster.self_id });

        const socket = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(socket);

        const addr_list = net.Address.parseIp4(seed_host, seed_port) catch blk: {
            var result = try std.net.getAddressList(self.allocator, seed_host, seed_port);
            defer result.deinit();
            if (result.addrs.len == 0) return error.NoAddressFound;
            break :blk result.addrs[0];
        };
        try self.signAndSend(socket, msg, &addr_list.any, addr_list.getOsSockLen());
    }

    fn run(self: *Gossip) void {
        var buf: [constants.GOSSIP_BUFFER_SIZE]u8 = undefined;

        while (self.running.load(.seq_cst)) {
            var fds = [1]posix.pollfd{.{ .fd = self.socket.?, .events = posix.POLL.IN, .revents = 0 }};
            const count = posix.poll(&fds, @intCast(constants.GOSSIP_INTERVAL_MS)) catch 0;

            if (count == 0) {
                self.gossipTick(&std.crypto.random);
                continue;
            }

            var src_addr: posix.sockaddr.in = undefined;
            var src_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

            const len = posix.recvfrom(self.socket.?, &buf, 0, @ptrCast(&src_addr), &src_len) catch |e| {
                log.err("Gossip recv error: {}", .{e});
                continue;
            };

            if (len < constants.GOSSIP_HMAC_SIZE) {
                log.warn("Dropped gossip packet: too short ({} bytes)", .{len});
                continue;
            }

            const received_hmac = buf[0..constants.GOSSIP_HMAC_SIZE];
            const payload = buf[constants.GOSSIP_HMAC_SIZE..len];

            var expected_hmac: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&expected_hmac, payload, self.cluster.secret_key);

            if (!std.mem.eql(u8, received_hmac[0..HmacSha256.mac_length], &expected_hmac)) {
                log.warn("Dropped gossip packet: HMAC mismatch", .{});
                continue;
            }

            self.handleMessage(payload, &src_addr) catch |e| {
                log.err("Failed to handle gossip message: {}", .{e});
            };
        }
    }

    fn gossipTick(self: *Gossip, random: *const std.Random) void {
        self.cluster.mutex.lock();
        if (self.cluster.nodes.items.len == 0) {
            self.cluster.mutex.unlock();
            return;
        }
        const idx = random.uintLessThan(usize, self.cluster.nodes.items.len);
        const node = self.cluster.nodes.items[idx];
        self.cluster.mutex.unlock();

        if (std.mem.eql(u8, node.id, self.cluster.self_id)) return;

        var buf: [constants.GOSSIP_PACKET_SIZE]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "JOIN {} {s}", .{ self.gossip_port, self.cluster.self_id }) catch return;

        const socket = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
        defer posix.close(socket);

        const peer_addr = net.Address.parseIp4(node.address, node.port) catch return;
        self.signAndSend(socket, msg, &peer_addr.any, peer_addr.getOsSockLen()) catch {};
    }

    fn signAndSend(self: *Gossip, socket: posix.socket_t, payload: []const u8, dest_addr: *const posix.sockaddr, dest_len: posix.socklen_t) !void {
        var buf: [constants.GOSSIP_PACKET_SIZE + constants.GOSSIP_HMAC_SIZE]u8 = undefined;

        var hmac: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&hmac, payload, self.cluster.secret_key);

        @memcpy(buf[0..constants.GOSSIP_HMAC_SIZE], &hmac);
        @memcpy(buf[constants.GOSSIP_HMAC_SIZE .. constants.GOSSIP_HMAC_SIZE + payload.len], payload);

        const packet_len = constants.GOSSIP_HMAC_SIZE + payload.len;
        _ = try posix.sendto(socket, buf[0..packet_len], 0, dest_addr, dest_len);
    }

    fn handleMessage(self: *Gossip, msg: []u8, src_addr: *const posix.sockaddr.in) !void {
        var iter = std.mem.splitScalar(u8, msg, ' ');
        const type_str = iter.next() orelse return;

        if (std.mem.eql(u8, type_str, "JOIN")) {
            const port_str = iter.next() orelse return;
            const id = iter.next() orelse return;
            const port = try std.fmt.parseInt(u16, port_str, 10);

            var ip_buf: [16]u8 = undefined;
            const bytes = @as([4]u8, @bitCast(src_addr.addr));
            const ip_str = try std.fmt.bufPrint(&ip_buf, "{}.{}.{}.{}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });

            try self.cluster.addNode(id, ip_str, port);
            log.info("z4 node joined: {s} @ {s}:{}", .{ id, ip_str, port });
        }
    }
};
