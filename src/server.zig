const std = @import("std");
const net = std.net;
const auth = @import("auth.zig");
const Storage = @import("storage.zig").Storage;
const s3 = @import("s3.zig");
const log = @import("log.zig");
const Cluster = @import("cluster.zig").Cluster;
const KeyManager = @import("keys.zig").KeyManager;
const constants = @import("constants.zig");
const posix = std.posix;
const RateLimiter = @import("ratelimit.zig").RateLimiter;
const audit = @import("audit.zig");
const ChunkedReader = @import("http_chunked.zig").ChunkedReader;

var shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var shutdown_pipe_write: std.atomic.Value(posix.fd_t) = std.atomic.Value(posix.fd_t).init(-1);

fn handleSignal(_: c_int) callconv(.c) void {
    const fd = shutdown_pipe_write.load(.monotonic);
    if (fd != -1) {
        _ = posix.write(fd, "x") catch {};
    }
    shutdown_requested.store(true, .release);
}

const CustomThreadPool = struct {
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,
    p_queue: std.ArrayList(net.Server.Connection),
    threads: []std.Thread,
    shutdown: bool,
    allocator: std.mem.Allocator,
    server: *Server,

    pub fn init(allocator: std.mem.Allocator, server: *Server, n_threads: usize) !*CustomThreadPool {
        const self = try allocator.create(CustomThreadPool);
        self.* = .{
            .mutex = .{},
            .cond = .{},
            .p_queue = try std.ArrayList(net.Server.Connection).initCapacity(allocator, 128),
            .threads = try allocator.alloc(std.Thread, n_threads),
            .shutdown = false,
            .allocator = allocator,
            .server = server,
        };

        for (self.threads) |*t| {
            t.* = try std.Thread.spawn(.{}, worker, .{self});
        }
        return self;
    }

    pub fn deinit(self: *CustomThreadPool) void {
        self.mutex.lock();
        self.shutdown = true;
        self.cond.broadcast();
        self.mutex.unlock();

        for (self.threads) |t| {
            t.join();
        }
        self.allocator.free(self.threads);
        self.p_queue.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn spawn(self: *CustomThreadPool, connection: net.Server.Connection) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.p_queue.append(self.allocator, connection);
        self.cond.signal();
    }

    fn worker(self: *CustomThreadPool) void {
        while (true) {
            self.mutex.lock();
            while (self.p_queue.items.len == 0 and !self.shutdown) {
                self.cond.wait(&self.mutex);
            }
            if (self.shutdown and self.p_queue.items.len == 0) {
                self.mutex.unlock();
                break;
            }
            const connection = self.p_queue.pop() orelse unreachable;
            self.mutex.unlock();

            self.server.handleConnection(connection);
        }
    }
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    storage: Storage,
    port: u16,
    cluster: *Cluster,
    pool: *CustomThreadPool,
    key_mgr: *KeyManager,
    no_auth: bool,
    rate_limiter: RateLimiter,

    pub fn init(allocator: std.mem.Allocator, storage: Storage, port: u16, cluster: *Cluster, threads: ?usize, key_mgr: *KeyManager, no_auth: bool) !Server {
        _ = threads;
        return Server{
            .allocator = allocator,
            .storage = storage,
            .port = port,
            .cluster = cluster,
            .pool = undefined,
            .key_mgr = key_mgr,
            .no_auth = no_auth,
            .rate_limiter = RateLimiter.init(
                allocator,
                constants.RATE_LIMIT_IP_RPS,
                constants.RATE_LIMIT_IP_BURST,
                constants.RATE_LIMIT_KEY_RPS,
                constants.RATE_LIMIT_KEY_BURST,
            ),
        };
    }

    pub fn deinit(self: *Server) void {
        self.rate_limiter.deinit();
    }

    pub fn start(self: *Server) !void {
        const pipe_fds = try posix.pipe();
        const pipe_r = pipe_fds[0];
        const pipe_w = pipe_fds[1];
        shutdown_pipe_write.store(pipe_w, .release);

        defer posix.close(pipe_r);
        defer posix.close(pipe_w);

        const sa = posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.INT, &sa, null);
        posix.sigaction(posix.SIG.TERM, &sa, null);
        log.info("Signal handlers installed", .{});

        const address = try net.Address.parseIp("0.0.0.0", self.port);
        var server = try address.listen(.{ .reuse_address = true });
        defer server.deinit();

        const cpu = try std.Thread.getCpuCount();
        const threads = if (cpu > 0) cpu else 64;

        self.pool = try CustomThreadPool.init(self.allocator, self, threads);
        defer self.pool.deinit();

        log.info("Server listening on 0.0.0.0:{}", .{self.port});

        var poll_fds = [_]posix.pollfd{
            .{ .fd = server.stream.handle, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = pipe_r, .events = posix.POLL.IN, .revents = 0 },
        };

        while (!shutdown_requested.load(.acquire)) {
            const count = posix.poll(&poll_fds, -1) catch |err| {
                if (err == error.Interrupted) continue;
                log.err("Poll failed: {}", .{err});
                continue;
            };

            if (count == 0) continue;

            if (poll_fds[1].revents & posix.POLL.IN != 0) {
                break;
            }

            if (poll_fds[0].revents & posix.POLL.IN != 0) {
                const connection = server.accept() catch |err| {
                    log.err("Accept failed: {}", .{err});
                    continue;
                };

                self.pool.spawn(connection) catch |err| {
                    log.err("Failed to queue task: {}", .{err});
                    connection.stream.close();
                    continue;
                };
            }
        }

        log.info("Shutting down gracefully, waiting for connections to drain...", .{});
    }

    fn handleConnection(self: *Server, connection: net.Server.Connection) void {
        defer connection.stream.close();

        if (connection.address.any.family == posix.AF.INET) {
            if (!self.rate_limiter.checkIp(connection.address.in.sa.addr)) {
                self.sendError(connection.stream, "429 Too Many Requests", "TooManyRequests", "IP rate limit exceeded");
                return;
            }
        }

        var keep_alive = true;

        while (keep_alive) {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const request_allocator = arena.allocator();

            var buffer: [constants.REQUEST_BUFFER_SIZE]u8 = undefined;
            const bytes_read = connection.stream.read(&buffer) catch {
                return;
            };

            if (bytes_read == 0) return;

            const raw_request = buffer[0..bytes_read];

            var line_iter = std.mem.splitSequence(u8, raw_request, "\r\n");
            const request_line = line_iter.next() orelse return;

            if (request_line.len > constants.MAX_REQUEST_LINE_LENGTH) {
                self.sendError(connection.stream, "414 URI Too Long", "RequestURITooLong", "The request line exceeds the maximum length");
                return;
            }

            var parts = std.mem.splitScalar(u8, request_line, ' ');
            const method = std.mem.trim(u8, parts.next() orelse return, " \t\r\n");
            const uri = parts.next() orelse return;

            const valid_methods = [_][]const u8{ "GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS" };
            var method_valid = false;
            for (valid_methods) |valid| {
                if (std.mem.eql(u8, method, valid)) {
                    method_valid = true;
                    break;
                }
            }
            if (!method_valid) {
                self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "The specified method is not allowed");
                return;
            }

            if (uri.len > constants.MAX_KEY_LENGTH + constants.MAX_BUCKET_NAME_LENGTH + 10) {
                self.sendError(connection.stream, "414 URI Too Long", "RequestURITooLong", "The request URI is too long");
                return;
            }

            var query_args = std.StringHashMap([]const u8).init(request_allocator);

            if (std.mem.indexOfScalar(u8, uri, '?')) |q_idx| {
                const query = uri[q_idx + 1 ..];
                var q_iter = std.mem.splitScalar(u8, query, '&');
                while (q_iter.next()) |pair| {
                    if (std.mem.indexOfScalar(u8, pair, '=')) |eq_idx| {
                        const k = pair[0..eq_idx];
                        const v = pair[eq_idx + 1 ..];
                        query_args.put(k, v) catch {};
                    } else {
                        query_args.put(pair, "") catch {};
                    }
                }
            }

            if (std.mem.eql(u8, uri, "/health") or std.mem.eql(u8, uri, "/health/")) {
                self.handleHealthCheck(connection.stream);
                if (keep_alive) {
                    continue;
                } else {
                    return;
                }
            }

            var headers = std.StringHashMap([]const u8).init(request_allocator);

            var header_count: usize = 0;
            const max_headers: usize = 100;

            while (line_iter.next()) |line| {
                if (line.len == 0) break;

                header_count += 1;
                if (header_count > max_headers) {
                    self.sendError(connection.stream, "431 Request Header Fields Too Large", "TooManyHeaders", "Too many headers in request");
                    return;
                }

                if (line.len > 8192) {
                    self.sendError(connection.stream, "431 Request Header Fields Too Large", "HeaderTooLarge", "Header line too long");
                    return;
                }

                if (std.mem.indexOfScalar(u8, line, ':')) |colon_idx| {
                    const key = std.mem.trim(u8, line[0..colon_idx], " ");
                    const value = std.mem.trim(u8, line[colon_idx + 1 ..], " ");
                    const lower_key = std.ascii.allocLowerString(request_allocator, key) catch continue;
                    headers.put(lower_key, value) catch {};
                }
            }

            if (headers.get("connection")) |conn| {
                if (std.mem.indexOf(u8, conn, "close")) |_| {
                    keep_alive = false;
                }
            }

            var user_id: []const u8 = "";

            if (!self.no_auth) {
                const access_key_opt = auth.verifyRequest(request_allocator, headers, query_args, method, uri, self.key_mgr) catch |e| {
                    log.warn("Auth Error: {}", .{e});
                    audit.logAudit(self.allocator, .AuthenticationFailed, "unknown", "-", uri, 403, "Signature verification failed");
                    self.sendError(connection.stream, "403 Forbidden", "AccessDenied", "Authentication failed");
                    continue;
                };

                if (access_key_opt) |key_id| {
                    user_id = key_id;
                    if (!self.rate_limiter.checkKey(key_id)) {
                        audit.logAudit(self.allocator, .AccessDenied, user_id, "-", uri, 429, "Rate limit exceeded");
                        self.sendError(connection.stream, "429 Too Many Requests", "TooManyRequests", "Account rate limit exceeded");
                        continue;
                    }
                }
            }

            log.info("Request: {s} {s}", .{ method, uri });

            if (std.mem.eql(u8, uri, "/")) {
                if (std.mem.eql(u8, method, "GET")) {
                    self.handleListBuckets(connection.stream);
                } else {
                    self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Root only supports GET");
                }
                continue;
            }

            var path = if (uri.len > 0 and uri[0] == '/') uri[1..] else uri;

            if (std.mem.indexOfScalar(u8, path, '?')) |q_idx| {
                path = path[0..q_idx];
            }

            var path_parts = std.mem.splitScalar(u8, path, '/');
            const bucket_name = path_parts.next() orelse {
                continue;
            };

            var key: []const u8 = "";
            if (bucket_name.len < path.len) {
                if (path.len > bucket_name.len + 1) {
                    key = path[bucket_name.len + 1 ..];
                }
            }

            if (key.len == 0) {
                if (query_args.contains("tagging")) {
                    if (std.mem.eql(u8, method, "PUT")) {
                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var body: []const u8 = "";
                        if (body_start_index) |idx| {
                            body = raw_request[idx + 4 ..];
                        }
                        self.handlePutBucketTagging(connection.stream, bucket_name, body);
                    } else if (std.mem.eql(u8, method, "GET")) {
                        self.handleGetBucketTagging(connection.stream, bucket_name);
                    } else if (std.mem.eql(u8, method, "DELETE")) {
                        self.handleDeleteBucketTagging(connection.stream, bucket_name);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                    continue;
                }

                if (query_args.contains("acl")) {
                    if (std.mem.eql(u8, method, "PUT")) {
                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var body: []const u8 = "";
                        if (body_start_index) |idx| {
                            body = raw_request[idx + 4 ..];
                        }
                        self.handlePutBucketAcl(connection.stream, bucket_name, body, headers, query_args);
                    } else if (std.mem.eql(u8, method, "GET")) {
                        self.handleGetBucketAcl(connection.stream, bucket_name);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                    continue;
                }

                if (query_args.contains("policy")) {
                    if (std.mem.eql(u8, method, "PUT")) {
                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var body: []const u8 = "";
                        if (body_start_index) |idx| {
                            body = raw_request[idx + 4 ..];
                        }
                        self.handlePutBucketPolicy(connection.stream, bucket_name, body);
                    } else if (std.mem.eql(u8, method, "GET")) {
                        self.handleGetBucketPolicy(connection.stream, bucket_name);
                    } else if (std.mem.eql(u8, method, "DELETE")) {
                        self.handleDeleteBucketPolicy(connection.stream, bucket_name);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                    continue;
                }

                if (query_args.contains("encryption")) {
                    if (std.mem.eql(u8, method, "PUT")) {
                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var body: []const u8 = "";
                        if (body_start_index) |idx| {
                            body = raw_request[idx + 4 ..];
                        }
                        self.handlePutBucketEncryption(connection.stream, bucket_name, body);
                    } else if (std.mem.eql(u8, method, "GET")) {
                        self.handleGetBucketEncryption(connection.stream, bucket_name);
                    } else if (std.mem.eql(u8, method, "DELETE")) {
                        self.handleDeleteBucketEncryption(connection.stream, bucket_name);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                    continue;
                }

                if (query_args.contains("versioning")) {
                    if (std.mem.eql(u8, method, "PUT")) {
                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var body: []const u8 = "";
                        if (body_start_index) |idx| {
                            body = raw_request[idx + 4 ..];
                        }
                        self.handlePutBucketVersioning(connection.stream, bucket_name, body);
                    } else if (std.mem.eql(u8, method, "GET")) {
                        self.handleGetBucketVersioning(connection.stream, bucket_name);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                    continue;
                }

                if (query_args.contains("lifecycle")) {
                    if (std.mem.eql(u8, method, "PUT")) {
                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var body: []const u8 = "";
                        if (body_start_index) |idx| {
                            body = raw_request[idx + 4 ..];
                        }
                        self.handlePutBucketLifecycle(connection.stream, bucket_name, body);
                    } else if (std.mem.eql(u8, method, "GET")) {
                        self.handleGetBucketLifecycle(connection.stream, bucket_name);
                    } else if (std.mem.eql(u8, method, "DELETE")) {
                        self.handleDeleteBucketLifecycle(connection.stream, bucket_name);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                    continue;
                }

                if (std.mem.eql(u8, method, "PUT")) {
                    self.handleCreateBucket(connection.stream, bucket_name, headers, query_args, user_id);
                } else if (std.mem.eql(u8, method, "DELETE")) {
                    self.handleDeleteBucket(connection.stream, bucket_name, user_id);
                } else if (std.mem.eql(u8, method, "GET")) {
                    if (query_args.contains("location")) {
                        self.handleGetBucketLocation(connection.stream);
                    } else {
                        self.handleListObjects(connection.stream, bucket_name, headers);
                    }
                } else if (std.mem.eql(u8, method, "HEAD")) {
                    if (self.storage.listBuckets()) |buckets| {
                        defer {
                            for (buckets) |b| self.allocator.free(b);
                            self.allocator.free(buckets);
                        }
                        var found = false;
                        for (buckets) |b| {
                            if (std.mem.eql(u8, b, bucket_name)) {
                                found = true;
                                break;
                            }
                        }
                        if (found) {
                            self.sendResponse(connection.stream, "200 OK", "text/plain", "");
                        } else {
                            self.sendError(connection.stream, "404 Not Found", "NoSuchBucket", "");
                        }
                    } else |_| {
                        self.sendError(connection.stream, "500", "Internal", "");
                    }
                } else {
                    self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                }
            } else {
                var clean_key = key;
                if (std.mem.indexOfScalar(u8, key, '?')) |q_idx| {
                    clean_key = key[0..q_idx];
                }

                if (query_args.contains("tagging")) {
                    if (std.mem.eql(u8, method, "PUT")) {
                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var body: []const u8 = "";
                        if (body_start_index) |idx| {
                            body = raw_request[idx + 4 ..];
                        }
                        self.handlePutObjectTagging(connection.stream, bucket_name, clean_key, body);
                    } else if (std.mem.eql(u8, method, "GET")) {
                        self.handleGetObjectTagging(connection.stream, bucket_name, clean_key);
                    } else if (std.mem.eql(u8, method, "DELETE")) {
                        self.handleDeleteObjectTagging(connection.stream, bucket_name, clean_key);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                    continue;
                }

                if (query_args.contains("acl")) {
                    if (std.mem.eql(u8, method, "PUT")) {
                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var body: []const u8 = "";
                        if (body_start_index) |idx| {
                            body = raw_request[idx + 4 ..];
                        }
                        self.handlePutObjectAcl(connection.stream, bucket_name, clean_key, body);
                    } else if (std.mem.eql(u8, method, "GET")) {
                        self.handleGetObjectAcl(connection.stream, bucket_name, clean_key);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                    continue;
                }

                if (std.mem.eql(u8, method, "PUT")) {
                    if (query_args.contains("uploadId") and query_args.contains("partNumber")) {
                        const upload_id = query_args.get("uploadId").?;
                        const part_num_str = query_args.get("partNumber").?;
                        const part_num = std.fmt.parseInt(u32, part_num_str, 10) catch {
                            self.sendError(connection.stream, "400 Bad Request", "InvalidArgument", "Invalid part number");
                            continue;
                        };

                        const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                        var initial_body: []const u8 = "";
                        if (body_start_index) |idx| {
                            initial_body = raw_request[idx + 4 ..];
                        }

                        self.handlePutObjectPart(connection.stream, bucket_name, clean_key, upload_id, part_num, initial_body, headers);
                        continue;
                    }

                    const body_start_index = std.mem.indexOf(u8, raw_request, "\r\n\r\n");
                    if (body_start_index) |idx| {
                        const body_start = idx + 4;
                        const initial_body = raw_request[body_start..];
                        self.handlePutObject(connection.stream, bucket_name, clean_key, initial_body, headers, user_id);
                    } else {
                        self.handlePutObject(connection.stream, bucket_name, clean_key, "", headers, user_id);
                    }
                } else if (std.mem.eql(u8, method, "POST")) {
                    if (query_args.contains("uploads")) {
                        self.handleInitMultipartUpload(connection.stream, bucket_name, clean_key);
                    } else if (query_args.contains("uploadId")) {
                        const upload_id = query_args.get("uploadId").?;
                        self.handleCompleteMultipartUpload(connection.stream, bucket_name, clean_key, upload_id);
                    } else {
                        self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                    }
                } else if (std.mem.eql(u8, method, "GET")) {
                    self.handleGetObject(connection.stream, bucket_name, clean_key, headers, query_args);
                } else if (std.mem.eql(u8, method, "HEAD")) {
                    self.handleHeadObject(connection.stream, bucket_name, clean_key);
                } else if (std.mem.eql(u8, method, "DELETE")) {
                    if (query_args.contains("uploadId")) {
                        const upload_id = query_args.get("uploadId").?;
                        self.storage.deleteMultipartUpload(bucket_name, upload_id) catch |err| {
                            if (err == error.NoSuchUpload) {
                                self.sendError(connection.stream, "404 Not Found", "NoSuchUpload", "Upload not found");
                            } else {
                                self.sendError(connection.stream, "500", "Internal", "Failed to abort upload");
                            }
                            continue;
                        };
                        self.sendError(connection.stream, "204 No Content", "", "");
                    } else {
                        self.handleDeleteObject(connection.stream, bucket_name, clean_key, user_id);
                    }
                } else {
                    self.sendError(connection.stream, "405 Method Not Allowed", "MethodNotAllowed", "Unsupported method");
                }
            }
        }
    }

    fn handleInitMultipartUpload(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8) void {
        const upload_id = self.storage.initMultipartUpload(bucket, key) catch |err| {
            log.err("InitMultipart failed: {}", .{err});
            self.sendError(stream, "500", "InternalError", "Failed to init upload");
            return;
        };
        defer self.allocator.free(upload_id);

        const xml = std.fmt.allocPrint(self.allocator, "<InitiateMultipartUploadResult><Bucket>{s}</Bucket><Key>{s}</Key><UploadId>{s}</UploadId></InitiateMultipartUploadResult>", .{ bucket, key, upload_id }) catch return;
        defer self.allocator.free(xml);

        self.sendResponse(stream, "200 OK", "application/xml", xml);
    }

    fn handlePutObjectPart(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8, upload_id: []const u8, part: u32, initial_data: []const u8, headers: std.StringHashMap([]const u8)) void {
        _ = key;

        const content_length_str = headers.get("content-length") orelse "0";
        const content_length = std.fmt.parseInt(u64, content_length_str, 10) catch 0;

        const etag = self.storage.putPartStreaming(bucket, upload_id, part, stream, content_length, initial_data) catch |err| {
            log.err("PutPart failed: {}", .{err});
            self.sendError(stream, "500", "InternalError", "Failed to put part");
            return;
        };

        const response_header = std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\nETag: {s}\r\nContent-Length: 0\r\nServer: z4\r\n\r\n", .{etag}) catch return;
        defer self.allocator.free(response_header);
        stream.writeAll(response_header) catch {};
    }

    fn handleCompleteMultipartUpload(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8, upload_id: []const u8) void {
        const etag = self.storage.completeMultipartUpload(bucket, key, upload_id) catch |err| {
            log.err("CompleteMultipart failed: {}", .{err});
            self.sendError(stream, "500", "InternalError", "Failed to complete upload");
            return;
        };
        defer self.allocator.free(etag);

        var xml_buffer = std.ArrayList(u8){};
        defer xml_buffer.deinit(self.allocator);

        const location = std.fmt.allocPrint(self.allocator, "http://localhost:9670/{s}/{s}", .{ bucket, key }) catch return;
        defer self.allocator.free(location);

        s3.writeCompleteMultipartUploadResult(self.allocator, xml_buffer.writer(self.allocator), location, bucket, key, etag) catch {
            self.sendError(stream, "500", "InternalError", "Failed to format response");
            return;
        };

        self.sendResponse(stream, "200 OK", "application/xml", xml_buffer.items);
    }

    fn sendResponse(self: *Server, stream: net.Stream, code: []const u8, content_type: []const u8, body: []const u8) void {
        const response_header = std.fmt.allocPrint(self.allocator, "HTTP/1.1 {s}\r\nContent-Length: {}\r\nContent-Type: {s}\r\nServer: z4\r\n\r\n", .{ code, body.len, content_type }) catch return;
        defer self.allocator.free(response_header);
        stream.writeAll(response_header) catch {};
        stream.writeAll(body) catch {};
    }

    fn sendResponseStats(self: *Server, stream: net.Stream, code: []const u8, content_type: []const u8, body: []const u8, content_range: []const u8, total_len: u64) void {
        const response_header = std.fmt.allocPrint(self.allocator, "HTTP/1.1 {s}\r\nContent-Length: {}\r\nContent-Type: {s}\r\nContent-Range: {s}\r\nAccept-Ranges: bytes\r\nServer: z4\r\n\r\n", .{ code, body.len, content_type, content_range }) catch return;
        _ = total_len;
        defer self.allocator.free(response_header);
        stream.writeAll(response_header) catch {};
        stream.writeAll(body) catch {};
    }

    fn sendError(self: *Server, stream: net.Stream, http_code: []const u8, s3_code: []const u8, message: []const u8) void {
        var xml_buffer = std.ArrayList(u8){};
        defer xml_buffer.deinit(self.allocator);

        const writer = xml_buffer.writer(self.allocator);
        s3.writeErrorXml(self.allocator, writer, .{
            .code = s3_code,
            .message = message,
            .resource = "",
            .request_id = "z4-request",
        }) catch {
            self.sendResponse(stream, http_code, "text/plain", message);
            return;
        };

        self.sendResponse(stream, http_code, "application/xml", xml_buffer.items);
    }

    fn handleListBuckets(self: *Server, stream: net.Stream) void {
        const buckets = self.storage.listBuckets() catch {
            self.sendError(stream, "500 Internal Server Error", "InternalError", "Failed to list buckets");
            return;
        };
        defer {
            for (buckets) |b| self.allocator.free(b);
            self.allocator.free(buckets);
        }

        var xml_buffer = std.ArrayList(u8){};
        defer xml_buffer.deinit(self.allocator);

        s3.writeListBucketsXml(self.allocator, xml_buffer.writer(self.allocator), buckets, null) catch return;

        self.sendResponse(stream, "200 OK", "application/xml", xml_buffer.items);
    }

    fn handleHealthCheck(self: *Server, stream: net.Stream) void {
        const response = "{\"status\":\"healthy\",\"service\":\"z4\"}";
        self.sendResponse(stream, "200 OK", "application/json", response);
    }

    fn handleCreateBucket(self: *Server, stream: net.Stream, bucket: []const u8, headers: std.StringHashMap([]const u8), query_args: std.StringHashMap([]const u8), user_id: []const u8) void {
        _ = headers;
        _ = query_args;
        self.storage.createBucket(bucket, user_id) catch |err| {
            if (err == error.BucketAlreadyExists) {
                audit.logAudit(self.allocator, .PutBucket, user_id, "-", bucket, 409, "Bucket already exists");
                self.sendError(stream, "409 Conflict", "BucketAlreadyExists", "Bucket already exists");
            } else {
                audit.logAudit(self.allocator, .PutBucket, user_id, "-", bucket, 500, "Failed to create bucket");
                self.sendError(stream, "500 Internal Server Error", "InternalError", "Failed to create bucket");
            }
            return;
        };
        audit.logAudit(self.allocator, .PutBucket, user_id, "-", bucket, 200, "Bucket created");
        self.sendResponse(stream, "200 OK", "text/plain", "");
    }

    fn handleListObjects(self: *Server, stream: net.Stream, bucket: []const u8, headers: std.StringHashMap([]const u8)) void {
        _ = headers;
        var xml_buffer = std.ArrayList(u8){};
        defer xml_buffer.deinit(self.allocator);

        var result = self.storage.listObjects(bucket, .{}) catch {
            self.sendError(stream, "404 Not Found", "NoSuchBucket", "The specified bucket does not exist.");
            return;
        };
        defer result.deinit();

        var s3_objects = std.ArrayList(s3.ObjectInfo){};
        defer s3_objects.deinit(self.allocator);

        for (result.objects) |obj| {
            s3_objects.append(self.allocator, .{
                .key = obj.key,
                .size = obj.size,
                .etag = obj.etag,
                .last_modified = obj.last_modified,
            }) catch continue;
        }

        s3.writeListObjectsV2Xml(self.allocator, xml_buffer.writer(self.allocator), .{
            .name = bucket,
            .prefix = "",
            .key_count = result.objects.len,
            .max_keys = constants.LIST_OBJECTS_MAX_KEYS,
            .is_truncated = result.is_truncated,
        }, s3_objects.items, result.common_prefixes) catch return;

        self.sendResponse(stream, "200 OK", "application/xml", xml_buffer.items);
    }

    fn handleDeleteBucket(self: *Server, stream: net.Stream, bucket: []const u8, user_id: []const u8) void {
        const resource = std.fmt.allocPrint(self.allocator, "arn:aws:s3:::{s}", .{bucket}) catch return;
        defer self.allocator.free(resource);
        if (!self.storage.evaluatePolicy(bucket, .DeleteBucket, "*", resource)) {
            audit.logAudit(self.allocator, .AccessDenied, user_id, "-", resource, 403, "Bucket Policy Deny");
            self.sendError(stream, "403 Forbidden", "AccessDenied", "Access Denied by bucket policy");
            return;
        }

        self.storage.deleteBucket(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                audit.logAudit(self.allocator, .DeleteBucket, user_id, "-", bucket, 404, "Bucket not found");
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "The specified bucket does not exist");
            } else if (err == error.BucketNotEmpty) {
                audit.logAudit(self.allocator, .DeleteBucket, user_id, "-", bucket, 409, "Bucket not empty");
                self.sendError(stream, "409 Conflict", "BucketNotEmpty", "The bucket you tried to delete is not empty");
            } else {
                audit.logAudit(self.allocator, .DeleteBucket, user_id, "-", bucket, 500, "Internal Error");
                log.err("DeleteBucket failed: {}", .{err});
                self.sendError(stream, "500 Internal Server Error", "InternalError", "Failed to delete bucket");
            }
            return;
        };

        audit.logAudit(self.allocator, .DeleteBucket, user_id, "-", bucket, 204, "Bucket deleted");
        self.sendError(stream, "204 No Content", "", "");
    }

    fn handleGetBucketLocation(self: *Server, stream: net.Stream) void {
        const xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>";
        self.sendResponse(stream, "200 OK", "application/xml", xml);
    }

    fn handlePutObject(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8, initial_data: []const u8, headers: std.StringHashMap([]const u8), user_id: []const u8) void {
        const resource = std.fmt.allocPrint(self.allocator, "arn:aws:s3:::{s}/{s}", .{ bucket, key }) catch return;
        defer self.allocator.free(resource);
        if (!self.storage.evaluatePolicy(bucket, .PutObject, "*", resource)) {
            audit.logAudit(self.allocator, .AccessDenied, user_id, "-", resource, 403, "Bucket Policy Deny");
            self.sendError(stream, "403 Forbidden", "AccessDenied", "Access Denied by bucket policy");
            return;
        }

        const full_key = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ bucket, key }) catch return;
        defer self.allocator.free(full_key);

        if (!self.cluster.isLocal(full_key)) {
            const node = self.cluster.getNodeFor(full_key);
            const url = std.fmt.allocPrint(self.allocator, "http://{s}:{}/{s}/{s}", .{ node.address, node.port, bucket, key }) catch return;
            defer self.allocator.free(url);
            const response_header = std.fmt.allocPrint(self.allocator, "HTTP/1.1 307 Temporary Redirect\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n", .{url}) catch return;
            defer self.allocator.free(response_header);
            stream.writeAll(response_header) catch {};
            return;
        }

        const content_type = headers.get("content-type") orelse "application/octet-stream";

        if (headers.get("x-amz-copy-source")) |copy_source| {
            var src = copy_source;
            if (std.mem.startsWith(u8, src, "/")) src = src[1..];

            if (std.mem.indexOfScalar(u8, src, '/')) |slash_idx| {
                const src_bucket = src[0..slash_idx];
                const src_key = src[slash_idx + 1 ..];

                self.storage.copyObject(src_bucket, src_key, bucket, key) catch |err| {
                    if (err == error.NoSuchKey) {
                        audit.logAudit(self.allocator, .PutObject, user_id, "-", resource, 404, "Copy Source Not Found");
                        self.sendError(stream, "404 Not Found", "NoSuchKey", "The specified key does not exist.");
                    } else if (err == error.NoSuchBucket) {
                        audit.logAudit(self.allocator, .PutObject, user_id, "-", resource, 404, "Copy Source Bucket Not Found");
                        self.sendError(stream, "404 Not Found", "NoSuchBucket", "The specified bucket does not exist.");
                    } else {
                        audit.logAudit(self.allocator, .PutObject, user_id, "-", resource, 500, "Copy Internal Error");
                        log.err("Copy failed: {}", .{err});
                        self.sendError(stream, "500", "InternalError", "Copy failed");
                    }
                    return;
                };

                audit.logAudit(self.allocator, .PutObject, user_id, "-", resource, 200, "Object Copied");
                const timestamp = std.time.milliTimestamp();
                const xml = std.fmt.allocPrint(self.allocator, "<CopyObjectResult><LastModified>{}</LastModified><ETag>\"000\"</ETag></CopyObjectResult>", .{timestamp}) catch return;
                defer self.allocator.free(xml);

                self.sendResponse(stream, "200 OK", "application/xml", xml);
                return;
            } else {
                self.sendError(stream, "400 Bad Request", "InvalidArgument", "Invalid copy source format");
                return;
            }
        }

        var user_meta = std.StringHashMap([]const u8).init(self.allocator);
        defer user_meta.deinit();

        var h_iter = headers.iterator();
        while (h_iter.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, "x-amz-meta-")) {
                user_meta.put(entry.key_ptr.*, entry.value_ptr.*) catch {};
            }
        }

        const content_length_str = headers.get("content-length") orelse "0";
        var content_length = std.fmt.parseInt(u64, content_length_str, 10) catch 0;

        var is_chunked = false;
        if (headers.get("transfer-encoding")) |te| {
            if (std.mem.indexOf(u8, te, "chunked") != null) {
                is_chunked = true;
                content_length = std.math.maxInt(u64);
            }
        }

        if (is_chunked) {
            var chunked_reader = ChunkedReader(net.Stream).init(self.allocator, stream);
            const version_id = self.storage.putObjectVersionedStreaming(bucket, key, chunked_reader.reader(), content_length, content_type, user_meta, initial_data) catch |e| {
                log.err("Failed to put object {s}/{s}: {}", .{ bucket, key, e });
                audit.logAudit(self.allocator, .PutObject, user_id, "-", resource, 500, "Put Internal Error");
                self.sendError(stream, "500 Internal Server Error", "InternalError", "Failed to put object");
                return;
            };
            defer self.allocator.free(version_id);
            audit.logAudit(self.allocator, .PutObject, user_id, "-", resource, 200, "Object Put (Chunked)");
            var resp_buf = std.ArrayList(u8).initCapacity(self.allocator, 256) catch return;
            defer resp_buf.deinit(self.allocator);
            const writer = resp_buf.writer(self.allocator);

            std.fmt.format(writer, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nx-amz-version-id: {s}\r\nServer: z4\r\n\r\n", .{version_id}) catch return;
            stream.writeAll(resp_buf.items) catch {};
            return;
        }

        const version_id = self.storage.putObjectVersionedStreaming(bucket, key, stream, content_length, content_type, user_meta, initial_data) catch |e| {
            log.err("Failed to put object {s}/{s}: {}", .{ bucket, key, e });
            audit.logAudit(self.allocator, .PutObject, user_id, "-", resource, 500, "Put Internal Error");
            self.sendError(stream, "500 Internal Server Error", "InternalError", "Failed to put object");
            return;
        };
        defer self.allocator.free(version_id);

        audit.logAudit(self.allocator, .PutObject, user_id, "-", resource, 200, "Object Put");
        var resp_buf = std.ArrayList(u8).initCapacity(self.allocator, 256) catch return;
        defer resp_buf.deinit(self.allocator);
        const writer = resp_buf.writer(self.allocator);

        std.fmt.format(writer, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nx-amz-version-id: {s}\r\nServer: z4\r\n\r\n", .{version_id}) catch return;
        stream.writeAll(resp_buf.items) catch {};
    }

    fn handleDeleteObject(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8, user_id: []const u8) void {
        const resource = std.fmt.allocPrint(self.allocator, "arn:aws:s3:::{s}/{s}", .{ bucket, key }) catch return;
        defer self.allocator.free(resource);

        if (!self.storage.evaluatePolicy(bucket, .DeleteObject, "*", resource)) {
            audit.logAudit(self.allocator, .AccessDenied, user_id, "-", resource, 403, "Bucket Policy Deny");
            self.sendError(stream, "403 Forbidden", "AccessDenied", "Access Denied by bucket policy");
            return;
        }

        self.storage.deleteObject(bucket, key) catch |err| {
            if (err == error.NoSuchKey) {} else if (err == error.NoSuchBucket) {
                audit.logAudit(self.allocator, .DeleteObject, user_id, "-", resource, 404, "Bucket not found");
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "The specified bucket does not exist");
                return;
            } else {
                audit.logAudit(self.allocator, .DeleteObject, user_id, "-", resource, 500, "Internal Error");
                log.err("DeleteObject failed: {}", .{err});
                self.sendError(stream, "500 Internal Server Error", "InternalError", "Failed to delete object");
                return;
            }
        };

        audit.logAudit(self.allocator, .DeleteObject, user_id, "-", resource, 204, "Object Deleted");
        self.sendError(stream, "204 No Content", "", "");
    }

    fn handleHeadObject(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8) void {
        const full_key = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ bucket, key }) catch return;
        defer self.allocator.free(full_key);

        if (!self.cluster.isLocal(full_key)) {
            const node = self.cluster.getNodeFor(full_key);
            const url = std.fmt.allocPrint(self.allocator, "http://{s}:{}/{s}/{s}", .{ node.address, node.port, bucket, key }) catch return;
            defer self.allocator.free(url);
            const response_header = std.fmt.allocPrint(self.allocator, "HTTP/1.1 307 Temporary Redirect\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n", .{url}) catch return;
            defer self.allocator.free(response_header);
            stream.writeAll(response_header) catch {};
            return;
        }

        var meta = self.storage.headObject(bucket, key) catch |err| {
            if (err == error.NoSuchKey) {
                self.sendError(stream, "404 Not Found", "NoSuchKey", "");
            } else if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                std.debug.print("HeadObject Error: {}\n", .{err});
                self.sendError(stream, "500", "Internal", "");
            }
            return;
        };
        defer meta.deinit(self.allocator);

        var resp_buf = std.ArrayList(u8).initCapacity(self.allocator, constants.RESPONSE_BUFFER_INITIAL_CAPACITY) catch return;
        defer resp_buf.deinit(self.allocator);
        const writer = resp_buf.writer(self.allocator);

        std.fmt.format(writer, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {s}\r\nETag: {s}\r\nLast-Modified: {}\r\nServer: z4\r\n", .{ meta.size, meta.content_type, meta.etag, meta.last_modified }) catch return;

        var m_iter = meta.user_metadata.iterator();
        while (m_iter.next()) |entry| {
            std.fmt.format(writer, "{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* }) catch {};
        }
        std.fmt.format(writer, "\r\n", .{}) catch {};

        stream.writeAll(resp_buf.items) catch {};
    }

    fn handleGetObject(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8, headers: std.StringHashMap([]const u8), query_args: std.StringHashMap([]const u8)) void {
        const resource = std.fmt.allocPrint(self.allocator, "arn:aws:s3:::{s}/{s}", .{ bucket, key }) catch return;
        defer self.allocator.free(resource);
        if (!self.storage.evaluatePolicy(bucket, .GetObject, "*", resource)) {
            self.sendError(stream, "403 Forbidden", "AccessDenied", "Access Denied by bucket policy");
            return;
        }

        const user_id = auth.getUserId(headers, query_args);
        var allowed = self.no_auth;

        if (!allowed) {
            if (user_id) |u| {
                log.debug("ACL Check - User: {s}", .{u});
            } else {
                log.debug("ACL Check - User: Anonymous", .{});
            }

            const checkGrants = struct {
                fn check(grants: []const @import("storage.zig").Storage.AclGrant, user: ?[]const u8) bool {
                    for (grants) |grant| {
                        if (grant.permission == .READ or grant.permission == .FULL_CONTROL) {
                            if (std.mem.eql(u8, grant.grantee, "http://acs.amazonaws.com/groups/global/AllUsers")) return true;
                            if (user) |u| {
                                if (std.mem.eql(u8, grant.grantee, u)) return true;
                            }
                        }
                    }
                    return false;
                }
            }.check;

            if (self.storage.getObjectAcl(bucket, key)) |acl| {
                defer {
                    var mut_acl = acl;
                    mut_acl.deinit();
                }
                if (user_id) |u| {
                    if (std.mem.eql(u8, acl.owner, u)) allowed = true;
                }
                log.debug("Object ACL Owner: {s}, Allowed: {}", .{ acl.owner, allowed });
                if (!allowed) allowed = checkGrants(acl.grants, user_id);
            } else |_| {
                if (self.storage.getBucketAcl(bucket)) |acl| {
                    defer {
                        var mut_acl = acl;
                        mut_acl.deinit();
                    }
                    if (user_id) |u| {
                        if (std.mem.eql(u8, acl.owner, u)) allowed = true;
                    }
                    log.debug("Bucket ACL Owner: {s}, Allowed: {}", .{ acl.owner, allowed });
                    if (!allowed) allowed = checkGrants(acl.grants, user_id);
                } else |_| {
                    allowed = true;
                }
            }
        }

        if (!allowed) {
            self.sendError(stream, "403 Forbidden", "AccessDenied", "Access Denied");
            return;
        }

        const full_key = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ bucket, key }) catch return;
        defer self.allocator.free(full_key);

        if (!self.cluster.isLocal(full_key)) {
            const node = self.cluster.getNodeFor(full_key);
            const url = std.fmt.allocPrint(self.allocator, "http://{s}:{}/{s}/{s}", .{ node.address, node.port, bucket, key }) catch return;
            defer self.allocator.free(url);

            const response_header = std.fmt.allocPrint(self.allocator, "HTTP/1.1 307 Temporary Redirect\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n", .{url}) catch return;
            defer self.allocator.free(response_header);
            stream.writeAll(response_header) catch {};
            return;
        }

        var start_byte: u64 = 0;
        var end_byte: u64 = 0;
        var has_range = false;

        if (headers.get("range")) |range_val| {
            if (std.mem.startsWith(u8, range_val, "bytes=")) {
                const range_str = range_val[6..];
                var it = std.mem.splitScalar(u8, range_str, '-');
                const s_str = it.next() orelse "0";
                const e_str = it.next() orelse "";

                start_byte = std.fmt.parseInt(u64, s_str, 10) catch 0;
                if (e_str.len > 0) {
                    end_byte = std.fmt.parseInt(u64, e_str, 10) catch 0;
                    if (end_byte >= start_byte) has_range = true;
                } else {
                    has_range = true;
                    end_byte = 0;
                }
            }
        }

        if (has_range) {
            const total_size = self.storage.getObjectSize(bucket, key) catch |err| {
                if (err == error.NoSuchKey) self.sendError(stream, "404 Not Found", "NoSuchKey", "") else self.sendError(stream, "500", "Internal", "");
                return;
            };

            var real_end = end_byte;
            if (real_end == 0 or real_end >= total_size) real_end = total_size - 1;

            const len = real_end - start_byte + 1;

            const data = self.storage.getObjectRange(bucket, key, start_byte, len) catch |err| {
                log.err("Range read failed: {}", .{err});
                self.sendError(stream, "500", "Internal", "Range read failed");
                return;
            };
            defer self.allocator.free(data);

            var cr_buf: [128]u8 = undefined;
            const cr = std.fmt.bufPrint(&cr_buf, "bytes {}-{}/{}", .{ start_byte, real_end, total_size }) catch "bytes */*";

            var content_type: []const u8 = "application/octet-stream";
            var meta_cleanup: bool = false;
            var meta_obj: ?Storage.ObjectMetadata = null;

            if (self.storage.headObject(bucket, key)) |meta| {
                meta_obj = meta;
                content_type = meta.content_type;
                meta_cleanup = true;
            } else |_| {}

            defer if (meta_cleanup) {
                if (meta_obj) |m| {
                    self.allocator.free(m.content_type);
                    self.allocator.free(m.etag);
                }
            };

            self.sendResponseStats(stream, "206 Partial Content", content_type, data, cr, total_size);
            return;
        }

        const data = self.storage.getObject(bucket, key) catch |err| {
            if (err == error.NoSuchKey) {
                self.sendError(stream, "404 Not Found", "NoSuchKey", "The specified key does not exist.");
            } else if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "The specified bucket does not exist.");
            } else {
                self.sendError(stream, "500 Internal Server Error", "InternalError", "Failed to get object");
            }
            return;
        };
        defer self.allocator.free(data);

        var content_type: []const u8 = "application/octet-stream";
        var meta_cleanup: bool = false;
        var meta_obj: ?Storage.ObjectMetadata = null;

        if (self.storage.headObject(bucket, key)) |meta| {
            meta_obj = meta;
            content_type = meta.content_type;
            meta_cleanup = true;
        } else |_| {}

        defer if (meta_cleanup) {
            if (meta_obj) |*m| m.deinit(self.allocator);
        };

        var resp_buf = std.ArrayList(u8).initCapacity(self.allocator, constants.RESPONSE_BUFFER_INITIAL_CAPACITY) catch return;
        defer resp_buf.deinit(self.allocator);
        const writer = resp_buf.writer(self.allocator);

        std.fmt.format(writer, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {s}\r\nServer: z4\r\n", .{ data.len, content_type }) catch return;

        if (meta_obj) |m| {
            std.fmt.format(writer, "ETag: {s}\r\nLast-Modified: {}\r\n", .{ m.etag, m.last_modified }) catch {};
            var iter = m.user_metadata.iterator();
            while (iter.next()) |entry| {
                std.fmt.format(writer, "{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* }) catch {};
            }
        }
        std.fmt.format(writer, "\r\n", .{}) catch {};

        stream.writeAll(resp_buf.items) catch {};
        stream.writeAll(data) catch {};
    }

    fn handlePutObjectTagging(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8, body: []const u8) void {
        var tags = std.StringHashMap([]const u8).init(self.allocator);
        defer tags.deinit();

        var pos: usize = 0;
        while (pos < body.len) {
            const tag_start = std.mem.indexOf(u8, body[pos..], "<Tag>") orelse break;
            const tag_end = std.mem.indexOf(u8, body[pos + tag_start ..], "</Tag>") orelse break;
            const tag_content = body[pos + tag_start + 5 .. pos + tag_start + tag_end];
            pos = pos + tag_start + tag_end + 6;

            const key_start = std.mem.indexOf(u8, tag_content, "<Key>") orelse continue;
            const key_end = std.mem.indexOf(u8, tag_content, "</Key>") orelse continue;
            const tag_key = tag_content[key_start + 5 .. key_end];

            const val_start = std.mem.indexOf(u8, tag_content, "<Value>") orelse continue;
            const val_end = std.mem.indexOf(u8, tag_content, "</Value>") orelse continue;
            const value = tag_content[val_start + 7 .. val_end];

            const key_dup = self.allocator.dupe(u8, tag_key) catch continue;
            const val_dup = self.allocator.dupe(u8, value) catch {
                self.allocator.free(key_dup);
                continue;
            };
            tags.put(key_dup, val_dup) catch {
                self.allocator.free(key_dup);
                self.allocator.free(val_dup);
            };
        }

        self.storage.putObjectTagging(bucket, key, tags) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else if (err == error.NoSuchKey) {
                self.sendError(stream, "404 Not Found", "NoSuchKey", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "204 No Content", "application/xml", "");
    }

    fn handleGetObjectTagging(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8) void {
        var tags = self.storage.getObjectTagging(bucket, key) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else if (err == error.NoSuchKey) {
                self.sendError(stream, "404 Not Found", "NoSuchKey", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };
        defer {
            var iter = tags.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            tags.deinit();
        }

        var resp = std.ArrayList(u8).initCapacity(self.allocator, 512) catch return;
        defer resp.deinit(self.allocator);
        const writer = resp.writer(self.allocator);

        std.fmt.format(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Tagging><TagSet>", .{}) catch return;

        var iter = tags.iterator();
        while (iter.next()) |entry| {
            std.fmt.format(writer, "<Tag><Key>{s}</Key><Value>{s}</Value></Tag>", .{ entry.key_ptr.*, entry.value_ptr.* }) catch {};
        }

        std.fmt.format(writer, "</TagSet></Tagging>", .{}) catch {};

        self.sendResponse(stream, "200 OK", "application/xml", resp.items);
    }

    fn handleDeleteObjectTagging(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8) void {
        self.storage.deleteObjectTagging(bucket, key) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else if (err == error.NoSuchKey) {
                self.sendError(stream, "404 Not Found", "NoSuchKey", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "204 No Content", "text/plain", "");
    }

    fn handlePutBucketTagging(self: *Server, stream: net.Stream, bucket: []const u8, body: []const u8) void {
        var tags = std.StringHashMap([]const u8).init(self.allocator);
        defer tags.deinit();

        var pos: usize = 0;
        while (pos < body.len) {
            const tag_start = std.mem.indexOf(u8, body[pos..], "<Tag>") orelse break;
            const tag_end = std.mem.indexOf(u8, body[pos + tag_start ..], "</Tag>") orelse break;
            const tag_content = body[pos + tag_start + 5 .. pos + tag_start + tag_end];
            pos = pos + tag_start + tag_end + 6;

            const key_start = std.mem.indexOf(u8, tag_content, "<Key>") orelse continue;
            const key_end = std.mem.indexOf(u8, tag_content, "</Key>") orelse continue;
            const key = tag_content[key_start + 5 .. key_end];

            const val_start = std.mem.indexOf(u8, tag_content, "<Value>") orelse continue;
            const val_end = std.mem.indexOf(u8, tag_content, "</Value>") orelse continue;
            const value = tag_content[val_start + 7 .. val_end];

            const key_dup = self.allocator.dupe(u8, key) catch continue;
            const val_dup = self.allocator.dupe(u8, value) catch {
                self.allocator.free(key_dup);
                continue;
            };
            tags.put(key_dup, val_dup) catch {
                self.allocator.free(key_dup);
                self.allocator.free(val_dup);
            };
        }

        self.storage.putBucketTagging(bucket, tags) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "204 No Content", "application/xml", "");
    }

    fn handleGetBucketTagging(self: *Server, stream: net.Stream, bucket: []const u8) void {
        var tags = self.storage.getBucketTagging(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };
        defer {
            var iter = tags.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            tags.deinit();
        }

        var resp = std.ArrayList(u8).initCapacity(self.allocator, 512) catch return;
        defer resp.deinit(self.allocator);
        const writer = resp.writer(self.allocator);

        std.fmt.format(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Tagging><TagSet>", .{}) catch return;

        var iter = tags.iterator();
        while (iter.next()) |entry| {
            std.fmt.format(writer, "<Tag><Key>{s}</Key><Value>{s}</Value></Tag>", .{ entry.key_ptr.*, entry.value_ptr.* }) catch {};
        }

        std.fmt.format(writer, "</TagSet></Tagging>", .{}) catch {};

        self.sendResponse(stream, "200 OK", "application/xml", resp.items);
    }

    fn handleDeleteBucketTagging(self: *Server, stream: net.Stream, bucket: []const u8) void {
        self.storage.deleteBucketTagging(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "204 No Content", "text/plain", "");
    }

    fn handlePutBucketAcl(self: *Server, stream: net.Stream, bucket: []const u8, body: []const u8, headers: std.StringHashMap([]const u8), query_args: std.StringHashMap([]const u8)) void {
        const user_id = auth.getUserId(headers, query_args);

        var owner_buf: [256]u8 = undefined;
        var owner: []const u8 = if (user_id) |u| u else "default";

        if (self.storage.getBucketAcl(bucket)) |existing_acl| {
            @memcpy(owner_buf[0..existing_acl.owner.len], existing_acl.owner);
            owner = owner_buf[0..existing_acl.owner.len];
            var mut = existing_acl;
            mut.deinit();
        } else |_| {}

        var grants = std.ArrayList(Storage.AclGrant).initCapacity(self.allocator, 8) catch return;
        defer grants.deinit(self.allocator);

        const canned_acl = headers.get("x-amz-acl") orelse query_args.get("x-amz-acl") orelse "";

        if (std.mem.eql(u8, canned_acl, "public-read")) {
            grants.append(self.allocator, .{ .grantee = owner, .permission = .FULL_CONTROL }) catch {};
            grants.append(self.allocator, .{ .grantee = "http://acs.amazonaws.com/groups/global/AllUsers", .permission = .READ }) catch {};
        } else if (std.mem.eql(u8, canned_acl, "public-read-write")) {
            grants.append(self.allocator, .{ .grantee = owner, .permission = .FULL_CONTROL }) catch {};
            grants.append(self.allocator, .{ .grantee = "http://acs.amazonaws.com/groups/global/AllUsers", .permission = .READ }) catch {};
            grants.append(self.allocator, .{ .grantee = "http://acs.amazonaws.com/groups/global/AllUsers", .permission = .WRITE }) catch {};
        } else if (std.mem.eql(u8, canned_acl, "private") or std.mem.eql(u8, body, "private")) {
            grants.append(self.allocator, .{ .grantee = owner, .permission = .FULL_CONTROL }) catch {};
        } else if (body.len > 0) {
            var pairs = std.mem.splitScalar(u8, body, '&');
            while (pairs.next()) |pair| {
                if (pair.len == 0) continue;
                if (std.mem.startsWith(u8, pair, "owner=")) {
                    owner = pair[6..];
                } else if (std.mem.startsWith(u8, pair, "grant=")) {
                    const grant_str = pair[6..];
                    if (std.mem.indexOfScalar(u8, grant_str, ':')) |colon_idx| {
                        const grantee = grant_str[0..colon_idx];
                        const perm_str = grant_str[colon_idx + 1 ..];
                        const permission: Storage.AclPermission = if (std.mem.eql(u8, perm_str, "FULL_CONTROL"))
                            .FULL_CONTROL
                        else if (std.mem.eql(u8, perm_str, "READ"))
                            .READ
                        else if (std.mem.eql(u8, perm_str, "WRITE"))
                            .WRITE
                        else if (std.mem.eql(u8, perm_str, "READ_ACP"))
                            .READ_ACP
                        else
                            .WRITE_ACP;
                        grants.append(self.allocator, .{ .grantee = grantee, .permission = permission }) catch {};
                    }
                }
            }
        }

        if (grants.items.len == 0) {
            grants.append(self.allocator, .{ .grantee = owner, .permission = .FULL_CONTROL }) catch {};
        }

        self.storage.putBucketAcl(bucket, owner, grants.items) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "200 OK", "application/xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    }

    fn handleGetBucketAcl(self: *Server, stream: net.Stream, bucket: []const u8) void {
        var acl = self.storage.getBucketAcl(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };
        defer acl.deinit();

        var resp = std.ArrayList(u8).initCapacity(self.allocator, 512) catch return;
        defer resp.deinit(self.allocator);
        const writer = resp.writer(self.allocator);

        std.fmt.format(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AccessControlPolicy><Owner><ID>{s}</ID></Owner><AccessControlList>", .{acl.owner}) catch return;

        for (acl.grants) |grant| {
            const perm_str = switch (grant.permission) {
                .FULL_CONTROL => "FULL_CONTROL",
                .READ => "READ",
                .WRITE => "WRITE",
                .READ_ACP => "READ_ACP",
                .WRITE_ACP => "WRITE_ACP",
            };
            std.fmt.format(writer, "<Grant><Grantee><ID>{s}</ID></Grantee><Permission>{s}</Permission></Grant>", .{ grant.grantee, perm_str }) catch {};
        }

        std.fmt.format(writer, "</AccessControlList></AccessControlPolicy>", .{}) catch {};

        self.sendResponse(stream, "200 OK", "application/xml", resp.items);
    }

    fn handlePutObjectAcl(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8, body: []const u8) void {
        var owner: []const u8 = "default";
        var grants = std.ArrayList(Storage.AclGrant).initCapacity(self.allocator, 8) catch return;
        defer grants.deinit(self.allocator);

        var pairs = std.mem.splitScalar(u8, body, '&');
        while (pairs.next()) |pair| {
            if (pair.len == 0) continue;
            if (std.mem.startsWith(u8, pair, "owner=")) {
                owner = pair[6..];
            } else if (std.mem.startsWith(u8, pair, "grant=")) {
                const grant_str = pair[6..];
                if (std.mem.indexOfScalar(u8, grant_str, ':')) |colon_idx| {
                    const grantee = grant_str[0..colon_idx];
                    const perm_str = grant_str[colon_idx + 1 ..];
                    const permission: Storage.AclPermission = if (std.mem.eql(u8, perm_str, "FULL_CONTROL"))
                        .FULL_CONTROL
                    else if (std.mem.eql(u8, perm_str, "READ"))
                        .READ
                    else if (std.mem.eql(u8, perm_str, "WRITE"))
                        .WRITE
                    else if (std.mem.eql(u8, perm_str, "READ_ACP"))
                        .READ_ACP
                    else
                        .WRITE_ACP;
                    grants.append(self.allocator, .{ .grantee = grantee, .permission = permission }) catch {};
                }
            }
        }

        self.storage.putObjectAcl(bucket, key, owner, grants.items) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else if (err == error.NoSuchKey) {
                self.sendError(stream, "404 Not Found", "NoSuchKey", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "200 OK", "application/xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    }

    fn handleGetObjectAcl(self: *Server, stream: net.Stream, bucket: []const u8, key: []const u8) void {
        var acl = self.storage.getObjectAcl(bucket, key) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else if (err == error.NoSuchKey) {
                self.sendError(stream, "404 Not Found", "NoSuchKey", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };
        defer acl.deinit();

        var resp = std.ArrayList(u8).initCapacity(self.allocator, 512) catch return;
        defer resp.deinit(self.allocator);
        const writer = resp.writer(self.allocator);

        std.fmt.format(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AccessControlPolicy><Owner><ID>{s}</ID></Owner><AccessControlList>", .{acl.owner}) catch return;

        for (acl.grants) |grant| {
            const perm_str = switch (grant.permission) {
                .FULL_CONTROL => "FULL_CONTROL",
                .READ => "READ",
                .WRITE => "WRITE",
                .READ_ACP => "READ_ACP",
                .WRITE_ACP => "WRITE_ACP",
            };
            std.fmt.format(writer, "<Grant><Grantee><ID>{s}</ID></Grantee><Permission>{s}</Permission></Grant>", .{ grant.grantee, perm_str }) catch {};
        }

        std.fmt.format(writer, "</AccessControlList></AccessControlPolicy>", .{}) catch {};

        self.sendResponse(stream, "200 OK", "application/xml", resp.items);
    }

    fn handlePutBucketPolicy(self: *Server, stream: net.Stream, bucket: []const u8, body: []const u8) void {
        self.storage.putBucketPolicy(bucket, body) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "200 OK", "text/plain", "");
    }

    fn handleGetBucketPolicy(self: *Server, stream: net.Stream, bucket: []const u8) void {
        const policy = self.storage.getBucketPolicy(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else if (err == error.NoSuchBucketPolicy) {
                self.sendError(stream, "404 Not Found", "NoSuchBucketPolicy", "The bucket policy does not exist");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };
        defer self.allocator.free(policy);

        self.sendResponse(stream, "200 OK", "application/json", policy);
    }

    fn handleDeleteBucketPolicy(self: *Server, stream: net.Stream, bucket: []const u8) void {
        self.storage.deleteBucketPolicy(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else if (err == error.NoSuchBucketPolicy) {
                self.sendResponse(stream, "204 No Content", "text/plain", "");
                return;
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "204 No Content", "text/plain", "");
    }

    fn handlePutBucketEncryption(self: *Server, stream: net.Stream, bucket: []const u8, body: []const u8) void {
        var algorithm: []const u8 = "AES256";

        if (std.mem.indexOf(u8, body, "AES256")) |_| {
            algorithm = "AES256";
        } else if (std.mem.indexOf(u8, body, "aws:kms")) |_| {
            algorithm = "aws:kms";
        }

        self.storage.putBucketEncryption(bucket, algorithm) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "200 OK", "application/xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    }

    fn handleGetBucketEncryption(self: *Server, stream: net.Stream, bucket: []const u8) void {
        const config = self.storage.getBucketEncryption(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        if (!config.enabled) {
            self.sendError(stream, "404 Not Found", "ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found");
            return;
        }

        var resp = std.ArrayList(u8).initCapacity(self.allocator, 512) catch return;
        defer resp.deinit(self.allocator);
        const writer = resp.writer(self.allocator);

        std.fmt.format(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>{s}</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>", .{config.algorithm.toString()}) catch return;

        self.sendResponse(stream, "200 OK", "application/xml", resp.items);
    }

    fn handleDeleteBucketEncryption(self: *Server, stream: net.Stream, bucket: []const u8) void {
        self.storage.deleteBucketEncryption(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "204 No Content", "text/plain", "");
    }

    fn handlePutBucketVersioning(self: *Server, stream: net.Stream, bucket: []const u8, body: []const u8) void {
        var status: Storage.VersioningStatus = .Disabled;

        if (std.mem.indexOf(u8, body, "Enabled")) |_| {
            status = .Enabled;
        } else if (std.mem.indexOf(u8, body, "Suspended")) |_| {
            status = .Suspended;
        }

        self.storage.putBucketVersioning(bucket, status) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "200 OK", "text/plain", "");
    }

    fn handleGetBucketVersioning(self: *Server, stream: net.Stream, bucket: []const u8) void {
        const status = self.storage.getBucketVersioning(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        var resp = std.ArrayList(u8).initCapacity(self.allocator, 256) catch return;
        defer resp.deinit(self.allocator);
        const writer = resp.writer(self.allocator);

        if (status == .Disabled) {
            std.fmt.format(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<VersioningConfiguration/>", .{}) catch return;
        } else {
            std.fmt.format(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<VersioningConfiguration><Status>{s}</Status></VersioningConfiguration>", .{status.toString()}) catch return;
        }

        self.sendResponse(stream, "200 OK", "application/xml", resp.items);
    }

    fn handlePutBucketLifecycle(self: *Server, stream: net.Stream, bucket: []const u8, body: []const u8) void {
        self.storage.putBucketLifecycle(bucket, body) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "200 OK", "text/plain", "");
    }

    fn handleGetBucketLifecycle(self: *Server, stream: net.Stream, bucket: []const u8) void {
        const lifecycle = self.storage.getBucketLifecycle(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else if (err == error.NoSuchLifecycleConfiguration) {
                self.sendError(stream, "404 Not Found", "NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };
        defer self.allocator.free(lifecycle);

        self.sendResponse(stream, "200 OK", "application/xml", lifecycle);
    }

    fn handleDeleteBucketLifecycle(self: *Server, stream: net.Stream, bucket: []const u8) void {
        self.storage.deleteBucketLifecycle(bucket) catch |err| {
            if (err == error.NoSuchBucket) {
                self.sendError(stream, "404 Not Found", "NoSuchBucket", "");
            } else {
                self.sendError(stream, "500", "InternalError", "");
            }
            return;
        };

        self.sendResponse(stream, "204 No Content", "text/plain", "");
    }
};
