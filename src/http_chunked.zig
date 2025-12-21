const std = @import("std");
const log = std.log.scoped(.chunked);

pub fn ChunkedReader(comptime ReaderType: type) type {
    return struct {
        underlying_reader: ReaderType,
        remaining_chunk_size: u64 = 0,
        finished: bool = false,
        allocator: std.mem.Allocator,

        const ReaderError = if (@hasDecl(ReaderType, "Error")) ReaderType.Error else if (@hasDecl(ReaderType, "ReadError")) ReaderType.ReadError else anyerror;

        pub const Error = ReaderError || error{
            InvalidChunkSize,
            InvalidChunkEnd,
            UnexpectedEOF,
        };

        pub const Reader = std.io.GenericReader(*@This(), Error, read);

        pub fn init(allocator: std.mem.Allocator, stream_reader: ReaderType) @This() {
            return .{
                .underlying_reader = stream_reader,
                .allocator = allocator,
            };
        }

        pub fn reader(self: *@This()) Reader {
            return .{ .context = self };
        }

        pub fn read(self: *@This(), dest: []u8) Error!usize {
            if (self.finished) return 0;
            if (dest.len == 0) return 0;

            if (self.remaining_chunk_size == 0) {
                const chunk_size = try self.readChunkSize();
                if (chunk_size == 0) {
                    self.finished = true;

                    try self.readCRLF();
                    return 0;
                }
                self.remaining_chunk_size = chunk_size;
            }

            const to_read = @min(dest.len, self.remaining_chunk_size);
            const n = try self.underlying_reader.read(dest[0..to_read]);
            if (n == 0) return error.UnexpectedEOF;

            self.remaining_chunk_size -= n;

            if (self.remaining_chunk_size == 0) {
                try self.readCRLF();
            }

            return n;
        }

        fn readChunkSize(self: *@This()) Error!u64 {
            var buf: [32]u8 = undefined;
            var pos: usize = 0;
            while (true) {
                if (pos >= buf.len) return error.InvalidChunkSize;
                const byte = try self.readUnderlyingByte();

                if (byte == '\n') {
                    if (pos > 0 and buf[pos - 1] == '\r') {
                        const hex_str = buf[0 .. pos - 1];

                        var size_end = hex_str.len;
                        if (std.mem.indexOfScalar(u8, hex_str, ';')) |semi| {
                            size_end = semi;
                        }

                        const size_trim = std.mem.trim(u8, hex_str[0..size_end], " \t");
                        if (size_trim.len == 0) return error.InvalidChunkSize;

                        return std.fmt.parseInt(u64, size_trim, 16) catch return error.InvalidChunkSize;
                    }
                }
                buf[pos] = byte;
                pos += 1;
            }
        }

        fn readCRLF(self: *@This()) Error!void {
            const b1 = try self.readUnderlyingByte();
            const b2 = try self.readUnderlyingByte();
            if (b1 != '\r' or b2 != '\n') return error.InvalidChunkEnd;
        }

        fn readUnderlyingByte(self: *@This()) Error!u8 {
            var buf: [1]u8 = undefined;
            const n = try self.underlying_reader.read(&buf);
            if (n == 0) return error.UnexpectedEOF;
            return buf[0];
        }
    };
}

test "ChunkedReader basic" {
    const data = "4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n";
    var fbs = std.io.fixedBufferStream(data);
    var chunked = ChunkedReader(std.io.FixedBufferStream([]const u8).Reader).init(std.testing.allocator, fbs.reader());

    var buf: [100]u8 = undefined;
    const n = try chunked.read(&buf);

    try std.testing.expectEqual(23, n);
    try std.testing.expectEqualStrings("Wikipedia in\r\n\r\nchunks.", buf[0..n]);

    const n2 = try chunked.read(&buf);
    try std.testing.expectEqual(0, n2);
}
