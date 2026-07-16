//! OpenPGP packet framing + MPI reader.
//!
//! Phase A, PR #2 of the pure-Zig PGP verifier plan
//! (plan-pure-zig-pgp.md, section 5). Operates on already-binary
//! packet bytes — ASCII armor stripping lives in `armor.zig` (PR #1).
//!
//! Implements both packet header formats (RFC 4880 §4.2):
//!
//!   Old-format header byte:  1 0 t t t t L L
//!     4-bit tag, 2-bit length type.
//!     LL=0 → 1-octet body length
//!     LL=1 → 2-octet body length (big-endian)
//!     LL=2 → 4-octet body length (big-endian)
//!     LL=3 → indeterminate length (rejected — not seen in
//!            pubkey/signature packets)
//!
//!   New-format header byte:  1 1 t t t t t t
//!     6-bit tag. Length octets that follow:
//!     b1 < 192            → 1-octet length = b1
//!     192 ≤ b1 < 224      → 2-octet length = ((b1 - 192) << 8) + b2 + 192
//!     b1 == 255           → 5-octet length = BE32(b2..b5)
//!     224 ≤ b1 < 255      → partial body length (rejected — never seen
//!                           in pubkey/signature packets either)
//!
//! MPI (RFC 4880 §3.2): 2-octet big-endian bit count followed by
//! `ceil(bits / 8)` payload bytes. Leading zero bytes are stripped
//! before being handed up to bigint code.

const std = @import("std");

pub const Tag = enum(u6) {
    signature = 2,
    public_key = 6,
    user_id = 13,
    public_subkey = 14,
    _,
};

pub const Packet = struct {
    /// Aliases into the iterator's input slice.
    tag: Tag,
    body: []const u8,
    /// Complete packet, including its old- or new-format header.
    /// This lets higher-level parsers preserve certificate framing.
    raw: []const u8,
};

pub const HeaderError = error{
    TruncatedHeader,
    TruncatedBody,
    PartialLengthUnsupported,
    IndeterminateLengthUnsupported,
    MalformedHeader,
};

pub const PacketIterator = struct {
    rest: []const u8,

    pub fn next(self: *PacketIterator) HeaderError!?Packet {
        if (self.rest.len == 0) return null;
        const first = self.rest[0];
        // Every packet header starts with the high bit set.
        if ((first & 0x80) == 0) return error.MalformedHeader;
        if ((first & 0x40) != 0) {
            return try self.parseNewFormat();
        } else {
            return try self.parseOldFormat();
        }
    }

    fn parseNewFormat(self: *PacketIterator) HeaderError!Packet {
        const packet_start = self.rest;
        const first = self.rest[0];
        const tag: Tag = @enumFromInt(@as(u6, @truncate(first & 0x3F)));

        if (self.rest.len < 2) return error.TruncatedHeader;
        const b1 = self.rest[1];

        var body_len: usize = undefined;
        var header_len: usize = undefined;

        if (b1 < 192) {
            body_len = b1;
            header_len = 2;
        } else if (b1 < 224) {
            if (self.rest.len < 3) return error.TruncatedHeader;
            const b2 = self.rest[2];
            body_len = (@as(usize, b1 - 192) << 8) + @as(usize, b2) + 192;
            header_len = 3;
        } else if (b1 < 255) {
            return error.PartialLengthUnsupported;
        } else {
            if (self.rest.len < 6) return error.TruncatedHeader;
            body_len = (@as(usize, self.rest[2]) << 24) |
                (@as(usize, self.rest[3]) << 16) |
                (@as(usize, self.rest[4]) << 8) |
                @as(usize, self.rest[5]);
            header_len = 6;
        }

        if (self.rest.len - header_len < body_len) return error.TruncatedBody;
        const body = self.rest[header_len .. header_len + body_len];
        self.rest = self.rest[header_len + body_len ..];
        return Packet{
            .tag = tag,
            .body = body,
            .raw = packet_start[0 .. header_len + body_len],
        };
    }

    fn parseOldFormat(self: *PacketIterator) HeaderError!Packet {
        const packet_start = self.rest;
        const first = self.rest[0];
        const tag: Tag = @enumFromInt(@as(u6, @truncate((first >> 2) & 0x0F)));
        const len_type: u2 = @truncate(first & 0x03);

        var body_len: usize = undefined;
        var header_len: usize = undefined;
        switch (len_type) {
            0 => {
                if (self.rest.len < 2) return error.TruncatedHeader;
                body_len = self.rest[1];
                header_len = 2;
            },
            1 => {
                if (self.rest.len < 3) return error.TruncatedHeader;
                body_len = (@as(usize, self.rest[1]) << 8) | @as(usize, self.rest[2]);
                header_len = 3;
            },
            2 => {
                if (self.rest.len < 5) return error.TruncatedHeader;
                body_len = (@as(usize, self.rest[1]) << 24) |
                    (@as(usize, self.rest[2]) << 16) |
                    (@as(usize, self.rest[3]) << 8) |
                    @as(usize, self.rest[4]);
                header_len = 5;
            },
            3 => return error.IndeterminateLengthUnsupported,
        }

        if (self.rest.len - header_len < body_len) return error.TruncatedBody;
        const body = self.rest[header_len .. header_len + body_len];
        self.rest = self.rest[header_len + body_len ..];
        return Packet{
            .tag = tag,
            .body = body,
            .raw = packet_start[0 .. header_len + body_len],
        };
    }
};

pub fn iterate(bytes: []const u8) PacketIterator {
    return .{ .rest = bytes };
}

/// Cap on MPI payload size. 1024 bytes = 8192 bits, larger than any
/// RSA-4096 modulus or signature. Anything bigger is rejected as
/// malformed input.
pub const MAX_MPI_BYTES: usize = 1024;

pub const Mpi = struct {
    /// Declared bit length (the 2-octet header value, verbatim).
    bit_length: u16,
    /// Payload bytes with leading zero bytes stripped. Empty slice for
    /// a zero MPI.
    bytes: []const u8,
};

pub const ReaderError = error{Truncated};

pub const MpiError = error{
    TruncatedMpi,
    MpiTooLarge,
};

/// Minimal stateful cursor over a const `[]u8`.
pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn rest(self: Reader) []const u8 {
        return self.bytes[self.pos..];
    }

    pub fn take(self: *Reader, n: usize) ReaderError![]const u8 {
        if (self.bytes.len - self.pos < n) return error.Truncated;
        const s = self.bytes[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    pub fn readU8(self: *Reader) ReaderError!u8 {
        const s = try self.take(1);
        return s[0];
    }

    pub fn readU16Be(self: *Reader) ReaderError!u16 {
        const s = try self.take(2);
        return (@as(u16, s[0]) << 8) | @as(u16, s[1]);
    }

    pub fn readU32Be(self: *Reader) ReaderError!u32 {
        const s = try self.take(4);
        return (@as(u32, s[0]) << 24) |
            (@as(u32, s[1]) << 16) |
            (@as(u32, s[2]) << 8) |
            @as(u32, s[3]);
    }
};

/// Read an OpenPGP MPI: BE16 bit count followed by ceil(bits/8) bytes.
/// Leading zero bytes are stripped from the payload.
///
/// RFC 4880 §3.2 states the bit count must reflect the position of the
/// most significant `1` bit (so a producer should never emit a leading
/// zero byte). We are lenient: if leading zero bytes are present we
/// silently strip them rather than rejecting. Strict validation is
/// the verifier's job, not the framing layer's.
pub fn readMpi(reader: *Reader) MpiError!Mpi {
    const bit_length = reader.readU16Be() catch return error.TruncatedMpi;
    const byte_count: usize = (@as(usize, bit_length) + 7) / 8;
    if (byte_count > MAX_MPI_BYTES) return error.MpiTooLarge;
    const payload = reader.take(byte_count) catch return error.TruncatedMpi;

    var i: usize = 0;
    while (i < payload.len and payload[i] == 0) : (i += 1) {}
    return Mpi{ .bit_length = bit_length, .bytes = payload[i..] };
}

pub fn isCanonicalMpi(mpi: Mpi) bool {
    if (mpi.bit_length == 0) return mpi.bytes.len == 0;
    const expected_len = (@as(usize, mpi.bit_length) + 7) / 8;
    if (mpi.bytes.len != expected_len or mpi.bytes[0] == 0) return false;
    const leading_bits: usize = 8 - @clz(mpi.bytes[0]);
    const actual_bits = (mpi.bytes.len - 1) * 8 + leading_bits;
    return actual_bits == mpi.bit_length;
}

// ===== Tests =====

const testing = std.testing;

test "old-format header, 1-octet length" {
    const data = [_]u8{ 0x98, 0x04, 0xAA, 0xBB, 0xCC, 0xDD };
    var it = iterate(&data);
    const pkt = (try it.next()).?;
    try testing.expectEqual(Tag.public_key, pkt.tag);
    try testing.expectEqual(@as(usize, 4), pkt.body.len);
    try testing.expect((try it.next()) == null);
}

test "old-format header, 2-octet length" {
    var data: [3 + 256]u8 = undefined;
    data[0] = 0x99;
    data[1] = 0x01;
    data[2] = 0x00;
    @memset(data[3..], 0xAA);
    var it = iterate(&data);
    const pkt = (try it.next()).?;
    try testing.expectEqual(Tag.public_key, pkt.tag);
    try testing.expectEqual(@as(usize, 256), pkt.body.len);
}

test "old-format header, 4-octet length" {
    var data: [5 + 4096]u8 = undefined;
    data[0] = 0x9A;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x10;
    data[4] = 0x00;
    @memset(data[5..], 0xAA);
    var it = iterate(&data);
    const pkt = (try it.next()).?;
    try testing.expectEqual(Tag.public_key, pkt.tag);
    try testing.expectEqual(@as(usize, 4096), pkt.body.len);
}

test "new-format header, 1-octet length" {
    const data = [_]u8{ 0xC6, 0x04, 0xAA, 0xBB, 0xCC, 0xDD };
    var it = iterate(&data);
    const pkt = (try it.next()).?;
    try testing.expectEqual(Tag.public_key, pkt.tag);
    try testing.expectEqual(@as(usize, 4), pkt.body.len);
}

test "new-format header, 2-octet length" {
    var data: [3 + 192]u8 = undefined;
    data[0] = 0xC6;
    data[1] = 0xC0;
    data[2] = 0x00;
    @memset(data[3..], 0xAA);
    var it = iterate(&data);
    const pkt = (try it.next()).?;
    try testing.expectEqual(Tag.public_key, pkt.tag);
    try testing.expectEqual(@as(usize, 192), pkt.body.len);
}

test "new-format header, 5-octet length" {
    var data: [6 + 4096]u8 = undefined;
    data[0] = 0xC6;
    data[1] = 0xFF;
    data[2] = 0x00;
    data[3] = 0x00;
    data[4] = 0x10;
    data[5] = 0x00;
    @memset(data[6..], 0xAA);
    var it = iterate(&data);
    const pkt = (try it.next()).?;
    try testing.expectEqual(Tag.public_key, pkt.tag);
    try testing.expectEqual(@as(usize, 4096), pkt.body.len);
}

test "multiple packets" {
    const data = [_]u8{ 0x98, 0x02, 0xAA, 0xBB, 0x98, 0x03, 0xCC, 0xDD, 0xEE };
    var it = iterate(&data);
    const p1 = (try it.next()).?;
    try testing.expectEqual(Tag.public_key, p1.tag);
    try testing.expectEqual(@as(usize, 2), p1.body.len);
    const p2 = (try it.next()).?;
    try testing.expectEqual(Tag.public_key, p2.tag);
    try testing.expectEqual(@as(usize, 3), p2.body.len);
    try testing.expect((try it.next()) == null);
}

test "partial length is rejected" {
    const data = [_]u8{ 0xC6, 0xE1, 0x00, 0x00 };
    var it = iterate(&data);
    try testing.expectError(error.PartialLengthUnsupported, it.next());
}

test "indeterminate length is rejected" {
    const data = [_]u8{ 0x9B, 0x00, 0x00, 0x00 };
    var it = iterate(&data);
    try testing.expectError(error.IndeterminateLengthUnsupported, it.next());
}

test "MPI read - single byte" {
    const data = [_]u8{ 0x00, 0x05, 0x13 };
    var r = Reader{ .bytes = &data };
    const mpi = try readMpi(&r);
    try testing.expectEqual(@as(u16, 5), mpi.bit_length);
    try testing.expectEqualSlices(u8, &[_]u8{0x13}, mpi.bytes);
}

test "MPI read - leading zero strip (lenient)" {
    const data = [_]u8{ 0x00, 0x10, 0x00, 0xFF };
    var r = Reader{ .bytes = &data };
    const mpi = try readMpi(&r);
    try testing.expectEqual(@as(u16, 16), mpi.bit_length);
    try testing.expectEqualSlices(u8, &[_]u8{0xFF}, mpi.bytes);
}

test "MPI read - exact-fit RSA-2048 modulus" {
    var data: [2 + 256]u8 = undefined;
    data[0] = 0x08;
    data[1] = 0x00;
    data[2] = 0x80;
    @memset(data[3..], 0xAA);
    var r = Reader{ .bytes = &data };
    const mpi = try readMpi(&r);
    try testing.expectEqual(@as(u16, 2048), mpi.bit_length);
    try testing.expectEqual(@as(usize, 256), mpi.bytes.len);
    try testing.expectEqual(@as(u8, 0x80), mpi.bytes[0]);
}

test "MPI rejects oversize" {
    // 65535 bits → 8192 payload bytes, exceeds MAX_MPI_BYTES (1024).
    const data = [_]u8{ 0xFF, 0xFF };
    var r = Reader{ .bytes = &data };
    try testing.expectError(error.MpiTooLarge, readMpi(&r));
}

test "MPI truncated payload" {
    const data = [_]u8{ 0x00, 0x10, 0xFF };
    var r = Reader{ .bytes = &data };
    try testing.expectError(error.TruncatedMpi, readMpi(&r));
}
