//! Pure-Zig incremental checksum API (PR1 of issue #34).
//!
//! This module exposes a small C ABI over std.crypto so later PRs can
//! swap C-side checksum verification away from OpenSSL without
//! changing the existing `TDNF_HASH_*` call sites first.

const std = @import("std");

pub const TDNF_RPMZIG_MAX_DIGEST_LEN: usize = 64;

const TDNF_HASH_MD5: c_int = 0;
const TDNF_HASH_SHA1: c_int = 1;
const TDNF_HASH_SHA256: c_int = 2;
const TDNF_HASH_SHA512: c_int = 3;

const MD5_DIGEST_LEN: usize = 16;
const SHA1_DIGEST_LEN: usize = 20;
const SHA256_DIGEST_LEN: usize = 32;
const SHA512_DIGEST_LEN: usize = 64;

threadlocal var last_error_buf: [256]u8 = undefined;
threadlocal var last_error_len: usize = 0;

const DigestState = union(enum) {
    md5: std.crypto.hash.Md5,
    sha1: std.crypto.hash.Sha1,
    sha256: std.crypto.hash.sha2.Sha256,
    sha512: std.crypto.hash.sha2.Sha512,
    finalized: void,
};

pub const DigestCtx = struct {
    state: DigestState,
};

fn setError(comptime fmt: []const u8, args: anytype) void {
    const slice = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
        const fallback = "(error message truncated)";
        @memcpy(last_error_buf[0..fallback.len], fallback);
        break :blk last_error_buf[0..fallback.len];
    };
    last_error_len = slice.len;
}

fn clearError() void {
    last_error_len = 0;
}

fn digestLenForState(state: DigestState) usize {
    return switch (state) {
        .md5 => MD5_DIGEST_LEN,
        .sha1 => SHA1_DIGEST_LEN,
        .sha256 => SHA256_DIGEST_LEN,
        .sha512 => SHA512_DIGEST_LEN,
        .finalized => 0,
    };
}

fn digestStateForKind(kind: c_int) ?DigestState {
    return switch (kind) {
        TDNF_HASH_MD5 => .{ .md5 = std.crypto.hash.Md5.init(.{}) },
        TDNF_HASH_SHA1 => .{ .sha1 = std.crypto.hash.Sha1.init(.{}) },
        TDNF_HASH_SHA256 => .{ .sha256 = std.crypto.hash.sha2.Sha256.init(.{}) },
        TDNF_HASH_SHA512 => .{ .sha512 = std.crypto.hash.sha2.Sha512.init(.{}) },
        else => null,
    };
}

fn requireActiveCtx(ctx: ?*DigestCtx) ?*DigestCtx {
    const digest = ctx orelse {
        setError("null digest context", .{});
        return null;
    };
    switch (digest.state) {
        .finalized => {
            setError("digest already finalized", .{});
            return null;
        },
        else => {},
    }
    return digest;
}

pub export fn tdnf_rpmzig_digest_open(kind: c_int) ?*DigestCtx {
    clearError();
    const state = digestStateForKind(kind) orelse {
        setError("unsupported digest kind: {d}", .{kind});
        return null;
    };

    const ctx = std.heap.c_allocator.create(DigestCtx) catch {
        setError("out of memory", .{});
        return null;
    };
    ctx.* = .{ .state = state };
    return ctx;
}

pub export fn tdnf_rpmzig_digest_update(
    ctx: ?*DigestCtx,
    buf: ?[*]const u8,
    len: usize,
) c_int {
    clearError();
    const digest = requireActiveCtx(ctx) orelse return -1;
    if (len == 0) return 0;

    const data_ptr = buf orelse {
        setError("null digest buffer", .{});
        return -1;
    };
    const data = data_ptr[0..len];

    switch (digest.state) {
        .md5 => |*h| h.update(data),
        .sha1 => |*h| h.update(data),
        .sha256 => |*h| h.update(data),
        .sha512 => |*h| h.update(data),
        .finalized => unreachable,
    }
    return 0;
}

pub export fn tdnf_rpmzig_digest_final(
    ctx: ?*DigestCtx,
    out_digest: ?[*]u8,
    out_len: usize,
) c_int {
    clearError();
    const digest = requireActiveCtx(ctx) orelse return -1;
    const out_ptr = out_digest orelse {
        setError("null output buffer", .{});
        return -1;
    };

    const needed = digestLenForState(digest.state);
    if (out_len < needed) {
        setError("output buffer too small: got {d}, need at least {d}", .{ out_len, needed });
        return -1;
    }

    switch (digest.state) {
        .md5 => |*h| h.final(out_ptr[0..MD5_DIGEST_LEN]),
        .sha1 => |*h| h.final(out_ptr[0..SHA1_DIGEST_LEN]),
        .sha256 => |*h| h.final(out_ptr[0..SHA256_DIGEST_LEN]),
        .sha512 => |*h| h.final(out_ptr[0..SHA512_DIGEST_LEN]),
        .finalized => unreachable,
    }
    digest.state = .{ .finalized = {} };
    return 0;
}

pub export fn tdnf_rpmzig_digest_close(ctx: ?*DigestCtx) void {
    const digest = ctx orelse return;
    std.heap.c_allocator.destroy(digest);
}

export fn tdnf_rpmzig_checksum_last_error() [*:0]const u8 {
    if (last_error_len >= last_error_buf.len) last_error_len = last_error_buf.len - 1;
    last_error_buf[last_error_len] = 0;
    return @ptrCast(&last_error_buf);
}

fn encodeHexLower(buf: []u8, bytes: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    std.debug.assert(buf.len >= bytes.len * 2);

    for (bytes, 0..) |byte, i| {
        buf[i * 2] = digits[byte >> 4];
        buf[i * 2 + 1] = digits[byte & 0x0F];
    }
    return buf[0 .. bytes.len * 2];
}

fn expectDigest(kind: c_int, chunks: []const []const u8, expected_hex: []const u8) !void {
    const testing = std.testing;

    const ctx = tdnf_rpmzig_digest_open(kind) orelse {
        std.debug.print("open failed: {s}\n", .{std.mem.span(tdnf_rpmzig_checksum_last_error())});
        return error.TestUnexpectedNull;
    };
    defer tdnf_rpmzig_digest_close(ctx);

    for (chunks) |chunk| {
        try testing.expectEqual(@as(c_int, 0), tdnf_rpmzig_digest_update(ctx, chunk.ptr, chunk.len));
    }

    var digest: [TDNF_RPMZIG_MAX_DIGEST_LEN]u8 = undefined;
    try testing.expectEqual(@as(c_int, 0), tdnf_rpmzig_digest_final(ctx, digest[0..].ptr, digest.len));

    var actual_hex_buf: [TDNF_RPMZIG_MAX_DIGEST_LEN * 2]u8 = undefined;
    const actual_hex = encodeHexLower(&actual_hex_buf, digest[0 .. expected_hex.len / 2]);
    try testing.expectEqualStrings(expected_hex, actual_hex);
}

test "MD5 vectors" {
    try expectDigest(TDNF_HASH_MD5, &.{}, "d41d8cd98f00b204e9800998ecf8427e");
    try expectDigest(TDNF_HASH_MD5, &.{ "a", "bc" }, "900150983cd24fb0d6963f7d28e17f72");
}

test "SHA1 vectors" {
    try expectDigest(TDNF_HASH_SHA1, &.{}, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    try expectDigest(TDNF_HASH_SHA1, &.{ "a", "bc" }, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

test "SHA256 vectors" {
    try expectDigest(TDNF_HASH_SHA256, &.{}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    try expectDigest(TDNF_HASH_SHA256, &.{ "a", "bc" }, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

test "SHA512 vectors" {
    try expectDigest(
        TDNF_HASH_SHA512,
        &.{},
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" ++
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    );
    try expectDigest(
        TDNF_HASH_SHA512,
        &.{ "a", "bc" },
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
}

test "unsupported digest kind reports last error" {
    const testing = std.testing;

    try testing.expect(tdnf_rpmzig_digest_open(99) == null);
    try testing.expectEqualStrings(
        "unsupported digest kind: 99",
        std.mem.span(tdnf_rpmzig_checksum_last_error()),
    );
}

test "final rejects short output buffer" {
    const testing = std.testing;

    const ctx = tdnf_rpmzig_digest_open(TDNF_HASH_SHA512) orelse return error.TestUnexpectedNull;
    defer tdnf_rpmzig_digest_close(ctx);

    var digest: [SHA512_DIGEST_LEN - 1]u8 = undefined;
    try testing.expectEqual(@as(c_int, -1), tdnf_rpmzig_digest_final(ctx, digest[0..].ptr, digest.len));
    try testing.expectEqualStrings(
        "output buffer too small: got 63, need at least 64",
        std.mem.span(tdnf_rpmzig_checksum_last_error()),
    );
}
