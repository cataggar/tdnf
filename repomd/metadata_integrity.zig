const std = @import("std");
const model = @import("model.zig");

pub fn digestMatches(checksum: model.Checksum, bytes: []const u8) bool {
    const checksum_type = model.spanZ(checksum.pszType) orelse return false;
    const expected = model.spanZ(checksum.pszValue) orelse return false;
    return switch (hashKind(checksum_type) orelse return false) {
        .md5 => blk: {
            var digest: [16]u8 = undefined;
            var hasher = std.crypto.hash.Md5.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
        .sha1 => blk: {
            var digest: [20]u8 = undefined;
            var hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
        .sha256 => blk: {
            var digest: [32]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
        .sha384 => blk: {
            var digest: [48]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha384.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
        .sha512 => blk: {
            var digest: [64]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha512.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
    };
}

const HashKind = enum {
    md5,
    sha1,
    sha256,
    sha384,
    sha512,
};

fn hashKind(raw: []const u8) ?HashKind {
    if (std.ascii.eqlIgnoreCase(raw, "md5")) return .md5;
    if (std.ascii.eqlIgnoreCase(raw, "sha1")) return .sha1;
    if (std.ascii.eqlIgnoreCase(raw, "sha256")) return .sha256;
    if (std.ascii.eqlIgnoreCase(raw, "sha384")) return .sha384;
    if (std.ascii.eqlIgnoreCase(raw, "sha512")) return .sha512;
    return null;
}
