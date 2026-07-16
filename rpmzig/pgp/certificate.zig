//! Transferable OpenPGP public-key certificate splitting and metadata.
//!
//! A binary stream can contain multiple certificates. A Tag 6 primary
//! public-key packet starts each certificate; following user IDs,
//! signatures, and Tag 14 subkeys belong to it until the next Tag 6.
//! Armor decoding, packet framing, and every primary/subkey version are
//! validated before a collection is returned.

const std = @import("std");
const armor = @import("armor.zig");
const packet = @import("packet.zig");
const pubkey = @import("pubkey.zig");

pub const KeyIdentity = struct {
    fingerprint: pubkey.Fingerprint,
    key_id: [8]u8,
    created_at: u32,
    version: u8,
};

pub const Certificate = struct {
    /// Complete binary transferable certificate, including packet headers.
    bytes: []const u8,
    primary: KeyIdentity,
    /// First Tag 13 User ID, if present.
    first_user_id: ?[]const u8,
    subkeys: []KeyIdentity,
};

pub const Collection = struct {
    allocator: std.mem.Allocator,
    /// Dearmored backing storage for every slice in `certificates`.
    blob: []u8,
    certificates: []Certificate,

    pub fn deinit(self: *Collection) void {
        for (self.certificates) |cert| self.allocator.free(cert.subkeys);
        self.allocator.free(self.certificates);
        self.allocator.free(self.blob);
        self.certificates = &.{};
        self.blob = &.{};
    }
};

pub const ParseError = error{
    EmptyInput,
    PrimaryNotFirst,
    MalformedPacket,
    MalformedKey,
    UnsupportedKeyVersion,
    InvalidUserId,
} || armor.ArmorError || std.mem.Allocator.Error;

const Pending = struct {
    start: usize,
    primary: KeyIdentity,
    first_user_id: ?[]const u8 = null,
};

/// Parse armored or binary input and split all transferable certificates.
pub fn parseAll(
    allocator: std.mem.Allocator,
    input: []const u8,
) ParseError!Collection {
    if (input.len == 0) return error.EmptyInput;

    if (armor.looksLikeArmor(input)) {
        return parseArmored(allocator, input);
    }
    const decoded = try armor.decodeAny(allocator, input);
    return parseDecoded(allocator, decoded.bytes);
}

fn parseArmored(
    allocator: std.mem.Allocator,
    input: []const u8,
) ParseError!Collection {
    var blocks = try armor.decodeBlocks(allocator, input);
    defer blocks.deinit();

    var blob = std.array_list.Managed(u8).init(allocator);
    errdefer blob.deinit();
    for (blocks.blocks) |block| try blob.appendSlice(block.bytes);

    return parseDecodedWithBoundaries(
        allocator,
        try blob.toOwnedSlice(),
        blocks.blocks,
    );
}

fn parseDecoded(
    allocator: std.mem.Allocator,
    decoded: []u8,
) ParseError!Collection {
    return parseDecodedWithBoundaries(allocator, decoded, &.{});
}

fn parseDecodedWithBoundaries(
    allocator: std.mem.Allocator,
    decoded: []u8,
    blocks: []const armor.DecodedKey,
) ParseError!Collection {
    errdefer allocator.free(decoded);
    var certificates = std.array_list.Managed(Certificate).init(allocator);
    errdefer {
        for (certificates.items) |cert| allocator.free(cert.subkeys);
        certificates.deinit();
    }

    if (blocks.len == 0) {
        try parsePacketStream(
            allocator,
            &certificates,
            decoded,
            0,
            decoded.len,
        );
    } else {
        var start: usize = 0;
        for (blocks) |block| {
            const end = start + block.bytes.len;
            // Each ASCII armor block is a standalone transferable-key
            // stream. Parsing it separately prevents a later block that
            // starts with a User ID or subkey from being absorbed by the
            // previous primary certificate.
            try parsePacketStream(
                allocator,
                &certificates,
                decoded,
                start,
                end,
            );
            start = end;
        }
    }

    return .{
        .allocator = allocator,
        .blob = decoded,
        .certificates = try certificates.toOwnedSlice(),
    };
}

fn parsePacketStream(
    allocator: std.mem.Allocator,
    certificates: *std.array_list.Managed(Certificate),
    blob: []u8,
    start: usize,
    end: usize,
) ParseError!void {
    var subkeys = std.array_list.Managed(KeyIdentity).init(allocator);
    defer subkeys.deinit();

    var pending: ?Pending = null;
    var it = packet.iterate(blob[start..end]);
    while (it.next() catch return error.MalformedPacket) |pkt| {
        const packet_start =
            start + @intFromPtr(pkt.raw.ptr) - @intFromPtr(blob[start..].ptr);
        switch (pkt.tag) {
            .public_key => {
                if (pending) |current| {
                    try appendCertificate(
                        allocator,
                        certificates,
                        &subkeys,
                        blob,
                        current,
                        packet_start,
                    );
                } else if (packet_start != start) {
                    return error.PrimaryNotFirst;
                }
                const key = try parseKey(pkt.body);
                pending = .{
                    .start = packet_start,
                    .primary = identity(key),
                };
            },
            .public_subkey => {
                if (pending == null) return error.PrimaryNotFirst;
                const key = try parseKey(pkt.body);
                try subkeys.append(identity(key));
            },
            .user_id => {
                if (pending == null) return error.PrimaryNotFirst;
                if (std.mem.indexOfScalar(u8, pkt.body, 0) != null)
                    return error.InvalidUserId;
                if (pending.?.first_user_id == null) {
                    pending.?.first_user_id = pkt.body;
                }
            },
            else => {
                if (pending == null) return error.PrimaryNotFirst;
            },
        }
    }

    const current = pending orelse return error.EmptyInput;
    try appendCertificate(
        allocator,
        certificates,
        &subkeys,
        blob,
        current,
        end,
    );
}

fn parseKey(body: []const u8) ParseError!pubkey.PublicKey {
    return pubkey.parseBodyStrict(body) catch |err| switch (err) {
        error.UnsupportedVersion => error.UnsupportedKeyVersion,
        else => error.MalformedKey,
    };
}

fn identity(key: pubkey.PublicKey) KeyIdentity {
    const fingerprint = pubkey.fingerprint(key);
    return .{
        .fingerprint = fingerprint,
        .key_id = fingerprint.keyId(),
        .created_at = key.created_at,
        .version = key.version,
    };
}

fn appendCertificate(
    allocator: std.mem.Allocator,
    certificates: *std.array_list.Managed(Certificate),
    subkeys: *std.array_list.Managed(KeyIdentity),
    blob: []const u8,
    pending: Pending,
    end: usize,
) ParseError!void {
    if (end <= pending.start) return error.MalformedPacket;
    const owned_subkeys = try subkeys.toOwnedSlice();
    errdefer allocator.free(owned_subkeys);
    try certificates.append(.{
        .bytes = blob[pending.start..end],
        .primary = pending.primary,
        .first_user_id = pending.first_user_id,
        .subkeys = owned_subkeys,
    });
}

const testing = std.testing;
const microsoft_armored = @embedFile("testdata/microsoft-rpm-key.asc");
const microsoft_binary = @embedFile("testdata/microsoft-rpm-key.bin");
const subkey_binary = @embedFile("testdata/rsa-primary-subkey-keyring.bin");

test "certificate parser exposes primary metadata and first user ID" {
    var parsed = try parseAll(testing.allocator, microsoft_armored);
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.certificates.len);
    const cert = parsed.certificates[0];
    try testing.expectEqual(@as(u8, 4), cert.primary.version);
    try testing.expectEqual(@as(u32, 0x5e6fda74), cert.primary.created_at);
    try testing.expectEqualStrings(
        "Mariner RPM Release Signing <marinerrpmprod@microsoft.com>",
        cert.first_user_id.?,
    );
    try testing.expectEqualSlices(u8, microsoft_binary, cert.bytes);
}

test "certificate parser splits concatenated binary certificates" {
    var input = std.array_list.Managed(u8).init(testing.allocator);
    defer input.deinit();
    try input.appendSlice(microsoft_binary);
    try input.appendSlice(microsoft_binary);

    var parsed = try parseAll(testing.allocator, input.items);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 2), parsed.certificates.len);
    try testing.expectEqualSlices(u8, microsoft_binary, parsed.certificates[0].bytes);
    try testing.expectEqualSlices(u8, microsoft_binary, parsed.certificates[1].bytes);
}

test "certificate parser exposes subkeys" {
    var parsed = try parseAll(testing.allocator, subkey_binary);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 1), parsed.certificates.len);
    try testing.expectEqual(@as(usize, 1), parsed.certificates[0].subkeys.len);
    try testing.expectEqual(@as(u8, 4), parsed.certificates[0].subkeys[0].version);
}

test "certificate parser rejects unsupported primary and subkey versions" {
    const bad_primary = [_]u8{ 0x98, 0x06, 0x03, 0, 0, 0, 0, 1 };
    try testing.expectError(
        error.UnsupportedKeyVersion,
        parseAll(testing.allocator, &bad_primary),
    );

    var bad_subkey = try testing.allocator.dupe(u8, subkey_binary);
    defer testing.allocator.free(bad_subkey);
    var it = packet.iterate(bad_subkey);
    _ = (try it.next()).?;
    const sub = (try it.next()).?;
    const sub_body_offset =
        @intFromPtr(sub.body.ptr) - @intFromPtr(bad_subkey.ptr);
    bad_subkey[sub_body_offset] = 3;
    try testing.expectError(
        error.UnsupportedKeyVersion,
        parseAll(testing.allocator, bad_subkey),
    );
}

test "certificate import parser rejects malformed primary and subkey material" {
    var key_body: [1 + 4 + 1 + 32]u8 = undefined;
    key_body[0] = 4;
    @memset(key_body[1..5], 0);
    key_body[5] = @intFromEnum(pubkey.Algorithm.ed25519);
    @memset(key_body[6..], 0xA5);

    var bad_primary: [2 + key_body.len + 1]u8 = undefined;
    bad_primary[0] = 0x98;
    bad_primary[1] = key_body.len + 1;
    @memcpy(bad_primary[2 .. 2 + key_body.len], &key_body);
    bad_primary[bad_primary.len - 1] = 0;
    try testing.expectError(
        error.MalformedKey,
        parseAll(testing.allocator, &bad_primary),
    );

    var bad_subkey: [2 + key_body.len + 2 + key_body.len + 1]u8 = undefined;
    bad_subkey[0] = 0x98;
    bad_subkey[1] = key_body.len;
    @memcpy(bad_subkey[2 .. 2 + key_body.len], &key_body);
    const subkey_start = 2 + key_body.len;
    bad_subkey[subkey_start] = 0xB8;
    bad_subkey[subkey_start + 1] = key_body.len + 1;
    @memcpy(
        bad_subkey[subkey_start + 2 .. subkey_start + 2 + key_body.len],
        &key_body,
    );
    bad_subkey[bad_subkey.len - 1] = 0;
    try testing.expectError(
        error.MalformedKey,
        parseAll(testing.allocator, &bad_subkey),
    );
}
