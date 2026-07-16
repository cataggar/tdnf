//! OpenPGP Tag 2 (Signature) packet parser — versions 4 and 6.
//!
//! Phase B, PR #4 of the pure-Zig PGP verifier plan
//! (plan-pure-zig-pgp.md, section 5). Builds on the packet-framing
//! and MPI reader from `packet.zig` (PR #2).
//!
//! Wire format (RFC 4880 §5.2.3 / RFC 9580 §5.2.3):
//!
//!   1 octet  version = 0x04
//!   1 octet  signature type
//!   1 octet  pk algorithm ID
//!   1 octet  hash algorithm ID
//!   2 (v4) or 4 (v6) octets hashed-subpacket length (N)
//!   N octets hashed subpackets
//!   2 (v4) or 4 (v6) octets unhashed-subpacket length (M)
//!   M octets unhashed subpackets
//!   2 octets hash hint (first two octets of computed hash)
//!   [v6 only: 1-octet salt length followed by the salt]
//!   [signature material — algorithm-specific]
//!
//! For verification PR #5 needs the exact byte range from the
//! version byte through the end of the hashed-subpacket data, which
//! we expose as `Signature.hashed_prefix` — this is what feeds into
//! the hash trailer `version || 0xFF || BE32(hashed_prefix.len)`.
//!
//! Subpacket framing (RFC 4880 §5.2.3.1): length is encoded the same
//! way as a new-format packet body length (1/2/5 octets). The length
//! includes the 1-octet type byte; type body is `length - 1` octets.
//! High bit of the type byte is the critical flag — unknown critical
//! types MUST fail the signature; unknown non-criticals are silently
//! skipped.

const std = @import("std");
const packet = @import("packet.zig");

/// Signature types we recognise (RFC 4880 §5.2.1).
pub const SigType = enum(u8) {
    binary_document = 0x00,
    text_document = 0x01,
    standalone = 0x02,
    generic_certify = 0x10,
    persona_certify = 0x11,
    casual_certify = 0x12,
    positive_certify = 0x13,
    subkey_binding = 0x18,
    primary_key_binding = 0x19,
    direct_key = 0x1F,
    key_revocation = 0x20,
    subkey_revocation = 0x28,
    certification_revocation = 0x30,
    timestamp = 0x40,
    third_party_confirmation = 0x50,
    _,
};

/// Public-key algorithm IDs (RFC 4880 §9.1 / RFC 9580 §9.1). Kept
/// in sync with the equivalent enum in `pubkey.zig` when that lands;
/// for now intentionally duplicated — PR #5 will consolidate.
pub const PkAlgorithm = enum(u8) {
    rsa_sign_and_encrypt = 1,
    rsa_sign_only = 3,
    dsa = 17,
    ecdsa = 19,
    eddsa_legacy = 22,
    ed25519 = 27,
    _,
};

/// Hash algorithm IDs (RFC 4880 §9.4 / RFC 9580 §9.5).
pub const HashAlgorithm = enum(u8) {
    sha1 = 2,
    sha256 = 8,
    sha384 = 9,
    sha512 = 10,
    sha224 = 11,
    sha3_256 = 12,
    sha3_512 = 14,
    _,
};

/// Algorithm-specific signature material decoded after the hash hint.
pub const SigMaterial = union(enum) {
    rsa: packet.Mpi,
    dsa: struct { r: packet.Mpi, s: packet.Mpi },
    ecdsa: struct { r: packet.Mpi, s: packet.Mpi },
    eddsa_legacy: struct { r: packet.Mpi, s: packet.Mpi },
    ed25519: [64]u8,
    unsupported: PkAlgorithm,
};

pub const SignatureParseError = error{
    UnsupportedVersion,
    TruncatedPacket,
    UnknownCriticalSubpacket,
    MalformedSubpacket,
    MalformedSalt,
    MalformedSignatureMaterial,
} || packet.ReaderError || packet.MpiError;

pub const Signature = struct {
    /// Version 4 or 6.
    version: u8,
    sig_type: SigType,
    pk_algo: PkAlgorithm,
    hash_algo: HashAlgorithm,
    /// Byte range from the version byte (inclusive) through the end
    /// of the hashed-subpacket data (exclusive of the unhashed-length
    /// field). Length is `6 + hashed_subpackets.len`. PR #5 builds
    /// the hash trailer `0x04 || 0xFF || BE32(hashed_prefix.len)`
    /// from this.
    hashed_prefix: []const u8,
    hashed_subpackets: []const u8,
    unhashed_subpackets: []const u8,
    hash_hint: [2]u8,
    /// Empty for v4. For v6 this aliases the packet body and has the
    /// algorithm-defined length from RFC 9580 Table 23.
    salt: []const u8,
    material: SigMaterial,

    /// Find an Issuer Fingerprint subpacket (type 33), preferring the
    /// hashed area and falling back to the unhashed area. Returns the
    /// fingerprint payload with its key-version octet stripped.
    pub fn issuerFingerprint(self: Signature) ?[]const u8 {
        const issuer = self.issuerFingerprintInfo() orelse return null;
        return issuer.bytes;
    }

    pub const IssuerFingerprint = struct {
        key_version: u8,
        bytes: []const u8,
    };

    /// Issuer Fingerprint subpacket including its key version. A hashed
    /// value is authoritative; an unhashed value is accepted only as a
    /// fallback when the hashed area has none.
    pub fn issuerFingerprintInfo(self: Signature) ?IssuerFingerprint {
        inline for ([_][]const u8{
            self.hashed_subpackets,
            self.unhashed_subpackets,
        }) |area| {
            var it = iterateSubpackets(area);
            while (it.next() catch return null) |sub| {
                if (sub.type_id == 33 and sub.data.len >= 1) {
                    return .{
                        .key_version = sub.data[0],
                        .bytes = sub.data[1..],
                    };
                }
            }
        }
        return null;
    }

    /// Walk both areas for an Issuer Key ID subpacket (type 16).
    /// Per the plan's "Critical gotchas": the hashed value is
    /// authoritative; the unhashed area is advisory. We therefore
    /// search the hashed area first and return on hit.
    pub fn issuerKeyId(self: Signature) ?[8]u8 {
        var out: [8]u8 = undefined;
        inline for ([_][]const u8{ self.hashed_subpackets, self.unhashed_subpackets }) |area| {
            var it = iterateSubpackets(area);
            while (it.next() catch return null) |sub| {
                if (sub.type_id == 16 and sub.data.len == 8) {
                    @memcpy(&out, sub.data);
                    return out;
                }
            }
        }
        return null;
    }

    /// Signature Creation Time (type 2) — 4-byte BE Unix timestamp.
    pub fn creationTime(self: Signature) ?u32 {
        var it = iterateSubpackets(self.hashed_subpackets);
        while (it.next() catch return null) |sub| {
            if (sub.type_id == 2 and sub.data.len == 4) {
                return (@as(u32, sub.data[0]) << 24) |
                    (@as(u32, sub.data[1]) << 16) |
                    (@as(u32, sub.data[2]) << 8) |
                    @as(u32, sub.data[3]);
            }
        }
        return null;
    }
};

/// One parsed subpacket. `data` aliases into the input area; the
/// `critical` flag is split off the high bit of the type byte so
/// `type_id` is the canonical 7-bit identifier.
pub const Subpacket = struct {
    type_id: u8,
    critical: bool,
    data: []const u8,
};

pub const SubpacketIterator = struct {
    rest: []const u8,

    pub fn next(self: *SubpacketIterator) SignatureParseError!?Subpacket {
        if (self.rest.len == 0) return null;
        const b1 = self.rest[0];

        var sub_len: usize = undefined;
        var header_len: usize = undefined;
        if (b1 < 192) {
            sub_len = b1;
            header_len = 1;
        } else if (b1 < 255) {
            if (self.rest.len < 2) return error.MalformedSubpacket;
            sub_len = (@as(usize, b1 - 192) << 8) + @as(usize, self.rest[1]) + 192;
            header_len = 2;
        } else {
            if (self.rest.len < 5) return error.MalformedSubpacket;
            sub_len = (@as(usize, self.rest[1]) << 24) |
                (@as(usize, self.rest[2]) << 16) |
                (@as(usize, self.rest[3]) << 8) |
                @as(usize, self.rest[4]);
            header_len = 5;
        }

        // Length must include at least the 1-octet type byte.
        if (sub_len == 0) return error.MalformedSubpacket;
        if (self.rest.len - header_len < sub_len) return error.MalformedSubpacket;

        const type_byte = self.rest[header_len];
        const critical = (type_byte & 0x80) != 0;
        const type_id = type_byte & 0x7F;
        const data = self.rest[header_len + 1 .. header_len + sub_len];
        self.rest = self.rest[header_len + sub_len ..];
        return Subpacket{ .type_id = type_id, .critical = critical, .data = data };
    }
};

pub fn iterateSubpackets(area: []const u8) SubpacketIterator {
    return .{ .rest = area };
}

/// Subpacket types defined by RFC 4880 / 4880bis / 9580. Anything
/// outside this set is "unknown" — and if its critical bit is set
/// the signature is rejected (RFC 4880 §5.2.3.1).
fn isKnownSubpacketType(type_id: u8) bool {
    return switch (type_id) {
        2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 16, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 38, 39 => true,
        else => false,
    };
}

fn validateSubpackets(area: []const u8) SignatureParseError!void {
    var it = iterateSubpackets(area);
    while (try it.next()) |sub| {
        if (sub.critical and !isKnownSubpacketType(sub.type_id)) {
            return error.UnknownCriticalSubpacket;
        }
    }
}

fn validateIssuerFingerprints(version: u8, area: []const u8) SignatureParseError!void {
    var it = iterateSubpackets(area);
    while (try it.next()) |sub| {
        if (sub.type_id != 33) continue;
        if (sub.data.len < 1 or sub.data[0] != version)
            return error.MalformedSubpacket;
        const expected_len: usize = switch (version) {
            4 => 1 + 20,
            6 => 1 + 32,
            else => unreachable,
        };
        if (sub.data.len != expected_len) return error.MalformedSubpacket;
    }
}

fn readMaterialMpi(
    reader: *packet.Reader,
    strict: bool,
) SignatureParseError!packet.Mpi {
    const mpi = try packet.readMpi(reader);
    if (strict and !packet.isCanonicalMpi(mpi))
        return error.MalformedSignatureMaterial;
    return mpi;
}

fn parseMaterial(
    version: u8,
    pk_algo: PkAlgorithm,
    material_bytes: []const u8,
) SignatureParseError!SigMaterial {
    var r = packet.Reader{ .bytes = material_bytes };
    const strict_mpi = version == 6;
    const material: SigMaterial = switch (pk_algo) {
        .rsa_sign_and_encrypt, .rsa_sign_only => blk: {
            const m = try readMaterialMpi(&r, strict_mpi);
            break :blk .{ .rsa = m };
        },
        .dsa => blk: {
            const rr = try readMaterialMpi(&r, strict_mpi);
            const s = try readMaterialMpi(&r, strict_mpi);
            break :blk .{ .dsa = .{ .r = rr, .s = s } };
        },
        .ecdsa => blk: {
            const rr = try readMaterialMpi(&r, strict_mpi);
            const s = try readMaterialMpi(&r, strict_mpi);
            break :blk .{ .ecdsa = .{ .r = rr, .s = s } };
        },
        .eddsa_legacy => blk: {
            const rr = try packet.readMpi(&r);
            const s = try packet.readMpi(&r);
            break :blk .{ .eddsa_legacy = .{ .r = rr, .s = s } };
        },
        .ed25519 => blk: {
            const s = r.take(64) catch return error.TruncatedPacket;
            var out: [64]u8 = undefined;
            @memcpy(&out, s);
            break :blk .{ .ed25519 = out };
        },
        else => return .{ .unsupported = pk_algo },
    };
    if (r.pos != material_bytes.len) return error.MalformedSignatureMaterial;
    return material;
}

fn readLength(body: []const u8, offset: usize, width: usize) SignatureParseError!usize {
    if (width != 2 and width != 4) unreachable;
    if (body.len - offset < width) return error.TruncatedPacket;
    var value: usize = 0;
    for (body[offset .. offset + width]) |byte| {
        value = std.math.mul(usize, value, 256) catch return error.TruncatedPacket;
        value = std.math.add(usize, value, byte) catch return error.TruncatedPacket;
    }
    return value;
}

fn saltLength(hash_algo: HashAlgorithm) ?usize {
    return switch (hash_algo) {
        .sha224, .sha256, .sha3_256 => 16,
        .sha384 => 24,
        .sha512, .sha3_512 => 32,
        else => null,
    };
}

/// Parse a v4 or v6 Signature packet body (the bytes *inside* the Tag 2
/// packet header — caller has already framed via `packet.iterate`).
pub fn parseBody(body: []const u8) SignatureParseError!Signature {
    if (body.len < 1) return error.TruncatedPacket;
    const version = body[0];
    if (version != 4 and version != 6) return error.UnsupportedVersion;

    const length_width: usize = if (version == 4) 2 else 4;
    const fixed_prefix_len = 4 + length_width;
    if (body.len < fixed_prefix_len) return error.TruncatedPacket;

    const sig_type: SigType = @enumFromInt(body[1]);
    const pk_algo: PkAlgorithm = @enumFromInt(body[2]);
    const hash_algo: HashAlgorithm = @enumFromInt(body[3]);
    const hashed_sub_len = try readLength(body, 4, length_width);

    const hashed_end = std.math.add(usize, fixed_prefix_len, hashed_sub_len) catch
        return error.TruncatedPacket;
    if (body.len < hashed_end or body.len - hashed_end < length_width)
        return error.TruncatedPacket;
    const hashed_subpackets = body[fixed_prefix_len..hashed_end];
    const hashed_prefix = body[0..hashed_end];

    const unhashed_sub_len = try readLength(body, hashed_end, length_width);

    const unhashed_start = hashed_end + length_width;
    const sub_end = std.math.add(usize, unhashed_start, unhashed_sub_len) catch
        return error.TruncatedPacket;
    // Need room for unhashed subpackets + 2-octet hash hint.
    if (body.len < sub_end + 2) return error.TruncatedPacket;
    const unhashed_subpackets = body[unhashed_start..sub_end];

    const hash_hint = [_]u8{ body[sub_end], body[sub_end + 1] };
    var material_start = sub_end + 2;
    var salt: []const u8 = &.{};
    if (version == 6) {
        if (material_start >= body.len) return error.TruncatedPacket;
        const salt_len: usize = body[material_start];
        material_start += 1;
        if (body.len - material_start < salt_len) return error.TruncatedPacket;
        salt = body[material_start .. material_start + salt_len];
        material_start += salt_len;
        if (saltLength(hash_algo)) |expected| {
            if (salt.len != expected) return error.MalformedSalt;
        }
    }
    const material_bytes = body[material_start..];

    // Validate subpacket framing in both areas before we surface the
    // packet — unknown criticals reject here.
    try validateSubpackets(hashed_subpackets);
    try validateSubpackets(unhashed_subpackets);
    try validateIssuerFingerprints(version, hashed_subpackets);
    try validateIssuerFingerprints(version, unhashed_subpackets);

    const material = try parseMaterial(version, pk_algo, material_bytes);

    return Signature{
        .version = version,
        .sig_type = sig_type,
        .pk_algo = pk_algo,
        .hash_algo = hash_algo,
        .hashed_prefix = hashed_prefix,
        .hashed_subpackets = hashed_subpackets,
        .unhashed_subpackets = unhashed_subpackets,
        .hash_hint = hash_hint,
        .salt = salt,
        .material = material,
    };
}

// ===== Tests =====

const testing = std.testing;

/// Helper: build a minimal v4 signature body with the supplied
/// hashed and unhashed subpacket bytes and a 256-byte RSA MPI.
fn buildRsaBody(
    comptime hashed: []const u8,
    comptime unhashed: []const u8,
) [6 + hashed.len + 2 + unhashed.len + 2 + 2 + 256]u8 {
    var body: [6 + hashed.len + 2 + unhashed.len + 2 + 2 + 256]u8 = undefined;
    body[0] = 0x04; // version
    body[1] = 0x00; // sig type: binary document
    body[2] = 0x01; // pk algo: RSA sign+encrypt
    body[3] = 0x08; // hash algo: SHA-256
    body[4] = @intCast((hashed.len >> 8) & 0xFF);
    body[5] = @intCast(hashed.len & 0xFF);
    @memcpy(body[6 .. 6 + hashed.len], hashed);
    var p: usize = 6 + hashed.len;
    body[p] = @intCast((unhashed.len >> 8) & 0xFF);
    body[p + 1] = @intCast(unhashed.len & 0xFF);
    p += 2;
    @memcpy(body[p .. p + unhashed.len], unhashed);
    p += unhashed.len;
    body[p] = 0x12; // hash hint hi
    body[p + 1] = 0x34; // hash hint lo
    p += 2;
    // 256-byte RSA-2048 sig MPI: BE16(bit_length=2048) + 256 bytes.
    body[p] = 0x08;
    body[p + 1] = 0x00;
    p += 2;
    @memset(body[p .. p + 256], 0xAA);
    return body;
}

test "parse minimal RSA detached sig" {
    const body = buildRsaBody("", "");
    const sig = try parseBody(&body);
    try testing.expectEqual(@as(u8, 4), sig.version);
    try testing.expectEqual(SigType.binary_document, sig.sig_type);
    try testing.expectEqual(PkAlgorithm.rsa_sign_and_encrypt, sig.pk_algo);
    try testing.expectEqual(HashAlgorithm.sha256, sig.hash_algo);
    try testing.expectEqual(@as(usize, 0), sig.hashed_subpackets.len);
    try testing.expectEqual(@as(usize, 0), sig.unhashed_subpackets.len);
    try testing.expectEqual(@as(u8, 0x12), sig.hash_hint[0]);
    try testing.expectEqual(@as(u8, 0x34), sig.hash_hint[1]);
    try testing.expectEqual(@as(usize, 6), sig.hashed_prefix.len);
    switch (sig.material) {
        .rsa => |m| {
            try testing.expectEqual(@as(u16, 2048), m.bit_length);
            try testing.expectEqual(@as(usize, 256), m.bytes.len);
        },
        else => return error.TestExpectedRsa,
    }
}

test "creation time subpacket extracted" {
    // length=5 (1 type + 4 data), type=2 (creation time), value=0x5F00ABCD.
    const hashed = [_]u8{ 0x05, 0x02, 0x5F, 0x00, 0xAB, 0xCD };
    const body = buildRsaBody(&hashed, "");
    const sig = try parseBody(&body);
    try testing.expectEqual(@as(?u32, 0x5F00ABCD), sig.creationTime());
}

test "issuer fingerprint subpacket (type 33) extracted" {
    // length=22 (1 type + 1 version + 20 fpr), type=33, ver=4, 20-byte fpr.
    const hashed = [_]u8{
        0x16, 0x21, 0x04,
        0x01, 0x02, 0x03,
        0x04, 0x05, 0x06,
        0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12,
        0x13, 0x14,
    };
    const body = buildRsaBody(&hashed, "");
    const sig = try parseBody(&body);
    const fpr = sig.issuerFingerprint() orelse return error.TestExpectedFpr;
    try testing.expectEqual(@as(usize, 20), fpr.len);
    try testing.expectEqualSlices(u8, hashed[3..], fpr);
}

test "issuer fingerprint falls back to unhashed area" {
    const unhashed = [_]u8{
        0x16, 0x21, 0x04,
        0x01, 0x02, 0x03,
        0x04, 0x05, 0x06,
        0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12,
        0x13, 0x14,
    };
    const body = buildRsaBody("", &unhashed);
    const sig = try parseBody(&body);
    const fpr = sig.issuerFingerprint() orelse return error.TestExpectedFpr;
    try testing.expectEqualSlices(u8, unhashed[3..], fpr);
}

test "issuer key id from unhashed area" {
    // length=9 (1 type + 8 keyid), type=16.
    const unhashed = [_]u8{
        0x09, 0x10,
        0xDE, 0xAD,
        0xBE, 0xEF,
        0xCA, 0xFE,
        0xBA, 0xBE,
    };
    const body = buildRsaBody("", &unhashed);
    const sig = try parseBody(&body);
    const kid = sig.issuerKeyId() orelse return error.TestExpectedKid;
    try testing.expectEqualSlices(u8, unhashed[2..], &kid);
}

test "hashed wins over unhashed for keyId" {
    const hashed = [_]u8{
        0x09, 0x10,
        0x11, 0x11,
        0x11, 0x11,
        0x11, 0x11,
        0x11, 0x11,
    };
    const unhashed = [_]u8{
        0x09, 0x10,
        0x22, 0x22,
        0x22, 0x22,
        0x22, 0x22,
        0x22, 0x22,
    };
    const body = buildRsaBody(&hashed, &unhashed);
    const sig = try parseBody(&body);
    const kid = sig.issuerKeyId() orelse return error.TestExpectedKid;
    try testing.expectEqualSlices(u8, hashed[2..], &kid);
}

test "v6 signature MPIs require canonical bit lengths" {
    var body = [_]u8{0} ** 34;
    body[0] = 6;
    body[2] = @intFromEnum(PkAlgorithm.rsa_sign_and_encrypt);
    body[3] = @intFromEnum(HashAlgorithm.sha256);
    body[14] = 16;
    body[32] = 8;
    body[33] = 0x80;
    _ = try parseBody(&body);

    body[32] = 7;
    try testing.expectError(
        error.MalformedSignatureMaterial,
        parseBody(&body),
    );

    var v4_body = [_]u8{0} ** 13;
    v4_body[0] = 4;
    v4_body[2] = @intFromEnum(PkAlgorithm.rsa_sign_and_encrypt);
    v4_body[3] = @intFromEnum(HashAlgorithm.sha256);
    v4_body[11] = 7;
    v4_body[12] = 0x80;
    _ = try parseBody(&v4_body);
}

test "unknown non-critical subpacket is skipped" {
    // length=2 (1 type + 1 data), type=0x7E (critical bit clear).
    const hashed = [_]u8{ 0x02, 0x7E, 0xAA };
    const body = buildRsaBody(&hashed, "");
    _ = try parseBody(&body);
}

test "unknown critical subpacket fails parse" {
    // length=2 (1 type + 1 data), type=0xFE (critical bit set, id 0x7E).
    const hashed = [_]u8{ 0x02, 0xFE, 0xAA };
    const body = buildRsaBody(&hashed, "");
    try testing.expectError(error.UnknownCriticalSubpacket, parseBody(&body));
}

test "Ed25519 sig material is 64 raw bytes" {
    // v4 sig: pk_algo=27 (Ed25519), hash_algo=10 (SHA-512), no
    // subpackets, hash hint, then 64 raw octets (no MPI wrapper).
    var body: [6 + 0 + 2 + 0 + 2 + 64]u8 = undefined;
    body[0] = 0x04;
    body[1] = 0x00;
    body[2] = 27; // Ed25519
    body[3] = 10; // SHA-512
    body[4] = 0x00;
    body[5] = 0x00;
    body[6] = 0x00; // unhashed len hi
    body[7] = 0x00; // unhashed len lo
    body[8] = 0xAB; // hash hint
    body[9] = 0xCD;
    var i: usize = 0;
    while (i < 64) : (i += 1) body[10 + i] = @intCast(i);
    const sig = try parseBody(&body);
    switch (sig.material) {
        .ed25519 => |raw| {
            var j: usize = 0;
            while (j < 64) : (j += 1) {
                try testing.expectEqual(@as(u8, @intCast(j)), raw[j]);
            }
        },
        else => return error.TestExpectedEd25519,
    }
}

test "hashed_prefix length is 6 + hashed_subpacket_data_len" {
    const hashed = [_]u8{ 0x05, 0x02, 0x00, 0x00, 0x00, 0x00 };
    const body = buildRsaBody(&hashed, "");
    const sig = try parseBody(&body);
    try testing.expectEqual(@as(usize, 6 + hashed.len), sig.hashed_prefix.len);
    // The prefix MUST start at the version byte and span exactly
    // through end-of-hashed-subpacket-data, with no unhashed length
    // word included.
    try testing.expectEqual(@as(u8, 0x04), sig.hashed_prefix[0]);
    try testing.expectEqualSlices(u8, &hashed, sig.hashed_prefix[6..]);
}

test "truncated body rejected" {
    // Only 3 bytes — header alone needs 6.
    const body = [_]u8{ 0x04, 0x00, 0x01 };
    try testing.expectError(error.TruncatedPacket, parseBody(&body));
}

test "unsupported version" {
    const body = [_]u8{ 0x03, 0x00, 0x01, 0x08, 0x00, 0x00 };
    try testing.expectError(error.UnsupportedVersion, parseBody(&body));
}

test "subpacket iterator: 2-octet length encoding" {
    // 2-octet length: 192 + (b1-192)*256 + b2 = 200.
    // 200 bytes total = 1 type byte + 199 data bytes.
    var area: [202]u8 = undefined;
    area[0] = 0xC0; // 192
    area[1] = 0x08; // 200 - 192 = 8
    area[2] = 0x02; // type = 2
    @memset(area[3..], 0xAA);
    var it = iterateSubpackets(&area);
    const sub = (try it.next()).?;
    try testing.expectEqual(@as(u8, 2), sub.type_id);
    try testing.expect(!sub.critical);
    try testing.expectEqual(@as(usize, 199), sub.data.len);
    try testing.expect((try it.next()) == null);
}

test "subpacket iterator: 5-octet length encoding" {
    var area: [6 + 100]u8 = undefined;
    area[0] = 0xFF;
    area[1] = 0x00;
    area[2] = 0x00;
    area[3] = 0x00;
    area[4] = 0x65; // 101 = 1 type + 100 data
    area[5] = 0x02; // type = 2
    @memset(area[6..], 0xBB);
    var it = iterateSubpackets(&area);
    const sub = (try it.next()).?;
    try testing.expectEqual(@as(u8, 2), sub.type_id);
    try testing.expectEqual(@as(usize, 100), sub.data.len);
    try testing.expect((try it.next()) == null);
}

test "subpacket iterator: zero-length is malformed" {
    const area = [_]u8{0x00};
    var it = iterateSubpackets(&area);
    try testing.expectError(error.MalformedSubpacket, it.next());
}
