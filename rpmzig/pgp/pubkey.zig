//! OpenPGP Public-Key / Public-Subkey packet parser + v4 fingerprint.
//!
//! Phase A, PR #3 of the pure-Zig PGP verifier plan
//! (plan-pure-zig-pgp.md, section 5). Operates on the *body* bytes
//! produced by `packet.iterate` for Tag 6 (Public-Key) and Tag 14
//! (Public-Subkey) packets.
//!
//! v4 Public-Key body layout (RFC 4880 §5.5.2 / RFC 9580 §5.5.2):
//!
//!   1 octet  version = 0x04
//!   4 octets creation timestamp (BE)
//!   1 octet  pk algorithm ID
//!   [algorithm-specific MPIs or octets]
//!
//! Algorithm-specific key material handled here:
//!
//!   RSA (1, 2, 3)    : MPI(n), MPI(e)                        -- parsed
//!   DSA (17)         : MPI(p), MPI(q), MPI(g), MPI(y)        -- skipped, marked unsupported
//!   ECDSA (19)       : 1-octet OID len, OID, MPI(Q)          -- skipped, marked unsupported
//!   EdDSALegacy (22) : 1-octet OID len, OID, MPI(Q w/ 0x40)  -- parsed (PR #9)
//!   Ed25519 (27)     : 32 raw octets                         -- parsed (PR #9)
//!
//! EdDSALegacy (22) and native Ed25519 (27) differ only in wire
//! framing; the cryptographic material is the same 32-byte Ed25519
//! public key. Both formats collapse onto a single
//! `KeyMaterial.ed25519` variant — the original algorithm ID is
//! still surfaced via `PublicKey.algo` for callers that need to
//! drive sig-side parsing differently.
//!
//! Unknown algorithms are surfaced as `KeyMaterial.unsupported` so a
//! keyring containing a mix of algorithms parses without failing the
//! whole walk. Callers that need the unsupported material can revisit
//! `PublicKey.body` directly.
//!
//! Only v4 keys are accepted. v6 (RFC 9580 §5.5.2) lands in PR #9 if
//! any distro starts shipping v6 signatures.
//!
//! v4 fingerprint (RFC 4880 §12.2):
//!
//!   fingerprint = SHA-1(0x99 || BE16(body_len) || body)
//!   v4 key id   = last 8 octets of fingerprint

const std = @import("std");
const packet = @import("packet.zig");

pub const Algorithm = enum(u8) {
    rsa_sign_and_encrypt = 1,
    rsa_encrypt_only = 2,
    rsa_sign_only = 3,
    dsa = 17,
    ecdsa = 19,
    eddsa_legacy = 22,
    ed25519 = 27,
    _,
};

pub fn isRsa(algo: Algorithm) bool {
    return switch (algo) {
        .rsa_sign_and_encrypt, .rsa_encrypt_only, .rsa_sign_only => true,
        else => false,
    };
}

pub const RsaKey = struct {
    n: packet.Mpi,
    e: packet.Mpi,
};

/// Ed25519 public-key material — 32 raw octets of the curve point.
///
/// Both EdDSALegacy (algo 22, OID-prefixed MPI(0x40 || Q)) and native
/// Ed25519 (algo 27, raw 32 octets) collapse onto this. Sig-side
/// dispatch differs (see `signature.SigMaterial`); the cryptographic
/// material does not.
pub const Ed25519Key = struct {
    point: [32]u8,
};

/// OID for ed25519 used by EdDSALegacy (RFC 4880bis):
/// 1.3.6.1.4.1.11591.15.1 — `2B 06 01 04 01 DA 47 0F 01` (9 octets).
pub const ED25519_OID = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };

pub const KeyMaterial = union(enum) {
    rsa: RsaKey,
    ed25519: Ed25519Key,
    unsupported: Algorithm,
};

pub const PublicKey = struct {
    version: u8,
    created_at: u32,
    algo: Algorithm,
    material: KeyMaterial,
    /// Slice into the input bytes covering the full packet *body*
    /// (after the header, before the next packet). Required for
    /// fingerprint computation and for hash-context construction
    /// when verifying subkey binding signatures.
    body: []const u8,
};

pub const Fingerprint = struct {
    bytes: [20]u8,

    /// v4 key id = last 8 octets of the 20-octet fingerprint.
    /// (Note: v6 key id, when added, will be the FIRST 8 octets of a
    /// 32-octet fingerprint — opposite ends.)
    pub fn keyId(self: Fingerprint) [8]u8 {
        return self.bytes[12..20].*;
    }
};

pub const ParseError = error{
    UnsupportedVersion,
} || packet.ReaderError || packet.MpiError;

/// Parse a v4 Public-Key / Public-Subkey packet body.
///
/// `body` must be the byte range returned by `packet.iterate` for a
/// Tag 6 or Tag 14 packet (i.e. without the header octets).
pub fn parseBody(body: []const u8) ParseError!PublicKey {
    var r = packet.Reader{ .bytes = body };

    const version = try r.readU8();
    if (version != 4) return error.UnsupportedVersion;
    const created_at = try r.readU32Be();
    const algo: Algorithm = @enumFromInt(try r.readU8());

    const material: KeyMaterial = switch (algo) {
        .rsa_sign_and_encrypt, .rsa_encrypt_only, .rsa_sign_only => blk: {
            const n = try packet.readMpi(&r);
            const e = try packet.readMpi(&r);
            break :blk .{ .rsa = .{ .n = n, .e = e } };
        },
        .eddsa_legacy => blk: {
            if (parseEddsaLegacy(&r)) |k| {
                break :blk .{ .ed25519 = k };
            } else |_| {
                // Malformed OID / unexpected length / non-ed25519 OID.
                // Leave the reader where it was on entry — we don't
                // know the framing once the OID disagreed — but we
                // still surface the packet as `unsupported` rather
                // than failing the whole keyring walk. The caller
                // can revisit `PublicKey.body` for raw access.
                break :blk .{ .unsupported = algo };
            }
        },
        .ed25519 => blk: {
            const raw = try r.take(32);
            var k: Ed25519Key = .{ .point = undefined };
            @memcpy(&k.point, raw);
            break :blk .{ .ed25519 = k };
        },
        else => blk: {
            try skipAlgorithmMaterial(&r, algo);
            break :blk .{ .unsupported = algo };
        },
    };

    return .{
        .version = version,
        .created_at = created_at,
        .algo = algo,
        .material = material,
        .body = body,
    };
}

/// Advance `r` past the algorithm-specific material of an unsupported
/// algorithm. Truncation inside known-shaped material is still an
/// error: we want to surface "this key blob is malformed" rather than
/// silently accept a half-parsed packet. For genuinely unknown
/// algorithm IDs the body slice itself delimits the material, so we
/// leave the reader where it is.
fn skipAlgorithmMaterial(r: *packet.Reader, algo: Algorithm) ParseError!void {
    switch (algo) {
        .dsa => {
            _ = try packet.readMpi(r);
            _ = try packet.readMpi(r);
            _ = try packet.readMpi(r);
            _ = try packet.readMpi(r);
        },
        .ecdsa => {
            const oid_len = try r.readU8();
            _ = try r.take(oid_len);
            _ = try packet.readMpi(r);
        },
        .rsa_sign_and_encrypt,
        .rsa_encrypt_only,
        .rsa_sign_only,
        .eddsa_legacy,
        .ed25519,
        => unreachable,
        _ => {},
    }
}

const EddsaLegacyError = error{
    UnsupportedOid,
    UnsupportedPointPrefix,
    UnsupportedPointLength,
} || packet.ReaderError || packet.MpiError;

/// Parse the EdDSALegacy (algo 22) public-key material:
///   1 octet  OID length (= 9)
///   9 octets OID = ED25519_OID
///   MPI(Q)   where Q = 0x40 || 32 raw octets (RFC 6637 §9, RFC 4880bis)
///
/// Returns the 32-byte Ed25519 public key. The leading 0x40 byte
/// marks the point as "native EdDSA" — uncompressed-but-with-y-only
/// encoding. The MPI strip in `packet.readMpi` removes leading zero
/// bytes; for a 263-bit MPI the top byte is 0x40 (high bit clear,
/// but second-highest set) so no leading zero is ever produced.
/// We defensively left-pad in case some non-standard producer emits
/// a shorter MPI.
fn parseEddsaLegacy(r: *packet.Reader) EddsaLegacyError!Ed25519Key {
    const oid_len = try r.readU8();
    if (oid_len != ED25519_OID.len) return error.UnsupportedOid;
    const oid = try r.take(oid_len);
    if (!std.mem.eql(u8, oid, &ED25519_OID)) return error.UnsupportedOid;

    const q = try packet.readMpi(r);
    if (q.bytes.len == 0) return error.UnsupportedPointLength;
    if (q.bytes[0] != 0x40) return error.UnsupportedPointPrefix;

    // After the 0x40 prefix come the 32 raw octets of the public key.
    const tail = q.bytes[1..];
    if (tail.len > 32) return error.UnsupportedPointLength;
    var key: Ed25519Key = .{ .point = @splat(0) };
    // Left-pad with zeros if the MPI stripped any leading zeros from
    // the y-coordinate. Producers shouldn't do this (the 0x40 prefix
    // keeps the MPI's MSB nonzero), but be defensive.
    @memcpy(key.point[32 - tail.len ..], tail);
    return key;
}

/// Compute the v4 OpenPGP fingerprint over the given Public-Key
/// packet body. The framing `0x99 || BE16(body_len) || body` is
/// applied internally.
pub fn fingerprintV4(body: []const u8) Fingerprint {
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(&.{0x99});
    const len_be: [2]u8 = .{
        @intCast((body.len >> 8) & 0xFF),
        @intCast(body.len & 0xFF),
    };
    hasher.update(&len_be);
    hasher.update(body);
    var out: [20]u8 = undefined;
    hasher.final(&out);
    return .{ .bytes = out };
}

// ===== Tests =====

const testing = std.testing;

test "parse hand-crafted RSA pubkey body" {
    // Minimal v4 RSA-2048 body:
    //   0x04 || BE32(0) || 0x01 || MPI(n, 2048 bits) || MPI(e = 0x010001)
    var body: [1 + 4 + 1 + 2 + 256 + 2 + 3]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 0x01;
    body[6] = 0x08;
    body[7] = 0x00;
    @memset(body[8..264], 0xAB);
    body[8] = 0x80;
    body[264] = 0x00;
    body[265] = 0x11;
    body[266] = 0x01;
    body[267] = 0x00;
    body[268] = 0x01;

    const pk = try parseBody(&body);
    try testing.expectEqual(@as(u8, 4), pk.version);
    try testing.expectEqual(@as(u32, 0), pk.created_at);
    try testing.expectEqual(Algorithm.rsa_sign_and_encrypt, pk.algo);
    switch (pk.material) {
        .rsa => |rsa| {
            try testing.expectEqual(@as(usize, 256), rsa.n.bytes.len);
            try testing.expectEqual(@as(u8, 0x80), rsa.n.bytes[0]);
            try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, rsa.e.bytes);
            try testing.expectEqual(@as(u16, 17), rsa.e.bit_length);
        },
        else => return error.TestExpectedRsaMaterial,
    }
}

test "parse real Microsoft Mariner key (Tag 6 in dearmored blob)" {
    const bytes = @embedFile("testdata/microsoft-rpm-key.bin");
    var it = packet.iterate(bytes);
    var found = false;
    while (try it.next()) |pkt| {
        if (pkt.tag != .public_key) continue;
        found = true;
        const pk = try parseBody(pkt.body);
        try testing.expectEqual(@as(u8, 4), pk.version);
        try testing.expect(isRsa(pk.algo));
        switch (pk.material) {
            .rsa => |rsa| {
                // RSA-2048 modulus, e = 0x010001 (typical).
                try testing.expectEqual(@as(usize, 256), rsa.n.bytes.len);
                try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, rsa.e.bytes);
            },
            else => return error.TestExpectedRsaMaterial,
        }
        // Fingerprint observed via `gpg --show-keys`:
        //   2BC9 4FFF 7015 A5F2 8F15  37AD 0CD9 FED3 3135 CE90
        const expected_fpr = [_]u8{
            0x2B, 0xC9, 0x4F, 0xFF, 0x70, 0x15, 0xA5, 0xF2, 0x8F, 0x15,
            0x37, 0xAD, 0x0C, 0xD9, 0xFE, 0xD3, 0x31, 0x35, 0xCE, 0x90,
        };
        const fpr = fingerprintV4(pkt.body);
        try testing.expectEqualSlices(u8, &expected_fpr, &fpr.bytes);
        try testing.expectEqualSlices(
            u8,
            &[_]u8{ 0x0C, 0xD9, 0xFE, 0xD3, 0x31, 0x35, 0xCE, 0x90 },
            &fpr.keyId(),
        );
        break;
    }
    try testing.expect(found);
}

test "fingerprintV4 of hand-crafted body matches reference SHA-1" {
    // Independent of parseBody: just an SHA-1 sanity check on a known
    // tiny input. Reference computed out-of-band:
    //   SHA-1(0x99 0x00 0x03 0x04 0x00 0x01)
    //     == e7217e8b0cd76a2b951b5ff54b004fd58da14a7b
    const body = [_]u8{ 0x04, 0x00, 0x01 };
    const fpr = fingerprintV4(&body);
    const expected = [_]u8{
        0xE7, 0x21, 0x7E, 0x8B, 0x0C, 0xD7, 0x6A, 0x2B, 0x95, 0x1B,
        0x5F, 0xF5, 0x4B, 0x00, 0x4F, 0xD5, 0x8D, 0xA1, 0x4A, 0x7B,
    };
    try testing.expectEqualSlices(u8, &expected, &fpr.bytes);
}

test "keyId returns last 8 fingerprint bytes" {
    const fpr = Fingerprint{ .bytes = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
    } };
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13 },
        &fpr.keyId(),
    );
}

test "unsupported version rejected" {
    const body = [_]u8{ 0x03, 0x00, 0x00, 0x00, 0x00, 0x01 };
    try testing.expectError(error.UnsupportedVersion, parseBody(&body));
}

test "truncated body rejected (no algo byte)" {
    // Only version + 4-byte creation timestamp, no algorithm octet.
    const body = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(error.Truncated, parseBody(&body));
}

test "truncated RSA modulus rejected" {
    // Version + creation + algo + start of MPI, then payload truncated.
    const body = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x80 };
    try testing.expectError(error.TruncatedMpi, parseBody(&body));
}

test "ECDSA key parses as Unsupported (not an error)" {
    // v4 || BE32(0) || algo=19 || OID len 8 || NIST P-256 OID || MPI(Q)
    const nistp256_oid = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    var body: [1 + 4 + 1 + 1 + 8 + 2 + 65]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 19;
    body[6] = nistp256_oid.len;
    @memcpy(body[7..15], &nistp256_oid);
    // MPI(Q): 515 bits, 65 bytes (0x04 || X || Y for an uncompressed P-256 point).
    body[15] = 0x02;
    body[16] = 0x03;
    body[17] = 0x04;
    @memset(body[18..82], 0xCC);

    const pk = try parseBody(&body);
    try testing.expectEqual(Algorithm.ecdsa, pk.algo);
    switch (pk.material) {
        .unsupported => |a| try testing.expectEqual(Algorithm.ecdsa, a),
        else => return error.TestExpectedUnsupportedMaterial,
    }
}

test "Ed25519 (native, algo 27) parses to 32-byte point" {
    var body: [1 + 4 + 1 + 32]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 27;
    @memset(body[6..38], 0xDD);

    const pk = try parseBody(&body);
    try testing.expectEqual(Algorithm.ed25519, pk.algo);
    switch (pk.material) {
        .ed25519 => |k| {
            var expected: [32]u8 = @splat(0xDD);
            try testing.expectEqualSlices(u8, &expected, &k.point);
        },
        else => return error.TestExpectedEd25519Material,
    }
}

test "EdDSALegacy (algo 22) parses to 32-byte point" {
    // v4 || BE32(0) || algo=22 || OID len 9 || ED25519_OID
    //    || MPI(0x40 || 32 raw bytes) — bit length 263.
    const expected_point: [32]u8 = @splat(0xC3);
    var body: [1 + 4 + 1 + 1 + 9 + 2 + 33]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 22;
    body[6] = ED25519_OID.len;
    @memcpy(body[7..16], &ED25519_OID);
    // MPI(Q) with Q = 0x40 || 0xC3 * 32. Bit length = 263.
    body[16] = 0x01;
    body[17] = 0x07;
    body[18] = 0x40;
    @memcpy(body[19..51], &expected_point);

    const pk = try parseBody(&body);
    try testing.expectEqual(Algorithm.eddsa_legacy, pk.algo);
    switch (pk.material) {
        .ed25519 => |k| {
            try testing.expectEqualSlices(u8, &expected_point, &k.point);
        },
        else => return error.TestExpectedEd25519Material,
    }
}

test "EdDSALegacy with wrong OID surfaces as Unsupported" {
    // OID length is 9 but bytes don't match the ed25519 OID — e.g.
    // the NIST P-256 OID padded out to 9 octets.
    var body: [1 + 4 + 1 + 1 + 9 + 2 + 33]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 22;
    body[6] = 9;
    @memset(body[7..16], 0xEE);
    body[16] = 0x01;
    body[17] = 0x07;
    body[18] = 0x40;
    @memset(body[19..51], 0xDD);

    const pk = try parseBody(&body);
    try testing.expectEqual(Algorithm.eddsa_legacy, pk.algo);
    switch (pk.material) {
        .unsupported => |a| try testing.expectEqual(Algorithm.eddsa_legacy, a),
        else => return error.TestExpectedUnsupportedMaterial,
    }
}

test "EdDSALegacy missing 0x40 point prefix surfaces as Unsupported" {
    var body: [1 + 4 + 1 + 1 + 9 + 2 + 33]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 22;
    body[6] = ED25519_OID.len;
    @memcpy(body[7..16], &ED25519_OID);
    // MPI with Q[0] != 0x40 — invalid native-point encoding.
    body[16] = 0x01;
    body[17] = 0x07;
    body[18] = 0x04;
    @memset(body[19..51], 0xDD);

    const pk = try parseBody(&body);
    switch (pk.material) {
        .unsupported => |a| try testing.expectEqual(Algorithm.eddsa_legacy, a),
        else => return error.TestExpectedUnsupportedMaterial,
    }
}

test "unknown algorithm parses as Unsupported" {
    // Algorithm 99 has no defined wire format; the parser leaves the
    // reader where it is and surfaces the raw enum value.
    const body = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x00, 99 };
    const pk = try parseBody(&body);
    switch (pk.material) {
        .unsupported => |a| try testing.expectEqual(@as(u8, 99), @intFromEnum(a)),
        else => return error.TestExpectedUnsupportedMaterial,
    }
}
