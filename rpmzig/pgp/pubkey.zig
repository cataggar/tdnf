//! OpenPGP Public-Key / Public-Subkey parser with v4/v6 fingerprints.
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
//! Algorithm-specific key material handled here:
//!
//!   RSA (1, 2, 3)    : MPI(n), MPI(e)                        -- parsed
//!   DSA (17)         : MPI(p), MPI(q), MPI(g), MPI(y)        -- skipped, marked unsupported
//!   ECDSA (19)       : 1-octet OID len, OID, MPI(Q)          -- parsed (P-256, P-384)
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
//! Unknown algorithms — and ECDSA on a non-{P-256, P-384} curve, or
//! with a malformed point — are surfaced as `KeyMaterial.unsupported`
//! so a keyring containing a mix of algorithms parses without failing
//! the whole walk. Callers that need the unsupported material can
//! revisit `PublicKey.body` directly.
//!
//! v4 fingerprint (RFC 4880 §12.2):
//!
//!   fingerprint = SHA-1(0x99 || BE16(body_len) || body)
//!   v4 key id   = last 8 octets of fingerprint
//!
//! v6 fingerprint (RFC 9580 §5.5.4):
//!
//!   fingerprint = SHA-256(0x9b || BE32(body_len) || body)
//!   v6 key id   = first 8 octets of fingerprint

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

pub const EcCurve = enum { p256, p384 };

pub const EcdsaKey = struct {
    curve: EcCurve,
    /// Q point in SEC1 uncompressed form: 0x04 || x || y. Length is
    /// 65 bytes for P-256 (32-byte coordinates) or 97 bytes for
    /// P-384 (48-byte coordinates). Aliases into the input body
    /// slice via the MPI reader.
    point: []const u8,
};

pub const KeyMaterial = union(enum) {
    rsa: RsaKey,
    ecdsa: EcdsaKey,
    ed25519: Ed25519Key,
    unsupported: Algorithm,
};

/// ECDSA NIST P-256 curve OID — `1.2.840.10045.3.1.7` encoded as
/// raw DER OID octets (the value bytes only, without the leading
/// `06 LL` length envelope).
pub const OID_NIST_P256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

/// ECDSA NIST P-384 curve OID — `1.3.132.0.34` encoded as raw DER
/// OID octets (no length envelope).
pub const OID_NIST_P384 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };

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
    bytes: [32]u8,
    len: u8,
    version: u8,

    pub fn slice(self: *const Fingerprint) []const u8 {
        return self.bytes[0..self.len];
    }

    /// v4 key IDs use the last 8 octets; v6 uses the first 8.
    pub fn keyId(self: Fingerprint) [8]u8 {
        return switch (self.version) {
            4 => self.bytes[self.len - 8 .. self.len][0..8].*,
            6 => self.bytes[0..8].*,
            else => unreachable,
        };
    }
};

pub const ParseError = error{
    UnsupportedVersion,
    NonCanonicalMpi,
    InvalidKeyMaterial,
    TrailingKeyMaterial,
} || packet.ReaderError || packet.MpiError;

/// Parse a v4 or v6 Public-Key / Public-Subkey packet body.
///
/// `body` must be the byte range returned by `packet.iterate` for a
/// Tag 6 or Tag 14 packet (i.e. without the header octets).
pub fn parseBody(body: []const u8) ParseError!PublicKey {
    return parseBodyWithMode(body, .lenient);
}

/// Parse a public-key packet for persistent trust-store import.
///
/// The verifier deliberately preserves some historical leniency for
/// unsupported keys. Importing a certificate is a trust boundary, so known
/// algorithm material must be complete and consume the whole packet body.
pub fn parseBodyStrict(body: []const u8) ParseError!PublicKey {
    return parseBodyWithMode(body, .strict_import);
}

const ParseMode = enum {
    lenient,
    strict_import,
};

fn parseBodyWithMode(
    body: []const u8,
    mode: ParseMode,
) ParseError!PublicKey {
    var r = packet.Reader{ .bytes = body };

    const version = try r.readU8();
    if (version != 4 and version != 6) return error.UnsupportedVersion;
    const created_at = try r.readU32Be();
    const algo: Algorithm = @enumFromInt(try r.readU8());

    var material_reader = if (version == 6) blk: {
        const material_len = try r.readU32Be();
        const material = try r.take(@intCast(material_len));
        if (r.rest().len != 0) return error.UnsupportedVersion;
        break :blk packet.Reader{ .bytes = material };
    } else r;

    const material: KeyMaterial = switch (algo) {
        .rsa_sign_and_encrypt, .rsa_encrypt_only, .rsa_sign_only => blk: {
            const n = try packet.readMpi(&material_reader);
            const e = try packet.readMpi(&material_reader);
            if (version == 6 and
                (!packet.isCanonicalMpi(n) or !packet.isCanonicalMpi(e)))
            {
                return error.NonCanonicalMpi;
            }
            break :blk .{ .rsa = .{ .n = n, .e = e } };
        },
        .eddsa_legacy => blk: {
            if (version == 6) break :blk .{ .unsupported = algo };
            const maybe_key = parseEddsaLegacy(&material_reader) catch |err| {
                if (mode == .strict_import) return err;
                break :blk .{ .unsupported = algo };
            };
            if (maybe_key) |k| {
                break :blk .{ .ed25519 = k };
            } else {
                break :blk .{ .unsupported = algo };
            }
        },
        .ed25519 => blk: {
            const raw = try material_reader.take(32);
            var k: Ed25519Key = .{ .point = undefined };
            @memcpy(&k.point, raw);
            break :blk .{ .ed25519 = k };
        },
        .ecdsa => blk: {
            const k = try parseEcdsaMaterial(
                &material_reader,
                version == 6,
            );
            break :blk switch (k) {
                .key => |key| .{ .ecdsa = key },
                .unsupported => .{ .unsupported = algo },
                .invalid => if (mode == .strict_import)
                    return error.InvalidKeyMaterial
                else
                    .{ .unsupported = algo },
            };
        },
        else => blk: {
            try skipAlgorithmMaterial(&material_reader, algo);
            break :blk .{ .unsupported = algo };
        },
    };

    if (mode == .strict_import and
        isKnownAlgorithm(algo) and
        material_reader.rest().len != 0)
    {
        return error.TrailingKeyMaterial;
    }
    if (version == 6 and material_reader.rest().len != 0) {
        switch (material) {
            .unsupported => {},
            else => return error.UnsupportedVersion,
        }
    }

    return .{
        .version = version,
        .created_at = created_at,
        .algo = algo,
        .material = material,
        .body = body,
    };
}

fn isKnownAlgorithm(algo: Algorithm) bool {
    return switch (algo) {
        .rsa_sign_and_encrypt,
        .rsa_encrypt_only,
        .rsa_sign_only,
        .dsa,
        .ecdsa,
        .eddsa_legacy,
        .ed25519,
        => true,
        else => false,
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
        .rsa_sign_and_encrypt,
        .rsa_encrypt_only,
        .rsa_sign_only,
        .eddsa_legacy,
        .ed25519,
        .ecdsa,
        => unreachable,
        _ => {},
    }
}

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
/// a shorter MPI. An unknown OID is well-framed but unsupported; malformed
/// Ed25519 material is distinct so strict import can reject it.
fn parseEddsaLegacy(r: *packet.Reader) ParseError!?Ed25519Key {
    const oid_len = try r.readU8();
    const oid = try r.take(oid_len);
    const q = try packet.readMpi(r);
    if (oid.len != ED25519_OID.len or !std.mem.eql(u8, oid, &ED25519_OID))
        return null;
    if (q.bytes.len == 0 or q.bytes[0] != 0x40)
        return error.InvalidKeyMaterial;

    // After the 0x40 prefix come the 32 raw octets of the public key.
    const tail = q.bytes[1..];
    if (tail.len > 32) return error.InvalidKeyMaterial;
    var key: Ed25519Key = .{ .point = @splat(0) };
    // Left-pad with zeros if the MPI stripped any leading zeros from
    // the y-coordinate. Producers shouldn't do this (the 0x40 prefix
    // keeps the MPI's MSB nonzero), but be defensive.
    @memcpy(key.point[32 - tail.len ..], tail);
    return key;
}

/// Parse ECDSA-specific key material (RFC 4880 §5.5.2 / RFC 6637):
///
///   1 octet   OID length
///   N octets  OID (raw DER value bytes — no `06 LL` envelope)
///   MPI(Q)    where Q is the EC point in SEC1 uncompressed form:
///             0x04 || x || y, each coord big-endian.
///
/// Returns `null` (with the reader advanced past the material) when
/// the curve is one we don't support or the point body is the wrong
/// shape. Genuine truncation errors propagate. The leading 0x04 byte
/// of SEC1 uncompressed encoding has its high bit clear, so
/// `packet.readMpi`'s leading-zero strip is a no-op and the MPI
/// payload comes back at the full curve length — see the inline
/// assertion below.
const EcdsaMaterial = union(enum) {
    key: EcdsaKey,
    unsupported,
    invalid,
};

fn parseEcdsaMaterial(
    r: *packet.Reader,
    strict_mpi: bool,
) ParseError!EcdsaMaterial {
    const oid_len = try r.readU8();
    const oid = try r.take(oid_len);

    const curve: EcCurve = if (std.mem.eql(u8, oid, &OID_NIST_P256))
        .p256
    else if (std.mem.eql(u8, oid, &OID_NIST_P384))
        .p384
    else {
        // Unknown curve OID — drain the MPI so the reader is left
        // in a known state, then surface as unsupported.
        const q = try packet.readMpi(r);
        if (strict_mpi and !packet.isCanonicalMpi(q))
            return error.NonCanonicalMpi;
        return .unsupported;
    };

    const q = try packet.readMpi(r);
    if (strict_mpi and !packet.isCanonicalMpi(q))
        return error.NonCanonicalMpi;
    const expected_len: usize = switch (curve) {
        .p256 => 65,
        .p384 => 97,
    };
    // SEC1 uncompressed point must be exactly the curve's expected
    // length and start with 0x04. (Compressed-point encoding 0x02 /
    // 0x03 is permitted by RFC 6637 but RPM signers never emit it,
    // and `std.crypto.sign.ecdsa` accepts uncompressed only.)
    if (q.bytes.len != expected_len) return .invalid;
    if (q.bytes[0] != 0x04) return .invalid;

    return .{ .key = .{ .curve = curve, .point = q.bytes } };
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
    var out: Fingerprint = .{
        .bytes = @splat(0),
        .len = 20,
        .version = 4,
    };
    hasher.final(out.bytes[0..20]);
    return out;
}

pub fn fingerprintV6(body: []const u8) Fingerprint {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&.{0x9b});
    const len_be: [4]u8 = .{
        @intCast((body.len >> 24) & 0xFF),
        @intCast((body.len >> 16) & 0xFF),
        @intCast((body.len >> 8) & 0xFF),
        @intCast(body.len & 0xFF),
    };
    hasher.update(&len_be);
    hasher.update(body);
    var out: Fingerprint = .{
        .bytes = @splat(0),
        .len = 32,
        .version = 6,
    };
    hasher.final(&out.bytes);
    return out;
}

pub fn fingerprint(key: PublicKey) Fingerprint {
    return switch (key.version) {
        4 => fingerprintV4(key.body),
        6 => fingerprintV6(key.body),
        else => unreachable,
    };
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

test "parse and fingerprint a v6 Ed25519 primary key" {
    var body: [42]u8 = @splat(0);
    body[0] = 6;
    body[5] = 27;
    body[9] = 32;
    for (body[10..], 0..) |*byte, index| byte.* = @intCast(index + 1);

    const key = try parseBody(&body);
    try testing.expectEqual(@as(u8, 6), key.version);
    try testing.expectEqual(Algorithm.ed25519, key.algo);
    switch (key.material) {
        .ed25519 => |ed| try testing.expectEqualSlices(u8, body[10..], &ed.point),
        else => return error.TestExpectedEd25519Material,
    }

    const fpr = fingerprint(key);
    try testing.expectEqual(@as(u8, 6), fpr.version);
    try testing.expectEqual(@as(usize, 32), fpr.slice().len);
    try testing.expectEqualSlices(u8, fpr.slice()[0..8], &fpr.keyId());

    var trailing: [43]u8 = undefined;
    @memcpy(trailing[0..42], &body);
    trailing[42] = 0;
    try testing.expectError(error.UnsupportedVersion, parseBody(&trailing));
}

test "v6 RSA key MPIs require canonical bit lengths" {
    var body = [_]u8{
        6,
        0,
        0,
        0,
        0,
        @intFromEnum(Algorithm.rsa_sign_and_encrypt),
        0,
        0,
        0,
        6,
        0,
        8,
        0x80,
        0,
        2,
        0x03,
    };
    _ = try parseBody(&body);

    body[11] = 7;
    try std.testing.expectError(error.NonCanonicalMpi, parseBody(&body));

    const v4_body = [_]u8{
        4,
        0,
        0,
        0,
        0,
        @intFromEnum(Algorithm.rsa_sign_and_encrypt),
        0,
        7,
        0x80,
        0,
        2,
        0x03,
    };
    _ = try parseBody(&v4_body);
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
        try testing.expectEqualSlices(u8, &expected_fpr, fpr.slice());
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
    try testing.expectEqualSlices(u8, &expected, fpr.slice());
}

test "v4 keyId returns last 8 fingerprint bytes" {
    const fpr = Fingerprint{
        .bytes = .{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0,    0,    0,    0,
            0,    0,    0,    0,    0,    0,    0,    0,
        },
        .len = 20,
        .version = 4,
    };
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

test "strict import parser rejects trailing and truncated v4 material" {
    var complete: [1 + 4 + 1 + 32]u8 = undefined;
    complete[0] = 4;
    @memset(complete[1..5], 0);
    complete[5] = @intFromEnum(Algorithm.ed25519);
    @memset(complete[6..], 0xA5);

    var trailing: [complete.len + 1]u8 = undefined;
    @memcpy(trailing[0..complete.len], &complete);
    trailing[complete.len] = 0;
    _ = try parseBody(&trailing);
    try testing.expectError(
        error.TrailingKeyMaterial,
        parseBodyStrict(&trailing),
    );

    try testing.expectError(
        error.Truncated,
        parseBodyStrict(complete[0 .. complete.len - 1]),
    );
}

test "strict import parser does not hide truncated legacy EdDSA" {
    var body: [1 + 4 + 1 + 1 + ED25519_OID.len + 1]u8 = undefined;
    body[0] = 4;
    @memset(body[1..5], 0);
    body[5] = @intFromEnum(Algorithm.eddsa_legacy);
    body[6] = ED25519_OID.len;
    @memcpy(body[7 .. 7 + ED25519_OID.len], &ED25519_OID);
    body[body.len - 1] = 0x01; // Truncated MPI bit-count.

    // Verifier parsing remains intentionally lenient for unsupported keys.
    const parsed = try parseBody(&body);
    switch (parsed.material) {
        .unsupported => {},
        else => return error.TestExpectedUnsupportedMaterial,
    }
    try testing.expectError(error.TruncatedMpi, parseBodyStrict(&body));
}

test "parse ECDSA P-256 public-key body" {
    // v4 || BE32(0) || algo=19 || OID len 8 || NIST P-256 OID || MPI(Q)
    var body: [1 + 4 + 1 + 1 + 8 + 2 + 65]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 19;
    body[6] = OID_NIST_P256.len;
    @memcpy(body[7..15], &OID_NIST_P256);
    // MPI(Q): 515 bits, 65 bytes (0x04 || X || Y for an uncompressed P-256 point).
    // bit_length = 8*65 - 5_leading_zero_bits_in_0x04 = 515 = 0x0203.
    body[15] = 0x02;
    body[16] = 0x03;
    body[17] = 0x04;
    @memset(body[18..82], 0xCC);

    const pk = try parseBody(&body);
    try testing.expectEqual(Algorithm.ecdsa, pk.algo);
    switch (pk.material) {
        .ecdsa => |ec| {
            try testing.expectEqual(EcCurve.p256, ec.curve);
            try testing.expectEqual(@as(usize, 65), ec.point.len);
            try testing.expectEqual(@as(u8, 0x04), ec.point[0]);
        },
        else => return error.TestExpectedEcdsaMaterial,
    }
}

test "parse ECDSA P-384 public-key body" {
    // v4 || BE32(0) || algo=19 || OID len 5 || NIST P-384 OID || MPI(Q)
    var body: [1 + 4 + 1 + 1 + 5 + 2 + 97]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 19;
    body[6] = OID_NIST_P384.len;
    @memcpy(body[7..12], &OID_NIST_P384);
    // MPI(Q): 771 bits = 8*97 - 5 leading zero bits in 0x04. 0x303.
    body[12] = 0x03;
    body[13] = 0x03;
    body[14] = 0x04;
    @memset(body[15..111], 0xDE);

    const pk = try parseBody(&body);
    try testing.expectEqual(Algorithm.ecdsa, pk.algo);
    switch (pk.material) {
        .ecdsa => |ec| {
            try testing.expectEqual(EcCurve.p384, ec.curve);
            try testing.expectEqual(@as(usize, 97), ec.point.len);
            try testing.expectEqual(@as(u8, 0x04), ec.point[0]);
        },
        else => return error.TestExpectedEcdsaMaterial,
    }
}

test "ECDSA on unsupported curve OID is surfaced as Unsupported" {
    // Use the brainpoolP256r1 OID (1.3.36.3.3.2.8.1.1.7), which is
    // a real curve we don't accept.
    const brainpool_oid = [_]u8{ 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
    var body: [1 + 4 + 1 + 1 + brainpool_oid.len + 2 + 65]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 19;
    body[6] = brainpool_oid.len;
    @memcpy(body[7 .. 7 + brainpool_oid.len], &brainpool_oid);
    const mpi_off = 7 + brainpool_oid.len;
    body[mpi_off] = 0x02;
    body[mpi_off + 1] = 0x03;
    body[mpi_off + 2] = 0x04;
    @memset(body[mpi_off + 3 ..], 0xCC);

    const pk = try parseBody(&body);
    switch (pk.material) {
        .unsupported => |a| try testing.expectEqual(Algorithm.ecdsa, a),
        else => return error.TestExpectedUnsupportedMaterial,
    }
}

test "ECDSA with malformed point (wrong length) is surfaced as Unsupported" {
    // P-256 OID but a 33-byte point — neither uncompressed (65) nor
    // compressed (33 with leading 0x02/0x03 starts with 0x04 — but
    // we explicitly reject anything other than the uncompressed
    // length for the curve).
    var body: [1 + 4 + 1 + 1 + 8 + 2 + 33]u8 = undefined;
    body[0] = 0x04;
    @memset(body[1..5], 0);
    body[5] = 19;
    body[6] = OID_NIST_P256.len;
    @memcpy(body[7..15], &OID_NIST_P256);
    // MPI(Q): bit_length 263 = 0x0107, 33 bytes payload.
    body[15] = 0x01;
    body[16] = 0x07;
    body[17] = 0x04;
    @memset(body[18..50], 0xBB);

    const pk = try parseBody(&body);
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
