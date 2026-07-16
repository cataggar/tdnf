//! OpenPGP keyring parser with subkey binding-signature verification.
//!
//! Phase C, PR #6 of the pure-Zig PGP verifier plan
//! (plan-pure-zig-pgp.md, section 5). Parses a single
//! `gpg-pubkey-*`-shaped blob (armored or binary) into a typed
//! `Keyring` whose entries carry an authenticated trust state:
//! every subkey's type-0x18 binding signature from the primary
//! key, and the embedded type-0x19 back-sig produced by the
//! subkey itself, are verified before `binding_ok = true` is set.
//!
//! Hash framing for both 0x18 and 0x19 (RFC 4880 §5.2.4 — "Subkey
//! Binding Signature" and "Primary Key Binding Signature"):
//!
//!   HASH( 0x99 || BE16(primary_body_len) || primary_body ||
//!         0x99 || BE16(subkey_body_len)  || subkey_body  ||
//!         sig.hashed_prefix ||
//!         0x04 || 0xFF || BE32(sig.hashed_prefix.len) )
//!
//! The 0x18 sig is verified with the primary key as signer. The
//! embedded 0x19 back-sig — carried as the Embedded Signature
//! subpacket (type 32, RFC 4880 §5.2.3.26) inside the 0x18 sig's
//! hashed or unhashed area — is verified with the subkey as signer over the
//! same framing.
//!
//! Conservative trust posture: PR #6 requires a valid back-sig for
//! *every* subkey we are willing to surface as `binding_ok = true`,
//! including subkeys with the Key Flags signing bit (0x02) cleared.
//! This is stricter than RFC 4880 strictly requires (the spec only
//! mandates the back-sig for signing-capable subkeys) but it makes
//! the trust decision uniform — a subkey is trustworthy as a sig
//! issuer iff both the primary's binding and the subkey's
//! reciprocal back-sig validate.
//!
//! RSA-only in PR #6 — non-RSA primary or subkeys leave the entry
//! in the list with `binding_ok = false`. The rest of the PGP
//! algorithm matrix lands in PRs #8 and #9.

const std = @import("std");

const armor = @import("armor.zig");
const packet = @import("packet.zig");
const pubkey = @import("pubkey.zig");
const signature = @import("signature.zig");

pub const KeyKind = enum { primary, subkey };

pub const KeyEntry = struct {
    kind: KeyKind,
    /// Slices into `Keyring.blob`. The keyring owns the backing
    /// buffer, so entries are valid for the lifetime of the parent
    /// `Keyring`.
    key: pubkey.PublicKey,
    fingerprint: pubkey.Fingerprint,
    /// True iff this entry can be safely treated as a signature
    /// issuer. For the primary key this is always true. For a
    /// subkey it is set only after a type-0x18 binding signature
    /// from the primary AND an embedded type-0x19 back-sig from
    /// the subkey itself both verify against the canonical
    /// (primary, subkey) hash framing.
    binding_ok: bool,
};

pub const Keyring = struct {
    allocator: std.mem.Allocator,
    /// Owned dearmored blob bytes. `KeyEntry.key.body` and the MPI
    /// slices inside the key material alias into this buffer;
    /// freeing it before the keyring would dangle.
    blob: []u8,
    entries: []KeyEntry,

    pub fn deinit(self: *Keyring) void {
        self.allocator.free(self.blob);
        self.allocator.free(self.entries);
        self.blob = &.{};
        self.entries = &.{};
    }
};

pub const ParseError = error{
    EmptyKeyring,
    PrimaryNotFirst,
    MalformedSignature,
} || armor.ArmorError || std.mem.Allocator.Error;

/// Parse a single `gpg-pubkey-*` blob (armored or binary; auto-
/// detected via `armor.decodeAny`) into a typed keyring.
///
/// Walks the packet stream once. The first packet must be a Tag 6
/// (Public-Key) primary; any subsequent Tag 14 (Public-Subkey)
/// packets are paired with the *next* Tag 2 (Signature) packet of
/// type 0x18 to verify their binding. Tag 2 packets unrelated to a
/// subkey (e.g. self-signatures over a User ID) are silently
/// skipped — PR #6 only needs subkey trust state. User ID / User
/// Attribute packets between the subkey and its binding sig are
/// likewise skipped.
pub fn parse(allocator: std.mem.Allocator, key_blob: []const u8) ParseError!Keyring {
    var decoded = try armor.decodeAny(allocator, key_blob);
    errdefer decoded.deinit();

    var entries = std.array_list.Managed(KeyEntry).init(allocator);
    errdefer entries.deinit();

    var it = packet.iterate(decoded.bytes);

    // First packet MUST be the primary public key.
    const first_pkt = (it.next() catch return error.MalformedSignature) orelse
        return error.EmptyKeyring;
    if (first_pkt.tag != .public_key) return error.PrimaryNotFirst;

    const primary_pk = pubkey.parseBody(first_pkt.body) catch
        return error.MalformedSignature;
    const primary_fpr = pubkey.fingerprint(primary_pk);
    const primary_body = first_pkt.body;

    try entries.append(.{
        .kind = .primary,
        .key = primary_pk,
        .fingerprint = primary_fpr,
        .binding_ok = true,
    });

    // State: index in `entries` of the most-recently-seen subkey
    // that is still awaiting its binding signature. Cleared once
    // we consume a Tag 2 for it (regardless of verification
    // outcome) so a single subkey can't be "rebound" by a later
    // attacker-supplied sig with stronger framing.
    var pending_sub: ?struct {
        idx: usize,
        body: []const u8,
        pk: pubkey.PublicKey,
    } = null;

    while (it.next() catch null) |pkt| {
        switch (pkt.tag) {
            .public_subkey => {
                const sub_pk = pubkey.parseBody(pkt.body) catch continue;
                try entries.append(.{
                    .kind = .subkey,
                    .key = sub_pk,
                    .fingerprint = pubkey.fingerprint(sub_pk),
                    .binding_ok = false,
                });
                pending_sub = .{
                    .idx = entries.items.len - 1,
                    .body = pkt.body,
                    .pk = sub_pk,
                };
            },
            .signature => {
                const ps = pending_sub orelse continue;
                const sig = signature.parseBody(pkt.body) catch continue;
                if (sig.sig_type != .subkey_binding) continue;

                const ok = verifyBinding(
                    primary_pk,
                    primary_body,
                    primary_fpr,
                    ps.pk,
                    ps.body,
                    entries.items[ps.idx].fingerprint,
                    sig,
                );
                if (ok) entries.items[ps.idx].binding_ok = true;
                pending_sub = null;
            },
            else => {
                // User ID / User Attribute / any other packet: keep
                // scanning. We don't drop `pending_sub` here so a
                // binding sig that follows after a self-sig over a
                // User ID still binds the subkey — though in
                // practice subkey binding sigs immediately follow
                // the subkey packet (RFC 4880 §11.1).
            },
        }
    }

    const entries_owned = try entries.toOwnedSlice();
    return Keyring{
        .allocator = allocator,
        .blob = decoded.bytes,
        .entries = entries_owned,
    };
}

/// Verify the binding chain for one subkey: the type-0x18 sig from
/// the primary and the embedded type-0x19 back-sig from the
/// subkey. Returns `true` only if both succeed.
fn verifyBinding(
    primary_pk: pubkey.PublicKey,
    primary_body: []const u8,
    primary_fpr: pubkey.Fingerprint,
    subkey_pk: pubkey.PublicKey,
    subkey_body: []const u8,
    subkey_fpr: pubkey.Fingerprint,
    binding_sig: signature.Signature,
) bool {
    if (primary_pk.version != 4 or subkey_pk.version != 4 or binding_sig.version != 4)
        return false;

    // ----- Issuer match: hashed Issuer Fingerprint == primary fpr.
    // We accept Issuer Key ID (type 16) as a fallback for older
    // generators that don't emit type 33, matching the policy in
    // verify.zig.
    if (binding_sig.issuerFingerprint()) |fpr_slice| {
        if (fpr_slice.len != 20) return false;
        if (!std.crypto.timing_safe.eql([20]u8, fpr_slice[0..20].*, primary_fpr.bytes[0..20].*))
            return false;
    } else if (binding_sig.issuerKeyId()) |kid| {
        if (!std.crypto.timing_safe.eql([8]u8, kid, primary_fpr.keyId()))
            return false;
    } else return false;

    // Frame primary + subkey bodies for the hash input.
    var primary_frame: [3]u8 = .{
        0x99,
        @intCast((primary_body.len >> 8) & 0xFF),
        @intCast(primary_body.len & 0xFF),
    };
    var subkey_frame: [3]u8 = .{
        0x99,
        @intCast((subkey_body.len >> 8) & 0xFF),
        @intCast(subkey_body.len & 0xFF),
    };
    const parts = [_][]const u8{
        &primary_frame, primary_body,
        &subkey_frame,  subkey_body,
    };

    // ----- (1) Verify the type-0x18 sig signed by the primary.
    if (!verifyRsaSig(primary_pk, binding_sig, &parts)) return false;

    // ----- (2) Locate + verify the embedded type-0x19 back-sig.
    const backsig_body =
        findEmbeddedSignature(binding_sig.hashed_subpackets) orelse
        findEmbeddedSignature(binding_sig.unhashed_subpackets) orelse
        return false;
    const backsig = signature.parseBody(backsig_body) catch return false;
    if (backsig.sig_type != .primary_key_binding) return false;

    // Issuer of back-sig must be the subkey.
    if (backsig.issuerFingerprint()) |fpr_slice| {
        if (fpr_slice.len != 20) return false;
        if (!std.crypto.timing_safe.eql([20]u8, fpr_slice[0..20].*, subkey_fpr.bytes[0..20].*))
            return false;
    } else if (backsig.issuerKeyId()) |kid| {
        if (!std.crypto.timing_safe.eql([8]u8, kid, subkey_fpr.keyId()))
            return false;
    } else return false;

    if (!verifyRsaSig(subkey_pk, backsig, &parts)) return false;

    return true;
}

/// Return the Embedded Signature subpacket payload (subpacket type
/// 32, RFC 4880 §5.2.3.26) from a hashed-subpacket area, or null.
fn findEmbeddedSignature(area: []const u8) ?[]const u8 {
    var it = signature.iterateSubpackets(area);
    while (it.next() catch return null) |sub| {
        if (sub.type_id == 32) return sub.data;
    }
    return null;
}

/// RSA-PKCS#1 v1.5 verify of `sig` (made by `signer`) over the
/// concatenation of `prefix_parts` || sig.hashed_prefix || sig
/// trailer. Non-RSA signer keys, unsupported algorithms, and
/// unsupported moduli all return false (the keyring caller treats
/// these as failed bindings rather than internal errors).
fn verifyRsaSig(
    signer: pubkey.PublicKey,
    sig: signature.Signature,
    prefix_parts: []const []const u8,
) bool {
    const rsa_signer = switch (signer.material) {
        .rsa => |k| k,
        else => return false,
    };
    const rsa_sig_mpi = switch (sig.material) {
        .rsa => |m| m,
        else => return false,
    };
    if (sig.sig_type != .subkey_binding and sig.sig_type != .primary_key_binding) {
        return false;
    }

    const HashKind = enum { sha256, sha512 };
    const hash_kind: HashKind = switch (sig.hash_algo) {
        .sha256 => .sha256,
        .sha512 => .sha512,
        else => return false,
    };

    const prefix_len: u32 = @intCast(sig.hashed_prefix.len);
    const trailer: [6]u8 = .{
        0x04,                                0xFF,
        @intCast((prefix_len >> 24) & 0xFF), @intCast((prefix_len >> 16) & 0xFF),
        @intCast((prefix_len >> 8) & 0xFF),  @intCast(prefix_len & 0xFF),
    };

    // Hash hint short-circuit — matches verify.zig PR #5's
    // ordering: compute the digest twice (cheap) but reject
    // obvious mismatches before touching the RSA core.
    const hint_ok = switch (hash_kind) {
        .sha256 => blk: {
            var d: [32]u8 = undefined;
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            for (prefix_parts) |p| h.update(p);
            h.update(sig.hashed_prefix);
            h.update(&trailer);
            h.final(&d);
            break :blk d[0] == sig.hash_hint[0] and d[1] == sig.hash_hint[1];
        },
        .sha512 => blk: {
            var d: [64]u8 = undefined;
            var h = std.crypto.hash.sha2.Sha512.init(.{});
            for (prefix_parts) |p| h.update(p);
            h.update(sig.hashed_prefix);
            h.update(&trailer);
            h.final(&d);
            break :blk d[0] == sig.hash_hint[0] and d[1] == sig.hash_hint[1];
        },
    };
    if (!hint_ok) return false;

    if (rsa_signer.e.bytes.len == 0 or rsa_signer.e.bytes.len > 4) return false;
    if (rsa_signer.n.bytes.len == 0) return false;
    const stdrsa = std.crypto.Certificate.rsa;
    const pkey = stdrsa.PublicKey.fromBytes(rsa_signer.e.bytes, rsa_signer.n.bytes) catch
        return false;

    const modulus_len = rsa_signer.n.bytes.len;
    if (rsa_sig_mpi.bytes.len > modulus_len) return false;

    // Build the full msg_parts list on the stack: caller's prefix
    // parts + hashed_prefix + trailer.
    var stack_parts: [8][]const u8 = undefined;
    if (prefix_parts.len + 2 > stack_parts.len) return false;
    for (prefix_parts, 0..) |p, i| stack_parts[i] = p;
    stack_parts[prefix_parts.len] = sig.hashed_prefix;
    stack_parts[prefix_parts.len + 1] = &trailer;
    const msg_parts = stack_parts[0 .. prefix_parts.len + 2];

    inline for (.{ 256, 384, 512 }) |comptime_mod_len| {
        if (modulus_len == comptime_mod_len) {
            var sig_buf: [comptime_mod_len]u8 = @splat(0);
            const off = comptime_mod_len - rsa_sig_mpi.bytes.len;
            @memcpy(sig_buf[off..], rsa_sig_mpi.bytes);
            const verdict = switch (hash_kind) {
                .sha256 => stdrsa.PKCS1v1_5Signature.concatVerify(
                    comptime_mod_len,
                    sig_buf,
                    msg_parts,
                    pkey,
                    std.crypto.hash.sha2.Sha256,
                ),
                .sha512 => stdrsa.PKCS1v1_5Signature.concatVerify(
                    comptime_mod_len,
                    sig_buf,
                    msg_parts,
                    pkey,
                    std.crypto.hash.sha2.Sha512,
                ),
            };
            verdict catch return false;
            return true;
        }
    }
    return false;
}

// =====================================================================
// Tests
// =====================================================================

const testing = std.testing;

const fixture_keyring = @embedFile("testdata/rsa-primary-subkey-keyring.bin");
const fixture_keyring_data = @embedFile("testdata/rsa-primary-subkey-data.bin");
const fixture_keyring_sig = @embedFile("testdata/rsa-primary-subkey-sig.bin");

test "parse keyring with primary + signing subkey + valid bindings" {
    var kr = try parse(testing.allocator, fixture_keyring);
    defer kr.deinit();

    try testing.expect(kr.entries.len >= 2);
    try testing.expectEqual(KeyKind.primary, kr.entries[0].kind);
    try testing.expect(kr.entries[0].binding_ok);
    try testing.expectEqual(KeyKind.subkey, kr.entries[1].kind);
    try testing.expect(kr.entries[1].binding_ok);
    // Primary and subkey have different fingerprints.
    try testing.expect(!std.mem.eql(
        u8,
        kr.entries[0].fingerprint.slice(),
        kr.entries[1].fingerprint.slice(),
    ));
}

test "reject keyring with no Tag 6 primary" {
    // Hand-craft a tiny blob whose first packet is anything other
    // than Tag 6. Old-format Tag 13 (User ID): tag byte
    // `0x80 | (13 << 2) | 1` = 0xB5, then BE16(0) body length.
    const blob = [_]u8{ 0xB5, 0x00, 0x00 };
    try testing.expectError(error.PrimaryNotFirst, parse(testing.allocator, &blob));
}

test "reject empty keyring" {
    // A truly empty blob — `armor.decodeAny` will pass it through
    // as-is (no `-----BEGIN` marker → binary path), and the
    // packet iterator returns null on the first call.
    try testing.expectError(error.EmptyKeyring, parse(testing.allocator, ""));
}

test "subkey with tampered binding sig is rejected" {
    // Duplicate the fixture and flip a byte deep inside the Tag 2
    // binding signature's MPI payload — late enough to clear the
    // header, hashed area, hash hint, and Embedded Signature
    // subpacket. The binding sig is the *last* packet in the
    // fixture so the very last byte is part of the RSA sig MPI.
    var tampered = try testing.allocator.dupe(u8, fixture_keyring);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xFF;

    var kr = try parse(testing.allocator, tampered);
    defer kr.deinit();

    try testing.expect(kr.entries.len >= 2);
    try testing.expect(kr.entries[0].binding_ok); // primary unaffected
    try testing.expect(!kr.entries[1].binding_ok); // subkey now untrusted
}

test "subkey with valid 0x18 but missing back-sig fails" {
    // Strip the Embedded Signature subpacket (type 32) from the
    // hashed area of the binding sig, then re-serialise the
    // keyring. The 0x18 sig will no longer validate because its
    // hashed-prefix length encoded in the trailer drops, but more
    // importantly the back-sig is gone so binding_ok must be
    // false even on the hypothetical the 0x18 still parsed.

    // Re-fetch the binding sig packet to find offsets.
    var dec = try armor.decodeAny(testing.allocator, fixture_keyring);
    defer dec.deinit();

    var it = packet.iterate(dec.bytes);
    var sig_pkt: ?packet.Packet = null;
    while (it.next() catch null) |pkt| {
        if (pkt.tag == .signature) {
            sig_pkt = pkt;
            break;
        }
    }
    const sig = signature.parseBody(sig_pkt.?.body) catch unreachable;

    // Find the Embedded Signature subpacket and its byte range
    // inside the hashed area.
    const hashed_off = @intFromPtr(sig.hashed_subpackets.ptr) - @intFromPtr(dec.bytes.ptr);
    var emb_data_off_in_area: usize = 0;
    var emb_data_len: usize = 0;
    // Walk the bytes the same way signature.SubpacketIterator does
    // so we can recover the subpacket *header* length too (the
    // public iterator only surfaces the inner data slice).
    var rest = sig.hashed_subpackets;
    while (rest.len > 0) {
        const b1 = rest[0];
        var sub_len: usize = undefined;
        var header_len: usize = undefined;
        if (b1 < 192) {
            sub_len = b1;
            header_len = 1;
        } else if (b1 < 255) {
            sub_len = (@as(usize, b1 - 192) << 8) + @as(usize, rest[1]) + 192;
            header_len = 2;
        } else {
            sub_len = (@as(usize, rest[1]) << 24) | (@as(usize, rest[2]) << 16) |
                (@as(usize, rest[3]) << 8) | @as(usize, rest[4]);
            header_len = 5;
        }
        const type_id = rest[header_len] & 0x7F;
        if (type_id == 32) {
            const off_in_area = sig.hashed_subpackets.len - rest.len;
            emb_data_off_in_area = off_in_area;
            emb_data_len = header_len + sub_len;
            break;
        }
        rest = rest[header_len + sub_len ..];
    }
    try testing.expect(emb_data_len > 0);

    // Stripped blob: everything before the Embedded subpacket,
    // then everything after it. Because we're shortening the
    // hashed area, the hashed-subpacket-length BE16 in the sig
    // body and the Tag 2 packet's old-format BE16 length both
    // need to be patched.
    const strip_off = hashed_off + emb_data_off_in_area;
    const strip_len = emb_data_len;

    var stripped = try testing.allocator.alloc(u8, dec.bytes.len - strip_len);
    defer testing.allocator.free(stripped);
    @memcpy(stripped[0..strip_off], dec.bytes[0..strip_off]);
    @memcpy(stripped[strip_off..], dec.bytes[strip_off + strip_len ..]);

    // Patch the Tag 2 packet body-length BE16. The sig packet
    // header is `0x89 || BE16(body_len)`; we find it by scanning
    // for the 0x89 byte that precedes our hashed_off.
    var pkt_hdr_off: usize = 0;
    var s: usize = 0;
    while (s < strip_off) : (s += 1) {
        if (stripped[s] == 0x89) pkt_hdr_off = s;
    }
    const old_body_len = (@as(usize, dec.bytes[pkt_hdr_off + 1]) << 8) |
        @as(usize, dec.bytes[pkt_hdr_off + 2]);
    const new_body_len = old_body_len - strip_len;
    stripped[pkt_hdr_off + 1] = @intCast((new_body_len >> 8) & 0xFF);
    stripped[pkt_hdr_off + 2] = @intCast(new_body_len & 0xFF);

    // Patch the hashed-subpacket-length BE16 in the sig body.
    // The body starts at pkt_hdr_off + 3, and the hashed-sub-len
    // word lives at offset 4..6 within the body.
    const hashed_len_off = pkt_hdr_off + 3 + 4;
    const old_hashed_len = (@as(usize, dec.bytes[hashed_len_off]) << 8) |
        @as(usize, dec.bytes[hashed_len_off + 1]);
    const new_hashed_len = old_hashed_len - strip_len;
    stripped[hashed_len_off] = @intCast((new_hashed_len >> 8) & 0xFF);
    stripped[hashed_len_off + 1] = @intCast(new_hashed_len & 0xFF);

    var kr = try parse(testing.allocator, stripped);
    defer kr.deinit();
    try testing.expect(kr.entries.len >= 2);
    try testing.expect(kr.entries[0].binding_ok);
    // The 0x18 sig itself no longer hashes correctly (we changed
    // its hashed_prefix length) — and the back-sig is gone — so
    // binding_ok must be false.
    try testing.expect(!kr.entries[1].binding_ok);
}

test "primary key always binding_ok = true" {
    var kr = try parse(testing.allocator, fixture_keyring);
    defer kr.deinit();
    try testing.expectEqual(KeyKind.primary, kr.entries[0].kind);
    try testing.expect(kr.entries[0].binding_ok);
}

test "fixture detached sig is signed by the subkey, not the primary" {
    // Sanity check on the test fixture: the Tag 2 in
    // rsa-primary-subkey-sig.bin has an Issuer Fingerprint that
    // matches the keyring's *subkey*, not the primary. If this
    // ever drifts the verifyDetached integration test below
    // becomes a false-pass.
    var kr = try parse(testing.allocator, fixture_keyring);
    defer kr.deinit();

    var it = packet.iterate(fixture_keyring_sig);
    const pkt = (try it.next()).?;
    try testing.expectEqual(packet.Tag.signature, pkt.tag);
    const sig = try signature.parseBody(pkt.body);
    const fpr = sig.issuerFingerprint().?;
    try testing.expectEqual(@as(usize, 20), fpr.len);
    try testing.expectEqualSlices(u8, kr.entries[1].fingerprint.slice(), fpr);
}
