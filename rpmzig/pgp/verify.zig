//! Top-level OpenPGP signature verifier — PR #5 of plan-pure-zig-pgp.md.
//!
//! Combines `armor` (PR #1), `packet` (PR #2), `pubkey` (PR #3) and
//! `signature` (PR #4) with `std.crypto.Certificate.rsa` to implement
//! RSA-PKCS#1v1.5 verification of v4 OpenPGP detached signatures.
//!
//! Scope, narrow by design (per plan section 5 "PR #5"):
//!
//!   * RSA only. ECDSA / Ed25519 / EdDSALegacy land in PRs #8 / #9.
//!   * SHA-256 + SHA-512 only. SHA-1 stays disabled until a policy
//!     knob lands (legacy keys only — Sequoia rejects SHA-1 since
//!     Feb 2023). SHA-384 is unused in practice.
//!   * Binary signature type (0x00) only. PR #6 adds subkey-binding
//!     (0x18) and back-sig (0x19) verification.
//!   * Subkey trust without binding-sig verification — i.e. a Tag 14
//!     subkey is accepted as a fingerprint match candidate, but the
//!     0x18 signature that ties it to its primary key is NOT yet
//!     validated. PR #6 closes this gap.
//!
//! Out-of-scope cases coerce to `.internal`. PR #7 wires this
//! verifier alongside the gpgme path for a log-only cross-check;
//! subsequent PRs shrink the `.internal` surface to zero.

const std = @import("std");

const armor = @import("armor.zig");
const packet = @import("packet.zig");
const pubkey = @import("pubkey.zig");
const signature = @import("signature.zig");

/// Verification verdict. Numeric values must stay in lock-step with
/// the C `TDNF_RPMZIG_VERIFY_*` constants in `rpmzig/verify.h` —
/// callers compare against them directly.
pub const Status = enum(c_int) {
    ok = 0,
    no_sig = 1,
    no_key = 2,
    bad = 3,
    /// Catch-all for "we couldn't decide": unsupported algorithm,
    /// unsupported signature type, malformed input that isn't
    /// clearly a forgery, allocator failure, etc. Numerically
    /// identical to `TDNF_RPMZIG_VERIFY_GPGME_ERROR` so the C side
    /// can compare the value without knowing which verifier ran.
    internal = 4,
};

/// Verify a single OpenPGP detached signature blob over `signed_data`,
/// against the supplied keyring. Returns a verdict; never raises.
///
/// * `sig_pkt_bytes` — the binary OpenPGP Signature packet (Tag 2),
///   header included. ASCII armor is NOT accepted here (sig packets
///   embedded in `.rpm` files are always binary). Wrap with
///   `armor.decodeAny` first if the caller has armored input.
/// * `signed_data` — the bytes the signature covers, verbatim.
/// * `key_blobs` — each entry is an OpenPGP public-key blob, armored
///   or binary; armor is auto-detected. A single blob may contain a
///   primary key and any number of subkeys; all of them are
///   considered when looking for the issuer.
pub fn verifyDetached(
    allocator: std.mem.Allocator,
    sig_pkt_bytes: []const u8,
    signed_data: []const u8,
    key_blobs: []const []const u8,
) Status {
    // --- 1. Decode the signature packet. ----------------------------
    var sig_iter = packet.iterate(sig_pkt_bytes);
    const first = (sig_iter.next() catch return .bad) orelse return .no_sig;
    if (first.tag != .signature) return .bad;
    const sig = signature.parseBody(first.body) catch return .bad;
    // signature.parseBody enforces v4 already.

    // --- 2. PR #5 scope filter. -------------------------------------
    if (sig.sig_type != .binary_document) return .internal;
    const HashKind = enum { sha256, sha512 };
    const hash_kind: HashKind = switch (sig.hash_algo) {
        .sha256 => .sha256,
        .sha512 => .sha512,
        else => return .internal,
    };
    const sig_rsa_mpi = switch (sig.material) {
        .rsa => |m| m,
        else => return .internal,
    };

    // --- 3. Locate the issuer identity. -----------------------------
    const IssuerKind = enum { fpr, kid };
    var issuer_kind: IssuerKind = undefined;
    var issuer_fpr_buf: [20]u8 = undefined;
    var issuer_keyid: [8]u8 = undefined;

    if (sig.issuerFingerprint()) |fpr_slice| {
        if (fpr_slice.len != 20) return .bad;
        @memcpy(&issuer_fpr_buf, fpr_slice);
        issuer_kind = .fpr;
    } else if (sig.issuerKeyId()) |kid| {
        issuer_keyid = kid;
        issuer_kind = .kid;
    } else {
        return .bad;
    }

    // --- 4. Walk the keyring; find a matching public key. -----------
    //
    // Each iteration owns a freshly-dearmored buffer; the parsed
    // `PublicKey` slices into that buffer (RSA MPI payloads, the
    // packet body, etc.). When we find a match we hand ownership of
    // the buffer to `matched_owner` so the slices stay valid past
    // the end of the loop. Non-matching buffers are freed eagerly.
    var matched: ?pubkey.PublicKey = null;
    var matched_owner: ?armor.DecodedKey = null;
    defer if (matched_owner) |*m| m.deinit();

    outer: for (key_blobs) |raw| {
        var dec = armor.decodeAny(allocator, raw) catch return .internal;
        var consumed = false;
        defer if (!consumed) dec.deinit();

        var it = packet.iterate(dec.bytes);
        while (it.next() catch break) |pkt| {
            if (pkt.tag != .public_key and pkt.tag != .public_subkey) continue;
            const pk = pubkey.parseBody(pkt.body) catch continue;
            const fpr = pubkey.fingerprintV4(pkt.body);
            const is_match = switch (issuer_kind) {
                .fpr => std.crypto.timing_safe.eql([20]u8, fpr.bytes, issuer_fpr_buf),
                .kid => std.crypto.timing_safe.eql([8]u8, fpr.keyId(), issuer_keyid),
            };
            if (is_match) {
                matched = pk;
                matched_owner = dec;
                consumed = true;
                break :outer;
            }
        }
    }
    const matched_pk = matched orelse return .no_key;
    const rsa_key = switch (matched_pk.material) {
        .rsa => |k| k,
        else => return .internal,
    };

    // --- 5. Compute the hash hint + digest fast-path. ---------------
    // Hash input (RFC 4880 §5.2.4 v4 detached, sig_type 0x00):
    //   HASH( signed_data || sig.hashed_prefix || 0x04 || 0xFF ||
    //         BE32(sig.hashed_prefix.len) )
    //
    // We compute the digest twice — once here for the 2-byte hash
    // hint short-circuit, and once again inside `concatVerify`. The
    // hint check is cheap (two hash ops are negligible next to a
    // single modexp) and lets us reject obvious mismatches before
    // ever touching the RSA core, which is the path attackers care
    // about.
    const prefix_len: u32 = @intCast(sig.hashed_prefix.len);
    const trailer: [6]u8 = .{
        0x04,
        0xFF,
        @intCast((prefix_len >> 24) & 0xFF),
        @intCast((prefix_len >> 16) & 0xFF),
        @intCast((prefix_len >> 8) & 0xFF),
        @intCast(prefix_len & 0xFF),
    };

    const hint_ok = switch (hash_kind) {
        .sha256 => blk: {
            var d: [32]u8 = undefined;
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(signed_data);
            h.update(sig.hashed_prefix);
            h.update(&trailer);
            h.final(&d);
            break :blk d[0] == sig.hash_hint[0] and d[1] == sig.hash_hint[1];
        },
        .sha512 => blk: {
            var d: [64]u8 = undefined;
            var h = std.crypto.hash.sha2.Sha512.init(.{});
            h.update(signed_data);
            h.update(sig.hashed_prefix);
            h.update(&trailer);
            h.final(&d);
            break :blk d[0] == sig.hash_hint[0] and d[1] == sig.hash_hint[1];
        },
    };
    if (!hint_ok) return .bad;

    // --- 6. RSA-PKCS#1v1.5 verify. ----------------------------------
    // Build a std.crypto rsa.PublicKey. The MPIs already have leading
    // zero bytes stripped by `packet.readMpi`. fromBytes argument
    // order is (exponent, modulus).
    if (rsa_key.e.bytes.len == 0 or rsa_key.e.bytes.len > 4) return .internal;
    if (rsa_key.n.bytes.len == 0) return .internal;
    const stdrsa = std.crypto.Certificate.rsa;
    const pkey = stdrsa.PublicKey.fromBytes(rsa_key.e.bytes, rsa_key.n.bytes) catch
        return .internal;

    // Pad the signature MPI back out to the modulus length (MPI
    // decoding strips any leading zero bytes that the wire format
    // happens to emit). RSA-PKCS1v1_5 requires the sig to be exactly
    // modulus_len bytes; std.crypto's verify takes a comptime-sized
    // array so we dispatch over the small set of supported moduli.
    //
    // `concatVerify` takes a `msg: []const []const u8` and hashes
    // each part in order — exactly the OpenPGP composite. We rely on
    // it to also re-hash internally; the duplicate work is bounded
    // and keeps the cryptographic core in stdlib.
    const modulus_len = rsa_key.n.bytes.len;
    if (sig_rsa_mpi.bytes.len > modulus_len) return .bad;

    const msg_parts = &[_][]const u8{ signed_data, sig.hashed_prefix, &trailer };

    inline for (.{ 256, 384, 512 }) |comptime_mod_len| {
        if (modulus_len == comptime_mod_len) {
            var sig_buf: [comptime_mod_len]u8 = @splat(0);
            const off = comptime_mod_len - sig_rsa_mpi.bytes.len;
            @memcpy(sig_buf[off..], sig_rsa_mpi.bytes);
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
            verdict catch return .bad;
            return .ok;
        }
    }
    // RSA modulus length we don't support (e.g. RSA-1024 or RSA-8192).
    return .no_key;
}

// =====================================================================
// Tests
// =====================================================================

const testing = std.testing;

const fixture_pubkey = @embedFile("testdata/rsa2048-pubkey.bin");
const fixture_sig = @embedFile("testdata/rsa2048-sig.bin");
const fixture_data = @embedFile("testdata/rsa2048-data.bin");
const microsoft_key = @embedFile("testdata/microsoft-rpm-key.bin");

test "RSA-2048 + SHA-256 happy path" {
    const keys = [_][]const u8{fixture_pubkey};
    const status = verifyDetached(
        testing.allocator,
        fixture_sig,
        fixture_data,
        &keys,
    );
    try testing.expectEqual(Status.ok, status);
}

test "tampered signed data → bad" {
    var tampered = try testing.allocator.dupe(u8, fixture_data);
    defer testing.allocator.free(tampered);
    tampered[0] ^= 0x01;
    const keys = [_][]const u8{fixture_pubkey};
    const status = verifyDetached(testing.allocator, fixture_sig, tampered, &keys);
    try testing.expectEqual(Status.bad, status);
}

test "missing key → no_key" {
    const keys = [_][]const u8{microsoft_key};
    const status = verifyDetached(testing.allocator, fixture_sig, fixture_data, &keys);
    try testing.expectEqual(Status.no_key, status);
}

test "empty keyring → no_key" {
    const keys = [_][]const u8{};
    const status = verifyDetached(testing.allocator, fixture_sig, fixture_data, &keys);
    try testing.expectEqual(Status.no_key, status);
}

test "tampered signature MPI → bad" {
    var bad_sig = try testing.allocator.dupe(u8, fixture_sig);
    defer testing.allocator.free(bad_sig);
    // Flip a byte deep in the MPI body — past the header, hashed
    // area and hash hint. The packet is 304 bytes; the MPI payload
    // lives in the last ~256.
    bad_sig[bad_sig.len - 16] ^= 0xFF;
    const keys = [_][]const u8{fixture_pubkey};
    const status = verifyDetached(testing.allocator, bad_sig, fixture_data, &keys);
    try testing.expectEqual(Status.bad, status);
}

test "malformed signature packet → bad/no_sig" {
    // Truncate the sig packet to just the first byte of the header.
    const bad: []const u8 = fixture_sig[0..1];
    const keys = [_][]const u8{fixture_pubkey};
    const status = verifyDetached(testing.allocator, bad, fixture_data, &keys);
    // Either bad (parse failure) or no_sig (iterator returned null)
    // is acceptable here; both mean "no usable signature".
    try testing.expect(status == .bad or status == .no_sig);
}

// =====================================================================
// C ABI bridge (consumed by verify_pure.c).
// =====================================================================
//
// Slice-shaped Zig API doesn't survive across the C ABI; the C side
// passes (pointer, length) pairs. We synthesize slices here and
// delegate to `verifyDetached`. Allocation goes through the C
// `malloc`-backed allocator since we have no other handle.

export fn rpmzig_verify_detached(
    sig_bytes: [*]const u8,
    sig_len: usize,
    signed_bytes: [*]const u8,
    signed_len: usize,
    key_blobs: ?[*]const ?[*]const u8,
    key_lens: ?[*]const usize,
    key_count: usize,
) c_int {
    const allocator = std.heap.c_allocator;

    // Build the slice-of-slices keyring on the stack (capped) or on
    // the heap (uncapped). key_count is bounded by what the C
    // caller passes, which for the rpm verify path is the size of
    // the keyring (a few dozen at most). Use a small stack cap with
    // heap fallback to keep the common path allocation-free.
    var stack_buf: [32][]const u8 = undefined;
    var keys_slice: []const []const u8 = &.{};
    var heap_keys: ?[][]const u8 = null;
    defer if (heap_keys) |hk| allocator.free(hk);

    if (key_count == 0 or key_blobs == null or key_lens == null) {
        keys_slice = &.{};
    } else {
        const blobs = key_blobs.?;
        const lens = key_lens.?;
        if (key_count <= stack_buf.len) {
            for (0..key_count) |i| {
                const ptr = blobs[i] orelse return @intFromEnum(Status.internal);
                stack_buf[i] = ptr[0..lens[i]];
            }
            keys_slice = stack_buf[0..key_count];
        } else {
            const hk = allocator.alloc([]const u8, key_count) catch
                return @intFromEnum(Status.internal);
            heap_keys = hk;
            for (0..key_count) |i| {
                const ptr = blobs[i] orelse return @intFromEnum(Status.internal);
                hk[i] = ptr[0..lens[i]];
            }
            keys_slice = hk;
        }
    }

    const status = verifyDetached(
        allocator,
        sig_bytes[0..sig_len],
        signed_bytes[0..signed_len],
        keys_slice,
    );
    return @intFromEnum(status);
}
