//! Top-level OpenPGP signature verifier — PRs #5 + #6 + #9 of
//! plan-pure-zig-pgp.md.
//!
//! Combines `armor` (PR #1), `packet` (PR #2), `pubkey` (PR #3),
//! `signature` (PR #4) and `keyring` (PR #6) with
//! Top-level OpenPGP signature verifier — PRs #5 + #6 + #8 + #9 of
//! plan-pure-zig-pgp.md.
//!
//! Combines `armor` (PR #1), `packet` (PR #2), `pubkey` (PR #3),
//! `signature` (PR #4) and `keyring` (PR #6) with
//! `std.crypto.Certificate.rsa`, `std.crypto.sign.ecdsa` and
//! `std.crypto.sign.Ed25519` to verify v4 OpenPGP detached
//! signatures.
//!
//! Algorithms wired in so far:
//!
//!   * RSA-PKCS#1v1.5 + SHA-256 / SHA-512  (PR #5).
//!   * ECDSA P-256+SHA-256 / P-384+SHA-384 (PR #8). The curve/hash
//!     pairing is strict — RPM 4.20's rpmsign emits the matching
//!     pair; deviation suggests malformed input and is rejected as
//!     `.internal`.
//!   * Ed25519 — both native (algo 27, RFC 9580) and EdDSALegacy
//!     (algo 22, GnuPG `--openpgp` default) wire formats — with
//!     SHA-256 or SHA-512 (PR #9).
//!
//! Scope notes:
//!
//!   * SHA-1 stays disabled until a policy knob lands (legacy keys
//!     only — Sequoia rejects SHA-1 since Feb 2023). SHA-384 is
//!     accepted only when paired with ECDSA P-384.
//!   * Binary signature type (0x00) only. Subkey-binding (0x18)
//!     and back-sig (0x19) verification live in `keyring.zig`.
//!   * Subkey trust is gated on `keyring.parse` having verified
//!     the type-0x18 binding signature from the primary plus the
//!     embedded type-0x19 back-sig from the subkey. A subkey
//!     grafted onto a legitimate primary blob without a valid
//!     binding chain is rejected as `.no_key`.
//!
//! Out-of-scope cases coerce to `.internal`. PR #7 wires this
//! verifier alongside the gpgme path for a log-only cross-check;
//! subsequent PRs shrink the `.internal` surface to zero.

const std = @import("std");

const packet = @import("packet.zig");
const pubkey = @import("pubkey.zig");
const signature = @import("signature.zig");
const keyring = @import("keyring.zig");

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

const HashKind = enum { sha256, sha384, sha512 };

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

    // --- 2. Scope filter. -------------------------------------------
    if (sig.sig_type != .binary_document) return .internal;
    const hash_kind: HashKind = switch (sig.hash_algo) {
        .sha256 => .sha256,
        .sha384 => .sha384,
        .sha512 => .sha512,
        else => return .internal,
    };
    switch (sig.material) {
        .rsa, .ed25519, .eddsa_legacy, .ecdsa => {},
        else => return .internal,
    }

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
    // Each blob is parsed via `keyring.parse`, which dearmors it
    // and verifies each subkey's type-0x18 binding signature plus
    // the embedded type-0x19 back-sig. Entries whose binding
    // failed remain in the list with `binding_ok = false`; we
    // reject those as candidate signers — a malicious subkey
    // grafted onto a legitimate primary blob would never have a
    // valid binding chain so this closes the trust gap PR #5
    // left.
    //
    // The matching keyring owns the dearmored blob that backs the
    // selected `pubkey.PublicKey`'s slices, so we move it into
    // `matched_keyring` to keep the data alive past the loop.
    var matched: ?pubkey.PublicKey = null;
    var matched_keyring: ?keyring.Keyring = null;
    defer if (matched_keyring) |*k| k.deinit();

    outer: for (key_blobs) |raw| {
        var kr = keyring.parse(allocator, raw) catch continue;
        var consumed = false;
        defer if (!consumed) kr.deinit();

        for (kr.entries) |entry| {
            if (entry.kind == .subkey and !entry.binding_ok) continue;
            const is_match = switch (issuer_kind) {
                .fpr => std.crypto.timing_safe.eql([20]u8, entry.fingerprint.bytes, issuer_fpr_buf),
                .kid => std.crypto.timing_safe.eql([8]u8, entry.fingerprint.keyId(), issuer_keyid),
            };
            if (is_match) {
                matched = entry.key;
                matched_keyring = kr;
                consumed = true;
                break :outer;
            }
        }
    }
    const matched_pk = matched orelse return .no_key;

    // --- 5. Compute the hash trailer + digest. ----------------------
    // Hash input (RFC 4880 §5.2.4 v4 detached, sig_type 0x00):
    //   HASH( signed_data || sig.hashed_prefix || 0x04 || 0xFF ||
    //         BE32(sig.hashed_prefix.len) )
    //
    // For Ed25519 / EdDSALegacy we feed the *digest* bytes to
    // Ed25519's `verify` (per RFC 9580 §5.2.3 / RFC 4880bis: the
    // OpenPGP-declared hash algo digests the data, then the digest
    // is fed to the EdDSA primitive — Ed25519 itself then hashes
    // that with SHA-512 internally). Confirmed against a real gpg
    // detached sig fixture before commit.
    //
    // ECDSA (PR #8) similarly takes the prehashed digest, then
    // `verifyPrehashed` performs the curve arithmetic. Curve / hash
    // pairing is enforced inside `verifyEcdsa`.
    //
    // For RSA-PKCS#1v1.5 we still want the digest available for
    // the 2-byte hash-hint short-circuit; the heavier
    // `concatVerify` recomputes the digest internally.
    const prefix_len: u32 = @intCast(sig.hashed_prefix.len);
    const trailer: [6]u8 = .{
        0x04,
        0xFF,
        @intCast((prefix_len >> 24) & 0xFF),
        @intCast((prefix_len >> 16) & 0xFF),
        @intCast((prefix_len >> 8) & 0xFF),
        @intCast(prefix_len & 0xFF),
    };

    var digest_buf: [64]u8 = undefined;
    const digest: []const u8 = switch (hash_kind) {
        .sha256 => blk: {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(signed_data);
            h.update(sig.hashed_prefix);
            h.update(&trailer);
            h.final(digest_buf[0..32]);
            break :blk digest_buf[0..32];
        },
        .sha384 => blk: {
            var h = std.crypto.hash.sha2.Sha384.init(.{});
            h.update(signed_data);
            h.update(sig.hashed_prefix);
            h.update(&trailer);
            h.final(digest_buf[0..48]);
            break :blk digest_buf[0..48];
        },
        .sha512 => blk: {
            var h = std.crypto.hash.sha2.Sha512.init(.{});
            h.update(signed_data);
            h.update(sig.hashed_prefix);
            h.update(&trailer);
            h.final(digest_buf[0..64]);
            break :blk digest_buf[0..64];
        },
    };
    if (digest[0] != sig.hash_hint[0] or digest[1] != sig.hash_hint[1]) return .bad;

    // --- 6. Algorithm dispatch. -------------------------------------
    return switch (matched_pk.material) {
        .rsa => |rsa_key| verifyRsa(
            sig,
            rsa_key,
            hash_kind,
            signed_data,
            &trailer,
        ),
        .ecdsa => |ec_key| verifyEcdsa(sig, ec_key, hash_kind, digest),
        .ed25519 => |ed_key| if (hash_kind == .sha384)
            // Ed25519 + SHA-384 isn't a pairing OpenPGP defines —
            // RFC 9580 specifies SHA-256 or SHA-512.
            .internal
        else
            verifyEd25519(sig, ed_key, digest),
        .unsupported => .internal,
    };
}

fn verifyRsa(
    sig: signature.Signature,
    rsa_key: pubkey.RsaKey,
    hash_kind: HashKind,
    signed_data: []const u8,
    trailer: *const [6]u8,
) Status {
    const sig_rsa_mpi = switch (sig.material) {
        .rsa => |m| m,
        else => return .internal,
    };

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

    const msg_parts = &[_][]const u8{ signed_data, sig.hashed_prefix, trailer };

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
                // RSA + SHA-384 isn't in the supported matrix (no
                // distro signs with it). Pure-Zig path stays small.
                .sha384 => return .internal,
            };
            verdict catch return .bad;
            return .ok;
        }
    }
    // RSA modulus length we don't support (e.g. RSA-1024 or RSA-8192).
    return .no_key;
}

fn verifyEd25519(
    sig: signature.Signature,
    ed_key: pubkey.Ed25519Key,
    digest: []const u8,
) Status {
    const Ed = std.crypto.sign.Ed25519;

    // Marshal the 64-byte (R || S) signature buffer from whichever
    // wire format the sig packet carried.
    var sig_bytes: [64]u8 = undefined;
    switch (sig.material) {
        .ed25519 => |raw64| sig_bytes = raw64,
        .eddsa_legacy => |rs| {
            // EdDSALegacy: MPI(r) || MPI(s) — each MPI may have
            // had leading zero bytes stripped by `packet.readMpi`,
            // so left-pad to 32 bytes. A correctly-formed sig
            // never has more than 32 bytes per component; reject
            // anything larger as malformed.
            @memset(&sig_bytes, 0);
            const r = rs.r.bytes;
            const s = rs.s.bytes;
            if (r.len > 32 or s.len > 32) return .bad;
            @memcpy(sig_bytes[32 - r.len .. 32], r);
            @memcpy(sig_bytes[64 - s.len .. 64], s);
        },
        else => return .internal,
    }

    // Reject the all-zero public key (point at infinity) up front —
    // std.crypto would also refuse it but the error path here is
    // .bad rather than .internal.
    const pk = Ed.PublicKey.fromBytes(ed_key.point) catch return .bad;
    const ed_sig = Ed.Signature.fromBytes(sig_bytes);

    // OpenPGP feeds the *digest* of (signed_data || hashed_prefix ||
    // trailer) to the EdDSA primitive. Ed25519 then hashes the
    // digest internally (SHA-512 over R || A || msg) as part of its
    // own verification — there is no double pre-hash from our side.
    ed_sig.verify(digest, pk) catch return .bad;
    return .ok;
}

/// ECDSA path. Strict (curve, hash) pairing:
///
///   * P-256 → SHA-256 → `std.crypto.sign.ecdsa.EcdsaP256Sha256`
///   * P-384 → SHA-384 → `std.crypto.sign.ecdsa.EcdsaP384Sha384`
///
/// OpenPGP transmits (r, s) as two MPIs — the leading-zero strip in
/// `packet.readMpi` can make them shorter than the curve order, so
/// we left-pad to the scalar length before concatenating into the
/// raw `[encoded_length]u8` `Signature.fromBytes` expects. The
/// (32 or 48 byte) precomputed `digest` is fed straight into
/// `verifyPrehashed`.
fn verifyEcdsa(
    sig: signature.Signature,
    ec_key: pubkey.EcdsaKey,
    hash_kind: HashKind,
    digest: []const u8,
) Status {
    const sig_ec = switch (sig.material) {
        .ecdsa => |m| m,
        else => return .internal,
    };

    // Strict curve/hash pairing. RPM 4.20's rpmsign always emits the
    // matching pair (RFC 6637 §13: "default hash algorithm" is also
    // the matching SHA-* size); any deviation here is suspicious.
    const Scheme = enum { p256, p384 };
    const scheme: Scheme = switch (ec_key.curve) {
        .p256 => if (hash_kind == .sha256) .p256 else return .internal,
        .p384 => if (hash_kind == .sha384) .p384 else return .internal,
    };

    switch (scheme) {
        inline .p256, .p384 => |comp_scheme| {
            const Ec = switch (comp_scheme) {
                .p256 => std.crypto.sign.ecdsa.EcdsaP256Sha256,
                .p384 => std.crypto.sign.ecdsa.EcdsaP384Sha384,
            };
            const digest_len: usize = switch (comp_scheme) {
                .p256 => 32,
                .p384 => 48,
            };
            // verifyDetached has already done the hash-hint
            // short-circuit on this same `digest`, so by the time
            // we land here we expect the slice to be the right
            // length. The check is cheap insurance against a
            // future refactor decoupling the two paths.
            if (digest.len != digest_len) return .internal;
            var prehashed: [digest_len]u8 = undefined;
            @memcpy(&prehashed, digest);

            const sig_encoded_len = Ec.Signature.encoded_length;
            const scalar_len = sig_encoded_len / 2;
            if (sig_ec.r.bytes.len > scalar_len) return .bad;
            if (sig_ec.s.bytes.len > scalar_len) return .bad;

            var raw: [sig_encoded_len]u8 = @splat(0);
            @memcpy(
                raw[scalar_len - sig_ec.r.bytes.len .. scalar_len],
                sig_ec.r.bytes,
            );
            @memcpy(
                raw[sig_encoded_len - sig_ec.s.bytes.len ..],
                sig_ec.s.bytes,
            );
            const sig_obj = Ec.Signature.fromBytes(raw);

            const pkey = Ec.PublicKey.fromSec1(ec_key.point) catch return .internal;
            sig_obj.verifyPrehashed(prehashed, pkey) catch return .bad;
            return .ok;
        },
    }
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

// ---------------------------------------------------------------------
// PR #6: subkey-issued signature with binding-chain enforcement.
// ---------------------------------------------------------------------

const subkey_fixture_keyring = @embedFile("testdata/rsa-primary-subkey-keyring.bin");
const subkey_fixture_data = @embedFile("testdata/rsa-primary-subkey-data.bin");
const subkey_fixture_sig = @embedFile("testdata/rsa-primary-subkey-sig.bin");

test "subkey signer with valid binding chain → ok" {
    const keys = [_][]const u8{subkey_fixture_keyring};
    const status = verifyDetached(
        testing.allocator,
        subkey_fixture_sig,
        subkey_fixture_data,
        &keys,
    );
    try testing.expectEqual(Status.ok, status);
}

test "subkey signer with tampered binding sig → no_key" {
    // Flip the last byte of the keyring — that lives inside the
    // RSA signature MPI of the type-0x18 binding sig, so the
    // subkey's `binding_ok` flips to false. The subkey is then no
    // longer considered a candidate signer; with the primary as
    // the only remaining trusted key (and it's not the issuer of
    // our detached sig) we should see `.no_key`.
    var tampered = try testing.allocator.dupe(u8, subkey_fixture_keyring);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xFF;

    const keys = [_][]const u8{tampered};
    const status = verifyDetached(
        testing.allocator,
        subkey_fixture_sig,
        subkey_fixture_data,
        &keys,
    );
    try testing.expectEqual(Status.no_key, status);
}

test "subkey signer when binding sig packet removed → no_key" {
    // Strip the trailing Tag 2 (binding sig) packet off the
    // keyring. The subkey is still in the entries list but
    // without a binding sig binding_ok stays false. The verify
    // path must reject it as a candidate signer → no_key (not
    // bad — there could in principle have been another usable
    // key in the keyring).
    //
    // The fixture packets are old-format with 2-octet length
    // (`0x99` primary, `0xB9` subkey, `0x89` sig). Find the
    // 0x89 byte that opens the third packet by walking headers
    // from the start.
    var idx: usize = 0;
    // primary: 0x99 || BE16(len) || body
    try testing.expectEqual(@as(u8, 0x99), subkey_fixture_keyring[idx]);
    const p_len = (@as(usize, subkey_fixture_keyring[idx + 1]) << 8) |
        @as(usize, subkey_fixture_keyring[idx + 2]);
    idx += 3 + p_len;
    // subkey: 0xB9 || BE16(len) || body
    try testing.expectEqual(@as(u8, 0xB9), subkey_fixture_keyring[idx]);
    const s_len = (@as(usize, subkey_fixture_keyring[idx + 1]) << 8) |
        @as(usize, subkey_fixture_keyring[idx + 2]);
    idx += 3 + s_len;
    // We're now at the start of the binding sig packet. Truncate
    // the blob here to drop it.
    const trimmed = subkey_fixture_keyring[0..idx];

    const keys = [_][]const u8{trimmed};
    const status = verifyDetached(
        testing.allocator,
        subkey_fixture_sig,
        subkey_fixture_data,
        &keys,
    );
    try testing.expectEqual(Status.no_key, status);
}

// ---------------------------------------------------------------------
// PR #8: ECDSA P-256 / P-384 + SHA-256 / SHA-384 detached signatures.
//
// Fixtures are generated by `testdata/gen_ecdsa_fixture.py` —
// re-running that script produces different bytes (key material is
// ephemeral) so the tests only assert verdict, not exact byte
// patterns. The wrong-key fixture is an independent P-256 keypair
// that has the right algorithm but the wrong fingerprint, so it
// exercises the `.no_key` branch rather than `.internal`.
// ---------------------------------------------------------------------

const ecdsa_p256_pubkey = @embedFile("testdata/ecdsa-p256-pubkey.bin");
const ecdsa_p256_sig = @embedFile("testdata/ecdsa-p256-sig.bin");
const ecdsa_p256_data = @embedFile("testdata/ecdsa-p256-data.bin");
const ecdsa_p256_wrong_pubkey = @embedFile("testdata/ecdsa-p256-wrong-pubkey.bin");
const ecdsa_p384_pubkey = @embedFile("testdata/ecdsa-p384-pubkey.bin");
const ecdsa_p384_sig = @embedFile("testdata/ecdsa-p384-sig.bin");
const ecdsa_p384_data = @embedFile("testdata/ecdsa-p384-data.bin");

test "ECDSA P-256 + SHA-256 happy path" {
    const keys = [_][]const u8{ecdsa_p256_pubkey};
    const status = verifyDetached(
        testing.allocator,
        ecdsa_p256_sig,
        ecdsa_p256_data,
        &keys,
    );
    try testing.expectEqual(Status.ok, status);
}

test "ECDSA P-256: tampered sig MPI → bad" {
    var bad_sig = try testing.allocator.dupe(u8, ecdsa_p256_sig);
    defer testing.allocator.free(bad_sig);
    // Flip a byte deep in the MPI payload. The sig body is 111 B; r
    // and s live in the trailing ~70 B, well past the header / hashed
    // area / hash hint.
    bad_sig[bad_sig.len - 8] ^= 0x55;
    const keys = [_][]const u8{ecdsa_p256_pubkey};
    const status = verifyDetached(testing.allocator, bad_sig, ecdsa_p256_data, &keys);
    try testing.expectEqual(Status.bad, status);
}

test "ECDSA P-256: wrong key → no_key" {
    const keys = [_][]const u8{ecdsa_p256_wrong_pubkey};
    const status = verifyDetached(
        testing.allocator,
        ecdsa_p256_sig,
        ecdsa_p256_data,
        &keys,
    );
    try testing.expectEqual(Status.no_key, status);
}

test "ECDSA P-256: tampered signed data → bad" {
    var tampered = try testing.allocator.dupe(u8, ecdsa_p256_data);
    defer testing.allocator.free(tampered);
    tampered[0] ^= 0x01;
    const keys = [_][]const u8{ecdsa_p256_pubkey};
    const status = verifyDetached(testing.allocator, ecdsa_p256_sig, tampered, &keys);
    try testing.expectEqual(Status.bad, status);
}

test "ECDSA P-384 + SHA-384 happy path" {
    const keys = [_][]const u8{ecdsa_p384_pubkey};
    const status = verifyDetached(
        testing.allocator,
        ecdsa_p384_sig,
        ecdsa_p384_data,
        &keys,
    );
    try testing.expectEqual(Status.ok, status);
}

test "ECDSA P-384: tampered sig MPI → bad" {
    var bad_sig = try testing.allocator.dupe(u8, ecdsa_p384_sig);
    defer testing.allocator.free(bad_sig);
    bad_sig[bad_sig.len - 8] ^= 0x55;
    const keys = [_][]const u8{ecdsa_p384_pubkey};
    const status = verifyDetached(testing.allocator, bad_sig, ecdsa_p384_data, &keys);
    try testing.expectEqual(Status.bad, status);
}

test "ECDSA: P-256 key but sig says SHA-512 → rejected" {
    // Hand-mutate the P-256 sig packet's hash-algo byte to SHA-512
    // (id 10). The packet body starts after the 3-byte old-format
    // header (`0x89 || BE16(len)`); hash_algo is at body offset 3.
    //
    // Two failure modes are equally acceptable here: the hash-hint
    // short-circuit (the SHA-512 of the data won't match the hint
    // recorded for the original SHA-256 sig) returns `.bad`, and a
    // hypothetical sig whose hint *did* match — but came with a
    // curve/hash mismatch — would return `.internal` from
    // `verifyEcdsa`'s strict-pairing check. Either way the verdict
    // is "rejected"; we just check the verifier doesn't accept it.
    var twisted_sig = try testing.allocator.dupe(u8, ecdsa_p256_sig);
    defer testing.allocator.free(twisted_sig);
    twisted_sig[3 + 3] = 10;
    const keys = [_][]const u8{ecdsa_p256_pubkey};
    const status = verifyDetached(
        testing.allocator,
        twisted_sig,
        ecdsa_p256_data,
        &keys,
    );
    try testing.expect(status == .bad or status == .internal);
}

// =====================================================================
// PR #9: Ed25519 + EdDSALegacy verification.
// =====================================================================
//
// Three fixture families:
//
//   * `eddsa-legacy-{pubkey,sig}.bin` — synthesised via
//     `gen_ed25519_fixture.py`; covers the GnuPG `--openpgp`-default
//     wire format (algo 22, OID-prefixed MPI(0x40 || Q), MPI(r) ||
//     MPI(s) signature).
//   * `eddsa-legacy-gpg-{pubkey,sig,data}.bin` — generated by
//     `gpg --quick-gen-key ... ed25519 sign` + `gpg --detach-sign
//     --digest-algo SHA512`. Pure-Zig verdict here must match gpgme
//     (which produced and verified these fixtures) — this nails the
//     OpenPGP-Ed25519 hash interpretation against the canonical
//     implementation. The matching private key was discarded
//     immediately after fixture generation.
//   * `ed25519-native-{pubkey,sig}.bin` — synthesised; covers the
//     RFC 9580 native form (algo 27, 32-byte raw key, 64-byte raw
//     sig).

const eddsa_legacy_pubkey = @embedFile("testdata/eddsa-legacy-pubkey.bin");
const eddsa_legacy_sig = @embedFile("testdata/eddsa-legacy-sig.bin");
const ed25519_native_pubkey = @embedFile("testdata/ed25519-native-pubkey.bin");
const ed25519_native_sig = @embedFile("testdata/ed25519-native-sig.bin");
const ed25519_data = @embedFile("testdata/ed25519-data.bin");

const eddsa_legacy_gpg_pubkey = @embedFile("testdata/eddsa-legacy-gpg-pubkey.bin");
const eddsa_legacy_gpg_sig = @embedFile("testdata/eddsa-legacy-gpg-sig.bin");
const eddsa_legacy_gpg_data = @embedFile("testdata/eddsa-legacy-gpg-data.bin");

test "EdDSALegacy (algo 22) happy path" {
    const keys = [_][]const u8{eddsa_legacy_pubkey};
    const status = verifyDetached(
        testing.allocator,
        eddsa_legacy_sig,
        ed25519_data,
        &keys,
    );
    try testing.expectEqual(Status.ok, status);
}

test "EdDSALegacy: real gpg-signed fixture verifies (gpgme cross-check)" {
    // This fixture was produced by `gpg --detach-sign --digest-algo
    // SHA512` and verified `Good signature` by gpg itself. Our
    // pure-Zig verdict must agree.
    const keys = [_][]const u8{eddsa_legacy_gpg_pubkey};
    const status = verifyDetached(
        testing.allocator,
        eddsa_legacy_gpg_sig,
        eddsa_legacy_gpg_data,
        &keys,
    );
    try testing.expectEqual(Status.ok, status);
}

test "native Ed25519 (algo 27) happy path" {
    const keys = [_][]const u8{ed25519_native_pubkey};
    const status = verifyDetached(
        testing.allocator,
        ed25519_native_sig,
        ed25519_data,
        &keys,
    );
    try testing.expectEqual(Status.ok, status);
}

test "tampered Ed25519 signature byte → bad" {
    var bad_sig = try testing.allocator.dupe(u8, eddsa_legacy_gpg_sig);
    defer testing.allocator.free(bad_sig);
    // Flip a byte well inside the sig material (last ~64 bytes of
    // the packet). The hash hint is upstream of this, so the hint
    // check still passes — we want to land in the EdDSA verifier
    // and have it reject.
    bad_sig[bad_sig.len - 8] ^= 0xFF;
    const keys = [_][]const u8{eddsa_legacy_gpg_pubkey};
    const status = verifyDetached(
        testing.allocator,
        bad_sig,
        eddsa_legacy_gpg_data,
        &keys,
    );
    try testing.expectEqual(Status.bad, status);
}

test "tampered native Ed25519 signature byte → bad" {
    var bad_sig = try testing.allocator.dupe(u8, ed25519_native_sig);
    defer testing.allocator.free(bad_sig);
    // Last byte of the packet lives inside the raw 64-byte (R || S)
    // sig material (no MPI wrapping for algo 27).
    bad_sig[bad_sig.len - 1] ^= 0x01;
    const keys = [_][]const u8{ed25519_native_pubkey};
    const status = verifyDetached(
        testing.allocator,
        bad_sig,
        ed25519_data,
        &keys,
    );
    try testing.expectEqual(Status.bad, status);
}

test "tampered Ed25519 signed data → bad" {
    var tampered = try testing.allocator.dupe(u8, ed25519_data);
    defer testing.allocator.free(tampered);
    tampered[0] ^= 0x01;
    const keys = [_][]const u8{eddsa_legacy_pubkey};
    const status = verifyDetached(
        testing.allocator,
        eddsa_legacy_sig,
        tampered,
        &keys,
    );
    try testing.expectEqual(Status.bad, status);
}

test "Ed25519 sig with wrong key in keyring → no_key" {
    // Use the native-form pubkey to look up an EdDSALegacy sig.
    // The fingerprints differ (different OpenPGP framing), so no
    // entry matches the issuer.
    const keys = [_][]const u8{ed25519_native_pubkey};
    const status = verifyDetached(
        testing.allocator,
        eddsa_legacy_sig,
        ed25519_data,
        &keys,
    );
    try testing.expectEqual(Status.no_key, status);
}

test "Ed25519 sig with empty keyring → no_key" {
    const keys = [_][]const u8{};
    const status = verifyDetached(
        testing.allocator,
        eddsa_legacy_sig,
        ed25519_data,
        &keys,
    );
    try testing.expectEqual(Status.no_key, status);
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
