#!/usr/bin/env python3
"""
Generate a deterministic-ish OpenPGP v4 keyring fixture for
`keyring.zig`'s unit tests — a primary RSA-2048 key with a signing
RSA-2048 subkey, a type-0x18 subkey-binding signature from the
primary, an embedded type-0x19 back-sig from the subkey, and a
binary detached signature over a small message produced by the
subkey.

Writes the following files alongside this script:

    rsa-primary-subkey-keyring.bin
        Tag 6 (primary) || Tag 14 (subkey) || Tag 2 (subkey-binding sig
        with embedded type-0x19 back-sig in the hashed area).
    rsa-primary-subkey-data.bin
        The opaque message bytes that the subkey signs.
    rsa-primary-subkey-sig.bin
        Tag 2 detached binary signature over the message, signed by
        the subkey.

The RSA private keys are generated freshly each run and discarded;
they never touch the filesystem. Re-running the script produces
different bytes (fingerprints and signature material change) — the
tests are written to verify *structure*, not exact bytes.

Requirements: python3 with the `cryptography` package.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


# ---------------------------------------------------------------------------
# Wire-format helpers (mirror gen_fixture.py).
# ---------------------------------------------------------------------------
def mpi(n: int) -> bytes:
    if n == 0:
        return b"\x00\x00"
    bit_len = n.bit_length()
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + n.to_bytes(byte_len, "big")


def old_format_packet(tag: int, body: bytes) -> bytes:
    """Wrap `body` in an old-format OpenPGP packet header (Tag is 4
    bits; always use the 2-octet length variant for simplicity)."""
    assert 0 <= tag < 16
    assert len(body) < 0x10000
    return bytes([0x80 | (tag << 2) | 1]) + struct.pack(">H", len(body)) + body


def framed_for_hash(body: bytes) -> bytes:
    """0x99 || BE16(body_len) || body — the framing used both for v4
    fingerprint computation and as input to subkey-binding sigs."""
    return b"\x99" + struct.pack(">H", len(body)) + body


def v4_fingerprint(body: bytes) -> bytes:
    return hashlib.sha1(framed_for_hash(body)).digest()


def pubkey_body(key: rsa.RSAPrivateKey, created: int) -> bytes:
    """v4 RSA Public-Key/Public-Subkey body:
    0x04 || BE32(created) || algo=1 (RSA) || MPI(n) || MPI(e)."""
    nums = key.public_key().public_numbers()
    return (
        bytes([0x04])
        + struct.pack(">I", created)
        + bytes([0x01])
        + mpi(nums.n)
        + mpi(nums.e)
    )


# ---------------------------------------------------------------------------
# Build the v4 binding signature (type 0x18) from primary over subkey,
# with an Embedded Signature subpacket (type 32) carrying the
# type-0x19 back-sig from the subkey itself.
# ---------------------------------------------------------------------------
def sign_v4(
    signer: rsa.RSAPrivateKey,
    sig_type: int,
    hashed_subpackets: bytes,
    unhashed_subpackets: bytes,
    hash_inputs: list[bytes],
) -> bytes:
    """Produce a v4 RSA + SHA-256 signature packet *body*. `hash_inputs`
    is the list of byte sequences fed into the hash *before* the
    hashed_prefix and trailer (i.e. for a detached binary sig this is
    just `[signed_data]`; for a subkey-binding sig it is
    `[framed_primary, framed_subkey]`)."""
    hashed_prefix = (
        bytes([0x04, sig_type, 0x01, 0x08])  # ver, type, RSA, SHA-256
        + struct.pack(">H", len(hashed_subpackets))
        + hashed_subpackets
    )
    trailer = bytes([0x04, 0xFF]) + struct.pack(">I", len(hashed_prefix))

    h = hashlib.sha256()
    for chunk in hash_inputs:
        h.update(chunk)
    h.update(hashed_prefix)
    h.update(trailer)
    digest = h.digest()
    hash_hint = digest[:2]

    sig_bytes = signer.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
    sig_int = int.from_bytes(sig_bytes, "big")
    sig_mpi = mpi(sig_int)

    return (
        hashed_prefix
        + struct.pack(">H", len(unhashed_subpackets))
        + unhashed_subpackets
        + hash_hint
        + sig_mpi
    )


def issuer_fpr_subpacket(fpr: bytes) -> bytes:
    """Build a length-prefixed Issuer Fingerprint subpacket (type 33)
    carrying the 1-octet key-version byte followed by the 20-byte v4
    fingerprint."""
    assert len(fpr) == 20
    inner = bytes([33, 0x04]) + fpr
    return bytes([len(inner)]) + inner


def key_flags_subpacket(flags: int) -> bytes:
    """Key Flags subpacket (type 27). One-octet flag value: bit 0x02
    is the 'signing' bit."""
    inner = bytes([27, flags])
    return bytes([len(inner)]) + inner


def embedded_signature_subpacket(sig_body: bytes) -> bytes:
    """Embedded Signature subpacket (type 32) carrying a full v4 sig
    body verbatim."""
    inner = bytes([32]) + sig_body
    # Length encoding: 1-octet form caps at 191; the 2-octet form
    # covers (192 .. 8383). Our back-sig is ~300 bytes so we need the
    # 2-octet form. (Subpacket length encoding matches new-format
    # packet body length — RFC 4880 §5.2.3.1.)
    n = len(inner)
    if n < 192:
        return bytes([n]) + inner
    if n < 8384:
        adj = n - 192
        return bytes([(adj >> 8) + 192, adj & 0xFF]) + inner
    return bytes([0xFF]) + struct.pack(">I", n) + inner


# ---------------------------------------------------------------------------
# Generate the keypair, the subkey, and assemble.
# ---------------------------------------------------------------------------
primary_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)

primary_body = pubkey_body(primary_key, created=0x66000000)
subkey_body_bytes = pubkey_body(subkey, created=0x66000001)

primary_fpr = v4_fingerprint(primary_body)
subkey_fpr = v4_fingerprint(subkey_body_bytes)

framed_primary = framed_for_hash(primary_body)
framed_subkey = framed_for_hash(subkey_body_bytes)

# Step 1: subkey signs the back-sig (type 0x19) over the same
# primary+subkey framing as the binding sig.
backsig_body = sign_v4(
    signer=subkey,
    sig_type=0x19,
    hashed_subpackets=issuer_fpr_subpacket(subkey_fpr),
    unhashed_subpackets=b"",
    hash_inputs=[framed_primary, framed_subkey],
)

# Step 2: primary signs the binding sig (type 0x18) over the same
# framing, with the Key Flags subpacket (S bit set) and the
# Embedded Signature subpacket containing the back-sig in the
# hashed area.
binding_hashed = (
    issuer_fpr_subpacket(primary_fpr)
    + key_flags_subpacket(0x02)
    + embedded_signature_subpacket(backsig_body)
)
binding_body = sign_v4(
    signer=primary_key,
    sig_type=0x18,
    hashed_subpackets=binding_hashed,
    unhashed_subpackets=b"",
    hash_inputs=[framed_primary, framed_subkey],
)

keyring_blob = (
    old_format_packet(6, primary_body)
    + old_format_packet(14, subkey_body_bytes)
    + old_format_packet(2, binding_body)
)

# Step 3: also produce a detached binary signature over a small
# message, signed by the subkey, so verify.zig can exercise the
# subkey-signer integration path end-to-end.
signed_data = b"the quick brown fox jumps over the lazy dog\n"
detached_body = sign_v4(
    signer=subkey,
    sig_type=0x00,
    hashed_subpackets=issuer_fpr_subpacket(subkey_fpr),
    unhashed_subpackets=b"",
    hash_inputs=[signed_data],
)
detached_packet = old_format_packet(2, detached_body)

# ---------------------------------------------------------------------------
# Write fixture files.
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
(HERE / "rsa-primary-subkey-keyring.bin").write_bytes(keyring_blob)
(HERE / "rsa-primary-subkey-data.bin").write_bytes(signed_data)
(HERE / "rsa-primary-subkey-sig.bin").write_bytes(detached_packet)

print(f"wrote keyring ({len(keyring_blob)} bytes)")
print(f"  primary fpr = {primary_fpr.hex()}")
print(f"  subkey  fpr = {subkey_fpr.hex()}")
print(f"  binding sig body len = {len(binding_body)}")
print(f"  back-sig body len    = {len(backsig_body)}")
print(f"wrote data    ({len(signed_data)} bytes)")
print(f"wrote sig     ({len(detached_body)} bytes)")
