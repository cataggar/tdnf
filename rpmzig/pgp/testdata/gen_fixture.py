#!/usr/bin/env python3
"""
Generate a deterministic-ish (re-seeded) OpenPGP v4 RSA-2048 + SHA-256
binary detached signature fixture for `verify.zig`'s unit tests.

Writes three files alongside this script:

    rsa2048-pubkey.bin  — raw OpenPGP Public-Key packet (Tag 6),
                          header-included, ready to feed straight
                          to `armor.decodeAny`.
    rsa2048-sig.bin     — raw OpenPGP Signature packet (Tag 2),
                          header-included.
    rsa2048-data.bin    — the bytes that were signed.

The matching RSA private key is generated freshly each run and
discarded; it never touches the filesystem. Re-running the script
produces different bytes (and the test will still pass because the
fingerprint linkage is consistent within one run). Treat the
generated files as opaque test fixtures.

Requirements: python3 with the `cryptography` package.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def mpi(n: int) -> bytes:
    """Encode an integer as an OpenPGP MPI (RFC 4880 §3.2)."""
    if n == 0:
        return b"\x00\x00"
    bit_len = n.bit_length()
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + n.to_bytes(byte_len, "big")


def old_format_packet(tag: int, body: bytes) -> bytes:
    """Wrap `body` in an old-format OpenPGP packet header.

    Tag 6 (Public-Key) traditionally uses old-format `0x99` (2-octet
    length); Tag 2 (Signature) uses `0x88` (1-octet length when the
    body is small enough, else `0x89`). We always emit the 2-octet
    form for simplicity.
    """
    assert 0 <= tag < 16, "old-format supports 4-bit tags only"
    assert len(body) < 0x10000
    return bytes([0x80 | (tag << 2) | 1]) + struct.pack(">H", len(body)) + body


# ---------------------------------------------------------------------------
# Generate the RSA key + body for the v4 Public-Key packet.
# ---------------------------------------------------------------------------
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_numbers = key.public_key().public_numbers()
n_mpi = mpi(pub_numbers.n)
e_mpi = mpi(pub_numbers.e)

# v4 Public-Key body: 0x04 || BE32(created) || algo=1 (RSA) || MPI(n) || MPI(e)
created = 0x65000000  # arbitrary 2024-ish unix timestamp
pubkey_body = bytes([0x04]) + struct.pack(">I", created) + bytes([0x01]) + n_mpi + e_mpi

# v4 fingerprint = SHA-1(0x99 || BE16(body_len) || body).
fpr = hashlib.sha1(b"\x99" + struct.pack(">H", len(pubkey_body)) + pubkey_body).digest()
assert len(fpr) == 20

# ---------------------------------------------------------------------------
# Build the v4 Signature packet body.
# ---------------------------------------------------------------------------
# Hashed area: a single Issuer-Fingerprint subpacket (type 33).
#   subpacket = length-prefix(1+1+20) || type=33 || version=4 || fpr(20)
ifp_inner = bytes([33, 0x04]) + fpr
assert len(ifp_inner) == 22
hashed_area = bytes([len(ifp_inner)]) + ifp_inner
hashed_sub_len = len(hashed_area)

# Unhashed area: Issuer Key ID subpacket (type 16) for compat with
# old verifiers that don't read the hashed Issuer Fingerprint.
keyid = fpr[-8:]
ikid_inner = bytes([16]) + keyid
unhashed_area = bytes([len(ikid_inner)]) + ikid_inner
unhashed_sub_len = len(unhashed_area)

# v4 sig hashed prefix (everything fed into the hash before the data):
#   0x04 || sig_type || pk_algo || hash_algo || BE16(N) || hashed_area
hashed_prefix = (
    bytes([0x04, 0x00, 0x01, 0x08])
    + struct.pack(">H", hashed_sub_len)
    + hashed_area
)

# The data we sign — opaque test content.
signed_data = b"the quick brown fox jumps over the lazy dog\n"

# Compute the hash input per RFC 4880 §5.2.4:
#   HASH( signed_data || hashed_prefix || 0x04 || 0xFF || BE32(len(hashed_prefix)) )
trailer = bytes([0x04, 0xFF]) + struct.pack(">I", len(hashed_prefix))
h = hashlib.sha256()
h.update(signed_data)
h.update(hashed_prefix)
h.update(trailer)
digest = h.digest()
hash_hint = digest[:2]

# Sign: PKCS#1 v1.5 over the SHA-256 hash. The `cryptography` library
# bundles the DigestInfo header for us when we use `Prehashed` —
# which matches what OpenPGP wants.
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
sig_bytes = key.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))

# Wrap the signature as an MPI.
sig_int = int.from_bytes(sig_bytes, "big")
sig_mpi = mpi(sig_int)

# Assemble the full v4 sig body.
sig_body = (
    hashed_prefix
    + struct.pack(">H", unhashed_sub_len)
    + unhashed_area
    + hash_hint
    + sig_mpi
)

# ---------------------------------------------------------------------------
# Frame and write to disk.
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
(HERE / "rsa2048-pubkey.bin").write_bytes(old_format_packet(6, pubkey_body))
(HERE / "rsa2048-sig.bin").write_bytes(old_format_packet(2, sig_body))
(HERE / "rsa2048-data.bin").write_bytes(signed_data)

print(f"wrote pubkey  ({len(pubkey_body)} body bytes), fingerprint = {fpr.hex()}")
print(f"wrote sig     ({len(sig_body)} body bytes)")
print(f"wrote data    ({len(signed_data)} bytes)")
