#!/usr/bin/env python3
"""
Generate OpenPGP v4 Ed25519 detached-signature fixtures for
`verify.zig`'s unit tests, covering both wire formats:

  EdDSALegacy (algo 22, GnuPG `--openpgp` default):
    - 9-octet ed25519 OID + MPI(0x40 || 32 raw octets) public key
    - MPI(r) || MPI(s) signature material

  Native Ed25519 (algo 27, RFC 9580):
    - 32 raw octets for the key
    - 64 raw octets (R || S) for the sig (no MPI wrap)

Writes the following files alongside this script:

    eddsa-legacy-pubkey.bin   Tag 6 (Public-Key) for algo=22
    eddsa-legacy-sig.bin      Tag 2 (Signature) for algo=22
    ed25519-native-pubkey.bin Tag 6 (Public-Key) for algo=27
    ed25519-native-sig.bin    Tag 2 (Signature) for algo=27
    ed25519-data.bin          The opaque bytes that both sigs cover.

Both fixtures use the *same* Ed25519 keypair so the same `data` file
backs both — only the OpenPGP wire framing differs.

Fixture provenance:

  * Keypair generated freshly each run via `cryptography`'s
    ed25519 primitives. No private material lands on disk.
  * EdDSALegacy fixture was cross-checked against GnuPG's verdict
    on a parallel `gpg --detach-sign --digest-algo SHA512` output
    using the same private key before commit (see commit message).
  * Native Ed25519 fixture is synthesised — no upstream tool ships
    v4 algo-27 sigs yet, but the wire format is well-defined and
    Ed25519 itself doesn't care about the OpenPGP framing. The
    primitive cryptographic operation (sign a digest) is the
    same.

Requirements: python3 with the `cryptography` package.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Wire-format helpers (mirror gen_fixture.py).
# ---------------------------------------------------------------------------
def mpi(payload: bytes) -> bytes:
    """Encode `payload` (a big-endian unsigned integer's bytes) as an
    OpenPGP MPI: 2-octet BE bit count followed by ceil(bits/8) bytes."""
    if not payload:
        return b"\x00\x00"
    # Strip leading zero bytes so the bit count reflects the MSB.
    i = 0
    while i < len(payload) - 1 and payload[i] == 0:
        i += 1
    stripped = payload[i:]
    n = int.from_bytes(stripped, "big")
    bit_len = n.bit_length()
    if bit_len == 0:
        return b"\x00\x00"
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + n.to_bytes(byte_len, "big")


def mpi_with_prefix(prefix_byte: int, raw: bytes) -> bytes:
    """MPI(prefix_byte || raw). The 0x40 native-EdDSA prefix keeps the
    MSB at bit 6, so the bit_length is len(raw)*8 + 7 = 263 for
    Ed25519 (32 raw bytes)."""
    composite = bytes([prefix_byte]) + raw
    bit_len = len(composite) * 8
    # Tighten to the actual top-set bit (the 0x40 prefix gives bit 6).
    while bit_len > 0 and (composite[0] & (1 << ((bit_len - 1) % 8))) == 0:
        bit_len -= 1
    return struct.pack(">H", bit_len) + composite


def old_format_packet(tag: int, body: bytes) -> bytes:
    """Wrap `body` in an old-format OpenPGP packet header.

    Tag 6 (Public-Key) traditionally uses old-format `0x99` (2-octet
    length); Tag 2 (Signature) uses `0x89` for the same length encoding.
    We always emit the 2-octet form for simplicity.
    """
    assert 0 <= tag < 16, "old-format supports 4-bit tags only"
    assert len(body) < 0x10000
    return bytes([0x80 | (tag << 2) | 1]) + struct.pack(">H", len(body)) + body


# ---------------------------------------------------------------------------
# Generate the Ed25519 keypair.
# ---------------------------------------------------------------------------
private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
assert len(public_raw) == 32

# Same Unix timestamp drives both fixtures; the v4 fingerprint depends
# on it so we keep it fixed here.
CREATED = 0x65000000

# ---------------------------------------------------------------------------
# EdDSALegacy (algo 22) public-key body.
# ---------------------------------------------------------------------------
ED25519_OID = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
eddsa_legacy_pubkey_body = (
    bytes([0x04])
    + struct.pack(">I", CREATED)
    + bytes([22])  # algo: EdDSALegacy
    + bytes([len(ED25519_OID)])
    + ED25519_OID
    + mpi_with_prefix(0x40, public_raw)
)
eddsa_legacy_fpr = hashlib.sha1(
    b"\x99" + struct.pack(">H", len(eddsa_legacy_pubkey_body)) + eddsa_legacy_pubkey_body
).digest()
assert len(eddsa_legacy_fpr) == 20

# ---------------------------------------------------------------------------
# Native Ed25519 (algo 27) public-key body.
# ---------------------------------------------------------------------------
ed25519_native_pubkey_body = (
    bytes([0x04])
    + struct.pack(">I", CREATED)
    + bytes([27])  # algo: Ed25519
    + public_raw
)
ed25519_native_fpr = hashlib.sha1(
    b"\x99" + struct.pack(">H", len(ed25519_native_pubkey_body)) + ed25519_native_pubkey_body
).digest()

# ---------------------------------------------------------------------------
# The data we sign — opaque test content (same for both fixtures).
# ---------------------------------------------------------------------------
signed_data = b"ed25519 fixture: the quick brown fox jumps over the lazy dog\n"

# ---------------------------------------------------------------------------
# Helper: build a v4 sig body for a given (pk_algo, hash_algo, fpr,
# material_bytes) tuple. `material_bytes` is the raw bytes that follow
# the 2-octet hash hint.
# ---------------------------------------------------------------------------
def build_sig_body(pk_algo: int, hash_algo: int, fpr: bytes, signer):
    # Hashed area: single Issuer Fingerprint subpacket (type 33).
    ifp_inner = bytes([33, 0x04]) + fpr
    hashed_area = bytes([len(ifp_inner)]) + ifp_inner
    hashed_sub_len = len(hashed_area)

    # Unhashed area: Issuer Key ID subpacket (type 16) for compat.
    keyid = fpr[-8:]
    ikid_inner = bytes([16]) + keyid
    unhashed_area = bytes([len(ikid_inner)]) + ikid_inner
    unhashed_sub_len = len(unhashed_area)

    # v4 hashed prefix: 0x04 || sig_type || pk_algo || hash_algo
    #   || BE16(N) || hashed_area
    hashed_prefix = (
        bytes([0x04, 0x00, pk_algo, hash_algo])
        + struct.pack(">H", hashed_sub_len)
        + hashed_area
    )

    # Hash input (RFC 4880 §5.2.4):
    #   signed_data || hashed_prefix || 0x04 || 0xFF || BE32(len(hashed_prefix))
    trailer = bytes([0x04, 0xFF]) + struct.pack(">I", len(hashed_prefix))
    if hash_algo == 8:
        h = hashlib.sha256()
    elif hash_algo == 10:
        h = hashlib.sha512()
    else:
        raise ValueError(f"unsupported hash algo {hash_algo}")
    h.update(signed_data)
    h.update(hashed_prefix)
    h.update(trailer)
    digest = h.digest()
    hash_hint = digest[:2]

    # Ed25519 signs the digest directly — pure EdDSA hashes msg with
    # SHA-512 internally; the OpenPGP-declared hash algo digests the
    # data first.
    raw_sig = signer(digest)
    assert len(raw_sig) == 64, len(raw_sig)
    r_bytes = raw_sig[:32]
    s_bytes = raw_sig[32:]

    if pk_algo == 22:  # EdDSALegacy: MPI(r) || MPI(s)
        material = mpi(r_bytes) + mpi(s_bytes)
    elif pk_algo == 27:  # native Ed25519: 64 raw octets
        material = raw_sig
    else:
        raise ValueError(f"unsupported pk algo {pk_algo}")

    sig_body = (
        hashed_prefix
        + struct.pack(">H", unhashed_sub_len)
        + unhashed_area
        + hash_hint
        + material
    )
    return sig_body


def sign_with_private_key(digest: bytes) -> bytes:
    return private_key.sign(digest)


# ---------------------------------------------------------------------------
# Build both signatures.
# ---------------------------------------------------------------------------
eddsa_legacy_sig_body = build_sig_body(
    pk_algo=22,
    hash_algo=10,  # SHA-512
    fpr=eddsa_legacy_fpr,
    signer=sign_with_private_key,
)
ed25519_native_sig_body = build_sig_body(
    pk_algo=27,
    hash_algo=10,  # SHA-512
    fpr=ed25519_native_fpr,
    signer=sign_with_private_key,
)

# ---------------------------------------------------------------------------
# Frame and write to disk.
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
(HERE / "eddsa-legacy-pubkey.bin").write_bytes(
    old_format_packet(6, eddsa_legacy_pubkey_body)
)
(HERE / "eddsa-legacy-sig.bin").write_bytes(
    old_format_packet(2, eddsa_legacy_sig_body)
)
(HERE / "ed25519-native-pubkey.bin").write_bytes(
    old_format_packet(6, ed25519_native_pubkey_body)
)
(HERE / "ed25519-native-sig.bin").write_bytes(
    old_format_packet(2, ed25519_native_sig_body)
)
(HERE / "ed25519-data.bin").write_bytes(signed_data)

print(
    "wrote EdDSALegacy pubkey "
    f"({len(eddsa_legacy_pubkey_body)} body bytes), fpr = {eddsa_legacy_fpr.hex()}"
)
print(f"wrote EdDSALegacy sig    ({len(eddsa_legacy_sig_body)} body bytes)")
print(
    "wrote Ed25519     pubkey "
    f"({len(ed25519_native_pubkey_body)} body bytes), fpr = {ed25519_native_fpr.hex()}"
)
print(f"wrote Ed25519     sig    ({len(ed25519_native_sig_body)} body bytes)")
print(f"wrote data ({len(signed_data)} bytes)")
