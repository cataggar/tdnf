#!/usr/bin/env python3
"""
Generate ECDSA P-256 + SHA-256 and P-384 + SHA-384 OpenPGP v4 binary
detached signature fixtures for `verify.zig`'s unit tests.

Mirrors `gen_fixture.py` (the RSA-2048 generator). For each curve,
writes three files alongside this script:

    ecdsa-p256-pubkey.bin / ecdsa-p384-pubkey.bin
        Raw OpenPGP Public-Key packet (Tag 6), header-included.
    ecdsa-p256-sig.bin / ecdsa-p384-sig.bin
        Raw OpenPGP Signature packet (Tag 2), header-included.
    ecdsa-p256-data.bin / ecdsa-p384-data.bin
        The opaque bytes that were signed.

Also writes:

    ecdsa-p256-wrong-pubkey.bin
        A second, independent P-256 public-key blob with a different
        keypair. Drives the `.no_key` test case.

The matching ECDSA private keys are generated freshly each run and
discarded; they never touch the filesystem. Re-running the script
produces different bytes — the tests verify structure + a single
known-good run, not exact bytes.

Requirements: python3 with the `cryptography` package.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)


# ---------------------------------------------------------------------------
# Wire-format helpers (mirror gen_fixture.py).
# ---------------------------------------------------------------------------
def mpi(n: int) -> bytes:
    """Encode an integer as an OpenPGP MPI (RFC 4880 §3.2)."""
    if n == 0:
        return b"\x00\x00"
    bit_len = n.bit_length()
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + n.to_bytes(byte_len, "big")


def old_format_packet(tag: int, body: bytes) -> bytes:
    """Wrap `body` in an old-format OpenPGP packet header (2-octet length)."""
    assert 0 <= tag < 16
    assert len(body) < 0x10000
    return bytes([0x80 | (tag << 2) | 1]) + struct.pack(">H", len(body)) + body


# ---------------------------------------------------------------------------
# ECDSA curve metadata.
# ---------------------------------------------------------------------------
# OIDs in the OpenPGP wire form: raw DER value bytes (no 06 LL envelope).
OID_NIST_P256 = bytes.fromhex("2A8648CE3D030107")  # 1.2.840.10045.3.1.7
OID_NIST_P384 = bytes.fromhex("2B81040022")        # 1.3.132.0.34

CURVES = {
    "p256": {
        "oid": OID_NIST_P256,
        "curve": ec.SECP256R1(),
        "hash": hashes.SHA256(),
        "hash_algo_id": 8,    # OpenPGP hash algo: SHA-256
        "coord_len": 32,
        "sha_factory": hashlib.sha256,
    },
    "p384": {
        "oid": OID_NIST_P384,
        "curve": ec.SECP384R1(),
        "hash": hashes.SHA384(),
        "hash_algo_id": 9,    # OpenPGP hash algo: SHA-384
        "coord_len": 48,
        "sha_factory": hashlib.sha384,
    },
}


def gen_pubkey_body(meta: dict, priv) -> tuple[bytes, bytes]:
    """Build the v4 ECDSA Public-Key packet body. Returns (body, fingerprint)."""
    nums = priv.public_key().public_numbers()
    coord_len = meta["coord_len"]
    x_b = nums.x.to_bytes(coord_len, "big")
    y_b = nums.y.to_bytes(coord_len, "big")
    # SEC1 uncompressed point: 0x04 || X || Y.
    sec1 = b"\x04" + x_b + y_b
    q_mpi = mpi(int.from_bytes(sec1, "big"))

    # v4 Public-Key body: 0x04 || BE32(created) || algo=19 (ECDSA) ||
    # OID-length-byte || OID || MPI(Q).
    created = 0x65000000  # arbitrary 2024-ish unix timestamp
    body = (
        bytes([0x04])
        + struct.pack(">I", created)
        + bytes([19])
        + bytes([len(meta["oid"])])
        + meta["oid"]
        + q_mpi
    )

    # v4 fingerprint = SHA-1(0x99 || BE16(body_len) || body).
    fpr = hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()
    return body, fpr


def gen_detached_sig(meta: dict, priv, fpr: bytes, signed_data: bytes) -> bytes:
    """Build the v4 ECDSA Signature packet body for a binary-detached sig."""
    # Hashed area: a single Issuer-Fingerprint subpacket (type 33).
    ifp_inner = bytes([33, 0x04]) + fpr
    hashed_area = bytes([len(ifp_inner)]) + ifp_inner

    # Unhashed area: Issuer Key ID subpacket (type 16) for compat
    # with old verifiers that don't read the hashed Issuer Fingerprint.
    keyid = fpr[-8:]
    ikid_inner = bytes([16]) + keyid
    unhashed_area = bytes([len(ikid_inner)]) + ikid_inner

    # v4 sig hashed prefix (everything fed into the hash before the data):
    #   0x04 || sig_type=0 || pk_algo=19 || hash_algo || BE16(N) || hashed_area
    hashed_prefix = (
        bytes([0x04, 0x00, 19, meta["hash_algo_id"]])
        + struct.pack(">H", len(hashed_area))
        + hashed_area
    )

    # Hash input per RFC 4880 §5.2.4:
    #   HASH( signed_data || hashed_prefix || 0x04 || 0xFF || BE32(prefix_len) )
    trailer = bytes([0x04, 0xFF]) + struct.pack(">I", len(hashed_prefix))
    h = meta["sha_factory"]()
    h.update(signed_data)
    h.update(hashed_prefix)
    h.update(trailer)
    digest = h.digest()
    hash_hint = digest[:2]

    # Sign the prehashed digest with deterministic-shaped ECDSA. The
    # `cryptography` library returns a DER-encoded (r, s); decode to
    # raw integers and re-encode as two OpenPGP MPIs.
    sig_der = priv.sign(digest, ec.ECDSA(Prehashed(meta["hash"])))
    r, s = decode_dss_signature(sig_der)

    sig_body = (
        hashed_prefix
        + struct.pack(">H", len(unhashed_area))
        + unhashed_area
        + hash_hint
        + mpi(r)
        + mpi(s)
    )
    return sig_body


def write_curve(label: str, signed_data: bytes) -> None:
    meta = CURVES[label]
    priv = ec.generate_private_key(meta["curve"])
    pubkey_body, fpr = gen_pubkey_body(meta, priv)
    sig_body = gen_detached_sig(meta, priv, fpr, signed_data)

    HERE = Path(__file__).resolve().parent
    (HERE / f"ecdsa-{label}-pubkey.bin").write_bytes(old_format_packet(6, pubkey_body))
    (HERE / f"ecdsa-{label}-sig.bin").write_bytes(old_format_packet(2, sig_body))
    (HERE / f"ecdsa-{label}-data.bin").write_bytes(signed_data)
    print(
        f"wrote {label}: pubkey body {len(pubkey_body)} B, "
        f"sig body {len(sig_body)} B, data {len(signed_data)} B; "
        f"fingerprint={fpr.hex()}"
    )


def write_wrong_p256() -> None:
    """A second, independent P-256 pubkey for the `.no_key` test."""
    meta = CURVES["p256"]
    priv = ec.generate_private_key(meta["curve"])
    pubkey_body, fpr = gen_pubkey_body(meta, priv)
    HERE = Path(__file__).resolve().parent
    (HERE / "ecdsa-p256-wrong-pubkey.bin").write_bytes(old_format_packet(6, pubkey_body))
    print(f"wrote p256 wrong pubkey ({len(pubkey_body)} B); fingerprint={fpr.hex()}")


if __name__ == "__main__":
    write_curve("p256", b"ecdsa p-256 + sha-256 rpmzig fixture\n")
    write_curve("p384", b"ecdsa p-384 + sha-384 rpmzig fixture\n")
    write_wrong_p256()
