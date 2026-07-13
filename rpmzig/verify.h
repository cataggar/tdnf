/*
 * Pure-Zig OpenPGP signature verification API for .rpm files (T3).
 *
 * Companion to rpmdb.h. The C shim in rpmzig/verify_pure.c bridges
 * `tdnf_rpm_file` into the Zig verifier under rpmzig/pgp/.
 */
#ifndef _TDNF_RPMZIG_STATUS_H_
#define _TDNF_RPMZIG_STATUS_H_

#include "rpmdb.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    TDNF_RPMZIG_STATUS_OK             = 0,
    TDNF_RPMZIG_STATUS_NO_SIG         = 1,
    TDNF_RPMZIG_STATUS_NO_KEY         = 2,
    TDNF_RPMZIG_STATUS_BAD            = 3,
    TDNF_RPMZIG_STATUS_INTERNAL_ERROR = 4,
};

/**
 * Verify the GPG signature on a .rpm file using a pure-Zig verifier
 * against an in-memory keyring. `key_blobs[]` is an array of
 * `key_count` OpenPGP public-key blobs (armored or binary); each
 * entry is `key_lens[i]` bytes long.
 *
 * Supported algorithms and policy match the Zig implementation in
 * `rpmzig/pgp/verify.zig` (currently RSA, ECDSA P-256/P-384, and
 * Ed25519 in both native and EdDSALegacy wire formats). Unsupported,
 * malformed, or otherwise unexpected cases return
 * TDNF_RPMZIG_STATUS_INTERNAL_ERROR (numeric 4).
 *
 * On success writes a TDNF_RPMZIG_STATUS_* status into *out_status.
 * Returns 0 on OK, non-zero otherwise.
 */
int tdnf_rpmzig_verify_pure(
    tdnf_rpm_file *fh,
    const void *const *key_blobs,
    const size_t *key_lens,
    size_t key_count,
    int *out_status
);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_RPMZIG_STATUS_H_ */
