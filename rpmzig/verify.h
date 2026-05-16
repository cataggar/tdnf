/*
 * GPG signature verification API for .rpm files (T3).
 *
 * Companion to rpmdb.h. The verifier itself lives in
 * rpmzig/verify.c so it can use the gpgme C API directly without
 * going through Zig FFI gymnastics.
 */
#ifndef _TDNF_RPMZIG_VERIFY_H_
#define _TDNF_RPMZIG_VERIFY_H_

#include "rpmdb.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    TDNF_RPMZIG_VERIFY_OK            = 0,
    TDNF_RPMZIG_VERIFY_NO_SIG        = 1,
    TDNF_RPMZIG_VERIFY_NO_KEY        = 2,
    TDNF_RPMZIG_VERIFY_BAD           = 3,
    TDNF_RPMZIG_VERIFY_GPGME_ERROR   = 4,
};

/**
 * Verify the GPG signature on a .rpm file. `gpg_homedir` is a path
 * to a directory containing GPG keys (set via `gpg --homedir
 * <dir> --import <key.pub>`); pass NULL or "" to use gpgme's
 * default (typically $GNUPGHOME or ~/.gnupg).
 *
 * On success writes a TDNF_RPMZIG_VERIFY_* status into *out_status.
 * Returns 0 when *out_status == TDNF_RPMZIG_VERIFY_OK, non-zero
 * otherwise (the value isn't itself a status code; it just lets
 * callers test "did verification succeed?" with `if (rc)`).
 */
int tdnf_rpmzig_verify(
    tdnf_rpm_file *fh,
    const char *gpg_homedir,
    int *out_status
);

/**
 * Verify the GPG signature on a .rpm file using an in-memory
 * keyring built from `key_blobs`. Each blob is an ASCII-armored or
 * binary OpenPGP public key (the same bytes you'd hand to `gpg
 * --import`).
 *
 * Behaviour, in order:
 *   1. Create a fresh temporary GPG home directory under $TMPDIR.
 *   2. Import every supplied blob via gpgme_op_import.
 *   3. Verify the rpm's signature against that keyring.
 *   4. Remove the temporary directory before returning.
 *
 * This matches what client/gpgcheck.c does today through
 * rpmKeyringAddKey + rpmReadPackageFile, but with rpmzig + gpgme
 * instead of librpm. It's the kernel of T3 PR #3, which will swap
 * the librpm path in TDNFGPGCheckPackage for this function.
 *
 * Status codes are the same TDNF_RPMZIG_VERIFY_* set.
 *
 * Pass `key_count = 0` and `key_blobs = NULL` to verify against an
 * empty keyring (useful for negative tests).
 */
int tdnf_rpmzig_verify_with_keys(
    tdnf_rpm_file *fh,
    const void *const *key_blobs,
    const size_t *key_lens,
    size_t key_count,
    int *out_status
);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_RPMZIG_VERIFY_H_ */
