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

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_RPMZIG_VERIFY_H_ */
