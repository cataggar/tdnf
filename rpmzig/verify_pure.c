/*
 * Pure-Zig signature verifier glue (PR #5 of plan-pure-zig-pgp.md).
 *
 * Bridges the C-side `tdnf_rpm_file` to the Zig-side
 * `rpmzig_verify_detached` (declared in pgp/verify.zig via `export
 * fn`). Stores no state and adds no extra crypto runtime dependency
 * beyond the Zig-side verifier already linked into rpmzig_lib.
 *
 * Status codes returned via *out_status are the same
 * TDNF_RPMZIG_STATUS_* set; INTERNAL_ERROR=4 is the catch-all for
 * unsupported or otherwise unexpected verifier input.
 */

#include <stdio.h>
#include <string.h>

#include "rpmdb.h"
#include "verify.h"

/* Declared in pgp/verify.zig via `export fn`. */
extern int rpmzig_verify_detached(
    const unsigned char *sig_bytes, size_t sig_len,
    const unsigned char *signed_bytes, size_t signed_len,
    const void *const *key_blobs, const size_t *key_lens, size_t key_count);

int tdnf_rpmzig_verify_pure(
    tdnf_rpm_file *fh,
    const void *const *key_blobs,
    const size_t *key_lens,
    size_t key_count,
    int *out_status)
{
    const unsigned char *sig_bytes = NULL;
    size_t sig_len = 0;
    const unsigned char *signed_bytes = NULL;
    size_t signed_len = 0;
    int rc = 0;
    int status = 0;

    if (!fh || !out_status) return -1;
    *out_status = TDNF_RPMZIG_STATUS_INTERNAL_ERROR;

    rc = tdnf_rpm_file_signed_range(fh,
        &sig_bytes, &sig_len,
        &signed_bytes, &signed_len);
    if (rc != 0) {
        *out_status = TDNF_RPMZIG_STATUS_NO_SIG;
        return 1;
    }

    status = rpmzig_verify_detached(
        sig_bytes, sig_len,
        signed_bytes, signed_len,
        key_blobs, key_lens, key_count);
    *out_status = status;
    return status == TDNF_RPMZIG_STATUS_OK ? 0 : 1;
}
