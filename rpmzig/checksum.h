/*
 * Pure-Zig checksum API shared by future C-side digest callers.
 *
 * The implementation lives in rpmzig/checksum.zig and exposes an
 * incremental hashing interface over std.crypto.
 */
#ifndef _TDNF_RPMZIG_CHECKSUM_H_
#define _TDNF_RPMZIG_CHECKSUM_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tdnf_rpmzig_digest_ctx tdnf_rpmzig_digest_ctx;

enum {
    TDNF_RPMZIG_MAX_DIGEST_LEN = 64,
};

/**
 * Open an incremental digest context.
 *
 * `kind` intentionally reuses the existing TDNF_HASH_* integer values
 * from common/structs.h exactly:
 *
 *   TDNF_HASH_MD5    == 0
 *   TDNF_HASH_SHA1   == 1
 *   TDNF_HASH_SHA256 == 2
 *   TDNF_HASH_SHA512 == 3
 *
 * This contract lets future callers pass `nChecksumType` /
 * `TDNF_HASH_*` straight through without a translation table.
 *
 * Returns a heap-allocated opaque context on success, or NULL on
 * error (use tdnf_rpmzig_checksum_last_error()).
 */
tdnf_rpmzig_digest_ctx *tdnf_rpmzig_digest_open(int kind);

/**
 * Feed `len` bytes into the digest context. Returns 0 on success,
 * -1 on error.
 */
int tdnf_rpmzig_digest_update(
    tdnf_rpmzig_digest_ctx *ctx,
    const unsigned char *buf,
    size_t len
);

/**
 * Finalize the digest and write the raw digest bytes into
 * `out_digest`. `out_len` must be at least the digest length for the
 * chosen algorithm; larger buffers are allowed. Returns 0 on
 * success, -1 on error.
 */
int tdnf_rpmzig_digest_final(
    tdnf_rpmzig_digest_ctx *ctx,
    unsigned char *out_digest,
    size_t out_len
);

/**
 * Free a digest context opened by tdnf_rpmzig_digest_open. Accepts
 * NULL.
 */
void tdnf_rpmzig_digest_close(tdnf_rpmzig_digest_ctx *ctx);

/**
 * Returns the last error message produced by any checksum call on the
 * current thread. The returned pointer is stable until the next call
 * into the checksum API. Returns an empty string when no error is
 * pending.
 */
const char *tdnf_rpmzig_checksum_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_RPMZIG_CHECKSUM_H_ */
