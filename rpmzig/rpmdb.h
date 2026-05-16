/*
 * tdnf rpmdb (Zig) — C ABI for the read-only Zig rpmdb reader.
 *
 * T1 of the librpm-replacement plan (see plan-replace-librpm.md in
 * the session-state archive). The implementation lives in
 * rpmzig/rpmdb.zig (+ rpmzig/header.zig for the RPM header v3
 * decoder) and is linked into libtdnf, tdnf-rpmdb-count, and
 * tdnf-rpmdb-list.
 */
#ifndef _TDNF_RPMZIG_RPMDB_H_
#define _TDNF_RPMZIG_RPMDB_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Count rows in /var/lib/rpm/rpmdb.sqlite's Packages table.
 *
 * `root` is the install-root prefix (matches rpm's --root). Pass NULL
 * or "" for "/".
 *
 * Returns the row count on success, or -1 on error. Use
 * tdnf_rpmdb_last_error() to retrieve the error message.
 */
int64_t tdnf_rpmdb_count_packages(const char *root);

/**
 * Returns the last error message produced by any rpmzig call on the
 * current thread. The returned pointer is stable until the next call
 * into rpmzig. Returns an empty string when no error is pending.
 */
const char *tdnf_rpmdb_last_error(void);

/**
 * Returns an opaque "cookie" string that captures the rpmdb state.
 * Two calls return the same cookie iff the rpmdb has not changed
 * between them. Replaces librpm's rpmdbCookie() — same role,
 * different format.
 *
 * Caller owns the returned string and must free it with
 * tdnf_rpmdb_string_free. Returns NULL on error.
 */
char *tdnf_rpmdb_cookie(const char *root);

/* --- forward iterator over the Packages table --- */

typedef struct tdnf_rpmdb_iter tdnf_rpmdb_iter;

/**
 * Open a forward iterator over the rpmdb Packages table for the
 * sqlite database under `root`.
 *
 * Returns NULL on error (use tdnf_rpmdb_last_error for details).
 */
tdnf_rpmdb_iter *tdnf_rpmdb_iter_open(const char *root);

/**
 * Close and free an iterator opened by tdnf_rpmdb_iter_open.
 * Accepts NULL.
 */
void tdnf_rpmdb_iter_close(tdnf_rpmdb_iter *it);

/**
 * Advance the iterator and write the next package's NEVRA string into
 * `*nevra_out`. The string is heap-allocated; free with
 * tdnf_rpmdb_string_free.
 *
 * The NEVRA format is `name-[epoch:]version-release.arch` — matching
 * librpm's `headerGetAsString(h, RPMTAG_NEVRA)` output exactly so
 * existing history-DB rows stay comparable.
 *
 * Returns:
 *    1 on success (NEVRA populated),
 *    0 on end-of-iteration,
 *   -1 on error (use tdnf_rpmdb_last_error).
 */
int tdnf_rpmdb_iter_next_nevra(tdnf_rpmdb_iter *it, char **nevra_out);

/**
 * Free a string returned by tdnf_rpmdb_iter_next_nevra. Accepts NULL.
 */
void tdnf_rpmdb_string_free(char *s);

/* --- `.rpm` file reader (T2) --- */

typedef struct tdnf_rpm_file tdnf_rpm_file;

/**
 * Open and parse a `.rpm` file. Returns NULL on error (consult
 * tdnf_rpmdb_last_error()).
 */
tdnf_rpm_file *tdnf_rpm_file_open(const char *path);

/**
 * Free a file handle. Accepts NULL.
 */
void tdnf_rpm_file_close(tdnf_rpm_file *fh);

/**
 * Returns a heap-allocated NEVRA string for this rpm file. Caller
 * frees with tdnf_rpmdb_string_free.
 */
char *tdnf_rpm_file_nevra(tdnf_rpm_file *fh);

/**
 * Returns the payload compressor name as a static C string
 * ("none", "gzip", "bzip2", "xz", "lzma", "zstd", "lz4", or
 * "unknown"). Lifetime: static; do not free.
 */
const char *tdnf_rpm_file_compressor(tdnf_rpm_file *fh);

/**
 * Returns the byte offset of the payload (cpio archive) within the
 * underlying file.
 */
int64_t tdnf_rpm_file_payload_offset(tdnf_rpm_file *fh);

/**
 * Returns 1 if the rpm has any of the known signature tags
 * (RSA/DSA/PGP/GPG/OpenPGP) in its signature header, 0 otherwise.
 * Returns -1 on a NULL handle.
 *
 * This is presence-only; real signature verification is T3.
 */
int tdnf_rpm_file_is_signed(tdnf_rpm_file *fh);

/**
 * Decompress the payload (cpio archive) into a fresh malloc'd
 * buffer. On success, writes the pointer to `*out` and the byte
 * count to `*out_size`. Caller frees the buffer with
 * tdnf_rpmdb_string_free.
 *
 * Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error).
 */
int tdnf_rpm_file_decompress_payload(
    tdnf_rpm_file *fh,
    unsigned char **out,
    size_t *out_size
);

/* --- files-in-package iterator --- */

typedef struct tdnf_rpm_files_iter tdnf_rpm_files_iter;

/**
 * Open a files-in-package iterator. Decompresses the payload up
 * front, so large packages briefly hold their full cpio archive in
 * memory.
 *
 * Returns NULL on error (use tdnf_rpmdb_last_error).
 */
tdnf_rpm_files_iter *tdnf_rpm_file_files_open(tdnf_rpm_file *fh);

/**
 * Free a files iterator. Accepts NULL.
 */
void tdnf_rpm_file_files_close(tdnf_rpm_files_iter *it);

/**
 * Advance the iterator. On success writes the next entry's name
 * into `*name_out` (stable pointer; do NOT free) and its mode bits
 * into `*mode_out` (may be NULL if uninterested).
 *
 * Returns:
 *    1 on success,
 *    0 on end-of-archive,
 *   -1 on error.
 */
int tdnf_rpm_file_files_next(
    tdnf_rpm_files_iter *it,
    const char **name_out,
    uint32_t *mode_out
);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_RPMZIG_RPMDB_H_ */

