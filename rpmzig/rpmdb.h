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
 * Advance the iterator and return the next package header blob from
 * the rpmdb Packages table.
 *
 * On success, `*blob_out` aliases sqlite-owned row memory and remains
 * valid until the next iterator advance or `tdnf_rpmdb_iter_close`.
 * `*blob_len_out` receives the blob length in bytes.
 *
 * Returns:
 *    1 on success (blob populated),
 *    0 on end-of-iteration,
 *   -1 on error (use tdnf_rpmdb_last_error).
 */
int tdnf_rpmdb_iter_next_header_blob(
    tdnf_rpmdb_iter *it,
    const unsigned char **blob_out,
    size_t *blob_len_out
);

/**
 * Free a string returned by tdnf_rpmdb_iter_next_nevra. Accepts NULL.
 */
void tdnf_rpmdb_string_free(char *s);

/* --- pubkey iterator (rpmdb-resident gpg-pubkey-* entries) --- */

typedef struct tdnf_rpmdb_pubkeys_iter tdnf_rpmdb_pubkeys_iter;

/**
 * Open a forward iterator over the rpmdb's `gpg-pubkey-*` entries.
 *
 * Each row stores an imported PGP public key as a fake installed
 * package: NAME="gpg-pubkey", VERSION=8-character key id, RELEASE=
 * creation timestamp, DESCRIPTION=armored key block. This iterator
 * yields the description and key id for each one.
 *
 * Returns NULL on error (use tdnf_rpmdb_last_error for details).
 */
tdnf_rpmdb_pubkeys_iter *tdnf_rpmdb_pubkeys_open(const char *root);

/**
 * Close and free a pubkey iterator. Accepts NULL.
 */
void tdnf_rpmdb_pubkeys_close(tdnf_rpmdb_pubkeys_iter *it);

/**
 * Advance the pubkey iterator. On hit, writes the armored ASCII key
 * block into `*key_out` (heap-allocated, free with
 * tdnf_rpmdb_string_free) and optionally its length (excluding
 * trailing NUL) into `*key_len_out`, plus the 8-character lowercase
 * hex key id into `*keyid_out` (heap-allocated, free with
 * tdnf_rpmdb_string_free).
 *
 * `key_len_out` and `keyid_out` may be NULL if the caller doesn't
 * need them.
 *
 * Returns:
 *    1 on success (key populated),
 *    0 on end-of-iteration,
 *   -1 on error (use tdnf_rpmdb_last_error).
 */
int tdnf_rpmdb_pubkeys_next(
    tdnf_rpmdb_pubkeys_iter *it,
    char **key_out,
    size_t *key_len_out,
    char **keyid_out
);

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
 * Returns the raw main-header blob for this rpm file.
 *
 * The returned bytes alias the file handle's owned buffer and remain
 * valid until tdnf_rpm_file_close(). The blob omits the 8-byte
 * standalone-header magic prefix and matches the rpmdb sqlite
 * Packages.blob format; callers can pass it back to
 * tdnf_rpm_file_install() as prior package metadata.
 *
 * Returns 0 on success, -1 on NULL arguments.
 */
int tdnf_rpm_file_main_header_blob(
    tdnf_rpm_file *fh,
    const unsigned char **out,
    size_t *out_len
);

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
 * Returns a static C string naming the kind of signature on this
 * rpm: "none", "rsa", "dsa", "pgp", "gpg", or "openpgp". Lifetime:
 * static; do not free.
 */
const char *tdnf_rpm_file_signature_kind(tdnf_rpm_file *fh);

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

/* --- native file installation engine (T4 building block) --- */

typedef enum tdnf_rpm_install_kind {
    TDNF_RPM_INSTALL_KIND_INSTALL = 0,
    TDNF_RPM_INSTALL_KIND_UPGRADE = 1,
    TDNF_RPM_INSTALL_KIND_REINSTALL = 2,
} tdnf_rpm_install_kind;

typedef struct tdnf_rpm_install_prior_header {
    const unsigned char *blob;
    size_t len;
} tdnf_rpm_install_prior_header;

/**
 * Callback used by tdnf_rpm_file_install() to ask whether `path`
 * conflicts with a file owned by another installed package that is
 * not being replaced in the current transaction.
 *
 * The callback should return:
 *   0  -> no conflict
 *   1  -> conflict; abort installation with ERROR_TDNF_TRANSACTION_FAILED
 *  <0  -> callback/query failure; abort installation
 *
 * `path` is the package-owned absolute path (for example
 * "/etc/foo.conf"), not rooted under install_root. `data` is the
 * opaque pointer from tdnf_rpm_install_options.conflict_fn_data.
 */
typedef int (*tdnf_rpm_install_conflict_fn)(void *data, const char *path);

typedef struct tdnf_rpm_install_options {
    /**
     * Install-root prefix. Pass NULL or "" for "/".
     */
    const char *install_root;
    /**
     * librpm-style RPMTRANS_FLAG_* bitmask. The native engine
     * currently consults JUSTDB, NODOCS, NOCAPS, and NOCONFIGS.
     */
    uint32_t trans_flags;
    /**
     * Controls config-file upgrade/reinstall semantics.
     */
    tdnf_rpm_install_kind install_kind;
    /**
     * Prior package headers being replaced or reinstalled. Each blob
     * is a raw header-v3 payload matching rpmdb sqlite Packages.blob
     * rows or tdnf_rpm_file_main_header_blob().
     */
    const tdnf_rpm_install_prior_header *prior_headers;
    size_t prior_header_count;
    /**
     * Optional ownership-conflict probe for #110 integration. May be
     * NULL when the caller does not yet have native file-ownership
     * data; in that case the engine only enforces config-file
     * replacement rules against prior_headers.
     */
    tdnf_rpm_install_conflict_fn conflict_fn;
    void *conflict_fn_data;
} tdnf_rpm_install_options;

/**
 * Install this rpm file's payload into install_root using the native
 * rpmzig file-installation engine.
 *
 * The engine applies file contents plus mode, ownership, and mtime,
 * preserves hardlinks, honours config(noreplace)/config overwrite
 * semantics using prior_headers, skips %ghost entries, and honours
 * NODOCS/NOCONFIGS/justdb/nocaps transaction flags.
 *
 * Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error()).
 */
int tdnf_rpm_file_install(
    tdnf_rpm_file *fh,
    const tdnf_rpm_install_options *options
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

/**
 * Returns the signature payload from the sig header and the byte
 * range of the file that the signature covers. Both slices alias
 * into the file handle's owned buffer.
 *
 * Returns 0 on success, -1 on failure (no signature, or NULL handle).
 */
int tdnf_rpm_file_signed_range(
    tdnf_rpm_file *fh,
    const unsigned char **sig_out,
    size_t *sig_len_out,
    const unsigned char **signed_out,
    size_t *signed_len_out
);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_RPMZIG_RPMDB_H_ */
