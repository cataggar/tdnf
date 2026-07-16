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
#include "../include/tdnfrpmconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tdnf_rpm_file tdnf_rpm_file;

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
int64_t tdnf_rpmdb_count_packages_config(
    const tdnf_rpm_config *config);

/**
 * Returns the last error message produced by any rpmzig call on the
 * current thread. The returned pointer is stable until the next call
 * into rpmzig. Returns an empty string when no error is pending.
 */
const char *tdnf_rpmdb_last_error(void);

/* --- native rpm configuration and macro expansion --- */

/**
 * Create a handle-scoped native rpm configuration rooted at
 * `install_root`. Pass NULL or "" for "/".
 *
 * Returns NULL on error (use tdnf_rpmdb_last_error()).
 */
tdnf_rpm_config *tdnf_rpm_config_create(const char *install_root);

/**
 * Destroy a configuration created by tdnf_rpm_config_create().
 * Accepts NULL.
 */
void tdnf_rpm_config_destroy(tdnf_rpm_config *config);

char *tdnf_rpm_config_install_root(const tdnf_rpm_config *config);
int tdnf_rpm_config_open_root_fd(const tdnf_rpm_config *config);

/**
 * Apply one command-line rpmdefine in whitespace or equals form.
 *
 * Returns 0 on success, -1 on invalid input or allocation failure.
 */
int tdnf_rpm_config_apply_define(
    tdnf_rpm_config *config,
    const char *definition
);

/**
 * Expand a named macro using the current handle-scoped definitions.
 *
 * The caller owns the returned string and must free it with
 * tdnf_rpm_config_string_free(). Returns NULL on error.
 */
char *tdnf_rpm_config_expand(
    const tdnf_rpm_config *config,
    const char *name
);

/**
 * Resolve a path macro under the configuration's install root.
 *
 * Only native path macros (_dbpath, _tmppath, _topdir, _specdir,
 * and _sourcedir) are accepted. The caller owns the returned string
 * and must free it with tdnf_rpm_config_string_free().
 */
char *tdnf_rpm_config_resolve_path(
    const tdnf_rpm_config *config,
    const char *name
);

/**
 * Returns an opaque "cookie" string that captures the rpmdb state.
 * Two calls return the same cookie iff the rpmdb has not changed
 * between them. It has the same role as the legacy database cookie,
 * with a native format.
 *
 * Caller owns the returned string and must free it with
 * tdnf_rpmdb_string_free. Returns NULL on error.
 */
char *tdnf_rpmdb_cookie(const char *root);

char *tdnf_rpmdb_cookie_config(
    const tdnf_rpm_config *config
);

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
 * Open a forward iterator using a handle-scoped native configuration.
 * A missing rpmdb is exposed as an empty iterator.
 */
tdnf_rpmdb_iter *tdnf_rpmdb_iter_open_config(
    const tdnf_rpm_config *config
);

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
 * The NEVRA format is `name-[epoch:]version-release.arch`, matching
 * legacy query output so existing history-DB rows stay comparable.
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
 * Advance the iterator and return the next package hnum and header blob.
 *
 * The blob has the same lifetime as
 * tdnf_rpmdb_iter_next_header_blob(). `*hnum_out` identifies the exact
 * Packages row represented by the returned blob.
 */
int tdnf_rpmdb_iter_next_header_blob_hnum(
    tdnf_rpmdb_iter *it,
    uint32_t *hnum_out,
    const unsigned char **blob_out,
    size_t *blob_len_out
);

/**
 * Free a string returned by tdnf_rpmdb_iter_next_nevra. Accepts NULL.
 */
void tdnf_rpmdb_string_free(char *s);

/* --- configured provider lookup --- */

/**
 * Find the first installed package providing `provide_name`, ordered by
 * rpmdb hnum. The returned version is the package VERSION unless a matching
 * provide has RPMSENSE_EQUAL, in which case it is that provide's EVR.
 *
 * The query uses the configured Providename secondary index and validates
 * the provider header's parallel name/flags/version arrays. `*version_out`
 * is allocated on success and must be freed with tdnf_rpmdb_string_free.
 *
 * Returns:
 *    1 when a provider was found
 *    0 when no provider was found
 *   -1 on query, header, or allocation error
 */
int tdnf_rpmdb_resolve_provider_version_config(
    const tdnf_rpm_config *config,
    const char *provide_name,
    char **version_out
);

/* --- native sqlite rpmdb write path --- */

/**
 * Insert one package into the sqlite rpmdb under `root`.
 *
 * The package header comes from `rpm_path`. The writer augments it the
 * same way real rpm does for an installed package: translated
 * signature-header tags, INSTALLTIME / INSTALLTID / INSTALLCOLOR, and
 * FILESTATES.
 *
 * `file_states` may be NULL when the caller wants the default
 * all-zero FILESTATES vector; otherwise it must point to exactly one
 * byte per file in the package payload.
 *
 * On success writes the newly allocated rpmdb `hnum` into `*hnum_out`
 * when non-NULL.
 *
 * Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error()).
 */
int tdnf_rpmdb_write_install(
    const char *root,
    const char *rpm_path,
    uint32_t install_tid,
    uint32_t install_time,
    uint32_t install_color,
    const unsigned char *file_states,
    size_t file_state_count,
    uint32_t *hnum_out
);

int tdnf_rpmdb_write_install_config(
    const tdnf_rpm_config *config,
    const char *rpm_path,
    uint32_t install_tid,
    uint32_t install_time,
    uint32_t install_color,
    const unsigned char *file_states,
    size_t file_state_count,
    uint32_t *hnum_out
);

/**
 * Insert the package represented by an already-open native file handle.
 *
 * The handle remains owned by the caller and is not closed. This variant
 * avoids reopening a pathname after package verification.
 */
int tdnf_rpmdb_write_install_file_config(
    const tdnf_rpm_config *config,
    tdnf_rpm_file *fh,
    uint32_t install_tid,
    uint32_t install_time,
    uint32_t install_color,
    const unsigned char *file_states,
    size_t file_state_count,
    uint32_t *hnum_out
);

/**
 * Replace an existing rpmdb row identified by `old_hnum` with the
 * package at `rpm_path`, allocating a fresh replacement `hnum` like
 * real rpm does for upgrade/reinstall writes.
 *
 * Returns 0 on success, -1 on error.
 */
int tdnf_rpmdb_write_replace(
    const char *root,
    uint32_t old_hnum,
    const char *rpm_path,
    uint32_t install_tid,
    uint32_t install_time,
    uint32_t install_color,
    const unsigned char *file_states,
    size_t file_state_count,
    uint32_t *new_hnum_out
);

int tdnf_rpmdb_write_replace_config(
    const tdnf_rpm_config *config,
    uint32_t old_hnum,
    const char *rpm_path,
    uint32_t install_tid,
    uint32_t install_time,
    uint32_t install_color,
    const unsigned char *file_states,
    size_t file_state_count,
    uint32_t *new_hnum_out
);

/**
 * Replace an rpmdb row from an already-open native file handle.
 *
 * The handle remains owned by the caller and is not closed.
 */
int tdnf_rpmdb_write_replace_file_config(
    const tdnf_rpm_config *config,
    uint32_t old_hnum,
    tdnf_rpm_file *fh,
    uint32_t install_tid,
    uint32_t install_time,
    uint32_t install_color,
    const unsigned char *file_states,
    size_t file_state_count,
    uint32_t *new_hnum_out
);

/**
 * Erase one installed package row, identified by its sqlite `hnum`,
 * from the rpmdb under `root`.
 *
 * Returns 0 on success, -1 on error.
 */
int tdnf_rpmdb_write_erase_hnum(const char *root, uint32_t hnum);
int tdnf_rpmdb_write_erase_hnum_config(
    const tdnf_rpm_config *config,
    uint32_t hnum
);

/**
 * Find the sqlite `hnum` for `nevra` under `root`.
 *
 * Returns:
 *    1 when found (`*hnum_out` populated)
 *    0 when no installed package matches
 *   -1 on error
 */
int tdnf_rpmdb_find_hnum_by_nevra(
    const char *root,
    const char *nevra,
    uint32_t *hnum_out
);
int tdnf_rpmdb_find_hnum_by_nevra_config(
    const tdnf_rpm_config *config,
    const char *nevra,
    uint32_t *hnum_out
);

/**
 * Look up every installed package hnum whose NAME matches `name`.
 *
 * On success writes a heap-allocated array of hnums into
 * `*hnums_out` (free with tdnf_rpmdb_hnums_free) and the count into
 * `*count_out`. When there are no matches, `*hnums_out` is NULL and
 * `*count_out` is 0.
 *
 * Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error()).
 */
int tdnf_rpmdb_find_hnums_by_name(
    const char *root,
    const char *name,
    uint32_t **hnums_out,
    size_t *count_out
);
int tdnf_rpmdb_find_hnums_by_name_config(
    const tdnf_rpm_config *config,
    const char *name,
    uint32_t **hnums_out,
    size_t *count_out
);

typedef struct tdnf_rpmdb_label_match {
    uint32_t hnum;
    char *name;
    char *evr;
    char *arch;
} tdnf_rpmdb_label_match;

/**
 * Find all installed rows whose NAME and canonical EVR exactly match.
 *
 * Results are ordered by rpmdb hnum and intentionally do not filter by arch,
 * matching the previous RPMDBI_LABEL lookup of "name-EVR". Each result carries
 * the row's actual name/EVR/arch metadata. Free with
 * tdnf_rpmdb_label_matches_free().
 */
int tdnf_rpmdb_find_label_matches_config(
    const tdnf_rpm_config *config,
    const char *name,
    const char *evr,
    tdnf_rpmdb_label_match **matches_out,
    size_t *count_out
);

void tdnf_rpmdb_label_matches_free(
    tdnf_rpmdb_label_match *matches,
    size_t count
);

/**
 * Free an hnum array returned by tdnf_rpmdb_find_hnums_by_name.
 * Accepts NULL.
 */
void tdnf_rpmdb_hnums_free(uint32_t *hnums);

/**
 * Read the raw main-header blob for the installed package with
 * `hnum` under `root`. On success writes a heap-allocated blob
 * pointer into `*blob_out` (free with tdnf_rpmdb_blob_free) and its
 * length into `*len_out`.
 *
 * Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error()).
 */
int tdnf_rpmdb_read_header_blob(
    const char *root,
    uint32_t hnum,
    unsigned char **blob_out,
    size_t *len_out
);
int tdnf_rpmdb_read_header_blob_config(
    const tdnf_rpm_config *config,
    uint32_t hnum,
    unsigned char **blob_out,
    size_t *len_out
);

/**
 * Free a blob returned by tdnf_rpmdb_read_header_blob. Accepts NULL.
 */
void tdnf_rpmdb_blob_free(unsigned char *blob);

/* --- pubkey iterator (rpmdb-resident gpg-pubkey-* entries) --- */

typedef struct tdnf_rpmdb_pubkeys_iter tdnf_rpmdb_pubkeys_iter;

/**
 * Import every transferable public-key certificate in `data`.
 *
 * Input may be binary packets or one or more concatenated ASCII-armored
 * public-key blocks. All armor CRCs, packet framing, primary keys, and
 * subkeys are validated before the rpmdb is changed. Matching records are
 * deduplicated by full primary fingerprint and replaced together in one
 * SQLite transaction.
 *
 * For compatibility with rpm 4 hosts, imported package VERSION values use
 * the primary eight-character short ID rather than rpm 6's full-fingerprint
 * VERSION schema. Full primary/subkey fingerprints are indexed as gpg(id)
 * provides. `imported_out` may be NULL.
 *
 * Returns 0 on success and -1 on error.
 */
int tdnf_rpmdb_import_pubkeys(
    const char *root,
    const void *data,
    size_t len,
    size_t *imported_out
);
int tdnf_rpmdb_import_pubkeys_config(
    const tdnf_rpm_config *config,
    const void *data,
    size_t len,
    size_t *imported_out
);

/**
 * Open a forward iterator over the rpmdb's `gpg-pubkey-*` entries.
 *
 * Each row stores an imported PGP public key as a fake installed
 * package: NAME="gpg-pubkey", VERSION=8-character key id, RELEASE=
 * creation timestamp, PUBKEYS=base64 packet stream, and DESCRIPTION=
 * armored key block. The iterator yields decoded PUBKEYS bytes, with
 * DESCRIPTION retained as a fallback for legacy records.
 *
 * Returns NULL on error (use tdnf_rpmdb_last_error for details).
 * A missing or schema-empty rpmdb opens as an empty iterator.
 */
tdnf_rpmdb_pubkeys_iter *tdnf_rpmdb_pubkeys_open(const char *root);
tdnf_rpmdb_pubkeys_iter *tdnf_rpmdb_pubkeys_open_config(
    const tdnf_rpm_config *config
);

/**
 * Close and free a pubkey iterator. Accepts NULL.
 */
void tdnf_rpmdb_pubkeys_close(tdnf_rpmdb_pubkeys_iter *it);

/**
 * Advance the pubkey iterator. On hit, writes the binary PUBKEYS content
 * (or the armored DESCRIPTION for legacy records without PUBKEYS) into
 * `*key_out` (heap-allocated, free with
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

enum {
    TDNF_RPM_PACKAGE_KIND_BINARY = 0,
    TDNF_RPM_PACKAGE_KIND_SOURCE = 1,
    TDNF_RPM_PACKAGE_KIND_NOSRC = 2,
};

/**
 * Return the package kind derived from SOURCEPACKAGE/NOSOURCE metadata.
 *
 * Returns TDNF_RPM_PACKAGE_KIND_*, or -1 for a NULL handle.
 */
int tdnf_rpm_file_package_kind(tdnf_rpm_file *fh);

typedef struct tdnf_rpm_file_metadata {
    const char *name;
    const char *version;
    const char *release;
    const char *arch;
    uint32_t epoch;
    int has_epoch;
    int package_kind;
    const unsigned char *main_header_blob;
    size_t main_header_blob_len;
} tdnf_rpm_file_metadata;

typedef struct tdnf_rpm_header_view {
    const unsigned char *blob;
    size_t len;
} tdnf_rpm_header_view;

/*
 * Lightweight helpers for transaction overlays. They return 1 for a match,
 * 0 for no match, and -1 for a malformed header or invalid argument.
 */
int tdnf_rpm_header_name_equals(
    const unsigned char *header_blob,
    size_t header_len,
    const char *name
);

int tdnf_rpm_header_owns_path(
    const unsigned char *header_blob,
    size_t header_len,
    const char *path
);

int tdnf_rpm_canonical_path_config(
    const tdnf_rpm_config *config,
    const char *path,
    char *output,
    size_t output_len
);

int tdnf_rpm_header_owns_path_config(
    const unsigned char *header_blob,
    size_t header_len,
    const char *path,
    const tdnf_rpm_config *config
);

/**
 * Return typed package metadata and the retained main-header blob.
 *
 * String and blob pointers alias the parsed file handle and remain valid until
 * tdnf_rpm_file_close(). No pathname is reopened and no librpm Header is
 * constructed.
 */
int tdnf_rpm_file_get_metadata(
    tdnf_rpm_file *fh,
    tdnf_rpm_file_metadata *metadata_out
);

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
 * Return the exact immutable bytes owned by this parsed file handle.
 *
 * The returned bytes alias the handle and remain valid until
 * tdnf_rpm_file_close(). Returns 0 on success, -1 on invalid arguments.
 */
int tdnf_rpm_file_bytes(
    tdnf_rpm_file *fh,
    const unsigned char **out,
    size_t *out_len
);

/**
 * Calculate a digest over the exact bytes owned by this parsed file handle.
 *
 * `kind` uses the TDNF_HASH_* values from common/structs.h. The output
 * buffer must be at least the digest length for that kind. Returns 0 on
 * success, or -1 on invalid arguments/allocation failure.
 */
int tdnf_rpm_file_digest(
    tdnf_rpm_file *fh,
    int kind,
    unsigned char *out_digest,
    size_t out_len
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

/*
 * Typed results returned by the native package-integrity ABI.  A result is
 * always written to the supplied out parameter when the function returns 0.
 * A -1 return means the ABI could not complete (invalid arguments, rpmdb
 * access failure, or allocation failure); consult tdnf_rpmdb_last_error().
 */
enum {
    TDNF_RPMZIG_INTEGRITY_OK          = 0,
    TDNF_RPMZIG_INTEGRITY_MISSING     = 1,
    TDNF_RPMZIG_INTEGRITY_BAD         = 2,
    TDNF_RPMZIG_INTEGRITY_UNSUPPORTED = 3,
    TDNF_RPMZIG_INTEGRITY_MALFORMED   = 4,
    TDNF_RPMZIG_INTEGRITY_INTERNAL    = 5,
};

/**
 * Verify all enabled internal digest candidates on an already-parsed RPM.
 *
 * The result applies the Phase 2 candidate aggregation rules: a verified
 * candidate suppresses failed, malformed, or unsupported optional payload
 * alternatives in the same group, and both header and payload coverage are
 * required.
 */
int tdnf_rpm_file_verify_digests(
    tdnf_rpm_file *fh,
    int *outcome_out
);

/**
 * Verify every recognized OpenPGP candidate on an already-parsed RPM against
 * the configured rpmdb keyring plus `fresh_key_blobs`.  The fresh key blobs
 * are optional and are normally the user-approved repository keys imported
 * immediately before this call.
 *
 * No file is reopened or reparsed.  A malformed/unreadable rpmdb keyring is
 * an ABI error (-1), never an empty trust set.
 */
int tdnf_rpm_file_verify_signatures_config(
    tdnf_rpm_file *fh,
    const tdnf_rpm_config *config,
    const void *const *fresh_key_blobs,
    const size_t *fresh_key_lens,
    size_t fresh_key_count,
    int *outcome_out
);

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

/**
 * Validate and extract a source/nosrc RPM from the retained parsed handle.
 *
 * Package-scoped name/version/release/epoch macros are applied in a child
 * configuration before _topdir/_specdir/_sourcedir are resolved. JUSTDB
 * validates the complete source package but suppresses filesystem writes.
 * Source packages are never written to the binary rpmdb.
 */
int tdnf_rpm_file_extract_source_config(
    tdnf_rpm_file *fh,
    const tdnf_rpm_config *config,
    uint32_t trans_flags
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
typedef int (*tdnf_rpm_changed_path_fn)(void *data, const char *path);

typedef struct tdnf_rpm_install_options {
    /**
     * Install-root prefix. Pass NULL or "" for "/".
     */
    const char *install_root;
    /**
     * Optional handle-scoped rpm configuration. When supplied it is
     * authoritative for the install root and native path macros.
     */
    const tdnf_rpm_config *config;
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
    /**
     * Optional notification for each package path actually installed.
     * The callback runs only after the corresponding filesystem action
     * succeeds. It returns 0 on success and non-zero to abort.
     */
    tdnf_rpm_changed_path_fn changed_path_fn;
    void *changed_path_fn_data;
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

/* --- native scriptlet execution primitive (T4 building block) --- */

typedef enum tdnf_rpm_scriptlet_phase {
    TDNF_RPM_SCRIPTLET_PHASE_PRE = 0,
    TDNF_RPM_SCRIPTLET_PHASE_POST = 1,
    TDNF_RPM_SCRIPTLET_PHASE_PREUN = 2,
    TDNF_RPM_SCRIPTLET_PHASE_POSTUN = 3,
    TDNF_RPM_SCRIPTLET_PHASE_PRETRANS = 4,
    TDNF_RPM_SCRIPTLET_PHASE_POSTTRANS = 5,
} tdnf_rpm_scriptlet_phase;

typedef enum tdnf_rpm_scriptlet_outcome {
    TDNF_RPM_SCRIPTLET_OUTCOME_NOT_RUN = 0,
    TDNF_RPM_SCRIPTLET_OUTCOME_OK = 1,
    TDNF_RPM_SCRIPTLET_OUTCOME_EXITED = 2,
    TDNF_RPM_SCRIPTLET_OUTCOME_SIGNALED = 3,
} tdnf_rpm_scriptlet_outcome;

typedef struct tdnf_rpm_scriptlet_options {
    /**
     * Install-root prefix for chrooted execution. Pass NULL or ""
     * for "/".
     */
    const char *install_root;
    /**
     * Optional handle-scoped rpm configuration. When supplied it is
     * authoritative for the install root and native path macros.
     */
    const tdnf_rpm_config *config;
    int install_root_fd;
    /**
     * librpm-style RPMTRANS_FLAG_* bitmask. The executor honours
     * NOSCRIPTS and JUSTDB plus the phase-specific NOPRE/NOPOST/
     * NOPREUN/NOPOSTUN/NOPRETRANS/NOPOSTTRANS flags.
     */
    uint32_t trans_flags;
    /**
     * Optional rpmdefine overrides applied to the native transaction
     * config store before execution. This is how callers override
     * macros such as _tmppath and _install_script_path.
     */
    const char *const *rpmdefines;
    size_t rpmdefine_count;
    /**
     * Positional arguments appended after the script path. Pass a
     * negative value to omit the corresponding argument.
     */
    int arg1;
    int arg2;
    /**
     * If non-negative, duplicate this file descriptor onto stderr in
     * the child before exec.
     */
    int script_fd;
    /**
     * When non-zero, duplicate stderr (or script_fd when supplied)
     * onto stdout before exec. This matches the tdnf JSON-output
     * requirement where scriptlet chatter must not corrupt stdout.
     */
    int redirect_stdout_to_stderr;
} tdnf_rpm_scriptlet_options;

typedef struct tdnf_rpm_scriptlet_result {
    int ran;
    int critical;
    tdnf_rpm_scriptlet_outcome outcome;
    int exit_status;
    int signal_number;
} tdnf_rpm_scriptlet_result;

/**
 * Execute one package/transaction scriptlet extracted from a
 * raw RPM main-header blob.
 *
 * The header blob must match the format returned by
 * tdnf_rpm_file_main_header_blob() or stored in the sqlite rpmdb
 * Packages.blob column. Shell scriptlets are supported by default.
 * Lua (`<lua>`) scriptlets are supported only when built with
 * `zig build -Drpmzig-lua=true ...`; otherwise they return -1.
 *
 * On success, `*result_out` is always populated. A non-zero script
 * exit is reported in `result_out->outcome` plus `exit_status`; it is
 * not treated as an API failure because callers need to distinguish
 * aborting phases (%pre/%preun/%pretrans) from warning-only phases.
 *
 * Returns 0 on success, -1 on API/parse/runtime setup failure (use
 * tdnf_rpmdb_last_error()).
 */
int tdnf_rpm_header_run_scriptlet(
    const unsigned char *header_blob,
    size_t header_len,
    tdnf_rpm_scriptlet_phase phase,
    const tdnf_rpm_scriptlet_options *options,
    tdnf_rpm_scriptlet_result *result_out
);

/* --- native trigger execution engine (T4 building block) --- */

typedef enum tdnf_rpm_trigger_phase {
    TDNF_RPM_TRIGGER_PHASE_TRIGGERIN = 0,
    TDNF_RPM_TRIGGER_PHASE_TRIGGERUN = 1,
    TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN = 2,
} tdnf_rpm_trigger_phase;

typedef struct tdnf_rpm_trigger_options {
    /**
     * Install-root prefix used to locate the sqlite rpmdb that
     * contains the trigger-owning packages. Pass NULL or "" to fall
     * back to install_root.
     */
    const char *db_root;
    /**
     * Install-root prefix for chrooted trigger-script execution.
     * Pass NULL or "" for "/".
     */
    const char *install_root;
    /**
     * Optional handle-scoped rpm configuration. When supplied it is
     * authoritative for the rpmdb, install root, and native macros.
     */
    const tdnf_rpm_config *config;
    int install_root_fd;
    /**
     * librpm-style RPMTRANS_FLAG_* bitmask. The trigger engine
     * honours NOSCRIPTS, JUSTDB, NOTRIGGERS, and the phase-specific
     * NOTRIGGERIN/NOTRIGGERUN/NOTRIGGERPOSTUN flags.
     */
    uint32_t trans_flags;
    /**
     * Optional rpmdefine overrides applied to the native transaction
     * config store before execution.
     */
    const char *const *rpmdefines;
    size_t rpmdefine_count;
    /**
     * If non-negative, duplicate this file descriptor onto stderr in
     * the child before exec.
     */
    int script_fd;
    /**
     * When non-zero, duplicate stderr (or script_fd when supplied)
     * onto stdout before exec.
     */
    int redirect_stdout_to_stderr;
    /**
     * Optional explicit `$2` argument for the trigger scripts.
     *
     * When `arg2_override_present == 0` the engine derives `$2`
     * from the current triggering-package instance count in the
     * rpmdb (real rpm's plain-install/plain-erase formula). When
     * non-zero, `arg2_override_value` is passed verbatim.
     *
     * The composed native transaction executor uses this to match
     * real rpm's upgrade semantics: `%triggerin` on the new package
     * during upgrade fires with `nPriors + 1` (real rpm briefly
     * has both old and new co-installed), and `%triggerun` /
     * `%triggerpostun` on the OLD package during upgrade cleanup
     * fire with `1` (the new instance survives). Plain install and
     * plain erase leave the override at 0 and let the engine
     * compute `$2` from the rpmdb.
     */
    int arg2_override_present;
    int arg2_override_value;
    /**
     * Optional phase-aware package-count view. When supplied, instance
     * counts use these headers instead of reopening the physical rpmdb.
     */
    const tdnf_rpm_header_view *transaction_headers;
    size_t transaction_header_count;
    int transaction_view_present;
    /**
     * Optional rpmdb-index-visible subset for trigger-owner discovery.
     * This differs from the count view for NODB additions.
     */
    const tdnf_rpm_header_view *trigger_owner_headers;
    size_t trigger_owner_header_count;
    int trigger_owner_view_present;
} tdnf_rpm_trigger_options;

typedef struct tdnf_rpm_trigger_result {
    int ran;
    int critical;
    tdnf_rpm_scriptlet_outcome outcome;
    int exit_status;
    int signal_number;
} tdnf_rpm_trigger_result;

/**
 * Execute every installed-package shell trigger matching the given
 * triggering package header and trigger phase.
 *
 * The trigger-owning packages are discovered from the sqlite rpmdb
 * under `options->db_root` (or `options->install_root` when db_root
 * is NULL/empty). The executor reuses the native shell/Lua scriptlet
 * path.
 *
 * Caller phase-ordering contract:
 *   - %triggerin: call after the triggering package's new rpmdb row
 *     is visible, so `$2` sees the post-install instance count.
 *   - %triggerun / %triggerpostun: call before erasing the old rpmdb
 *     row, so the engine can subtract the just-removed instance and
 *     match real rpm's `$2` semantics.
 *
 * `$1` is the installed count of the trigger-owning package name;
 * `$2` is the installed count of the triggering package name after
 * the current install/remove step, matching real rpm's trigger arg
 * convention.
 *
 * Trigger phases are warning-only in real rpm. Accordingly, a
 * non-zero trigger exit populates result_out->outcome and returns 0;
 * API/setup/parse failures return -1 (use tdnf_rpmdb_last_error()).
 */
int tdnf_rpm_header_run_triggers(
    const unsigned char *header_blob,
    size_t header_len,
    tdnf_rpm_trigger_phase phase,
    const tdnf_rpm_trigger_options *options,
    tdnf_rpm_trigger_result *result_out
);

typedef enum tdnf_rpm_file_trigger_kind {
    TDNF_RPM_FILE_TRIGGER_KIND_PACKAGE = 0,
    TDNF_RPM_FILE_TRIGGER_KIND_TRANSACTION = 1,
} tdnf_rpm_file_trigger_kind;

typedef enum tdnf_rpm_trigger_priority_class {
    TDNF_RPM_TRIGGER_PRIORITY_ALL = 0,
    TDNF_RPM_TRIGGER_PRIORITY_HIGH = 1,
    TDNF_RPM_TRIGGER_PRIORITY_LOW = 2,
} tdnf_rpm_trigger_priority_class;

typedef struct tdnf_rpm_trigger_path {
    const char *path;
    const unsigned char *source_header_blob;
    size_t source_header_len;
} tdnf_rpm_trigger_path;

typedef struct tdnf_rpm_file_trigger_owner {
    const unsigned char *header_blob;
    size_t header_len;
    const tdnf_rpm_trigger_path *paths;
    size_t path_count;
    uint64_t order;
} tdnf_rpm_file_trigger_owner;

typedef struct tdnf_rpm_file_trigger_options {
    const char *install_root;
    const tdnf_rpm_config *config;
    int install_root_fd;
    uint32_t trans_flags;
    const char *const *rpmdefines;
    size_t rpmdefine_count;
    int script_fd;
    int redirect_stdout_to_stderr;
    int suppress_stdin;
} tdnf_rpm_file_trigger_options;

/**
 * Validate all ordinary, package-file and transaction-file trigger
 * arrays, plus the file path triplet needed for matching. This is
 * side-effect free and rejects partial arrays, bad types/counts,
 * out-of-range script/directory indices and mixed script phases.
 */
int tdnf_rpm_header_validate_trigger_metadata(
    const unsigned char *header_blob,
    size_t header_len
);

/**
 * Validate trigger metadata and fully expand/format every -e/-q trigger
 * script using the transaction configuration. This is side-effect free and
 * is intended for whole-transaction prevalidation.
 */
int tdnf_rpm_header_validate_trigger_scripts_config(
    const unsigned char *header_blob,
    size_t header_len,
    const tdnf_rpm_config *config
);

/**
 * Return 1 when a header contains any package or transaction file-trigger
 * metadata, 0 when it contains none, and -1 on malformed input.
 */
int tdnf_rpm_header_has_file_trigger_metadata(
    const unsigned char *header_blob,
    size_t header_len,
    tdnf_rpm_file_trigger_kind kind
);

/**
 * Enumerate installed trigger-visible paths from a header. NORMAL and
 * NETSHARED states are included; other states, ghosts and paths excluded
 * by NODOCS/NOCONFIGS are omitted.
 */
int tdnf_rpm_header_foreach_trigger_file(
    const unsigned char *header_blob,
    size_t header_len,
    uint32_t trans_flags,
    tdnf_rpm_changed_path_fn callback,
    void *callback_data
);

/**
 * Run a priority-sorted set of package or transaction file triggers.
 * Each owner supplies the phase-visible matching path set. One line is sent
 * to stdin for every matching prefix/path pair unless suppress_stdin is set
 * (used by %transfiletriggerpostun). Scripts receive `$1=0` and no `$2`.
 */
int tdnf_rpm_run_file_triggers(
    const tdnf_rpm_file_trigger_owner *owners,
    size_t owner_count,
    tdnf_rpm_trigger_phase phase,
    tdnf_rpm_file_trigger_kind kind,
    tdnf_rpm_trigger_priority_class priority_class,
    const tdnf_rpm_file_trigger_options *options,
    tdnf_rpm_trigger_result *result_out
);

/* --- native file erase engine (T4 building block) --- */

/**
 * Callback used by tdnf_rpm_erase_hnum() to decide whether `path`
 * must remain on disk for another package at the current transaction
 * phase.
 *
 * The callback should return:
 *   0  -> erase engine may remove/rename the path
 *   1  -> keep the path on disk
 *  <0  -> callback/query failure; abort erase
 *
 * `path` is the package-owned absolute path (for example
 * "/etc/foo.conf"), not rooted under `root`. `data` is the opaque
 * pointer from tdnf_rpm_erase_options.keep_path_fn_data.
 *
 * When no callback is supplied, the default implementation keeps
 * exact paths still owned by another installed package according to
 * the native rpmdb Basenames/Dirnames data. Multi-package erase
 * transactions with shared paths should provide an explicit callback
 * so later erase phases can keep shared files/directories until the
 * final owner is processed.
 */
typedef int (*tdnf_rpm_erase_keep_path_fn)(void *data, const char *path);

typedef struct tdnf_rpm_erase_options {
    /**
     * Optional handle-scoped rpm configuration. When supplied it is
     * authoritative for the rpmdb, install root, and native macros.
     */
    const tdnf_rpm_config *config;
    /**
     * librpm-style RPMTRANS_FLAG_* bitmask. The native erase engine
     * currently consults JUSTDB only.
     */
    uint32_t trans_flags;
    /**
     * Optional keep-path probe. May be NULL for plain single-package
     * erases that can rely on the default native rpmdb ownership
     * query.
     */
    tdnf_rpm_erase_keep_path_fn keep_path_fn;
    void *keep_path_fn_data;
} tdnf_rpm_erase_options;

/**
 * Erase one installed package's on-disk files, identified by its
 * sqlite rpmdb `hnum`, under `root`.
 *
 * This performs the filesystem half only: it skips %ghost entries,
 * renames modified %config files to `.rpmsave`, preserves paths that
 * must stay on disk per keep_path_fn/default ownership checks, and
 * removes explicit directory entries bottom-up when they are empty.
 *
 * It does NOT remove the rpmdb row. Callers should run any surrounding
 * scriptlet/trigger phases they need and then finish with
 * tdnf_rpmdb_write_erase_hnum() to match real rpm's ordering.
 *
 * `options` may be NULL for defaults.
 *
 * Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error()).
 */
int tdnf_rpm_erase_hnum(
    const char *root,
    uint32_t hnum,
    const tdnf_rpm_erase_options *options
);

/**
 * Erase on-disk files described by a raw stored header blob, under
 * `root`, without touching any rpmdb rows.
 *
 * Unlike tdnf_rpm_erase_hnum(), the header is supplied directly by
 * the caller. This is used on the UPGRADE path: after
 * tdnf_rpmdb_write_replace() has atomically overwritten the OLD
 * package's row with the NEW blob, the OLD hnum no longer resolves
 * to the OLD header, but the caller already captured that blob before
 * write_replace. Passing it back here removes any files unique to the
 * OLD version (files the NEW version does not ship).
 *
 * When no keep_path callback is supplied, the default probe queries
 * the live native rpmdb for any installed package that owns each
 * path. Because upgrade calls this AFTER write_replace, the rpmdb
 * reflects the NEW package's manifest at the replaced hnum, so paths
 * shared with the NEW version are naturally preserved.
 * When keep_path_fn is supplied, ownership queries are delegated entirely to
 * that callback and this function does not open the rpmdb in write mode.
 *
 * `options` may be NULL for defaults.
 *
 * Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error()).
 */
int tdnf_rpm_erase_header_blob(
    const char *root,
    const unsigned char *blob,
    size_t blob_len,
    const tdnf_rpm_erase_options *options
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
