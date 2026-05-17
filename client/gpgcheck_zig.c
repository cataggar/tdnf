/*
 * rpmzig primary signature verifier for TDNFGPGCheckPackage.
 *
 * Compiled into libtdnf only when build.zig is invoked with
 * -Drpmzig-verify=true or -Drpmzig-verify-pure-zig=true (both
 * define TDNF_RPMZIG_VERIFY). When neither flag is set this file
 * is not part of the build and libtdnf gains no new dependencies.
 *
 * Under the flag, this function REPLACES the librpm
 * rpmVerifySignatures path (TDNFGPGCheck) — rpmzig is the sole
 * signature verifier on the install path. The rpmts is separately
 * set to RPMVSF_MASK_NOSIGNATURES so rpmReadPackageFile runs as a
 * header-only reader.
 *
 * Backend selection (compile-time, no runtime branching):
 *
 *   TDNF_RPMZIG_VERIFY (default rpmzig build)
 *       Dispatches to tdnf_rpmzig_verify_with_keys (gpgme backend
 *       in rpmzig/verify.c). libtdnf links libgpgme.so.11.
 *
 *   TDNF_RPMZIG_VERIFY_PURE_ZIG (plan-pure-zig-pgp.md PR #11)
 *       Dispatches to tdnf_rpmzig_verify_pure (pure-Zig backend in
 *       rpmzig/verify_pure.c plus rpmzig/pgp). verify.c is
 *       excluded from the build; libtdnf does NOT link libgpgme,
 *       libgpg-error, or libassuan. This is the configuration
 *       documented in plan acceptance #3.
 *
 * Trust set (both backends):
 *   - every gpg-pubkey-* installed in the rpmdb (the same keyring
 *     'rpm --import' / TDNFImportGPGKeyFile build up over time)
 *   - the fresh key tdnf just fetched for this repo
 *
 * The status codes match TDNF_RPMZIG_VERIFY_* from verify.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../rpmzig/rpmdb.h"
#include "../rpmzig/verify.h"
#include "gpgcheck_zig.h"

/*
 * Slurp a key file into a heap buffer. Returns 0 on success.
 * Caller frees *out.
 */
static int slurp_key(const char *path, unsigned char **out, size_t *out_len)
{
    FILE *fp = NULL;
    long n = 0;
    unsigned char *buf = NULL;

    fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    n = ftell(fp);
    if (n < 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    buf = malloc((size_t)n);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out = buf;
    *out_len = (size_t)n;
    return 0;
}

int TDNFRpmzigVerify(
    const char *pkg_path,
    const char *key_path,
    const char *install_root,
    int *out_status)
{
    tdnf_rpm_file *fh = NULL;
    unsigned char *fresh_key = NULL;
    size_t fresh_key_len = 0;
    tdnf_rpmdb_pubkeys_iter *it = NULL;
#define MAX_RPMDB_KEYS 128
    char *rpmdb_keys[MAX_RPMDB_KEYS];
    size_t rpmdb_key_lens[MAX_RPMDB_KEYS];
    size_t rpmdb_count = 0;
    const void *blobs[MAX_RPMDB_KEYS + 1];
    size_t lens[MAX_RPMDB_KEYS + 1];
    size_t total_keys = 0;
    int status = TDNF_RPMZIG_VERIFY_GPGME_ERROR;
    int rc = 0;
    size_t i = 0;

    if (!pkg_path || !key_path || !out_status) return -1;

    fh = tdnf_rpm_file_open(pkg_path);
    if (!fh) {
        fprintf(stderr,
            "rpmzig-verify: open %s: %s\n",
            pkg_path, tdnf_rpmdb_last_error());
        return -1;
    }

    if (slurp_key(key_path, &fresh_key, &fresh_key_len) != 0) {
        fprintf(stderr,
            "rpmzig-verify: read key %s failed\n", key_path);
        tdnf_rpm_file_close(fh);
        return -1;
    }

    /* Walk gpg-pubkey-* entries in the rpmdb. If this fails for any
     * reason we keep going with just the fresh key — a missing rpmdb
     * keyring shouldn't block install of a freshly-trusted package. */
    it = tdnf_rpmdb_pubkeys_open(install_root);
    if (it) {
        while (rpmdb_count < MAX_RPMDB_KEYS) {
            char *kbuf = NULL;
            size_t klen = 0;
            int n = tdnf_rpmdb_pubkeys_next(it, &kbuf, &klen, NULL);
            if (n == 0) break;
            if (n < 0) {
                fprintf(stderr,
                    "rpmzig-verify: rpmdb pubkey walk: %s\n",
                    tdnf_rpmdb_last_error());
                break;
            }
            rpmdb_keys[rpmdb_count] = kbuf;
            rpmdb_key_lens[rpmdb_count] = klen;
            rpmdb_count++;
        }
        tdnf_rpmdb_pubkeys_close(it);
    }

    for (i = 0; i < rpmdb_count; i++) {
        blobs[total_keys] = rpmdb_keys[i];
        lens[total_keys] = rpmdb_key_lens[i];
        total_keys++;
    }
    blobs[total_keys] = fresh_key;
    lens[total_keys] = fresh_key_len;
    total_keys++;

#ifdef TDNF_RPMZIG_VERIFY_PURE_ZIG
    /* Pure-Zig path (plan-pure-zig-pgp.md PR #11): the gpgme
     * backend is not compiled into this build; route straight to
     * tdnf_rpmzig_verify_pure. Same keyring, same status codes. */
    (void)tdnf_rpmzig_verify_pure(fh, blobs, lens, total_keys, &status);
#else
    /* gpgme backend (default rpmzig build). */
    (void)tdnf_rpmzig_verify_with_keys(fh, blobs, lens, total_keys, &status);
#endif

    *out_status = status;
    rc = (status == TDNF_RPMZIG_VERIFY_OK) ? 0 : 1;

    for (i = 0; i < rpmdb_count; i++) {
        tdnf_rpmdb_string_free(rpmdb_keys[i]);
    }
    free(fresh_key);
    tdnf_rpm_file_close(fh);
    return rc;
#undef MAX_RPMDB_KEYS
}
