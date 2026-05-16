/*
 * rpmzig cross-check shim for TDNFGPGCheckPackage.
 *
 * Compiled into libtdnf only when build.zig is invoked with
 * -Drpmzig-verify=true (defines TDNF_RPMZIG_VERIFY). When the
 * macro is unset this file is not part of the build and libtdnf
 * gains no new dependencies.
 *
 * The function below is called from client/gpgcheck.c after the
 * existing librpm-based TDNFGPGCheck() returns OK on a freshly
 * downloaded gpgkey URL. It runs the *same* verification through
 * rpmzig + gpgme (independent of librpm) and logs if the two
 * verdicts disagree. It never overrides librpm's decision — this
 * is monitor mode, intended to gather field data before flipping
 * the default verifier in a follow-up.
 *
 * After enough monitor-mode runs accumulate without disagreement,
 * a follow-up PR will:
 *   1. flip the verifier order so rpmzig is primary,
 *   2. set RPMVSF_MASK_NOSIGNATURES on the rpmts so librpm only
 *      does the header read for transaction use, and
 *   3. drop the librpm verify call entirely.
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

/*
 * Cross-check verification of `pkg_path` against:
 *   - every gpg-pubkey-* in the rpmdb under `install_root`, and
 *   - the armored ASCII key in `key_path` (the fresh key tdnf
 *     just fetched for `pRepo->pszUrlGPGKey`).
 *
 * Returns one of TDNF_RPMZIG_VERIFY_* (0 = OK). Returns a negative
 * value on any unexpected I/O error.
 *
 * Logs to stderr if the rpmzig verdict differs from `librpm_ok`
 * (true when librpm just said "verified"). The caller decides
 * what to do with the return value — under -Drpmzig-verify=true
 * client/gpgcheck.c escalates non-OK to ERROR_TDNF_RPM_GPG_NO_MATCH.
 *
 * `install_root` may be NULL or "" to mean "/".
 */
int TDNFRpmzigCrossCheck(
    const char *pkg_path,
    const char *key_path,
    const char *install_root,
    int librpm_ok)
{
    tdnf_rpm_file *fh = NULL;
    unsigned char *fresh_key = NULL;
    size_t fresh_key_len = 0;
    tdnf_rpmdb_pubkeys_iter *it = NULL;
    /* Owned heap blobs harvested from the rpmdb; freed on every exit
     * path. Capped at MAX_RPMDB_KEYS so a corrupt rpmdb can't push
     * us into unbounded allocation. */
#define MAX_RPMDB_KEYS 128
    char *rpmdb_keys[MAX_RPMDB_KEYS];
    size_t rpmdb_key_lens[MAX_RPMDB_KEYS];
    size_t rpmdb_count = 0;
    const void *blobs[MAX_RPMDB_KEYS + 1];
    size_t lens[MAX_RPMDB_KEYS + 1];
    size_t total_keys = 0;
    int status = TDNF_RPMZIG_VERIFY_GPGME_ERROR;
    int rpmzig_ok = 0;
    int rc = -1;
    size_t i = 0;

    if (!pkg_path || !key_path) return -1;

    fh = tdnf_rpm_file_open(pkg_path);
    if (!fh) {
        fprintf(stderr,
            "rpmzig-crosscheck: open %s: %s\n",
            pkg_path, tdnf_rpmdb_last_error());
        return -1;
    }

    if (slurp_key(key_path, &fresh_key, &fresh_key_len) != 0) {
        fprintf(stderr,
            "rpmzig-crosscheck: read key %s failed\n", key_path);
        tdnf_rpm_file_close(fh);
        return -1;
    }

    /* Walk gpg-pubkey-* entries in the rpmdb. If this fails for any
     * reason we keep going with just the fresh key — a missing rpmdb
     * keyring shouldn't break the verify path. */
    it = tdnf_rpmdb_pubkeys_open(install_root);
    if (it) {
        while (rpmdb_count < MAX_RPMDB_KEYS) {
            char *kbuf = NULL;
            size_t klen = 0;
            int n = tdnf_rpmdb_pubkeys_next(it, &kbuf, &klen, NULL);
            if (n == 0) break;
            if (n < 0) {
                fprintf(stderr,
                    "rpmzig-crosscheck: rpmdb pubkey walk: %s\n",
                    tdnf_rpmdb_last_error());
                break;
            }
            rpmdb_keys[rpmdb_count] = kbuf;
            rpmdb_key_lens[rpmdb_count] = klen;
            rpmdb_count++;
        }
        tdnf_rpmdb_pubkeys_close(it);
    } else {
        /* Common in test/chroot setups where the rpmdb is empty;
         * not an error. */
    }

    for (i = 0; i < rpmdb_count; i++) {
        blobs[total_keys] = rpmdb_keys[i];
        lens[total_keys] = rpmdb_key_lens[i];
        total_keys++;
    }
    blobs[total_keys] = fresh_key;
    lens[total_keys] = fresh_key_len;
    total_keys++;

    (void)tdnf_rpmzig_verify_with_keys(fh, blobs, lens, total_keys, &status);

    rpmzig_ok = (status == TDNF_RPMZIG_VERIFY_OK);
    if (rpmzig_ok != librpm_ok) {
        fprintf(stderr,
            "rpmzig-crosscheck: DISAGREEMENT for %s:"
            " librpm=%s rpmzig=%s (status=%d, rpmdb_keys=%zu, fresh_key=1)."
            " Using librpm verdict.\n",
            pkg_path,
            librpm_ok ? "OK" : "FAIL",
            rpmzig_ok ? "OK" : "FAIL",
            status, rpmdb_count);
    }

    rc = status;
    for (i = 0; i < rpmdb_count; i++) {
        tdnf_rpmdb_string_free(rpmdb_keys[i]);
    }
    free(fresh_key);
    tdnf_rpm_file_close(fh);
    return rc;
#undef MAX_RPMDB_KEYS
}
