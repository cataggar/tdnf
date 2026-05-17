/*
 * rpmzig primary signature verifier for TDNFGPGCheckPackage.
 *
 * Compiled into libtdnf only when build.zig is invoked with
 * -Drpmzig-verify=true (defines TDNF_RPMZIG_VERIFY). When the
 * macro is unset this file is not part of the build and libtdnf
 * gains no new dependencies.
 *
 * Under the flag, this function REPLACES the librpm
 * rpmVerifySignatures path (TDNFGPGCheck) — rpmzig + gpgme is
 * the sole signature verifier on the install path. The rpmts is
 * separately set to RPMVSF_MASK_NOSIGNATURES so rpmReadPackageFile
 * runs as a header-only reader.
 *
 * Trust set:
 *   - every gpg-pubkey-* installed in the rpmdb (the same keyring
 *     'rpm --import' / TDNFImportGPGKeyFile build up over time)
 *   - the fresh key tdnf just fetched for this repo
 *
 * The status codes match TDNF_RPMZIG_VERIFY_* from verify.h.
 *
 * When -Drpmzig-verify-pure-zig=true is *also* set (defines
 * TDNF_RPMZIG_VERIFY_PURE_ZIG), the pure-Zig verifier
 * tdnf_rpmzig_verify_pure runs alongside the gpgme path with the
 * same keyring. The gpgme verdict remains authoritative, but the
 * cross-check is now strict (plan-pure-zig-pgp.md PR #10): a
 * single divergence between the two verdicts is escalated to a
 * hard error by forcing *out_status to TDNF_RPMZIG_VERIFY_BAD,
 * which the caller in client/gpgcheck.c surfaces as
 * ERROR_TDNF_RPM_GPG_NO_MATCH and refuses to install the package.
 * The soak period (PR #7's log-only behaviour) is over. PR #11
 * flips pure-Zig to primary and drops the gpgme link entirely.
 *
 * This mirrors the log-to-error promotion the librpm-replacement
 * plan applied to its own rpmzig+librpm cross-check in T3 PR #4
 * (commit 0d3ed83).
 *
 * Manual cross-check (until the pytest path adds a parametrize):
 *
 *   zig build -Drpmzig-verify-pure-zig=true install --prefix ./out
 *   sudo LD_LIBRARY_PATH=./out/lib ./out/bin/tdnf install -y <pkg> \
 *       2>&1 | grep rpmzig-pure-zig
 *
 * On agreement, every fresh-key install prints one
 * `rpmzig-pure-zig: agrees ...` line. On disagreement the install
 * aborts with `rpmzig-pure-zig: DISAGREEMENT ...` followed by the
 * usual ERROR_TDNF_RPM_GPG_NO_MATCH path from gpgcheck.c.
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

    (void)tdnf_rpmzig_verify_with_keys(fh, blobs, lens, total_keys, &status);

#ifdef TDNF_RPMZIG_VERIFY_PURE_ZIG
    /* Strict cross-check: pure-Zig verifier must agree with the
     * gpgme path. Same fh + same in-memory keyring. The soak
     * period (PR #7's log-only behaviour) is over — any divergence
     * is treated as a hard failure. We override `status` so the
     * caller in client/gpgcheck.c takes the existing non-OK branch
     * and raises ERROR_TDNF_RPM_GPG_NO_MATCH, refusing the install.
     * gpgme remains authoritative on agreement; PR #11 flips
     * pure-Zig to primary and drops the gpgme link. */
    {
        const char *slash = strrchr(pkg_path, '/');
        const char *pkg_name = slash ? slash + 1 : pkg_path;
        int pure_status = TDNF_RPMZIG_VERIFY_GPGME_ERROR;
        (void)tdnf_rpmzig_verify_pure(
            fh, blobs, lens, total_keys, &pure_status);
        if (pure_status != status) {
            fprintf(stderr,
                "rpmzig-pure-zig: DISAGREEMENT vs gpgme "
                "(verifier mismatch is a hard error) for %s: "
                "pure=%d gpgme=%d\n",
                pkg_name, pure_status, status);
            status = TDNF_RPMZIG_VERIFY_BAD;
        } else {
            fprintf(stderr,
                "rpmzig-pure-zig: agrees with gpgme (status=%d) for %s\n",
                pure_status, pkg_name);
        }
    }
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
