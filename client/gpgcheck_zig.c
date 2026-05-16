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
 * Cross-check verification of `pkg_path` against `key_path` using
 * rpmzig. Returns one of TDNF_RPMZIG_VERIFY_*. Returns -1 on any
 * unexpected I/O error.
 *
 * Logs to stderr if the rpmzig verdict differs from `librpm_ok`
 * (true when librpm just said "verified").
 */
int TDNFRpmzigCrossCheck(
    const char *pkg_path,
    const char *key_path,
    int librpm_ok)
{
    tdnf_rpm_file *fh = NULL;
    unsigned char *blob = NULL;
    size_t blob_len = 0;
    const void *blobs[1];
    size_t lens[1];
    int status = TDNF_RPMZIG_VERIFY_GPGME_ERROR;
    int rpmzig_ok = 0;

    if (!pkg_path || !key_path) return -1;

    fh = tdnf_rpm_file_open(pkg_path);
    if (!fh) {
        fprintf(stderr,
            "rpmzig-crosscheck: open %s: %s\n",
            pkg_path, tdnf_rpmdb_last_error());
        return -1;
    }

    if (slurp_key(key_path, &blob, &blob_len) != 0) {
        fprintf(stderr, "rpmzig-crosscheck: read key %s failed\n", key_path);
        tdnf_rpm_file_close(fh);
        return -1;
    }

    blobs[0] = blob;
    lens[0] = blob_len;
    (void)tdnf_rpmzig_verify_with_keys(fh, blobs, lens, 1, &status);

    rpmzig_ok = (status == TDNF_RPMZIG_VERIFY_OK);
    if (rpmzig_ok != librpm_ok) {
        fprintf(stderr,
            "rpmzig-crosscheck: DISAGREEMENT for %s:"
            " librpm=%s rpmzig=%s (status=%d). Using librpm verdict.\n",
            pkg_path,
            librpm_ok ? "OK" : "FAIL",
            rpmzig_ok ? "OK" : "FAIL",
            status);
    }

    free(blob);
    tdnf_rpm_file_close(fh);
    return status;
}
