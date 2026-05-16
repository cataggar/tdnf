/*
 * GPG signature verification for .rpm files (T3 PR #1).
 *
 * Uses gpgme to verify a signature payload against a signed byte
 * range, both pulled from rpmzig's parsed `RpmFile`. The verifier
 * is independent of librpm — no rpmtsGetKeyring, no rpmKeyringAddKey,
 * no rpmReadPackageFile. The caller supplies a GPG home directory
 * with the public keys already imported (`gpg --homedir <dir>
 * --import <key.pub>`); future work will route tdnf's existing
 * downloaded GPG keys into this keyring.
 *
 * Status codes returned via *out_status:
 *
 *   TDNF_RPMZIG_VERIFY_OK             signature verified successfully
 *   TDNF_RPMZIG_VERIFY_NO_SIG         rpm carries no signature
 *   TDNF_RPMZIG_VERIFY_NO_KEY         signature present, no matching key in keyring
 *   TDNF_RPMZIG_VERIFY_BAD            signature is invalid (data or sig was tampered)
 *   TDNF_RPMZIG_VERIFY_GPGME_ERROR    gpgme initialisation / op_verify failed
 *
 * Return value mirrors the status: 0 on OK, non-zero on anything
 * else (so it can be used directly in if-conditions).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include <gpgme.h>

#include "rpmdb.h"
#include "verify.h"

int tdnf_rpmzig_verify(
    tdnf_rpm_file *fh,
    const char *gpg_homedir,
    int *out_status)
{
    const unsigned char *sig_bytes = NULL;
    size_t sig_len = 0;
    const unsigned char *signed_bytes = NULL;
    size_t signed_len = 0;
    int rc = 0;
    gpgme_error_t err = 0;
    gpgme_ctx_t ctx = NULL;
    gpgme_data_t sig_data = NULL;
    gpgme_data_t signed_data = NULL;
    gpgme_verify_result_t result = NULL;
    gpgme_signature_t s = NULL;
    gpgme_err_code_t code = 0;
    int verify_rc = 1;

    if (!fh || !out_status) {
        return -1;
    }
    *out_status = TDNF_RPMZIG_VERIFY_GPGME_ERROR;

    rc = tdnf_rpm_file_signed_range(fh,
        &sig_bytes, &sig_len,
        &signed_bytes, &signed_len);
    if (rc != 0) {
        *out_status = TDNF_RPMZIG_VERIFY_NO_SIG;
        return 1;
    }

    gpgme_check_version(NULL);

    err = gpgme_new(&ctx);
    if (err) {
        fprintf(stderr, "rpmzig-verify: gpgme_new: %s\n", gpgme_strerror(err));
        goto out;
    }
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        fprintf(stderr, "rpmzig-verify: set_protocol: %s\n", gpgme_strerror(err));
        goto out;
    }
    if (gpg_homedir && *gpg_homedir) {
        err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP,
            NULL /* exec_path */, gpg_homedir);
        if (err) {
            fprintf(stderr, "rpmzig-verify: set_engine_info: %s\n",
                gpgme_strerror(err));
            goto out;
        }
    }

    err = gpgme_data_new_from_mem(&sig_data,
        (const char *)sig_bytes, sig_len, /*copy=*/0);
    if (err) {
        fprintf(stderr, "rpmzig-verify: data_new(sig): %s\n", gpgme_strerror(err));
        goto out;
    }
    err = gpgme_data_new_from_mem(&signed_data,
        (const char *)signed_bytes, signed_len, /*copy=*/0);
    if (err) {
        fprintf(stderr, "rpmzig-verify: data_new(signed): %s\n", gpgme_strerror(err));
        goto out;
    }

    err = gpgme_op_verify(ctx, sig_data, signed_data, NULL);
    if (err) {
        fprintf(stderr, "rpmzig-verify: op_verify: %s\n", gpgme_strerror(err));
        goto out;
    }

    result = gpgme_op_verify_result(ctx);
    if (!result || !result->signatures) {
        fprintf(stderr, "rpmzig-verify: op_verify_result: no signatures\n");
        goto out;
    }

    /* Inspect the first (typically only) signature. */
    s = result->signatures;
    code = gpgme_err_code(s->status);

    switch (code) {
        case GPG_ERR_NO_ERROR:
            *out_status = TDNF_RPMZIG_VERIFY_OK;
            verify_rc = 0;
            break;
        case GPG_ERR_NO_PUBKEY:
            *out_status = TDNF_RPMZIG_VERIFY_NO_KEY;
            verify_rc = 2;
            break;
        case GPG_ERR_BAD_SIGNATURE:
            *out_status = TDNF_RPMZIG_VERIFY_BAD;
            verify_rc = 3;
            break;
        default:
            *out_status = TDNF_RPMZIG_VERIFY_GPGME_ERROR;
            fprintf(stderr, "rpmzig-verify: signature status %s\n",
                gpgme_strerror(s->status));
            verify_rc = 4;
            break;
    }

out:
    if (signed_data) gpgme_data_release(signed_data);
    if (sig_data) gpgme_data_release(sig_data);
    if (ctx) gpgme_release(ctx);
    return verify_rc;
}

/*
 * Build a temporary GPG home directory, mkdtemp-style, under
 * $TMPDIR (or /tmp). Returns the malloc'd path on success; caller
 * frees and rm -rf's it. On error, returns NULL.
 */
static char *mk_tmp_homedir(void)
{
    const char *tmpdir = NULL;
    size_t n = 0;
    char *p = NULL;
    tmpdir = getenv("TMPDIR");
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
    n = strlen(tmpdir) + sizeof("/tdnf-rpmzig-XXXXXX");
    p = malloc(n);
    if (!p) return NULL;
    snprintf(p, n, "%s/tdnf-rpmzig-XXXXXX", tmpdir);
    if (!mkdtemp(p)) {
        free(p);
        return NULL;
    }
    return p;
}

static void rm_rf(const char *path)
{
    DIR *d = NULL;
    struct dirent *ent = NULL;
    char child[4096];
    struct stat st;

    if (!path) return;
    d = opendir(path);
    if (!d) {
        (void)unlink(path);
        (void)rmdir(path);
        return;
    }
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (lstat(child, &st) != 0) continue;
        if (S_ISDIR(st.st_mode))
            rm_rf(child);
        else
            (void)unlink(child);
    }
    closedir(d);
    (void)rmdir(path);
}

int tdnf_rpmzig_verify_with_keys(
    tdnf_rpm_file *fh,
    const void *const *key_blobs,
    const size_t *key_lens,
    size_t key_count,
    int *out_status)
{
    char *tmp = NULL;
    gpgme_ctx_t ctx = NULL;
    gpgme_data_t kd = NULL;
    gpgme_error_t err = 0;
    int rc = -1;
    size_t i = 0;

    if (!fh || !out_status) return -1;
    *out_status = TDNF_RPMZIG_VERIFY_GPGME_ERROR;

    tmp = mk_tmp_homedir();
    if (!tmp) {
        fprintf(stderr, "rpmzig-verify: mkdtemp failed\n");
        return -1;
    }

    gpgme_check_version(NULL);

    err = gpgme_new(&ctx);
    if (err) {
        fprintf(stderr, "rpmzig-verify: gpgme_new: %s\n", gpgme_strerror(err));
        goto out;
    }
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        fprintf(stderr, "rpmzig-verify: set_protocol: %s\n", gpgme_strerror(err));
        goto out;
    }
    err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL, tmp);
    if (err) {
        fprintf(stderr, "rpmzig-verify: set_engine_info: %s\n", gpgme_strerror(err));
        goto out;
    }

    for (i = 0; i < key_count; i++) {
        err = gpgme_data_new_from_mem(&kd,
            (const char *)key_blobs[i], key_lens[i], /*copy=*/0);
        if (err) {
            fprintf(stderr, "rpmzig-verify: data_new(key %zu): %s\n",
                i, gpgme_strerror(err));
            goto out;
        }
        err = gpgme_op_import(ctx, kd);
        if (err) {
            fprintf(stderr, "rpmzig-verify: op_import(key %zu): %s\n",
                i, gpgme_strerror(err));
            gpgme_data_release(kd);
            kd = NULL;
            goto out;
        }
        gpgme_data_release(kd);
        kd = NULL;
    }

    /* Reuse the verify path against this freshly-keyed homedir. */
    gpgme_release(ctx);
    ctx = NULL;
    rc = tdnf_rpmzig_verify(fh, tmp, out_status);

out:
    if (kd) gpgme_data_release(kd);
    if (ctx) gpgme_release(ctx);
    if (tmp) {
        rm_rf(tmp);
        free(tmp);
    }
    return rc;
}
