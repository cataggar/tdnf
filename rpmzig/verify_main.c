/*
 * tdnf-rpm-verify — smoke-test for the Zig + gpgme signature
 * verifier.
 *
 * Two modes:
 *
 *   tdnf-rpm-verify <file.rpm> [--homedir <dir>]
 *       Verify against an existing GPG home directory.
 *
 *   tdnf-rpm-verify <file.rpm> --key <key.asc> [--key <key2.asc> ...]
 *       Load each .asc into a fresh in-memory keyring (a temp
 *       homedir under $TMPDIR, removed before exit) and verify.
 *       This is the mode T3 PR #3 will route through.
 *
 * Exits with:
 *   0 — signature verified OK
 *   1 — rpm not signed
 *   2 — signature present but no matching key in keyring
 *   3 — signature is bad
 *   4 — gpgme error or unexpected status
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rpmdb.h"
#include "verify.h"

#define MAX_KEYS 16

static int slurp(const char *path, unsigned char **out, size_t *out_len)
{
    FILE *fp = NULL;
    long n = 0;
    unsigned char *buf = NULL;

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "tdnf-rpm-verify: open key %s: ", path);
        perror("");
        return -1;
    }
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

int main(int argc, char **argv)
{
    tdnf_rpm_file *fh = NULL;
    const char *path = NULL;
    const char *homedir = NULL;
    const char *key_paths[MAX_KEYS] = { 0 };
    unsigned char *key_blobs[MAX_KEYS] = { 0 };
    size_t key_lens[MAX_KEYS] = { 0 };
    size_t key_count = 0;
    int status = 0;
    int rc = 0;
    int exit_code = 4;
    int i = 0;

    if (argc < 2) {
        fprintf(stderr,
            "usage: %s <file.rpm> [--homedir <dir>] [--key <key.asc> ...]\n",
            argv[0]);
        return 4;
    }
    path = argv[1];
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--homedir") == 0 && i + 1 < argc) {
            homedir = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (key_count >= MAX_KEYS) {
                fprintf(stderr, "too many --key (max %d)\n", MAX_KEYS);
                return 4;
            }
            key_paths[key_count++] = argv[++i];
        } else if (i == 2 && argv[i][0] != '-') {
            /* Legacy: bare 2nd arg = homedir, for back-compat with PR #13. */
            homedir = argv[i];
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 4;
        }
    }
    if (homedir && key_count > 0) {
        fprintf(stderr, "--homedir and --key are mutually exclusive\n");
        return 4;
    }

    fh = tdnf_rpm_file_open(path);
    if (!fh) {
        fprintf(stderr, "tdnf-rpm-verify: open: %s\n", tdnf_rpmdb_last_error());
        return 4;
    }

    printf("Signature: %s\n", tdnf_rpm_file_signature_kind(fh));
    fflush(stdout);

    if (key_count > 0) {
        for (i = 0; i < (int)key_count; i++) {
            if (slurp(key_paths[i], &key_blobs[i], &key_lens[i]) != 0) {
                exit_code = 4;
                goto out;
            }
        }
        rc = tdnf_rpmzig_verify_with_keys(fh,
            (const void *const *)key_blobs, key_lens, key_count, &status);
    } else {
        rc = tdnf_rpmzig_verify(fh, homedir, &status);
    }

    switch (status) {
        case TDNF_RPMZIG_VERIFY_OK:
            printf("Result:    OK\n");
            exit_code = 0;
            break;
        case TDNF_RPMZIG_VERIFY_NO_SIG:
            printf("Result:    no signature\n");
            exit_code = 1;
            break;
        case TDNF_RPMZIG_VERIFY_NO_KEY:
            printf("Result:    signature present, NO matching key\n");
            exit_code = 2;
            break;
        case TDNF_RPMZIG_VERIFY_BAD:
            printf("Result:    BAD signature\n");
            exit_code = 3;
            break;
        case TDNF_RPMZIG_VERIFY_GPGME_ERROR:
        default:
            printf("Result:    gpgme error\n");
            exit_code = 4;
            break;
    }
    (void)rc;

out:
    for (i = 0; i < (int)key_count; i++) free(key_blobs[i]);
    tdnf_rpm_file_close(fh);
    return exit_code;
}
