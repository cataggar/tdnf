/*
 * tdnf-rpm-verify — smoke-test for the pure-Zig rpmzig verifier.
 *
 * Builds the same in-memory keyring that libtdnf uses:
 *
 *   tdnf-rpm-verify <file.rpm> --key <key.asc> [--key <key2.asc> ...]
 *       Load each .asc into the verifier's in-memory keyring.
 *
 *   tdnf-rpm-verify <file.rpm> --rpmdb [root]
 *       Load every gpg-pubkey-* entry from the rpmdb under [root]
 *       (default "/") into the keyring.
 *
 *   tdnf-rpm-verify <file.rpm> [--key ...] [--rpmdb [root]]
 *       Combine both sources in one verification run.
 *
 * Exits with:
 *   0 — signature verified OK
 *   1 — rpm not signed
 *   2 — signature present but no matching key in keyring
 *   3 — signature is bad
 *   4 — internal error or unexpected status
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rpmdb.h"
#include "verify.h"

#define MAX_KEYS 128

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
    const char *key_paths[MAX_KEYS] = { 0 };
    unsigned char *key_blobs[MAX_KEYS] = { 0 };
    /* parallel array: 1 = blob was allocated by tdnf_rpmdb_pubkeys_*
     * (free with tdnf_rpmdb_string_free); 0 = allocated by slurp()
     * (free with free()). */
    int key_is_rpmdb[MAX_KEYS] = { 0 };
    size_t key_lens[MAX_KEYS] = { 0 };
    size_t key_count = 0;
    int use_rpmdb = 0;
    const char *rpmdb_root = "/";
    int status = 0;
    int exit_code = 4;
    int i = 0;
    tdnf_rpmdb_pubkeys_iter *it = NULL;

    if (argc < 2) {
        fprintf(stderr,
            "usage: %s <file.rpm> "
            "[--key <key.asc> ...] [--rpmdb [root]]\n",
            argv[0]);
        return 4;
    }
    path = argv[1];
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (key_count >= MAX_KEYS) {
                fprintf(stderr, "too many --key (max %d)\n", MAX_KEYS);
                return 4;
            }
            key_paths[key_count++] = argv[++i];
        } else if (strcmp(argv[i], "--rpmdb") == 0) {
            use_rpmdb = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                rpmdb_root = argv[++i];
            }
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 4;
        }
    }

    fh = tdnf_rpm_file_open(path);
    if (!fh) {
        fprintf(stderr, "tdnf-rpm-verify: open: %s\n", tdnf_rpmdb_last_error());
        return 4;
    }

    printf("Verifier: pure-Zig\n");
    printf("Signature: %s\n", tdnf_rpm_file_signature_kind(fh));
    fflush(stdout);

    for (i = 0; i < (int)key_count; i++) {
        if (slurp(key_paths[i], &key_blobs[i], &key_lens[i]) != 0) {
            exit_code = 4;
            goto out;
        }
    }

    if (use_rpmdb) {
        size_t loaded = 0;
        it = tdnf_rpmdb_pubkeys_open(rpmdb_root);
        if (!it) {
            fprintf(stderr,
                "tdnf-rpm-verify: rpmdb open %s: %s\n",
                rpmdb_root, tdnf_rpmdb_last_error());
            exit_code = 4;
            goto out;
        }
        while (key_count < MAX_KEYS) {
            char *kbuf = NULL;
            size_t klen = 0;
            int n = tdnf_rpmdb_pubkeys_next(it, &kbuf, &klen, NULL);
            if (n == 0) break;
            if (n < 0) {
                fprintf(stderr, "tdnf-rpm-verify: rpmdb walk: %s\n",
                        tdnf_rpmdb_last_error());
                exit_code = 4;
                goto out;
            }
            key_blobs[key_count] = (unsigned char *)kbuf;
            key_lens[key_count] = klen;
            key_is_rpmdb[key_count] = 1;
            key_count++;
            loaded++;
        }
        printf("RpmDB:     %zu key(s) under %s\n", loaded, rpmdb_root);
    }

    (void)tdnf_rpmzig_verify_pure(fh,
        (const void *const *)key_blobs, key_lens, key_count, &status);

    switch (status) {
        case TDNF_RPMZIG_STATUS_OK:
            printf("Result:    OK\n");
            exit_code = 0;
            break;
        case TDNF_RPMZIG_STATUS_NO_SIG:
            printf("Result:    no signature\n");
            exit_code = 1;
            break;
        case TDNF_RPMZIG_STATUS_NO_KEY:
            printf("Result:    signature present, NO matching key\n");
            exit_code = 2;
            break;
        case TDNF_RPMZIG_STATUS_BAD:
            printf("Result:    BAD signature\n");
            exit_code = 3;
            break;
        case TDNF_RPMZIG_STATUS_INTERNAL_ERROR:
        default:
            printf("Result:    internal error / unsupported input\n");
            exit_code = 4;
            break;
    }

out:
    if (it) tdnf_rpmdb_pubkeys_close(it);
    for (i = 0; i < (int)key_count; i++) {
        if (key_is_rpmdb[i]) {
            tdnf_rpmdb_string_free((char *)key_blobs[i]);
        } else {
            free(key_blobs[i]);
        }
    }
    tdnf_rpm_file_close(fh);
    return exit_code;
}
