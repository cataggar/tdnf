/*
 * tdnf-rpm-verify — smoke-test for the rpmzig signature verifiers.
 *
 * Two backends are available; the gpgme-backed one is the default,
 * the pure-Zig one (plan-pure-zig-pgp.md PR #5) is selected via
 * --pure. Both share the same --key / --rpmdb / --homedir flags
 * except --homedir is ignored under --pure (the pure verifier has
 * no GPG-home concept; the keyring is built solely from --key
 * and/or --rpmdb).
 *
 * Under -Drpmzig-verify-pure-zig=true (PR #11) the gpgme backend
 * (verify.c) is excluded from the build, the binary always
 * dispatches to the pure-Zig verifier, and --homedir is rejected
 * with a usage error.
 *
 * Three sources of keys (combinable in the --rpmdb + --key case):
 *
 *   tdnf-rpm-verify <file.rpm> [--homedir <dir>]
 *       Verify against an existing GPG home directory (gpgme path
 *       only).
 *
 *   tdnf-rpm-verify <file.rpm> --key <key.asc> [--key <key2.asc> ...]
 *       Load each .asc into a fresh in-memory keyring (gpgme path:
 *       a temp homedir under $TMPDIR; pure path: an array of blobs
 *       in memory).
 *
 *   tdnf-rpm-verify <file.rpm> --rpmdb [root]
 *       Load every gpg-pubkey-* entry from the rpmdb under [root]
 *       (default "/") into the keyring. Combine with --key to also
 *       include locally-staged keys.
 *
 *   tdnf-rpm-verify <file.rpm> --pure ...
 *       Run the pure-Zig verifier instead of gpgme. Implies
 *       --key/--rpmdb (no --homedir). This is the only mode under
 *       -Drpmzig-verify-pure-zig=true.
 *
 *   (--homedir is mutually exclusive with --key/--rpmdb and with
 *    --pure.)
 *
 * Exits with:
 *   0 — signature verified OK
 *   1 — rpm not signed
 *   2 — signature present but no matching key in keyring
 *   3 — signature is bad
 *   4 — gpgme/internal error or unexpected status
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
#ifndef TDNF_RPMZIG_VERIFY_PURE_ZIG
    const char *homedir = NULL;
#endif
    const char *key_paths[MAX_KEYS] = { 0 };
    unsigned char *key_blobs[MAX_KEYS] = { 0 };
    /* parallel array: 1 = blob was allocated by tdnf_rpmdb_pubkeys_*
     * (free with tdnf_rpmdb_string_free); 0 = allocated by slurp()
     * (free with free()). */
    int key_is_rpmdb[MAX_KEYS] = { 0 };
    size_t key_lens[MAX_KEYS] = { 0 };
    size_t key_count = 0;
    int use_rpmdb = 0;
    int use_pure = 0;
    const char *rpmdb_root = "/";
    int status = 0;
    int rc = 0;
    int exit_code = 4;
    int i = 0;
    tdnf_rpmdb_pubkeys_iter *it = NULL;

    if (argc < 2) {
        fprintf(stderr,
#ifdef TDNF_RPMZIG_VERIFY_PURE_ZIG
            "usage: %s <file.rpm> --pure "
            "[--key <key.asc> ...] [--rpmdb [root]]\n",
#else
            "usage: %s <file.rpm> [--pure] [--homedir <dir>] "
            "[--key <key.asc> ...] [--rpmdb [root]]\n",
#endif
            argv[0]);
        return 4;
    }
    path = argv[1];
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--homedir") == 0 && i + 1 < argc) {
#ifdef TDNF_RPMZIG_VERIFY_PURE_ZIG
            fprintf(stderr,
                "--homedir is not supported in this build "
                "(pure-Zig verifier only — use --key/--rpmdb)\n");
            return 4;
#else
            homedir = argv[++i];
#endif
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
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
        } else if (strcmp(argv[i], "--pure") == 0) {
            use_pure = 1;
        } else if (i == 2 && argv[i][0] != '-') {
#ifdef TDNF_RPMZIG_VERIFY_PURE_ZIG
            fprintf(stderr,
                "bare homedir is not supported in this build "
                "(pure-Zig verifier only — use --key/--rpmdb)\n");
            return 4;
#else
            /* Legacy: bare 2nd arg = homedir, for back-compat with PR #13. */
            homedir = argv[i];
#endif
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 4;
        }
    }
#ifdef TDNF_RPMZIG_VERIFY_PURE_ZIG
    /* gpgme backend is excluded from this build — always use the
     * pure-Zig verifier. */
    use_pure = 1;
#else
    if (homedir && (key_count > 0 || use_rpmdb)) {
        fprintf(stderr,
            "--homedir is mutually exclusive with --key and --rpmdb\n");
        return 4;
    }
    if (use_pure && homedir) {
        fprintf(stderr,
            "--pure is mutually exclusive with --homedir (use --key/--rpmdb)\n");
        return 4;
    }
#endif

    fh = tdnf_rpm_file_open(path);
    if (!fh) {
        fprintf(stderr, "tdnf-rpm-verify: open: %s\n", tdnf_rpmdb_last_error());
        return 4;
    }

    printf("Verifier: %s\n", use_pure ? "pure-Zig" : "gpgme");
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

    if (use_pure) {
        rc = tdnf_rpmzig_verify_pure(fh,
            (const void *const *)key_blobs, key_lens, key_count, &status);
#ifndef TDNF_RPMZIG_VERIFY_PURE_ZIG
    } else if (key_count > 0) {
        rc = tdnf_rpmzig_verify_with_keys(fh,
            (const void *const *)key_blobs, key_lens, key_count, &status);
    } else {
        rc = tdnf_rpmzig_verify(fh, homedir, &status);
#endif
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
            printf("Result:    %s\n",
                use_pure ? "internal error / unsupported input" : "gpgme error");
            exit_code = 4;
            break;
    }
    (void)rc;

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
