/*
 * tdnf-rpm-verify — smoke-test for the Zig + gpgme signature
 * verifier.
 *
 * Usage:
 *   tdnf-rpm-verify <file.rpm> [gpg_homedir]
 *
 * Exits with:
 *   0 — signature verified OK
 *   1 — rpm not signed
 *   2 — signature present but no matching key in keyring
 *   3 — signature is bad
 *   4 — gpgme error or unexpected status
 *
 * `gpg_homedir` defaults to the gpgme default ($GNUPGHOME or
 * ~/.gnupg). Set up a keyring beforehand with:
 *
 *   mkdir -p /tmp/rpm-keyring && chmod 700 /tmp/rpm-keyring
 *   gpg --homedir /tmp/rpm-keyring --import /path/to/key.asc
 *
 * Then:  tdnf-rpm-verify some.rpm /tmp/rpm-keyring
 */
#include <stdio.h>
#include <stdlib.h>

#include "rpmdb.h"
#include "verify.h"

int main(int argc, char **argv)
{
    tdnf_rpm_file *fh = NULL;
    const char *path = NULL;
    const char *homedir = NULL;
    int status = 0;
    int rc = 0;
    int exit_code = 4;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <file.rpm> [gpg_homedir]\n", argv[0]);
        return 4;
    }
    path = argv[1];
    homedir = (argc == 3) ? argv[2] : NULL;

    fh = tdnf_rpm_file_open(path);
    if (!fh) {
        fprintf(stderr, "tdnf-rpm-verify: open: %s\n", tdnf_rpmdb_last_error());
        return 4;
    }

    printf("Signature: %s\n", tdnf_rpm_file_signature_kind(fh));
    fflush(stdout);

    rc = tdnf_rpmzig_verify(fh, homedir, &status);

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

    tdnf_rpm_file_close(fh);
    return exit_code;
}
