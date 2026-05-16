/*
 * tdnf-rpm-info — smoke-test for the Zig `.rpm` file parser.
 *
 * Usage:
 *     tdnf-rpm-info <file.rpm>
 *
 * Prints the package NEVRA, payload compressor, and payload offset.
 * Should match `rpm -qp --queryformat '%{NEVRA}\n%{PAYLOADCOMPRESSOR}\n'`
 * on the same file.
 *
 * Installed under libexec/tdnf/.
 */
#include <stdio.h>
#include <stdlib.h>

#include "rpmdb.h"

int main(int argc, char **argv)
{
    tdnf_rpm_file *fh = NULL;
    char *nevra = NULL;
    int exit_code = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <file.rpm>\n", argv[0]);
        return 2;
    }

    fh = tdnf_rpm_file_open(argv[1]);
    if (!fh) {
        fprintf(stderr, "tdnf-rpm-info: %s\n", tdnf_rpmdb_last_error());
        return 1;
    }

    nevra = tdnf_rpm_file_nevra(fh);
    if (!nevra) {
        fprintf(stderr, "tdnf-rpm-info: nevra: %s\n", tdnf_rpmdb_last_error());
        exit_code = 1;
        goto out;
    }
    printf("NEVRA:       %s\n", nevra);
    printf("Compressor:  %s\n", tdnf_rpm_file_compressor(fh));
    printf("Payload at:  %lld\n", (long long)tdnf_rpm_file_payload_offset(fh));
    printf("Signed:      %s\n",
        tdnf_rpm_file_is_signed(fh) ? "yes" : "no");

out:
    tdnf_rpmdb_string_free(nevra);
    tdnf_rpm_file_close(fh);
    return exit_code;
}
