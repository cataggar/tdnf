/*
 * tdnf-rpm-files — smoke-test for the Zig payload decompressor +
 * cpio walker.
 *
 * Usage:
 *     tdnf-rpm-files <file.rpm>
 *
 * Prints one filename per line — equivalent to `rpm -qpl <file>` but
 * with the rpm convention `./` prefix preserved (rpm -qpl strips it).
 *
 * Installed under libexec/tdnf/.
 */
#include <stdio.h>
#include <stdlib.h>

#include "rpmdb.h"

int main(int argc, char **argv)
{
    tdnf_rpm_file *fh = NULL;
    tdnf_rpm_files_iter *it = NULL;
    const char *name = NULL;
    uint32_t mode = 0;
    int rc = 0;
    int exit_code = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <file.rpm>\n", argv[0]);
        return 2;
    }

    fh = tdnf_rpm_file_open(argv[1]);
    if (!fh) {
        fprintf(stderr, "tdnf-rpm-files: open: %s\n", tdnf_rpmdb_last_error());
        return 1;
    }

    it = tdnf_rpm_file_files_open(fh);
    if (!it) {
        fprintf(stderr, "tdnf-rpm-files: files_open: %s\n", tdnf_rpmdb_last_error());
        exit_code = 1;
        goto out;
    }

    while ((rc = tdnf_rpm_file_files_next(it, &name, &mode)) == 1) {
        printf("%s\n", name);
    }
    if (rc < 0) {
        fprintf(stderr, "tdnf-rpm-files: %s\n", tdnf_rpmdb_last_error());
        exit_code = 1;
    }

out:
    tdnf_rpm_file_files_close(it);
    tdnf_rpm_file_close(fh);
    return exit_code;
}
