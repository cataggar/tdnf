/*
 * tdnf-rpmdb-list — smoke-test for the Zig rpmdb iterator.
 *
 * Prints one NEVRA per installed package, like `rpm -qa`. Output
 * order matches rpmdb's `hnum` column (install order); compare
 * against `rpm -qa | sort` to check completeness regardless of
 * order.
 *
 * Installed under libexec/tdnf/ alongside tdnf-rpmdb-count.
 */
#include <stdio.h>
#include <stdlib.h>

#include "rpmdb.h"

int main(int argc, char **argv)
{
    const char *root = (argc > 1) ? argv[1] : "/";
    tdnf_rpmdb_iter *it = NULL;
    char *nevra = NULL;
    int rc = 0;
    int exit_code = 0;

    it = tdnf_rpmdb_iter_open(root);
    if (!it) {
        fprintf(stderr, "tdnf-rpmdb-list: open: %s\n", tdnf_rpmdb_last_error());
        return 1;
    }

    while ((rc = tdnf_rpmdb_iter_next_nevra(it, &nevra)) == 1) {
        printf("%s\n", nevra);
        tdnf_rpmdb_string_free(nevra);
        nevra = NULL;
    }

    if (rc < 0) {
        fprintf(stderr, "tdnf-rpmdb-list: %s\n", tdnf_rpmdb_last_error());
        exit_code = 1;
    }

    tdnf_rpmdb_iter_close(it);
    return exit_code;
}
