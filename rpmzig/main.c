/*
 * tdnf-rpmdb-count — minimal smoke-test binary for the Zig rpmdb
 * reader.
 *
 * Usage:
 *     tdnf-rpmdb-count [root]
 *
 * Prints the number of rows in the Packages table of the rpmdb under
 * `root` (default: /). Should match `rpm -qa | wc -l` on the same
 * root. Installed under libexec/tdnf/ alongside tdnf-history-util.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rpmdb.h"

int main(int argc, char **argv)
{
    const char *root = (argc > 1) ? argv[1] : "/";
    int64_t count = tdnf_rpmdb_count_packages(root);
    if (count < 0) {
        const char *err = tdnf_rpmdb_last_error();
        fprintf(stderr, "tdnf-rpmdb-count: %s\n",
                (err && *err) ? err : "unknown error");
        return 1;
    }
    printf("%lld\n", (long long)count);
    return 0;
}
