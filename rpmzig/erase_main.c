/*
 * tdnf-rpm-erase — smoke-test for the native rpmzig file-erase
 * engine.
 *
 * Usage:
 *   tdnf-rpm-erase --root <root> [--tsflag justdb] <hnum>
 *
 * Erases installed-package files by sqlite rpmdb hnum, then removes
 * the rpmdb row in the same order real rpm uses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rpm/rpmts.h>

#include "rpmdb.h"

static int parse_u32(const char *text, uint32_t *out)
{
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (!text || !*text || !end || *end || value > 0xffffffffUL) {
        return -1;
    }
    *out = (uint32_t)value;
    return 0;
}

static uint32_t parse_tsflag(const char *text)
{
    if (!strcmp(text, "justdb")) {
        return RPMTRANS_FLAG_JUSTDB;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *root = NULL;
    uint32_t hnum = 0;
    uint32_t trans_flags = 0;
    int i = 0;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--root")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --root\n");
                return 2;
            }
            root = argv[++i];
        } else if (!strcmp(argv[i], "--tsflag")) {
            uint32_t flag = 0;
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --tsflag\n");
                return 2;
            }
            flag = parse_tsflag(argv[++i]);
            if (!flag) {
                fprintf(stderr, "unsupported --tsflag value: %s\n", argv[i]);
                return 2;
            }
            trans_flags |= flag;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "unsupported option: %s\n", argv[i]);
            return 2;
        } else if (hnum == 0) {
            if (parse_u32(argv[i], &hnum) < 0) {
                fprintf(stderr, "invalid hnum: %s\n", argv[i]);
                return 2;
            }
        } else {
            fprintf(stderr, "unexpected positional argument: %s\n", argv[i]);
            return 2;
        }
    }

    if (!root || hnum == 0) {
        fprintf(stderr, "usage: %s --root <root> [--tsflag justdb] <hnum>\n", argv[0]);
        return 2;
    }

    {
        tdnf_rpm_erase_options options = {
            .trans_flags = trans_flags,
            .keep_path_fn = NULL,
            .keep_path_fn_data = NULL,
        };
        if (tdnf_rpm_erase_hnum(root, hnum, &options) != 0) {
            fprintf(stderr, "tdnf-rpm-erase: erase: %s\n", tdnf_rpmdb_last_error());
            return 1;
        }
    }

    if (tdnf_rpmdb_write_erase_hnum(root, hnum) != 0) {
        fprintf(stderr, "tdnf-rpm-erase: erase-hnum: %s\n", tdnf_rpmdb_last_error());
        return 1;
    }

    return 0;
}
