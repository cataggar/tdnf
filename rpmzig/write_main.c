/*
 * tdnf-rpmdb-write — smoke-test driver for the native sqlite rpmdb
 * write path.
 *
 * Usage:
 *   tdnf-rpmdb-write install <root> <file.rpm> [install_tid [install_time [install_color]]]
 *   tdnf-rpmdb-write replace <root> <old_hnum> <file.rpm> [install_tid [install_time [install_color]]]
 *   tdnf-rpmdb-write erase-hnum <root> <hnum>
 *   tdnf-rpmdb-write find-hnum <root> <nevra>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage:\n"
            "  %s install <root> <file.rpm> [install_tid [install_time [install_color]]]\n"
            "  %s replace <root> <old_hnum> <file.rpm> [install_tid [install_time [install_color]]]\n"
            "  %s erase-hnum <root> <hnum>\n"
            "  %s find-hnum <root> <nevra>\n",
            argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    uint32_t tid = 0;
    uint32_t when = 0;
    uint32_t color = 3;
    uint32_t hnum = 0;
    int rc;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    if (!strcmp(argv[1], "install")) {
        if (argc < 4 || argc > 7) {
            usage(argv[0]);
            return 2;
        }
        tid = (argc > 4) ? 0 : (uint32_t)time(NULL);
        when = tid;
        if (argc > 4 && parse_u32(argv[4], &tid) < 0) {
            fprintf(stderr, "invalid install_tid: %s\n", argv[4]);
            return 2;
        }
        if (argc > 5 && parse_u32(argv[5], &when) < 0) {
            fprintf(stderr, "invalid install_time: %s\n", argv[5]);
            return 2;
        }
        if (argc > 6 && parse_u32(argv[6], &color) < 0) {
            fprintf(stderr, "invalid install_color: %s\n", argv[6]);
            return 2;
        }
        if (argc == 5) {
            when = tid;
        }
        rc = tdnf_rpmdb_write_install(argv[2], argv[3], tid, when, color,
                                      NULL, 0, &hnum);
        if (rc != 0) {
            fprintf(stderr, "tdnf-rpmdb-write install: %s\n",
                    tdnf_rpmdb_last_error());
            return 1;
        }
        printf("%u\n", hnum);
        return 0;
    }

    if (!strcmp(argv[1], "replace")) {
        uint32_t old_hnum = 0;
        if (argc < 5 || argc > 8) {
            usage(argv[0]);
            return 2;
        }
        if (parse_u32(argv[3], &old_hnum) < 0) {
            fprintf(stderr, "invalid old_hnum: %s\n", argv[3]);
            return 2;
        }
        tid = (argc > 5) ? 0 : (uint32_t)time(NULL);
        when = tid;
        if (argc > 5 && parse_u32(argv[5], &tid) < 0) {
            fprintf(stderr, "invalid install_tid: %s\n", argv[5]);
            return 2;
        }
        if (argc > 6 && parse_u32(argv[6], &when) < 0) {
            fprintf(stderr, "invalid install_time: %s\n", argv[6]);
            return 2;
        }
        if (argc > 7 && parse_u32(argv[7], &color) < 0) {
            fprintf(stderr, "invalid install_color: %s\n", argv[7]);
            return 2;
        }
        if (argc == 6) {
            when = tid;
        }
        rc = tdnf_rpmdb_write_replace(argv[2], old_hnum, argv[4], tid, when,
                                      color, NULL, 0, &hnum);
        if (rc != 0) {
            fprintf(stderr, "tdnf-rpmdb-write replace: %s\n",
                    tdnf_rpmdb_last_error());
            return 1;
        }
        printf("%u\n", hnum);
        return 0;
    }

    if (!strcmp(argv[1], "erase-hnum")) {
        if (argc != 4) {
            usage(argv[0]);
            return 2;
        }
        if (parse_u32(argv[3], &hnum) < 0) {
            fprintf(stderr, "invalid hnum: %s\n", argv[3]);
            return 2;
        }
        rc = tdnf_rpmdb_write_erase_hnum(argv[2], hnum);
        if (rc != 0) {
            fprintf(stderr, "tdnf-rpmdb-write erase-hnum: %s\n",
                    tdnf_rpmdb_last_error());
            return 1;
        }
        return 0;
    }

    if (!strcmp(argv[1], "find-hnum")) {
        if (argc != 4) {
            usage(argv[0]);
            return 2;
        }
        rc = tdnf_rpmdb_find_hnum_by_nevra(argv[2], argv[3], &hnum);
        if (rc < 0) {
            fprintf(stderr, "tdnf-rpmdb-write find-hnum: %s\n",
                    tdnf_rpmdb_last_error());
            return 1;
        }
        if (rc == 0) {
            return 3;
        }
        printf("%u\n", hnum);
        return 0;
    }

    usage(argv[0]);
    return 2;
}
