/*
 * tdnf-rpm-scriptlet — smoke-test exe for the native rpmzig
 * scriptlet executor.
 *
 * Usage:
 *   tdnf-rpm-scriptlet --root <root> --phase pre|post|preun|postun|pretrans|posttrans
 *                      [--arg1 N] [--arg2 N]
 *                      [--rpmdefine TEXT ...]
 *                      [--tsflag noscripts|nopre|nopost|nopreun|nopostun|nopretrans|noposttrans ...]
 *                      [--script-fd N] [--redirect-stdout-to-stderr]
 *                      <package.rpm>
 *
 * Exit status:
 *   0   -> scriptlet absent/skipped/succeeded
 *   40  -> scriptlet exited non-zero in a warning-only phase
 *   41  -> scriptlet exited non-zero in a critical phase
 *   42  -> scriptlet died from signal in a warning-only phase
 *   43  -> scriptlet died from signal in a critical phase
 *   1   -> API/runtime setup failure (see stderr)
 *   2   -> usage error
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rpm/rpmts.h>

#include "rpmdb.h"

static uint32_t parse_tsflag(const char *text)
{
    if (!strcmp(text, "noscripts")) {
        return RPMTRANS_FLAG_NOSCRIPTS;
    }
    if (!strcmp(text, "nopre")) {
        return RPMTRANS_FLAG_NOPRE;
    }
    if (!strcmp(text, "nopost")) {
        return RPMTRANS_FLAG_NOPOST;
    }
    if (!strcmp(text, "nopreun")) {
        return RPMTRANS_FLAG_NOPREUN;
    }
    if (!strcmp(text, "nopostun")) {
        return RPMTRANS_FLAG_NOPOSTUN;
    }
    if (!strcmp(text, "nopretrans")) {
        return RPMTRANS_FLAG_NOPRETRANS;
    }
    if (!strcmp(text, "noposttrans")) {
        return RPMTRANS_FLAG_NOPOSTTRANS;
    }
    return 0;
}

static int parse_phase(const char *text, tdnf_rpm_scriptlet_phase *phase_out)
{
    if (!strcmp(text, "pre")) {
        *phase_out = TDNF_RPM_SCRIPTLET_PHASE_PRE;
        return 0;
    }
    if (!strcmp(text, "post")) {
        *phase_out = TDNF_RPM_SCRIPTLET_PHASE_POST;
        return 0;
    }
    if (!strcmp(text, "preun")) {
        *phase_out = TDNF_RPM_SCRIPTLET_PHASE_PREUN;
        return 0;
    }
    if (!strcmp(text, "postun")) {
        *phase_out = TDNF_RPM_SCRIPTLET_PHASE_POSTUN;
        return 0;
    }
    if (!strcmp(text, "pretrans")) {
        *phase_out = TDNF_RPM_SCRIPTLET_PHASE_PRETRANS;
        return 0;
    }
    if (!strcmp(text, "posttrans")) {
        *phase_out = TDNF_RPM_SCRIPTLET_PHASE_POSTTRANS;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    const char *install_root = NULL;
    const char *rpm_path = NULL;
    const unsigned char *blob = NULL;
    size_t blob_len = 0;
    tdnf_rpm_file *fh = NULL;
    tdnf_rpm_scriptlet_phase phase = TDNF_RPM_SCRIPTLET_PHASE_PRE;
    tdnf_rpm_scriptlet_result result = {0};
    tdnf_rpm_scriptlet_options options = {
        .install_root = NULL,
        .trans_flags = 0,
        .rpmdefines = NULL,
        .rpmdefine_count = 0,
        .arg1 = -1,
        .arg2 = -1,
        .script_fd = -1,
        .redirect_stdout_to_stderr = 0,
    };
    const char **rpmdefines = NULL;
    int phase_set = 0;
    int exit_code = 0;
    int i = 0;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--root")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --root\n");
                return 2;
            }
            install_root = argv[++i];
        } else if (!strcmp(argv[i], "--phase")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --phase\n");
                return 2;
            }
            if (parse_phase(argv[++i], &phase) != 0) {
                fprintf(stderr, "unsupported --phase value: %s\n", argv[i]);
                return 2;
            }
            phase_set = 1;
        } else if (!strcmp(argv[i], "--arg1")) {
            char *end = NULL;
            long value;
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --arg1\n");
                return 2;
            }
            errno = 0;
            value = strtol(argv[++i], &end, 10);
            if (errno != 0 || !end || *end != '\0') {
                fprintf(stderr, "invalid --arg1 value: %s\n", argv[i]);
                return 2;
            }
            options.arg1 = (int)value;
        } else if (!strcmp(argv[i], "--arg2")) {
            char *end = NULL;
            long value;
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --arg2\n");
                return 2;
            }
            errno = 0;
            value = strtol(argv[++i], &end, 10);
            if (errno != 0 || !end || *end != '\0') {
                fprintf(stderr, "invalid --arg2 value: %s\n", argv[i]);
                return 2;
            }
            options.arg2 = (int)value;
        } else if (!strcmp(argv[i], "--script-fd")) {
            char *end = NULL;
            long value;
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --script-fd\n");
                return 2;
            }
            errno = 0;
            value = strtol(argv[++i], &end, 10);
            if (errno != 0 || !end || *end != '\0' || value < 0) {
                fprintf(stderr, "invalid --script-fd value: %s\n", argv[i]);
                return 2;
            }
            options.script_fd = (int)value;
        } else if (!strcmp(argv[i], "--redirect-stdout-to-stderr")) {
            options.redirect_stdout_to_stderr = 1;
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
            options.trans_flags |= flag;
        } else if (!strcmp(argv[i], "--rpmdefine")) {
            const char **new_defines = NULL;
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --rpmdefine\n");
                return 2;
            }
            new_defines = realloc(rpmdefines,
                                  sizeof(*rpmdefines) * (options.rpmdefine_count + 1));
            if (!new_defines) {
                fprintf(stderr, "tdnf-rpm-scriptlet: out of memory\n");
                return 1;
            }
            rpmdefines = new_defines;
            rpmdefines[options.rpmdefine_count++] = argv[++i];
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "unsupported option: %s\n", argv[i]);
            return 2;
        } else if (!rpm_path) {
            rpm_path = argv[i];
        } else {
            fprintf(stderr, "unexpected positional argument: %s\n", argv[i]);
            return 2;
        }
    }

    if (!install_root || !phase_set || !rpm_path) {
        fprintf(stderr,
                "usage: %s --root <root> --phase pre|post|preun|postun|pretrans|posttrans "
                "[--arg1 N] [--arg2 N] [--rpmdefine TEXT ...] "
                "[--tsflag noscripts|nopre|nopost|nopreun|nopostun|nopretrans|noposttrans ...] "
                "[--script-fd N] [--redirect-stdout-to-stderr] <package.rpm>\n",
                argv[0]);
        return 2;
    }

    fh = tdnf_rpm_file_open(rpm_path);
    if (!fh) {
        fprintf(stderr, "tdnf-rpm-scriptlet: open: %s\n", tdnf_rpmdb_last_error());
        exit_code = 1;
        goto out;
    }

    if (tdnf_rpm_file_main_header_blob(fh, &blob, &blob_len) != 0) {
        fprintf(stderr, "tdnf-rpm-scriptlet: main header: %s\n", tdnf_rpmdb_last_error());
        exit_code = 1;
        goto out;
    }

    options.install_root = install_root;
    options.rpmdefines = rpmdefines;

    if (tdnf_rpm_header_run_scriptlet(blob, blob_len, phase, &options, &result) != 0) {
        fprintf(stderr, "tdnf-rpm-scriptlet: run: %s\n", tdnf_rpmdb_last_error());
        exit_code = 1;
        goto out;
    }

    switch (result.outcome) {
        case TDNF_RPM_SCRIPTLET_OUTCOME_NOT_RUN:
        case TDNF_RPM_SCRIPTLET_OUTCOME_OK:
            exit_code = 0;
            break;
        case TDNF_RPM_SCRIPTLET_OUTCOME_EXITED:
            exit_code = result.critical ? 41 : 40;
            break;
        case TDNF_RPM_SCRIPTLET_OUTCOME_SIGNALED:
            exit_code = result.critical ? 43 : 42;
            break;
        default:
            exit_code = 1;
            break;
    }

out:
    if (fh) {
        tdnf_rpm_file_close(fh);
    }
    free(rpmdefines);
    return exit_code;
}
