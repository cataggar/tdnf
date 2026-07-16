/*
 * tdnf-rpm-install — smoke-test for the native rpmzig file-install
 * engine.
 *
 * Usage:
 *   tdnf-rpm-install --root <root> [--upgrade|--reinstall]
 *                    [--prior <old.rpm> ...]
 *                    [--tsflag justdb|nodocs|nocaps|noconfigs ...]
 *                    <new.rpm>
 *
 * Installs the payload into <root> without touching the rpmdb.
 * Installed under libexec/tdnf/.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tdnfrpmtrans.h>
#include "rpmdb.h"

static TDNF_RPMTRANS_FLAGS parse_tsflag(const char *text)
{
    if (!strcmp(text, "justdb")) {
        return TDNF_RPMTRANS_FLAG_JUSTDB;
    }
    if (!strcmp(text, "nodocs")) {
        return TDNF_RPMTRANS_FLAG_NODOCS;
    }
    if (!strcmp(text, "nocaps")) {
        return TDNF_RPMTRANS_FLAG_NOCAPS;
    }
    if (!strcmp(text, "noconfigs")) {
        return TDNF_RPMTRANS_FLAG_NOCONFIGS;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *install_root = NULL;
    const char *rpm_path = NULL;
    tdnf_rpm_file *fh = NULL;
    tdnf_rpm_file **prior_files = NULL;
    tdnf_rpm_install_prior_header *prior_headers = NULL;
    size_t prior_count = 0;
    tdnf_rpm_install_kind install_kind = TDNF_RPM_INSTALL_KIND_INSTALL;
    TDNF_RPMTRANS_FLAGS trans_flags = TDNF_RPMTRANS_FLAG_NONE;
    int exit_code = 0;
    int i = 0;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--root")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --root\n");
                return 2;
            }
            install_root = argv[++i];
        } else if (!strcmp(argv[i], "--upgrade")) {
            install_kind = TDNF_RPM_INSTALL_KIND_UPGRADE;
        } else if (!strcmp(argv[i], "--reinstall")) {
            install_kind = TDNF_RPM_INSTALL_KIND_REINSTALL;
        } else if (!strcmp(argv[i], "--prior")) {
            const unsigned char *blob = NULL;
            size_t blob_len = 0;
            tdnf_rpm_file *prior_fh = NULL;
            tdnf_rpm_file **new_prior_files = NULL;
            tdnf_rpm_install_prior_header *new_prior_headers = NULL;

            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for --prior\n");
                return 2;
            }

            prior_fh = tdnf_rpm_file_open(argv[++i]);
            if (!prior_fh) {
                fprintf(stderr, "tdnf-rpm-install: open prior rpm: %s\n",
                        tdnf_rpmdb_last_error());
                exit_code = 1;
                goto out;
            }

            if (tdnf_rpm_file_main_header_blob(prior_fh, &blob, &blob_len) != 0) {
                fprintf(stderr, "tdnf-rpm-install: prior main header: %s\n",
                        tdnf_rpmdb_last_error());
                tdnf_rpm_file_close(prior_fh);
                exit_code = 1;
                goto out;
            }

            new_prior_files = realloc(prior_files,
                                      sizeof(*prior_files) * (prior_count + 1));
            if (!new_prior_files) {
                fprintf(stderr, "tdnf-rpm-install: out of memory\n");
                tdnf_rpm_file_close(prior_fh);
                exit_code = 1;
                goto out;
            }
            new_prior_headers = realloc(prior_headers,
                                        sizeof(*prior_headers) * (prior_count + 1));
            if (!new_prior_headers) {
                fprintf(stderr, "tdnf-rpm-install: out of memory\n");
                prior_files = new_prior_files;
                tdnf_rpm_file_close(prior_fh);
                exit_code = 1;
                goto out;
            }
            prior_files = new_prior_files;
            prior_headers = new_prior_headers;
            prior_files[prior_count] = prior_fh;
            prior_headers[prior_count].blob = blob;
            prior_headers[prior_count].len = blob_len;
            prior_count++;
        } else if (!strcmp(argv[i], "--tsflag")) {
            TDNF_RPMTRANS_FLAGS flag = TDNF_RPMTRANS_FLAG_NONE;
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
        } else if (!rpm_path) {
            rpm_path = argv[i];
        } else {
            fprintf(stderr, "unexpected positional argument: %s\n", argv[i]);
            return 2;
        }
    }

    if (!install_root || !rpm_path) {
        fprintf(stderr,
                "usage: %s --root <root> [--upgrade|--reinstall] "
                "[--prior <old.rpm> ...] "
                "[--tsflag justdb|nodocs|nocaps|noconfigs ...] <new.rpm>\n",
                argv[0]);
        return 2;
    }

    fh = tdnf_rpm_file_open(rpm_path);
    if (!fh) {
        fprintf(stderr, "tdnf-rpm-install: open: %s\n", tdnf_rpmdb_last_error());
        exit_code = 1;
        goto out;
    }

    {
        tdnf_rpm_install_options options = {
            .install_root = install_root,
            .trans_flags = trans_flags,
            .install_kind = install_kind,
            .prior_headers = prior_headers,
            .prior_header_count = prior_count,
            .conflict_fn = NULL,
            .conflict_fn_data = NULL,
        };
        if (tdnf_rpm_file_install(fh, &options) != 0) {
            fprintf(stderr, "tdnf-rpm-install: install: %s\n",
                    tdnf_rpmdb_last_error());
            exit_code = 1;
            goto out;
        }
    }

out:
    if (fh) {
        tdnf_rpm_file_close(fh);
    }
    for (i = 0; i < (int)prior_count; ++i) {
        tdnf_rpm_file_close(prior_files[i]);
    }
    free(prior_files);
    free(prior_headers);
    return exit_code;
}
