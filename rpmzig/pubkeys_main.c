/*
 * tdnf-rpmdb-pubkeys — smoke-test for the Zig rpmdb pubkey iterator.
 *
 * Lists every `gpg-pubkey-*` entry in the rpmdb. By default prints
 *
 *     <keyid>  <byte-length-of-armored-key>
 *
 * one per line. Pass `--dump` to also print the armored key bodies
 * (intended for diffing against `rpm -q --qf '%{DESCRIPTION}'`
 * output).
 *
 * Installed under libexec/tdnf/ alongside the other smoke binaries.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rpmdb.h"

int main(int argc, char **argv)
{
    const char *root = "/";
    int dump = 0;
    tdnf_rpmdb_pubkeys_iter *it = NULL;
    int rc;
    char *key = NULL;
    char *keyid = NULL;
    size_t key_len = 0;
    int exit_code = 0;
    size_t count = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dump") == 0) {
            dump = 1;
        } else if (argv[i][0] == '-') {
            fprintf(stderr,
                    "usage: tdnf-rpmdb-pubkeys [--dump] [root]\n");
            return 2;
        } else {
            root = argv[i];
        }
    }

    it = tdnf_rpmdb_pubkeys_open(root);
    if (!it) {
        fprintf(stderr, "tdnf-rpmdb-pubkeys: open: %s\n",
                tdnf_rpmdb_last_error());
        return 1;
    }

    while ((rc = tdnf_rpmdb_pubkeys_next(it, &key, &key_len, &keyid)) == 1) {
        printf("%s  %zu\n", keyid ? keyid : "(noid)", key_len);
        if (dump) {
            fputs(key, stdout);
            if (key_len == 0 || key[key_len - 1] != '\n') {
                fputc('\n', stdout);
            }
        }
        tdnf_rpmdb_string_free(key);
        tdnf_rpmdb_string_free(keyid);
        key = NULL;
        keyid = NULL;
        key_len = 0;
        count++;
    }

    if (rc < 0) {
        fprintf(stderr, "tdnf-rpmdb-pubkeys: %s\n",
                tdnf_rpmdb_last_error());
        exit_code = 1;
    } else if (count == 0) {
        fprintf(stderr,
                "tdnf-rpmdb-pubkeys: no gpg-pubkey-* entries found "
                "in rpmdb under %s\n",
                root);
    }

    tdnf_rpmdb_pubkeys_close(it);
    return exit_code;
}
