/*
 * tdnf-rpmdb-import-pubkeys — smoke-test for the native certificate
 * import ABI.
 */
#include <stdio.h>
#include <stdlib.h>

#include "rpmdb.h"

static int slurp(const char *path, unsigned char **out, size_t *out_len)
{
    FILE *fp = NULL;
    unsigned char *data = NULL;
    long length = 0;

    fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    length = ftell(fp);
    if (length <= 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    data = malloc((size_t)length);
    if (!data) {
        fclose(fp);
        return -1;
    }
    if (fread(data, 1, (size_t)length, fp) != (size_t)length) {
        free(data);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out = data;
    *out_len = (size_t)length;
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char *data = NULL;
    size_t length = 0;
    size_t imported = 0;
    int rc = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <root> <key-file>\n", argv[0]);
        return 2;
    }
    if (slurp(argv[2], &data, &length) != 0) {
        fprintf(stderr, "%s: unable to read %s\n", argv[0], argv[2]);
        return 1;
    }
    if (tdnf_rpmdb_import_pubkeys(
            argv[1], data, length, &imported) != 0) {
        fprintf(stderr, "%s: %s\n", argv[0], tdnf_rpmdb_last_error());
        goto cleanup;
    }
    printf("%zu\n", imported);
    rc = 0;

cleanup:
    free(data);
    return rc;
}
