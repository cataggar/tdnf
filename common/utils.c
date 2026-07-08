/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

hash_op hash_ops[TDNF_HASH_SENTINEL] =
    {
       [TDNF_HASH_MD5]    = {"md5", TDNF_MD5_DIGEST_LEN},
       [TDNF_HASH_SHA1]   = {"sha1", TDNF_SHA1_DIGEST_LEN},
       [TDNF_HASH_SHA256] = {"sha256", TDNF_SHA256_DIGEST_LEN},
       [TDNF_HASH_SHA512] = {"sha512", TDNF_SHA512_DIGEST_LEN},
    };

hash_type hashType[] =
    {
        {"md5", TDNF_HASH_MD5},
        {"sha1", TDNF_HASH_SHA1},
        {"sha-1", TDNF_HASH_SHA1},
        {"sha256", TDNF_HASH_SHA256},
        {"sha-256", TDNF_HASH_SHA256},
        {"sha512", TDNF_HASH_SHA512},
        {"sha-512", TDNF_HASH_SHA512}
    };

static uint32_t
TDNFGetDigestForFileRpmzig(
    const char *filename,
    int type,
    uint8_t *digest
    );

static int
TDNFIsFipsModeEnabled(
    void
    );

uint32_t
TDNFGetDigestForFile(
    const char *filename,
    int type,
    uint8_t *digest
    )
{
    uint32_t dwError = 0;

    if (IsNullOrEmptyString(filename) || !digest)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (type < TDNF_HASH_MD5 || type >= TDNF_HASH_SENTINEL)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (type == TDNF_HASH_MD5 && TDNFIsFipsModeEnabled())
    {
        pr_err("Digest Init Failed\n");
        dwError = ERROR_TDNF_FIPS_MODE_FORBIDDEN;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGetDigestForFileRpmzig(filename, type, digest);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
TDNFGetDigestForFileRpmzig(
    const char *filename,
    int type,
    uint8_t *digest
    )
{
    uint32_t dwError = 0;
    int fd = -1;
    char buf[BUFSIZ] = {0};
    int length = 0;
    hash_op *hash = NULL;
    tdnf_rpmzig_digest_ctx *ctx = NULL;
    const char *pszRpmzigError = NULL;

    if (IsNullOrEmptyString(filename) || !digest)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (type < TDNF_HASH_MD5 || type >= TDNF_HASH_SENTINEL)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    hash = hash_ops + type;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        pr_err("ERROR: Checksum validating (%s) FAILED\n", filename);
        dwError = errno;
        BAIL_ON_TDNF_SYSTEM_ERROR_UNCOND(dwError);
    }

    ctx = tdnf_rpmzig_digest_open(type);
    if (!ctx)
    {
        pszRpmzigError = tdnf_rpmzig_checksum_last_error();
        pr_err(
            "rpmzig digest open failed for %s (%s): %s\n",
            filename,
            hash->hash_type,
            IsNullOrEmptyString(pszRpmzigError) ? "unknown error" : pszRpmzigError
        );
        dwError = ERROR_TDNF_CHECKSUM_VALIDATION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    while ((length = read(fd, buf, BUFSIZ - 1)) > 0)
    {
        if (tdnf_rpmzig_digest_update(ctx, (const unsigned char *)buf, (size_t)length) != 0)
        {
            pszRpmzigError = tdnf_rpmzig_checksum_last_error();
            pr_err(
                "rpmzig digest update failed for %s (%s): %s\n",
                filename,
                hash->hash_type,
                IsNullOrEmptyString(pszRpmzigError) ? "unknown error" : pszRpmzigError
            );
            dwError = ERROR_TDNF_CHECKSUM_VALIDATION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        memset(buf, 0, BUFSIZ);
    }

    if (length == -1)
    {
        pr_err("Error: Checksum validating (%s) FAILED\n", filename);
        dwError = errno;
        BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
    }

    if (tdnf_rpmzig_digest_final(ctx, digest, hash->length) != 0)
    {
        pszRpmzigError = tdnf_rpmzig_checksum_last_error();
        pr_err(
            "rpmzig digest final failed for %s (%s): %s\n",
            filename,
            hash->hash_type,
            IsNullOrEmptyString(pszRpmzigError) ? "unknown error" : pszRpmzigError
        );
        dwError = ERROR_TDNF_CHECKSUM_VALIDATION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    if (fd >= 0)
    {
        close(fd);
    }
    tdnf_rpmzig_digest_close(ctx);
    return dwError;
error:
    goto cleanup;
}

static int
TDNFIsFipsModeEnabled(
    void
    )
{
    uint32_t dwError = 0;
    char *pszFipsMode = NULL;
    const char *pszFipsValue = NULL;
    int nFipsModeEnabled = 0;

    dwError = TDNFFileReadAllText("/proc/sys/crypto/fips_enabled", &pszFipsMode, NULL);
    if (dwError)
    {
        goto cleanup;
    }

    pszFipsValue = TDNFLeftTrim(pszFipsMode);
    if (!IsNullOrEmptyString(pszFipsValue) && pszFipsValue[0] == '1')
    {
        nFipsModeEnabled = 1;
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszFipsMode);
    return nFipsModeEnabled;
}

uint32_t
TDNFCheckHash(
    const char *filename,
    const unsigned char *digest,
    int type
    )
{

    uint32_t dwError = 0;
    uint8_t digest_from_file[TDNF_MAX_DIGEST_LEN] = {0};
    hash_op *hash = NULL;

    if (IsNullOrEmptyString(filename) ||
       !digest)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (type  < TDNF_HASH_MD5 || type >= TDNF_HASH_SENTINEL)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    hash = hash_ops + type;

    dwError = TDNFGetDigestForFile(filename, type, digest_from_file);
    BAIL_ON_TDNF_ERROR(dwError);

    if (memcmp(digest_from_file, digest, hash->length))
    {
        dwError = ERROR_TDNF_CHECKSUM_VALIDATION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;
error:
    if (!IsNullOrEmptyString(filename))
    {
        pr_err("Error: Validating Checksum (%s) FAILED (digest mismatch)\n", filename);
    }
    goto cleanup;
}

/* Returns nonzero if hex_digest is properly formatted; that is each
   letter is in [0-9A-Za-z] and the length of the string equals to the
   result length of digest * 2. */
uint32_t
TDNFCheckHexDigest(
    const char *hex_digest,
    int digest_length
    )
{
    int i = 0;

    if(IsNullOrEmptyString(hex_digest) ||
       (digest_length <= 0))
    {
        return 0;
    }

    for(i = 0; hex_digest[i]; ++i)
    {
        if(!isxdigit(hex_digest[i]))
        {
            return 0;
        }
    }

    return digest_length * 2 == i;
}

uint32_t
TDNFHexToUint(
    const char *hex_digest,
    unsigned char *uintValue
    )
{
    uint32_t dwError = 0;
    char buf[3] = {0};
    unsigned long val = 0;

    if(IsNullOrEmptyString(hex_digest) ||
       !uintValue)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    buf[0] = hex_digest[0];
    buf[1] = hex_digest[1];

    errno = 0;
    val = strtoul(buf, NULL, 16);
    if(errno)
    {
        pr_err("Error: strtoul call failed\n");
        dwError = errno;
        BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
    }
    *uintValue = (unsigned char)(val&0xff);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFChecksumFromHexDigest(
    const char *hex_digest,
    unsigned char *ppdigest
    )
{
    uint32_t dwError = 0;
    unsigned char *pdigest = NULL;
    size_t i = 0;
    size_t len = 0;
    unsigned char uintValue = 0;

    if(IsNullOrEmptyString(hex_digest) ||
       !ppdigest)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    len = strlen(hex_digest);

    dwError = TDNFAllocateMemory(1, len/2, (void **)&pdigest);
    BAIL_ON_TDNF_ERROR(dwError);

    for(i = 0; i < len; i += 2)
    {
        dwError = TDNFHexToUint(hex_digest + i, &uintValue);
        BAIL_ON_TDNF_ERROR(dwError);

        pdigest[i>>1] = uintValue;
    }
    memcpy( ppdigest, pdigest, len>>1 );

cleanup:
    TDNF_SAFE_FREE_MEMORY(pdigest);
    return dwError;

error:
    goto cleanup;
}
