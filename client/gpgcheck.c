/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

#include "gpgcheck_zig.h"

static void
TDNFFreeFreshGPGKeys(
    void **ppKeys,
    size_t nKeyCount
    );

static uint32_t
TDNFMapDigestIntegrityOutcome(
    int nOutcome
    );

static uint32_t
TDNFMapSignatureIntegrityOutcome(
    int nOutcome
    );

static uint32_t
TDNFGPGCheckPackageInternal(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszFilePath,
    tdnf_rpm_file *pRpmFile,
    int *pnPolicyRejected
    );

uint32_t
ReadGPGKeyFile(
    const char* pszFile,
    char** ppszKeyData,
    int* pnSize
   )
{
    uint32_t dwError = 0;
    char* pszKeyData = NULL;
    int nPathIsDir = 0;

    if(IsNullOrEmptyString(pszFile) || !ppszKeyData || !pnSize)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFIsDir(pszFile, &nPathIsDir);
    if(dwError)
    {
        pr_err("Error: Accessing gpgkey at %s\n",
            pszFile);
    }
    BAIL_ON_TDNF_ERROR(dwError);

    if(nPathIsDir)
    {
        dwError = ERROR_TDNF_KEYURL_INVALID;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFFileReadAllText(pszFile, &pszKeyData, pnSize);
    BAIL_ON_TDNF_ERROR(dwError);

    *ppszKeyData = pszKeyData;

cleanup:
    return dwError;

error:
    TDNF_SAFE_FREE_MEMORY(pszKeyData);
    goto cleanup;
}

uint32_t
TDNFImportGPGKeyFile(
    void *pLegacyTransaction,
    const char* pszFile
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_config *pRpmConfig = NULL;
    char* pszKeyData = NULL;
    int nKeyDataSize = 0;

    if(pLegacyTransaction == NULL || IsNullOrEmptyString(pszFile))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = ReadGPGKeyFile(pszFile, &pszKeyData, &nKeyDataSize);
    BAIL_ON_TDNF_ERROR(dwError);

    pRpmConfig = tdnf_rpm_config_create("/");
    if(!pRpmConfig)
    {
        pr_err("Unable to initialize native package configuration: %s\n",
               tdnf_rpm_config_last_error());
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFImportGPGKeyData(
                  pRpmConfig,
                  pszKeyData,
                  (size_t)nKeyDataSize);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    tdnf_rpm_config_destroy(pRpmConfig);
    TDNF_SAFE_FREE_MEMORY(pszKeyData);
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFImportGPGKeyData(
    const tdnf_rpm_config *pRpmConfig,
    const void *pKeyData,
    size_t nKeyDataSize
    )
{
    uint32_t dwError = 0;
    size_t nImported = 0;

    if(pRpmConfig == NULL || pKeyData == NULL || nKeyDataSize == 0)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(tdnf_rpmdb_import_pubkeys_config(
           pRpmConfig,
           pKeyData,
           nKeyDataSize,
           &nImported) != 0 ||
       nImported == 0)
    {
        pr_err("Unable to import repository key: %s\n",
               tdnf_rpmdb_last_error());
        dwError = ERROR_TDNF_INVALID_PUBKEY_FILE;
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
TDNFGPGCheckPackageInternal(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszFilePath,
    tdnf_rpm_file *pRpmFile,
    int *pnPolicyRejected
    )
{
    uint32_t dwError = 0;
    char** ppszUrlGPGKeys = NULL;
    char* pszLocalGPGKey = NULL;
    char* pszKeyData = NULL;
    void **ppFreshKeys = NULL;
    size_t *pnFreshKeyLengths = NULL;
    size_t nFreshKeyCount = 0;
    size_t nConfiguredKeyCount = 0;
    int nAnswer = 0;
    int nRemote = 0;
    int nIntegrityOutcome = TDNF_RPMZIG_INTEGRITY_INTERNAL;
    int nSigned = 0;
    int nKeyDataSize = 0;
    size_t nIndex = 0;

    if(pnPolicyRejected)
    {
        *pnPolicyRejected = 0;
    }

    if(pTdnf == NULL || pTdnf->pConf == NULL ||
       pTdnf->pRpmConfig == NULL || pRepo == NULL ||
       IsNullOrEmptyString(pszFilePath) || pRpmFile == NULL)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    /*
     * --nogpgcheck still requires a syntactically valid RPM, but leaves its
     * internal digest and signature candidates unchecked.
     */
    if (!pRepo->nGPGCheck)
    {
        goto cleanup;
    }

    if (!pTdnf->pConf->nSkipDigest)
    {
        if(tdnf_rpm_file_verify_digests(pRpmFile, &nIntegrityOutcome) != 0)
        {
            pr_err("Unable to verify package digests for %s: %s\n",
                   pszFilePath, tdnf_rpmdb_last_error());
            dwError = ERROR_TDNF_RPM_CHECK;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        dwError = TDNFMapDigestIntegrityOutcome(nIntegrityOutcome);
        if(dwError && pnPolicyRejected &&
           nIntegrityOutcome != TDNF_RPMZIG_INTEGRITY_INTERNAL)
        {
            *pnPolicyRejected = 1;
        }
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (pTdnf->pConf->nSkipSignature)
    {
        goto cleanup;
    }

    nSigned = tdnf_rpm_file_is_signed(pRpmFile);
    if(nSigned < 0)
    {
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!nSigned)
    {
        if(pnPolicyRejected)
        {
            *pnPolicyRejected = 1;
        }
        dwError = ERROR_TDNF_RPM_UNSIGNED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(TDNFRpmzigVerifyFile(
           pRpmFile,
           pTdnf->pRpmConfig,
           NULL,
           NULL,
           0,
           &nIntegrityOutcome) != 0)
    {
        pr_err("Unable to verify package signature for %s: %s\n",
               pszFilePath, tdnf_rpmdb_last_error());
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(nIntegrityOutcome == TDNF_RPMZIG_INTEGRITY_OK)
    {
        goto cleanup;
    }
    if(nIntegrityOutcome != TDNF_RPMZIG_INTEGRITY_MISSING)
    {
        dwError = TDNFMapSignatureIntegrityOutcome(nIntegrityOutcome);
        if(dwError && pnPolicyRejected &&
           nIntegrityOutcome != TDNF_RPMZIG_INTEGRITY_INTERNAL)
        {
            *pnPolicyRejected = 1;
        }
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGetGPGKeys(pTdnf, pRepo, &ppszUrlGPGKeys);
    BAIL_ON_TDNF_ERROR(dwError);

    for(nIndex = 0; ppszUrlGPGKeys[nIndex]; nIndex++)
    {
        nConfiguredKeyCount++;
    }
    if(!nConfiguredKeyCount)
    {
        dwError = ERROR_TDNF_NO_GPGKEY_CONF_ENTRY;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(
                  nConfiguredKeyCount,
                  sizeof(*ppFreshKeys),
                  (void **)&ppFreshKeys);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(
                  nConfiguredKeyCount,
                  sizeof(*pnFreshKeyLengths),
                  (void **)&pnFreshKeyLengths);
    BAIL_ON_TDNF_ERROR(dwError);

    for(nIndex = 0; ppszUrlGPGKeys[nIndex]; nIndex++)
    {
        pr_info("importing key from %s\n", ppszUrlGPGKeys[nIndex]);
        nAnswer = 0;
        dwError = TDNFYesOrNo(pTdnf->pArgs, "Is this ok [y/N]: ", &nAnswer);
        BAIL_ON_TDNF_ERROR(dwError);

        if(!nAnswer)
        {
            dwError = ERROR_TDNF_OPERATION_ABORTED;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        nRemote = 0;
        dwError = TDNFUriIsRemote(ppszUrlGPGKeys[nIndex], &nRemote);
        if (dwError == ERROR_TDNF_URL_INVALID)
        {
            dwError = ERROR_TDNF_KEYURL_INVALID;
        }
        BAIL_ON_TDNF_ERROR(dwError);

        if(nRemote)
        {
            dwError = TDNFFetchRemoteGPGKey(
                          pTdnf,
                          pRepo,
                          ppszUrlGPGKeys[nIndex],
                          &pszLocalGPGKey);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        else
        {
            dwError = TDNFPathFromUri(
                          ppszUrlGPGKeys[nIndex],
                          &pszLocalGPGKey);
            if (dwError == ERROR_TDNF_URL_INVALID)
            {
                dwError = ERROR_TDNF_KEYURL_INVALID;
            }
            BAIL_ON_TDNF_ERROR(dwError);
        }

        dwError = ReadGPGKeyFile(
                      pszLocalGPGKey,
                      &pszKeyData,
                      &nKeyDataSize);
        BAIL_ON_TDNF_ERROR(dwError);
        if(nKeyDataSize <= 0)
        {
            dwError = ERROR_TDNF_INVALID_PUBKEY_FILE;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        dwError = TDNFImportGPGKeyData(
                      pTdnf->pRpmConfig,
                      pszKeyData,
                      (size_t)nKeyDataSize);
        BAIL_ON_TDNF_ERROR(dwError);

        ppFreshKeys[nFreshKeyCount] = pszKeyData;
        pnFreshKeyLengths[nFreshKeyCount] = (size_t)nKeyDataSize;
        nFreshKeyCount++;
        pszKeyData = NULL;
        nKeyDataSize = 0;

        if(nRemote && unlink(pszLocalGPGKey))
        {
            dwError = errno;
            BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
        }
        nRemote = 0;
        TDNF_SAFE_FREE_MEMORY(pszLocalGPGKey);
    }

    if(TDNFRpmzigVerifyFile(
           pRpmFile,
           pTdnf->pRpmConfig,
           (const void *const *)ppFreshKeys,
           pnFreshKeyLengths,
           nFreshKeyCount,
           &nIntegrityOutcome) != 0)
    {
        pr_err("Unable to verify package signature for %s: %s\n",
               pszFilePath, tdnf_rpmdb_last_error());
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    dwError = TDNFMapSignatureIntegrityOutcome(nIntegrityOutcome);
    if(dwError && pnPolicyRejected &&
       nIntegrityOutcome != TDNF_RPMZIG_INTEGRITY_INTERNAL)
    {
        *pnPolicyRejected = 1;
    }
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_STRINGARRAY(ppszUrlGPGKeys);
    TDNF_SAFE_FREE_MEMORY(pszKeyData);
    TDNFFreeFreshGPGKeys(ppFreshKeys, nFreshKeyCount);
    TDNF_SAFE_FREE_MEMORY(pnFreshKeyLengths);
    if(nRemote && pszLocalGPGKey)
    {
        (void)unlink(pszLocalGPGKey);
    }
    TDNF_SAFE_FREE_MEMORY(pszLocalGPGKey);
    return dwError;

error:
    goto cleanup;
}

uint32_t
TDNFGPGCheckPackageWithFile(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszFilePath,
    tdnf_rpm_file *pRpmFile,
    int *pnPolicyRejected
    )
{
    return TDNFGPGCheckPackageInternal(
               pTdnf,
               pRepo,
               pszFilePath,
               pRpmFile,
               pnPolicyRejected);
}

uint32_t
TDNFGPGCheckPackageEx(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszFilePath,
    tdnf_rpm_file **ppRpmFile,
    int *pnPolicyRejected
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_file *pRpmFile = NULL;

    if(ppRpmFile)
    {
        *ppRpmFile = NULL;
    }
    if(pnPolicyRejected)
    {
        *pnPolicyRejected = 0;
    }

    if(pTdnf == NULL || pTdnf->pConf == NULL ||
       pTdnf->pRpmConfig == NULL || pRepo == NULL ||
       IsNullOrEmptyString(pszFilePath))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pRpmFile = tdnf_rpm_file_open(pszFilePath);
    if(!pRpmFile)
    {
        pr_err("Unable to parse package %s: %s\n",
               pszFilePath, tdnf_rpmdb_last_error());
        dwError = ERROR_TDNF_RPMRC_NOTFOUND;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGPGCheckPackageInternal(
                  pTdnf,
                  pRepo,
                  pszFilePath,
                  pRpmFile,
                  pnPolicyRejected);
    BAIL_ON_TDNF_ERROR(dwError);

    if(ppRpmFile)
    {
        *ppRpmFile = pRpmFile;
        pRpmFile = NULL;
    }

cleanup:
    tdnf_rpm_file_close(pRpmFile);
    return dwError;

error:
    goto cleanup;
}

uint32_t
TDNFGPGCheckPackage(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszFilePath,
    tdnf_rpm_file **ppRpmFile
    )
{
    return TDNFGPGCheckPackageEx(
               pTdnf,
               pRepo,
               pszFilePath,
               ppRpmFile,
               NULL);
}

static void
TDNFFreeFreshGPGKeys(
    void **ppKeys,
    size_t nKeyCount
    )
{
    size_t nIndex = 0;

    if(!ppKeys)
    {
        return;
    }
    for(nIndex = 0; nIndex < nKeyCount; nIndex++)
    {
        TDNFFreeMemory(ppKeys[nIndex]);
    }
    TDNFFreeMemory(ppKeys);
}

static uint32_t
TDNFMapDigestIntegrityOutcome(
    int nOutcome
    )
{
    switch(nOutcome)
    {
        case TDNF_RPMZIG_INTEGRITY_OK:
            return 0;
        case TDNF_RPMZIG_INTEGRITY_MISSING:
            pr_err("RPM is missing required internal digest coverage\n");
            return ERROR_TDNF_RPM_CHECK;
        case TDNF_RPMZIG_INTEGRITY_BAD:
            pr_err("RPM internal digest verification failed\n");
            return ERROR_TDNF_RPM_CHECK;
        case TDNF_RPMZIG_INTEGRITY_UNSUPPORTED:
            pr_err("RPM uses an unsupported internal digest\n");
            return ERROR_TDNF_RPM_CHECK;
        case TDNF_RPMZIG_INTEGRITY_MALFORMED:
            pr_err("RPM contains malformed internal digest metadata\n");
            return ERROR_TDNF_RPM_CHECK;
        default:
            pr_err("RPM internal digest verification could not complete\n");
            return ERROR_TDNF_RPM_CHECK;
    }
}

static uint32_t
TDNFMapSignatureIntegrityOutcome(
    int nOutcome
    )
{
    switch(nOutcome)
    {
        case TDNF_RPMZIG_INTEGRITY_OK:
            return 0;
        case TDNF_RPMZIG_INTEGRITY_MISSING:
            pr_err("RPM signature has no matching trusted key\n");
            return ERROR_TDNF_RPM_GPG_NO_MATCH;
        case TDNF_RPMZIG_INTEGRITY_BAD:
            pr_err("RPM signature verification failed\n");
            return ERROR_TDNF_RPM_GPG_NO_MATCH;
        case TDNF_RPMZIG_INTEGRITY_UNSUPPORTED:
            pr_err("RPM signature uses unsupported OpenPGP metadata\n");
            return ERROR_TDNF_RPM_GPG_PARSE_FAILED;
        case TDNF_RPMZIG_INTEGRITY_MALFORMED:
            pr_err("RPM contains malformed OpenPGP signature metadata\n");
            return ERROR_TDNF_RPM_GPG_PARSE_FAILED;
        default:
            pr_err("RPM signature verification could not complete\n");
            return ERROR_TDNF_RPM_CHECK;
    }
}

uint32_t
TDNFFetchRemoteGPGKey(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszUrlGPGKey,
    char** ppszKeyLocation
    )
{
    uint32_t dwError = 0;
    char* pszFilePath = NULL;
    char* pszNormalPath = NULL;
    char* pszTopKeyCacheDir = NULL;
    char* pszRealTopKeyCacheDir = NULL;
    char* pszDownloadCacheDir = NULL;
    char* pszKeyLocation = NULL;

    if(!pTdnf || !pRepo || IsNullOrEmptyString(pszUrlGPGKey))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFPathFromUri(pszUrlGPGKey, &pszKeyLocation);
    if (dwError == ERROR_TDNF_URL_INVALID)
    {
        dwError = ERROR_TDNF_KEYURL_INVALID;
    }
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFGetCachePath(pTdnf, pRepo,
                               "keys", NULL,
                               &pszTopKeyCacheDir);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFNormalizePath(pszTopKeyCacheDir,
                                &pszRealTopKeyCacheDir);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFJoinPath(
                  &pszFilePath,
                  pszRealTopKeyCacheDir,
                  pszKeyLocation,
                  NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFNormalizePath(
                  pszFilePath,
                  &pszNormalPath);
    BAIL_ON_TDNF_ERROR(dwError);

    if (strncmp(pszRealTopKeyCacheDir, pszNormalPath, strlen(pszRealTopKeyCacheDir)))
    {
        dwError = ERROR_TDNF_KEYURL_INVALID;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFDirName(pszNormalPath, &pszDownloadCacheDir);
    BAIL_ON_TDNF_ERROR(dwError);

    if(access(pszDownloadCacheDir, F_OK))
    {
        if(errno != ENOENT)
        {
            dwError = errno;
        }
        BAIL_ON_TDNF_SYSTEM_ERROR(dwError);

        dwError = TDNFUtilsMakeDirs(pszDownloadCacheDir);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFDownloadFile(pTdnf, pRepo, pszUrlGPGKey, pszFilePath,
                               basename(pszFilePath));
    BAIL_ON_TDNF_ERROR(dwError);

    *ppszKeyLocation = pszNormalPath;

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszFilePath);
    TDNF_SAFE_FREE_MEMORY(pszRealTopKeyCacheDir);
    TDNF_SAFE_FREE_MEMORY(pszTopKeyCacheDir);
    TDNF_SAFE_FREE_MEMORY(pszDownloadCacheDir);
    TDNF_SAFE_FREE_MEMORY(pszKeyLocation);
    return dwError;

error:
    pr_err("Error processing key: %s\n", pszUrlGPGKey);
    TDNF_SAFE_FREE_MEMORY(pszNormalPath);
    *ppszKeyLocation = NULL;
    goto cleanup;
}
