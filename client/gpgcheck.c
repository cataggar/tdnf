/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

#include "gpgcheck_zig.h"
#include "../rpmzig/verify.h"

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
    rpmts pTS,
    const char* pszFile
    )
{
    uint32_t dwError = 0;
    uint8_t* pPkt = NULL;
    size_t nPktLen = 0;
    char* pszKeyData = NULL;
    int nKeyDataSize;
    int nKeys = 0;
    int nOffset = 0;

    if(pTS == NULL || IsNullOrEmptyString(pszFile))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = ReadGPGKeyFile(pszFile, &pszKeyData, &nKeyDataSize);
    BAIL_ON_TDNF_ERROR(dwError);

    while (nOffset < nKeyDataSize)
    {
        pgpArmor nArmor = pgpParsePkts(pszKeyData + nOffset, &pPkt, &nPktLen);
        if(nArmor == PGPARMOR_PUBKEY)
        {
            dwError = rpmtsImportPubkey(pTS, pPkt, nPktLen);
            BAIL_ON_TDNF_ERROR(dwError);
            nKeys++;
        }
        nOffset += nPktLen;
    }

    if (nKeys == 0) {
        dwError = ERROR_TDNF_INVALID_PUBKEY_FILE;
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszKeyData);
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFGPGCheckPackage(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszFilePath,
    Header *pRpmHeader
    )
{
    uint32_t dwError = 0;
    Header rpmHeader = NULL;
    FD_t fp = NULL;
    char** ppszUrlGPGKeys = NULL;
    char* pszLocalGPGKey = NULL;
    int nAnswer = 0;
    int nRemote = 0;
    int i;
    int nMatched = 0;
    char *pszTmp = NULL;
    int nSavedVfyLevel = 0;
    rpmVSFlags savedVSFlags = 0;

    if(pTS == NULL || pTdnf == NULL || pRepo == NULL || IsNullOrEmptyString(pszFilePath))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    nSavedVfyLevel = rpmtsVfyLevel(pTS->pTS);
    savedVSFlags = rpmtsVSFlags(pTS->pTS);

    if (pRepo->nGPGCheck)
    {
        int level = RPMSIG_VERIFIABLE_TYPE;
        if (pTdnf->pConf->nSkipSignature) {
            level &= ~RPMSIG_SIGNATURE_TYPE;
            rpmtsSetVSFlags(pTS->pTS, rpmtsVSFlags(pTS->pTS) | RPMVSF_MASK_NOSIGNATURES);
        }
        if (pTdnf->pConf->nSkipDigest) {
            level &= ~RPMSIG_DIGEST_TYPE;
            rpmtsSetVSFlags(pTS->pTS, rpmtsVSFlags(pTS->pTS) | RPMVSF_MASK_NODIGESTS);
        }
        /* librpm is no longer the signature verifier — rpmzig's
         * pure-Zig path is. Skip librpm's sig check so
         * rpmReadPackageFile acts as a pure header reader and
         * doesn't fail with RPMRC_NOTTRUSTED on rpms whose keys
         * aren't yet in the rpmdb trust set. Header digest checks
         * stay active. */
        rpmtsSetVSFlags(pTS->pTS, rpmtsVSFlags(pTS->pTS) | RPMVSF_MASK_NOSIGNATURES);
        level &= ~RPMSIG_SIGNATURE_TYPE;
        rpmtsSetVfyLevel(pTS->pTS, level);
    } else {
        rpmtsSetVfyLevel(pTS->pTS, RPMSIG_NONE_TYPE);
    }

    fp = Fopen (pszFilePath, "r.ufdio");
    if(!fp)
    {
        dwError = errno;
        BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
    }

    dwError = rpmReadPackageFile(
                  pTS->pTS,
                  fp,
                  pszFilePath,
                  &rpmHeader);
    Fclose(fp);
    fp = NULL;

    BAIL_ON_TDNF_RPM_ERROR(dwError);

    if (pRepo->nGPGCheck && !pTdnf->pConf->nSkipSignature) {
        /* refuse to install an unsigned package if gpgcheck is enabled */
        if (((pszTmp = headerGetAsString(rpmHeader, RPMTAG_SIGPGP)) == NULL) &&
            ((pszTmp = headerGetAsString(rpmHeader, RPMTAG_SIGGPG)) == NULL) &&
            ((pszTmp = headerGetAsString(rpmHeader, RPMTAG_DSAHEADER)) == NULL) &&
#ifdef BUILD_WITH_RPM_6X
            ((pszTmp = headerGetAsString(rpmHeader, RPMTAG_OPENPGP)) == NULL) &&
#endif
            ((pszTmp = headerGetAsString(rpmHeader, RPMTAG_RSAHEADER)) == NULL))
        {
            dwError = ERROR_TDNF_RPM_UNSIGNED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    if (pRepo->nGPGCheck && !pTdnf->pConf->nSkipSignature)
    {
        dwError = TDNFGetGPGKeys(pTdnf, pRepo, &ppszUrlGPGKeys);
        BAIL_ON_TDNF_ERROR(dwError);

        for (i = 0; ppszUrlGPGKeys[i]; i++) {
            pr_info("importing key from %s\n", ppszUrlGPGKeys[i]);
            dwError = TDNFYesOrNo(pTdnf->pArgs, "Is this ok [y/N]: ", &nAnswer);
            BAIL_ON_TDNF_ERROR(dwError);

            if(!nAnswer)
            {
                dwError = ERROR_TDNF_OPERATION_ABORTED;
                BAIL_ON_TDNF_ERROR(dwError);
            }

            dwError = TDNFUriIsRemote(ppszUrlGPGKeys[i], &nRemote);
            if (dwError == ERROR_TDNF_URL_INVALID)
            {
                dwError = ERROR_TDNF_KEYURL_INVALID;
            }
            BAIL_ON_TDNF_ERROR(dwError);

            if (nRemote)
            {
                dwError = TDNFFetchRemoteGPGKey(pTdnf, pRepo, ppszUrlGPGKeys[i], &pszLocalGPGKey);
                BAIL_ON_TDNF_ERROR(dwError);
            }
            else
            {
                dwError = TDNFPathFromUri(ppszUrlGPGKeys[i], &pszLocalGPGKey);
                if (dwError == ERROR_TDNF_URL_INVALID)
                {
                    dwError = ERROR_TDNF_KEYURL_INVALID;
                }
                BAIL_ON_TDNF_ERROR(dwError);
            }
            /* Persist each user-approved repo key to the rpmdb as a
             * gpg-pubkey-* entry so subsequent installs and external
             * rpm(8) queries see the same trust set. rpmzig still
             * receives the fresh key directly below; this import is
             * for durable keyring compatibility, not for the current
             * verification attempt. */
            dwError = TDNFImportGPGKeyFile(pTS->pTS, pszLocalGPGKey);
            BAIL_ON_TDNF_ERROR(dwError);

            {
                int rpmzig_status = TDNF_RPMZIG_STATUS_INTERNAL_ERROR;
                (void)TDNFRpmzigVerify(
                    pszFilePath, pszLocalGPGKey,
                    pTdnf->pArgs ? pTdnf->pArgs->pszInstallRoot : NULL,
                    &rpmzig_status);
                if (rpmzig_status == TDNF_RPMZIG_STATUS_OK)
                {
                    nMatched++;
                }
                else if (rpmzig_status == TDNF_RPMZIG_STATUS_NO_KEY)
                {
                    /* The fresh key didn't match this signature.
                     * Try the next gpgkey url, if any. */
                }
                else
                {
                    pr_err("rpmzig refused signature on %s "
                           "(status=%d). Refusing to install.\n",
                           pszFilePath, rpmzig_status);
                    dwError = ERROR_TDNF_RPM_GPG_NO_MATCH;
                    BAIL_ON_TDNF_ERROR(dwError);
                }
            }

            if (nRemote)
            {
                if (unlink(pszLocalGPGKey))
                {
                    dwError = errno;
                    BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
                }
            }

            TDNF_SAFE_FREE_MEMORY(pszLocalGPGKey);
        }

        if (nMatched == 0)
        {
            dwError = ERROR_TDNF_RPM_GPG_NO_MATCH;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    /* optional output parameter */
    if (pRpmHeader != NULL)
    {
        *pRpmHeader = rpmHeader;
    }
    else if(rpmHeader)
    {
        headerFree(rpmHeader);
    }

cleanup:
    rpmtsSetVSFlags(pTS->pTS, savedVSFlags);
    rpmtsSetVfyLevel(pTS->pTS, nSavedVfyLevel);
    TDNF_SAFE_FREE_STRINGARRAY(ppszUrlGPGKeys);
    TDNF_SAFE_FREE_MEMORY(pszLocalGPGKey);
    TDNF_SAFE_FREE_MEMORY(pszTmp);
    if(fp)
    {
        Fclose(fp);
    }
    return dwError;

error:
    if(rpmHeader)
    {
        headerFree(rpmHeader);
    }
    goto cleanup;
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
