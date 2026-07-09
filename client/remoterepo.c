/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

static int
progress_cb_impl(
    void *pUserData,
    int64_t dlTotal,
    int64_t dlNow,
    int64_t ulTotal,
    int64_t ulNow
    )
{
    uint32_t dPercent;
    pcb_data *pData = (pcb_data *)pUserData;

    UNUSED(ulNow);
    UNUSED(ulTotal);

    if (dlTotal <= 0)
    {
        return 0;
    }

    if (dlNow < dlTotal)
    {
        time(&pData->cur_time);
        if (pData->prev_time &&
            difftime(pData->cur_time, pData->prev_time) < 1.0)
        {
            return 0;
        }
        pData->prev_time = pData->cur_time;
        dPercent = (uint32_t)(((double)dlNow / (double)dlTotal) * 100.0);
    }
    else
    {
        pData->prev_time = 0;
        dPercent = 100;
    }

    if (!isatty(STDOUT_FILENO))
    {
        pr_info("%s %u%% %ld\n", pData->pszData, dPercent, dlNow);
    }
    else
    {
        pr_info("%-35s %10ld %u%%\r", pData->pszData, dlNow, dPercent);
    }

    fflush(stdout);

    return 0;
}

static int
progress_cb(
    void *pUserData,
    int64_t dlTotal,
    int64_t dlNow,
    int64_t ulTotal,
    int64_t ulNow
    )
{
    return progress_cb_impl(pUserData, dlTotal, dlNow, ulTotal, ulNow);
}

static uint32_t
set_progress_cb_data(
    const char *pszData,
    pcb_data **ppData
    )
{
    uint32_t dwError = 0;
    static pcb_data pData;

    if(!ppData || IsNullOrEmptyString(pszData))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    memset(&pData, 0, sizeof(pcb_data));
    strncpy(pData.pszData, pszData, sizeof(pData.pszData) - 1);
    *ppData = &pData;

cleanup:
    return dwError;

error:
    goto cleanup;
}

static int
TDNFZigDownloadErrorIsFatal(
    uint32_t dwError,
    long lStatus
    )
{
    if (lStatus >= 400)
    {
        return 1;
    }

    switch(dwError)
    {
        case ERROR_TDNF_CALL_NOT_SUPPORTED:
        case ERROR_TDNF_INVALID_PARAMETER:
        case ERROR_TDNF_URL_INVALID:
        case ERROR_TDNF_SET_SSL_SETTINGS:
        case ERROR_TDNF_OPERATION_ABORTED:
        case ERROR_TDNF_OUT_OF_MEMORY:
            return 1;
        default:
            break;
    }

    return 0;
}

static uint32_t
TDNFPrepareZigDownloadRequest(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char *pszFileUrl,
    const char *pszFileTmp,
    const char *pszProgressData,
    TDNF_ZIG_DOWNLOAD_REQUEST *pRequest,
    int *pnNoOutput
    )
{
    uint32_t dwError = 0;
    pcb_data *pProgressData = NULL;

    if(!pTdnf ||
       !pTdnf->pArgs ||
       !pTdnf->pConf ||
       !pRepo ||
       IsNullOrEmptyString(pszFileUrl) ||
       IsNullOrEmptyString(pszFileTmp) ||
       !pRequest ||
       !pnNoOutput)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    memset(pRequest, 0, sizeof(*pRequest));
    pRequest->pszUrl = pszFileUrl;
    pRequest->pszDestination = pszFileTmp;
    pRequest->pszUserAgent = pTdnf->pConf->pszUserAgentHeader;
    pRequest->pszProxy = pTdnf->pConf->pszProxy;
    pRequest->pszProxyUserPwd = pTdnf->pConf->pszProxyUserPass;
    pRequest->pszUserName = pRepo->pszUser;
    pRequest->pszPassword = pRepo->pszPass;
    pRequest->pszSSLCaCert = pRepo->pszSSLCaCert;
    pRequest->pszSSLClientCert = pRepo->pszSSLClientCert;
    pRequest->pszSSLClientKey = pRepo->pszSSLClientKey;
    pRequest->nSSLVerify = pRepo->nSSLVerify ? 1 : 0;
    pRequest->nConnectTimeout = (long)pTdnf->pConf->nConnectTimeout;
    pRequest->nTimeout = (long)pRepo->nTimeout;
    pRequest->nLowSpeedLimit = (long)pRepo->nMinrate;
    pRequest->nLowSpeedTime = (long)pRepo->nTimeout;
    pRequest->nMaxRecvSpeed = (long)pRepo->nThrottle;

    *pnNoOutput = 1;
    if (!pTdnf->pArgs->nQuiet && pszProgressData != NULL)
    {
        if (isatty(STDOUT_FILENO) || pTdnf->pArgs->nVerbose)
        {
            dwError = set_progress_cb_data(pszProgressData, &pProgressData);
            BAIL_ON_TDNF_ERROR(dwError);

            pRequest->pfnProgress = progress_cb;
            pRequest->pProgressData = pProgressData;
            *pnNoOutput = 0;
        }
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}


uint32_t
TDNFDownloadFileFromRepo(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char *pszLocation,
    const char *pszFile,
    const char *pszProgressData
)
{
    uint32_t dwError = 0;
    char *pszUrl = NULL;

    if(!pTdnf ||
       !pTdnf->pArgs || !pRepo ||
       IsNullOrEmptyString(pszLocation) ||
       IsNullOrEmptyString(pszFile))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (pRepo->ppszBaseUrls && pRepo->ppszBaseUrls[0] &&
        strstr(pszLocation, "://") == NULL) {
        /* Try one base URL after the other until we succeed */
        /* Note: this can be improved:
         * 1) we could start with the last good URL next time instead of
         *    starting with 0 each time
         * 2) we could store a list of known bad/good URLs
         */
        for (int i = 0; pRepo->ppszBaseUrls[i]; i++) {
            dwError = TDNFJoinPath(&pszUrl, pRepo->ppszBaseUrls[i], pszLocation, NULL);
            BAIL_ON_TDNF_ERROR(dwError);

            dwError = TDNFDownloadFile(pTdnf, pRepo, pszUrl, pszFile, pszProgressData);
            if (dwError == 0) {
                break;
            }
            if (pRepo->ppszBaseUrls[i + 1]) {
                pr_err("Warning: failed to download %s, trying next base URL\n", pszUrl);
            }
            TDNF_SAFE_FREE_MEMORY(pszUrl);
        }
    } else {
        /* pszLocation is already an absolute URL (xml:base was absolute), or
           there is no base URL (command line packages): use it directly. */
        dwError = TDNFDownloadFile(pTdnf, pRepo, pszLocation, pszFile, pszProgressData);
    }
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszUrl);
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFDownloadFile(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char *pszFileUrl,
    const char *pszFile,
    const char *pszProgressData
    )
{
    uint32_t dwError = 0;
    char *pszFileTmp = NULL;
    long lStatus = 0;
    int i;
    int nNoOutput = 1;
    TDNF_ZIG_DOWNLOAD_REQUEST request = {0};

    /* TDNFFetchRemoteGPGKey sends pszProgressData as NULL */
    if(!pTdnf ||
       !pRepo ||
       IsNullOrEmptyString(pszFileUrl) ||
       IsNullOrEmptyString(pszFile))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateStringPrintf(&pszFileTmp,
                                       "%s.tmp",
                                       pszFile);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFPrepareZigDownloadRequest(
                  pTdnf,
                  pRepo,
                  pszFileUrl,
                  pszFileTmp,
                  pszProgressData,
                  &request,
                  &nNoOutput);
    BAIL_ON_TDNF_ERROR(dwError);

    for(i = 0; i <= pRepo->nRetries; i++)
    {
        if (i > 0)
        {
            pr_info("retrying %d/%d\n", i, pRepo->nRetries);
        }

        lStatus = 0;
        dwError = TDNFZigDownloadFile(&request, &lStatus);
        if (dwError == 0)
        {
            break;
        }

        if (lStatus >= 400)
        {
            pr_err(
                    "Error: %ld when downloading %s. Please check repo url "
                    "or refresh metadata with 'tdnf makecache'.\n",
                    lStatus,
                    pszFileUrl);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if (i == pRepo->nRetries || TDNFZigDownloadErrorIsFatal(dwError, lStatus))
        {
            pr_err("Error: failed to download %s: %s\n",
                   pszFileUrl,
                   TDNFZigDownloadLastError());
            BAIL_ON_TDNF_ERROR(dwError);
        }

        unlink(pszFileTmp);
    }

    /* finish progress line output,
       but only if progress was enabled */
    if (!nNoOutput)
    {
        pr_info("\n");
    }

    if(lStatus >= 400)
    {
        pr_err(
                "Error: %ld when downloading %s. Please check repo url "
                "or refresh metadata with 'tdnf makecache'.\n",
                lStatus,
                pszFileUrl);
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    else
    {
        if (rename(pszFileTmp, pszFile) == -1)
        {
            dwError = errno;
            BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
        }
        if (chmod(pszFile, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) == -1)
        {
            dwError = errno;
            BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
        }
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszFileTmp);
    return dwError;

error:
    if(!IsNullOrEmptyString(pszFileTmp))
    {
        unlink(pszFileTmp);
    }

    goto cleanup;
}

uint32_t
TDNFCreatePackageUrl(
    PTDNF_REPO_DATA pRepo,
    const char* pszPackageLocation,
    char **ppszPackageUrl
    )
{
    uint32_t dwError = 0;
    char *pszPackageUrl = NULL;

    if(!pRepo ||
       IsNullOrEmptyString(pszPackageLocation) ||
       !ppszPackageUrl)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (pRepo->ppszBaseUrls && pRepo->ppszBaseUrls[0] &&
        strstr(pszPackageLocation, "://") == NULL) {
        dwError = TDNFJoinPath(&pszPackageUrl, pRepo->ppszBaseUrls[0], pszPackageLocation, NULL);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    else
    {
        /* pszPackageLocation is already an absolute URL (xml:base was absolute),
           or there is no base URL: use it as-is. */
        dwError = TDNFAllocateString(pszPackageLocation, &pszPackageUrl);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    *ppszPackageUrl = pszPackageUrl;

cleanup:
    return dwError;
error:
    TDNF_SAFE_FREE_MEMORY(pszPackageUrl);
    goto cleanup;
}

uint32_t
TDNFDownloadPackage(
    PTDNF pTdnf,
    const char* pszPackageLocation,
    const char* pszPkgName,
    PTDNF_REPO_DATA pRepo,
    const char* pszRpmCacheDir
    )
{
    uint32_t dwError = 0;
    char *pszPackageFile = NULL;
    char *pszCopyOfPackageLocation = NULL;
    int nSize = 0;

    if(!pTdnf ||
       !pTdnf->pArgs ||
       IsNullOrEmptyString(pszPackageLocation) ||
       IsNullOrEmptyString(pszPkgName) ||
       !pRepo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateString(pszPackageLocation,
                                 &pszCopyOfPackageLocation);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFJoinPath(&pszPackageFile,
                           pszRpmCacheDir,
                           basename(pszCopyOfPackageLocation),
                           NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    /* don't download if file is already there. Older versions may have left
       size 0 files, so check for those too */
    dwError = TDNFGetFileSize(pszPackageFile, &nSize);
    if ((dwError == ERROR_TDNF_FILE_NOT_FOUND) || (nSize == 0))
    {
        dwError = TDNFDownloadFileFromRepo(pTdnf,
                                   pRepo,
                                   pszPackageLocation,
                                   pszPackageFile,
                                   pszPkgName);
    }
    else if(dwError == 0)
    {
        pr_info("%s package already downloaded\n", pszPkgName);
    }
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszCopyOfPackageLocation);
    TDNF_SAFE_FREE_MEMORY(pszPackageFile);
    return dwError;

error:
    goto cleanup;
}

uint32_t
TDNFDownloadPackageToCache(
    PTDNF pTdnf,
    const char* pszPackageLocation,
    const char* pszPkgName,
    PTDNF_REPO_DATA pRepo,
    char** ppszFilePath
    )
{
    uint32_t dwError = 0;
    char* pszRpmCacheDir = NULL;
    char* pszNormalRpmCacheDir = NULL;

    if(!pTdnf ||
       IsNullOrEmptyString(pszPackageLocation) ||
       IsNullOrEmptyString(pszPkgName) ||
       !pRepo ||
       !ppszFilePath)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFJoinPath(&pszRpmCacheDir,
                           pTdnf->pConf->pszCacheDir,
                           pRepo->pszId,
                           "rpms",
                           NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFNormalizePath(pszRpmCacheDir,
                                &pszNormalRpmCacheDir);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFDownloadPackageToTree(pTdnf,
                                        pszPackageLocation,
                                        pszPkgName,
                                        pRepo,
                                        pszNormalRpmCacheDir,
                                        ppszFilePath);
    BAIL_ON_TDNF_ERROR(dwError);
cleanup:
    TDNF_SAFE_FREE_MEMORY(pszNormalRpmCacheDir);
    TDNF_SAFE_FREE_MEMORY(pszRpmCacheDir);
    return dwError;
error:
    goto cleanup;
}

/*
 * TDNFDownloadPackageToTree()
 *
 * Download a package while preserving the directory path. For example,
 * if pszPackageLocation is "RPMS/x86_64/foo-1.2-3.rpm", the destination will
 * be downloaded under the destination directory in RPMS/x86_64/foo-1.2-3.rpm
 * (so 'RPMS/x86_64/' will be preserved).
*/

uint32_t
TDNFDownloadPackageToTree(
    PTDNF pTdnf,
    const char* pszPackageLocation,
    const char* pszPkgName,
    PTDNF_REPO_DATA pRepo,
    char* pszNormalRpmCacheDir,
    char** ppszFilePath
    )
{
    uint32_t dwError = 0;
    char* pszFilePath = NULL;
    char* pszNormalPath = NULL;
    char* pszDownloadCacheDir = NULL;
    char* pszRemotePath = NULL;

    if(!pTdnf ||
       IsNullOrEmptyString(pszPackageLocation) ||
       IsNullOrEmptyString(pszPkgName) ||
       !pRepo ||
       IsNullOrEmptyString(pszNormalRpmCacheDir) ||
       !ppszFilePath)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFPathFromUri(pszPackageLocation, &pszRemotePath);
    if (dwError == ERROR_TDNF_URL_INVALID)
    {
        dwError = TDNFAllocateString(pszPackageLocation, &pszRemotePath);
    }
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFJoinPath(&pszFilePath, pszNormalRpmCacheDir, pszRemotePath, NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFNormalizePath(
                  pszFilePath,
                  &pszNormalPath);
    BAIL_ON_TDNF_ERROR(dwError);

    if (strncmp(pszNormalRpmCacheDir, pszNormalPath,
                strlen(pszNormalRpmCacheDir)))
    {
        dwError = ERROR_TDNF_URL_INVALID;
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

    if(access(pszNormalPath, F_OK))
    {
        if(errno != ENOENT)
        {
            dwError = errno;
            BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
        }
        dwError = TDNFDownloadPackage(pTdnf, pszPackageLocation, pszPkgName,
            pRepo, pszDownloadCacheDir);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *ppszFilePath = pszNormalPath;
cleanup:
    TDNF_SAFE_FREE_MEMORY(pszFilePath);
    TDNF_SAFE_FREE_MEMORY(pszDownloadCacheDir);
    TDNF_SAFE_FREE_MEMORY(pszRemotePath);
    return dwError;

error:
    TDNF_SAFE_FREE_MEMORY(pszNormalPath);
    goto cleanup;

}

/*
 * TDNFDownloadPackageToDirectory()
 *
 * Download a package withou preserving the directory path. For example,
 * if pszPackageLocation is "RPMS/x86_64/foo-1.2-3.rpm", the destination will
 * be downloaded under the destination directory (pszDirectory) as foo-1.2-3.rpm
 * (so RPMS/x86_64/ will be stripped).
*/

uint32_t
TDNFDownloadPackageToDirectory(
    PTDNF pTdnf,
    const char* pszPackageLocation,
    const char* pszPkgName,
    PTDNF_REPO_DATA pRepo,
    const char* pszDirectory,
    char** ppszFilePath
    )
{
    uint32_t dwError = 0;
    char* pszFilePath = NULL;
    char* pszRemotePath = NULL;
    char* pszFileName = NULL;

    if(!pTdnf ||
       IsNullOrEmptyString(pszPackageLocation) ||
       IsNullOrEmptyString(pszPkgName) ||
       !pRepo ||
       IsNullOrEmptyString(pszDirectory) ||
       !ppszFilePath)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFPathFromUri(pszPackageLocation, &pszRemotePath);
    if (dwError == ERROR_TDNF_URL_INVALID)
    {
        dwError = TDNFAllocateString(pszPackageLocation, &pszRemotePath);
    }
    BAIL_ON_TDNF_ERROR(dwError);

    pszFileName = basename(pszRemotePath);

    dwError = TDNFJoinPath(&pszFilePath, pszDirectory, pszFileName, NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFDownloadPackage(pTdnf, pszPackageLocation, pszPkgName,
                                  pRepo, pszDirectory);
    BAIL_ON_TDNF_ERROR(dwError);

    *ppszFilePath = pszFilePath;
cleanup:
    TDNF_SAFE_FREE_MEMORY(pszRemotePath);
    return dwError;

error:
    TDNF_SAFE_FREE_MEMORY(pszFilePath);
    goto cleanup;
}
