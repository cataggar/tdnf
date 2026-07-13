#define _GNU_SOURCE 1
#include "includes.h"

#ifdef TDNF_NATIVE_QUERY_CROSSCHECK

static uint32_t
QueryCrosscheckBuildRepoInputs(
    PTDNF pTdnf,
    PTDNF_REPOMD_NATIVE_REPO_INPUT *ppRepos,
    uint32_t *pdwRepoCount
    );

static void
QueryCrosscheckFreeRepoInputs(
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos,
    uint32_t dwRepoCount
    );

static const char*
QueryCrosscheckInstallRoot(
    PTDNF pTdnf
    );

static void
QueryCrosscheckLog(
    const char *pszPrefix,
    const char *pszFormat,
    ...
    );

static uint32_t
QueryCrosscheckCompareLineArrays(
    const char *pszPrefix,
    char **ppszLegacy,
    uint32_t dwLegacyCount,
    char **ppszNative,
    uint32_t dwNativeCount
    );

static uint32_t
QueryCrosscheckSerializeListResults(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    int nDetail,
    char ***pppszLines
    );

static uint32_t
QueryCrosscheckSerializeSearchResults(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    char ***pppszLines
    );

static uint32_t
QueryCrosscheckSerializeProvidesResults(
    PTDNF_PKG_INFO pPkgInfos,
    char ***pppszLines,
    uint32_t *pdwCount
    );

static uint32_t
QueryCrosscheckSerializeRepoQueryResults(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    PTDNF_REPOQUERY_ARGS pRepoqueryArgs,
    char ***pppszLines
    );

static uint32_t
QueryCrosscheckSerializeUpdateAdvisories(
    PTDNF pTdnf,
    PSolvPackageList pPkgList,
    char ***pppszIds,
    uint32_t *pdwCount
    );

static uint32_t
QueryCrosscheckAppendPkgInfoLine(
    FILE *pMem,
    PTDNF_PKG_INFO pPkgInfo,
    PTDNF_REPOQUERY_ARGS pRepoqueryArgs,
    int nDetail,
    int nSearch,
    int nProvides
    );

static uint32_t
QueryCrosscheckAppendDependencies(
    FILE *pMem,
    PTDNF_PKG_INFO pPkgInfo,
    unsigned int depKeySet
    );

static uint32_t
QueryCrosscheckAppendStringArray(
    FILE *pMem,
    char **ppszValues
    );

static uint32_t
QueryCrosscheckAppendChangeLogs(
    FILE *pMem,
    PTDNF_PKG_CHANGELOG_ENTRY pEntries
    );

static uint32_t
QueryCrosscheckCompactUserInstalled(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t *pdwCount,
    struct history_ctx *pHistoryCtx
    );

static uint32_t
QueryCrosscheckApplyLocationUrls(
    PTDNF pTdnf,
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount
    );

static uint32_t
QueryCrosscheckMapSearchError(
    uint32_t dwError
    );

static uint32_t
QueryCrosscheckMapProvidesError(
    uint32_t dwError
    );

static uint32_t
QueryCrosscheckMapRepoQueryError(
    uint32_t dwError
    );

static uint32_t
QueryCrosscheckSerializeResultsCommon(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    PTDNF_REPOQUERY_ARGS pRepoqueryArgs,
    int nDetail,
    int nSearch,
    int nProvides,
    char ***pppszLines
    );

void
TDNFQueryCrosscheckList(
    PTDNF pTdnf,
    TDNF_SCOPE nScope,
    char **ppszPackageNameSpecs,
    TDNF_PKG_DETAIL nDetail,
    uint32_t dwLibError,
    PTDNF_PKG_INFO pLibPkgInfos,
    uint32_t dwLibCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwNativeError = 0;
    uint32_t dwRepoCount = 0;
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos = NULL;
    PTDNF_PKG_INFO pNativePkgInfos = NULL;
    uint32_t dwNativeCount = 0;
    char **ppszLegacy = NULL;
    char **ppszNative = NULL;

    if(!pTdnf)
    {
        goto cleanup;
    }

    dwError = QueryCrosscheckBuildRepoInputs(pTdnf, &pRepos, &dwRepoCount);
    if(dwError)
    {
        QueryCrosscheckLog("list", "failed to build repo inputs (%u)\n", dwError);
        goto cleanup;
    }

    dwNativeError = TDNFRepoMdNativeList(
                        pRepos,
                        dwRepoCount,
                        QueryCrosscheckInstallRoot(pTdnf),
                        nScope,
                        ppszPackageNameSpecs,
                        nDetail,
                        &pNativePkgInfos,
                        &dwNativeCount);

    if(dwNativeError != dwLibError)
    {
        QueryCrosscheckLog(
            "list",
            "error mismatch legacy=%u native=%u native_last_error=%s\n",
            dwLibError,
            dwNativeError,
            TDNFRepoMdNativeQueryLastError());
        goto cleanup;
    }
    if(dwLibError)
    {
        QueryCrosscheckLog("list", "compared error result %u\n", dwLibError);
        goto cleanup;
    }

    dwError = QueryCrosscheckSerializeListResults(
                  pLibPkgInfos,
                  dwLibCount,
                  nDetail,
                  &ppszLegacy);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = QueryCrosscheckSerializeListResults(
                  pNativePkgInfos,
                  dwNativeCount,
                  nDetail,
                  &ppszNative);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = QueryCrosscheckCompareLineArrays(
                  "list",
                  ppszLegacy,
                  dwLibCount,
                  ppszNative,
                  dwNativeCount);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNFFreeStringArray(ppszLegacy);
    TDNFFreeStringArray(ppszNative);
    TDNFFreePackageInfoArray(pNativePkgInfos, dwNativeCount);
    QueryCrosscheckFreeRepoInputs(pRepos, dwRepoCount);
    return;
error:
    QueryCrosscheckLog("list", "serialization failure (%u)\n", dwError);
    goto cleanup;
}

void
TDNFQueryCrosscheckSearch(
    PTDNF pTdnf,
    char **ppszSearchStrings,
    int nStartIndex,
    int nEndIndex,
    uint32_t dwLibError,
    PTDNF_PKG_INFO pLibPkgInfos,
    uint32_t dwLibCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwNativeError = 0;
    uint32_t dwRepoCount = 0;
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos = NULL;
    PTDNF_PKG_INFO pNativePkgInfos = NULL;
    uint32_t dwNativeCount = 0;
    char **ppszLegacy = NULL;
    char **ppszNative = NULL;

    if(!pTdnf)
    {
        goto cleanup;
    }

    dwError = QueryCrosscheckBuildRepoInputs(pTdnf, &pRepos, &dwRepoCount);
    if(dwError)
    {
        QueryCrosscheckLog("search", "failed to build repo inputs (%u)\n", dwError);
        goto cleanup;
    }

    dwNativeError = TDNFRepoMdNativeSearch(
                        pRepos,
                        dwRepoCount,
                        QueryCrosscheckInstallRoot(pTdnf),
                        ppszSearchStrings,
                        nStartIndex,
                        nEndIndex,
                        &pNativePkgInfos,
                        &dwNativeCount);
    dwNativeError = QueryCrosscheckMapSearchError(dwNativeError);

    if(dwNativeError != dwLibError)
    {
        QueryCrosscheckLog(
            "search",
            "error mismatch legacy=%u native=%u native_last_error=%s\n",
            dwLibError,
            dwNativeError,
            TDNFRepoMdNativeQueryLastError());
        goto cleanup;
    }
    if(dwLibError)
    {
        QueryCrosscheckLog("search", "compared error result %u\n", dwLibError);
        goto cleanup;
    }

    dwError = QueryCrosscheckSerializeSearchResults(pLibPkgInfos, dwLibCount, &ppszLegacy);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = QueryCrosscheckSerializeSearchResults(pNativePkgInfos, dwNativeCount, &ppszNative);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = QueryCrosscheckCompareLineArrays("search", ppszLegacy, dwLibCount, ppszNative, dwNativeCount);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNFFreeStringArray(ppszLegacy);
    TDNFFreeStringArray(ppszNative);
    TDNFFreePackageInfoArray(pNativePkgInfos, dwNativeCount);
    QueryCrosscheckFreeRepoInputs(pRepos, dwRepoCount);
    return;
error:
    QueryCrosscheckLog("search", "serialization failure (%u)\n", dwError);
    goto cleanup;
}

void
TDNFQueryCrosscheckProvides(
    PTDNF pTdnf,
    const char *pszSpec,
    uint32_t dwLibError,
    PTDNF_PKG_INFO pLibPkgInfos
    )
{
    uint32_t dwError = 0;
    uint32_t dwNativeError = 0;
    uint32_t dwRepoCount = 0;
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos = NULL;
    PTDNF_PKG_INFO pNativePkgInfos = NULL;
    char **ppszLegacy = NULL;
    char **ppszNative = NULL;
    uint32_t dwLegacyCount = 0;
    uint32_t dwNativeCount = 0;

    if(!pTdnf || IsNullOrEmptyString(pszSpec))
    {
        goto cleanup;
    }

    dwError = QueryCrosscheckBuildRepoInputs(pTdnf, &pRepos, &dwRepoCount);
    if(dwError)
    {
        QueryCrosscheckLog("provides", "failed to build repo inputs (%u)\n", dwError);
        goto cleanup;
    }

    dwNativeError = TDNFRepoMdNativeProvides(
                        pRepos,
                        dwRepoCount,
                        QueryCrosscheckInstallRoot(pTdnf),
                        pszSpec,
                        &pNativePkgInfos);
    dwNativeError = QueryCrosscheckMapProvidesError(dwNativeError);

    if(dwNativeError != dwLibError)
    {
        QueryCrosscheckLog(
            "provides",
            "error mismatch legacy=%u native=%u native_last_error=%s\n",
            dwLibError,
            dwNativeError,
            TDNFRepoMdNativeQueryLastError());
        goto cleanup;
    }
    if(dwLibError)
    {
        QueryCrosscheckLog("provides", "compared error result %u for '%s'\n", dwLibError, pszSpec);
        goto cleanup;
    }

    dwError = QueryCrosscheckSerializeProvidesResults(
                  pLibPkgInfos,
                  &ppszLegacy,
                  &dwLegacyCount);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = QueryCrosscheckSerializeProvidesResults(
                  pNativePkgInfos,
                  &ppszNative,
                  &dwNativeCount);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = QueryCrosscheckCompareLineArrays(
                  "provides",
                  ppszLegacy,
                  dwLegacyCount,
                  ppszNative,
                  dwNativeCount);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNFFreeStringArray(ppszLegacy);
    TDNFFreeStringArray(ppszNative);
    TDNFFreePackageInfo(pNativePkgInfos);
    QueryCrosscheckFreeRepoInputs(pRepos, dwRepoCount);
    return;
error:
    QueryCrosscheckLog("provides", "serialization failure (%u)\n", dwError);
    goto cleanup;
}

void
TDNFQueryCrosscheckRepoQuery(
    PTDNF pTdnf,
    PTDNF_REPOQUERY_ARGS pRepoqueryArgs,
    uint32_t dwLibError,
    PTDNF_PKG_INFO pLibPkgInfos,
    uint32_t dwLibCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwNativeError = 0;
    uint32_t dwRepoCount = 0;
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos = NULL;
    PTDNF_PKG_INFO pNativePkgInfos = NULL;
    uint32_t dwNativeCount = 0;
    char **ppszLegacy = NULL;
    char **ppszNative = NULL;
    struct history_ctx *pHistoryCtx = NULL;

    if(!pTdnf || !pRepoqueryArgs)
    {
        goto cleanup;
    }

    dwError = QueryCrosscheckBuildRepoInputs(pTdnf, &pRepos, &dwRepoCount);
    if(dwError)
    {
        QueryCrosscheckLog("repoquery", "failed to build repo inputs (%u)\n", dwError);
        goto cleanup;
    }

    dwNativeError = TDNFRepoMdNativeRepoQuery(
                        pRepos,
                        dwRepoCount,
                        QueryCrosscheckInstallRoot(pTdnf),
                        pRepoqueryArgs,
                        &pNativePkgInfos,
                        &dwNativeCount);
    dwNativeError = QueryCrosscheckMapRepoQueryError(dwNativeError);

    if(!dwNativeError && pRepoqueryArgs->nUserInstalled)
    {
        dwError = TDNFGetHistoryCtx(pTdnf, &pHistoryCtx, 0);
        if(dwError)
        {
            QueryCrosscheckLog("repoquery", "failed to open history context (%u)\n", dwError);
            goto cleanup;
        }

        dwError = QueryCrosscheckCompactUserInstalled(pNativePkgInfos, &dwNativeCount, pHistoryCtx);
        if(dwError)
        {
            QueryCrosscheckLog("repoquery", "failed to filter userinstalled packages (%u)\n", dwError);
            goto cleanup;
        }
        if(!dwNativeCount)
        {
            dwNativeError = ERROR_TDNF_NO_DATA;
        }
    }

    if(!dwNativeError && pRepoqueryArgs->nLocation)
    {
        dwError = QueryCrosscheckApplyLocationUrls(pTdnf, pNativePkgInfos, dwNativeCount);
        if(dwError)
        {
            QueryCrosscheckLog("repoquery", "failed to apply location urls (%u)\n", dwError);
            goto cleanup;
        }
    }

    if(dwNativeError != dwLibError)
    {
        QueryCrosscheckLog(
            "repoquery",
            "error mismatch legacy=%u native=%u native_last_error=%s\n",
            dwLibError,
            dwNativeError,
            TDNFRepoMdNativeQueryLastError());
        goto cleanup;
    }
    if(dwLibError)
    {
        QueryCrosscheckLog("repoquery", "compared error result %u\n", dwLibError);
        goto cleanup;
    }

    dwError = QueryCrosscheckSerializeRepoQueryResults(
                  pLibPkgInfos,
                  dwLibCount,
                  pRepoqueryArgs,
                  &ppszLegacy);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = QueryCrosscheckSerializeRepoQueryResults(
                  pNativePkgInfos,
                  dwNativeCount,
                  pRepoqueryArgs,
                  &ppszNative);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = QueryCrosscheckCompareLineArrays(
                  "repoquery",
                  ppszLegacy,
                  dwLibCount,
                  ppszNative,
                  dwNativeCount);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    if (pHistoryCtx)
    {
        destroy_history_ctx(pHistoryCtx);
    }
    TDNFFreeStringArray(ppszLegacy);
    TDNFFreeStringArray(ppszNative);
    TDNFFreePackageInfoArray(pNativePkgInfos, dwNativeCount);
    QueryCrosscheckFreeRepoInputs(pRepos, dwRepoCount);
    return;
error:
    QueryCrosscheckLog("repoquery", "serialization failure (%u)\n", dwError);
    goto cleanup;
}

void
TDNFQueryCrosscheckUpdateAdvisories(
    PTDNF pTdnf,
    Id dwPkgId,
    PSolvPackageList pPkgList
    )
{
    uint32_t dwError = 0;
    uint32_t dwNativeError = 0;
    uint32_t dwRepoCount = 0;
    uint32_t dwEpoch = 0;
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos = NULL;
    char *pszName = NULL;
    char *pszVersion = NULL;
    char *pszRelease = NULL;
    char *pszArch = NULL;
    char *pszEvr = NULL;
    char **ppszLegacy = NULL;
    char **ppszNative = NULL;
    uint32_t dwLegacyCount = 0;
    uint32_t dwNativeCount = 0;

    if(!pTdnf || !pTdnf->pSack)
    {
        goto cleanup;
    }

    dwError = QueryCrosscheckBuildRepoInputs(pTdnf, &pRepos, &dwRepoCount);
    if(dwError)
    {
        QueryCrosscheckLog("updateinfo", "failed to build repo inputs (%u)\n", dwError);
        goto cleanup;
    }

    dwError = SolvGetNevraFromId(
                    pTdnf->pSack,
                    dwPkgId,
                    &dwEpoch,
                    &pszName,
                    &pszVersion,
                    &pszRelease,
                    &pszArch,
                    &pszEvr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = QueryCrosscheckSerializeUpdateAdvisories(
                  pTdnf,
                  pPkgList,
                  &ppszLegacy,
                  &dwLegacyCount);
    BAIL_ON_TDNF_ERROR(dwError);

    dwNativeError = TDNFRepoMdNativeUpdateAdvisoryIds(
                        pRepos,
                        dwRepoCount,
                        pszName,
                        pszArch,
                        pszEvr,
                        &ppszNative,
                        &dwNativeCount);
    if(dwNativeError == ERROR_TDNF_NO_DATA && dwLegacyCount == 0)
    {
        QueryCrosscheckLog(
            "updateinfo",
            "package '%s.%s' compared 0 advisory ids\n",
            pszName,
            pszArch);
        goto cleanup;
    }
    if(dwNativeError)
    {
        QueryCrosscheckLog(
            "updateinfo",
            "native advisory lookup failed (%u): %s\n",
            dwNativeError,
            TDNFRepoMdNativeQueryLastError());
        goto cleanup;
    }

    dwError = QueryCrosscheckCompareLineArrays(
                  "updateinfo",
                  ppszLegacy,
                  dwLegacyCount,
                  ppszNative,
                  dwNativeCount);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszName);
    TDNF_SAFE_FREE_MEMORY(pszVersion);
    TDNF_SAFE_FREE_MEMORY(pszRelease);
    TDNF_SAFE_FREE_MEMORY(pszArch);
    TDNF_SAFE_FREE_MEMORY(pszEvr);
    TDNFFreeStringArray(ppszLegacy);
    TDNFFreeStringArray(ppszNative);
    QueryCrosscheckFreeRepoInputs(pRepos, dwRepoCount);
    return;
error:
    QueryCrosscheckLog("updateinfo", "serialization failure (%u)\n", dwError);
    goto cleanup;
}

static uint32_t
QueryCrosscheckBuildRepoInputs(
    PTDNF pTdnf,
    PTDNF_REPOMD_NATIVE_REPO_INPUT *ppRepos,
    uint32_t *pdwRepoCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos = NULL;
    PTDNF_REPO_DATA pRepoData = NULL;

    if(!pTdnf || !ppRepos || !pdwRepoCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pRepoData = pTdnf->pRepos;
    while(pRepoData)
    {
        if(pRepoData->nEnabled && pRepoData->nHasMetaData)
        {
            if(!IsNullOrEmptyString(pRepoData->pszId))
            {
                dwCount++;
            }
        }
        pRepoData = pRepoData->pNext;
    }

    if(!dwCount)
    {
        goto cleanup;
    }

    dwError = TDNFAllocateMemory(
                  dwCount,
                  sizeof(TDNF_REPOMD_NATIVE_REPO_INPUT),
                  (void **)&pRepos);
    BAIL_ON_TDNF_ERROR(dwError);

    pRepoData = pTdnf->pRepos;
    dwCount = 0;
    while(pRepoData)
    {
        if(pRepoData->nEnabled && pRepoData->nHasMetaData &&
           !IsNullOrEmptyString(pRepoData->pszId))
        {
            dwError = TDNFGetCachePath(
                          pTdnf,
                          pRepoData,
                          NULL,
                          NULL,
                          (char **)&pRepos[dwCount].pszCacheDir);
            BAIL_ON_TDNF_ERROR(dwError);

            pRepos[dwCount].pszId = pRepoData->pszId;
            dwCount++;
        }
        pRepoData = pRepoData->pNext;
    }

    *ppRepos = pRepos;
    *pdwRepoCount = dwCount;

cleanup:
    return dwError;
error:
    QueryCrosscheckFreeRepoInputs(pRepos, dwCount);
    goto cleanup;
}

static void
QueryCrosscheckFreeRepoInputs(
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos,
    uint32_t dwRepoCount
    )
{
    uint32_t dwIndex = 0;

    if(!pRepos)
    {
        return;
    }

    for(dwIndex = 0; dwIndex < dwRepoCount; dwIndex++)
    {
        char *pszCacheDir = (char *)pRepos[dwIndex].pszCacheDir;
        TDNF_SAFE_FREE_MEMORY(pszCacheDir);
        pRepos[dwIndex].pszCacheDir = NULL;
    }
    TDNF_SAFE_FREE_MEMORY(pRepos);
}

static const char*
QueryCrosscheckInstallRoot(
    PTDNF pTdnf
    )
{
    if(!pTdnf || !pTdnf->pArgs || IsNullOrEmptyString(pTdnf->pArgs->pszInstallRoot) ||
       !strcmp(pTdnf->pArgs->pszInstallRoot, "/"))
    {
        return NULL;
    }
    return pTdnf->pArgs->pszInstallRoot;
}

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
static void
QueryCrosscheckLog(
    const char *pszPrefix,
    const char *pszFormat,
    ...
    )
{
    const char *pszLogFile = getenv("TDNF_QUERY_CROSSCHECK_LOGFILE");
    FILE *pLog = NULL;
    va_list vaList;

    if(IsNullOrEmptyString(pszLogFile))
    {
        return;
    }

    pLog = fopen(pszLogFile, "a");
    if(!pLog)
    {
        return;
    }

    fprintf(pLog, "native query crosscheck [%s]: ",
            pszPrefix ? pszPrefix : "unknown");
    va_start(vaList, pszFormat);
    vfprintf(pLog, pszFormat, vaList);
    va_end(vaList);
    fclose(pLog);
}
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static uint32_t
QueryCrosscheckCompareLineArrays(
    const char *pszPrefix,
    char **ppszLegacy,
    uint32_t dwLegacyCount,
    char **ppszNative,
    uint32_t dwNativeCount
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;

    if(dwLegacyCount != dwNativeCount)
    {
        QueryCrosscheckLog(
            pszPrefix,
            "count mismatch legacy=%u native=%u first_legacy='%s' first_native='%s'\n",
            dwLegacyCount,
            dwNativeCount,
            (ppszLegacy && ppszLegacy[0]) ? ppszLegacy[0] : "",
            (ppszNative && ppszNative[0]) ? ppszNative[0] : "");
        goto cleanup;
    }

    for(i = 0; i < dwLegacyCount; i++)
    {
        const char *pszLegacy = (ppszLegacy && ppszLegacy[i]) ? ppszLegacy[i] : "";
        const char *pszNative = (ppszNative && ppszNative[i]) ? ppszNative[i] : "";
        if(strcmp(pszLegacy, pszNative))
        {
            QueryCrosscheckLog(
                pszPrefix,
                "entry %u mismatch legacy='%s' native='%s'\n",
                i,
                pszLegacy,
                pszNative);
            goto cleanup;
        }
    }

    QueryCrosscheckLog(
        pszPrefix,
        "compared %u result line(s) with no mismatches\n",
        dwLegacyCount);

cleanup:
    return dwError;
}

static uint32_t
QueryCrosscheckSerializeListResults(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    int nDetail,
    char ***pppszLines
    )
{
    return QueryCrosscheckSerializeResultsCommon(
               pPkgInfos,
               dwCount,
               NULL,
               nDetail,
               0,
               0,
               pppszLines);
}

static uint32_t
QueryCrosscheckSerializeSearchResults(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    char ***pppszLines
    )
{
    return QueryCrosscheckSerializeResultsCommon(
               pPkgInfos,
               dwCount,
               NULL,
               DETAIL_LIST,
               1,
               0,
               pppszLines);
}

static uint32_t
QueryCrosscheckSerializeProvidesResults(
    PTDNF_PKG_INFO pPkgInfos,
    char ***pppszLines,
    uint32_t *pdwCount
    )
{
    uint32_t dwCount = 0;
    PTDNF_PKG_INFO pPkgInfo = pPkgInfos;

    while(pPkgInfo)
    {
        dwCount++;
        pPkgInfo = pPkgInfo->pNext;
    }

    if(pdwCount)
    {
        *pdwCount = dwCount;
    }

    return QueryCrosscheckSerializeResultsCommon(
               pPkgInfos,
               dwCount,
               NULL,
               DETAIL_LIST,
               0,
               1,
               pppszLines);
}

static uint32_t
QueryCrosscheckSerializeRepoQueryResults(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    PTDNF_REPOQUERY_ARGS pRepoqueryArgs,
    char ***pppszLines
    )
{
    return QueryCrosscheckSerializeResultsCommon(
               pPkgInfos,
               dwCount,
               pRepoqueryArgs,
               pRepoqueryArgs->nChangeLogs ? DETAIL_CHANGELOG :
               pRepoqueryArgs->nSource ? DETAIL_SOURCEPKG :
               pRepoqueryArgs->nLocation ? DETAIL_LOCATION : DETAIL_LIST,
               0,
               0,
               pppszLines);
}

static uint32_t
QueryCrosscheckSerializeResultsCommon(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    PTDNF_REPOQUERY_ARGS pRepoqueryArgs,
    int nDetail,
    int nSearch,
    int nProvides,
    char ***pppszLines
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;
    char **ppszLines = NULL;
    PTDNF_PKG_INFO pPkgInfo = pPkgInfos;

    if(!pppszLines)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(
                  dwCount + 1,
                  sizeof(char *),
                  (void **)&ppszLines);
    BAIL_ON_TDNF_ERROR(dwError);

    if(nProvides)
    {
        for(i = 0; i < dwCount && pPkgInfo; i++, pPkgInfo = pPkgInfo->pNext)
        {
            FILE *pMem = NULL;
            size_t nSize = 0;
            char *pszLine = NULL;

            pMem = open_memstream(&pszLine, &nSize);
            if(!pMem)
            {
                dwError = ERROR_TDNF_OUT_OF_MEMORY;
                BAIL_ON_TDNF_ERROR(dwError);
            }
            dwError = QueryCrosscheckAppendPkgInfoLine(
                          pMem,
                          pPkgInfo,
                          pRepoqueryArgs,
                          nDetail,
                          nSearch,
                          nProvides);
            fclose(pMem);
            pMem = NULL;
            BAIL_ON_TDNF_ERROR(dwError);
            ppszLines[i] = pszLine;
        }
    }
    else
    {
        for(i = 0; i < dwCount; i++)
        {
            FILE *pMem = NULL;
            size_t nSize = 0;
            char *pszLine = NULL;

            pMem = open_memstream(&pszLine, &nSize);
            if(!pMem)
            {
                dwError = ERROR_TDNF_OUT_OF_MEMORY;
                BAIL_ON_TDNF_ERROR(dwError);
            }
            dwError = QueryCrosscheckAppendPkgInfoLine(
                          pMem,
                          &pPkgInfos[i],
                          pRepoqueryArgs,
                          nDetail,
                          nSearch,
                          nProvides);
            fclose(pMem);
            pMem = NULL;
            BAIL_ON_TDNF_ERROR(dwError);
            ppszLines[i] = pszLine;
        }
    }

    *pppszLines = ppszLines;

cleanup:
    return dwError;
error:
    if(ppszLines)
    {
        TDNFFreeStringArray(ppszLines);
    }
    goto cleanup;
}

static uint32_t
QueryCrosscheckAppendPkgInfoLine(
    FILE *pMem,
    PTDNF_PKG_INFO pPkgInfo,
    PTDNF_REPOQUERY_ARGS pRepoqueryArgs,
    int nDetail,
    int nSearch,
    int nProvides
    )
{
    uint32_t dwError = 0;

    if(!pMem || !pPkgInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(nSearch)
    {
        fprintf(pMem, "%s\037%s",
                pPkgInfo->pszName ? pPkgInfo->pszName : "",
                pPkgInfo->pszSummary ? pPkgInfo->pszSummary : "");
        goto cleanup;
    }

    fprintf(pMem,
            "%s\037%s\037%u\037%s\037%s\037%s\037%s",
            pPkgInfo->pszRepoName ? pPkgInfo->pszRepoName : "",
            pPkgInfo->pszName ? pPkgInfo->pszName : "",
            pPkgInfo->dwEpoch,
            pPkgInfo->pszVersion ? pPkgInfo->pszVersion : "",
            pPkgInfo->pszRelease ? pPkgInfo->pszRelease : "",
            pPkgInfo->pszArch ? pPkgInfo->pszArch : "",
            pPkgInfo->pszEVR ? pPkgInfo->pszEVR : "");

    if(nProvides)
    {
        fprintf(pMem,
                "\037%s",
                pPkgInfo->pszSummary ? pPkgInfo->pszSummary : "");
        goto cleanup;
    }

    if(pRepoqueryArgs && pRepoqueryArgs->pszQueryFormat)
    {
        fprintf(pMem,
                "\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s",
                pPkgInfo->pszSummary ? pPkgInfo->pszSummary : "",
                pPkgInfo->pszURL ? pPkgInfo->pszURL : "",
                pPkgInfo->pszLicense ? pPkgInfo->pszLicense : "",
                pPkgInfo->pszDescription ? pPkgInfo->pszDescription : "",
                pPkgInfo->pszFormattedSize ? pPkgInfo->pszFormattedSize : "",
                pPkgInfo->pszFormattedDownloadSize ? pPkgInfo->pszFormattedDownloadSize : "",
                pPkgInfo->pszSourcePkg ? pPkgInfo->pszSourcePkg : "",
                pPkgInfo->pszLocation ? pPkgInfo->pszLocation : "");
    }
    else if(nDetail == DETAIL_INFO)
    {
        fprintf(pMem,
                "\037%s\037%s\037%s\037%s\037%s\037%s",
                pPkgInfo->pszSummary ? pPkgInfo->pszSummary : "",
                pPkgInfo->pszURL ? pPkgInfo->pszURL : "",
                pPkgInfo->pszLicense ? pPkgInfo->pszLicense : "",
                pPkgInfo->pszDescription ? pPkgInfo->pszDescription : "",
                pPkgInfo->pszFormattedSize ? pPkgInfo->pszFormattedSize : "",
                pPkgInfo->pszFormattedDownloadSize ? pPkgInfo->pszFormattedDownloadSize : "");
    }
    else if(nDetail == DETAIL_SOURCEPKG)
    {
        fprintf(pMem,
                "\037%s",
                pPkgInfo->pszSourcePkg ? pPkgInfo->pszSourcePkg : "");
    }
    else if(nDetail == DETAIL_LOCATION)
    {
        fprintf(pMem,
                "\037%s",
                pPkgInfo->pszLocation ? pPkgInfo->pszLocation : "");
    }
    else if(nDetail == DETAIL_CHANGELOG)
    {
        dwError = QueryCrosscheckAppendChangeLogs(pMem, pPkgInfo->pChangeLogEntries);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(pRepoqueryArgs)
    {
        if(pRepoqueryArgs->nList)
        {
            fputc('\037', pMem);
            dwError = QueryCrosscheckAppendStringArray(pMem, pPkgInfo->ppszFileList);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        else if(pRepoqueryArgs->depKeySet)
        {
            fputc('\037', pMem);
            dwError = QueryCrosscheckAppendDependencies(
                          pMem,
                          pPkgInfo,
                          pRepoqueryArgs->depKeySet);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
QueryCrosscheckAppendDependencies(
    FILE *pMem,
    PTDNF_PKG_INFO pPkgInfo,
    unsigned int depKeySet
    )
{
    uint32_t dwError = 0;
    int depKey = 0;
    int nFirst = 1;

    if(!pMem || !pPkgInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(depKey = 0; depKey < REPOQUERY_DEP_KEY_COUNT; depKey++)
    {
        if(!(depKeySet & (1U << depKey)))
        {
            continue;
        }
        if(!nFirst)
        {
            fputc('\036', pMem);
        }
        nFirst = 0;
        fprintf(pMem, "%d=", depKey);
        dwError = QueryCrosscheckAppendStringArray(
                      pMem,
                      pPkgInfo->pppszDependencies ? pPkgInfo->pppszDependencies[depKey] : NULL);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
QueryCrosscheckAppendStringArray(
    FILE *pMem,
    char **ppszValues
    )
{
    int nFirst = 1;

    if(!pMem)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    while(ppszValues && *ppszValues)
    {
        if(!nFirst)
        {
            fputc('\035', pMem);
        }
        nFirst = 0;
        fputs(*ppszValues, pMem);
        ppszValues++;
    }
    return 0;
}

static uint32_t
QueryCrosscheckAppendChangeLogs(
    FILE *pMem,
    PTDNF_PKG_CHANGELOG_ENTRY pEntries
    )
{
    int nFirst = 1;

    if(!pMem)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    while(pEntries)
    {
        if(!nFirst)
        {
            fputc('\036', pMem);
        }
        nFirst = 0;
        fprintf(pMem,
                "%s\035%lld\035%s",
                pEntries->pszAuthor ? pEntries->pszAuthor : "",
                (long long)pEntries->timeTime,
                pEntries->pszText ? pEntries->pszText : "");
        pEntries = pEntries->pNext;
    }
    return 0;
}

static uint32_t
QueryCrosscheckSerializeUpdateAdvisories(
    PTDNF pTdnf,
    PSolvPackageList pPkgList,
    char ***pppszIds,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t i = 0;
    char **ppszIds = NULL;
    Id dwAdvId = 0;

    if(!pTdnf || !pTdnf->pSack || !pppszIds || !pdwCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(!pPkgList)
    {
        goto cleanup;
    }

    dwError = SolvGetPackageListSize(pPkgList, &dwCount);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(
                  dwCount + 1,
                  sizeof(char *),
                  (void **)&ppszIds);
    BAIL_ON_TDNF_ERROR(dwError);

    for(i = 0; i < dwCount; i++)
    {
        const char *pszName = NULL;

        dwError = SolvGetPackageId(pPkgList, i, &dwAdvId);
        BAIL_ON_TDNF_ERROR(dwError);
        pszName = pool_lookup_str(pTdnf->pSack->pPool, dwAdvId, SOLVABLE_NAME);
        if(pszName)
        {
            dwError = TDNFAllocateString(pszName, &ppszIds[i]);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    *pppszIds = ppszIds;
    *pdwCount = dwCount;

cleanup:
    return dwError;
error:
    if(ppszIds)
    {
        TDNFFreeStringArray(ppszIds);
    }
    goto cleanup;
}

static uint32_t
QueryCrosscheckCompactUserInstalled(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t *pdwCount,
    struct history_ctx *pHistoryCtx
    )
{
    uint32_t dwError = 0;
    uint32_t dwRead = 0;
    uint32_t dwWrite = 0;

    if(!pPkgInfos || !pdwCount || !pHistoryCtx)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(dwRead = 0; dwRead < *pdwCount; dwRead++)
    {
        int nValue = 0;
        int rc = history_get_auto_flag(pHistoryCtx, pPkgInfos[dwRead].pszName, &nValue);
        if(rc != 0)
        {
            dwError = ERROR_TDNF_HISTORY_ERROR;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(nValue == 0)
        {
            if(dwWrite != dwRead)
            {
                pPkgInfos[dwWrite] = pPkgInfos[dwRead];
                memset(&pPkgInfos[dwRead], 0, sizeof(pPkgInfos[dwRead]));
            }
            dwWrite++;
        }
        else
        {
            TDNFFreePackageInfoContents(&pPkgInfos[dwRead]);
            memset(&pPkgInfos[dwRead], 0, sizeof(pPkgInfos[dwRead]));
        }
    }

    while(dwWrite < *pdwCount)
    {
        memset(&pPkgInfos[dwWrite], 0, sizeof(pPkgInfos[dwWrite]));
        dwWrite++;
    }

    *pdwCount = dwWrite;

cleanup:
    if(!dwError)
    {
        uint32_t i = 0;
        for(i = 0; i < *pdwCount; i++)
        {
            pPkgInfos[i].pNext = (i + 1 < *pdwCount) ? &pPkgInfos[i + 1] : NULL;
        }
    }
    return dwError;
error:
    goto cleanup;
}

static uint32_t
QueryCrosscheckApplyLocationUrls(
    PTDNF pTdnf,
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;

    if(!pTdnf || !pPkgInfos)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(i = 0; i < dwCount; i++)
    {
        PTDNF_REPO_DATA pRepo = NULL;
        char *pszLocation = NULL;

        if(!pPkgInfos[i].pszRepoName || !strcmp(pPkgInfos[i].pszRepoName, SYSTEM_REPO_NAME) ||
           !pPkgInfos[i].pszLocation)
        {
            continue;
        }

        dwError = TDNFFindRepoById(pTdnf, pPkgInfos[i].pszRepoName, &pRepo);
        BAIL_ON_TDNF_ERROR(dwError);

        pszLocation = pPkgInfos[i].pszLocation;
        dwError = TDNFCreatePackageUrl(pRepo, pszLocation, &pPkgInfos[i].pszLocation);
        BAIL_ON_TDNF_ERROR(dwError);
        TDNF_SAFE_FREE_MEMORY(pszLocation);
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
QueryCrosscheckMapSearchError(
    uint32_t dwError
    )
{
    if(dwError == ERROR_TDNF_NO_MATCH)
    {
        return ERROR_TDNF_NO_SEARCH_RESULTS;
    }
    return dwError;
}

static uint32_t
QueryCrosscheckMapProvidesError(
    uint32_t dwError
    )
{
    if(dwError == ERROR_TDNF_NO_MATCH)
    {
        return ERROR_TDNF_NO_DATA;
    }
    return dwError;
}

static uint32_t
QueryCrosscheckMapRepoQueryError(
    uint32_t dwError
    )
{
    if(dwError == ERROR_TDNF_NO_MATCH)
    {
        return ERROR_TDNF_NO_DATA;
    }
    return dwError;
}

#else

void
TDNFQueryCrosscheckList(
    PTDNF pTdnf,
    TDNF_SCOPE nScope,
    char **ppszPackageNameSpecs,
    TDNF_PKG_DETAIL nDetail,
    uint32_t dwLibError,
    PTDNF_PKG_INFO pLibPkgInfos,
    uint32_t dwLibCount
    )
{
    (void)pTdnf;
    (void)nScope;
    (void)ppszPackageNameSpecs;
    (void)nDetail;
    (void)dwLibError;
    (void)pLibPkgInfos;
    (void)dwLibCount;
}

void
TDNFQueryCrosscheckSearch(
    PTDNF pTdnf,
    char **ppszSearchStrings,
    int nStartIndex,
    int nEndIndex,
    uint32_t dwLibError,
    PTDNF_PKG_INFO pLibPkgInfos,
    uint32_t dwLibCount
    )
{
    (void)pTdnf;
    (void)ppszSearchStrings;
    (void)nStartIndex;
    (void)nEndIndex;
    (void)dwLibError;
    (void)pLibPkgInfos;
    (void)dwLibCount;
}

void
TDNFQueryCrosscheckProvides(
    PTDNF pTdnf,
    const char *pszSpec,
    uint32_t dwLibError,
    PTDNF_PKG_INFO pLibPkgInfos
    )
{
    (void)pTdnf;
    (void)pszSpec;
    (void)dwLibError;
    (void)pLibPkgInfos;
}

void
TDNFQueryCrosscheckRepoQuery(
    PTDNF pTdnf,
    PTDNF_REPOQUERY_ARGS pRepoqueryArgs,
    uint32_t dwLibError,
    PTDNF_PKG_INFO pLibPkgInfos,
    uint32_t dwLibCount
    )
{
    (void)pTdnf;
    (void)pRepoqueryArgs;
    (void)dwLibError;
    (void)pLibPkgInfos;
    (void)dwLibCount;
}

void
TDNFQueryCrosscheckUpdateAdvisories(
    PTDNF pTdnf,
    Id dwPkgId,
    PSolvPackageList pPkgList
    )
{
    (void)pTdnf;
    (void)dwPkgId;
    (void)pPkgList;
}

#endif
