#define _GNU_SOURCE 1
#include "includes.h"

#define NATIVE_QUERY_FIELD_SEP ((char)0x1f)
#define NATIVE_QUERY_GROUP_SEP ((char)0x1e)
#define NATIVE_QUERY_ITEM_SEP  ((char)0x1d)

static uint32_t
NativeQuerySerializePackageIdCommon(
    Pool *pPool,
    Id dwPkgId,
    char **ppszLine
    );

static int
NativeQuerySplitNevra(
    char *pszNevra,
    char **ppszName,
    char **ppszEvr,
    char **ppszArch
    );

static uint32_t
NativeQueryAppendRefMatches(
    PSolvSack pSack,
    const char *pszPackageRef,
    int nInstalledOnly,
    Queue *pQueue,
    uint32_t *pdwMatches
    );

static uint32_t
NativeQueryParseSummaryLine(
    const char *pszLine,
    PTDNF_UPDATEINFO_SUMMARY pSummary
    );

static uint32_t
NativeQueryParseUpdateInfoLine(
    const char *pszLine,
    PTDNF_UPDATEINFO *ppInfo
    );

static uint32_t
NativeQueryParseUpdateInfoPackage(
    const char *pszText,
    PTDNF_UPDATEINFO_PKG *ppPkg
    );

static uint32_t
NativeQueryParseUnsigned(
    const char *pszValue,
    uint32_t *pdwValue
    );

static char*
NativeQuerySplitField(
    char **ppszCursor,
    char chSep
    );

uint32_t
TDNFNativeQueryBuildRepoInputs(
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
        if(pRepoData->nEnabled && pRepoData->nHasMetaData &&
           !IsNullOrEmptyString(pRepoData->pszId))
        {
            dwCount++;
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
            pRepos[dwCount].pszSnapshotFile = pRepoData->pszSnapshotFile;
            dwCount++;
        }
        pRepoData = pRepoData->pNext;
    }

    *ppRepos = pRepos;
    *pdwRepoCount = dwCount;

cleanup:
    return dwError;
error:
    TDNFNativeQueryFreeRepoInputs(pRepos, dwCount);
    goto cleanup;
}

uint32_t
TDNFNativeQueryBuildSingleRepoInput(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepoData,
    TDNF_REPOMD_NATIVE_REPO_INPUT *pRepo
    )
{
    uint32_t dwError = 0;

    if(!pTdnf || !pRepoData || !pRepo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    memset(pRepo, 0, sizeof(*pRepo));

    dwError = TDNFGetCachePath(
                  pTdnf,
                  pRepoData,
                  NULL,
                  NULL,
                  (char **)&pRepo->pszCacheDir);
    BAIL_ON_TDNF_ERROR(dwError);

    pRepo->pszId = pRepoData->pszId;
    pRepo->pszSnapshotFile = pRepoData->pszSnapshotFile;

cleanup:
    return dwError;
error:
    {
        char *pszCacheDir = (char *)pRepo->pszCacheDir;
        TDNF_SAFE_FREE_MEMORY(pszCacheDir);
        pRepo->pszCacheDir = NULL;
    }
    goto cleanup;
}

void
TDNFNativeQueryFreeRepoInputs(
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

const char*
TDNFNativeQueryInstallRoot(
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

uint32_t
TDNFNativeQueryFilterUserInstalled(
    PTDNF pTdnf,
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwRead = 0;
    uint32_t dwWrite = 0;
    struct history_ctx *pHistoryCtx = NULL;

    if(!pTdnf || !pPkgInfos || !pdwCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGetHistoryCtx(pTdnf, &pHistoryCtx, 0);
    BAIL_ON_TDNF_ERROR(dwError);

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

    for(dwRead = 0; dwRead < *pdwCount; dwRead++)
    {
        pPkgInfos[dwRead].pNext = (dwRead + 1 < *pdwCount) ? &pPkgInfos[dwRead + 1] : NULL;
    }

cleanup:
    if(pHistoryCtx)
    {
        destroy_history_ctx(pHistoryCtx);
    }
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFNativeQueryApplyLocationUrls(
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

uint32_t
TDNFNativeQuerySerializePackageId(
    PSolvSack pSack,
    Id dwPkgId,
    char **ppszLine
    )
{
    if(!pSack)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    return NativeQuerySerializePackageIdCommon(pSack->pPool, dwPkgId, ppszLine);
}

uint32_t
TDNFNativeQuerySerializeQueuePackageRefs(
    PSolvSack pSack,
    Queue *pQueue,
    char ***pppszRefs,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t i = 0;
    char **ppszRefs = NULL;

    if(!pSack || !pQueue || !pppszRefs || !pdwCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwCount = (uint32_t)pQueue->count;
    dwError = TDNFAllocateMemory(
                  dwCount + 1,
                  sizeof(char *),
                  (void **)&ppszRefs);
    BAIL_ON_TDNF_ERROR(dwError);

    for(i = 0; i < dwCount; i++)
    {
        dwError = TDNFNativeQuerySerializePackageId(
                      pSack,
                      pQueue->elements[i],
                      &ppszRefs[i]);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *pppszRefs = ppszRefs;
    *pdwCount = dwCount;

cleanup:
    return dwError;
error:
    if(ppszRefs)
    {
        TDNFFreeStringArray(ppszRefs);
    }
    goto cleanup;
}

uint32_t
TDNFNativeQuerySerializePackageListRefs(
    PSolvSack pSack,
    PSolvPackageList pPkgList,
    char ***pppszRefs,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t i = 0;
    char **ppszRefs = NULL;
    Id dwPkgId = 0;

    if(!pSack || !pPkgList || !pppszRefs || !pdwCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = SolvGetPackageListSize(pPkgList, &dwCount);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(
                  dwCount + 1,
                  sizeof(char *),
                  (void **)&ppszRefs);
    BAIL_ON_TDNF_ERROR(dwError);

    for(i = 0; i < dwCount; i++)
    {
        dwError = SolvGetPackageId(pPkgList, i, &dwPkgId);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFNativeQuerySerializePackageId(
                      pSack,
                      dwPkgId,
                      &ppszRefs[i]);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *pppszRefs = ppszRefs;
    *pdwCount = dwCount;

cleanup:
    return dwError;
error:
    if(ppszRefs)
    {
        TDNFFreeStringArray(ppszRefs);
    }
    goto cleanup;
}

uint32_t
TDNFNativeQuerySerializePackageInfoRefs(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    char ***pppszRefs,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;
    char **ppszRefs = NULL;

    if(!pppszRefs || !pdwCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(
                  dwCount + 1,
                  sizeof(char *),
                  (void **)&ppszRefs);
    BAIL_ON_TDNF_ERROR(dwError);

    for(i = 0; i < dwCount; i++)
    {
        char *pszNevra = NULL;
        const char *pszName = pPkgInfos[i].pszName ? pPkgInfos[i].pszName : "";
        const char *pszEvr = pPkgInfos[i].pszEVR ? pPkgInfos[i].pszEVR : "";
        const char *pszArch = pPkgInfos[i].pszArch ? pPkgInfos[i].pszArch : "";

        if(!IsNullOrEmptyString(pszArch))
        {
            dwError = TDNFAllocateStringPrintf(
                          &pszNevra,
                          "%s-%s.%s",
                          pszName,
                          pszEvr,
                          pszArch);
        }
        else
        {
            dwError = TDNFAllocateStringPrintf(
                          &pszNevra,
                          "%s-%s",
                          pszName,
                          pszEvr);
        }
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFAllocateStringPrintf(
                      &ppszRefs[i],
                      "%s%c%s",
                      pPkgInfos[i].pszRepoName ? pPkgInfos[i].pszRepoName : "",
                      NATIVE_QUERY_FIELD_SEP,
                      pszNevra);
        TDNF_SAFE_FREE_MEMORY(pszNevra);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *pppszRefs = ppszRefs;
    *pdwCount = dwCount;

cleanup:
    return dwError;
error:
    if(ppszRefs)
    {
        TDNFFreeStringArray(ppszRefs);
    }
    goto cleanup;
}

uint32_t
TDNFNativeQuerySerializeAutoInstalledRefs(
    PTDNF pTdnf,
    struct history_ctx *pHistoryCtx,
    char ***pppszRefs,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    char **ppszRefs = NULL;
    Pool *pPool = NULL;
    Id p = 0;
    Solvable *s = NULL;

    if(!pTdnf || !pTdnf->pSack || !pHistoryCtx || !pppszRefs || !pdwCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pPool = pTdnf->pSack->pPool;

    FOR_REPO_SOLVABLES(pPool->installed, p, s)
    {
        const char *pszName = pool_id2str(pPool, s->name);
        int nIsAuto = 0;
        int rc = history_get_auto_flag(pHistoryCtx, pszName, &nIsAuto);

        if(rc != 0)
        {
            dwError = ERROR_TDNF_HISTORY_ERROR;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(nIsAuto)
        {
            dwCount++;
        }
    }

    dwError = TDNFAllocateMemory(
                  dwCount + 1,
                  sizeof(char *),
                  (void **)&ppszRefs);
    BAIL_ON_TDNF_ERROR(dwError);

    FOR_REPO_SOLVABLES(pPool->installed, p, s)
    {
        const char *pszName = pool_id2str(pPool, s->name);
        int nIsAuto = 0;
        int rc = history_get_auto_flag(pHistoryCtx, pszName, &nIsAuto);

        if(rc != 0)
        {
            dwError = ERROR_TDNF_HISTORY_ERROR;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(!nIsAuto)
        {
            continue;
        }

        dwError = NativeQuerySerializePackageIdCommon(
                      pPool,
                      p,
                      &ppszRefs[dwIndex++]);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *pppszRefs = ppszRefs;
    *pdwCount = dwCount;

cleanup:
    return dwError;
error:
    if(ppszRefs)
    {
        TDNFFreeStringArray(ppszRefs);
    }
    goto cleanup;
}

uint32_t
TDNFNativeQueryResolvePackageRefArrayToQueue(
    PSolvSack pSack,
    char **ppszPackageRefs,
    uint32_t dwCount,
    int nInstalledOnly,
    Queue *pQueue
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;

    if(!pSack || !ppszPackageRefs || !pQueue)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(i = 0; i < dwCount; i++)
    {
        uint32_t dwMatches = 0;

        if(IsNullOrEmptyString(ppszPackageRefs[i]))
        {
            continue;
        }

        dwError = NativeQueryAppendRefMatches(
                      pSack,
                      ppszPackageRefs[i],
                      nInstalledOnly,
                      pQueue,
                      &dwMatches);
        BAIL_ON_TDNF_ERROR(dwError);

        if(dwMatches == 0)
        {
            dwError = ERROR_TDNF_NO_DATA;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFNativeQueryResolveSinglePackageRef(
    PSolvSack pSack,
    const char *pszPackageRef,
    int nInstalledOnly,
    Id *pdwPkgId
    )
{
    uint32_t dwError = 0;
    Queue queueMatches = {0};

    if(!pSack || IsNullOrEmptyString(pszPackageRef) || !pdwPkgId)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    queue_init(&queueMatches);

    dwError = NativeQueryAppendRefMatches(
                  pSack,
                  pszPackageRef,
                  nInstalledOnly,
                  &queueMatches,
                  NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    if(queueMatches.count == 0)
    {
        dwError = ERROR_TDNF_NO_DATA;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *pdwPkgId = queueMatches.elements[0];

cleanup:
    queue_free(&queueMatches);
    return dwError;
error:
    if(pdwPkgId)
    {
        *pdwPkgId = 0;
    }
    goto cleanup;
}

uint32_t
TDNFNativeQueryBuildUpdateInfoSummary(
    char **ppszLines,
    uint32_t dwCount,
    PTDNF_UPDATEINFO_SUMMARY *ppSummary
    )
{
    uint32_t dwError = 0;
    PTDNF_UPDATEINFO_SUMMARY pSummary = NULL;
    uint32_t i = 0;

    if(!ppszLines || !ppSummary)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(
                  UPDATE_ENHANCEMENT + 1,
                  sizeof(TDNF_UPDATEINFO_SUMMARY),
                  (void **)&pSummary);
    BAIL_ON_TDNF_ERROR(dwError);

    for(i = 0; i <= UPDATE_ENHANCEMENT; i++)
    {
        pSummary[i].nType = i;
    }

    for(i = 0; i < dwCount; i++)
    {
        dwError = NativeQueryParseSummaryLine(ppszLines[i], pSummary);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *ppSummary = pSummary;

cleanup:
    return dwError;
error:
    if(ppSummary)
    {
        *ppSummary = NULL;
    }
    TDNFFreeUpdateInfoSummary(pSummary);
    goto cleanup;
}

uint32_t
TDNFNativeQueryBuildUpdateInfo(
    char **ppszLines,
    uint32_t dwCount,
    PTDNF_UPDATEINFO *ppInfo
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;
    PTDNF_UPDATEINFO pHead = NULL;
    PTDNF_UPDATEINFO pTail = NULL;

    if(!ppszLines || !ppInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(i = 0; i < dwCount; i++)
    {
        PTDNF_UPDATEINFO pInfoNode = NULL;

        dwError = NativeQueryParseUpdateInfoLine(ppszLines[i], &pInfoNode);
        BAIL_ON_TDNF_ERROR(dwError);

        if(!pHead)
        {
            pHead = pInfoNode;
        }
        else
        {
            pTail->pNext = pInfoNode;
        }
        pTail = pInfoNode;
    }

    *ppInfo = pHead;

cleanup:
    return dwError;
error:
    if(ppInfo)
    {
        *ppInfo = NULL;
    }
    TDNFFreeUpdateInfo(pHead);
    goto cleanup;
}

static uint32_t
NativeQuerySerializePackageIdCommon(
    Pool *pPool,
    Id dwPkgId,
    char **ppszLine
    )
{
    uint32_t dwError = 0;
    Solvable *pSolv = NULL;
    const char *pszRepo = "";
    const char *pszNevra = NULL;
    char *pszLine = NULL;

    if(!pPool || !ppszLine)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pSolv = pool_id2solvable(pPool, dwPkgId);
    if(!pSolv)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(pSolv->repo && pSolv->repo->name)
    {
        pszRepo = pSolv->repo->name;
    }

    pszNevra = pool_solvable2str(pPool, pSolv);
    if(!pszNevra)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateStringPrintf(
                  &pszLine,
                  "%s%c%s",
                  pszRepo,
                  NATIVE_QUERY_FIELD_SEP,
                  pszNevra);
    BAIL_ON_TDNF_ERROR(dwError);

    *ppszLine = pszLine;

cleanup:
    return dwError;
error:
    if(ppszLine)
    {
        *ppszLine = NULL;
    }
    TDNF_SAFE_FREE_MEMORY(pszLine);
    goto cleanup;
}

static int
NativeQuerySplitNevra(
    char *pszNevra,
    char **ppszName,
    char **ppszEvr,
    char **ppszArch
    )
{
    char *p = pszNevra + strlen(pszNevra) - 1;

    while(p > pszNevra && *p != '.')
    {
        p--;
    }
    if(p <= pszNevra)
    {
        return -1;
    }

    *p = '\0';
    *ppszArch = p + 1;
    p--;

    while(p > pszNevra && *p != '-')
    {
        p--;
    }
    if(p <= pszNevra)
    {
        return -2;
    }
    p--;
    while(p > pszNevra && *p != '-')
    {
        p--;
    }
    if(p <= pszNevra)
    {
        return -3;
    }

    *p = '\0';
    *ppszEvr = p + 1;
    *ppszName = pszNevra;
    return 0;
}

static uint32_t
NativeQueryAppendRefMatches(
    PSolvSack pSack,
    const char *pszPackageRef,
    int nInstalledOnly,
    Queue *pQueue,
    uint32_t *pdwMatches
    )
{
    uint32_t dwError = 0;
    Pool *pPool = NULL;
    char *pszCopy = NULL;
    char *pszRepo = NULL;
    char *pszNevra = NULL;
    char *pszName = NULL;
    char *pszEvr = NULL;
    char *pszArch = NULL;
    uint32_t dwMatches = 0;
    Id p = 0;
    Solvable *s = NULL;
    Pool *pool = NULL;

    if(!pSack || !pSack->pPool || IsNullOrEmptyString(pszPackageRef) || !pQueue)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pPool = pSack->pPool;
    pool = pPool;

    dwError = TDNFAllocateString(pszPackageRef, &pszCopy);
    BAIL_ON_TDNF_ERROR(dwError);

    pszRepo = pszCopy;
    pszNevra = strchr(pszCopy, NATIVE_QUERY_FIELD_SEP);
    if(!pszNevra)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *pszNevra = '\0';
    pszNevra++;
    if(IsNullOrEmptyString(pszRepo) || IsNullOrEmptyString(pszNevra))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(NativeQuerySplitNevra(pszNevra, &pszName, &pszEvr, &pszArch) != 0)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(nInstalledOnly)
    {
        FOR_REPO_SOLVABLES(pPool->installed, p, s)
        {
            const char *pszPkgName = NULL;
            const char *pszPkgArch = NULL;
            const char *pszPkgEvr = NULL;
            const char *pszPkgRepo = NULL;

            if(!s || !s->repo || !s->repo->name)
            {
                continue;
            }

            pszPkgRepo = s->repo->name;
            if(strcmp(pszPkgRepo, pszRepo))
            {
                continue;
            }

            pszPkgName = pool_id2str(pPool, s->name);
            pszPkgArch = pool_id2str(pPool, s->arch);
            pszPkgEvr = solvable_lookup_str(s, SOLVABLE_EVR);
            if(!pszPkgName || !pszPkgArch || !pszPkgEvr)
            {
                continue;
            }

            if(strcmp(pszPkgName, pszName) ||
               strcmp(pszPkgArch, pszArch) ||
               pool_evrcmp_str(pPool, pszPkgEvr, pszEvr, EVRCMP_COMPARE) != 0)
            {
                continue;
            }

            queue_pushunique(pQueue, p);
            dwMatches++;
        }
    }
    else
    {
        FOR_POOL_SOLVABLES(p)
        {
            const char *pszPkgName = NULL;
            const char *pszPkgArch = NULL;
            const char *pszPkgEvr = NULL;
            const char *pszPkgRepo = NULL;

            s = pool_id2solvable(pPool, p);
            if(!s || !s->repo || !s->repo->name)
            {
                continue;
            }

            pszPkgRepo = s->repo->name;
            if(strcmp(pszPkgRepo, pszRepo))
            {
                continue;
            }

            pszPkgName = pool_id2str(pPool, s->name);
            pszPkgArch = pool_id2str(pPool, s->arch);
            pszPkgEvr = solvable_lookup_str(s, SOLVABLE_EVR);
            if(!pszPkgName || !pszPkgArch || !pszPkgEvr)
            {
                continue;
            }

            if(strcmp(pszPkgName, pszName) ||
               strcmp(pszPkgArch, pszArch) ||
               pool_evrcmp_str(pPool, pszPkgEvr, pszEvr, EVRCMP_COMPARE) != 0)
            {
                continue;
            }

            queue_pushunique(pQueue, p);
            dwMatches++;
        }
    }

    if(pdwMatches)
    {
        *pdwMatches = dwMatches;
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszCopy);
    return dwError;
error:
    if(pdwMatches)
    {
        *pdwMatches = 0;
    }
    goto cleanup;
}

static uint32_t
NativeQueryParseSummaryLine(
    const char *pszLine,
    PTDNF_UPDATEINFO_SUMMARY pSummary
    )
{
    uint32_t dwError = 0;
    char *pszCopy = NULL;
    char *pszCursor = NULL;
    char *pszType = NULL;
    char *pszCount = NULL;
    uint32_t dwType = 0;
    uint32_t dwValue = 0;

    if(IsNullOrEmptyString(pszLine) || !pSummary)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateString(pszLine, &pszCopy);
    BAIL_ON_TDNF_ERROR(dwError);

    pszCursor = pszCopy;
    pszType = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_FIELD_SEP);
    pszCount = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_FIELD_SEP);
    if(!pszType || !pszCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = NativeQueryParseUnsigned(pszType, &dwType);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = NativeQueryParseUnsigned(pszCount, &dwValue);
    BAIL_ON_TDNF_ERROR(dwError);

    if(dwType > UPDATE_ENHANCEMENT)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pSummary[dwType].nType = (int)dwType;
    pSummary[dwType].nCount = (int)dwValue;

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszCopy);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
NativeQueryParseUpdateInfoLine(
    const char *pszLine,
    PTDNF_UPDATEINFO *ppInfo
    )
{
    uint32_t dwError = 0;
    char *pszCopy = NULL;
    char *pszCursor = NULL;
    char *pszType = NULL;
    char *pszReboot = NULL;
    char *pszId = NULL;
    char *pszDescription = NULL;
    char *pszDate = NULL;
    char *pszPackages = NULL;
    uint32_t dwType = 0;
    uint32_t dwRebootRequired = 0;
    PTDNF_UPDATEINFO pInfo = NULL;
    PTDNF_UPDATEINFO_PKG pPkgHead = NULL;
    PTDNF_UPDATEINFO_PKG pPkgTail = NULL;

    if(IsNullOrEmptyString(pszLine) || !ppInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateString(pszLine, &pszCopy);
    BAIL_ON_TDNF_ERROR(dwError);

    pszCursor = pszCopy;
    pszType = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_FIELD_SEP);
    pszReboot = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_FIELD_SEP);
    pszId = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_FIELD_SEP);
    pszDescription = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_FIELD_SEP);
    pszDate = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_FIELD_SEP);
    pszPackages = pszCursor;

    if(!pszType || !pszReboot || !pszId || !pszDescription || !pszDate)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = NativeQueryParseUnsigned(pszType, &dwType);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = NativeQueryParseUnsigned(pszReboot, &dwRebootRequired);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_UPDATEINFO), (void **)&pInfo);
    BAIL_ON_TDNF_ERROR(dwError);

    pInfo->nType = (int)dwType;
    pInfo->nRebootRequired = (int)dwRebootRequired;
    if(!IsNullOrEmptyString(pszId))
    {
        dwError = TDNFAllocateString(pszId, &pInfo->pszID);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!IsNullOrEmptyString(pszDescription))
    {
        dwError = TDNFAllocateString(pszDescription, &pInfo->pszDescription);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!IsNullOrEmptyString(pszDate))
    {
        dwError = TDNFAllocateString(pszDate, &pInfo->pszDate);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszPackages))
    {
        char *pszPkgCursor = pszPackages;
        char *pszPkgText = NULL;

        while((pszPkgText = NativeQuerySplitField(&pszPkgCursor, NATIVE_QUERY_GROUP_SEP)) != NULL)
        {
            PTDNF_UPDATEINFO_PKG pPkg = NULL;

            if(IsNullOrEmptyString(pszPkgText))
            {
                continue;
            }

            dwError = NativeQueryParseUpdateInfoPackage(pszPkgText, &pPkg);
            BAIL_ON_TDNF_ERROR(dwError);

            if(!pPkgHead)
            {
                pPkgHead = pPkg;
            }
            else
            {
                pPkgTail->pNext = pPkg;
            }
            pPkgTail = pPkg;
        }
    }

    pInfo->pPackages = pPkgHead;
    *ppInfo = pInfo;

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszCopy);
    return dwError;
error:
    if(ppInfo)
    {
        *ppInfo = NULL;
    }
    if(pPkgHead)
    {
        TDNFFreeUpdateInfoPackages(pPkgHead);
    }
    if(pInfo)
    {
        TDNFFreeUpdateInfo(pInfo);
    }
    goto cleanup;
}

static uint32_t
NativeQueryParseUpdateInfoPackage(
    const char *pszText,
    PTDNF_UPDATEINFO_PKG *ppPkg
    )
{
    uint32_t dwError = 0;
    char *pszCopy = NULL;
    char *pszCursor = NULL;
    char *pszName = NULL;
    char *pszEvr = NULL;
    char *pszArch = NULL;
    char *pszFileName = NULL;
    PTDNF_UPDATEINFO_PKG pPkg = NULL;

    if(IsNullOrEmptyString(pszText) || !ppPkg)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateString(pszText, &pszCopy);
    BAIL_ON_TDNF_ERROR(dwError);

    pszCursor = pszCopy;
    pszName = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_ITEM_SEP);
    pszEvr = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_ITEM_SEP);
    pszArch = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_ITEM_SEP);
    pszFileName = NativeQuerySplitField(&pszCursor, NATIVE_QUERY_ITEM_SEP);
    if(!pszName || !pszEvr || !pszArch || pszFileName == NULL)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_UPDATEINFO_PKG), (void **)&pPkg);
    BAIL_ON_TDNF_ERROR(dwError);

    if(!IsNullOrEmptyString(pszName))
    {
        dwError = TDNFAllocateString(pszName, &pPkg->pszName);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!IsNullOrEmptyString(pszEvr))
    {
        dwError = TDNFAllocateString(pszEvr, &pPkg->pszEVR);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!IsNullOrEmptyString(pszArch))
    {
        dwError = TDNFAllocateString(pszArch, &pPkg->pszArch);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!IsNullOrEmptyString(pszFileName))
    {
        dwError = TDNFAllocateString(pszFileName, &pPkg->pszFileName);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *ppPkg = pPkg;

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszCopy);
    return dwError;
error:
    if(ppPkg)
    {
        *ppPkg = NULL;
    }
    if(pPkg)
    {
        TDNFFreeUpdateInfoPackages(pPkg);
    }
    goto cleanup;
}

static uint32_t
NativeQueryParseUnsigned(
    const char *pszValue,
    uint32_t *pdwValue
    )
{
    uint32_t dwError = 0;
    char *pszEnd = NULL;
    unsigned long dwParsed = 0;

    if(IsNullOrEmptyString(pszValue) || !pdwValue)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    errno = 0;
    dwParsed = strtoul(pszValue, &pszEnd, 10);
    if(errno != 0 || !pszEnd || *pszEnd != '\0' || dwParsed > UINT32_MAX)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *pdwValue = (uint32_t)dwParsed;

cleanup:
    return dwError;
error:
    goto cleanup;
}

static char*
NativeQuerySplitField(
    char **ppszCursor,
    char chSep
    )
{
    char *pszField = NULL;
    char *pszSep = NULL;

    if(!ppszCursor || !*ppszCursor)
    {
        return NULL;
    }

    pszField = *ppszCursor;
    pszSep = strchr(pszField, chSep);
    if(pszSep)
    {
        *pszSep = '\0';
        *ppszCursor = pszSep + 1;
    }
    else
    {
        *ppszCursor = NULL;
    }
    return pszField;
}
