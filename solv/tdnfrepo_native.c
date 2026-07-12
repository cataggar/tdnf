#define _GNU_SOURCE 1
#include "includes.h"
#include <rpmdb.h>

static int
SolvNativeIsAdvisory(
    Pool *pPool,
    Solvable *pSolv
    );

static Id
SolvNativeFindMatchingSolvable(
    Repo *pRepo,
    Id dwName,
    Id dwArch,
    Id dwEvr,
    int nAdvisory
    );

static void
SolvNativeCountRepoKinds(
    Repo *pRepo,
    uint32_t *pdwPackages,
    uint32_t *pdwAdvisories
    );

static int
SolvNativeCompareStringField(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszRepoName
    );

static int
SolvNativeCompareNumField(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszRepoName
    );

static int
SolvNativeCompareChecksumField(
    Solvable *pLegacy,
    Solvable *pNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszRepoName
    );

static int
SolvNativeCompareIdArray(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszRepoName
    );

static int
SolvNativeCompareFileLists(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    );

static int
SolvNativeCompareChangelogs(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    );

static int
SolvNativeCompareUpdateCollections(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    );

static int
SolvNativeCompareUpdateReferences(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    );

static int
SolvNativeCompareSourceFields(
    Solvable *pLegacy,
    Solvable *pNative,
    const char *pszRepoName
    );

static int
SolvNativeComparePackage(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    );

static int
SolvNativeCompareAdvisory(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    );

static int
SolvNativeStringsEqual(
    const char *pszLeft,
    const char *pszRight
    );

static const char*
SolvNativePoolIdToDep(
    Pool *pPool,
    Id dwId
    );

static const char*
SolvNativePoolIdToStr(
    Pool *pPool,
    Id dwId
    );

static uint32_t
SolvAddRpmLegacy(
    Repo *pRepo,
    const char *pszPath,
    int dwFlags,
    Id *pdwSolvableId
    );

uint32_t
SolvReadYumRepoNative(
    Repo *pRepo,
    const char *pszRepomd,
    const char *pszPrimary,
    const char *pszFilelists,
    const char *pszUpdateinfo,
    const char *pszOther
    )
{
    return TDNFRepoMdNativeLoadSolvRepo(
               pRepo,
               pszRepomd,
               pszPrimary,
               pszFilelists,
               pszUpdateinfo,
               pszOther);
}

uint32_t
SolvSerializeRepo(
    Repo *pRepo,
    char **ppszBytes,
    size_t *pnSize
    )
{
    uint32_t dwError = 0;
    FILE *pMem = NULL;
    char *pszBytes = NULL;
    size_t nSize = 0;

    if(!pRepo || !ppszBytes || !pnSize)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    pMem = open_memstream(&pszBytes, &nSize);
    if(!pMem)
    {
        dwError = ERROR_TDNF_SOLV_IO;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    if(repo_write(pRepo, pMem))
    {
        dwError = ERROR_TDNF_REPO_WRITE;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    if(fclose(pMem))
    {
        pMem = NULL;
        dwError = ERROR_TDNF_SOLV_IO;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    pMem = NULL;

    *ppszBytes = pszBytes;
    *pnSize = nSize;

cleanup:
    return dwError;

error:
    if(pMem)
    {
        fclose(pMem);
    }
    if(pszBytes)
    {
        free(pszBytes);
    }
    if(ppszBytes)
    {
        *ppszBytes = NULL;
    }
    if(pnSize)
    {
        *pnSize = 0;
    }
    goto cleanup;
}

uint32_t
SolvReadInstalledRpmsNative(
    Repo* pRepo,
    const char *pszRootDir,
    int dwFlags
    )
{
    uint32_t dwError = 0;

    if(!pRepo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    dwError = TDNFRepoMdNativeLoadInstalledSolvRepo(pRepo, pszRootDir, dwFlags);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
SolvAddRpmNative(
    Repo *pRepo,
    const char *pszPath,
    int dwFlags,
    Id *pdwSolvableId
    )
{
    uint32_t dwError = 0;
    uint32_t dwSolvableId = 0;

    if(pdwSolvableId)
    {
        *pdwSolvableId = 0;
    }

    if(!pRepo || IsNullOrEmptyString(pszPath))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    dwError = TDNFRepoMdNativeAddRpm(pRepo, pszPath, dwFlags, &dwSolvableId);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

    if(pdwSolvableId)
    {
        *pdwSolvableId = (Id)dwSolvableId;
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static uint32_t
SolvAddRpmLegacy(
    Repo *pRepo,
    const char *pszPath,
    int dwFlags,
    Id *pdwSolvableId
    )
{
    uint32_t dwError = 0;
    Id dwSolvableId = 0;

    if(pdwSolvableId)
    {
        *pdwSolvableId = 0;
    }

    if(!pRepo || IsNullOrEmptyString(pszPath))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    dwSolvableId = repo_add_rpm(pRepo, pszPath, dwFlags);
    if(!dwSolvableId)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    if(pdwSolvableId)
    {
        *pdwSolvableId = dwSolvableId;
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static void
SolvLogNativeCrosscheckSuccess(
    const char *pszPrefix,
    const char *pszRepoName,
    Repo *pRepo,
    int nFocusedComparison
    )
{
    uint32_t dwPackages = 0;
    uint32_t dwAdvisories = 0;
    uint32_t dwError = 0;
    const char *pszLogFile = getenv("TDNF_NATIVE_CROSSCHECK_LOGFILE");
    FILE *pLog = NULL;
    char *pszMessage = NULL;

    if(IsNullOrEmptyString(pszLogFile))
    {
        return;
    }

    SolvNativeCountRepoKinds(pRepo, &dwPackages, &dwAdvisories);

    dwError = TDNFAllocateStringPrintf(
                  &pszMessage,
                  "%s: repo '%s' compared %u package(s)%s with no mismatches\n",
                  pszPrefix ? pszPrefix : "native crosscheck",
                  pszRepoName ? pszRepoName : "(unknown)",
                  dwPackages,
                  nFocusedComparison ? " after focused comparison" : "");
    if(!dwError && pszMessage)
    {
        pLog = fopen(pszLogFile, "a");
        if(pLog)
        {
            fputs(pszMessage, pLog);
            fclose(pLog);
            pLog = NULL;
        }
    }

    if(pLog)
    {
        fclose(pLog);
    }
    TDNF_SAFE_FREE_MEMORY(pszMessage);
    (void)dwAdvisories;
}

static int
SolvInstalledCrosscheckShouldRun(
    const char *pszRootDir,
    const char *pszStateFile,
    char **ppszCookie
    )
{
    FILE *pState = NULL;
    char *pszCookie = NULL;
    char szStateCookie[256] = {0};
    int nShouldRun = 1;

    if(ppszCookie)
    {
        *ppszCookie = NULL;
    }

    pszCookie = tdnf_rpmdb_cookie(pszRootDir);
    if(ppszCookie)
    {
        *ppszCookie = pszCookie;
    }

    if(IsNullOrEmptyString(pszStateFile) || IsNullOrEmptyString(pszCookie))
    {
        return 1;
    }

    pState = fopen(pszStateFile, "r");
    if(!pState)
    {
        return 1;
    }

    if(fgets(szStateCookie, sizeof(szStateCookie), pState))
    {
        size_t nLen = strlen(szStateCookie);

        while(nLen > 0 &&
              (szStateCookie[nLen - 1] == '\n' || szStateCookie[nLen - 1] == '\r'))
        {
            szStateCookie[--nLen] = '\0';
        }
        if(szStateCookie[0] &&
           !strcmp(szStateCookie, pszCookie))
        {
            nShouldRun = 0;
        }
    }

    fclose(pState);
    return nShouldRun;
}

static void
SolvInstalledCrosscheckUpdateState(
    const char *pszStateFile,
    const char *pszCookie
    )
{
    FILE *pState = NULL;

    if(IsNullOrEmptyString(pszStateFile) || IsNullOrEmptyString(pszCookie))
    {
        return;
    }

    pState = fopen(pszStateFile, "w");
    if(!pState)
    {
        return;
    }

    fputs(pszCookie, pState);
    fclose(pState);
}

static uint32_t
SolvGetInstalledCrosscheckStateFile(
    const char *pszCachePath,
    char **ppszStateFile
    )
{
    uint32_t dwError = 0;
    int nIsDir = 0;

    if(ppszStateFile)
    {
        *ppszStateFile = NULL;
    }

    if(IsNullOrEmptyString(pszCachePath) || !ppszStateFile)
    {
        goto cleanup;
    }

    dwError = TDNFIsDir(pszCachePath, &nIsDir);
    if(dwError == ERROR_TDNF_FILE_NOT_FOUND)
    {
        dwError = 0;
        nIsDir = 0;
    }
    BAIL_ON_TDNF_ERROR(dwError);

    if(nIsDir)
    {
        dwError = TDNFJoinPath(
                      ppszStateFile,
                      pszCachePath,
                      SYSTEM_REPO_NAME ".native-crosscheck.cookie",
                      NULL);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    else
    {
        dwError = TDNFAllocateStringPrintf(
                      ppszStateFile,
                      "%s.native-crosscheck.cookie",
                      pszCachePath);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static Id
SolvNativeFindMatchingSolvableByStrings(
    Repo *pRepo,
    const char *pszName,
    const char *pszArch,
    const char *pszEvr,
    int nAdvisory
    )
{
    Id p = 0;
    Solvable *pSolv = NULL;

    if(!pRepo || !pRepo->pool)
    {
        return 0;
    }

    FOR_REPO_SOLVABLES(pRepo, p, pSolv)
    {
        if(SolvNativeIsAdvisory(pRepo->pool, pSolv) != nAdvisory)
        {
            continue;
        }
        if(SolvNativeStringsEqual(pool_id2str(pRepo->pool, pSolv->name), pszName) &&
           SolvNativeStringsEqual(pool_id2str(pRepo->pool, pSolv->arch), pszArch) &&
           SolvNativeStringsEqual(pool_id2str(pRepo->pool, pSolv->evr), pszEvr))
        {
            return p;
        }
    }

    return 0;
}

static int
SolvNativeCompareChecksumFieldCrossPool(
    Solvable *pLegacy,
    Solvable *pNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszPrefix,
    const char *pszRepoName
    )
{
    Id dwLegacyType = 0;
    Id dwNativeType = 0;
    const char *pszLegacy = solvable_lookup_checksum(pLegacy, dwKeyName, &dwLegacyType);
    const char *pszNative = solvable_lookup_checksum(pNative, dwKeyName, &dwNativeType);
    const char *pszLegacyType = dwLegacyType ? pool_id2str(pLegacy->repo->pool, dwLegacyType) : NULL;
    const char *pszNativeType = dwNativeType ? pool_id2str(pNative->repo->pool, dwNativeType) : NULL;

    if(!SolvNativeStringsEqual(pszLegacy, pszNative) ||
       !SolvNativeStringsEqual(pszLegacyType, pszNativeType))
    {
        pr_err("%s: repo '%s' %s mismatch legacy=%s/%s native=%s/%s\n",
               pszPrefix ? pszPrefix : "native rpmdb crosscheck",
               pszRepoName ? pszRepoName : "(unknown)",
               pszField,
               pszLegacyType ? pszLegacyType : "(null)",
               pszLegacy ? pszLegacy : "(null)",
               pszNativeType ? pszNativeType : "(null)",
               pszNative ? pszNative : "(null)");
        return 1;
    }

    return 0;
}

static int
SolvNativeCompareNumFieldCrossPool(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszPrefix,
    const char *pszRepoName
    )
{
    unsigned long long nLegacy = repo_lookup_num(pLegacy, dwLegacy, dwKeyName, 0);
    unsigned long long nNative = repo_lookup_num(pNative, dwNative, dwKeyName, 0);

    if(nLegacy != nNative)
    {
        pr_err("%s: repo '%s' %s mismatch legacy=%llu native=%llu\n",
               pszPrefix ? pszPrefix : "native rpmdb crosscheck",
               pszRepoName ? pszRepoName : "(unknown)",
               pszField,
               nLegacy,
               nNative);
        return 1;
    }

    return 0;
}

static int
SolvNativeCompareIdArraySampleCrossPool(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszPrefix,
    const char *pszRepoName
    )
{
    Queue qLegacy = {0};
    Queue qNative = {0};
    const char *pszLegacyFirst = "(empty)";
    const char *pszNativeFirst = "(empty)";
    int nMismatch = 0;

    queue_init(&qLegacy);
    queue_init(&qNative);

    repo_lookup_idarray(pLegacy, dwLegacy, dwKeyName, &qLegacy);
    repo_lookup_idarray(pNative, dwNative, dwKeyName, &qNative);

    if(qLegacy.count > 0)
    {
        pszLegacyFirst = pool_dep2str(pLegacy->pool, qLegacy.elements[0]);
    }
    if(qNative.count > 0)
    {
        pszNativeFirst = pool_dep2str(pNative->pool, qNative.elements[0]);
    }

    if(qLegacy.count != qNative.count ||
       !SolvNativeStringsEqual(pszLegacyFirst, pszNativeFirst))
    {
        pr_err("%s: repo '%s' %s mismatch legacy_count=%d native_count=%d first_legacy='%s' first_native='%s'\n",
               pszPrefix ? pszPrefix : "native rpmdb crosscheck",
               pszRepoName ? pszRepoName : "(unknown)",
               pszField,
               qLegacy.count,
               qNative.count,
               pszLegacyFirst,
               pszNativeFirst);
        nMismatch = 1;
    }

    queue_free(&qLegacy);
    queue_free(&qNative);
    return nMismatch;
}

static int
SolvNativeCompareFileListsSampleCrossPool(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszPrefix,
    const char *pszRepoName
    )
{
    Dataiterator di = {0};
    int nLegacyCount = 0;
    int nNativeCount = 0;

    dataiterator_init(&di, pLegacy->pool, pLegacy, dwLegacy,
                      SOLVABLE_FILELIST, NULL,
                      SEARCH_FILES | SEARCH_COMPLETE_FILELIST);
    while(dataiterator_step(&di))
    {
        nLegacyCount++;
    }
    dataiterator_free(&di);

    dataiterator_init(&di, pNative->pool, pNative, dwNative,
                      SOLVABLE_FILELIST, NULL,
                      SEARCH_FILES | SEARCH_COMPLETE_FILELIST);
    while(dataiterator_step(&di))
    {
        nNativeCount++;
    }
    dataiterator_free(&di);

    if(nLegacyCount != nNativeCount)
    {
        pr_err("%s: repo '%s' file list mismatch legacy_count=%d native_count=%d\n",
               pszPrefix ? pszPrefix : "native rpmdb crosscheck",
               pszRepoName ? pszRepoName : "(unknown)",
               nLegacyCount,
               nNativeCount);
        return 1;
    }

    return 0;
}

static int
SolvNativeComparePackageSampleCrossPool(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszPrefix,
    const char *pszRepoName
    )
{
    Solvable *pLegacySolv = pool_id2solvable(pLegacy->pool, dwLegacy);
    Solvable *pNativeSolv = pool_id2solvable(pNative->pool, dwNative);

    if(!pLegacySolv || !pNativeSolv)
    {
        pr_err("%s: repo '%s' had an internal package lookup failure\n",
               pszPrefix ? pszPrefix : "native rpmdb crosscheck",
               pszRepoName ? pszRepoName : "(unknown)");
        return 1;
    }

    if(SolvNativeCompareChecksumFieldCrossPool(pLegacySolv, pNativeSolv, SOLVABLE_CHECKSUM, "checksum", pszPrefix, pszRepoName) ||
       SolvNativeCompareChecksumFieldCrossPool(pLegacySolv, pNativeSolv, SOLVABLE_HDRID, "hdrid", pszPrefix, pszRepoName) ||
       SolvNativeCompareChecksumFieldCrossPool(pLegacySolv, pNativeSolv, SOLVABLE_PKGID, "pkgid", pszPrefix, pszRepoName) ||
       SolvNativeCompareNumFieldCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_BUILDTIME, "buildtime", pszPrefix, pszRepoName) ||
       SolvNativeCompareNumFieldCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_INSTALLTIME, "installtime", pszPrefix, pszRepoName) ||
       SolvNativeCompareNumFieldCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_INSTALLSIZE, "installsize", pszPrefix, pszRepoName) ||
       SolvNativeCompareNumFieldCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_DOWNLOADSIZE, "downloadsize", pszPrefix, pszRepoName) ||
       SolvNativeCompareNumFieldCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_HEADEREND, "headerend", pszPrefix, pszRepoName) ||
       SolvNativeCompareIdArraySampleCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_PROVIDES, "provides", pszPrefix, pszRepoName) ||
       SolvNativeCompareIdArraySampleCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_REQUIRES, "requires", pszPrefix, pszRepoName) ||
       SolvNativeCompareIdArraySampleCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_CONFLICTS, "conflicts", pszPrefix, pszRepoName) ||
       SolvNativeCompareIdArraySampleCrossPool(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_OBSOLETES, "obsoletes", pszPrefix, pszRepoName) ||
       SolvNativeCompareFileListsSampleCrossPool(pLegacy, dwLegacy, pNative, dwNative, pszPrefix, pszRepoName))
    {
        pr_err("%s: repo '%s' package sample '%s.%s' evr '%s' mismatched\n",
               pszPrefix ? pszPrefix : "native rpmdb crosscheck",
               pszRepoName ? pszRepoName : "(unknown)",
               pool_id2str(pLegacy->pool, pLegacySolv->name),
               pool_id2str(pLegacy->pool, pLegacySolv->arch),
               pool_id2str(pLegacy->pool, pLegacySolv->evr));
        return 1;
    }

    return 0;
}

static int
SolvNativeCrosscheckInstalledSamples(
    Repo *pLegacy,
    Repo *pNative,
    const char *pszPrefix,
    const char *pszRepoName
    )
{
    uint32_t dwLegacyPackages = 0;
    uint32_t dwNativePackages = 0;
    uint32_t dwLegacyAdvisories = 0;
    uint32_t dwNativeAdvisories = 0;
    uint32_t dwSeenPackages = 0;
    Id p = 0;
    Solvable *pSolv = NULL;

    SolvNativeCountRepoKinds(pLegacy, &dwLegacyPackages, &dwLegacyAdvisories);
    SolvNativeCountRepoKinds(pNative, &dwNativePackages, &dwNativeAdvisories);

    if(dwLegacyPackages != dwNativePackages)
    {
        pr_err("%s: repo '%s' package count mismatch legacy=%u native=%u\n",
               pszPrefix ? pszPrefix : "native rpmdb crosscheck",
               pszRepoName ? pszRepoName : "(unknown)",
               dwLegacyPackages,
               dwNativePackages);
        return 1;
    }
    if(dwLegacyAdvisories != dwNativeAdvisories)
    {
        pr_err("%s: repo '%s' advisory count mismatch legacy=%u native=%u\n",
               pszPrefix ? pszPrefix : "native rpmdb crosscheck",
               pszRepoName ? pszRepoName : "(unknown)",
               dwLegacyAdvisories,
               dwNativeAdvisories);
        return 1;
    }

    FOR_REPO_SOLVABLES(pLegacy, p, pSolv)
    {
        Id dwNative = 0;
        const char *pszName = NULL;
        const char *pszArch = NULL;
        const char *pszEvr = NULL;

        if(SolvNativeIsAdvisory(pLegacy->pool, pSolv))
        {
            continue;
        }

        if(dwSeenPackages >= 8)
        {
            break;
        }
        dwSeenPackages++;

        pszName = pool_id2str(pLegacy->pool, pSolv->name);
        pszArch = pool_id2str(pLegacy->pool, pSolv->arch);
        pszEvr = pool_id2str(pLegacy->pool, pSolv->evr);
        dwNative = SolvNativeFindMatchingSolvableByStrings(
                       pNative,
                       pszName,
                       pszArch,
                       pszEvr,
                       0);
        if(!dwNative)
        {
            pr_err("%s: repo '%s' missing package '%s.%s' evr '%s' in native bridge\n",
                   pszPrefix ? pszPrefix : "native rpmdb crosscheck",
                   pszRepoName ? pszRepoName : "(unknown)",
                   pszName ? pszName : "(null)",
                   pszArch ? pszArch : "(null)",
                   pszEvr ? pszEvr : "(null)");
            return 1;
        }
        if(SolvNativeComparePackageSampleCrossPool(pLegacy, p, pNative, dwNative, pszPrefix, pszRepoName))
        {
            return 1;
        }
    }

    return 0;
}

void
SolvCrosscheckInstalledRpmsWithNative(
    Repo *pLegacyRepo,
    const char *pszCacheFileName,
    int dwFlags
    )
{
    static int nInstalledCrosschecked = 0;
    uint32_t dwError = 0;
    const char *pszRootDir = NULL;
    Pool *pPool = NULL;
    Repo *pNative = NULL;
    char *pszCookie = NULL;
    char *pszStateFile = NULL;
    int nMatched = 0;

    if(nInstalledCrosschecked)
    {
        return;
    }
    nInstalledCrosschecked = 1;

    if(!pLegacyRepo || !pLegacyRepo->pool)
    {
        pr_err("native rpmdb crosscheck: repo '%s' had an internal comparison setup failure\n",
               SYSTEM_REPO_NAME);
        return;
    }

    pszRootDir = pool_get_rootdir(pLegacyRepo->pool);
    if(!pszRootDir)
    {
        pszRootDir = "";
    }

    dwError = SolvGetInstalledCrosscheckStateFile(
                  pszCacheFileName,
                  &pszStateFile);
    if(dwError)
    {
        pr_err("native rpmdb crosscheck: repo '%s' failed to derive a state-file path (%u)\n",
               SYSTEM_REPO_NAME,
               dwError);
        goto cleanup;
    }

    if(!SolvInstalledCrosscheckShouldRun(pszRootDir, pszStateFile, &pszCookie))
    {
        goto cleanup;
    }

    pPool = pool_create();
    if(!pPool)
    {
        pr_err("native rpmdb crosscheck: repo '%s' failed to create a temporary pool\n",
               SYSTEM_REPO_NAME);
        goto cleanup;
    }
    if(pszRootDir[0])
    {
        pool_set_rootdir(pPool, pszRootDir);
    }

    pNative = repo_create(pPool, SYSTEM_REPO_NAME);
    if(!pNative)
    {
        pr_err("native rpmdb crosscheck: repo '%s' failed to create a temporary native repo\n",
               SYSTEM_REPO_NAME);
        goto cleanup;
    }

    dwError = SolvReadInstalledRpmsNative(pNative, pszRootDir, dwFlags);
    if(dwError)
    {
        pr_err("native rpmdb crosscheck: repo '%s' failed to load the native comparison repo (%u): %s\n",
               SYSTEM_REPO_NAME,
               dwError,
               TDNFRepoMdNativeLastError());
        goto cleanup;
    }

    if(!SolvNativeCrosscheckInstalledSamples(
            pLegacyRepo,
            pNative,
            "native rpmdb crosscheck",
            SYSTEM_REPO_NAME))
    {
        SolvLogNativeCrosscheckSuccess("native rpmdb crosscheck", SYSTEM_REPO_NAME, pNative, 0);
        nMatched = 1;
    }

cleanup:
    if(nMatched)
    {
        SolvInstalledCrosscheckUpdateState(pszStateFile, pszCookie);
    }
    if(pszCookie)
    {
        tdnf_rpmdb_string_free(pszCookie);
    }
    TDNF_SAFE_FREE_MEMORY(pszStateFile);
    if(pPool)
    {
        pool_free(pPool);
    }
}

void
SolvCrosscheckRpmPathWithNative(
    const char *pszPrefix,
    const char *pszPath,
    int dwFlags
    )
{
    uint32_t dwError = 0;
    Pool *pPool = NULL;
    Repo *pLegacy = NULL;
    Repo *pNative = NULL;
    char *pszLegacyBytes = NULL;
    char *pszNativeBytes = NULL;
    size_t nLegacySize = 0;
    size_t nNativeSize = 0;

    if(IsNullOrEmptyString(pszPath))
    {
        return;
    }

    pPool = pool_create();
    if(!pPool)
    {
        pr_err("%s: rpm '%s' failed to create a temporary pool\n",
               pszPrefix ? pszPrefix : "native rpm crosscheck",
               pszPath);
        goto cleanup;
    }

    pLegacy = repo_create(pPool, pszPath);
    pNative = repo_create(pPool, pszPath);
    if(!pLegacy || !pNative)
    {
        pr_err("%s: rpm '%s' failed to create temporary repos\n",
               pszPrefix ? pszPrefix : "native rpm crosscheck",
               pszPath);
        goto cleanup;
    }

    dwError = SolvAddRpmLegacy(pLegacy, pszPath, dwFlags, NULL);
    if(dwError)
    {
        pr_err("%s: rpm '%s' failed to load the legacy comparison repo (%u)\n",
               pszPrefix ? pszPrefix : "native rpm crosscheck",
               pszPath,
               dwError);
        goto cleanup;
    }

    dwError = SolvAddRpmNative(pNative, pszPath, dwFlags, NULL);
    if(dwError)
    {
        pr_err("%s: rpm '%s' failed to load the native comparison repo (%u): %s\n",
               pszPrefix ? pszPrefix : "native rpm crosscheck",
               pszPath,
               dwError,
               TDNFRepoMdNativeLastError());
        goto cleanup;
    }

    repo_internalize(pLegacy);
    repo_internalize(pNative);

    dwError = SolvSerializeRepo(pLegacy, &pszLegacyBytes, &nLegacySize);
    if(dwError)
    {
        pr_err("%s: rpm '%s' failed to serialize the legacy repo (%u)\n",
               pszPrefix ? pszPrefix : "native rpm crosscheck",
               pszPath,
               dwError);
        goto cleanup;
    }

    dwError = SolvSerializeRepo(pNative, &pszNativeBytes, &nNativeSize);
    if(dwError)
    {
        pr_err("%s: rpm '%s' failed to serialize the native repo (%u)\n",
               pszPrefix ? pszPrefix : "native rpm crosscheck",
               pszPath,
               dwError);
        goto cleanup;
    }

    if(nLegacySize == nNativeSize &&
       pszLegacyBytes &&
       pszNativeBytes &&
       !memcmp(pszLegacyBytes, pszNativeBytes, nLegacySize))
    {
        SolvLogNativeCrosscheckSuccess(pszPrefix, pszPath, pNative, 0);
        goto cleanup;
    }

    if(!SolvLogNativeRepoMismatch(pszPath, pLegacy, pNative, 1))
    {
        SolvLogNativeCrosscheckSuccess(pszPrefix, pszPath, pNative, 1);
    }

cleanup:
    if(pszLegacyBytes)
    {
        free(pszLegacyBytes);
    }
    if(pszNativeBytes)
    {
        free(pszNativeBytes);
    }
    if(pPool)
    {
        pool_free(pPool);
    }
}

int
SolvLogNativeRepoMismatch(
    const char *pszRepoName,
    Repo *pLegacy,
    Repo *pNative,
    int nAllowUnfocusedDiff
    )
{
    Pool *pPool = NULL;
    uint32_t dwLegacyPackages = 0;
    uint32_t dwLegacyAdvisories = 0;
    uint32_t dwNativePackages = 0;
    uint32_t dwNativeAdvisories = 0;
    Id p = 0;
    Solvable *pSolv = NULL;

    if(!pLegacy || !pNative || !pLegacy->pool || pLegacy->pool != pNative->pool)
    {
        pr_err("native repomd crosscheck: repo '%s' had an internal comparison setup failure\n",
               pszRepoName ? pszRepoName : "(unknown)");
        return 1;
    }

    pPool = pLegacy->pool;
    SolvNativeCountRepoKinds(pLegacy, &dwLegacyPackages, &dwLegacyAdvisories);
    SolvNativeCountRepoKinds(pNative, &dwNativePackages, &dwNativeAdvisories);

    if(dwLegacyPackages != dwNativePackages)
    {
        pr_err("native repomd crosscheck: repo '%s' package count mismatch legacy=%u native=%u\n",
               pszRepoName ? pszRepoName : "(unknown)",
               dwLegacyPackages,
               dwNativePackages);
        return 1;
    }
    if(dwLegacyAdvisories != dwNativeAdvisories)
    {
        pr_err("native repomd crosscheck: repo '%s' advisory count mismatch legacy=%u native=%u\n",
               pszRepoName ? pszRepoName : "(unknown)",
               dwLegacyAdvisories,
               dwNativeAdvisories);
        return 1;
    }

    FOR_REPO_SOLVABLES(pLegacy, p, pSolv)
    {
        Id dwNativeId = 0;
        int nAdvisory = SolvNativeIsAdvisory(pPool, pSolv);

        dwNativeId = SolvNativeFindMatchingSolvable(
                         pNative,
                         pSolv->name,
                         pSolv->arch,
                         pSolv->evr,
                         nAdvisory);
        if(!dwNativeId)
        {
            pr_err("native repomd crosscheck: repo '%s' missing %s '%s.%s' evr '%s' in native bridge\n",
                   pszRepoName ? pszRepoName : "(unknown)",
                   nAdvisory ? "advisory" : "package",
                   SolvNativePoolIdToStr(pPool, pSolv->name),
                   SolvNativePoolIdToStr(pPool, pSolv->arch),
                   SolvNativePoolIdToStr(pPool, pSolv->evr));
            return 1;
        }

        if(nAdvisory)
        {
            if(SolvNativeCompareAdvisory(pPool,
                                         pLegacy,
                                         p,
                                         pNative,
                                         dwNativeId,
                                         pszRepoName))
            {
                return 1;
            }
        }
        else
        {
            if(SolvNativeComparePackage(pPool,
                                        pLegacy,
                                        p,
                                        pNative,
                                        dwNativeId,
                                        pszRepoName))
            {
                return 1;
            }
        }
    }

    if(nAllowUnfocusedDiff)
    {
        return 0;
    }

    pr_err("native repomd crosscheck: repo '%s' serialized output differed but no focused field mismatch was isolated\n",
           pszRepoName ? pszRepoName : "(unknown)");
    return 1;
}

static int
SolvNativeIsAdvisory(
    Pool *pPool,
    Solvable *pSolv
    )
{
    const char *pszName = NULL;

    if(!pPool || !pSolv)
    {
        return 0;
    }

    pszName = pool_id2str(pPool, pSolv->name);
    return pszName && !strncmp(pszName, "patch:", 6);
}

static Id
SolvNativeFindMatchingSolvable(
    Repo *pRepo,
    Id dwName,
    Id dwArch,
    Id dwEvr,
    int nAdvisory
    )
{
    Id p = 0;
    Solvable *pSolv = NULL;

    if(!pRepo || !pRepo->pool)
    {
        return 0;
    }

    FOR_REPO_SOLVABLES(pRepo, p, pSolv)
    {
        if(SolvNativeIsAdvisory(pRepo->pool, pSolv) != nAdvisory)
        {
            continue;
        }
        if(pSolv->name == dwName &&
           pSolv->arch == dwArch &&
           pSolv->evr == dwEvr)
        {
            return p;
        }
    }

    return 0;
}

static void
SolvNativeCountRepoKinds(
    Repo *pRepo,
    uint32_t *pdwPackages,
    uint32_t *pdwAdvisories
    )
{
    Id p = 0;
    Solvable *pSolv = NULL;

    if(pdwPackages)
    {
        *pdwPackages = 0;
    }
    if(pdwAdvisories)
    {
        *pdwAdvisories = 0;
    }
    if(!pRepo || !pRepo->pool)
    {
        return;
    }

    FOR_REPO_SOLVABLES(pRepo, p, pSolv)
    {
        if(SolvNativeIsAdvisory(pRepo->pool, pSolv))
        {
            if(pdwAdvisories)
            {
                (*pdwAdvisories)++;
            }
        }
        else
        {
            if(pdwPackages)
            {
                (*pdwPackages)++;
            }
        }
    }
}

static int
SolvNativeCompareStringField(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszRepoName
    )
{
    const char *pszLegacy = repo_lookup_str(pLegacy, dwLegacy, dwKeyName);
    const char *pszNative = repo_lookup_str(pNative, dwNative, dwKeyName);

    if(!SolvNativeStringsEqual(pszLegacy, pszNative))
    {
        pr_err("native repomd crosscheck: repo '%s' %s mismatch legacy='%s' native='%s'\n",
               pszRepoName ? pszRepoName : "(unknown)",
               pszField,
               pszLegacy ? pszLegacy : "(null)",
               pszNative ? pszNative : "(null)");
        return 1;
    }
    return 0;
}

static int
SolvNativeCompareNumField(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszRepoName
    )
{
    unsigned long long nLegacy = repo_lookup_num(pLegacy, dwLegacy, dwKeyName, 0);
    unsigned long long nNative = repo_lookup_num(pNative, dwNative, dwKeyName, 0);

    if(nLegacy != nNative)
    {
        pr_err("native repomd crosscheck: repo '%s' %s mismatch legacy=%llu native=%llu\n",
               pszRepoName ? pszRepoName : "(unknown)",
               pszField,
               nLegacy,
               nNative);
        return 1;
    }
    return 0;
}

static int
SolvNativeCompareChecksumField(
    Solvable *pLegacy,
    Solvable *pNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszRepoName
    )
{
    Id dwLegacyType = 0;
    Id dwNativeType = 0;
    const char *pszLegacy = solvable_lookup_checksum(pLegacy, dwKeyName, &dwLegacyType);
    const char *pszNative = solvable_lookup_checksum(pNative, dwKeyName, &dwNativeType);

    if(!SolvNativeStringsEqual(pszLegacy, pszNative) ||
       !SolvNativeStringsEqual(
            dwLegacyType ? pool_id2str(pLegacy->repo->pool, dwLegacyType) : NULL,
            dwNativeType ? pool_id2str(pNative->repo->pool, dwNativeType) : NULL))
    {
        pr_err("native repomd crosscheck: repo '%s' %s mismatch legacy=%s/%s native=%s/%s\n",
               pszRepoName ? pszRepoName : "(unknown)",
               pszField,
               dwLegacyType ? pool_id2str(pLegacy->repo->pool, dwLegacyType) : "(null)",
               pszLegacy ? pszLegacy : "(null)",
               dwNativeType ? pool_id2str(pNative->repo->pool, dwNativeType) : "(null)",
               pszNative ? pszNative : "(null)");
        return 1;
    }

    return 0;
}

static int
SolvNativeCompareIdArray(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    Id dwKeyName,
    const char *pszField,
    const char *pszRepoName
    )
{
    Queue qLegacy = {0};
    Queue qNative = {0};
    int nMismatch = 0;
    int i = 0;
    Pool *pPool = pLegacy->pool;

    queue_init(&qLegacy);
    queue_init(&qNative);

    repo_lookup_idarray(pLegacy, dwLegacy, dwKeyName, &qLegacy);
    repo_lookup_idarray(pNative, dwNative, dwKeyName, &qNative);

    if(qLegacy.count != qNative.count)
    {
        nMismatch = 1;
    }
    else
    {
        for(i = 0; i < qLegacy.count; ++i)
        {
            if(qLegacy.elements[i] != qNative.elements[i])
            {
                nMismatch = 1;
                break;
            }
        }
    }

    if(nMismatch)
    {
        const char *pszLegacy = qLegacy.count > 0 ? SolvNativePoolIdToDep(pPool, qLegacy.elements[0]) : "(empty)";
        const char *pszNative = qNative.count > 0 ? SolvNativePoolIdToDep(pPool, qNative.elements[0]) : "(empty)";
        pr_err("native repomd crosscheck: repo '%s' %s mismatch legacy_count=%d native_count=%d first_legacy='%s' first_native='%s'\n",
               pszRepoName ? pszRepoName : "(unknown)",
               pszField,
               qLegacy.count,
               qNative.count,
               pszLegacy,
               pszNative);
    }

    queue_free(&qLegacy);
    queue_free(&qNative);
    return nMismatch;
}

static int
SolvNativeCompareFileLists(
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    )
{
    Dataiterator di = {0};
    Queue qLegacy = {0};
    Queue qNative = {0};
    int nMismatch = 0;
    int i = 0;
    Pool *pPool = pLegacy->pool;

    queue_init(&qLegacy);
    queue_init(&qNative);

    dataiterator_init(&di, pPool, pLegacy, dwLegacy,
                      SOLVABLE_FILELIST, NULL,
                      SEARCH_FILES | SEARCH_COMPLETE_FILELIST);
    while(dataiterator_step(&di))
    {
        queue_push(&qLegacy, pool_str2id(pPool, di.kv.str, 1));
    }
    dataiterator_free(&di);

    dataiterator_init(&di, pPool, pNative, dwNative,
                      SOLVABLE_FILELIST, NULL,
                      SEARCH_FILES | SEARCH_COMPLETE_FILELIST);
    while(dataiterator_step(&di))
    {
        queue_push(&qNative, pool_str2id(pPool, di.kv.str, 1));
    }
    dataiterator_free(&di);

    if(qLegacy.count != qNative.count)
    {
        nMismatch = 1;
    }
    else
    {
        for(i = 0; i < qLegacy.count; ++i)
        {
            if(qLegacy.elements[i] != qNative.elements[i])
            {
                nMismatch = 1;
                break;
            }
        }
    }

    if(nMismatch)
    {
        pr_err("native repomd crosscheck: repo '%s' file list mismatch legacy_count=%d native_count=%d first_legacy='%s' first_native='%s'\n",
               pszRepoName ? pszRepoName : "(unknown)",
               qLegacy.count,
               qNative.count,
               qLegacy.count > 0 ? SolvNativePoolIdToStr(pPool, qLegacy.elements[0]) : "(empty)",
               qNative.count > 0 ? SolvNativePoolIdToStr(pPool, qNative.elements[0]) : "(empty)");
    }

    queue_free(&qLegacy);
    queue_free(&qNative);
    return nMismatch;
}

static int
SolvNativeCompareChangelogs(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    )
{
    Dataiterator diLegacy = {0};
    Dataiterator diNative = {0};
    int nLegacyCount = 0;
    int nNativeCount = 0;

    dataiterator_init(&diLegacy, pPool, pLegacy, dwLegacy,
                      SOLVABLE_CHANGELOG_AUTHOR, NULL, 0);
    dataiterator_prepend_keyname(&diLegacy, SOLVABLE_CHANGELOG);
    while(dataiterator_step(&diLegacy))
    {
        nLegacyCount++;
    }
    dataiterator_free(&diLegacy);

    dataiterator_init(&diNative, pPool, pNative, dwNative,
                      SOLVABLE_CHANGELOG_AUTHOR, NULL, 0);
    dataiterator_prepend_keyname(&diNative, SOLVABLE_CHANGELOG);
    while(dataiterator_step(&diNative))
    {
        nNativeCount++;
    }
    dataiterator_free(&diNative);

    if(nLegacyCount != nNativeCount)
    {
        pr_err("native repomd crosscheck: repo '%s' changelog count mismatch legacy=%d native=%d\n",
               pszRepoName ? pszRepoName : "(unknown)",
               nLegacyCount,
               nNativeCount);
        return 1;
    }

    return 0;
}

static int
SolvNativeCompareUpdateCollections(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    )
{
    Dataiterator diLegacy = {0};
    Dataiterator diNative = {0};

    dataiterator_init(&diLegacy, pPool, pLegacy, dwLegacy, UPDATE_COLLECTION, 0, 0);
    dataiterator_init(&diNative, pPool, pNative, dwNative, UPDATE_COLLECTION, 0, 0);

    while(1)
    {
        int nHasLegacy = dataiterator_step(&diLegacy);
        int nHasNative = dataiterator_step(&diNative);
        const char *pszLegacyName = NULL;
        const char *pszNativeName = NULL;
        const char *pszLegacyEvr = NULL;
        const char *pszNativeEvr = NULL;
        const char *pszLegacyArch = NULL;
        const char *pszNativeArch = NULL;
        const char *pszLegacyFile = NULL;
        const char *pszNativeFile = NULL;
        int nLegacyReboot = 0;
        int nNativeReboot = 0;

        if(nHasLegacy != nHasNative)
        {
            pr_err("native repomd crosscheck: repo '%s' advisory package count mismatch in updateinfo\n",
                   pszRepoName ? pszRepoName : "(unknown)");
            dataiterator_free(&diLegacy);
            dataiterator_free(&diNative);
            return 1;
        }
        if(!nHasLegacy)
        {
            break;
        }

        dataiterator_setpos(&diLegacy);
        pszLegacyName = pool_lookup_str(pPool, SOLVID_POS, UPDATE_COLLECTION_NAME);
        pszLegacyEvr = pool_lookup_str(pPool, SOLVID_POS, UPDATE_COLLECTION_EVR);
        pszLegacyArch = pool_lookup_str(pPool, SOLVID_POS, UPDATE_COLLECTION_ARCH);
        pszLegacyFile = pool_lookup_str(pPool, SOLVID_POS, UPDATE_COLLECTION_FILENAME);
        nLegacyReboot = pool_lookup_void(pPool, SOLVID_POS, UPDATE_REBOOT);

        dataiterator_setpos(&diNative);
        pszNativeName = pool_lookup_str(pPool, SOLVID_POS, UPDATE_COLLECTION_NAME);
        pszNativeEvr = pool_lookup_str(pPool, SOLVID_POS, UPDATE_COLLECTION_EVR);
        pszNativeArch = pool_lookup_str(pPool, SOLVID_POS, UPDATE_COLLECTION_ARCH);
        pszNativeFile = pool_lookup_str(pPool, SOLVID_POS, UPDATE_COLLECTION_FILENAME);
        nNativeReboot = pool_lookup_void(pPool, SOLVID_POS, UPDATE_REBOOT);

        if(!SolvNativeStringsEqual(pszLegacyName, pszNativeName) ||
           !SolvNativeStringsEqual(pszLegacyEvr, pszNativeEvr) ||
           !SolvNativeStringsEqual(pszLegacyArch, pszNativeArch) ||
           !SolvNativeStringsEqual(pszLegacyFile, pszNativeFile) ||
           nLegacyReboot != nNativeReboot)
        {
            pr_err("native repomd crosscheck: repo '%s' update collection mismatch legacy=%s/%s/%s native=%s/%s/%s\n",
                   pszRepoName ? pszRepoName : "(unknown)",
                   pszLegacyName ? pszLegacyName : "(null)",
                   pszLegacyEvr ? pszLegacyEvr : "(null)",
                   pszLegacyArch ? pszLegacyArch : "(null)",
                   pszNativeName ? pszNativeName : "(null)",
                   pszNativeEvr ? pszNativeEvr : "(null)",
                   pszNativeArch ? pszNativeArch : "(null)");
            dataiterator_free(&diLegacy);
            dataiterator_free(&diNative);
            return 1;
        }
    }

    dataiterator_free(&diLegacy);
    dataiterator_free(&diNative);
    return 0;
}

static int
SolvNativeCompareUpdateReferences(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    )
{
    Dataiterator diLegacy = {0};
    Dataiterator diNative = {0};

    dataiterator_init(&diLegacy, pPool, pLegacy, dwLegacy, UPDATE_REFERENCE, 0, 0);
    dataiterator_init(&diNative, pPool, pNative, dwNative, UPDATE_REFERENCE, 0, 0);

    while(1)
    {
        int nHasLegacy = dataiterator_step(&diLegacy);
        int nHasNative = dataiterator_step(&diNative);
        const char *pszLegacyType = NULL;
        const char *pszNativeType = NULL;
        const char *pszLegacyHref = NULL;
        const char *pszNativeHref = NULL;
        const char *pszLegacyId = NULL;
        const char *pszNativeId = NULL;
        const char *pszLegacyTitle = NULL;
        const char *pszNativeTitle = NULL;

        if(nHasLegacy != nHasNative)
        {
            pr_err("native repomd crosscheck: repo '%s' update reference count mismatch\n",
                   pszRepoName ? pszRepoName : "(unknown)");
            dataiterator_free(&diLegacy);
            dataiterator_free(&diNative);
            return 1;
        }
        if(!nHasLegacy)
        {
            break;
        }

        dataiterator_setpos(&diLegacy);
        pszLegacyType = pool_lookup_str(pPool, SOLVID_POS, UPDATE_REFERENCE_TYPE);
        pszLegacyHref = pool_lookup_str(pPool, SOLVID_POS, UPDATE_REFERENCE_HREF);
        pszLegacyId = pool_lookup_str(pPool, SOLVID_POS, UPDATE_REFERENCE_ID);
        pszLegacyTitle = pool_lookup_str(pPool, SOLVID_POS, UPDATE_REFERENCE_TITLE);

        dataiterator_setpos(&diNative);
        pszNativeType = pool_lookup_str(pPool, SOLVID_POS, UPDATE_REFERENCE_TYPE);
        pszNativeHref = pool_lookup_str(pPool, SOLVID_POS, UPDATE_REFERENCE_HREF);
        pszNativeId = pool_lookup_str(pPool, SOLVID_POS, UPDATE_REFERENCE_ID);
        pszNativeTitle = pool_lookup_str(pPool, SOLVID_POS, UPDATE_REFERENCE_TITLE);

        if(!SolvNativeStringsEqual(pszLegacyType, pszNativeType) ||
           !SolvNativeStringsEqual(pszLegacyHref, pszNativeHref) ||
           !SolvNativeStringsEqual(pszLegacyId, pszNativeId) ||
           !SolvNativeStringsEqual(pszLegacyTitle, pszNativeTitle))
        {
            pr_err("native repomd crosscheck: repo '%s' update reference mismatch legacy=%s/%s native=%s/%s\n",
                   pszRepoName ? pszRepoName : "(unknown)",
                   pszLegacyType ? pszLegacyType : "(null)",
                   pszLegacyId ? pszLegacyId : "(null)",
                   pszNativeType ? pszNativeType : "(null)",
                   pszNativeId ? pszNativeId : "(null)");
            dataiterator_free(&diLegacy);
            dataiterator_free(&diNative);
            return 1;
        }
    }

    dataiterator_free(&diLegacy);
    dataiterator_free(&diNative);
    return 0;
}

static int
SolvNativeCompareSourceFields(
    Solvable *pLegacy,
    Solvable *pNative,
    const char *pszRepoName
    )
{
    if(!SolvNativeStringsEqual(solvable_lookup_str(pLegacy, SOLVABLE_SOURCENAME),
                               solvable_lookup_str(pNative, SOLVABLE_SOURCENAME)) ||
       !SolvNativeStringsEqual(solvable_lookup_str(pLegacy, SOLVABLE_SOURCEARCH),
                               solvable_lookup_str(pNative, SOLVABLE_SOURCEARCH)) ||
       !SolvNativeStringsEqual(solvable_lookup_str(pLegacy, SOLVABLE_SOURCEEVR),
                               solvable_lookup_str(pNative, SOLVABLE_SOURCEEVR)))
    {
        pr_err("native repomd crosscheck: repo '%s' source package metadata mismatch\n",
               pszRepoName ? pszRepoName : "(unknown)");
        return 1;
    }
    return 0;
}

static int
SolvNativeComparePackage(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    )
{
    Solvable *pLegacySolv = pool_id2solvable(pPool, dwLegacy);
    Solvable *pNativeSolv = pool_id2solvable(pPool, dwNative);

    if(!pLegacySolv || !pNativeSolv)
    {
        pr_err("native repomd crosscheck: repo '%s' had an internal package lookup failure\n",
               pszRepoName ? pszRepoName : "(unknown)");
        return 1;
    }

    if(SolvNativeCompareChecksumField(pLegacySolv, pNativeSolv, SOLVABLE_CHECKSUM, "checksum", pszRepoName) ||
       SolvNativeCompareChecksumField(pLegacySolv, pNativeSolv, SOLVABLE_HDRID, "hdrid", pszRepoName) ||
       SolvNativeCompareChecksumField(pLegacySolv, pNativeSolv, SOLVABLE_PKGID, "pkgid", pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_BUILDTIME, "buildtime", pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_INSTALLTIME, "installtime", pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_INSTALLSIZE, "installsize", pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_DOWNLOADSIZE, "downloadsize", pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_HEADEREND, "headerend", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_SUMMARY, "summary", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_DESCRIPTION, "description", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_PACKAGER, "packager", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_VENDOR, "vendor", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_URL, "url", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_LICENSE, "license", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_GROUP, "group", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_BUILDHOST, "buildhost", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_MEDIABASE, "mediabase", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_PROVIDES, "provides", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_REQUIRES, "requires", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_CONFLICTS, "conflicts", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_OBSOLETES, "obsoletes", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_RECOMMENDS, "recommends", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_SUGGESTS, "suggests", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_SUPPLEMENTS, "supplements", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_ENHANCES, "enhances", pszRepoName) ||
       SolvNativeCompareSourceFields(pLegacySolv, pNativeSolv, pszRepoName) ||
       SolvNativeCompareFileLists(pLegacy, dwLegacy, pNative, dwNative, pszRepoName) ||
       SolvNativeCompareChangelogs(pPool, pLegacy, dwLegacy, pNative, dwNative, pszRepoName))
    {
        pr_err("native repomd crosscheck: repo '%s' package sample '%s.%s' evr '%s' mismatched\n",
               pszRepoName ? pszRepoName : "(unknown)",
               SolvNativePoolIdToStr(pPool, pLegacySolv->name),
               SolvNativePoolIdToStr(pPool, pLegacySolv->arch),
               SolvNativePoolIdToStr(pPool, pLegacySolv->evr));
        return 1;
    }

    return 0;
}

static int
SolvNativeCompareAdvisory(
    Pool *pPool,
    Repo *pLegacy,
    Id dwLegacy,
    Repo *pNative,
    Id dwNative,
    const char *pszRepoName
    )
{
    if(SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_BUILDTIME, "advisory buildtime", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_PATCHCATEGORY, "patchcategory", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, UPDATE_STATUS, "update status", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_SUMMARY, "advisory summary", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_DESCRIPTION, "advisory description", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, UPDATE_SEVERITY, "update severity", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, UPDATE_RIGHTS, "update rights", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_CONFLICTS, "advisory conflicts", pszRepoName) ||
       SolvNativeCompareIdArray(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_PROVIDES, "advisory provides", pszRepoName) ||
       SolvNativeCompareUpdateCollections(pPool, pLegacy, dwLegacy, pNative, dwNative, pszRepoName) ||
       SolvNativeCompareUpdateReferences(pPool, pLegacy, dwLegacy, pNative, dwNative, pszRepoName) ||
       repo_lookup_void(pLegacy, dwLegacy, UPDATE_REBOOT) != repo_lookup_void(pNative, dwNative, UPDATE_REBOOT))
    {
        pr_err("native repomd crosscheck: repo '%s' advisory sample '%s' mismatched\n",
               pszRepoName ? pszRepoName : "(unknown)",
               SolvNativePoolIdToStr(pPool, pool_id2solvable(pPool, dwLegacy)->name));
        return 1;
    }

    return 0;
}

static int
SolvNativeStringsEqual(
    const char *pszLeft,
    const char *pszRight
    )
{
    if(pszLeft == pszRight)
    {
        return 1;
    }
    if(!pszLeft || !pszRight)
    {
        return 0;
    }
    return !strcmp(pszLeft, pszRight);
}

static const char*
SolvNativePoolIdToDep(
    Pool *pPool,
    Id dwId
    )
{
    if(!pPool || !dwId)
    {
        return "(null)";
    }
    return pool_dep2str(pPool, dwId);
}

static const char*
SolvNativePoolIdToStr(
    Pool *pPool,
    Id dwId
    )
{
    if(!pPool || !dwId)
    {
        return "(null)";
    }
    return pool_id2str(pPool, dwId);
}
