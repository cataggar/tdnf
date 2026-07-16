
/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

uint32_t
SolvReadYumRepo(
    Repo *pRepo,
    const char *pszRepoName,
    const char *pszRepomd,
    const char *pszPrimary,
    const char *pszFilelists,
    const char *pszUpdateinfo,
    const char *pszOther
    )
{
    uint32_t dwError = 0;

    if(!pRepo || !pszRepoName || !pszRepomd || !pszPrimary)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    dwError = SolvReadYumRepoNative(
                  pRepo,
                  pszRepomd,
                  pszPrimary,
                  pszFilelists,
                  pszUpdateinfo,
                  pszOther);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

cleanup:

    return dwError;

error:
    goto cleanup;
}

uint32_t
SolvCountPackages(
    PSolvSack pSack,
    uint32_t* pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    const Pool* pool = 0;
    Id p = 0;
    if(!pSack || !pSack->pPool || !pdwCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    pool = pSack->pPool;
    FOR_POOL_SOLVABLES(p)
    {
        if (pool->considered && !MAPTST(pool->considered, p))
            continue;
        dwCount++;
    }
    *pdwCount = dwCount;
cleanup:
    return dwError;
error:
    goto cleanup;

}

static
uint32_t
readRpmsFromDir(
    Repo *pRepo,
    const char *pszDir
)
{
    uint32_t dwError = 0;
    DIR *pDir = NULL;
    struct dirent *pEnt = NULL;
    char *pszPath = NULL;

    pDir = opendir(pszDir);
    if(pDir == NULL) {
        dwError = errno;
        BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
    }
    while ((pEnt = readdir (pDir)) != NULL ) {
        int isDir;

        if (pEnt->d_name[0] == '.') {
            /* skip '.', '..', but also any dir name starting with '.' */
            continue;
        }

        dwError = TDNFJoinPath(
                      &pszPath,
                      pszDir,
                      pEnt->d_name,
                      NULL);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFIsDir(pszPath, &isDir);
        if (dwError) {
            pr_err("ReadRpms: Error while operating on '%s', '%s'\n",
                    pszPath, strerror(errno));
        }
        BAIL_ON_TDNF_ERROR(dwError);

        if (isDir) {
            dwError = readRpmsFromDir(pRepo, pszPath);
            BAIL_ON_TDNF_ERROR(dwError);
        } else if (strcmp(&pEnt->d_name[strlen(pEnt->d_name)-4], ".rpm") == 0) {
            dwError = SolvAddRpmNative(
                          pRepo,
                          pszPath,
                          REPO_REUSE_REPODATA|REPO_NO_INTERNALIZE,
                          NULL);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        TDNF_SAFE_FREE_MEMORY(pszPath);
    }
cleanup:
    if(pDir) {
        closedir(pDir);
    }
    TDNF_SAFE_FREE_MEMORY(pszPath);

    return dwError;

error:
    goto cleanup;
}

static uint32_t
SolvGetInstalledRepoCachePath(
    const char *pszCacheDir,
    const char *pszFileName,
    char **ppszPath
    )
{
    uint32_t dwError = 0;
    char *pszSolvCacheDir = NULL;
    char *pszPath = NULL;

    if(ppszPath)
    {
        *ppszPath = NULL;
    }

    if(IsNullOrEmptyString(pszCacheDir) ||
       IsNullOrEmptyString(pszFileName) ||
       !ppszPath)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFJoinPath(
                  &pszSolvCacheDir,
                  pszCacheDir,
                  TDNF_SOLVCACHE_DIR_NAME,
                  NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFJoinPath(
                  &pszPath,
                  pszSolvCacheDir,
                  pszFileName,
                  NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    *ppszPath = pszPath;

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszSolvCacheDir);
    return dwError;

error:
    TDNF_SAFE_FREE_MEMORY(pszPath);
    goto cleanup;
}

static void
SolvTrimLineEnding(
    char *pszValue
    )
{
    size_t nLen = 0;

    if(IsNullOrEmptyString(pszValue))
    {
        return;
    }

    nLen = strlen(pszValue);
    while(nLen > 0 &&
          (pszValue[nLen - 1] == '\n' || pszValue[nLen - 1] == '\r'))
    {
        pszValue[--nLen] = '\0';
    }
}

static int
SolvUseInstalledRepoCache(
    Repo *pRepo,
    const char *pszCacheDir,
    const char *pszCookie
    )
{
    uint32_t dwError = 0;
    FILE *pSolvFile = NULL;
    FILE *pCookieFile = NULL;
    char *pszSolvPath = NULL;
    char *pszCookiePath = NULL;
    char szCookie[128] = {0};
    int nUseInstalledCache = 0;

    if(!pRepo ||
       IsNullOrEmptyString(pszCacheDir) ||
       IsNullOrEmptyString(pszCookie))
    {
        goto cleanup;
    }

    dwError = SolvGetInstalledRepoCachePath(
                  pszCacheDir,
                  SYSTEM_REPO_NAME ".solv",
                  &pszSolvPath);
    if(dwError)
    {
        goto cleanup;
    }

    dwError = SolvGetInstalledRepoCachePath(
                  pszCacheDir,
                  SYSTEM_REPO_NAME ".cookie",
                  &pszCookiePath);
    if(dwError)
    {
        goto cleanup;
    }

    pCookieFile = fopen(pszCookiePath, "r");
    if(!pCookieFile)
    {
        goto cleanup;
    }
    if(!fgets(szCookie, sizeof(szCookie), pCookieFile))
    {
        goto cleanup;
    }
    SolvTrimLineEnding(szCookie);

    if(strcmp(szCookie, pszCookie))
    {
        goto cleanup;
    }

    pSolvFile = fopen(pszSolvPath, "r");
    if(!pSolvFile)
    {
        goto cleanup;
    }

    if(repo_add_solv(pRepo, pSolvFile, 0))
    {
        repo_empty(pRepo, 1);
        if(!IsNullOrEmptyString(pszSolvPath))
        {
            unlink(pszSolvPath);
        }
        if(!IsNullOrEmptyString(pszCookiePath))
        {
            unlink(pszCookiePath);
        }
        goto cleanup;
    }

    nUseInstalledCache = 1;

cleanup:
    if(pSolvFile)
    {
        fclose(pSolvFile);
    }
    if(pCookieFile)
    {
        fclose(pCookieFile);
    }
    TDNF_SAFE_FREE_MEMORY(pszSolvPath);
    TDNF_SAFE_FREE_MEMORY(pszCookiePath);
    return nUseInstalledCache;
}

static void
SolvCreateInstalledRepoCache(
    Repo *pRepo,
    const char *pszCacheDir,
    const char *pszCookie
    )
{
    uint32_t dwError = 0;
    FILE *pSolvFile = NULL;
    FILE *pCookieFile = NULL;
    char *pszSolvCacheDir = NULL;
    char *pszSolvPath = NULL;
    char *pszCookiePath = NULL;
    char *pszTempSolvFile = NULL;
    int fd = -1;
    mode_t mask = 0;

    if(!pRepo ||
       IsNullOrEmptyString(pszCacheDir) ||
       IsNullOrEmptyString(pszCookie))
    {
        goto cleanup;
    }

    dwError = TDNFJoinPath(
                  &pszSolvCacheDir,
                  pszCacheDir,
                  TDNF_SOLVCACHE_DIR_NAME,
                  NULL);
    if(dwError)
    {
        goto cleanup;
    }

    if(access(pszSolvCacheDir, W_OK | X_OK))
    {
        if(errno != ENOENT)
        {
            goto cleanup;
        }

        dwError = TDNFUtilsMakeDirs(pszSolvCacheDir);
        if(dwError == ERROR_TDNF_ALREADY_EXISTS)
        {
            dwError = 0;
        }
        if(dwError)
        {
            goto cleanup;
        }
    }

    dwError = SolvGetInstalledRepoCachePath(
                  pszCacheDir,
                  SYSTEM_REPO_NAME ".solv",
                  &pszSolvPath);
    if(dwError)
    {
        goto cleanup;
    }

    dwError = SolvGetInstalledRepoCachePath(
                  pszCacheDir,
                  SYSTEM_REPO_NAME ".cookie",
                  &pszCookiePath);
    if(dwError)
    {
        goto cleanup;
    }

    pszTempSolvFile = solv_dupjoin(pszSolvCacheDir, "/", ".newsolv-XXXXXX");
    if(!pszTempSolvFile)
    {
        goto cleanup;
    }

    mask = umask(S_IRUSR | S_IWUSR | S_IRWXG);
    umask(mask);
    fd = mkstemp(pszTempSolvFile);
    if(fd < 0)
    {
        goto cleanup;
    }

    fchmod(fd, 0444);
    pSolvFile = fdopen(fd, "w");
    if(!pSolvFile)
    {
        close(fd);
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    if(repo_write(pRepo, pSolvFile))
    {
        goto cleanup;
    }

    if(fclose(pSolvFile))
    {
        pSolvFile = NULL;
        goto cleanup;
    }
    pSolvFile = NULL;

    if(rename(pszTempSolvFile, pszSolvPath) == -1)
    {
        goto cleanup;
    }
    unlink(pszTempSolvFile);

    pCookieFile = fopen(pszCookiePath, "w");
    if(!pCookieFile)
    {
        goto cleanup;
    }
    if(fputs(pszCookie, pCookieFile) == EOF ||
       fputc('\n', pCookieFile) == EOF)
    {
        goto cleanup;
    }
    fclose(pCookieFile);
    pCookieFile = NULL;

cleanup:
    if(pCookieFile)
    {
        fclose(pCookieFile);
    }
    if(pSolvFile)
    {
        fclose(pSolvFile);
        if(!IsNullOrEmptyString(pszTempSolvFile))
        {
            unlink(pszTempSolvFile);
        }
    }
    else if(fd >= 0)
    {
        close(fd);
        if(!IsNullOrEmptyString(pszTempSolvFile))
        {
            unlink(pszTempSolvFile);
        }
    }
    TDNF_SAFE_FREE_MEMORY(pszTempSolvFile);
    TDNF_SAFE_FREE_MEMORY(pszSolvCacheDir);
    TDNF_SAFE_FREE_MEMORY(pszSolvPath);
    TDNF_SAFE_FREE_MEMORY(pszCookiePath);
}

uint32_t
SolvReadRpmsFromDirectory(
    Repo *pRepo,
    const char *pszDir
    )
{
    uint32_t dwError = 0;

    if(!pRepo || IsNullOrEmptyString(pszDir))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    dwError = readRpmsFromDir(pRepo, pszDir);
    BAIL_ON_TDNF_ERROR(dwError);

    repo_internalize(pRepo);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
SolvReadInstalledRpms(
    Repo* pRepo,
    const char *pszCacheFileName,
    const tdnf_rpm_config *pRpmConfig
    )
{
    uint32_t dwError = 0;
    const char *pszRootDir = NULL;
    char *pszCookie = NULL;
    int  dwFlags = 0;
    int nUseInstalledCache = 0;

    if(!pRepo || !pRepo->pool)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    pszRootDir = pool_get_rootdir(pRepo->pool);
    if(!IsNullOrEmptyString(pszCacheFileName))
    {
        pszCookie = pRpmConfig ?
                        tdnf_rpmdb_cookie_config(pRpmConfig) :
                        tdnf_rpmdb_cookie(pszRootDir);
        nUseInstalledCache = SolvUseInstalledRepoCache(
                                 pRepo,
                                 pszCacheFileName,
                                 pszCookie);
    }

    if(nUseInstalledCache)
    {
        goto cleanup;
    }

    dwFlags = REPO_REUSE_REPODATA | RPM_ADD_WITH_HDRID | REPO_USE_ROOTDIR;
    dwError = SolvReadInstalledRpmsNative(
                  pRepo,
                  pszRootDir,
                  pRpmConfig,
                  dwFlags);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

    SolvCreateInstalledRepoCache(pRepo, pszCacheFileName, pszCookie);

cleanup:
    if(pszCookie)
    {
        tdnf_rpmdb_string_free(pszCookie);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
SolvCalculateCookieForFile(
    const char *pszFilePath,
    unsigned char *pszCookie
    )
{
    FILE *fp = NULL;
    int32_t nLen = 0;
    uint32_t dwError = 0;
    Chksum *pChkSum = NULL;
    char buf[BUFSIZ] = {0};

    if (!pszFilePath)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    fp = fopen(pszFilePath, "r");
    if (!fp)
    {
        dwError = ERROR_TDNF_SOLV_IO;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    pChkSum = solv_chksum_create(REPOKEY_TYPE_SHA256);
    if (!pChkSum)
    {
        dwError = ERROR_TDNF_SOLV_CHKSUM;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    solv_chksum_add(pChkSum, SOLV_COOKIE_IDENT, strlen(SOLV_COOKIE_IDENT));

    while ((nLen = fread(buf, 1, sizeof(buf) - 1, fp)) > 0)
    {
          solv_chksum_add(pChkSum, buf, nLen);
          memset(buf, 0, sizeof(buf));
    }
    solv_chksum_free(pChkSum, pszCookie);

cleanup:
    if (fp)
    {
        fclose(fp);
    }

    return dwError;

error:
    goto cleanup;
}

/* Create a name for the repo cache path based on repo name and
   a hash of the url.
*/
uint32_t
SolvCreateRepoCacheName(
    const char *pszName,
    const char *pszUrl,
    char **ppszCacheName
    )
{
    uint32_t dwError = 0;
    Chksum *pChkSum = NULL;
    unsigned char pCookie[SOLV_COOKIE_LEN] = {0};
    char pszCookie[9] = {0};
    char *pszCacheName = NULL;

    if (!pszName || !pszUrl || !ppszCacheName)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    pChkSum = solv_chksum_create(REPOKEY_TYPE_SHA256);
    if (!pChkSum)
    {
        dwError = ERROR_TDNF_SOLV_CHKSUM;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    solv_chksum_add(pChkSum, pszUrl, strlen(pszUrl));
    solv_chksum_free(pChkSum, pCookie);

    snprintf(pszCookie, sizeof(pszCookie), "%.2x%.2x%.2x%.2x",
             pCookie[0], pCookie[1], pCookie[2], pCookie[3]);

    dwError = TDNFAllocateStringPrintf(&pszCacheName, "%s-%s", pszName, pszCookie);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

    *ppszCacheName = pszCacheName;
cleanup:
    return dwError;

error:
    TDNF_SAFE_FREE_MEMORY(pszCacheName);
    goto cleanup;
}

uint32_t
SolvGetMetaDataCachePath(
    PSOLV_REPO_INFO_INTERNAL pSolvRepoInfo,
    char** ppszCachePath
    )
{
    char *pszCachePath = NULL;
    uint32_t dwError = 0;
    Repo *pRepo = NULL;

    if (!pSolvRepoInfo || !pSolvRepoInfo->pRepo || !ppszCachePath)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    pRepo = pSolvRepoInfo->pRepo;
    if (!IsNullOrEmptyString(pRepo->name))
    {
        dwError = TDNFAllocateStringPrintf(
                      &pszCachePath,
                      "%s/%s/%s.solv",
                      pSolvRepoInfo->pszRepoCacheDir,
                      TDNF_SOLVCACHE_DIR_NAME,
                      pRepo->name);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    *ppszCachePath = pszCachePath;
cleanup:
    return dwError;
error:
    TDNF_SAFE_FREE_MEMORY(pszCachePath);
    goto cleanup;
}

uint32_t
SolvAddSolvMetaData(
    PSOLV_REPO_INFO_INTERNAL pSolvRepoInfo,
    const char *pszTempSolvFile
    )
{
    uint32_t dwError = 0;
    Repo *pRepo = NULL;
    FILE *fp = NULL;
    int i = 0;

    if (!pSolvRepoInfo || !pSolvRepoInfo->pRepo || !pszTempSolvFile)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    pRepo = pSolvRepoInfo->pRepo;
    if (!pRepo->pool)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    for (i = pRepo->start; i < pRepo->end; i++)
    {
         if (pRepo->pool->solvables[i].repo != pRepo)
         {
             break;
         }
    }
    if (i < pRepo->end)
    {
        goto cleanup;
    }
    fp = fopen (pszTempSolvFile, "r");
    if (fp == NULL)
    {
        dwError = errno;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    repo_empty(pRepo, 1);
    if (repo_add_solv(pRepo, fp, SOLV_ADD_NO_STUBS))
    {
        dwError = ERROR_TDNF_ADD_SOLV;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

cleanup:
    if (fp != NULL)
    {
        fclose(fp);
    }
    return dwError;
error:
    goto cleanup;
}

uint32_t
SolvUseMetaDataCache(
    const PSolvSack pSack,
    PSOLV_REPO_INFO_INTERNAL pSolvRepoInfo,
    int       *nUseMetaDataCache
    )
{
    uint32_t dwError = 0;
    FILE *fp = NULL;
    Repo *pRepo = NULL;
    const unsigned char *pszCookie = NULL;
    unsigned char pszTempCookie[32];
    char *pszCacheFilePath = NULL;

    if (!pSack || !pSolvRepoInfo || !pSolvRepoInfo->pRepo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    pRepo = pSolvRepoInfo->pRepo;
    pszCookie = pSolvRepoInfo->nCookieSet ? pSolvRepoInfo->cookie : NULL;

    dwError = SolvGetMetaDataCachePath(pSolvRepoInfo, &pszCacheFilePath);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

    if (IsNullOrEmptyString(pszCacheFilePath))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    fp = fopen(pszCacheFilePath, "r");
    if (fp == NULL)
    {
        dwError = ERROR_TDNF_SOLV_CACHE_NOT_CREATED;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    // Reading the cookie from cached Solv File
    if (fseek (fp, -sizeof(pszTempCookie), SEEK_END) || fread (pszTempCookie, sizeof(pszTempCookie), 1, fp) != 1)
    {
        dwError = ERROR_TDNF_SOLV_IO;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    // compare the calculated cookie with the one read from Solv file
    if (pszCookie && memcmp (pszCookie, pszTempCookie, sizeof(pszTempCookie)) != 0)
    {
        dwError = ERROR_TDNF_SOLV_IO;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    rewind(fp);
    if (repo_add_solv(pRepo, fp, 0))
    {
        dwError = ERROR_TDNF_ADD_SOLV;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    *nUseMetaDataCache = 1;

cleanup:
    if (fp != NULL)
    {
       fclose(fp);
    }
    TDNF_SAFE_FREE_MEMORY(pszCacheFilePath);
    return dwError;
error:
    if (dwError == ERROR_TDNF_SOLV_CACHE_NOT_CREATED)
    {
        dwError = 0;
    }
    goto cleanup;
}

uint32_t
SolvCreateMetaDataCache(
    const PSolvSack pSack,
    PSOLV_REPO_INFO_INTERNAL pSolvRepoInfo
    )
{
    uint32_t dwError = 0;
    Repo *pRepo = NULL;
    FILE *fp = NULL;
    int fd = 0;
    char *pszSolvCacheDir = NULL;
    char *pszTempSolvFile = NULL;
    char *pszCacheFilePath = NULL;
    mode_t mask = 0;

    if (!pSack || !pSolvRepoInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    pRepo = pSolvRepoInfo->pRepo;
    dwError = TDNFJoinPath(
                  &pszSolvCacheDir,
                  pSolvRepoInfo->pszRepoCacheDir,
                  TDNF_SOLVCACHE_DIR_NAME,
                  NULL);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

    if (access(pszSolvCacheDir, W_OK | X_OK))
    {
        if(errno != ENOENT)
        {
            dwError = errno;
        }
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

        dwError = TDNFUtilsMakeDirs(pszSolvCacheDir);
        if (dwError == ERROR_TDNF_ALREADY_EXISTS)
        {
            dwError = 0;
        }
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    pszTempSolvFile = solv_dupjoin(pszSolvCacheDir, "/", ".newsolv-XXXXXX");
    mask = umask(S_IRUSR | S_IWUSR | S_IRWXG);
    umask(mask);
    fd = mkstemp(pszTempSolvFile);
    if (fd < 0)
    {
        dwError = ERROR_TDNF_SOLV_IO;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    fchmod(fd, 0444);
    fp = fdopen(fd, "w");
    if (fp == NULL)
    {
        dwError = ERROR_TDNF_SOLV_IO;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    if (repo_write(pRepo, fp))
    {
        dwError = ERROR_TDNF_REPO_WRITE;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    if (pSolvRepoInfo->nCookieSet)
    {
        if (fwrite(pSolvRepoInfo->cookie, SOLV_COOKIE_LEN, 1, fp) != 1)
        {
            dwError = ERROR_TDNF_SOLV_IO;
            BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
        }
    }

    if (fclose(fp))
    {
        fp = NULL;/* so that error branch will not attempt to close again */
        dwError = ERROR_TDNF_SOLV_IO;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    fp = NULL;
    dwError = SolvAddSolvMetaData(pSolvRepoInfo, pszTempSolvFile);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

    dwError = SolvGetMetaDataCachePath(pSolvRepoInfo, &pszCacheFilePath);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

    if (IsNullOrEmptyString(pszCacheFilePath))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    if (rename(pszTempSolvFile, pszCacheFilePath) == -1)
    {
        dwError = ERROR_TDNF_SYSTEM_BASE + errno;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }
    unlink(pszTempSolvFile);
cleanup:
    TDNF_SAFE_FREE_MEMORY(pszTempSolvFile);
    TDNF_SAFE_FREE_MEMORY(pszSolvCacheDir);
    TDNF_SAFE_FREE_MEMORY(pszCacheFilePath);
    return dwError;
error:
    if (fp != NULL)
    {
        fclose(fp);
        unlink(pszTempSolvFile);
    }
    else if (fd > 0)
    {
        close(fd);
        unlink(pszTempSolvFile);
    }
    goto cleanup;
}
