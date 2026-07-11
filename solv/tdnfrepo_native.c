#define _GNU_SOURCE 1
#include "includes.h"

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
SolvNativeCompareChecksum(
    Solvable *pLegacy,
    Solvable *pNative,
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

void
SolvLogNativeRepoMismatch(
    const char *pszRepoName,
    Repo *pLegacy,
    Repo *pNative
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
        return;
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
    }
    if(dwLegacyAdvisories != dwNativeAdvisories)
    {
        pr_err("native repomd crosscheck: repo '%s' advisory count mismatch legacy=%u native=%u\n",
               pszRepoName ? pszRepoName : "(unknown)",
               dwLegacyAdvisories,
               dwNativeAdvisories);
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
            return;
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
                return;
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
                return;
            }
        }
    }

    pr_err("native repomd crosscheck: repo '%s' serialized output differed but no focused field mismatch was isolated\n",
           pszRepoName ? pszRepoName : "(unknown)");
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
SolvNativeCompareChecksum(
    Solvable *pLegacy,
    Solvable *pNative,
    const char *pszRepoName
    )
{
    Id dwLegacyType = 0;
    Id dwNativeType = 0;
    const char *pszLegacy = solvable_lookup_checksum(pLegacy, SOLVABLE_CHECKSUM, &dwLegacyType);
    const char *pszNative = solvable_lookup_checksum(pNative, SOLVABLE_CHECKSUM, &dwNativeType);

    if(!SolvNativeStringsEqual(pszLegacy, pszNative) ||
       !SolvNativeStringsEqual(
            dwLegacyType ? pool_id2str(pLegacy->repo->pool, dwLegacyType) : NULL,
            dwNativeType ? pool_id2str(pNative->repo->pool, dwNativeType) : NULL))
    {
        pr_err("native repomd crosscheck: repo '%s' checksum mismatch legacy=%s/%s native=%s/%s\n",
               pszRepoName ? pszRepoName : "(unknown)",
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

    if(SolvNativeCompareChecksum(pLegacySolv, pNativeSolv, pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_BUILDTIME, "buildtime", pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_INSTALLSIZE, "installsize", pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_DOWNLOADSIZE, "downloadsize", pszRepoName) ||
       SolvNativeCompareNumField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_HEADEREND, "headerend", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_SUMMARY, "summary", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_DESCRIPTION, "description", pszRepoName) ||
       SolvNativeCompareStringField(pLegacy, dwLegacy, pNative, dwNative, SOLVABLE_PACKAGER, "packager", pszRepoName) ||
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
