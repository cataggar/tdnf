/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

static
uint32_t
TDNFGoalObserveNativeSolver(
    PTDNF pTdnf,
    const Queue *pQueueJobs,
    const TDNF_SOLVED_PKG_INFO *pInfo,
    int nAllowErasing,
    int nAutoErase,
    int nProblems, int nUnresolved
);

static
uint32_t
TDNFGoalBuildNativeSolverRepoInputs(
    PTDNF pTdnf,
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY *ppRepos,
    uint32_t *pdwRepoCount
);

static
void
TDNFGoalFreeNativeSolverRepoInputs(
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY pRepos,
    uint32_t dwRepoCount
);

static
uint32_t
TDNFGoalBuildNativeSolverJobs(
    PTDNF pTdnf,
    const Queue *pQueueJobs,
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *ppJobs, uint32_t *pdwJobCount,
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *ppEraseJobs, uint32_t *pdwEraseJobCount,
    int *pnUpdateAll, int *pnDistSyncAll
);

static
void
TDNFGoalFreeNativeSolverJobs(
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB pJobs,
    uint32_t dwJobCount
);

static
int
TDNFGoalIsNativeSolverPackage(
    Pool *pPool,
    Solvable *pSolvable
);

static
uint32_t
TDNFGoalBuildNativeSolverHiddenAvailable(
    PTDNF pTdnf,
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *ppHiddenAvailable,
    uint32_t *pdwHiddenAvailableCount
);

static
uint32_t
TDNFGoalGetAllResultsIgnoreNoData(
    Transaction* pTrans,
    const Solver* pSolv,
    PTDNF_SOLVED_PKG_INFO* ppInfo,
    PTDNF pTdnf,
    int nReInstall
);

uint32_t
TDNFGetPackagesWithSpecifiedType(
    Transaction* pTrans,
    PTDNF pTdnf,
    PTDNF_PKG_INFO* pPkgInfo,
    Id dwType)
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    PSolvPackageList pPkgList = NULL;

    if(!pTdnf || !pTdnf->pSack|| !pTrans || !pPkgInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = SolvGetTransResultsWithType(
                  pTrans,
                  dwType,
                  &pPkgList);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = SolvGetPackageListSize(pPkgList, &dwCount);
    BAIL_ON_TDNF_ERROR(dwError);

    if(dwCount > 0)
    {
        dwError = TDNFPopulatePkgInfos(
                      pTdnf->pSack,
                      pPkgList,
                      pPkgInfo);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    if(pPkgList)
    {
        SolvFreePackageList(pPkgList);
    }
    return dwError;

error:
    if(dwError == ERROR_TDNF_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

uint32_t
TDNFGetInstallPackages(
    Transaction* pTrans,
    PTDNF pTdnf,
    PTDNF_PKG_INFO* pPkgInfo)
{
    return TDNFGetPackagesWithSpecifiedType(
               pTrans,
               pTdnf,
               pPkgInfo,
               SOLVER_TRANSACTION_INSTALL);
}

uint32_t
TDNFGetReinstallPackages(
    Transaction* pTrans,
    PTDNF pTdnf,
    PTDNF_PKG_INFO* pPkgInfo)
{
    return TDNFGetPackagesWithSpecifiedType(
               pTrans,
               pTdnf,
               pPkgInfo,
               SOLVER_TRANSACTION_REINSTALL);
}

uint32_t
TDNFGetUpgradePackages(
    Transaction* pTrans,
    PTDNF pTdnf,
    PTDNF_PKG_INFO* pPkgInfo)
{
    return TDNFGetPackagesWithSpecifiedType(
               pTrans,
               pTdnf,
               pPkgInfo,
               SOLVER_TRANSACTION_UPGRADE);
}

uint32_t
TDNFGetErasePackages(
    Transaction* pTrans,
    PTDNF pTdnf,
    PTDNF_PKG_INFO* pPkgInfo)
{
    return TDNFGetPackagesWithSpecifiedType(
               pTrans,
               pTdnf,
               pPkgInfo,
               SOLVER_TRANSACTION_ERASE);
}

uint32_t
TDNFGetObsoletedPackages(
    Transaction* pTrans,
    PTDNF pTdnf,
    PTDNF_PKG_INFO* pPkgInfo)
{
    return TDNFGetPackagesWithSpecifiedType(
               pTrans,
               pTdnf,
               pPkgInfo,
               SOLVER_TRANSACTION_OBSOLETED);
}

uint32_t
TDNFGetDownGradePackages(
    Transaction* pTrans,
    PTDNF pTdnf,
    PTDNF_PKG_INFO* pPkgInfo,
    PTDNF_PKG_INFO* pRemovePkgInfo)
{
    uint32_t dwError = 0;
    PSolvPackageList pInstalledPkgList = NULL;
    Id dwInstalledId = 0;
    PSolvPackageList pRemovePkgList = NULL;
    PTDNF_PKG_INFO pInfo = NULL;
    Queue queuePkgToRemove = {0};

    if(!pTdnf || !pTdnf->pSack|| !pTrans || !pPkgInfo || !pRemovePkgInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    queue_init(&queuePkgToRemove);
    dwError = TDNFGetPackagesWithSpecifiedType(
                  pTrans,
                  pTdnf,
                  pPkgInfo,
                  SOLVER_TRANSACTION_DOWNGRADE);
    BAIL_ON_TDNF_ERROR(dwError);
    pInfo = *pPkgInfo;
    if(!pInfo)
    {
        dwError = ERROR_TDNF_NO_DATA;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    while(pInfo)
    {
        dwError = SolvFindInstalledPkgByName(
                      pTdnf->pSack,
                      pInfo->pszName,
                      &pInstalledPkgList);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = SolvGetPackageId(pInstalledPkgList, 0, &dwInstalledId);
        BAIL_ON_TDNF_ERROR(dwError);
        queue_push(&queuePkgToRemove, dwInstalledId);
        pInfo = pInfo->pNext;
        SolvFreePackageList(pInstalledPkgList);
        pInstalledPkgList = NULL;
    }

    if(queuePkgToRemove.count > 0)
    {
        dwError = SolvQueueToPackageList(&queuePkgToRemove, &pRemovePkgList);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFPopulatePkgInfos(
                      pTdnf->pSack,
                      pRemovePkgList,
                      pRemovePkgInfo);
        BAIL_ON_TDNF_ERROR(dwError);
    }
cleanup:
    queue_free(&queuePkgToRemove);
    if(pRemovePkgList)
    {
        SolvFreePackageList(pRemovePkgList);
    }
    if(pInstalledPkgList)
    {
        SolvFreePackageList(pInstalledPkgList);
    }
    return dwError;

error:
    if(dwError == ERROR_TDNF_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

static uint32_t
SolvAddDebugInfo(
    Solver *pSolv,
    const char *pszDir
    )
{
    uint32_t dwError = 0;
    uint32_t dwResultFlags = TESTCASE_RESULT_TRANSACTION |
                             TESTCASE_RESULT_PROBLEMS;
    if(!pSolv || IsNullOrEmptyString(pszDir))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //returns 1 for success.
    dwError = testcase_write(pSolv, pszDir, dwResultFlags, NULL, NULL);
    if(dwError == 0)
    {
        pr_err("Could not write debugdata to folder %s\n", pszDir);
    }
    //need not fail if debugdata write fails.
    dwError = 0;

cleanup:
    return dwError;

error:
    goto cleanup;
}

static
uint32_t
TDNFAddUserInstalledToJobs(
    PTDNF pTdnf,
    Queue* pQueueJobs
    )
{
    uint32_t dwError = 0;
    struct history_ctx *pHistoryCtx = NULL;

    if(!pTdnf || !pQueueJobs)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGetHistoryCtx(pTdnf, &pHistoryCtx, 1);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = SolvAddUserInstalledToJobs(pQueueJobs,
                                         pTdnf->pSack->pPool,
                                         pHistoryCtx);
    BAIL_ON_TDNF_ERROR(dwError);
cleanup:
    if (pHistoryCtx)
    {
        destroy_history_ctx(pHistoryCtx);
    }
    return dwError;
error:
    goto cleanup;
}

static
uint32_t
TDNFSolv(
    PTDNF pTdnf,
    Queue *pQueueJobs,
    char** ppszExcludes,
    uint32_t dwExcludeCount,
    int nAllowErasing,
    int nAutoErase,
    int nReInstall, int nUnresolved,
    PTDNF_SOLVED_PKG_INFO* ppInfo
    )
{
    uint32_t dwError = 0;
    PTDNF_SOLVED_PKG_INFO pInfo = NULL;
    TDNF_SKIPPROBLEM_TYPE dwSkipProblem = SKIPPROBLEM_NONE;
    Solver *pSolv = NULL;
    Transaction *pTrans = NULL;
    int nFlags = 0;
    int nProblems = 0;
    int retries = 0;

    if(!pTdnf || !ppInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(pTdnf->pArgs->nBest)
    {
        nFlags = nFlags | SOLVER_FORCEBEST;
    }
    if (nAutoErase)
    {
        nFlags = nFlags | SOLVER_CLEANDEPS;
    }

    dwError = SolvAddFlagsToJobs(pQueueJobs, nFlags);
    BAIL_ON_TDNF_ERROR(dwError);

    if (dwExcludeCount != 0 && ppszExcludes)
    {
        if (!pTdnf->pSack || !pTdnf->pSack->pPool)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        dwError = SolvAddExcludes(pTdnf->pSack->pPool, ppszExcludes);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFSolvAddInstallOnlyPkgs(pTdnf, pQueueJobs, pTdnf->pSack->pPool);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFSolvAddPkgLocks(pTdnf, pQueueJobs, pTdnf->pSack->pPool);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFSolvAddMinVersions(pTdnf, pTdnf->pSack->pPool);
    BAIL_ON_TDNF_ERROR(dwError);

    pSolv = solver_create(pTdnf->pSack->pPool);
    if(pSolv == NULL)
    {
        dwError = ERROR_TDNF_OUT_OF_MEMORY;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(nAllowErasing)
    {
        if (pTdnf->pConf->ppszProtectedPkgs) {
            dwError = TDNFSolvAddProtectPkgs(pTdnf, pQueueJobs, pTdnf->pSack->pPool);
            BAIL_ON_TDNF_ERROR(dwError);
        } else {
            solver_set_flag(pSolv, SOLVER_FLAG_ALLOW_UNINSTALL, 1);
        }
    }
    solver_set_flag(pSolv, SOLVER_FLAG_BEST_OBEY_POLICY, 1);
    solver_set_flag(pSolv, SOLVER_FLAG_ALLOW_VENDORCHANGE, 1);
    solver_set_flag(pSolv, SOLVER_FLAG_KEEP_ORPHANS, 1);
    solver_set_flag(pSolv, SOLVER_FLAG_BEST_OBEY_POLICY, 1);
    solver_set_flag(pSolv, SOLVER_FLAG_YUM_OBSOLETES, 1);
    solver_set_flag(pSolv, SOLVER_FLAG_ALLOW_DOWNGRADE, 1);
    solver_set_flag(pSolv, SOLVER_FLAG_INSTALL_ALSO_UPDATES, 1);

    do {
        /* in case this is second or later try */
        if(pTrans)
        {
            transaction_free(pTrans);
            pTrans = NULL;
        }

        nProblems = solver_solve(pSolv, pQueueJobs);
        if (nProblems > 0)
        {
            dwError = TDNFGetSkipProblemOption(pTdnf, &dwSkipProblem);
            BAIL_ON_TDNF_ERROR(dwError);
            dwError = SolvReportProblems(pTdnf->pSack, pSolv, dwSkipProblem);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        pTrans = solver_create_transaction(pSolv);
        if(!pTrans)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if (pTdnf->pConf->ppszProtectedPkgs) {
            /* catch protected obsoleted packages, and double check for removals */
            dwError = TDNFSolvCheckProtectPkgsInTrans(pTdnf, pTrans, pTdnf->pSack->pPool);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if (pTdnf->pConf->ppszInstallOnlyPkgs) {
            /* check if we are going to exceed the installonly limit */
            /* if so, removal jobs will be added and we'll try to solve again */
            dwError = TDNFSolvCheckInstallOnlyLimitInTrans(pTdnf, pTrans, pTdnf->pSack->pPool, pQueueJobs);
            if (dwError != ERROR_TDNF_INSTALLONLY_LIMIT_EXCEEDED) {
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
        retries++;
    } while (dwError == ERROR_TDNF_INSTALLONLY_LIMIT_EXCEEDED && retries < 2);
    BAIL_ON_TDNF_ERROR(dwError);

    if(pTdnf->pArgs->nDebugSolver)
    {
        dwError = SolvAddDebugInfo(pSolv, "debugdata");
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGoalGetAllResultsIgnoreNoData(
                  pTrans,
                  pSolv,
                  &pInfo,
                  pTdnf,
                  nReInstall);
    BAIL_ON_TDNF_ERROR(dwError);

    if(pTdnf->pArgs->nDebugSolver)
    {
        uint32_t dwShadowError = TDNFGoalObserveNativeSolver(
                                     pTdnf,
                                     pQueueJobs,
                                     pInfo,
                                     nAllowErasing,
                                     nAutoErase,
                                     nProblems, nUnresolved);
        if(dwShadowError)
        {
            pr_info("native-solver-shadow: unavailable (%u)\n",
                    dwShadowError);
        }
    }

    *ppInfo = pInfo;

cleanup:
    if(pTrans)
    {
        transaction_free(pTrans);
    }
    if(pSolv)
    {
        solver_free(pSolv);
    }
    return dwError;

error:
    TDNF_SAFE_FREE_MEMORY(pInfo);
    if(ppInfo)
    {
        *ppInfo = NULL;
    }
    goto cleanup;
}

uint32_t
TDNFGoalNoDeps(
    PTDNF pTdnf,
    Queue* pQueuePkgList,
    PTDNF_SOLVED_PKG_INFO* ppInfo
    )
{
    uint32_t dwError = 0;
    PSolvPackageList pPkgList = NULL;
    PTDNF_PKG_INFO pPkgInfo = NULL;
    PTDNF_SOLVED_PKG_INFO pInfo = NULL;

    if(!pTdnf || !ppInfo || !pQueuePkgList)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = SolvQueueToPackageList(pQueuePkgList, &pPkgList);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFPopulatePkgInfos(pTdnf->pSack, pPkgList, &pPkgInfo);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(
                  1,
                  sizeof(TDNF_SOLVED_PKG_INFO),
                  (void**)&pInfo);
    BAIL_ON_TDNF_ERROR(dwError);

    pInfo->pPkgsToInstall = pPkgInfo;
    *ppInfo = pInfo;

cleanup:
    return dwError;
error:
    if(pPkgInfo) {
        TDNFFreePackageInfo(pPkgInfo);
    }
    TDNF_SAFE_FREE_MEMORY(pInfo);
    goto cleanup;
}

uint32_t
TDNFGoal(
    PTDNF pTdnf,
    Queue* pQueuePkgList,
    PTDNF_SOLVED_PKG_INFO* ppInfo,
    TDNF_ALTERTYPE nAlterType, int nUnresolved
    )
{
    uint32_t dwError = 0;
    Queue queueJobs = {0};
    int nAllowErasing = 0;
    char** ppszExcludes = NULL;
    uint32_t dwExcludeCount = 0;
    char **ppszAutoInstalled = NULL;

    if(!pTdnf || !ppInfo || !pQueuePkgList)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFPkgsToExclude(pTdnf, &dwExcludeCount, &ppszExcludes);
    BAIL_ON_TDNF_ERROR(dwError);

    queue_init(&queueJobs);
    if (nAlterType == ALTER_UPGRADEALL)
    {
        dwError = SolvAddUpgradeAllJob(&queueJobs);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    else if(nAlterType == ALTER_DISTRO_SYNC)
    {
        dwError = SolvAddDistUpgradeJob(&queueJobs);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    else
    {
        if (pQueuePkgList->count == 0)
        {
            dwError = ERROR_TDNF_ALREADY_INSTALLED;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        for (int i = 0; i < pQueuePkgList->count; i++)
        {
            Id dwId = pQueuePkgList->elements[i];
            TDNFAddGoal(pTdnf, nAlterType, &queueJobs, dwId,
                        dwExcludeCount, ppszExcludes);
        }
    }

    nAllowErasing =
        pTdnf->pArgs->nAllowErasing ||
        nAlterType == ALTER_ERASE ||
        nAlterType == ALTER_AUTOERASE ||
        nAlterType == ALTER_AUTOERASEALL;
    if(nAllowErasing)
    {
        TDNFAddUserInstalledToJobs(pTdnf, &queueJobs);
        BAIL_ON_TDNF_ERROR(dwError);
        /* TODO: deal with no db error? */
    }

    dwError = TDNFSolv(pTdnf, &queueJobs, ppszExcludes, dwExcludeCount,
                       nAllowErasing,
                       (pTdnf->pConf->nCleanRequirementsOnRemove &&
                                !pTdnf->pArgs->nNoAutoRemove) ||
                                nAlterType == ALTER_AUTOERASE,
                                nAlterType == ALTER_REINSTALL ||
                                (nAlterType == ALTER_DISTRO_SYNC && pTdnf->pConf->nDistroSyncReinstallChanged),
                       nUnresolved, ppInfo);
    BAIL_ON_TDNF_ERROR(dwError);

    if (nAlterType == ALTER_INSTALL)
    {
        dwError = TDNFAddUserInstall(pTdnf, pQueuePkgList, *ppInfo);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    TDNF_SAFE_FREE_STRINGARRAY(ppszAutoInstalled);
    TDNF_SAFE_FREE_STRINGARRAY(ppszExcludes);
    queue_free(&queueJobs);
    return dwError;

error:
    goto cleanup;
}

static
uint32_t
TDNFGoalObserveNativeSolver(
    PTDNF pTdnf,
    const Queue *pQueueJobs,
    const TDNF_SOLVED_PKG_INFO *pInfo,
    int nAllowErasing,
    int nAutoErase,
    int nProblems, int nUnresolved
    )
{
    uint32_t dwError = 0;
    uint32_t dwRepoCount = 0, dwJobCount = 0, dwEraseJobCount = 0;
    uint32_t dwHiddenAvailableCount = 0;
    int nUpdateAll = 0, nDistSyncAll = 0;
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY pRepos = NULL;
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB pJobs = NULL, pEraseJobs = NULL;
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB pHiddenAvailable = NULL;
    const char *pszNativeArch = NULL;
    char *pszNativeArchOwned = NULL;
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT comparison = {0};

    if(!pTdnf || !pTdnf->pArgs || !pTdnf->pConf || !pTdnf->pSack ||
       !pTdnf->pSack->pPool || !pTdnf->pRpmConfig || !pQueueJobs || !pInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(nProblems || nUnresolved ||
       pTdnf->pConf->ppszPkgLocks || pTdnf->pConf->ppszInstallOnlyPkgs)
    {
        dwError = ERROR_TDNF_CALL_NOT_SUPPORTED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pTdnf->pArgs->pszArch))
    {
        pszNativeArch = pTdnf->pArgs->pszArch;
    }
    else
    {
        dwError = TDNFGetKernelArch(&pszNativeArchOwned);
        BAIL_ON_TDNF_ERROR(dwError);
        pszNativeArch = pszNativeArchOwned;
    }
    if(IsNullOrEmptyString(pszNativeArch))
    {
        dwError = ERROR_TDNF_NO_DATA;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGoalBuildNativeSolverRepoInputs(
                  pTdnf, &pRepos, &dwRepoCount);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TDNFGoalBuildNativeSolverJobs(
                  pTdnf, pQueueJobs, &pJobs, &dwJobCount, &pEraseJobs, &dwEraseJobCount, &nUpdateAll, &nDistSyncAll);
    BAIL_ON_TDNF_ERROR(dwError);
    if((dwEraseJobCount && dwJobCount) ||
       (!nAllowErasing && dwEraseJobCount) ||
       (nAllowErasing && !dwEraseJobCount &&
        (pInfo->pPkgsToRemove || pInfo->pPkgsToUpgrade || pInfo->pPkgsToDowngrade ||
         pInfo->pPkgsUnNeeded || pInfo->pPkgsToReinstall || pInfo->pPkgsObsoleted || pInfo->pPkgsRemovedByDowngrade)))
    {
        dwError = ERROR_TDNF_CALL_NOT_SUPPORTED;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    dwError = TDNFGoalBuildNativeSolverHiddenAvailable(
                  pTdnf, &pHiddenAvailable, &dwHiddenAvailableCount);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TDNFRepoMdNativeSolverLiveCompareV11(
                  pRepos, dwRepoCount, pJobs, dwJobCount,
                  pEraseJobs, dwEraseJobCount, pHiddenAvailable, dwHiddenAvailableCount,
                  pTdnf->pArgs->nAllDeps, pTdnf->pArgs->nBest, nAutoErase, pTdnf->pArgs->nSkipBroken, nAllowErasing,
                  nUpdateAll, nDistSyncAll,
                  (const char *const *)pTdnf->pConf->ppszProtectedPkgs,
                  pTdnf->pRpmConfig, pszNativeArch, pInfo, &comparison);
    if(dwError && !IsNullOrEmptyString(TDNFRepoMdLastError()))
    {
        pr_info("native-solver-shadow: %s\n", TDNFRepoMdLastError());
    }
    BAIL_ON_TDNF_ERROR(dwError);

    switch(comparison.dwStatus)
    {
        case TDNF_REPOMD_NATIVE_SOLVER_COMPARE_PROJECTED_MATCH:
            pr_info("native-solver-shadow: projected match\n");
            break;
        case TDNF_REPOMD_NATIVE_SOLVER_COMPARE_MISMATCH:
            pr_err("native-solver-shadow: mismatch action=%u index=%u "
                   "native=%u legacy=%u\n",
                   comparison.dwActionKind,
                   comparison.dwDifferenceIndex,
                   comparison.dwNativeCount,
                   comparison.dwLegacyCount);
            break;
        case TDNF_REPOMD_NATIVE_SOLVER_COMPARE_UNSUPPORTED:
            pr_info("native-solver-shadow: comparison unsupported "
                    "reason=%u action=%u\n",
                    comparison.dwReason,
                    comparison.dwActionKind);
            break;
        default:
            dwError = ERROR_TDNF_CALL_NOT_SUPPORTED;
            BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszNativeArchOwned);
    TDNFGoalFreeNativeSolverJobs(pHiddenAvailable, dwHiddenAvailableCount);
    TDNFGoalFreeNativeSolverJobs(pJobs, dwJobCount + dwEraseJobCount);
    TDNFGoalFreeNativeSolverRepoInputs(pRepos, dwRepoCount);
    return dwError;
error:
    goto cleanup;
}

static
uint32_t
TDNFGoalBuildNativeSolverRepoInputs(
    PTDNF pTdnf,
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY *ppRepos,
    uint32_t *pdwRepoCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY pRepos = NULL;
    PTDNF_REPO_DATA pRepoData = NULL;

    if(!pTdnf || !ppRepos || !pdwRepoCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(pRepoData = pTdnf->pRepos; pRepoData; pRepoData = pRepoData->pNext)
    {
        if(pRepoData->nEnabled && pRepoData->nHasMetaData &&
           !IsNullOrEmptyString(pRepoData->pszId))
        {
            dwCount++;
        }
    }
    if(!dwCount)
    {
        dwError = ERROR_TDNF_NO_DATA;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(
                  dwCount, sizeof(*pRepos), (void **)&pRepos);
    BAIL_ON_TDNF_ERROR(dwError);

    dwCount = 0;
    for(pRepoData = pTdnf->pRepos; pRepoData; pRepoData = pRepoData->pNext)
    {
        if(!pRepoData->nEnabled || !pRepoData->nHasMetaData ||
           IsNullOrEmptyString(pRepoData->pszId))
        {
            continue;
        }
        dwError = TDNFGetCachePath(
                      pTdnf, pRepoData, NULL, NULL,
                      (char **)&pRepos[dwCount].pszCacheDir);
        BAIL_ON_TDNF_ERROR(dwError);

        pRepos[dwCount].pszId = pRepoData->pszId;
        pRepos[dwCount].pszSnapshotFile = pRepoData->pszSnapshotFile;
        pRepos[dwCount].nPriority = pRepoData->nPriority;
        pRepos[dwCount].dwCost =
            TDNF_REPOMD_NATIVE_SOLVER_DEFAULT_REPOSITORY_COST;
        dwCount++;
    }

    *ppRepos = pRepos;
    *pdwRepoCount = dwCount;

cleanup:
    return dwError;
error:
    TDNFGoalFreeNativeSolverRepoInputs(pRepos, dwCount);
    goto cleanup;
}

static
void
TDNFGoalFreeNativeSolverRepoInputs(
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY pRepos,
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

static
uint32_t
TDNFGoalBuildNativeSolverJobs(
    PTDNF pTdnf,
    const Queue *pQueueJobs,
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *ppJobs, uint32_t *pdwJobCount,
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *ppEraseJobs, uint32_t *pdwEraseJobCount,
    int *pnUpdateAll, int *pnDistSyncAll
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0, dwIndex = 0;
    uint32_t dwInstallCount = 0, dwEraseCount = 0;
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB pJobs = NULL;
    Pool *pPool = NULL;
    int nUpdateAll = 0, nDistSyncAll = 0;
    if(!pTdnf || !pTdnf->pArgs || !pTdnf->pConf || !pTdnf->pSack ||
       !pTdnf->pSack->pPool || !pQueueJobs || !ppJobs || !pdwJobCount ||
       !ppEraseJobs || !pdwEraseJobCount || !pnUpdateAll || !pnDistSyncAll ||
       pQueueJobs->count <= 0 ||
       pQueueJobs->count % 2 != 0)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pPool = pTdnf->pSack->pPool;
    dwCount = (uint32_t)pQueueJobs->count / 2;
    dwError = TDNFAllocateMemory(
                  dwCount, sizeof(*pJobs), (void **)&pJobs);
    BAIL_ON_TDNF_ERROR(dwError);
    for(dwIndex = 0; dwIndex < dwCount; dwIndex++)
    {
        /* XOR removes only expected policy bits; wrong shapes stay set. */
        Id how = pQueueJobs->elements[dwIndex * 2] ^
                 (pTdnf->pArgs->nBest ? SOLVER_FORCEBEST : 0) ^
                 (pTdnf->pConf->nCleanRequirementsOnRemove && !pTdnf->pArgs->nNoAutoRemove ? SOLVER_CLEANDEPS : 0);
        Id dwPkgId = pQueueJobs->elements[dwIndex * 2 + 1];
        Solvable *pSolvable = NULL;
        PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB pJob = NULL;
        int nInstall = how == (SOLVER_SOLVABLE | SOLVER_INSTALL),
            nErase = how == (SOLVER_SOLVABLE | SOLVER_ERASE),
            nUserInstalled = how == (SOLVER_SOLVABLE | SOLVER_USERINSTALLED),
            nUpdateAllJob = how == (SOLVER_SOLVABLE_ALL | SOLVER_UPDATE),
            nDistSyncAllJob = how == (SOLVER_SOLVABLE_ALL | SOLVER_DISTUPGRADE);

        if((nUpdateAllJob || nDistSyncAllJob) && !dwPkgId && dwCount == 1)
        {
            nUpdateAll = nUpdateAllJob;
            nDistSyncAll = nDistSyncAllJob;
            continue;
        }
        if((!nInstall && !nErase && !nUserInstalled) || dwPkgId <= 0 ||
           dwPkgId >= pPool->nsolvables)
        {
            dwError = ERROR_TDNF_CALL_NOT_SUPPORTED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        pSolvable = pool_id2solvable(pPool, dwPkgId);
        if(!pSolvable || !pSolvable->repo ||
           pSolvable->repo == pTdnf->pSolvCmdLineRepo ||
           IsNullOrEmptyString(pSolvable->repo->name) ||
           !strcmp(pSolvable->repo->name, CMDLINE_REPO_NAME) ||
           (nInstall && pSolvable->repo == pPool->installed) ||
           (!nInstall && pSolvable->repo != pPool->installed))
        {
            dwError = ERROR_TDNF_CALL_NOT_SUPPORTED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(nUserInstalled) continue;
        pJob = nInstall ? &pJobs[dwInstallCount++] : &pJobs[dwCount - ++dwEraseCount];
        pJob->pszRepository = pSolvable->repo->name;
        dwError = SolvGetNevraFromId(
                      pTdnf->pSack, dwPkgId, &pJob->dwEpoch, (char **)&pJob->pszName, (char **)&pJob->pszVersion,
                      (char **)&pJob->pszRelease, (char **)&pJob->pszArch, NULL);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    memmove(pJobs + dwInstallCount, pJobs + dwCount - dwEraseCount,
            dwEraseCount * sizeof(*pJobs));
    *ppJobs = pJobs; *pdwJobCount = dwInstallCount;
    *ppEraseJobs = dwEraseCount ? pJobs + dwInstallCount : NULL;
    *pdwEraseJobCount = dwEraseCount;
    *pnUpdateAll = nUpdateAll;
    *pnDistSyncAll = nDistSyncAll;
cleanup:
    return dwError;
error:
    TDNFGoalFreeNativeSolverJobs(pJobs, dwCount);
    goto cleanup;
}

static
void
TDNFGoalFreeNativeSolverJobs(
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB pJobs,
    uint32_t dwJobCount
    )
{
    uint32_t dwIndex = 0;

    if(!pJobs)
    {
        return;
    }
    for(dwIndex = 0; dwIndex < dwJobCount; dwIndex++)
    {
        char *pszName = (char *)pJobs[dwIndex].pszName;
        char *pszVersion = (char *)pJobs[dwIndex].pszVersion;
        char *pszRelease = (char *)pJobs[dwIndex].pszRelease;
        char *pszArch = (char *)pJobs[dwIndex].pszArch;
        TDNF_SAFE_FREE_MEMORY(pszName);
        TDNF_SAFE_FREE_MEMORY(pszVersion);
        TDNF_SAFE_FREE_MEMORY(pszRelease);
        TDNF_SAFE_FREE_MEMORY(pszArch);
        pJobs[dwIndex].pszName = NULL;
        pJobs[dwIndex].pszVersion = NULL;
        pJobs[dwIndex].pszRelease = NULL;
        pJobs[dwIndex].pszArch = NULL;
    }
    TDNF_SAFE_FREE_MEMORY(pJobs);
}

static
int
TDNFGoalIsNativeSolverPackage(
    Pool *pPool,
    Solvable *pSolvable
    )
{
    const char *pszName = NULL;

    if(!pPool || !pSolvable)
    {
        return 0;
    }
    pszName = pool_id2str(pPool, pSolvable->name);
    return pszName && strncmp(pszName, "patch:", 6);
}

static
uint32_t
TDNFGoalBuildNativeSolverHiddenAvailable(
    PTDNF pTdnf,
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *ppHiddenAvailable,
    uint32_t *pdwHiddenAvailableCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    Id dwPkgId = 0;
    Pool *pPool = NULL;
    PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB pHiddenAvailable = NULL;

    if(!pTdnf || !pTdnf->pSack || !pTdnf->pSack->pPool ||
       !ppHiddenAvailable || !pdwHiddenAvailableCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    pPool = pTdnf->pSack->pPool;
    if(!pPool->considered)
    {
        goto cleanup;
    }
    for(dwPkgId = 1; dwPkgId < pPool->nsolvables; dwPkgId++)
    {
        Solvable *pSolvable = pool_id2solvable((Pool *)pPool, dwPkgId);
        if(!pSolvable || !pSolvable->repo ||
           MAPTST(pPool->considered, dwPkgId) ||
           pSolvable->repo == pPool->installed ||
           !TDNFGoalIsNativeSolverPackage(pPool, pSolvable))
        {
            continue;
        }
        if(IsNullOrEmptyString(pSolvable->repo->name))
        {
            dwError = ERROR_TDNF_CALL_NOT_SUPPORTED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(pSolvable->repo == pTdnf->pSolvCmdLineRepo ||
           !strcmp(pSolvable->repo->name, CMDLINE_REPO_NAME))
        {
            continue;
        }
        dwCount++;
    }
    if(!dwCount)
    {
        goto cleanup;
    }

    dwError = TDNFAllocateMemory(
                  dwCount,
                  sizeof(TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB),
                  (void **)&pHiddenAvailable);
    BAIL_ON_TDNF_ERROR(dwError);

    for(dwPkgId = 1; dwPkgId < pPool->nsolvables; dwPkgId++)
    {
        Solvable *pSolvable = pool_id2solvable(pPool, dwPkgId);
        if(!pSolvable || !pSolvable->repo ||
           MAPTST(pPool->considered, dwPkgId) ||
           pSolvable->repo == pPool->installed ||
           !TDNFGoalIsNativeSolverPackage(pPool, pSolvable))
        {
            continue;
        }
        if(IsNullOrEmptyString(pSolvable->repo->name))
        {
            dwError = ERROR_TDNF_CALL_NOT_SUPPORTED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(pSolvable->repo == pTdnf->pSolvCmdLineRepo ||
           !strcmp(pSolvable->repo->name, CMDLINE_REPO_NAME))
        {
            continue;
        }
        pHiddenAvailable[dwIndex].pszRepository = pSolvable->repo->name;
        dwError = SolvGetNevraFromId(
                      pTdnf->pSack,
                      dwPkgId,
                      &pHiddenAvailable[dwIndex].dwEpoch,
                      (char **)&pHiddenAvailable[dwIndex].pszName,
                      (char **)&pHiddenAvailable[dwIndex].pszVersion,
                      (char **)&pHiddenAvailable[dwIndex].pszRelease,
                      (char **)&pHiddenAvailable[dwIndex].pszArch,
                      NULL);
        BAIL_ON_TDNF_ERROR(dwError);
        dwIndex++;
    }

    *ppHiddenAvailable = pHiddenAvailable;
    *pdwHiddenAvailableCount = dwCount;

cleanup:
    return dwError;
error:
    TDNFGoalFreeNativeSolverJobs(pHiddenAvailable, dwCount);
    goto cleanup;
}

uint32_t
TDNFHistoryGoal(
    PTDNF pTdnf,
    Queue *pqInstall,
    Queue *pqErase,
    PTDNF_SOLVED_PKG_INFO* ppInfo
    )
{
    uint32_t dwError = 0;
    Queue queueJobs = {0};
    char** ppszExcludes = NULL;
    uint32_t dwExcludeCount = 0;

    if(!pTdnf || !ppInfo || !pqInstall || !pqErase)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFPkgsToExclude(pTdnf, &dwExcludeCount, &ppszExcludes);
    BAIL_ON_TDNF_ERROR(dwError);

    queue_init(&queueJobs);

    for (int i = 0; i < pqInstall->count; i++)
    {
        Id id = pqInstall->elements[i];
        dwError = TDNFAddGoal(pTdnf, ALTER_INSTALL, &queueJobs, id,
                    dwExcludeCount, ppszExcludes);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for (int i = 0; i < pqErase->count; i++)
    {
        Id id = pqErase->elements[i];
        dwError = TDNFAddGoal(pTdnf, ALTER_ERASE, &queueJobs, id,
                    dwExcludeCount, ppszExcludes);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFSolv(pTdnf, &queueJobs, ppszExcludes, dwExcludeCount,
                       1, /* nAllowErasing */
                       0, /* nAutoErase */
                       0, /* nReInstall */ 0, /* nUnresolved */
                       ppInfo);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAddUserInstall(pTdnf, pqInstall, *ppInfo);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_STRINGARRAY(ppszExcludes);
    queue_free(&queueJobs);
    return dwError;

error:
    goto cleanup;
}

uint32_t
TDNFAddUserInstall(
    PTDNF pTdnf,
    const Queue* pQueueGoal,
    PTDNF_SOLVED_PKG_INFO ppInfo
    )
{
    uint32_t dwError = 0;
    int i;
    char **ppszPkgsUserInstall = NULL;

    if (!pTdnf || !pQueueGoal || !ppInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(pQueueGoal->count + 1,
                                 sizeof(char **),
                                 (void **)&ppszPkgsUserInstall);
    BAIL_ON_TDNF_ERROR(dwError);

    for (i = 0; i < pQueueGoal->count; i++)
    {
        dwError = SolvGetPkgNameFromId(
                       pTdnf->pSack,
                       pQueueGoal->elements[i],
                       &ppszPkgsUserInstall[i]);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ppInfo->ppszPkgsUserInstall = ppszPkgsUserInstall;
cleanup:
    return dwError;
error:
    TDNF_SAFE_FREE_MEMORY(ppszPkgsUserInstall);
    goto cleanup;
}

uint32_t
TDNFMarkAutoInstalledSinglePkg(
    PTDNF pTdnf,
    const char *pszPkgName
)
{
    uint32_t dwError = 0;
    int rc;
    struct history_ctx *pHistoryCtx = NULL;

    if (!pTdnf || !pszPkgName)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGetHistoryCtx(pTdnf, &pHistoryCtx, 1);
    BAIL_ON_TDNF_ERROR(dwError);

    rc = history_set_auto_flag(pHistoryCtx, pszPkgName, 0);
    if (rc != 0)
    {
        dwError = ERROR_TDNF_HISTORY_ERROR;
        BAIL_ON_TDNF_ERROR(dwError);
    }
cleanup:
    if (pHistoryCtx)
    {
        destroy_history_ctx(pHistoryCtx);
    }
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFMarkAutoInstalled(
    PTDNF pTdnf,
    struct history_ctx *pHistoryCtx,
    PTDNF_SOLVED_PKG_INFO ppInfo,
    int nAutoOnly
    )
{
    uint32_t dwError = 0;
    PTDNF_PKG_INFO pPkgInfo = NULL;

    if (!pTdnf || !pHistoryCtx || !ppInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    /* ppInfo->pPkgsToInstall contains packages that were installed.
       ppInfo->ppszPkgsUserInstall contains packages that the user intended to
       install. Therefore, any packages that are in pPkgsToInstall but not in
       ppszPkgsUserInstall are automatic installs and were pulled in by
       dependencies.

       Corner cases:
       - packages that are dependencies but are already installed will be
         unaffected
       - on upgrades/downgrades, only additional packages will be in
         pPkgsToInstall. These are automatic if the upgrade was invoked w/out
         package args. If they are in package args, they are not in pPkgsToInstall
         (but will be in pPkgsToUpgrade) and their status will not change.
    */
    for (pPkgInfo = ppInfo->pPkgsToInstall; pPkgInfo; pPkgInfo = pPkgInfo->pNext)
    {
        const char *pszName = pPkgInfo->pszName;
        int nFlag = 1;
        /* check if user installed */
        if (ppInfo->ppszPkgsUserInstall)
        {
            /* TODO: if both lists were sorted, we could start with i
               where it left last time */
            for (int i = 0; ppInfo->ppszPkgsUserInstall[i]; i++)
            {
                if (strcmp(pszName,
                           ppInfo->ppszPkgsUserInstall[i]) == 0)
                {
                    nFlag = 0;
                    break;
                }
            }
        }
        /* During upgrades, ppInfo->pPkgsToInstall contains any packages that are
           being installed as a dependency automatically as well as any
           ppszInstallOnlyPkgs which are installing a new version. The packages
           configured as installonlypkgs need to retain to retain their previous
           install status.
        */
        if (nFlag == 1 && pTdnf->pConf && pTdnf->pConf->ppszInstallOnlyPkgs)
        {
            for (int i = 0; pTdnf->pConf->ppszInstallOnlyPkgs[i]; i++)
            {
                if (strcmp(pTdnf->pConf->ppszInstallOnlyPkgs[i], pszName) == 0)
                {
                    // Lookup current auto install status, ensure matching status
                    int value = 0;
                    int rc = history_get_auto_flag(pHistoryCtx, pszName, &value);
                    if (rc != 0)
                    {
                        dwError = ERROR_TDNF_HISTORY_ERROR;
                        BAIL_ON_TDNF_ERROR(dwError);
                    }
                    if (value == 0)
                    {
                        // Packages previously marked as user installed should
                        // remain user installed.
                        nFlag = 0;
                        break;
                    }
                }
            }
        }
        if (!nAutoOnly || nFlag == 1)
        {
            int rc = history_set_auto_flag(pHistoryCtx, pszName, nFlag);
            if (rc != 0)
            {
                dwError = ERROR_TDNF_HISTORY_ERROR;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
    }
cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFAddGoal(
    PTDNF pTdnf,
    TDNF_ALTERTYPE nAlterType,
    Queue* pQueueJobs,
    Id dwId,
    uint32_t dwCount,
    char** ppszExcludes
    )
{
    uint32_t dwError = 0;
    char* pszPkg = NULL;
    char** ppszPackagesTemp = NULL;
    char* pszName = NULL;

    if(!pQueueJobs || dwId == 0 || !pTdnf->pSack || !pTdnf->pSack->pPool)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (dwCount != 0 && ppszExcludes)
    {
        dwError = SolvGetPkgNameFromId(
                      pTdnf->pSack,
                      dwId,
                      &pszName);
        BAIL_ON_TDNF_ERROR(dwError);
        ppszPackagesTemp = ppszExcludes;

        while(ppszPackagesTemp && *ppszPackagesTemp)
        {
            if (SolvIsGlob(*ppszPackagesTemp))
            {
                if (!fnmatch(*ppszPackagesTemp, pszName, 0))
                {
                    goto cleanup;
                }
            }
            else if (!strcmp(pszName, *ppszPackagesTemp))
            {
                goto cleanup;
            }
            ++ppszPackagesTemp;
        }
    }

    switch(nAlterType)
    {
        case ALTER_DOWNGRADEALL:
        case ALTER_DOWNGRADE:
            dwError = SolvAddPkgDowngradeJob(pQueueJobs, dwId);
            BAIL_ON_TDNF_ERROR(dwError);
            break;
        case ALTER_ERASE:
        case ALTER_AUTOERASE:
        case ALTER_AUTOERASEALL:
            dwError = SolvAddPkgEraseJob(pQueueJobs, dwId);
            BAIL_ON_TDNF_ERROR(dwError);
            break;
        case ALTER_REINSTALL:
        case ALTER_INSTALL:
        case ALTER_UPGRADE:
            dwError = SolvAddPkgInstallJob(pQueueJobs, dwId);
            BAIL_ON_TDNF_ERROR(dwError);
            break;
        default:
            dwError = ERROR_TDNF_INVALID_RESOLVE_ARG;
            BAIL_ON_TDNF_ERROR(dwError);
    }
cleanup:
    TDNF_SAFE_FREE_MEMORY(pszPkg);
    TDNF_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    goto cleanup;
}

static
uint32_t
TDNFGoalGetAllResultsIgnoreNoData(
    Transaction* pTrans,
    const Solver* pSolv,
    PTDNF_SOLVED_PKG_INFO* ppInfo,
    PTDNF pTdnf,
    int nReInstall
    )
{
    uint32_t dwError = 0;
    PTDNF_SOLVED_PKG_INFO pInfo = NULL;

    if(!pTrans || !pSolv || !ppInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(
                  1,
                  sizeof(TDNF_SOLVED_PKG_INFO),
                  (void**)&pInfo);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFGetInstallPackages(
                  pTrans,
                  pTdnf,
                  &pInfo->pPkgsToInstall);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFGetUpgradePackages(
                  pTrans,
                  pTdnf,
                  &pInfo->pPkgsToUpgrade);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFGetDownGradePackages(
                  pTrans,
                  pTdnf,
                  &pInfo->pPkgsToDowngrade,
                  &pInfo->pPkgsRemovedByDowngrade);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFGetErasePackages(
                  pTrans,
                  pTdnf,
                  &pInfo->pPkgsToRemove);
    BAIL_ON_TDNF_ERROR(dwError);

    if(nReInstall)
    {
        dwError = TDNFGetReinstallPackages(
                      pTrans,
                      pTdnf,
                      &pInfo->pPkgsToReinstall);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGetObsoletedPackages(
                  pTrans,
                  pTdnf,
                  &pInfo->pPkgsObsoleted);
    BAIL_ON_TDNF_ERROR(dwError);

    *ppInfo = pInfo;
cleanup:
    return dwError;

error:
    if(ppInfo)
    {
        *ppInfo = NULL;
    }
    if(pInfo)
    {
        TDNFFreeSolvedPackageInfo(pInfo);
    }
    goto cleanup;
}

uint32_t
TDNFSolvAddPkgLocks(
    PTDNF pTdnf,
    Queue* pQueueJobs,
    Pool *pPool
    )
{
    uint32_t dwError = 0;
    char **ppszPackages = NULL;
    int i;

    if(!pTdnf || !pQueueJobs || !pPool)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ppszPackages = pTdnf->pConf->ppszPkgLocks;

    for (i = 0; ppszPackages && ppszPackages[i]; i++)
    {
        char *pszPkg = ppszPackages[i];
        Id idPkg = pool_str2id(pPool, pszPkg, 1);
        if (idPkg)
        {
            Id p;
            Solvable *s;
            FOR_REPO_SOLVABLES(pPool->installed, p, s)
            {
                if (idPkg == s->name)
                {
                    queue_push2(pQueueJobs, SOLVER_SOLVABLE_NAME|SOLVER_LOCK, idPkg);
                    break;
                }
            }
        }
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFSolvAddInstallOnlyPkgs(
    PTDNF pTdnf,
    Queue* pQueueJobs,
    Pool *pPool
    )
{
    uint32_t dwError = 0;
    char **ppszPackages = NULL;
    int i;

    if(!pTdnf || !pQueueJobs || !pPool)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ppszPackages = pTdnf->pConf->ppszInstallOnlyPkgs;

    for (i = 0; ppszPackages && ppszPackages[i]; i++)
    {
        char *pszPkg = ppszPackages[i];
        Id idPkg = pool_str2id(pPool, pszPkg, 1);
        if (idPkg)
        {
            Id p;
            Solvable *s;
            /* only mark if they are installed - first install doesn't care */
            /* we are marking the name, so we just need to mark it once */
            /* the flag only affects to be installed packages and
               it has no effect for already installed packages */
            FOR_REPO_SOLVABLES(pPool->installed, p, s)
            {
                if (idPkg == s->name)
                {
                    queue_push2(pQueueJobs, SOLVER_SOLVABLE_NAME|SOLVER_MULTIVERSION, idPkg);
                    break;
                }
            }
        }
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFSolvCheckInstallOnlyLimitInTrans(
    PTDNF pTdnf,
    Transaction *pTrans,
    Pool *pPool,
    Queue *pQueueJobs
    )
{
    uint32_t dwError = 0;
    char **ppszPackages = NULL;
    int i;
    int nLimit;
    Queue qPkgs = {0};
    Map *pMapRemove = NULL;

    if(!pTdnf || !pTrans || !pPool || !pTdnf->pConf)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ppszPackages = pTdnf->pConf->ppszInstallOnlyPkgs;
    nLimit = pTdnf->pConf->nInstallOnlyLimit;

    dwError = TDNFAllocateMemory(
                          1,
                          sizeof(Map),
                          (void**)&pMapRemove);
    BAIL_ON_TDNF_ERROR(dwError);

    map_init(pMapRemove, pPool->nsolvables);

    for (i = 0; ppszPackages && ppszPackages[i]; i++)
    {
        char *pszPkg = ppszPackages[i];
        Id idName = pool_str2id(pPool, pszPkg, 1);
        int n = 0;

        /* count installed packages */
        if (idName)
        {
            Id p;
            Solvable *s;

            FOR_REPO_SOLVABLES(pPool->installed, p, s) {
                if (idName == s->name) {
                    n++;
                }
            }
        }
        /* increment if more gets installed,
           subtract if any gets removed */
        for (int j = 0; j < pTrans->steps.count; j++) {
            Id idType;
            Id idPkg = pTrans->steps.elements[j];
            const Solvable *s = pool_id2solvable(pPool, idPkg);

            if (idName == s->name) {
                idType = transaction_type(pTrans, idPkg,
                                          SOLVER_TRANSACTION_SHOW_MULTIINSTALL);
                if (idType == SOLVER_TRANSACTION_MULTIINSTALL) {
                    n++;
                } else if (idType == SOLVER_TRANSACTION_ERASE) {
                    map_set(pMapRemove, idPkg);
                    n--;
                }
            }
        }

        /* if we exceed the limit, add erase jobs */
        if (n > nLimit) {
            Id p;
            Solvable *s;

            /* we are going to add jobs and return this error,
               so the caller can re-solve */
            dwError = ERROR_TDNF_INSTALLONLY_LIMIT_EXCEEDED;

            /* TODO: look for lowest versions? Currently looks like least
               recent installed gets selected first - which may be fine too */
            FOR_REPO_SOLVABLES(pPool->installed, p, s) {
                if (idName == s->name && !MAPTST(pMapRemove, p)) {
                    map_set(pMapRemove, p);
                    queue_push2(pQueueJobs, SOLVER_SOLVABLE|SOLVER_ERASE, p);
                    n--;
                    if (n <= nLimit)
                        break;
                }
            }
        }
    }

cleanup:
    if (pMapRemove) {
        map_free(pMapRemove);
        TDNFFreeMemory(pMapRemove);
    }
    queue_free(&qPkgs);
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFSolvAddMinVersions(
    PTDNF pTdnf,
    Pool *pPool
    )
{
    uint32_t dwError = 0;
    char **ppszPackages = NULL;
    char **ppszExcludeLines = NULL;
    uint32_t dwExcludeCount = 0;
    Map *pMapMinVersions = NULL;
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos = NULL;
    uint32_t dwRepoCount = 0;
    uint32_t i = 0;

    if(!pTdnf || !pPool)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ppszPackages = pTdnf->pConf->ppszMinVersions;
    if (!ppszPackages)
    {
        goto cleanup;
    }

    dwError = TDNFAllocateMemory(
                          1,
                          sizeof(Map),
                          (void**)&pMapMinVersions);
    BAIL_ON_TDNF_ERROR(dwError);

    map_init(pMapMinVersions, pPool->nsolvables);

    dwError = TDNFNativeQueryBuildRepoInputs(pTdnf, &pRepos, &dwRepoCount);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFRepoMdNativeMinVersionExcludeLinesConfig(
                  pRepos,
                  dwRepoCount,
                  pTdnf->pRpmConfig,
                  ppszPackages,
                  &ppszExcludeLines,
                  &dwExcludeCount);
    BAIL_ON_TDNF_ERROR(dwError);

    for(i = 0; i < dwExcludeCount; i++)
    {
        Id dwPkgId = 0;

        dwError = TDNFNativeQueryResolveSinglePackageRef(
                      pTdnf->pSack,
                      ppszExcludeLines[i],
                      0,
                      &dwPkgId);
        BAIL_ON_TDNF_ERROR(dwError);

        MAPSET(pMapMinVersions, dwPkgId);
    }

    if (!pPool->considered)
    {
        dwError = TDNFAllocateMemory(
                             1,
                             sizeof(Map),
                             (void**)&pPool->considered);
        map_init(pPool->considered, pPool->nsolvables);
        map_setall(pPool->considered);
    }

    map_subtract(pPool->considered, pMapMinVersions);

cleanup:
    TDNFFreeStringArray(ppszExcludeLines);
    TDNFNativeQueryFreeRepoInputs(pRepos, dwRepoCount);
    if(pMapMinVersions)
    {
        map_free(pMapMinVersions);
        TDNFFreeMemory(pMapMinVersions);
    }
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFSolvAddProtectPkgs(
    PTDNF pTdnf,
    Queue* pQueueJobs,
    Pool *pPool
    )
{
    uint32_t dwError = 0;
    char **ppszProtectedPkgs = NULL;
    int i, j;
    Queue qPkgs = {0};
    Id p;
    Solvable *s;

    if(!pTdnf || !pQueueJobs || !pPool || !pTdnf->pConf)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ppszProtectedPkgs = pTdnf->pConf->ppszProtectedPkgs;
    queue_init(&qPkgs);
    for (i = 0; ppszProtectedPkgs[i]; i++) {
        Id idPkg = pool_str2id(pPool, ppszProtectedPkgs[i], 1);
        if (idPkg) {
            queue_push(&qPkgs, idPkg);
        }
    }

    /* Not setting SOLVER_ALLOWUNINSTALL will not prevent a package from being
       uninstalled if it's going to be removed directly. */
    for (j = 0; j < pQueueJobs->count; j += 2) {
        Id how = pQueueJobs->elements[j];
        /* assuming that all erase jobs that we added use SOLVER_SOLVABLE */
        if (((how & SOLVER_JOBMASK) == SOLVER_ERASE) && (how & SOLVER_SOLVABLE)) {
            Id what = pQueueJobs->elements[j+1];
            s = pool_id2solvable(pPool, what);
            for (i = 0; i < qPkgs.count; i++) {
                if (qPkgs.elements[i] == s->name)
                    break;
            }
            if (i < qPkgs.count) {
                const char *pszPkgName = ppszProtectedPkgs[i];
                /* if this is a history transaction,
                   we may add it again (with another version) */
                for (i = 0; i < pQueueJobs->count; i += 2) {
                    if (i == j)
                        continue;
                    how = pQueueJobs->elements[i];
                    if (((how & SOLVER_JOBMASK) == SOLVER_INSTALL) && (how & SOLVER_SOLVABLE)) {
                        Id what_add = pQueueJobs->elements[i+1];
                        const Solvable *s_add = pool_id2solvable(pPool, what_add);
                        if (s_add->name == s->name) {
                            break;
                        }
                    }
                }
                if (i == pQueueJobs->count) { /* not found in re-adds */
                    pr_err("package %s is protected\n", pszPkgName);
                    dwError = ERROR_TDNF_PROTECTED;
                    BAIL_ON_TDNF_ERROR(dwError);
                }
            }
        }
    }

    /* There is no "SOLVER_PROTECTED" flag, so we allow
       all pkgs that are not protected to be removed. */
    FOR_REPO_SOLVABLES(pPool->installed, p, s)
    {
        for (i = 0; i < qPkgs.count; i++) {
            if (qPkgs.elements[i] == s->name)
                break;
        }
        if (i == qPkgs.count) {
            queue_push2(pQueueJobs, SOLVER_SOLVABLE|SOLVER_ALLOWUNINSTALL, p);
        } else {
            /* autoerase would remove this, even if we do not set
               SOLVER_ALLOWUNINSTALL for it */
            queue_push2(pQueueJobs, SOLVER_SOLVABLE|SOLVER_USERINSTALLED, p);
        }
    }

cleanup:
    queue_free(&qPkgs);
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFSolvCheckProtectPkgsInTrans(
    PTDNF pTdnf,
    Transaction *pTrans,
    Pool *pPool
    )
{
    uint32_t dwError = 0;
    char **ppszProtectedPkgs = NULL;
    int i;
    Queue qPkgs = {0};

    if(!pTdnf || !pTrans || !pPool || !pTdnf->pConf)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ppszProtectedPkgs = pTdnf->pConf->ppszProtectedPkgs;
    queue_init(&qPkgs);
    for (i = 0; ppszProtectedPkgs[i]; i++) {
        Id idPkg = pool_str2id(pPool, ppszProtectedPkgs[i], 1);
        if (idPkg) {
            queue_push(&qPkgs, idPkg);
        }
    }

    for (i = 0; i < pTrans->steps.count; i++) {
        Id idType;
        Id idPkg = pTrans->steps.elements[i];

        idType = transaction_type(pTrans, idPkg,
                                  SOLVER_TRANSACTION_SHOW_OBSOLETES);
        if (idType != SOLVER_TRANSACTION_OBSOLETED) {
            idType = transaction_type(pTrans, idPkg,
                                      SOLVER_TRANSACTION_SHOW_ACTIVE|
                                          SOLVER_TRANSACTION_SHOW_ALL);
        }
        if (idType == SOLVER_TRANSACTION_OBSOLETED ||
            idType == SOLVER_TRANSACTION_ERASE) {
            int j;
            const Solvable *s = pool_id2solvable(pPool, idPkg);
            for (j = 0; j < qPkgs.count; j++) {
                if (qPkgs.elements[j] == s->name) {
                    pr_err("package %s would be %s but it is protected\n",
                           ppszProtectedPkgs[j],
                           idType == SOLVER_TRANSACTION_OBSOLETED ?
                               "obsoleted" : "removed");
                    dwError = ERROR_TDNF_PROTECTED;
                    BAIL_ON_TDNF_ERROR(dwError);
                }
            }
        }
    }

cleanup:
    queue_free(&qPkgs);
    return dwError;
error:
    goto cleanup;
}
