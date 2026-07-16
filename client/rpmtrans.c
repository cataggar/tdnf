/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

#include "../llconf/nodes.h"

#include "rpmtrans_native.h"

#define INSTALL_INSTALL 0
#define INSTALL_UPGRADE 1
#define INSTALL_REINSTALL 2

static void
TDNFClearNativePlan(
    PTDNFRPMTS pTS
    );

static void
TDNFFreeTransactionItems(
    PTDNFRPMTS pTS
    );

static uint32_t
TDNFRecordTransactionItem(
    PTDNFRPMTS pTS,
    TDNF_RPM_TS_ITEM_TYPE nType,
    int nPackageKind,
    tdnf_rpm_file **ppRpmFile,
    const char *pszPath,
    uint32_t dwRpmDbHnum,
    const char *pszName,
    const char *pszEVR,
    const char *pszArch
    );

static uint32_t
TDNFNativeOrderAndCheck(
    PTDNFRPMTS pTS,
    PTDNF pTdnf
    );

static uint32_t
TDNFRpmCleanupTS(PTDNF pTdnf,
                 PTDNFRPMTS pTS)
{
    uint32_t dwError = 0;
    int nKeepCachedRpms = 0;
    int nDownloadOnly = 0;

    if(!pTS)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    nKeepCachedRpms = pTdnf->pConf->nKeepCache;
    nDownloadOnly = pTdnf->pArgs->nDownloadOnly;

    if(pTS->pCachedRpmsArray)
    {
        if(!nKeepCachedRpms && !nDownloadOnly)
        {
            TDNFRemoveCachedRpms(pTS->pCachedRpmsArray);
        }
        TDNFFreeCachedRpmsArray(pTS->pCachedRpmsArray);
    }
    TDNFClearNativePlan(pTS);
    TDNFFreeTransactionItems(pTS);
    TDNF_SAFE_FREE_MEMORY(pTS);

error:
    return dwError;
}

static uint32_t
TDNFRpmCreateTS(
    PTDNF pTdnf,
    PTDNF_SOLVED_PKG_INFO pSolvedInfo,
    PTDNFRPMTS *ppTS
    )
{
    uint32_t dwError = 0;
    PTDNFRPMTS pTS = NULL;

    if(!pTdnf || !pTdnf->pArgs || !pTdnf->pConf || !pSolvedInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(1, sizeof(TDNFRPMTS), (void **)&pTS);
    BAIL_ON_TDNF_ERROR(dwError);

    pTS->nQuiet = pTdnf->pArgs->nQuiet;

    dwError = TDNFAllocateMemory(
                  1,
                  sizeof(TDNF_CACHED_RPM_LIST),
                  (void**)&pTS->pCachedRpmsArray);
    BAIL_ON_TDNF_ERROR(dwError);

    pTS->nTransFlags = pTdnf->pConf->rpmTransFlags;

    dwError = TDNFPopulateTransaction(pTS, pTdnf, pSolvedInfo);
    BAIL_ON_TDNF_ERROR(dwError);

    *ppTS = pTS;

cleanup:
    return dwError;

error:
    if (pTS != NULL)
    {
        TDNFRpmCleanupTS(pTdnf, pTS);
    }
    goto cleanup;
}

static uint32_t
TDNFRunTransactionWithHistory(
    PTDNF pTdnf,
    PTDNFRPMTS pTS,
    struct history_ctx *pHistoryCtx,
    const char *pszCmdLine
    )
{
    uint32_t dwError = 0;
    int rc;
    char *pszDataDir = NULL;

    if(!pTdnf || !pTS || !pHistoryCtx)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFJoinPath(&pszDataDir,
                           pTdnf->pArgs->pszInstallRoot,
                           pTdnf->pConf->pszPersistDir,
                           NULL);
    if (dwError == 0 && pszDataDir)
    {
        dwError = TDNFUtilsMakeDirs(pszDataDir);
        if (dwError == ERROR_TDNF_ALREADY_EXISTS)
            dwError = 0;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    rc = history_sync_config(pHistoryCtx, pTdnf->pRpmConfig);
    if (rc != 0)
    {
        dwError = ERROR_TDNF_HISTORY_ERROR;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFRunTransaction(pTS, pTdnf);
    BAIL_ON_TDNF_ERROR(dwError);

    rc = history_update_state_config(
             pHistoryCtx,
             pTdnf->pRpmConfig,
             pszCmdLine);
    if (rc != 0)
    {
        dwError = ERROR_TDNF_HISTORY_ERROR;
        BAIL_ON_TDNF_ERROR(dwError);
    }
cleanup:
    TDNF_SAFE_FREE_MEMORY(pszDataDir);
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFRpmExecTransaction(
    PTDNF pTdnf,
    PTDNF_SOLVED_PKG_INFO pSolvedInfo
    )
{
    uint32_t dwError = 0;
    int nDownloadOnly = 0;
    PTDNFRPMTS pTS = NULL;
    struct history_ctx *pHistoryCtx = NULL;
    char *pszCmdLine = NULL;

    if(!pTdnf || !pTdnf->pArgs || !pTdnf->pConf || !pSolvedInfo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFRpmCreateTS(pTdnf, pSolvedInfo, &pTS);
    BAIL_ON_TDNF_ERROR(dwError);

    nDownloadOnly = pTdnf->pArgs->nDownloadOnly;
    if (!nDownloadOnly) {
        if (!pTdnf->pArgs->nTestOnly)
        {
            dwError = TDNFGetHistoryCtx(pTdnf, &pHistoryCtx, 0);
            BAIL_ON_TDNF_ERROR(dwError);

            if (pTdnf->pArgs->nArgc >= 1)
            {
                dwError = TDNFJoinArrayToString(&(pTdnf->pArgs->ppszArgv[1]),
                                                " ",
                                                pTdnf->pArgs->nArgc,
                                                &pszCmdLine);
                BAIL_ON_TDNF_ERROR(dwError);
            }

            dwError = TDNFRunTransactionWithHistory(pTdnf, pTS, pHistoryCtx, pszCmdLine);
            BAIL_ON_TDNF_ERROR(dwError);

            dwError = TDNFMarkAutoInstalled(pTdnf, pHistoryCtx, pSolvedInfo, 0);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        else
        {
            dwError = TDNFRunTransaction(pTS, pTdnf);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszCmdLine);
    if (pTS != NULL)
    {
        TDNFRpmCleanupTS(pTdnf, pTS);
    }
    if (pHistoryCtx)
    {
        destroy_history_ctx(pHistoryCtx);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
TDNFRpmExecHistoryTransaction(
    PTDNF pTdnf,
    PTDNF_SOLVED_PKG_INFO pSolvedInfo,
    PTDNF_HISTORY_ARGS pHistoryArgs
    )
{
    uint32_t dwError = 0;
    int nDownloadOnly = 0;
    PTDNFRPMTS pTS = NULL;
    struct history_ctx *pHistoryCtx = NULL;
    char *pszCmdLine = NULL;

    if(!pTdnf || !pSolvedInfo || !pHistoryArgs)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFRpmCreateTS(pTdnf, pSolvedInfo, &pTS);
    BAIL_ON_TDNF_ERROR(dwError);

    nDownloadOnly = pTdnf->pArgs->nDownloadOnly;
    if (!nDownloadOnly && !pTdnf->pArgs->nTestOnly) {
        int rc = 0;
        int trans_id;

        dwError = TDNFGetHistoryCtx(pTdnf, &pHistoryCtx, 0);
        BAIL_ON_TDNF_ERROR(dwError);

        trans_id = history_get_current_transaction_id(pHistoryCtx);

        if (pTdnf->pArgs->nArgc >= 1)
        {
            dwError = TDNFJoinArrayToString(&(pTdnf->pArgs->ppszArgv[1]),
                                            " ",
                                            pTdnf->pArgs->nArgc,
                                            &pszCmdLine);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        dwError = TDNFRunTransactionWithHistory(pTdnf, pTS, pHistoryCtx, pszCmdLine);
        BAIL_ON_TDNF_ERROR(dwError);

        /* if no rpm was added/removed no transaction was added yet,
            so we need to create a new transaction for the flags */
        if (trans_id == history_get_current_transaction_id(pHistoryCtx))
        {
            rc = history_add_transaction(pHistoryCtx, pszCmdLine);
            if (rc != 0)
            {
                dwError = ERROR_TDNF_HISTORY_ERROR;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
        else
        {
            /* Corner case where a redo/undo pulls additional dependencies. This
               can happen when those were installed originally, but have since
               been removed (this cannot happen on rollback because we'd restore the
               exact state).
               Avoid setting the flag to 0 (by using nAutoOnly=1) because it may
               be re-set again, and this case only applies to auto installed pkgs.
            */
            dwError = TDNFMarkAutoInstalled(pTdnf, pHistoryCtx, pSolvedInfo, 1);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if (pHistoryArgs->nCommand == HISTORY_CMD_ROLLBACK)
        {
            rc = history_restore_auto_flags(pHistoryCtx, pHistoryArgs->nTo);
        }
        else if (pHistoryArgs->nCommand == HISTORY_CMD_UNDO)
        {
            rc = history_replay_auto_flags(pHistoryCtx, pHistoryArgs->nTo, pHistoryArgs->nFrom - 1);
        }
        else if (pHistoryArgs->nCommand == HISTORY_CMD_REDO)
        {
            rc = history_replay_auto_flags(pHistoryCtx, pHistoryArgs->nFrom - 1, pHistoryArgs->nTo);
        }
        if (rc != 0)
        {
            dwError = ERROR_TDNF_HISTORY_ERROR;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }
    else if(!nDownloadOnly && pTdnf->pArgs->nTestOnly)
    {
        dwError = TDNFRunTransaction(pTS, pTdnf);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszCmdLine);
    if (pTS != NULL)
    {
        TDNFRpmCleanupTS(pTdnf, pTS);
    }
    if (pHistoryCtx)
    {
        destroy_history_ctx(pHistoryCtx);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
TDNFPopulateTransaction(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    PTDNF_SOLVED_PKG_INFO pSolvedInfo
    )
{
    uint32_t dwError = 0;
    if(pSolvedInfo->pPkgsToInstall)
    {
        dwError = TDNFTransAddInstallPkgs(
                      pTS,
                      pTdnf,
                      pSolvedInfo->pPkgsToInstall, INSTALL_INSTALL);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(pSolvedInfo->pPkgsToReinstall)
    {
        dwError = TDNFTransAddInstallPkgs(
                      pTS,
                      pTdnf,
                      pSolvedInfo->pPkgsToReinstall,
                      INSTALL_REINSTALL);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(pSolvedInfo->pPkgsToUpgrade)
    {
        dwError = TDNFTransAddInstallPkgs(
                      pTS,
                      pTdnf,
                      pSolvedInfo->pPkgsToUpgrade,
                      INSTALL_UPGRADE);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(pSolvedInfo->pPkgsToRemove)
    {
        dwError = TDNFTransAddErasePkgs(
                      pTS,
                      pTdnf,
                      pSolvedInfo->pPkgsToRemove);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(pSolvedInfo->pPkgsObsoleted)
    {
        dwError = TDNFTransAddErasePkgs(
                      pTS,
                      pTdnf,
                      pSolvedInfo->pPkgsObsoleted);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(pSolvedInfo->pPkgsToDowngrade)
    {
        dwError = TDNFTransAddInstallPkgs(
                      pTS,
                      pTdnf,
                      pSolvedInfo->pPkgsToDowngrade,
                      INSTALL_INSTALL);
        BAIL_ON_TDNF_ERROR(dwError);
        if(pSolvedInfo->pPkgsRemovedByDowngrade)
        {
            dwError = TDNFTransAddErasePkgs(
                      pTS,
                      pTdnf,
                      pSolvedInfo->pPkgsRemovedByDowngrade);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static void
TDNFClearNativePlan(
    PTDNFRPMTS pTS
    )
{
    if(!pTS)
    {
        return;
    }

    TDNFRepoMdNativeTransactionPlanFree(pTS->pNativePlan);
    pTS->pNativePlan = NULL;
}

static void
TDNFFreeTransactionItems(
    PTDNFRPMTS pTS
    )
{
    PTDNF_RPM_TS_ITEM pItem = NULL;
    PTDNF_RPM_TS_ITEM pNext = NULL;

    if(!pTS)
    {
        return;
    }

    pItem = pTS->pTransactionItems;
    while(pItem)
    {
        pNext = pItem->pNext;
        tdnf_rpm_file_close(pItem->pRpmFile);
        TDNF_SAFE_FREE_MEMORY(pItem->pszPath);
        TDNF_SAFE_FREE_MEMORY(pItem->pszName);
        TDNF_SAFE_FREE_MEMORY(pItem->pszEVR);
        TDNF_SAFE_FREE_MEMORY(pItem->pszArch);
        TDNF_SAFE_FREE_MEMORY(pItem);
        pItem = pNext;
    }

    pTS->pTransactionItems = NULL;
    pTS->pTransactionItemsTail = NULL;
    pTS->dwTransactionItemCount = 0;
}

static uint32_t
TDNFRecordTransactionItem(
    PTDNFRPMTS pTS,
    TDNF_RPM_TS_ITEM_TYPE nType,
    int nPackageKind,
    tdnf_rpm_file **ppRpmFile,
    const char *pszPath,
    uint32_t dwRpmDbHnum,
    const char *pszName,
    const char *pszEVR,
    const char *pszArch
    )
{
    uint32_t dwError = 0;
    PTDNF_RPM_TS_ITEM pItem = NULL;
    PTDNF_RPM_TS_ITEM pExisting = NULL;

    if(!pTS ||
       (nType != TDNF_RPM_TS_ITEM_ERASE &&
        (!ppRpmFile || !*ppRpmFile ||
         nPackageKind != TDNF_RPM_PACKAGE_KIND_BINARY)) ||
       (nType == TDNF_RPM_TS_ITEM_ERASE && !dwRpmDbHnum))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(nType == TDNF_RPM_TS_ITEM_ERASE)
    {
        for(pExisting = pTS->pTransactionItems;
            pExisting;
            pExisting = pExisting->pNext)
        {
            if(pExisting->nType == TDNF_RPM_TS_ITEM_ERASE &&
               pExisting->dwRpmDbHnum == dwRpmDbHnum)
            {
                goto cleanup;
            }
        }
    }

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_RPM_TS_ITEM), (void **)&pItem);
    BAIL_ON_TDNF_ERROR(dwError);

    pItem->nType = nType;
    pItem->nPackageKind = nPackageKind;
    pItem->dwRpmDbHnum = dwRpmDbHnum;

    if(!IsNullOrEmptyString(pszPath))
    {
        dwError = TDNFAllocateString(pszPath, &pItem->pszPath);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!IsNullOrEmptyString(pszName))
    {
        dwError = TDNFAllocateString(pszName, &pItem->pszName);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!IsNullOrEmptyString(pszEVR))
    {
        dwError = TDNFAllocateString(pszEVR, &pItem->pszEVR);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!IsNullOrEmptyString(pszArch))
    {
        dwError = TDNFAllocateString(pszArch, &pItem->pszArch);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(ppRpmFile)
    {
        pItem->pRpmFile = *ppRpmFile;
        *ppRpmFile = NULL;
    }

    if(pTS->pTransactionItemsTail)
    {
        pTS->pTransactionItemsTail->pNext = pItem;
    }
    else
    {
        pTS->pTransactionItems = pItem;
    }
    pTS->pTransactionItemsTail = pItem;
    pTS->dwTransactionItemCount++;

cleanup:
    return dwError;

error:
    if(pItem)
    {
        TDNF_SAFE_FREE_MEMORY(pItem->pszPath);
        TDNF_SAFE_FREE_MEMORY(pItem->pszName);
        TDNF_SAFE_FREE_MEMORY(pItem->pszEVR);
        TDNF_SAFE_FREE_MEMORY(pItem->pszArch);
        TDNF_SAFE_FREE_MEMORY(pItem);
    }
    goto cleanup;
}

static uint32_t
TDNFNativeOrderAndCheck(
    PTDNFRPMTS pTS,
    PTDNF pTdnf
    )
{
    uint32_t dwError = 0;
    TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2 *pInputs = NULL;
    const unsigned char **ppbHeaders = NULL;
    size_t *pnHeaderLengths = NULL;
    uint64_t *pqwPackageSizes = NULL;
    PTDNF_RPM_TS_ITEM pItem = NULL;
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan = NULL;
    uint32_t dwIndex = 0;
    const char *pszLastError = NULL;

    if(!pTS || !pTdnf)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    TDNFClearNativePlan(pTS);

    if(!pTS->dwTransactionItemCount)
    {
        goto cleanup;
    }

    dwError = TDNFAllocateMemory(
                  pTS->dwTransactionItemCount,
                  sizeof(TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2),
                  (void **)&pInputs);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(
                  pTS->dwTransactionItemCount,
                  sizeof(*ppbHeaders),
                  (void **)&ppbHeaders);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(
                  pTS->dwTransactionItemCount,
                  sizeof(*pnHeaderLengths),
                  (void **)&pnHeaderLengths);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(
                  pTS->dwTransactionItemCount,
                  sizeof(*pqwPackageSizes),
                  (void **)&pqwPackageSizes);
    BAIL_ON_TDNF_ERROR(dwError);

    pItem = pTS->pTransactionItems;
    while(pItem)
    {
        const unsigned char *pbHeader = NULL;
        const unsigned char *pbRpm = NULL;
        size_t nHeaderLength = 0;
        size_t nRpmLength = 0;

        if(dwIndex >= pTS->dwTransactionItemCount)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        switch(pItem->nType)
        {
            case TDNF_RPM_TS_ITEM_INSTALL:
                pInputs[dwIndex].dwOperation =
                    TDNF_REPOMD_NATIVE_TRANSACTION_OP_INSTALL;
                break;

            case TDNF_RPM_TS_ITEM_UPGRADE:
                pInputs[dwIndex].dwOperation =
                    TDNF_REPOMD_NATIVE_TRANSACTION_OP_UPGRADE;
                break;

            case TDNF_RPM_TS_ITEM_REINSTALL:
                pInputs[dwIndex].dwOperation =
                    TDNF_REPOMD_NATIVE_TRANSACTION_OP_REINSTALL;
                break;

            case TDNF_RPM_TS_ITEM_ERASE:
                pInputs[dwIndex].dwOperation =
                    TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE;
                break;

            default:
                dwError = ERROR_TDNF_INVALID_PARAMETER;
                BAIL_ON_TDNF_ERROR(dwError);
        }

        if(pItem->nType != TDNF_RPM_TS_ITEM_ERASE)
        {
            if(!pItem->pRpmFile ||
               tdnf_rpm_file_main_header_blob(
                   pItem->pRpmFile,
                   &pbHeader,
                   &nHeaderLength) != 0 ||
               tdnf_rpm_file_bytes(
                   pItem->pRpmFile,
                   &pbRpm,
                   &nRpmLength) != 0)
            {
                dwError = ERROR_TDNF_RPM_CHECK;
                BAIL_ON_TDNF_ERROR(dwError);
            }
            ppbHeaders[dwIndex] = pbHeader;
            pnHeaderLengths[dwIndex] = nHeaderLength;
            pqwPackageSizes[dwIndex] = nRpmLength;
        }

        pInputs[dwIndex].pszPath = pItem->pszPath;
        pInputs[dwIndex].pszName = pItem->pszName;
        pInputs[dwIndex].pszEVR = pItem->pszEVR;
        pInputs[dwIndex].pszArch = pItem->pszArch;
        pInputs[dwIndex].dwRpmDbHnum = pItem->dwRpmDbHnum;

        dwIndex++;
        pItem = pItem->pNext;
    }

    if(dwIndex != pTS->dwTransactionItemCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = tdnf_repomd_native_verified_transaction_solve_config(
                  pInputs,
                  ppbHeaders,
                  pnHeaderLengths,
                  pqwPackageSizes,
                  pTS->dwTransactionItemCount,
                  pTdnf->pRpmConfig,
                  &pPlan);
    if(dwError)
    {
        pszLastError = TDNFRepoMdNativeTransactionLastError();
        if(!IsNullOrEmptyString(pszLastError))
        {
            pr_err("rpmzig-transaction-check: %s\n", pszLastError);
        }
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(!pPlan ||
       pPlan->dwItemCount != pTS->dwTransactionItemCount ||
       (pPlan->dwItemCount &&
        (!pPlan->pdwOrderIndices || !pPlan->pItems)))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pTS->pNativePlan = pPlan;
    pPlan = NULL;

    if(pTS->pNativePlan->dwProblemCount)
    {
        dwError = ERROR_TDNF_RPM_CHECK;
        for(dwIndex = 0;
            dwIndex < pTS->pNativePlan->dwProblemCount;
            dwIndex++)
        {
            if(pTS->pNativePlan->pProblems[dwIndex].nType ==
               TDNF_REPOMD_NATIVE_PROBLEM_FILE_CONFLICT)
            {
                dwError = ERROR_TDNF_TRANSACTION_FAILED;
                break;
            }
        }
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pInputs);
    TDNF_SAFE_FREE_MEMORY(ppbHeaders);
    TDNF_SAFE_FREE_MEMORY(pnHeaderLengths);
    TDNF_SAFE_FREE_MEMORY(pqwPackageSizes);
    TDNFRepoMdNativeTransactionPlanFree(pPlan);
    return dwError;

error:
    goto cleanup;
}

static void
reportProblems(PTDNFRPMTS pTS)
{
    uint32_t dwIndex = 0;
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan = NULL;

    if(!pTS || !pTS->pNativePlan)
    {
        return;
    }

    pPlan = pTS->pNativePlan;
    if(!pPlan->dwProblemCount || !pPlan->pProblems)
    {
        return;
    }

    pr_crit("Found %u problems\n", pPlan->dwProblemCount);
    for(dwIndex = 0; dwIndex < pPlan->dwProblemCount; dwIndex++)
    {
        const TDNF_REPOMD_NATIVE_TRANSACTION_PROBLEM *pProblem =
            &pPlan->pProblems[dwIndex];
        const char *pszPackage = pProblem->pszPackage ?
            pProblem->pszPackage : "(unknown)";
        const char *pszRelated = pProblem->pszRelatedPackage ?
            pProblem->pszRelatedPackage : "(unknown)";
        const char *pszSubject = pProblem->pszSubject ?
            pProblem->pszSubject : "(unknown)";

        switch(pProblem->nType)
        {
            case TDNF_REPOMD_NATIVE_PROBLEM_DEPENDENCY:
                pr_crit("nothing provides %s needed by %s\n",
                        pszSubject, pszPackage);
                break;
            case TDNF_REPOMD_NATIVE_PROBLEM_PRETRANS:
                pr_crit("nothing provides %s needed by %s\n",
                        pszSubject, pszPackage);
                pr_err("Detected rpm pre-transaction dependency errors. "
                       "Install %s first to resolve this failure.\n",
                       pszSubject);
                break;
            case TDNF_REPOMD_NATIVE_PROBLEM_CONFLICT:
                pr_crit("package %s conflicts with %s\n",
                        pszPackage, pszRelated);
                break;
            case TDNF_REPOMD_NATIVE_PROBLEM_OBSOLETES:
                pr_crit("package %s obsoletes %s\n",
                        pszPackage, pszRelated);
                break;
            case TDNF_REPOMD_NATIVE_PROBLEM_FILE_CONFLICT:
                pr_crit("file %s from install of %s conflicts with file "
                        "from package %s\n",
                        pszSubject, pszPackage, pszRelated);
                break;
            case TDNF_REPOMD_NATIVE_PROBLEM_UNSUPPORTED_MULTIPLE:
                pr_crit("package %s has %u installed %s instances selected "
                        "for one upgrade; remove extra instances or configure "
                        "the package as installonly\n",
                        pszPackage, pProblem->dwCount, pszSubject);
                break;
            default:
                pr_crit("unknown native transaction problem for %s\n",
                        pszPackage);
                break;
        }
    }
}

/*
 * Restrict number of open files. When rpm cannot access /proc
 * it tries to set the close on exec flag for every possible
 * fd, which may take a long time if the limit is very high.
 * See also https://github.com/rpm-software-management/rpm/issues/2081.
 * This can be disabled by setting "openmax=0" in the configuration.
 *
 * The native transaction executor (client/rpmtrans_native.c) does not
 * exhibit this legacy behaviour, so TDNFSetOpenMax is no
 * longer wired into the transaction path. The `openmax` config key
 * remains parsed and stored on TDNF_CONF for public-API stability but
 * is a no-op.
 */

uint32_t
TDNFRunTransaction(
    PTDNFRPMTS pTS,
    PTDNF pTdnf
    )
{
    uint32_t dwError = 0;

    if(!pTS || !pTdnf || !pTdnf->pConf || !pTdnf->pArgs)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFNativeOrderAndCheck(pTS, pTdnf);
    BAIL_ON_TDNF_ERROR(dwError);

    if(!pTS->dwTransactionItemCount)
    {
        goto cleanup;
    }

    /*
     * The composed rpmzig install/rpmdb-write/erase/scriptlet/trigger
     * executor is authoritative and has no build-time opt-out.
     */
    dwError = TDNFRunTransactionNative(pTS, pTdnf, pTS->pNativePlan);
    if (dwError)
    {
        reportProblems(pTS);
    }

cleanup:
    return dwError;

error:
    if(pTS)
    {
        reportProblems(pTS);
    }
    goto cleanup;
}

uint32_t
TDNFTransAddInstallPkgs(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    PTDNF_PKG_INFO pInfos,
    int nInstallFlag
    )
{
    uint32_t dwError = 0;
    PTDNF_PKG_INFO pInfo;

    if(!pInfos)
    {
        dwError = ERROR_TDNF_NO_DATA;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for (pInfo = pInfos; pInfo; pInfo = pInfo->pNext)
    {
        PTDNF_REPO_DATA pRepo = NULL;

        dwError = TDNFFindRepoById(pTdnf, pInfo->pszRepoName, &pRepo);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFTransAddInstallPkg(
                      pTS,
                      pTdnf,
                      pInfo,
                      pRepo,
                      nInstallFlag);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    if(dwError == ERROR_TDNF_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

uint32_t
TDNFTransAddInstallPkg(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    PTDNF_PKG_INFO pInfo,
    PTDNF_REPO_DATA pRepo,
    int nInstallFlag
    )
{
    uint32_t dwError = 0;
    char* pszFilePath = NULL;
    tdnf_rpm_file *pRpmFile = NULL;
    tdnf_rpm_file_metadata rpmMetadata = {0};
    PTDNF_CACHED_RPM_ENTRY pRpmCache = NULL;
    const char* pszPackageLocation = NULL;
    const char* pszPkgName = NULL;
    const char* pszHeaderName = NULL;
    const char* pszHeaderArch = NULL;
    char* pszHeaderEVR = NULL;
    uint8_t digest_from_file[TDNF_MAX_DIGEST_LEN] = {0};
    hash_op *hash = NULL;
    const unsigned char *pbRpmBytes = NULL;
    size_t nRpmLength = 0;
    int nPackageKind = TDNF_RPM_PACKAGE_KIND_BINARY;

    if(!pTS || !pTdnf || !pInfo || !pRepo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pszPackageLocation = pInfo->pszLocation;
    pszPkgName = pInfo->pszName;

    if (pszPackageLocation[0] == '/')
    {
        dwError = TDNFAllocateString(
                      pszPackageLocation,
                      &pszFilePath
                  );
        BAIL_ON_TDNF_ERROR(dwError);
    }
    else
    {
        if (!pTdnf->pArgs->nDownloadOnly || pTdnf->pArgs->pszDownloadDir == NULL)
        {
            int nInPlace = 0;
            int i;

            /* avoid copying a file to cache if we can access it directly */

            /* location may already be an absolute file:// URL (from xml:base) */
            if (strncasecmp(pszPackageLocation, "file://", 7) == 0)
            {
                dwError = TDNFAllocateString(pszPackageLocation + 7, &pszFilePath);
                BAIL_ON_TDNF_ERROR(dwError);
                if (access(pszFilePath, F_OK) == 0)
                {
                    nInPlace = 1;
                }
                else
                {
                    TDNF_SAFE_FREE_MEMORY(pszFilePath);
                }
            }

            if (!nInPlace)
            {
                for (i = 0; pRepo->ppszBaseUrls[i]; i++) {
                    if (strncasecmp(pRepo->ppszBaseUrls[i], "file://", 7) == 0)
                    {
                        dwError = TDNFJoinPath(&pszFilePath,
                                               &(pRepo->ppszBaseUrls[i][7]),
                                               pszPackageLocation,
                                               NULL);
                        BAIL_ON_TDNF_ERROR(dwError);
                        if(access(pszFilePath, F_OK) == 0) {
                            nInPlace = 1;
                            break;
                        }
                        TDNF_SAFE_FREE_MEMORY(pszFilePath);
                    }
                }
            }

            if (!nInPlace)
            {
                dwError = TDNFDownloadPackageToCache(
                              pTdnf,
                              pszPackageLocation,
                              pszPkgName,
                              pRepo,
                              &pszFilePath
                );
            }
        }
        else
        {
            dwError = TDNFDownloadPackageToDirectory(
                          pTdnf,
                          pszPackageLocation,
                          pszPkgName,
                          pRepo,
                          pTdnf->pArgs->pszDownloadDir,
                          &pszFilePath
            );

        }
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //A download could have been triggered.
    //So check access and bail if not available
    if(access(pszFilePath, F_OK))
    {
        dwError = errno;
        pr_err("could not access file %s: %s (%d)\n", pszFilePath, strerror(errno), errno);
        BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
    }

    /*
     * Parse once and keep this handle for every subsequent check and for the
     * transaction.  In particular, never validate repodata against a path
     * that is reopened before signature/digest verification.
     */
    pRpmFile = tdnf_rpm_file_open(pszFilePath);
    if(!pRpmFile)
    {
        pr_err("Unable to parse package %s: %s\n",
               pszFilePath, tdnf_rpmdb_last_error());
        dwError = ERROR_TDNF_RPMRC_NOTFOUND;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(pInfo->pbChecksum != NULL) {
        if(pInfo->nChecksumType < TDNF_HASH_MD5 ||
           pInfo->nChecksumType >= TDNF_HASH_SENTINEL)
        {
            dwError = ERROR_TDNF_CHECKSUM_MISMATCH;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        hash = hash_ops + pInfo->nChecksumType;

        if(tdnf_rpm_file_digest(
               pRpmFile,
               pInfo->nChecksumType,
               digest_from_file,
               sizeof(digest_from_file)) != 0)
        {
            pr_err("Unable to calculate checksum for %s: %s\n",
                   pszFilePath, tdnf_rpmdb_last_error());
            dwError = ERROR_TDNF_RPM_CHECK;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if (memcmp(digest_from_file, pInfo->pbChecksum, hash->length))
        {
            pr_err("rpm file (%s) Checksum FAILED (digest mismatch)\n", pszFilePath);
            dwError = ERROR_TDNF_CHECKSUM_MISMATCH;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    if(tdnf_rpm_file_bytes(pRpmFile, &pbRpmBytes, &nRpmLength) != 0)
    {
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (nRpmLength != (size_t)pInfo->dwDownloadSizeBytes) {
        pr_err("rpm file (%s) size (%zu) does not match expected size (%u)\n", pszFilePath, nRpmLength, pInfo->dwDownloadSizeBytes);
        dwError = ERROR_TDNF_SIZE_MISMATCH;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGPGCheckPackageWithFile(
                  pTdnf,
                  pRepo,
                  pszFilePath,
                  pRpmFile,
                  NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    if(tdnf_rpm_file_get_metadata(pRpmFile, &rpmMetadata) != 0 ||
       !rpmMetadata.main_header_blob ||
       !rpmMetadata.main_header_blob_len)
    {
        pr_err("Unable to read native package metadata for %s: %s\n",
               pszFilePath, tdnf_rpmdb_last_error());
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    nPackageKind = rpmMetadata.package_kind;
    pszHeaderName = rpmMetadata.name;
    pszHeaderArch = rpmMetadata.arch;
    if(rpmMetadata.has_epoch)
    {
        dwError = TDNFAllocateStringPrintf(
                      &pszHeaderEVR,
                      "%u:%s-%s",
                      rpmMetadata.epoch,
                      rpmMetadata.version,
                      rpmMetadata.release);
    }
    else
    {
        dwError = TDNFAllocateStringPrintf(
                      &pszHeaderEVR,
                      "%s-%s",
                      rpmMetadata.version,
                      rpmMetadata.release);
    }
    BAIL_ON_TDNF_ERROR(dwError);
    if(IsNullOrEmptyString(pszHeaderName) ||
       IsNullOrEmptyString(pszHeaderEVR) ||
       IsNullOrEmptyString(pszHeaderArch))
    {
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(nPackageKind != TDNF_RPM_PACKAGE_KIND_BINARY &&
       nPackageKind != TDNF_RPM_PACKAGE_KIND_SOURCE &&
       nPackageKind != TDNF_RPM_PACKAGE_KIND_NOSRC)
    {
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(pTS->pCachedRpmsArray &&
       !strncmp(pszFilePath, pTdnf->pConf->pszCacheDir,
           strlen(pTdnf->pConf->pszCacheDir)))
    {
        dwError = TDNFAllocateMemory(
                      1,
                      sizeof(TDNF_CACHED_RPM_ENTRY),
                      (void**)&pRpmCache);
        BAIL_ON_TDNF_ERROR(dwError);
        pRpmCache->pszFilePath = pszFilePath;
    }

    if(nPackageKind != TDNF_RPM_PACKAGE_KIND_BINARY)
    {
        if (!pTdnf->pArgs->nDownloadOnly && !pTdnf->pArgs->nTestOnly)
        {
            if(tdnf_rpm_file_extract_source_config(
                   pRpmFile,
                   pTdnf->pRpmConfig,
                   (uint32_t)pTS->nTransFlags) != 0)
            {
                pr_err("Unable to extract source package %s: %s\n",
                       pszFilePath, tdnf_rpmdb_last_error());
                dwError = ERROR_TDNF_RPM_CHECK;
            }
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }
    else
    {
        dwError = TDNFRecordTransactionItem(
                      pTS,
                      nInstallFlag == INSTALL_REINSTALL ?
                          TDNF_RPM_TS_ITEM_REINSTALL :
                          (nInstallFlag == INSTALL_UPGRADE ?
                               TDNF_RPM_TS_ITEM_UPGRADE :
                               TDNF_RPM_TS_ITEM_INSTALL),
                      nPackageKind,
                      &pRpmFile,
                      pszFilePath,
                      0,
                      pszHeaderName,
                      pszHeaderEVR,
                      pszHeaderArch);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(pRpmCache)
    {
        pRpmCache->pNext = pTS->pCachedRpmsArray->pHead;
        pTS->pCachedRpmsArray->pHead = pRpmCache;
        pRpmCache = NULL;
        pszFilePath = NULL;
    }

cleanup:
    tdnf_rpm_file_close(pRpmFile);
    TDNF_SAFE_FREE_MEMORY(pszHeaderEVR);
    TDNF_SAFE_FREE_MEMORY(pszFilePath);
    return dwError;

error:
    pr_err("Error processing package: %s\n", pszPackageLocation ? pszPackageLocation : "(null)");
    TDNF_SAFE_FREE_MEMORY(pszFilePath);
    TDNF_SAFE_FREE_MEMORY(pRpmCache);
    goto cleanup;
}

uint32_t
TDNFTransAddErasePkgs(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    PTDNF_PKG_INFO pInfos
    )
{
    uint32_t dwError = 0;
    PTDNF_PKG_INFO pInfo;

    if(!pInfos)
    {
        dwError = ERROR_TDNF_NO_DATA;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(pInfo = pInfos; pInfo; pInfo = pInfo->pNext)
    {
        dwError = TDNFTransAddErasePkg(pTS, pTdnf, pInfo);
        BAIL_ON_TDNF_ERROR(dwError);
    }
cleanup:
    return dwError;

error:
    if(dwError == ERROR_TDNF_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

uint32_t
TDNFTransAddErasePkg(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    PTDNF_PKG_INFO pInfo
    )
{
    uint32_t dwError = 0;
    tdnf_rpmdb_label_match *pMatches = NULL;
    size_t nMatchCount = 0;
    size_t i = 0;
    const char *pszPkgName = NULL;
    const char *pszPkgEvr = NULL;

    if(!pTS || !pTdnf || !pTdnf->pRpmConfig || !pInfo ||
       IsNullOrEmptyString(pInfo->pszName) ||
       IsNullOrEmptyString(pInfo->pszEVR))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pszPkgName = pInfo->pszName;
    pszPkgEvr = pInfo->pszEVR;

    if(tdnf_rpmdb_find_label_matches_config(
           pTdnf->pRpmConfig,
           pszPkgName,
           pszPkgEvr,
           &pMatches,
           &nMatchCount) != 0)
    {
        pr_err("Unable to look up installed package %s-%s: %s\n",
               pszPkgName, pszPkgEvr, tdnf_rpmdb_last_error());
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(i = 0; i < nMatchCount; i++)
    {
        if(!IsNullOrEmptyString(pInfo->pszArch) &&
           (IsNullOrEmptyString(pMatches[i].arch) ||
            strcmp(pInfo->pszArch, pMatches[i].arch)))
        {
            continue;
        }
        dwError = TDNFRecordTransactionItem(
                      pTS,
                      TDNF_RPM_TS_ITEM_ERASE,
                      TDNF_RPM_PACKAGE_KIND_BINARY,
                      NULL,
                      NULL,
                      pMatches[i].hnum,
                      pMatches[i].name,
                      pMatches[i].evr,
                      pMatches[i].arch);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    tdnf_rpmdb_label_matches_free(pMatches, nMatchCount);
    return dwError;

error:
    goto cleanup;
}

void*
TDNFRpmCB(
    const void *pArg,
    int nWhat,
    int64_t llAmount,
    int64_t llTotal,
    const void *pKey,
    void *pData
    )
{
    (void)pArg;
    (void)nWhat;
    (void)llAmount;
    (void)llTotal;
    (void)pKey;
    (void)pData;
    return NULL;
}

uint32_t
TDNFRemoveCachedRpms(
    PTDNF_CACHED_RPM_LIST pCachedRpmsList
    )
{
    uint32_t dwError = 0;
    PTDNF_CACHED_RPM_ENTRY pCur = NULL;

    if(!pCachedRpmsList)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    pCur = pCachedRpmsList->pHead;
    while(pCur != NULL)
    {
        if(!IsNullOrEmptyString(pCur->pszFilePath))
        {
            if(unlink(pCur->pszFilePath))
            {
                dwError = errno;
                BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
            }
        }
        pCur = pCur->pNext;
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

void
TDNFFreeCachedRpmsArray(
    PTDNF_CACHED_RPM_LIST pArray
    )
{
    PTDNF_CACHED_RPM_ENTRY pCur = NULL;
    PTDNF_CACHED_RPM_ENTRY pNext = NULL;

    if(pArray)
    {
        pCur = pArray->pHead;
        while(pCur != NULL)
        {
            pNext = pCur->pNext;
            TDNF_SAFE_FREE_MEMORY(pCur->pszFilePath);
            TDNF_SAFE_FREE_MEMORY(pCur);
            pCur = pNext;
        }
        TDNF_SAFE_FREE_MEMORY(pArray);
    }
}
