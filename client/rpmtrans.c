/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

#include "rpm/rpmcli.h"

#include "../llconf/nodes.h"

#include "rpmtrans_native.h"

#define INSTALL_INSTALL 0
#define INSTALL_UPGRADE 1
#define INSTALL_REINSTALL 2

static void
TDNFClearNativeProblems(
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
    Header pHeader,
    const char *pszPath,
    uint32_t dwDbOffset,
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

    if(pTS->pTS)
    {
        rpmtsCloseDB(pTS->pTS);
        rpmtsFree(pTS->pTS);
    }
    if(pTS->pCachedRpmsArray)
    {
        if(!nKeepCachedRpms && !nDownloadOnly)
        {
            TDNFRemoveCachedRpms(pTS->pCachedRpmsArray);
        }
        TDNFFreeCachedRpmsArray(pTS->pCachedRpmsArray);
    }
    TDNFClearNativeProblems(pTS);
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

    rpmSetVerbosity(TDNFConfGetRpmVerbosity(pTdnf));

    pTS->pTS = rpmtsCreate();
    if(!pTS->pTS)
    {
        dwError = ERROR_TDNF_RPMTS_CREATE_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pTS->nTransFlags = pTdnf->pConf->rpmTransFlags;

    if(rpmtsSetRootDir (pTS->pTS, pTdnf->pArgs->pszInstallRoot))
    {
        dwError = ERROR_TDNF_RPMTS_BAD_ROOT_DIR;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(rpmtsSetNotifyCallback(pTS->pTS, TDNFRpmCB, (void*)pTS))
    {
        dwError = ERROR_TDNF_RPMTS_SET_CB_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

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

    rc = history_sync(pHistoryCtx, pTdnf->pArgs->pszInstallRoot);
    if (rc != 0)
    {
        dwError = ERROR_TDNF_HISTORY_ERROR;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFRunTransaction(pTS, pTdnf);
    BAIL_ON_TDNF_ERROR(dwError);

    rc = history_update_state(pHistoryCtx, pTdnf->pArgs->pszInstallRoot, pszCmdLine);
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
                      pSolvedInfo->pPkgsToRemove);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(pSolvedInfo->pPkgsObsoleted)
    {
        dwError = TDNFTransAddErasePkgs(
                      pTS,
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
TDNFClearNativeProblems(
    PTDNFRPMTS pTS
    )
{
    if(!pTS)
    {
        return;
    }

    if(pTS->ppszNativeProblems)
    {
        TDNFFreeStringArray(pTS->ppszNativeProblems);
        pTS->ppszNativeProblems = NULL;
    }
    pTS->dwNativeProblemCount = 0;
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
        if(pItem->pHeader)
        {
            headerFree(pItem->pHeader);
        }
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
    Header pHeader,
    const char *pszPath,
    uint32_t dwDbOffset,
    const char *pszName,
    const char *pszEVR,
    const char *pszArch
    )
{
    uint32_t dwError = 0;
    PTDNF_RPM_TS_ITEM pItem = NULL;

    if(!pTS || !pHeader)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_RPM_TS_ITEM), (void **)&pItem);
    BAIL_ON_TDNF_ERROR(dwError);

    pItem->nType = nType;
    pItem->pHeader = headerLink(pHeader);
    if(!pItem->pHeader)
    {
        dwError = ERROR_TDNF_OUT_OF_MEMORY;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    pItem->dwDbOffset = dwDbOffset;

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
        if(pItem->pHeader)
        {
            headerFree(pItem->pHeader);
        }
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
    TDNF_REPOMD_NATIVE_TRANSACTION_ITEM *pInputs = NULL;
    PTDNF_RPM_TS_ITEM pItem = NULL;
    char **ppszOrderLines = NULL;
    char **ppszProblemLines = NULL;
    uint32_t dwOrderCount = 0;
    uint32_t dwProblemCount = 0;
    uint32_t dwIndex = 0;
    const char *pszLastError = NULL;

    if(!pTS || !pTdnf)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    TDNFClearNativeProblems(pTS);

    if(!pTS->dwTransactionItemCount)
    {
        goto cleanup;
    }

    dwError = TDNFAllocateMemory(
                  pTS->dwTransactionItemCount,
                  sizeof(TDNF_REPOMD_NATIVE_TRANSACTION_ITEM),
                  (void **)&pInputs);
    BAIL_ON_TDNF_ERROR(dwError);

    pItem = pTS->pTransactionItems;
    while(pItem)
    {
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

        pInputs[dwIndex].pszPath = pItem->pszPath;
        pInputs[dwIndex].pszName = pItem->pszName;
        pInputs[dwIndex].pszEVR = pItem->pszEVR;
        pInputs[dwIndex].pszArch = pItem->pszArch;

        dwIndex++;
        pItem = pItem->pNext;
    }

    if(dwIndex != pTS->dwTransactionItemCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFRepoMdNativeTransactionSolve(
                  pInputs,
                  pTS->dwTransactionItemCount,
                  TDNFNativeQueryInstallRoot(pTdnf),
                  &ppszOrderLines,
                  &dwOrderCount,
                  &ppszProblemLines,
                  &dwProblemCount);
    if(dwError)
    {
        pszLastError = TDNFRepoMdNativeTransactionLastError();
        if(!IsNullOrEmptyString(pszLastError))
        {
            pr_err("rpmzig-transaction-check: %s\n", pszLastError);
        }
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(dwProblemCount)
    {
        pTS->ppszNativeProblems = ppszProblemLines;
        pTS->dwNativeProblemCount = dwProblemCount;
        ppszProblemLines = NULL;
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    /*
     * `ppszOrderLines` used to feed the librpm rpmts rebuild step
     * consumed by the retired `rpmtsRun` fallback. The native
     * executor (client/rpmtrans_native.c) walks
     * `pTS->pTransactionItems` directly and does its own ordering,
     * so the order lines returned by TDNFRepoMdNativeTransactionSolve
     * are dropped here.
     */

cleanup:
    TDNF_SAFE_FREE_MEMORY(pInputs);
    TDNFFreeStringArray(ppszOrderLines);
    if(ppszProblemLines)
    {
        TDNFFreeStringArray(ppszProblemLines);
    }
    return dwError;

error:
    goto cleanup;
}

static uint32_t
TDNFDetectPreTransFailure(
    rpmts pTS,
    char *pszError
    )
{
    uint32_t dwError = 0;
    rpmtsi pi = NULL;
    rpmte pte = NULL;
    char *pszToken;
    int i = 0;
    char *pszErrorStr = NULL;
    char *pszPkgName = NULL;
    char *pszSymbol = NULL;
    char *pszVersion = NULL;
    char *pszCachePkgName = NULL;
    char *pszCachePkgEVR = NULL;

    if (!pTS || IsNullOrEmptyString(pszError))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    // Error Str has the format: <Pkg-Name> <Symbol> <version-release>
    dwError = TDNFAllocateString(pszError, &pszErrorStr);
    BAIL_ON_TDNF_ERROR(dwError);

    pszToken = strtok(pszErrorStr, " ");
    while (pszToken != NULL)
    {
        switch(i)
        {
            case 0:
                pszPkgName = pszToken;
                break;
            case 1:
                pszSymbol = pszToken;
                break;
            case 2:
                pszVersion = pszToken;
                break;
            default:
                pr_err("RPM problem string format unsupported\n");
                dwError = ERROR_TDNF_INVALID_PARAMETER;
                BAIL_ON_TDNF_ERROR(dwError);
        }
        i++;
        pszToken = strtok(NULL, " ");
    }

    if (IsNullOrEmptyString(pszPkgName) || IsNullOrEmptyString(pszSymbol) || IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pi = rpmtsiInit(pTS);
    while ((pte = rpmtsiNext(pi, 0)) != NULL)
    {
        dwError = TDNFAllocateString(rpmteN(pte), &pszCachePkgName);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFAllocateString(rpmteEVR(pte), &pszCachePkgEVR);
        BAIL_ON_TDNF_ERROR(dwError);

        if (strcmp(pszCachePkgName, pszPkgName) == 0)
        {
            if ((strchr(pszSymbol, '>') && (rpmvercmp(pszCachePkgEVR, pszVersion) > 0)) ||
                (strchr(pszSymbol, '<') && (rpmvercmp(pszCachePkgEVR, pszVersion) < 0)) ||
                (strchr(pszSymbol, '=') && (rpmvercmp(pszCachePkgEVR, pszVersion) == 0)))
            {
                pr_err("Detected rpm pre-transaction dependency errors. "
                        "Install %s %s %s first to resolve this failure.\n",
                        pszPkgName, pszSymbol, pszVersion);
                break;
            }
        }
    }

cleanup:
    rpmtsiFree(pi);
    TDNF_SAFE_FREE_MEMORY(pszErrorStr);
    TDNF_SAFE_FREE_MEMORY(pszCachePkgName);
    TDNF_SAFE_FREE_MEMORY(pszCachePkgEVR);
    return dwError;
error:
    goto cleanup;
}


static void
reportProblems(PTDNFRPMTS pTS)
{
    rpmps ps = NULL;
    rpmpsi psi = NULL;
    char *pErrorStr = NULL;

    if(!pTS)
    {
        goto cleanup;
    }

    if(pTS->ppszNativeProblems && pTS->dwNativeProblemCount)
    {
        uint32_t dwIndex = 0;

        pr_crit("Found %u problems\n", pTS->dwNativeProblemCount);
        for(dwIndex = 0; dwIndex < pTS->dwNativeProblemCount; dwIndex++)
        {
            pr_crit("%s\n", pTS->ppszNativeProblems[dwIndex]);
        }
        goto cleanup;
    }

    ps = rpmtsProblems(pTS->pTS);
    if(ps)
    {
        int nProbs = rpmpsNumProblems(ps);
        if(nProbs > 0)
        {
            pr_crit("Found %d problems\n", nProbs);

            psi = rpmpsInitIterator(ps);
            while(rpmpsNextIterator(psi) >= 0)
            {
                rpmProblem prob = rpmpsGetProblem(psi);
                char *msg = rpmProblemString(prob);
                if (strstr(msg, "no digest") != NULL)
                {
                    pr_crit("%s. Use --skipdigest to ignore\n", msg);
                }
                else
                {
                    pr_crit("%s\n", msg);
                    if (rpmProblemGetType(prob) == RPMPROB_REQUIRES)
                    {
                        uint32_t dwError = 0;

                        dwError = TDNFAllocateString(rpmProblemGetStr(prob), &pErrorStr);
                        BAIL_ON_TDNF_ERROR(dwError);

                        dwError = TDNFDetectPreTransFailure(pTS->pTS, pErrorStr);
                        BAIL_ON_TDNF_ERROR(dwError);

                        TDNF_SAFE_FREE_MEMORY(pErrorStr);
                    }
                }
            }
        }
    }
cleanup:
    TDNF_SAFE_FREE_MEMORY(pErrorStr);
    if (psi)
    {
        rpmpsFreeIterator(psi);
    }
    if (ps)
    {
        rpmpsFree(ps);
    }
    return;

error:
    goto cleanup;
}

/*
 * Restrict number of open files. When rpm cannot access /proc
 * it tries to set the close on exec flag for every possible
 * fd, which may take a long time if the limit is very high.
 * See also https://github.com/rpm-software-management/rpm/issues/2081.
 * This can be disabled by setting "openmax=0" in the configuration.
 *
 * The native transaction executor (client/rpmtrans_native.c) does not
 * exhibit this librpm-specific behaviour, so TDNFSetOpenMax is no
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

    /*
     * Composed rpmzig native install/rpmdb-write/erase/scriptlet/
     * trigger executor: replaces librpm's rpmtsRun path entirely.
     * There is no build-time opt-out — the librpm rpmtsRun fallback
     * that was retained by PR #132 as a rollback safety net has been
     * removed (issue #117 follow-up).
     */
    dwError = TDNFRunTransactionNative(pTS, pTdnf);
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
    Header rpmHeader = NULL;
    PTDNF_CACHED_RPM_ENTRY pRpmCache = NULL;
    const char* pszPackageLocation = NULL;
    const char* pszPkgName = NULL;
    uint8_t digest_from_file[TDNF_MAX_DIGEST_LEN] = {0};
    hash_op *hash = NULL;
    int nSize = 0;

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

    if(pInfo->pbChecksum != NULL) {
        hash = hash_ops + pInfo->nChecksumType;

        dwError = TDNFGetDigestForFile(pszFilePath, pInfo->nChecksumType, digest_from_file);
        BAIL_ON_TDNF_ERROR(dwError);

        if (memcmp(digest_from_file, pInfo->pbChecksum, hash->length))
        {
            pr_err("rpm file (%s) Checksum FAILED (digest mismatch)\n", pszFilePath);
            dwError = ERROR_TDNF_CHECKSUM_MISMATCH;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    dwError = TDNFGetFileSize(pszFilePath, &nSize);
    BAIL_ON_TDNF_ERROR(dwError);

    if (nSize != (int)pInfo->dwDownloadSizeBytes) {
        pr_err("rpm file (%s) size (%u) does not match expected size (%u)\n", pszFilePath, nSize, pInfo->dwDownloadSizeBytes);
        dwError = ERROR_TDNF_SIZE_MISMATCH;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGPGCheckPackage(pTS, pTdnf, pRepo, pszFilePath, &rpmHeader);
    BAIL_ON_TDNF_ERROR(dwError);

    if (!pRepo->nGPGCheck)
    {
        rpmtsSetVSFlags(pTS->pTS, rpmtsVSFlags(pTS->pTS) | RPMVSF_MASK_NODIGESTS | RPMVSF_MASK_NOSIGNATURES);
        rpmtsSetVfyLevel(pTS->pTS, ~RPMSIG_VERIFIABLE_TYPE);
    }

    if (headerIsSource(rpmHeader)) {
        if (!pTdnf->pArgs->nDownloadOnly && !pTdnf->pArgs->nTestOnly) {
            dwError = rpmInstallSource(pTS->pTS, pszFilePath, NULL, NULL);
            BAIL_ON_TDNF_RPM_ERROR(dwError);
        }
    } else {
        if (nInstallFlag == INSTALL_REINSTALL){
            dwError = rpmtsAddReinstallElement(
                      pTS->pTS,
                      rpmHeader,
                      (fnpyKey)pszFilePath);
        } else {
            dwError = rpmtsAddInstallElement(
                          pTS->pTS,
                          rpmHeader,
                          (fnpyKey)pszFilePath,
                          nInstallFlag == INSTALL_UPGRADE,
                          NULL);
        }
        BAIL_ON_TDNF_RPM_ERROR(dwError);
    }

    dwError = TDNFRecordTransactionItem(
                  pTS,
                  nInstallFlag == INSTALL_REINSTALL ?
                      TDNF_RPM_TS_ITEM_REINSTALL :
                      (nInstallFlag == INSTALL_UPGRADE ?
                           TDNF_RPM_TS_ITEM_UPGRADE :
                           TDNF_RPM_TS_ITEM_INSTALL),
                  rpmHeader,
                  pszFilePath,
                  0,
                  headerGetString(rpmHeader, RPMTAG_NAME),
                  headerGetString(rpmHeader, RPMTAG_EVR),
                  headerGetString(rpmHeader, RPMTAG_ARCH));
    BAIL_ON_TDNF_ERROR(dwError);

    /* add to cached array only when file is actually in cache dir */
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
        pRpmCache->pNext = pTS->pCachedRpmsArray->pHead;
        pTS->pCachedRpmsArray->pHead = pRpmCache;
    }

cleanup:
    if(rpmHeader)
    {
        headerFree(rpmHeader);
    }
    if(!pTS->pCachedRpmsArray && dwError == 0)
    {
        TDNF_SAFE_FREE_MEMORY(pszFilePath);
    }
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
        dwError = TDNFTransAddErasePkg(pTS, pInfo);
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
    PTDNF_PKG_INFO pInfo
    )
{
    uint32_t dwError = 0;
    Header pRpmHeader = NULL;
    rpmdbMatchIterator pIterator = NULL;
    char *pszFullName = NULL;
    const char *pszPkgName = NULL;
    const char *pszPkgEvr = NULL;
    const char *pszPkgArch = NULL;

    if(!pTS || !pInfo || IsNullOrEmptyString(pInfo->pszName) ||
       IsNullOrEmptyString(pInfo->pszEVR))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pszPkgName = pInfo->pszName;
    pszPkgEvr = pInfo->pszEVR;
    pszPkgArch = pInfo->pszArch;

    dwError = TDNFAllocateStringPrintf(&pszFullName, "%s-%s", pszPkgName, pszPkgEvr);
    BAIL_ON_TDNF_ERROR(dwError);

    pIterator = rpmtsInitIterator(pTS->pTS, (rpmTag)RPMDBI_LABEL, pszFullName, 0);
    while ((pRpmHeader = rpmdbNextIterator(pIterator)) != NULL)
    {
        uint32_t nOffset = rpmdbGetIteratorOffset(pIterator);
        if(nOffset)
        {
            dwError = rpmtsAddEraseElement(pTS->pTS, pRpmHeader, nOffset);
            BAIL_ON_TDNF_ERROR(dwError);

            dwError = TDNFRecordTransactionItem(
                          pTS,
                          TDNF_RPM_TS_ITEM_ERASE,
                          pRpmHeader,
                          NULL,
                          nOffset,
                          pszPkgName,
                          pszPkgEvr,
                          pszPkgArch);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszFullName);
    if(pIterator)
    {
        rpmdbFreeIterator(pIterator);
    }
    return dwError;

error:
    goto cleanup;
}

void*
TDNFRpmCB(
     const void* pArg,
     const rpmCallbackType what,
     const rpm_loff_t amount,
     const rpm_loff_t total,
     fnpyKey key,
     rpmCallbackData data
     )
{
    Header pPkgHeader = (Header) pArg;
    void* pResult = NULL;
    char* pszFileName = (char*)key;
    PTDNFRPMTS pTS = (PTDNFRPMTS)data;

    switch (what)
    {
        case RPMCALLBACK_INST_OPEN_FILE:
            if(IsNullOrEmptyString(pszFileName))
            {
                return NULL;
            }
            pTS->pFD = Fopen(pszFileName, "r.ufdio");
            return (void *)pTS->pFD;
            break;

        case RPMCALLBACK_INST_CLOSE_FILE:
            if(pTS->pFD)
            {
                Fclose(pTS->pFD);
                pTS->pFD = NULL;
            }
            break;
        case RPMCALLBACK_INST_START:
        case RPMCALLBACK_UNINST_START:
            if(pTS->nQuiet)
                break;
            if(what == RPMCALLBACK_INST_START)
            {
                pr_info("%s", "Installing/Updating: ");
            }
            else
            {
                pr_info("%s", "Removing: ");
            }
            {
                char* pszNevra = NULL;
                if (!headerIsSource(pPkgHeader)) {
                    pszNevra = headerGetAsString(pPkgHeader, RPMTAG_NEVRA);
                    pr_info("%s\n", pszNevra);
                } else {
                    /* don't confuse users with arch */
                    pszNevra = headerGetAsString(pPkgHeader, RPMTAG_NEVR);
                    pr_info("%s (source)\n", pszNevra);
                }
                free(pszNevra);
                (void)fflush(stdout);
            }
            break;
        case RPMCALLBACK_SCRIPT_ERROR:
            {
                /* https://bugzilla.redhat.com/show_bug.cgi?id=216221#c15 */
                const char *pszScript;
                const char* pszNevra = headerGetAsString(pPkgHeader, RPMTAG_NEVRA);

                switch (amount)
                {
                    case RPMTAG_PREIN:
                        pszScript = "%prein";
                        break;
                    case RPMTAG_POSTIN:
                        pszScript = "%postin";
                        break;
                    case RPMTAG_PREUN:
                        pszScript = "%preun";
                        break;
                    case RPMTAG_POSTUN:
                        pszScript = "%postun";
                        break;
                    default:
                        pszScript = "(unknown)";
                        break;
                }
                /* %pre and %preun will cause errors (install/uninstall will fail),
                   other scripts just warn (install/uninstall will succeed) */
                pr_crit("package %s: script %s in %s\n",
                    pszNevra, total == RPMRC_OK ? "warning" : "error", pszScript);
            }
            break;
        default:
            break;
    }

    return pResult;
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
