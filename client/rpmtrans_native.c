/*
 * Copyright (C) 2015-2026 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

/*
 * See rpmtrans_native.h for the design overview.
 */

#include "includes.h"

#include <time.h>

#include "../rpmzig/rpmdb.h"
#include "rpmtrans_native.h"

typedef struct _NATIVE_VIEW_ENTRY
{
    uint32_t dwHnum;
    const unsigned char *pbBlob;
    size_t nBlobLen;
    int nActive;
    int nDbVisible;
    int nOwnsBlob;
    int nAdded;
    int nRemoved;
    uint64_t qwOrder;
    uint64_t qwRemovalOrder;
} NATIVE_VIEW_ENTRY;

typedef struct _NATIVE_TRANSACTION_VIEW
{
    NATIVE_VIEW_ENTRY *pEntries;
    size_t nCount;
    size_t nCapacity;
} NATIVE_TRANSACTION_VIEW;

typedef struct _NATIVE_OWNERSHIP_CTX
{
    NATIVE_TRANSACTION_VIEW *pView;
    const tdnf_rpm_config *pRpmConfig;
    const uint32_t *pdwIgnoredHnums;
    size_t nIgnoredHnums;
} NATIVE_OWNERSHIP_CTX;

typedef struct _NATIVE_PATH_NODE
{
    tdnf_rpm_trigger_path path;
    char *pszOwnedPath;
    struct _NATIVE_PATH_NODE *pNext;
    struct _NATIVE_PATH_NODE *pHashNext;
    size_t nHash;
} NATIVE_PATH_NODE;

typedef struct _NATIVE_PATH_LIST
{
    NATIVE_PATH_NODE *pHead;
    NATIVE_PATH_NODE *pTail;
    NATIVE_PATH_NODE **ppBuckets;
    size_t nBucketCount;
    size_t nCount;
} NATIVE_PATH_LIST;

typedef struct _NATIVE_PATH_APPEND_CTX
{
    NATIVE_PATH_LIST *pList;
    const unsigned char *pbSourceBlob;
    size_t nSourceLen;
    NATIVE_OWNERSHIP_CTX *pOwnershipCtx;
} NATIVE_PATH_APPEND_CTX;

typedef struct _NATIVE_INSTALL_PATH_CTX
{
    NATIVE_PATH_LIST *pItemPaths;
    const unsigned char *pbSourceBlob;
    size_t nSourceLen;
} NATIVE_INSTALL_PATH_CTX;

typedef struct _NATIVE_POSTUN_OWNER
{
    const unsigned char *pbBlob;
    size_t nBlobLen;
    uint64_t qwOrder;
    NATIVE_PATH_LIST paths;
    struct _NATIVE_POSTUN_OWNER *pNext;
} NATIVE_POSTUN_OWNER;

typedef struct _NATIVE_POSTUN_QUEUE
{
    NATIVE_POSTUN_OWNER *pHead;
    NATIVE_POSTUN_OWNER *pTail;
    size_t nCount;
} NATIVE_POSTUN_QUEUE;

static const char *
GetInstallRoot(
    PTDNF pTdnf
    )
{
    if (pTdnf && pTdnf->pArgs && pTdnf->pArgs->pszInstallRoot &&
        pTdnf->pArgs->pszInstallRoot[0])
    {
        return pTdnf->pArgs->pszInstallRoot;
    }
    return "/";
}

static void
LogRpmzigError(
    const char *pszAction
    )
{
    const char *pszErr = tdnf_rpmdb_last_error();
    if (!IsNullOrEmptyString(pszErr))
    {
        pr_err("rpmzig-transaction-execute: %s failed: %s\n",
               pszAction, pszErr);
    }
    else
    {
        pr_err("rpmzig-transaction-execute: %s failed\n", pszAction);
    }
}

static void
PathListHashCleanup(
    NATIVE_PATH_LIST *pList
    )
{
    if(pList)
    {
        TDNF_SAFE_FREE_MEMORY(pList->ppBuckets);
        pList->nBucketCount = 0;
    }
}

static size_t
PathListHash(
    const char *pszPath,
    const unsigned char *pbSourceBlob,
    size_t nSourceLen
    )
{
    const unsigned char *pByte = (const unsigned char *)pszPath;
    size_t nHash = (size_t)(uintptr_t)pbSourceBlob ^ nSourceLen;

    while(*pByte)
    {
        nHash = (nHash * 33U) ^ *pByte;
        pByte++;
    }
    return nHash;
}

static uint32_t
PathListRehash(
    NATIVE_PATH_LIST *pList,
    size_t nBucketCount
    )
{
    uint32_t dwError = 0;
    NATIVE_PATH_NODE **ppBuckets = NULL;
    NATIVE_PATH_NODE *pNode = NULL;
    size_t nBucket = 0;

    if(!pList || !nBucketCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    dwError = TDNFAllocateMemory(
                  nBucketCount,
                  sizeof(*ppBuckets),
                  (void **)&ppBuckets);
    BAIL_ON_TDNF_ERROR(dwError);

    for(pNode = pList->pHead; pNode; pNode = pNode->pNext)
    {
        nBucket = pNode->nHash % nBucketCount;
        pNode->pHashNext = ppBuckets[nBucket];
        ppBuckets[nBucket] = pNode;
    }

    PathListHashCleanup(pList);
    pList->ppBuckets = ppBuckets;
    pList->nBucketCount = nBucketCount;
    ppBuckets = NULL;

cleanup:
    TDNF_SAFE_FREE_MEMORY(ppBuckets);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
PathListEnsureHashCapacity(
    NATIVE_PATH_LIST *pList
    )
{
    uint32_t dwError = 0;
    size_t nBucketCount = 0;

    if(!pList)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!pList->nBucketCount)
    {
        nBucketCount = 256;
    }
    else if(pList->nCount >= pList->nBucketCount)
    {
        if(pList->nBucketCount > SIZE_MAX / 2)
        {
            dwError = ERROR_TDNF_OVERFLOW;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        nBucketCount = pList->nBucketCount * 2;
    }
    if(nBucketCount)
    {
        dwError = PathListRehash(pList, nBucketCount);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static void
PathListCleanup(
    NATIVE_PATH_LIST *pList
    )
{
    NATIVE_PATH_NODE *pNode = NULL;
    NATIVE_PATH_NODE *pNext = NULL;

    if(!pList)
    {
        return;
    }
    for(pNode = pList->pHead; pNode; pNode = pNext)
    {
        pNext = pNode->pNext;
        TDNF_SAFE_FREE_MEMORY(pNode->pszOwnedPath);
        TDNFFreeMemory(pNode);
    }
    PathListHashCleanup(pList);
    memset(pList, 0, sizeof(*pList));
}

static uint32_t
PathListAppend(
    NATIVE_PATH_LIST *pList,
    const char *pszPath,
    const unsigned char *pbSourceBlob,
    size_t nSourceLen
    )
{
    uint32_t dwError = 0;
    NATIVE_PATH_NODE *pNode = NULL;
    NATIVE_PATH_NODE *pExisting = NULL;
    size_t nBucket = 0;
    size_t nHash = 0;

    if(!pList || IsNullOrEmptyString(pszPath) || pszPath[0] != '/' ||
       !pbSourceBlob || !nSourceLen)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    dwError = PathListEnsureHashCapacity(pList);
    BAIL_ON_TDNF_ERROR(dwError);
    nHash = PathListHash(pszPath, pbSourceBlob, nSourceLen);
    nBucket = nHash % pList->nBucketCount;
    for(pExisting = pList->ppBuckets[nBucket];
        pExisting;
        pExisting = pExisting->pHashNext)
    {
        if(pExisting->nHash == nHash &&
           pExisting->path.source_header_blob == pbSourceBlob &&
           pExisting->path.source_header_len == nSourceLen &&
           !strcmp(pExisting->pszOwnedPath, pszPath))
        {
            goto cleanup;
        }
    }

    dwError = TDNFAllocateMemory(
                  1,
                  sizeof(*pNode),
                  (void **)&pNode);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TDNFAllocateString(
                  pszPath,
                  &pNode->pszOwnedPath);
    BAIL_ON_TDNF_ERROR(dwError);
    pNode->path.path = pNode->pszOwnedPath;
    pNode->path.source_header_blob = pbSourceBlob;
    pNode->path.source_header_len = nSourceLen;
    pNode->nHash = nHash;

    if(pList->pTail)
    {
        pList->pTail->pNext = pNode;
    }
    else
    {
        pList->pHead = pNode;
    }
    pList->pTail = pNode;
    pNode->pHashNext = pList->ppBuckets[nBucket];
    pList->ppBuckets[nBucket] = pNode;
    pList->nCount++;
    pNode = NULL;

cleanup:
    if(pNode)
    {
        TDNF_SAFE_FREE_MEMORY(pNode->pszOwnedPath);
        TDNFFreeMemory(pNode);
    }
    return dwError;

error:
    goto cleanup;
}

static uint32_t
PathListMerge(
    NATIVE_PATH_LIST *pDestination,
    const NATIVE_PATH_LIST *pSource
    )
{
    uint32_t dwError = 0;
    const NATIVE_PATH_NODE *pNode = NULL;

    if(!pDestination || !pSource)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(pNode = pSource->pHead; pNode; pNode = pNode->pNext)
    {
        dwError = PathListAppend(
                      pDestination,
                      pNode->pszOwnedPath,
                      pNode->path.source_header_blob,
                      pNode->path.source_header_len);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static uint32_t
PathListFlatten(
    const NATIVE_PATH_LIST *pList,
    tdnf_rpm_trigger_path **ppPaths
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_trigger_path *pPaths = NULL;
    const NATIVE_PATH_NODE *pNode = NULL;
    size_t i = 0;

    if(!pList || !ppPaths)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    *ppPaths = NULL;
    if(pList->nCount)
    {
        dwError = TDNFAllocateMemory(
                      pList->nCount,
                      sizeof(*pPaths),
                      (void **)&pPaths);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(pNode = pList->pHead; pNode; pNode = pNode->pNext)
    {
        if(i >= pList->nCount)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        pPaths[i++] = pNode->path;
    }
    if(i != pList->nCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    *ppPaths = pPaths;
    pPaths = NULL;

cleanup:
    TDNF_SAFE_FREE_MEMORY(pPaths);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
TransactionViewInit(
    NATIVE_TRANSACTION_VIEW *pView,
    const tdnf_rpm_config *pRpmConfig,
    size_t nAdditionalCapacity
    )
{
    uint32_t dwError = 0;
    int64_t nPhysicalCount = 0;
    tdnf_rpmdb_iter *pIter = NULL;

    if(!pView || !pRpmConfig)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    memset(pView, 0, sizeof(*pView));
    nPhysicalCount = tdnf_rpmdb_count_packages_config(pRpmConfig);
    if(nPhysicalCount < 0 ||
       (uint64_t)nPhysicalCount > SIZE_MAX - nAdditionalCapacity)
    {
        LogRpmzigError("rpmdb_count_packages");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    pView->nCapacity = (size_t)nPhysicalCount + nAdditionalCapacity;
    if(pView->nCapacity)
    {
        dwError = TDNFAllocateMemory(
                      pView->nCapacity,
                      sizeof(*pView->pEntries),
                      (void **)&pView->pEntries);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pIter = tdnf_rpmdb_iter_open_config(pRpmConfig);
    if(!pIter)
    {
        LogRpmzigError("rpmdb_iter_open");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(;;)
    {
        uint32_t dwHnum = 0;
        const unsigned char *pbBlob = NULL;
        size_t nBlobLen = 0;
        unsigned char *pbCopy = NULL;
        int nResult = tdnf_rpmdb_iter_next_header_blob_hnum(
                          pIter,
                          &dwHnum,
                          &pbBlob,
                          &nBlobLen);
        if(nResult == 0)
        {
            break;
        }
        if(nResult < 0 || !pbBlob || !nBlobLen ||
           pView->nCount >= pView->nCapacity)
        {
            LogRpmzigError("rpmdb_iter_next");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        dwError = TDNFAllocateMemory(
                      nBlobLen,
                      sizeof(*pbCopy),
                      (void **)&pbCopy);
        BAIL_ON_TDNF_ERROR(dwError);
        memcpy(pbCopy, pbBlob, nBlobLen);
        pView->pEntries[pView->nCount].dwHnum = dwHnum;
        pView->pEntries[pView->nCount].pbBlob = pbCopy;
        pView->pEntries[pView->nCount].nBlobLen = nBlobLen;
        pView->pEntries[pView->nCount].nActive = 1;
        pView->pEntries[pView->nCount].nDbVisible = 1;
        pView->pEntries[pView->nCount].nOwnsBlob = 1;
        pView->pEntries[pView->nCount].qwOrder = pView->nCount;
        pView->nCount++;
    }

cleanup:
    tdnf_rpmdb_iter_close(pIter);
    return dwError;

error:
    goto cleanup;
}

static void
TransactionViewCleanup(
    NATIVE_TRANSACTION_VIEW *pView
    )
{
    size_t i = 0;
    if(!pView)
    {
        return;
    }
    for(i = 0; i < pView->nCount; i++)
    {
        if(pView->pEntries[i].nOwnsBlob)
        {
            TDNFFreeMemory((void *)pView->pEntries[i].pbBlob);
            pView->pEntries[i].pbBlob = NULL;
        }
    }
    TDNF_SAFE_FREE_MEMORY(pView->pEntries);
    memset(pView, 0, sizeof(*pView));
}

static NATIVE_VIEW_ENTRY *
TransactionViewFindHnum(
    NATIVE_TRANSACTION_VIEW *pView,
    uint32_t dwHnum
    )
{
    size_t i = 0;
    if(!pView || !dwHnum)
    {
        return NULL;
    }
    for(i = 0; i < pView->nCount; i++)
    {
        if(pView->pEntries[i].dwHnum == dwHnum)
        {
            return &pView->pEntries[i];
        }
    }
    return NULL;
}

static uint32_t
TransactionViewActivate(
    NATIVE_TRANSACTION_VIEW *pView,
    const unsigned char *pbBlob,
    size_t nBlobLen,
    uint32_t dwHnum,
    int nDbVisible
    )
{
    if(!pView || !pbBlob || !nBlobLen ||
       pView->nCount >= pView->nCapacity)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    pView->pEntries[pView->nCount].pbBlob = pbBlob;
    pView->pEntries[pView->nCount].nBlobLen = nBlobLen;
    pView->pEntries[pView->nCount].dwHnum = dwHnum;
    pView->pEntries[pView->nCount].nActive = 1;
    pView->pEntries[pView->nCount].nDbVisible = nDbVisible;
    pView->pEntries[pView->nCount].nAdded = 1;
    pView->pEntries[pView->nCount].qwOrder = pView->nCount;
    pView->nCount++;
    return 0;
}

static uint32_t
TransactionViewHideDbHnum(
    NATIVE_TRANSACTION_VIEW *pView,
    uint32_t dwHnum
    )
{
    NATIVE_VIEW_ENTRY *pEntry = TransactionViewFindHnum(pView, dwHnum);
    if(!pEntry || !pEntry->nDbVisible)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    pEntry->nDbVisible = 0;
    return 0;
}

static uint32_t
TransactionViewDeactivateHnum(
    NATIVE_TRANSACTION_VIEW *pView,
    uint32_t dwHnum
    )
{
    NATIVE_VIEW_ENTRY *pEntry = TransactionViewFindHnum(pView, dwHnum);
    if(!pEntry || !pEntry->nActive)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    pEntry->nActive = 0;
    return 0;
}

static int
TransactionViewCountName(
    NATIVE_TRANSACTION_VIEW *pView,
    const char *pszName
    )
{
    size_t i = 0;
    int nCount = 0;
    if(!pView || IsNullOrEmptyString(pszName))
    {
        return -1;
    }
    for(i = 0; i < pView->nCount; i++)
    {
        int nResult = 0;
        if(!pView->pEntries[i].nActive)
        {
            continue;
        }
        nResult = tdnf_rpm_header_name_equals(
                      pView->pEntries[i].pbBlob,
                      pView->pEntries[i].nBlobLen,
                      pszName);
        if(nResult < 0)
        {
            return -1;
        }
        if(nResult)
        {
            if(nCount == INT_MAX)
            {
                return -1;
            }
            nCount++;
        }
    }
    return nCount;
}

static uint32_t
TransactionViewHeadersByVisibility(
    NATIVE_TRANSACTION_VIEW *pView,
    int nDbVisibleOnly,
    tdnf_rpm_header_view **ppHeaders,
    size_t *pnHeaderCount
    )
{
    uint32_t dwError = 0;
    size_t i = 0;
    size_t nCount = 0;
    tdnf_rpm_header_view *pHeaders = NULL;

    if(!pView || !ppHeaders || !pnHeaderCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    *ppHeaders = NULL;
    *pnHeaderCount = 0;
    for(i = 0; i < pView->nCount; i++)
    {
        if((nDbVisibleOnly && pView->pEntries[i].nDbVisible) ||
           (!nDbVisibleOnly && pView->pEntries[i].nActive))
        {
            nCount++;
        }
    }
    if(nCount)
    {
        dwError = TDNFAllocateMemory(
                      nCount,
                      sizeof(*pHeaders),
                      (void **)&pHeaders);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    nCount = 0;
    for(i = 0; i < pView->nCount; i++)
    {
        if((nDbVisibleOnly && !pView->pEntries[i].nDbVisible) ||
           (!nDbVisibleOnly && !pView->pEntries[i].nActive))
        {
            continue;
        }
        pHeaders[nCount].blob = pView->pEntries[i].pbBlob;
        pHeaders[nCount].len = pView->pEntries[i].nBlobLen;
        nCount++;
    }
    *ppHeaders = pHeaders;
    *pnHeaderCount = nCount;
    pHeaders = NULL;

cleanup:
    TDNF_SAFE_FREE_MEMORY(pHeaders);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
TransactionViewHeaders(
    NATIVE_TRANSACTION_VIEW *pView,
    tdnf_rpm_header_view **ppHeaders,
    size_t *pnHeaderCount
    )
{
    return TransactionViewHeadersByVisibility(
               pView,
               0,
               ppHeaders,
               pnHeaderCount);
}

static uint32_t
TransactionViewDbHeaders(
    NATIVE_TRANSACTION_VIEW *pView,
    tdnf_rpm_header_view **ppHeaders,
    size_t *pnHeaderCount
    )
{
    return TransactionViewHeadersByVisibility(
               pView,
               1,
               ppHeaders,
               pnHeaderCount);
}

static int
OwnershipIgnoresHnum(
    const NATIVE_OWNERSHIP_CTX *pCtx,
    uint32_t dwHnum
    )
{
    size_t i = 0;
    for(i = 0; i < pCtx->nIgnoredHnums; i++)
    {
        if(pCtx->pdwIgnoredHnums[i] == dwHnum)
        {
            return 1;
        }
    }
    return 0;
}

static int
NativePathOwned(
    void *pData,
    const char *pszPath
    )
{
    NATIVE_OWNERSHIP_CTX *pCtx = (NATIVE_OWNERSHIP_CTX *)pData;
    size_t i = 0;
    if(!pCtx || !pCtx->pView || IsNullOrEmptyString(pszPath))
    {
        return -1;
    }
    for(i = 0; i < pCtx->pView->nCount; i++)
    {
        NATIVE_VIEW_ENTRY *pEntry = &pCtx->pView->pEntries[i];
        int nResult = 0;
        if(!pEntry->nActive ||
           OwnershipIgnoresHnum(pCtx, pEntry->dwHnum))
        {
            continue;
        }
        nResult = tdnf_rpm_header_owns_path_config(
                      pEntry->pbBlob,
                      pEntry->nBlobLen,
                      pszPath,
                      pCtx->pRpmConfig);
        if(nResult)
        {
            return nResult;
        }
    }
    return 0;
}

static int
AppendTriggerPath(
    void *pData,
    const char *pszPath
    )
{
    NATIVE_PATH_APPEND_CTX *pCtx = (NATIVE_PATH_APPEND_CTX *)pData;
    int nOwned = 0;

    if(!pCtx || !pCtx->pList)
    {
        return -1;
    }
    if(pCtx->pOwnershipCtx)
    {
        nOwned = NativePathOwned(pCtx->pOwnershipCtx, pszPath);
        if(nOwned < 0)
        {
            return -1;
        }
        if(nOwned > 0)
        {
            return 0;
        }
    }
    return PathListAppend(
               pCtx->pList,
               pszPath,
               pCtx->pbSourceBlob,
               pCtx->nSourceLen) == 0 ? 0 : -1;
}

static int
AppendInstalledTriggerPath(
    void *pData,
    const char *pszPath
    )
{
    NATIVE_INSTALL_PATH_CTX *pCtx = (NATIVE_INSTALL_PATH_CTX *)pData;

    if(!pCtx || !pCtx->pItemPaths)
    {
        return -1;
    }
    return PathListAppend(
               pCtx->pItemPaths,
               pszPath,
               pCtx->pbSourceBlob,
               pCtx->nSourceLen) == 0 ? 0 : -1;
}

static uint32_t
CollectHeaderTriggerPaths(
    const unsigned char *pbBlob,
    size_t nBlobLen,
    uint32_t dwTransFlags,
    NATIVE_OWNERSHIP_CTX *pOwnershipCtx,
    NATIVE_PATH_LIST *pPaths
    )
{
    NATIVE_PATH_APPEND_CTX append_ctx;

    memset(&append_ctx, 0, sizeof(append_ctx));
    if(!pbBlob || !nBlobLen || !pPaths)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    append_ctx.pList = pPaths;
    append_ctx.pbSourceBlob = pbBlob;
    append_ctx.nSourceLen = nBlobLen;
    append_ctx.pOwnershipCtx = pOwnershipCtx;
    if(tdnf_rpm_header_foreach_trigger_file(
           pbBlob,
           nBlobLen,
           dwTransFlags,
           AppendTriggerPath,
           &append_ctx) != 0)
    {
        LogRpmzigError("foreach_trigger_file");
        return ERROR_TDNF_TRANSACTION_FAILED;
    }
    return 0;
}

static uint32_t
CollectAllDbTriggerPaths(
    NATIVE_TRANSACTION_VIEW *pView,
    uint32_t dwTransFlags,
    NATIVE_PATH_LIST *pPaths
    )
{
    uint32_t dwError = 0;
    size_t i = 0;

    if(!pView || !pPaths)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(i = 0; i < pView->nCount; i++)
    {
        NATIVE_VIEW_ENTRY *pEntry = &pView->pEntries[i];
        if(!pEntry->nDbVisible)
        {
            continue;
        }
        dwError = CollectHeaderTriggerPaths(
                      pEntry->pbBlob,
                      pEntry->nBlobLen,
                      pEntry->nAdded ? dwTransFlags : 0,
                      NULL,
                      pPaths);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static void
PostunQueueCleanup(
    NATIVE_POSTUN_QUEUE *pQueue
    )
{
    NATIVE_POSTUN_OWNER *pOwner = NULL;
    NATIVE_POSTUN_OWNER *pNext = NULL;

    if(!pQueue)
    {
        return;
    }
    for(pOwner = pQueue->pHead; pOwner; pOwner = pNext)
    {
        pNext = pOwner->pNext;
        PathListCleanup(&pOwner->paths);
        TDNFFreeMemory(pOwner);
    }
    memset(pQueue, 0, sizeof(*pQueue));
}

static NATIVE_POSTUN_OWNER *
PostunQueueFindOwner(
    NATIVE_POSTUN_QUEUE *pQueue,
    const unsigned char *pbBlob
    )
{
    NATIVE_POSTUN_OWNER *pOwner = NULL;

    if(!pQueue || !pbBlob)
    {
        return NULL;
    }
    for(pOwner = pQueue->pHead; pOwner; pOwner = pOwner->pNext)
    {
        if(pOwner->pbBlob == pbBlob)
        {
            return pOwner;
        }
    }
    return NULL;
}

static uint32_t
SchedulePostunTransactionTriggers(
    NATIVE_POSTUN_QUEUE *pQueue,
    NATIVE_TRANSACTION_VIEW *pView,
    const NATIVE_PATH_LIST *pRemovedPaths
    )
{
    uint32_t dwError = 0;
    size_t i = 0;

    if(!pQueue || !pView || !pRemovedPaths)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!pRemovedPaths->nCount)
    {
        goto cleanup;
    }
    for(i = 0; i < pView->nCount; i++)
    {
        NATIVE_VIEW_ENTRY *pEntry = &pView->pEntries[i];
        NATIVE_POSTUN_OWNER *pOwner = NULL;

        if(!pEntry->nDbVisible)
        {
            continue;
        }
        pOwner = PostunQueueFindOwner(pQueue, pEntry->pbBlob);
        if(!pOwner)
        {
            dwError = TDNFAllocateMemory(
                          1,
                          sizeof(*pOwner),
                          (void **)&pOwner);
            BAIL_ON_TDNF_ERROR(dwError);
            pOwner->pbBlob = pEntry->pbBlob;
            pOwner->nBlobLen = pEntry->nBlobLen;
            pOwner->qwOrder = pEntry->qwOrder;
            if(pQueue->pTail)
            {
                pQueue->pTail->pNext = pOwner;
            }
            else
            {
                pQueue->pHead = pOwner;
            }
            pQueue->pTail = pOwner;
            pQueue->nCount++;
        }
        dwError = PathListMerge(&pOwner->paths, pRemovedPaths);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static int
TransactionViewContainsDbBlob(
    NATIVE_TRANSACTION_VIEW *pView,
    const unsigned char *pbBlob
    )
{
    size_t i = 0;
    if(!pView || !pbBlob)
    {
        return 0;
    }
    for(i = 0; i < pView->nCount; i++)
    {
        if(pView->pEntries[i].nDbVisible &&
           pView->pEntries[i].pbBlob == pbBlob)
        {
            return 1;
        }
    }
    return 0;
}

/*
 * Return the effective transaction flag mask. Adds NOSCRIPTS +
 * NOTRIGGERS + NODB (and the JUSTDB bit for good measure) whenever
 * we are in test-only mode.
 */
static uint32_t
EffectiveTransFlags(
    PTDNFRPMTS pTS,
    PTDNF pTdnf
    )
{
    uint32_t dwFlags = (uint32_t)pTS->nTransFlags;
    if (pTdnf->pArgs->nTestOnly)
    {
        dwFlags |= TDNF_RPMTRANS_FLAG_TEST |
                   TDNF_RPMTRANS_FLAG_NOSCRIPTS |
                   TDNF_RPMTRANS_FLAG_NOTRIGGERS |
                   TDNF_RPMTRANS_FLAG_JUSTDB |
                   TDNF_RPMTRANS_FLAG_NODB;
    }
    return dwFlags;
}

static void
LogScriptletOutcome(
    const char *pszNevra,
    const char *pszPhase,
    const tdnf_rpm_scriptlet_result *pResult
    )
{
    if (!pResult->ran)
    {
        return;
    }
    if (pResult->outcome == TDNF_RPM_SCRIPTLET_OUTCOME_OK)
    {
        return;
    }
    if (pResult->outcome == TDNF_RPM_SCRIPTLET_OUTCOME_SIGNALED)
    {
        pr_crit("package %s: script %s in %s (signal %d)\n",
                pszNevra ? pszNevra : "(unknown)",
                pResult->critical ? "error" : "warning",
                pszPhase, pResult->signal_number);
    }
    else
    {
        pr_crit("package %s: script %s in %s (exit %d)\n",
                pszNevra ? pszNevra : "(unknown)",
                pResult->critical ? "error" : "warning",
                pszPhase, pResult->exit_status);
    }
}

/*
 * Run one scriptlet phase from the given header blob and translate
 * the outcome into a tdnf error code. Warning-only phases never
 * abort; critical phases (%pre/%preun/%pretrans) abort with
 * ERROR_TDNF_TRANSACTION_FAILED.
 */
static uint32_t
RunScriptlet(
    const unsigned char *pbBlob,
    size_t nLen,
    tdnf_rpm_scriptlet_phase phase,
    const char *pszPhaseName,
    const char *pszNevra,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    int nArg1,
    int nArg2,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    tdnf_rpm_scriptlet_options options;
    tdnf_rpm_scriptlet_result result;
    int nInstallRootFd = -1;

    memset(&options, 0, sizeof(options));
    memset(&result, 0, sizeof(result));

    options.install_root = pszInstallRoot;
    options.config = pRpmConfig;
    nInstallRootFd = tdnf_rpm_config_open_root_fd(pRpmConfig);
    if(nInstallRootFd < 0)
    {
        LogRpmzigError("pin scriptlet installroot");
        return ERROR_TDNF_TRANSACTION_FAILED;
    }
    options.install_root_fd = nInstallRootFd;
    options.trans_flags = dwTransFlags;
    options.rpmdefines = NULL;
    options.rpmdefine_count = 0;
    options.arg1 = nArg1;
    options.arg2 = nArg2;
    options.script_fd = nScriptFd;
    options.redirect_stdout_to_stderr = nRedirectToStderr;

    if (tdnf_rpm_header_run_scriptlet(pbBlob, nLen, phase, &options, &result) != 0)
    {
        close(nInstallRootFd);
        LogRpmzigError(pszPhaseName);
        return ERROR_TDNF_TRANSACTION_FAILED;
    }
    close(nInstallRootFd);

    LogScriptletOutcome(pszNevra, pszPhaseName, &result);

    if (result.ran && result.critical &&
        result.outcome != TDNF_RPM_SCRIPTLET_OUTCOME_OK &&
        result.outcome != TDNF_RPM_SCRIPTLET_OUTCOME_NOT_RUN)
    {
        return ERROR_TDNF_TRANSACTION_FAILED;
    }
    return 0;
}

static uint32_t
RunTriggers(
    const unsigned char *pbBlob,
    size_t nLen,
    tdnf_rpm_trigger_phase phase,
    const char *pszPhaseName,
    const char *pszNevra,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    NATIVE_TRANSACTION_VIEW *pView,
    int nScriptFd,
    int nRedirectToStderr,
    int nArg2OverridePresent,
    int nArg2OverrideValue
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_trigger_options options;
    tdnf_rpm_trigger_result result;
    tdnf_rpm_header_view *pHeaders = NULL;
    tdnf_rpm_header_view *pOwnerHeaders = NULL;
    size_t nHeaderCount = 0;
    size_t nOwnerHeaderCount = 0;
    int nInstallRootFd = -1;

    memset(&options, 0, sizeof(options));
    memset(&result, 0, sizeof(result));
    nInstallRootFd = tdnf_rpm_config_open_root_fd(pRpmConfig);
    if(nInstallRootFd < 0)
    {
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    options.install_root_fd = nInstallRootFd;

    dwError = TransactionViewHeaders(pView, &pHeaders, &nHeaderCount);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TransactionViewDbHeaders(
                  pView,
                  &pOwnerHeaders,
                  &nOwnerHeaderCount);
    BAIL_ON_TDNF_ERROR(dwError);

    options.db_root = pszInstallRoot;
    options.install_root = pszInstallRoot;
    options.config = pRpmConfig;
    options.trans_flags = dwTransFlags;
    options.rpmdefines = NULL;
    options.rpmdefine_count = 0;
    options.script_fd = nScriptFd;
    options.redirect_stdout_to_stderr = nRedirectToStderr;
    options.arg2_override_present = nArg2OverridePresent;
    options.arg2_override_value = nArg2OverrideValue;
    options.transaction_headers = pHeaders;
    options.transaction_header_count = nHeaderCount;
    options.transaction_view_present = 1;
    options.trigger_owner_headers = pOwnerHeaders;
    options.trigger_owner_header_count = nOwnerHeaderCount;
    options.trigger_owner_view_present = 1;

    if (tdnf_rpm_header_run_triggers(pbBlob, nLen, phase, &options, &result) != 0)
    {
        LogRpmzigError(pszPhaseName);
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    /* Triggers are always warning-only in real rpm. */
    (void)pszNevra;

cleanup:
    if(nInstallRootFd >= 0)
    {
        close(nInstallRootFd);
    }
    TDNF_SAFE_FREE_MEMORY(pOwnerHeaders);
    TDNF_SAFE_FREE_MEMORY(pHeaders);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
RunFileTriggerOwners(
    tdnf_rpm_file_trigger_owner *pOwners,
    size_t nOwnerCount,
    tdnf_rpm_trigger_phase phase,
    tdnf_rpm_file_trigger_kind kind,
    tdnf_rpm_trigger_priority_class priorityClass,
    const char *pszPhaseName,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr,
    int nSuppressStdin
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_file_trigger_options options;
    tdnf_rpm_trigger_result result;
    size_t nInputIndex = 0;
    size_t nOutputCount = 0;
    int nHasFileTriggers = 0;
    int nInstallRootFd = -1;

    memset(&options, 0, sizeof(options));
    memset(&result, 0, sizeof(result));
    if(nOwnerCount && !pOwners)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(nInputIndex = 0; nInputIndex < nOwnerCount; nInputIndex++)
    {
        nHasFileTriggers = tdnf_rpm_header_has_file_trigger_metadata(
                               pOwners[nInputIndex].header_blob,
                               pOwners[nInputIndex].header_len,
                               kind);
        if(nHasFileTriggers < 0)
        {
            LogRpmzigError("inspect file trigger owner");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(nHasFileTriggers)
        {
            if(nOutputCount != nInputIndex)
            {
                pOwners[nOutputCount] = pOwners[nInputIndex];
            }
            nOutputCount++;
        }
    }
    nOwnerCount = nOutputCount;
    if(!nOwnerCount)
    {
        goto cleanup;
    }
    nInstallRootFd = tdnf_rpm_config_open_root_fd(pRpmConfig);
    if(nInstallRootFd < 0)
    {
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    options.install_root = pszInstallRoot;
    options.config = pRpmConfig;
    options.install_root_fd = nInstallRootFd;
    options.trans_flags = dwTransFlags;
    options.script_fd = nScriptFd;
    options.redirect_stdout_to_stderr = nRedirectToStderr;
    options.suppress_stdin = nSuppressStdin;

    if(tdnf_rpm_run_file_triggers(
           pOwners,
           nOwnerCount,
           phase,
           kind,
           priorityClass,
           &options,
           &result) != 0)
    {
        LogRpmzigError(pszPhaseName);
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    if(nInstallRootFd >= 0)
    {
        close(nInstallRootFd);
    }
    return dwError;

error:
    goto cleanup;
}

static uint32_t
RunOtherPackageFileTriggers(
    NATIVE_TRANSACTION_VIEW *pView,
    const NATIVE_PATH_LIST *pPaths,
    const unsigned char *pbCurrentBlob,
    tdnf_rpm_trigger_phase phase,
    tdnf_rpm_trigger_priority_class priorityClass,
    const char *pszPhaseName,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_file_trigger_owner *pOwners = NULL;
    tdnf_rpm_trigger_path *pFlatPaths = NULL;
    size_t nOwnerCount = 0;
    size_t i = 0;

    if(!pView || !pPaths)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    dwError = PathListFlatten(pPaths, &pFlatPaths);
    BAIL_ON_TDNF_ERROR(dwError);
    if(pView->nCount)
    {
        dwError = TDNFAllocateMemory(
                      pView->nCount,
                      sizeof(*pOwners),
                      (void **)&pOwners);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(i = 0; i < pView->nCount; i++)
    {
        NATIVE_VIEW_ENTRY *pEntry = &pView->pEntries[i];
        if(!pEntry->nDbVisible ||
           (pEntry->pbBlob == pbCurrentBlob &&
            phase != TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN))
        {
            continue;
        }
        pOwners[nOwnerCount].header_blob = pEntry->pbBlob;
        pOwners[nOwnerCount].header_len = pEntry->nBlobLen;
        pOwners[nOwnerCount].paths = pFlatPaths;
        pOwners[nOwnerCount].path_count = pPaths->nCount;
        pOwners[nOwnerCount].order = pEntry->qwOrder;
        nOwnerCount++;
    }

    dwError = RunFileTriggerOwners(
                  pOwners,
                  nOwnerCount,
                  phase,
                  TDNF_RPM_FILE_TRIGGER_KIND_PACKAGE,
                  priorityClass,
                  pszPhaseName,
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr,
                  0);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pOwners);
    TDNF_SAFE_FREE_MEMORY(pFlatPaths);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
RunImmediatePackageFileTriggers(
    NATIVE_TRANSACTION_VIEW *pView,
    const unsigned char *pbOwnerBlob,
    size_t nOwnerBlobLen,
    uint64_t qwOwnerOrder,
    tdnf_rpm_trigger_phase phase,
    tdnf_rpm_trigger_priority_class priorityClass,
    const char *pszPhaseName,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    NATIVE_PATH_LIST paths;
    tdnf_rpm_trigger_path *pFlatPaths = NULL;
    tdnf_rpm_file_trigger_owner owner;
    int nHasFileTriggers = 0;

    memset(&paths, 0, sizeof(paths));
    memset(&owner, 0, sizeof(owner));
    nHasFileTriggers = tdnf_rpm_header_has_file_trigger_metadata(
                           pbOwnerBlob,
                           nOwnerBlobLen,
                           TDNF_RPM_FILE_TRIGGER_KIND_PACKAGE);
    if(nHasFileTriggers < 0)
    {
        LogRpmzigError("inspect package file triggers");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(!nHasFileTriggers)
    {
        goto cleanup;
    }
    dwError = CollectAllDbTriggerPaths(
                  pView,
                  dwTransFlags,
                  &paths);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = PathListFlatten(&paths, &pFlatPaths);
    BAIL_ON_TDNF_ERROR(dwError);

    owner.header_blob = pbOwnerBlob;
    owner.header_len = nOwnerBlobLen;
    owner.paths = pFlatPaths;
    owner.path_count = paths.nCount;
    owner.order = qwOwnerOrder;

    dwError = RunFileTriggerOwners(
                  &owner,
                  1,
                  phase,
                  TDNF_RPM_FILE_TRIGGER_KIND_PACKAGE,
                  priorityClass,
                  pszPhaseName,
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr,
                  0);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pFlatPaths);
    PathListCleanup(&paths);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
RunStableTransactionFileTriggers(
    NATIVE_TRANSACTION_VIEW *pView,
    const NATIVE_PATH_LIST *pPaths,
    tdnf_rpm_trigger_phase phase,
    const char *pszPhaseName,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_file_trigger_owner *pOwners = NULL;
    tdnf_rpm_trigger_path *pFlatPaths = NULL;
    size_t nOwnerCount = 0;
    size_t i = 0;

    if(!pView || !pPaths)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    dwError = PathListFlatten(pPaths, &pFlatPaths);
    BAIL_ON_TDNF_ERROR(dwError);
    if(pView->nCount)
    {
        dwError = TDNFAllocateMemory(
                      pView->nCount,
                      sizeof(*pOwners),
                      (void **)&pOwners);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(i = 0; i < pView->nCount; i++)
    {
        NATIVE_VIEW_ENTRY *pEntry = &pView->pEntries[i];
        if(!pEntry->nDbVisible || pEntry->nAdded || pEntry->nRemoved)
        {
            continue;
        }
        pOwners[nOwnerCount].header_blob = pEntry->pbBlob;
        pOwners[nOwnerCount].header_len = pEntry->nBlobLen;
        pOwners[nOwnerCount].paths = pFlatPaths;
        pOwners[nOwnerCount].path_count = pPaths->nCount;
        pOwners[nOwnerCount].order = pEntry->qwOrder;
        nOwnerCount++;
    }

    dwError = RunFileTriggerOwners(
                  pOwners,
                  nOwnerCount,
                  phase,
                  TDNF_RPM_FILE_TRIGGER_KIND_TRANSACTION,
                  TDNF_RPM_TRIGGER_PRIORITY_ALL,
                  pszPhaseName,
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr,
                  phase == TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pOwners);
    TDNF_SAFE_FREE_MEMORY(pFlatPaths);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
RunRemovedImmediateTransactionFileTriggers(
    NATIVE_TRANSACTION_VIEW *pView,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    NATIVE_PATH_LIST paths;
    tdnf_rpm_trigger_path *pFlatPaths = NULL;
    size_t nRemovedCount = 0;
    size_t nOrder = 0;
    size_t i = 0;
    int nHasRemovedFileTriggers = 0;
    int nHasFileTriggers = 0;

    memset(&paths, 0, sizeof(paths));
    for(i = 0; i < pView->nCount; i++)
    {
        if(pView->pEntries[i].nRemoved)
        {
            nRemovedCount++;
            nHasFileTriggers = tdnf_rpm_header_has_file_trigger_metadata(
                                   pView->pEntries[i].pbBlob,
                                   pView->pEntries[i].nBlobLen,
                                   TDNF_RPM_FILE_TRIGGER_KIND_TRANSACTION);
            if(nHasFileTriggers < 0)
            {
                LogRpmzigError("inspect removed transaction file triggers");
                dwError = ERROR_TDNF_TRANSACTION_FAILED;
                BAIL_ON_TDNF_ERROR(dwError);
            }
            if(nHasFileTriggers)
            {
                nHasRemovedFileTriggers = 1;
            }
        }
    }
    if(!nRemovedCount || !nHasRemovedFileTriggers)
    {
        goto cleanup;
    }
    dwError = CollectAllDbTriggerPaths(pView, 0, &paths);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = PathListFlatten(&paths, &pFlatPaths);
    BAIL_ON_TDNF_ERROR(dwError);
    for(nOrder = 0; nOrder < nRemovedCount; nOrder++)
    {
        NATIVE_VIEW_ENTRY *pEntry = NULL;
        tdnf_rpm_file_trigger_owner owner;

        memset(&owner, 0, sizeof(owner));
        for(i = 0; i < pView->nCount; i++)
        {
            if(pView->pEntries[i].nRemoved &&
               pView->pEntries[i].qwRemovalOrder == nOrder)
            {
                pEntry = &pView->pEntries[i];
                break;
            }
        }
        if(!pEntry)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        owner.header_blob = pEntry->pbBlob;
        owner.header_len = pEntry->nBlobLen;
        owner.paths = pFlatPaths;
        owner.path_count = paths.nCount;
        owner.order = pEntry->qwRemovalOrder;

        dwError = RunFileTriggerOwners(
                      &owner,
                      1,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                      TDNF_RPM_FILE_TRIGGER_KIND_TRANSACTION,
                      TDNF_RPM_TRIGGER_PRIORITY_ALL,
                      "%transfiletriggerun (transaction package)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr,
                      0);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pFlatPaths);
    PathListCleanup(&paths);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
RunAddedImmediateTransactionFileTriggers(
    NATIVE_TRANSACTION_VIEW *pView,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    NATIVE_PATH_LIST paths;
    tdnf_rpm_trigger_path *pFlatPaths = NULL;
    size_t i = 0;
    int nHasAddedFileTriggers = 0;
    int nHasFileTriggers = 0;

    memset(&paths, 0, sizeof(paths));
    for(i = 0; i < pView->nCount; i++)
    {
        if(!pView->pEntries[i].nAdded)
        {
            continue;
        }
        nHasFileTriggers = tdnf_rpm_header_has_file_trigger_metadata(
                               pView->pEntries[i].pbBlob,
                               pView->pEntries[i].nBlobLen,
                               TDNF_RPM_FILE_TRIGGER_KIND_TRANSACTION);
        if(nHasFileTriggers < 0)
        {
            LogRpmzigError("inspect added transaction file triggers");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(nHasFileTriggers)
        {
            nHasAddedFileTriggers = 1;
            break;
        }
    }
    if(!nHasAddedFileTriggers)
    {
        goto cleanup;
    }
    dwError = CollectAllDbTriggerPaths(pView, dwTransFlags, &paths);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = PathListFlatten(&paths, &pFlatPaths);
    BAIL_ON_TDNF_ERROR(dwError);
    for(i = 0; i < pView->nCount; i++)
    {
        NATIVE_VIEW_ENTRY *pEntry = &pView->pEntries[i];
        tdnf_rpm_file_trigger_owner owner;

        if(!pEntry->nAdded)
        {
            continue;
        }
        memset(&owner, 0, sizeof(owner));
        owner.header_blob = pEntry->pbBlob;
        owner.header_len = pEntry->nBlobLen;
        owner.paths = pFlatPaths;
        owner.path_count = paths.nCount;
        owner.order = pEntry->qwOrder;

        dwError = RunFileTriggerOwners(
                      &owner,
                      1,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERIN,
                      TDNF_RPM_FILE_TRIGGER_KIND_TRANSACTION,
                      TDNF_RPM_TRIGGER_PRIORITY_ALL,
                      "%transfiletriggerin (transaction package)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr,
                      0);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pFlatPaths);
    PathListCleanup(&paths);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
RunScheduledPostunTransactionFileTriggers(
    NATIVE_POSTUN_QUEUE *pQueue,
    NATIVE_TRANSACTION_VIEW *pView,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_file_trigger_owner *pOwners = NULL;
    tdnf_rpm_trigger_path **ppFlatPaths = NULL;
    NATIVE_POSTUN_OWNER *pQueued = NULL;
    size_t nOwnerCount = 0;
    size_t i = 0;

    if(!pQueue || !pView)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(pQueue->nCount)
    {
        dwError = TDNFAllocateMemory(
                      pQueue->nCount,
                      sizeof(*pOwners),
                      (void **)&pOwners);
        BAIL_ON_TDNF_ERROR(dwError);
        dwError = TDNFAllocateMemory(
                      pQueue->nCount,
                      sizeof(*ppFlatPaths),
                      (void **)&ppFlatPaths);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(pQueued = pQueue->pHead;
        pQueued;
        pQueued = pQueued->pNext)
    {
        if(!TransactionViewContainsDbBlob(pView, pQueued->pbBlob))
        {
            continue;
        }
        dwError = PathListFlatten(
                      &pQueued->paths,
                      &ppFlatPaths[nOwnerCount]);
        BAIL_ON_TDNF_ERROR(dwError);
        pOwners[nOwnerCount].header_blob = pQueued->pbBlob;
        pOwners[nOwnerCount].header_len = pQueued->nBlobLen;
        pOwners[nOwnerCount].paths = ppFlatPaths[nOwnerCount];
        pOwners[nOwnerCount].path_count = pQueued->paths.nCount;
        pOwners[nOwnerCount].order = pQueued->qwOrder;
        nOwnerCount++;
    }

    dwError = RunFileTriggerOwners(
                  pOwners,
                  nOwnerCount,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN,
                  TDNF_RPM_FILE_TRIGGER_KIND_TRANSACTION,
                  TDNF_RPM_TRIGGER_PRIORITY_ALL,
                  "%transfiletriggerpostun",
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr,
                  1);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    if(ppFlatPaths)
    {
        for(i = 0; i < pQueue->nCount; i++)
        {
            TDNF_SAFE_FREE_MEMORY(ppFlatPaths[i]);
        }
    }
    TDNF_SAFE_FREE_MEMORY(ppFlatPaths);
    TDNF_SAFE_FREE_MEMORY(pOwners);
    return dwError;

error:
    goto cleanup;
}

/*
 * Emit an rpmzig install-options blob wired to the transaction overlay,
 * prior headers and changed-path collector.
 */
static void
FillInstallOptions(
    tdnf_rpm_install_options *pOptions,
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    tdnf_rpm_install_kind eKind,
    const tdnf_rpm_install_prior_header *pPriors,
    size_t nPriors,
    NATIVE_OWNERSHIP_CTX *pOwnershipCtx,
    NATIVE_INSTALL_PATH_CTX *pPathCtx
    )
{
    memset(pOptions, 0, sizeof(*pOptions));
    pOptions->install_root = pszInstallRoot;
    pOptions->config = pRpmConfig;
    pOptions->trans_flags = dwTransFlags;
    pOptions->install_kind = eKind;
    pOptions->prior_headers = pPriors;
    pOptions->prior_header_count = nPriors;
    pOptions->conflict_fn = NativePathOwned;
    pOptions->conflict_fn_data = pOwnershipCtx;
    pOptions->changed_path_fn = AppendInstalledTriggerPath;
    pOptions->changed_path_fn_data = pPathCtx;
}

static uint32_t
CollectPriorRows(
    const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan,
    uint32_t dwInputIndex,
    NATIVE_TRANSACTION_VIEW *pView,
    const uint32_t **ppahnums,
    const unsigned char ***papBlobs,
    size_t **panBlobLens,
    size_t *pnCount
    )
{
    uint32_t dwError = 0;
    const uint32_t *pHnums = NULL;
    const unsigned char **ppBlobs = NULL;
    size_t *pnLens = NULL;
    size_t nHnums = 0;
    size_t i = 0;

    *ppahnums = NULL;
    *papBlobs = NULL;
    *panBlobLens = NULL;
    *pnCount = 0;

    if(!pPlan || !pView || dwInputIndex >= pPlan->dwItemCount ||
       !pPlan->pItems)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    nHnums = pPlan->pItems[dwInputIndex].dwPriorCount;
    if(!nHnums)
    {
        goto cleanup;
    }
    if(!pPlan->pdwPriorHnums ||
       pPlan->pItems[dwInputIndex].dwPriorOffset >
           pPlan->dwPriorHnumCount ||
       nHnums > pPlan->dwPriorHnumCount -
           pPlan->pItems[dwInputIndex].dwPriorOffset)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    pHnums = &pPlan->pdwPriorHnums[
        pPlan->pItems[dwInputIndex].dwPriorOffset];

    dwError = TDNFAllocateMemory(
                  nHnums,
                  sizeof(*ppBlobs),
                  (void **)&ppBlobs);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TDNFAllocateMemory(
                  nHnums,
                  sizeof(*pnLens),
                  (void **)&pnLens);
    BAIL_ON_TDNF_ERROR(dwError);

    for (i = 0; i < nHnums; i++)
    {
        NATIVE_VIEW_ENTRY *pEntry =
            TransactionViewFindHnum(pView, pHnums[i]);
        if(!pEntry || !pEntry->nActive)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        ppBlobs[i] = pEntry->pbBlob;
        pnLens[i] = pEntry->nBlobLen;
    }

    *ppahnums = pHnums;
    *papBlobs = ppBlobs;
    *panBlobLens = pnLens;
    *pnCount = nHnums;
    ppBlobs = NULL;
    pnLens = NULL;

cleanup:
    TDNF_SAFE_FREE_MEMORY(ppBlobs);
    TDNF_SAFE_FREE_MEMORY(pnLens);
    return dwError;

error:
    goto cleanup;
}

static void
FreePriorRows(
    const unsigned char **papBlobs,
    size_t *panBlobLens
    )
{
    TDNF_SAFE_FREE_MEMORY(papBlobs);
    TDNF_SAFE_FREE_MEMORY(panBlobLens);
}

/*
 * Per-package sub-phase for erasing the OLD version(s) already
 * replaced by an UPGRADE/REINSTALL step. File triggers bracket the
 * ordinary trigger/script/file phases at rpm's high/low priority
 * boundaries. Ordinary scriptlets and name triggers retain their
 * package-count arguments; file and transaction-file triggers always
 * receive `$1=0` and no `$2`, as in rpm's runFileTriggers path.
 * Filesystem cleanup relies on the erase engine's default
 * keep-path probe: paths still owned by the new package are kept,
 * files/directories unique to the old package are removed.
 */
static uint32_t
EraseOldAfterReplace(
    const char *pszInstallRoot,
    const tdnf_rpm_config *pRpmConfig,
    uint32_t dwTransFlags,
    NATIVE_TRANSACTION_VIEW *pView,
    uint32_t dwOldHnum,
    const unsigned char *pbOldBlob,
    size_t nOldLen,
    const char *pszName,
    const char *pszNevra,
    int nEraseDbRow,
    NATIVE_POSTUN_QUEUE *pPostunQueue,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_erase_options erase_options;
    NATIVE_OWNERSHIP_CTX ownership_ctx;
    NATIVE_PATH_LIST removed_paths;
    NATIVE_PATH_LIST transaction_removed_paths;
    NATIVE_VIEW_ENTRY *pOldEntry = NULL;
    int nCurrentCount = 0;
    int nCountAfter = 0;

    memset(&erase_options, 0, sizeof(erase_options));
    memset(&ownership_ctx, 0, sizeof(ownership_ctx));
    memset(&removed_paths, 0, sizeof(removed_paths));
    memset(&transaction_removed_paths, 0, sizeof(transaction_removed_paths));
    pOldEntry = TransactionViewFindHnum(pView, dwOldHnum);
    if(!pOldEntry || !pOldEntry->nActive)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    nCurrentCount = TransactionViewCountName(pView, pszName);
    if(nCurrentCount <= 0)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    nCountAfter = nCurrentCount - 1;
    ownership_ctx.pView = pView;
    ownership_ctx.pRpmConfig = pRpmConfig;
    ownership_ctx.pdwIgnoredHnums = &dwOldHnum;
    ownership_ctx.nIgnoredHnums = 1;
    erase_options.config = pRpmConfig;
    erase_options.trans_flags = dwTransFlags;
    erase_options.keep_path_fn = NativePathOwned;
    erase_options.keep_path_fn_data = &ownership_ctx;

    dwError = CollectHeaderTriggerPaths(
                  pbOldBlob,
                  nOldLen,
                  0,
                  &ownership_ctx,
                  &removed_paths);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = CollectHeaderTriggerPaths(
                  pbOldBlob,
                  nOldLen,
                  0,
                  NULL,
                  &transaction_removed_paths);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunImmediatePackageFileTriggers(
                  pView,
                  pbOldBlob,
                  nOldLen,
                  pOldEntry->qwOrder,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                  TDNF_RPM_TRIGGER_PRIORITY_HIGH,
                  "%filetriggerun (removed package, high)",
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunOtherPackageFileTriggers(
                  pView,
                  &removed_paths,
                  pbOldBlob,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                  TDNF_RPM_TRIGGER_PRIORITY_HIGH,
                  "%filetriggerun (high)",
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunTriggers(pbOldBlob, nOldLen,
                          TDNF_RPM_TRIGGER_PHASE_TRIGGERUN, "%triggerun",
                          pszNevra, pszInstallRoot, pRpmConfig,
                          dwTransFlags, pView,
                          nScriptFd, nRedirectToStderr,
                          1, nCountAfter);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunScriptlet(pbOldBlob, nOldLen,
                           TDNF_RPM_SCRIPTLET_PHASE_PREUN, "%preun",
                           pszNevra, pszInstallRoot, pRpmConfig,
                           dwTransFlags,
                           nCountAfter, -1,
                           nScriptFd, nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunImmediatePackageFileTriggers(
                  pView,
                  pbOldBlob,
                  nOldLen,
                  pOldEntry->qwOrder,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                  TDNF_RPM_TRIGGER_PRIORITY_LOW,
                  "%filetriggerun (removed package, low)",
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunOtherPackageFileTriggers(
                  pView,
                  &removed_paths,
                  pbOldBlob,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                  TDNF_RPM_TRIGGER_PRIORITY_LOW,
                  "%filetriggerun (low)",
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    if (tdnf_rpm_erase_header_blob(pszInstallRoot,
                                   pbOldBlob, nOldLen,
                                   &erase_options) != 0)
    {
        LogRpmzigError("rpm_erase_header_blob");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TransactionViewDeactivateHnum(pView, dwOldHnum);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunOtherPackageFileTriggers(
                  pView,
                  &removed_paths,
                  pbOldBlob,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN,
                  TDNF_RPM_TRIGGER_PRIORITY_HIGH,
                  "%filetriggerpostun (high)",
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunScriptlet(pbOldBlob, nOldLen,
                           TDNF_RPM_SCRIPTLET_PHASE_POSTUN, "%postun",
                           pszNevra, pszInstallRoot, pRpmConfig,
                           dwTransFlags,
                           nCountAfter, -1,
                           nScriptFd, nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunTriggers(pbOldBlob, nOldLen,
                          TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN, "%triggerpostun",
                          pszNevra, pszInstallRoot, pRpmConfig,
                          dwTransFlags, pView,
                          nScriptFd, nRedirectToStderr,
                          1, nCountAfter);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunOtherPackageFileTriggers(
                  pView,
                  &removed_paths,
                  pbOldBlob,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN,
                  TDNF_RPM_TRIGGER_PRIORITY_LOW,
                  "%filetriggerpostun (low)",
                  pszInstallRoot,
                  pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = SchedulePostunTransactionTriggers(
                  pPostunQueue,
                  pView,
                  &transaction_removed_paths);
    BAIL_ON_TDNF_ERROR(dwError);

    if(!(dwTransFlags & TDNF_RPMTRANS_FLAG_NODB))
    {
        if(nEraseDbRow &&
           tdnf_rpmdb_write_erase_hnum_config(
               pRpmConfig,
               dwOldHnum) != 0)
        {
            LogRpmzigError("rpmdb_write_erase_hnum");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        dwError = TransactionViewHideDbHnum(pView, dwOldHnum);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    PathListCleanup(&transaction_removed_paths);
    PathListCleanup(&removed_paths);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
ProcessInstallItem(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan,
    uint32_t dwInputIndex,
    NATIVE_TRANSACTION_VIEW *pView,
    const uint32_t *pdwRemovedHnums,
    size_t nRemovedHnums,
    NATIVE_PATH_LIST *pTransactionAddedPaths,
    NATIVE_POSTUN_QUEUE *pPostunQueue,
    PTDNF_RPM_TS_ITEM pItem,
    uint32_t dwTransFlags,
    uint32_t dwInstallTid,
    uint32_t dwInstallTime,
    const char *pszInstallRoot,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_file *pFile = pItem->pRpmFile;
    const unsigned char *pbBlob = NULL;
    size_t nLen = 0;
    tdnf_rpm_install_options install_options;
    tdnf_rpm_install_prior_header *pPriorViews = NULL;
    const uint32_t *pPriorHnums = NULL;
    const unsigned char **ppPriorBlobs = NULL;
    size_t *pnPriorLens = NULL;
    size_t nPriors = 0;
    tdnf_rpm_install_kind eKind;
    uint32_t dwNewHnum = 0;
    int nArg1 = 0;
    int nCount = 0;
    const char *pszNevra = NULL;
    char *pszNevraBuf = NULL;
    const tdnf_rpm_config *pRpmConfig = pTdnf->pRpmConfig;
    NATIVE_OWNERSHIP_CTX ownership_ctx;
    NATIVE_INSTALL_PATH_CTX install_path_ctx;
    NATIVE_PATH_LIST item_paths;
    NATIVE_VIEW_ENTRY *pNewEntry = NULL;

    memset(&ownership_ctx, 0, sizeof(ownership_ctx));
    memset(&install_path_ctx, 0, sizeof(install_path_ctx));
    memset(&item_paths, 0, sizeof(item_paths));

    if (!pFile)
    {
        pr_err("rpmzig-transaction-execute: install item missing verified "
               ".rpm handle\n");
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (tdnf_rpm_file_main_header_blob(pFile, &pbBlob, &nLen) != 0)
    {
        LogRpmzigError("rpm_file_main_header_blob");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    /* Compose a NEVRA-ish string for user-facing log lines. */
    if (!IsNullOrEmptyString(pItem->pszName) &&
        !IsNullOrEmptyString(pItem->pszEVR) &&
        !IsNullOrEmptyString(pItem->pszArch))
    {
        dwError = TDNFAllocateStringPrintf(&pszNevraBuf, "%s-%s.%s",
                                           pItem->pszName,
                                           pItem->pszEVR,
                                           pItem->pszArch);
        BAIL_ON_TDNF_ERROR(dwError);
        pszNevra = pszNevraBuf;
    }

    switch (pItem->nType)
    {
        case TDNF_RPM_TS_ITEM_INSTALL:
            eKind = TDNF_RPM_INSTALL_KIND_INSTALL;
            break;
        case TDNF_RPM_TS_ITEM_UPGRADE:
            eKind = TDNF_RPM_INSTALL_KIND_UPGRADE;
            break;
        case TDNF_RPM_TS_ITEM_REINSTALL:
            eKind = TDNF_RPM_INSTALL_KIND_REINSTALL;
            break;
        default:
            pr_err("rpmzig-transaction-execute: unexpected item type %d\n",
                   pItem->nType);
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = CollectPriorRows(pPlan,
                               dwInputIndex,
                               pView,
                               &pPriorHnums, &ppPriorBlobs,
                               &pnPriorLens, &nPriors);
    BAIL_ON_TDNF_ERROR(dwError);
    if(pItem->nType == TDNF_RPM_TS_ITEM_UPGRADE && nPriors > 1)
    {
        dwError = ERROR_TDNF_RPM_CHECK;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (nPriors > 0)
    {
        size_t i = 0;
        dwError = TDNFAllocateMemory(nPriors,
                                     sizeof(tdnf_rpm_install_prior_header),
                                     (void **)&pPriorViews);
        BAIL_ON_TDNF_ERROR(dwError);
        for (i = 0; i < nPriors; i++)
        {
            pPriorViews[i].blob = ppPriorBlobs[i];
            pPriorViews[i].len = pnPriorLens[i];
        }
    }
    ownership_ctx.pView = pView;
    ownership_ctx.pRpmConfig = pRpmConfig;
    ownership_ctx.pdwIgnoredHnums = pdwRemovedHnums;
    ownership_ctx.nIgnoredHnums = nRemovedHnums;
    install_path_ctx.pItemPaths = &item_paths;
    install_path_ctx.pbSourceBlob = pbBlob;
    install_path_ctx.nSourceLen = nLen;

    nCount = TransactionViewCountName(pView, pItem->pszName);
    if(nCount < 0 || nCount == INT_MAX)
    {
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    nArg1 = nCount + 1;

    /* %pre on the new package */
    if (!pTdnf->pArgs->nTestOnly)
    {
        dwError = RunScriptlet(pbBlob, nLen,
                               TDNF_RPM_SCRIPTLET_PHASE_PRE, "%pre",
                               pszNevra, pszInstallRoot, pRpmConfig, dwTransFlags,
                               nArg1, -1, nScriptFd, nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(!pTS->nQuiet)
    {
        pr_info("%s: %s\n",
                pItem->nType == TDNF_RPM_TS_ITEM_REINSTALL ?
                    "Reinstalling" :
                pItem->nType == TDNF_RPM_TS_ITEM_UPGRADE ?
                    "Upgrading" : "Installing",
                pszNevra ? pszNevra : pItem->pszPath);
    }

    if (!pTdnf->pArgs->nTestOnly)
    {
        FillInstallOptions(&install_options, pszInstallRoot, pRpmConfig,
                           dwTransFlags, eKind, pPriorViews, nPriors,
                           &ownership_ctx, &install_path_ctx);
        if (tdnf_rpm_file_install(pFile, &install_options) != 0)
        {
            LogRpmzigError("rpm_file_install");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if(!(dwTransFlags & TDNF_RPMTRANS_FLAG_NODB) && nPriors > 0)
        {
            if (tdnf_rpmdb_write_replace_file_config(
                    pRpmConfig,
                    pPriorHnums[0],
                    pFile,
                    dwInstallTid,
                    dwInstallTime,
                    0,
                    NULL,
                    0,
                    &dwNewHnum) != 0)
            {
                LogRpmzigError("rpmdb_write_replace");
                dwError = ERROR_TDNF_TRANSACTION_FAILED;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
        else if(!(dwTransFlags & TDNF_RPMTRANS_FLAG_NODB))
        {
            if (tdnf_rpmdb_write_install_file_config(
                    pRpmConfig,
                    pFile,
                    dwInstallTid,
                    dwInstallTime,
                    0,
                    NULL,
                    0,
                    &dwNewHnum) != 0)
            {
                LogRpmzigError("rpmdb_write_install");
                dwError = ERROR_TDNF_TRANSACTION_FAILED;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
        dwError = TransactionViewActivate(
                      pView,
                      pbBlob,
                      nLen,
                      dwNewHnum,
                      !(dwTransFlags & TDNF_RPMTRANS_FLAG_NODB));
        BAIL_ON_TDNF_ERROR(dwError);
        pNewEntry = &pView->pEntries[pView->nCount - 1];
        if(pNewEntry->nDbVisible)
        {
            dwError = PathListMerge(
                          pTransactionAddedPaths,
                          &item_paths);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    if (!pTdnf->pArgs->nTestOnly)
    {
        dwError = RunOtherPackageFileTriggers(
                      pView,
                      &item_paths,
                      pbBlob,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERIN,
                      TDNF_RPM_TRIGGER_PRIORITY_HIGH,
                      "%filetriggerin (high)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunImmediatePackageFileTriggers(
                      pView,
                      pbBlob,
                      nLen,
                      pNewEntry->qwOrder,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERIN,
                      TDNF_RPM_TRIGGER_PRIORITY_HIGH,
                      "%filetriggerin (installed package, high)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        /* %post on the new package */
        dwError = RunScriptlet(pbBlob, nLen,
                               TDNF_RPM_SCRIPTLET_PHASE_POST, "%post",
                               pszNevra, pszInstallRoot, pRpmConfig, dwTransFlags,
                               nArg1, -1, nScriptFd, nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        /*
         * %triggerin fired by OTHER installed pkgs targeting this
         * name. For fresh install, arg2 defaults to the rpmdb count
         * (which is 1 after write_install). For upgrade/reinstall,
         * write_replace atomically swapped the row so the rpmdb
         * still shows exactly one instance — but real rpm's
         * transient state briefly has BOTH the old and new
         * installed at %triggerin time, so `$2` = 1 (new) + nPriors
         * (old rows that get erased below). Override accordingly.
         */
        dwError = RunTriggers(pbBlob, nLen,
                              TDNF_RPM_TRIGGER_PHASE_TRIGGERIN, "%triggerin",
                              pszNevra, pszInstallRoot, pRpmConfig, dwTransFlags,
                              pView,
                              nScriptFd, nRedirectToStderr,
                              1, nArg1);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunOtherPackageFileTriggers(
                      pView,
                      &item_paths,
                      pbBlob,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERIN,
                      TDNF_RPM_TRIGGER_PRIORITY_LOW,
                      "%filetriggerin (low)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunImmediatePackageFileTriggers(
                      pView,
                      pbBlob,
                      nLen,
                      pNewEntry->qwOrder,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERIN,
                      TDNF_RPM_TRIGGER_PRIORITY_LOW,
                      "%filetriggerin (installed package, low)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        /*
         * For upgrade/reinstall: run the old-package cleanup
         * (%preun, file-erase for files unique to the old version,
         * %postun — all with arg1=1 because the new instance
         * survives). The rpmdb row itself was atomically replaced
         * by write_replace() above; EraseOldAfterReplace only does
         * the filesystem + scriptlet halves.
         */
        {
            size_t i = 0;
            for (i = 0; i < nPriors; i++)
            {
                dwError = EraseOldAfterReplace(pszInstallRoot, pRpmConfig,
                                               dwTransFlags,
                                               pView,
                                               pPriorHnums[i],
                                               ppPriorBlobs[i], pnPriorLens[i],
                                               pItem->pszName,
                                               pszNevra,
                                               i > 0,
                                               pPostunQueue,
                                               nScriptFd, nRedirectToStderr);
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
    }
cleanup:
    PathListCleanup(&item_paths);
    TDNF_SAFE_FREE_MEMORY(pPriorViews);
    FreePriorRows(ppPriorBlobs, pnPriorLens);
    TDNF_SAFE_FREE_MEMORY(pszNevraBuf);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
ProcessEraseItem(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    NATIVE_TRANSACTION_VIEW *pView,
    NATIVE_POSTUN_QUEUE *pPostunQueue,
    PTDNF_RPM_TS_ITEM pItem,
    uint32_t dwTransFlags,
    const char *pszInstallRoot,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    const unsigned char *pbBlob = NULL;
    size_t nLen = 0;
    tdnf_rpm_erase_options erase_options;
    NATIVE_OWNERSHIP_CTX ownership_ctx;
    NATIVE_VIEW_ENTRY *pEntry = NULL;
    const char *pszNevra = NULL;
    char *pszNevraBuf = NULL;
    const tdnf_rpm_config *pRpmConfig = pTdnf->pRpmConfig;
    int nCurrentCount = 0;
    int nCountAfter = 0;
    NATIVE_PATH_LIST removed_paths;
    NATIVE_PATH_LIST transaction_removed_paths;

    memset(&ownership_ctx, 0, sizeof(ownership_ctx));
    memset(&removed_paths, 0, sizeof(removed_paths));
    memset(&transaction_removed_paths, 0, sizeof(transaction_removed_paths));
    if (pItem->dwRpmDbHnum == 0)
    {
        pr_err("rpmzig-transaction-execute: erase item missing hnum\n");
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (!IsNullOrEmptyString(pItem->pszName) &&
        !IsNullOrEmptyString(pItem->pszEVR) &&
        !IsNullOrEmptyString(pItem->pszArch))
    {
        dwError = TDNFAllocateStringPrintf(&pszNevraBuf, "%s-%s.%s",
                                           pItem->pszName,
                                           pItem->pszEVR,
                                           pItem->pszArch);
        BAIL_ON_TDNF_ERROR(dwError);
        pszNevra = pszNevraBuf;
    }

    pEntry = TransactionViewFindHnum(pView, pItem->dwRpmDbHnum);
    if(!pEntry || !pEntry->nActive)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    pbBlob = pEntry->pbBlob;
    nLen = pEntry->nBlobLen;
    nCurrentCount = TransactionViewCountName(pView, pItem->pszName);
    if(nCurrentCount <= 0)
    {
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    nCountAfter = nCurrentCount - 1;
    ownership_ctx.pView = pView;
    ownership_ctx.pRpmConfig = pRpmConfig;
    ownership_ctx.pdwIgnoredHnums = &pItem->dwRpmDbHnum;
    ownership_ctx.nIgnoredHnums = 1;

    dwError = CollectHeaderTriggerPaths(
                  pbBlob,
                  nLen,
                  0,
                  &ownership_ctx,
                  &removed_paths);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = CollectHeaderTriggerPaths(
                  pbBlob,
                  nLen,
                  0,
                  NULL,
                  &transaction_removed_paths);
    BAIL_ON_TDNF_ERROR(dwError);

    /*
     * Triggers fired BEFORE %preun so real rpm's "$2 = count after
     * this step" semantics see the pre-removal instance count minus
     * one (the engine handles the -1 internally).
     */
    if (!pTdnf->pArgs->nTestOnly)
    {
        dwError = RunImmediatePackageFileTriggers(
                      pView,
                      pbBlob,
                      nLen,
                      pEntry->qwOrder,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                      TDNF_RPM_TRIGGER_PRIORITY_HIGH,
                      "%filetriggerun (removed package, high)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunOtherPackageFileTriggers(
                      pView,
                      &removed_paths,
                      pbBlob,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                      TDNF_RPM_TRIGGER_PRIORITY_HIGH,
                      "%filetriggerun (high)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunTriggers(pbBlob, nLen,
                              TDNF_RPM_TRIGGER_PHASE_TRIGGERUN, "%triggerun",
                              pszNevra, pszInstallRoot, pRpmConfig, dwTransFlags,
                              pView,
                              nScriptFd, nRedirectToStderr,
                              1, nCountAfter);
        BAIL_ON_TDNF_ERROR(dwError);

        /* %preun on the erased package (arg1 = 0 for total removal) */
        dwError = RunScriptlet(pbBlob, nLen,
                               TDNF_RPM_SCRIPTLET_PHASE_PREUN, "%preun",
                               pszNevra, pszInstallRoot, pRpmConfig, dwTransFlags,
                               nCountAfter, -1,
                               nScriptFd, nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunImmediatePackageFileTriggers(
                      pView,
                      pbBlob,
                      nLen,
                      pEntry->qwOrder,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                      TDNF_RPM_TRIGGER_PRIORITY_LOW,
                      "%filetriggerun (removed package, low)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunOtherPackageFileTriggers(
                      pView,
                      &removed_paths,
                      pbBlob,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                      TDNF_RPM_TRIGGER_PRIORITY_LOW,
                      "%filetriggerun (low)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(!pTS->nQuiet)
    {
        pr_info("Removing: %s\n",
                pszNevra ? pszNevra : pItem->pszName);
    }

    if (!pTdnf->pArgs->nTestOnly)
    {
        memset(&erase_options, 0, sizeof(erase_options));
        erase_options.config = pRpmConfig;
        erase_options.trans_flags = dwTransFlags;
        erase_options.keep_path_fn = NativePathOwned;
        erase_options.keep_path_fn_data = &ownership_ctx;

        if (tdnf_rpm_erase_header_blob(
                pszInstallRoot,
                pbBlob,
                nLen,
                &erase_options) != 0)
        {
            LogRpmzigError("rpm_erase_header_blob");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        dwError = TransactionViewDeactivateHnum(
                      pView,
                      pItem->dwRpmDbHnum);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunOtherPackageFileTriggers(
                      pView,
                      &removed_paths,
                      pbBlob,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN,
                      TDNF_RPM_TRIGGER_PRIORITY_HIGH,
                      "%filetriggerpostun (high)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunScriptlet(pbBlob, nLen,
                               TDNF_RPM_SCRIPTLET_PHASE_POSTUN, "%postun",
                               pszNevra, pszInstallRoot, pRpmConfig, dwTransFlags,
                               nCountAfter, -1,
                               nScriptFd, nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        /* %triggerpostun fired AFTER %postun. */
        dwError = RunTriggers(pbBlob, nLen,
                              TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN, "%triggerpostun",
                              pszNevra, pszInstallRoot, pRpmConfig, dwTransFlags,
                              pView,
                              nScriptFd, nRedirectToStderr,
                              1, nCountAfter);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = RunOtherPackageFileTriggers(
                      pView,
                      &removed_paths,
                      pbBlob,
                      TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN,
                      TDNF_RPM_TRIGGER_PRIORITY_LOW,
                      "%filetriggerpostun (low)",
                      pszInstallRoot,
                      pRpmConfig,
                      dwTransFlags,
                      nScriptFd,
                      nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = SchedulePostunTransactionTriggers(
                      pPostunQueue,
                      pView,
                      &transaction_removed_paths);
        BAIL_ON_TDNF_ERROR(dwError);

        if (!(dwTransFlags & TDNF_RPMTRANS_FLAG_NODB))
        {
            if(tdnf_rpmdb_write_erase_hnum_config(
                   pRpmConfig,
                   pItem->dwRpmDbHnum) != 0)
            {
                LogRpmzigError("rpmdb_write_erase_hnum");
                dwError = ERROR_TDNF_TRANSACTION_FAILED;
                BAIL_ON_TDNF_ERROR(dwError);
            }
            dwError = TransactionViewHideDbHnum(
                          pView,
                          pItem->dwRpmDbHnum);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

cleanup:
    PathListCleanup(&transaction_removed_paths);
    PathListCleanup(&removed_paths);
    TDNF_SAFE_FREE_MEMORY(pszNevraBuf);
    return dwError;

error:
    goto cleanup;
}

/*
 * Whole-transaction %pretrans / %posttrans pass across every
 * install/upgrade/reinstall item.
 */
static uint32_t
RunTransPhase(
    const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan,
    PTDNF_RPM_TS_ITEM *ppInputItems,
    NATIVE_TRANSACTION_VIEW *pView,
    const tdnf_rpm_config *pRpmConfig,
    tdnf_rpm_scriptlet_phase phase,
    const char *pszPhaseName,
    const char *pszInstallRoot,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;
    PTDNF_RPM_TS_ITEM pItem = NULL;

    for (dwIndex = 0; dwIndex < pPlan->dwItemCount; dwIndex++)
    {
        tdnf_rpm_file *pFile = NULL;
        const unsigned char *pbBlob = NULL;
        size_t nLen = 0;
        int nArg1 = 0;

        uint32_t dwInputIndex = pPlan->pdwOrderIndices[dwIndex];
        if(dwInputIndex >= pPlan->dwItemCount)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        pItem = ppInputItems[dwInputIndex];
        if(!pItem)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        pFile = pItem->pRpmFile;

        if (pItem->nType == TDNF_RPM_TS_ITEM_ERASE)
        {
            continue;
        }
        if (!pFile)
        {
            pr_err("rpmzig-transaction-execute: install item missing "
                   "verified .rpm handle in transaction phase\n");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            goto error;
        }
        if (tdnf_rpm_file_main_header_blob(pFile, &pbBlob, &nLen) != 0)
        {
            LogRpmzigError("rpm_file_main_header_blob (trans phase)");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            goto error;
        }

        nArg1 = TransactionViewCountName(pView, pItem->pszName);
        if(nArg1 < 0 ||
           (phase == TDNF_RPM_SCRIPTLET_PHASE_PRETRANS &&
            nArg1 == INT_MAX))
        {
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(phase == TDNF_RPM_SCRIPTLET_PHASE_PRETRANS)
        {
            uint32_t dwPriorOrder = 0;
            nArg1++;
            for(dwPriorOrder = 0;
                dwPriorOrder < dwIndex;
                dwPriorOrder++)
            {
                uint32_t dwPriorInput =
                    pPlan->pdwOrderIndices[dwPriorOrder];
                PTDNF_RPM_TS_ITEM pPriorItem =
                    ppInputItems[dwPriorInput];
                if(pPriorItem &&
                   pPriorItem->nType != TDNF_RPM_TS_ITEM_ERASE &&
                   !IsNullOrEmptyString(pPriorItem->pszName) &&
                   !strcmp(pPriorItem->pszName, pItem->pszName))
                {
                    if(nArg1 == INT_MAX)
                    {
                        dwError = ERROR_TDNF_TRANSACTION_FAILED;
                        BAIL_ON_TDNF_ERROR(dwError);
                    }
                    nArg1++;
                }
            }
        }
        dwError = RunScriptlet(pbBlob, nLen, phase, pszPhaseName,
                               pItem->pszName, pszInstallRoot, pRpmConfig,
                               dwTransFlags,
                               nArg1, -1, nScriptFd, nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
AppendUniqueHnum(
    uint32_t *pdwHnums,
    size_t nCapacity,
    size_t *pnCount,
    uint32_t dwHnum
    )
{
    size_t i = 0;
    if(!pdwHnums || !pnCount || !dwHnum)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    for(i = 0; i < *pnCount; i++)
    {
        if(pdwHnums[i] == dwHnum)
        {
            return 0;
        }
    }
    if(*pnCount >= nCapacity)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }
    pdwHnums[*pnCount] = dwHnum;
    (*pnCount)++;
    return 0;
}

static uint32_t
PrevalidatePlan(
    PTDNFRPMTS pTS,
    const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan,
    PTDNF_RPM_TS_ITEM *ppInputItems,
    NATIVE_TRANSACTION_VIEW *pView,
    const tdnf_rpm_config *pRpmConfig
    )
{
    uint32_t dwError = 0;
    unsigned char *pbSeen = NULL;
    uint32_t dwIndex = 0;
    size_t nViewIndex = 0;

    if(!pTS || !pPlan || !ppInputItems || !pView || !pRpmConfig ||
       pPlan->dwItemCount != pTS->dwTransactionItemCount ||
       pPlan->dwProblemCount ||
       (pPlan->dwItemCount &&
        (!pPlan->pdwOrderIndices || !pPlan->pItems)))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if(pPlan->dwItemCount)
    {
        dwError = TDNFAllocateMemory(
                      pPlan->dwItemCount,
                      sizeof(*pbSeen),
                      (void **)&pbSeen);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(nViewIndex = 0;
        nViewIndex < pView->nCount;
        nViewIndex++)
    {
        NATIVE_VIEW_ENTRY *pEntry = &pView->pEntries[nViewIndex];
        if(tdnf_rpm_header_validate_trigger_scripts_config(
               pEntry->pbBlob,
               pEntry->nBlobLen,
               pRpmConfig) != 0)
        {
            LogRpmzigError("validate installed trigger metadata");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    for(dwIndex = 0; dwIndex < pPlan->dwItemCount; dwIndex++)
    {
        uint32_t dwInputIndex = pPlan->pdwOrderIndices[dwIndex];
        const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN_ITEM *pPlanItem = NULL;
        PTDNF_RPM_TS_ITEM pItem = NULL;
        uint32_t i = 0;

        if(dwInputIndex >= pPlan->dwItemCount || pbSeen[dwInputIndex])
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        pbSeen[dwInputIndex] = 1;
        pItem = ppInputItems[dwInputIndex];
        pPlanItem = &pPlan->pItems[dwInputIndex];
        if(!pItem ||
           pPlanItem->dwPriorOffset > pPlan->dwPriorHnumCount ||
           pPlanItem->dwPriorCount >
               pPlan->dwPriorHnumCount - pPlanItem->dwPriorOffset ||
           (pPlanItem->dwPriorCount && !pPlan->pdwPriorHnums))
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(pItem->nType == TDNF_RPM_TS_ITEM_UPGRADE &&
           pPlanItem->dwPriorCount > 1)
        {
            dwError = ERROR_TDNF_RPM_CHECK;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(pItem->nType == TDNF_RPM_TS_ITEM_ERASE)
        {
            NATIVE_VIEW_ENTRY *pEntry =
                TransactionViewFindHnum(pView, pItem->dwRpmDbHnum);
            if(pPlanItem->dwPriorCount || !pEntry || !pEntry->nActive)
            {
                dwError = ERROR_TDNF_INVALID_PARAMETER;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
        else if(!pItem->pRpmFile)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        else
        {
            const unsigned char *pbBlob = NULL;
            size_t nBlobLen = 0;
            if(tdnf_rpm_file_main_header_blob(
                   pItem->pRpmFile,
                   &pbBlob,
                   &nBlobLen) != 0 ||
               tdnf_rpm_header_validate_trigger_scripts_config(
                   pbBlob,
                   nBlobLen,
                   pRpmConfig) != 0)
            {
                LogRpmzigError("validate transaction trigger metadata");
                dwError = ERROR_TDNF_TRANSACTION_FAILED;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }

        for(i = 0; i < pPlanItem->dwPriorCount; i++)
        {
            uint32_t dwHnum = pPlan->pdwPriorHnums[
                pPlanItem->dwPriorOffset + i];
            NATIVE_VIEW_ENTRY *pEntry =
                TransactionViewFindHnum(pView, dwHnum);
            if(!pEntry || !pEntry->nActive)
            {
                dwError = ERROR_TDNF_INVALID_PARAMETER;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
    }

cleanup:
    TDNF_SAFE_FREE_MEMORY(pbSeen);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
MarkRemovedViewEntries(
    const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan,
    PTDNF_RPM_TS_ITEM *ppInputItems,
    NATIVE_TRANSACTION_VIEW *pView
    )
{
    uint32_t dwError = 0;
    uint32_t dwOrder = 0;
    uint64_t qwRemovalOrder = 0;

    if(!pPlan || !ppInputItems || !pView)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(dwOrder = 0; dwOrder < pPlan->dwItemCount; dwOrder++)
    {
        uint32_t dwInputIndex = pPlan->pdwOrderIndices[dwOrder];
        PTDNF_RPM_TS_ITEM pItem = ppInputItems[dwInputIndex];
        const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN_ITEM *pPlanItem =
            &pPlan->pItems[dwInputIndex];
        uint32_t i = 0;

        if(pItem->nType == TDNF_RPM_TS_ITEM_ERASE)
        {
            NATIVE_VIEW_ENTRY *pEntry =
                TransactionViewFindHnum(pView, pItem->dwRpmDbHnum);
            if(!pEntry)
            {
                dwError = ERROR_TDNF_INVALID_PARAMETER;
                BAIL_ON_TDNF_ERROR(dwError);
            }
            if(!pEntry->nRemoved)
            {
                pEntry->nRemoved = 1;
                pEntry->qwRemovalOrder = qwRemovalOrder++;
            }
        }
        for(i = 0; i < pPlanItem->dwPriorCount; i++)
        {
            uint32_t dwHnum = pPlan->pdwPriorHnums[
                pPlanItem->dwPriorOffset + i];
            NATIVE_VIEW_ENTRY *pEntry =
                TransactionViewFindHnum(pView, dwHnum);
            if(!pEntry)
            {
                dwError = ERROR_TDNF_INVALID_PARAMETER;
                BAIL_ON_TDNF_ERROR(dwError);
            }
            if(!pEntry->nRemoved)
            {
                pEntry->nRemoved = 1;
                pEntry->qwRemovalOrder = qwRemovalOrder++;
            }
        }
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static uint32_t
CollectTransactionRemovedPaths(
    NATIVE_TRANSACTION_VIEW *pView,
    NATIVE_PATH_LIST *pRemovedPaths
    )
{
    uint32_t dwError = 0;
    size_t nRemovedCount = 0;
    size_t nOrder = 0;
    size_t i = 0;

    if(!pView || !pRemovedPaths)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(i = 0; i < pView->nCount; i++)
    {
        if(pView->pEntries[i].nRemoved)
        {
            nRemovedCount++;
        }
    }
    for(nOrder = 0; nOrder < nRemovedCount; nOrder++)
    {
        NATIVE_VIEW_ENTRY *pEntry = NULL;
        for(i = 0; i < pView->nCount; i++)
        {
            if(pView->pEntries[i].nRemoved &&
               pView->pEntries[i].qwRemovalOrder == nOrder)
            {
                pEntry = &pView->pEntries[i];
                break;
            }
        }
        if(!pEntry)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        dwError = CollectHeaderTriggerPaths(
                      pEntry->pbBlob,
                      pEntry->nBlobLen,
                      0,
                      NULL,
                      pRemovedPaths);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
TDNFRunTransactionNative(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;
    PTDNF_RPM_TS_ITEM pItem = NULL;
    const char *pszInstallRoot = NULL;
    uint32_t dwTransFlags = 0;
    uint32_t dwInstallTid = 0;
    uint32_t dwInstallTime = 0;
    int nScriptFd = -1;
    int nRedirectToStderr = 0;
    PTDNF_RPM_TS_ITEM *ppInputItems = NULL;
    PTDNF_RPM_TS_ITEM pInputItem = NULL;
    uint32_t dwInputIndex = 0;
    NATIVE_TRANSACTION_VIEW transaction_view;
    NATIVE_PATH_LIST transaction_added_paths;
    NATIVE_PATH_LIST transaction_removed_paths;
    NATIVE_POSTUN_QUEUE postun_queue;
    uint32_t *pdwRemovedHnums = NULL;
    size_t nRemovedHnumCount = 0;
    size_t nRemovedHnumCapacity = 0;

    memset(&transaction_view, 0, sizeof(transaction_view));
    memset(&transaction_added_paths, 0, sizeof(transaction_added_paths));
    memset(&transaction_removed_paths, 0, sizeof(transaction_removed_paths));
    memset(&postun_queue, 0, sizeof(postun_queue));
    if (!pTS || !pTdnf || !pTdnf->pArgs || !pTdnf->pConf ||
        !pTdnf->pRpmConfig || !pPlan)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if (pPlan->dwItemCount != pTS->dwTransactionItemCount ||
        (pPlan->dwPriorHnumCount && !pPlan->pdwPriorHnums))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pszInstallRoot = GetInstallRoot(pTdnf);
    dwTransFlags = EffectiveTransFlags(pTS, pTdnf);
    dwInstallTid = (uint32_t)time(NULL);
    dwInstallTime = dwInstallTid;

    if(pPlan->dwItemCount)
    {
        dwError = TDNFAllocateMemory(
                      pPlan->dwItemCount,
                      sizeof(*ppInputItems),
                      (void **)&ppInputItems);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(pInputItem = pTS->pTransactionItems;
        pInputItem;
        pInputItem = pInputItem->pNext)
    {
        if(dwInputIndex >= pPlan->dwItemCount)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        ppInputItems[dwInputIndex++] = pInputItem;
    }
    if(dwInputIndex != pPlan->dwItemCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(pPlan->dwPriorHnumCount >
       SIZE_MAX - pPlan->dwItemCount)
    {
        dwError = ERROR_TDNF_OVERFLOW;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    nRemovedHnumCapacity =
        pPlan->dwPriorHnumCount + pPlan->dwItemCount;
    if(nRemovedHnumCapacity)
    {
        dwError = TDNFAllocateMemory(
                      nRemovedHnumCapacity,
                      sizeof(*pdwRemovedHnums),
                      (void **)&pdwRemovedHnums);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(dwIndex = 0; dwIndex < pPlan->dwPriorHnumCount; dwIndex++)
    {
        dwError = AppendUniqueHnum(
                      pdwRemovedHnums,
                      nRemovedHnumCapacity,
                      &nRemovedHnumCount,
                      pPlan->pdwPriorHnums[dwIndex]);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    for(dwIndex = 0; dwIndex < pPlan->dwItemCount; dwIndex++)
    {
        pItem = ppInputItems[dwIndex];
        if(pItem && pItem->nType == TDNF_RPM_TS_ITEM_ERASE)
        {
            dwError = AppendUniqueHnum(
                          pdwRemovedHnums,
                          nRemovedHnumCapacity,
                          &nRemovedHnumCount,
                          pItem->dwRpmDbHnum);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    dwError = TransactionViewInit(
                  &transaction_view,
                  pTdnf->pRpmConfig,
                  pPlan->dwItemCount);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = PrevalidatePlan(
                  pTS,
                  pPlan,
                  ppInputItems,
                  &transaction_view,
                  pTdnf->pRpmConfig);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = MarkRemovedViewEntries(
                  pPlan,
                  ppInputItems,
                  &transaction_view);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = CollectTransactionRemovedPaths(
                  &transaction_view,
                  &transaction_removed_paths);
    BAIL_ON_TDNF_ERROR(dwError);

    /*
     * When JSON output is enabled, redirect scriptlet stdout to
     * stderr so the JSON stream on stdout stays clean.
     */
    if (pTdnf->pArgs->nJsonOutput)
    {
        nScriptFd = dup(STDERR_FILENO);
        if (nScriptFd < 0)
        {
            dwError = ERROR_TDNF_RPMTS_FDDUP_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        nRedirectToStderr = 1;
    }

    if(!pTS->nQuiet)
    {
        pr_info("Running transaction (rpmzig native executor)\n");
    }

    dwError = RunTransPhase(pPlan,
                            ppInputItems,
                            &transaction_view,
                            pTdnf->pRpmConfig,
                            TDNF_RPM_SCRIPTLET_PHASE_PRETRANS, "%pretrans",
                            pszInstallRoot, dwTransFlags,
                            nScriptFd, nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunStableTransactionFileTriggers(
                  &transaction_view,
                  &transaction_removed_paths,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERUN,
                  "%transfiletriggerun",
                  pszInstallRoot,
                  pTdnf->pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunRemovedImmediateTransactionFileTriggers(
                  &transaction_view,
                  pszInstallRoot,
                  pTdnf->pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    /* Per-item main phase */
    for (dwIndex = 0; dwIndex < pPlan->dwItemCount; dwIndex++)
    {
        dwInputIndex = pPlan->pdwOrderIndices[dwIndex];
        if(dwInputIndex >= pPlan->dwItemCount)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        pItem = ppInputItems[dwInputIndex];
        if(!pItem)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        switch (pItem->nType)
        {
            case TDNF_RPM_TS_ITEM_INSTALL:
            case TDNF_RPM_TS_ITEM_UPGRADE:
            case TDNF_RPM_TS_ITEM_REINSTALL:
                dwError = ProcessInstallItem(pTS, pTdnf,
                                             pPlan, dwInputIndex,
                                             &transaction_view,
                                             pdwRemovedHnums,
                                             nRemovedHnumCount,
                                             &transaction_added_paths,
                                             &postun_queue,
                                             pItem,
                                             dwTransFlags,
                                             dwInstallTid, dwInstallTime,
                                             pszInstallRoot,
                                             nScriptFd, nRedirectToStderr);
                BAIL_ON_TDNF_ERROR(dwError);
                break;

            case TDNF_RPM_TS_ITEM_ERASE:
                dwError = ProcessEraseItem(pTS, pTdnf,
                                           &transaction_view,
                                           &postun_queue,
                                           pItem,
                                           dwTransFlags, pszInstallRoot,
                                           nScriptFd, nRedirectToStderr);
                BAIL_ON_TDNF_ERROR(dwError);
                break;

            default:
                pr_err("rpmzig-transaction-execute: unknown item type %d\n",
                       pItem->nType);
                dwError = ERROR_TDNF_INVALID_PARAMETER;
                BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    dwError = RunTransPhase(pPlan,
                            ppInputItems,
                            &transaction_view,
                            pTdnf->pRpmConfig,
                            TDNF_RPM_SCRIPTLET_PHASE_POSTTRANS, "%posttrans",
                            pszInstallRoot, dwTransFlags,
                            nScriptFd, nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    /*
     * rpm runs transaction-file triggers already present before this
     * transaction first, then queued post-uninstall triggers, and finally
     * transaction-file triggers from packages added by this transaction.
     */
    dwError = RunStableTransactionFileTriggers(
                  &transaction_view,
                  &transaction_added_paths,
                  TDNF_RPM_TRIGGER_PHASE_TRIGGERIN,
                  "%transfiletriggerin",
                  pszInstallRoot,
                  pTdnf->pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunScheduledPostunTransactionFileTriggers(
                  &postun_queue,
                  &transaction_view,
                  pszInstallRoot,
                  pTdnf->pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = RunAddedImmediateTransactionFileTriggers(
                  &transaction_view,
                  pszInstallRoot,
                  pTdnf->pRpmConfig,
                  dwTransFlags,
                  nScriptFd,
                  nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    if (nScriptFd >= 0)
    {
        close(nScriptFd);
    }
    PostunQueueCleanup(&postun_queue);
    PathListCleanup(&transaction_removed_paths);
    PathListCleanup(&transaction_added_paths);
    TransactionViewCleanup(&transaction_view);
    TDNF_SAFE_FREE_MEMORY(pdwRemovedHnums);
    TDNF_SAFE_FREE_MEMORY(ppInputItems);
    return dwError;

error:
    goto cleanup;
}
