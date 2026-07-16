/*
 * Copyright (C) 2015-2022 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"
#include "../llconf/nodes.h"

uint32_t
TDNFUpdateInfoSummary(
    PTDNF pTdnf,
    char** ppszPackageNameSpecs,
    PTDNF_UPDATEINFO_SUMMARY* ppSummary
    )
{
    uint32_t dwError = 0;
    PTDNF_UPDATEINFO_SUMMARY pSummary = NULL;
    char *pszSeverity = NULL;
    uint32_t dwSecurity = 0;
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos = NULL;
    uint32_t dwRepoCount = 0;
    char **ppszLines = NULL;
    uint32_t dwLineCount = 0;

    if(!pTdnf || !pTdnf->pSack || !pTdnf->pSack->pPool ||
       !ppSummary)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFRefresh(pTdnf);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFGetSecuritySeverityOption(
                  pTdnf,
                  &dwSecurity,
                  &pszSeverity);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFNativeQueryBuildRepoInputs(pTdnf, &pRepos, &dwRepoCount);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFRepoMdNativeUpdateInfoSummaryLinesConfig(
                  pRepos,
                  dwRepoCount,
                  pTdnf->pRpmConfig,
                  ppszPackageNameSpecs,
                  dwSecurity,
                  pszSeverity,
                  &ppszLines,
                  &dwLineCount);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFNativeQueryBuildUpdateInfoSummary(ppszLines, dwLineCount, &pSummary);
    BAIL_ON_TDNF_ERROR(dwError);

    *ppSummary = pSummary;

cleanup:
    TDNFFreeStringArray(ppszLines);
    TDNFNativeQueryFreeRepoInputs(pRepos, dwRepoCount);
    TDNF_SAFE_FREE_MEMORY(pszSeverity);
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
TDNFGetSecuritySeverityOption(
    PTDNF pTdnf,
    uint32_t *pdwSecurity,
    char **ppszSeverity
    )
{
    uint32_t dwError = 0;
    struct cnfnode *cn = NULL;
    uint32_t dwSecurity = 0;
    char* pszSeverity = NULL;

    if(!pTdnf || !pTdnf->pArgs)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for (cn = pTdnf->pArgs->cn_setopts->first_child; cn; cn = cn->next) {
        if(strcasecmp(cn->name, "sec-severity") == 0) {
            dwError = TDNFAllocateString(cn->value, &pszSeverity);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        if(strcasecmp(cn->name, "security") == 0) {
            dwSecurity = 1;
        }
    }

    *pdwSecurity = dwSecurity;
    *ppszSeverity = pszSeverity;
cleanup:
    return dwError;

error:
    TDNF_SAFE_FREE_MEMORY(pszSeverity);
    if(ppszSeverity)
    {
        *ppszSeverity = NULL;
    }
    if(pdwSecurity)
    {
        *pdwSecurity = 0;
    }
    goto cleanup;
}

uint32_t
TDNFNumUpdatePkgs(
    PTDNF_UPDATEINFO pInfo,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    PTDNF_UPDATEINFO_PKG pPkg = NULL;
    if(!pInfo || !pdwCount)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    while(pInfo)
    {
        pPkg = pInfo->pPackages;
        while(pPkg)
        {
            dwCount++;
            pPkg = pPkg->pNext;
        }
        pInfo = pInfo->pNext;
    }
    *pdwCount = dwCount;
cleanup:
    return dwError;

error:
    if(pdwCount)
    {
        *pdwCount = 0;
    }
    goto cleanup;
}

uint32_t
TDNFGetUpdatePkgs(
    PTDNF pTdnf,
    char*** pppszPkgs,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    char**   ppszPkgs = NULL;
    PTDNF_UPDATEINFO_PKG pPkg = NULL;
    int nIndex = 0;
    char* pszPkgName = NULL;

    PTDNF_UPDATEINFO pUpdateInfo = NULL;
    PTDNF_UPDATEINFO pInfo = NULL;

    if(!pTdnf || !pdwCount || !pppszPkgs)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFUpdateInfo(pTdnf, &pszPkgName, &pUpdateInfo);
    BAIL_ON_TDNF_ERROR(dwError);

    pInfo = pUpdateInfo;
    dwError = TDNFNumUpdatePkgs(pInfo, &dwCount);
    BAIL_ON_TDNF_ERROR(dwError);

    if(dwCount == 0)
    {
        goto cleanup;
    }

    dwError = TDNFAllocateMemory(
                  dwCount + 1,
                  sizeof(char*),
                  (void**)&ppszPkgs);
    BAIL_ON_TDNF_ERROR(dwError);

    for(pInfo = pUpdateInfo; pInfo; pInfo = pInfo->pNext)
    {
        pPkg = pInfo->pPackages;
        while(pPkg)
        {
            dwError = TDNFAllocateString(
                          pPkg->pszName,
                          &ppszPkgs[nIndex++]);
            BAIL_ON_TDNF_ERROR(dwError);
            pPkg = pPkg->pNext;
        }

    }
    *pppszPkgs = ppszPkgs;
    *pdwCount  = dwCount;
cleanup:
    if(pUpdateInfo)
    {
        TDNFFreeUpdateInfo(pUpdateInfo);
    }
    return dwError;

error:
    if(pppszPkgs)
    {
        *pppszPkgs = NULL;
    }
    if(ppszPkgs)
    {
        TDNFFreeStringArray(ppszPkgs);
    }
    goto cleanup;
}

uint32_t
TDNFGetRebootRequiredOption(
    PTDNF pTdnf,
    uint32_t *pdwRebootRequired
    )
{
    uint32_t dwError = 0;
    struct cnfnode *cn = NULL;
    uint32_t dwRebootRequired = 0;

    if(!pTdnf || !pTdnf->pArgs)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for (cn = pTdnf->pArgs->cn_setopts->first_child; cn; cn = cn->next) {
        if(strcasecmp(cn->name, "reboot-required") == 0) {
            dwRebootRequired = 1;
            break;
        }
    }
    *pdwRebootRequired = dwRebootRequired;
cleanup:
    return dwError;

error:
    if(pdwRebootRequired)
    {
       *pdwRebootRequired = 0;
    }
    goto cleanup;
}
