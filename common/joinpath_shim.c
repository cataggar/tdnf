/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

uint32_t
TDNFJoinPathFromArray(
    char **ppszPath,
    char **ppszNodes,
    int nCount
    );

uint32_t
TDNFJoinPath(
    char **ppszPath,
    ...
    )
{
    uint32_t dwError = 0;
    va_list ap;
    char *pszNode = NULL;
    int i = 0, nCount = 0;
    char **ppszNodes = NULL;

    if (!ppszPath)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        goto cleanup;
    }

    va_start(ap, ppszPath);
    for (pszNode = va_arg(ap, char *); pszNode; pszNode = va_arg(ap, char *))
    {
        nCount++;
    }
    va_end(ap);

    dwError = TDNFAllocateMemory(nCount + 1, sizeof(char *), (void **)&ppszNodes);
    BAIL_ON_TDNF_ERROR(dwError);

    va_start(ap, ppszPath);
    for (pszNode = va_arg(ap, char *), i = 0; pszNode; pszNode = va_arg(ap, char *), i++)
    {
        ppszNodes[i] = pszNode;
    }
    va_end(ap);

    dwError = TDNFJoinPathFromArray(ppszPath, ppszNodes, nCount);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(ppszNodes);
    return dwError;

error:
    if (ppszPath)
    {
        *ppszPath = NULL;
    }
    goto cleanup;
}
