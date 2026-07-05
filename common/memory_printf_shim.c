/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

extern uint32_t
TDNFAllocateStringVPrintf(
    char **ppszDst,
    const char *pszFmt,
    va_list argListSize,
    va_list argListWrite
    );

uint32_t
TDNFAllocateStringPrintf(
    char **ppszDst,
    const char *pszFmt,
    ...
    )
{
    uint32_t dwError = 0;
    va_list argList;
    va_list argListSize;
    va_list argListWrite;

    if (!ppszDst || !pszFmt)
    {
        if (ppszDst)
        {
            *ppszDst = NULL;
        }
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        goto cleanup;
    }

    va_start(argList, pszFmt);
    va_copy(argListSize, argList);
    va_copy(argListWrite, argList);
    dwError = TDNFAllocateStringVPrintf(
                  ppszDst,
                  pszFmt,
                  argListSize,
                  argListWrite);
    va_end(argListWrite);
    va_end(argListSize);
    va_end(argList);

cleanup:
    return dwError;
}
