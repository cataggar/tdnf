/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

/*
 * va_list cannot be passed across the Zig export-fn (C ABI) boundary
 * portably: on x86_64 SysV, va_list is an array-of-1-struct type that
 * decays to a pointer at C call sites, but Zig's translate-c does not
 * apply that same array-to-pointer parameter adjustment for `export fn`,
 * so a Zig function declared to accept `va_list` directly fails to
 * compile for the x86_64_sysv calling convention (it compiles fine on
 * aarch64, where va_list is a plain struct, which is what let this slip
 * through arm64-only testing previously). To stay portable, the entire
 * vsnprintf() probe-then-format sequence stays in C here, and only the
 * already-portable, non-variadic TDNFAllocateMemory/TDNFFreeMemory (Zig)
 * entry points are used for the actual buffer allocation.
 */
uint32_t
TDNFAllocateStringPrintf(
    char **ppszDst,
    const char *pszFmt,
    ...
    )
{
    uint32_t dwError = 0;
    va_list argList;
    va_list argListWrite;
    char chDstTest = 0;
    int nSizeProbe = 0;
    int nWritten = 0;
    size_t nSize = 0;
    char *pszDst = NULL;

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
    va_copy(argListWrite, argList);

    nSizeProbe = vsnprintf(&chDstTest, 1, pszFmt, argList);
    va_end(argList);
    if (nSizeProbe <= 0)
    {
        va_end(argListWrite);
        *ppszDst = NULL;
        dwError = ERROR_TDNF_SYSTEM_BASE + errno;
        goto cleanup;
    }

    nSize = (size_t)nSizeProbe + 1;
    if (nSize > TDNF_DEFAULT_MAX_STRING_LEN)
    {
        va_end(argListWrite);
        *ppszDst = NULL;
        dwError = ERROR_TDNF_STRING_TOO_LONG;
        goto cleanup;
    }

    dwError = TDNFAllocateMemory(1, nSize, (void **)&pszDst);
    if (dwError)
    {
        va_end(argListWrite);
        *ppszDst = NULL;
        goto cleanup;
    }

    nWritten = vsnprintf(pszDst, nSize, pszFmt, argListWrite);
    va_end(argListWrite);
    if (nWritten <= 0)
    {
        TDNFFreeMemory(pszDst);
        *ppszDst = NULL;
        dwError = ERROR_TDNF_SYSTEM_BASE + errno;
        goto cleanup;
    }

    *ppszDst = pszDst;

cleanup:
    return dwError;
}
