/*
 * Copyright (C) 2025 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*TDNF_ZIG_XFERINFOFUNCTION)(
    void* pUserData,
    int64_t nDownloadTotal,
    int64_t nDownloadedNow,
    int64_t nUploadTotal,
    int64_t nUploadedNow
    );

typedef struct _TDNF_ZIG_DOWNLOAD_REQUEST
{
    const char* pszUrl;
    const char* pszDestination;
    TDNF_ZIG_XFERINFOFUNCTION pfnProgress;
    void* pProgressData;
    const char* pszUserAgent;
    const char* pszProxy;
    const char* pszProxyUserPwd;
    const char* pszUserName;
    const char* pszPassword;
    const char* pszSSLCaCert;
    const char* pszSSLClientCert;
    const char* pszSSLClientKey;
    int nSSLVerify;
    long nConnectTimeout;
    long nTimeout;
    long nLowSpeedLimit;
    long nLowSpeedTime;
    long nMaxRecvSpeed;
} TDNF_ZIG_DOWNLOAD_REQUEST;

uint32_t
TDNFZigDownloadFile(
    const TDNF_ZIG_DOWNLOAD_REQUEST* pRequest,
    long* pnResponseCode
    );

const char*
TDNFZigDownloadLastError(
    void
    );

#ifdef __cplusplus
}
#endif
