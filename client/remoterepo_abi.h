/*
 * Copyright (C) 2015-2026 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * are located in the COPYING file of this distribution.
 */

#pragma once

#include <stdint.h>

#include <tdnftypes.h>

uint32_t
TDNFDownloadFileFromRepo(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char *pszLocation,
    const char *pszFile,
    const char *pszProgressData
    );

uint32_t
TDNFDownloadFile(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char *pszFileUrl,
    const char *pszFile,
    const char *pszProgressData
    );

uint32_t
TDNFCreatePackageUrl(
    PTDNF_REPO_DATA pRepo,
    const char *pszPackageLocation,
    char **ppszPackageUrl
    );

uint32_t
TDNFDownloadPackageToCache(
    PTDNF pTdnf,
    const char *pszPackageLocation,
    const char *pszPkgName,
    PTDNF_REPO_DATA pRepo,
    char **ppszFilePath
    );

uint32_t
TDNFDownloadPackageToTree(
    PTDNF pTdnf,
    const char *pszPackageLocation,
    const char *pszPkgName,
    PTDNF_REPO_DATA pRepo,
    char *pszNormalRpmCacheDir,
    char **ppszFilePath
    );

uint32_t
TDNFDownloadPackageToDirectory(
    PTDNF pTdnf,
    const char *pszPackageLocation,
    const char *pszPkgName,
    PTDNF_REPO_DATA pRepo,
    const char *pszDirectory,
    char **ppszFilePath
    );
