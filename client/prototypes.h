/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#ifndef __CLIENT_PROTOTYPES_H__
#define __CLIENT_PROTOTYPES_H__

#include <unistd.h>

extern uid_t gEuid;
struct cnfnode;

uint32_t
tdnf_repomd_native_verified_transaction_solve_config(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2 *pItems,
    const unsigned char *const *ppbHeaders,
    const size_t *pnHeaderLengths,
    const uint64_t *pqwPackageSizes,
    uint32_t dwItemCount,
    const tdnf_rpm_config *pConfig,
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN **ppPlan
    );

//querynative.c
uint32_t
TDNFNativeQueryBuildRepoInputs(
    PTDNF pTdnf,
    PTDNF_REPOMD_NATIVE_REPO_INPUT *ppRepos,
    uint32_t *pdwRepoCount
    );

uint32_t
TDNFNativeQueryBuildSingleRepoInput(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepoData,
    TDNF_REPOMD_NATIVE_REPO_INPUT *pRepo
    );

void
TDNFNativeQueryFreeRepoInputs(
    PTDNF_REPOMD_NATIVE_REPO_INPUT pRepos,
    uint32_t dwRepoCount
    );

const char*
TDNFNativeQueryInstallRoot(
    PTDNF pTdnf
    );

uint32_t
TDNFNativeQueryFilterUserInstalled(
    PTDNF pTdnf,
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t *pdwCount
    );

uint32_t
TDNFNativeQueryApplyLocationUrls(
    PTDNF pTdnf,
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount
    );

uint32_t
TDNFNativeQueryInstalledPkgIds(
    PTDNF_PACKAGE_CONTEXT pSack,
    PTDNF_ID_LIST pQueue
    );

uint32_t
TDNFNativeQuerySerializePackageId(
    PTDNF_PACKAGE_CONTEXT pSack,
    TDNF_PKG_ID dwPkgId,
    char **ppszLine
    );

uint32_t
TDNFNativeQuerySerializeQueuePackageRefs(
    PTDNF_PACKAGE_CONTEXT pSack,
    PTDNF_ID_LIST pQueue,
    char ***pppszRefs,
    uint32_t *pdwCount
    );

uint32_t
TDNFNativeQuerySerializePackageInfoRefs(
    PTDNF_PKG_INFO pPkgInfos,
    uint32_t dwCount,
    char ***pppszRefs,
    uint32_t *pdwCount
    );

uint32_t
TDNFNativeQuerySerializeAutoInstalledRefs(
    PTDNF pTdnf,
    struct history_ctx *pHistoryCtx,
    char ***pppszRefs,
    uint32_t *pdwCount
    );

uint32_t
TDNFNativeQueryResolvePackageRefArrayToQueue(
    PTDNF_PACKAGE_CONTEXT pSack,
    char **ppszPackageRefs,
    uint32_t dwCount,
    int nInstalledOnly,
    PTDNF_ID_LIST pQueue
    );

uint32_t
TDNFNativeQueryResolveSinglePackageRef(
    PTDNF_PACKAGE_CONTEXT pSack,
    const char *pszPackageRef,
    int nInstalledOnly,
    TDNF_PKG_ID *pdwPkgId
    );

uint32_t
TDNFNativeQuerySplitPackageRef(
    const char *pszRef,
    char **ppszRepo,
    uint32_t *pdwEpoch,
    char **ppszName,
    char **ppszVersion,
    char **ppszRelease,
    char **ppszArch
    );

uint32_t
TDNFNativeQueryBuildUpdateInfoSummary(
    char **ppszLines,
    uint32_t dwCount,
    PTDNF_UPDATEINFO_SUMMARY *ppSummary
    );

uint32_t
TDNFNativeQueryBuildUpdateInfo(
    char **ppszLines,
    uint32_t dwCount,
    PTDNF_UPDATEINFO *ppInfo
    );

//gpgcheck.c
uint32_t
ReadGPGKeyFile(
    const char* pszFile,
    char** ppszKeyData,
    int* pnSize
   );




uint32_t
TDNFGPGCheckPackageEx(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszFilePath,
    tdnf_rpm_file **ppRpmFile,
    int *pnPolicyRejected
    );

uint32_t
TDNFGPGCheckPackageWithFile(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszFilePath,
    tdnf_rpm_file *pRpmFile,
    int *pnPolicyRejected
    );

uint32_t
TDNFFetchRemoteGPGKey(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char* pszUrlGPGKey,
    char** ppszKeyLocation
    );

uint32_t
TDNFRefreshSack(
    PTDNF pTdnf,
    PTDNF_PACKAGE_CONTEXT pSack,
    int nCleanMetadata
    );

void
TDNFFreeHistoryInfoItems(
    PTDNF_HISTORY_INFO_ITEM pHistoryItems,
    int nCount
);

//packageutils.c

uint32_t
TDNFAddPackagesForInstall(
    PTDNF_PACKAGE_CONTEXT pSack,
    PTDNF_ID_LIST pQueueGoal,
    const char* pszPkgName,
    int nSource,
    int nInstallOnly
    );

uint32_t
TDNFMatchForReinstall(
    PTDNF_PACKAGE_CONTEXT pSack,
    const char* pszName,
    PTDNF_ID_LIST pQueueGoal
    );

uint32_t
TDNFPopulatePkgInfosFromRefs(
    PTDNF_PACKAGE_CONTEXT pSack,
    char **ppszPackageRefs,
    uint32_t dwRefCount,
    PTDNF_PKG_INFO* ppPkgInfo
    );

uint32_t
TDNFPkgInfoFilterNewest(
    PTDNF_PACKAGE_CONTEXT pSack,
    PTDNF_PKG_INFO pPkgInfos
);





uint32_t
TDNFAddPackagesForErase(
    PTDNF_PACKAGE_CONTEXT pSack,
    PTDNF_ID_LIST pQueueGoal,
    const char* pszPkgName
    );

uint32_t
TDNFAddPackagesForUpgrade(
    PTDNF_PACKAGE_CONTEXT pSack,
    PTDNF_ID_LIST pQueueGoal,
    const char* pszPkgName
    );



uint32_t
TDNFAddPackagesForDowngrade(
    PTDNF pTdnf,
    PTDNF_PACKAGE_CONTEXT pSack,
    PTDNF_ID_LIST pQueueGoal,
    const char* pszPkgName
    );

uint32_t
TDNFGetAvailableCacheBytes(
    PTDNF_CONF pConf,
    uint64_t* pqwAvailCacheBytes
    );

uint32_t
TDNFCheckDownloadCacheBytes(
    PTDNF_SOLVED_PKG_INFO pSolvedPkgInfo,
    uint64_t qwAvailCacheBytes
    );


//goal.c
uint32_t
TDNFGoal(
    PTDNF pTdnf,
    PTDNF_ID_LIST pkgList,
    PTDNF_SOLVED_PKG_INFO* ppInfo,
    TDNF_ALTERTYPE nAlterType, int nUnresolved
    );

uint32_t
TDNFGoalNoDeps(
    PTDNF pTdnf,
    PTDNF_ID_LIST pQueuePkgList,
    PTDNF_SOLVED_PKG_INFO* ppInfo
    );

uint32_t
TDNFHistoryGoal(
    PTDNF pTdnf,
    PTDNF_ID_LIST pqInstall,
    PTDNF_ID_LIST pqErase,
    PTDNF_SOLVED_PKG_INFO* ppInfo
    );

TDNF_TRANSACTION_PLAN_CAPTURE_HIDDEN uint32_t
TDNFSolv(
    PTDNF pTdnf,
    PTDNF_ID_LIST pQueueJobs,
    char **ppszExcludes,
    uint32_t dwExcludeCount,
    int nAllowErasing,
    int nAutoErase,
    int nReInstall,
    int nUnresolved,
    PTDNF_SOLVED_PKG_INFO *ppInfo
    );

uint32_t
TDNFAddUserInstall(
    PTDNF pTdnf,
    const TDNF_ID_LIST *pQueueGoal,
    PTDNF_SOLVED_PKG_INFO ppInfo
    );

uint32_t
TDNFMarkAutoInstalledSinglePkg(
    PTDNF pTdnf,
    const char *pszPkgName
);

uint32_t
TDNFMarkAutoInstalled(
    PTDNF pTdnf,
    struct history_ctx *pHistoryCtx,
    PTDNF_SOLVED_PKG_INFO ppInfo,
    int nAutoOnly
    );

uint32_t
TDNFAddGoal(
    PTDNF pTdnf,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_ID_LIST pQueueJobs,
    TDNF_PKG_ID dwId,
    uint32_t dwCount,
    char** ppszExcludes
    );


uint32_t
TDNFPkgsToExclude(
    PTDNF pTdnf,
    uint32_t *pdwPkgsToExclude,
    char***  pppszExclude
    );



uint32_t
TDNFGoalAddHiddenPackages(
    PTDNF pTdnf,
    char **ppszExcludes
    );


TDNF_TRANSACTION_PLAN_REQUEST_TRACE *
TDNFTransactionPlanRequestTraceCreate(
    uint32_t alter_type,
    const char *const *subjects,
    uint32_t subject_count
    );

TDNF_TRANSACTION_PLAN_REQUEST_TRACE *
TDNFTransactionPlanRequestTraceCreateHistory(void);

void
TDNFTransactionPlanRequestTraceDestroy(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace
    );

void
TDNFTransactionPlanRequestTraceRecordGoalRange(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    const int32_t *ids,
    uint32_t start,
    uint32_t end,
    uint32_t alter_type,
    uint32_t reason,
    uint32_t request_ref
    );

void
TDNFTransactionPlanRequestTraceRecordHistoryGoal(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    const char *subject,
    uint32_t request_kind,
    uint32_t action,
    const int32_t *ids,
    uint32_t start,
    uint32_t end,
    uint32_t outcome
    );

void
TDNFTransactionPlanRequestTraceRecordRequestOutcome(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    uint32_t request_ref,
    uint32_t outcome
    );

void
TDNFTransactionPlanRequestTraceCommitGoal(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    int32_t selection_id,
    uint32_t alter_type,
    const int32_t *queue,
    uint32_t start,
    uint32_t end
    );

void
TDNFTransactionPlanRequestTraceRecordPackageJob(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    uint32_t queue_pair_index,
    uint32_t action,
    int32_t selection_id,
    int32_t raw_how,
    uint32_t raw_flags,
    uint32_t reason,
    uint32_t request_ref
    );

void
TDNFTransactionPlanRequestTraceRecordPackageJobRange(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    const int32_t *queue,
    uint32_t start,
    uint32_t end,
    uint32_t action,
    uint32_t reason,
    uint32_t request_ref
    );

void
TDNFTransactionPlanRequestTraceRecordNameJob(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    uint32_t queue_pair_index,
    uint32_t action,
    const char *selection_name,
    int32_t raw_how,
    uint32_t raw_flags,
    uint32_t reason,
    uint32_t request_ref
    );

void
TDNFTransactionPlanRequestTraceRecordAllJob(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    uint32_t queue_pair_index,
    uint32_t action,
    int32_t raw_how,
    uint32_t raw_flags,
    uint32_t reason,
    uint32_t request_ref
    );

void
TDNFTransactionPlanRequestTraceRecordCapabilityJob(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    uint32_t queue_pair_index,
    uint32_t action,
    const TDNF_TRANSACTION_PLAN_CAPTURE_CAPABILITY *capability,
    int32_t raw_how,
    uint32_t raw_flags,
    uint32_t reason,
    uint32_t request_ref
    );

void
TDNFTransactionPlanRequestTraceRecordPolicies(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    const char *const *excludes,
    const char *const *installonly_names,
    const char *const *locked_names,
    const char *const *min_versions,
    const char *const *protected_names,
    uint32_t allow_erasing
    );

void
TDNFTransactionPlanRequestTraceFinalize(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    const int32_t *queue,
    uint32_t element_count,
    int32_t clean_deps_mask,
    int32_t force_best_mask
    );

const TDNF_TRANSACTION_PLAN_REQUEST_TRACE_VIEW *
TDNFTransactionPlanRequestTraceGetView(
    const TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace
    );

uint32_t
TDNFTransactionPlanRequestTraceCaptureFactsCreate(
    const TDNF_TRANSACTION_PLAN_REQUEST_TRACE *trace,
    const TDNF_TRANSACTION_PLAN_REQUEST_TRACE_PACKAGE_REF *package_refs,
    uint32_t package_ref_count,
    const TDNF_TRANSACTION_PLAN_REQUEST_TRACE_CAPTURE_FACTS **facts,
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE_CAPTURE_OWNER **owner
    );

void
TDNFTransactionPlanRequestTraceCaptureFactsDestroy(
    TDNF_TRANSACTION_PLAN_REQUEST_TRACE_CAPTURE_OWNER *owner
    );


uint32_t
TDNFReadConfig(
    PTDNF pTdnf,
    const char* pszConfFile,
    const char* pszConfGroup
    );

uint32_t
TDNFConfigExpandVars(
    PTDNF pTdnf
    );

uint32_t
TDNFConfigReadProxySettings(
    PCONF_SECTION pSection,
    PTDNF_CONF pConf);

void
TDNFFreeConfig(
    PTDNF_CONF pConf
    );

uint32_t
TDNFConfigReplaceVars(
    PTDNF pTdnf,
    char** pszString
    );


//repo.c

uint32_t
TDNFInitRepo(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepoData,
    PTDNF_PACKAGE_CONTEXT pSack
    );

uint32_t
TDNFGetGPGKeys(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    char*** pppszUrlGPGKeys
    );

uint32_t
TDNFGetRepoMD(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepoData,
    const char *pszRepoDataDir,
    PTDNF_REPO_METADATA *ppRepoMD
    );



void
TDNFFreeRepoMetadata(
    PTDNF_REPO_METADATA pRepoMD
    );



uint32_t
TDNFDownloadMetadata(
    PTDNF pTdnf,
    PTDNF_REPO_DATA pRepo,
    const char *pszRepoDir,
    int nPrintOnly
    );


//repolist.c

uint32_t
TDNFLoadRepoData(
    PTDNF pTdnf,
    PTDNF_REPO_DATA* ppReposAll
    );

uint32_t
TDNFRepoListFinalize(
    PTDNF pTdnf
    );


uint32_t
TDNFCloneRepo(
    PTDNF_REPO_DATA pRepoIn,
    PTDNF_REPO_DATA* ppRepo
    );

void
TDNFFreeReposInternal(
    PTDNF_REPO_DATA pRepos
    );

//resolve.c
uint32_t
TDNFPrepareAllPackages(
    PTDNF pTdnf,
    TDNF_ALTERTYPE* pAlterType,
    char** ppszPkgsNotResolved,
    PTDNF_ID_LIST pQueueGoal
    );


uint32_t
TDNFAddNotResolved(
    char** ppszPkgsNotResolved,
    const char* pszPkgName
    );

uint32_t
TDNFResolveBuildDependencies(
    PTDNF pTdnf,
    char **ppszPackageNameSpecs,
    char **ppszPkgsNotResolved,
    PTDNF_ID_LIST queueGoal
    );

//rpmtrans.c
uint32_t
TDNFRpmExecTransaction(
    PTDNF pTdnf,
    PTDNF_SOLVED_PKG_INFO pInfo
    );

uint32_t
TDNFRpmExecHistoryTransaction(
    PTDNF pTdnf,
    PTDNF_SOLVED_PKG_INFO pSolvedInfo,
    PTDNF_HISTORY_ARGS pHistoryArgs
    );










//updateinfo.zig
uint32_t
TDNFGetSecuritySeverityOption(
    PTDNF pTdnf,
    uint32_t *pdwSecurity,
    char **ppszSeverity
    );


uint32_t
TDNFGetUpdatePkgs(
    PTDNF pTdnf,
    char*** pppszPkgs,
    uint32_t *pdwCount
    );

uint32_t
TDNFGetRebootRequiredOption(
    PTDNF pTdnf,
    uint32_t *pdwRebootRequired
    );

//utils.c


uint32_t
TDNFIsFileOrSymlink(
    const char* pszPath,
    int* pnPathIsFile
    );

uint32_t
TDNFGetFileSize(
    const char* pszPath,
    int *pnSize
    );

int
TDNFIsGlob(
    const char* pszString
    );

uint32_t
TDNFUtilsMakeDir(
    const char* pszPath
    );

uint32_t
TDNFGetReleaseVersion(
   const char* pszRootDir,
   const char* pszDistroVerPkg,
   char** ppszVersion
   );

uint32_t
TdnfGetReleaseVersionConfig(
   const tdnf_rpm_config* pRpmConfig,
   const char* pszDistroVerPkg,
   char** ppszVersion
   );

uint32_t
TDNFGetKernelArch(
    char** ppszArch
    );

uint32_t
TDNFParseMetadataExpire(
    const char* pszMetadataExpire,
    long* plMetadataExpire
    );


uint32_t
TDNFAppendPath(
    const char *pszBase,
    const char *pszPart,
    char **ppszPath
    );

//validate.c
uint32_t
TDNFGetSkipProblemOption(
    PTDNF pTdnf,
    TDNF_SKIPPROBLEM_TYPE *pdwSkipProblem
    );

/* goal.c */
uint32_t
TDNFReportNativeSolverProblems(
    void *pHandle,
    TDNF_SKIPPROBLEM_TYPE dwSkipProblem
    );

/* plugins.c */
uint32_t
TDNFLoadPlugins(
    PTDNF pTdnf
    );

void
TDNFFreePlugins(
    PTDNF_PLUGIN pPlugins
    );

uint32_t
BuiltinPluginsRepoConfig(
    PTDNF pTdnf,
    const struct cnfnode *pSection
    );

uint32_t
BuiltinPluginsRepoMDDownloadStart(
    PTDNF pTdnf,
    const char *pszRepoId,
    const char *pszRepoDataDir
    );

uint32_t
BuiltinPluginsRepoMDDownloadEnd(
    PTDNF pTdnf,
    const char *pszRepoId,
    const char *pszRepoMDFile
    );

uint32_t BuiltinMetalinkCreate(PTDNF pTdnf, void **ppHandle);
void BuiltinMetalinkDestroy(void *pHandle);
uint32_t BuiltinMetalinkRepoConfig(
    void *pHandle,
    const struct cnfnode *pSection
    );
uint32_t BuiltinMetalinkRepoMDDownloadStart(
    void *pHandle,
    const char *pszRepoId,
    const char *pszRepoDataDir
    );
uint32_t BuiltinMetalinkRepoMDDownloadEnd(
    void *pHandle,
    const char *pszRepoId,
    const char *pszRepoMDFile
    );

uint32_t BuiltinRepoGPGCheckCreate(PTDNF pTdnf, void **ppHandle);
void BuiltinRepoGPGCheckDestroy(void *pHandle);
uint32_t BuiltinRepoGPGCheckRepoConfig(
    void *pHandle,
    const struct cnfnode *pSection
    );
uint32_t BuiltinRepoGPGCheckRepoMDDownloadEnd(
    void *pHandle,
    const char *pszRepoId,
    const char *pszRepoMDFile
    );

struct cnfnode *parse_varsdirs(char *dirs[]);

char *replace_vars(struct cnfnode *cn_vars, const char *source);

#endif /* __CLIENT_PROTOTYPES_H__ */
