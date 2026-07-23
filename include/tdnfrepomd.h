/* Pure-Zig repomd.xml parser C ABI (PR2 of issue #86). */

#ifndef _TDNF_REPOMD_H_
#define _TDNF_REPOMD_H_

#include <stddef.h>
#include <stdint.h>
#include <tdnfrpmconfig.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct s_Repo Repo;
typedef struct _TDNF_PKG_INFO TDNF_PKG_INFO, *PTDNF_PKG_INFO;
typedef struct _TDNF_SOLVED_PKG_INFO
    TDNF_SOLVED_PKG_INFO, *PTDNF_SOLVED_PKG_INFO;
typedef struct _TDNF_REPOQUERY_ARGS TDNF_REPOQUERY_ARGS, *PTDNF_REPOQUERY_ARGS;

typedef struct tdnf_repomd_doc TDNF_REPOMD_DOC;

enum {
    TDNF_REPOMD_RECORD_KIND_UNKNOWN = 0,
    TDNF_REPOMD_RECORD_KIND_PRIMARY = 1,
    TDNF_REPOMD_RECORD_KIND_FILELISTS = 2,
    TDNF_REPOMD_RECORD_KIND_OTHER = 3,
    TDNF_REPOMD_RECORD_KIND_UPDATEINFO = 4,
};

typedef struct _TDNF_REPOMD_CHECKSUM
{
    const char *pszType;
    const char *pszValue;
} TDNF_REPOMD_CHECKSUM;

typedef struct _TDNF_REPOMD_RECORD
{
    const char *pszType;
    uint32_t dwKind;
    const char *pszLocationHref;
    TDNF_REPOMD_CHECKSUM checksum;
    TDNF_REPOMD_CHECKSUM openChecksum;
    uint64_t nTimestamp;
    uint64_t nSize;
    uint64_t nOpenSize;
    uint64_t nDatabaseVersion;
    int nHasTimestamp;
    int nHasSize;
    int nHasOpenSize;
    int nHasDatabaseVersion;
} TDNF_REPOMD_RECORD;

typedef struct _TDNF_REPOMD_NATIVE_REPO_INPUT
{
    const char *pszId;
    const char *pszCacheDir;
    const char *pszSnapshotFile;
} TDNF_REPOMD_NATIVE_REPO_INPUT, *PTDNF_REPOMD_NATIVE_REPO_INPUT;

enum {
    TDNF_REPOMD_NATIVE_TRANSACTION_OP_INSTALL = 1,
    TDNF_REPOMD_NATIVE_TRANSACTION_OP_REINSTALL = 2,
    TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE = 3,
    TDNF_REPOMD_NATIVE_TRANSACTION_OP_UPGRADE = 4,
};

typedef struct _TDNF_REPOMD_NATIVE_TRANSACTION_ITEM
{
    uint32_t dwOperation;
    const char *pszPath;
    const char *pszName;
    const char *pszEVR;
    const char *pszArch;
} TDNF_REPOMD_NATIVE_TRANSACTION_ITEM, *PTDNF_REPOMD_NATIVE_TRANSACTION_ITEM;

/*
 * Versioned transaction input. The legacy structure above is ABI-stable and
 * remains the input to the original transaction APIs.
 */
typedef struct _TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2
{
    uint32_t dwOperation;
    const char *pszPath;
    const char *pszName;
    const char *pszEVR;
    const char *pszArch;
    /* Exact Packages-row identity for erase; zero for legacy lookup/others. */
    uint32_t dwRpmDbHnum;
} TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
 *PTDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2;

typedef enum _TDNF_REPOMD_NATIVE_PROBLEM_TYPE
{
    TDNF_REPOMD_NATIVE_PROBLEM_DEPENDENCY = 1,
    TDNF_REPOMD_NATIVE_PROBLEM_PRETRANS = 2,
    TDNF_REPOMD_NATIVE_PROBLEM_CONFLICT = 3,
    TDNF_REPOMD_NATIVE_PROBLEM_OBSOLETES = 4,
    TDNF_REPOMD_NATIVE_PROBLEM_FILE_CONFLICT = 5,
    TDNF_REPOMD_NATIVE_PROBLEM_UNSUPPORTED_MULTIPLE = 6
} TDNF_REPOMD_NATIVE_PROBLEM_TYPE;

/*
 * A native transaction problem. Strings alias the containing plan and remain
 * valid until TDNFRepoMdNativeTransactionPlanFree().
 *
 * pszPackage is the package that raised the problem. pszRelatedPackage is
 * populated for package/file conflicts. pszSubject is the missing dependency,
 * conflicting path, or package name whose installed multiplicity is
 * unsupported.
 */
typedef struct _TDNF_REPOMD_NATIVE_TRANSACTION_PROBLEM
{
    TDNF_REPOMD_NATIVE_PROBLEM_TYPE nType;
    uint32_t dwInputIndex;
    const char *pszPackage;
    const char *pszRelatedPackage;
    const char *pszSubject;
    uint32_t dwCount;
} TDNF_REPOMD_NATIVE_TRANSACTION_PROBLEM;

/*
 * Per-input execution metadata. Prior hnums are stored in the plan's flat
 * pdwPriorHnums array at [dwPriorOffset, dwPriorOffset + dwPriorCount).
 */
typedef struct _TDNF_REPOMD_NATIVE_TRANSACTION_PLAN_ITEM
{
    uint32_t dwPriorOffset;
    uint32_t dwPriorCount;
} TDNF_REPOMD_NATIVE_TRANSACTION_PLAN_ITEM;

/*
 * One owned, validated native transaction plan. pdwOrderIndices is a complete
 * permutation of the original input indexes. pItems is indexed by original
 * input index and identifies the exact installed rows superseded by each
 * upgrade or reinstall.
 */
typedef struct _TDNF_REPOMD_NATIVE_TRANSACTION_PLAN
{
    uint32_t dwItemCount;
    uint32_t *pdwOrderIndices;
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN_ITEM *pItems;
    uint32_t dwPriorHnumCount;
    uint32_t *pdwPriorHnums;
    uint32_t dwProblemCount;
    TDNF_REPOMD_NATIVE_TRANSACTION_PROBLEM *pProblems;
} TDNF_REPOMD_NATIVE_TRANSACTION_PLAN;

typedef enum _TDNF_REPOMD_NATIVE_SOLVER_ACTION_KIND
{
    TDNF_REPOMD_NATIVE_SOLVER_ACTION_INSTALL = 1,
    TDNF_REPOMD_NATIVE_SOLVER_ACTION_ERASE = 2,
    TDNF_REPOMD_NATIVE_SOLVER_ACTION_UPGRADE = 3,
    TDNF_REPOMD_NATIVE_SOLVER_ACTION_DOWNGRADE = 4,
    TDNF_REPOMD_NATIVE_SOLVER_ACTION_REINSTALL = 5,
    TDNF_REPOMD_NATIVE_SOLVER_ACTION_OBSOLETE = 6
} TDNF_REPOMD_NATIVE_SOLVER_ACTION_KIND;

typedef enum _TDNF_REPOMD_NATIVE_SOLVER_ACTION_REASON
{
    TDNF_REPOMD_NATIVE_SOLVER_REASON_USER = 1,
    TDNF_REPOMD_NATIVE_SOLVER_REASON_DEPENDENCY = 2,
    TDNF_REPOMD_NATIVE_SOLVER_REASON_WEAK_DEPENDENCY = 3,
    TDNF_REPOMD_NATIVE_SOLVER_REASON_CLEANUP = 4,
    TDNF_REPOMD_NATIVE_SOLVER_REASON_OBSOLETES = 5,
    TDNF_REPOMD_NATIVE_SOLVER_REASON_INSTALL_ONLY = 6,
    TDNF_REPOMD_NATIVE_SOLVER_REASON_POLICY = 7
} TDNF_REPOMD_NATIVE_SOLVER_ACTION_REASON;

typedef enum _TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_KIND
{
    TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_UNSATISFIED_REQUIREMENT = 1,
    TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_CONFLICT = 2,
    TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_OBSOLETES = 3,
    TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_NO_CANDIDATE = 4,
    TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_NOT_INSTALLABLE = 5,
    TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_PROTECTED_PACKAGE = 6,
    TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_INSTALL_ONLY_LIMIT = 7
} TDNF_REPOMD_NATIVE_SOLVER_PROBLEM_KIND;

typedef enum _TDNF_REPOMD_NATIVE_SOLVER_REPOSITORY_KIND
{
    TDNF_REPOMD_NATIVE_SOLVER_REPOSITORY_INSTALLED = 1,
    TDNF_REPOMD_NATIVE_SOLVER_REPOSITORY_AVAILABLE = 2,
    TDNF_REPOMD_NATIVE_SOLVER_REPOSITORY_COMMAND_LINE = 3
} TDNF_REPOMD_NATIVE_SOLVER_REPOSITORY_KIND;

typedef enum _TDNF_REPOMD_NATIVE_SOLVER_COMPARISON
{
    TDNF_REPOMD_NATIVE_SOLVER_COMPARISON_NONE = 0,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARISON_EQUAL = 1,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARISON_LESS = 2,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARISON_LESS_OR_EQUAL = 3,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARISON_GREATER = 4,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARISON_GREATER_OR_EQUAL = 5
} TDNF_REPOMD_NATIVE_SOLVER_COMPARISON;

/*
 * One package referenced by a native solver result. Package references in
 * the other result arrays are zero-based indexes into pPackages. Optional
 * scalar values are accompanied by explicit nHas* fields.
 */
typedef struct _TDNF_REPOMD_NATIVE_SOLVER_PACKAGE
{
    const char *pszRepository;
    const char *pszName;
    const char *pszVersion;
    const char *pszRelease;
    const char *pszArch;
    const char *pszChecksumType;
    const char *pszChecksumValue;
    const char *pszLocationHref;
    const char *pszLocationBase;
    const char *pszSummary;
    uint64_t nPackageSize;
    uint64_t nInstalledSize;
    uint32_t dwPackageId;
    uint32_t dwRepositoryId;
    uint32_t dwEpoch;
    uint32_t dwRpmDbHnum;
    int nRepositoryKind;
    int nHasEpoch;
    int nHasRpmDbHnum;
    int nChecksumIsPkgId;
    int nHasPackageSize;
    int nHasInstalledSize;
} TDNF_REPOMD_NATIVE_SOLVER_PACKAGE;

/*
 * Canonical package decision. Prior package references occupy
 * [dwPriorOffset, dwPriorOffset + dwPriorCount) in both
 * pdwPriorPackageRefs and pdwPriorHnums.
 */
typedef struct _TDNF_REPOMD_NATIVE_SOLVER_ACTION
{
    uint32_t dwPackageRef;
    uint32_t dwKind;
    uint32_t dwReason;
    uint32_t dwPriorOffset;
    uint32_t dwPriorCount;
    uint32_t dwRequestedJobId;
    int nHasRequestedJobId;
} TDNF_REPOMD_NATIVE_SOLVER_ACTION;

typedef struct _TDNF_REPOMD_NATIVE_SOLVER_RELATION
{
    const char *pszName;
    const char *pszVersion;
    const char *pszRelease;
    const char *pszFlags;
    uint32_t dwComparison;
    uint32_t dwEpoch;
    uint32_t dwSense;
    int nHasEpoch;
    int nPre;
} TDNF_REPOMD_NATIVE_SOLVER_RELATION;

typedef struct _TDNF_REPOMD_NATIVE_SOLVER_PROBLEM
{
    TDNF_REPOMD_NATIVE_SOLVER_RELATION capability;
    uint32_t dwKind;
    uint32_t dwPackageRef;
    uint32_t dwRelatedPackageRef;
    uint32_t dwJobId;
    uint32_t dwCount;
    int nHasPackageRef;
    int nHasRelatedPackageRef;
    int nHasCapability;
    int nHasJobId;
} TDNF_REPOMD_NATIVE_SOLVER_PROBLEM;

/*
 * Owned canonical native solver output. Every pointer, including all strings,
 * remains valid until TDNFRepoMdNativeSolverResultFree(). Array order matches
 * the native materializer; the package table is ordered by native package id.
 */
typedef struct _TDNF_REPOMD_NATIVE_SOLVER_RESULT
{
    TDNF_REPOMD_NATIVE_SOLVER_PACKAGE *pPackages;
    uint32_t *pdwSelectedPackageRefs;
    TDNF_REPOMD_NATIVE_SOLVER_ACTION *pActions;
    uint32_t *pdwPriorPackageRefs;
    uint32_t *pdwPriorHnums;
    TDNF_REPOMD_NATIVE_SOLVER_PROBLEM *pProblems;
    uint32_t *pdwSkippedJobIds;
    uint32_t dwPackageCount;
    uint32_t dwSelectedPackageCount;
    uint32_t dwActionCount;
    uint32_t dwPriorPackageRefCount;
    uint32_t dwProblemCount;
    uint32_t dwSkippedJobCount;
} TDNF_REPOMD_NATIVE_SOLVER_RESULT;

typedef enum _TDNF_REPOMD_NATIVE_SOLVER_COMPARE_STATUS
{
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_PROJECTED_MATCH = 1,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_MISMATCH = 2,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_UNSUPPORTED = 3,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID = 4
} TDNF_REPOMD_NATIVE_SOLVER_COMPARE_STATUS;

typedef enum _TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON
{
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON_NONE = 0,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON_NATIVE_PROBLEMS = 1,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON_SKIPPED_JOBS = 2,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON_PRIOR_ACTION = 3,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON_NATIVE_ACTION_KIND = 4,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON_LEGACY_ACTION_BUCKET = 5,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON_DUPLICATE_KEY = 6
} TDNF_REPOMD_NATIVE_SOLVER_COMPARE_REASON;

typedef struct _TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT
{
    uint32_t dwStatus;
    uint32_t dwReason;
    uint32_t dwActionKind;
    uint32_t dwDifferenceIndex;
    uint32_t dwNativeCount;
    uint32_t dwLegacyCount;
} TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT;

typedef struct _TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY
{
    const char *pszId;
    const char *pszCacheDir;
    const char *pszSnapshotFile;
    int32_t nPriority;
    uint32_t dwCost;
} TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
 *PTDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY;

typedef struct _TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB
{
    const char *pszRepository;
    const char *pszName;
    const char *pszVersion;
    const char *pszRelease;
    const char *pszArch;
    const char *pszChecksumType;
    const char *pszChecksumValue;
    uint32_t dwEpoch;
    int nChecksumIsPkgId;
} TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
 *PTDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB;

enum {
    TDNF_REPOMD_NATIVE_SOLVER_DEFAULT_REPOSITORY_COST = 1000
};

#ifndef RPMDB_REPORT_PROGRESS
#define RPMDB_REPORT_PROGRESS           (1 << 8)
#define RPM_ADD_WITH_PKGID             (1 << 9)
#define RPM_ADD_NO_FILELIST            (1 << 10)
#define RPM_ADD_NO_RPMLIBREQS          (1 << 11)
#define RPM_ADD_WITH_SHA1SUM           (1 << 12)
#define RPM_ADD_WITH_SHA256SUM         (1 << 13)
#define RPM_ADD_TRIGGERS               (1 << 14)
#define RPM_ADD_WITH_HDRID             (1 << 15)
#define RPM_ADD_WITH_LEADSIGID         (1 << 16)
#define RPM_ADD_WITH_CHANGELOG         (1 << 17)
#define RPM_ADD_FILTERED_FILELIST      (1 << 18)
#define RPMDB_KEEP_GPG_PUBKEY          (1 << 19)
#define RPM_ADD_WITH_ORDERWITHREQUIRES (1 << 20)
#define RPMDB_EMPTY_REFREPO            (1 << 30)
#endif

/*
 * Parse a repomd.xml buffer. `buf` need not be NUL-terminated.
 * On success stores a document handle in `*ppDoc`; caller frees it with
 * TDNFRepoMdFree.
 */
uint32_t
TDNFRepoMdParseBuffer(
    const char *buf,
    size_t len,
    TDNF_REPOMD_DOC **ppDoc
    );

/*
 * Parse a repomd.xml file by path.
 */
uint32_t
TDNFRepoMdParseFile(
    const char *pszPath,
    TDNF_REPOMD_DOC **ppDoc
    );

/*
 * Return the last repomd parser/load error produced by the current thread.
 */
const char*
TDNFRepoMdLastError(
    void
    );

/*
 * Free a parsed document. Accepts NULL.
 */
void
TDNFRepoMdFree(
    TDNF_REPOMD_DOC *pDoc
    );

/*
 * Return the optional <revision> text, or NULL when it is absent.
 * The returned pointer aliases `pDoc` and remains valid until
 * TDNFRepoMdFree.
 */
const char*
TDNFRepoMdGetRevision(
    const TDNF_REPOMD_DOC *pDoc
    );

/*
 * Return the number of <data> records in the document.
 */
uint32_t
TDNFRepoMdGetRecordCount(
    const TDNF_REPOMD_DOC *pDoc
    );

/*
 * Return the record at `dwIndex`, or NULL if `dwIndex` is out of range.
 * The returned pointer aliases `pDoc` and remains valid until
 * TDNFRepoMdFree.
 */
const TDNF_REPOMD_RECORD*
TDNFRepoMdGetRecord(
    const TDNF_REPOMD_DOC *pDoc,
    uint32_t dwIndex
    );

/*
 * Return the last native repo->libsolv bridge error produced by the current
 * thread.
 */
const char*
TDNFRepoMdNativeLastError(
    void
    );

/*
 * Return the last native query-layer crosscheck error produced by the
 * current thread.
 */
const char*
TDNFRepoMdNativeQueryLastError(
    void
    );

/*
 * Return the last native transaction ordering/check error produced by the
 * current thread.
 */
const char*
TDNFRepoMdNativeTransactionLastError(
    void
    );

/*
 * Parse repo metadata with the native Zig parsers and populate an existing
 * libsolv Repo using manual-construction APIs. Optional metadata paths may be
 * NULL. The caller owns `pRepo`.
 */
uint32_t
TDNFRepoMdNativeLoadSolvRepo(
    Repo *pRepo,
    const char *pszRepomd,
    const char *pszPrimary,
    const char *pszFilelists,
    const char *pszUpdateinfo,
    const char *pszOther
    );

/*
 * Populate an existing libsolv Repo from the installed rpmdb under
 * `pszRootDir`, using the native Zig header->package bridge. `nFlags`
 * mirrors the `repo_add_rpmdb_reffp` flag word that selected the legacy
 * loader's metadata shape.
 */
uint32_t
TDNFRepoMdNativeLoadInstalledSolvRepo(
    Repo *pRepo,
    const char *pszRootDir,
    int nFlags
    );

uint32_t
TDNFRepoMdNativeLoadInstalledSolvRepoConfig(
    Repo *pRepo,
    const tdnf_rpm_config *pConfig,
    int nFlags
    );

/*
 * Add a single `.rpm` file to an existing libsolv Repo using the native
 * Zig rpm-file parser plus manual solvable construction. `nFlags` mirrors
 * `repo_add_rpm`. When `pdwSolvableId` is non-NULL, the added solvable id is
 * stored there on success.
 */
uint32_t
TDNFRepoMdNativeAddRpm(
    Repo *pRepo,
    const char *pszPath,
    int nFlags,
    uint32_t *pdwSolvableId
    );

/*
 * Run the native metadata-backed implementation of `tdnf list` / `info`
 * style queries. `nScope` and `nDetail` use the TDNF_SCOPE /
 * TDNF_PKG_DETAIL integer values from tdnftypes.h.
 */
uint32_t
TDNFRepoMdNativeList(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    int nScope,
    char **ppszPackageNameSpecs,
    int nDetail,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

/*
 * Run the native metadata-backed implementation of `tdnf search`.
 */
uint32_t
TDNFRepoMdNativeSearch(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    char **ppszSearchStrings,
    int nStartIndex,
    int nEndIndex,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *punCount
    );

/*
 * Run the native metadata-backed implementation of `tdnf provides` /
 * `whatprovides`.
 */
uint32_t
TDNFRepoMdNativeProvides(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    const char *pszSpec,
    PTDNF_PKG_INFO *ppPkgInfo
    );

/*
 * Run the native rpmzig transaction ordering and final dependency/conflict
 * verification pass on a prepared transaction. On success `pppszOrderLines`
 * receives one decimal input-index string per transaction element in the
 * native execution order, and `pppszProblemLines` receives zero or more
 * user-facing problem messages. Both outputs are NULL-terminated arrays owned
 * by the caller and must be freed with TDNFFreeStringArray().
 */
uint32_t
TDNFRepoMdNativeTransactionSolve(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM *pItems,
    uint32_t dwItemCount,
    const char *pszInstallRoot,
    char ***pppszOrderLines,
    uint32_t *pdwOrderCount,
    char ***pppszProblemLines,
    uint32_t *pdwProblemCount
    );

/*
 * Versioned counterpart carrying exact rpmdb row identities. Callers that
 * populate dwRpmDbHnum must use this entry point rather than the legacy API.
 */
uint32_t
TDNFRepoMdNativeTransactionSolveV2(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2 *pItems,
    uint32_t dwItemCount,
    const char *pszInstallRoot,
    char ***pppszOrderLines,
    uint32_t *pdwOrderCount,
    char ***pppszProblemLines,
    uint32_t *pdwProblemCount
    );

/*
 * Structured counterpart to TDNFRepoMdNativeTransactionSolve(). The returned
 * plan owns all order, prior-row, and typed-problem storage and must be freed
 * with TDNFRepoMdNativeTransactionPlanFree().
 */
uint32_t
TDNFRepoMdNativeTransactionPlanSolve(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM *pItems,
    uint32_t dwItemCount,
    const char *pszInstallRoot,
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN **ppPlan
    );

uint32_t
TDNFRepoMdNativeTransactionPlanSolveV2(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2 *pItems,
    uint32_t dwItemCount,
    const char *pszInstallRoot,
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN **ppPlan
    );

void
TDNFRepoMdNativeTransactionPlanFree(
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan
    );

/*
 * Free a native solver result and all storage reachable from it. Accepts NULL.
 */
void
TDNFRepoMdNativeSolverResultFree(
    TDNF_REPOMD_NATIVE_SOLVER_RESULT *pResult
    );

/*
 * Compare the exact install/erase target projection of a native result with
 * the authoritative legacy solved-package buckets. This deliberately ignores
 * selected packages, action reasons/request provenance, unresolved/user-
 * install names, and UI flags. Priors, other action kinds, native problems,
 * skipped jobs, legacy upgrade/downgrade/reinstall/obsolete/unneeded buckets,
 * and duplicate projected identities produce UNSUPPORTED rather than MATCH.
 *
 * A successful call returns zero and always sets pComparison. Mismatch and
 * unsupported statuses are comparison outcomes, not API errors.
 */
uint32_t
TDNFRepoMdNativeSolverResultCompare(
    const TDNF_REPOMD_NATIVE_SOLVER_RESULT *pNative,
    const TDNF_SOLVED_PKG_INFO *pLegacy,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT *pComparison
    );

/*
 * Produce a strict native solve from live cached metadata and rpmdb inputs,
 * then compare its exact install/erase projection with the authoritative
 * legacy result. This operation is observational: it does not mutate any
 * input and returns mismatch or unsupported as comparison statuses.
 */
uint32_t
TDNFRepoMdNativeSolverLiveCompare(
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY *pRepositories,
    uint32_t dwRepositoryCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pJobs,
    uint32_t dwJobCount,
    const tdnf_rpm_config *pRpmConfig,
    const char *pszNativeArch,
    const TDNF_SOLVED_PKG_INFO *pLegacy,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT *pComparison
    );

/*
 * Version 2 additionally accepts the exact available-package complement of
 * the authoritative Pool.considered map. Entries use the live-job selector
 * layout but are visibility inputs, not jobs. A null pointer is valid only
 * when dwHiddenAvailableCount is zero. Clear installed-package bits are
 * intentionally omitted: libsolv retains those packages as providers.
 */
uint32_t
TDNFRepoMdNativeSolverLiveCompareV2(
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY *pRepositories,
    uint32_t dwRepositoryCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pJobs,
    uint32_t dwJobCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pHiddenAvailable,
    uint32_t dwHiddenAvailableCount,
    const tdnf_rpm_config *pRpmConfig,
    const char *pszNativeArch,
    const TDNF_SOLVED_PKG_INFO *pLegacy,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT *pComparison
    );

/*
 * Version 3 additionally accepts the authoritative --alldeps mode. When
 * nAllDeps is nonzero, the native universe omits the installed repository,
 * matching TDNFInit's libsolv input construction.
 */
uint32_t
TDNFRepoMdNativeSolverLiveCompareV3(
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY *pRepositories,
    uint32_t dwRepositoryCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pJobs,
    uint32_t dwJobCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pHiddenAvailable,
    uint32_t dwHiddenAvailableCount,
    int nAllDeps,
    const tdnf_rpm_config *pRpmConfig,
    const char *pszNativeArch,
    const TDNF_SOLVED_PKG_INFO *pLegacy,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT *pComparison
    );

/*
 * Version 4 additionally accepts the authoritative --best mode. When nBest
 * is nonzero, native replacement policy matches SOLVER_FORCEBEST on each
 * original libsolv job.
 */
uint32_t
TDNFRepoMdNativeSolverLiveCompareV4(
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY *pRepositories,
    uint32_t dwRepositoryCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pJobs,
    uint32_t dwJobCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pHiddenAvailable,
    uint32_t dwHiddenAvailableCount,
    int nAllDeps,
    int nBest,
    const tdnf_rpm_config *pRpmConfig,
    const char *pszNativeArch,
    const TDNF_SOLVED_PKG_INFO *pLegacy,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT *pComparison
    );

/*
 * Version 5 additionally accepts authoritative clean-deps policy. When
 * nCleanDeps is nonzero, native cleanup policy matches SOLVER_CLEANDEPS on
 * each original libsolv job. Erase and autoremove jobs remain unsupported.
 */
uint32_t
TDNFRepoMdNativeSolverLiveCompareV5(
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY *pRepositories,
    uint32_t dwRepositoryCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pJobs,
    uint32_t dwJobCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pHiddenAvailable,
    uint32_t dwHiddenAvailableCount,
    int nAllDeps,
    int nBest,
    int nCleanDeps,
    const tdnf_rpm_config *pRpmConfig,
    const char *pszNativeArch,
    const TDNF_SOLVED_PKG_INFO *pLegacy,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT *pComparison
    );

/*
 * Version 6 additionally accepts authoritative skip-broken policy. The live
 * observer invokes this boundary only after libsolv reports zero problems;
 * native results that skip any jobs remain unsupported by the comparator.
 */
uint32_t
TDNFRepoMdNativeSolverLiveCompareV6(
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY *pRepositories,
    uint32_t dwRepositoryCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pJobs,
    uint32_t dwJobCount,
    const TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB *pHiddenAvailable,
    uint32_t dwHiddenAvailableCount,
    int nAllDeps,
    int nBest,
    int nCleanDeps,
    int nSkipBroken,
    const tdnf_rpm_config *pRpmConfig,
    const char *pszNativeArch,
    const TDNF_SOLVED_PKG_INFO *pLegacy,
    TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT *pComparison
    );

/*
 * Run the native metadata-backed implementation of repoquery-style
 * selectors and field population. `pRepoqueryArgs` uses the public
 * TDNF_REPOQUERY_ARGS layout from tdnftypes.h.
 */
uint32_t
TDNFRepoMdNativeRepoQuery(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    const TDNF_REPOQUERY_ARGS *pRepoqueryArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

/*
 * Return advisory ids whose updateinfo collections are newer than the
 * supplied installed package NEVRA.
 */
uint32_t
TDNFRepoMdNativeUpdateAdvisoryIds(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszName,
    const char *pszArch,
    const char *pszEvr,
    char ***pppszAdvisoryIds,
    uint32_t *pdwCount
    );

/*
 * Find exact NEVRA matches in either the installed rpmdb (`nInstalled != 0`)
 * or the enabled available repositories (`nInstalled == 0`). Returned lines
 * are serialized as `repo<US>nevra`.
 */
uint32_t
TDNFRepoMdNativeFindNevraMatches(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    const char *pszNevra,
    int nInstalled,
    char ***pppszMatches,
    uint32_t *pdwCount
    );

/*
 * Find exact `name=EVR` matches in a single available repository. Returned
 * lines are serialized as `repo<US>nevra`.
 */
uint32_t
TDNFRepoMdNativeFindNameEvrMatches(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszNameEvr,
    char ***pppszMatches,
    uint32_t *pdwCount
    );

/*
 * Compute updateinfo summary counts for installed packages, applying the same
 * security/severity filtering as `client/updateinfo.c`. Returned lines are
 * serialized as `type<US>count`.
 */
uint32_t
TDNFRepoMdNativeUpdateInfoSummaryLines(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    char **ppszPackageNameSpecs,
    uint32_t dwSecurity,
    const char *pszSeverity,
    char ***pppszLines,
    uint32_t *pdwCount
    );

/*
 * Compute updateinfo advisory detail lines for installed packages, applying
 * the same security/severity/reboot filtering as `client/updateinfo.c`.
 */
uint32_t
TDNFRepoMdNativeUpdateInfoLines(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    char **ppszPackageNameSpecs,
    uint32_t dwSecurity,
    const char *pszSeverity,
    uint32_t dwRebootRequired,
    char ***pppszLines,
    uint32_t *pdwCount
    );

/*
 * Compute the set of packages filtered out by the configured minversion
 * constraints. Returned lines are serialized as `repo<US>nevra`.
 */
uint32_t
TDNFRepoMdNativeMinVersionExcludeLines(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    char **ppszMinVersions,
    char ***pppszLines,
    uint32_t *pdwCount
    );

/*
 * Compute the best downgrade candidate for the supplied installed package
 * under the current repository snapshot/minversion constraints. Returns either
 * zero lines or one serialized `repo<US>nevra` line.
 */
uint32_t
TDNFRepoMdNativeDowngradeCandidateLines(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    char **ppszMinVersions,
    const char *pszInstalledRepoNevra,
    char ***pppszLines,
    uint32_t *pdwCount
    );

/*
 * Return unique `requires` dependency strings for the serialized package
 * references (`repo<US>nevra`) supplied in `ppszPackageRefs`.
 */
uint32_t
TDNFRepoMdNativeRequiresForPackageRefs(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const char *pszInstallRoot,
    char **ppszPackageRefs,
    char ***pppszDeps,
    uint32_t *pdwCount
    );

/*
 * Return serialized `repo<US>nevra` lines for the subset of
 * `ppszAutoInstalledRefs` that are still orphaned when evaluated against the
 * installed RPM metadata rooted at `pszInstallRoot`.
 */
uint32_t
TDNFRepoMdNativeAutoInstalledOrphanLines(
    const char *pszInstallRoot,
    char **ppszAutoInstalledRefs,
    char ***pppszLines,
    uint32_t *pdwCount
    );

/*
 * Config-aware counterparts to the native APIs that load installed rpmdb
 * state. Each takes a non-NULL handle created by tdnf_rpm_config_create()
 * in place of `pszInstallRoot`; installed state is resolved using that
 * handle's macro definitions. The root-only APIs above remain compatible
 * wrappers with their existing semantics.
 */
uint32_t
TDNFRepoMdNativeListConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    int nScope,
    char **ppszPackageNameSpecs,
    int nDetail,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

uint32_t
TDNFRepoMdNativeSearchConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    char **ppszSearchStrings,
    int nStartIndex,
    int nEndIndex,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *punCount
    );

uint32_t
TDNFRepoMdNativeProvidesConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    const char *pszSpec,
    PTDNF_PKG_INFO *ppPkgInfo
    );

uint32_t
TDNFRepoMdNativeTransactionSolveConfig(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM *pItems,
    uint32_t dwItemCount,
    const tdnf_rpm_config *pConfig,
    char ***pppszOrderLines,
    uint32_t *pdwOrderCount,
    char ***pppszProblemLines,
    uint32_t *pdwProblemCount
    );

uint32_t
TDNFRepoMdNativeTransactionSolveConfigV2(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2 *pItems,
    uint32_t dwItemCount,
    const tdnf_rpm_config *pConfig,
    char ***pppszOrderLines,
    uint32_t *pdwOrderCount,
    char ***pppszProblemLines,
    uint32_t *pdwProblemCount
    );

uint32_t
TDNFRepoMdNativeTransactionPlanSolveConfig(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM *pItems,
    uint32_t dwItemCount,
    const tdnf_rpm_config *pConfig,
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN **ppPlan
    );

uint32_t
TDNFRepoMdNativeTransactionPlanSolveConfigV2(
    const TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2 *pItems,
    uint32_t dwItemCount,
    const tdnf_rpm_config *pConfig,
    TDNF_REPOMD_NATIVE_TRANSACTION_PLAN **ppPlan
    );

uint32_t
TDNFRepoMdNativeRepoQueryConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    const TDNF_REPOQUERY_ARGS *pRepoqueryArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

uint32_t
TDNFRepoMdNativeFindNevraMatchesConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    const char *pszNevra,
    int nInstalled,
    char ***pppszMatches,
    uint32_t *pdwCount
    );

uint32_t
TDNFRepoMdNativeUpdateInfoSummaryLinesConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    char **ppszPackageNameSpecs,
    uint32_t dwSecurity,
    const char *pszSeverity,
    char ***pppszLines,
    uint32_t *pdwCount
    );

uint32_t
TDNFRepoMdNativeUpdateInfoLinesConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    char **ppszPackageNameSpecs,
    uint32_t dwSecurity,
    const char *pszSeverity,
    uint32_t dwRebootRequired,
    char ***pppszLines,
    uint32_t *pdwCount
    );

uint32_t
TDNFRepoMdNativeMinVersionExcludeLinesConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    char **ppszMinVersions,
    char ***pppszLines,
    uint32_t *pdwCount
    );

uint32_t
TDNFRepoMdNativeRequiresForPackageRefsConfig(
    const TDNF_REPOMD_NATIVE_REPO_INPUT *pRepos,
    uint32_t dwRepoCount,
    const tdnf_rpm_config *pConfig,
    char **ppszPackageRefs,
    char ***pppszDeps,
    uint32_t *pdwCount
    );

uint32_t
TDNFRepoMdNativeAutoInstalledOrphanLinesConfig(
    const tdnf_rpm_config *pConfig,
    char **ppszAutoInstalledRefs,
    char ***pppszLines,
    uint32_t *pdwCount
    );

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_REPOMD_H_ */
