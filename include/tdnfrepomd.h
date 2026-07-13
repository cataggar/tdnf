/* Pure-Zig repomd.xml parser C ABI (PR2 of issue #86). */

#ifndef _TDNF_REPOMD_H_
#define _TDNF_REPOMD_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct s_Repo Repo;
typedef struct _TDNF_PKG_INFO TDNF_PKG_INFO, *PTDNF_PKG_INFO;
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
} TDNF_REPOMD_NATIVE_REPO_INPUT, *PTDNF_REPOMD_NATIVE_REPO_INPUT;

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

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_REPOMD_H_ */
