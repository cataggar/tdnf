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

typedef struct _NATIVE_INSTALL_CTX
{
    const char *pszInstallRoot;
    uint32_t dwNewHnum;
} NATIVE_INSTALL_CTX;

typedef struct _NATIVE_ERASE_CTX
{
    const char *pszInstallRoot;
    uint32_t dwOldHnum;
} NATIVE_ERASE_CTX;

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

static int
NativeInstallConflict(
    void *pData,
    const char *pszPath
    )
{
    NATIVE_INSTALL_CTX *pCtx = (NATIVE_INSTALL_CTX *)pData;
    /*
     * Any other installed package owning `pszPath` after we have
     * placed the new row is treated as a real conflict. For fresh
     * installs (dwNewHnum == 0) the transaction-check step already
     * enforced cross-package conflicts at solve time via libsolv;
     * for upgrade/reinstall the install engine already skips files
     * owned by prior_headers. This callback is reserved as a hook
     * for future per-file enforcement (see the PR description) but
     * always returns 0 (no conflict) today.
     */
    (void)pCtx;
    (void)pszPath;
    return 0;
}

static int
NativeEraseKeepPath(
    void *pData,
    const char *pszPath
    )
{
    NATIVE_ERASE_CTX *pCtx = (NATIVE_ERASE_CTX *)pData;
    /*
     * Reserved hook. When callers of tdnf_rpm_erase_hnum leave
     * keep_path_fn NULL, the engine's built-in default probe
     * queries the native rpmdb (Basenames/Dirnames excluding
     * dwOldHnum). Overriding here would let us layer a
     * transaction-scoped view (e.g. "the next erase item also
     * owned this path"); not needed for the initial PR.
     */
    (void)pCtx;
    (void)pszPath;
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
        dwFlags |= RPMTRANS_FLAG_TEST | RPMTRANS_FLAG_NOSCRIPTS |
                   RPMTRANS_FLAG_NOTRIGGERS | RPMTRANS_FLAG_JUSTDB;
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
    uint32_t dwTransFlags,
    int nArg1,
    int nArg2,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    tdnf_rpm_scriptlet_options options;
    tdnf_rpm_scriptlet_result result;

    memset(&options, 0, sizeof(options));
    memset(&result, 0, sizeof(result));

    options.install_root = pszInstallRoot;
    options.trans_flags = dwTransFlags;
    options.rpmdefines = NULL;
    options.rpmdefine_count = 0;
    options.arg1 = nArg1;
    options.arg2 = nArg2;
    options.script_fd = nScriptFd;
    options.redirect_stdout_to_stderr = nRedirectToStderr;

    if (tdnf_rpm_header_run_scriptlet(pbBlob, nLen, phase, &options, &result) != 0)
    {
        LogRpmzigError(pszPhaseName);
        return ERROR_TDNF_TRANSACTION_FAILED;
    }

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
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr,
    int nArg2OverridePresent,
    int nArg2OverrideValue
    )
{
    tdnf_rpm_trigger_options options;
    tdnf_rpm_trigger_result result;

    memset(&options, 0, sizeof(options));
    memset(&result, 0, sizeof(result));

    options.db_root = pszInstallRoot;
    options.install_root = pszInstallRoot;
    options.trans_flags = dwTransFlags;
    options.rpmdefines = NULL;
    options.rpmdefine_count = 0;
    options.script_fd = nScriptFd;
    options.redirect_stdout_to_stderr = nRedirectToStderr;
    options.arg2_override_present = nArg2OverridePresent;
    options.arg2_override_value = nArg2OverrideValue;

    if (tdnf_rpm_header_run_triggers(pbBlob, nLen, phase, &options, &result) != 0)
    {
        LogRpmzigError(pszPhaseName);
        return ERROR_TDNF_TRANSACTION_FAILED;
    }

    /* Triggers are always warning-only in real rpm. */
    (void)pszNevra;
    return 0;
}

/*
 * Compute arg1 for %pre/%post scriptlets on the NEW package side of
 * an install/upgrade/reinstall step, matching real rpm's convention:
 *   - fresh install: 1
 *   - upgrade / reinstall (prior instance exists): 2
 */
static int
NewPkgArg1(TDNF_RPM_TS_ITEM_TYPE nType)
{
    switch (nType)
    {
        case TDNF_RPM_TS_ITEM_INSTALL:
            return 1;
        case TDNF_RPM_TS_ITEM_UPGRADE:
        case TDNF_RPM_TS_ITEM_REINSTALL:
            return 2;
        default:
            return 1;
    }
}

/*
 * Emit an rpmzig install-options blob wired to `pszInstallRoot`,
 * `dwTransFlags`, `eKind` and the list of prior header blobs. The
 * callback is intentionally left NULL to fall back to the engine's
 * built-in behavior (which trusts prior_headers for upgrade /
 * reinstall skip semantics and does not perform a per-file
 * cross-package conflict check on fresh installs — that is enforced
 * upstream by the transaction-check step).
 */
static void
FillInstallOptions(
    tdnf_rpm_install_options *pOptions,
    const char *pszInstallRoot,
    uint32_t dwTransFlags,
    tdnf_rpm_install_kind eKind,
    const tdnf_rpm_install_prior_header *pPriors,
    size_t nPriors
    )
{
    memset(pOptions, 0, sizeof(*pOptions));
    pOptions->install_root = pszInstallRoot;
    pOptions->trans_flags = dwTransFlags;
    pOptions->install_kind = eKind;
    pOptions->prior_headers = pPriors;
    pOptions->prior_header_count = nPriors;
    pOptions->conflict_fn = NULL;
    pOptions->conflict_fn_data = NULL;
}

/*
 * Collect all installed rpmdb rows with the same package name as
 * `pszName` under `pszInstallRoot`, filtered to exclude anything
 * matching `pszSkipNevra` (used for reinstall to skip the row we
 * are replacing, since it is handled via `write_replace`). Returns
 * arrays of `pahnums`, `papBlobs`, `panBlobLens` of length
 * `*pnCount`; every entry must be freed via `FreePriorRows`.
 */
static uint32_t
CollectPriorRows(
    const char *pszInstallRoot,
    const char *pszName,
    uint32_t **ppahnums,
    unsigned char ***papBlobs,
    size_t **panBlobLens,
    size_t *pnCount
    )
{
    uint32_t dwError = 0;
    uint32_t *pHnums = NULL;
    size_t nHnums = 0;
    uint32_t *pKeepHnums = NULL;
    unsigned char **ppBlobs = NULL;
    size_t *pnLens = NULL;
    size_t nKept = 0;
    size_t i = 0;
    size_t j = 0;

    *ppahnums = NULL;
    *papBlobs = NULL;
    *panBlobLens = NULL;
    *pnCount = 0;

    if (IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (tdnf_rpmdb_find_hnums_by_name(pszInstallRoot, pszName, &pHnums, &nHnums) != 0)
    {
        LogRpmzigError("find_hnums_by_name");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    if (nHnums == 0)
    {
        goto cleanup;
    }

    dwError = TDNFAllocateMemory(nHnums, sizeof(uint32_t), (void **)&pKeepHnums);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TDNFAllocateMemory(nHnums, sizeof(unsigned char *), (void **)&ppBlobs);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TDNFAllocateMemory(nHnums, sizeof(size_t), (void **)&pnLens);
    BAIL_ON_TDNF_ERROR(dwError);

    for (i = 0; i < nHnums; i++)
    {
        unsigned char *pbBlob = NULL;
        size_t nLen = 0;
        if (tdnf_rpmdb_read_header_blob(pszInstallRoot, pHnums[i], &pbBlob, &nLen) != 0)
        {
            LogRpmzigError("read_header_blob");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        pKeepHnums[nKept] = pHnums[i];
        ppBlobs[nKept] = pbBlob;
        pnLens[nKept] = nLen;
        nKept++;
    }

    *ppahnums = pKeepHnums;
    *papBlobs = ppBlobs;
    *panBlobLens = pnLens;
    *pnCount = nKept;
    pKeepHnums = NULL;
    ppBlobs = NULL;
    pnLens = NULL;

cleanup:
    tdnf_rpmdb_hnums_free(pHnums);
    TDNF_SAFE_FREE_MEMORY(pKeepHnums);
    if (ppBlobs)
    {
        for (j = 0; j < nKept; j++)
        {
            tdnf_rpmdb_blob_free(ppBlobs[j]);
        }
        TDNF_SAFE_FREE_MEMORY(ppBlobs);
    }
    TDNF_SAFE_FREE_MEMORY(pnLens);
    return dwError;

error:
    goto cleanup;
}

static void
FreePriorRows(
    uint32_t *pahnums,
    unsigned char **papBlobs,
    size_t *panBlobLens,
    size_t nCount
    )
{
    size_t i = 0;
    if (papBlobs)
    {
        for (i = 0; i < nCount; i++)
        {
            tdnf_rpmdb_blob_free(papBlobs[i]);
        }
        TDNFFreeMemory(papBlobs);
    }
    TDNF_SAFE_FREE_MEMORY(pahnums);
    TDNF_SAFE_FREE_MEMORY(panBlobLens);
}

/*
 * Per-package sub-phase for erasing the OLD version(s) already
 * replaced by an UPGRADE/REINSTALL step. Runs %triggerun ->
 * %preun -> file-erase -> %postun -> %triggerpostun, all with
 * arg1=1 (one instance of the name remains: the newly installed
 * one) and arg2=1 override on the triggers (the new instance
 * survives so `$2` reflects that surviving instance, matching
 * real rpm's transient two-instance state for upgrades).
 * Filesystem cleanup relies on the erase engine's default
 * keep-path probe: paths still owned by the new package are kept,
 * files/directories unique to the old package are removed.
 */
static uint32_t
EraseOldAfterReplace(
    const char *pszInstallRoot,
    uint32_t dwTransFlags,
    const unsigned char *pbOldBlob,
    size_t nOldLen,
    const char *pszNevra,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    tdnf_rpm_erase_options erase_options;

    memset(&erase_options, 0, sizeof(erase_options));
    erase_options.trans_flags = dwTransFlags;
    erase_options.keep_path_fn = NULL;
    erase_options.keep_path_fn_data = NULL;

    /*
     * %triggerun on the OLD blob BEFORE %preun. arg2=1 override:
     * after this upgrade step the new instance is what remains, so
     * real rpm passes `$2 = 1` here regardless of what the current
     * rpmdb row count is (write_replace already atomically swapped
     * the row so the DB now shows only the new version).
     */
    dwError = RunTriggers(pbOldBlob, nOldLen,
                          TDNF_RPM_TRIGGER_PHASE_TRIGGERUN, "%triggerun",
                          pszNevra, pszInstallRoot, dwTransFlags,
                          nScriptFd, nRedirectToStderr,
                          /*override present*/ 1, /*value*/ 1);
    BAIL_ON_TDNF_ERROR(dwError);

    /* %preun on old (arg1=1: one instance survives = the new one) */
    dwError = RunScriptlet(pbOldBlob, nOldLen,
                           TDNF_RPM_SCRIPTLET_PHASE_PREUN, "%preun",
                           pszNevra, pszInstallRoot, dwTransFlags,
                           1, -1, nScriptFd, nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    /*
     * File-erase for the old header. The default keep-path probe
     * queries the native rpmdb for any package that owns each path.
     * By this point write_replace() has atomically overwritten the
     * OLD row at its hnum with the NEW header blob, so the rpmdb's
     * Basenames/Dirnames tables reflect the NEW package's file list
     * there. As a result the default probe keeps:
     *   - paths still owned by the NEW package (shared/renamed-to-
     *     same-name files never get deleted),
     *   - paths owned by any completely different installed package
     *     (shared-ownership across unrelated packages),
     * and only removes paths unique to the OLD version. %ghost and
     * modified-%config handling (rename to .rpmsave) reuse the same
     * logic as tdnf_rpm_erase_hnum since it's the same engine.
     */
    if (tdnf_rpm_erase_header_blob(pszInstallRoot,
                                   pbOldBlob, nOldLen,
                                   &erase_options) != 0)
    {
        LogRpmzigError("rpm_erase_header_blob");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    /* %postun on old (arg1=1) */
    dwError = RunScriptlet(pbOldBlob, nOldLen,
                           TDNF_RPM_SCRIPTLET_PHASE_POSTUN, "%postun",
                           pszNevra, pszInstallRoot, dwTransFlags,
                           1, -1, nScriptFd, nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    /*
     * %triggerpostun on the OLD blob AFTER %postun. Same arg2=1
     * override reasoning as %triggerun above.
     */
    dwError = RunTriggers(pbOldBlob, nOldLen,
                          TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN, "%triggerpostun",
                          pszNevra, pszInstallRoot, dwTransFlags,
                          nScriptFd, nRedirectToStderr,
                          /*override present*/ 1, /*value*/ 1);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
ProcessInstallItem(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
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
    tdnf_rpm_file *pFile = NULL;
    const unsigned char *pbBlob = NULL;
    size_t nLen = 0;
    tdnf_rpm_install_options install_options;
    tdnf_rpm_install_prior_header *pPriorViews = NULL;
    uint32_t *pPriorHnums = NULL;
    unsigned char **ppPriorBlobs = NULL;
    size_t *pnPriorLens = NULL;
    size_t nPriors = 0;
    tdnf_rpm_install_kind eKind;
    uint32_t dwNewHnum = 0;
    int nArg1 = NewPkgArg1(pItem->nType);
    const char *pszNevra = NULL;
    char *pszNevraBuf = NULL;

    (void)pTS;
    (void)dwInstallTime;

    if (IsNullOrEmptyString(pItem->pszPath))
    {
        pr_err("rpmzig-transaction-execute: install item missing .rpm path\n");
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pFile = tdnf_rpm_file_open(pItem->pszPath);
    if (!pFile)
    {
        LogRpmzigError("rpm_file_open");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
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
            dwError = CollectPriorRows(pszInstallRoot,
                                       pItem->pszName,
                                       &pPriorHnums, &ppPriorBlobs,
                                       &pnPriorLens, &nPriors);
            BAIL_ON_TDNF_ERROR(dwError);
            break;
        case TDNF_RPM_TS_ITEM_REINSTALL:
            eKind = TDNF_RPM_INSTALL_KIND_REINSTALL;
            dwError = CollectPriorRows(pszInstallRoot,
                                       pItem->pszName,
                                       &pPriorHnums, &ppPriorBlobs,
                                       &pnPriorLens, &nPriors);
            BAIL_ON_TDNF_ERROR(dwError);
            break;
        default:
            pr_err("rpmzig-transaction-execute: unexpected item type %d\n",
                   pItem->nType);
            dwError = ERROR_TDNF_INVALID_PARAMETER;
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

    /* %pre on the new package */
    if (!pTdnf->pArgs->nTestOnly)
    {
        dwError = RunScriptlet(pbBlob, nLen,
                               TDNF_RPM_SCRIPTLET_PHASE_PRE, "%pre",
                               pszNevra, pszInstallRoot, dwTransFlags,
                               nArg1, -1, nScriptFd, nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pr_info("%s: %s\n",
            pItem->nType == TDNF_RPM_TS_ITEM_REINSTALL ? "Reinstalling" :
            pItem->nType == TDNF_RPM_TS_ITEM_UPGRADE   ? "Upgrading"    :
                                                         "Installing",
            pszNevra ? pszNevra : pItem->pszPath);

    if (!pTdnf->pArgs->nTestOnly)
    {
        FillInstallOptions(&install_options, pszInstallRoot,
                           dwTransFlags, eKind, pPriorViews, nPriors);
        if (tdnf_rpm_file_install(pFile, &install_options) != 0)
        {
            LogRpmzigError("rpm_file_install");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        /* Write the new rpmdb row. */
        if (nPriors == 1)
        {
            if (tdnf_rpmdb_write_replace(pszInstallRoot,
                                         pPriorHnums[0],
                                         pItem->pszPath,
                                         dwInstallTid, dwInstallTime,
                                         0, NULL, 0, &dwNewHnum) != 0)
            {
                LogRpmzigError("rpmdb_write_replace");
                dwError = ERROR_TDNF_TRANSACTION_FAILED;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
        else if (nPriors == 0)
        {
            if (tdnf_rpmdb_write_install(pszInstallRoot,
                                         pItem->pszPath,
                                         dwInstallTid, dwInstallTime,
                                         0, NULL, 0, &dwNewHnum) != 0)
            {
                LogRpmzigError("rpmdb_write_install");
                dwError = ERROR_TDNF_TRANSACTION_FAILED;
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
        else
        {
            /*
             * Multi-instance upgrade path (>=2 prior rows sharing
             * the new package's name).
             *
             * tdnf's dependency resolver marks installonly packages
             * (installonlypkgs — kernel, kernel-modules, ...) as
             * INSTALL items rather than UPGRADE items, and prunes
             * the installonly_limit via separate ERASE items. See
             * client/goal.c for the resolver behaviour and
             * pytests/tests/test_multiinstall.py for the exercised
             * workflow. As a result, UPGRADE items reach the
             * executor with exactly nPriors == 1 in every path
             * tdnf's own code takes today.
             *
             * The only way we'd see nPriors >= 2 here is an
             * externally-manipulated rpmdb: e.g. a user manually
             * used `rpm -i --force` to install two versions of a
             * non-installonly package outside tdnf, then asked
             * tdnf to upgrade it. That is not a supported workflow.
             * Refuse loudly (not silently) so the user knows what
             * happened; falling back to librpm would not be safer
             * since the librpm path handled this by erasing all
             * priors, which is very likely not what the user
             * wanted either.
             */
            pr_err("rpmzig-transaction-execute: package '%s' has %zu "
                   "prior installed instances in the rpmdb, but tdnf's "
                   "transaction resolver expected at most one for an "
                   "UPGRADE item. This usually indicates the rpmdb was "
                   "modified outside tdnf (e.g. `rpm -i --force` for "
                   "the same package). Use `rpm -e` to remove the "
                   "extra instance(s) first, or install the package "
                   "as installonly.\n",
                   pItem->pszName, nPriors);
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    /* %post on the new package */
    if (!pTdnf->pArgs->nTestOnly)
    {
        dwError = RunScriptlet(pbBlob, nLen,
                               TDNF_RPM_SCRIPTLET_PHASE_POST, "%post",
                               pszNevra, pszInstallRoot, dwTransFlags,
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
                              pszNevra, pszInstallRoot, dwTransFlags,
                              nScriptFd, nRedirectToStderr,
                              /*override present*/ nPriors > 0 ? 1 : 0,
                              /*value*/ (int)(1 + nPriors));
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
                dwError = EraseOldAfterReplace(pszInstallRoot,
                                               dwTransFlags,
                                               ppPriorBlobs[i], pnPriorLens[i],
                                               pszNevra,
                                               nScriptFd, nRedirectToStderr);
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
    }

cleanup:
    tdnf_rpm_file_close(pFile);
    TDNF_SAFE_FREE_MEMORY(pPriorViews);
    FreePriorRows(pPriorHnums, ppPriorBlobs, pnPriorLens, nPriors);
    TDNF_SAFE_FREE_MEMORY(pszNevraBuf);
    return dwError;

error:
    goto cleanup;
}

static uint32_t
ProcessEraseItem(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    PTDNF_RPM_TS_ITEM pItem,
    uint32_t dwTransFlags,
    const char *pszInstallRoot,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    unsigned char *pbBlob = NULL;
    size_t nLen = 0;
    tdnf_rpm_erase_options erase_options;
    const char *pszNevra = NULL;
    char *pszNevraBuf = NULL;

    (void)pTS;

    if (pItem->dwDbOffset == 0)
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

    if (tdnf_rpmdb_read_header_blob(pszInstallRoot, pItem->dwDbOffset,
                                    &pbBlob, &nLen) != 0)
    {
        LogRpmzigError("read_header_blob (erase)");
        dwError = ERROR_TDNF_TRANSACTION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    /*
     * Triggers fired BEFORE %preun so real rpm's "$2 = count after
     * this step" semantics see the pre-removal instance count minus
     * one (the engine handles the -1 internally).
     */
    if (!pTdnf->pArgs->nTestOnly)
    {
        dwError = RunTriggers(pbBlob, nLen,
                              TDNF_RPM_TRIGGER_PHASE_TRIGGERUN, "%triggerun",
                              pszNevra, pszInstallRoot, dwTransFlags,
                              nScriptFd, nRedirectToStderr,
                              /*override present*/ 0, /*value*/ 0);
        BAIL_ON_TDNF_ERROR(dwError);

        /* %preun on the erased package (arg1 = 0 for total removal) */
        dwError = RunScriptlet(pbBlob, nLen,
                               TDNF_RPM_SCRIPTLET_PHASE_PREUN, "%preun",
                               pszNevra, pszInstallRoot, dwTransFlags,
                               0, -1, nScriptFd, nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pr_info("Removing: %s\n", pszNevra ? pszNevra : pItem->pszName);

    if (!pTdnf->pArgs->nTestOnly)
    {
        /*
         * File-erase, then rpmdb-row-erase. Leave keep_path_fn NULL
         * so the engine's default rpmdb ownership probe is used.
         */
        memset(&erase_options, 0, sizeof(erase_options));
        erase_options.trans_flags = dwTransFlags;
        erase_options.keep_path_fn = NULL;
        erase_options.keep_path_fn_data = NULL;

        if (tdnf_rpm_erase_hnum(pszInstallRoot, pItem->dwDbOffset,
                                &erase_options) != 0)
        {
            LogRpmzigError("rpm_erase_hnum");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if (tdnf_rpmdb_write_erase_hnum(pszInstallRoot,
                                        pItem->dwDbOffset) != 0)
        {
            LogRpmzigError("rpmdb_write_erase_hnum");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        /* %postun on the erased package (arg1 = 0) */
        dwError = RunScriptlet(pbBlob, nLen,
                               TDNF_RPM_SCRIPTLET_PHASE_POSTUN, "%postun",
                               pszNevra, pszInstallRoot, dwTransFlags,
                               0, -1, nScriptFd, nRedirectToStderr);
        BAIL_ON_TDNF_ERROR(dwError);

        /* %triggerpostun fired AFTER %postun. */
        dwError = RunTriggers(pbBlob, nLen,
                              TDNF_RPM_TRIGGER_PHASE_TRIGGERPOSTUN, "%triggerpostun",
                              pszNevra, pszInstallRoot, dwTransFlags,
                              nScriptFd, nRedirectToStderr,
                              /*override present*/ 0, /*value*/ 0);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    tdnf_rpmdb_blob_free(pbBlob);
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
    PTDNFRPMTS pTS,
    tdnf_rpm_scriptlet_phase phase,
    const char *pszPhaseName,
    const char *pszInstallRoot,
    uint32_t dwTransFlags,
    int nScriptFd,
    int nRedirectToStderr
    )
{
    uint32_t dwError = 0;
    PTDNF_RPM_TS_ITEM pItem = NULL;

    for (pItem = pTS->pTransactionItems; pItem != NULL; pItem = pItem->pNext)
    {
        tdnf_rpm_file *pFile = NULL;
        const unsigned char *pbBlob = NULL;
        size_t nLen = 0;
        int nArg1 = 0;

        if (pItem->nType == TDNF_RPM_TS_ITEM_ERASE)
        {
            continue;
        }
        if (IsNullOrEmptyString(pItem->pszPath))
        {
            continue;
        }

        pFile = tdnf_rpm_file_open(pItem->pszPath);
        if (!pFile)
        {
            LogRpmzigError("rpm_file_open (trans phase)");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            goto error;
        }
        if (tdnf_rpm_file_main_header_blob(pFile, &pbBlob, &nLen) != 0)
        {
            LogRpmzigError("rpm_file_main_header_blob (trans phase)");
            tdnf_rpm_file_close(pFile);
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            goto error;
        }

        nArg1 = NewPkgArg1(pItem->nType);
        dwError = RunScriptlet(pbBlob, nLen, phase, pszPhaseName,
                               pItem->pszName, pszInstallRoot,
                               dwTransFlags,
                               nArg1, -1, nScriptFd, nRedirectToStderr);
        tdnf_rpm_file_close(pFile);
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
    PTDNF pTdnf
    )
{
    uint32_t dwError = 0;
    PTDNF_RPM_TS_ITEM pItem = NULL;
    const char *pszInstallRoot = NULL;
    uint32_t dwTransFlags = 0;
    uint32_t dwInstallTid = 0;
    uint32_t dwInstallTime = 0;
    FD_t fdScript = NULL;
    int nScriptFd = -1;
    int nRedirectToStderr = 0;

    if (!pTS || !pTdnf || !pTdnf->pArgs || !pTdnf->pConf)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pszInstallRoot = GetInstallRoot(pTdnf);
    dwTransFlags = EffectiveTransFlags(pTS, pTdnf);
    dwInstallTid = (uint32_t)time(NULL);
    dwInstallTime = dwInstallTid;

    /*
     * When JSON output is enabled, redirect scriptlet stdout to
     * stderr so the JSON stream on stdout stays clean. Matches the
     * behaviour in the librpm path (`rpmtsSetScriptFd(fdDup(STDERR_FILENO))`).
     */
    if (pTdnf->pArgs->nJsonOutput)
    {
        fdScript = fdDup(STDERR_FILENO);
        if (fdScript == NULL)
        {
            dwError = ERROR_TDNF_RPMTS_FDDUP_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        nScriptFd = Fileno(fdScript);
        nRedirectToStderr = 1;
    }

    /* Pre-flight: refuse source RPMs — the native install engine does not support them. */
    for (pItem = pTS->pTransactionItems; pItem != NULL; pItem = pItem->pNext)
    {
        if (pItem->pHeader && headerIsSource(pItem->pHeader))
        {
            pr_err("rpmzig-transaction-execute: source RPMs are not "
                   "supported by the native transaction executor\n");
            dwError = ERROR_TDNF_TRANSACTION_FAILED;
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }

    pr_info("Running transaction (rpmzig native executor)\n");

    /* %pretrans pass (skipped in test-only mode by trans_flags). */
    dwError = RunTransPhase(pTS,
                            TDNF_RPM_SCRIPTLET_PHASE_PRETRANS, "%pretrans",
                            pszInstallRoot, dwTransFlags,
                            nScriptFd, nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

    /* Per-item main phase */
    for (pItem = pTS->pTransactionItems; pItem != NULL; pItem = pItem->pNext)
    {
        switch (pItem->nType)
        {
            case TDNF_RPM_TS_ITEM_INSTALL:
            case TDNF_RPM_TS_ITEM_UPGRADE:
            case TDNF_RPM_TS_ITEM_REINSTALL:
                dwError = ProcessInstallItem(pTS, pTdnf, pItem,
                                             dwTransFlags,
                                             dwInstallTid, dwInstallTime,
                                             pszInstallRoot,
                                             nScriptFd, nRedirectToStderr);
                BAIL_ON_TDNF_ERROR(dwError);
                break;

            case TDNF_RPM_TS_ITEM_ERASE:
                dwError = ProcessEraseItem(pTS, pTdnf, pItem,
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

    /* %posttrans pass */
    dwError = RunTransPhase(pTS,
                            TDNF_RPM_SCRIPTLET_PHASE_POSTTRANS, "%posttrans",
                            pszInstallRoot, dwTransFlags,
                            nScriptFd, nRedirectToStderr);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    if (fdScript)
    {
        Fclose(fdScript);
    }
    return dwError;

error:
    goto cleanup;
}

/* Silence -Wunused-function warnings for reserved conflict/keep hooks. */
static void
TDNFTouchNativeCallbacks(void)
{
    (void)NativeInstallConflict;
    (void)NativeEraseKeepPath;
}

static void __attribute__((constructor))
TDNFRefRpmzigNative(void)
{
    TDNFTouchNativeCallbacks();
}
