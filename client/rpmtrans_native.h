/*
 * Copyright (C) 2015-2026 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

/*
 * Composed rpmzig transaction executor.
 *
 * `TDNFRunTransaction` in `rpmtrans.c` dispatches here (after native
 * ordering + check) to apply the transaction using the five
 * standalone rpmzig engines (#109 file install, #110 sqlite rpmdb
 * write, #111 file erase, #112 shell scriptlets, #113 triggers).
 *
 * This is the sole transaction-execution path; the former rollback
 * implementation and its build switch have been removed.
 */

#pragma once

#include "structs.h"
#include "prototypes.h"

/*
 * Execute `pPlan` against the retained verified handles and erase metadata in
 * `pTS`. The plan must come directly from the native verified solver.
 *
 * Returns 0 on success, or a tdnf error code on failure.
 */
uint32_t
TDNFRunTransactionNative(
    PTDNFRPMTS pTS,
    PTDNF pTdnf,
    const TDNF_REPOMD_NATIVE_TRANSACTION_PLAN *pPlan
    );
