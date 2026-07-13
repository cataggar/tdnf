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
 * When the tdnf shared library is built with
 * `-Drpmzig-transaction-execute=true`, `TDNFRunTransaction` in
 * `rpmtrans.c` dispatches here (after native ordering + check) to
 * apply the transaction using the five standalone rpmzig engines
 * (#109 file install, #110 sqlite rpmdb write, #111 file erase,
 * #112 shell scriptlets, #113 triggers) instead of calling
 * librpm's `rpmtsRun`.
 *
 * This is opt-in and gated by `TDNF_RPMZIG_TRANSACTION_EXECUTE`; the
 * default build still runs librpm's transaction execution loop.
 */

#pragma once

#ifdef TDNF_RPMZIG_TRANSACTION_EXECUTE

#include "structs.h"
#include "prototypes.h"

/*
 * Execute the ordered transaction items on `pTS` using the rpmzig
 * native engines. `pTS->pTransactionItems` must already be populated
 * and reordered by `TDNFNativeOrderAndCheck` before this is called.
 *
 * Returns 0 on success, or a tdnf error code on failure.
 */
uint32_t
TDNFRunTransactionNative(
    PTDNFRPMTS pTS,
    PTDNF pTdnf
    );

#endif /* TDNF_RPMZIG_TRANSACTION_EXECUTE */
