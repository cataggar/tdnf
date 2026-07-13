/*
 * Copyright (C) 2022-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

#define ASSERT_ARG(x) { \
    if (!(x)) { \
        dwError = ERROR_TDNF_INVALID_PARAMETER; \
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError); \
    } \
}

#define ASSERT_MEM(x) { \
    if (!(x)) { \
        dwError = ERROR_TDNF_OUT_OF_MEMORY; \
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError); \
    } \
}

uint32_t
SolvRequiresFromQueue(
    Pool *pool,
    Queue *pq_pkgs,  /* solvable ids */
    Queue *pq_deps   /* string ids */
)
{
    uint32_t dwError = 0;
    int i,j;

    for (i = 0; i < pq_pkgs->count; i++) {
        Queue q_tmp = {0};
        Solvable *p_solv = pool_id2solvable(pool, pq_pkgs->elements[i]);
        solvable_lookup_deparray(p_solv, SOLVABLE_REQUIRES, &q_tmp, -1);
        for(j = 0; j < q_tmp.count; j++) {
            queue_pushunique(pq_deps, q_tmp.elements[j]);
        }
        queue_free(&q_tmp);
    }
    return dwError;
}
