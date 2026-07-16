/*
 * Copyright (C) 2026 VMware, Inc. All Rights Reserved.
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

typedef uint32_t TDNF_RPMTRANS_FLAGS;

#define TDNF_RPMTRANS_FLAG_NONE              UINT32_C(0x00000000)
#define TDNF_RPMTRANS_FLAG_TEST              UINT32_C(0x00000001)
#define TDNF_RPMTRANS_FLAG_NOSCRIPTS         UINT32_C(0x00000004)
#define TDNF_RPMTRANS_FLAG_JUSTDB            UINT32_C(0x00000008)
#define TDNF_RPMTRANS_FLAG_NOTRIGGERS        UINT32_C(0x00000010)
#define TDNF_RPMTRANS_FLAG_NODOCS            UINT32_C(0x00000020)
#define TDNF_RPMTRANS_FLAG_ALLFILES          UINT32_C(0x00000040)
#define TDNF_RPMTRANS_FLAG_NOPLUGINS         UINT32_C(0x00000080)
#define TDNF_RPMTRANS_FLAG_NOCONTEXTS        UINT32_C(0x00000100)
#define TDNF_RPMTRANS_FLAG_NOCAPS            UINT32_C(0x00000200)
#define TDNF_RPMTRANS_FLAG_NODB              UINT32_C(0x00000400)
#define TDNF_RPMTRANS_FLAG_NOTRIGGERPREIN    UINT32_C(0x00010000)
#define TDNF_RPMTRANS_FLAG_NOPRE             UINT32_C(0x00020000)
#define TDNF_RPMTRANS_FLAG_NOPOST            UINT32_C(0x00040000)
#define TDNF_RPMTRANS_FLAG_NOTRIGGERIN       UINT32_C(0x00080000)
#define TDNF_RPMTRANS_FLAG_NOTRIGGERUN       UINT32_C(0x00100000)
#define TDNF_RPMTRANS_FLAG_NOPREUN           UINT32_C(0x00200000)
#define TDNF_RPMTRANS_FLAG_NOPOSTUN          UINT32_C(0x00400000)
#define TDNF_RPMTRANS_FLAG_NOTRIGGERPOSTUN   UINT32_C(0x00800000)
#define TDNF_RPMTRANS_FLAG_NOPRETRANS        UINT32_C(0x01000000)
#define TDNF_RPMTRANS_FLAG_NOPOSTTRANS       UINT32_C(0x02000000)
#define TDNF_RPMTRANS_FLAG_NOMD5             UINT32_C(0x08000000)
#define TDNF_RPMTRANS_FLAG_NOFILEDIGEST      UINT32_C(0x08000000)
#define TDNF_RPMTRANS_FLAG_NOARTIFACTS       UINT32_C(0x20000000)
#define TDNF_RPMTRANS_FLAG_NOCONFIGS         UINT32_C(0x40000000)
#define TDNF_RPMTRANS_FLAG_DEPLOOPS          UINT32_C(0x80000000)

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(TDNF_RPMTRANS_FLAGS) == 4, "transaction flags must be uint32");
static_assert(TDNF_RPMTRANS_FLAG_TEST == (UINT32_C(1) << 0), "TEST flag value changed");
static_assert(TDNF_RPMTRANS_FLAG_NOPLUGINS == (UINT32_C(1) << 7), "NOPLUGINS flag value changed");
static_assert(TDNF_RPMTRANS_FLAG_NOFILEDIGEST == (UINT32_C(1) << 27), "NOFILEDIGEST flag value changed");
static_assert(TDNF_RPMTRANS_FLAG_DEPLOOPS == (UINT32_C(1) << 31), "DEPLOOPS flag value changed");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(TDNF_RPMTRANS_FLAGS) == 4, "transaction flags must be uint32");
_Static_assert(TDNF_RPMTRANS_FLAG_TEST == (UINT32_C(1) << 0), "TEST flag value changed");
_Static_assert(TDNF_RPMTRANS_FLAG_NOPLUGINS == (UINT32_C(1) << 7), "NOPLUGINS flag value changed");
_Static_assert(TDNF_RPMTRANS_FLAG_NOFILEDIGEST == (UINT32_C(1) << 27), "NOFILEDIGEST flag value changed");
_Static_assert(TDNF_RPMTRANS_FLAG_DEPLOOPS == (UINT32_C(1) << 31), "DEPLOOPS flag value changed");
#endif

#ifdef __cplusplus
}
#endif
