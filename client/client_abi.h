/*
 * Copyright (C) 2026 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#pragma once

#include <tdnftypes.h>
#include <tdnfdownload.h>
#include <tdnfrepomd.h>
#include <tdnfrpmconfig.h>

#include "../rpmzig/rpmdb.h"

typedef struct _TDNF_ID_LIST TDNF_ID_LIST, *PTDNF_ID_LIST;

#include "package_context.h"
#include "transaction_plan_capture_abi.inc"
#include "structs.h"
#include "../llconf/nodes.h"
