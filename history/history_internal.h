/*
 * Copyright (C) 2022 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#pragma once

#include <sqlite3.h>

#include "history.h"

struct history_ctx
{
    sqlite3 *db;
    int *installed_ids; /* installed ids must be sorted */
    int installed_count;
    char *cookie;
    int trans_id;
};
