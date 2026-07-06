/*
 * Copyright (C) 2022-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU General Public License v2 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "jsondump.h"

__attribute__((format(printf, 1, 0)))
static char *alloc_vsprintf(const char *fmt, va_list ap)
{
    int size = 0;
    char *p = NULL;
    va_list aq;

    va_copy(aq, ap);

    size = vsnprintf(p, size, fmt, ap);
    if (size < 0)
        goto err;

    size++;
    p = calloc(size, sizeof(char));
    if (p == NULL)
        goto err;

    size = vsnprintf(p, size, fmt, aq);
    if (size < 0)
        goto err;

    va_end(aq);
    return p;

err:
    if (p)
        free(p);
    va_end(aq);
    return NULL;
}

int jd_map_add_fmt(struct json_dump *jd, const char *key, const char *format, ...)
{
    va_list args;
    char *buf;
    int rc;

    va_start(args, format);
    buf = alloc_vsprintf(format, args);
    va_end(args);

    if (buf == NULL)
        return -1;

    rc = jd_map_add_string(jd, key, buf);

    free(buf);

    return rc;
}

int jd_list_add_fmt(struct json_dump *jd, const char *format, ...)
{
    va_list args;
    char *buf;
    int rc;

    va_start(args, format);
    buf = alloc_vsprintf(format, args);
    va_end(args);

    if (buf == NULL)
        return -1;

    rc = jd_list_add_string(jd, buf);

    free(buf);

    return rc;
}
