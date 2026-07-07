/*
 * Copyright (C) 2019-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

FILE *
TDNFLogGetStream(
    int32_t loglevel
    );

/*
 * Keep the variadic boundary in C. The Zig backend decides whether a message
 * should be emitted and which stream to target.
 */
void
log_console(
    int32_t loglevel,
    const char *format,
    ...
    )
{
    va_list args;
    FILE *stream = NULL;

    if (!format)
    {
        return;
    }

    stream = TDNFLogGetStream(loglevel);
    if (!stream)
    {
        return;
    }

    va_start(args, format);
    vfprintf(stream, format, args);
    fflush(stream);
    va_end(args);
}
