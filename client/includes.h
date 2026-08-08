/*
 * Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#ifndef __CLIENT_INCLUDES_H__
#define __CLIENT_INCLUDES_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <ftw.h>
#include <time.h>
#include <utime.h>
#include <fnmatch.h>
#include <libgen.h>
#include <ctype.h>
#include <limits.h>
#include <sys/file.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/types.h>

#include <dirent.h>

#include <tdnf.h>
#include <tdnfrpmconfig.h>
#include <tdnfrepomd.h>
#include <tdnf-common-defines.h>

#include "../rpmzig/rpmdb.h"
#include "repoutils_abi.h"
#include "remoterepo_abi.h"

/* Every C file in client/ uses the native package context. The
   libsolv-confinement-audit build step proves libsolv headers are
   unreachable here. */
/* Every module that compiles client/ must declare whether libsolv headers
   are in scope for it, and exactly one answer is allowed.
   libsolv-confinement-audit declares OUT_OF_SCOPE and is the module that
   proves the claim. libtdnf and the two plugins declare IN_SCOPE: they no
   longer add libsolv's include paths at all, but they are built for the
   native target, where a host libsolv-devel is reachable through
   /usr/include, so they assert nothing.

   Requiring the declaration is what makes the negative control below fail
   closed: deleting the audit's -D would otherwise disarm the control
   silently, which is the same class of fault as the audit passing
   vacuously. */
#if defined(TDNF_CLIENT_LIBSOLV_IN_SCOPE) == \
    defined(TDNF_CLIENT_LIBSOLV_OUT_OF_SCOPE)
#  error "define exactly one of TDNF_CLIENT_LIBSOLV_IN_SCOPE / _OUT_OF_SCOPE"
#endif

/* The negative control. libsolv-confinement-audit compiles this file's
   consumers with libsolv's include paths absent -- but "absent" is only
   meaningful if libsolv is not reachable some other way, e.g. from the
   host's /usr/include, where libsolv-devel is a normal build dependency on
   the distributions tdnf targets. Without this the audit could pass while
   proving nothing. Compiled inside the audited module, it sees the
   configuration under test by construction, whether the header arrives by
   include path, cflag or environment. What it cannot do is generalise over
   *names*: each probe below has to name a header, so the set of spellings
   is the limit of what it proves.

   Two probes, because they fail differently. Reachability asks whether a
   libsolv header can be found by name, and has to name every spelling this
   build makes one reachable under: libsolv is handed to its consumers both
   as <solv/pool.h> and, via libsolv_flat_include, as the flat <pool.h>, and
   the quoted forms search -iquote and the includer's directory, which
   __has_include(<...>) does not consult. libsolvext is a third, separate
   tree holding solv_xfopen.h, testcase.h and tools_util.h -- no pool.h and
   no pooltypes.h -- so it needs naming of its own. pooltypes.h and
   solv_xfopen.h are distinctive enough to probe unqualified; pool.h and
   queue.h are not. Presence asks whether a
   libsolv header is already in scope, which catches routes that need no
   search at all -- -include on the command line being the obvious one. Its
   macro set covers the core headers that do not drag in pooltypes.h
   transitively (bitmap, knownid, solvversion, util) plus the two guarded
   ext ones; testcase.h has no guard of its own but includes pool.h. */
#ifdef TDNF_CLIENT_LIBSOLV_OUT_OF_SCOPE
#  if !defined(__has_include)
#    error "libsolv-confinement-audit needs __has_include to check itself"
#  elif __has_include(<solv/pool.h>) || __has_include("solv/pool.h") || \
        __has_include(<solv/pooltypes.h>) || __has_include("solv/pooltypes.h") || \
        __has_include(<pooltypes.h>) || __has_include("pooltypes.h") || \
        __has_include(<solv/solv_xfopen.h>) || __has_include("solv/solv_xfopen.h") || \
        __has_include(<solv_xfopen.h>) || __has_include("solv_xfopen.h")
#    error "libsolv is reachable from client/; the confinement audit would prove nothing"
#  endif
#  if defined(LIBSOLV_POOL_H) || defined(LIBSOLV_POOLTYPES_H) || \
      defined(LIBSOLV_QUEUE_H) || defined(LIBSOLV_SOLVER_H) || \
      defined(LIBSOLV_BITMAP_H) || defined(LIBSOLV_KNOWNID_H) || \
      defined(LIBSOLV_SOLVVERSION_H) || defined(LIBSOLV_UTIL_H) || \
      defined(SOLV_XFOPEN_H) || defined(LIBSOLV_TOOLS_UTIL_H)
#    error "a libsolv header is already in scope in client/; the confinement audit would prove nothing"
#  endif
#endif

#include "../common/defines.h"
#include "../common/config.h"
#include "../common/structs.h"
#include "../common/prototypes.h"
#include "../history/history.h"
#include "package_context.h"

#include "defines.h"
#include "builtin_plugins.h"
#include "transaction_plan_capture_abi.inc"
#include "structs.h"
#include "history_abi.inc"
#include "prototypes.h"

#include "config.h"

#endif /* __CLIENT_INCLUDES_H__ */
