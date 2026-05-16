/*
 * tdnf rpmdb (Zig) — C ABI for the read-only Zig rpmdb reader.
 *
 * This is T1 of the librpm-replacement plan (see
 * plan-replace-librpm.md in the session-state archive). The
 * implementation lives in rpmzig/rpmdb.zig and is linked into
 * libtdnf and tdnf-rpmdb-count.
 *
 * The first iteration exposes only a row count over the Packages
 * table. PR #2 will add an iterator over decoded RPM headers and
 * replace the rpmdb walk in history/history.c.
 */
#ifndef _TDNF_RPMZIG_RPMDB_H_
#define _TDNF_RPMZIG_RPMDB_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Count rows in /var/lib/rpm/rpmdb.sqlite's Packages table.
 *
 * `root` is the install-root prefix (matches rpm's --root). Pass NULL
 * or "" for "/".
 *
 * Returns the row count on success, or -1 on error. Use
 * tdnf_rpmdb_last_error() to retrieve the error message.
 */
int64_t tdnf_rpmdb_count_packages(const char *root);

/**
 * Returns the last error message produced by any rpmzig call on the
 * current thread. The returned pointer is stable until the next call
 * into rpmzig. Returns an empty string when no error is pending.
 */
const char *tdnf_rpmdb_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_RPMZIG_RPMDB_H_ */
