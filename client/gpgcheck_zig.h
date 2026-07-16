/* Internal header for the parsed-file rpmzig integrity bridge. */
#ifndef _TDNF_CLIENT_GPGCHECK_ZIG_H_
#define _TDNF_CLIENT_GPGCHECK_ZIG_H_

#include <stddef.h>

#include "../rpmzig/rpmdb.h"

#ifdef __cplusplus
extern "C" {
#endif

int TDNFRpmzigVerify(
    const char *pszPkgPath,
    const char *pszKeyPath,
    const char *pszInstallRoot,
    int *pnStatus
);

/*
 * Verify all package-signature candidates on an already parsed native RPM
 * file.  The configured rpmdb trust set and every user-approved fresh key
 * are collected before the one final verifier invocation.
 *
 * On a successful ABI call returns 0 and writes a
 * TDNF_RPMZIG_INTEGRITY_* value to *out_status.  Returns -1 for rpmdb or
 * allocation failures before an integrity outcome is available.
 */
int TDNFRpmzigVerifyFile(
    tdnf_rpm_file *pRpmFile,
    const tdnf_rpm_config *pRpmConfig,
    const void *const *ppFreshKeys,
    const size_t *pnFreshKeyLengths,
    size_t nFreshKeyCount,
    int *out_status
);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_CLIENT_GPGCHECK_ZIG_H_ */
