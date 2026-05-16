/*
 * Internal header for the rpmzig cross-check shim. Both gpgcheck.c
 * (caller) and gpgcheck_zig.c (definition) include this. Pulled in
 * only when libtdnf was built with -Drpmzig-verify=true.
 */
#ifndef _TDNF_CLIENT_GPGCHECK_ZIG_H_
#define _TDNF_CLIENT_GPGCHECK_ZIG_H_

#ifdef __cplusplus
extern "C" {
#endif

int TDNFRpmzigCrossCheck(
    const char *pkg_path,
    const char *key_path,
    int librpm_ok
);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_CLIENT_GPGCHECK_ZIG_H_ */
