/*
 * Internal header for the rpmzig sig-verify entry point. Both
 * gpgcheck.c (caller) and gpgcheck_zig.c (definition) include this.
 * Pulled in only when libtdnf was built with -Drpmzig-verify=true.
 */
#ifndef _TDNF_CLIENT_GPGCHECK_ZIG_H_
#define _TDNF_CLIENT_GPGCHECK_ZIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Verify the GPG signature on `pkg_path` using rpmzig + gpgme,
 * with a keyring built from:
 *   - every gpg-pubkey-* entry in the rpmdb under `install_root`
 *     (NULL/"" → "/"), and
 *   - the armored ASCII key in `key_path` (the fresh repo key
 *     tdnf just fetched).
 *
 * On success writes a TDNF_RPMZIG_VERIFY_* status into *out_status
 * (0 = OK, 1 = NO_SIG, 2 = NO_KEY, 3 = BAD, 4 = GPGME_ERROR).
 * Returns 0 if *out_status == OK, non-zero otherwise (the value
 * itself is implementation-defined; callers should branch on
 * *out_status).
 *
 * Returns -1 on an unexpected I/O error before verification could
 * be attempted; in that case *out_status is left unchanged.
 */
int TDNFRpmzigVerify(
    const char *pkg_path,
    const char *key_path,
    const char *install_root,
    int *out_status
);

#ifdef __cplusplus
}
#endif

#endif /* _TDNF_CLIENT_GPGCHECK_ZIG_H_ */
