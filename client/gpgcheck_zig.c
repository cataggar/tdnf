/*
 * The C package-checker keeps error-code policy and user interaction.  This
 * narrow bridge owns no files or buffers: rpmzig receives the parsed file
 * handle, configuration, and complete fresh key set directly.
 */

#include "includes.h"

#include "../rpmzig/verify.h"
#include "gpgcheck_zig.h"

static int
SlurpKey(
    const char *pszPath,
    unsigned char **ppKey,
    size_t *pnKeyLength
    );

int
TDNFRpmzigVerify(
    const char *pszPkgPath,
    const char *pszKeyPath,
    const char *pszInstallRoot,
    int *pnStatus
    )
{
    tdnf_rpm_file *pFile = NULL;
    unsigned char *pFreshKey = NULL;
    size_t nFreshKeyLength = 0;
    tdnf_rpmdb_pubkeys_iter *pIter = NULL;
#define MAX_RPMDB_KEYS 128
    char *ppRpmDbKeys[MAX_RPMDB_KEYS] = {0};
    size_t pnRpmDbKeyLengths[MAX_RPMDB_KEYS] = {0};
    size_t nRpmDbCount = 0;
    const void *ppKeys[MAX_RPMDB_KEYS + 1] = {0};
    size_t pnKeyLengths[MAX_RPMDB_KEYS + 1] = {0};
    size_t nKeyCount = 0;
    int nStatus = TDNF_RPMZIG_STATUS_INTERNAL_ERROR;
    int nResult = 0;
    size_t i = 0;

    if(!pszPkgPath || !pszKeyPath || !pnStatus)
    {
        return -1;
    }

    pFile = tdnf_rpm_file_open(pszPkgPath);
    if(!pFile)
    {
        pr_err("rpmzig: open %s: %s\n",
               pszPkgPath,
               tdnf_rpmdb_last_error());
        return -1;
    }

    if(SlurpKey(pszKeyPath, &pFreshKey, &nFreshKeyLength) != 0)
    {
        pr_err("rpmzig: read key %s failed\n", pszKeyPath);
        tdnf_rpm_file_close(pFile);
        return -1;
    }

    pIter = tdnf_rpmdb_pubkeys_open(pszInstallRoot);
    if(pIter)
    {
        while(nRpmDbCount < MAX_RPMDB_KEYS)
        {
            char *pKey = NULL;
            size_t nKeyLength = 0;
            int nNext = tdnf_rpmdb_pubkeys_next(
                            pIter,
                            &pKey,
                            &nKeyLength,
                            NULL);
            if(nNext == 0)
            {
                break;
            }
            if(nNext < 0)
            {
                pr_err("rpmzig: rpmdb pubkey walk: %s\n",
                       tdnf_rpmdb_last_error());
                break;
            }
            ppRpmDbKeys[nRpmDbCount] = pKey;
            pnRpmDbKeyLengths[nRpmDbCount] = nKeyLength;
            nRpmDbCount++;
        }
        tdnf_rpmdb_pubkeys_close(pIter);
    }

    for(i = 0; i < nRpmDbCount; i++)
    {
        ppKeys[nKeyCount] = ppRpmDbKeys[i];
        pnKeyLengths[nKeyCount] = pnRpmDbKeyLengths[i];
        nKeyCount++;
    }
    ppKeys[nKeyCount] = pFreshKey;
    pnKeyLengths[nKeyCount] = nFreshKeyLength;
    nKeyCount++;

    (void)tdnf_rpmzig_verify_pure(
              pFile,
              ppKeys,
              pnKeyLengths,
              nKeyCount,
              &nStatus);

    *pnStatus = nStatus;
    nResult = nStatus == TDNF_RPMZIG_STATUS_OK ? 0 : 1;

    for(i = 0; i < nRpmDbCount; i++)
    {
        tdnf_rpmdb_string_free(ppRpmDbKeys[i]);
    }
    free(pFreshKey);
    tdnf_rpm_file_close(pFile);
    return nResult;
#undef MAX_RPMDB_KEYS
}

int
TDNFRpmzigVerifyFile(
    tdnf_rpm_file *pRpmFile,
    const tdnf_rpm_config *pRpmConfig,
    const void *const *ppFreshKeys,
    const size_t *pnFreshKeyLengths,
    size_t nFreshKeyCount,
    int *out_status)
{
    return tdnf_rpm_file_verify_signatures_config(
               pRpmFile,
               pRpmConfig,
               ppFreshKeys,
               pnFreshKeyLengths,
               nFreshKeyCount,
               out_status);
}

static int
SlurpKey(
    const char *pszPath,
    unsigned char **ppKey,
    size_t *pnKeyLength
    )
{
    FILE *pFile = NULL;
    long nLength = 0;
    unsigned char *pKey = NULL;

    pFile = fopen(pszPath, "rb");
    if(!pFile)
    {
        return -1;
    }
    if(fseek(pFile, 0, SEEK_END) != 0)
    {
        fclose(pFile);
        return -1;
    }
    nLength = ftell(pFile);
    if(nLength < 0)
    {
        fclose(pFile);
        return -1;
    }
    rewind(pFile);
    pKey = malloc((size_t)nLength);
    if(!pKey)
    {
        fclose(pFile);
        return -1;
    }
    if(fread(pKey, 1, (size_t)nLength, pFile) != (size_t)nLength)
    {
        free(pKey);
        fclose(pFile);
        return -1;
    }
    fclose(pFile);
    *ppKey = pKey;
    *pnKeyLength = (size_t)nLength;
    return 0;
}
