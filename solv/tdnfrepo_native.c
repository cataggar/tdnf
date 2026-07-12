#include "includes.h"

uint32_t
SolvReadYumRepoNative(
    Repo *pRepo,
    const char *pszRepomd,
    const char *pszPrimary,
    const char *pszFilelists,
    const char *pszUpdateinfo,
    const char *pszOther
    )
{
    return TDNFRepoMdNativeLoadSolvRepo(
               pRepo,
               pszRepomd,
               pszPrimary,
               pszFilelists,
               pszUpdateinfo,
               pszOther);
}

uint32_t
SolvReadInstalledRpmsNative(
    Repo* pRepo,
    const char *pszRootDir,
    int dwFlags
    )
{
    uint32_t dwError = 0;

    if(!pRepo)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    dwError = TDNFRepoMdNativeLoadInstalledSolvRepo(pRepo, pszRootDir, dwFlags);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
SolvAddRpmNative(
    Repo *pRepo,
    const char *pszPath,
    int dwFlags,
    Id *pdwSolvableId
    )
{
    uint32_t dwError = 0;
    uint32_t dwSolvableId = 0;

    if(pdwSolvableId)
    {
        *pdwSolvableId = 0;
    }

    if(!pRepo || IsNullOrEmptyString(pszPath))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);
    }

    dwError = TDNFRepoMdNativeAddRpm(pRepo, pszPath, dwFlags, &dwSolvableId);
    BAIL_ON_TDNF_LIBSOLV_ERROR(dwError);

    if(pdwSolvableId)
    {
        *pdwSolvableId = (Id)dwSolvableId;
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}
