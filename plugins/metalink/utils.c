/*
 * Copyright (C) 2021-2023 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

#define MIN_URL_LENGTH  4
#define ATTR_NAME       (char*)"name"
#define ATTR_PROTOCOL   (char*)"protocol"
#define ATTR_TYPE       (char*)"type"
#define ATTR_LOCATION   (char*)"location"
#define ATTR_PREFERENCE (char*)"preference"
#define ATTR_PRIORITY   (char*)"priority"

static int hashTypeComparator(const void * p1, const void * p2)
{
    return strcmp(*((const char **)p1), *((const char **)p2));
}

typedef struct _TDNF_METALINK_CALLBACK_CONTEXT
{
    TDNF_ML_CTX  *ml_ctx;
    const char   *filename;
} TDNF_METALINK_CALLBACK_CONTEXT;

struct MetalinkElementInfo {
    uint32_t     dwError;
    TDNF_METALINK_CALLBACK_CONTEXT  cbCtx;
    const char   *startElement;
    const char   *endElement;
    const char   **attributes;
};

static int
TDNFGetResourceType(
    const char *resource_type,
    int *type
    )
{
    uint32_t dwError = 0;
    static _Bool sorted;
    const hash_type *currHash = NULL;

    if (IsNullOrEmptyString(resource_type) ||
       !type)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if(!sorted)
    {
        qsort(hashType, sizeOfStruct(hashType), sizeof(*hashType), hashTypeComparator);
        sorted = 1;
    }

    currHash = bsearch(&resource_type, hashType, sizeOfStruct(hashType),
                       sizeof(*hashType), hashTypeComparator);

    /* In case metalink file have resource type which we
     * do not support yet, we should not report error.
     * We should instead skip and verify the hash for the
     * supported resource type.
     */
    if(!currHash)
    {
        *type = -1;
    }
    else
    {
        *type = currHash->hash_value;
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFCheckRepoMDFileHashFromMetalink(
    const char *pszFile,
    TDNF_ML_CTX *ml_ctx
    )
{
    uint32_t dwError = 0;
    TDNF_ML_HASH_LIST *hashList = NULL;
    unsigned char digest[TDNF_MAX_DIGEST_LEN] = {0};
    int hash_Type = -1;
    TDNF_ML_HASH_INFO *currHashInfo = NULL;

    if(IsNullOrEmptyString(pszFile) ||
       !ml_ctx)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    /* find best (highest) available hash type */
    for(hashList = ml_ctx->hashes; hashList; hashList = hashList->next)
    {
        int currHashType = TDNF_HASH_SENTINEL;
        currHashInfo = hashList->data;

        if(currHashInfo == NULL)
        {
            dwError = ERROR_TDNF_INVALID_REPO_FILE;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        dwError = TDNFGetResourceType(currHashInfo->type, &currHashType);
        BAIL_ON_TDNF_ERROR(dwError);

        if (hash_Type < currHashType)
            hash_Type = currHashType;
    }

    if (hash_Type < 0) {
        /* no hash type was found */
        dwError = ERROR_TDNF_INVALID_REPO_FILE;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    /* otherwise hash_Type is the best one */

    /* now check for all best hash types. Test until one succeeds
       or until we run out */
    for(hashList = ml_ctx->hashes; hashList; hashList = hashList->next)
    {
        int currHashType = TDNF_HASH_SENTINEL;
        currHashInfo = hashList->data;

        dwError = TDNFGetResourceType(currHashInfo->type, &currHashType);
        BAIL_ON_TDNF_ERROR(dwError);

        /* filter for our best type and also check that the value is valid */
        if (hash_Type == currHashType &&
            TDNFCheckHexDigest(currHashInfo->value, hash_ops[currHashType].length)) {
            dwError = TDNFChecksumFromHexDigest(currHashInfo->value, digest);
            BAIL_ON_TDNF_ERROR(dwError);

            dwError = TDNFCheckHash(pszFile, digest, hash_Type);
            if (dwError != 0 && dwError != ERROR_TDNF_CHECKSUM_VALIDATION_FAILED) {
                BAIL_ON_TDNF_ERROR(dwError);
            }
            if (dwError == 0)
                break;
        }
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static void
TDNFMetalinkHashFree(
    void *pData
    )
{
    TDNF_ML_HASH_INFO *ml_hash_info = pData;

    if (!ml_hash_info)
    {
        return;
    }

    TDNF_SAFE_FREE_MEMORY(ml_hash_info->type);
    TDNF_SAFE_FREE_MEMORY(ml_hash_info->value);
    TDNF_SAFE_FREE_MEMORY(ml_hash_info);
}

static void
TDNFMetalinkUrlFree(
    void *pData
    )
{
    TDNF_ML_URL_INFO *ml_url_info = pData;

    if (!ml_url_info)
    {
        return;
    }

    TDNF_SAFE_FREE_MEMORY(ml_url_info->protocol);
    TDNF_SAFE_FREE_MEMORY(ml_url_info->type);
    TDNF_SAFE_FREE_MEMORY(ml_url_info->location);
    TDNF_SAFE_FREE_MEMORY(ml_url_info->url);
    TDNF_SAFE_FREE_MEMORY(ml_url_info);
}

static uint32_t
TDNFMetalinkAllocateStringBuffer(
    const char *pszBuffer,
    size_t nBufferLength,
    char **ppszValue
    )
{
    uint32_t dwError = 0;
    char *pszValue = NULL;

    if (!pszBuffer || !ppszValue)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(nBufferLength + 1, sizeof(char), (void **)&pszValue);
    BAIL_ON_TDNF_ERROR(dwError);

    if (nBufferLength > 0)
    {
        memcpy(pszValue, pszBuffer, nBufferLength);
    }
    pszValue[nBufferLength] = '\0';

    *ppszValue = pszValue;

cleanup:
    return dwError;
error:
    TDNF_SAFE_FREE_MEMORY(pszValue);
    if (ppszValue)
    {
        *ppszValue = NULL;
    }
    goto cleanup;
}

static uint32_t
TDNFMetalinkParseFileName(
    TDNF_METALINK_CALLBACK_CONTEXT *pCbCtx,
    const char *pszName
    )
{
    uint32_t dwError = 0;

    if (!pCbCtx || !pCbCtx->ml_ctx || IsNullOrEmptyString(pCbCtx->filename) ||
        IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (strcmp(pszName, pCbCtx->filename))
    {
        pr_err("%s: Invalid filename from metalink file:%s", __func__, pszName);
        dwError = ERROR_TDNF_METALINK_PARSER_INVALID_FILE_NAME;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (pCbCtx->ml_ctx->filename != NULL)
    {
        if (strcmp(pCbCtx->ml_ctx->filename, pszName))
        {
            dwError = ERROR_TDNF_METALINK_PARSER_INVALID_FILE_NAME;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        goto cleanup;
    }

    dwError = TDNFAllocateString(pszName, &pCbCtx->ml_ctx->filename);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
TDNFMetalinkParseSizeValue(
    TDNF_ML_CTX *ml_ctx,
    const char *pszValue,
    size_t nValueLength
    )
{
    uint32_t dwError = 0;
    char size_buf[12];
    char *p = size_buf;
    const char *q = pszValue;

    if (!ml_ctx || !pszValue)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    while ((size_t)(q - pszValue) < nValueLength &&
           p < size_buf + sizeof(size_buf) - 1 &&
           isdigit((unsigned char)*q))
    {
        *p++ = *q++;
    }
    *p = 0;

    if (!size_buf[0])
    {
        dwError = ERROR_TDNF_METALINK_PARSER_MISSING_FILE_SIZE;
        pr_err("XML Parser Error: file size is missing: '%s'", size_buf);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ml_ctx->size = strtoi(size_buf);

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
TDNFMetalinkNormalizeUrlPreference(
    const char *pszRankingValue,
    bool bRankingIsPriority,
    int *pnPreference
    )
{
    uint32_t dwError = 0;
    const char *pszRankingName = bRankingIsPriority ? ATTR_PRIORITY : ATTR_PREFERENCE;

    if (!pnPreference)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    *pnPreference = 0;
    if (IsNullOrEmptyString(pszRankingValue))
    {
        goto cleanup;
    }

    if (bRankingIsPriority)
    {
        long nPriority = 0;

        if (sscanf(pszRankingValue, "%ld", &nPriority) != 1)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            pr_err("XML Parser Warning: %s is invalid value: %s\n",
                   pszRankingName, pszRankingValue);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if (nPriority <= 0 || nPriority >= INT_MAX)
        {
            dwError = ERROR_TDNF_METALINK_PARSER_MISSING_URL_ATTR;
            pr_err("XML Parser Warning: Bad value (\"%s\") of \"%s\""
                   "attribute in url element (should be in range 1-%d)",
                   pszRankingValue, pszRankingName, INT_MAX - 1);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        *pnPreference = INT_MAX - (int)nPriority;
    }
    else
    {
        int nPreference = 0;

        if (sscanf(pszRankingValue, "%d", &nPreference) != 1)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            pr_err("XML Parser Warning: %s is invalid value: %s\n",
                   pszRankingName, pszRankingValue);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        if (nPreference < 0 || nPreference > 100)
        {
            dwError = ERROR_TDNF_METALINK_PARSER_MISSING_URL_ATTR;
            pr_err("XML Parser Warning: Bad value (\"%s\") of \"%s\""
                   "attribute in url element (should be in range 0-100)",
                   pszRankingValue, pszRankingName);
            BAIL_ON_TDNF_ERROR(dwError);
        }

        *pnPreference = nPreference;
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
TDNFMetalinkParseHashValue(
    TDNF_ML_CTX *ml_ctx,
    const char *pszType,
    const char *pszValue,
    size_t nValueLength
    )
{
    uint32_t dwError = 0;
    char *pszHashValue = NULL;
    TDNF_ML_HASH_INFO *ml_hash_info = NULL;

    if (!ml_ctx || IsNullOrEmptyString(pszType) || !pszValue)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_ML_HASH_INFO), (void**)&ml_hash_info);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateString(pszType, &ml_hash_info->type);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFMetalinkAllocateStringBuffer(pszValue, nValueLength, &pszHashValue);
    BAIL_ON_TDNF_ERROR(dwError);

    if (IsNullOrEmptyString(pszHashValue))
    {
        dwError = ERROR_TDNF_METALINK_PARSER_MISSING_HASH_CONTENT;
        pr_err("XML Parser Error:HASH value is not present in HASH element");
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ml_hash_info->value = pszHashValue;
    pszHashValue = NULL;

    dwError = TDNFAppendList(&ml_ctx->hashes, ml_hash_info);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszHashValue);
    return dwError;

error:
    if (ml_hash_info)
    {
        TDNFMetalinkHashFree(ml_hash_info);
        ml_hash_info = NULL;
    }
    goto cleanup;
}

static uint32_t
TDNFMetalinkParseUrlValue(
    TDNF_ML_CTX *ml_ctx,
    const char *pszProtocol,
    const char *pszType,
    const char *pszLocation,
    const char *pszRankingValue,
    bool bRankingIsPriority,
    const char *pszValue,
    size_t nValueLength
    )
{
    uint32_t dwError = 0;
    char *pszUrlValue = NULL;
    TDNF_ML_URL_INFO *ml_url_info = NULL;

    if (!ml_ctx || !pszValue)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_ML_URL_INFO), (void**)&ml_url_info);
    BAIL_ON_TDNF_ERROR(dwError);

    if (!IsNullOrEmptyString(pszProtocol))
    {
        dwError = TDNFAllocateString(pszProtocol, &ml_url_info->protocol);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (!IsNullOrEmptyString(pszType))
    {
        dwError = TDNFAllocateString(pszType, &ml_url_info->type);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (!IsNullOrEmptyString(pszLocation))
    {
        dwError = TDNFAllocateString(pszLocation, &ml_url_info->location);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFMetalinkNormalizeUrlPreference(
                    pszRankingValue,
                    bRankingIsPriority,
                    &ml_url_info->preference);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFMetalinkAllocateStringBuffer(pszValue, nValueLength, &pszUrlValue);
    BAIL_ON_TDNF_ERROR(dwError);

    if (IsNullOrEmptyString(pszUrlValue))
    {
        dwError = ERROR_TDNF_METALINK_PARSER_MISSING_URL_CONTENT;
        pr_err("URL is not present in URL element");
        BAIL_ON_TDNF_ERROR(dwError);
    }

    ml_url_info->url = pszUrlValue;
    pszUrlValue = NULL;

    dwError = TDNFAppendList(&ml_ctx->urls, ml_url_info);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszUrlValue);
    return dwError;

error:
    if (ml_url_info)
    {
        TDNFMetalinkUrlFree(ml_url_info);
        ml_url_info = NULL;
    }
    goto cleanup;
}

#ifdef TDNF_METALINK_ZIG_XML
static uint32_t
TDNFMetalinkZigParseFile(
    void *pUserData,
    const char *pszName
    )
{
    return TDNFMetalinkParseFileName(
                (TDNF_METALINK_CALLBACK_CONTEXT *)pUserData,
                pszName);
}

static uint32_t
TDNFMetalinkZigParseSize(
    void *pUserData,
    const char *pszValue,
    size_t nValueLength
    )
{
    TDNF_METALINK_CALLBACK_CONTEXT *pCbCtx = pUserData;

    if (!pCbCtx)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }

    return TDNFMetalinkParseSizeValue(
                pCbCtx->ml_ctx,
                pszValue,
                nValueLength);
}

static uint32_t
TDNFMetalinkZigParseHash(
    void *pUserData,
    const char *pszType,
    const char *pszValue,
    size_t nValueLength
    )
{
    TDNF_METALINK_CALLBACK_CONTEXT *pCbCtx = pUserData;

    if (!pCbCtx)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }

    return TDNFMetalinkParseHashValue(
                pCbCtx->ml_ctx,
                pszType,
                pszValue,
                nValueLength);
}

static uint32_t
TDNFMetalinkZigParseUrl(
    void *pUserData,
    const char *pszProtocol,
    const char *pszType,
    const char *pszLocation,
    const char *pszRankingValue,
    bool bRankingIsPriority,
    const char *pszValue,
    size_t nValueLength
    )
{
    TDNF_METALINK_CALLBACK_CONTEXT *pCbCtx = pUserData;

    if (!pCbCtx)
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }

    return TDNFMetalinkParseUrlValue(
                pCbCtx->ml_ctx,
                pszProtocol,
                pszType,
                pszLocation,
                pszRankingValue,
                bRankingIsPriority,
                pszValue,
                nValueLength);
}
#endif

void
TDNFMetalinkFree(
    TDNF_ML_CTX *ml_ctx
    )
{
    if (!ml_ctx)
        return;

    TDNF_SAFE_FREE_MEMORY(ml_ctx->filename);
    TDNFDeleteList(&ml_ctx->hashes, TDNFMetalinkHashFree);
    TDNFDeleteList(&ml_ctx->urls, TDNFMetalinkUrlFree);
    TDNF_SAFE_FREE_MEMORY(ml_ctx);
}

char *
TDNFSearchTag(
    const char **attr,
    const char *type
    )
{
    if (!attr || !type)
    {
        return NULL;
    }

    for (int i = 0; attr[i]; i += 2)
    {
        if((!strcmp(attr[i], type)) && (attr[i + 1] != NULL))
        {
           return (char *)attr[i + 1];
        }
    }

    return NULL;
}

uint32_t
TDNFParseFileTag(
    void *userData
    )
{
    uint32_t dwError = 0;
    const char *name = NULL;
    struct MetalinkElementInfo* elementInfo = (struct MetalinkElementInfo*)userData;

    if(!elementInfo || !elementInfo->cbCtx.ml_ctx || IsNullOrEmptyString(elementInfo->cbCtx.filename))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    name = TDNFSearchTag(elementInfo->attributes, ATTR_NAME);

    if (!name)
    {
        pr_err("%s: Missing attribute \"name\" of file element", __func__);
        dwError = ERROR_TDNF_METALINK_PARSER_MISSING_FILE_ATTR;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFMetalinkParseFileName(&elementInfo->cbCtx, name);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFParseHashTag(
    void *userData,
    const char *val,
    int len
    )
{
    uint32_t dwError = 0;
    const char *type = NULL;
    struct MetalinkElementInfo* elementInfo = (struct MetalinkElementInfo*)userData;

    if(!elementInfo || !elementInfo->cbCtx.ml_ctx)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //Get Hash Properties
    type = TDNFSearchTag(elementInfo->attributes, ATTR_TYPE);

    if (!type)
    {
        dwError = ERROR_TDNF_METALINK_PARSER_MISSING_HASH_ATTR;
        pr_err("XML Parser Error:HASH element doesn't have attribute \"type\"");
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFMetalinkParseHashValue(
                    elementInfo->cbCtx.ml_ctx,
                    type,
                    val,
                    (size_t)len);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
TDNFParseUrlTag(
    void *userData,
    const char *val,
    int len
    )
{
    uint32_t dwError = 0;
    struct MetalinkElementInfo* elementInfo = (struct MetalinkElementInfo*)userData;
    const char *pszProtocol = NULL;
    const char *pszType = NULL;
    const char *pszLocation = NULL;
    const char *pszPreference = NULL;

    if(!elementInfo || !elementInfo->cbCtx.ml_ctx)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    pszProtocol = TDNFSearchTag(elementInfo->attributes, ATTR_PROTOCOL);
    pszType = TDNFSearchTag(elementInfo->attributes, ATTR_TYPE);
    pszLocation = TDNFSearchTag(elementInfo->attributes, ATTR_LOCATION);
    pszPreference = TDNFSearchTag(elementInfo->attributes, ATTR_PREFERENCE);

    dwError = TDNFMetalinkParseUrlValue(
                    elementInfo->cbCtx.ml_ctx,
                    pszProtocol,
                    pszType,
                    pszLocation,
                    pszPreference,
                    false,
                    val,
                    (size_t)len);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

void
TDNFXmlParseStartElement(
    void *userData,
    const char *name,
    const char **attrs
    )
{
    struct MetalinkElementInfo* elementInfo = (struct MetalinkElementInfo*)userData;

    if(elementInfo->dwError != 0)
    {
        BAIL_ON_TDNF_ERROR(elementInfo->dwError);
    }

    // Set the start element name and attribute
    elementInfo->startElement = name;
    elementInfo->attributes = attrs;

cleanup:
    return;
error:
    goto cleanup;
}

void
TDNFXmlParseData(
    void *userData,
    const char *val,
    int len
    )
{
    struct MetalinkElementInfo* elementInfo = (struct MetalinkElementInfo*)userData;

    if(!elementInfo || !elementInfo->cbCtx.ml_ctx ||
       IsNullOrEmptyString(elementInfo->cbCtx.filename) || elementInfo->dwError)
    {
        uint32_t dwError = ERROR_TDNF_INVALID_PARAMETER;

        if (elementInfo)
            elementInfo->dwError = dwError;

        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (elementInfo->startElement == NULL)
        return;

    if(!strcmp(elementInfo->startElement, TAG_NAME_FILE))
    {
        elementInfo->dwError = TDNFParseFileTag(userData);
        BAIL_ON_TDNF_ERROR(elementInfo->dwError);
    }
    else if(!strcmp(elementInfo->startElement, TAG_NAME_SIZE))
    {
        elementInfo->dwError = TDNFMetalinkParseSizeValue(
                                    elementInfo->cbCtx.ml_ctx,
                                    val,
                                    (size_t)len);
        BAIL_ON_TDNF_ERROR(elementInfo->dwError);
    }
    else if(!strcmp(elementInfo->startElement, TAG_NAME_HASH))
    {
        elementInfo->dwError = TDNFParseHashTag(userData, val, len);
        BAIL_ON_TDNF_ERROR(elementInfo->dwError);
    }
    else if(!strcmp(elementInfo->startElement, TAG_NAME_URL) && len > MIN_URL_LENGTH)
    {
        elementInfo->dwError = TDNFParseUrlTag(userData, val, len);
        BAIL_ON_TDNF_ERROR(elementInfo->dwError);
    }

cleanup:
    return;
error:
    goto cleanup;
}

void
TDNFXmlParseEndElement(
    void *userData,
    const char *name
    )
{
    struct MetalinkElementInfo* elementInfo = (struct MetalinkElementInfo*)userData;
    elementInfo->endElement = name;
    elementInfo->startElement = NULL;

    if(elementInfo->dwError != 0)
       BAIL_ON_TDNF_ERROR(elementInfo->dwError);

cleanup:
     return;
error:
     goto cleanup;
}

static uint32_t
TDNFMetalinkReadFileBuffer(
    FILE *file,
    char **ppszBuffer,
    size_t *pnBufferSize
    )
{
    uint32_t dwError = 0;
    struct stat st = {0};
    size_t nBufferSize = 0;
    char *pszBuffer = NULL;

    if (!file || !ppszBuffer || !pnBufferSize)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (fstat(fileno(file), &st) == -1)
    {
        pr_err("Error getting file information");
        dwError = errno;
        BAIL_ON_TDNF_SYSTEM_ERROR_UNCOND(dwError);
    }

    nBufferSize = (size_t)st.st_size;

    dwError = TDNFAllocateMemory(nBufferSize + 1, sizeof(char), (void **)&pszBuffer);
    BAIL_ON_TDNF_ERROR(dwError);

    if (fread(pszBuffer, 1, nBufferSize, file) != nBufferSize)
    {
        pr_err("Failed to read the metalink file.");
        dwError = errno;
        BAIL_ON_TDNF_SYSTEM_ERROR_UNCOND(dwError);
    }

    pszBuffer[nBufferSize] = '\0';

    *ppszBuffer = pszBuffer;
    *pnBufferSize = nBufferSize;

cleanup:
    return dwError;
error:
    TDNF_SAFE_FREE_MEMORY(pszBuffer);
    if (ppszBuffer)
    {
        *ppszBuffer = NULL;
    }
    if (pnBufferSize)
    {
        *pnBufferSize = 0;
    }
    goto cleanup;
}

#if !defined(TDNF_METALINK_ZIG_XML) || defined(TDNF_METALINK_ZIG_XML_CROSSCHECK)
static uint32_t
TDNFMetalinkParseBufferWithExpat(
    TDNF_ML_CTX *ml_ctx,
    const char *pszBuffer,
    size_t nBufferSize,
    const char *pszFilename
    )
{
    uint32_t dwError = 0;
    struct MetalinkElementInfo elementInfo = {0};
    XML_Parser parser = XML_ParserCreate(NULL);

    if (!ml_ctx || !pszBuffer || IsNullOrEmptyString(pszFilename) || parser == NULL)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    elementInfo.cbCtx.ml_ctx = ml_ctx;
    elementInfo.cbCtx.filename = pszFilename;

    XML_SetElementHandler(parser, TDNFXmlParseStartElement, TDNFXmlParseEndElement);
    XML_SetCharacterDataHandler(parser, TDNFXmlParseData);
    XML_SetUserData(parser, &elementInfo);

    dwError = XML_Parse(parser, pszBuffer, (int)(nBufferSize + 1), XML_TRUE);
    BAIL_ON_TDNF_ERROR(dwError);

    if (elementInfo.dwError != 0)
    {
        dwError = elementInfo.dwError;
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    if (parser != NULL)
    {
        XML_ParserFree(parser);
    }
    return dwError;
error:
    goto cleanup;
}
#endif

#ifdef TDNF_METALINK_ZIG_XML
static uint32_t
TDNFMetalinkParseBufferWithZig(
    TDNF_ML_CTX *ml_ctx,
    const char *pszBuffer,
    size_t nBufferSize,
    const char *pszFilename
    )
{
    TDNF_METALINK_CALLBACK_CONTEXT cbCtx = {0};
    TDNF_METALINK_XML_CALLBACKS callbacks = {
        .pfnFile = TDNFMetalinkZigParseFile,
        .pfnSize = TDNFMetalinkZigParseSize,
        .pfnHash = TDNFMetalinkZigParseHash,
        .pfnUrl = TDNFMetalinkZigParseUrl,
    };

    if (!ml_ctx || !pszBuffer || IsNullOrEmptyString(pszFilename))
    {
        return ERROR_TDNF_INVALID_PARAMETER;
    }

    cbCtx.ml_ctx = ml_ctx;
    cbCtx.filename = pszFilename;

    return TDNFMetalinkXmlParseBuffer(pszBuffer, nBufferSize, &callbacks, &cbCtx);
}
#endif

#ifdef TDNF_METALINK_ZIG_XML_CROSSCHECK
static bool
TDNFMetalinkStringsEqual(
    const char *pszLeft,
    const char *pszRight
    )
{
    if (pszLeft == NULL || pszRight == NULL)
    {
        return pszLeft == pszRight;
    }

    return strcmp(pszLeft, pszRight) == 0;
}

static const char *
TDNFMetalinkLogString(
    const char *pszValue
    )
{
    return pszValue ? pszValue : "(null)";
}

static void
TDNFMetalinkCrossCheckLogHeader(
    bool *pbLoggedHeader,
    const char *pszFilename
    )
{
    if (!pbLoggedHeader || *pbLoggedHeader)
    {
        return;
    }

    pr_crit("metalink Zig XML cross-check mismatch for %s",
            TDNFMetalinkLogString(pszFilename));
    *pbLoggedHeader = true;
}

static size_t
TDNFMetalinkListCount(
    TDNF_ML_LIST *pList
    )
{
    size_t nCount = 0;

    while (pList)
    {
        nCount++;
        pList = pList->next;
    }

    return nCount;
}

static void
TDNFMetalinkCrossCheckCompareHashes(
    const char *pszFilename,
    TDNF_ML_HASH_LIST *pExpatHashList,
    TDNF_ML_HASH_LIST *pZigHashList,
    bool *pbLoggedHeader
    )
{
    size_t nIndex = 0;
    size_t nExpatCount = TDNFMetalinkListCount(pExpatHashList);
    size_t nZigCount = TDNFMetalinkListCount(pZigHashList);

    if (nExpatCount != nZigCount)
    {
        TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
        pr_err("  hashes.count: expat=%zu zig=%zu", nExpatCount, nZigCount);
    }

    while (pExpatHashList || pZigHashList)
    {
        TDNF_ML_HASH_INFO *pExpatHash = pExpatHashList ? pExpatHashList->data : NULL;
        TDNF_ML_HASH_INFO *pZigHash = pZigHashList ? pZigHashList->data : NULL;

        if (!pExpatHashList || !pZigHashList)
        {
            TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
            pr_err("  hash[%zu]: expat.type=\"%s\" expat.value=\"%s\" zig.type=\"%s\" zig.value=\"%s\"",
                   nIndex,
                   TDNFMetalinkLogString(pExpatHash ? pExpatHash->type : NULL),
                   TDNFMetalinkLogString(pExpatHash ? pExpatHash->value : NULL),
                   TDNFMetalinkLogString(pZigHash ? pZigHash->type : NULL),
                   TDNFMetalinkLogString(pZigHash ? pZigHash->value : NULL));
        }
        else
        {
            if (!TDNFMetalinkStringsEqual(pExpatHash ? pExpatHash->type : NULL,
                                          pZigHash ? pZigHash->type : NULL))
            {
                TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
                pr_err("  hash[%zu].type: expat=\"%s\" zig=\"%s\"",
                       nIndex,
                       TDNFMetalinkLogString(pExpatHash ? pExpatHash->type : NULL),
                       TDNFMetalinkLogString(pZigHash ? pZigHash->type : NULL));
            }

            if (!TDNFMetalinkStringsEqual(pExpatHash ? pExpatHash->value : NULL,
                                          pZigHash ? pZigHash->value : NULL))
            {
                TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
                pr_err("  hash[%zu].value: expat=\"%s\" zig=\"%s\"",
                       nIndex,
                       TDNFMetalinkLogString(pExpatHash ? pExpatHash->value : NULL),
                       TDNFMetalinkLogString(pZigHash ? pZigHash->value : NULL));
            }
        }

        pExpatHashList = pExpatHashList ? pExpatHashList->next : NULL;
        pZigHashList = pZigHashList ? pZigHashList->next : NULL;
        nIndex++;
    }
}

static void
TDNFMetalinkCrossCheckCompareUrls(
    const char *pszFilename,
    TDNF_ML_URL_LIST *pExpatUrlList,
    TDNF_ML_URL_LIST *pZigUrlList,
    bool *pbLoggedHeader
    )
{
    size_t nIndex = 0;
    size_t nExpatCount = TDNFMetalinkListCount(pExpatUrlList);
    size_t nZigCount = TDNFMetalinkListCount(pZigUrlList);

    if (nExpatCount != nZigCount)
    {
        TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
        pr_err("  urls.count: expat=%zu zig=%zu", nExpatCount, nZigCount);
    }

    while (pExpatUrlList || pZigUrlList)
    {
        TDNF_ML_URL_INFO *pExpatUrl = pExpatUrlList ? pExpatUrlList->data : NULL;
        TDNF_ML_URL_INFO *pZigUrl = pZigUrlList ? pZigUrlList->data : NULL;

        if (!pExpatUrlList || !pZigUrlList)
        {
            TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
            pr_err("  url[%zu]: expat.protocol=\"%s\" expat.type=\"%s\" expat.location=\"%s\" expat.preference=%d expat.url=\"%s\" zig.protocol=\"%s\" zig.type=\"%s\" zig.location=\"%s\" zig.preference=%d zig.url=\"%s\"",
                   nIndex,
                   TDNFMetalinkLogString(pExpatUrl ? pExpatUrl->protocol : NULL),
                   TDNFMetalinkLogString(pExpatUrl ? pExpatUrl->type : NULL),
                   TDNFMetalinkLogString(pExpatUrl ? pExpatUrl->location : NULL),
                   pExpatUrl ? pExpatUrl->preference : 0,
                   TDNFMetalinkLogString(pExpatUrl ? pExpatUrl->url : NULL),
                   TDNFMetalinkLogString(pZigUrl ? pZigUrl->protocol : NULL),
                   TDNFMetalinkLogString(pZigUrl ? pZigUrl->type : NULL),
                   TDNFMetalinkLogString(pZigUrl ? pZigUrl->location : NULL),
                   pZigUrl ? pZigUrl->preference : 0,
                   TDNFMetalinkLogString(pZigUrl ? pZigUrl->url : NULL));
        }
        else
        {
            if (!TDNFMetalinkStringsEqual(pExpatUrl->protocol, pZigUrl->protocol))
            {
                TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
                pr_err("  url[%zu].protocol: expat=\"%s\" zig=\"%s\"",
                       nIndex,
                       TDNFMetalinkLogString(pExpatUrl->protocol),
                       TDNFMetalinkLogString(pZigUrl->protocol));
            }
            if (!TDNFMetalinkStringsEqual(pExpatUrl->type, pZigUrl->type))
            {
                TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
                pr_err("  url[%zu].type: expat=\"%s\" zig=\"%s\"",
                       nIndex,
                       TDNFMetalinkLogString(pExpatUrl->type),
                       TDNFMetalinkLogString(pZigUrl->type));
            }
            if (!TDNFMetalinkStringsEqual(pExpatUrl->location, pZigUrl->location))
            {
                TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
                pr_err("  url[%zu].location: expat=\"%s\" zig=\"%s\"",
                       nIndex,
                       TDNFMetalinkLogString(pExpatUrl->location),
                       TDNFMetalinkLogString(pZigUrl->location));
            }
            if (pExpatUrl->preference != pZigUrl->preference)
            {
                TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
                pr_err("  url[%zu].preference: expat=%d zig=%d",
                       nIndex,
                       pExpatUrl->preference,
                       pZigUrl->preference);
            }
            if (!TDNFMetalinkStringsEqual(pExpatUrl->url, pZigUrl->url))
            {
                TDNFMetalinkCrossCheckLogHeader(pbLoggedHeader, pszFilename);
                pr_err("  url[%zu].url: expat=\"%s\" zig=\"%s\"",
                       nIndex,
                       TDNFMetalinkLogString(pExpatUrl->url),
                       TDNFMetalinkLogString(pZigUrl->url));
            }
        }

        pExpatUrlList = pExpatUrlList ? pExpatUrlList->next : NULL;
        pZigUrlList = pZigUrlList ? pZigUrlList->next : NULL;
        nIndex++;
    }
}

static void
TDNFMetalinkCrossCheckCompareResults(
    const char *pszFilename,
    TDNF_ML_CTX *pExpatCtx,
    TDNF_ML_CTX *pZigCtx
    )
{
    bool bLoggedHeader = false;

    if (!pExpatCtx || !pZigCtx)
    {
        return;
    }

    TDNFSortListOnPreference(&pExpatCtx->urls);
    TDNFSortListOnPreference(&pZigCtx->urls);

    if (!TDNFMetalinkStringsEqual(pExpatCtx->filename, pZigCtx->filename))
    {
        TDNFMetalinkCrossCheckLogHeader(&bLoggedHeader, pszFilename);
        pr_err("  filename: expat=\"%s\" zig=\"%s\"",
               TDNFMetalinkLogString(pExpatCtx->filename),
               TDNFMetalinkLogString(pZigCtx->filename));
    }

    if (pExpatCtx->size != pZigCtx->size)
    {
        TDNFMetalinkCrossCheckLogHeader(&bLoggedHeader, pszFilename);
        pr_err("  size: expat=%ld zig=%ld",
               pExpatCtx->size,
               pZigCtx->size);
    }

    TDNFMetalinkCrossCheckCompareHashes(
        pszFilename,
        pExpatCtx->hashes,
        pZigCtx->hashes,
        &bLoggedHeader);
    TDNFMetalinkCrossCheckCompareUrls(
        pszFilename,
        pExpatCtx->urls,
        pZigCtx->urls,
        &bLoggedHeader);
}

static void
TDNFMetalinkRunZigXmlCrossCheck(
    TDNF_ML_CTX *pExpatCtx,
    const char *pszBuffer,
    size_t nBufferSize,
    const char *pszFilename
    )
{
    uint32_t dwError = 0;
    TDNF_ML_CTX *pZigCtx = NULL;

    if (!pExpatCtx || !pszBuffer || IsNullOrEmptyString(pszFilename))
    {
        return;
    }

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_ML_CTX), (void **)&pZigCtx);
    if (dwError != 0)
    {
        pr_err("Unable to allocate metalink Zig XML cross-check context for %s, ERROR: code=%u",
               pszFilename, dwError);
        goto cleanup;
    }

    dwError = TDNFMetalinkParseBufferWithZig(
                    pZigCtx,
                    pszBuffer,
                    nBufferSize,
                    pszFilename);
    if (dwError != 0)
    {
        pr_crit("metalink Zig XML cross-check parser mismatch for %s",
                pszFilename);
        pr_err("  expat=0 zig=%u", dwError);
        goto cleanup;
    }

    TDNFMetalinkCrossCheckCompareResults(pszFilename, pExpatCtx, pZigCtx);

cleanup:
    /* Best-effort debug-only cross-check: keep the temporary Zig parse
     * result alive until process exit rather than perturb the primary
     * expat path with extra cleanup failure modes in this PR.
     */
    UNUSED(pZigCtx);
}
#endif

uint32_t
TDNFMetalinkParseFile(
    TDNF_ML_CTX *ml_ctx,
    FILE *file,
    const char *filename
    )
{
    uint32_t dwError = 0;
    size_t nBufferSize = 0;
    char *pszBuffer = NULL;

    if(!ml_ctx || (file == NULL) || IsNullOrEmptyString(filename))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFMetalinkReadFileBuffer(file, &pszBuffer, &nBufferSize);
    BAIL_ON_TDNF_ERROR(dwError);

#ifdef TDNF_METALINK_ZIG_XML_CROSSCHECK
    dwError = TDNFMetalinkParseBufferWithExpat(ml_ctx, pszBuffer, nBufferSize, filename);
    BAIL_ON_TDNF_ERROR(dwError);

    TDNFMetalinkRunZigXmlCrossCheck(ml_ctx, pszBuffer, nBufferSize, filename);
#elif defined(TDNF_METALINK_ZIG_XML)
    dwError = TDNFMetalinkParseBufferWithZig(ml_ctx, pszBuffer, nBufferSize, filename);
    BAIL_ON_TDNF_ERROR(dwError);
#else
    dwError = TDNFMetalinkParseBufferWithExpat(ml_ctx, pszBuffer, nBufferSize, filename);
    BAIL_ON_TDNF_ERROR(dwError);
#endif

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszBuffer);
    return dwError;
error:
    goto cleanup;
}
