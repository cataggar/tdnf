/* Pure-Zig metalink XML parser C ABI (PR1 of issue #38). */

#ifndef __PLUGINS_METALINK_XML_H__
#define __PLUGINS_METALINK_XML_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t (*TDNF_ML_ON_FILE)(
    void *ctx,
    const char *name
    );

typedef uint32_t (*TDNF_ML_ON_SIZE)(
    void *ctx,
    const char *text,
    size_t len
    );

typedef uint32_t (*TDNF_ML_ON_HASH)(
    void *ctx,
    const char *type,
    const char *text,
    size_t len
    );

typedef uint32_t (*TDNF_ML_ON_URL)(
    void *ctx,
    const char *protocol,
    const char *type,
    const char *location,
    const char *ranking_attr,
    bool ranking_is_priority,
    const char *text,
    size_t len
    );

typedef struct _TDNF_METALINK_XML_CALLBACKS
{
    TDNF_ML_ON_FILE pfnFile;
    TDNF_ML_ON_SIZE pfnSize;
    TDNF_ML_ON_HASH pfnHash;
    TDNF_ML_ON_URL  pfnUrl;
} TDNF_METALINK_XML_CALLBACKS;

/*
 * `protocol`, `type`, `location`, and `ranking_attr` may be NULL if the
 * source element omits them. `text` is not guaranteed to be NUL-terminated;
 * use `len`.
 */
uint32_t
TDNFMetalinkXmlParseBuffer(
    const char *buf,
    size_t len,
    const TDNF_METALINK_XML_CALLBACKS *cbs,
    void *ctx
    );

#ifdef __cplusplus
}
#endif

#endif /* __PLUGINS_METALINK_XML_H__ */
