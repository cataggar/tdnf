#ifndef __TDNF_RPMZIG_LUA_SCRIPTLET_H__
#define __TDNF_RPMZIG_LUA_SCRIPTLET_H__

#include <stddef.h>

int tdnf_rpmzig_lua_supported(void);
int tdnf_rpmzig_lua_run(const char *script, size_t script_len, int arg1, int arg2);

#endif
