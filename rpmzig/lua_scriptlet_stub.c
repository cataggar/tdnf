#include "lua_scriptlet.h"

int tdnf_rpmzig_lua_supported(void)
{
    return 0;
}

int tdnf_rpmzig_lua_run(const char *script, size_t script_len, int arg1, int arg2)
{
    (void)script;
    (void)script_len;
    (void)arg1;
    (void)arg2;
    return 127;
}
