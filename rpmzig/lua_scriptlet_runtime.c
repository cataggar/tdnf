#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#if __has_include(<lua5.4/lauxlib.h>)
#include <lua5.4/lauxlib.h>
#include <lua5.4/lualib.h>
#elif __has_include(<lua.h>)
#include <lauxlib.h>
#include <lualib.h>
#else
#error "Lua headers not found. Install liblua5.4-dev or the equivalent lua-devel package."
#endif

#include "lua_scriptlet.h"

extern char **environ;

#define FILES_ITER_METATABLE "tdnf.rpmzig.files_iter"

typedef struct lua_files_iter
{
    DIR *pDir;
} LUA_FILES_ITER;

static int luaPushError(lua_State *L, int nCode, const char *pszInfo)
{
    lua_pushnil(L);
    lua_pushstring(L, pszInfo ? pszInfo : strerror(nCode));
    lua_pushinteger(L, nCode);
    return 3;
}

static int luaPushResult(lua_State *L, int nResult)
{
    lua_pushinteger(L, nResult);
    return 1;
}

static int luaRpmExecute(lua_State *L);
static int luaRpmInput(lua_State *L);
static int luaRpmSpawn(lua_State *L);
static int luaRpmGlob(lua_State *L);
static int luaRpmVercmp(lua_State *L);
static int luaPosixAccess(lua_State *L);
static int luaPosixChmod(lua_State *L);
static int luaPosixFiles(lua_State *L);
static int luaPosixMkdir(lua_State *L);
static int luaPosixReadlink(lua_State *L);
static int luaPosixStat(lua_State *L);
static int luaPosixSymlink(lua_State *L);
static int luaPosixUname(lua_State *L);
static int luaPosixUtime(lua_State *L);
static int luaFilesIterNext(lua_State *L);
static int luaFilesIterGc(lua_State *L);
static int luaOpenRpm(lua_State *L);
static int luaOpenPosix(lua_State *L);

static const luaL_Reg gRpmLib[] = {
    { "execute", luaRpmExecute },
    { "input", luaRpmInput },
    { "spawn", luaRpmSpawn },
    { "glob", luaRpmGlob },
    { "vercmp", luaRpmVercmp },
    { NULL, NULL },
};

static const luaL_Reg gPosixLib[] = {
    { "access", luaPosixAccess },
    { "chmod", luaPosixChmod },
    { "files", luaPosixFiles },
    { "mkdir", luaPosixMkdir },
    { "readlink", luaPosixReadlink },
    { "stat", luaPosixStat },
    { "symlink", luaPosixSymlink },
    { "uname", luaPosixUname },
    { "utime", luaPosixUtime },
    { NULL, NULL },
};

static void luaCreateFilesIterMetatable(lua_State *L)
{
    if (luaL_newmetatable(L, FILES_ITER_METATABLE)) {
        lua_pushcfunction(L, luaFilesIterGc);
        lua_setfield(L, -2, "__gc");
    }
    lua_pop(L, 1);
}

static int luaOpenRpm(lua_State *L)
{
    luaL_newlib(L, gRpmLib);
    return 1;
}

static int luaOpenPosix(lua_State *L)
{
    luaL_newlib(L, gPosixLib);
    return 1;
}

static const char *luaStatType(const struct stat *pStat)
{
    if (S_ISREG(pStat->st_mode)) {
        return "regular";
    }
    if (S_ISDIR(pStat->st_mode)) {
        return "directory";
    }
    if (S_ISLNK(pStat->st_mode)) {
        return "link";
    }
    if (S_ISCHR(pStat->st_mode)) {
        return "character device";
    }
    if (S_ISBLK(pStat->st_mode)) {
        return "block device";
    }
    if (S_ISFIFO(pStat->st_mode)) {
        return "fifo";
    }
    if (S_ISSOCK(pStat->st_mode)) {
        return "socket";
    }
    return "unknown";
}

static int luaParseAccessMode(const char *pszMode)
{
    int nMode = 0;

    if (!pszMode || !*pszMode) {
        return F_OK;
    }

    if (strchr(pszMode, 'r')) {
        nMode |= R_OK;
    }
    if (strchr(pszMode, 'w')) {
        nMode |= W_OK;
    }
    if (strchr(pszMode, 'x')) {
        nMode |= X_OK;
    }

    return nMode ? nMode : F_OK;
}

static int luaPosixAccess(lua_State *L)
{
    const char *pszPath = luaL_checkstring(L, 1);
    const char *pszMode = luaL_optstring(L, 2, NULL);
    const int nMode = luaParseAccessMode(pszMode);

    if (access(pszPath, nMode) != 0) {
        return luaPushError(L, errno, NULL);
    }

    return luaPushResult(L, 0);
}

static int luaPosixChmod(lua_State *L)
{
    const char *pszPath = luaL_checkstring(L, 1);
    const mode_t nMode = (mode_t)luaL_checkinteger(L, 2);

    if (chmod(pszPath, nMode) != 0) {
        return luaPushError(L, errno, NULL);
    }

    return luaPushResult(L, 0);
}

static int luaPosixMkdir(lua_State *L)
{
    const char *pszPath = luaL_checkstring(L, 1);
    mode_t nMode = 0777;

    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
        nMode = (mode_t)luaL_checkinteger(L, 2);
    }

    if (mkdir(pszPath, nMode) != 0) {
        return luaPushError(L, errno, NULL);
    }

    return luaPushResult(L, 0);
}

static int luaPosixReadlink(lua_State *L)
{
    char szBuffer[4096];
    const char *pszPath = luaL_checkstring(L, 1);
    ssize_t nLen = 0;

    nLen = readlink(pszPath, szBuffer, sizeof(szBuffer) - 1);
    if (nLen < 0) {
        return luaPushError(L, errno, NULL);
    }

    szBuffer[nLen] = '\0';
    lua_pushstring(L, szBuffer);
    return 1;
}

static int luaPosixStat(lua_State *L)
{
    const char *pszPath = luaL_checkstring(L, 1);
    struct stat st = {0};

    if (lstat(pszPath, &st) != 0) {
        return luaPushError(L, errno, NULL);
    }

    lua_newtable(L);
    lua_pushstring(L, luaStatType(&st));
    lua_setfield(L, -2, "type");
    lua_pushinteger(L, (lua_Integer)st.st_mode);
    lua_setfield(L, -2, "mode");
    return 1;
}

static int luaPosixSymlink(lua_State *L)
{
    const char *pszTarget = luaL_checkstring(L, 1);
    const char *pszPath = luaL_checkstring(L, 2);

    if (symlink(pszTarget, pszPath) != 0) {
        return luaPushError(L, errno, NULL);
    }

    return luaPushResult(L, 0);
}

static int luaPosixUname(lua_State *L)
{
    const char *pszFormat = luaL_optstring(L, 1, NULL);
    struct utsname uts = {0};
    luaL_Buffer buffer;

    if (uname(&uts) != 0) {
        return luaPushError(L, errno, NULL);
    }

    if (!pszFormat) {
        lua_newtable(L);
        lua_pushstring(L, uts.sysname);
        lua_setfield(L, -2, "sysname");
        lua_pushstring(L, uts.nodename);
        lua_setfield(L, -2, "nodename");
        lua_pushstring(L, uts.release);
        lua_setfield(L, -2, "release");
        lua_pushstring(L, uts.version);
        lua_setfield(L, -2, "version");
        lua_pushstring(L, uts.machine);
        lua_setfield(L, -2, "machine");
        return 1;
    }

    luaL_buffinit(L, &buffer);

    while (*pszFormat) {
        if (*pszFormat == '%' && pszFormat[1] != '\0') {
            const char *pszValue = NULL;

            ++pszFormat;
            switch (*pszFormat) {
                case 's':
                    pszValue = uts.sysname;
                    break;
                case 'n':
                    pszValue = uts.nodename;
                    break;
                case 'r':
                    pszValue = uts.release;
                    break;
                case 'v':
                    pszValue = uts.version;
                    break;
                case 'm':
                    pszValue = uts.machine;
                    break;
                default:
                    luaL_addchar(&buffer, '%');
                    luaL_addchar(&buffer, *pszFormat);
                    pszValue = NULL;
                    break;
            }
            if (pszValue) {
                luaL_addstring(&buffer, pszValue);
            }
        } else {
            luaL_addchar(&buffer, *pszFormat);
        }
        ++pszFormat;
    }

    luaL_pushresult(&buffer);
    return 1;
}

static int luaPosixUtime(lua_State *L)
{
    const char *pszPath = luaL_checkstring(L, 1);

    if (utimes(pszPath, NULL) != 0) {
        return luaPushError(L, errno, NULL);
    }

    return luaPushResult(L, 0);
}

static int luaFilesIterGc(lua_State *L)
{
    LUA_FILES_ITER *pIter = (LUA_FILES_ITER *)luaL_checkudata(L, 1, FILES_ITER_METATABLE);

    if (pIter->pDir) {
        closedir(pIter->pDir);
        pIter->pDir = NULL;
    }

    return 0;
}

static int luaFilesIterNext(lua_State *L)
{
    LUA_FILES_ITER *pIter = (LUA_FILES_ITER *)lua_touserdata(L, lua_upvalueindex(1));
    struct dirent *pEntry = NULL;

    if (!pIter || !pIter->pDir) {
        return 0;
    }

    errno = 0;
    pEntry = readdir(pIter->pDir);
    if (!pEntry) {
        const int nErrno = errno;

        closedir(pIter->pDir);
        pIter->pDir = NULL;
        if (nErrno != 0) {
            return luaL_error(L, "readdir failed: %s", strerror(nErrno));
        }
        return 0;
    }

    lua_pushstring(L, pEntry->d_name);
    return 1;
}

static int luaPosixFiles(lua_State *L)
{
    const char *pszPath = luaL_checkstring(L, 1);
    LUA_FILES_ITER *pIter = NULL;
    DIR *pDir = opendir(pszPath);

    if (!pDir) {
        return luaPushError(L, errno, NULL);
    }

    pIter = (LUA_FILES_ITER *)lua_newuserdata(L, sizeof(*pIter));
    pIter->pDir = pDir;
    luaL_getmetatable(L, FILES_ITER_METATABLE);
    lua_setmetatable(L, -2);
    lua_pushcclosure(L, luaFilesIterNext, 1);
    return 1;
}

static int luaRpmDoSpawnAction(lua_State *L, posix_spawn_file_actions_t *pActions)
{
    const char *pszKey = luaL_checkstring(L, -2);
    const char *pszValue = luaL_checkstring(L, -1);

    if (!strcmp(pszKey, "stdin")) {
        return posix_spawn_file_actions_addopen(pActions, STDIN_FILENO, pszValue, O_RDONLY, 0644);
    }
    if (!strcmp(pszKey, "stdout")) {
        return posix_spawn_file_actions_addopen(pActions, STDOUT_FILENO, pszValue, O_WRONLY | O_APPEND | O_CREAT, 0644);
    }
    if (!strcmp(pszKey, "stderr")) {
        return posix_spawn_file_actions_addopen(pActions, STDERR_FILENO, pszValue, O_WRONLY | O_APPEND | O_CREAT, 0644);
    }

    return EINVAL;
}

static int luaRpmSpawn(lua_State *L)
{
    posix_spawn_file_actions_t actions = {0};
    posix_spawn_file_actions_t *pActions = NULL;
    int nArgc = 0;
    int nStatus = 0;
    int nIndex = 0;
    pid_t nPid = 0;
    char **ppszArgv = NULL;
    int nResult = 0;

    luaL_checktype(L, 1, LUA_TTABLE);
    nArgc = (int)luaL_len(L, 1);
    if (nArgc == 0) {
        return luaL_error(L, "command not supplied");
    }

    if (lua_istable(L, 2)) {
        nResult = posix_spawn_file_actions_init(&actions);
        if (nResult != 0) {
            return luaPushError(L, nResult, "spawn file action init");
        }
        pActions = &actions;

        lua_pushnil(L);
        while (lua_next(L, 2) != 0) {
            nResult = luaRpmDoSpawnAction(L, &actions);
            lua_pop(L, 1);
            if (nResult != 0) {
                posix_spawn_file_actions_destroy(&actions);
                return luaPushError(L, nResult, NULL);
            }
        }
    }

    ppszArgv = (char **)calloc((size_t)nArgc + 1, sizeof(*ppszArgv));
    if (!ppszArgv) {
        if (pActions) {
            posix_spawn_file_actions_destroy(&actions);
        }
        return luaL_error(L, "out of memory");
    }

    for (nIndex = 0; nIndex < nArgc; ++nIndex) {
        lua_rawgeti(L, 1, nIndex + 1);
        ppszArgv[nIndex] = (char *)luaL_checkstring(L, -1);
        lua_pop(L, 1);
    }
    ppszArgv[nArgc] = NULL;

    nResult = posix_spawnp(&nPid, ppszArgv[0], pActions, NULL, ppszArgv, environ);
    free(ppszArgv);
    if (pActions) {
        posix_spawn_file_actions_destroy(&actions);
    }
    if (nResult != 0) {
        return luaPushError(L, nResult, NULL);
    }
    if (waitpid(nPid, &nStatus, 0) == -1) {
        return luaPushError(L, errno, NULL);
    }
    if (nStatus != 0) {
        if (WIFSIGNALED(nStatus)) {
            return luaPushError(L, WTERMSIG(nStatus), "exit signal");
        }
        return luaPushError(L, WEXITSTATUS(nStatus), "exit code");
    }

    return luaPushResult(L, WEXITSTATUS(nStatus));
}

static int luaRpmExecute(lua_State *L)
{
    const char *pszFile = luaL_checkstring(L, 1);
    const int nArgc = lua_gettop(L);
    pid_t nPid = 0;
    int nStatus = 0;
    int nIndex = 0;
    int nResult = 0;
    char **ppszArgv = (char **)calloc((size_t)nArgc + 1, sizeof(*ppszArgv));

    if (!ppszArgv) {
        return luaL_error(L, "out of memory");
    }

    ppszArgv[0] = (char *)pszFile;
    for (nIndex = 1; nIndex < nArgc; ++nIndex) {
        ppszArgv[nIndex] = (char *)luaL_checkstring(L, nIndex + 1);
    }
    ppszArgv[nArgc] = NULL;

    nResult = posix_spawnp(&nPid, pszFile, NULL, NULL, ppszArgv, environ);
    free(ppszArgv);
    if (nResult != 0) {
        return luaPushError(L, nResult, NULL);
    }
    if (waitpid(nPid, &nStatus, 0) == -1) {
        return luaPushError(L, errno, NULL);
    }
    if (nStatus != 0) {
        if (WIFSIGNALED(nStatus)) {
            return luaPushError(L, WTERMSIG(nStatus), "exit signal");
        }
        return luaPushError(L, WEXITSTATUS(nStatus), "exit code");
    }

    return luaPushResult(L, nStatus);
}

static int luaRpmInput(lua_State *L)
{
    char *pszLine = NULL;
    size_t nCapacity = 0;
    ssize_t nLength = getline(&pszLine, &nCapacity, stdin);

    if (nLength < 0) {
        free(pszLine);
        lua_pushnil(L);
        return 1;
    }
    while (nLength > 0 &&
           (pszLine[nLength - 1] == '\n' ||
            pszLine[nLength - 1] == '\r')) {
        nLength--;
    }
    lua_pushlstring(L, pszLine, (size_t)nLength);
    free(pszLine);
    return 1;
}

static int luaRpmGlob(lua_State *L)
{
    const char *pszPattern = luaL_checkstring(L, 1);
    glob_t matches = {0};
    int nRc = glob(pszPattern, GLOB_NOCHECK, NULL, &matches);
    size_t nIndex = 0;

    if (nRc != 0 && nRc != GLOB_NOMATCH) {
        globfree(&matches);
        return luaL_error(L, "glob %s failed", pszPattern);
    }

    lua_createtable(L, 0, (int)matches.gl_pathc);
    for (nIndex = 0; nIndex < matches.gl_pathc; ++nIndex) {
        lua_pushstring(L, matches.gl_pathv[nIndex]);
        lua_rawseti(L, -2, (lua_Integer)nIndex + 1);
    }
    globfree(&matches);
    return 1;
}

static int luaVersionTokenByte(int ch)
{
    return isalnum((unsigned char)ch) || ch == '~' || ch == '^';
}

static const char *luaDigitRunEnd(const char *pszValue)
{
    while (*pszValue && isdigit((unsigned char)*pszValue)) {
        ++pszValue;
    }
    return pszValue;
}

static const char *luaAlphaRunEnd(const char *pszValue)
{
    while (*pszValue && isalpha((unsigned char)*pszValue)) {
        ++pszValue;
    }
    return pszValue;
}

static const char *luaTrimLeadingZeros(const char *pszStart, const char *pszEnd)
{
    while (pszStart < pszEnd && *pszStart == '0') {
        ++pszStart;
    }
    return pszStart;
}

static int luaOrderSlice(const char *pszLeft, size_t nLeftLen, const char *pszRight, size_t nRightLen)
{
    const size_t nMinLen = nLeftLen < nRightLen ? nLeftLen : nRightLen;
    const int nCmp = memcmp(pszLeft, pszRight, nMinLen);

    if (nCmp < 0) {
        return -1;
    }
    if (nCmp > 0) {
        return 1;
    }
    if (nLeftLen < nRightLen) {
        return -1;
    }
    if (nLeftLen > nRightLen) {
        return 1;
    }
    return 0;
}

static int luaCompareRpmVersionSlice(const char *pszLeft, size_t nLeftLen, const char *pszRight, size_t nRightLen)
{
    const char *pszLeftCur = pszLeft;
    const char *pszRightCur = pszRight;
    const char *pszLeftEnd = pszLeft + nLeftLen;
    const char *pszRightEnd = pszRight + nRightLen;

    while (1) {
        while (pszLeftCur < pszLeftEnd && !luaVersionTokenByte(*pszLeftCur)) {
            ++pszLeftCur;
        }
        while (pszRightCur < pszRightEnd && !luaVersionTokenByte(*pszRightCur)) {
            ++pszRightCur;
        }

        if ((pszLeftCur < pszLeftEnd && *pszLeftCur == '~') ||
            (pszRightCur < pszRightEnd && *pszRightCur == '~')) {
            if (pszLeftCur >= pszLeftEnd || *pszLeftCur != '~') {
                return 1;
            }
            if (pszRightCur >= pszRightEnd || *pszRightCur != '~') {
                return -1;
            }
            ++pszLeftCur;
            ++pszRightCur;
            continue;
        }

        if ((pszLeftCur < pszLeftEnd && *pszLeftCur == '^') ||
            (pszRightCur < pszRightEnd && *pszRightCur == '^')) {
            if (pszLeftCur >= pszLeftEnd) {
                return -1;
            }
            if (pszRightCur >= pszRightEnd) {
                return 1;
            }
            if (*pszLeftCur != '^') {
                return 1;
            }
            if (*pszRightCur != '^') {
                return -1;
            }
            ++pszLeftCur;
            ++pszRightCur;
            continue;
        }

        if (pszLeftCur >= pszLeftEnd && pszRightCur >= pszRightEnd) {
            return 0;
        }
        if (pszLeftCur >= pszLeftEnd) {
            return -1;
        }
        if (pszRightCur >= pszRightEnd) {
            return 1;
        }

        if (isdigit((unsigned char)*pszLeftCur) != isdigit((unsigned char)*pszRightCur)) {
            return isdigit((unsigned char)*pszLeftCur) ? 1 : -1;
        }

        if (isdigit((unsigned char)*pszLeftCur)) {
            const char *pszLeftDigitsEnd = luaDigitRunEnd(pszLeftCur);
            const char *pszRightDigitsEnd = luaDigitRunEnd(pszRightCur);
            const char *pszLeftDigits = luaTrimLeadingZeros(pszLeftCur, pszLeftDigitsEnd);
            const char *pszRightDigits = luaTrimLeadingZeros(pszRightCur, pszRightDigitsEnd);
            const size_t nLeftDigitsLen = (size_t)(pszLeftDigitsEnd - pszLeftDigits);
            const size_t nRightDigitsLen = (size_t)(pszRightDigitsEnd - pszRightDigits);
            int nCmp = 0;

            if (nLeftDigitsLen < nRightDigitsLen) {
                return -1;
            }
            if (nLeftDigitsLen > nRightDigitsLen) {
                return 1;
            }

            nCmp = luaOrderSlice(pszLeftDigits, nLeftDigitsLen, pszRightDigits, nRightDigitsLen);
            if (nCmp != 0) {
                return nCmp;
            }

            pszLeftCur = pszLeftDigitsEnd;
            pszRightCur = pszRightDigitsEnd;
            continue;
        }

        {
            const char *pszLeftAlphaEnd = luaAlphaRunEnd(pszLeftCur);
            const char *pszRightAlphaEnd = luaAlphaRunEnd(pszRightCur);
            const size_t nLeftAlphaLen = (size_t)(pszLeftAlphaEnd - pszLeftCur);
            const size_t nRightAlphaLen = (size_t)(pszRightAlphaEnd - pszRightCur);
            const int nCmp = luaOrderSlice(pszLeftCur, nLeftAlphaLen, pszRightCur, nRightAlphaLen);

            if (nCmp != 0) {
                return nCmp;
            }
            pszLeftCur = pszLeftAlphaEnd;
            pszRightCur = pszRightAlphaEnd;
        }
    }
}

static void luaSplitEvr(
    const char *pszEvr,
    unsigned int *pdwEpoch,
    int *pbHasEpoch,
    const char **ppszVersion,
    size_t *pnVersionLen,
    const char **ppszRelease,
    size_t *pnReleaseLen)
{
    const char *pszBody = pszEvr;
    const char *pszColon = strchr(pszEvr, ':');
    const char *pszDash = NULL;

    *pbHasEpoch = 0;
    *pdwEpoch = 0;
    *ppszVersion = pszEvr;
    *pnVersionLen = 0;
    *ppszRelease = "";
    *pnReleaseLen = 0;

    if (pszColon && pszColon != pszEvr) {
        char *pszEnd = NULL;
        unsigned long dwEpoch = strtoul(pszEvr, &pszEnd, 10);

        if (pszEnd == pszColon) {
            *pbHasEpoch = 1;
            *pdwEpoch = (unsigned int)dwEpoch;
            pszBody = pszColon + 1;
        }
    }

    if (*pszBody == '\0') {
        *ppszVersion = "";
        *pnVersionLen = 0;
        return;
    }

    pszDash = strrchr(pszBody, '-');
    if (pszDash && pszDash != pszBody && pszDash[1] != '\0') {
        *ppszVersion = pszBody;
        *pnVersionLen = (size_t)(pszDash - pszBody);
        *ppszRelease = pszDash + 1;
        *pnReleaseLen = strlen(pszDash + 1);
        return;
    }

    *ppszVersion = pszBody;
    *pnVersionLen = strlen(pszBody);
}

static int luaCompareEvr(const char *pszLeft, const char *pszRight)
{
    unsigned int dwLeftEpoch = 0;
    unsigned int dwRightEpoch = 0;
    int bLeftHasEpoch = 0;
    int bRightHasEpoch = 0;
    const char *pszLeftVersion = NULL;
    const char *pszRightVersion = NULL;
    size_t nLeftVersionLen = 0;
    size_t nRightVersionLen = 0;
    const char *pszLeftRelease = NULL;
    const char *pszRightRelease = NULL;
    size_t nLeftReleaseLen = 0;
    size_t nRightReleaseLen = 0;
    int nCmp = 0;

    luaSplitEvr(pszLeft, &dwLeftEpoch, &bLeftHasEpoch, &pszLeftVersion, &nLeftVersionLen, &pszLeftRelease, &nLeftReleaseLen);
    luaSplitEvr(pszRight, &dwRightEpoch, &bRightHasEpoch, &pszRightVersion, &nRightVersionLen, &pszRightRelease, &nRightReleaseLen);

    if ((bLeftHasEpoch ? dwLeftEpoch : 0) < (bRightHasEpoch ? dwRightEpoch : 0)) {
        return -1;
    }
    if ((bLeftHasEpoch ? dwLeftEpoch : 0) > (bRightHasEpoch ? dwRightEpoch : 0)) {
        return 1;
    }

    nCmp = luaCompareRpmVersionSlice(pszLeftVersion, nLeftVersionLen, pszRightVersion, nRightVersionLen);
    if (nCmp != 0) {
        return nCmp;
    }

    return luaCompareRpmVersionSlice(pszLeftRelease, nLeftReleaseLen, pszRightRelease, nRightReleaseLen);
}

static int luaRpmVercmp(lua_State *L)
{
    const char *pszLeft = luaL_checkstring(L, 1);
    const char *pszRight = luaL_checkstring(L, 2);

    lua_pushinteger(L, luaCompareEvr(pszLeft, pszRight));
    return 1;
}

static void luaBuildArgTable(lua_State *L, int nArg1, int nArg2)
{
    int nIndex = 1;

    lua_newtable(L);
    lua_pushstring(L, "<lua>");
    lua_rawseti(L, -2, nIndex++);

    if (nArg1 >= 0) {
        lua_pushfstring(L, "%d", nArg1);
        lua_rawseti(L, -2, nIndex++);
    }
    if (nArg2 >= 0) {
        lua_pushfstring(L, "%d", nArg2);
        lua_rawseti(L, -2, nIndex++);
    }
}

static char *luaBuildScriptBuffer(const char *pszScript, size_t nScriptLen, int nArg1, int nArg2)
{
    static const char szPrelude[] = "local opt, arg = ...;";
    static const char szArg1[] = "arg[2] = tonumber(arg[2]);";
    static const char szArg2[] = "arg[3] = tonumber(arg[3]);";
    const size_t nPreludeLen = sizeof(szPrelude) - 1;
    const size_t nArg1Len = nArg1 >= 0 ? sizeof(szArg1) - 1 : 0;
    const size_t nArg2Len = nArg2 >= 0 ? sizeof(szArg2) - 1 : 0;
    char *pszBuffer = (char *)malloc(nPreludeLen + nArg1Len + nArg2Len + nScriptLen + 1);

    if (!pszBuffer) {
        return NULL;
    }

    memcpy(pszBuffer, szPrelude, nPreludeLen);
    if (nArg1Len) {
        memcpy(pszBuffer + nPreludeLen, szArg1, nArg1Len);
    }
    if (nArg2Len) {
        memcpy(pszBuffer + nPreludeLen + nArg1Len, szArg2, nArg2Len);
    }
    memcpy(pszBuffer + nPreludeLen + nArg1Len + nArg2Len, pszScript, nScriptLen);
    pszBuffer[nPreludeLen + nArg1Len + nArg2Len + nScriptLen] = '\0';

    return pszBuffer;
}

int tdnf_rpmzig_lua_supported(void)
{
    return 1;
}

int tdnf_rpmzig_lua_run(const char *pszScript, size_t nScriptLen, int nArg1, int nArg2)
{
    lua_State *L = NULL;
    char *pszBuffer = NULL;
    int nRc = 1;

    if (!pszScript) {
        fprintf(stderr, "lua setup failed: missing script body\n");
        return 1;
    }

    L = luaL_newstate();
    if (!L) {
        fprintf(stderr, "lua setup failed: out of memory\n");
        return 1;
    }

    luaL_openlibs(L);
    luaCreateFilesIterMetatable(L);
    luaL_requiref(L, "rpm", luaOpenRpm, 1);
    lua_pop(L, 1);
    luaL_requiref(L, "posix", luaOpenPosix, 1);
    lua_pop(L, 1);

    pszBuffer = luaBuildScriptBuffer(pszScript, nScriptLen, nArg1, nArg2);
    if (!pszBuffer) {
        fprintf(stderr, "lua setup failed: out of memory\n");
        goto cleanup;
    }

    if (luaL_loadbuffer(L, pszBuffer, strlen(pszBuffer), "<lua>") != LUA_OK) {
        fprintf(stderr, "invalid syntax in lua scriptlet: %s\n", lua_tostring(L, -1));
        lua_pop(L, 1);
        goto cleanup;
    }

    lua_newtable(L);
    luaBuildArgTable(L, nArg1, nArg2);

    if (lua_pcall(L, 2, LUA_MULTRET, 0) != LUA_OK) {
        fprintf(stderr, "lua script failed: %s\n", lua_tostring(L, -1));
        lua_pop(L, 1);
        goto cleanup;
    }

    nRc = 0;

cleanup:
    free(pszBuffer);
    if (L) {
        lua_close(L);
    }
    return nRc;
}
