// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const c = @cImport({
    @cInclude("errno.h");
    @cInclude("jsondump.h");
    @cInclude("stdio.h");
    @cInclude("tdnf.h");
    @cInclude("tdnfcli.h");
    @cInclude("tdnferror.h");
});
const output = @import("output.zig");

extern fn log_console(loglevel: i32, format: [*:0]const u8, ...) void;
extern fn TDNFFreeMemory(pMemory: ?*anyopaque) void;
extern fn TDNFFreeStringArray(ppszArray: [*c]?[*:0]u8) void;
extern fn TDNFUtilsFormatSize(unSize: u64, ppszFormattedSize: ?*?[*:0]u8) u32;
extern fn GlobalGetDnfCheckUpdateCompat() bool;

const LOG_INFO: c_int = 0;
const LOG_CRIT: c_int = 2;
const MAX_COL_LEN: usize = 256;
const LIST_COL_COUNT: c_int = 3;

fn checkJsonResult(nResult: c_int) u32 {
    if (nResult != 0) {
        return c.ERROR_TDNF_JSONDUMP;
    }
    return 0;
}

fn destroyJsonDump(ppDump: *?*c.struct_json_dump) void {
    if (ppDump.*) |pDump| {
        c.jd_destroy(pDump);
        ppDump.* = null;
    }
}

fn freeOwnedString(ppValue: *?[*:0]u8) void {
    if (ppValue.*) |value| {
        TDNFFreeMemory(@ptrCast(value));
        ppValue.* = null;
    }
}

fn freeStringArray(ppszArray: [*c][*c]u8) void {
    if (ppszArray != null) {
        TDNFFreeStringArray(ppszArray);
    }
}

fn getErrno() c_int {
    return c.__errno_location().*;
}

fn TDNFCliListPackagesPrint(
    pPkgInfo: [*c]c.TDNF_PKG_INFO,
    dwCount: u32,
    nJsonOutput: c_int,
) u32 {
    if (nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(0);
        if (jd == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd);

        _ = c.jd_list_start(jd);

        var dwIndex: u32 = 0;
        while (dwIndex < dwCount) : (dwIndex += 1) {
            var jd_pkg: ?*c.struct_json_dump = c.jd_create(0);
            if (jd_pkg == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd_pkg);

            var dwError = checkJsonResult(c.jd_map_start(jd_pkg));
            if (dwError != 0) {
                return dwError;
            }

            const pPkg = &pPkgInfo[@intCast(dwIndex)];

            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Name", pPkg.pszName));
            if (dwError != 0) {
                return dwError;
            }
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Arch", pPkg.pszArch));
            if (dwError != 0) {
                return dwError;
            }
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Evr", pPkg.pszEVR));
            if (dwError != 0) {
                return dwError;
            }
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Repo", pPkg.pszRepoName));
            if (dwError != 0) {
                return dwError;
            }
            dwError = checkJsonResult(c.jd_list_add_child(jd, jd_pkg));
            if (dwError != 0) {
                return dwError;
            }

            destroyJsonDump(&jd_pkg);
        }

        _ = c.fputs(jd.?.buf, c.stdout);
        return 0;
    }

    var nColPercents = [_]c_int{ 55, 25, 15 };
    var nColWidths = [_]c_int{0} ** LIST_COL_COUNT;

    const dwError = output.GetColumnWidths(LIST_COL_COUNT, &nColPercents, &nColWidths);
    if (dwError != 0) {
        return dwError;
    }

    var dwIndex: u32 = 0;
    while (dwIndex < dwCount) : (dwIndex += 1) {
        const pPkg = &pPkgInfo[@intCast(dwIndex)];
        var szNameAndArch = [_]u8{0} ** MAX_COL_LEN;
        var szVersionAndRelease = [_]u8{0} ** MAX_COL_LEN;

        if (c.snprintf(&szNameAndArch, szNameAndArch.len, "%s.%s ", pPkg.pszName, pPkg.pszArch) < 0) {
            return @as(u32, @intCast(getErrno()));
        }

        if (c.snprintf(&szVersionAndRelease, szVersionAndRelease.len, "%s ", pPkg.pszEVR) < 0) {
            return @as(u32, @intCast(getErrno()));
        }

        log_console(
            LOG_CRIT,
            "%-*s %-*s %*s\n",
            nColWidths[0],
            @as([*:0]const u8, @ptrCast(&szNameAndArch)),
            nColWidths[1],
            @as([*:0]const u8, @ptrCast(&szVersionAndRelease)),
            nColWidths[2],
            pPkg.pszRepoName,
        );
    }

    return 0;
}

pub export fn TDNFCliCleanCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnClean == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var nCleanType: u32 = c.CLEANTYPE_NONE;
    var dwError = c.TDNFCliParseCleanArgs(cmd_args, &nCleanType);
    if (dwError != 0) {
        return dwError;
    }

    dwError = context.pFnClean.?(context, nCleanType);
    if (dwError != 0) {
        return dwError;
    }

    log_console(LOG_INFO, "Done.\n");
    return 0;
}

pub export fn TDNFCliCountCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnCount == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var dwCount: u32 = 0;
    const dwError = context.pFnCount.?(context, &dwCount);
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        _ = c.fprintf(c.stdout, "%u", dwCount);
    } else {
        log_console(LOG_CRIT, "Package count = %u\n", dwCount);
    }

    return 0;
}

pub export fn TDNFCliListCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnList == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var pPkgInfo: [*c]c.TDNF_PKG_INFO = null;
    var dwCount: u32 = 0;
    var pListArgs: ?*c.TDNF_LIST_ARGS = null;
    defer if (pListArgs != null) c.TDNFCliFreeListArgs(pListArgs);
    defer if (pPkgInfo != null) c.TDNFFreePackageInfoArray(pPkgInfo, dwCount);

    var dwError = c.TDNFCliParseListArgs(cmd_args, &pListArgs);
    if (dwError != 0) {
        return dwError;
    }

    dwError = context.pFnList.?(context, pListArgs, &pPkgInfo, &dwCount);
    if (cmd_args.nJsonOutput != 0 and dwError == c.ERROR_TDNF_NO_MATCH) {
        dwError = 0;
    }
    if (dwError != 0) {
        return dwError;
    }

    return TDNFCliListPackagesPrint(pPkgInfo, dwCount, cmd_args.nJsonOutput);
}

pub export fn TDNFCliInfoCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnInfo == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var pszFormattedSize: ?[*:0]u8 = null;
    defer freeOwnedString(&pszFormattedSize);

    var pPkgInfo: [*c]c.TDNF_PKG_INFO = null;
    var pInfoArgs: ?*c.TDNF_LIST_ARGS = null;
    var dwCount: u32 = 0;
    defer if (pInfoArgs != null) c.TDNFCliFreeListArgs(pInfoArgs);
    defer if (pPkgInfo != null) c.TDNFFreePackageInfoArray(pPkgInfo, dwCount);

    var dwError = c.TDNFCliParseInfoArgs(cmd_args, &pInfoArgs);
    if (dwError != 0) {
        return dwError;
    }

    dwError = context.pFnInfo.?(context, pInfoArgs, &pPkgInfo, &dwCount);
    if (cmd_args.nJsonOutput != 0 and dwError == c.ERROR_TDNF_NO_MATCH) {
        dwError = 0;
    }
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(1024);
        if (jd == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd);

        dwError = checkJsonResult(c.jd_list_start(jd));
        if (dwError != 0) {
            return dwError;
        }

        var dwIndex: u32 = 0;
        while (dwIndex < dwCount) : (dwIndex += 1) {
            var jd_pkg: ?*c.struct_json_dump = c.jd_create(0);
            if (jd_pkg == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd_pkg);

            dwError = checkJsonResult(c.jd_map_start(jd_pkg));
            if (dwError != 0) {
                return dwError;
            }

            const pPkg = &pPkgInfo[@intCast(dwIndex)];

            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Name", pPkg.pszName));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Arch", pPkg.pszArch));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Evr", pPkg.pszEVR));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Repo", pPkg.pszRepoName));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Url", pPkg.pszURL));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_int(
                jd_pkg,
                "InstallSize",
                @as(c_int, @intCast(pPkg.dwInstallSizeBytes)),
            ));
            if (dwError != 0) return dwError;
            if (pPkg.dwDownloadSizeBytes != 0) {
                dwError = checkJsonResult(c.jd_map_add_int(
                    jd_pkg,
                    "DownloadSize",
                    @as(c_int, @intCast(pPkg.dwDownloadSizeBytes)),
                ));
                if (dwError != 0) return dwError;
            }
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Summary", pPkg.pszSummary));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "License", pPkg.pszLicense));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Description", pPkg.pszDescription));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_list_add_child(jd, jd_pkg));
            if (dwError != 0) return dwError;

            destroyJsonDump(&jd_pkg);
        }

        _ = c.fputs(jd.?.buf, c.stdout);
        return 0;
    }

    var dwTotalSize: u64 = 0;
    var dwIndex: u32 = 0;
    while (dwIndex < dwCount) : (dwIndex += 1) {
        const pPkg = &pPkgInfo[@intCast(dwIndex)];

        log_console(LOG_CRIT, "Name          : %s\n", pPkg.pszName);
        log_console(LOG_CRIT, "Arch          : %s\n", pPkg.pszArch);
        log_console(LOG_CRIT, "Epoch         : %d\n", @as(c_int, @intCast(pPkg.dwEpoch)));
        log_console(LOG_CRIT, "Version       : %s\n", pPkg.pszVersion);
        log_console(LOG_CRIT, "Release       : %s\n", pPkg.pszRelease);
        log_console(
            LOG_CRIT,
            "Install Size  : %s (%u)\n",
            pPkg.pszFormattedSize,
            pPkg.dwInstallSizeBytes,
        );
        if (pPkg.dwDownloadSizeBytes != 0) {
            log_console(
                LOG_CRIT,
                "Download Size  : %s (%u)\n",
                pPkg.pszFormattedDownloadSize,
                pPkg.dwDownloadSizeBytes,
            );
        }
        log_console(LOG_CRIT, "Repo          : %s\n", pPkg.pszRepoName);
        log_console(LOG_CRIT, "Summary       : %s\n", pPkg.pszSummary);
        log_console(LOG_CRIT, "URL           : %s\n", pPkg.pszURL);
        log_console(LOG_CRIT, "License       : %s\n", pPkg.pszLicense);
        log_console(LOG_CRIT, "Description   : %s\n", pPkg.pszDescription);
        log_console(LOG_CRIT, "\n");

        dwTotalSize += pPkg.dwInstallSizeBytes;
    }

    dwError = TDNFUtilsFormatSize(dwTotalSize, &pszFormattedSize);
    if (dwError != 0) {
        return dwError;
    }

    if (dwCount > 0) {
        log_console(
            LOG_CRIT,
            "\nTotal Size: %s (%lu)\n",
            pszFormattedSize.?,
            @as(c_ulong, @intCast(dwTotalSize)),
        );
    }

    return 0;
}

pub export fn TDNFCliRepoListCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnRepoList == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var pRepoList: ?*c.TDNF_REPO_DATA = null;
    defer c.TDNFFreeRepos(pRepoList);

    var nFilter: c.TDNF_REPOLISTFILTER = c.REPOLISTFILTER_ENABLED;
    var dwError = c.TDNFCliParseRepoListArgs(cmd_args, &nFilter);
    if (dwError != 0) {
        return dwError;
    }

    dwError = context.pFnRepoList.?(context, nFilter, &pRepoList);
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(0);
        if (jd == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd);

        _ = c.jd_list_start(jd);

        var pRepo = pRepoList;
        while (pRepo) |repo| : (pRepo = repo.pNext) {
            var jd_repo: ?*c.struct_json_dump = c.jd_create(0);
            if (jd_repo == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd_repo);

            dwError = checkJsonResult(c.jd_map_start(jd_repo));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_repo, "Repo", repo.pszId));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_repo, "RepoName", repo.pszName));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_bool(jd_repo, "Enabled", repo.nEnabled));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_list_add_child(jd, jd_repo));
            if (dwError != 0) return dwError;

            destroyJsonDump(&jd_repo);
        }

        _ = c.fputs(jd.?.buf, c.stdout);
        return 0;
    }

    if (pRepoList != null) {
        log_console(LOG_CRIT, "%-20s%-41s%-9s\n", "repo id", "repo name", "status");
    }

    var pRepo = pRepoList;
    while (pRepo) |repo| : (pRepo = repo.pNext) {
        log_console(
            LOG_CRIT,
            "%-19s %-40s %-9s\n",
            repo.pszId,
            repo.pszName,
            if (repo.nEnabled != 0)
                @as([*:0]const u8, "enabled")
            else
                @as([*:0]const u8, "disabled"),
        );
    }

    return 0;
}

pub export fn TDNFCliSearchCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnSearch == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var pPkgInfo: [*c]c.TDNF_PKG_INFO = null;
    var dwCount: u32 = 0;
    defer c.TDNFFreePackageInfoArray(pPkgInfo, dwCount);

    var dwError = context.pFnSearch.?(context, cmd_args, &pPkgInfo, &dwCount);
    if (cmd_args.nJsonOutput != 0 and dwError == c.ERROR_TDNF_NO_SEARCH_RESULTS) {
        dwError = 0;
    }
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(0);
        if (jd == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd);

        _ = c.jd_list_start(jd);

        var dwIndex: u32 = 0;
        while (dwIndex < dwCount) : (dwIndex += 1) {
            var jd_pkg: ?*c.struct_json_dump = c.jd_create(0);
            if (jd_pkg == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd_pkg);

            dwError = checkJsonResult(c.jd_map_start(jd_pkg));
            if (dwError != 0) {
                return dwError;
            }

            const pPkg = &pPkgInfo[@intCast(dwIndex)];
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Name", pPkg.pszName));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Summary", pPkg.pszSummary));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_list_add_child(jd, jd_pkg));
            if (dwError != 0) return dwError;

            destroyJsonDump(&jd_pkg);
        }

        _ = c.fputs(jd.?.buf, c.stdout);
        return 0;
    }

    var dwIndex: u32 = 0;
    while (dwIndex < dwCount) : (dwIndex += 1) {
        const pPkg = &pPkgInfo[@intCast(dwIndex)];
        log_console(LOG_CRIT, "%s : %s\n", pPkg.pszName, pPkg.pszSummary);
    }

    return 0;
}

pub export fn TDNFCliCheckLocalCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnCheckLocal == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    if (cmd_args.nCmdCount < 2) {
        return c.ERROR_TDNF_CLI_CHECKLOCAL_EXPECT_DIR;
    }

    const dwError = context.pFnCheckLocal.?(context, cmd_args.ppszCmds[1]);
    if (dwError != 0) {
        return dwError;
    }

    log_console(LOG_CRIT, "Check completed without issues\n");
    return 0;
}

pub export fn TDNFCliProvidesCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnProvides == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    if (cmd_args.nCmdCount < 2) {
        return c.ERROR_TDNF_CLI_PROVIDES_EXPECT_ARG;
    }

    var pPkgInfos: ?*c.TDNF_PKG_INFO = null;
    defer c.TDNFFreePackageInfo(pPkgInfos);

    var dwError = context.pFnProvides.?(context, cmd_args.ppszCmds[1], &pPkgInfos);
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(0);
        if (jd == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd);

        _ = c.jd_list_start(jd);

        var pPkg = pPkgInfos;
        while (pPkg) |pkg| : (pPkg = pkg.pNext) {
            var jd_pkg: ?*c.struct_json_dump = c.jd_create(0);
            if (jd_pkg == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd_pkg);

            dwError = checkJsonResult(c.jd_map_start(jd_pkg));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Name", pkg.pszName));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Arch", pkg.pszArch));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Evr", pkg.pszEVR));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Summary", pkg.pszSummary));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_list_add_child(jd, jd_pkg));
            if (dwError != 0) return dwError;

            destroyJsonDump(&jd_pkg);
        }

        _ = c.fputs(jd.?.buf, c.stdout);
        return 0;
    }

    var pPkg = pPkgInfos;
    while (pPkg) |pkg| : (pPkg = pkg.pNext) {
        log_console(LOG_CRIT, "%s-%s.%s : %s\n", pkg.pszName, pkg.pszEVR, pkg.pszArch, pkg.pszSummary);
        log_console(LOG_CRIT, "Repo\t : %s\n", pkg.pszRepoName);
    }

    return 0;
}

pub export fn TDNFCliCheckUpdateCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnCheckUpdate == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    const nCheckUpdateCompat = GlobalGetDnfCheckUpdateCompat();
    var pPkgInfo: [*c]c.TDNF_PKG_INFO = null;
    var dwCount: u32 = 0;
    var ppszPackageArgs: [*c][*c]u8 = null;
    defer freeStringArray(ppszPackageArgs);
    defer if (pPkgInfo != null) c.TDNFFreePackageInfoArray(pPkgInfo, dwCount);

    var nPackageCount: c_int = 0;
    var dwError = c.TDNFCliParsePackageArgs(cmd_args, &ppszPackageArgs, &nPackageCount);
    if (dwError != 0) {
        return dwError;
    }

    dwError = context.pFnCheckUpdate.?(context, ppszPackageArgs, &pPkgInfo, &dwCount);
    if (dwError != 0) {
        return dwError;
    }

    if (!nCheckUpdateCompat and cmd_args.nJsonOutput == 0) {
        var dwIndex: u32 = 0;
        while (dwIndex < dwCount) : (dwIndex += 1) {
            const pPkg = &pPkgInfo[@intCast(dwIndex)];
            log_console(LOG_CRIT, "%*s\r", @as(c_int, 80), pPkg.pszRepoName);
            log_console(LOG_CRIT, "%*s\r", @as(c_int, 50), pPkg.pszEVR);
            log_console(LOG_CRIT, "%s.%s", pPkg.pszName, pPkg.pszArch);
            log_console(LOG_CRIT, "\n");
        }
    } else {
        dwError = TDNFCliListPackagesPrint(pPkgInfo, dwCount, cmd_args.nJsonOutput);
        if (dwError != 0) {
            return dwError;
        }
    }

    if (nCheckUpdateCompat and dwCount > 0) {
        return c.ERROR_TDNF_CLI_CHECK_UPDATES_AVAILABLE;
    }

    return 0;
}

pub export fn TDNFCliCheckCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    _ = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    const dwError = context.pFnCheck.?(context);
    if (dwError != 0) {
        return dwError;
    }

    log_console(LOG_CRIT, "Check completed without issues\n");
    return 0;
}
