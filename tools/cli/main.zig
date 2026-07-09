// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("jsondump.h");
    @cInclude("stdio.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
    @cInclude("tdnf.h");
    @cInclude("tdnfcli.h");
    @cInclude("tdnferror.h");
});

extern fn log_console(loglevel: i32, format: [*:0]const u8, ...) void;
extern fn TDNFFreeMemory(pMemory: ?*anyopaque) void;

const LOG_INFO: c_int = 0;
const LOG_ERR: c_int = 1;

const command_map = [_]c.TDNF_CLI_CMD_MAP{
    .{ .pszCmdName = "autoerase", .pFnCmd = c.TDNFCliAutoEraseCommand, .ReqRoot = true },
    .{ .pszCmdName = "autoremove", .pFnCmd = c.TDNFCliAutoEraseCommand, .ReqRoot = true },
    .{ .pszCmdName = "check", .pFnCmd = c.TDNFCliCheckCommand, .ReqRoot = false },
    .{ .pszCmdName = "check-local", .pFnCmd = c.TDNFCliCheckLocalCommand, .ReqRoot = false },
    .{ .pszCmdName = "check-update", .pFnCmd = c.TDNFCliCheckUpdateCommand, .ReqRoot = false },
    .{ .pszCmdName = "clean", .pFnCmd = c.TDNFCliCleanCommand, .ReqRoot = false },
    .{ .pszCmdName = "count", .pFnCmd = c.TDNFCliCountCommand, .ReqRoot = false },
    .{ .pszCmdName = "distro-sync", .pFnCmd = c.TDNFCliDistroSyncCommand, .ReqRoot = true },
    .{ .pszCmdName = "downgrade", .pFnCmd = c.TDNFCliDowngradeCommand, .ReqRoot = true },
    .{ .pszCmdName = "erase", .pFnCmd = c.TDNFCliEraseCommand, .ReqRoot = true },
    .{ .pszCmdName = "help", .pFnCmd = c.TDNFCliHelpCommand, .ReqRoot = false },
    .{ .pszCmdName = "history", .pFnCmd = c.TDNFCliHistoryCommand, .ReqRoot = true },
    .{ .pszCmdName = "info", .pFnCmd = c.TDNFCliInfoCommand, .ReqRoot = false },
    .{ .pszCmdName = "install", .pFnCmd = c.TDNFCliInstallCommand, .ReqRoot = true },
    .{ .pszCmdName = "list", .pFnCmd = c.TDNFCliListCommand, .ReqRoot = false },
    .{ .pszCmdName = "makecache", .pFnCmd = c.TDNFCliMakeCacheCommand, .ReqRoot = false },
    .{ .pszCmdName = "mark", .pFnCmd = c.TDNFCliMarkCommand, .ReqRoot = false },
    .{ .pszCmdName = "provides", .pFnCmd = c.TDNFCliProvidesCommand, .ReqRoot = false },
    .{ .pszCmdName = "whatprovides", .pFnCmd = c.TDNFCliProvidesCommand, .ReqRoot = false },
    .{ .pszCmdName = "reinstall", .pFnCmd = c.TDNFCliReinstallCommand, .ReqRoot = true },
    .{ .pszCmdName = "remove", .pFnCmd = c.TDNFCliEraseCommand, .ReqRoot = true },
    .{ .pszCmdName = "repolist", .pFnCmd = c.TDNFCliRepoListCommand, .ReqRoot = false },
    .{ .pszCmdName = "reposync", .pFnCmd = c.TDNFCliRepoSyncCommand, .ReqRoot = false },
    .{ .pszCmdName = "repoquery", .pFnCmd = c.TDNFCliRepoQueryCommand, .ReqRoot = false },
    .{ .pszCmdName = "search", .pFnCmd = c.TDNFCliSearchCommand, .ReqRoot = false },
    .{ .pszCmdName = "update", .pFnCmd = c.TDNFCliUpgradeCommand, .ReqRoot = true },
    .{ .pszCmdName = "update-to", .pFnCmd = c.TDNFCliUpgradeCommand, .ReqRoot = true },
    .{ .pszCmdName = "upgrade", .pFnCmd = c.TDNFCliUpgradeCommand, .ReqRoot = true },
    .{ .pszCmdName = "upgrade-to", .pFnCmd = c.TDNFCliUpgradeCommand, .ReqRoot = true },
    .{ .pszCmdName = "updateinfo", .pFnCmd = c.TDNFCliUpdateInfoCommand, .ReqRoot = false },
};

fn destroyJsonDump(ppDump: *?*c.struct_json_dump) void {
    if (ppDump.*) |pDump| {
        c.jd_destroy(pDump);
        ppDump.* = null;
    }
}

fn checkJsonResult(nResult: c_int) u32 {
    if (nResult != 0) {
        return c.ERROR_TDNF_JSONDUMP;
    }
    return 0;
}

fn freeOwnedString(ppValue: *?[*:0]u8) void {
    if (ppValue.*) |value| {
        TDNFFreeMemory(@ptrCast(value));
        ppValue.* = null;
    }
}

fn cliHandle(pContext: ?*c.TDNF_CLI_CONTEXT) c.PTDNF {
    return @ptrCast(pContext.?.hTdnf);
}

fn findCommand(pszCmd: [*c]const u8) ?*const c.TDNF_CLI_CMD_MAP {
    for (&command_map) |*cmd| {
        if (c.strcmp(pszCmd, cmd.pszCmdName) == 0) {
            return cmd;
        }
    }
    return null;
}

fn initializeContext() c.TDNF_CLI_CONTEXT {
    var context: c.TDNF_CLI_CONTEXT = std.mem.zeroes(c.TDNF_CLI_CONTEXT);

    context.pFnCheck = TDNFCliInvokeCheck;
    context.pFnCheckLocal = TDNFCliInvokeCheckLocal;
    context.pFnCheckUpdate = TDNFCliInvokeCheckUpdate;
    context.pFnClean = TDNFCliInvokeClean;
    context.pFnCount = TDNFCliInvokeCount;
    context.pFnInfo = TDNFCliInvokeInfo;
    context.pFnList = TDNFCliInvokeList;
    context.pFnProvides = TDNFCliInvokeProvides;
    context.pFnRepoList = TDNFCliInvokeRepoList;
    context.pFnRepoSync = TDNFCliInvokeRepoSync;
    context.pFnRepoQuery = TDNFCliInvokeRepoQuery;
    context.pFnAlter = TDNFCliInvokeAlter;
    context.pFnResolve = TDNFCliInvokeResolve;
    context.pFnSearch = TDNFCliInvokeSearch;
    context.pFnUpdateInfo = TDNFCliInvokeUpdateInfo;
    context.pFnUpdateInfoSummary = TDNFCliInvokeUpdateInfoSummary;
    context.pFnHistoryList = TDNFCliInvokeHistoryList;
    context.pFnHistoryResolve = TDNFCliInvokeHistoryResolve;
    context.pFnAlterHistory = TDNFCliInvokeAlterHistory;
    context.pFnMark = TDNFCliInvokeMark;
    context.pFnGetPackageUrls = TDNFCliInvokeGetPackageUrls;
    context.pFnHistoryGetId = TDNFCliInvokeHistoryGetId;

    return context;
}

fn TDNFCliPrintError(dwErrorCode: u32, doJson: c_int) u32 {
    if (dwErrorCode == 0 or dwErrorCode == c.ERROR_TDNF_CLI_CHECK_UPDATES_AVAILABLE) {
        return 0;
    }

    var dwError: u32 = 0;
    var pszError: ?[*:0]u8 = null;
    defer freeOwnedString(&pszError);

    if (dwErrorCode < c.ERROR_TDNF_BASE) {
        dwError = c.TDNFCliGetErrorString(dwErrorCode, @ptrCast(&pszError));
    } else {
        dwError = c.TDNFGetErrorString(dwErrorCode, @ptrCast(&pszError));
    }

    if (dwError != 0 or pszError == null) {
        log_console(LOG_ERR, "Retrieving error string for %u failed with %u\n", dwErrorCode, dwError);
        return dwError;
    }

    var dwPrintCode = dwErrorCode;
    if (dwPrintCode == c.ERROR_TDNF_CLI_NOTHING_TO_DO or dwPrintCode == c.ERROR_TDNF_NO_DATA) {
        dwPrintCode = 0;
    }

    if (doJson != 0) {
        if (dwPrintCode != 0) {
            var jd: ?*c.struct_json_dump = c.jd_create(0);
            if (jd == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd);

            dwError = checkJsonResult(c.jd_map_start(jd));
            if (dwError != 0) {
                return dwError;
            }
            dwError = checkJsonResult(c.jd_map_add_int(jd, "Error", @as(c_int, @intCast(dwPrintCode))));
            if (dwError != 0) {
                return dwError;
            }
            dwError = checkJsonResult(c.jd_map_add_string(jd, "ErrorMessage", pszError));
            if (dwError != 0) {
                return dwError;
            }
            _ = c.fputs(jd.?.buf, c.stdout);
        }
    } else if (dwPrintCode != 0) {
        log_console(LOG_ERR, "Error(%u) : %s\n", dwPrintCode, pszError.?);
    } else {
        log_console(LOG_ERR, "%s\n", pszError.?);
    }

    return 0;
}

fn TDNFCliShowVersion(pCmdArgs: ?*c.TDNF_CMD_ARGS) void {
    const cmd_args = pCmdArgs orelse return;

    if (cmd_args.nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(0);
        if (jd == null) {
            return;
        }
        defer destroyJsonDump(&jd);

        if (checkJsonResult(c.jd_map_start(jd)) != 0) {
            return;
        }
        if (checkJsonResult(c.jd_map_add_string(jd, "Name", c.TDNFGetPackageName())) != 0) {
            return;
        }
        if (checkJsonResult(c.jd_map_add_string(jd, "Version", c.TDNFGetVersion())) != 0) {
            return;
        }
        _ = c.fputs(jd.?.buf, c.stdout);
    } else {
        log_console(LOG_INFO, "%s: %s\n", c.TDNFGetPackageName(), c.TDNFGetVersion());
    }
}

fn TDNFCliInvokeCheck(pContext: ?*c.TDNF_CLI_CONTEXT) callconv(.c) u32 {
    return c.TDNFCheckPackages(cliHandle(pContext));
}

fn TDNFCliInvokeCheckLocal(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pszFolder: [*c]const u8,
) callconv(.c) u32 {
    return c.TDNFCheckLocalPackages(cliHandle(pContext), pszFolder);
}

fn TDNFCliInvokeCheckUpdate(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    ppszPackageArgs: [*c][*c]u8,
    ppPkgInfo: ?*[*c]c.TDNF_PKG_INFO,
    pdwCount: ?*u32,
) callconv(.c) u32 {
    return c.TDNFCheckUpdates(cliHandle(pContext), ppszPackageArgs, ppPkgInfo, pdwCount);
}

fn TDNFCliInvokeClean(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    nCleanType: u32,
) callconv(.c) u32 {
    return c.TDNFClean(cliHandle(pContext), nCleanType);
}

fn TDNFCliInvokeCount(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pnCount: ?*u32,
) callconv(.c) u32 {
    return c.TDNFCountCommand(cliHandle(pContext), pnCount);
}

fn TDNFCliInvokeAlter(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO,
) callconv(.c) u32 {
    return c.TDNFAlterCommand(cliHandle(pContext), pSolvedPkgInfo);
}

fn TDNFCliInvokeAlterHistory(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO,
    pHistoryArgs: ?*c.TDNF_HISTORY_ARGS,
) callconv(.c) u32 {
    return c.TDNFAlterHistoryCommand(cliHandle(pContext), pSolvedPkgInfo, pHistoryArgs);
}

fn TDNFCliInvokeInfo(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pInfoArgs: ?*c.TDNF_LIST_ARGS,
    ppPkgInfo: ?*[*c]c.TDNF_PKG_INFO,
    pdwCount: ?*u32,
) callconv(.c) u32 {
    return c.TDNFInfo(cliHandle(pContext), pInfoArgs.?.nScope, pInfoArgs.?.ppszPackageNameSpecs, ppPkgInfo, pdwCount);
}

fn TDNFCliInvokeList(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pListArgs: ?*c.TDNF_LIST_ARGS,
    ppPkgInfo: ?*[*c]c.TDNF_PKG_INFO,
    pdwCount: ?*u32,
) callconv(.c) u32 {
    return c.TDNFList(cliHandle(pContext), pListArgs.?.nScope, pListArgs.?.ppszPackageNameSpecs, ppPkgInfo, pdwCount);
}

fn TDNFCliInvokeProvides(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pszProvides: [*c]const u8,
    ppPkgInfos: ?*?*c.TDNF_PKG_INFO,
) callconv(.c) u32 {
    return c.TDNFProvides(cliHandle(pContext), pszProvides, ppPkgInfos);
}

fn TDNFCliInvokeRepoList(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    nFilter: c.TDNF_REPOLISTFILTER,
    ppRepos: ?*?*c.TDNF_REPO_DATA,
) callconv(.c) u32 {
    return c.TDNFRepoList(cliHandle(pContext), nFilter, ppRepos);
}

fn TDNFCliInvokeRepoSync(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pRepoSyncArgs: ?*c.TDNF_REPOSYNC_ARGS,
) callconv(.c) u32 {
    return c.TDNFRepoSync(cliHandle(pContext), pRepoSyncArgs);
}

fn TDNFCliInvokeRepoQuery(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pRepoQueryArgs: ?*c.TDNF_REPOQUERY_ARGS,
    ppPkgInfos: ?*[*c]c.TDNF_PKG_INFO,
    pdwCount: ?*u32,
) callconv(.c) u32 {
    return c.TDNFRepoQuery(cliHandle(pContext), pRepoQueryArgs, ppPkgInfos, pdwCount);
}

fn TDNFCliInvokeResolve(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    nAlterType: c.TDNF_ALTERTYPE,
    ppSolvedPkgInfo: ?*?*c.TDNF_SOLVED_PKG_INFO,
) callconv(.c) u32 {
    return c.TDNFResolve(cliHandle(pContext), nAlterType, ppSolvedPkgInfo);
}

fn TDNFCliInvokeSearch(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    ppPkgInfo: ?*[*c]c.TDNF_PKG_INFO,
    pdwCount: ?*u32,
) callconv(.c) u32 {
    return c.TDNFSearchCommand(cliHandle(pContext), pCmdArgs, ppPkgInfo, pdwCount);
}

fn TDNFCliInvokeUpdateInfo(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pInfoArgs: ?*c.TDNF_UPDATEINFO_ARGS,
    ppUpdateInfo: ?*?*c.TDNF_UPDATEINFO,
) callconv(.c) u32 {
    return c.TDNFUpdateInfo(cliHandle(pContext), pInfoArgs.?.ppszPackageNameSpecs, ppUpdateInfo);
}

fn TDNFCliInvokeUpdateInfoSummary(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    nAvail: c.TDNF_AVAIL,
    pInfoArgs: ?*c.TDNF_UPDATEINFO_ARGS,
    ppSummary: ?*?*c.TDNF_UPDATEINFO_SUMMARY,
) callconv(.c) u32 {
    _ = nAvail;
    return c.TDNFUpdateInfoSummary(cliHandle(pContext), pInfoArgs.?.ppszPackageNameSpecs, ppSummary);
}

fn TDNFCliInvokeHistoryList(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pHistoryArgs: ?*c.TDNF_HISTORY_ARGS,
    ppHistoryInfo: ?*?*c.TDNF_HISTORY_INFO,
) callconv(.c) u32 {
    return c.TDNFHistoryList(cliHandle(pContext), pHistoryArgs, ppHistoryInfo);
}

fn TDNFCliInvokeHistoryResolve(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pHistoryArgs: ?*c.TDNF_HISTORY_ARGS,
    ppSolvedPkgInfo: ?*?*c.TDNF_SOLVED_PKG_INFO,
) callconv(.c) u32 {
    return c.TDNFHistoryResolve(cliHandle(pContext), pHistoryArgs, ppSolvedPkgInfo);
}

fn TDNFCliInvokeGetPackageUrls(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO,
    pppszUrls: [*c][*c][*c]u8,
    pnCount: [*c]c_int,
) callconv(.c) u32 {
    return c.TDNFGetPackageUrls(cliHandle(pContext), pSolvedPkgInfo, pppszUrls, pnCount);
}

fn TDNFCliInvokeHistoryGetId(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pnId: ?*c_int,
) callconv(.c) u32 {
    return c.TDNFHistoryGetId(cliHandle(pContext), pnId);
}

fn TDNFCliInvokeMark(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    ppszPkgNameSpecs: [*c][*c]u8,
    nValue: u32,
) callconv(.c) u32 {
    return c.TDNFMark(cliHandle(pContext), ppszPkgNameSpecs, nValue);
}

pub fn main(init: std.process.Init.Minimal) u8 {
    const argv = init.args.vector;
    const argc: c_int = @intCast(argv.len);
    const argv_ptr: [*c]?[*:0]u8 = @ptrCast(@constCast(argv.ptr));

    var dwError: u32 = 0;
    var pTdnf: c.PTDNF = null;
    var pCmdArgs: ?*c.TDNF_CMD_ARGS = null;

    defer {
        if (pTdnf != null) {
            c.TDNFCloseHandle(pTdnf);
        }
        if (pCmdArgs != null) {
            c.TDNFFreeCmdArgs(pCmdArgs);
        }
        c.TDNFUninit();
    }

    dwError = c.TDNFCliParseArgs(argc, @ptrCast(argv_ptr), &pCmdArgs);
    if (dwError == 0) {
        const cmd_args = pCmdArgs.?;

        if (cmd_args.nShowVersion != 0) {
            TDNFCliShowVersion(cmd_args);
        } else if (cmd_args.nShowHelp != 0) {
            c.TDNFCliShowHelp();
        } else if (cmd_args.nCmdCount > 0) {
            const pszCmd: [*c]const u8 = cmd_args.ppszCmds[0];
            var context = initializeContext();

            if (findCommand(pszCmd)) |pCmd| {
                if (pCmd.ReqRoot and c.geteuid() != 0) {
                    dwError = c.ERROR_TDNF_PERM;
                } else {
                    if (c.strcmp(pszCmd, "makecache") == 0) {
                        cmd_args.nRefresh = 1;
                    }

                    dwError = c.TDNFInit();
                    if (dwError == 0) {
                        dwError = c.TDNFOpenHandle(cmd_args, &pTdnf);
                    }
                    if (dwError == 0) {
                        context.hTdnf = @ptrCast(pTdnf);
                        dwError = pCmd.pFnCmd.?(&context, cmd_args);
                    }
                }
            } else {
                if (cmd_args.nJsonOutput == 0) {
                    c.TDNFCliShowNoSuchCommand(pszCmd);
                }
                dwError = c.ERROR_TDNF_CLI_NO_SUCH_CMD;
            }
        } else {
            if (cmd_args.nJsonOutput == 0) {
                c.TDNFCliShowUsage();
            }
            dwError = c.ERROR_TDNF_CLI_NO_SUCH_CMD;
        }
    }

    if (dwError != 0) {
        _ = TDNFCliPrintError(dwError, if (pCmdArgs) |args| args.nJsonOutput else 0);
        if (dwError == c.ERROR_TDNF_CLI_NOTHING_TO_DO or dwError == c.ERROR_TDNF_NO_DATA) {
            dwError = 0;
        }
    }

    return @truncate(dwError);
}
