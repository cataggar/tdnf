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
extern fn TDNFFreeSolvedPackageInfo(pSolvedPkgInfo: c.PTDNF_SOLVED_PKG_INFO) void;
extern fn TDNFUtilsFormatSize(unSize: u64, ppszFormattedSize: ?*?[*:0]u8) u32;
extern fn TDNFYesOrNo(
    pArgs: ?*c.TDNF_CMD_ARGS,
    pszQuestion: ?[*:0]const u8,
    pAnswer: ?*c_int,
) u32;

const LOG_INFO: c_int = 0;
const LOG_CRIT: c_int = 2;
const COL_COUNT: c_int = 6;
const MAX_COL_LEN: usize = 256;

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

fn freeStringArray(ppszArray: [*c][*c]u8) void {
    if (ppszArray != null) {
        TDNFFreeStringArray(ppszArray);
    }
}

fn freeOwnedString(ppValue: *?[*:0]u8) void {
    if (ppValue.*) |value| {
        TDNFFreeMemory(@ptrCast(value));
        ppValue.* = null;
    }
}

fn getErrno() c_int {
    return c.__errno_location().*;
}

fn nonNullString(pszValue: ?[*:0]const u8) [*:0]const u8 {
    return pszValue orelse "";
}

fn mapAlterError(dwError: u32) u32 {
    return if (dwError == c.ERROR_TDNF_ALREADY_INSTALLED)
        c.ERROR_TDNF_CLI_NOTHING_TO_DO
    else
        dwError;
}

fn addSolvedPackageList(
    jd: ?*c.struct_json_dump,
    pszKey: [*:0]const u8,
    pPkgInfos: ?*c.TDNF_PKG_INFO,
) u32 {
    if (pPkgInfos == null) {
        return 0;
    }

    var jd_list: ?*c.struct_json_dump = null;
    defer destroyJsonDump(&jd_list);

    const dwError = JDPkgList(pPkgInfos, &jd_list);
    if (dwError != 0) {
        return dwError;
    }

    return checkJsonResult(c.jd_map_add_child(jd, pszKey, jd_list));
}

fn printActionHeader(nAlterType: c.TDNF_ALTERTYPE) u32 {
    switch (nAlterType) {
        c.ALTER_INSTALL => log_console(LOG_INFO, "\nInstalling:"),
        c.ALTER_UPGRADE => log_console(LOG_INFO, "\nUpgrading:"),
        c.ALTER_ERASE => log_console(LOG_INFO, "\nRemoving:"),
        c.ALTER_DOWNGRADE => log_console(LOG_INFO, "\nDowngrading:"),
        c.ALTER_REINSTALL => log_console(LOG_INFO, "\nReinstalling:"),
        c.ALTER_OBSOLETED => log_console(LOG_INFO, "\nObsoleting:"),
        else => return c.ERROR_TDNF_INVALID_PARAMETER,
    }

    log_console(LOG_INFO, "\n");
    return 0;
}

fn formatEpochVersionRelease(
    pPkgInfo: *c.TDNF_PKG_INFO,
    pszBuffer: *[MAX_COL_LEN]u8,
) u32 {
    const nResult = if (pPkgInfo.dwEpoch != 0)
        c.snprintf(
            pszBuffer,
            pszBuffer.len,
            "%u:%s-%s",
            @as(c_uint, @intCast(pPkgInfo.dwEpoch)),
            pPkgInfo.pszVersion,
            pPkgInfo.pszRelease,
        )
    else
        c.snprintf(
            pszBuffer,
            pszBuffer.len,
            "%s-%s",
            pPkgInfo.pszVersion,
            pPkgInfo.pszRelease,
        );

    if (nResult < 0) {
        return @as(u32, @intCast(getErrno()));
    }

    return 0;
}

fn alterCommandWithType(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    nAlterType: c.TDNF_ALTERTYPE,
) u32 {
    return TDNFCliAlterCommand(pContext, pCmdArgs, nAlterType);
}

fn selectAllIfNoArgs(
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    nDefaultType: c.TDNF_ALTERTYPE,
    nAllType: c.TDNF_ALTERTYPE,
) c.TDNF_ALTERTYPE {
    if (pCmdArgs != null and pCmdArgs.?.nCmdCount == 1) {
        return nAllType;
    }
    return nDefaultType;
}

fn TDNFCliAskAndAlter(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const solved_info = pSolvedPkgInfo orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var dwError = TDNFCliAskForAction(cmd_args, solved_info);
    if (dwError != 0) {
        if (cmd_args.nJsonOutput != 0 and dwError == c.ERROR_TDNF_OPERATION_ABORTED) {
            return 0;
        }
        return dwError;
    }

    dwError = context.pFnAlter.?(context, solved_info);
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        dwError = TDNFCliPrintActionComplete(cmd_args);
        if (dwError != 0) {
            return dwError;
        }
    }

    return 0;
}

pub export fn TDNFCliInstallCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    return alterCommandWithType(pContext, pCmdArgs, c.ALTER_INSTALL);
}

pub export fn TDNFCliEraseCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    return alterCommandWithType(pContext, pCmdArgs, c.ALTER_ERASE);
}

pub export fn TDNFCliUpgradeCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    return alterCommandWithType(
        pContext,
        pCmdArgs,
        selectAllIfNoArgs(pCmdArgs, c.ALTER_UPGRADE, c.ALTER_UPGRADEALL),
    );
}

pub export fn TDNFCliDistroSyncCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    return alterCommandWithType(pContext, pCmdArgs, c.ALTER_DISTRO_SYNC);
}

pub export fn TDNFCliDowngradeCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    return alterCommandWithType(
        pContext,
        pCmdArgs,
        selectAllIfNoArgs(pCmdArgs, c.ALTER_DOWNGRADE, c.ALTER_DOWNGRADEALL),
    );
}

pub export fn TDNFCliAutoEraseCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    return alterCommandWithType(
        pContext,
        pCmdArgs,
        selectAllIfNoArgs(pCmdArgs, c.ALTER_AUTOERASE, c.ALTER_AUTOERASEALL),
    );
}

pub export fn TDNFCliReinstallCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    return alterCommandWithType(pContext, pCmdArgs, c.ALTER_REINSTALL);
}

pub export fn TDNFCliAskForAction(
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO,
) u32 {
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const solved_info = pSolvedPkgInfo orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const nSilent = cmd_args.nNoOutput;

    if (nSilent == 0 and solved_info.ppszPkgsNotResolved != null) {
        const dwError = PrintNotAvailable(solved_info.ppszPkgsNotResolved);
        if (dwError != 0) {
            return dwError;
        }
    }

    if (solved_info.nNeedAction == 0) {
        if (solved_info.ppszPkgsNotResolved != null and solved_info.ppszPkgsNotResolved[0] != null) {
            return c.ERROR_TDNF_NO_MATCH;
        }
        return c.ERROR_TDNF_CLI_NOTHING_TO_DO;
    }

    if (nSilent == 0) {
        var dwError: u32 = 0;

        if (cmd_args.nJsonOutput != 0) {
            dwError = PrintSolvedInfoJson(solved_info);
        } else {
            dwError = PrintSolvedInfo(solved_info);
        }
        if (dwError != 0) {
            return dwError;
        }

        if (cmd_args.nDownloadOnly != 0) {
            log_console(LOG_INFO, "tdnf will only download packages needed for the transaction\n");
        }
    }

    if (solved_info.nNeedAction != 0) {
        var nAnswer: c_int = 0;
        const dwError = TDNFYesOrNo(cmd_args, "Is this ok [y/N]: ", &nAnswer);
        if (dwError != 0) {
            return dwError;
        }
        if (nAnswer == 0) {
            return c.ERROR_TDNF_OPERATION_ABORTED;
        }
    }

    return 0;
}

pub export fn TDNFCliPrintActionComplete(pCmdArgs: ?*c.TDNF_CMD_ARGS) u32 {
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    if (cmd_args.nNoOutput == 0) {
        log_console(LOG_INFO, "\nComplete!\n");
        if (cmd_args.nDownloadOnly != 0) {
            if (cmd_args.pszDownloadDir != null) {
                log_console(
                    LOG_INFO,
                    "Packages have been downloaded to %s.\n",
                    cmd_args.pszDownloadDir,
                );
            } else {
                log_console(LOG_INFO, "Packages have been downloaded to cache.\n");
            }
        }
    }

    return 0;
}

pub export fn TDNFCliAlterCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    nAlterType: c.TDNF_ALTERTYPE,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    if (context.hTdnf == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    var ppszPackageArgs: [*c][*c]u8 = null;
    defer freeStringArray(ppszPackageArgs);

    var pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO = null;
    defer TDNFFreeSolvedPackageInfo(pSolvedPkgInfo);

    var nPackageCount: c_int = 0;

    var dwError = c.TDNFCliParsePackageArgs(cmd_args, &ppszPackageArgs, &nPackageCount);
    if (dwError != 0) {
        return mapAlterError(dwError);
    }

    dwError = context.pFnResolve.?(context, nAlterType, &pSolvedPkgInfo);
    if (dwError != 0) {
        return mapAlterError(dwError);
    }

    if (cmd_args.nUrlsOnly != 0) {
        var ppszUrls: [*c][*c]u8 = null;
        defer freeStringArray(ppszUrls);

        var nCount: c_int = 0;
        dwError = context.pFnGetPackageUrls.?(context, pSolvedPkgInfo, &ppszUrls, &nCount);
        if (dwError != 0) {
            return mapAlterError(dwError);
        }

        var i: c_int = 0;
        while (i < nCount) : (i += 1) {
            log_console(LOG_CRIT, "%s\n", ppszUrls[@intCast(i)]);
        }

        return 0;
    }

    dwError = TDNFCliAskAndAlter(context, cmd_args, pSolvedPkgInfo);
    if (dwError != 0) {
        return mapAlterError(dwError);
    }

    return 0;
}

fn JDPkgList(
    pPkgInfos: ?*c.TDNF_PKG_INFO,
    ppJDList: ?*?*c.struct_json_dump,
) u32 {
    if (ppJDList == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    var pPkgInfo = pPkgInfos orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    ppJDList.?.* = null;

    var jd_list: ?*c.struct_json_dump = c.jd_create(0);
    if (jd_list == null) {
        return c.ERROR_TDNF_JSONDUMP;
    }
    errdefer destroyJsonDump(&jd_list);

    var dwError = checkJsonResult(c.jd_list_start(jd_list));
    if (dwError != 0) {
        return dwError;
    }

    while (true) {
        var jd_pkg: ?*c.struct_json_dump = c.jd_create(0);
        if (jd_pkg == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd_pkg);

        dwError = checkJsonResult(c.jd_map_start(jd_pkg));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Name", pPkgInfo.pszName));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Arch", pPkgInfo.pszArch));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_map_add_fmt(
            jd_pkg,
            "Evr",
            "%s-%s",
            pPkgInfo.pszVersion,
            pPkgInfo.pszRelease,
        ));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_map_add_int(
            jd_pkg,
            "InstallSize",
            @as(c_int, @intCast(pPkgInfo.dwInstallSizeBytes)),
        ));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Repo", pPkgInfo.pszRepoName));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_list_add_child(jd_list, jd_pkg));
        if (dwError != 0) {
            return dwError;
        }

        destroyJsonDump(&jd_pkg);
        if (pPkgInfo.pNext == null) {
            break;
        }
        pPkgInfo = pPkgInfo.pNext.?;
    }

    ppJDList.?.* = jd_list;
    return 0;
}

pub export fn PrintSolvedInfoJson(pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO) u32 {
    const solved_info = pSolvedPkgInfo orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var jd: ?*c.struct_json_dump = c.jd_create(1024);
    if (jd == null) {
        return c.ERROR_TDNF_JSONDUMP;
    }
    defer destroyJsonDump(&jd);

    var dwError = checkJsonResult(c.jd_map_start(jd));
    if (dwError != 0) {
        return dwError;
    }

    dwError = addSolvedPackageList(jd, "Exist", solved_info.pPkgsExisting);
    if (dwError != 0) {
        return dwError;
    }
    dwError = addSolvedPackageList(jd, "Unavailable", solved_info.pPkgsNotAvailable);
    if (dwError != 0) {
        return dwError;
    }
    dwError = addSolvedPackageList(jd, "Install", solved_info.pPkgsToInstall);
    if (dwError != 0) {
        return dwError;
    }
    dwError = addSolvedPackageList(jd, "Upgrade", solved_info.pPkgsToUpgrade);
    if (dwError != 0) {
        return dwError;
    }
    dwError = addSolvedPackageList(jd, "Downgrade", solved_info.pPkgsToDowngrade);
    if (dwError != 0) {
        return dwError;
    }
    dwError = addSolvedPackageList(jd, "Remove", solved_info.pPkgsToRemove);
    if (dwError != 0) {
        return dwError;
    }
    dwError = addSolvedPackageList(jd, "UnNeeded", solved_info.pPkgsUnNeeded);
    if (dwError != 0) {
        return dwError;
    }
    dwError = addSolvedPackageList(jd, "Reinstall", solved_info.pPkgsToReinstall);
    if (dwError != 0) {
        return dwError;
    }
    dwError = addSolvedPackageList(jd, "Obsolete", solved_info.pPkgsObsoleted);
    if (dwError != 0) {
        return dwError;
    }

    _ = c.fputs(jd.?.buf, c.stdout);
    return 0;
}

pub export fn PrintSolvedInfo(pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO) u32 {
    const solved_info = pSolvedPkgInfo orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var dwError: u32 = 0;

    if (solved_info.pPkgsExisting != null) {
        dwError = PrintExistingPackagesSkipped(solved_info.pPkgsExisting);
        if (dwError != 0) {
            return dwError;
        }
    }
    if (solved_info.pPkgsNotAvailable != null) {
        dwError = PrintNotAvailablePackages(solved_info.pPkgsNotAvailable);
        if (dwError != 0) {
            return dwError;
        }
    }
    if (solved_info.pPkgsToInstall != null) {
        dwError = PrintAction(solved_info.pPkgsToInstall, c.ALTER_INSTALL);
        if (dwError != 0) {
            return dwError;
        }
    }
    if (solved_info.pPkgsToUpgrade != null) {
        dwError = PrintAction(solved_info.pPkgsToUpgrade, c.ALTER_UPGRADE);
        if (dwError != 0) {
            return dwError;
        }
    }
    if (solved_info.pPkgsToDowngrade != null) {
        dwError = PrintAction(solved_info.pPkgsToDowngrade, c.ALTER_DOWNGRADE);
        if (dwError != 0) {
            return dwError;
        }
    }
    if (solved_info.pPkgsToRemove != null) {
        dwError = PrintAction(solved_info.pPkgsToRemove, c.ALTER_ERASE);
        if (dwError != 0) {
            return dwError;
        }
    }
    if (solved_info.pPkgsUnNeeded != null) {
        dwError = PrintAction(solved_info.pPkgsUnNeeded, c.ALTER_ERASE);
        if (dwError != 0) {
            return dwError;
        }
    }
    if (solved_info.pPkgsToReinstall != null) {
        dwError = PrintAction(solved_info.pPkgsToReinstall, c.ALTER_REINSTALL);
        if (dwError != 0) {
            return dwError;
        }
    }
    if (solved_info.pPkgsObsoleted != null) {
        dwError = PrintAction(solved_info.pPkgsObsoleted, c.ALTER_OBSOLETED);
        if (dwError != 0) {
            return dwError;
        }
    }

    return 0;
}

pub export fn PrintNotAvailable(ppszPkgsNotAvailable: [*c][*c]u8) u32 {
    const pkgs = if (ppszPkgsNotAvailable != null)
        ppszPkgsNotAvailable
    else
        return c.ERROR_TDNF_INVALID_PARAMETER;

    var i: usize = 0;
    while (pkgs[i] != null) : (i += 1) {
        log_console(
            LOG_INFO,
            "No package \x1b[1m\x1b[30m%s \x1b[0mavailable\n",
            pkgs[i].?,
        );
    }

    return 0;
}

pub export fn PrintExistingPackagesSkipped(pPkgInfos: ?*c.TDNF_PKG_INFO) u32 {
    var pPkgInfo = pPkgInfos orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    while (true) {
        log_console(
            LOG_INFO,
            "Package %s-%s-%s.%s is already installed, skipping.\n",
            pPkgInfo.pszName,
            pPkgInfo.pszVersion,
            pPkgInfo.pszRelease,
            pPkgInfo.pszArch,
        );

        if (pPkgInfo.pNext == null) {
            break;
        }
        pPkgInfo = pPkgInfo.pNext.?;
    }

    return 0;
}

pub export fn PrintNotAvailablePackages(pPkgInfos: ?*c.TDNF_PKG_INFO) u32 {
    var pPkgInfo = pPkgInfos orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    while (true) {
        log_console(LOG_INFO, "No package %s available.\n", pPkgInfo.pszName);

        if (pPkgInfo.pNext == null) {
            break;
        }
        pPkgInfo = pPkgInfo.pNext.?;
    }

    return 0;
}

pub export fn PrintAction(
    pPkgInfos: ?*c.TDNF_PKG_INFO,
    nAlterType: c.TDNF_ALTERTYPE,
) u32 {
    var pPkgInfo = pPkgInfos orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var dwError = printActionHeader(nAlterType);
    if (dwError != 0) {
        return dwError;
    }

    var nColPercents = [_]c_int{ 20, 15, 20, 15, 10, 10 };
    var nColWidths = [_]c_int{0} ** COL_COUNT;
    dwError = output.GetColumnWidths(COL_COUNT, &nColPercents, &nColWidths);
    if (dwError != 0) {
        return dwError;
    }

    var nTotalInstallSize: u64 = 0;
    var nTotalDownloadSize: u64 = 0;
    var pszTotalInstallSize: ?[*:0]u8 = null;
    defer freeOwnedString(&pszTotalInstallSize);
    var pszTotalDownloadSize: ?[*:0]u8 = null;
    defer freeOwnedString(&pszTotalDownloadSize);

    while (true) {
        var szEpochVersionRelease = [_]u8{0} ** MAX_COL_LEN;

        nTotalInstallSize += pPkgInfo.dwInstallSizeBytes;
        nTotalDownloadSize += pPkgInfo.dwDownloadSizeBytes;

        dwError = formatEpochVersionRelease(pPkgInfo, &szEpochVersionRelease);
        if (dwError != 0) {
            return dwError;
        }

        log_console(
            LOG_INFO,
            "%-*s %-*s %-*s %-*s %-*s %*s\n",
            nColWidths[0],
            nonNullString(pPkgInfo.pszName),
            nColWidths[1],
            nonNullString(pPkgInfo.pszArch),
            nColWidths[2],
            @as([*:0]const u8, @ptrCast(&szEpochVersionRelease)),
            nColWidths[3],
            nonNullString(pPkgInfo.pszRepoName),
            nColWidths[4],
            nonNullString(pPkgInfo.pszFormattedSize),
            nColWidths[5],
            nonNullString(pPkgInfo.pszFormattedDownloadSize),
        );

        if (pPkgInfo.pNext == null) {
            break;
        }
        pPkgInfo = pPkgInfo.pNext.?;
    }

    dwError = TDNFUtilsFormatSize(nTotalInstallSize, &pszTotalInstallSize);
    if (dwError != 0) {
        return dwError;
    }
    log_console(LOG_INFO, "\nTotal installed size: %s\n", pszTotalInstallSize.?);

    dwError = TDNFUtilsFormatSize(nTotalDownloadSize, &pszTotalDownloadSize);
    if (dwError != 0) {
        return dwError;
    }
    log_console(LOG_INFO, "Total download size: %s\n", pszTotalDownloadSize.?);

    return 0;
}
