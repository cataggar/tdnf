// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("jsondump.h");
    @cInclude("tdnf.h");
    @cInclude("tdnfcli.h");
    @cInclude("tdnferror.h");
});

extern fn log_console(loglevel: i32, format: [*:0]const u8, ...) void;

const LOG_CRIT: c_int = 2;

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

pub export fn TDNFGetUpdateInfoType(nType: c_int) [*:0]const u8 {
    return switch (nType) {
        c.UPDATE_SECURITY => "Security",
        c.UPDATE_BUGFIX => "Bugfix",
        c.UPDATE_ENHANCEMENT => "Enhancement",
        else => "Unknown",
    };
}

pub export fn TDNFCliUpdateInfoCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var pUpdateInfo: ?*c.TDNF_UPDATEINFO = null;
    defer c.TDNFFreeUpdateInfo(pUpdateInfo);

    var pInfoArgs: ?*c.TDNF_UPDATEINFO_ARGS = null;
    defer c.TDNFCliFreeUpdateInfoArgs(pInfoArgs);

    var dwError = c.TDNFCliParseUpdateInfoArgs(cmd_args, &pInfoArgs);
    if (dwError != 0) {
        return dwError;
    }

    if (pInfoArgs.?.nMode == c.OUTPUT_SUMMARY) {
        return TDNFCliUpdateInfoSummary(context, cmd_args, pInfoArgs);
    }

    dwError = context.pFnUpdateInfo.?(context, pInfoArgs, &pUpdateInfo);
    if (dwError == c.ERROR_TDNF_NO_DATA) {
        dwError = 0;
    }
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        return TDNFCliUpdateInfoOutputJson(pUpdateInfo, pInfoArgs.?.nMode);
    }

    return TDNFCliUpdateInfoOutput(pUpdateInfo, pInfoArgs.?.nMode);
}

pub export fn TDNFCliUpdateInfoSummary(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    pInfoArgs: ?*c.TDNF_UPDATEINFO_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const info_args = pInfoArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var pSummary: ?[*]c.TDNF_UPDATEINFO_SUMMARY = null;
    defer c.TDNFFreeUpdateInfoSummary(pSummary);

    var dwError = context.pFnUpdateInfoSummary.?(context, c.AVAIL_AVAILABLE, info_args, &pSummary);
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(0);
        if (jd == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd);

        dwError = checkJsonResult(c.jd_map_start(jd));
        if (dwError != 0) {
            return dwError;
        }

        var i: c_int = c.UPDATE_UNKNOWN;
        while (i <= c.UPDATE_ENHANCEMENT) : (i += 1) {
            const summary = pSummary.?[@intCast(i)];
            dwError = checkJsonResult(c.jd_map_add_int(
                jd,
                TDNFGetUpdateInfoType(summary.nType),
                summary.nCount,
            ));
            if (dwError != 0) {
                return dwError;
            }
        }

        _ = c.fputs(jd.?.buf, c.stdout);
        return 0;
    }

    var nCount: c_int = 0;
    var i: c_int = c.UPDATE_UNKNOWN;
    while (i <= c.UPDATE_ENHANCEMENT) : (i += 1) {
        const summary = pSummary.?[@intCast(i)];
        if (summary.nCount > 0) {
            nCount += 1;
            log_console(
                LOG_CRIT,
                "%d %s notice(s)\n",
                summary.nCount,
                TDNFGetUpdateInfoType(summary.nType),
            );
        }
    }

    if (nCount == 0) {
        log_console(LOG_CRIT, "\n%d updates.\n", nCount);
        return c.ERROR_TDNF_NO_DATA;
    }

    return 0;
}

pub export fn TDNFCliUpdateInfoOutput(
    pInfo: ?*c.TDNF_UPDATEINFO,
    mode: c.TDNF_UPDATEINFO_OUTPUT,
) u32 {
    var pCurrentInfo = pInfo;
    while (pCurrentInfo) |info| : (pCurrentInfo = info.pNext) {
        var pPkg = info.pPackages;
        while (pPkg) |pkg| : (pPkg = pkg[0].pNext) {
            if (mode == c.OUTPUT_INFO) {
                log_console(
                    LOG_CRIT,
                    "       Name : %s\n" ++
                        "  Update ID : %s\n" ++
                        "       Type : %s\n" ++
                        "    Updated : %s\n" ++
                        "Needs Reboot: %d\n" ++
                        "Description : %s\n",
                    pkg[0].pszFileName,
                    info.pszID,
                    TDNFGetUpdateInfoType(info.nType),
                    info.pszDate,
                    info.nRebootRequired,
                    info.pszDescription,
                );
            } else if (mode == c.OUTPUT_LIST) {
                log_console(
                    LOG_CRIT,
                    "%s %s %s\n",
                    info.pszID,
                    TDNFGetUpdateInfoType(info.nType),
                    pkg[0].pszFileName,
                );
            }
        }
    }

    return 0;
}

pub export fn TDNFCliUpdateInfoOutputJson(
    pInfo: ?*c.TDNF_UPDATEINFO,
    mode: c.TDNF_UPDATEINFO_OUTPUT,
) u32 {
    var jd: ?*c.struct_json_dump = c.jd_create(0);
    if (jd == null) {
        return c.ERROR_TDNF_JSONDUMP;
    }
    defer destroyJsonDump(&jd);

    var dwError = checkJsonResult(c.jd_list_start(jd));
    if (dwError != 0) {
        return dwError;
    }

    var pCurrentInfo = pInfo;
    while (pCurrentInfo) |info| : (pCurrentInfo = info.pNext) {
        var jd_info: ?*c.struct_json_dump = c.jd_create(0);
        if (jd_info == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd_info);

        var jd_pkgs: ?*c.struct_json_dump = c.jd_create(0);
        if (jd_pkgs == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd_pkgs);

        dwError = checkJsonResult(c.jd_map_start(jd_info));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_map_add_string(
            jd_info,
            "Type",
            TDNFGetUpdateInfoType(info.nType),
        ));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_map_add_string(jd_info, "UpdateID", info.pszID));
        if (dwError != 0) {
            return dwError;
        }

        if (mode == c.OUTPUT_INFO) {
            dwError = checkJsonResult(c.jd_map_add_string(jd_info, "Updated", info.pszDate));
            if (dwError != 0) {
                return dwError;
            }
            dwError = checkJsonResult(c.jd_map_add_bool(jd_info, "NeedsReboot", info.nRebootRequired));
            if (dwError != 0) {
                return dwError;
            }
            dwError = checkJsonResult(c.jd_map_add_string(jd_info, "Description", info.pszDescription));
            if (dwError != 0) {
                return dwError;
            }
        }

        dwError = checkJsonResult(c.jd_list_start(jd_pkgs));
        if (dwError != 0) {
            return dwError;
        }

        var pPkg = info.pPackages;
        while (pPkg) |pkg| : (pPkg = pkg[0].pNext) {
            dwError = checkJsonResult(c.jd_list_add_string(jd_pkgs, pkg[0].pszFileName));
            if (dwError != 0) {
                return dwError;
            }
        }

        dwError = checkJsonResult(c.jd_map_add_child(jd_info, "Packages", jd_pkgs));
        if (dwError != 0) {
            return dwError;
        }
        dwError = checkJsonResult(c.jd_list_add_child(jd, jd_info));
        if (dwError != 0) {
            return dwError;
        }
    }

    _ = c.fputs(jd.?.buf, c.stdout);
    return 0;
}

test "TDNFGetUpdateInfoType preserves well-known names" {
    try std.testing.expectEqualStrings("Unknown", std.mem.span(TDNFGetUpdateInfoType(c.UPDATE_UNKNOWN)));
    try std.testing.expectEqualStrings("Security", std.mem.span(TDNFGetUpdateInfoType(c.UPDATE_SECURITY)));
    try std.testing.expectEqualStrings("Bugfix", std.mem.span(TDNFGetUpdateInfoType(c.UPDATE_BUGFIX)));
    try std.testing.expectEqualStrings("Enhancement", std.mem.span(TDNFGetUpdateInfoType(c.UPDATE_ENHANCEMENT)));
}
