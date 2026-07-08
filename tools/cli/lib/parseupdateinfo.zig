// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("nodes.h");
    @cInclude("tdnfcli.h");
    @cInclude("tdnferror.h");
});
const choice_parse = @import("choice_parse.zig");
const parselistargs = @import("parselistargs.zig");

const ModeChoice = choice_parse.NamedValue(c.TDNF_UPDATEINFO_OUTPUT);
const modes = [_]ModeChoice{
    .{ .name = "summary", .value = c.OUTPUT_SUMMARY },
    .{ .name = "list", .value = c.OUTPUT_LIST },
    .{ .name = "info", .value = c.OUTPUT_INFO },
};

fn duplicateString(pszValue: [*c]const u8, ppOut: *allowzero [*c]u8) u32 {
    if (pszValue == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }
    const pszDup = c.strdup(pszValue) orelse return c.ERROR_TDNF_OUT_OF_MEMORY;
    ppOut.* = @ptrCast(pszDup);
    return 0;
}

fn allocateCStringArray(nCount: usize) [*c][*c]u8 {
    const pAllocated = c.calloc(nCount + 1, @sizeOf([*c]u8)) orelse return null;
    return @ptrCast(@alignCast(pAllocated));
}

fn freeStringArray(ppszArray: [*c][*c]u8) void {
    if (ppszArray != null) {
        var i: usize = 0;
        while (ppszArray[i] != null) : (i += 1) {
            c.free(ppszArray[i]);
        }
        c.free(@ptrCast(ppszArray));
    }
}

fn duplicateCmdArgs(
    ppszCmds: [*c][*c]u8,
    nStartIndex: c_int,
    nCount: c_int,
    ppOut: *[*c][*c]u8,
) u32 {
    const count: usize = @intCast(nCount);
    const start_index: usize = @intCast(nStartIndex);
    const ppszDuped = allocateCStringArray(count);
    if (ppszDuped == null) {
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    }
    var i: usize = 0;
    errdefer freeStringArray(ppszDuped);

    while (i < count) : (i += 1) {
        const dwError = duplicateString(ppszCmds[start_index + i], &ppszDuped[i]);
        if (dwError != 0) {
            return dwError;
        }
    }

    ppOut.* = ppszDuped;
    return 0;
}

fn freeUpdateInfoArgs(pUpdateInfoArgs: *c.TDNF_UPDATEINFO_ARGS) void {
    freeStringArray(pUpdateInfoArgs.ppszPackageNameSpecs);
    c.free(pUpdateInfoArgs);
}

pub export fn TDNFCliParseUpdateInfoArgs(
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    ppUpdateInfoArgs: ?*[*c]c.TDNF_UPDATEINFO_ARGS,
) u32 {
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const out = ppUpdateInfoArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    if (cmd_args.nCmdCount < 1) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pAllocated = c.calloc(1, @sizeOf(c.TDNF_UPDATEINFO_ARGS)) orelse
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    const pUpdateInfoArgs: *c.TDNF_UPDATEINFO_ARGS = @ptrCast(@alignCast(pAllocated));
    errdefer freeUpdateInfoArgs(pUpdateInfoArgs);

    pUpdateInfoArgs.nMode = c.OUTPUT_SUMMARY;
    pUpdateInfoArgs.nScope = c.SCOPE_AVAILABLE;

    var pNode: [*c]c.struct_cnfnode = if (cmd_args.cn_setopts != null) cmd_args.cn_setopts[0].first_child else null;
    while (pNode != null) : (pNode = pNode[0].next) {
        var dwError = parselistargs.TDNFCliParseScope(pNode[0].name, &pUpdateInfoArgs.nScope);
        if (dwError == 0) {
            continue;
        }
        if (dwError == c.ERROR_TDNF_CLI_NO_MATCH) {
            dwError = 0;
        }
        if (dwError != 0) {
            return dwError;
        }

        dwError = TDNFCliParseMode(pNode[0].name, &pUpdateInfoArgs.nMode);
        if (dwError == c.ERROR_TDNF_CLI_NO_MATCH) {
            continue;
        }
        if (dwError != 0) {
            return dwError;
        }
    }

    var nStartIndex: c_int = 1;
    if (cmd_args.nCmdCount > nStartIndex) {
        var dwError = TDNFCliParseMode(cmd_args.ppszCmds[@intCast(nStartIndex)], &pUpdateInfoArgs.nMode);
        if (dwError == c.ERROR_TDNF_CLI_NO_MATCH) {
            dwError = 0;
            nStartIndex -= 1;
        }
        if (dwError != 0) {
            return dwError;
        }
        nStartIndex += 1;
    }

    if (cmd_args.nCmdCount > nStartIndex) {
        var dwError = parselistargs.TDNFCliParseScope(cmd_args.ppszCmds[@intCast(nStartIndex)], &pUpdateInfoArgs.nScope);
        if (dwError == c.ERROR_TDNF_CLI_NO_MATCH) {
            dwError = 0;
            nStartIndex -= 1;
        }
        if (dwError != 0) {
            return dwError;
        }
        nStartIndex += 1;
    }

    const nPackageCount = cmd_args.nCmdCount - nStartIndex;
    const dwError = duplicateCmdArgs(cmd_args.ppszCmds, nStartIndex, nPackageCount, &pUpdateInfoArgs.ppszPackageNameSpecs);
    if (dwError != 0) {
        return dwError;
    }

    out.* = pUpdateInfoArgs;
    return 0;
}

pub export fn TDNFCliParseMode(
    pszMode: [*c]const u8,
    pnMode: ?*c.TDNF_UPDATEINFO_OUTPUT,
) u32 {
    const out = pnMode orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    if (pszMode == null or pszMode[0] == 0) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const nMode = choice_parse.parseChoice(c.TDNF_UPDATEINFO_OUTPUT, @ptrCast(pszMode), &modes) orelse
        return c.ERROR_TDNF_CLI_NO_MATCH;
    out.* = nMode;
    return 0;
}

pub export fn TDNFCliFreeUpdateInfoArgs(pUpdateInfoArgs: ?*c.TDNF_UPDATEINFO_ARGS) void {
    if (pUpdateInfoArgs) |updateinfo_args| {
        freeUpdateInfoArgs(updateinfo_args);
    }
}

test "TDNFCliParseMode preserves updateinfo modes" {
    var nMode: c.TDNF_UPDATEINFO_OUTPUT = c.OUTPUT_SUMMARY;

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseMode("InFo", &nMode));
    try std.testing.expectEqual(
        @as(@TypeOf(nMode), @intCast(c.OUTPUT_INFO)),
        nMode,
    );
}
