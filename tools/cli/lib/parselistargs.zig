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

const ScopeChoice = choice_parse.NamedValue(c.TDNF_SCOPE);
const scopes = [_]ScopeChoice{
    .{ .name = "all", .value = c.SCOPE_ALL },
    .{ .name = "installed", .value = c.SCOPE_INSTALLED },
    .{ .name = "available", .value = c.SCOPE_AVAILABLE },
    .{ .name = "extras", .value = c.SCOPE_EXTRAS },
    .{ .name = "obsoletes", .value = c.SCOPE_OBSOLETES },
    .{ .name = "recent", .value = c.SCOPE_RECENT },
    .{ .name = "upgrades", .value = c.SCOPE_UPGRADES },
    .{ .name = "updates", .value = c.SCOPE_UPGRADES },
    .{ .name = "downgrades", .value = c.SCOPE_DOWNGRADES },
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

fn freeStringArray(ppszArray: [*c][*c]u8) void {
    if (ppszArray != null) {
        var i: usize = 0;
        while (ppszArray[i] != null) : (i += 1) {
            c.free(ppszArray[i]);
        }
        c.free(@ptrCast(ppszArray));
    }
}

fn freeListArgs(pListArgs: *c.TDNF_LIST_ARGS) void {
    freeStringArray(pListArgs.ppszPackageNameSpecs);
    c.free(pListArgs);
}

pub export fn TDNFCliParseInfoArgs(
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    ppListArgs: ?*[*c]c.TDNF_LIST_ARGS,
) u32 {
    return TDNFCliParseListArgs(pCmdArgs, ppListArgs);
}

pub export fn TDNFCliParsePackageArgs(
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    pppszPackageArgs: ?*[*c][*c]u8,
    pnPackageCount: ?*const c_int,
) u32 {
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const out = pppszPackageArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    _ = pnPackageCount orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    const nPackageCount = cmd_args.nCmdCount - 1;
    if (nPackageCount < 0) {
        return c.ERROR_TDNF_CLI_NOT_ENOUGH_ARGS;
    }

    return duplicateCmdArgs(cmd_args.ppszCmds, 1, nPackageCount, out);
}

pub export fn TDNFCliParseListArgs(
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    ppListArgs: ?*[*c]c.TDNF_LIST_ARGS,
) u32 {
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const out = ppListArgs orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    if (cmd_args.nCmdCount < 1) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pAllocated = c.calloc(1, @sizeOf(c.TDNF_LIST_ARGS)) orelse
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    const pListArgs: *c.TDNF_LIST_ARGS = @ptrCast(@alignCast(pAllocated));
    errdefer freeListArgs(pListArgs);

    pListArgs.nScope = c.SCOPE_ALL;

    var pNode: [*c]c.struct_cnfnode = if (cmd_args.cn_setopts != null) cmd_args.cn_setopts[0].first_child else null;
    while (pNode != null) : (pNode = pNode[0].next) {
        const dwError = TDNFCliParseScope(pNode[0].name, &pListArgs.nScope);
        if (dwError == c.ERROR_TDNF_CLI_NO_MATCH) {
            continue;
        }
        if (dwError != 0) {
            return dwError;
        }
    }

    var nStartIndex: c_int = 1;
    if (cmd_args.nCmdCount > 1) {
        nStartIndex = 2;
        const dwError = TDNFCliParseScope(cmd_args.ppszCmds[1], &pListArgs.nScope);
        if (dwError == c.ERROR_TDNF_CLI_NO_MATCH) {
            nStartIndex = 1;
        } else if (dwError != 0) {
            return dwError;
        }
    }

    const nPackageCount = cmd_args.nCmdCount - nStartIndex;
    const dwError = duplicateCmdArgs(cmd_args.ppszCmds, nStartIndex, nPackageCount, &pListArgs.ppszPackageNameSpecs);
    if (dwError != 0) {
        return dwError;
    }

    out.* = pListArgs;
    return 0;
}

pub export fn TDNFCliParseScope(
    pszScope: [*c]const u8,
    pnScope: ?*c.TDNF_SCOPE,
) u32 {
    const out = pnScope orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    if (pszScope == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const nScope = choice_parse.parseChoice(c.TDNF_SCOPE, @ptrCast(pszScope), &scopes) orelse
        return c.ERROR_TDNF_CLI_NO_MATCH;
    out.* = nScope;
    return 0;
}

pub export fn TDNFCliFreeListArgs(pListArgs: ?*c.TDNF_LIST_ARGS) void {
    if (pListArgs) |list_args| {
        freeListArgs(list_args);
    }
}

test "TDNFCliParseScope preserves list scope aliases" {
    var nScope: c.TDNF_SCOPE = c.SCOPE_ALL;

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseScope("UpDaTeS", &nScope));
    try std.testing.expectEqual(
        @as(@TypeOf(nScope), @intCast(c.SCOPE_UPGRADES)),
        nScope,
    );
}
