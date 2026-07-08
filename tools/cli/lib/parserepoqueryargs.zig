// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("string.h");
    @cInclude("strings.h");
    @cInclude("stdlib.h");
    @cInclude("nodes.h");
    @cInclude("tdnfcli.h");
    @cInclude("tdnferror.h");
});

const dep_keys = [_][*:0]const u8{
    "provides",
    "obsoletes",
    "conflicts",
    "requires",
    "recommends",
    "suggests",
    "supplements",
    "enhances",
    "depends",
    "requires-pre",
};

const what_keys = [_][*:0]const u8{
    "whatprovides",
    "whatobsoletes",
    "whatconflicts",
    "whatrequires",
    "whatrecommends",
    "whatsuggests",
    "whatsupplements",
    "whatenhances",
    "whatdepends",
};

fn equalsIgnoreCase(pszValue: ?[*:0]const u8, pszExpected: [*:0]const u8) bool {
    return pszValue != null and c.strcasecmp(pszValue, pszExpected) == 0;
}

fn duplicateString(pszValue: [*c]const u8, ppOut: *allowzero [*c]u8) u32 {
    if (pszValue == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszDup = c.strdup(pszValue) orelse return c.ERROR_TDNF_OUT_OF_MEMORY;
    ppOut.* = @ptrCast(pszDup);
    return 0;
}

fn duplicateBytes(pszValue: []const u8, ppOut: *allowzero [*c]u8) u32 {
    const pAllocated = c.calloc(pszValue.len + 1, 1) orelse return c.ERROR_TDNF_OUT_OF_MEMORY;
    const pBytes: [*]u8 = @ptrCast(pAllocated);
    @memcpy(pBytes[0..pszValue.len], pszValue);
    pBytes[pszValue.len] = 0;
    ppOut.* = @ptrCast(pBytes);
    return 0;
}

fn freeCString(pszValue: [*c]u8) void {
    if (pszValue) |value| {
        c.free(value);
    }
}

fn freeStringArray(ppszArray: [*c][*c]u8) void {
    if (ppszArray) |ppValues| {
        var i: usize = 0;
        while (ppValues[i] != null) : (i += 1) {
            freeCString(ppValues[i]);
        }
        c.free(@ptrCast(ppValues));
    }
}

fn replaceString(ppszField: *[*c]u8, pszValue: [*c]const u8) u32 {
    freeCString(ppszField.*);
    ppszField.* = null;
    return duplicateString(pszValue, ppszField);
}

fn countCommaTokens(pszValue: []const u8) usize {
    var nCount: usize = 0;
    var i: usize = 0;

    while (i < pszValue.len) {
        while (i < pszValue.len and pszValue[i] == ',') : (i += 1) {}
        if (i >= pszValue.len) {
            break;
        }

        nCount += 1;
        while (i < pszValue.len and pszValue[i] != ',') : (i += 1) {}
    }

    return nCount;
}

fn splitCommaList(pszValue: [*c]const u8, ppOut: *allowzero [*c][*c]u8) u32 {
    if (pszValue == null) {
        ppOut.* = null;
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const value = std.mem.span(pszValue);
    const nCount = countCommaTokens(value);
    const pAllocated = c.calloc(nCount + 1, @sizeOf([*c]u8)) orelse {
        ppOut.* = null;
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    };
    const ppszValues: [*c][*c]u8 = @ptrCast(@alignCast(pAllocated));
    errdefer freeStringArray(ppszValues);

    var i: usize = 0;
    var p: usize = 0;
    while (p < value.len) {
        while (p < value.len and value[p] == ',') : (p += 1) {}
        if (p >= value.len) {
            break;
        }

        const nStart = p;
        while (p < value.len and value[p] != ',') : (p += 1) {}

        const dwError = duplicateBytes(value[nStart..p], &ppszValues[i]);
        if (dwError != 0) {
            return dwError;
        }
        i += 1;
    }

    ppOut.* = ppszValues;
    return 0;
}

fn replaceStringArray(pppszField: *allowzero [*c][*c]u8, pszValue: [*c]const u8) u32 {
    freeStringArray(pppszField.*);
    pppszField.* = null;
    return splitCommaList(pszValue, pppszField);
}

fn ensureArchArray(pRepoqueryArgs: *c.TDNF_REPOQUERY_ARGS) u32 {
    if (pRepoqueryArgs.ppszArchs == null) {
        const nArchSlots: usize = @as(usize, c.TDNF_REPOQUERY_MAXARCHS) + 1;
        const pAllocated = c.calloc(nArchSlots, @sizeOf([*c]u8)) orelse
            return c.ERROR_TDNF_OUT_OF_MEMORY;
        pRepoqueryArgs.ppszArchs = @ptrCast(@alignCast(pAllocated));
    }

    return 0;
}

fn ensureWhatKeyArray(pRepoqueryArgs: *c.TDNF_REPOQUERY_ARGS) u32 {
    if (pRepoqueryArgs.pppszWhatKeys == null) {
        const nWhatKeys: usize = @intCast(c.REPOQUERY_WHAT_KEY_COUNT);
        const pAllocated = c.calloc(nWhatKeys, @sizeOf([*c][*c]u8)) orelse
            return c.ERROR_TDNF_OUT_OF_MEMORY;
        pRepoqueryArgs.pppszWhatKeys = @ptrCast(@alignCast(pAllocated));
    }

    return 0;
}

fn appendArch(pRepoqueryArgs: *c.TDNF_REPOQUERY_ARGS, pszArch: [*c]const u8) u32 {
    var dwError = ensureArchArray(pRepoqueryArgs);
    if (dwError != 0) {
        return dwError;
    }

    var i: usize = 0;
    while (i < c.TDNF_REPOQUERY_MAXARCHS and pRepoqueryArgs.ppszArchs[i] != null) : (i += 1) {}
    if (i >= c.TDNF_REPOQUERY_MAXARCHS) {
        return 0;
    }

    dwError = duplicateString(pszArch, &pRepoqueryArgs.ppszArchs[i]);
    return dwError;
}

fn hasLocationTag(pszQueryFormat: [*c]const u8) bool {
    return pszQueryFormat != null and c.strstr(pszQueryFormat, "%{location}") != null;
}

fn parseDepKey(pRepoqueryArgs: *c.TDNF_REPOQUERY_ARGS, pNode: [*c]c.struct_cnfnode) ?u32 {
    for (dep_keys, 0..) |dep_key, dep_index| {
        if (equalsIgnoreCase(pNode[0].name, dep_key)) {
            const nMask: c_uint = @as(c_uint, 1) << @intCast(dep_index);
            if ((pRepoqueryArgs.depKeySet & nMask) == 0) {
                if (pNode[0].next != null) {
                    return c.ERROR_TDNF_CLI_INVALID_MIXED_QUERY_QUERYFORMAT;
                }

                pRepoqueryArgs.depKeySet |= nMask;
                return 0;
            }

            return c.ERROR_TDNF_CLI_ONE_DEP_ONLY;
        }
    }

    return null;
}

fn parseWhatKey(pRepoqueryArgs: *c.TDNF_REPOQUERY_ARGS, pNode: [*c]c.struct_cnfnode) ?u32 {
    for (what_keys, 0..) |what_key, what_index| {
        if (equalsIgnoreCase(pNode[0].name, what_key)) {
            const dwError = replaceStringArray(&pRepoqueryArgs.pppszWhatKeys[what_index], pNode[0].value);
            return dwError;
        }
    }

    return null;
}

fn parseSetOpt(pRepoqueryArgs: *c.TDNF_REPOQUERY_ARGS, pNode: [*c]c.struct_cnfnode) u32 {
    if (equalsIgnoreCase(pNode[0].name, "arch")) {
        return appendArch(pRepoqueryArgs, pNode[0].value);
    } else if (equalsIgnoreCase(pNode[0].name, "file")) {
        return replaceString(&pRepoqueryArgs.pszFile, pNode[0].value);
    } else if (equalsIgnoreCase(pNode[0].name, "changelogs")) {
        pRepoqueryArgs.nChangeLogs = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "available")) {
        pRepoqueryArgs.nAvailable = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "installed")) {
        pRepoqueryArgs.nInstalled = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "extras")) {
        pRepoqueryArgs.nExtras = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "location")) {
        pRepoqueryArgs.nLocation = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "duplicates")) {
        pRepoqueryArgs.nDuplicates = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "list")) {
        pRepoqueryArgs.nList = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "qf")) {
        if (pNode[0].next != null) {
            return c.ERROR_TDNF_CLI_INVALID_MIXED_QUERY_QUERYFORMAT;
        }

        const dwError = replaceString(&pRepoqueryArgs.pszQueryFormat, pNode[0].value);
        if (dwError != 0) {
            return dwError;
        }

        if (hasLocationTag(pRepoqueryArgs.pszQueryFormat)) {
            pRepoqueryArgs.nLocation = 1;
        }
    } else if (equalsIgnoreCase(pNode[0].name, "source")) {
        pRepoqueryArgs.nSource = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "upgrades")) {
        pRepoqueryArgs.nUpgrades = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "downgrades")) {
        pRepoqueryArgs.nDowngrades = 1;
    } else if (equalsIgnoreCase(pNode[0].name, "userinstalled")) {
        pRepoqueryArgs.nUserInstalled = 1;
    } else if (parseDepKey(pRepoqueryArgs, pNode)) |dwError| {
        return dwError;
    } else if (parseWhatKey(pRepoqueryArgs, pNode)) |dwError| {
        return dwError;
    }

    return 0;
}

pub export fn TDNFCliParseRepoQueryArgs(
    pArgs: ?*c.TDNF_CMD_ARGS,
    ppRepoqueryArgs: ?*?*c.TDNF_REPOQUERY_ARGS,
) u32 {
    const cmd_args = pArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const out = ppRepoqueryArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    out.* = null;

    const pAllocated = c.calloc(1, @sizeOf(c.TDNF_REPOQUERY_ARGS)) orelse
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    const pRepoqueryArgs: *c.TDNF_REPOQUERY_ARGS = @ptrCast(@alignCast(pAllocated));
    errdefer TDNFCliFreeRepoQueryArgs(pRepoqueryArgs);

    var dwError = ensureWhatKeyArray(pRepoqueryArgs);
    if (dwError != 0) {
        return dwError;
    }

    var pNode: [*c]c.struct_cnfnode = if (cmd_args.cn_setopts != null) cmd_args.cn_setopts[0].first_child else null;
    while (pNode != null) : (pNode = pNode[0].next) {
        dwError = parseSetOpt(pRepoqueryArgs, pNode);
        if (dwError != 0) {
            return dwError;
        }
    }

    if (cmd_args.nCmdCount > 2) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    if (cmd_args.nCmdCount > 1) {
        dwError = replaceString(&pRepoqueryArgs.pszSpec, cmd_args.ppszCmds[1]);
        if (dwError != 0) {
            return dwError;
        }
    }

    out.* = pRepoqueryArgs;
    return 0;
}

pub export fn TDNFCliFreeRepoQueryArgs(pRepoqueryArgs: ?*c.TDNF_REPOQUERY_ARGS) void {
    if (pRepoqueryArgs) |repoquery_args| {
        freeStringArray(repoquery_args.ppszArchs);
        if (repoquery_args.pppszWhatKeys != null) {
            var i: usize = 0;
            const nWhatKeys: usize = @intCast(c.REPOQUERY_WHAT_KEY_COUNT);
            while (i < nWhatKeys) : (i += 1) {
                freeStringArray(repoquery_args.pppszWhatKeys[i]);
            }
            c.free(@ptrCast(repoquery_args.pppszWhatKeys));
        }
        freeCString(repoquery_args.pszFile);
        freeCString(repoquery_args.pszSpec);
        freeCString(repoquery_args.pszQueryFormat);
        c.free(repoquery_args);
    }
}

test "TDNFCliParseRepoQueryArgs preserves repoquery selectors" {
    var setopt_root: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var arch0_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var arch1_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var available_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var whatrequires_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);

    arch0_node.name = @constCast("arch");
    arch0_node.value = @constCast("x86_64");
    arch1_node.name = @constCast("arch");
    arch1_node.value = @constCast("noarch");
    available_node.name = @constCast("available");
    whatrequires_node.name = @constCast("whatrequires");
    whatrequires_node.value = @constCast("doesnotexist,tdnf-repoquery-base");

    arch0_node.next = &arch1_node;
    arch1_node.next = &available_node;
    available_node.next = &whatrequires_node;
    setopt_root.first_child = &arch0_node;

    var ppszCmds = [_]?[*:0]u8{
        @constCast("repoquery"),
        @constCast("tdnf-repoquery-requires"),
    };
    var cmd_args: c.TDNF_CMD_ARGS = std.mem.zeroes(c.TDNF_CMD_ARGS);
    cmd_args.ppszCmds = @ptrCast(&ppszCmds);
    cmd_args.nCmdCount = 2;
    cmd_args.cn_setopts = &setopt_root;

    var pRepoqueryArgs: ?*c.TDNF_REPOQUERY_ARGS = null;
    defer TDNFCliFreeRepoQueryArgs(pRepoqueryArgs);

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseRepoQueryArgs(&cmd_args, &pRepoqueryArgs));
    try std.testing.expect(pRepoqueryArgs != null);
    try std.testing.expectEqual(@as(c_int, 1), pRepoqueryArgs.?.nAvailable);
    try std.testing.expectEqualStrings(
        "tdnf-repoquery-requires",
        std.mem.span(pRepoqueryArgs.?.pszSpec.?),
    );
    try std.testing.expectEqualStrings("x86_64", std.mem.span(pRepoqueryArgs.?.ppszArchs[0].?));
    try std.testing.expectEqualStrings("noarch", std.mem.span(pRepoqueryArgs.?.ppszArchs[1].?));
    try std.testing.expect(pRepoqueryArgs.?.pppszWhatKeys[c.REPOQUERY_WHAT_KEY_REQUIRES] != null);
    try std.testing.expectEqualStrings(
        "doesnotexist",
        std.mem.span(pRepoqueryArgs.?.pppszWhatKeys[c.REPOQUERY_WHAT_KEY_REQUIRES][0].?),
    );
    try std.testing.expectEqualStrings(
        "tdnf-repoquery-base",
        std.mem.span(pRepoqueryArgs.?.pppszWhatKeys[c.REPOQUERY_WHAT_KEY_REQUIRES][1].?),
    );
}

test "TDNFCliParseRepoQueryArgs preserves qf location handling" {
    var setopt_root: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var qf_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);

    qf_node.name = @constCast("qf");
    qf_node.value = @constCast("%{location}");
    setopt_root.first_child = &qf_node;

    var ppszCmds = [_]?[*:0]u8{
        @constCast("repoquery"),
        @constCast("tdnf-repoquery-base"),
    };
    var cmd_args: c.TDNF_CMD_ARGS = std.mem.zeroes(c.TDNF_CMD_ARGS);
    cmd_args.ppszCmds = @ptrCast(&ppszCmds);
    cmd_args.nCmdCount = 2;
    cmd_args.cn_setopts = &setopt_root;

    var pRepoqueryArgs: ?*c.TDNF_REPOQUERY_ARGS = null;
    defer TDNFCliFreeRepoQueryArgs(pRepoqueryArgs);

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseRepoQueryArgs(&cmd_args, &pRepoqueryArgs));
    try std.testing.expectEqual(@as(c_int, 1), pRepoqueryArgs.?.nLocation);
    try std.testing.expectEqualStrings("%{location}", std.mem.span(pRepoqueryArgs.?.pszQueryFormat.?));
}

test "TDNFCliParseRepoQueryArgs rejects mixed qf queries" {
    var setopt_root: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var qf_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var file_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);

    qf_node.name = @constCast("qf");
    qf_node.value = @constCast("%{name}");
    file_node.name = @constCast("file");
    file_node.value = @constCast("/usr/lib/repoquery/tdnf-repoquery-requires");

    qf_node.next = &file_node;
    setopt_root.first_child = &qf_node;

    var cmd_args: c.TDNF_CMD_ARGS = std.mem.zeroes(c.TDNF_CMD_ARGS);
    cmd_args.cn_setopts = &setopt_root;

    var pRepoqueryArgs: ?*c.TDNF_REPOQUERY_ARGS = @ptrFromInt(@alignOf(c.TDNF_REPOQUERY_ARGS));
    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_CLI_INVALID_MIXED_QUERY_QUERYFORMAT),
        TDNFCliParseRepoQueryArgs(&cmd_args, &pRepoqueryArgs),
    );
    try std.testing.expect(pRepoqueryArgs == null);
}
