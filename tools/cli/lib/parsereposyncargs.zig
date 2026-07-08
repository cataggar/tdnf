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

fn equalsIgnoreCase(pszValue: [*c]const u8, comptime pszExpected: [*:0]const u8) bool {
    return pszValue != null and c.strcasecmp(pszValue, pszExpected) == 0;
}

fn duplicateString(pszValue: [*c]const u8, ppOut: *allowzero [*c]u8) u32 {
    if (pszValue == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }
    const value = pszValue;
    const pszDup = c.strdup(value) orelse return c.ERROR_TDNF_OUT_OF_MEMORY;
    ppOut.* = @ptrCast(pszDup);
    return 0;
}

fn ensureArchArray(pReposyncArgs: *c.TDNF_REPOSYNC_ARGS) u32 {
    if (pReposyncArgs.ppszArchs == null) {
        const nArchSlots: usize = @as(usize, c.TDNF_REPOSYNC_MAXARCHS) + 1;
        const pAllocated = c.calloc(nArchSlots, @sizeOf(?[*:0]u8)) orelse
            return c.ERROR_TDNF_OUT_OF_MEMORY;
        pReposyncArgs.ppszArchs = @ptrCast(@alignCast(pAllocated));
    }
    return 0;
}

fn appendArch(pReposyncArgs: *c.TDNF_REPOSYNC_ARGS, pszArch: [*c]const u8) u32 {
    var dwError = ensureArchArray(pReposyncArgs);
    if (dwError != 0) {
        return dwError;
    }

    var i: usize = 0;
    while (i < c.TDNF_REPOSYNC_MAXARCHS and pReposyncArgs.ppszArchs[i] != null) : (i += 1) {}
    if (i >= c.TDNF_REPOSYNC_MAXARCHS) {
        return 0;
    }

    dwError = duplicateString(pszArch, &pReposyncArgs.ppszArchs[i]);
    return dwError;
}

fn freeCString(pszValue: [*c]u8) void {
    if (pszValue) |value| {
        c.free(value);
    }
}

fn freeArchArray(ppszArchs: [*c][*c]u8) void {
    if (ppszArchs) |ppArchs| {
        var i: usize = 0;
        while (i < c.TDNF_REPOSYNC_MAXARCHS and ppArchs[i] != null) : (i += 1) {
            freeCString(ppArchs[i]);
        }
        c.free(@ptrCast(ppArchs));
    }
}

pub export fn TDNFCliParseRepoSyncArgs(
    pArgs: ?*c.TDNF_CMD_ARGS,
    ppReposyncArgs: ?*?*c.TDNF_REPOSYNC_ARGS,
) u32 {
    const cmd_args = pArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const out = ppReposyncArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    const pAllocated = c.calloc(1, @sizeOf(c.TDNF_REPOSYNC_ARGS)) orelse
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    const pReposyncArgs: *c.TDNF_REPOSYNC_ARGS = @ptrCast(@alignCast(pAllocated));
    errdefer TDNFCliFreeRepoSyncArgs(pReposyncArgs);

    var pNode: [*c]c.struct_cnfnode = if (cmd_args.cn_setopts != null) cmd_args.cn_setopts[0].first_child else null;
    while (pNode != null) : (pNode = pNode[0].next) {
        if (equalsIgnoreCase(pNode[0].name, "arch")) {
            const dwError = appendArch(pReposyncArgs, pNode[0].value);
            if (dwError != 0) {
                return dwError;
            }
        } else if (equalsIgnoreCase(pNode[0].name, "delete")) {
            pReposyncArgs.nDelete = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "download-metadata")) {
            pReposyncArgs.nDownloadMetadata = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "gpgcheck")) {
            pReposyncArgs.nGPGCheck = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "newest-only")) {
            pReposyncArgs.nNewestOnly = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "norepopath")) {
            pReposyncArgs.nNoRepoPath = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "source")) {
            pReposyncArgs.nSourceOnly = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "urls")) {
            pReposyncArgs.nPrintUrlsOnly = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "download-path")) {
            freeCString(pReposyncArgs.pszDownloadPath);
            pReposyncArgs.pszDownloadPath = null;
            const dwError = duplicateString(pNode[0].value, &pReposyncArgs.pszDownloadPath);
            if (dwError != 0) {
                return dwError;
            }
        } else if (equalsIgnoreCase(pNode[0].name, "metadata-path")) {
            freeCString(pReposyncArgs.pszMetaDataPath);
            pReposyncArgs.pszMetaDataPath = null;
            const dwError = duplicateString(pNode[0].value, &pReposyncArgs.pszMetaDataPath);
            if (dwError != 0) {
                return dwError;
            }
        }
    }

    out.* = pReposyncArgs;
    return 0;
}

pub export fn TDNFCliFreeRepoSyncArgs(pReposyncArgs: ?*c.TDNF_REPOSYNC_ARGS) void {
    if (pReposyncArgs) |reposync_args| {
        freeArchArray(reposync_args.ppszArchs);
        freeCString(reposync_args.pszDownloadPath);
        freeCString(reposync_args.pszMetaDataPath);
        c.free(reposync_args);
    }
}

test "TDNFCliParseRepoSyncArgs preserves reposync flags and values" {
    var setopt_root: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var arch0_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var arch1_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var delete_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var path_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var metadata_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);

    arch0_node.name = @constCast("arch");
    arch0_node.value = @constCast("x86_64");
    arch1_node.name = @constCast("arch");
    arch1_node.value = @constCast("aarch64");
    delete_node.name = @constCast("delete");
    path_node.name = @constCast("download-path");
    path_node.value = @constCast("/repo-sync/download");
    metadata_node.name = @constCast("metadata-path");
    metadata_node.value = @constCast("/repo-sync/metadata");

    arch0_node.next = &arch1_node;
    arch1_node.next = &delete_node;
    delete_node.next = &path_node;
    path_node.next = &metadata_node;
    setopt_root.first_child = &arch0_node;

    var cmd_args: c.TDNF_CMD_ARGS = std.mem.zeroes(c.TDNF_CMD_ARGS);
    cmd_args.cn_setopts = &setopt_root;

    var pReposyncArgs: ?*c.TDNF_REPOSYNC_ARGS = null;
    defer TDNFCliFreeRepoSyncArgs(pReposyncArgs);

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseRepoSyncArgs(&cmd_args, &pReposyncArgs));
    try std.testing.expect(pReposyncArgs != null);
    try std.testing.expectEqual(@as(c_int, 1), pReposyncArgs.?.nDelete);
    try std.testing.expect(pReposyncArgs.?.ppszArchs != null);
    try std.testing.expectEqualStrings("x86_64", std.mem.span(pReposyncArgs.?.ppszArchs[0].?));
    try std.testing.expectEqualStrings("aarch64", std.mem.span(pReposyncArgs.?.ppszArchs[1].?));
    try std.testing.expectEqualStrings(
        "/repo-sync/download",
        std.mem.span(pReposyncArgs.?.pszDownloadPath.?),
    );
    try std.testing.expectEqualStrings(
        "/repo-sync/metadata",
        std.mem.span(pReposyncArgs.?.pszMetaDataPath.?),
    );
}

test "TDNFCliParseRepoSyncArgs preserves boolean option names" {
    var setopt_root: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var metadata_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var gpg_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var newest_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var norepopath_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var source_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var urls_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);

    metadata_node.name = @constCast("download-metadata");
    gpg_node.name = @constCast("gpgcheck");
    newest_node.name = @constCast("newest-only");
    norepopath_node.name = @constCast("norepopath");
    source_node.name = @constCast("source");
    urls_node.name = @constCast("urls");

    metadata_node.next = &gpg_node;
    gpg_node.next = &newest_node;
    newest_node.next = &norepopath_node;
    norepopath_node.next = &source_node;
    source_node.next = &urls_node;
    setopt_root.first_child = &metadata_node;

    var cmd_args: c.TDNF_CMD_ARGS = std.mem.zeroes(c.TDNF_CMD_ARGS);
    cmd_args.cn_setopts = &setopt_root;

    var pReposyncArgs: ?*c.TDNF_REPOSYNC_ARGS = null;
    defer TDNFCliFreeRepoSyncArgs(pReposyncArgs);

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseRepoSyncArgs(&cmd_args, &pReposyncArgs));
    try std.testing.expectEqual(@as(c_int, 1), pReposyncArgs.?.nDownloadMetadata);
    try std.testing.expectEqual(@as(c_int, 1), pReposyncArgs.?.nGPGCheck);
    try std.testing.expectEqual(@as(c_int, 1), pReposyncArgs.?.nNewestOnly);
    try std.testing.expectEqual(@as(c_int, 1), pReposyncArgs.?.nNoRepoPath);
    try std.testing.expectEqual(@as(c_int, 1), pReposyncArgs.?.nSourceOnly);
    try std.testing.expectEqual(@as(c_int, 1), pReposyncArgs.?.nPrintUrlsOnly);
}
