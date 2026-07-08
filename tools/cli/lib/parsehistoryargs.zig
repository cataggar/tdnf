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

fn equals(pszValue: ?[*:0]const u8, comptime pszExpected: [*:0]const u8) bool {
    return pszValue != null and c.strcmp(pszValue, pszExpected) == 0;
}

fn equalsIgnoreCase(pszValue: ?[*:0]const u8, comptime pszExpected: [*:0]const u8) bool {
    return pszValue != null and c.strcasecmp(pszValue, pszExpected) == 0;
}

fn parseRangeValue(pszValue: []const u8) c_int {
    return std.fmt.parseInt(c_int, pszValue, 10) catch 0;
}

fn parseCommand(pHistoryArgs: *c.TDNF_HISTORY_ARGS, pszCommand: ?[*:0]const u8) void {
    if (equals(pszCommand, "list")) {
        pHistoryArgs.nCommand = c.HISTORY_CMD_LIST;
    } else if (equals(pszCommand, "init") or equals(pszCommand, "update")) {
        pHistoryArgs.nCommand = c.HISTORY_CMD_INIT;
    } else if (equals(pszCommand, "rollback")) {
        pHistoryArgs.nCommand = c.HISTORY_CMD_ROLLBACK;
    } else if (equals(pszCommand, "undo")) {
        pHistoryArgs.nCommand = c.HISTORY_CMD_UNDO;
    } else if (equals(pszCommand, "redo")) {
        pHistoryArgs.nCommand = c.HISTORY_CMD_REDO;
    } else if (equals(pszCommand, "id")) {
        pHistoryArgs.nCommand = c.HISTORY_CMD_ID;
    }
}

fn parseRange(pHistoryArgs: *c.TDNF_HISTORY_ARGS, pszRange: ?[*:0]const u8) void {
    const range = pszRange orelse return;
    const slice = std.mem.span(range);
    if (slice.len == 0 or !std.ascii.isDigit(slice[0])) {
        return;
    }

    var it = std.mem.tokenizeScalar(u8, slice, '-');
    if (it.next()) |pszFrom| {
        pHistoryArgs.nFrom = parseRangeValue(pszFrom);
    }
    if (it.next()) |pszTo| {
        pHistoryArgs.nTo = parseRangeValue(pszTo);
    }
}

fn parseSetOpts(pHistoryArgs: *c.TDNF_HISTORY_ARGS, pSetOpts: [*c]c.struct_cnfnode) void {
    var pNode: [*c]c.struct_cnfnode = if (pSetOpts != null) pSetOpts[0].first_child else null;
    while (pNode != null) : (pNode = pNode[0].next) {
        if (equalsIgnoreCase(pNode[0].name, "info")) {
            pHistoryArgs.nInfo = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "reverse")) {
            pHistoryArgs.nReverse = 1;
        } else if (equalsIgnoreCase(pNode[0].name, "from")) {
            if (pNode[0].value) |pszValue| {
                pHistoryArgs.nFrom = parseRangeValue(std.mem.span(pszValue));
            } else {
                pHistoryArgs.nFrom = 0;
            }
        } else if (equalsIgnoreCase(pNode[0].name, "to")) {
            if (pNode[0].value) |pszValue| {
                pHistoryArgs.nTo = parseRangeValue(std.mem.span(pszValue));
            } else {
                pHistoryArgs.nTo = 0;
            }
        }
    }
}

pub export fn TDNFCliParseHistoryArgs(
    pArgs: ?*c.TDNF_CMD_ARGS,
    ppHistoryArgs: ?*?*c.TDNF_HISTORY_ARGS,
) u32 {
    const cmd_args = pArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const out = ppHistoryArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    const pAllocated = c.calloc(1, @sizeOf(c.TDNF_HISTORY_ARGS)) orelse
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    const pHistoryArgs: *c.TDNF_HISTORY_ARGS = @ptrCast(@alignCast(pAllocated));

    if (cmd_args.nCmdCount > 1) {
        parseCommand(pHistoryArgs, cmd_args.ppszCmds[1]);
    }
    if (cmd_args.nCmdCount > 2) {
        parseRange(pHistoryArgs, cmd_args.ppszCmds[2]);
    }

    parseSetOpts(pHistoryArgs, cmd_args.cn_setopts);

    if (pHistoryArgs.nTo == 0) {
        pHistoryArgs.nTo = pHistoryArgs.nFrom;
    }

    out.* = pHistoryArgs;
    return 0;
}

pub export fn TDNFCliFreeHistoryArgs(pHistoryArgs: ?*c.TDNF_HISTORY_ARGS) void {
    if (pHistoryArgs) |history_args| {
        c.free(history_args);
    }
}

test "TDNFCliParseHistoryArgs preserves history command and range parsing" {
    var setopt_root: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var from_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var info_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);

    from_node.name = @constCast("from");
    from_node.value = @constCast("41");
    info_node.name = @constCast("info");
    from_node.next = &info_node;
    setopt_root.first_child = &from_node;

    var ppszCmds = [_]?[*:0]u8{
        @constCast("history"),
        @constCast("rollback"),
        @constCast("12-16"),
    };
    var cmd_args: c.TDNF_CMD_ARGS = std.mem.zeroes(c.TDNF_CMD_ARGS);
    cmd_args.ppszCmds = @ptrCast(&ppszCmds);
    cmd_args.nCmdCount = 3;
    cmd_args.cn_setopts = &setopt_root;

    var pHistoryArgs: ?*c.TDNF_HISTORY_ARGS = null;
    defer TDNFCliFreeHistoryArgs(pHistoryArgs);

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseHistoryArgs(&cmd_args, &pHistoryArgs));
    try std.testing.expect(pHistoryArgs != null);
    try std.testing.expectEqual(
        @as(@TypeOf(pHistoryArgs.?.nCommand), @intCast(c.HISTORY_CMD_ROLLBACK)),
        pHistoryArgs.?.nCommand,
    );
    try std.testing.expectEqual(@as(c_int, 1), pHistoryArgs.?.nInfo);
    try std.testing.expectEqual(@as(c_int, 41), pHistoryArgs.?.nFrom);
    try std.testing.expectEqual(@as(c_int, 16), pHistoryArgs.?.nTo);
}

test "TDNFCliParseHistoryArgs defaults missing to range end" {
    var setopt_root: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    var reverse_node: c.struct_cnfnode = std.mem.zeroes(c.struct_cnfnode);
    reverse_node.name = @constCast("reverse");
    setopt_root.first_child = &reverse_node;

    var ppszCmds = [_]?[*:0]u8{
        @constCast("history"),
        @constCast("id"),
        @constCast("9"),
    };
    var cmd_args: c.TDNF_CMD_ARGS = std.mem.zeroes(c.TDNF_CMD_ARGS);
    cmd_args.ppszCmds = @ptrCast(&ppszCmds);
    cmd_args.nCmdCount = 3;
    cmd_args.cn_setopts = &setopt_root;

    var pHistoryArgs: ?*c.TDNF_HISTORY_ARGS = null;
    defer TDNFCliFreeHistoryArgs(pHistoryArgs);

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseHistoryArgs(&cmd_args, &pHistoryArgs));
    try std.testing.expect(pHistoryArgs != null);
    try std.testing.expectEqual(
        @as(@TypeOf(pHistoryArgs.?.nCommand), @intCast(c.HISTORY_CMD_ID)),
        pHistoryArgs.?.nCommand,
    );
    try std.testing.expectEqual(@as(c_int, 1), pHistoryArgs.?.nReverse);
    try std.testing.expectEqual(@as(c_int, 9), pHistoryArgs.?.nFrom);
    try std.testing.expectEqual(@as(c_int, 9), pHistoryArgs.?.nTo);
}
