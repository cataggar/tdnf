// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("tdnfcli.h");
    @cInclude("tdnferror.h");
});
const choice_parse = @import("choice_parse.zig");

const FilterType = choice_parse.NamedValue(c.TDNF_REPOLISTFILTER);
const filter_types = [_]FilterType{
    .{ .name = "all", .value = c.REPOLISTFILTER_ALL },
    .{ .name = "enabled", .value = c.REPOLISTFILTER_ENABLED },
    .{ .name = "disabled", .value = c.REPOLISTFILTER_DISABLED },
};

fn setFilterOut(pnFilter: ?*c.TDNF_REPOLISTFILTER, nFilter: c.TDNF_REPOLISTFILTER) void {
    if (pnFilter) |out| {
        out.* = nFilter;
    }
}

pub export fn TDNFCliParseRepoListArgs(
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    pnFilter: ?*c.TDNF_REPOLISTFILTER,
) u32 {
    var nFilter: c.TDNF_REPOLISTFILTER = c.REPOLISTFILTER_ENABLED;

    if (pCmdArgs == null or pnFilter == null) {
        setFilterOut(pnFilter, c.REPOLISTFILTER_ENABLED);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const cmd_args = pCmdArgs.?;
    if (cmd_args.nCmdCount > 1) {
        const dwError = TDNFCliParseFilter(cmd_args.ppszCmds[1], &nFilter);
        if (dwError != 0) {
            setFilterOut(pnFilter, c.REPOLISTFILTER_ENABLED);
            return dwError;
        }
    }

    pnFilter.?.* = nFilter;
    return 0;
}

pub export fn TDNFCliParseFilter(
    pszFilter: ?[*:0]const u8,
    pnFilter: ?*c.TDNF_REPOLISTFILTER,
) u32 {
    const out = pnFilter orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const nFilter = choice_parse.parseChoice(c.TDNF_REPOLISTFILTER, pszFilter, &filter_types) orelse {
        out.* = c.REPOLISTFILTER_ENABLED;
        return if (pszFilter == null)
            c.ERROR_TDNF_INVALID_PARAMETER
        else
            c.ERROR_TDNF_CLI_NO_MATCH;
    };

    out.* = nFilter;
    return 0;
}

test "TDNFCliParseFilter preserves repolist filters" {
    var nFilter: c.TDNF_REPOLISTFILTER = c.REPOLISTFILTER_ALL;

    try std.testing.expectEqual(@as(u32, 0), TDNFCliParseFilter("DisAbLeD", &nFilter));
    try std.testing.expectEqual(
        @as(@TypeOf(nFilter), @intCast(c.REPOLISTFILTER_DISABLED)),
        nFilter,
    );
}
