// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

pub const c = @import("getopt_c.zig").c;

pub export fn TDNFCliArgParseReset() void {
    c.optind = 1;
    c.opterr = 0;
    c.optopt = 0;
    c.optarg = null;
}

pub export fn TDNFCliArgParseSetOptErr(nValue: c_int) void {
    c.opterr = nValue;
}

pub export fn TDNFCliArgParseOptArg() ?[*:0]u8 {
    return c.optarg;
}

pub export fn TDNFCliArgParseOptInd() c_int {
    return c.optind;
}

pub export fn TDNFCliArgParseOptOpt() c_int {
    return c.optopt;
}

pub export fn TDNFCliArgParseLongOnly(
    argc: c_int,
    argv: [*c]?[*:0]u8,
    pszShortOptions: ?[*:0]const u8,
    pstOptions: [*c]const c.struct_option,
    pnOptionIndex: ?*c_int,
) c_int {
    return c.getopt_long_only(
        argc,
        @ptrCast(argv),
        pszShortOptions,
        pstOptions,
        pnOptionIndex,
    );
}

pub export fn TDNFCliArgParseLong(
    argc: c_int,
    argv: [*c]?[*:0]u8,
    pszShortOptions: ?[*:0]const u8,
    pstOptions: [*c]const c.struct_option,
    pnOptionIndex: ?*c_int,
) c_int {
    return c.getopt_long(
        argc,
        @ptrCast(argv),
        pszShortOptions,
        pstOptions,
        pnOptionIndex,
    );
}
