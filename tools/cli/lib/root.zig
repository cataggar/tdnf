// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("getopt.h");
});
const argparse = @import("argparse.zig");
const help = @import("help.zig");
const options = @import("options.zig");
const parseargs = @import("parseargs.zig");
const parsecleanargs = @import("parsecleanargs.zig");
const parsehistoryargs = @import("parsehistoryargs.zig");
const parselistargs = @import("parselistargs.zig");
const parserepolistargs = @import("parserepolistargs.zig");
const parserepoqueryargs = @import("parserepoqueryargs.zig");
const parsereposyncargs = @import("parsereposyncargs.zig");
const parseupdateinfo = @import("parseupdateinfo.zig");

comptime {
    _ = argparse;
    _ = help;
    _ = options;
    _ = parseargs;
    _ = parsecleanargs;
    _ = parsehistoryargs;
    _ = parselistargs;
    _ = parserepolistargs;
    _ = parserepoqueryargs;
    _ = parsereposyncargs;
    _ = parseupdateinfo;
}

test "TDNFCliArgParseReset clears getopt state" {
    c.optind = 42;
    c.opterr = 7;
    c.optopt = 9;
    c.optarg = @constCast("demo");

    argparse.TDNFCliArgParseReset();

    try std.testing.expectEqual(@as(c_int, 1), argparse.TDNFCliArgParseOptInd());
    try std.testing.expectEqual(@as(c_int, 0), c.opterr);
    try std.testing.expectEqual(@as(c_int, 0), argparse.TDNFCliArgParseOptOpt());
    try std.testing.expect(argparse.TDNFCliArgParseOptArg() == null);
}
