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

comptime {
    _ = argparse;
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
