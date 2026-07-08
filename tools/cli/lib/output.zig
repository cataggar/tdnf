// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("sys/ioctl.h");
    @cInclude("unistd.h");
    @cInclude("tdnferror.h");
});

pub export fn GetConsoleWidth(pnConsoleWidth: ?*c_int) u32 {
    const out = pnConsoleWidth orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var stWinSize: c.struct_winsize = std.mem.zeroes(c.struct_winsize);
    const nIoctlError = c.ioctl(c.STDOUT_FILENO, c.TIOCGWINSZ, &stWinSize);

    if (nIoctlError != 0) {
        out.* = 80;
    } else {
        out.* = stWinSize.ws_col;
    }

    return 0;
}

pub export fn GetColumnWidths(
    nCount: c_int,
    pnColPercents: [*c]const c_int,
    pnColWidths: [*c]c_int,
) u32 {
    if (pnColPercents == null or pnColWidths == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    var nConsoleWidth: c_int = 0;
    const dwError = GetConsoleWidth(&nConsoleWidth);
    if (dwError != 0) {
        return dwError;
    }

    var nIndex: c_int = 0;
    while (nIndex < nCount) : (nIndex += 1) {
        pnColWidths[@intCast(nIndex)] =
            @divTrunc(nConsoleWidth * pnColPercents[@intCast(nIndex)], 100);
    }

    return 0;
}

test "GetColumnWidths validates arguments" {
    var nWidths = [_]c_int{0} ** 2;
    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        GetColumnWidths(2, null, &nWidths),
    );
    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        GetColumnWidths(2, &[_]c_int{ 50, 50 }, null),
    );
}
