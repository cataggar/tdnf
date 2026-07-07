// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

pub fn NamedValue(comptime T: type) type {
    return struct {
        name: []const u8,
        value: T,
    };
}

pub fn parseChoice(
    comptime T: type,
    pszChoice: ?[*:0]const u8,
    choices: []const NamedValue(T),
) ?T {
    const choice = pszChoice orelse return null;
    const choice_slice = std.mem.span(choice);

    for (choices) |entry| {
        if (std.ascii.eqlIgnoreCase(choice_slice, entry.name)) {
            return entry.value;
        }
    }
    return null;
}

test "parseChoice matches values case-insensitively" {
    const Choice = NamedValue(u32);
    const choices = [_]Choice{
        .{ .name = "all", .value = 1 },
        .{ .name = "metadata", .value = 2 },
    };

    try std.testing.expectEqual(@as(?u32, 1), parseChoice(u32, "ALL", &choices));
    try std.testing.expectEqual(@as(?u32, null), parseChoice(u32, "missing", &choices));
}
