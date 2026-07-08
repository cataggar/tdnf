// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const getopt = @import("getopt_c.zig").c;
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("string.h");
    @cInclude("tdnfclierror.h");
    @cInclude("tdnferror.h");
});

fn isNullOrEmpty(pszValue: [*c]const u8) bool {
    return pszValue == null or pszValue[0] == 0;
}

fn stripOptionMarker(pszName: [*c]const u8) [*c]const u8 {
    if (pszName != null and std.mem.startsWith(u8, std.mem.span(pszName), "--")) {
        return pszName + 2;
    }
    return pszName;
}

pub fn validateOptionsRaw(
    pszName: [*c]const u8,
    pszArg: [*c]const u8,
    pKnownOptions: [*c]const getopt.struct_option,
) u32 {
    return TDNFCliValidateOptions(pszName, pszArg, @constCast(pKnownOptions));
}

pub export fn _TDNFCliGetOptionByName(
    pszName: [*c]const u8,
    pKnownOptions: [*c]getopt.struct_option,
    ppOption: ?*[*c]getopt.struct_option,
) u32 {
    if (isNullOrEmpty(pszName) or pKnownOptions == null or ppOption == null) {
        if (ppOption) |out| {
            out.* = null;
        }
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszSearch = stripOptionMarker(pszName);
    var pOption = pKnownOptions;
    while (pOption != null and pOption[0].name != null) : (pOption += 1) {
        if (c.strcmp(pszSearch, pOption[0].name) == 0) {
            ppOption.?.* = pOption;
            return 0;
        }
    }

    ppOption.?.* = null;
    return c.ERROR_TDNF_CLI_OPTION_NAME_INVALID;
}

pub export fn TDNFCliValidateOptionName(
    pszName: [*c]const u8,
    pKnownOptions: [*c]getopt.struct_option,
) u32 {
    var pOption: [*c]getopt.struct_option = null;

    if (isNullOrEmpty(pszName) or pKnownOptions == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    return _TDNFCliGetOptionByName(pszName, pKnownOptions, &pOption);
}

pub export fn TDNFCliValidateOptionArg(
    pszName: [*c]const u8,
    pszArg: [*c]const u8,
    pKnownOptions: [*c]getopt.struct_option,
) u32 {
    var pOption: [*c]getopt.struct_option = null;
    var dwError: u32 = 0;

    if (isNullOrEmpty(pszName) or pKnownOptions == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    dwError = _TDNFCliGetOptionByName(pszName, pKnownOptions, &pOption);
    if (dwError != 0) {
        return dwError;
    }

    if (isNullOrEmpty(pszArg) and pOption[0].has_arg == getopt.required_argument) {
        return c.ERROR_TDNF_CLI_OPTION_ARG_REQUIRED;
    }

    if (!isNullOrEmpty(pszArg) and pOption[0].has_arg == getopt.no_argument) {
        return c.ERROR_TDNF_CLI_OPTION_ARG_UNEXPECTED;
    }

    return 0;
}

pub export fn TDNFCliValidateOptions(
    pszName: [*c]const u8,
    pszArg: [*c]const u8,
    pKnownOptions: [*c]getopt.struct_option,
) u32 {
    var dwError: u32 = 0;

    if (isNullOrEmpty(pszName) or pKnownOptions == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    dwError = TDNFCliValidateOptionName(pszName, pKnownOptions);
    if (dwError != 0) {
        return dwError;
    }

    return TDNFCliValidateOptionArg(pszName, pszArg, pKnownOptions);
}

test "_TDNFCliGetOptionByName strips leading dashes" {
    var known_options = [_]getopt.struct_option{
        .{ .name = "config", .has_arg = getopt.required_argument, .flag = null, .val = 'c' },
        .{ .name = null, .has_arg = 0, .flag = null, .val = 0 },
    };
    var pOption: [*c]getopt.struct_option = null;

    try std.testing.expectEqual(
        @as(u32, 0),
        _TDNFCliGetOptionByName("--config", &known_options, &pOption),
    );
    try std.testing.expect(pOption != null);
    try std.testing.expectEqualStrings("config", std.mem.span(pOption[0].name.?));
}

test "TDNFCliValidateOptionArg preserves required and no-argument checks" {
    var known_options = [_]getopt.struct_option{
        .{ .name = "config", .has_arg = getopt.required_argument, .flag = null, .val = 'c' },
        .{ .name = "help", .has_arg = getopt.no_argument, .flag = null, .val = 'h' },
        .{ .name = null, .has_arg = 0, .flag = null, .val = 0 },
    };

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_CLI_OPTION_ARG_REQUIRED),
        TDNFCliValidateOptionArg("config", null, &known_options),
    );
    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_CLI_OPTION_ARG_UNEXPECTED),
        TDNFCliValidateOptionArg("help", "1", &known_options),
    );
}
