// Copyright (C) 2019-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const libc = std.c;

extern var stdout: *libc.FILE;
extern var stderr: *libc.FILE;

const LOG_INFO: c_int = 0;
const LOG_ERR: c_int = 1;
const LOG_CRIT: c_int = 2;

var gbQuiet = false;
var gbJson = false;
var gbDnfCheckUpdateCompat = false;

fn resetGlobalStateForTest() void {
    gbQuiet = false;
    gbJson = false;
    gbDnfCheckUpdateCompat = false;
}

fn tdnfLogGetStream(nLogLevel: c_int) ?*libc.FILE {
    switch (nLogLevel) {
        LOG_INFO, LOG_CRIT => {
            if (gbJson) {
                return null;
            }
            if (nLogLevel == LOG_INFO and gbQuiet) {
                return null;
            }
            return stdout;
        },
        LOG_ERR => {
            return stderr;
        },
        else => {
            return null;
        },
    }
}

export fn GlobalSetQuiet(nValue: i32) void {
    if (nValue > 0) {
        gbQuiet = true;
    }
}

export fn GlobalSetJson(nValue: i32) void {
    if (nValue > 0) {
        gbJson = true;
    }
}

export fn GlobalSetDnfCheckUpdateCompat(nValue: i32) void {
    if (nValue > 0) {
        gbDnfCheckUpdateCompat = true;
    }
}

export fn GlobalGetDnfCheckUpdateCompat() bool {
    return gbDnfCheckUpdateCompat;
}

export fn TDNFLogGetStream(nLogLevel: c_int) ?*libc.FILE {
    return tdnfLogGetStream(nLogLevel);
}

test "GlobalSetQuiet only suppresses info logs" {
    resetGlobalStateForTest();
    defer resetGlobalStateForTest();

    try std.testing.expect(tdnfLogGetStream(LOG_INFO) == stdout);
    try std.testing.expect(tdnfLogGetStream(LOG_CRIT) == stdout);
    try std.testing.expect(tdnfLogGetStream(LOG_ERR) == stderr);

    GlobalSetQuiet(1);
    try std.testing.expect(tdnfLogGetStream(LOG_INFO) == null);
    try std.testing.expect(tdnfLogGetStream(LOG_CRIT) == stdout);
    try std.testing.expect(tdnfLogGetStream(LOG_ERR) == stderr);

    GlobalSetQuiet(0);
    try std.testing.expect(tdnfLogGetStream(LOG_INFO) == null);
}

test "GlobalSetJson suppresses stdout logs and is one way" {
    resetGlobalStateForTest();
    defer resetGlobalStateForTest();

    GlobalSetJson(1);
    try std.testing.expect(tdnfLogGetStream(LOG_INFO) == null);
    try std.testing.expect(tdnfLogGetStream(LOG_CRIT) == null);
    try std.testing.expect(tdnfLogGetStream(LOG_ERR) == stderr);

    GlobalSetJson(0);
    try std.testing.expect(tdnfLogGetStream(LOG_INFO) == null);
    try std.testing.expect(tdnfLogGetStream(LOG_CRIT) == null);
}

test "GlobalSetDnfCheckUpdateCompat is one way" {
    resetGlobalStateForTest();
    defer resetGlobalStateForTest();

    try std.testing.expect(!GlobalGetDnfCheckUpdateCompat());

    GlobalSetDnfCheckUpdateCompat(0);
    try std.testing.expect(!GlobalGetDnfCheckUpdateCompat());

    GlobalSetDnfCheckUpdateCompat(1);
    try std.testing.expect(GlobalGetDnfCheckUpdateCompat());

    GlobalSetDnfCheckUpdateCompat(0);
    try std.testing.expect(GlobalGetDnfCheckUpdateCompat());
}

test "log setters ignore non positive values and unknown levels are suppressed" {
    resetGlobalStateForTest();
    defer resetGlobalStateForTest();

    GlobalSetQuiet(-1);
    GlobalSetJson(0);
    try std.testing.expect(tdnfLogGetStream(LOG_INFO) == stdout);
    try std.testing.expect(tdnfLogGetStream(99) == null);
}
