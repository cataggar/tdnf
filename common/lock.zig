// Copyright (C) 2021-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

const c = @cImport({
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("string.h");
});

extern fn log_console(nLogLevel: c_int, pszFormat: [*:0]const u8, ...) void;
extern fn flock(nFd: c_int, nOperation: c_int) c_int;
extern fn close(nFd: c_int) c_int;
extern fn sleep(nSeconds: c_uint) c_uint;

const LOG_ERR: c_int = 1;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const LOCK_UN: c_int = 8;

fn isNullOrEmptyString(pszValueOpt: ?[*:0]const u8) bool {
    return pszValueOpt == null or pszValueOpt.?[0] == 0;
}

fn tdnfCreateLockFile(pszLockPath: [*:0]const u8) c_int {
    const oflag: std.c.O = .{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .CLOEXEC = true,
    };
    const oldmask = std.c.umask(@as(std.c.mode_t, 0o22));
    const nLockFd = std.c.open(pszLockPath, oflag, @as(std.c.mode_t, 0o644));
    _ = std.c.umask(oldmask);

    if (nLockFd < 0) {
        const nErrNo = c.__errno_location().*;
        log_console(
            LOG_ERR,
            "%s: open failed for %s (%s)\n",
            "tdnfCreateLockFile",
            pszLockPath,
            c.strerror(nErrNo),
        );
        return -1;
    }

    {
        var szPidBuf = [_]u8{0} ** 128;
        const nWritten = c.snprintf(
            &szPidBuf[0],
            szPidBuf.len,
            "%ld\n",
            @as(c_long, @intCast(std.c.getpid())),
        );

        if (nWritten > 0) {
            if (std.c.write(nLockFd, szPidBuf[0..].ptr, @as(usize, @intCast(nWritten))) == 0) {
                std.c.sync();
            }
        }
    }

    return nLockFd;
}

export fn tdnfLockAcquire(pszLockPathOpt: ?[*:0]const u8) c_int {
    var nLockFd: c_int = -1;
    const pszLockPath = pszLockPathOpt orelse "";

    if (isNullOrEmptyString(pszLockPathOpt)) {
        log_console(LOG_ERR, "%s: lockPath is empty\n", "tdnfLockAcquire");
        return -1;
    }

    nLockFd = tdnfCreateLockFile(pszLockPath);
    if (nLockFd < 0) {
        log_console(LOG_ERR, "%s: tdnfCreateLockFile failed\n", "tdnfLockAcquire");
        return -1;
    }

    while (true) {
        if (flock(nLockFd, LOCK_EX | LOCK_NB) == 0) {
            break;
        }
        log_console(
            LOG_ERR,
            "WARNING: failed to acquire lock on: %s, retrying ...\n",
            pszLockPath,
        );
        _ = sleep(1);
    }

    return nLockFd;
}

export fn tdnfLockFree(pszLockPathOpt: ?[*:0]const u8, nLockFd: c_int) void {
    const pszLockPath = pszLockPathOpt orelse "";

    if (nLockFd >= 0) {
        if (flock(nLockFd, LOCK_UN) != 0) {
            log_console(LOG_ERR, "ERROR: failed to unlock: '%s'\n", pszLockPath);
        }
        _ = close(nLockFd);
    }

    if (std.c.access(pszLockPath, 0) == 0 and c.remove(pszLockPath) != 0) {
        log_console(LOG_ERR, "WARNING: Unable to remove lockfile(%s)\n", pszLockPath);
    }
}

test "tdnfLockAcquire writes the pid and tdnfLockFree removes the file" {
    var szLockPath = [_]u8{0} ** 128;
    const pszLockPath = try std.fmt.bufPrintZ(
        &szLockPath,
        "zig-test-lock-{d}.lock",
        .{std.c.getpid()},
    );

    _ = c.remove(pszLockPath);

    const nLockFd = tdnfLockAcquire(pszLockPath);
    try std.testing.expect(nLockFd >= 0);
    defer _ = c.remove(pszLockPath);

    const pLockFile = c.fopen(pszLockPath, "rb");
    try std.testing.expect(pLockFile != null);
    defer _ = c.fclose(pLockFile);

    var szContents = [_]u8{0} ** 128;
    const nRead = c.fread(&szContents[0], 1, szContents.len - 1, pLockFile);
    const pszContents = szContents[0..nRead];

    var szExpectedPid = [_]u8{0} ** 32;
    const pszExpectedPid = try std.fmt.bufPrint(&szExpectedPid, "{d}\n", .{std.c.getpid()});
    try std.testing.expectEqualStrings(pszExpectedPid, pszContents);

    tdnfLockFree(pszLockPath, nLockFd);
    try std.testing.expect(std.c.access(pszLockPath, 0) != 0);
}
