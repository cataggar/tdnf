// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

const c = @cImport({
    @cInclude("errno.h");
    @cInclude("stdarg.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("defines.h");
    @cInclude("tdnferror.h");
});

const AllocOps = struct {
    ctx: ?*anyopaque = null,
    callocFn: *const fn (ctx: ?*anyopaque, count: usize, size: usize) ?*anyopaque,
    reallocFn: *const fn (ctx: ?*anyopaque, ptr: ?*anyopaque, size: usize) ?*anyopaque,
    freeFn: *const fn (ctx: ?*anyopaque, ptr: ?*anyopaque) void,
};

const libc_ops = AllocOps{
    .callocFn = libcCalloc,
    .reallocFn = libcRealloc,
    .freeFn = libcFree,
};

fn libcCalloc(_: ?*anyopaque, count: usize, size: usize) ?*anyopaque {
    return c.calloc(count, size);
}

fn libcRealloc(_: ?*anyopaque, ptr: ?*anyopaque, size: usize) ?*anyopaque {
    return c.realloc(ptr, size);
}

fn libcFree(_: ?*anyopaque, ptr: ?*anyopaque) void {
    if (ptr) |p| {
        c.free(p);
    }
}

fn setNullOut(comptime T: type, out: ?*T) void {
    if (out) |p| {
        p.* = null;
    }
}

fn freeWithOps(ops: AllocOps, ptr: ?*anyopaque) void {
    ops.freeFn(ops.ctx, ptr);
}

fn freeCStringWithOps(ops: AllocOps, psz: ?[*:0]u8) void {
    if (psz) |p| {
        freeWithOps(ops, @ptrCast(p));
    }
}

fn freeStringArrayWithCArrayOps(ops: AllocOps, ppszArray: [*c]?[*:0]u8) void {
    if (ppszArray == null) {
        return;
    }
    var i: usize = 0;
    while (ppszArray[i] != null) : (i += 1) {
        freeCStringWithOps(ops, ppszArray[i]);
    }
    freeWithOps(ops, @ptrCast(ppszArray));
}

fn freeStringArrayWithCountWithCArrayOps(
    ops: AllocOps,
    ppszArray: [*c]?[*:0]u8,
    nCount: c_int,
) void {
    if (ppszArray == null) {
        return;
    }
    var remaining = nCount;
    while (remaining > 0) {
        remaining -= 1;
        freeCStringWithOps(ops, ppszArray[@as(usize, @intCast(remaining))]);
    }
    freeWithOps(ops, @ptrCast(ppszArray));
}

fn systemErrorFromErrno() u32 {
    const err = c.ERROR_TDNF_SYSTEM_BASE + std.c._errno().*;
    return @intCast(err);
}

fn allocateMemoryWithOps(
    ops: AllocOps,
    nNumElements: usize,
    nSize: usize,
    ppMemory: ?*?*anyopaque,
) u32 {
    if (ppMemory == null or nSize == 0 or nNumElements == 0) {
        setNullOut(?*anyopaque, ppMemory);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    if (nNumElements > std.math.maxInt(usize) / nSize) {
        setNullOut(?*anyopaque, ppMemory);
        return c.ERROR_TDNF_INVALID_ALLOCSIZE;
    }

    const pMemory = ops.callocFn(ops.ctx, nNumElements, nSize);
    if (pMemory == null) {
        setNullOut(?*anyopaque, ppMemory);
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    }

    ppMemory.?.* = pMemory;
    return 0;
}

fn reallocateMemoryWithOps(
    ops: AllocOps,
    nSize: usize,
    ppMemory: ?*?*anyopaque,
) u32 {
    if (ppMemory == null or nSize == 0) {
        if (ppMemory) |out| {
            freeWithOps(ops, out.*);
            out.* = null;
        }
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pMemory = ops.reallocFn(ops.ctx, ppMemory.?.*, nSize);
    if (pMemory == null) {
        freeWithOps(ops, ppMemory.?.*);
        ppMemory.?.* = null;
        freeWithOps(ops, pMemory);
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    }

    ppMemory.?.* = pMemory;
    return 0;
}

fn allocateStringWithOps(
    ops: AllocOps,
    pszSrcOpt: ?[*:0]const u8,
    ppszDst: ?*?[*:0]u8,
) u32 {
    if (pszSrcOpt == null or ppszDst == null) {
        setNullOut(?[*:0]u8, ppszDst);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszSrc = pszSrcOpt.?;
    const src = std.mem.span(pszSrc);
    if (src.len > @as(usize, c.TDNF_DEFAULT_MAX_STRING_LEN)) {
        setNullOut(?[*:0]u8, ppszDst);
        return c.ERROR_TDNF_STRING_TOO_LONG;
    }

    var raw: ?*anyopaque = null;
    const dwError = allocateMemoryWithOps(ops, src.len + 1, 1, &raw);
    if (dwError != 0) {
        setNullOut(?[*:0]u8, ppszDst);
        return dwError;
    }

    const bytes: [*]u8 = @ptrCast(raw.?);
    @memcpy(bytes[0..src.len], src);
    bytes[src.len] = 0;

    ppszDst.?.* = @ptrCast(bytes);
    return 0;
}

fn safeAllocateStringWithOps(
    ops: AllocOps,
    pszSrcOpt: ?[*:0]const u8,
    ppszDst: ?*?[*:0]u8,
) u32 {
    var pszDst: ?[*:0]u8 = null;

    if (ppszDst == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    if (pszSrcOpt != null) {
        const dwError = allocateStringWithOps(ops, pszSrcOpt, &pszDst);
        if (dwError != 0) {
            return dwError;
        }
    }

    ppszDst.?.* = pszDst;
    return 0;
}

fn allocateStringVPrintfWithOps(
    ops: AllocOps,
    ppszDst: ?*?[*:0]u8,
    pszFmtOpt: ?[*:0]const u8,
    argListSize: c.va_list,
    argListWrite: c.va_list,
) u32 {
    if (ppszDst == null or pszFmtOpt == null) {
        setNullOut(?[*:0]u8, ppszDst);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszFmt = pszFmtOpt.?;
    var chDstTest: u8 = 0;

    const nSizeProbe = c.vsnprintf(@ptrCast(&chDstTest), 1, pszFmt, argListSize);
    if (nSizeProbe <= 0) {
        setNullOut(?[*:0]u8, ppszDst);
        return systemErrorFromErrno();
    }

    const nSize = @as(usize, @intCast(nSizeProbe)) + 1;
    if (nSize > @as(usize, c.TDNF_DEFAULT_MAX_STRING_LEN)) {
        setNullOut(?[*:0]u8, ppszDst);
        return c.ERROR_TDNF_STRING_TOO_LONG;
    }

    var raw: ?*anyopaque = null;
    const allocError = allocateMemoryWithOps(ops, 1, nSize, &raw);
    if (allocError != 0) {
        setNullOut(?[*:0]u8, ppszDst);
        return allocError;
    }

    const bytes: [*]u8 = @ptrCast(raw.?);
    const pszDst: [*:0]u8 = @ptrCast(bytes);

    const nWritten = c.vsnprintf(@ptrCast(bytes), nSize, pszFmt, argListWrite);
    if (nWritten <= 0) {
        setNullOut(?[*:0]u8, ppszDst);
        freeCStringWithOps(ops, pszDst);
        return systemErrorFromErrno();
    }

    ppszDst.?.* = pszDst;
    return 0;
}

fn allocateStringArrayWithOps(
    ops: AllocOps,
    ppszSrc: [*c]?[*:0]u8,
    pppszDst: ?*[*c]?[*:0]u8,
) u32 {
    var ppszDst: [*c]?[*:0]u8 = null;

    if (ppszSrc == null or pppszDst == null) {
        setNullOut([*c]?[*:0]u8, pppszDst);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    var n: usize = 0;
    while (ppszSrc[n] != null) : (n += 1) {}

    var raw: ?*anyopaque = null;
    const allocError = allocateMemoryWithOps(ops, n + 1, @sizeOf(?[*:0]u8), &raw);
    if (allocError != 0) {
        setNullOut([*c]?[*:0]u8, pppszDst);
        return allocError;
    }

    ppszDst = @ptrCast(@alignCast(raw.?));

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const dwError = safeAllocateStringWithOps(ops, ppszSrc[i], &ppszDst[i]);
        if (dwError != 0) {
            freeStringArrayWithCArrayOps(ops, ppszDst);
            setNullOut([*c]?[*:0]u8, pppszDst);
            return dwError;
        }
    }

    pppszDst.?.* = ppszDst;
    return 0;
}

fn allocateStringNWithOps(
    ops: AllocOps,
    pszSrcOpt: ?[*:0]const u8,
    dwNumElements: u32,
    ppszDst: ?*?[*:0]u8,
) u32 {
    if (pszSrcOpt == null or ppszDst == null) {
        setNullOut(?[*:0]u8, ppszDst);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszSrc = pszSrcOpt.?;
    const src = std.mem.span(pszSrc);
    const dwSrcLength = src.len;
    const nNumElements: usize = @intCast(dwNumElements);

    if (nNumElements > dwSrcLength) {
        setNullOut(?[*:0]u8, ppszDst);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    var raw: ?*anyopaque = null;
    const allocError = allocateMemoryWithOps(ops, nNumElements + 1, 1, &raw);
    if (allocError != 0) {
        setNullOut(?[*:0]u8, ppszDst);
        return allocError;
    }

    const bytes: [*]u8 = @ptrCast(raw.?);
    @memcpy(bytes[0..nNumElements], src[0..nNumElements]);
    bytes[nNumElements] = 0;

    ppszDst.?.* = @ptrCast(bytes);
    return 0;
}

export fn TDNFAllocateMemory(
    nNumElements: usize,
    nSize: usize,
    ppMemory: ?*?*anyopaque,
) u32 {
    return allocateMemoryWithOps(libc_ops, nNumElements, nSize, ppMemory);
}

export fn TDNFReAllocateMemory(
    nSize: usize,
    ppMemory: ?*?*anyopaque,
) u32 {
    return reallocateMemoryWithOps(libc_ops, nSize, ppMemory);
}

export fn TDNFFreeMemory(pMemory: ?*anyopaque) void {
    freeWithOps(libc_ops, pMemory);
}

export fn TDNFAllocateString(
    pszSrc: ?[*:0]const u8,
    ppszDst: ?*?[*:0]u8,
) u32 {
    return allocateStringWithOps(libc_ops, pszSrc, ppszDst);
}

export fn TDNFSafeAllocateString(
    pszSrc: ?[*:0]const u8,
    ppszDst: ?*?[*:0]u8,
) u32 {
    return safeAllocateStringWithOps(libc_ops, pszSrc, ppszDst);
}

export fn TDNFAllocateStringVPrintf(
    ppszDst: ?*?[*:0]u8,
    pszFmt: ?[*:0]const u8,
    argListSize: c.va_list,
    argListWrite: c.va_list,
) u32 {
    return allocateStringVPrintfWithOps(libc_ops, ppszDst, pszFmt, argListSize, argListWrite);
}

export fn TDNFAllocateStringArray(
    ppszSrc: [*c]?[*:0]u8,
    pppszDst: ?*[*c]?[*:0]u8,
) u32 {
    return allocateStringArrayWithOps(libc_ops, ppszSrc, pppszDst);
}

export fn TDNFFreeStringArray(ppszArray: [*c]?[*:0]u8) void {
    freeStringArrayWithCArrayOps(libc_ops, ppszArray);
}

export fn TDNFFreeStringArrayWithCount(
    ppszArray: [*c]?[*:0]u8,
    nCount: c_int,
) void {
    freeStringArrayWithCountWithCArrayOps(libc_ops, ppszArray, nCount);
}

export fn TDNFAllocateStringN(
    pszSrc: ?[*:0]const u8,
    dwNumElements: u32,
    ppszDst: ?*?[*:0]u8,
) u32 {
    return allocateStringNWithOps(libc_ops, pszSrc, dwNumElements, ppszDst);
}

const TrackingFreeContext = struct {
    freed: bool = false,
};

fn trackingFree(ctx: ?*anyopaque, ptr: ?*anyopaque) void {
    const tracking: *TrackingFreeContext = @ptrCast(@alignCast(ctx.?));
    tracking.freed = true;
    libcFree(null, ptr);
}

fn alwaysFailCalloc(_: ?*anyopaque, _: usize, _: usize) ?*anyopaque {
    return null;
}

fn alwaysFailRealloc(_: ?*anyopaque, _: ?*anyopaque, _: usize) ?*anyopaque {
    return null;
}

extern fn TDNFTestAllocateStringPrintf(
    ppszDst: ?*?[*:0]u8,
    pszArg: ?[*:0]const u8,
    nValue: c_int,
) u32;

test "TDNFAllocateMemory zeroes allocations and clears stale output on zero-size rejection" {
    var raw: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFAllocateMemory(4, 2, &raw));
    defer TDNFFreeMemory(raw);

    const bytes: [*]u8 = @ptrCast(raw.?);
    for (bytes[0..8]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }

    const stale = c.malloc(1).?;
    var stale_out: ?*anyopaque = stale;
    try std.testing.expectEqual(@as(u32, c.ERROR_TDNF_INVALID_PARAMETER), TDNFAllocateMemory(0, 1, &stale_out));
    try std.testing.expect(stale_out == null);
    c.free(stale);
}

test "TDNFAllocateMemory rejects size overflow" {
    const stale = c.malloc(1).?;
    var out: ?*anyopaque = stale;
    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_ALLOCSIZE),
        TDNFAllocateMemory(std.math.maxInt(usize), 2, &out),
    );
    try std.testing.expect(out == null);
    c.free(stale);
}

test "TDNFReAllocateMemory grows and shrinks while preserving prefix bytes" {
    var raw: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFAllocateMemory(4, 1, &raw));
    defer TDNFFreeMemory(raw);

    var bytes: [*]u8 = @ptrCast(raw.?);
    bytes[0] = 1;
    bytes[1] = 2;
    bytes[2] = 3;
    bytes[3] = 4;

    try std.testing.expectEqual(@as(u32, 0), TDNFReAllocateMemory(16, &raw));
    bytes = @ptrCast(raw.?);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, bytes[0..4]);

    try std.testing.expectEqual(@as(u32, 0), TDNFReAllocateMemory(2, &raw));
    bytes = @ptrCast(raw.?);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, bytes[0..2]);
}

test "TDNFReAllocateMemory frees the old buffer on failure" {
    var tracking = TrackingFreeContext{};
    const ops = AllocOps{
        .ctx = &tracking,
        .callocFn = libcCalloc,
        .reallocFn = alwaysFailRealloc,
        .freeFn = trackingFree,
    };

    var raw: ?*anyopaque = c.calloc(1, 4);
    try std.testing.expect(raw != null);

    try std.testing.expectEqual(@as(u32, c.ERROR_TDNF_OUT_OF_MEMORY), reallocateMemoryWithOps(ops, 8, &raw));
    try std.testing.expect(tracking.freed);
    try std.testing.expect(raw == null);
}

test "TDNFReAllocateMemory frees the old buffer on invalid parameter" {
    var tracking = TrackingFreeContext{};
    const ops = AllocOps{
        .ctx = &tracking,
        .callocFn = libcCalloc,
        .reallocFn = libcRealloc,
        .freeFn = trackingFree,
    };

    var raw: ?*anyopaque = c.calloc(1, 4);
    try std.testing.expect(raw != null);

    try std.testing.expectEqual(@as(u32, c.ERROR_TDNF_INVALID_PARAMETER), reallocateMemoryWithOps(ops, 0, &raw));
    try std.testing.expect(tracking.freed);
    try std.testing.expect(raw == null);
}

test "TDNFAllocateString and TDNFSafeAllocateString preserve output semantics" {
    var allocated: ?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFAllocateString("hello", &allocated));
    defer TDNFFreeMemory(@ptrCast(allocated.?));
    try std.testing.expectEqualStrings("hello", std.mem.span(allocated.?));

    const stale = c.malloc(1).?;
    var safe_out: ?[*:0]u8 = @ptrCast(stale);
    try std.testing.expectEqual(@as(u32, 0), TDNFSafeAllocateString(null, &safe_out));
    try std.testing.expect(safe_out == null);
    c.free(stale);

    var preserved = [_:0]u8{ 'k', 'e', 'e', 'p', 0 };
    var preserved_out: ?[*:0]u8 = &preserved;
    const fail_ops = AllocOps{
        .callocFn = alwaysFailCalloc,
        .reallocFn = libcRealloc,
        .freeFn = libcFree,
    };
    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_OUT_OF_MEMORY),
        safeAllocateStringWithOps(fail_ops, "copy me", &preserved_out),
    );
    try std.testing.expect(preserved_out == &preserved);
}

test "TDNFAllocateStringPrintf formats through the C shim" {
    var formatted: ?[*:0]u8 = null;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFTestAllocateStringPrintf(&formatted, "value", 7),
    );
    defer TDNFFreeMemory(@ptrCast(formatted.?));
    try std.testing.expectEqualStrings("value 7", std.mem.span(formatted.?));
}

test "TDNFAllocateStringArray duplicates each entry and TDNFFreeStringArrayWithCount frees counted arrays" {
    var one = [_:0]u8{ 'o', 'n', 'e', 0 };
    var two = [_:0]u8{ 't', 'w', 'o', 0 };
    var src = [_]?[*:0]u8{ &one, &two, null };
    var duplicated: [*c]?[*:0]u8 = null;

    try std.testing.expectEqual(@as(u32, 0), TDNFAllocateStringArray(@ptrCast(&src), &duplicated));
    defer TDNFFreeStringArray(duplicated);

    try std.testing.expect(duplicated != null);
    try std.testing.expectEqualStrings("one", std.mem.span(duplicated[0].?));
    try std.testing.expectEqualStrings("two", std.mem.span(duplicated[1].?));
    try std.testing.expect(duplicated[2] == null);

    var counted_raw: ?*anyopaque = null;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFAllocateMemory(2, @sizeOf(?[*:0]u8), &counted_raw),
    );
    const counted: [*c]?[*:0]u8 = @ptrCast(@alignCast(counted_raw.?));
    try std.testing.expectEqual(@as(u32, 0), TDNFAllocateString("alpha", &counted[0]));
    try std.testing.expectEqual(@as(u32, 0), TDNFAllocateString("beta", &counted[1]));
    TDNFFreeStringArrayWithCount(counted, 2);
}

test "TDNFAllocateStringN returns prefixes including the empty string" {
    var prefix: ?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFAllocateStringN("hello", 2, &prefix));
    defer TDNFFreeMemory(@ptrCast(prefix.?));
    try std.testing.expectEqualStrings("he", std.mem.span(prefix.?));

    var empty: ?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFAllocateStringN("hello", 0, &empty));
    defer TDNFFreeMemory(@ptrCast(empty.?));
    try std.testing.expectEqualStrings("", std.mem.span(empty.?));
}
