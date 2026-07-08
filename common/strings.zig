// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("string.h");
    @cInclude("stdlib.h");
    @cInclude("tdnferror.h");
});

extern fn TDNFAllocateMemory(nNumElements: usize, nSize: usize, ppMemory: ?*?*anyopaque) u32;
extern fn TDNFReAllocateMemory(nSize: usize, ppMemory: ?*?*anyopaque) u32;
extern fn TDNFFreeMemory(pMemory: ?*anyopaque) void;
extern fn TDNFFreeStringArray(ppszArray: [*c]?[*:0]u8) void;
extern fn TDNFFreeStringArrayWithCount(ppszArray: [*c]?[*:0]u8, nCount: c_int) void;

fn isNullOrEmptyString(pszValueOpt: ?[*:0]const u8) bool {
    return pszValueOpt == null or pszValueOpt.?[0] == 0;
}

fn setNullOut(comptime T: type, out: ?*T) void {
    if (out) |p| {
        p.* = null;
    }
}

fn freeCString(pszValueOpt: ?[*:0]u8) void {
    if (pszValueOpt) |pszValue| {
        TDNFFreeMemory(@ptrCast(pszValue));
    }
}

fn allocateCStringCapacity(nCapacity: usize, ppszDst: ?*?[*:0]u8) u32 {
    var raw: ?*anyopaque = null;

    if (ppszDst == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const dwError = TDNFAllocateMemory(nCapacity, 1, &raw);
    if (dwError != 0) {
        ppszDst.?.* = null;
        return dwError;
    }

    ppszDst.?.* = @ptrCast(raw.?);
    return 0;
}

fn allocateOwnedString(pszValue: []const u8, ppszDst: ?*?[*:0]u8) u32 {
    var pszDst: ?[*:0]u8 = null;

    if (ppszDst == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const dwError = allocateCStringCapacity(pszValue.len + 1, &pszDst);
    if (dwError != 0) {
        ppszDst.?.* = null;
        return dwError;
    }

    const pBytes: [*]u8 = @ptrCast(pszDst.?);
    @memcpy(pBytes[0..pszValue.len], pszValue);
    pBytes[pszValue.len] = 0;

    ppszDst.?.* = pszDst;
    return 0;
}

fn isSeparator(pszSep: [*:0]const u8, ch: u8) bool {
    return std.mem.indexOfScalar(u8, std.mem.span(pszSep), ch) != null;
}

fn sortCStringPointers(ppszArray: [*c]?[*:0]u8, nCount: usize) void {
    var i: usize = 1;
    while (i < nCount) : (i += 1) {
        var j = i;
        while (j > 0) : (j -= 1) {
            if (c.strcmp(@ptrCast(ppszArray[j - 1].?), @ptrCast(ppszArray[j].?)) <= 0) {
                break;
            }
            const pszTmp = ppszArray[j - 1];
            ppszArray[j - 1] = ppszArray[j];
            ppszArray[j] = pszTmp;
        }
    }
}

export fn TDNFStringSepCount(
    pszBufOpt: ?[*:0]const u8,
    pszSepOpt: ?[*:0]const u8,
    nSepCount: ?*usize,
) u32 {
    var nCount: usize = 0;
    var i: usize = 0;

    if (pszBufOpt == null or isNullOrEmptyString(pszSepOpt) or nSepCount == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszBuf = pszBufOpt.?;
    const pszSep = pszSepOpt.?;

    while (pszBuf[i] != 0) {
        while (pszBuf[i] != 0 and isSeparator(pszSep, pszBuf[i])) : (i += 1) {}
        if (pszBuf[i] == 0) {
            break;
        }

        nCount += 1;
        while (pszBuf[i] != 0 and !isSeparator(pszSep, pszBuf[i])) : (i += 1) {}
    }

    nSepCount.?.* = nCount;
    return 0;
}

export fn TDNFSplitStringToArray(
    pszBufOpt: ?[*:0]const u8,
    pszSepOpt: ?[*:0]const u8,
    pppszTokens: ?*[*c]?[*:0]u8,
) u32 {
    var dwError: u32 = 0;
    var ppszToks: [*c]?[*:0]u8 = null;
    var nCount: usize = 0;
    var i: usize = 0;
    var p: usize = 0;

    if (pszBufOpt == null or isNullOrEmptyString(pszSepOpt) or pppszTokens == null) {
        setNullOut([*c]?[*:0]u8, pppszTokens);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszBuf = pszBufOpt.?;
    const pszSep = pszSepOpt.?;
    const buf = std.mem.span(pszBuf);

    dwError = TDNFStringSepCount(pszBuf, pszSep, &nCount);
    if (dwError != 0) {
        setNullOut([*c]?[*:0]u8, pppszTokens);
        return dwError;
    }

    {
        var raw: ?*anyopaque = null;
        dwError = TDNFAllocateMemory(nCount + 1, @sizeOf(?[*:0]u8), &raw);
        if (dwError != 0) {
            setNullOut([*c]?[*:0]u8, pppszTokens);
            return dwError;
        }
        ppszToks = @ptrCast(@alignCast(raw.?));
    }

    while (p < buf.len) {
        while (p < buf.len and isSeparator(pszSep, buf[p])) : (p += 1) {}
        if (p >= buf.len) {
            break;
        }

        const p0 = p;
        while (p < buf.len and !isSeparator(pszSep, buf[p])) : (p += 1) {}

        dwError = allocateOwnedString(buf[p0..p], &ppszToks[i]);
        if (dwError != 0) {
            TDNFFreeStringArrayWithCount(ppszToks, @intCast(nCount));
            pppszTokens.?.* = null;
            return dwError;
        }
        i += 1;
    }

    pppszTokens.?.* = ppszToks;
    return 0;
}

export fn TDNFMergeStringArrays(
    pppszArray0: ?*[*c]?[*:0]u8,
    ppszArray1: [*c]?[*:0]u8,
) u32 {
    var dwError: u32 = 0;
    var n0: c_int = 0;
    var n1: c_int = 0;
    var raw: ?*anyopaque = null;

    if (pppszArray0 == null or ppszArray1 == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    dwError = TDNFStringArrayCount(pppszArray0.?.*, &n0);
    if (dwError != 0) {
        return dwError;
    }

    dwError = TDNFStringArrayCount(ppszArray1, &n1);
    if (dwError != 0) {
        return dwError;
    }

    raw = if (pppszArray0.?.* == null) null else @ptrCast(pppszArray0.?.*);
    dwError = TDNFReAllocateMemory(@as(usize, @intCast(n0 + n1 + 1)) * @sizeOf(?[*:0]u8), &raw);
    pppszArray0.?.* = if (raw) |pRaw| @ptrCast(@alignCast(pRaw)) else null;
    if (dwError != 0) {
        return dwError;
    }

    var i: usize = 0;
    while (i < @as(usize, @intCast(n1))) : (i += 1) {
        pppszArray0.?.*[@as(usize, @intCast(n0)) + i] = ppszArray1[i];
    }
    pppszArray0.?.*[@as(usize, @intCast(n0 + n1))] = null;

    TDNFFreeMemory(@ptrCast(ppszArray1));
    return 0;
}

export fn TDNFAddStringArray(
    pppszArray: ?*[*c]?[*:0]u8,
    pszValueOpt: ?[*:0]const u8,
) u32 {
    var dwError: u32 = 0;
    var ppszArrayToAdd: [*c]?[*:0]u8 = null;

    if (pppszArray == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    if (isNullOrEmptyString(pszValueOpt)) {
        if (pppszArray.?.* != null) {
            TDNFFreeStringArray(pppszArray.?.*);
            pppszArray.?.* = null;
        }
        return 0;
    }

    dwError = TDNFSplitStringToArray(pszValueOpt, " ", &ppszArrayToAdd);
    if (dwError != 0) {
        return dwError;
    }

    if (pppszArray.?.* != null) {
        dwError = TDNFMergeStringArrays(pppszArray, ppszArrayToAdd);
        if (dwError != 0) {
            TDNFFreeStringArray(ppszArrayToAdd);
            return dwError;
        }
    } else {
        pppszArray.?.* = ppszArrayToAdd;
    }

    return 0;
}

export fn TDNFJoinArrayToString(
    ppszArray: [*c]?[*:0]u8,
    pszSepOpt: ?[*:0]const u8,
    count: c_int,
    ppszResult: ?*?[*:0]u8,
) u32 {
    var dwError: u32 = 0;
    var pszResult: ?[*:0]u8 = null;
    var p: usize = 0;
    var i: usize = 0;

    if (ppszArray == null or pszSepOpt == null or ppszResult == null or count < 0) {
        setNullOut(?[*:0]u8, ppszResult);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszSep = pszSepOpt.?;
    const sep = std.mem.span(pszSep);
    const nCount: usize = @intCast(count);
    var nSize: usize = sep.len * nCount + 1;

    while (i < nCount and ppszArray[i] != null) : (i += 1) {
        nSize += std.mem.span(ppszArray[i].?).len;
    }

    dwError = allocateCStringCapacity(nSize, &pszResult);
    if (dwError != 0) {
        setNullOut(?[*:0]u8, ppszResult);
        return dwError;
    }

    i = 0;
    while (i < nCount and ppszArray[i] != null) : (i += 1) {
        const token = std.mem.span(ppszArray[i].?);
        const bytes: [*]u8 = @ptrCast(pszResult.?);
        @memcpy(bytes[p .. p + token.len], token);
        p += token.len;

        if (i < nCount - 1 and ppszArray[i + 1] != null) {
            @memcpy(bytes[p .. p + sep.len], sep);
            p += sep.len;
        }
    }
    (@as([*]u8, @ptrCast(pszResult.?)))[p] = 0;

    ppszResult.?.* = pszResult;
    return 0;
}

export fn TDNFJoinArrayToStringSorted(
    ppszDependencies: [*c]?[*:0]u8,
    pszSepOpt: ?[*:0]const u8,
    ppszResult: ?*?[*:0]u8,
) u32 {
    var dwError: u32 = 0;
    var nCount: usize = 0;
    var ppszLines: [*c]?[*:0]u8 = null;
    var pszTmpResult: ?[*:0]u8 = null;
    var p: usize = 0;

    if (pszSepOpt == null or ppszResult == null) {
        setNullOut(?[*:0]u8, ppszResult);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    if (ppszDependencies != null) {
        while (ppszDependencies[nCount] != null) : (nCount += 1) {}
    }

    if (nCount > 0) {
        var raw: ?*anyopaque = null;
        dwError = TDNFAllocateMemory(nCount + 1, @sizeOf(?[*:0]u8), &raw);
        if (dwError != 0) {
            setNullOut(?[*:0]u8, ppszResult);
            return dwError;
        }
        ppszLines = @ptrCast(@alignCast(raw.?));

        var i: usize = 0;
        while (i < nCount) : (i += 1) {
            ppszLines[i] = ppszDependencies[i];
        }

        dwError = TDNFStringArraySort(ppszLines);
        if (dwError != 0) {
            TDNFFreeMemory(@ptrCast(ppszLines));
            setNullOut(?[*:0]u8, ppszResult);
            return dwError;
        }

        const sep = std.mem.span(pszSepOpt.?);
        var nSize: usize = sep.len * (nCount + 1) + 1;
        i = 0;
        while (i < nCount) : (i += 1) {
            if (i == 0 or c.strcmp(@ptrCast(ppszLines[i].?), @ptrCast(ppszLines[i - 1].?)) != 0) {
                nSize += std.mem.span(ppszLines[i].?).len;
            }
        }

        dwError = allocateCStringCapacity(nSize, &pszTmpResult);
        if (dwError != 0) {
            TDNFFreeMemory(@ptrCast(ppszLines));
            setNullOut(?[*:0]u8, ppszResult);
            return dwError;
        }

        i = 0;
        while (i < nCount) : (i += 1) {
            const bytes: [*]u8 = @ptrCast(pszTmpResult.?);
            const token = std.mem.span(ppszLines[i].?);
            if (i == 0) {
                @memcpy(bytes[p .. p + token.len], token);
                p += token.len;
            } else if (c.strcmp(@ptrCast(ppszLines[i].?), @ptrCast(ppszLines[i - 1].?)) != 0) {
                @memcpy(bytes[p .. p + sep.len], sep);
                p += sep.len;
                @memcpy(bytes[p .. p + token.len], token);
                p += token.len;
            }
        }
        (@as([*]u8, @ptrCast(pszTmpResult.?)))[p] = 0;
    }

    if (pszTmpResult) |pszFilled| {
        ppszResult.?.* = if (c.strdup(@ptrCast(pszFilled))) |pszDup| @ptrCast(pszDup) else null;
    } else {
        ppszResult.?.* = if (c.strdup("")) |pszDup| @ptrCast(pszDup) else null;
    }

    if (ppszLines != null) {
        TDNFFreeMemory(@ptrCast(ppszLines));
    }
    freeCString(pszTmpResult);
    return dwError;
}

export fn TDNFReplaceString(
    pszSourceOpt: ?[*:0]const u8,
    pszSearchOpt: ?[*:0]const u8,
    pszReplaceOpt: ?[*:0]const u8,
    ppszDst: ?*?[*:0]u8,
) u32 {
    var pszDst: ?[*:0]u8 = null;

    if (isNullOrEmptyString(pszSourceOpt) or isNullOrEmptyString(pszSearchOpt) or pszReplaceOpt == null or ppszDst == null) {
        setNullOut(?[*:0]u8, ppszDst);
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const source = std.mem.span(pszSourceOpt.?);
    const search = std.mem.span(pszSearchOpt.?);
    const replace = std.mem.span(pszReplaceOpt.?);

    var nOccurrences: usize = 0;
    var nSourceIndex: usize = 0;
    while (std.mem.indexOfPos(u8, source, nSourceIndex, search)) |nFound| {
        nOccurrences += 1;
        nSourceIndex = nFound + search.len;
    }

    var nLength = source.len;
    if (replace.len >= search.len) {
        const nExtra = std.math.mul(usize, nOccurrences, replace.len - search.len) catch return c.ERROR_TDNF_INVALID_ALLOCSIZE;
        nLength = std.math.add(usize, nLength, nExtra) catch return c.ERROR_TDNF_INVALID_ALLOCSIZE;
    } else {
        nLength -= nOccurrences * (search.len - replace.len);
    }

    const dwError = allocateCStringCapacity(nLength + 1, &pszDst);
    if (dwError != 0) {
        setNullOut(?[*:0]u8, ppszDst);
        return dwError;
    }

    const bytes: [*]u8 = @ptrCast(pszDst.?);
    var nDestIndex: usize = 0;
    nSourceIndex = 0;
    while (std.mem.indexOfPos(u8, source, nSourceIndex, search)) |nFound| {
        const prefix = source[nSourceIndex..nFound];
        @memcpy(bytes[nDestIndex .. nDestIndex + prefix.len], prefix);
        nDestIndex += prefix.len;

        @memcpy(bytes[nDestIndex .. nDestIndex + replace.len], replace);
        nDestIndex += replace.len;
        nSourceIndex = nFound + search.len;
    }

    const suffix = source[nSourceIndex..];
    @memcpy(bytes[nDestIndex .. nDestIndex + suffix.len], suffix);
    nDestIndex += suffix.len;
    bytes[nDestIndex] = 0;

    ppszDst.?.* = pszDst;
    return 0;
}

export fn TDNFTrimSuffix(pszSourceOpt: ?[*:0]u8, pszSuffixOpt: ?[*:0]const u8) u32 {
    if (isNullOrEmptyString(pszSourceOpt) or isNullOrEmptyString(pszSuffixOpt)) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const pszSuffix = pszSuffixOpt.?;
    const pszIndex = c.strstr(@ptrCast(pszSourceOpt.?), @ptrCast(pszSuffix));
    if (pszIndex == null or c.strcmp(pszIndex, @ptrCast(pszSuffix)) != 0) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    pszIndex[0] = 0;
    return 0;
}

export fn TDNFStringEndsWith(pszSourceOpt: ?[*:0]const u8, pszSuffixOpt: ?[*:0]const u8) u32 {
    if (isNullOrEmptyString(pszSourceOpt) or isNullOrEmptyString(pszSuffixOpt)) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const source = std.mem.span(pszSourceOpt.?);
    const suffix = std.mem.span(pszSuffixOpt.?);
    if (suffix.len > source.len) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    if (!std.mem.eql(u8, source[source.len - suffix.len ..], suffix)) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    return 0;
}

export fn TDNFStringArrayCount(ppszStringArray: [*c]?[*:0]u8, pnCount: ?*c_int) u32 {
    var nCount: c_int = 0;

    if (ppszStringArray == null or pnCount == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    while (ppszStringArray[@intCast(nCount)] != null) : (nCount += 1) {}
    pnCount.?.* = nCount;
    return 0;
}

export fn TDNFStringArraySort(ppszArray: [*c]?[*:0]u8) u32 {
    var nCount: c_int = 0;

    if (ppszArray == null) {
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    while (ppszArray[@intCast(nCount)] != null) : (nCount += 1) {}
    sortCStringPointers(ppszArray, @intCast(nCount));
    return 0;
}

test "TDNFStringSepCount and TDNFSplitStringToArray skip repeated separators" {
    var nSepCount: usize = 0;
    try std.testing.expectEqual(@as(u32, 0), TDNFStringSepCount(" alpha, beta,,gamma ", " ,", &nSepCount));
    try std.testing.expectEqual(@as(usize, 3), nSepCount);

    var ppszTokens: [*c]?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFSplitStringToArray(" alpha, beta,,gamma ", " ,", &ppszTokens));
    defer TDNFFreeStringArray(ppszTokens);

    try std.testing.expectEqualStrings("alpha", std.mem.span(ppszTokens[0].?));
    try std.testing.expectEqualStrings("beta", std.mem.span(ppszTokens[1].?));
    try std.testing.expectEqualStrings("gamma", std.mem.span(ppszTokens[2].?));
    try std.testing.expect(ppszTokens[3] == null);
}

test "TDNFMergeStringArrays and TDNFAddStringArray preserve ownership semantics" {
    var ppszFirst: [*c]?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFSplitStringToArray("one two", " ", &ppszFirst));
    defer if (ppszFirst != null) TDNFFreeStringArray(ppszFirst);

    var ppszSecond: [*c]?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFSplitStringToArray("three four", " ", &ppszSecond));

    try std.testing.expectEqual(@as(u32, 0), TDNFMergeStringArrays(&ppszFirst, ppszSecond));
    try std.testing.expectEqualStrings("one", std.mem.span(ppszFirst[0].?));
    try std.testing.expectEqualStrings("two", std.mem.span(ppszFirst[1].?));
    try std.testing.expectEqualStrings("three", std.mem.span(ppszFirst[2].?));
    try std.testing.expectEqualStrings("four", std.mem.span(ppszFirst[3].?));
    try std.testing.expect(ppszFirst[4] == null);

    var ppszValues: [*c]?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFAddStringArray(&ppszValues, "alpha beta"));
    defer if (ppszValues != null) TDNFFreeStringArray(ppszValues);

    try std.testing.expectEqual(@as(u32, 0), TDNFAddStringArray(&ppszValues, "gamma"));
    try std.testing.expectEqualStrings("alpha", std.mem.span(ppszValues[0].?));
    try std.testing.expectEqualStrings("beta", std.mem.span(ppszValues[1].?));
    try std.testing.expectEqualStrings("gamma", std.mem.span(ppszValues[2].?));

    try std.testing.expectEqual(@as(u32, 0), TDNFAddStringArray(&ppszValues, ""));
    try std.testing.expect(ppszValues == null);
}

test "TDNFJoinArrayToString and TDNFJoinArrayToStringSorted join expected output" {
    var alpha = [_:0]u8{ 'a', 'l', 'p', 'h', 'a', 0 };
    var beta = [_:0]u8{ 'b', 'e', 't', 'a', 0 };
    var gamma = [_:0]u8{ 'g', 'a', 'm', 'm', 'a', 0 };
    var values = [_]?[*:0]u8{ &alpha, &beta, &gamma, null };

    var pszJoined: ?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFJoinArrayToString(@ptrCast(&values), ",", 3, &pszJoined));
    defer freeCString(pszJoined);
    try std.testing.expectEqualStrings("alpha,beta,gamma", std.mem.span(pszJoined.?));

    var bravo = [_:0]u8{ 'b', 'r', 'a', 'v', 'o', 0 };
    var alpha2 = [_:0]u8{ 'a', 'l', 'p', 'h', 'a', 0 };
    var delta = [_:0]u8{ 'd', 'e', 'l', 't', 'a', 0 };
    var sorted_values = [_]?[*:0]u8{ &bravo, &alpha2, &delta, &alpha, null };

    var pszSorted: ?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFJoinArrayToStringSorted(@ptrCast(&sorted_values), "|", &pszSorted));
    defer freeCString(pszSorted);
    try std.testing.expectEqualStrings("alpha|bravo|delta", std.mem.span(pszSorted.?));

    var pszEmpty: ?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFJoinArrayToStringSorted(null, ",", &pszEmpty));
    defer freeCString(pszEmpty);
    try std.testing.expectEqualStrings("", std.mem.span(pszEmpty.?));
}

test "TDNFReplaceString, TDNFTrimSuffix, and TDNFStringEndsWith preserve string behavior" {
    var pszReplaced: ?[*:0]u8 = null;
    try std.testing.expectEqual(@as(u32, 0), TDNFReplaceString("foo-bar-foo", "foo", "baz", &pszReplaced));
    defer freeCString(pszReplaced);
    try std.testing.expectEqualStrings("baz-bar-baz", std.mem.span(pszReplaced.?));

    var szFile = [_:0]u8{ 'n', 'a', 'm', 'e', '.', 'r', 'p', 'm', 0 };
    try std.testing.expectEqual(@as(u32, 0), TDNFTrimSuffix(&szFile, ".rpm"));
    try std.testing.expectEqualStrings("name", std.mem.span(@as([*:0]u8, @ptrCast(&szFile))));

    var szTricky = [_:0]u8{ 'a', 'b', 'c', 'a', 'b', 'c', 0 };
    try std.testing.expectEqual(@as(u32, c.ERROR_TDNF_INVALID_PARAMETER), TDNFTrimSuffix(&szTricky, "abc"));

    try std.testing.expectEqual(@as(u32, 0), TDNFStringEndsWith("package.rpm", ".rpm"));
    try std.testing.expectEqual(@as(u32, c.ERROR_TDNF_INVALID_PARAMETER), TDNFStringEndsWith("package.rpm", ".deb"));
}

test "TDNFStringArrayCount and TDNFStringArraySort order arrays lexicographically" {
    var zulu = [_:0]u8{ 'z', 'u', 'l', 'u', 0 };
    var bravo = [_:0]u8{ 'b', 'r', 'a', 'v', 'o', 0 };
    var alpha = [_:0]u8{ 'a', 'l', 'p', 'h', 'a', 0 };
    var values = [_]?[*:0]u8{ &zulu, &bravo, &alpha, null };
    var nCount: c_int = 0;

    try std.testing.expectEqual(@as(u32, 0), TDNFStringArrayCount(@ptrCast(&values), &nCount));
    try std.testing.expectEqual(@as(c_int, 3), nCount);

    try std.testing.expectEqual(@as(u32, 0), TDNFStringArraySort(@ptrCast(&values)));
    try std.testing.expectEqualStrings("alpha", std.mem.span(values[0].?));
    try std.testing.expectEqualStrings("bravo", std.mem.span(values[1].?));
    try std.testing.expectEqualStrings("zulu", std.mem.span(values[2].?));
}
