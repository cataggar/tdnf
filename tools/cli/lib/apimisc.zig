// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const builtin = @import("builtin");
const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("jsondump.h");
    @cInclude("stdio.h");
    @cInclude("string.h");
    @cInclude("strings.h");
    @cInclude("time.h");
    @cInclude("unistd.h");
    @cInclude("tdnf.h");
    @cInclude("tdnfcli.h");
    @cInclude("tdnferror.h");
});
const output = @import("output.zig");

extern fn log_console(loglevel: i32, format: [*:0]const u8, ...) void;
extern fn TDNFAllocateMemory(nNumElements: usize, nSize: usize, ppMemory: ?*?*anyopaque) u32;
extern fn TDNFAllocateString(pszSrc: ?[*:0]const u8, ppszDst: ?*?[*:0]u8) u32;
extern fn TDNFFreeMemory(pMemory: ?*anyopaque) void;
extern fn TDNFCliAskForAction(
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO,
) u32;
extern fn TDNFCliPrintActionComplete(pCmdArgs: ?*c.TDNF_CMD_ARGS) u32;
extern fn TDNFJoinArrayToStringSorted(
    ppszDependencies: [*c]?[*:0]u8,
    pszSep: ?[*:0]const u8,
    ppszResult: ?*?[*:0]u8,
) u32;
extern fn TDNFStringArraySort(ppszArray: [*c]?[*:0]u8) u32;

const allocator = std.heap.c_allocator;
const LOG_INFO: c_int = 0;
const LOG_ERR: c_int = 1;
const LOG_CRIT: c_int = 2;

const CliErrorDesc = struct {
    code: u32,
    desc: [*:0]const u8,
};

const cli_error_descs = [_]CliErrorDesc{
    .{ .code = c.ERROR_TDNF_CLI_BASE, .desc = "Generic base error." },
    .{ .code = c.ERROR_TDNF_CLI_NO_MATCH, .desc = "There was no match for the search." },
    .{ .code = c.ERROR_TDNF_CLI_INVALID_ARGUMENT, .desc = "Invalid argument." },
    .{ .code = c.ERROR_TDNF_CLI_CLEAN_REQUIRES_OPTION, .desc = "Clean requires an option: packages, metadata, dbcache, plugins, expire-cache, all" },
    .{ .code = c.ERROR_TDNF_CLI_NOT_ENOUGH_ARGS, .desc = "The command line parser could not continue. Expected at least one argument." },
    .{ .code = c.ERROR_TDNF_CLI_NOTHING_TO_DO, .desc = "Nothing to do." },
    .{ .code = c.ERROR_TDNF_CLI_OPTION_NAME_INVALID, .desc = "Command line error: option is invalid." },
    .{ .code = c.ERROR_TDNF_CLI_OPTION_ARG_REQUIRED, .desc = "Command line error: expected one argument." },
    .{ .code = c.ERROR_TDNF_CLI_OPTION_ARG_UNEXPECTED, .desc = "Command line error: argument was unexpected." },
    .{ .code = c.ERROR_TDNF_CLI_CHECKLOCAL_EXPECT_DIR, .desc = "check-local requires path to rpm directory as a parameter" },
    .{ .code = c.ERROR_TDNF_CLI_PROVIDES_EXPECT_ARG, .desc = "Need an item to match." },
    .{ .code = c.ERROR_TDNF_CLI_SETOPT_NO_EQUALS, .desc = "Missing equal sign in setopt argument. setopt requires an argument of the form key=value." },
    .{ .code = c.ERROR_TDNF_CLI_NO_SUCH_CMD, .desc = "Please check your command" },
    .{ .code = c.ERROR_TDNF_CLI_DOWNLOADDIR_REQUIRES_DOWNLOADONLY, .desc = "--downloaddir requires --downloadonly" },
    .{ .code = c.ERROR_TDNF_CLI_ONE_DEP_ONLY, .desc = "only one dependency allowed" },
    .{ .code = c.ERROR_TDNF_CLI_ALLDEPS_REQUIRES_DOWNLOADONLY, .desc = "--alldeps requires --downloadonly" },
    .{ .code = c.ERROR_TDNF_CLI_NODEPS_REQUIRES_DOWNLOADONLY, .desc = "--nodeps requires --downloadonly" },
    .{ .code = c.ERROR_TDNF_CLI_INVALID_MIXED_QUERY_QUERYFORMAT, .desc = "--qf requires only querytags. Invalid Mixed Query" },
};

const dep_keys = [_][*:0]const u8{
    "provides",
    "obsoletes",
    "conflicts",
    "requires",
    "recommends",
    "suggests",
    "supplements",
    "enhances",
    "depends",
    "requires-pre",
};

const dep_json_keys = [_][*:0]const u8{
    "Provides",
    "Obsoletes",
    "Conflicts",
    "Requires",
    "Recommends",
    "Suggests",
    "Supplements",
    "Enhances",
    "Depends",
    "RequiresPre",
};

comptime {
    if (dep_keys.len != c.REPOQUERY_DEP_KEY_COUNT) {
        @compileError("dep_keys table out of sync with REPOQUERY_DEP_KEY_COUNT");
    }
    if (dep_json_keys.len != c.REPOQUERY_DEP_KEY_COUNT) {
        @compileError("dep_json_keys table out of sync with REPOQUERY_DEP_KEY_COUNT");
    }
}

fn checkJsonResult(nResult: c_int) u32 {
    if (nResult != 0) {
        return c.ERROR_TDNF_JSONDUMP;
    }
    return 0;
}

fn destroyJsonDump(ppDump: *?*c.struct_json_dump) void {
    if (ppDump.*) |pDump| {
        c.jd_destroy(pDump);
        ppDump.* = null;
    }
}

fn freeOwnedString(ppValue: *?[*:0]u8) void {
    if (ppValue.*) |value| {
        TDNFFreeMemory(@ptrCast(value));
        ppValue.* = null;
    }
}

fn cString(ptr: anytype) ?[*:0]const u8 {
    return switch (@typeInfo(@TypeOf(ptr))) {
        .optional => if (ptr) |p| @ptrCast(p) else null,
        else => if (ptr != null) @ptrCast(ptr) else null,
    };
}

fn cStringSlice(ptr: anytype) []const u8 {
    return if (cString(ptr)) |psz| std.mem.span(psz) else "";
}

fn appendByte(builder: *std.ArrayList(u8), value: u8) u32 {
    builder.append(allocator, value) catch return c.ERROR_TDNF_OUT_OF_MEMORY;
    return 0;
}

fn appendSlice(builder: *std.ArrayList(u8), bytes: []const u8) u32 {
    builder.appendSlice(allocator, bytes) catch return c.ERROR_TDNF_OUT_OF_MEMORY;
    return 0;
}

fn appendCString(builder: *std.ArrayList(u8), value: anytype) u32 {
    return appendSlice(builder, cStringSlice(value));
}

fn allocateCString(bytes: []const u8, ppszOut: *?[*:0]u8) u32 {
    var raw: ?*anyopaque = null;
    const dwError = TDNFAllocateMemory(bytes.len + 1, 1, &raw);
    if (dwError != 0) {
        ppszOut.* = null;
        return dwError;
    }

    const pszOut: [*:0]u8 = @ptrCast(@alignCast(raw.?));
    const out_bytes: [*]u8 = @ptrCast(pszOut);
    @memcpy(out_bytes[0..bytes.len], bytes);
    out_bytes[bytes.len] = 0;
    ppszOut.* = pszOut;
    return 0;
}

fn tdnfRefreshHandle(hTdnf: ?*anyopaque) u32 {
    if (builtin.is_test) {
        return 0;
    }
    return c.TDNFRefresh(@ptrCast(hTdnf));
}

fn freeHistoryInfo(pHistoryInfo: ?*c.TDNF_HISTORY_INFO) void {
    if (builtin.is_test) {
        return;
    }
    c.TDNFFreeHistoryInfo(pHistoryInfo);
}

fn depBit(index: usize) u32 {
    return @as(u32, 1) << @intCast(index);
}

fn firstDepKeyIndex(depKeySet: u32) ?usize {
    var index: usize = 0;
    while (index < dep_keys.len) : (index += 1) {
        if ((depKeySet & depBit(index)) != 0) {
            return index;
        }
    }
    return null;
}

fn countCStringArray(ppszArray: anytype) usize {
    if (ppszArray == null) {
        return 0;
    }

    var count: usize = 0;
    while (ppszArray[count] != null) : (count += 1) {}
    return count;
}

fn setRepoQueryDepKeysFromFormat(pRepoqueryArgs: *c.TDNF_REPOQUERY_ARGS) u32 {
    const pszQueryFormat = cString(pRepoqueryArgs.pszQueryFormat) orelse return 0;
    const format = std.mem.span(pszQueryFormat);

    var i: usize = 0;
    while (i < format.len) {
        if (format[i] == '%' and i + 1 < format.len and format[i + 1] == '{') {
            const tag_start = i + 2;
            var tag_end = tag_start;
            while (tag_end < format.len and format[tag_end] != '}') : (tag_end += 1) {}
            if (tag_end >= format.len) {
                return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
            }

            const tag = format[tag_start..tag_end];
            for (dep_keys, 0..) |dep_key, index| {
                if (std.ascii.eqlIgnoreCase(tag, std.mem.span(dep_key))) {
                    pRepoqueryArgs.depKeySet |= depBit(index);
                    break;
                }
            }

            i = tag_end + 1;
        } else {
            i += 1;
        }
    }

    return 0;
}

fn appendRepoQueryTagValue(
    builder: *std.ArrayList(u8),
    tag: []const u8,
    pPkgInfo: [*c]c.TDNF_PKG_INFO,
) u32 {
    const pkg = &pPkgInfo[0];

    if (std.mem.eql(u8, tag, "name")) return appendCString(builder, pkg.pszName);
    if (std.mem.eql(u8, tag, "arch")) return appendCString(builder, pkg.pszArch);
    if (std.mem.eql(u8, tag, "version")) return appendCString(builder, pkg.pszVersion);
    if (std.mem.eql(u8, tag, "reponame")) return appendCString(builder, pkg.pszRepoName);
    if (std.mem.eql(u8, tag, "release")) return appendCString(builder, pkg.pszRelease);
    if (std.mem.eql(u8, tag, "evr")) return appendCString(builder, pkg.pszEVR);
    if (std.mem.eql(u8, tag, "location")) return appendCString(builder, pkg.pszLocation);
    if (std.mem.eql(u8, tag, "sourcename")) return appendCString(builder, pkg.pszSourcePkg);
    if (std.mem.eql(u8, tag, "size")) return appendCString(builder, pkg.pszFormattedDownloadSize);
    if (std.mem.eql(u8, tag, "downloadsize")) return appendCString(builder, pkg.pszFormattedDownloadSize);
    if (std.mem.eql(u8, tag, "installsize")) return appendCString(builder, pkg.pszFormattedSize);
    if (std.mem.eql(u8, tag, "sourcerpm")) return appendCString(builder, pkg.pszSourcePkg);
    if (std.mem.eql(u8, tag, "description")) return appendCString(builder, pkg.pszDescription);
    if (std.mem.eql(u8, tag, "summary")) return appendCString(builder, pkg.pszSummary);
    if (std.mem.eql(u8, tag, "license")) return appendCString(builder, pkg.pszLicense);
    if (std.mem.eql(u8, tag, "url")) return appendCString(builder, pkg.pszURL);

    for (dep_keys, 0..) |dep_key, index| {
        if (std.mem.eql(u8, tag, std.mem.span(dep_key))) {
            var pszJoined: ?[*:0]u8 = null;
            defer freeOwnedString(&pszJoined);

            const dwError = TDNFJoinArrayToStringSorted(pkg.pppszDependencies[index], "\n", &pszJoined);
            if (dwError != 0) {
                return dwError;
            }
            return appendCString(builder, pszJoined);
        }
    }

    return c.ERROR_TDNF_INVALID_PARAMETER;
}

fn formatRepoQueryString(
    pszFormat: [*:0]const u8,
    pPkgInfo: [*c]c.TDNF_PKG_INFO,
    ppszResult: *?[*:0]u8,
) u32 {
    var builder: std.ArrayList(u8) = .empty;
    defer builder.deinit(allocator);

    const format = std.mem.span(pszFormat);
    var i: usize = 0;
    while (i < format.len) {
        if (format[i] == '%' and i + 1 < format.len and format[i + 1] == '{') {
            const tag_start = i + 2;
            var tag_end = tag_start;
            while (tag_end < format.len and format[tag_end] != '}') : (tag_end += 1) {}
            if (tag_end >= format.len) {
                return 1;
            }

            const tag = format[tag_start..tag_end];
            const dwError = appendRepoQueryTagValue(&builder, tag, pPkgInfo);
            if (dwError != 0) {
                if (dwError == c.ERROR_TDNF_INVALID_PARAMETER) {
                    log_console(
                        LOG_ERR,
                        "Unknown tag: %.*s\n",
                        @as(c_int, @intCast(tag.len)),
                        tag.ptr,
                    );
                }
                return dwError;
            }

            i = tag_end + 1;
        } else if (format[i] == '\\') {
            var esc: u8 = 0;
            if (i + 1 < format.len) {
                esc = format[i + 1];
                i += 2;
            } else {
                i += 1;
            }

            const replacement: u8 = switch (esc) {
                '"' => '"',
                '\\' => '\\',
                'b' => '\x08',
                'f' => '\x0c',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                else => esc,
            };
            const dwError = appendByte(&builder, replacement);
            if (dwError != 0) {
                return dwError;
            }
        } else {
            const dwError = appendByte(&builder, format[i]);
            if (dwError != 0) {
                return dwError;
            }
            i += 1;
        }
    }

    return allocateCString(builder.items, ppszResult);
}

pub export fn TDNFCliFreeSolvedPackageInfo(pSolvedPkgInfo: c.PTDNF_SOLVED_PKG_INFO) void {
    c.TDNFFreeSolvedPackageInfo(pSolvedPkgInfo);
}

pub export fn TDNFCliGetErrorString(
    dwErrorCode: u32,
    ppszError: ?*?[*:0]u8,
) u32 {
    var pszError: ?[*:0]u8 = null;

    for (cli_error_descs) |desc| {
        if (dwErrorCode == desc.code) {
            const dwError = TDNFAllocateString(desc.desc, &pszError);
            if (dwError != 0) {
                freeOwnedString(&pszError);
                return dwError;
            }
            break;
        }
    }

    if (ppszError) |out| {
        out.* = pszError;
    }

    return 0;
}

pub export fn TDNFCliRepoSyncCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnRepoSync == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var pReposyncArgs: ?*c.TDNF_REPOSYNC_ARGS = null;
    defer if (pReposyncArgs != null) c.TDNFCliFreeRepoSyncArgs(pReposyncArgs);

    var dwError = c.TDNFCliParseRepoSyncArgs(cmd_args, &pReposyncArgs);
    if (dwError != 0) {
        return dwError;
    }

    dwError = context.pFnRepoSync.?(context, pReposyncArgs);
    if (dwError != 0) {
        return dwError;
    }

    return 0;
}

pub export fn TDNFCliRepoQueryCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnRepoQuery == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var pRepoqueryArgs: ?*c.TDNF_REPOQUERY_ARGS = null;
    defer if (pRepoqueryArgs != null) c.TDNFCliFreeRepoQueryArgs(pRepoqueryArgs);

    var pPkgInfos: [*c]c.TDNF_PKG_INFO = null;
    var dwCount: u32 = 0;
    defer if (pPkgInfos != null) c.TDNFFreePackageInfoArray(pPkgInfos, dwCount);

    var pszResult: ?[*:0]u8 = null;
    defer freeOwnedString(&pszResult);

    var ppszLinesRaw: ?*anyopaque = null;
    defer if (ppszLinesRaw != null) TDNFFreeMemory(ppszLinesRaw);

    var dwError = c.TDNFCliParseRepoQueryArgs(cmd_args, &pRepoqueryArgs);
    if (dwError != 0) {
        return dwError;
    }

    if (pRepoqueryArgs.?.pszQueryFormat != null) {
        dwError = setRepoQueryDepKeysFromFormat(pRepoqueryArgs.?);
        if (dwError != 0) {
            return dwError;
        }
    }

    dwError = context.pFnRepoQuery.?(context, pRepoqueryArgs, &pPkgInfos, &dwCount);
    if (dwError != 0) {
        return dwError;
    }

    const depkey_opt = firstDepKeyIndex(pRepoqueryArgs.?.depKeySet);

    if (cmd_args.nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(0);
        if (jd == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd);

        _ = c.jd_list_start(jd);

        var i: usize = 0;
        while (i < dwCount) : (i += 1) {
            var jd_pkg: ?*c.struct_json_dump = c.jd_create(0);
            if (jd_pkg == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd_pkg);

            dwError = checkJsonResult(c.jd_map_start(jd_pkg));
            if (dwError != 0) {
                return dwError;
            }

            const pPkgInfo = &pPkgInfos[@intCast(i)];

            dwError = checkJsonResult(c.jd_map_add_fmt(
                jd_pkg,
                "Nevra",
                "%s-%s-%s.%s",
                pPkgInfo.pszName,
                pPkgInfo.pszVersion,
                pPkgInfo.pszRelease,
                pPkgInfo.pszArch,
            ));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Name", pPkgInfo.pszName));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Arch", pPkgInfo.pszArch));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Evr", pPkgInfo.pszEVR));
            if (dwError != 0) return dwError;
            dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Repo", pPkgInfo.pszRepoName));
            if (dwError != 0) return dwError;

            if (pPkgInfo.ppszFileList != null) {
                var jd_list: ?*c.struct_json_dump = c.jd_create(0);
                if (jd_list == null) {
                    return c.ERROR_TDNF_JSONDUMP;
                }
                defer destroyJsonDump(&jd_list);

                _ = c.jd_list_start(jd_list);
                var j: usize = 0;
                while (pPkgInfo.ppszFileList[j] != null) : (j += 1) {
                    dwError = checkJsonResult(c.jd_list_add_string(jd_list, pPkgInfo.ppszFileList[j]));
                    if (dwError != 0) return dwError;
                }
                dwError = checkJsonResult(c.jd_map_add_child(jd_pkg, "Files", jd_list));
                if (dwError != 0) return dwError;
                destroyJsonDump(&jd_list);
            }

            if (depkey_opt) |depkey| {
                if ((pRepoqueryArgs.?.depKeySet & depBit(depkey)) != 0 and pPkgInfo.pppszDependencies[depkey] != null) {
                    var jd_list: ?*c.struct_json_dump = c.jd_create(0);
                    if (jd_list == null) {
                        return c.ERROR_TDNF_JSONDUMP;
                    }
                    defer destroyJsonDump(&jd_list);

                    _ = c.jd_list_start(jd_list);
                    var j: usize = 0;
                    while (pPkgInfo.pppszDependencies[depkey][j] != null) : (j += 1) {
                        dwError = checkJsonResult(c.jd_list_add_string(jd_list, pPkgInfo.pppszDependencies[depkey][j]));
                        if (dwError != 0) return dwError;
                    }
                    dwError = checkJsonResult(c.jd_map_add_child(jd_pkg, dep_json_keys[depkey], jd_list));
                    if (dwError != 0) return dwError;
                    destroyJsonDump(&jd_list);
                }
            }

            if (pPkgInfo.pChangeLogEntries != null) {
                var jd_list: ?*c.struct_json_dump = c.jd_create(0);
                if (jd_list == null) {
                    return c.ERROR_TDNF_JSONDUMP;
                }
                defer destroyJsonDump(&jd_list);

                _ = c.jd_list_start(jd_list);
                var pEntry = pPkgInfo.pChangeLogEntries;
                while (pEntry != null) : (pEntry = pEntry[0].pNext) {
                    const entry = pEntry.?;
                    var jd_entry: ?*c.struct_json_dump = c.jd_create(0);
                    if (jd_entry == null) {
                        return c.ERROR_TDNF_JSONDUMP;
                    }
                    defer destroyJsonDump(&jd_entry);

                    dwError = checkJsonResult(c.jd_map_start(jd_entry));
                    if (dwError != 0) return dwError;

                    var szTime = [_]u8{0} ** 20;
                    if (c.strftime(&szTime, szTime.len, "%a %b %d %Y", c.localtime(&entry[0].timeTime)) != 0) {
                        dwError = checkJsonResult(c.jd_map_add_string(
                            jd_entry,
                            "Time",
                            @as([*:0]const u8, @ptrCast(&szTime)),
                        ));
                        if (dwError != 0) return dwError;
                    }
                    dwError = checkJsonResult(c.jd_map_add_string(jd_entry, "Author", entry[0].pszAuthor));
                    if (dwError != 0) return dwError;
                    dwError = checkJsonResult(c.jd_map_add_string(jd_entry, "Text", entry[0].pszText));
                    if (dwError != 0) return dwError;
                    dwError = checkJsonResult(c.jd_list_add_child(jd_list, jd_entry));
                    if (dwError != 0) return dwError;
                    destroyJsonDump(&jd_entry);
                }
                dwError = checkJsonResult(c.jd_map_add_child(jd_pkg, "ChangeLogs", jd_list));
                if (dwError != 0) return dwError;
                destroyJsonDump(&jd_list);
            }

            if (pPkgInfo.pszSourcePkg != null) {
                dwError = checkJsonResult(c.jd_map_add_string(jd_pkg, "Source", pPkgInfo.pszSourcePkg));
                if (dwError != 0) return dwError;
            }

            dwError = checkJsonResult(c.jd_list_add_child(jd, jd_pkg));
            if (dwError != 0) return dwError;
            destroyJsonDump(&jd_pkg);
        }

        _ = c.fputs(jd.?.buf, c.stdout);
        return 0;
    }

    if (pRepoqueryArgs.?.pszQueryFormat != null) {
        var i: usize = 0;
        while (i < dwCount) : (i += 1) {
            dwError = formatRepoQueryString(
                cString(pRepoqueryArgs.?.pszQueryFormat).?,
                &pPkgInfos[@intCast(i)],
                &pszResult,
            );
            if (dwError != 0) {
                return dwError;
            }
            log_console(LOG_CRIT, "%s\n", pszResult.?);
            freeOwnedString(&pszResult);
        }
        return 0;
    }

    var nCount: usize = 0;
    var i: usize = 0;
    while (i < dwCount) : (i += 1) {
        const pPkgInfo = &pPkgInfos[@intCast(i)];

        if (depkey_opt) |depkey| {
            if ((pRepoqueryArgs.?.depKeySet & depBit(depkey)) != 0 and pPkgInfo.pppszDependencies[depkey] != null) {
                nCount += countCStringArray(pPkgInfo.pppszDependencies[depkey]);
            } else if (pPkgInfo.ppszFileList != null) {
                nCount += countCStringArray(pPkgInfo.ppszFileList);
            } else if (pPkgInfo.pChangeLogEntries != null) {
                var pEntry = pPkgInfo.pChangeLogEntries;
                while (pEntry != null) : (pEntry = pEntry[0].pNext) {
                    const entry = pEntry.?;
                    var szTime = [_]u8{0} ** 20;
                    if (c.strftime(&szTime, szTime.len, "%a %b %d %Y", c.localtime(&entry[0].timeTime)) != 0) {
                        log_console(
                            LOG_CRIT,
                            "%s %s\n%s\n",
                            @as([*:0]const u8, @ptrCast(&szTime)),
                            entry[0].pszAuthor,
                            entry[0].pszText,
                        );
                    } else {
                        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
                    }
                }
            } else if (pPkgInfo.pszSourcePkg != null) {
                log_console(LOG_CRIT, "%s\n", pPkgInfo.pszSourcePkg);
            } else if (pPkgInfo.pszLocation != null) {
                log_console(LOG_CRIT, "%s\n", pPkgInfo.pszLocation);
            } else {
                log_console(
                    LOG_CRIT,
                    "%s-%s-%s.%s\n",
                    pPkgInfo.pszName,
                    pPkgInfo.pszVersion,
                    pPkgInfo.pszRelease,
                    pPkgInfo.pszArch,
                );
            }
        } else if (pPkgInfo.ppszFileList != null) {
            nCount += countCStringArray(pPkgInfo.ppszFileList);
        } else if (pPkgInfo.pChangeLogEntries != null) {
            var pEntry = pPkgInfo.pChangeLogEntries;
            while (pEntry != null) : (pEntry = pEntry[0].pNext) {
                const entry = pEntry.?;
                var szTime = [_]u8{0} ** 20;
                if (c.strftime(&szTime, szTime.len, "%a %b %d %Y", c.localtime(&entry[0].timeTime)) != 0) {
                    log_console(
                        LOG_CRIT,
                        "%s %s\n%s\n",
                        @as([*:0]const u8, @ptrCast(&szTime)),
                        entry[0].pszAuthor,
                        entry[0].pszText,
                    );
                } else {
                    return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
                }
            }
        } else if (pPkgInfo.pszSourcePkg != null) {
            log_console(LOG_CRIT, "%s\n", pPkgInfo.pszSourcePkg);
        } else if (pPkgInfo.pszLocation != null) {
            log_console(LOG_CRIT, "%s\n", pPkgInfo.pszLocation);
        } else {
            log_console(
                LOG_CRIT,
                "%s-%s-%s.%s\n",
                pPkgInfo.pszName,
                pPkgInfo.pszVersion,
                pPkgInfo.pszRelease,
                pPkgInfo.pszArch,
            );
        }
    }

    if (nCount > 0) {
        dwError = TDNFAllocateMemory(nCount + 1, @sizeOf(?[*:0]u8), &ppszLinesRaw);
        if (dwError != 0) {
            return dwError;
        }
        const ppszLines: [*c]?[*:0]u8 = @ptrCast(@alignCast(ppszLinesRaw.?));

        var k: usize = 0;
        i = 0;
        while (i < dwCount) : (i += 1) {
            const pPkgInfo = &pPkgInfos[@intCast(i)];

            if (depkey_opt) |depkey| {
                if ((pRepoqueryArgs.?.depKeySet & depBit(depkey)) != 0 and pPkgInfo.pppszDependencies[depkey] != null) {
                    var j: usize = 0;
                    while (pPkgInfo.pppszDependencies[depkey][j] != null) : (j += 1) {
                        ppszLines[k] = @ptrCast(pPkgInfo.pppszDependencies[depkey][j]);
                        k += 1;
                    }
                } else if (pPkgInfo.ppszFileList != null) {
                    var j: usize = 0;
                    while (pPkgInfo.ppszFileList[j] != null) : (j += 1) {
                        ppszLines[k] = @ptrCast(pPkgInfo.ppszFileList[j]);
                        k += 1;
                    }
                }
            } else if (pPkgInfo.ppszFileList != null) {
                var j: usize = 0;
                while (pPkgInfo.ppszFileList[j] != null) : (j += 1) {
                    ppszLines[k] = @ptrCast(pPkgInfo.ppszFileList[j]);
                    k += 1;
                }
            }
        }

        dwError = TDNFStringArraySort(ppszLines);
        if (dwError != 0) {
            return dwError;
        }

        var j: usize = 0;
        while (ppszLines[j] != null) : (j += 1) {
            if (j == 0 or c.strcmp(@ptrCast(ppszLines[j].?), @ptrCast(ppszLines[j - 1].?)) != 0) {
                log_console(LOG_CRIT, "%s\n", ppszLines[j].?);
            }
        }
    }

    return 0;
}

pub export fn TDNFCliMakeCacheCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    _ = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    const dwError = TDNFCliRefresh(context);
    if (dwError != 0) {
        return dwError;
    }

    log_console(LOG_CRIT, "Metadata cache created.\n");
    return 0;
}

pub export fn TDNFCliRefresh(pContext: ?*c.TDNF_CLI_CONTEXT) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    const dwError = tdnfRefreshHandle(context.hTdnf);
    if (dwError == c.ERROR_TDNF_SYSTEM_BASE + c.EACCES and c.geteuid() != 0) {
        log_console(
            LOG_ERR,
            "\ntdnf repo cache needs to be refreshed but you have insufficient permissions\n" ++
                "You can use one of the below methods to workaround this\n" ++
                "1. Login as root and refresh cache\n" ++
                "2. Use -c (--config) with a configuration file that has 'cachedir' set to a directory where you have access\n" ++
                "3. Use -C (--cacheonly) and use the existing cache in the system\n\n",
        );
    }
    return dwError;
}

fn TDNFCliHistoryId(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    var nId: c_int = 0;
    const dwError = context.pFnHistoryGetId.?(context, &nId);
    if (dwError != 0) {
        return dwError;
    }

    if (cmd_args.nJsonOutput != 0) {
        var jd: ?*c.struct_json_dump = c.jd_create(0);
        if (jd == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd);

        var json_error = checkJsonResult(c.jd_map_start(jd));
        if (json_error != 0) {
            return json_error;
        }
        json_error = checkJsonResult(c.jd_map_add_int(jd, "Id", nId));
        if (json_error != 0) {
            return json_error;
        }
        _ = c.fputs(jd.?.buf, c.stdout);
    } else {
        log_console(LOG_CRIT, "%d\n", nId);
    }

    return 0;
}

fn TDNFCliHistoryAlter(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    pHistoryArgs: ?*c.TDNF_HISTORY_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const history_args = pHistoryArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    var pSolvedPkgInfo: ?*c.TDNF_SOLVED_PKG_INFO = null;
    defer c.TDNFFreeSolvedPackageInfo(pSolvedPkgInfo);

    var dwError = context.pFnHistoryResolve.?(context, history_args, &pSolvedPkgInfo);
    if (dwError != 0) {
        return dwError;
    }

    if (history_args.nCommand == c.HISTORY_CMD_INIT) {
        return 0;
    }

    if (pSolvedPkgInfo.?.ppszPkgsNotResolved == null or pSolvedPkgInfo.?.ppszPkgsNotResolved[0] == null) {
        dwError = TDNFCliAskForAction(cmd_args, pSolvedPkgInfo);
        if (cmd_args.nJsonOutput != 0 and dwError == c.ERROR_TDNF_OPERATION_ABORTED) {
            dwError = 0;
        }
        if (dwError != 0) {
            return dwError;
        }

        dwError = context.pFnAlterHistory.?(context, pSolvedPkgInfo, history_args);
        if (dwError != 0) {
            return dwError;
        }

        if (cmd_args.nJsonOutput != 0) {
            dwError = TDNFCliPrintActionComplete(cmd_args);
            if (dwError != 0) {
                return dwError;
            }
        }

        return 0;
    }

    log_console(LOG_CRIT, "The following packages could not be resolved:\n\n");
    var i: usize = 0;
    while (pSolvedPkgInfo.?.ppszPkgsNotResolved[i] != null) : (i += 1) {
        log_console(LOG_CRIT, "%s\n", pSolvedPkgInfo.?.ppszPkgsNotResolved[i]);
    }
    log_console(
        LOG_CRIT,
        "\n" ++
            "The package(s) may have been moved out of the enabled repositories since the\n" ++
            "last time they were installed. You may be able to resolve this by enabling\n" ++
            "additional repositories.\n",
    );
    return c.ERROR_TDNF_NO_MATCH;
}

fn TDNFCliHistoryList(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
    pHistoryArgs: ?*c.TDNF_HISTORY_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const history_args = pHistoryArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    var pHistoryInfo: ?*c.TDNF_HISTORY_INFO = null;
    defer freeHistoryInfo(pHistoryInfo);

    var dwError = context.pFnHistoryList.?(context, history_args, &pHistoryInfo);
    if (dwError != 0) {
        return dwError;
    }

    const history_info = pHistoryInfo.?;
    const pItems = history_info.pItems;

    if (cmd_args.nJsonOutput == 0) {
        var nConsoleWidth: c_int = 0;
        dwError = output.GetConsoleWidth(&nConsoleWidth);
        if (dwError != 0) {
            return dwError;
        }

        const nCmdWidth: c_int = nConsoleWidth - 4 - 21 - 9 - 7;
        log_console(LOG_CRIT, "ID   %-*s date/time             +add  / -rem\n", nCmdWidth, "cmd line");

        var i: usize = 0;
        const item_count: usize = @intCast(history_info.nItemCount);
        while (i < item_count) : (i += 1) {
            const item = &pItems[@intCast(i)];
            var szTime = [_]u8{0} ** 22;
            _ = c.strftime(&szTime, szTime.len, "%a %b %d %Y %H:%M", c.localtime(&item.timeStamp));
            log_console(
                LOG_CRIT,
                "%4d %-*s %-21s +%-4d / -%-4d\n",
                item.nId,
                nCmdWidth,
                item.pszCmdLine,
                @as([*:0]const u8, @ptrCast(&szTime)),
                item.nAddedCount,
                item.nRemovedCount,
            );

            if (history_args.nInfo != 0) {
                if (item.ppszAddedPkgs != null and item.ppszAddedPkgs[0] != null) {
                    const added_count: usize = @intCast(item.nAddedCount);
                    log_console(LOG_CRIT, "added: ");
                    var j: usize = 0;
                    while (j + 1 < added_count) : (j += 1) {
                        log_console(LOG_CRIT, "%s, ", item.ppszAddedPkgs[j]);
                    }
                    log_console(LOG_CRIT, "%s", item.ppszAddedPkgs[added_count - 1]);
                    log_console(LOG_CRIT, "\n");
                }
                if (item.ppszRemovedPkgs != null and item.ppszRemovedPkgs[0] != null) {
                    const removed_count: usize = @intCast(item.nRemovedCount);
                    log_console(LOG_CRIT, "removed: ");
                    var j: usize = 0;
                    while (j + 1 < removed_count) : (j += 1) {
                        log_console(LOG_CRIT, "%s, ", item.ppszRemovedPkgs[j]);
                    }
                    log_console(LOG_CRIT, "%s", item.ppszRemovedPkgs[removed_count - 1]);
                    log_console(LOG_CRIT, "\n");
                }
                log_console(LOG_CRIT, "\n");
            }
        }

        return 0;
    }

    var jd: ?*c.struct_json_dump = c.jd_create(0);
    if (jd == null) {
        return c.ERROR_TDNF_JSONDUMP;
    }
    defer destroyJsonDump(&jd);

    dwError = checkJsonResult(c.jd_list_start(jd));
    if (dwError != 0) {
        return dwError;
    }

    var i: usize = 0;
    const item_count: usize = @intCast(history_info.nItemCount);
    while (i < item_count) : (i += 1) {
        const item = &pItems[@intCast(i)];

        var jd_item: ?*c.struct_json_dump = c.jd_create(0);
        if (jd_item == null) {
            return c.ERROR_TDNF_JSONDUMP;
        }
        defer destroyJsonDump(&jd_item);

        dwError = checkJsonResult(c.jd_map_start(jd_item));
        if (dwError != 0) return dwError;
        dwError = checkJsonResult(c.jd_map_add_int(jd_item, "Id", item.nId));
        if (dwError != 0) return dwError;
        dwError = checkJsonResult(c.jd_map_add_string(jd_item, "CmdLine", item.pszCmdLine));
        if (dwError != 0) return dwError;
        dwError = checkJsonResult(c.jd_map_add_int64(jd_item, "TimeStamp", item.timeStamp));
        if (dwError != 0) return dwError;
        dwError = checkJsonResult(c.jd_map_add_int(jd_item, "AddedCount", item.nAddedCount));
        if (dwError != 0) return dwError;
        dwError = checkJsonResult(c.jd_map_add_int(jd_item, "RemovedCount", item.nRemovedCount));
        if (dwError != 0) return dwError;

        if (history_args.nInfo != 0) {
            var jd_list_added: ?*c.struct_json_dump = c.jd_create(0);
            if (jd_list_added == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd_list_added);
            _ = c.jd_list_start(jd_list_added);

            var jd_list_removed: ?*c.struct_json_dump = c.jd_create(0);
            if (jd_list_removed == null) {
                return c.ERROR_TDNF_JSONDUMP;
            }
            defer destroyJsonDump(&jd_list_removed);
            _ = c.jd_list_start(jd_list_removed);

            if (item.ppszAddedPkgs != null and item.ppszAddedPkgs[0] != null) {
                var j: usize = 0;
                const added_count: usize = @intCast(item.nAddedCount);
                while (j < added_count) : (j += 1) {
                    dwError = checkJsonResult(c.jd_list_add_string(jd_list_added, item.ppszAddedPkgs[j]));
                    if (dwError != 0) return dwError;
                }
            }
            if (item.ppszRemovedPkgs != null and item.ppszRemovedPkgs[0] != null) {
                var j: usize = 0;
                const removed_count: usize = @intCast(item.nRemovedCount);
                while (j < removed_count) : (j += 1) {
                    dwError = checkJsonResult(c.jd_list_add_string(jd_list_removed, item.ppszRemovedPkgs[j]));
                    if (dwError != 0) return dwError;
                }
            }

            dwError = checkJsonResult(c.jd_map_add_child(jd_item, "Added", jd_list_added));
            if (dwError != 0) return dwError;
            destroyJsonDump(&jd_list_added);

            dwError = checkJsonResult(c.jd_map_add_child(jd_item, "Removed", jd_list_removed));
            if (dwError != 0) return dwError;
            destroyJsonDump(&jd_list_removed);
        }

        dwError = checkJsonResult(c.jd_list_add_child(jd, jd_item));
        if (dwError != 0) return dwError;
        destroyJsonDump(&jd_item);
    }

    _ = c.fputs(jd.?.buf, c.stdout);
    return 0;
}

pub export fn TDNFCliHistoryCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var pHistoryArgs: ?*c.TDNF_HISTORY_ARGS = null;
    defer if (pHistoryArgs != null) c.TDNFCliFreeHistoryArgs(pHistoryArgs);

    var dwError = c.TDNFCliParseHistoryArgs(cmd_args, &pHistoryArgs);
    if (dwError != 0) {
        return dwError;
    }

    if (pHistoryArgs.?.nCommand == c.HISTORY_CMD_LIST) {
        dwError = TDNFCliHistoryList(context, cmd_args, pHistoryArgs);
    } else if (pHistoryArgs.?.nCommand == c.HISTORY_CMD_ID) {
        dwError = TDNFCliHistoryId(context, cmd_args);
    } else {
        dwError = TDNFCliHistoryAlter(context, cmd_args, pHistoryArgs);
    }
    if (dwError != 0) {
        return dwError;
    }

    return 0;
}

pub export fn TDNFCliMarkCommand(
    pContext: ?*c.TDNF_CLI_CONTEXT,
    pCmdArgs: ?*c.TDNF_CMD_ARGS,
) u32 {
    const context = pContext orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    const cmd_args = pCmdArgs orelse return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;

    if (context.hTdnf == null or context.pFnCount == null) {
        return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
    }

    var nValue: u32 = 0;
    if (cmd_args.nCmdCount > 1) {
        if (c.strcmp(cmd_args.ppszCmds[1], "install") == 0) {
            nValue = 0;
        } else if (c.strcmp(cmd_args.ppszCmds[1], "remove") == 0) {
            nValue = 1;
        } else {
            log_console(LOG_CRIT, "unknown action '%s'\n", cmd_args.ppszCmds[1]);
            return c.ERROR_TDNF_CLI_INVALID_ARGUMENT;
        }
    } else {
        log_console(LOG_CRIT, "need action ('install' or 'remove') as argument\n");
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    if (cmd_args.nCmdCount > 2) {
        return context.pFnMark.?(context, &cmd_args.ppszCmds[2], nValue);
    }

    log_console(LOG_CRIT, "need package spec(s) as argument\n");
    return c.ERROR_TDNF_INVALID_PARAMETER;
}
