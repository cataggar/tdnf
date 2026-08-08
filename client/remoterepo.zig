// Copyright (C) 2015-2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// are located in the COPYING file of this distribution.

const std = @import("std");
const builtin = @import("builtin");
const abi = @import("client_abi");
const download = @import("client_download");
const errors = @import("tdnf_error");
const repoutils = @import("repoutils.zig");

const CmdArgs = abi.CmdArgs;
const Conf = abi.Conf;
const RepoData = abi.RepoData;
const Tdnf = abi.Tdnf;
const Allocator = std.mem.Allocator;
const Stat = std.os.linux.Statx;

const c = std.c;
const LOG_INFO: c_int = 0;
const LOG_ERR: c_int = 1;
const LOG_NOTICE: c_int = 3;
const STDERR_FILENO: c_int = 2;
const at_symlink_nofollow: c_int = 0x100;
const mode_regular: u16 = 0o100000;
const mode_type_mask: u16 = 0o170000;

extern fn TDNFAllocateString(
    source: ?[*:0]const u8,
    output: ?*?[*:0]u8,
) callconv(.c) u32;
extern fn TDNFFreeMemory(memory: ?*anyopaque) callconv(.c) void;
extern fn log_console(level: c_int, format: [*:0]const u8, ...) callconv(.c) void;

const libc = struct {
    extern fn fchmod(c_int, c_uint) c_int;
    extern fn fsync(c_int) c_int;
    extern fn isatty(c_int) c_int;
    extern fn renameat(c_int, [*:0]const u8, c_int, [*:0]const u8) c_int;
    extern fn realpath([*:0]const u8, [*c]u8) [*c]u8;
    extern fn time(?*std.c.time_t) std.c.time_t;
};

const ProgressData = struct {
    current_time: std.c.time_t = 0,
    previous_time: std.c.time_t = 0,
    text: [64]u8 = [_]u8{0} ** 64,
};

const PinnedParent = struct {
    fd: c_int,
    name: [std.fs.max_name_bytes + 1]u8,

    fn deinit(self: *PinnedParent) void {
        _ = c.close(self.fd);
    }

    fn nameZ(self: *const PinnedParent) [*:0]const u8 {
        return @ptrCast(&self.name);
    }
};

var progress_data: ProgressData = .{};
var temp_counter = std.atomic.Value(u64).init(0);

fn errnoValue() c_int {
    return std.c._errno().*;
}

fn systemError(value: c_int) u32 {
    return errors.ERROR_TDNF_SYSTEM_BASE + @as(u32, @intCast(value));
}

fn isNullOrEmpty(value: ?[*:0]const u8) bool {
    return value == null or value.?[0] == 0;
}

fn cString(value: [*c]u8) ?[*:0]const u8 {
    if (value == null) return null;
    return @ptrCast(value);
}

fn freeCString(value: ?[*:0]u8) void {
    if (value) |pointer| TDNFFreeMemory(@ptrCast(pointer));
}

fn allocateCString(value: []const u8, output: *?[*:0]u8) u32 {
    const temporary = std.heap.c_allocator.dupeZ(u8, value) catch
        return errors.ERROR_TDNF_OUT_OF_MEMORY;
    defer std.heap.c_allocator.free(temporary);
    return TDNFAllocateString(temporary.ptr, output);
}

fn isSafeComponent(value: []const u8) bool {
    return value.len != 0 and
        !std.mem.eql(u8, value, ".") and
        !std.mem.eql(u8, value, "..") and
        std.mem.indexOfScalar(u8, value, '/') == null and
        std.mem.indexOfScalar(u8, value, 0) == null;
}

fn statAt(parent_fd: c_int, name: [*:0]const u8, output: *Stat) c_int {
    return std.c.statx(
        parent_fd,
        name,
        @intCast(at_symlink_nofollow),
        .{ .TYPE = true, .SIZE = true },
        output,
    );
}

fn isRegular(stat: Stat) bool {
    return stat.mode & mode_type_mask == mode_regular;
}

fn openDirectoryPathNoFollow(
    path: []const u8,
    create: bool,
    output: *c_int,
) u32 {
    if (path.len == 0) return errors.ERROR_TDNF_INVALID_PARAMETER;

    var current_fd = std.c.open(
        if (std.fs.path.isAbsolute(path)) "/" else ".",
        .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        },
    );
    if (current_fd < 0) return systemError(errnoValue());
    defer {
        if (current_fd >= 0) _ = c.close(current_fd);
    }

    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (!isSafeComponent(component)) {
            return errors.ERROR_TDNF_INVALID_PARAMETER;
        }
        if (component.len > std.fs.max_name_bytes) {
            return systemError(@intFromEnum(std.posix.E.NAMETOOLONG));
        }

        var component_buffer: [std.fs.max_name_bytes + 1]u8 = undefined;
        @memcpy(component_buffer[0..component.len], component);
        component_buffer[component.len] = 0;
        const component_z: [*:0]const u8 = @ptrCast(&component_buffer);

        var next_fd = std.c.openat(current_fd, component_z, .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        });
        if (next_fd < 0 and create and
            errnoValue() == @intFromEnum(std.posix.E.NOENT))
        {
            if (std.c.mkdirat(current_fd, component_z, 0o755) != 0 and
                errnoValue() != @intFromEnum(std.posix.E.EXIST))
            {
                return systemError(errnoValue());
            }
            next_fd = std.c.openat(current_fd, component_z, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            });
        }
        if (next_fd < 0) return systemError(errnoValue());
        _ = c.close(current_fd);
        current_fd = next_fd;
    }

    output.* = current_fd;
    current_fd = -1;
    return 0;
}

fn openDirectoryComponents(
    root_fd: c_int,
    relative_path: []const u8,
    output: *c_int,
) u32 {
    var current_fd = std.c.dup(root_fd);
    if (current_fd < 0) return systemError(errnoValue());
    defer {
        if (current_fd >= 0) _ = c.close(current_fd);
    }

    var components = std.mem.splitScalar(u8, relative_path, '/');
    while (components.next()) |component| {
        if (component.len == 0) continue;
        if (!isSafeComponent(component)) {
            return errors.ERROR_TDNF_URL_INVALID;
        }
        if (component.len > std.fs.max_name_bytes) {
            return systemError(@intFromEnum(std.posix.E.NAMETOOLONG));
        }
        var component_buffer: [std.fs.max_name_bytes + 1]u8 = undefined;
        @memcpy(component_buffer[0..component.len], component);
        component_buffer[component.len] = 0;
        const component_z: [*:0]const u8 = @ptrCast(&component_buffer);

        var next_fd = std.c.openat(current_fd, component_z, .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        });
        if (next_fd < 0 and errnoValue() == @intFromEnum(std.posix.E.NOENT)) {
            if (std.c.mkdirat(current_fd, component_z, 0o755) != 0 and
                errnoValue() != @intFromEnum(std.posix.E.EXIST))
            {
                return systemError(errnoValue());
            }
            next_fd = std.c.openat(current_fd, component_z, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            });
        }
        if (next_fd < 0) return systemError(errnoValue());
        _ = c.close(current_fd);
        current_fd = next_fd;
    }

    output.* = current_fd;
    current_fd = -1;
    return 0;
}

fn pinParent(path: []const u8, create: bool, output: *PinnedParent) u32 {
    if (path.len == 0) return errors.ERROR_TDNF_INVALID_PARAMETER;
    var end = path.len;
    while (end > 1 and path[end - 1] == '/') : (end -= 1) {}
    const trimmed = path[0..end];
    const slash = std.mem.lastIndexOfScalar(u8, trimmed, '/');
    const filename = if (slash) |index| trimmed[index + 1 ..] else trimmed;
    if (!isSafeComponent(filename)) return errors.ERROR_TDNF_INVALID_PARAMETER;
    if (filename.len > std.fs.max_name_bytes) {
        return systemError(@intFromEnum(std.posix.E.NAMETOOLONG));
    }
    const parent = if (slash) |index|
        if (index == 0) "/" else trimmed[0..index]
    else
        ".";
    var parent_fd: c_int = -1;
    const result = openDirectoryPathNoFollow(parent, create, &parent_fd);
    if (result != 0) return result;

    output.* = .{ .fd = parent_fd, .name = undefined };
    @memcpy(output.name[0..filename.len], filename);
    output.name[filename.len] = 0;
    return 0;
}

fn normalizePinnedDirectory(
    fd: c_int,
    allocator: Allocator,
) ![]u8 {
    const proc_path = try std.fmt.allocPrintSentinel(
        allocator,
        "/proc/self/fd/{d}",
        .{fd},
        0,
    );
    defer allocator.free(proc_path);
    var resolved: [std.fs.max_path_bytes]u8 = undefined;
    if (libc.realpath(proc_path, @ptrCast(&resolved)) == null) {
        return error.InvalidPath;
    }
    return allocator.dupe(u8, std.mem.sliceTo(&resolved, 0));
}

fn remotePath(location: []const u8, allocator: Allocator) ![]u8 {
    if (std.mem.indexOf(u8, location, "://") == null) {
        return allocator.dupe(u8, location);
    }
    const uri = std.Uri.parse(location) catch return error.InvalidUrl;
    if (!(std.ascii.eqlIgnoreCase(uri.scheme, "http") or
        std.ascii.eqlIgnoreCase(uri.scheme, "https") or
        std.ascii.eqlIgnoreCase(uri.scheme, "file")))
    {
        return error.InvalidUrl;
    }
    if (uri.path.percent_encoded.len == 0) return error.InvalidUrl;
    const path = try allocator.dupe(u8, uri.path.percent_encoded);
    return std.Uri.percentDecodeInPlace(path);
}

fn safeRelativePath(path: []const u8, allocator: Allocator) ![]u8 {
    var result = std.ArrayList(u8).empty;
    errdefer result.deinit(allocator);
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (!isSafeComponent(component)) return error.InvalidUrl;
        if (result.items.len != 0) try result.append(allocator, '/');
        try result.appendSlice(allocator, component);
    }
    if (result.items.len == 0) return error.InvalidUrl;
    return result.toOwnedSlice(allocator);
}

fn packageFilename(location: []const u8, allocator: Allocator) ![]u8 {
    const path = try remotePath(location, allocator);
    defer allocator.free(path);
    const relative = try safeRelativePath(path, allocator);
    defer allocator.free(relative);
    const filename = std.fs.path.basename(relative);
    if (!isSafeComponent(filename)) return error.InvalidUrl;
    return allocator.dupe(u8, filename);
}

fn joinUrl(allocator: Allocator, base: []const u8, location: []const u8) ![]u8 {
    if (base.len == 0 or location.len == 0) return error.InvalidParameter;
    const base_end = std.mem.trimEnd(u8, base, "/");
    const location_start = std.mem.trimStart(u8, location, "/");
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_end, location_start });
}

fn redactUrl(allocator: Allocator, value: []const u8) ![]const u8 {
    const scheme = std.mem.indexOf(u8, value, "://") orelse
        return allocator.dupe(u8, value);
    const authority_start = scheme + 3;
    const authority_end = std.mem.indexOfScalarPos(u8, value, authority_start, '/') orelse
        value.len;
    const at = std.mem.lastIndexOfScalar(u8, value[authority_start..authority_end], '@') orelse
        return allocator.dupe(u8, value);
    return std.fmt.allocPrint(
        allocator,
        "{s}<redacted>@{s}",
        .{ value[0..authority_start], value[authority_start + at + 1 ..] },
    );
}

fn progressCallbackImpl(
    user_data: ?*anyopaque,
    download_total: i64,
    download_now: i64,
    upload_total: i64,
    upload_now: i64,
) callconv(.c) c_int {
    _ = upload_total;
    _ = upload_now;
    if (download_total <= 0 or user_data == null) return 0;

    const data: *ProgressData = @ptrCast(@alignCast(user_data.?));
    var percent: u32 = undefined;
    if (download_now < download_total) {
        data.current_time = libc.time(null);
        if (data.previous_time != 0 and
            data.current_time - data.previous_time < 1)
        {
            return 0;
        }
        data.previous_time = data.current_time;
        percent = @intFromFloat(
            (@as(f64, @floatFromInt(download_now)) /
                @as(f64, @floatFromInt(download_total))) * 100.0,
        );
    } else {
        data.previous_time = 0;
        percent = 100;
    }

    const text: [*:0]const u8 = @ptrCast(&data.text);
    if (builtin.is_test) return 0;
    if (libc.isatty(STDERR_FILENO) == 0) {
        log_console(LOG_NOTICE, "%s %u%% %ld\n", text, percent, download_now);
    } else {
        log_console(LOG_NOTICE, "%-35s %10ld %u%%\r", text, download_now, percent);
    }
    return 0;
}

fn progressCallback(
    user_data: ?*anyopaque,
    download_total: i64,
    download_now: i64,
    upload_total: i64,
    upload_now: i64,
) callconv(.c) c_int {
    return progressCallbackImpl(
        user_data,
        download_total,
        download_now,
        upload_total,
        upload_now,
    );
}

fn setProgressData(text: []const u8) *ProgressData {
    progress_data = .{};
    const length = @min(text.len, progress_data.text.len - 1);
    @memcpy(progress_data.text[0..length], text[0..length]);
    return &progress_data;
}

fn downloadErrorIsFatal(result: u32, status: c_long) bool {
    if (status >= 400) return true;
    return switch (result) {
        errors.ERROR_TDNF_CALL_NOT_SUPPORTED,
        errors.ERROR_TDNF_INVALID_PARAMETER,
        errors.ERROR_TDNF_URL_INVALID,
        errors.ERROR_TDNF_SET_SSL_SETTINGS,
        errors.ERROR_TDNF_OPERATION_ABORTED,
        errors.ERROR_TDNF_OUT_OF_MEMORY,
        => true,
        else => false,
    };
}

fn prepareDownloadRequest(
    handle: *Tdnf,
    repo: *RepoData,
    url: [*:0]const u8,
    destination: [*:0]const u8,
    progress_text: ?[*:0]const u8,
    request: *download.TDNF_ZIG_DOWNLOAD_REQUEST,
    no_output: *bool,
) u32 {
    const args = handle.pArgs orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const conf = handle.pConf orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    request.* = .{
        .pszUrl = url,
        .pszDestination = destination,
        .pfnProgress = null,
        .pProgressData = null,
        .pszUserAgent = cString(conf.pszUserAgentHeader),
        .pszProxy = cString(conf.pszProxy),
        .pszProxyUserPwd = cString(conf.pszProxyUserPass),
        .pszUserName = cString(repo.pszUser),
        .pszPassword = cString(repo.pszPass),
        .pszSSLCaCert = cString(repo.pszSSLCaCert),
        .pszSSLClientCert = cString(repo.pszSSLClientCert),
        .pszSSLClientKey = cString(repo.pszSSLClientKey),
        .nSSLVerify = if (repo.nSSLVerify != 0) 1 else 0,
        .nConnectTimeout = conf.nConnectTimeout,
        .nTimeout = repo.nTimeout,
        .nLowSpeedLimit = repo.nMinrate,
        .nLowSpeedTime = repo.nTimeout,
        .nMaxRecvSpeed = repo.nThrottle,
    };
    no_output.* = true;
    if (args.nQuiet == 0 and progress_text != null and
        (libc.isatty(1) != 0 or args.nVerbose != 0))
    {
        request.pfnProgress = progressCallback;
        request.pProgressData = setProgressData(std.mem.span(progress_text.?));
        no_output.* = false;
    }
    return 0;
}

fn downloadToPinnedParent(
    handle: *Tdnf,
    repo: *RepoData,
    url: [*:0]const u8,
    parent: *PinnedParent,
    progress_text: ?[*:0]const u8,
) u32 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const sequence = temp_counter.fetchAdd(1, .monotonic);
    const temp_name = std.fmt.allocPrintSentinel(
        allocator,
        ".tdnf-{d}-{d}.tmp",
        .{ std.c.getpid(), sequence },
        0,
    ) catch return errors.ERROR_TDNF_OUT_OF_MEMORY;
    const temp_path = std.fmt.allocPrintSentinel(
        allocator,
        "/proc/self/fd/{d}/{s}",
        .{ parent.fd, temp_name },
        0,
    ) catch return errors.ERROR_TDNF_OUT_OF_MEMORY;
    defer _ = c.unlinkat(parent.fd, temp_name, 0);

    var request: download.TDNF_ZIG_DOWNLOAD_REQUEST = undefined;
    var no_output = true;
    var result = prepareDownloadRequest(
        handle,
        repo,
        url,
        temp_path,
        progress_text,
        &request,
        &no_output,
    );
    if (result != 0) return result;

    var attempt: c_int = 0;
    while (attempt <= repo.nRetries) : (attempt += 1) {
        if (attempt > 0 and !builtin.is_test) {
            log_console(LOG_INFO, "retrying %d/%d\n", attempt, repo.nRetries);
        }
        var status: c_long = 0;
        result = download.TDNFZigDownloadFile(&request, &status);
        if (result == 0) break;

        const safe_url = redactUrl(allocator, std.mem.span(url)) catch "download URL";
        if (status >= 400) {
            if (!builtin.is_test) log_console(
                LOG_ERR,
                "Error: %ld when downloading %.*s. Please check repo url or refresh metadata with 'tdnf makecache'.\n",
                status,
                @as(c_int, @intCast(safe_url.len)),
                safe_url.ptr,
            );
            return result;
        }
        if (attempt == repo.nRetries or downloadErrorIsFatal(result, status)) {
            if (!builtin.is_test) log_console(
                LOG_ERR,
                "Error: failed to download %.*s: %s\n",
                @as(c_int, @intCast(safe_url.len)),
                safe_url.ptr,
                download.TDNFZigDownloadLastError(),
            );
            return result;
        }
        _ = c.unlinkat(parent.fd, temp_name, 0);
    }

    if (!no_output and !builtin.is_test) log_console(LOG_INFO, "\n");
    const temp_fd = std.c.openat(parent.fd, temp_name, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    });
    if (temp_fd < 0) return systemError(errnoValue());
    defer _ = c.close(temp_fd);
    if (libc.fchmod(temp_fd, 0o644) != 0) return systemError(errnoValue());
    if (libc.fsync(temp_fd) != 0) return systemError(errnoValue());
    if (libc.renameat(parent.fd, temp_name, parent.fd, parent.nameZ()) != 0) {
        return systemError(errnoValue());
    }
    _ = libc.fsync(parent.fd);
    return 0;
}

fn downloadPackage(
    handle: *Tdnf,
    package_location: [*:0]const u8,
    package_name: [*:0]const u8,
    repo: *RepoData,
    directory_fd: c_int,
) u32 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const filename = packageFilename(std.mem.span(package_location), allocator) catch |err|
        return if (err == error.OutOfMemory)
            errors.ERROR_TDNF_OUT_OF_MEMORY
        else
            errors.ERROR_TDNF_URL_INVALID;
    if (filename.len > std.fs.max_name_bytes) {
        return systemError(@intFromEnum(std.posix.E.NAMETOOLONG));
    }
    const filename_z = allocator.dupeZ(u8, filename) catch
        return errors.ERROR_TDNF_OUT_OF_MEMORY;

    var stat: Stat = undefined;
    if (statAt(directory_fd, filename_z, &stat) == 0) {
        if (!isRegular(stat)) return systemError(@intFromEnum(std.posix.E.LOOP));
        if (stat.size != 0) {
            if (!builtin.is_test) {
                log_console(LOG_INFO, "%s package already downloaded\n", package_name);
            }
            return 0;
        }
    } else if (errnoValue() != @intFromEnum(std.posix.E.NOENT)) {
        return systemError(errnoValue());
    }

    var parent = PinnedParent{ .fd = std.c.dup(directory_fd), .name = undefined };
    if (parent.fd < 0) return systemError(errnoValue());
    defer parent.deinit();
    @memcpy(parent.name[0..filename.len], filename);
    parent.name[filename.len] = 0;
    return downloadFileFromRepoPinned(
        handle,
        repo,
        package_location,
        &parent,
        package_name,
    );
}

fn downloadFileFromRepoPinned(
    handle: *Tdnf,
    repo: *RepoData,
    location: [*:0]const u8,
    parent: *PinnedParent,
    progress_text: ?[*:0]const u8,
) u32 {
    if (repo.ppszBaseUrls) |base_urls| {
        if (base_urls[0] != null and
            std.mem.indexOf(u8, std.mem.span(location), "://") == null)
        {
            var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
            defer arena_state.deinit();
            const allocator = arena_state.allocator();
            var index: usize = 0;
            while (base_urls[index]) |base_url| : (index += 1) {
                const url = joinUrl(
                    allocator,
                    std.mem.span(base_url),
                    std.mem.span(location),
                ) catch |err| return if (err == error.OutOfMemory)
                    errors.ERROR_TDNF_OUT_OF_MEMORY
                else
                    errors.ERROR_TDNF_INVALID_PARAMETER;
                const url_z = allocator.dupeZ(u8, url) catch
                    return errors.ERROR_TDNF_OUT_OF_MEMORY;
                const result = downloadToPinnedParent(
                    handle,
                    repo,
                    url_z,
                    parent,
                    progress_text,
                );
                if (result == 0) return 0;
                if (base_urls[index + 1] != null) {
                    const safe_url = redactUrl(allocator, url) catch "download URL";
                    if (!builtin.is_test) log_console(
                        LOG_ERR,
                        "Warning: failed to download %.*s, trying next base URL\n",
                        @as(c_int, @intCast(safe_url.len)),
                        safe_url.ptr,
                    );
                } else {
                    return result;
                }
            }
        }
    }
    return downloadToPinnedParent(handle, repo, location, parent, progress_text);
}

pub export fn TDNFDownloadFileFromRepo(
    handle_opt: ?*Tdnf,
    repo_opt: ?*RepoData,
    location_opt: ?[*:0]const u8,
    file_opt: ?[*:0]const u8,
    progress_text: ?[*:0]const u8,
) u32 {
    const handle = handle_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    if (handle.pArgs == null) return errors.ERROR_TDNF_INVALID_PARAMETER;
    const repo = repo_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const location = location_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const file = file_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    if (location[0] == 0 or file[0] == 0) return errors.ERROR_TDNF_INVALID_PARAMETER;

    var parent: PinnedParent = undefined;
    const result = pinParent(std.mem.span(file), false, &parent);
    if (result != 0) return result;
    defer parent.deinit();
    return downloadFileFromRepoPinned(handle, repo, location, &parent, progress_text);
}

pub export fn TDNFDownloadFile(
    handle_opt: ?*Tdnf,
    repo_opt: ?*RepoData,
    url_opt: ?[*:0]const u8,
    file_opt: ?[*:0]const u8,
    progress_text: ?[*:0]const u8,
) u32 {
    const handle = handle_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const repo = repo_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const url = url_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const file = file_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    if (url[0] == 0 or file[0] == 0) return errors.ERROR_TDNF_INVALID_PARAMETER;

    var parent: PinnedParent = undefined;
    const result = pinParent(std.mem.span(file), false, &parent);
    if (result != 0) return result;
    defer parent.deinit();
    return downloadToPinnedParent(handle, repo, url, &parent, progress_text);
}

pub export fn TDNFCreatePackageUrl(
    repo_opt: ?*RepoData,
    location_opt: ?[*:0]const u8,
    output: ?*?[*:0]u8,
) u32 {
    const out = output orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    out.* = null;
    const repo = repo_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const location = location_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    if (location[0] == 0) return errors.ERROR_TDNF_INVALID_PARAMETER;

    if (repo.ppszBaseUrls) |base_urls| {
        if (base_urls[0]) |base_url| {
            if (std.mem.indexOf(u8, std.mem.span(location), "://") == null) {
                var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
                defer arena_state.deinit();
                const joined = joinUrl(
                    arena_state.allocator(),
                    std.mem.span(base_url),
                    std.mem.span(location),
                ) catch |err| return if (err == error.OutOfMemory)
                    errors.ERROR_TDNF_OUT_OF_MEMORY
                else
                    errors.ERROR_TDNF_INVALID_PARAMETER;
                return allocateCString(joined, out);
            }
        }
    }
    return TDNFAllocateString(location, out);
}

pub export fn TDNFDownloadPackageToCache(
    handle_opt: ?*Tdnf,
    location_opt: ?[*:0]const u8,
    package_name_opt: ?[*:0]const u8,
    repo_opt: ?*RepoData,
    output: ?*?[*:0]u8,
) u32 {
    const out = output orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    out.* = null;
    const handle = handle_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const repo = repo_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const location = location_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const package_name = package_name_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    if (location[0] == 0 or package_name[0] == 0) {
        return errors.ERROR_TDNF_INVALID_PARAMETER;
    }

    var cache_path: ?[*:0]u8 = null;
    const result = repoutils.RepoutilsGetRpmCachePath(
        handle,
        repo,
        &cache_path,
    );
    if (result != 0) return result;
    defer freeCString(cache_path);
    return TDNFDownloadPackageToTree(
        handle,
        location,
        package_name,
        repo,
        cache_path,
        out,
    );
}

pub export fn TDNFDownloadPackageToTree(
    handle_opt: ?*Tdnf,
    location_opt: ?[*:0]const u8,
    package_name_opt: ?[*:0]const u8,
    repo_opt: ?*RepoData,
    cache_dir_opt: ?[*:0]u8,
    output: ?*?[*:0]u8,
) u32 {
    const out = output orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    out.* = null;
    const handle = handle_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const repo = repo_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const location = location_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const package_name = package_name_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const cache_dir = cache_dir_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    if (location[0] == 0 or package_name[0] == 0 or cache_dir[0] == 0) {
        return errors.ERROR_TDNF_INVALID_PARAMETER;
    }
    const cache_path = std.mem.span(cache_dir);
    if (!std.fs.path.isAbsolute(cache_path)) {
        return errors.ERROR_TDNF_INVALID_PARAMETER;
    }

    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    var cache_root_fd: c_int = -1;
    var result = openDirectoryPathNoFollow(cache_path, true, &cache_root_fd);
    if (result != 0) return result;
    defer _ = c.close(cache_root_fd);
    const normalized_cache = normalizePinnedDirectory(
        cache_root_fd,
        allocator,
    ) catch |err| return if (err == error.OutOfMemory)
        errors.ERROR_TDNF_OUT_OF_MEMORY
    else
        systemError(errnoValue());
    const raw_remote = remotePath(std.mem.span(location), allocator) catch |err|
        return if (err == error.OutOfMemory)
            errors.ERROR_TDNF_OUT_OF_MEMORY
        else
            errors.ERROR_TDNF_URL_INVALID;
    const relative = safeRelativePath(raw_remote, allocator) catch |err|
        return if (err == error.OutOfMemory)
            errors.ERROR_TDNF_OUT_OF_MEMORY
        else
            errors.ERROR_TDNF_URL_INVALID;
    const filename = std.fs.path.basename(relative);
    const directory = std.fs.path.dirname(relative) orelse "";
    const final_path = std.fs.path.join(
        allocator,
        &.{ normalized_cache, directory, filename },
    ) catch return errors.ERROR_TDNF_OUT_OF_MEMORY;
    var allocated_path: ?[*:0]u8 = null;
    result = allocateCString(final_path, &allocated_path);
    if (result != 0) return result;
    defer if (out.* == null) freeCString(allocated_path);

    var directory_fd: c_int = -1;
    result = openDirectoryComponents(cache_root_fd, directory, &directory_fd);
    if (result != 0) return result;
    defer _ = c.close(directory_fd);

    result = downloadPackage(
        handle,
        location,
        package_name,
        repo,
        directory_fd,
    );
    if (result != 0) return result;

    out.* = allocated_path;
    return 0;
}

pub export fn TDNFDownloadPackageToDirectory(
    handle_opt: ?*Tdnf,
    location_opt: ?[*:0]const u8,
    package_name_opt: ?[*:0]const u8,
    repo_opt: ?*RepoData,
    directory_opt: ?[*:0]const u8,
    output: ?*?[*:0]u8,
) u32 {
    const out = output orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    out.* = null;
    const handle = handle_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const repo = repo_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const location = location_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const package_name = package_name_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    const directory = directory_opt orelse return errors.ERROR_TDNF_INVALID_PARAMETER;
    if (location[0] == 0 or package_name[0] == 0 or directory[0] == 0) {
        return errors.ERROR_TDNF_INVALID_PARAMETER;
    }

    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const filename = packageFilename(std.mem.span(location), allocator) catch |err|
        return if (err == error.OutOfMemory)
            errors.ERROR_TDNF_OUT_OF_MEMORY
        else
            errors.ERROR_TDNF_URL_INVALID;
    const final_path = std.fs.path.join(
        allocator,
        &.{ std.mem.span(directory), filename },
    ) catch return errors.ERROR_TDNF_OUT_OF_MEMORY;
    var allocated_path: ?[*:0]u8 = null;
    var result = allocateCString(final_path, &allocated_path);
    if (result != 0) return result;
    defer if (out.* == null) freeCString(allocated_path);

    var directory_fd: c_int = -1;
    result = openDirectoryPathNoFollow(std.mem.span(directory), false, &directory_fd);
    if (result != 0) return result;
    defer _ = c.close(directory_fd);

    result = downloadPackage(handle, location, package_name, repo, directory_fd);
    if (result != 0) return result;
    out.* = allocated_path;
    return 0;
}

const TestScratchDir = ".zig-cache/tdnf-remoterepo-tests";

const TestFixture = struct {
    args: CmdArgs = .{},
    conf: Conf = .{},
    repo: RepoData = .{},
    handle: Tdnf = .{},
    base_urls: [2]?[*:0]u8 = .{ null, null },

    fn init(
        self: *TestFixture,
        cache_dir: [*:0]u8,
        base_url: ?[*:0]u8,
    ) void {
        self.* = .{};
        self.conf.pszCacheDir = cache_dir;
        self.handle.pArgs = &self.args;
        self.handle.pConf = &self.conf;
        self.repo.pszId = @constCast("repo-id");
        self.repo.pszCacheName = @constCast("different-cache-name");
        self.repo.nSSLVerify = 1;
        if (base_url) |url| {
            self.base_urls[0] = url;
            self.repo.ppszBaseUrls = @ptrCast(&self.base_urls);
        }
    }
};

fn resetTestDirectory(name: []const u8) ![:0]u8 {
    const io = std.testing.io;
    try std.Io.Dir.cwd().createDirPath(io, TestScratchDir);
    const relative = try std.fs.path.join(
        std.testing.allocator,
        &.{ TestScratchDir, name },
    );
    std.Io.Dir.cwd().deleteTree(io, relative) catch {};
    try std.Io.Dir.cwd().createDirPath(io, relative);
    defer std.testing.allocator.free(relative);
    return std.Io.Dir.cwd().realPathFileAlloc(
        io,
        relative,
        std.testing.allocator,
    );
}

fn writeTestFile(path: []const u8, data: []const u8) !void {
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = data,
    });
}

fn readTestFile(path: []const u8) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    var buffer: [256]u8 = undefined;
    var reader = file.reader(std.testing.io, &buffer);
    return reader.interface.allocRemaining(
        std.testing.allocator,
        .limited(64 * 1024),
    );
}

fn zString(value: []const u8) ![:0]u8 {
    return std.testing.allocator.dupeZ(u8, value);
}

const RetryServer = struct {
    io: std.Io,
    listener: *std.Io.net.Server,

    fn threadMain(self: *RetryServer) void {
        defer {
            self.listener.deinit(self.io);
            std.testing.allocator.destroy(self.listener);
            std.testing.allocator.destroy(self);
        }
        const dropped = self.listener.accept(self.io) catch return;
        dropped.close(self.io);

        const stream = self.listener.accept(self.io) catch return;
        defer stream.close(self.io);
        var reader_buffer: [2048]u8 = undefined;
        var reader = stream.reader(self.io, &reader_buffer);
        var http_reader: std.http.Reader = .{
            .in = &reader.interface,
            .interface = undefined,
            .state = .ready,
            .max_head_len = 2048,
        };
        _ = http_reader.receiveHead() catch return;
        var writer_buffer: [256]u8 = undefined;
        var writer = stream.writer(self.io, &writer_buffer);
        writer.interface.writeAll(
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nretry success",
        ) catch return;
        writer.interface.flush() catch return;
    }
};

fn spawnRetryServer() !struct { thread: std.Thread, port: u16 } {
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    const listener = try address.listen(io, .{ .reuse_address = true });
    const boxed_listener = try std.testing.allocator.create(std.Io.net.Server);
    boxed_listener.* = listener;
    const context = try std.testing.allocator.create(RetryServer);
    context.* = .{ .io = io, .listener = boxed_listener };
    const thread = try std.Thread.spawn(.{}, RetryServer.threadMain, .{context});
    return .{
        .thread = thread,
        .port = boxed_listener.socket.address.getPort(),
    };
}

test "package URL construction preserves absolute URLs and joins relative locations" {
    var fixture: TestFixture = .{};
    const cache = try zString("/unused");
    defer std.testing.allocator.free(cache);
    const base = try zString("https://repo.example/base/");
    defer std.testing.allocator.free(base);
    fixture.init(cache.ptr, base.ptr);

    var result: ?[*:0]u8 = null;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFCreatePackageUrl(
            &fixture.repo,
            "packages/example.rpm",
            &result,
        ),
    );
    defer freeCString(result);
    try std.testing.expectEqualStrings(
        "https://repo.example/base/packages/example.rpm",
        std.mem.span(result.?),
    );

    var absolute: ?[*:0]u8 = null;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFCreatePackageUrl(
            &fixture.repo,
            "file:///packages/local.rpm",
            &absolute,
        ),
    );
    defer freeCString(absolute);
    try std.testing.expectEqualStrings(
        "file:///packages/local.rpm",
        std.mem.span(absolute.?),
    );
}

test "file downloads replace atomically and preserve the old final on failure" {
    const root = try resetTestDirectory("atomic-file");
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "source.rpm" },
    );
    defer std.testing.allocator.free(source);
    const final = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "final.rpm" },
    );
    defer std.testing.allocator.free(final);
    try writeTestFile(source, "new package bytes");
    try writeTestFile(final, "old package bytes");

    const cache = try zString(root);
    defer std.testing.allocator.free(cache);
    var fixture: TestFixture = .{};
    fixture.init(cache.ptr, null);
    const source_url = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "file://{s}",
        .{source},
        0,
    );
    defer std.testing.allocator.free(source_url);
    const final_z = try zString(final);
    defer std.testing.allocator.free(final_z);

    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFDownloadFile(
            &fixture.handle,
            &fixture.repo,
            source_url.ptr,
            final_z.ptr,
            null,
        ),
    );
    const body = try readTestFile(final);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("new package bytes", body);

    try writeTestFile(final, "keep this final");
    const missing_url = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "file://{s}/missing",
        .{root},
        0,
    );
    defer std.testing.allocator.free(missing_url);
    try std.testing.expect(
        TDNFDownloadFile(
            &fixture.handle,
            &fixture.repo,
            missing_url.ptr,
            final_z.ptr,
            null,
        ) != 0,
    );
    const preserved = try readTestFile(final);
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("keep this final", preserved);
}

test "package cache uses repository ID path and reuses a nonempty cache hit" {
    const root = try resetTestDirectory("cache-hit");
    defer std.testing.allocator.free(root);
    const repository = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "repository" },
    );
    defer std.testing.allocator.free(repository);
    const package_dir = try std.fs.path.join(
        std.testing.allocator,
        &.{ repository, "packages" },
    );
    defer std.testing.allocator.free(package_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, package_dir);
    const source = try std.fs.path.join(
        std.testing.allocator,
        &.{ package_dir, "example.rpm" },
    );
    defer std.testing.allocator.free(source);
    try writeTestFile(source, "first package");

    const cache_root = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "cache" },
    );
    defer std.testing.allocator.free(cache_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, cache_root);
    const cache_z = try zString(cache_root);
    defer std.testing.allocator.free(cache_z);
    const base_url = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "file://{s}",
        .{repository},
        0,
    );
    defer std.testing.allocator.free(base_url);
    var fixture: TestFixture = .{};
    fixture.init(cache_z.ptr, base_url.ptr);

    var output: ?[*:0]u8 = null;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFDownloadPackageToCache(
            &fixture.handle,
            "packages/example.rpm",
            "example",
            &fixture.repo,
            &output,
        ),
    );
    defer freeCString(output);
    const expected = try std.fs.path.join(
        std.testing.allocator,
        &.{ cache_root, "repo-id", "rpms", "packages", "example.rpm" },
    );
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, std.mem.span(output.?));

    try writeTestFile(source, "changed source");
    var second_output: ?[*:0]u8 = null;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFDownloadPackageToCache(
            &fixture.handle,
            "packages/example.rpm",
            "example",
            &fixture.repo,
            &second_output,
        ),
    );
    defer freeCString(second_output);
    const cached = try readTestFile(expected);
    defer std.testing.allocator.free(cached);
    try std.testing.expectEqualStrings("first package", cached);
}

test "transport failures retry and repository downloads fall back to the next base URL" {
    const root = try resetTestDirectory("retry-fallback");
    defer std.testing.allocator.free(root);
    const cache = try zString(root);
    defer std.testing.allocator.free(cache);
    var fixture: TestFixture = .{};
    fixture.init(cache.ptr, null);
    fixture.repo.nRetries = 1;

    const retry_server = try spawnRetryServer();
    defer retry_server.thread.join();
    const retry_url = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "http://127.0.0.1:{d}/package.rpm",
        .{retry_server.port},
        0,
    );
    defer std.testing.allocator.free(retry_url);
    const retry_dest = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "retried.rpm" },
    );
    defer std.testing.allocator.free(retry_dest);
    const retry_dest_z = try zString(retry_dest);
    defer std.testing.allocator.free(retry_dest_z);
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFDownloadFile(
            &fixture.handle,
            &fixture.repo,
            retry_url.ptr,
            retry_dest_z.ptr,
            null,
        ),
    );
    const retried = try readTestFile(retry_dest);
    defer std.testing.allocator.free(retried);
    try std.testing.expectEqualStrings("retry success", retried);

    const good_repo = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "good-repo" },
    );
    defer std.testing.allocator.free(good_repo);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, good_repo);
    const good_file = try std.fs.path.join(
        std.testing.allocator,
        &.{ good_repo, "fallback.rpm" },
    );
    defer std.testing.allocator.free(good_file);
    try writeTestFile(good_file, "fallback success");
    const missing_repo = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "missing-repo" },
    );
    defer std.testing.allocator.free(missing_repo);
    const first_url = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "file://{s}",
        .{missing_repo},
        0,
    );
    defer std.testing.allocator.free(first_url);
    const second_url = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "file://{s}",
        .{good_repo},
        0,
    );
    defer std.testing.allocator.free(second_url);
    var bases = [3]?[*:0]u8{
        first_url.ptr,
        second_url.ptr,
        null,
    };
    fixture.repo.ppszBaseUrls = @ptrCast(&bases);
    fixture.repo.nRetries = 0;
    const fallback_dest = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "fallback.rpm" },
    );
    defer std.testing.allocator.free(fallback_dest);
    const fallback_dest_z = try zString(fallback_dest);
    defer std.testing.allocator.free(fallback_dest_z);
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFDownloadFileFromRepo(
            &fixture.handle,
            &fixture.repo,
            "fallback.rpm",
            fallback_dest_z.ptr,
            null,
        ),
    );
    const fallback = try readTestFile(fallback_dest);
    defer std.testing.allocator.free(fallback);
    try std.testing.expectEqualStrings("fallback success", fallback);
}

test "package tree rejects traversal and malicious cache symlinks" {
    const root = try resetTestDirectory("unsafe-cache");
    defer std.testing.allocator.free(root);
    const cache_root = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "cache" },
    );
    defer std.testing.allocator.free(cache_root);
    const outside = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "outside" },
    );
    defer std.testing.allocator.free(outside);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, cache_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, outside);
    const sentinel = try std.fs.path.join(
        std.testing.allocator,
        &.{ outside, "sentinel" },
    );
    defer std.testing.allocator.free(sentinel);
    try writeTestFile(sentinel, "outside");

    const cache_z = try zString(cache_root);
    defer std.testing.allocator.free(cache_z);
    var fixture: TestFixture = .{};
    fixture.init(cache_z.ptr, null);
    var output: ?[*:0]u8 = null;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_URL_INVALID,
        TDNFDownloadPackageToTree(
            &fixture.handle,
            "../outside/escape.rpm",
            "escape",
            &fixture.repo,
            cache_z.ptr,
            &output,
        ),
    );
    try std.testing.expect(output == null);

    const repo_link = try std.fs.path.join(
        std.testing.allocator,
        &.{ cache_root, "repo-id" },
    );
    defer std.testing.allocator.free(repo_link);
    try std.Io.Dir.symLinkAbsolute(
        std.testing.io,
        outside,
        repo_link,
        .{ .is_directory = true },
    );
    try std.testing.expect(
        TDNFDownloadPackageToCache(
            &fixture.handle,
            "packages/escape.rpm",
            "escape",
            &fixture.repo,
            &output,
        ) != 0,
    );
    const preserved = try readTestFile(sentinel);
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("outside", preserved);
}

test "URL helpers surface allocator exhaustion without partial output" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        joinUrl(
            failing.allocator(),
            "https://repo.example",
            "packages/example.rpm",
        ),
    );
}
