const std = @import("std");
const header = @import("rpm_header");
const install_engine = @import("install.zig");
const lua_scriptlet_options = @import("lua_scriptlet_options");
const txn_config = @import("txn_config.zig");

const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const c = @cImport({
    @cInclude("errno.h");
    @cInclude("lua_scriptlet.h");
    @cInclude("signal.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/types.h");
    @cInclude("sys/wait.h");
    @cInclude("time.h");
    @cInclude("unistd.h");
});
const rpmtrans = @cImport({
    @cInclude("tdnfrpmtrans.h");
});

pub const Phase = enum(u32) {
    pre = 0,
    post = 1,
    preun = 2,
    postun = 3,
    pretrans = 4,
    posttrans = 5,
};

pub const Outcome = enum(u32) {
    not_run = 0,
    ok = 1,
    exited = 2,
    signaled = 3,
};

pub const Result = struct {
    ran: bool,
    critical: bool,
    outcome: Outcome,
    exit_status: i32 = 0,
    signal_number: i32 = 0,
};

pub const Options = struct {
    install_root: []const u8,
    config: ?*const txn_config.TxnConfig = null,
    trans_flags: u32 = 0,
    rpmdefines: []const []const u8 = &.{},
    arg1: ?i32 = null,
    arg2: ?i32 = null,
    stdin_data: ?[]const u8 = null,
    script_fd: ?c_int = null,
    redirect_stdout_to_stderr: bool = false,
    pinned_root_fd: ?c_int = null,
};

pub const RunError = Allocator.Error ||
    txn_config.InitError ||
    txn_config.ExpandError ||
    txn_config.ParseDefineError ||
    txn_config.SetMacroError ||
    install_engine.Error ||
    error{
        BadHeader,
        PathTooLong,
        SyscallFailed,
        UnsupportedInterpreter,
    };

const PhaseInfo = struct {
    name: []const u8,
    script_tag: u32,
    prog_tag: u32,
    skip_flag: u32,
    critical: bool,
};

fn phaseInfo(phase: Phase) PhaseInfo {
    return switch (phase) {
        .pre => .{
            .name = "%pre",
            .script_tag = @intFromEnum(header.TagId.prein),
            .prog_tag = @intFromEnum(header.TagId.preinprog),
            .skip_flag = rpmtrans.TDNF_RPMTRANS_FLAG_NOPRE,
            .critical = true,
        },
        .post => .{
            .name = "%post",
            .script_tag = @intFromEnum(header.TagId.postin),
            .prog_tag = @intFromEnum(header.TagId.postinprog),
            .skip_flag = rpmtrans.TDNF_RPMTRANS_FLAG_NOPOST,
            .critical = false,
        },
        .preun => .{
            .name = "%preun",
            .script_tag = @intFromEnum(header.TagId.preun),
            .prog_tag = @intFromEnum(header.TagId.preunprog),
            .skip_flag = rpmtrans.TDNF_RPMTRANS_FLAG_NOPREUN,
            .critical = true,
        },
        .postun => .{
            .name = "%postun",
            .script_tag = @intFromEnum(header.TagId.postun),
            .prog_tag = @intFromEnum(header.TagId.postunprog),
            .skip_flag = rpmtrans.TDNF_RPMTRANS_FLAG_NOPOSTUN,
            .critical = false,
        },
        .pretrans => .{
            .name = "%pretrans",
            .script_tag = @intFromEnum(header.TagId.pretrans),
            .prog_tag = @intFromEnum(header.TagId.pretransprog),
            .skip_flag = rpmtrans.TDNF_RPMTRANS_FLAG_NOPRETRANS,
            .critical = true,
        },
        .posttrans => .{
            .name = "%posttrans",
            .script_tag = @intFromEnum(header.TagId.posttrans),
            .prog_tag = @intFromEnum(header.TagId.posttransprog),
            .skip_flag = rpmtrans.TDNF_RPMTRANS_FLAG_NOPOSTTRANS,
            .critical = false,
        },
    };
}

pub fn runHeaderScript(
    allocator: Allocator,
    hdr: header.Header,
    phase: Phase,
    options: Options,
) RunError!Result {
    const info = phaseInfo(phase);
    if ((options.trans_flags & (rpmtrans.TDNF_RPMTRANS_FLAG_NOSCRIPTS |
        rpmtrans.TDNF_RPMTRANS_FLAG_JUSTDB)) != 0 or
        (options.trans_flags & info.skip_flag) != 0)
    {
        return .{
            .ran = false,
            .critical = info.critical,
            .outcome = .not_run,
        };
    }

    const script_body = hdr.getStringRaw(info.script_tag);
    const has_prog = hdr.findRaw(info.prog_tag) != null;
    if (script_body == null and !has_prog) {
        return .{
            .ran = false,
            .critical = info.critical,
            .outcome = .not_run,
        };
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const interpreter = try collectInterpreterArgs(arena_alloc, hdr, info.prog_tag);
    return runPreparedScript(allocator, interpreter, script_body, info.critical, options);
}

pub fn runPreparedScript(
    allocator: Allocator,
    interpreter: []const []const u8,
    script_body: ?[]const u8,
    critical: bool,
    options: Options,
) RunError!Result {
    var config = if (options.config) |supplied|
        try supplied.clone(allocator)
    else
        try txn_config.TxnConfig.init(allocator, options.install_root);
    defer config.deinit();

    for (options.rpmdefines) |define| {
        _ = try config.applyRpmDefine(define);
    }
    var pinned_root = if (options.pinned_root_fd) |root_fd| blk: {
        const duplicate = std.c.fcntl(
            root_fd,
            std.c.F.DUPFD_CLOEXEC,
            @as(c_int, 0),
        );
        if (duplicate < 0) return error.SyscallFailed;
        break :blk try install_engine.RootDir.initFromOwnedFd(
            allocator,
            duplicate,
            null,
            null,
        );
    } else try install_engine.RootDir.init(
        allocator,
        config.installRoot(),
        null,
        null,
    );
    defer pinned_root.deinit();

    if (interpreter.len == 0) {
        return .{
            .ran = false,
            .critical = critical,
            .outcome = .not_run,
        };
    }
    if (std.mem.eql(u8, interpreter[0], "<lua>")) {
        const body = script_body orelse {
            return .{
                .ran = false,
                .critical = critical,
                .outcome = .not_run,
            };
        };
        if (c.tdnf_rpmzig_lua_supported() == 0) {
            return error.UnsupportedInterpreter;
        }
        return try runLuaScriptProcess(
            allocator,
            &config,
            &pinned_root,
            body,
            critical,
            options,
        );
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var script_file: ?TempScript = null;
    defer {
        if (script_file) |temp| {
            pinned_root.remove(temp.exec_path) catch {};
        }
    }

    var argv = std.ArrayList(?[*:0]const u8).empty;
    defer argv.deinit(arena_alloc);

    for (interpreter) |arg| {
        const arg_z = try arena_alloc.dupeZ(u8, arg);
        try argv.append(arena_alloc, arg_z.ptr);
    }

    if (script_body) |body| {
        script_file = try writeTempScript(
            arena_alloc,
            &config,
            &pinned_root,
            body,
        );
        const exec_z = try arena_alloc.dupeZ(u8, script_file.?.exec_path);
        try argv.append(arena_alloc, exec_z.ptr);
    }

    if (options.arg1) |value| {
        const text = try std.fmt.allocPrint(arena_alloc, "{d}", .{value});
        const text_z = try arena_alloc.dupeZ(u8, text);
        try argv.append(arena_alloc, text_z.ptr);
    }
    if (options.arg2) |value| {
        const text = try std.fmt.allocPrint(arena_alloc, "{d}", .{value});
        const text_z = try arena_alloc.dupeZ(u8, text);
        try argv.append(arena_alloc, text_z.ptr);
    }
    try argv.append(arena_alloc, null);

    const expanded_path = try config.expandMacroAlloc(arena_alloc, .install_script_path);
    const path_env = try arena_alloc.dupeZ(u8, expanded_path);
    const input_fd = try prepareInputFd(options.stdin_data);
    defer if (input_fd >= 0) {
        _ = linux.close(input_fd);
    };

    const pid = c.fork();
    if (pid < 0) {
        return error.SyscallFailed;
    }
    if (pid == 0) {
        runExecChild(
            argv.items.ptr,
            path_env.ptr,
            pinned_root.fd,
            std.mem.eql(u8, config.installRoot(), "/"),
            input_fd,
            options.script_fd orelse -1,
            options.redirect_stdout_to_stderr,
        );
    }

    return waitForChild(pid, critical);
}

fn runLuaScriptProcess(
    allocator: Allocator,
    config: *const txn_config.TxnConfig,
    pinned_root: *const install_engine.RootDir,
    body: []const u8,
    critical: bool,
    options: Options,
) RunError!Result {
    const expanded_path = try config.expandMacroAlloc(allocator, .install_script_path);
    defer allocator.free(expanded_path);
    const path_env = try allocator.dupeZ(u8, expanded_path);
    defer allocator.free(path_env);
    const input_fd = try prepareInputFd(options.stdin_data);
    defer if (input_fd >= 0) {
        _ = linux.close(input_fd);
    };

    const pid = c.fork();
    if (pid < 0) {
        return error.SyscallFailed;
    }
    if (pid == 0) {
        runLuaChild(
            body.ptr,
            body.len,
            path_env.ptr,
            pinned_root.fd,
            std.mem.eql(u8, config.installRoot(), "/"),
            options.arg1 orelse -1,
            options.arg2 orelse -1,
            input_fd,
            options.script_fd orelse -1,
            options.redirect_stdout_to_stderr,
        );
    }

    return waitForChild(pid, critical);
}

fn waitForChild(pid: c_int, critical: bool) RunError!Result {
    var status: c_int = 0;
    while (true) {
        switch (std.posix.errno(std.posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.SyscallFailed,
        }
    }

    if (std.posix.W.IFEXITED(@bitCast(status))) {
        const exit_status: i32 = std.posix.W.EXITSTATUS(@bitCast(status));
        return .{
            .ran = true,
            .critical = critical,
            .outcome = if (exit_status == 0) .ok else .exited,
            .exit_status = exit_status,
        };
    }
    if (std.posix.W.IFSIGNALED(@bitCast(status))) {
        return .{
            .ran = true,
            .critical = critical,
            .outcome = .signaled,
            .signal_number = @as(i32, @intCast(@intFromEnum(std.posix.W.TERMSIG(@bitCast(status))))),
        };
    }

    return .{
        .ran = true,
        .critical = critical,
        .outcome = .signaled,
        .signal_number = 0,
    };
}

fn collectInterpreterArgs(
    allocator: Allocator,
    hdr: header.Header,
    prog_tag: u32,
) Allocator.Error![]const []const u8 {
    var args = std.ArrayList([]const u8).empty;
    defer args.deinit(allocator);

    const count = hdr.stringArrayCountRaw(prog_tag);
    if (count > 0) {
        for (0..count) |index| {
            const value = hdr.stringArrayItemRaw(prog_tag, index) orelse continue;
            try args.append(allocator, value);
        }
    } else if (hdr.getStringRaw(prog_tag)) |value| {
        try args.append(allocator, value);
    } else {
        try args.append(allocator, txn_config.DEFAULT_SCRIPT_INTERPRETER);
    }

    return args.toOwnedSlice(allocator);
}

const TempScript = struct {
    exec_path: []const u8,
};

fn writeTempScript(
    allocator: Allocator,
    config: *const txn_config.TxnConfig,
    pinned_root: *const install_engine.RootDir,
    body: []const u8,
) RunError!TempScript {
    const exec_dir = try config.expandMacroAlloc(allocator, .tmppath);
    defer allocator.free(exec_dir);
    if (exec_dir.len == 0 or exec_dir[0] != '/') {
        return error.SyscallFailed;
    }
    try pinned_root.ensureDirectory(exec_dir);

    var attempts: usize = 0;
    while (attempts < 16) : (attempts += 1) {
        const token = (@as(u64, @intCast(c.time(null))) << 32) ^
            (@as(u64, @intCast(c.getpid())) << 16) ^
            @as(u64, attempts);
        const filename = try std.fmt.allocPrint(allocator, "tdnf-scriptlet-{x}", .{token});
        defer allocator.free(filename);
        const exec_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ exec_dir, filename });
        const fd = (try pinned_root.createExclusiveRegular(
            exec_path,
            0o700,
        )) orelse continue;
        errdefer pinned_root.remove(exec_path) catch {};

        if (writeAll(fd, body) != 0) {
            _ = linux.close(fd);
            return error.SyscallFailed;
        }
        if (std.posix.errno(linux.close(fd)) != .SUCCESS) {
            return error.SyscallFailed;
        }
        return .{
            .exec_path = exec_path,
        };
    }

    return error.SyscallFailed;
}

fn writeAll(fd: c_int, bytes: []const u8) c_int {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = linux.write(fd, bytes.ptr + offset, bytes.len - offset);
        switch (std.posix.errno(written)) {
            .SUCCESS => offset += @intCast(written),
            .INTR => continue,
            else => return -1,
        }
    }
    return 0;
}

fn ensureDirPathAbsolute(allocator: Allocator, dir_path: []const u8) RunError!void {
    if (dir_path.len == 0 or dir_path[0] != '/') return error.SyscallFailed;
    const scratch = try allocator.dupeZ(u8, dir_path);
    defer allocator.free(scratch);

    var index: usize = 1;
    while (index <= dir_path.len) : (index += 1) {
        if (index != dir_path.len and scratch[index] != '/') continue;

        const saved = scratch[index];
        scratch[index] = 0;
        if (scratch[1] != 0) {
            if (c.mkdir(scratch.ptr, 0o755) != 0) {
                const err: std.c.E = @enumFromInt(std.c._errno().*);
                if (err != .EXIST) return error.SyscallFailed;
            }
        }
        scratch[index] = saved;
    }
}

fn prepareChildProcess(
    path_env: [*:0]u8,
    install_root_fd: c_int,
    install_root_is_host: bool,
    input_fd: c_int,
    script_fd: c_int,
    redirect_stdout_to_stderr: bool,
) bool {
    if (input_fd >= 0) {
        if (std.posix.errno(linux.dup2(input_fd, c.STDIN_FILENO)) != .SUCCESS) {
            return false;
        }
        if (input_fd != c.STDIN_FILENO) {
            _ = linux.close(input_fd);
        }
    } else {
        const null_rc = linux.openat(
            std.posix.AT.FDCWD,
            "/dev/null",
            .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
            0,
        );
        if (std.posix.errno(null_rc) != .SUCCESS) {
            return false;
        }
        const null_fd: c_int = @intCast(null_rc);
        if (std.posix.errno(linux.dup2(null_fd, c.STDIN_FILENO)) != .SUCCESS) {
            _ = linux.close(null_fd);
            return false;
        }
        _ = linux.close(null_fd);
    }

    if (script_fd >= 0) {
        _ = linux.dup2(script_fd, c.STDERR_FILENO);
    }
    if (redirect_stdout_to_stderr) {
        const target = if (script_fd >= 0) script_fd else c.STDERR_FILENO;
        _ = linux.dup2(target, c.STDOUT_FILENO);
    }

    if (c.setenv("PATH", path_env, 1) != 0) {
        return false;
    }

    if (std.posix.errno(linux.fchdir(install_root_fd)) != .SUCCESS) {
        return false;
    }
    if (!install_root_is_host) {
        if (std.posix.errno(linux.chroot(".")) != .SUCCESS) {
            return false;
        }
    }
    if (std.posix.errno(linux.chdir("/")) != .SUCCESS) {
        return false;
    }
    _ = linux.close(install_root_fd);

    return true;
}

fn runExecChild(
    argv: [*]const ?[*:0]const u8,
    path_env: [*:0]u8,
    install_root_fd: c_int,
    install_root_is_host: bool,
    input_fd: c_int,
    script_fd: c_int,
    redirect_stdout_to_stderr: bool,
) noreturn {
    if (!prepareChildProcess(
        path_env,
        install_root_fd,
        install_root_is_host,
        input_fd,
        script_fd,
        redirect_stdout_to_stderr,
    )) {
        c._exit(127);
    }

    _ = c.execv(argv[0].?, @ptrCast(argv));
    c._exit(127);
}

fn runLuaChild(
    script_ptr: [*]const u8,
    script_len: usize,
    path_env: [*:0]u8,
    install_root_fd: c_int,
    install_root_is_host: bool,
    arg1: c_int,
    arg2: c_int,
    input_fd: c_int,
    script_fd: c_int,
    redirect_stdout_to_stderr: bool,
) noreturn {
    if (!prepareChildProcess(
        path_env,
        install_root_fd,
        install_root_is_host,
        input_fd,
        script_fd,
        redirect_stdout_to_stderr,
    )) {
        c._exit(127);
    }

    const rc = c.tdnf_rpmzig_lua_run(script_ptr, script_len, arg1, arg2);
    c._exit(if (rc == 0) 0 else 1);
}

fn prepareInputFd(data: ?[]const u8) RunError!c_int {
    const bytes = data orelse return -1;
    const raw_fd = linux.memfd_create("tdnf-trigger-input", 0);
    if (std.posix.errno(raw_fd) != .SUCCESS) {
        return error.SyscallFailed;
    }
    const fd: c_int = @intCast(raw_fd);
    errdefer _ = linux.close(fd);

    if (writeAll(fd, bytes) != 0) {
        return error.SyscallFailed;
    }
    const seek_rc = linux.lseek(fd, 0, c.SEEK_SET);
    if (std.posix.errno(seek_rc) != .SUCCESS) {
        return error.SyscallFailed;
    }
    return fd;
}

fn testTmpPath(allocator: Allocator) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    switch (linux.errno(linux.getcwd(buf[0..].ptr, buf.len))) {
        .SUCCESS => {},
        else => return error.SyscallFailed,
    }
    const cwd_len = std.mem.findScalar(u8, &buf, 0) orelse return error.SyscallFailed;
    return std.fmt.allocPrint(allocator, "{s}/.scriptlet-zig-tests", .{buf[0..cwd_len]});
}

fn testTmpDefine(allocator: Allocator, tmp_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "_tmppath {s}", .{tmp_path});
}

fn luaContractSupported() !bool {
    const supported = c.tdnf_rpmzig_lua_supported() != 0;
    try std.testing.expectEqual(lua_scriptlet_options.enabled, supported);
    return supported;
}

test "scriptlet config expands recursive tmppath and PATH" {
    const allocator = std.testing.allocator;
    var config = try txn_config.TxnConfig.init(allocator, "/native-root");
    defer config.deinit();
    _ = try config.applyRpmDefine("_native_tmp /run/tdnf");
    _ = try config.applyRpmDefine("_tmppath %{_native_tmp}/scripts");
    _ = try config.applyRpmDefine("_native_script_path /opt/tdnf/bin");
    _ = try config.applyRpmDefine("_install_script_path %{_native_script_path}:/usr/bin");

    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/native-root/run/tdnf/scripts",
        try config.resolvePath(.tmppath, &tmp_buf),
    );
    const path = try config.expandMacroAlloc(allocator, .install_script_path);
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/opt/tdnf/bin:/usr/bin", path);
}

test "scriptlet temp files stay under pinned installroot after path swap" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "root/var/tmp");
    try tmp.dir.createDirPath(std.testing.io, "outside");
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    switch (linux.errno(linux.getcwd(cwd_buf[0..].ptr, cwd_buf.len))) {
        .SUCCESS => {},
        else => return error.SyscallFailed,
    }
    const cwd_len = std.mem.findScalar(u8, &cwd_buf, 0) orelse
        return error.SyscallFailed;
    const cwd = cwd_buf[0..cwd_len];
    const base = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ cwd, tmp.sub_path },
    );
    defer allocator.free(base);
    const root_path = try std.fmt.allocPrint(
        allocator,
        "{s}/root",
        .{base},
    );
    defer allocator.free(root_path);
    const parked_path = try std.fmt.allocPrint(
        allocator,
        "{s}/parked",
        .{base},
    );
    defer allocator.free(parked_path);
    const outside_path = try std.fmt.allocPrint(
        allocator,
        "{s}/outside",
        .{base},
    );
    defer allocator.free(outside_path);
    var config = try txn_config.TxnConfig.init(allocator, root_path);
    defer config.deinit();
    var pinned_root = try install_engine.RootDir.init(
        allocator,
        root_path,
        null,
        null,
    );
    defer pinned_root.deinit();
    const root_z = try allocator.dupeZ(u8, root_path);
    defer allocator.free(root_z);
    const parked_z = try allocator.dupeZ(u8, parked_path);
    defer allocator.free(parked_z);
    const outside_z = try allocator.dupeZ(u8, outside_path);
    defer allocator.free(outside_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        std.c.rename(root_z.ptr, parked_z.ptr),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.symlink(outside_z.ptr, root_z.ptr),
    );
    const temp = try writeTempScript(
        allocator,
        &config,
        &pinned_root,
        "echo safe",
    );
    defer allocator.free(temp.exec_path);
    defer pinned_root.remove(temp.exec_path) catch {};
    const parked_script = try std.fmt.allocPrint(
        allocator,
        "{s}{s}",
        .{ parked_path, temp.exec_path },
    );
    defer allocator.free(parked_script);
    const outside_script = try std.fmt.allocPrint(
        allocator,
        "{s}{s}",
        .{ outside_path, temp.exec_path },
    );
    defer allocator.free(outside_script);
    try tmp.dir.access(
        std.testing.io,
        parked_script[base.len + 1 ..],
        .{},
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.access(
            std.testing.io,
            outside_script[base.len + 1 ..],
            .{},
        ),
    );
}

const TestHeaderEntry = struct {
    tag: u32,
    typ: u32,
    count: u32,
    data: []const u8,
};

fn buildTestHeaderBlob(
    allocator: Allocator,
    entries: []const TestHeaderEntry,
) ![]u8 {
    const IndexSpec = struct { tag: u32, typ: u32, offset: u32, count: u32 };

    var index_specs = std.ArrayList(IndexSpec).empty;
    defer index_specs.deinit(allocator);
    var data = std.ArrayList(u8).empty;
    defer data.deinit(allocator);

    for (entries) |entry| {
        try index_specs.append(allocator, .{
            .tag = entry.tag,
            .typ = entry.typ,
            .offset = @intCast(data.items.len),
            .count = entry.count,
        });
        try data.appendSlice(allocator, entry.data);
    }

    const total_len = 8 + index_specs.items.len * 16 + data.items.len;
    const blob = try allocator.alloc(u8, total_len);

    writeBeU32(blob[0..4], @intCast(index_specs.items.len));
    writeBeU32(blob[4..8], @intCast(data.items.len));

    var cursor: usize = 8;
    for (index_specs.items) |entry| {
        writeBeU32(blob[cursor .. cursor + 4], entry.tag);
        writeBeU32(blob[cursor + 4 .. cursor + 8], entry.typ);
        writeBeU32(blob[cursor + 8 .. cursor + 12], entry.offset);
        writeBeU32(blob[cursor + 12 .. cursor + 16], entry.count);
        cursor += 16;
    }
    @memcpy(blob[cursor..], data.items);
    return blob;
}

fn writeBeU32(buf: []u8, value: u32) void {
    buf[0] = @intCast((value >> 24) & 0xff);
    buf[1] = @intCast((value >> 16) & 0xff);
    buf[2] = @intCast((value >> 8) & 0xff);
    buf[3] = @intCast(value & 0xff);
}

fn writeAbsoluteFile(allocator: Allocator, path: []const u8, bytes: []const u8) !void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const open_rc = linux.openat(
        std.posix.AT.FDCWD,
        path_z.ptr,
        .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        },
        0o644,
    );
    switch (std.posix.errno(open_rc)) {
        .SUCCESS => {},
        else => return error.SyscallFailed,
    }
    const fd: c_int = @intCast(open_rc);

    if (writeAll(fd, bytes) != 0) {
        _ = linux.close(fd);
        return error.SyscallFailed;
    }
    if (std.posix.errno(linux.close(fd)) != .SUCCESS) {
        return error.SyscallFailed;
    }
}

fn createAbsoluteOutputFile(allocator: Allocator, path: []const u8) !c_int {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const open_rc = linux.openat(
        std.posix.AT.FDCWD,
        path_z.ptr,
        .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        },
        0o644,
    );
    switch (std.posix.errno(open_rc)) {
        .SUCCESS => return @intCast(open_rc),
        else => return error.SyscallFailed,
    }
}

fn readAbsoluteFile(allocator: Allocator, path: []const u8) ![]u8 {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const open_rc = linux.openat(
        std.posix.AT.FDCWD,
        path_z.ptr,
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    );
    switch (std.posix.errno(open_rc)) {
        .SUCCESS => {},
        else => return error.SyscallFailed,
    }
    const fd: c_int = @intCast(open_rc);
    defer _ = linux.close(fd);

    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(allocator);

    var buf: [256]u8 = undefined;
    while (true) {
        const read_rc = linux.read(fd, buf[0..].ptr, buf.len);
        switch (std.posix.errno(read_rc)) {
            .SUCCESS => {
                const count: usize = @intCast(read_rc);
                if (count == 0) break;
                try bytes.appendSlice(allocator, buf[0..count]);
            },
            .INTR => continue,
            else => return error.SyscallFailed,
        }
    }

    return bytes.toOwnedSlice(allocator);
}

test "runHeaderScript succeeds with default shell" {
    const allocator = std.testing.allocator;
    const tmp_path = try testTmpPath(allocator);
    defer allocator.free(tmp_path);
    const define = try testTmpDefine(allocator, tmp_path);
    defer allocator.free(define);
    const defines = [_][]const u8{define};
    try ensureDirPathAbsolute(allocator, tmp_path);

    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.prein), .typ = 6, .count = 1, .data = ":\n\x00" },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    const result = try runHeaderScript(allocator, hdr, .pre, .{
        .install_root = "/",
        .rpmdefines = &defines,
        .arg1 = 1,
    });
    try std.testing.expect(result.ran);
    try std.testing.expect(result.critical);
    try std.testing.expectEqual(Outcome.ok, result.outcome);
}

test "runHeaderScript surfaces non-zero exit" {
    const allocator = std.testing.allocator;
    const tmp_path = try testTmpPath(allocator);
    defer allocator.free(tmp_path);
    const define = try testTmpDefine(allocator, tmp_path);
    defer allocator.free(define);
    const defines = [_][]const u8{define};
    try ensureDirPathAbsolute(allocator, tmp_path);

    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.postin), .typ = 6, .count = 1, .data = "exit 7\n\x00" },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    const result = try runHeaderScript(allocator, hdr, .post, .{
        .install_root = "/",
        .rpmdefines = &defines,
        .arg1 = 1,
    });
    try std.testing.expect(result.ran);
    try std.testing.expect(!result.critical);
    try std.testing.expectEqual(Outcome.exited, result.outcome);
    try std.testing.expectEqual(@as(i32, 7), result.exit_status);
}

test "runHeaderScript passes arg1" {
    const allocator = std.testing.allocator;
    const tmp_path = try testTmpPath(allocator);
    defer allocator.free(tmp_path);
    const define = try testTmpDefine(allocator, tmp_path);
    defer allocator.free(define);
    const defines = [_][]const u8{define};
    try ensureDirPathAbsolute(allocator, tmp_path);

    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.preun), .typ = 6, .count = 1, .data = "[ \"$1\" = \"5\" ]\n\x00" },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    const result = try runHeaderScript(allocator, hdr, .preun, .{
        .install_root = "/",
        .rpmdefines = &defines,
        .arg1 = 5,
    });
    try std.testing.expect(result.ran);
    try std.testing.expectEqual(Outcome.ok, result.outcome);
}

test "runPreparedScript supplies trigger stdin" {
    const allocator = std.testing.allocator;
    const tmp_path = try testTmpPath(allocator);
    defer allocator.free(tmp_path);
    const define = try testTmpDefine(allocator, tmp_path);
    defer allocator.free(define);
    const defines = [_][]const u8{define};
    try ensureDirPathAbsolute(allocator, tmp_path);

    const result = try runPreparedScript(
        allocator,
        &.{"/bin/sh"},
        "IFS= read -r first\nIFS= read -r second\n" ++
            "[ \"$first\" = /one ] && [ \"$second\" = /two ]\n",
        false,
        .{
            .install_root = "/",
            .rpmdefines = &defines,
            .stdin_data = "/one\n/two\n",
        },
    );
    try std.testing.expectEqual(Outcome.ok, result.outcome);
}

test "Lua rpm.input reads trigger stdin" {
    if (c.tdnf_rpmzig_lua_supported() == 0) return;

    const allocator = std.testing.allocator;
    const result = try runPreparedScript(
        allocator,
        &.{"<lua>"},
        "local first = rpm.input()\n" ++
            "local second = rpm.input()\n" ++
            "if first ~= '/one' or second ~= '/two' or " ++
            "rpm.input() ~= nil then error('bad trigger input') end\n",
        false,
        .{
            .install_root = "/",
            .stdin_data = "/one\n/two\n",
        },
    );
    try std.testing.expectEqual(Outcome.ok, result.outcome);
}

test "Lua contract exposes 5.4 arguments libraries and modules" {
    if (!try luaContractSupported()) return;

    const allocator = std.testing.allocator;
    const with_args = try runPreparedScript(
        allocator,
        &.{"<lua>"},
        \\assert(_VERSION == "Lua 5.4")
        \\assert(type(opt) == "table" and next(opt) == nil)
        \\assert(#arg == 3)
        \\assert(arg[1] == "<lua>")
        \\assert(type(arg[2]) == "number" and arg[2] == 7)
        \\assert(type(arg[3]) == "number" and arg[3] == 9)
        \\assert(require("rpm") == rpm)
        \\assert(require("posix") == posix)
        \\for _, name in ipairs({
        \\  "package", "coroutine", "table", "io", "os",
        \\  "string", "math", "utf8", "debug"
        \\}) do
        \\  assert(type(_G[name]) == "table", name)
        \\end
        \\local co = coroutine.create(function() return string.upper("ok") end)
        \\local resumed, value = coroutine.resume(co)
        \\assert(resumed and value == "OK")
        \\assert(utf8.len("lua") == 3)
    ,
        true,
        .{
            .install_root = "/",
            .arg1 = 7,
            .arg2 = 9,
        },
    );
    try std.testing.expect(with_args.ran);
    try std.testing.expect(with_args.critical);
    try std.testing.expectEqual(Outcome.ok, with_args.outcome);

    const without_args = try runPreparedScript(
        allocator,
        &.{"<lua>"},
        \\assert(#arg == 1)
        \\assert(arg[1] == "<lua>")
        \\assert(arg[2] == nil and arg[3] == nil)
    ,
        false,
        .{ .install_root = "/" },
    );
    try std.testing.expect(without_args.ran);
    try std.testing.expect(!without_args.critical);
    try std.testing.expectEqual(Outcome.ok, without_args.outcome);
}

test "Lua contract preserves helper results and errors" {
    if (!try luaContractSupported()) return;

    const allocator = std.testing.allocator;
    const tmp_path = try testTmpPath(allocator);
    defer allocator.free(tmp_path);
    try ensureDirPathAbsolute(allocator, tmp_path);
    const unique: u64 = (@as(u64, @intCast(c.time(null))) << 32) ^
        @as(u64, @intCast(c.getpid()));
    const missing_path = try std.fmt.allocPrint(
        allocator,
        "{s}/lua-contract-missing-{d}",
        .{ tmp_path, unique },
    );
    defer allocator.free(missing_path);
    const script = try std.fmt.allocPrint(
        allocator,
        \\local missing = "{s}"
        \\local result, message, code =
        \\  rpm.execute("/bin/sh", "-c", "exit 7")
        \\assert(result == nil and message == "exit code" and code == 7)
        \\result, message, code =
        \\  rpm.spawn({{"/bin/sh", "-c", "exit 8"}})
        \\assert(result == nil and message == "exit code" and code == 8)
        \\result, message, code = posix.access(missing)
        \\assert(result == nil and type(message) == "string" and code > 0)
        \\local pattern = missing .. "-*"
        \\local matches = rpm.glob(pattern)
        \\assert(#matches == 1 and matches[1] == pattern)
        \\assert(rpm.vercmp("1.0~rc1", "1.0") < 0)
        \\assert(rpm.vercmp("1.0^git1", "1.0") > 0)
        \\assert(rpm.vercmp("2:1.0-1", "1:9.0-9") > 0)
        \\assert(rpm.vercmp("1.01", "1.1") == 0)
        \\assert(rpm.vercmp("1.0-2", "1.0-10") < 0)
        \\local ok, err = pcall(rpm.spawn, {{}})
        \\assert(not ok and string.find(err, "command not supplied", 1, true))
        \\ok = pcall(posix.chmod, "/", "invalid")
        \\assert(not ok)
    ,
        .{missing_path},
    );
    defer allocator.free(script);
    const result = try runPreparedScript(
        allocator,
        &.{"<lua>"},
        script,
        true,
        .{ .install_root = "/" },
    );
    try std.testing.expectEqual(Outcome.ok, result.outcome);
}

test "Lua contract maps failures and routes output" {
    if (!try luaContractSupported()) return;

    const allocator = std.testing.allocator;
    const tmp_path = try testTmpPath(allocator);
    defer allocator.free(tmp_path);
    try ensureDirPathAbsolute(allocator, tmp_path);

    const unique: u64 = (@as(u64, @intCast(c.time(null))) << 32) ^
        @as(u64, @intCast(c.getpid()));
    const output_path = try std.fmt.allocPrint(
        allocator,
        "{s}/lua-contract-output-{d}",
        .{ tmp_path, unique },
    );
    defer allocator.free(output_path);
    const output_path_z = try allocator.dupeZ(u8, output_path);
    defer allocator.free(output_path_z);
    defer _ = c.unlink(output_path_z.ptr);
    const output_fd = try createAbsoluteOutputFile(allocator, output_path);
    errdefer _ = linux.close(output_fd);

    const runtime_failure = try runPreparedScript(
        allocator,
        &.{"<lua>"},
        \\io.stdout:write("stdout-marker\n")
        \\io.stdout:flush()
        \\io.stderr:write("stderr-marker\n")
        \\io.stderr:flush()
        \\error("runtime-marker")
    ,
        false,
        .{
            .install_root = "/",
            .script_fd = output_fd,
            .redirect_stdout_to_stderr = true,
        },
    );
    try std.testing.expect(runtime_failure.ran);
    try std.testing.expect(!runtime_failure.critical);
    try std.testing.expectEqual(Outcome.exited, runtime_failure.outcome);
    try std.testing.expectEqual(@as(i32, 1), runtime_failure.exit_status);

    const syntax_failure = try runPreparedScript(
        allocator,
        &.{"<lua>"},
        "local broken = (\n",
        true,
        .{
            .install_root = "/",
            .script_fd = output_fd,
        },
    );
    try std.testing.expect(syntax_failure.ran);
    try std.testing.expect(syntax_failure.critical);
    try std.testing.expectEqual(Outcome.exited, syntax_failure.outcome);
    try std.testing.expectEqual(@as(i32, 1), syntax_failure.exit_status);

    if (std.posix.errno(linux.close(output_fd)) != .SUCCESS) {
        return error.SyscallFailed;
    }
    const output = try readAbsoluteFile(allocator, output_path);
    defer allocator.free(output);
    try std.testing.expect(std.mem.indexOf(
        u8,
        output,
        "stdout-marker\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        output,
        "stderr-marker\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        output,
        "lua script failed:",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        output,
        "runtime-marker",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        output,
        "invalid syntax in lua scriptlet:",
    ) != null);
}

test "runHeaderScript handles Lua bash-style postun" {
    const allocator = std.testing.allocator;
    const tmp_path = try testTmpPath(allocator);
    defer allocator.free(tmp_path);
    try ensureDirPathAbsolute(allocator, tmp_path);

    const shells_path = try std.fmt.allocPrint(allocator, "{s}/lua-shells", .{tmp_path});
    defer allocator.free(shells_path);
    try writeAbsoluteFile(allocator, shells_path, "/bin/bash\n/usr/bin/fish\n/bin/sh\n");

    const script = try std.fmt.allocPrint(
        allocator,
        \\local shells_path = "{s}"
        \\if arg[2] == 0 then
        \\  t = {{}}
        \\  for line in io.lines(shells_path) do
        \\    if line ~= "/bin/bash" and line ~= "/bin/sh" then
        \\      table.insert(t, line)
        \\    end
        \\  end
        \\  f = io.open(shells_path, "w+")
        \\  for _, line in pairs(t) do
        \\    f:write(line .. "\n")
        \\  end
        \\  f:close()
        \\end
        \\
    ,
        .{shells_path},
    );
    defer allocator.free(script);
    const script_data = try std.fmt.allocPrint(allocator, "{s}\x00", .{script});
    defer allocator.free(script_data);

    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.postun), .typ = 6, .count = 1, .data = script_data },
        .{ .tag = @intFromEnum(header.TagId.postunprog), .typ = 6, .count = 1, .data = "<lua>\x00" },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    if (c.tdnf_rpmzig_lua_supported() == 0) {
        try std.testing.expectError(error.UnsupportedInterpreter, runHeaderScript(allocator, hdr, .postun, .{
            .install_root = "/",
            .arg1 = 0,
        }));
        return;
    }

    const result = try runHeaderScript(allocator, hdr, .postun, .{
        .install_root = "/",
        .arg1 = 0,
    });
    try std.testing.expect(result.ran);
    try std.testing.expectEqual(Outcome.ok, result.outcome);

    const contents = try readAbsoluteFile(allocator, shells_path);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("/usr/bin/fish\n", contents);
}

test "runHeaderScript exposes Lua rpm and posix helpers" {
    const allocator = std.testing.allocator;
    const tmp_path = try testTmpPath(allocator);
    defer allocator.free(tmp_path);
    try ensureDirPathAbsolute(allocator, tmp_path);

    const unique: u64 = (@as(u64, @intCast(c.time(null))) << 32) ^
        @as(u64, @intCast(c.getpid()));
    const root_path = try std.fmt.allocPrint(allocator, "{s}/lua-helper-{d}", .{ tmp_path, unique });
    defer allocator.free(root_path);
    const marker_path = try std.fmt.allocPrint(allocator, "{s}/marker", .{root_path});
    defer allocator.free(marker_path);
    const spawned_path = try std.fmt.allocPrint(allocator, "{s}/spawned", .{root_path});
    defer allocator.free(spawned_path);
    const spawn_input_path = try std.fmt.allocPrint(allocator, "{s}/spawn-input", .{root_path});
    defer allocator.free(spawn_input_path);
    const spawn_error_path = try std.fmt.allocPrint(allocator, "{s}/spawn-error", .{root_path});
    defer allocator.free(spawn_error_path);
    const execed_path = try std.fmt.allocPrint(allocator, "{s}/execed", .{root_path});
    defer allocator.free(execed_path);

    const script = try std.fmt.allocPrint(
        allocator,
        \\local root = "{s}"
        \\local marker = "{s}"
        \\local spawned = "{s}"
        \\local spawn_input = "{s}"
        \\local spawn_error = "{s}"
        \\local execed = "{s}"
        \\assert(rpm.vercmp("6.0.rc1", "6.0") > 0)
        \\assert(posix.uname("%r") ~= nil)
        \\assert(posix.mkdir(root) == 0)
        \\assert(posix.mkdir(root .. "/dir") == 0)
        \\assert(posix.mkdir(root .. "/mode-dir", 448) == 0)
        \\local mode_dir = assert(posix.stat(root .. "/mode-dir"))
        \\assert((mode_dir.mode & 511) == 448)
        \\local f = io.open(marker, "w+")
        \\f:write("marker")
        \\f:close()
        \\assert(posix.utime(marker) == 0)
        \\assert(posix.chmod(marker, 365) == 0)
        \\local marker_stat = assert(posix.stat(marker))
        \\assert(marker_stat.type == "regular")
        \\assert((marker_stat.mode & 511) == 365)
        \\local missing, missing_message, missing_code =
        \\  posix.stat(root .. "/missing")
        \\assert(missing == nil and type(missing_message) == "string")
        \\assert(missing_code > 0)
        \\assert(posix.symlink("dir", root .. "/link") == 0)
        \\local st = posix.stat(root .. "/link")
        \\assert(st and st.type == "link")
        \\assert(posix.readlink(root .. "/link") == "dir")
        \\assert(posix.access(root .. "/dir", "x") == 0)
        \\local seen_dir = false
        \\for entry in posix.files(root) do
        \\  if entry == "dir" then
        \\    seen_dir = true
        \\  end
        \\end
        \\assert(seen_dir)
        \\local matches = rpm.glob(root .. "/d*")
        \\assert(matches[1] == root .. "/dir")
        \\local input = assert(io.open(spawn_input, "w+"))
        \\input:write("input\n")
        \\input:close()
        \\assert(rpm.spawn(
        \\  {{"/bin/sh", "-c",
        \\    "IFS= read -r line; echo spawned:$line; echo spawn-error >&2"}},
        \\  {{stdin = spawn_input, stdout = spawned, stderr = spawn_error}}
        \\) == 0)
        \\local spawn_result, spawn_message, spawn_code =
        \\  rpm.spawn({{"/bin/true"}}, {{invalid = marker}})
        \\assert(spawn_result == nil and type(spawn_message) == "string")
        \\assert(spawn_code > 0)
        \\local signal_result, signal_message, signal_code =
        \\  rpm.execute("/bin/sh", "-c", "kill -TERM $$")
        \\assert(signal_result == nil and signal_message == "exit signal")
        \\assert(signal_code == 15)
        \\assert(rpm.execute("/bin/sh", "-c", "printf execed > " .. execed) == 0)
        \\
    ,
        .{
            root_path,
            marker_path,
            spawned_path,
            spawn_input_path,
            spawn_error_path,
            execed_path,
        },
    );
    defer allocator.free(script);
    const script_data = try std.fmt.allocPrint(allocator, "{s}\x00", .{script});
    defer allocator.free(script_data);

    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.pretrans), .typ = 6, .count = 1, .data = script_data },
        .{ .tag = @intFromEnum(header.TagId.pretransprog), .typ = 6, .count = 1, .data = "<lua>\x00" },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    if (c.tdnf_rpmzig_lua_supported() == 0) {
        try std.testing.expectError(error.UnsupportedInterpreter, runHeaderScript(allocator, hdr, .pretrans, .{
            .install_root = "/",
        }));
        return;
    }

    const result = try runHeaderScript(allocator, hdr, .pretrans, .{
        .install_root = "/",
    });
    try std.testing.expect(result.ran);
    try std.testing.expectEqual(Outcome.ok, result.outcome);

    const spawned = try readAbsoluteFile(allocator, spawned_path);
    defer allocator.free(spawned);
    try std.testing.expectEqualStrings("spawned:input\n", spawned);

    const spawn_error = try readAbsoluteFile(allocator, spawn_error_path);
    defer allocator.free(spawn_error);
    try std.testing.expectEqualStrings("spawn-error\n", spawn_error);

    const execed = try readAbsoluteFile(allocator, execed_path);
    defer allocator.free(execed);
    try std.testing.expectEqualStrings("execed", execed);
}
