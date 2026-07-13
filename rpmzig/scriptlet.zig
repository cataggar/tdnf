const std = @import("std");
const header = @import("rpm_header");
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

const RPMTRANS_FLAG_NOSCRIPTS: u32 = 1 << 2;
const RPMTRANS_FLAG_NOPRE: u32 = 1 << 17;
const RPMTRANS_FLAG_NOPOST: u32 = 1 << 18;
const RPMTRANS_FLAG_NOPREUN: u32 = 1 << 21;
const RPMTRANS_FLAG_NOPOSTUN: u32 = 1 << 22;
const RPMTRANS_FLAG_NOPRETRANS: u32 = 1 << 24;
const RPMTRANS_FLAG_NOPOSTTRANS: u32 = 1 << 25;

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
    trans_flags: u32 = 0,
    rpmdefines: []const []const u8 = &.{},
    arg1: ?i32 = null,
    arg2: ?i32 = null,
    script_fd: ?c_int = null,
    redirect_stdout_to_stderr: bool = false,
};

pub const RunError = Allocator.Error ||
    txn_config.InitError ||
    txn_config.ParseDefineError ||
    txn_config.SetMacroError ||
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
            .skip_flag = RPMTRANS_FLAG_NOPRE,
            .critical = true,
        },
        .post => .{
            .name = "%post",
            .script_tag = @intFromEnum(header.TagId.postin),
            .prog_tag = @intFromEnum(header.TagId.postinprog),
            .skip_flag = RPMTRANS_FLAG_NOPOST,
            .critical = false,
        },
        .preun => .{
            .name = "%preun",
            .script_tag = @intFromEnum(header.TagId.preun),
            .prog_tag = @intFromEnum(header.TagId.preunprog),
            .skip_flag = RPMTRANS_FLAG_NOPREUN,
            .critical = true,
        },
        .postun => .{
            .name = "%postun",
            .script_tag = @intFromEnum(header.TagId.postun),
            .prog_tag = @intFromEnum(header.TagId.postunprog),
            .skip_flag = RPMTRANS_FLAG_NOPOSTUN,
            .critical = false,
        },
        .pretrans => .{
            .name = "%pretrans",
            .script_tag = @intFromEnum(header.TagId.pretrans),
            .prog_tag = @intFromEnum(header.TagId.pretransprog),
            .skip_flag = RPMTRANS_FLAG_NOPRETRANS,
            .critical = true,
        },
        .posttrans => .{
            .name = "%posttrans",
            .script_tag = @intFromEnum(header.TagId.posttrans),
            .prog_tag = @intFromEnum(header.TagId.posttransprog),
            .skip_flag = RPMTRANS_FLAG_NOPOSTTRANS,
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
    if ((options.trans_flags & RPMTRANS_FLAG_NOSCRIPTS) != 0 or
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
    var config = try txn_config.TxnConfig.init(allocator, options.install_root);
    defer config.deinit();

    for (options.rpmdefines) |define| {
        _ = try config.applyRpmDefine(define);
    }

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
        return try runLuaScriptProcess(allocator, &config, body, critical, options);
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var script_file: ?TempScript = null;
    defer {
        if (script_file) |temp| {
            const host_z = arena_alloc.dupeZ(u8, temp.host_path) catch null;
            if (host_z) |path_z| {
                _ = linux.unlink(path_z.ptr);
            }
        }
    }

    var argv = std.ArrayList(?[*:0]const u8).empty;
    defer argv.deinit(arena_alloc);

    for (interpreter) |arg| {
        const arg_z = try arena_alloc.dupeZ(u8, arg);
        try argv.append(arena_alloc, arg_z.ptr);
    }

    if (script_body) |body| {
        script_file = try writeTempScript(arena_alloc, &config, body);
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

    const path_env = try arena_alloc.dupeZ(u8, config.value(.install_script_path));
    const install_root_z = try arena_alloc.dupeZ(u8, config.installRoot());

    const pid = c.fork();
    if (pid < 0) {
        return error.SyscallFailed;
    }
    if (pid == 0) {
        runExecChild(
            argv.items.ptr,
            path_env.ptr,
            install_root_z.ptr,
            options.script_fd orelse -1,
            options.redirect_stdout_to_stderr,
        );
    }

    return waitForChild(pid, critical);
}

fn runLuaScriptProcess(
    allocator: Allocator,
    config: *const txn_config.TxnConfig,
    body: []const u8,
    critical: bool,
    options: Options,
) RunError!Result {
    const path_env = try allocator.dupeZ(u8, config.value(.install_script_path));
    const install_root_z = try allocator.dupeZ(u8, config.installRoot());

    const pid = c.fork();
    if (pid < 0) {
        return error.SyscallFailed;
    }
    if (pid == 0) {
        runLuaChild(
            body.ptr,
            body.len,
            path_env.ptr,
            install_root_z.ptr,
            options.arg1 orelse -1,
            options.arg2 orelse -1,
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
    host_path: []const u8,
    exec_path: []const u8,
};

fn writeTempScript(
    allocator: Allocator,
    config: *const txn_config.TxnConfig,
    body: []const u8,
) RunError!TempScript {
    var host_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const host_dir = config.resolvePath(.tmppath, &host_dir_buf) catch return error.PathTooLong;
    try ensureDirPathAbsolute(allocator, host_dir);

    const exec_dir = config.value(.tmppath);

    var attempts: usize = 0;
    while (attempts < 16) : (attempts += 1) {
        const token = (@as(u64, @intCast(c.time(null))) << 32) ^
            (@as(u64, @intCast(c.getpid())) << 16) ^
            @as(u64, attempts);
        const filename = try std.fmt.allocPrint(allocator, "tdnf-scriptlet-{x}", .{token});
        const host_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ host_dir, filename });
        const exec_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ exec_dir, filename });
        const host_path_z = try allocator.dupeZ(u8, host_path);
        defer allocator.free(host_path_z);

        const open_rc = linux.openat(
            std.posix.AT.FDCWD,
            host_path_z.ptr,
            .{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .EXCL = true,
                .CLOEXEC = true,
            },
            0o700,
        );
        switch (std.posix.errno(open_rc)) {
            .SUCCESS => {},
            .EXIST => continue,
            else => return error.SyscallFailed,
        }
        const fd: c_int = @intCast(open_rc);
        errdefer _ = linux.unlink(host_path_z.ptr);

        if (writeAll(fd, body) != 0) {
            _ = linux.close(fd);
            return error.SyscallFailed;
        }
        if (std.posix.errno(linux.close(fd)) != .SUCCESS) {
            return error.SyscallFailed;
        }

        return .{
            .host_path = host_path,
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
    install_root: [*:0]u8,
    script_fd: c_int,
    redirect_stdout_to_stderr: bool,
) bool {
    const null_rc = linux.openat(
        std.posix.AT.FDCWD,
        "/dev/null",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    );
    if (std.posix.errno(null_rc) == .SUCCESS) {
        const null_fd: c_int = @intCast(null_rc);
        _ = linux.dup2(null_fd, c.STDIN_FILENO);
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

    if (!std.mem.eql(u8, std.mem.span(install_root), "/")) {
        if (std.posix.errno(linux.chroot(install_root)) != .SUCCESS) {
            return false;
        }
    }
    if (std.posix.errno(linux.chdir("/")) != .SUCCESS) {
        return false;
    }

    return true;
}

fn runExecChild(
    argv: [*]const ?[*:0]const u8,
    path_env: [*:0]u8,
    install_root: [*:0]u8,
    script_fd: c_int,
    redirect_stdout_to_stderr: bool,
) noreturn {
    if (!prepareChildProcess(path_env, install_root, script_fd, redirect_stdout_to_stderr)) {
        c._exit(127);
    }

    _ = c.execv(argv[0].?, @ptrCast(argv));
    c._exit(127);
}

fn runLuaChild(
    script_ptr: [*]const u8,
    script_len: usize,
    path_env: [*:0]u8,
    install_root: [*:0]u8,
    arg1: c_int,
    arg2: c_int,
    script_fd: c_int,
    redirect_stdout_to_stderr: bool,
) noreturn {
    if (!prepareChildProcess(path_env, install_root, script_fd, redirect_stdout_to_stderr)) {
        c._exit(127);
    }

    const rc = c.tdnf_rpmzig_lua_run(script_ptr, script_len, arg1, arg2);
    c._exit(if (rc == 0) 0 else 1);
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
    const execed_path = try std.fmt.allocPrint(allocator, "{s}/execed", .{root_path});
    defer allocator.free(execed_path);

    const script = try std.fmt.allocPrint(
        allocator,
        \\local root = "{s}"
        \\local marker = "{s}"
        \\local spawned = "{s}"
        \\local execed = "{s}"
        \\assert(rpm.vercmp("6.0.rc1", "6.0") > 0)
        \\assert(posix.uname("%r") ~= nil)
        \\assert(posix.mkdir(root) == 0)
        \\assert(posix.mkdir(root .. "/dir") == 0)
        \\local f = io.open(marker, "w+")
        \\f:write("marker")
        \\f:close()
        \\assert(posix.utime(marker) == 0)
        \\assert(posix.chmod(marker, 0555) == 0)
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
        \\assert(rpm.spawn({{"/bin/sh", "-c", "printf spawned"}}, {{stdout = spawned}}) == 0)
        \\assert(rpm.execute("/bin/sh", "-c", "printf execed > " .. execed) == 0)
        \\
    ,
        .{ root_path, marker_path, spawned_path, execed_path },
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
    try std.testing.expectEqualStrings("spawned", spawned);

    const execed = try readAbsoluteFile(allocator, execed_path);
    defer allocator.free(execed);
    try std.testing.expectEqualStrings("execed", execed);
}
