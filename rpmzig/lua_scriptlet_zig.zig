const std = @import("std");
const zlua = @import("zlua");

const c = @cImport({
    @cInclude("dirent.h");
    @cInclude("errno.h");
    @cInclude("glob.h");
    @cInclude("spawn.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/time.h");
    @cInclude("sys/utsname.h");
    @cInclude("sys/wait.h");
    @cInclude("unistd.h");
});

const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const spawn_o_rdonly: c_int = 0;
const spawn_o_wronly: c_int = 1;
const spawn_o_creat: c_int = 0o100;
const spawn_o_append: c_int = 0o2000;

extern var environ: [*:null]?[*:0]u8;

pub fn run(
    script: []const u8,
    arg1: c_int,
    arg2: c_int,
) c_int {
    return runLua(script, arg1, arg2) catch |err| {
        var message_buffer: [256]u8 = undefined;
        const message = std.fmt.bufPrint(
            &message_buffer,
            "lua setup failed: {s}\n",
            .{@errorName(err)},
        ) catch "lua setup failed\n";
        writeRawStderr(message);
        return 1;
    };
}

fn runLua(script: []const u8, arg1: c_int, arg2: c_int) !c_int {
    const allocator = std.heap.c_allocator;
    const stdin = try readStdin(allocator);
    defer allocator.free(stdin);
    try seekStdin(0);

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stdout_buffer: [4096]u8 = undefined;
    var stderr_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buffer);
    defer stdout_writer.flush() catch {};
    defer stderr_writer.flush() catch {};

    var stdin_bridge = StdinBridge{};
    var lua = try zlua.State.init(allocator, .{
        .stdlib = .full,
        .capabilities = .{
            .io = .{
                .runtime = io,
                .stdin = stdin,
                .stdout = &stdout_writer.interface,
                .stderr = &stderr_writer.interface,
            },
            .filesystem = .{ .custom = .{
                .read_file_alloc = filesystemReadFile,
                .write_file = filesystemWriteFile,
                .remove_file = filesystemRemoveFile,
                .rename_file = filesystemRenameFile,
            } },
            .environment = .{ .custom = .{ .get = environmentGet } },
            .clock = .system,
            .process = .{ .custom = .{
                .context = &stdin_bridge,
                .execute = executeShell,
            } },
        },
    });
    defer lua.deinit();
    stdin_bridge.lua = &lua;

    try lua.setGlobal("_VERSION", "Lua 5.4");
    try installHostModules(&lua);

    const source = try std.mem.concat(
        allocator,
        u8,
        &.{ "local opt, arg = ...;", script },
    );
    defer allocator.free(source);

    var chunk = lua.loadString(source, .{ .name = "<lua>" }) catch |err| {
        reportLuaError(
            &lua,
            &stderr_writer.interface,
            "invalid syntax in lua scriptlet: ",
            err,
        );
        return 1;
    };
    defer chunk.deinit();

    var opt = try lua.createTable(.{});
    defer opt.deinit();
    var arg = try lua.createTable(.{ .array_hint = 3 });
    defer arg.deinit();
    try arg.set(1, "<lua>");
    if (arg1 >= 0) try arg.set(2, @as(i64, arg1));
    if (arg2 >= 0) try arg.set(3, @as(i64, arg2));

    chunk.call(.{ opt, arg }, void) catch |err| {
        reportLuaError(
            &lua,
            &stderr_writer.interface,
            "lua script failed: ",
            err,
        );
        lua.closeOpenFiles() catch {};
        return 1;
    };
    lua.closeOpenFiles() catch |err| {
        reportLuaError(
            &lua,
            &stderr_writer.interface,
            "lua script failed: ",
            err,
        );
        return 1;
    };
    return 0;
}

fn installHostModules(lua: *zlua.State) !void {
    var rpm = try lua.createModule("rpm");
    defer rpm.deinit();
    try addFunction(lua, rpm, "execute", rpmExecute);
    try addFunction(lua, rpm, "input", rpmInput);
    try addFunction(lua, rpm, "next_file", rpmInput);
    try addFunction(lua, rpm, "next_line", rpmInput);
    try addFunction(lua, rpm, "spawn", rpmSpawn);
    try addFunction(lua, rpm, "glob", rpmGlob);
    try addFunction(lua, rpm, "vercmp", rpmVercmp);
    try lua.setGlobal("rpm", rpm);
    try lua.preloadModule("rpm", rpm);

    var posix = try lua.createModule("posix");
    defer posix.deinit();
    try addFunction(lua, posix, "access", posixAccess);
    try addFunction(lua, posix, "chmod", posixChmod);
    try addFunction(lua, posix, "dir", posixFilesEntries);
    try addFunction(lua, posix, "_files_entries", posixFilesEntries);
    try addFunction(lua, posix, "link", posixLink);
    try addFunction(lua, posix, "mkdir", posixMkdir);
    try addFunction(lua, posix, "readlink", posixReadlink);
    try addFunction(lua, posix, "rmdir", posixRmdir);
    try addFunction(lua, posix, "stat", posixStat);
    try addFunction(lua, posix, "symlink", posixSymlink);
    try addFunction(lua, posix, "uname", posixUname);
    try addFunction(lua, posix, "unlink", posixUnlink);
    try addFunction(lua, posix, "utime", posixUtime);
    try lua.setGlobal("posix", posix);
    try lua.preloadModule("posix", posix);

    var os = try lua.getGlobal("os", zlua.Table);
    defer os.deinit();
    try addFunction(lua, os, "exit", luaOsExit);

    try lua.doString(
        \\local host_spawn = rpm.spawn
        \\rpm.spawn = function(argv, actions)
        \\  if actions ~= nil then
        \\    for key in pairs(actions) do
        \\      if key ~= "stdin" and key ~= "stdout" and key ~= "stderr" then
        \\        return nil, "Invalid argument", 22
        \\      end
        \\    end
        \\  end
        \\  return host_spawn(argv, actions)
        \\end
        \\local files_entries = posix._files_entries
        \\posix._files_entries = nil
        \\posix.files = function(path)
        \\  local entries, message, code = files_entries(path)
        \\  if entries == nil then return nil, message, code end
        \\  local index = 0
        \\  return function()
        \\    index = index + 1
        \\    return entries[index]
        \\  end
        \\end
    , .{ .name = "=tdnf lua host wrappers" });
}

fn addFunction(
    lua: *zlua.State,
    module: zlua.Table,
    name: []const u8,
    callback: zlua.HostFn,
) !void {
    var function = try lua.register(name, callback);
    defer function.deinit();
    try module.set(name, function);
}

fn reportLuaError(
    lua: *zlua.State,
    writer: *std.Io.Writer,
    prefix: []const u8,
    err: anyerror,
) void {
    const allocated = lua.errorMessage() catch null;
    defer if (allocated) |message| lua.allocator().free(message);
    writer.print("{s}{s}\n", .{
        prefix,
        allocated orelse @errorName(err),
    }) catch {};
    writer.flush() catch {};
}

fn writeRawStderr(bytes: []const u8) void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = c.write(
            c.STDERR_FILENO,
            bytes.ptr + written,
            bytes.len - written,
        );
        if (count > 0) {
            written += @intCast(count);
            continue;
        }
        if (count < 0 and std.c.errno(count) == .INTR) continue;
        return;
    }
}

fn readStdin(allocator: Allocator) ![]u8 {
    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(allocator);

    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = c.read(c.STDIN_FILENO, &buffer, buffer.len);
        if (count > 0) {
            try bytes.appendSlice(allocator, buffer[0..@intCast(count)]);
            continue;
        }
        if (count == 0) break;
        if (std.c.errno(count) == .INTR) continue;
        return error.ReadFailed;
    }
    return bytes.toOwnedSlice(allocator);
}

fn filesystemReadFile(
    _: ?*anyopaque,
    allocator: Allocator,
    path: []const u8,
) ![]const u8 {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const open_rc = linux.openat(
        std.posix.AT.FDCWD,
        path_z.ptr,
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    );
    if (linux.errno(open_rc) != .SUCCESS) return error.OpenFailed;
    const fd: c_int = @intCast(open_rc);
    defer _ = linux.close(fd);

    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = linux.read(fd, &buffer, buffer.len);
        switch (linux.errno(count)) {
            .SUCCESS => {
                if (count == 0) break;
                try bytes.appendSlice(allocator, buffer[0..count]);
            },
            .INTR => continue,
            else => return error.ReadFailed,
        }
    }
    return bytes.toOwnedSlice(allocator);
}

fn filesystemWriteFile(
    _: ?*anyopaque,
    path: []const u8,
    contents: []const u8,
) !void {
    const allocator = std.heap.c_allocator;
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
        0o666,
    );
    if (linux.errno(open_rc) != .SUCCESS) return error.OpenFailed;
    const fd: c_int = @intCast(open_rc);
    defer _ = linux.close(fd);

    var written: usize = 0;
    while (written < contents.len) {
        const count = linux.write(fd, contents.ptr + written, contents.len - written);
        switch (linux.errno(count)) {
            .SUCCESS => {
                if (count == 0) return error.WriteFailed;
                written += count;
            },
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

fn filesystemRemoveFile(_: ?*anyopaque, path: []const u8) !void {
    const allocator = std.heap.c_allocator;
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    if (c.remove(path_z.ptr) != 0) return error.RemoveFailed;
}

fn filesystemRenameFile(
    _: ?*anyopaque,
    old_path: []const u8,
    new_path: []const u8,
) !void {
    const allocator = std.heap.c_allocator;
    const old_z = try allocator.dupeZ(u8, old_path);
    defer allocator.free(old_z);
    const new_z = try allocator.dupeZ(u8, new_path);
    defer allocator.free(new_z);
    if (c.rename(old_z.ptr, new_z.ptr) != 0) return error.RenameFailed;
}

threadlocal var environment_name_buffer: [4096]u8 = undefined;

fn environmentGet(_: ?*anyopaque, name: []const u8) ?[]const u8 {
    if (name.len >= environment_name_buffer.len) return null;
    @memcpy(environment_name_buffer[0..name.len], name);
    environment_name_buffer[name.len] = 0;
    const value = c.getenv(@ptrCast(&environment_name_buffer)) orelse return null;
    return std.mem.span(value);
}

fn rpmInput(ctx: *zlua.Context) !void {
    const line = try ctx.state().readStdinLine() orelse {
        try ctx.returnValues(@as(zlua.Value, .nil));
        return;
    };
    var end = line.len;
    while (end > 0 and line[end - 1] == '\r') {
        end -= 1;
    }
    try ctx.returnValues(line[0..end]);
}

fn luaOsExit(ctx: *zlua.Context) !void {
    var exit_code: c_int = 0;
    if (ctx.argCount() != 0) {
        var value = try ctx.arg(0, zlua.Value);
        defer value.deinit();
        exit_code = switch (value) {
            .nil => 0,
            .boolean => |success| if (success) 0 else 1,
            .integer => |code| @intCast(code),
            .number => |code| if (@trunc(code) == code)
                @intFromFloat(code)
            else
                return ctx.raise("exit code must be an integer or boolean"),
            else => return ctx.raise("exit code must be an integer or boolean"),
        };
    }
    const close_state = (try ctx.optionalArg(1, bool)) orelse false;
    if (close_state) {
        ctx.state().closeOpenFiles() catch c._exit(1);
    }
    ctx.state().flushIo() catch c._exit(1);
    c._exit(exit_code);
}

const StdinBridge = struct {
    lua: ?*zlua.State = null,

    fn beforeSpawn(self: *StdinBridge) !void {
        const lua = self.lua orelse return error.MissingLuaState;
        try seekStdin(try lua.stdinPosition());
    }

    fn afterSpawn(self: *StdinBridge) !void {
        const lua = self.lua orelse return error.MissingLuaState;
        try lua.setStdinPosition(try stdinPosition());
    }
};

fn seekStdin(pos: usize) !void {
    const rc = linux.lseek(c.STDIN_FILENO, @intCast(pos), c.SEEK_SET);
    if (linux.errno(rc) != .SUCCESS) return error.SeekFailed;
}

fn stdinPosition() !usize {
    const rc = linux.lseek(c.STDIN_FILENO, 0, c.SEEK_CUR);
    if (linux.errno(rc) != .SUCCESS) return error.SeekFailed;
    return rc;
}

fn executeShell(context: ?*anyopaque, command: []const u8) !zlua.ProcessResult {
    const stdin_bridge: *StdinBridge = @ptrCast(@alignCast(context orelse
        return error.MissingStdinBridge));
    const allocator = std.heap.c_allocator;
    const command_z = try allocator.dupeZ(u8, command);
    defer allocator.free(command_z);

    var argv = [_]?[*:0]const u8{
        "/bin/sh",
        "-c",
        command_z.ptr,
        null,
    };
    try stdin_bridge.beforeSpawn();
    var pid: c.pid_t = 0;
    const spawn_rc = c.posix_spawn(
        &pid,
        "/bin/sh",
        null,
        null,
        @ptrCast(&argv),
        @ptrCast(environ),
    );
    if (spawn_rc != 0) return error.SpawnFailed;

    var status: c_int = 0;
    while (c.waitpid(pid, &status, 0) < 0) {
        if (errnoValue() == c.EINTR) continue;
        return error.WaitFailed;
    }
    try stdin_bridge.afterSpawn();
    if (std.posix.W.IFSIGNALED(@bitCast(status))) {
        return .{
            .status = .signal,
            .code = @intFromEnum(std.posix.W.TERMSIG(@bitCast(status))),
        };
    }
    return .{
        .status = .exit,
        .code = std.posix.W.EXITSTATUS(@bitCast(status)),
    };
}

fn rpmExecute(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    var args = std.ArrayList([:0]u8).empty;
    defer freeStringList(allocator, &args);

    for (0..ctx.argCount()) |index| {
        const value = try ctx.arg(index, []const u8);
        try args.append(allocator, try allocator.dupeZ(u8, value));
    }
    if (args.items.len == 0) return ctx.raise("command not supplied");
    try spawnAndReturn(ctx, args.items, null);
}

fn rpmSpawn(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    var argv_table = try ctx.arg(0, zlua.Table);
    defer argv_table.deinit();

    var args = std.ArrayList([:0]u8).empty;
    defer freeStringList(allocator, &args);
    var index: i64 = 1;
    while (true) : (index += 1) {
        var value = try argv_table.get(index, zlua.Value);
        defer value.deinit();
        switch (value) {
            .nil => break,
            .string => |text| {
                try args.append(allocator, try allocator.dupeZ(u8, text));
            },
            else => return ctx.raise("command argument must be a string"),
        }
    }
    if (args.items.len == 0) return ctx.raise("command not supplied");

    var action_table = try ctx.optionalArg(1, zlua.Table);
    defer if (action_table) |*table| table.deinit();
    try spawnAndReturn(ctx, args.items, action_table);
}

fn spawnAndReturn(
    ctx: *zlua.Context,
    args: []const [:0]u8,
    action_table: ?zlua.Table,
) !void {
    const allocator = ctx.state().allocator();
    var stdin_bridge = StdinBridge{ .lua = ctx.state() };
    const argv = try allocator.alloc(?[*:0]const u8, args.len + 1);
    defer allocator.free(argv);
    for (args, 0..) |arg, index| argv[index] = arg.ptr;
    argv[args.len] = null;

    var actions: c.posix_spawn_file_actions_t = undefined;
    var actions_initialized = false;
    defer {
        if (actions_initialized) {
            _ = c.posix_spawn_file_actions_destroy(&actions);
        }
    }

    var action_paths = std.ArrayList([:0]u8).empty;
    defer freeStringList(allocator, &action_paths);
    if (action_table) |table| {
        const init_rc = c.posix_spawn_file_actions_init(&actions);
        if (init_rc != 0) {
            try pushError(ctx, init_rc, "spawn file action init");
            return;
        }
        actions_initialized = true;

        const specs = [_]struct {
            name: []const u8,
            fd: c_int,
            flags: c_int,
        }{
            .{ .name = "stdin", .fd = c.STDIN_FILENO, .flags = spawn_o_rdonly },
            .{
                .name = "stdout",
                .fd = c.STDOUT_FILENO,
                .flags = spawn_o_wronly | spawn_o_append | spawn_o_creat,
            },
            .{
                .name = "stderr",
                .fd = c.STDERR_FILENO,
                .flags = spawn_o_wronly | spawn_o_append | spawn_o_creat,
            },
        };
        for (specs) |spec| {
            const path = try table.get(spec.name, ?[]const u8) orelse continue;
            const path_z = try allocator.dupeZ(u8, path);
            try action_paths.append(allocator, path_z);
            const action_rc = c.posix_spawn_file_actions_addopen(
                &actions,
                spec.fd,
                path_z.ptr,
                spec.flags,
                @as(c.mode_t, 0o644),
            );
            if (action_rc != 0) {
                try pushError(ctx, action_rc, null);
                return;
            }
        }
    }

    try stdin_bridge.beforeSpawn();
    var pid: c.pid_t = 0;
    const spawn_rc = c.posix_spawnp(
        &pid,
        args[0].ptr,
        if (actions_initialized) &actions else null,
        null,
        @ptrCast(argv.ptr),
        @ptrCast(environ),
    );
    if (spawn_rc != 0) {
        try pushError(ctx, spawn_rc, null);
        return;
    }

    var status: c_int = 0;
    while (c.waitpid(pid, &status, 0) < 0) {
        const code = errnoValue();
        if (code == c.EINTR) continue;
        try pushError(ctx, code, null);
        return;
    }
    try stdin_bridge.afterSpawn();
    if (std.posix.W.IFSIGNALED(@bitCast(status))) {
        try pushError(
            ctx,
            @intCast(@intFromEnum(std.posix.W.TERMSIG(@bitCast(status)))),
            "exit signal",
        );
        return;
    }
    const exit_code: c_int = std.posix.W.EXITSTATUS(@bitCast(status));
    if (exit_code != 0) {
        try pushError(ctx, exit_code, "exit code");
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn rpmGlob(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const pattern = try ctx.arg(0, []const u8);
    const pattern_z = try allocator.dupeZ(u8, pattern);
    defer allocator.free(pattern_z);

    var matches: c.glob_t = std.mem.zeroes(c.glob_t);
    const rc = c.glob(pattern_z.ptr, c.GLOB_NOCHECK, null, &matches);
    if (rc != 0 and rc != c.GLOB_NOMATCH) {
        return ctx.raise("glob failed");
    }
    defer c.globfree(&matches);

    var result = try ctx.state().createTable(.{
        .array_hint = @intCast(matches.gl_pathc),
    });
    defer result.deinit();
    for (0..matches.gl_pathc) |index| {
        try result.set(
            @as(i64, @intCast(index + 1)),
            std.mem.span(matches.gl_pathv[index]),
        );
    }
    try ctx.returnValues(result);
}

fn rpmVercmp(ctx: *zlua.Context) !void {
    const left = try ctx.arg(0, []const u8);
    const right = try ctx.arg(1, []const u8);
    try ctx.returnValues(@as(i64, compareEvr(left, right)));
}

fn posixAccess(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const mode_text = try ctx.optionalArg(1, []const u8);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    var mode: c_int = c.F_OK;
    if (mode_text) |text| {
        mode = 0;
        if (std.mem.indexOfScalar(u8, text, 'r') != null) mode |= c.R_OK;
        if (std.mem.indexOfScalar(u8, text, 'w') != null) mode |= c.W_OK;
        if (std.mem.indexOfScalar(u8, text, 'x') != null) mode |= c.X_OK;
        if (mode == 0) mode = c.F_OK;
    }
    if (c.access(path_z.ptr, mode) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn posixChmod(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    var stat: c.struct_stat = std.mem.zeroes(c.struct_stat);
    if (c.stat(path_z.ptr, &stat) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    const mode = try parseModeArgument(ctx, 1, stat.st_mode);
    if (c.chmod(path_z.ptr, mode) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn posixMkdir(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const mode = (try ctx.optionalArg(1, i64)) orelse 0o777;
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    if (c.mkdir(path_z.ptr, @intCast(mode)) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn posixReadlink(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    var buffer: [4096]u8 = undefined;
    const length = linux.readlink(path_z.ptr, &buffer, buffer.len);
    const readlink_error = linux.errno(length);
    if (readlink_error != .SUCCESS) {
        try pushError(ctx, @intCast(@intFromEnum(readlink_error)), null);
        return;
    }
    try ctx.returnValues(buffer[0..length]);
}

fn posixLink(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const old_path = try ctx.arg(0, []const u8);
    const new_path = try ctx.arg(1, []const u8);
    const old_z = try allocator.dupeZ(u8, old_path);
    defer allocator.free(old_z);
    const new_z = try allocator.dupeZ(u8, new_path);
    defer allocator.free(new_z);
    if (c.link(old_z.ptr, new_z.ptr) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn posixRmdir(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    if (c.rmdir(path_z.ptr) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn posixStat(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    var stat: c.struct_stat = std.mem.zeroes(c.struct_stat);
    if (c.lstat(path_z.ptr, &stat) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }

    var mode_buffer: [9]u8 = undefined;
    statModeString(stat.st_mode, &mode_buffer);
    if (try ctx.optionalArg(1, []const u8)) |selector| {
        if (std.mem.eql(u8, selector, "mode")) {
            try ctx.returnValues(mode_buffer[0..]);
        } else if (std.mem.eql(u8, selector, "ino")) {
            try ctx.returnValues(@as(f64, @floatFromInt(stat.st_ino)));
        } else if (std.mem.eql(u8, selector, "dev")) {
            try ctx.returnValues(@as(f64, @floatFromInt(stat.st_dev)));
        } else if (std.mem.eql(u8, selector, "nlink")) {
            try ctx.returnValues(@as(i64, @intCast(stat.st_nlink)));
        } else if (std.mem.eql(u8, selector, "uid")) {
            try ctx.returnValues(@as(i64, @intCast(stat.st_uid)));
        } else if (std.mem.eql(u8, selector, "gid")) {
            try ctx.returnValues(@as(i64, @intCast(stat.st_gid)));
        } else if (std.mem.eql(u8, selector, "size")) {
            try ctx.returnValues(@as(i64, @intCast(stat.st_size)));
        } else if (std.mem.eql(u8, selector, "atime")) {
            try ctx.returnValues(@as(i64, @intCast(stat.st_atim.tv_sec)));
        } else if (std.mem.eql(u8, selector, "mtime")) {
            try ctx.returnValues(@as(i64, @intCast(stat.st_mtim.tv_sec)));
        } else if (std.mem.eql(u8, selector, "ctime")) {
            try ctx.returnValues(@as(i64, @intCast(stat.st_ctim.tv_sec)));
        } else if (std.mem.eql(u8, selector, "type")) {
            try ctx.returnValues(statType(stat.st_mode));
        } else if (std.mem.eql(u8, selector, "_mode")) {
            try ctx.returnValues(@as(i64, @intCast(stat.st_mode)));
        } else {
            return ctx.raise("unknown stat selector");
        }
        return;
    }

    var result = try ctx.state().createTable(.{ .hash_hint = 12 });
    defer result.deinit();
    try result.set("mode", mode_buffer[0..]);
    try result.set("ino", @as(f64, @floatFromInt(stat.st_ino)));
    try result.set("dev", @as(f64, @floatFromInt(stat.st_dev)));
    try result.set("nlink", @as(i64, @intCast(stat.st_nlink)));
    try result.set("uid", @as(i64, @intCast(stat.st_uid)));
    try result.set("gid", @as(i64, @intCast(stat.st_gid)));
    try result.set("size", @as(i64, @intCast(stat.st_size)));
    try result.set("atime", @as(i64, @intCast(stat.st_atim.tv_sec)));
    try result.set("mtime", @as(i64, @intCast(stat.st_mtim.tv_sec)));
    try result.set("ctime", @as(i64, @intCast(stat.st_ctim.tv_sec)));
    try result.set("type", statType(stat.st_mode));
    try result.set("_mode", @as(i64, @intCast(stat.st_mode)));
    try ctx.returnValues(result);
}

fn posixSymlink(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const target = try ctx.arg(0, []const u8);
    const path = try ctx.arg(1, []const u8);
    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    if (c.symlink(target_z.ptr, path_z.ptr) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn posixUname(ctx: *zlua.Context) !void {
    var uts: c.struct_utsname = std.mem.zeroes(c.struct_utsname);
    if (c.uname(&uts) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }

    const sysname = cArraySlice(&uts.sysname);
    const nodename = cArraySlice(&uts.nodename);
    const release = cArraySlice(&uts.release);
    const version = cArraySlice(&uts.version);
    const machine = cArraySlice(&uts.machine);
    const format = try ctx.optionalArg(0, []const u8);
    if (format == null) {
        var result = try ctx.state().createTable(.{ .hash_hint = 5 });
        defer result.deinit();
        try result.set("sysname", sysname);
        try result.set("nodename", nodename);
        try result.set("release", release);
        try result.set("version", version);
        try result.set("machine", machine);
        try ctx.returnValues(result);
        return;
    }

    const allocator = ctx.state().allocator();
    var output = std.ArrayList(u8).empty;
    defer output.deinit(allocator);
    var index: usize = 0;
    while (index < format.?.len) : (index += 1) {
        if (format.?[index] != '%' or index + 1 >= format.?.len) {
            try output.append(allocator, format.?[index]);
            continue;
        }
        index += 1;
        const value: ?[]const u8 = switch (format.?[index]) {
            's' => sysname,
            'n' => nodename,
            'r' => release,
            'v' => version,
            'm' => machine,
            else => null,
        };
        if (value) |text| {
            try output.appendSlice(allocator, text);
        } else {
            try output.append(allocator, '%');
            try output.append(allocator, format.?[index]);
        }
    }
    try ctx.returnValues(output.items);
}

fn posixUnlink(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    if (c.unlink(path_z.ptr) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn posixUtime(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    if (c.utimes(path_z.ptr, null) != 0) {
        try pushError(ctx, errnoValue(), null);
        return;
    }
    try ctx.returnValues(@as(i64, 0));
}

fn posixFilesEntries(ctx: *zlua.Context) !void {
    const allocator = ctx.state().allocator();
    const path = try ctx.arg(0, []const u8);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const dir = c.opendir(path_z.ptr) orelse {
        try pushError(ctx, errnoValue(), null);
        return;
    };
    defer _ = c.closedir(dir);

    var entries = try ctx.state().createTable(.{});
    defer entries.deinit();
    var index: i64 = 1;
    while (true) {
        std.c._errno().* = 0;
        const entry = c.readdir(dir) orelse {
            const code = errnoValue();
            if (code != 0) {
                try pushError(ctx, code, "readdir failed");
                return;
            }
            break;
        };
        try entries.set(index, cArraySlice(entry.*.d_name[0..]));
        index += 1;
    }
    try ctx.returnValues(entries);
}

fn pushError(ctx: *zlua.Context, code: c_int, info: ?[]const u8) !void {
    const message = info orelse blk: {
        const raw = c.strerror(code);
        break :blk if (raw == null) "unknown error" else std.mem.span(raw);
    };
    try ctx.returnValues(.{
        @as(zlua.Value, .nil),
        message,
        @as(i64, code),
    });
}

fn errnoValue() c_int {
    return std.c._errno().*;
}

fn freeStringList(
    allocator: Allocator,
    strings: *std.ArrayList([:0]u8),
) void {
    for (strings.items) |string| allocator.free(string);
    strings.deinit(allocator);
}

fn statType(mode: c.mode_t) []const u8 {
    return switch (mode & c.S_IFMT) {
        c.S_IFREG => "regular",
        c.S_IFDIR => "directory",
        c.S_IFLNK => "link",
        c.S_IFCHR => "character device",
        c.S_IFBLK => "block device",
        c.S_IFIFO => "fifo",
        c.S_IFSOCK => "socket",
        else => "unknown",
    };
}

fn parseModeArgument(
    ctx: *zlua.Context,
    index: usize,
    initial_mode: c.mode_t,
) !c.mode_t {
    var value = try ctx.arg(index, zlua.Value);
    defer value.deinit();
    var buffer: [64]u8 = undefined;
    const text = switch (value) {
        .string => |string| string,
        .integer => |integer| std.fmt.bufPrint(&buffer, "{d}", .{integer}) catch
            return ctx.raise("bad mode"),
        .number => |number| blk: {
            if (@trunc(number) != number) return ctx.raise("bad mode");
            break :blk std.fmt.bufPrint(&buffer, "{d}", .{
                @as(i64, @intFromFloat(number)),
            }) catch return ctx.raise("bad mode");
        },
        else => return ctx.raise("mode must be a string or number"),
    };
    return parseMode(text, initial_mode) orelse ctx.raise("bad mode");
}

fn parseMode(text: []const u8, initial_mode: c.mode_t) ?c.mode_t {
    if (text.len == 0) return null;
    if (text[0] >= '0' and text[0] <= '7') {
        return std.fmt.parseInt(c.mode_t, text, 8) catch null;
    }
    if (text.len == 9 and (text[0] == 'r' or text[0] == '-')) {
        const clear_mask: c.mode_t = c.S_ISUID | c.S_ISGID | 0o777;
        var mode = initial_mode & ~clear_mask;
        const bits = [_]c.mode_t{
            c.S_IRUSR, c.S_IWUSR, c.S_IXUSR,
            c.S_IRGRP, c.S_IWGRP, c.S_IXGRP,
            c.S_IROTH, c.S_IWOTH, c.S_IXOTH,
        };
        const chars = "rwxrwxrwx";
        for (text, 0..) |char, index| {
            if (char == chars[index]) {
                mode |= bits[index];
            } else if (char == 's' and index == 2) {
                mode |= c.S_ISUID | c.S_IXUSR;
            } else if (char == 's' and index == 5) {
                mode |= c.S_ISGID | c.S_IXGRP;
            } else if (char != '-') {
                return null;
            }
        }
        return mode;
    }
    return parseSymbolicMode(text, initial_mode);
}

fn parseSymbolicMode(text: []const u8, initial_mode: c.mode_t) ?c.mode_t {
    var mode = initial_mode;
    var clauses = std.mem.splitScalar(u8, text, ',');
    while (clauses.next()) |clause| {
        var index: usize = 0;
        var affected: c.mode_t = 0;
        while (index < clause.len) : (index += 1) {
            affected |= switch (clause[index]) {
                'u' => 0o4700,
                'g' => 0o2070,
                'o' => 0o1007,
                'a' => 0o7777,
                ' ' => continue,
                else => break,
            };
        }
        if (affected == 0) affected = 0o7777;
        if (index >= clause.len) return null;
        const operation = clause[index];
        if (operation != '+' and operation != '-' and operation != '=') {
            return null;
        }
        index += 1;
        var changes: c.mode_t = 0;
        while (index < clause.len) : (index += 1) {
            changes |= switch (clause[index]) {
                'r' => 0o444,
                'w' => 0o222,
                'x' => 0o111,
                's' => 0o6000,
                ' ' => continue,
                else => return null,
            };
        }
        const selected = changes & affected;
        switch (operation) {
            '+' => mode |= selected,
            '-' => mode &= ~@as(c.mode_t, selected),
            '=' => {
                mode &= ~@as(c.mode_t, affected);
                mode |= selected;
            },
            else => unreachable,
        }
    }
    return mode;
}

fn statModeString(mode: c.mode_t, output: *[9]u8) void {
    const bits = [_]c.mode_t{
        c.S_IRUSR, c.S_IWUSR, c.S_IXUSR,
        c.S_IRGRP, c.S_IWGRP, c.S_IXGRP,
        c.S_IROTH, c.S_IWOTH, c.S_IXOTH,
    };
    const chars = "rwxrwxrwx";
    for (bits, 0..) |bit, index| {
        output[index] = if (mode & bit != 0) chars[index] else '-';
    }
    if (mode & c.S_ISUID != 0) output[2] = if (mode & c.S_IXUSR != 0) 's' else 'S';
    if (mode & c.S_ISGID != 0) output[5] = if (mode & c.S_IXGRP != 0) 's' else 'S';
}

fn cArraySlice(array: []const u8) []const u8 {
    const length = std.mem.indexOfScalar(u8, array, 0) orelse array.len;
    return array[0..length];
}

fn compareEvr(left: []const u8, right: []const u8) i32 {
    const left_parts = splitEvr(left);
    const right_parts = splitEvr(right);
    if (left_parts.epoch < right_parts.epoch) return -1;
    if (left_parts.epoch > right_parts.epoch) return 1;
    const version = compareVersion(left_parts.version, right_parts.version);
    if (version != 0) return version;
    return compareVersion(left_parts.release, right_parts.release);
}

const Evr = struct {
    epoch: u32 = 0,
    version: []const u8 = "",
    release: []const u8 = "",
};

fn splitEvr(value: []const u8) Evr {
    var result = Evr{};
    var body = value;
    if (std.mem.indexOfScalar(u8, value, ':')) |colon| {
        if (colon != 0) {
            if (std.fmt.parseInt(u32, value[0..colon], 10)) |epoch| {
                result.epoch = epoch;
                body = value[colon + 1 ..];
            } else |_| {}
        }
    }
    if (std.mem.lastIndexOfScalar(u8, body, '-')) |dash| {
        if (dash != 0 and dash + 1 < body.len) {
            result.version = body[0..dash];
            result.release = body[dash + 1 ..];
            return result;
        }
    }
    result.version = body;
    return result;
}

fn compareVersion(left_raw: []const u8, right_raw: []const u8) i32 {
    var left = left_raw;
    var right = right_raw;
    while (true) {
        while (left.len != 0 and !isVersionToken(left[0])) left = left[1..];
        while (right.len != 0 and !isVersionToken(right[0])) right = right[1..];

        if ((left.len != 0 and left[0] == '~') or
            (right.len != 0 and right[0] == '~'))
        {
            if (left.len == 0 or left[0] != '~') return 1;
            if (right.len == 0 or right[0] != '~') return -1;
            left = left[1..];
            right = right[1..];
            continue;
        }
        if ((left.len != 0 and left[0] == '^') or
            (right.len != 0 and right[0] == '^'))
        {
            if (left.len == 0) return -1;
            if (right.len == 0) return 1;
            if (left[0] != '^') return 1;
            if (right[0] != '^') return -1;
            left = left[1..];
            right = right[1..];
            continue;
        }
        if (left.len == 0 and right.len == 0) return 0;
        if (left.len == 0) return -1;
        if (right.len == 0) return 1;

        const left_digit = std.ascii.isDigit(left[0]);
        const right_digit = std.ascii.isDigit(right[0]);
        if (left_digit != right_digit) return if (left_digit) 1 else -1;

        const left_end = tokenEnd(left, left_digit);
        const right_end = tokenEnd(right, right_digit);
        var left_token = left[0..left_end];
        var right_token = right[0..right_end];
        left = left[left_end..];
        right = right[right_end..];
        if (left_digit) {
            left_token = std.mem.trimStart(u8, left_token, "0");
            right_token = std.mem.trimStart(u8, right_token, "0");
            if (left_token.len < right_token.len) return -1;
            if (left_token.len > right_token.len) return 1;
        }
        const order = std.mem.order(u8, left_token, right_token);
        if (order != .eq) return if (order == .lt) -1 else 1;
    }
}

fn isVersionToken(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '~' or byte == '^';
}

fn tokenEnd(value: []const u8, digits: bool) usize {
    var end: usize = 0;
    while (end < value.len and
        (if (digits)
            std.ascii.isDigit(value[end])
        else
            std.ascii.isAlphabetic(value[end]))) : (end += 1)
    {}
    return end;
}
