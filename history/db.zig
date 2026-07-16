const std = @import("std");
const sqlite = @import("sqlite");

pub const busy_timeout_ms: c_int = 5000;

pub const Error = sqlite.Error || error{
    BusyTimeoutFailed,
    OutOfMemory,
    SyscallFailed,
    UnsafePath,
};

pub const Database = struct {
    raw: sqlite.Database,
    dir_fd: c_int,

    pub fn init(path: [*:0]const u8) Error!Database {
        const path_slice = std.mem.span(path);
        const slash = std.mem.lastIndexOfScalar(u8, path_slice, '/');
        const absolute = path_slice.len != 0 and path_slice[0] == '/';
        const parent_start: usize = if (absolute) 1 else 0;
        const parent_path = if (slash) |index|
            if (index <= parent_start)
                ""
            else
                path_slice[parent_start..index]
        else
            "";
        const basename = if (slash) |index|
            path_slice[index + 1 ..]
        else
            path_slice;
        if (basename.len == 0 or
            std.mem.indexOfScalar(u8, basename, '/') != null)
        {
            return error.UnsafePath;
        }
        const start_fd = std.c.open(if (absolute) "/" else ".", .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        });
        if (start_fd < 0) return error.SyscallFailed;
        var dir_fd = start_fd;
        errdefer _ = std.c.close(dir_fd);
        var components = std.mem.splitScalar(u8, parent_path, '/');
        while (components.next()) |component| {
            if (component.len == 0 or
                std.mem.eql(u8, component, ".") or
                std.mem.eql(u8, component, ".."))
            {
                return error.UnsafePath;
            }
            const component_z = try std.heap.c_allocator.dupeZ(
                u8,
                component,
            );
            defer std.heap.c_allocator.free(component_z);
            const next_fd = std.c.openat(dir_fd, component_z.ptr, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            });
            if (next_fd < 0) return error.UnsafePath;
            _ = std.c.close(dir_fd);
            dir_fd = next_fd;
        }
        const pinned_path = try std.fmt.allocPrintSentinel(
            std.heap.c_allocator,
            "/proc/self/fd/{d}/{s}",
            .{ dir_fd, basename },
            0,
        );
        defer std.heap.c_allocator.free(pinned_path);
        var db = Database{
            .raw = try sqlite.Database.open(.{
                .path = pinned_path,
                .mode = .ReadWrite,
                .create = true,
            }),
            .dir_fd = dir_fd,
        };
        errdefer db.raw.close();
        try db.busyTimeout(busy_timeout_ms);
        return db;
    }

    pub fn fromPtr(ptr: ?*sqlite.c.sqlite3) Database {
        return .{
            .raw = .{ .ptr = ptr },
            .dir_fd = -1,
        };
    }

    pub fn close(self: Database) void {
        self.raw.close();
        if (self.dir_fd >= 0) _ = std.c.close(self.dir_fd);
    }

    pub fn busyTimeout(self: Database, milliseconds: c_int) Error!void {
        const rc = sqlite.c.sqlite3_busy_timeout(self.raw.ptr, milliseconds);
        if (rc != sqlite.c.SQLITE_OK) {
            return error.BusyTimeoutFailed;
        }
    }

    pub fn lastInsertRowId(self: Database) i64 {
        return sqlite.c.sqlite3_last_insert_rowid(self.raw.ptr);
    }

    pub fn begin(self: Database) !void {
        try self.raw.exec("BEGIN TRANSACTION;", .{});
    }

    pub fn commit(self: Database) !void {
        try self.raw.exec("COMMIT;", .{});
    }

    pub fn rollback(self: Database) !void {
        try self.raw.exec("ROLLBACK;", .{});
    }

    pub fn exec(self: Database, sql: []const u8, params: anytype) !void {
        try self.raw.exec(sql, params);
    }

    pub inline fn prepare(
        self: Database,
        comptime Params: type,
        comptime Result: type,
        sql: []const u8,
    ) !sqlite.Statement(Params, Result) {
        return self.raw.prepare(Params, Result, sql);
    }

    pub fn errmsg(self: Database) []const u8 {
        return if (self.raw.errmsg()) |msg| std.mem.span(msg) else "";
    }
};

pub fn dupeZ(bytes: []const u8) ![*:0]u8 {
    return (try std.heap.c_allocator.dupeZ(u8, bytes)).ptr;
}

pub fn freeZ(value: ?[*:0]u8) void {
    if (value) |ptr| {
        std.heap.c_allocator.free(std.mem.span(ptr));
    }
}

pub fn textFromPtr(value: ?[*:0]const u8) ?sqlite.Text {
    return if (value) |ptr| sqlite.text(std.mem.span(ptr)) else null;
}

pub fn dupeOptionalText(value: ?sqlite.Text) !?[*:0]u8 {
    return if (value) |text| try dupeZ(text.data) else null;
}

pub fn errorToRc(err: anyerror) c_int {
    return switch (err) {
        else => -1,
    };
}

pub fn errorToDwError(err: anyerror) u32 {
    return switch (err) {
        else => 1,
    };
}

test "history database stays in pinned no-follow parent" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "root/db");
    try tmp.dir.createDirPath(std.testing.io, "outside");
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_len = try std.process.currentPath(std.testing.io, &cwd_buf);
    const cwd = cwd_buf[0..cwd_len];
    const base = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ cwd, tmp.sub_path },
    );
    defer allocator.free(base);
    const db_dir = try std.fmt.allocPrint(
        allocator,
        "{s}/root/db",
        .{base},
    );
    defer allocator.free(db_dir);
    const parked = try std.fmt.allocPrint(
        allocator,
        "{s}/root/parked",
        .{base},
    );
    defer allocator.free(parked);
    const outside = try std.fmt.allocPrint(
        allocator,
        "{s}/outside",
        .{base},
    );
    defer allocator.free(outside);
    const db_path = try std.fmt.allocPrintSentinel(
        allocator,
        "{s}/history.db",
        .{db_dir},
        0,
    );
    defer allocator.free(db_path);
    var database = try Database.init(db_path.ptr);
    const db_dir_z = try allocator.dupeZ(u8, db_dir);
    defer allocator.free(db_dir_z);
    const parked_z = try allocator.dupeZ(u8, parked);
    defer allocator.free(parked_z);
    const outside_z = try allocator.dupeZ(u8, outside);
    defer allocator.free(outside_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        std.c.rename(db_dir_z.ptr, parked_z.ptr),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        std.c.symlink(outside_z.ptr, db_dir_z.ptr),
    );
    database.exec(
        "CREATE TABLE pinned(value INTEGER);",
        .{},
    ) catch {};
    database.close();
    try tmp.dir.access(
        std.testing.io,
        "root/parked/history.db",
        .{},
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.access(std.testing.io, "outside/history.db", .{}),
    );

    const escaped_path = try std.fmt.allocPrintSentinel(
        allocator,
        "{s}/root/db/escaped.db",
        .{base},
        0,
    );
    defer allocator.free(escaped_path);
    try std.testing.expectError(
        error.UnsafePath,
        Database.init(escaped_path.ptr),
    );
}
