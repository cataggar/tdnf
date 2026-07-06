const std = @import("std");
const sqlite = @import("sqlite");

pub const busy_timeout_ms: c_int = 5000;

pub const Error = sqlite.Error || error{
    BusyTimeoutFailed,
};

pub const Database = struct {
    raw: sqlite.Database,

    pub fn init(path: [*:0]const u8) Error!Database {
        var db = Database{
            .raw = try sqlite.Database.open(.{
                .path = path,
                .mode = .ReadWrite,
                .create = true,
            }),
        };
        try db.busyTimeout(busy_timeout_ms);
        return db;
    }

    pub fn fromPtr(ptr: ?*sqlite.c.sqlite3) Database {
        return .{
            .raw = .{ .ptr = ptr },
        };
    }

    pub fn close(self: Database) void {
        self.raw.close();
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
