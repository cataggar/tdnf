//! tdnf rpmdb (Zig).
//!
//! T1 of the librpm-replacement plan (see
//! ../plan-replace-librpm.md). This module owns the read-only
//! interface to /var/lib/rpm/rpmdb.sqlite.
//!
//! T1 PR #1 (this file): the minimum viable surface — counting rows
//! in the Packages table. Validates the FFI shape and build wiring
//! before the header-blob decoder lands in PR #2.
//!
//! Future T1 PR #2 will add an iterator that yields parsed RPM
//! headers and replace the rpmdb walk in `history/history.c`.

const std = @import("std");

const c = @cImport({
    @cInclude("sqlite3.h");
});

const PKG_TABLE = "Packages";
const DEFAULT_ROOT = "/";
const DEFAULT_DB_PATH = "var/lib/rpm/rpmdb.sqlite";

/// Last error message produced by any function in this module on the
/// calling thread. Stable until the next call. Empty when no error has
/// occurred since the last call that succeeded.
threadlocal var last_error_buf: [256]u8 = undefined;
threadlocal var last_error_len: usize = 0;

fn setError(comptime fmt: []const u8, args: anytype) void {
    const slice = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
        // truncate but keep something useful
        const fallback = "(error message truncated)";
        @memcpy(last_error_buf[0..fallback.len], fallback);
        break :blk last_error_buf[0..fallback.len];
    };
    last_error_len = slice.len;
}

fn clearError() void {
    last_error_len = 0;
}

/// Count rows in the rpmdb's Packages table.
///
/// `root` is the install-root prefix to read the rpmdb under (matches
/// rpm's `--root`). Pass `NULL` or `""` for `/`.
///
/// Returns the row count on success, or -1 on error (the message is
/// retrievable via `tdnf_rpmdb_last_error`).
///
/// The Packages row count is the canonical "how many packages are
/// installed?" number — matches `rpm -qa | wc -l` exactly.
export fn tdnf_rpmdb_count_packages(root: ?[*:0]const u8) i64 {
    clearError();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";

    const db_path = buildDbPath(&buf, root_slice) catch |err| {
        setError("path build failed: {t}", .{err});
        return -1;
    };

    var db: ?*c.sqlite3 = null;
    const open_rc = c.sqlite3_open_v2(
        db_path.ptr,
        &db,
        c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
        null,
    );
    defer {
        if (db != null) _ = c.sqlite3_close(db);
    }
    if (open_rc != c.SQLITE_OK) {
        setError("sqlite3_open_v2({s}): {s}", .{
            db_path,
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        return -1;
    }

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT COUNT(*) FROM " ++ PKG_TABLE;
    const prepare_rc = c.sqlite3_prepare_v2(
        db,
        sql,
        sql.len,
        &stmt,
        null,
    );
    defer {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
    }
    if (prepare_rc != c.SQLITE_OK) {
        setError("sqlite3_prepare_v2 ({s}): {s}", .{
            sql,
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        return -1;
    }

    const step_rc = c.sqlite3_step(stmt);
    if (step_rc != c.SQLITE_ROW) {
        setError("sqlite3_step returned {d}, expected SQLITE_ROW", .{step_rc});
        return -1;
    }
    return c.sqlite3_column_int64(stmt, 0);
}

/// Returns the last error message produced by this thread.
/// Lifetime: stable until the next call into this module.
/// Returns an empty string when no error is pending.
export fn tdnf_rpmdb_last_error() [*:0]const u8 {
    // ensure null-termination
    if (last_error_len >= last_error_buf.len) last_error_len = last_error_buf.len - 1;
    last_error_buf[last_error_len] = 0;
    return @ptrCast(&last_error_buf);
}

fn buildDbPath(buf: []u8, root: []const u8) ![]const u8 {
    const effective_root = if (root.len == 0) DEFAULT_ROOT else root;
    // Match rpm's path joining: drop trailing slash, then join with
    // "/var/lib/rpm/rpmdb.sqlite".
    var trimmed = std.mem.trimEnd(u8, effective_root, "/");
    if (trimmed.len == 0) trimmed = ""; // root == "/" -> ""
    const needed = trimmed.len + 1 + DEFAULT_DB_PATH.len + 1; // +1 for '/', +1 for NUL
    if (needed > buf.len) return error.PathTooLong;
    return try std.fmt.bufPrintZ(buf, "{s}/{s}", .{ trimmed, DEFAULT_DB_PATH });
}

test "buildDbPath default root" {
    var buf: [256]u8 = undefined;
    const path = try buildDbPath(&buf, "");
    try std.testing.expectEqualStrings("/var/lib/rpm/rpmdb.sqlite", path);
}

test "buildDbPath relative root" {
    var buf: [256]u8 = undefined;
    const path = try buildDbPath(&buf, "/mnt/sysroot");
    try std.testing.expectEqualStrings("/mnt/sysroot/var/lib/rpm/rpmdb.sqlite", path);
}

test "buildDbPath strips trailing slash" {
    var buf: [256]u8 = undefined;
    const path = try buildDbPath(&buf, "/mnt/sysroot/");
    try std.testing.expectEqualStrings("/mnt/sysroot/var/lib/rpm/rpmdb.sqlite", path);
}
