//! tdnf rpmdb (Zig).
//!
//! T1 of the librpm-replacement plan (see
//! ../plan-replace-librpm.md). This module owns the read-only
//! interface to /var/lib/rpm/rpmdb.sqlite.
//!
//! T1 PR #1 (committed): the minimum viable surface —
//! `tdnf_rpmdb_count_packages` validates the FFI shape and build
//! wiring.
//!
//! T1 PR #2 (this file): iterator over the Packages table that
//! returns parsed RPM headers, plus a NEVRA-formatter shortcut.
//! `header.zig` decodes the binary header v3 blob. Header storage
//! is owned by the iterator (one row buffered at a time); NEVRA
//! strings are heap-allocated and freed by the caller via
//! `tdnf_rpmdb_string_free`.

const std = @import("std");
const header = @import("header.zig");

const c = @cImport({
    @cInclude("sqlite3.h");
    @cInclude("stdlib.h");
});

const PKG_TABLE = "Packages";
const DEFAULT_ROOT = "/";
const DEFAULT_DB_PATH = "var/lib/rpm/rpmdb.sqlite";

threadlocal var last_error_buf: [256]u8 = undefined;
threadlocal var last_error_len: usize = 0;

fn setError(comptime fmt: []const u8, args: anytype) void {
    const slice = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
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
/// See rpmdb.h for the full contract.
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
export fn tdnf_rpmdb_last_error() [*:0]const u8 {
    if (last_error_len >= last_error_buf.len) last_error_len = last_error_buf.len - 1;
    last_error_buf[last_error_len] = 0;
    return @ptrCast(&last_error_buf);
}

/// Returns an opaque "cookie" string that captures the rpmdb state.
///
/// Two calls return the same cookie iff the rpmdb has not changed
/// between them (no install/remove/upgrade). Format is
/// `<max_hnum>:<count>` over the Packages table — both axes change
/// when packages are added or removed, and `max_hnum` advances even
/// on reinstalls (rpm allocates a fresh `hnum` for each row write).
///
/// Replaces librpm's `rpmdbCookie()` — same role, different format.
/// Existing history DBs from the librpm era will see one spurious
/// "delta" transaction on first sync after upgrade because the
/// format differs; subsequent syncs match.
///
/// Caller owns the returned string and must free it with
/// `tdnf_rpmdb_string_free`. Returns NULL on error.
export fn tdnf_rpmdb_cookie(root: ?[*:0]const u8) ?[*:0]u8 {
    clearError();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    const db_path = buildDbPath(&buf, root_slice) catch |err| {
        setError("path build failed: {t}", .{err});
        return null;
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
        return null;
    }

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT IFNULL(MAX(hnum), 0), COUNT(*) FROM " ++ PKG_TABLE;
    const prepare_rc = c.sqlite3_prepare_v2(db, sql, sql.len, &stmt, null);
    defer {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
    }
    if (prepare_rc != c.SQLITE_OK) {
        setError("sqlite3_prepare_v2: {s}", .{
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        return null;
    }
    const step_rc = c.sqlite3_step(stmt);
    if (step_rc != c.SQLITE_ROW) {
        setError("sqlite3_step returned {d}, expected SQLITE_ROW", .{step_rc});
        return null;
    }
    const max_hnum = c.sqlite3_column_int64(stmt, 0);
    const count = c.sqlite3_column_int64(stmt, 1);

    var local_buf: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&local_buf, "{d}:{d}", .{ max_hnum, count }) catch {
        setError("cookie format buffer too small", .{});
        return null;
    };
    const out = c.malloc(text.len + 1) orelse {
        setError("out of memory", .{});
        return null;
    };
    const out_bytes = @as([*]u8, @ptrCast(out));
    @memcpy(out_bytes[0..text.len], text);
    out_bytes[text.len] = 0;
    return @ptrCast(out);
}

// -------------------------------------------------------------------
// Iterator
// -------------------------------------------------------------------

const Iter = struct {
    db: ?*c.sqlite3,
    stmt: ?*c.sqlite3_stmt,
};

/// Open a forward iterator over the rpmdb Packages table.
/// Returns NULL on error (use tdnf_rpmdb_last_error for details).
export fn tdnf_rpmdb_iter_open(root: ?[*:0]const u8) ?*Iter {
    clearError();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    const db_path = buildDbPath(&buf, root_slice) catch |err| {
        setError("path build failed: {t}", .{err});
        return null;
    };

    var db: ?*c.sqlite3 = null;
    const open_rc = c.sqlite3_open_v2(
        db_path.ptr,
        &db,
        c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
        null,
    );
    if (open_rc != c.SQLITE_OK) {
        setError("sqlite3_open_v2({s}): {s}", .{
            db_path,
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        if (db != null) _ = c.sqlite3_close(db);
        return null;
    }

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT blob FROM " ++ PKG_TABLE ++ " ORDER BY hnum";
    const prepare_rc = c.sqlite3_prepare_v2(db, sql, sql.len, &stmt, null);
    if (prepare_rc != c.SQLITE_OK) {
        setError("sqlite3_prepare_v2: {s}", .{
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        _ = c.sqlite3_close(db);
        return null;
    }

    const iter = std.heap.c_allocator.create(Iter) catch {
        setError("out of memory", .{});
        _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_close(db);
        return null;
    };
    iter.* = .{ .db = db, .stmt = stmt };
    return iter;
}

/// Close and free an iterator opened by tdnf_rpmdb_iter_open.
export fn tdnf_rpmdb_iter_close(it: ?*Iter) void {
    const iter = it orelse return;
    if (iter.stmt) |s| _ = c.sqlite3_finalize(s);
    if (iter.db) |d| _ = c.sqlite3_close(d);
    std.heap.c_allocator.destroy(iter);
}

/// Advance the iterator and write the next package's NEVRA string into
/// `*nevra_out`. Caller owns the string and must free it with
/// tdnf_rpmdb_string_free.
///
/// Returns 1 on hit, 0 on end-of-iteration, -1 on error.
export fn tdnf_rpmdb_iter_next_nevra(it: ?*Iter, nevra_out: ?*[*:0]u8) i32 {
    clearError();
    const iter = it orelse {
        setError("null iterator", .{});
        return -1;
    };
    const out = nevra_out orelse {
        setError("null out param", .{});
        return -1;
    };

    while (true) {
        const step_rc = c.sqlite3_step(iter.stmt);
        if (step_rc == c.SQLITE_DONE) return 0;
        if (step_rc != c.SQLITE_ROW) {
            setError("sqlite3_step: {s}", .{
                std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(iter.db))),
            });
            return -1;
        }
        const blob_ptr = c.sqlite3_column_blob(iter.stmt, 0);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(iter.stmt, 0));
        if (blob_ptr == null or blob_len == 0) {
            // Empty header row — skip silently. rpmdb shouldn't have
            // these, but we don't want to fail the whole walk.
            continue;
        }
        const blob: []const u8 = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];

        const h = header.Header.parse(blob) catch |err| {
            setError("header.parse: {t}", .{err});
            return -1;
        };
        const nevra_opt = h.allocNevra(std.heap.c_allocator) catch {
            setError("out of memory building NEVRA", .{});
            return -1;
        };
        const nevra = nevra_opt orelse {
            setError("header missing required tag for NEVRA", .{});
            return -1;
        };
        // Re-allocate with a trailing NUL so the caller gets a C string.
        const zptr = c.malloc(nevra.len + 1) orelse {
            std.heap.c_allocator.free(nevra);
            setError("out of memory", .{});
            return -1;
        };
        const zbytes = @as([*]u8, @ptrCast(zptr));
        @memcpy(zbytes[0..nevra.len], nevra);
        zbytes[nevra.len] = 0;
        std.heap.c_allocator.free(nevra);
        out.* = @ptrCast(zbytes);
        return 1;
    }
}

/// Free a string returned by an iterator. (Wraps `free(3)` so callers
/// don't have to think about which allocator we used.)
export fn tdnf_rpmdb_string_free(s: ?[*:0]u8) void {
    if (s) |p| c.free(@ptrCast(p));
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

fn buildDbPath(buf: []u8, root: []const u8) ![]const u8 {
    const effective_root = if (root.len == 0) DEFAULT_ROOT else root;
    var trimmed = std.mem.trimEnd(u8, effective_root, "/");
    if (trimmed.len == 0) trimmed = "";
    const needed = trimmed.len + 1 + DEFAULT_DB_PATH.len + 1;
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

test {
    // pull in header.zig tests
    _ = header;
}

