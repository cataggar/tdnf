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
const sqlite = @import("sqlite");
const header = @import("rpm_header");
const pkgfile = @import("rpm_pkgfile");
const checksum = @import("checksum.zig");
const integrity = @import("integrity.zig");
const rpmdb_pubkey = @import("rpmdb_pubkey.zig");
const certificate = @import("pgp/certificate.zig");
const rpmdb_write = @import("rpmdb_write.zig");
const lua_scriptlet_options = @import("lua_scriptlet_options");
const lua_scriptlet_runtime = if (lua_scriptlet_options.zig_runtime)
    @import("lua_scriptlet_zig.zig")
else
    struct {};
pub const txn_config = @import("txn_config.zig");
const source_engine = @import("source.zig");
const scriptlet_engine = @import("scriptlet.zig");
const trigger_engine = @import("trigger.zig");
const c = sqlite.c;
const libc = std.c;
const pubkey_c = @cImport({
    @cInclude("errno.h");
    @cInclude("time.h");
    @cInclude("unistd.h");
});

comptime {
    _ = integrity;
    _ = lua_scriptlet_runtime;
}

pub const TxnConfig = txn_config.TxnConfig;
pub const TxnMacro = txn_config.Macro;
pub const ParsedRpmDefine = txn_config.ParsedRpmDefine;
pub const parseRpmDefine = txn_config.parseRpmDefine;
pub const macroFromName = txn_config.macroFromName;
pub const DEFAULT_DBPATH = txn_config.DEFAULT_DBPATH;
pub const DEFAULT_TMPPATH = txn_config.DEFAULT_TMPPATH;
pub const DEFAULT_INSTALL_SCRIPT_PATH = txn_config.DEFAULT_INSTALL_SCRIPT_PATH;
pub const DEFAULT_SCRIPT_INTERPRETER = txn_config.DEFAULT_SCRIPT_INTERPRETER;
pub const RpmDbWriter = rpmdb_write.Writer;
pub const RpmDbInstallOptions = rpmdb_write.InstallOptions;
pub const DEFAULT_INSTALL_COLOR = rpmdb_write.DEFAULT_INSTALL_COLOR;
pub const ScriptletPhase = scriptlet_engine.Phase;
pub const ScriptletOutcome = scriptlet_engine.Outcome;
pub const TriggerPhase = trigger_engine.Phase;

const PKG_TABLE = "Packages";
const RPMSENSE_EQUAL: u32 = 1 << 3;

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

const PinnedReadDb = struct {
    root: ?install_engine.RootDir,
    dir_fd: c_int,
    path: ?[:0]u8,
    exists: bool,

    fn initConfig(config: *const TxnConfig) !PinnedReadDb {
        const expanded = try config.expandMacroAlloc(
            std.heap.c_allocator,
            .dbpath,
        );
        defer std.heap.c_allocator.free(expanded);
        const allocated_dir = if (expanded.len != 0 and expanded[0] == '/')
            null
        else
            try std.fmt.allocPrint(
                std.heap.c_allocator,
                "/{s}",
                .{expanded},
            );
        defer if (allocated_dir) |value|
            std.heap.c_allocator.free(value);
        const raw_dir = allocated_dir orelse expanded;
        const trimmed = std.mem.trimEnd(u8, raw_dir, "/");
        const db_dir = if (trimmed.len == 0) "/" else trimmed;
        var root = (try install_engine.RootDir.initExisting(
            std.heap.c_allocator,
            config.installRoot(),
            null,
            null,
        )) orelse return .{
            .root = null,
            .dir_fd = -1,
            .path = null,
            .exists = false,
        };
        errdefer root.deinit();
        const dir_fd_opt = try root.openDirectory(db_dir, false);
        const dir_fd = dir_fd_opt orelse return .{
            .root = root,
            .dir_fd = -1,
            .path = null,
            .exists = false,
        };
        errdefer _ = std.c.close(dir_fd);
        const basename_z = txn_config.DEFAULT_RPMDB_BASENAME;
        const probe_fd = std.c.openat(dir_fd, basename_z, .{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        });
        if (probe_fd < 0) {
            if (std.c.errno(probe_fd) == .NOENT) {
                return .{
                    .root = root,
                    .dir_fd = dir_fd,
                    .path = null,
                    .exists = false,
                };
            }
            return error.SqliteOpenFailed;
        }
        _ = std.c.close(probe_fd);
        const path = try std.fmt.allocPrintSentinel(
            std.heap.c_allocator,
            "/proc/self/fd/{d}/{s}",
            .{ dir_fd, basename_z },
            0,
        );
        return .{
            .root = root,
            .dir_fd = dir_fd,
            .path = path,
            .exists = true,
        };
    }

    fn deinit(self: *PinnedReadDb) void {
        if (self.path) |path| std.heap.c_allocator.free(path);
        if (self.dir_fd >= 0) _ = std.c.close(self.dir_fd);
        if (self.root) |*root| root.deinit();
        self.dir_fd = -1;
        self.path = null;
    }
};

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
    return countPackagesAtPath(db_path);
}

export fn tdnf_rpmdb_count_packages_config(config: ?*const TxnConfig) i64 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    var pinned = PinnedReadDb.initConfig(cfg) catch |err| {
        setError("pinned rpmdb open failed: {t}", .{err});
        return -1;
    };
    defer pinned.deinit();
    if (!pinned.exists) return 0;
    return countPackagesAtPath(pinned.path.?);
}

fn countPackagesAtPath(db_path: []const u8) i64 {
    const path_z = std.heap.c_allocator.dupeZ(u8, db_path) catch {
        setError("out of memory", .{});
        return -1;
    };
    defer std.heap.c_allocator.free(path_z);
    const probe_fd = std.c.open(path_z.ptr, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    });
    if (probe_fd < 0) {
        if (std.posix.errno(probe_fd) == .NOENT) return 0;
        setError("unable to open rpmdb path", .{});
        return -1;
    }
    _ = std.c.close(probe_fd);
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

export fn tdnf_rpm_config_last_error() [*:0]const u8 {
    return tdnf_rpmdb_last_error();
}

/// Create one handle-scoped native rpm configuration.
export fn tdnf_rpm_config_create(root: ?[*:0]const u8) ?*TxnConfig {
    clearError();
    const config = std.heap.c_allocator.create(TxnConfig) catch {
        setError("out of memory", .{});
        return null;
    };
    const root_slice = if (root) |ptr| std.mem.span(ptr) else "";
    config.* = TxnConfig.init(std.heap.c_allocator, root_slice) catch |err| {
        std.heap.c_allocator.destroy(config);
        setError("rpm_config_create: {t}", .{err});
        return null;
    };
    config.loadConventionalMacroFiles() catch |err| {
        config.deinit();
        std.heap.c_allocator.destroy(config);
        setError("rpm_config_create macros: {t}", .{err});
        return null;
    };
    return config;
}

/// Destroy a native rpm configuration.
export fn tdnf_rpm_config_destroy(config: ?*TxnConfig) void {
    const cfg = config orelse return;
    cfg.deinit();
    std.heap.c_allocator.destroy(cfg);
}

fn rpmConfigInstallRoot(
    config: ?*const TxnConfig,
) callconv(.c) ?[*:0]u8 {
    const cfg = config orelse return null;
    return std.heap.c_allocator.dupeZ(
        u8,
        cfg.installRoot(),
    ) catch null;
}

fn rpmConfigOpenRootFd(
    config: ?*const TxnConfig,
) callconv(.c) c_int {
    const cfg = config orelse return -1;
    var root = install_engine.RootDir.init(
        std.heap.c_allocator,
        cfg.installRoot(),
        null,
        null,
    ) catch return -1;
    return root.releaseFd();
}

comptime {
    @export(&rpmConfigInstallRoot, .{
        .name = "tdnf_rpm_config_install_root",
        .visibility = .hidden,
    });
    @export(&rpmConfigOpenRootFd, .{
        .name = "tdnf_rpm_config_open_root_fd",
        .visibility = .hidden,
    });
}

/// Apply one command-line rpmdefine to a native configuration.
export fn tdnf_rpm_config_apply_define(
    config: ?*TxnConfig,
    definition: ?[*:0]const u8,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const define_ptr = definition orelse {
        setError("null rpmdefine", .{});
        return -1;
    };
    _ = cfg.applyRpmDefine(std.mem.span(define_ptr)) catch |err| {
        setError("rpm_config_apply_define: {t}", .{err});
        return -1;
    };
    return 0;
}

/// Expand one macro and return a libc-owned C string.
export fn tdnf_rpm_config_expand(
    config: ?*const TxnConfig,
    name: ?[*:0]const u8,
) ?[*:0]u8 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return null;
    };
    const name_ptr = name orelse {
        setError("null macro name", .{});
        return null;
    };
    const expanded = cfg.expandNameAlloc(
        std.heap.c_allocator,
        std.mem.span(name_ptr),
    ) catch |err| {
        setError("rpm_config_expand: {t}", .{err});
        return null;
    };
    defer std.heap.c_allocator.free(expanded);
    return dupZ(expanded);
}

/// Resolve one known path macro under the configuration's install root.
export fn tdnf_rpm_config_resolve_path(
    config: ?*const TxnConfig,
    name: ?[*:0]const u8,
) ?[*:0]u8 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return null;
    };
    const name_ptr = name orelse {
        setError("null macro name", .{});
        return null;
    };
    const macro_name = macroFromName(std.mem.span(name_ptr)) orelse {
        setError("unknown path macro: {s}", .{std.mem.span(name_ptr)});
        return null;
    };
    if (!macro_name.isInstallRootRelative()) {
        setError("macro is not an install-root-relative path: {s}", .{
            std.mem.span(name_ptr),
        });
        return null;
    }

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = cfg.resolvePath(macro_name, &path_buf) catch |err| {
        setError("rpm_config_resolve_path: {t}", .{err});
        return null;
    };
    return dupZ(path);
}

export fn tdnf_rpm_config_string_free(value: ?[*:0]u8) void {
    if (value) |ptr| libc.free(@ptrCast(ptr));
}

/// Returns an opaque "cookie" string that captures the rpmdb state.
///
/// Two calls return the same cookie iff the rpmdb has not changed
/// between them (no install/remove/upgrade). Format is
/// `<max_hnum>:<count>` over the Packages table — both axes change
/// when packages are added or removed, and `max_hnum` advances even
/// on reinstalls (rpm allocates a fresh `hnum` for each row write).
///
/// Native database-state cookie with a deliberately independent format.
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
    return cookieAtPath(db_path);
}

export fn tdnf_rpmdb_cookie_config(config: ?*const TxnConfig) ?[*:0]u8 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return null;
    };
    var pinned = PinnedReadDb.initConfig(cfg) catch |err| {
        setError("pinned rpmdb open failed: {t}", .{err});
        return null;
    };
    defer pinned.deinit();
    if (!pinned.exists) return dupZ("0:0");
    return cookieAtPath(pinned.path.?);
}

fn cookieAtPath(db_path: []const u8) ?[*:0]u8 {
    const path_z = std.heap.c_allocator.dupeZ(u8, db_path) catch {
        setError("out of memory", .{});
        return null;
    };
    defer std.heap.c_allocator.free(path_z);
    const probe_fd = std.c.open(path_z.ptr, std.c.O{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
    });
    if (probe_fd < 0) {
        if (std.posix.errno(probe_fd) == .NOENT) {
            return dupZ("0:0");
        }
        setError("unable to access rpmdb: {s}", .{db_path});
        return null;
    }
    _ = std.c.close(probe_fd);

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
    const out = libc.malloc(text.len + 1) orelse {
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

pub const Iter = struct {
    db: ?*c.sqlite3,
    stmt: ?*c.sqlite3_stmt,
    pinned: ?PinnedReadDb,

    pub const OpenError = error{
        OutOfMemory,
        PathTooLong,
        SqliteOpenFailed,
        SqlitePrepareFailed,
    };

    pub const NextHeaderError = error{
        SqliteStepFailed,
        HeaderParseFailed,
        InvalidHnum,
    };

    pub const NextBlobError = error{
        SqliteStepFailed,
        InvalidHnum,
    };

    pub const HeaderBlobRow = struct {
        hnum: u32,
        blob: []const u8,
    };

    pub fn openRoot(root: []const u8) OpenError!*Iter {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const db_path = buildDbPath(&buf, root) catch return error.PathTooLong;
        return openAtPath(db_path);
    }

    pub fn openConfig(config: *const TxnConfig) OpenError!*Iter {
        var pinned = PinnedReadDb.initConfig(config) catch
            return error.SqliteOpenFailed;
        errdefer pinned.deinit();
        if (!pinned.exists) {
            pinned.deinit();
            const empty = std.heap.c_allocator.create(Iter) catch
                return error.OutOfMemory;
            empty.* = .{ .db = null, .stmt = null, .pinned = null };
            return empty;
        }
        const iter = try openAtPath(pinned.path.?);
        iter.pinned = pinned;
        return iter;
    }

    pub fn openAtPath(db_path: []const u8) OpenError!*Iter {
        const path_z = std.heap.c_allocator.dupeZ(u8, db_path) catch return error.OutOfMemory;
        defer std.heap.c_allocator.free(path_z);

        const probe_fd = std.c.open(path_z.ptr, std.c.O{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
        });
        if (probe_fd < 0) {
            if (std.posix.errno(probe_fd) == .NOENT) {
                const empty = std.heap.c_allocator.create(Iter) catch {
                    return error.OutOfMemory;
                };
                empty.* = .{ .db = null, .stmt = null, .pinned = null };
                return empty;
            }
            return error.SqliteOpenFailed;
        }
        _ = std.c.close(probe_fd);

        var db: ?*c.sqlite3 = null;
        const open_rc = c.sqlite3_open_v2(
            path_z.ptr,
            &db,
            c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
            null,
        );
        if (open_rc != c.SQLITE_OK) {
            if (db != null) _ = c.sqlite3_close(db);
            return error.SqliteOpenFailed;
        }

        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "SELECT hnum, blob FROM " ++ PKG_TABLE ++ " ORDER BY hnum";
        const prepare_rc = c.sqlite3_prepare_v2(db, sql, sql.len, &stmt, null);
        if (prepare_rc != c.SQLITE_OK) {
            _ = c.sqlite3_close(db);
            return error.SqlitePrepareFailed;
        }

        const iter = std.heap.c_allocator.create(Iter) catch {
            _ = c.sqlite3_finalize(stmt);
            _ = c.sqlite3_close(db);
            return error.OutOfMemory;
        };
        iter.* = .{ .db = db, .stmt = stmt, .pinned = null };
        return iter;
    }

    pub fn close(self: *Iter) void {
        if (self.stmt) |s| _ = c.sqlite3_finalize(s);
        if (self.db) |d| _ = c.sqlite3_close(d);
        if (self.pinned) |*pinned| pinned.deinit();
        std.heap.c_allocator.destroy(self);
    }

    /// Advances to the next non-empty row and returns a parsed header.
    ///
    /// The returned header aliases sqlite-owned row memory and is only
    /// valid until the next `nextHeader` call or `close`.
    pub fn nextHeader(self: *Iter) NextHeaderError!?header.Header {
        const blob = try self.nextHeaderBlob() orelse return null;
        return header.Header.parse(blob) catch error.HeaderParseFailed;
    }

    /// Advances to the next non-empty row and returns the raw header blob.
    ///
    /// The returned slice aliases sqlite-owned row memory and is only
    /// valid until the next iterator advance or `close`.
    pub fn nextHeaderBlob(self: *Iter) NextBlobError!?[]const u8 {
        const row = try self.nextHeaderBlobHnum() orelse return null;
        return row.blob;
    }

    /// Advances to the next non-empty row and returns its exact hnum and
    /// raw header blob.
    pub fn nextHeaderBlobHnum(self: *Iter) NextBlobError!?HeaderBlobRow {
        if (self.stmt == null) return null;
        while (true) {
            const step_rc = c.sqlite3_step(self.stmt);
            if (step_rc == c.SQLITE_DONE) return null;
            if (step_rc != c.SQLITE_ROW) {
                return error.SqliteStepFailed;
            }
            const raw_hnum = c.sqlite3_column_int64(self.stmt, 0);
            const hnum = std.math.cast(u32, raw_hnum) orelse
                return error.InvalidHnum;
            if (hnum == 0) return error.InvalidHnum;
            const blob_ptr = c.sqlite3_column_blob(self.stmt, 1);
            const blob_len: usize = @intCast(c.sqlite3_column_bytes(self.stmt, 1));
            if (blob_ptr == null or blob_len == 0) continue;
            return .{
                .hnum = hnum,
                .blob = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len],
            };
        }
    }
};

/// Open a forward iterator over the rpmdb Packages table.
/// Returns NULL on error (use tdnf_rpmdb_last_error for details).
export fn tdnf_rpmdb_iter_open(root: ?[*:0]const u8) ?*Iter {
    clearError();
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    return Iter.openRoot(root_slice) catch |err| {
        setError("rpmdb_iter_open: {t}", .{err});
        return null;
    };
}

export fn tdnf_rpmdb_iter_open_config(config: ?*const TxnConfig) ?*Iter {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return null;
    };
    return Iter.openConfig(cfg) catch |err| {
        setError("rpmdb_iter_open_config: {t}", .{err});
        return null;
    };
}

/// Close and free an iterator opened by tdnf_rpmdb_iter_open.
export fn tdnf_rpmdb_iter_close(it: ?*Iter) void {
    const iter = it orelse return;
    iter.close();
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

    const h = iter.nextHeader() catch |err| {
        setError("iter.nextHeader: {t}", .{err});
        return -1;
    } orelse return 0;

    const nevra_opt = h.allocNevra(std.heap.c_allocator) catch {
        setError("out of memory building NEVRA", .{});
        return -1;
    };
    const nevra = nevra_opt orelse {
        setError("header missing required tag for NEVRA", .{});
        return -1;
    };
    // Re-allocate with a trailing NUL so the caller gets a C string.
    const zptr = libc.malloc(nevra.len + 1) orelse {
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

/// Advance the iterator and return the next raw header blob.
/// The blob aliases sqlite-owned row memory and remains valid until
/// the next iterator advance or `close`.
export fn tdnf_rpmdb_iter_next_header_blob(
    it: ?*Iter,
    blob_out: ?*?[*]const u8,
    blob_len_out: ?*usize,
) i32 {
    clearError();
    const iter = it orelse {
        setError("null iterator", .{});
        return -1;
    };
    const out = blob_out orelse {
        setError("null blob out param", .{});
        return -1;
    };
    const len_out = blob_len_out orelse {
        setError("null blob len out param", .{});
        return -1;
    };

    const blob = iter.nextHeaderBlob() catch |err| {
        setError("iter.nextHeaderBlob: {t}", .{err});
        return -1;
    } orelse {
        out.* = null;
        len_out.* = 0;
        return 0;
    };

    out.* = @ptrCast(blob.ptr);
    len_out.* = blob.len;
    return 1;
}

export fn tdnf_rpmdb_iter_next_header_blob_hnum(
    it: ?*Iter,
    hnum_out: ?*u32,
    blob_out: ?*?[*]const u8,
    blob_len_out: ?*usize,
) i32 {
    clearError();
    const iter = it orelse {
        setError("null iterator", .{});
        return -1;
    };
    const exact_hnum_out = hnum_out orelse {
        setError("null hnum out param", .{});
        return -1;
    };
    const out = blob_out orelse {
        setError("null blob out param", .{});
        return -1;
    };
    const len_out = blob_len_out orelse {
        setError("null blob len out param", .{});
        return -1;
    };

    const row = iter.nextHeaderBlobHnum() catch |err| {
        setError("iter.nextHeaderBlobHnum: {t}", .{err});
        return -1;
    } orelse {
        exact_hnum_out.* = 0;
        out.* = null;
        len_out.* = 0;
        return 0;
    };

    exact_hnum_out.* = row.hnum;
    out.* = @ptrCast(row.blob.ptr);
    len_out.* = row.blob.len;
    return 1;
}

/// Free a string returned by an iterator. (Wraps `free(3)` so callers
/// don't have to think about which allocator we used.)
export fn tdnf_rpmdb_string_free(s: ?[*:0]u8) void {
    if (s) |p| libc.free(@ptrCast(p));
}

const ProviderQueryError = error{
    MalformedProvider,
    OutOfMemory,
    SqliteBindFailed,
    SqliteOpenFailed,
    SqlitePrepareFailed,
    SqliteStepFailed,
};

fn resolveProviderHeaderVersion(
    allocator: std.mem.Allocator,
    hdr: header.Header,
    provide_name: []const u8,
) ProviderQueryError![]u8 {
    const version_entry = hdr.find(.version) orelse
        return error.MalformedProvider;
    if (@as(header.TypeId, @enumFromInt(version_entry.typ)) != .string or
        version_entry.count != 1)
    {
        return error.MalformedProvider;
    }
    const name_entry = hdr.find(.providename) orelse
        return error.MalformedProvider;
    if (@as(header.TypeId, @enumFromInt(name_entry.typ)) != .string_array) {
        return error.MalformedProvider;
    }
    const provide_version_entry = hdr.find(.provideversion) orelse
        return error.MalformedProvider;
    if (@as(header.TypeId, @enumFromInt(provide_version_entry.typ)) !=
        .string_array)
    {
        return error.MalformedProvider;
    }

    const package_version = (hdr.getStringChecked(.version) catch
        return error.MalformedProvider) orelse return error.MalformedProvider;
    if (package_version.len == 0) return error.MalformedProvider;

    const name_count = (hdr.stringArrayCountChecked(.providename) catch
        return error.MalformedProvider) orelse return error.MalformedProvider;
    const flag_count = (hdr.u32ArrayCountChecked(.provideflags) catch
        return error.MalformedProvider) orelse return error.MalformedProvider;
    const version_count = (hdr.stringArrayCountChecked(.provideversion) catch
        return error.MalformedProvider) orelse return error.MalformedProvider;
    if (name_count == 0 or
        name_count != flag_count or
        name_count != version_count)
    {
        return error.MalformedProvider;
    }

    var matched = false;
    var equal_version: ?[]const u8 = null;
    for (0..name_count) |index| {
        const name = (hdr.stringArrayItemChecked(.providename, index) catch
            return error.MalformedProvider) orelse return error.MalformedProvider;
        const flags = (hdr.u32ArrayItemChecked(.provideflags, index) catch
            return error.MalformedProvider) orelse return error.MalformedProvider;
        const version = (hdr.stringArrayItemChecked(.provideversion, index) catch
            return error.MalformedProvider) orelse return error.MalformedProvider;
        if (name.len == 0) return error.MalformedProvider;

        if (std.mem.eql(u8, name, provide_name)) {
            matched = true;
            if (equal_version == null and (flags & RPMSENSE_EQUAL) != 0) {
                if (version.len == 0) return error.MalformedProvider;
                equal_version = version;
            }
        }
    }
    if (!matched) return error.MalformedProvider;

    return allocator.dupe(u8, equal_version orelse package_version) catch
        error.OutOfMemory;
}

fn resolveProviderVersionAtPath(
    allocator: std.mem.Allocator,
    db_path: []const u8,
    provide_name: []const u8,
) ProviderQueryError!?[]u8 {
    const path_z = allocator.dupeZ(u8, db_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    const probe_fd = std.c.open(path_z.ptr, std.c.O{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
    });
    if (probe_fd < 0) {
        if (std.posix.errno(probe_fd) == .NOENT) return null;
        return error.SqliteOpenFailed;
    }
    _ = std.c.close(probe_fd);

    var db: ?*c.sqlite3 = null;
    const open_rc = c.sqlite3_open_v2(
        path_z.ptr,
        &db,
        c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
        null,
    );
    if (open_rc != c.SQLITE_OK) {
        if (db != null) _ = c.sqlite3_close(db);
        return error.SqliteOpenFailed;
    }
    defer _ = c.sqlite3_close(db);

    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        "SELECT packages.blob FROM 'Providename' AS provider " ++
        "LEFT JOIN Packages AS packages ON packages.hnum=provider.hnum " ++
        "WHERE provider.key=? ORDER BY provider.hnum, provider.idx LIMIT 1";
    if (c.sqlite3_prepare_v2(db, sql.ptr, @intCast(sql.len), &stmt, null) != c.SQLITE_OK) {
        return error.SqlitePrepareFailed;
    }
    defer _ = c.sqlite3_finalize(stmt);

    if (c.sqlite3_bind_text(
        stmt,
        1,
        provide_name.ptr,
        @intCast(provide_name.len),
        null,
    ) != c.SQLITE_OK) {
        return error.SqliteBindFailed;
    }

    const step_rc = c.sqlite3_step(stmt);
    if (step_rc == c.SQLITE_DONE) return null;
    if (step_rc != c.SQLITE_ROW) return error.SqliteStepFailed;

    const blob_ptr = c.sqlite3_column_blob(stmt, 0) orelse
        return error.MalformedProvider;
    const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    if (blob_len == 0) return error.MalformedProvider;
    const blob = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];
    const hdr = header.Header.parse(blob) catch return error.MalformedProvider;
    return try resolveProviderHeaderVersion(allocator, hdr, provide_name);
}

/// Resolve distrover-style provider versions through the configured rpmdb.
export fn tdnf_rpmdb_resolve_provider_version_config(
    config: ?*const TxnConfig,
    provide_name: ?[*:0]const u8,
    version_out: ?*?[*:0]u8,
) i32 {
    clearError();
    const out = version_out orelse {
        setError("null version_out", .{});
        return -1;
    };
    out.* = null;
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const name_ptr = provide_name orelse {
        setError("null provide name", .{});
        return -1;
    };
    const name = std.mem.span(name_ptr);
    if (name.len == 0) {
        setError("empty provide name", .{});
        return -1;
    }

    var pinned = PinnedReadDb.initConfig(cfg) catch |err| {
        setError("provider rpmdb path: {t}", .{err});
        return -1;
    };
    defer pinned.deinit();
    if (!pinned.exists) return 0;
    const version = resolveProviderVersionAtPath(
        std.heap.c_allocator,
        pinned.path.?,
        name,
    ) catch |err| {
        setError("provider query for {s}: {t}", .{ name, err });
        return -1;
    } orelse return 0;
    defer std.heap.c_allocator.free(version);

    out.* = dupZ(version) orelse return -1;
    return 1;
}

// -------------------------------------------------------------------
// Native sqlite write path
// -------------------------------------------------------------------

export fn tdnf_rpmdb_write_install(
    root: ?[*:0]const u8,
    rpm_path: ?[*:0]const u8,
    install_tid: u32,
    install_time: u32,
    install_color: u32,
    file_states: ?[*]const u8,
    file_state_count: usize,
    hnum_out: ?*u32,
) i32 {
    clearError();
    const path_ptr = rpm_path orelse {
        setError("null rpm_path", .{});
        return -1;
    };
    const path_slice = std.mem.span(path_ptr);
    const path_z = std.heap.c_allocator.dupeZ(u8, path_slice) catch {
        setError("out of memory", .{});
        return -1;
    };
    defer std.heap.c_allocator.free(path_z);

    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    var writer = rpmdb_write.Writer.openRoot(root_slice) catch |err| {
        setError("Writer.openRoot: {t}", .{err});
        return -1;
    };
    defer writer.close();

    const states_slice: ?[]const u8 = if (file_state_count == 0)
        null
    else if (file_states) |ptr|
        ptr[0..file_state_count]
    else {
        setError("null file_states with non-zero count", .{});
        return -1;
    };

    const hnum = writer.installRpmPath(path_z, .{
        .install_tid = install_tid,
        .install_time = if (install_time == 0) null else install_time,
        .install_color = install_color,
        .file_states = states_slice,
    }) catch |err| {
        setError("Writer.installRpmPath({s}): {t}", .{ path_slice, err });
        return -1;
    };
    if (hnum_out) |out| out.* = hnum;
    return 0;
}

export fn tdnf_rpmdb_write_install_config(
    config: ?*const TxnConfig,
    rpm_path: ?[*:0]const u8,
    install_tid: u32,
    install_time: u32,
    install_color: u32,
    file_states: ?[*]const u8,
    file_state_count: usize,
    hnum_out: ?*u32,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const path_ptr = rpm_path orelse {
        setError("null rpm_path", .{});
        return -1;
    };
    const path_slice = std.mem.span(path_ptr);
    const path_z = std.heap.c_allocator.dupeZ(u8, path_slice) catch {
        setError("out of memory", .{});
        return -1;
    };
    defer std.heap.c_allocator.free(path_z);
    var writer = rpmdb_write.Writer.openConfig(cfg) catch |err| {
        setError("Writer.openConfig: {t}", .{err});
        return -1;
    };
    defer writer.close();
    const states_slice: ?[]const u8 = if (file_state_count == 0)
        null
    else if (file_states) |ptr|
        ptr[0..file_state_count]
    else {
        setError("null file_states with non-zero count", .{});
        return -1;
    };
    const hnum = writer.installRpmPath(path_z, .{
        .install_tid = install_tid,
        .install_time = if (install_time == 0) null else install_time,
        .install_color = install_color,
        .file_states = states_slice,
    }) catch |err| {
        setError("Writer.installRpmPath({s}): {t}", .{ path_slice, err });
        return -1;
    };
    if (hnum_out) |out| out.* = hnum;
    return 0;
}

export fn tdnf_rpmdb_write_install_file_config(
    config: ?*const TxnConfig,
    fh: ?*FileHandle,
    install_tid: u32,
    install_time: u32,
    install_color: u32,
    file_states: ?[*]const u8,
    file_state_count: usize,
    hnum_out: ?*u32,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const file = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const states_slice: ?[]const u8 = if (file_state_count == 0)
        null
    else if (file_states) |ptr|
        ptr[0..file_state_count]
    else {
        setError("null file_states with non-zero count", .{});
        return -1;
    };
    var writer = rpmdb_write.Writer.openConfig(cfg) catch |err| {
        setError("Writer.openConfig: {t}", .{err});
        return -1;
    };
    defer writer.close();
    const hnum = writer.installRpm(&file.file, .{
        .install_tid = install_tid,
        .install_time = if (install_time == 0) null else install_time,
        .install_color = install_color,
        .file_states = states_slice,
    }) catch |err| {
        setError("Writer.installRpm: {t}", .{err});
        return -1;
    };
    if (hnum_out) |out| out.* = hnum;
    return 0;
}

export fn tdnf_rpmdb_write_replace(
    root: ?[*:0]const u8,
    old_hnum: u32,
    rpm_path: ?[*:0]const u8,
    install_tid: u32,
    install_time: u32,
    install_color: u32,
    file_states: ?[*]const u8,
    file_state_count: usize,
    new_hnum_out: ?*u32,
) i32 {
    clearError();
    const path_ptr = rpm_path orelse {
        setError("null rpm_path", .{});
        return -1;
    };
    const path_slice = std.mem.span(path_ptr);
    const path_z = std.heap.c_allocator.dupeZ(u8, path_slice) catch {
        setError("out of memory", .{});
        return -1;
    };
    defer std.heap.c_allocator.free(path_z);

    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    var writer = rpmdb_write.Writer.openRoot(root_slice) catch |err| {
        setError("Writer.openRoot: {t}", .{err});
        return -1;
    };
    defer writer.close();

    const states_slice: ?[]const u8 = if (file_state_count == 0)
        null
    else if (file_states) |ptr|
        ptr[0..file_state_count]
    else {
        setError("null file_states with non-zero count", .{});
        return -1;
    };

    var rpm = pkgfile.RpmFile.open(std.heap.c_allocator, path_z) catch |err| {
        setError("RpmFile.open({s}): {t}", .{ path_slice, err });
        return -1;
    };
    defer rpm.close(std.heap.c_allocator);

    const new_hnum = writer.replaceRpm(old_hnum, &rpm, .{
        .install_tid = install_tid,
        .install_time = if (install_time == 0) null else install_time,
        .install_color = install_color,
        .file_states = states_slice,
    }) catch |err| {
        setError("Writer.replaceRpm({s}): {t}", .{ path_slice, err });
        return -1;
    };
    if (new_hnum_out) |out| out.* = new_hnum;
    return 0;
}

export fn tdnf_rpmdb_write_replace_file_config(
    config: ?*const TxnConfig,
    old_hnum: u32,
    fh: ?*FileHandle,
    install_tid: u32,
    install_time: u32,
    install_color: u32,
    file_states: ?[*]const u8,
    file_state_count: usize,
    new_hnum_out: ?*u32,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const file = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const states_slice: ?[]const u8 = if (file_state_count == 0)
        null
    else if (file_states) |ptr|
        ptr[0..file_state_count]
    else {
        setError("null file_states with non-zero count", .{});
        return -1;
    };
    var writer = rpmdb_write.Writer.openConfig(cfg) catch |err| {
        setError("Writer.openConfig: {t}", .{err});
        return -1;
    };
    defer writer.close();
    const new_hnum = writer.replaceRpm(old_hnum, &file.file, .{
        .install_tid = install_tid,
        .install_time = if (install_time == 0) null else install_time,
        .install_color = install_color,
        .file_states = states_slice,
    }) catch |err| {
        setError("Writer.replaceRpm: {t}", .{err});
        return -1;
    };
    if (new_hnum_out) |out| out.* = new_hnum;
    return 0;
}

export fn tdnf_rpmdb_write_replace_config(
    config: ?*const TxnConfig,
    old_hnum: u32,
    rpm_path: ?[*:0]const u8,
    install_tid: u32,
    install_time: u32,
    install_color: u32,
    file_states: ?[*]const u8,
    file_state_count: usize,
    new_hnum_out: ?*u32,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const path_ptr = rpm_path orelse {
        setError("null rpm_path", .{});
        return -1;
    };
    const path_slice = std.mem.span(path_ptr);
    const path_z = std.heap.c_allocator.dupeZ(u8, path_slice) catch {
        setError("out of memory", .{});
        return -1;
    };
    defer std.heap.c_allocator.free(path_z);
    var writer = rpmdb_write.Writer.openConfig(cfg) catch |err| {
        setError("Writer.openConfig: {t}", .{err});
        return -1;
    };
    defer writer.close();
    const states_slice: ?[]const u8 = if (file_state_count == 0)
        null
    else if (file_states) |ptr|
        ptr[0..file_state_count]
    else {
        setError("null file_states with non-zero count", .{});
        return -1;
    };
    var rpm = pkgfile.RpmFile.open(std.heap.c_allocator, path_z) catch |err| {
        setError("RpmFile.open({s}): {t}", .{ path_slice, err });
        return -1;
    };
    defer rpm.close(std.heap.c_allocator);
    const new_hnum = writer.replaceRpm(old_hnum, &rpm, .{
        .install_tid = install_tid,
        .install_time = if (install_time == 0) null else install_time,
        .install_color = install_color,
        .file_states = states_slice,
    }) catch |err| {
        setError("Writer.replaceRpm({s}): {t}", .{ path_slice, err });
        return -1;
    };
    if (new_hnum_out) |out| out.* = new_hnum;
    return 0;
}

export fn tdnf_rpmdb_write_erase_hnum(root: ?[*:0]const u8, hnum: u32) i32 {
    clearError();
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    var writer = rpmdb_write.Writer.openRoot(root_slice) catch |err| {
        setError("Writer.openRoot: {t}", .{err});
        return -1;
    };
    defer writer.close();

    writer.eraseHnum(hnum) catch |err| {
        setError("Writer.eraseHnum({d}): {t}", .{ hnum, err });
        return -1;
    };
    return 0;
}

export fn tdnf_rpmdb_write_erase_hnum_config(config: ?*const TxnConfig, hnum: u32) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    var writer = rpmdb_write.Writer.openConfig(cfg) catch |err| {
        setError("Writer.openConfig: {t}", .{err});
        return -1;
    };
    defer writer.close();
    writer.eraseHnum(hnum) catch |err| {
        setError("Writer.eraseHnum({d}): {t}", .{ hnum, err });
        return -1;
    };
    return 0;
}

export fn tdnf_rpmdb_find_hnum_by_nevra(
    root: ?[*:0]const u8,
    nevra: ?[*:0]const u8,
    hnum_out: ?*u32,
) i32 {
    clearError();
    const nevra_ptr = nevra orelse {
        setError("null nevra", .{});
        return -1;
    };
    const out = hnum_out orelse {
        setError("null hnum_out", .{});
        return -1;
    };

    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    var writer = rpmdb_write.Writer.openRoot(root_slice) catch |err| {
        setError("Writer.openRoot: {t}", .{err});
        return -1;
    };
    defer writer.close();

    return findHnumByNevra(&writer, nevra_ptr, out);
}

export fn tdnf_rpmdb_find_hnum_by_nevra_config(
    config: ?*const TxnConfig,
    nevra: ?[*:0]const u8,
    hnum_out: ?*u32,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const nevra_ptr = nevra orelse {
        setError("null nevra", .{});
        return -1;
    };
    const out = hnum_out orelse {
        setError("null hnum_out", .{});
        return -1;
    };

    const iter = Iter.openConfig(cfg) catch |err| {
        setError("Iter.openConfig: {t}", .{err});
        return -1;
    };
    defer iter.close();
    const wanted = std.mem.span(nevra_ptr);
    while (true) {
        const row = iter.nextHeaderBlobHnum() catch |err| {
            setError("Iter.nextHeaderBlobHnum: {t}", .{err});
            return -1;
        } orelse break;
        const hdr = header.Header.parse(row.blob) catch {
            setError("malformed rpmdb header", .{});
            return -1;
        };
        const actual = (hdr.allocNevra(std.heap.c_allocator) catch {
            setError("out of memory", .{});
            return -1;
        }) orelse continue;
        defer std.heap.c_allocator.free(actual);
        if (std.mem.eql(u8, actual, wanted)) {
            out.* = row.hnum;
            return 1;
        }
    }
    out.* = 0;
    return 0;
}

fn findHnumByNevra(
    writer: *rpmdb_write.Writer,
    nevra: [*:0]const u8,
    out: *u32,
) i32 {
    const found = writer.findHnumByNevra(std.heap.c_allocator, std.mem.span(nevra)) catch |err| {
        setError("Writer.findHnumByNevra: {t}", .{err});
        return -1;
    };
    if (found) |hnum| {
        out.* = hnum;
        return 1;
    }
    out.* = 0;
    return 0;
}

/// Look up every installed package hnum whose main-header NAME
/// matches `name`. On success writes a heap-allocated array of hnums
/// into `*hnums_out` (free via tdnf_rpmdb_hnums_free) and the count
/// into `*count_out`.
///
/// Returns 0 on success (including "no matches" — in which case
/// `*hnums_out` is NULL and `*count_out` is 0), -1 on error.
export fn tdnf_rpmdb_find_hnums_by_name(
    root: ?[*:0]const u8,
    name: ?[*:0]const u8,
    hnums_out: ?*?[*]u32,
    count_out: ?*usize,
) i32 {
    clearError();
    const name_ptr = name orelse {
        setError("null name", .{});
        return -1;
    };
    const hout = hnums_out orelse {
        setError("null hnums_out", .{});
        return -1;
    };
    const cout = count_out orelse {
        setError("null count_out", .{});
        return -1;
    };
    hout.* = null;
    cout.* = 0;

    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    var writer = rpmdb_write.Writer.openRoot(root_slice) catch |err| {
        setError("Writer.openRoot: {t}", .{err});
        return -1;
    };
    defer writer.close();

    const found = writer.findHnumsByName(std.heap.c_allocator, std.mem.span(name_ptr)) catch |err| {
        setError("Writer.findHnumsByName: {t}", .{err});
        return -1;
    };
    if (found.len == 0) {
        std.heap.c_allocator.free(found);
        return 0;
    }

    // Copy into a libc-malloc'd buffer so the caller can free with
    // tdnf_rpmdb_hnums_free (i.e. plain free(3)).
    const bytes = found.len * @sizeOf(u32);
    const buf_ptr = libc.malloc(bytes) orelse {
        std.heap.c_allocator.free(found);
        setError("out of memory", .{});
        return -1;
    };
    const buf = @as([*]u32, @ptrCast(@alignCast(buf_ptr)));
    @memcpy(buf[0..found.len], found);
    std.heap.c_allocator.free(found);
    hout.* = buf;
    cout.* = found.len;
    return 0;
}

export fn tdnf_rpmdb_find_hnums_by_name_config(
    config: ?*const TxnConfig,
    name: ?[*:0]const u8,
    hnums_out: ?*?[*]u32,
    count_out: ?*usize,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const name_ptr = name orelse {
        setError("null name", .{});
        return -1;
    };
    const hout = hnums_out orelse {
        setError("null hnums_out", .{});
        return -1;
    };
    const cout = count_out orelse {
        setError("null count_out", .{});
        return -1;
    };
    hout.* = null;
    cout.* = 0;
    const iter = Iter.openConfig(cfg) catch |err| {
        setError("Iter.openConfig: {t}", .{err});
        return -1;
    };
    defer iter.close();
    var found_list = std.ArrayList(u32).empty;
    defer found_list.deinit(std.heap.c_allocator);
    const wanted = std.mem.span(name_ptr);
    while (true) {
        const row = iter.nextHeaderBlobHnum() catch |err| {
            setError("Iter.nextHeaderBlobHnum: {t}", .{err});
            return -1;
        } orelse break;
        const hdr = header.Header.parse(row.blob) catch {
            setError("malformed rpmdb header", .{});
            return -1;
        };
        const actual = hdr.getString(.name) orelse continue;
        if (std.mem.eql(u8, actual, wanted)) {
            found_list.append(std.heap.c_allocator, row.hnum) catch {
                setError("out of memory", .{});
                return -1;
            };
        }
    }
    const found = found_list.items;
    if (found.len == 0) {
        return 0;
    }
    const buf_ptr = libc.malloc(found.len * @sizeOf(u32)) orelse {
        setError("out of memory", .{});
        return -1;
    };
    const buf = @as([*]u32, @ptrCast(@alignCast(buf_ptr)));
    @memcpy(buf[0..found.len], found);
    hout.* = buf;
    cout.* = found.len;
    return 0;
}

const LabelMatch = extern struct {
    hnum: u32,
    name: ?[*:0]u8,
    evr: ?[*:0]u8,
    arch: ?[*:0]u8,
};

const OwnedLabelMatch = struct {
    hnum: u32,
    name: [:0]u8,
    evr: [:0]u8,
    arch: [:0]u8,
};

export fn tdnf_rpmdb_find_label_matches_config(
    config: ?*const TxnConfig,
    name: ?[*:0]const u8,
    evr: ?[*:0]const u8,
    matches_out: ?*?[*]LabelMatch,
    count_out: ?*usize,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const name_ptr = name orelse {
        setError("null package name", .{});
        return -1;
    };
    const evr_ptr = evr orelse {
        setError("null package EVR", .{});
        return -1;
    };
    const output = matches_out orelse {
        setError("null label matches output", .{});
        return -1;
    };
    const output_count = count_out orelse {
        setError("null label match count output", .{});
        return -1;
    };
    output.* = null;
    output_count.* = 0;

    const iter = Iter.openConfig(cfg) catch |err| {
        setError("Iter.openConfig: {t}", .{err});
        return -1;
    };
    defer iter.close();

    const wanted_name = std.mem.span(name_ptr);
    const wanted_evr = std.mem.span(evr_ptr);

    var matches = std.ArrayList(OwnedLabelMatch).empty;
    defer matches.deinit(std.heap.c_allocator);
    var transfer_complete = false;
    defer if (!transfer_complete) {
        for (matches.items) |match| {
            std.heap.c_allocator.free(match.name);
            std.heap.c_allocator.free(match.evr);
            std.heap.c_allocator.free(match.arch);
        }
    };

    while (true) {
        const row = iter.nextHeaderBlobHnum() catch |err| {
            setError("Iter.nextHeaderBlobHnum: {t}", .{err});
            return -1;
        } orelse break;
        const hdr = header.Header.parse(row.blob) catch |err| {
            setError("header.parse({d}): {t}", .{ row.hnum, err });
            return -1;
        };
        const actual_name = hdr.getStringChecked(.name) catch {
            setError("malformed package name at hnum {d}", .{row.hnum});
            return -1;
        } orelse {
            setError("missing package name at hnum {d}", .{row.hnum});
            return -1;
        };
        if (!std.mem.eql(u8, actual_name, wanted_name)) {
            continue;
        }
        const actual_arch = hdr.getStringChecked(.arch) catch {
            setError("malformed package arch at hnum {d}", .{row.hnum});
            return -1;
        } orelse {
            setError("missing package arch at hnum {d}", .{row.hnum});
            return -1;
        };
        const actual_evr = (hdr.allocEvr(std.heap.c_allocator) catch {
            setError("out of memory building EVR", .{});
            return -1;
        }) orelse {
            setError("missing package EVR at hnum {d}", .{row.hnum});
            return -1;
        };
        defer std.heap.c_allocator.free(actual_evr);
        if (!std.mem.eql(u8, actual_evr, wanted_evr)) {
            continue;
        }

        const name_copy = std.heap.c_allocator.dupeZ(u8, actual_name) catch {
            setError("out of memory copying package name", .{});
            return -1;
        };
        errdefer std.heap.c_allocator.free(name_copy);
        const evr_copy = std.heap.c_allocator.dupeZ(u8, actual_evr) catch {
            setError("out of memory copying package EVR", .{});
            return -1;
        };
        errdefer std.heap.c_allocator.free(evr_copy);
        const arch_copy = std.heap.c_allocator.dupeZ(u8, actual_arch) catch {
            setError("out of memory copying package arch", .{});
            return -1;
        };
        errdefer std.heap.c_allocator.free(arch_copy);
        matches.append(std.heap.c_allocator, .{
            .hnum = row.hnum,
            .name = name_copy,
            .evr = evr_copy,
            .arch = arch_copy,
        }) catch {
            setError("out of memory appending label match", .{});
            return -1;
        };
    }

    if (matches.items.len == 0) {
        transfer_complete = true;
        return 0;
    }
    const raw = libc.malloc(matches.items.len * @sizeOf(LabelMatch)) orelse {
        setError("out of memory allocating label matches", .{});
        return -1;
    };
    const result: [*]LabelMatch = @ptrCast(@alignCast(raw));
    for (matches.items, 0..) |match, index| {
        result[index] = .{
            .hnum = match.hnum,
            .name = match.name.ptr,
            .evr = match.evr.ptr,
            .arch = match.arch.ptr,
        };
    }
    output.* = result;
    output_count.* = matches.items.len;
    transfer_complete = true;
    return 0;
}

export fn tdnf_rpmdb_label_matches_free(
    matches: ?[*]LabelMatch,
    count: usize,
) void {
    const values = matches orelse return;
    for (values[0..count]) |match| {
        if (match.name) |value| libc.free(@ptrCast(value));
        if (match.evr) |value| libc.free(@ptrCast(value));
        if (match.arch) |value| libc.free(@ptrCast(value));
    }
    libc.free(@ptrCast(values));
}

/// Free an hnum array returned by tdnf_rpmdb_find_hnums_by_name.
export fn tdnf_rpmdb_hnums_free(hnums: ?[*]u32) void {
    if (hnums) |p| libc.free(@ptrCast(p));
}

/// Read the raw main-header blob for the installed package with
/// `hnum` under `root`. On success writes a heap-allocated blob
/// pointer into `*blob_out` (free via tdnf_rpmdb_blob_free) and its
/// length into `*len_out`.
///
/// Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error()).
export fn tdnf_rpmdb_read_header_blob(
    root: ?[*:0]const u8,
    hnum: u32,
    blob_out: ?*?[*]u8,
    len_out: ?*usize,
) i32 {
    clearError();
    const bout = blob_out orelse {
        setError("null blob_out", .{});
        return -1;
    };
    const lout = len_out orelse {
        setError("null len_out", .{});
        return -1;
    };
    bout.* = null;
    lout.* = 0;

    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    var writer = rpmdb_write.Writer.openRoot(root_slice) catch |err| {
        setError("Writer.openRoot: {t}", .{err});
        return -1;
    };
    defer writer.close();

    const blob = writer.readHeaderBlobCopy(std.heap.c_allocator, hnum) catch |err| {
        setError("Writer.readHeaderBlobCopy({d}): {t}", .{ hnum, err });
        return -1;
    };
    defer std.heap.c_allocator.free(blob);

    const buf_ptr = libc.malloc(blob.len) orelse {
        setError("out of memory", .{});
        return -1;
    };
    const buf = @as([*]u8, @ptrCast(buf_ptr));
    @memcpy(buf[0..blob.len], blob);
    bout.* = buf;
    lout.* = blob.len;
    return 0;
}

export fn tdnf_rpmdb_read_header_blob_config(
    config: ?*const TxnConfig,
    hnum: u32,
    blob_out: ?*?[*]u8,
    len_out: ?*usize,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const bout = blob_out orelse {
        setError("null blob_out", .{});
        return -1;
    };
    const lout = len_out orelse {
        setError("null len_out", .{});
        return -1;
    };
    bout.* = null;
    lout.* = 0;
    const iter = Iter.openConfig(cfg) catch |err| {
        setError("Iter.openConfig: {t}", .{err});
        return -1;
    };
    defer iter.close();
    while (true) {
        const row = iter.nextHeaderBlobHnum() catch |err| {
            setError("Iter.nextHeaderBlobHnum: {t}", .{err});
            return -1;
        } orelse break;
        if (row.hnum != hnum) continue;
        const buf_ptr = libc.malloc(row.blob.len) orelse {
            setError("out of memory", .{});
            return -1;
        };
        const buf = @as([*]u8, @ptrCast(buf_ptr));
        @memcpy(buf[0..row.blob.len], row.blob);
        bout.* = buf;
        lout.* = row.blob.len;
        return 0;
    }
    setError("rpmdb hnum {d} not found", .{hnum});
    return -1;
}

/// Free a blob returned by tdnf_rpmdb_read_header_blob.
export fn tdnf_rpmdb_blob_free(blob: ?[*]u8) void {
    if (blob) |p| libc.free(@ptrCast(p));
}

// -------------------------------------------------------------------
// Pubkey iterator (gpg-pubkey-* installed packages)
// -------------------------------------------------------------------
//
// `rpm --import` stores each imported public key as an installed
// package whose NAME is "gpg-pubkey", VERSION is the key id, RELEASE
// is the key's creation timestamp, PUBKEYS contains its base64 packet
// stream, and DESCRIPTION contains an armored rendering. We trust
// PUBKEYS when present and retain DESCRIPTION as a legacy fallback.
//
// This is the read-only side of the T3 PR #5 verifier flip: the
// rpmzig verifier can preload the rpmdb's existing trust set rather
// than re-prompting users for keys that librpm already has.

const PubkeyIter = struct {
    db: ?*c.sqlite3,
    stmt: ?*c.sqlite3_stmt,
    pinned: ?PinnedReadDb,
};

/// Import every armored or binary certificate and replace matching primary
/// fingerprints atomically. Returns 0 on success and -1 on error.
export fn tdnf_rpmdb_import_pubkeys(
    root: ?[*:0]const u8,
    data: ?*const anyopaque,
    len: usize,
    imported_out: ?*usize,
) i32 {
    clearError();
    const bytes = importBytes(data, len) orelse return -1;
    const timestamp = importTimestamp() orelse return -1;
    const root_slice: []const u8 = if (root) |value|
        std.mem.span(value)
    else
        "";
    const count = rpmdb_pubkey.importRoot(
        std.heap.c_allocator,
        root_slice,
        bytes,
        timestamp,
    ) catch |err| {
        setError("pubkey import failed: {t}", .{err});
        return -1;
    };
    if (imported_out) |out| out.* = count;
    return 0;
}

export fn tdnf_rpmdb_import_pubkeys_config(
    config: ?*const TxnConfig,
    data: ?*const anyopaque,
    len: usize,
    imported_out: ?*usize,
) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const bytes = importBytes(data, len) orelse return -1;
    const timestamp = importTimestamp() orelse return -1;
    const count = rpmdb_pubkey.importConfig(
        std.heap.c_allocator,
        cfg,
        bytes,
        timestamp,
    ) catch |err| {
        setError("pubkey import failed: {t}", .{err});
        return -1;
    };
    if (imported_out) |out| out.* = count;
    return 0;
}

fn importBytes(data: ?*const anyopaque, len: usize) ?[]const u8 {
    if (data == null or len == 0) {
        setError("empty pubkey input", .{});
        return null;
    }
    return @as([*]const u8, @ptrCast(data.?))[0..len];
}

fn importTimestamp() ?u32 {
    const now = pubkey_c.time(null);
    if (now < 0 or now > std.math.maxInt(u32)) {
        setError("system time is outside the rpm timestamp range", .{});
        return null;
    }
    return @intCast(now);
}

/// Open a forward iterator over rpmdb rows whose RPMTAG_NAME is
/// "gpg-pubkey".
export fn tdnf_rpmdb_pubkeys_open(root: ?[*:0]const u8) ?*PubkeyIter {
    clearError();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    const db_path = buildDbPath(&buf, root_slice) catch |err| {
        setError("path build failed: {t}", .{err});
        return null;
    };
    return pubkeysOpenAtPath(db_path);
}

/// Config-aware form of `tdnf_rpmdb_pubkeys_open`.
export fn tdnf_rpmdb_pubkeys_open_config(
    config: ?*const TxnConfig,
) ?*PubkeyIter {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return null;
    };
    var pinned = PinnedReadDb.initConfig(cfg) catch |err| {
        setError("pinned rpmdb open failed: {t}", .{err});
        return null;
    };
    errdefer pinned.deinit();
    if (!pinned.exists) {
        pinned.deinit();
        return allocEmptyPubkeyIter();
    }
    const iter = pubkeysOpenAtPath(pinned.path.?) orelse {
        pinned.deinit();
        return null;
    };
    iter.pinned = pinned;
    return iter;
}

fn pubkeysOpenAtPath(db_path: []const u8) ?*PubkeyIter {
    const path_z: [*:0]const u8 = @ptrCast(db_path.ptr);
    if (pubkey_c.access(path_z, pubkey_c.F_OK) != 0) {
        const errno = std.c.errno(-1);
        if (errno == .NOENT or errno == .NOTDIR) {
            return allocEmptyPubkeyIter();
        }
        setError("rpmdb access({s}) failed: {t}", .{ db_path, errno });
        return null;
    }

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
    // Same query as iter_open; we filter the gpg-pubkey rows in Zig
    // because the NAME tag is buried inside the binary blob.
    const sql = "SELECT blob FROM " ++ PKG_TABLE ++ " ORDER BY hnum";
    const prepare_rc = c.sqlite3_prepare_v2(db, sql, sql.len, &stmt, null);
    if (prepare_rc != c.SQLITE_OK) {
        if (databaseHasNoTables(db)) {
            _ = c.sqlite3_close(db);
            return allocEmptyPubkeyIter();
        }
        setError("sqlite3_prepare_v2: {s}", .{
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        _ = c.sqlite3_close(db);
        return null;
    }

    const iter = std.heap.c_allocator.create(PubkeyIter) catch {
        setError("out of memory", .{});
        _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_close(db);
        return null;
    };
    iter.* = .{ .db = db, .stmt = stmt, .pinned = null };
    return iter;
}

fn allocEmptyPubkeyIter() ?*PubkeyIter {
    const iter = std.heap.c_allocator.create(PubkeyIter) catch {
        setError("out of memory", .{});
        return null;
    };
    iter.* = .{ .db = null, .stmt = null, .pinned = null };
    return iter;
}

fn databaseHasNoTables(db: ?*c.sqlite3) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table'";
    if (c.sqlite3_prepare_v2(db, sql, sql.len, &stmt, null) != c.SQLITE_OK)
        return false;
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return false;
    return c.sqlite3_column_int64(stmt, 0) == 0;
}

/// Close and free a pubkey iterator.
export fn tdnf_rpmdb_pubkeys_close(it: ?*PubkeyIter) void {
    const iter = it orelse return;
    if (iter.stmt) |s| _ = c.sqlite3_finalize(s);
    if (iter.db) |d| _ = c.sqlite3_close(d);
    if (iter.pinned) |*pinned| pinned.deinit();
    std.heap.c_allocator.destroy(iter);
}

/// Advance to the next `gpg-pubkey-*` row and write decoded PUBKEYS
/// bytes, or legacy RPMTAG_DESCRIPTION when PUBKEYS is absent.
///
/// On hit, writes:
///   *key_out      → malloc'd NUL-terminated C string with the
///                   armored key (free with tdnf_rpmdb_string_free)
///   *key_len_out  → byte length of the armored key, not counting
///                   the trailing NUL (may be NULL if uninterested)
///   *keyid_out    → malloc'd lowercase hex 8-character key id
///                   (= RPMTAG_VERSION); free with
///                   tdnf_rpmdb_string_free (may be NULL)
///
/// Returns 1 on hit, 0 on end-of-iteration, -1 on error.
export fn tdnf_rpmdb_pubkeys_next(
    it: ?*PubkeyIter,
    key_out: ?*[*:0]u8,
    key_len_out: ?*usize,
    keyid_out: ?*[*:0]u8,
) i32 {
    clearError();
    const iter = it orelse {
        setError("null iterator", .{});
        return -1;
    };
    const out = key_out orelse {
        setError("null key_out", .{});
        return -1;
    };
    if (iter.stmt == null) return 0;

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
            setError("rpmdb contains an empty header blob", .{});
            return -1;
        }
        const blob: []const u8 = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];

        const h = header.Header.parse(blob) catch |err| {
            setError("header.parse: {t}", .{err});
            return -1;
        };
        const name = h.getStringChecked(.name) catch |err| {
            setError("invalid rpmdb NAME: {t}", .{err});
            return -1;
        } orelse {
            setError("rpmdb header is missing NAME", .{});
            return -1;
        };
        if (!std.mem.eql(u8, name, "gpg-pubkey")) continue;

        const keyid = h.getStringChecked(.version) catch |err| {
            setError("invalid gpg-pubkey VERSION: {t}", .{err});
            return -1;
        } orelse {
            setError("gpg-pubkey header is missing VERSION", .{});
            return -1;
        };
        if (!isPubkeyVersion(keyid)) {
            setError("invalid gpg-pubkey VERSION", .{});
            return -1;
        }

        const pubkeys = rpmdb_pubkey.decodePubkeys(
            std.heap.c_allocator,
            h,
        ) catch |err| {
            setError("invalid gpg-pubkey PUBKEYS: {t}", .{err});
            return -1;
        };
        const key_bytes: []const u8 = if (pubkeys) |bytes|
            bytes
        else
            (h.getStringChecked(.description) catch |err| {
                setError("invalid gpg-pubkey DESCRIPTION: {t}", .{err});
                return -1;
            }) orelse {
                setError("gpg-pubkey header has neither PUBKEYS nor DESCRIPTION", .{});
                return -1;
            };
        defer if (pubkeys) |bytes| std.heap.c_allocator.free(bytes);

        var parsed = certificate.parseAll(
            std.heap.c_allocator,
            key_bytes,
        ) catch |err| {
            setError("invalid gpg-pubkey certificate: {t}", .{err});
            return -1;
        };
        parsed.deinit();

        out.* = dupZ(key_bytes) orelse return -1;
        if (key_len_out) |p| p.* = key_bytes.len;
        if (keyid_out) |p| {
            const id_z = dupZ(keyid) orelse {
                libc.free(@ptrCast(out.*));
                return -1;
            };
            p.* = id_z;
        }
        return 1;
    }
}

fn isPubkeyVersion(version: []const u8) bool {
    if (version.len != 8) return false;
    for (version) |ch| {
        if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

/// Helper: malloc + copy + NUL-terminate. Returns null and sets
/// last-error on allocation failure.
fn dupZ(src: []const u8) ?[*:0]u8 {
    const ptr = libc.malloc(src.len + 1) orelse {
        setError("out of memory", .{});
        return null;
    };
    const bytes = @as([*]u8, @ptrCast(ptr));
    @memcpy(bytes[0..src.len], src);
    bytes[src.len] = 0;
    return @ptrCast(bytes);
}

// -------------------------------------------------------------------
// `.rpm` file reader (T2)
// -------------------------------------------------------------------

const cpio = @import("cpio.zig");
const install_engine = @import("install.zig");
const erase_engine = @import("erase.zig");

const CInstallPriorHeader = extern struct {
    blob: ?[*]const u8,
    len: usize,
};

const CInstallConflictFn = *const fn (?*anyopaque, [*:0]const u8) callconv(.c) c_int;
const CChangedPathFn = *const fn (?*anyopaque, [*:0]const u8) callconv(.c) c_int;

const CInstallOptions = extern struct {
    install_root: ?[*:0]const u8,
    config: ?*const TxnConfig,
    trans_flags: u32,
    install_kind: c_int,
    prior_headers: ?[*]const CInstallPriorHeader,
    prior_header_count: usize,
    conflict_fn: ?CInstallConflictFn,
    conflict_fn_data: ?*anyopaque,
    changed_path_fn: ?CChangedPathFn,
    changed_path_fn_data: ?*anyopaque,
};

const CScriptletOptions = extern struct {
    install_root: ?[*:0]const u8,
    config: ?*const TxnConfig,
    install_root_fd: c_int,
    trans_flags: u32,
    rpmdefines: ?[*]const ?[*:0]const u8,
    rpmdefine_count: usize,
    arg1: c_int,
    arg2: c_int,
    script_fd: c_int,
    redirect_stdout_to_stderr: c_int,
};

const CScriptletResult = extern struct {
    ran: c_int,
    critical: c_int,
    outcome: u32,
    exit_status: c_int,
    signal_number: c_int,
};

const CHeaderView = extern struct {
    blob: ?[*]const u8,
    len: usize,
};

const CTriggerOptions = extern struct {
    db_root: ?[*:0]const u8,
    install_root: ?[*:0]const u8,
    config: ?*const TxnConfig,
    install_root_fd: c_int,
    trans_flags: u32,
    rpmdefines: ?[*]const ?[*:0]const u8,
    rpmdefine_count: usize,
    script_fd: c_int,
    redirect_stdout_to_stderr: c_int,
    /// Optional explicit `$2` argument for trigger scripts. When
    /// `arg2_override_present` is 0, the engine derives `$2` from
    /// the current rpmdb state (real rpm's plain-erase / plain-
    /// install formula). When non-zero, `arg2_override_value` is
    /// passed verbatim as `$2` — the executor uses this to match
    /// real rpm's upgrade semantics where the transient two-
    /// instance state is not visible after `write_replace`. See
    /// `Options.arg2_override` in rpmzig/trigger.zig for details.
    arg2_override_present: c_int,
    arg2_override_value: c_int,
    transaction_headers: ?[*]const CHeaderView,
    transaction_header_count: usize,
    transaction_view_present: c_int,
    trigger_owner_headers: ?[*]const CHeaderView,
    trigger_owner_header_count: usize,
    trigger_owner_view_present: c_int,
};

const CTriggerResult = extern struct {
    ran: c_int,
    critical: c_int,
    outcome: u32,
    exit_status: c_int,
    signal_number: c_int,
};

const CTriggerPath = extern struct {
    path: ?[*:0]const u8,
    source_header_blob: ?[*]const u8,
    source_header_len: usize,
};

const CFileTriggerOwner = extern struct {
    header_blob: ?[*]const u8,
    header_len: usize,
    paths: ?[*]const CTriggerPath,
    path_count: usize,
    order: u64,
};

const CFileTriggerOptions = extern struct {
    install_root: ?[*:0]const u8,
    config: ?*const TxnConfig,
    install_root_fd: c_int,
    trans_flags: u32,
    rpmdefines: ?[*]const ?[*:0]const u8,
    rpmdefine_count: usize,
    script_fd: c_int,
    redirect_stdout_to_stderr: c_int,
    suppress_stdin: c_int,
};

const ConflictBridge = struct {
    cb: ?CInstallConflictFn,
    data: ?*anyopaque,
};

const ChangedPathBridge = struct {
    cb: ?CChangedPathFn,
    data: ?*anyopaque,
};

fn conflictBridge(ctx: ?*anyopaque, path: []const u8) i32 {
    const bridge: *const ConflictBridge = @ptrCast(@alignCast(ctx orelse return -1));
    const cb = bridge.cb orelse return 0;
    const path_z = std.heap.c_allocator.dupeZ(u8, path) catch return -1;
    defer std.heap.c_allocator.free(path_z);
    return cb(bridge.data, path_z);
}

fn changedPathBridge(ctx: ?*anyopaque, path: []const u8) i32 {
    const bridge: *const ChangedPathBridge = @ptrCast(@alignCast(ctx orelse return -1));
    const cb = bridge.cb orelse return 0;
    const path_z = std.heap.c_allocator.dupeZ(u8, path) catch return -1;
    defer std.heap.c_allocator.free(path_z);
    return cb(bridge.data, path_z);
}

const CEraseKeepPathFn = *const fn (?*anyopaque, [*:0]const u8) callconv(.c) c_int;

const CEraseOptions = extern struct {
    config: ?*const TxnConfig,
    trans_flags: u32,
    keep_path_fn: ?CEraseKeepPathFn,
    keep_path_fn_data: ?*anyopaque,
};

const EraseKeepPathBridge = struct {
    cb: ?CEraseKeepPathFn,
    data: ?*anyopaque,
};

fn eraseKeepPathBridge(ctx: ?*anyopaque, path: []const u8) i32 {
    const bridge: *const EraseKeepPathBridge = @ptrCast(@alignCast(ctx orelse return -1));
    const cb = bridge.cb orelse return 0;
    const path_z = std.heap.c_allocator.dupeZ(u8, path) catch return -1;
    defer std.heap.c_allocator.free(path_z);
    return cb(bridge.data, path_z);
}

const DefaultEraseKeepPathCtx = struct {
    writer: *rpmdb_write.Writer,
    hnum: u32,
};

fn defaultEraseKeepPath(ctx: ?*anyopaque, path: []const u8) i32 {
    const keep_ctx: *DefaultEraseKeepPathCtx = @ptrCast(@alignCast(ctx orelse return -1));
    const owned = keep_ctx.writer.pathOwnedByOtherPackage(keep_ctx.hnum, path) catch return -1;
    return if (owned) 1 else 0;
}

// PR #5 of plan-pure-zig-pgp.md: pull the pure-Zig PGP verifier into
// the rpmzig static library so its `export fn rpmzig_verify_detached`
// is reachable from C. A bare `_ = @import(...)` in a `comptime`
// block forces the compiler to evaluate the module at non-test
// build time, which in turn instantiates any `export fn` it declares.
comptime {
    _ = @import("pgp/verify.zig");
    _ = @import("checksum.zig");
}

/// Opaque handle wrapping a parsed RpmFile and its allocator.
pub const FileHandle = struct {
    file: pkgfile.RpmFile,

    pub fn mainHeader(self: *const FileHandle) header.Header {
        return self.file.main;
    }
};

const FileMetadata = extern struct {
    name: ?[*:0]const u8,
    version: ?[*:0]const u8,
    release: ?[*:0]const u8,
    arch: ?[*:0]const u8,
    epoch: u32,
    has_epoch: c_int,
    package_kind: c_int,
    main_header_blob: ?[*]const u8,
    main_header_blob_len: usize,
};

/// Open and parse a `.rpm` file. Returns NULL on error (consult
/// tdnf_rpmdb_last_error()).
export fn tdnf_rpm_file_open(path: ?[*:0]const u8) ?*FileHandle {
    clearError();
    const p = path orelse {
        setError("null path", .{});
        return null;
    };
    const path_slice = std.mem.span(p);
    // Convert to sentinel-terminated for libc.
    const path_z = std.heap.c_allocator.dupeZ(u8, path_slice) catch {
        setError("out of memory", .{});
        return null;
    };
    defer std.heap.c_allocator.free(path_z);

    const fh = std.heap.c_allocator.create(FileHandle) catch {
        setError("out of memory", .{});
        return null;
    };
    fh.file = pkgfile.RpmFile.open(std.heap.c_allocator, path_z) catch |err| {
        setError("rpm_file_open({s}): {t}", .{ path_slice, err });
        std.heap.c_allocator.destroy(fh);
        return null;
    };
    return fh;
}

/// Free a file handle. Accepts NULL.
export fn tdnf_rpm_file_close(fh: ?*FileHandle) void {
    const f = fh orelse return;
    f.file.close(std.heap.c_allocator);
    std.heap.c_allocator.destroy(f);
}

/// Returns a heap-allocated NEVRA string for this rpm file. Caller
/// frees with tdnf_rpmdb_string_free.
export fn tdnf_rpm_file_nevra(fh: ?*FileHandle) ?[*:0]u8 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return null;
    };
    const nevra_opt = f.file.allocNevra(std.heap.c_allocator) catch {
        setError("out of memory", .{});
        return null;
    };
    const nevra = nevra_opt orelse {
        setError("file header missing required tag for NEVRA", .{});
        return null;
    };
    defer std.heap.c_allocator.free(nevra);

    const out = libc.malloc(nevra.len + 1) orelse {
        setError("out of memory", .{});
        return null;
    };
    const out_bytes = @as([*]u8, @ptrCast(out));
    @memcpy(out_bytes[0..nevra.len], nevra);
    out_bytes[nevra.len] = 0;
    return @ptrCast(out_bytes);
}

export fn tdnf_rpm_file_package_kind(fh: ?*FileHandle) i32 {
    const f = fh orelse return -1;
    return switch (f.file.packageKind()) {
        .binary => 0,
        .source => 1,
        .nosrc => 2,
    };
}

export fn tdnf_rpm_file_get_metadata(
    fh: ?*FileHandle,
    metadata_out: ?*FileMetadata,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const out = metadata_out orelse {
        setError("null metadata output", .{});
        return -1;
    };
    out.* = std.mem.zeroes(FileMetadata);

    const name = f.file.main.getStringChecked(.name) catch {
        setError("malformed package name", .{});
        return -1;
    } orelse {
        setError("package name is missing", .{});
        return -1;
    };
    const version = f.file.main.getStringChecked(.version) catch {
        setError("malformed package version", .{});
        return -1;
    } orelse {
        setError("package version is missing", .{});
        return -1;
    };
    const release = f.file.main.getStringChecked(.release) catch {
        setError("malformed package release", .{});
        return -1;
    } orelse {
        setError("package release is missing", .{});
        return -1;
    };
    const arch = f.file.main.getStringChecked(.arch) catch {
        setError("malformed package arch", .{});
        return -1;
    } orelse {
        setError("package arch is missing", .{});
        return -1;
    };
    if (name.len == 0 or version.len == 0 or release.len == 0 or arch.len == 0) {
        setError("package metadata contains an empty required value", .{});
        return -1;
    }
    const epoch = f.file.main.getU32Checked(.epoch) catch {
        setError("malformed package epoch", .{});
        return -1;
    };

    out.name = @ptrCast(name.ptr);
    out.version = @ptrCast(version.ptr);
    out.release = @ptrCast(release.ptr);
    out.arch = @ptrCast(arch.ptr);
    out.epoch = epoch orelse 0;
    out.has_epoch = if (epoch != null) 1 else 0;
    out.package_kind = switch (f.file.packageKind()) {
        .binary => 0,
        .source => 1,
        .nosrc => 2,
    };
    out.main_header_blob = f.file.main.bytes.ptr;
    out.main_header_blob_len = f.file.main.bytes.len;
    return 0;
}

export fn tdnf_rpm_header_name_equals(
    header_blob: ?[*]const u8,
    header_len: usize,
    name: ?[*:0]const u8,
) i32 {
    clearError();
    const blob_ptr = header_blob orelse {
        setError("null header blob", .{});
        return -1;
    };
    const name_ptr = name orelse {
        setError("null package name", .{});
        return -1;
    };
    if (header_len == 0) {
        setError("empty header blob", .{});
        return -1;
    }
    const hdr = header.Header.parse(blob_ptr[0..header_len]) catch |err| {
        setError("header.parse: {t}", .{err});
        return -1;
    };
    const actual = hdr.getStringChecked(.name) catch {
        setError("malformed package name", .{});
        return -1;
    } orelse {
        setError("package name is missing", .{});
        return -1;
    };
    return if (std.mem.eql(u8, actual, std.mem.span(name_ptr))) 1 else 0;
}

export fn tdnf_rpm_header_owns_path(
    header_blob: ?[*]const u8,
    header_len: usize,
    path: ?[*:0]const u8,
) i32 {
    clearError();
    const blob_ptr = header_blob orelse {
        setError("null header blob", .{});
        return -1;
    };
    const path_ptr = path orelse {
        setError("null package path", .{});
        return -1;
    };
    if (header_len == 0) {
        setError("empty header blob", .{});
        return -1;
    }
    const hdr = header.Header.parse(blob_ptr[0..header_len]) catch |err| {
        setError("header.parse: {t}", .{err});
        return -1;
    };
    var manifest = install_engine.Manifest.init(
        std.heap.c_allocator,
        hdr,
    ) catch |err| {
        setError("manifest: {t}", .{err});
        return -1;
    };
    defer manifest.deinit();
    return if (manifest.index.contains(std.mem.span(path_ptr))) 1 else 0;
}

fn rpmCanonicalPathConfig(
    config: ?*const TxnConfig,
    path: ?[*:0]const u8,
    output: ?[*]u8,
    output_len: usize,
) callconv(.c) i32 {
    clearError();
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const path_ptr = path orelse {
        setError("null package path", .{});
        return -1;
    };
    const out = output orelse {
        setError("null canonical path output", .{});
        return -1;
    };
    var root = install_engine.RootDir.init(
        std.heap.c_allocator,
        cfg.installRoot(),
        null,
        null,
    ) catch |err| {
        setError("open installroot: {t}", .{err});
        return -1;
    };
    defer root.deinit();
    const canonical = root.canonicalPathOwned(
        std.mem.span(path_ptr),
    ) catch |err| {
        setError("canonical path: {t}", .{err});
        return -1;
    };
    defer std.heap.c_allocator.free(canonical);
    if (canonical.len + 1 > output_len) {
        setError("canonical path output is too small", .{});
        return -1;
    }
    @memcpy(out[0..canonical.len], canonical);
    out[canonical.len] = 0;
    return 0;
}

fn rpmHeaderOwnsPathConfig(
    header_blob: ?[*]const u8,
    header_len: usize,
    path: ?[*:0]const u8,
    config: ?*const TxnConfig,
) callconv(.c) i32 {
    clearError();
    const blob_ptr = header_blob orelse return -1;
    const path_ptr = path orelse return -1;
    const cfg = config orelse return -1;
    const hdr = header.Header.parse(blob_ptr[0..header_len]) catch return -1;
    var manifest = install_engine.Manifest.init(
        std.heap.c_allocator,
        hdr,
    ) catch return -1;
    defer manifest.deinit();
    var root = install_engine.RootDir.init(
        std.heap.c_allocator,
        cfg.installRoot(),
        null,
        null,
    ) catch return -1;
    defer root.deinit();
    const wanted = root.canonicalPathOwned(
        std.mem.span(path_ptr),
    ) catch return -1;
    defer std.heap.c_allocator.free(wanted);
    for (manifest.files) |file| {
        const candidate = root.canonicalPathOwned(file.path) catch return -1;
        defer std.heap.c_allocator.free(candidate);
        if (std.mem.eql(u8, candidate, wanted)) return 1;
    }
    return 0;
}

comptime {
    @export(&rpmCanonicalPathConfig, .{
        .name = "tdnf_rpm_canonical_path_config",
        .visibility = .hidden,
    });
    @export(&rpmHeaderOwnsPathConfig, .{
        .name = "tdnf_rpm_header_owns_path_config",
        .visibility = .hidden,
    });
}

/// Returns the raw main-header blob for this rpm file.
///
/// The returned bytes alias the file handle's owned buffer and stay
/// valid until tdnf_rpm_file_close(). The blob is the header-v3 body
/// without the 8-byte standalone magic prefix, matching rpmdb.sqlite's
/// Packages.blob format and suitable for tdnf_rpm_file_install()'s
/// prior_headers input.
export fn tdnf_rpm_file_main_header_blob(
    fh: ?*FileHandle,
    out: ?*[*]const u8,
    out_len: ?*usize,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const out_ptr = out orelse {
        setError("null out pointer", .{});
        return -1;
    };
    const len_ptr = out_len orelse {
        setError("null out_len pointer", .{});
        return -1;
    };

    out_ptr.* = f.file.main.bytes.ptr;
    len_ptr.* = f.file.main.bytes.len;
    return 0;
}

export fn tdnf_rpm_file_bytes(
    fh: ?*FileHandle,
    out: ?*[*]const u8,
    out_len: ?*usize,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const out_ptr = out orelse {
        setError("null out pointer", .{});
        return -1;
    };
    const len_ptr = out_len orelse {
        setError("null out_len pointer", .{});
        return -1;
    };

    out_ptr.* = f.file.bytes.ptr;
    len_ptr.* = f.file.bytes.len;
    return 0;
}

export fn tdnf_rpm_file_digest(
    fh: ?*FileHandle,
    kind: c_int,
    out_digest: ?[*]u8,
    out_len: usize,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const out = out_digest orelse {
        setError("null digest output", .{});
        return -1;
    };
    const ctx = checksum.tdnf_rpmzig_digest_open(kind) orelse {
        setError("unable to open digest context", .{});
        return -1;
    };
    defer checksum.tdnf_rpmzig_digest_close(ctx);

    if (checksum.tdnf_rpmzig_digest_update(
        ctx,
        f.file.bytes.ptr,
        f.file.bytes.len,
    ) != 0) {
        setError("unable to update digest context", .{});
        return -1;
    }
    if (checksum.tdnf_rpmzig_digest_final(ctx, out, out_len) != 0) {
        setError("unable to finalize digest context", .{});
        return -1;
    }
    return 0;
}

/// Returns the payload compressor name as a static C string.
/// One of: "none", "gzip", "bzip2", "xz", "lzma", "zstd", "lz4",
/// "unknown".
export fn tdnf_rpm_file_compressor(fh: ?*FileHandle) [*:0]const u8 {
    const f = fh orelse return "unknown";
    return switch (f.file.compressor) {
        .none => "none",
        .gzip => "gzip",
        .bzip2 => "bzip2",
        .xz => "xz",
        .lzma => "lzma",
        .zstd => "zstd",
        .lz4 => "lz4",
        .unknown => "unknown",
    };
}

/// Returns the byte offset of the payload (cpio archive) within the
/// underlying file. Useful for callers that want to stream the
/// payload through a decompressor.
export fn tdnf_rpm_file_payload_offset(fh: ?*FileHandle) i64 {
    const f = fh orelse return -1;
    return @intCast(f.file.payload_offset);
}

/// Returns 1 if the rpm has any of the known signature tags
/// (RSA/DSA/PGP/GPG/OpenPGP) in its signature header, 0 otherwise.
/// Returns -1 on a NULL handle. This is *presence* only — real
/// verification is T3.
export fn tdnf_rpm_file_is_signed(fh: ?*FileHandle) i32 {
    const f = fh orelse return -1;
    return if (f.file.isSigned()) 1 else 0;
}

const IntegrityOutcome = enum(i32) {
    ok = 0,
    missing = 1,
    bad = 2,
    unsupported = 3,
    malformed = 4,
    internal = 5,
};

fn classifyDigests(report: *const integrity.Report) IntegrityOutcome {
    var saw_bad = false;
    var saw_unsupported = false;
    var saw_malformed = false;

    for (report.candidates, 0..) |candidate, index| {
        if (candidate.suppressed_legacy) continue;
        switch (candidate.outcome) {
            .bad_digest => {
                if (!report.failureSuppressedByAlternative(index))
                    saw_bad = true;
            },
            .malformed_tag => {
                if (!report.failureSuppressedByAlternative(index))
                    saw_malformed = true;
            },
            .unsupported_digest => {
                if (!report.failureSuppressedByAlternative(index))
                    saw_unsupported = true;
            },
            else => {},
        }
    }

    if (saw_malformed) return .malformed;
    if (saw_bad) return .bad;
    if (saw_unsupported) return .unsupported;
    if (!report.coverage.header_verified or !report.coverage.payload_verified)
        return .missing;
    return .ok;
}

fn classifySignatures(report: *const integrity.SignatureReport) IntegrityOutcome {
    var saw_missing_key = false;
    var saw_bad = false;
    var saw_unsupported = false;
    var saw_malformed = false;
    var saw_internal = false;

    for (report.candidates) |candidate| {
        switch (candidate.outcome) {
            .no_key => saw_missing_key = true,
            .bad_signature => saw_bad = true,
            .unsupported_openpgp => saw_unsupported = true,
            .malformed_tag, .malformed_base64, .malformed_openpgp => saw_malformed = true,
            .unchecked => saw_internal = true,
            else => {},
        }
    }

    if (saw_malformed) return .malformed;
    if (saw_bad) return .bad;
    if (saw_unsupported) return .unsupported;
    if (saw_internal) return .internal;
    if (report.coverage.no_signature_candidates or saw_missing_key)
        return .missing;
    if (report.coverage.any_enabled_unsuppressed_failure or
        !report.coverage.fully_verified)
        return .internal;
    return .ok;
}

fn verifyFileDigests(
    allocator: std.mem.Allocator,
    file: *const FileHandle,
    out: *i32,
) i32 {
    var report = integrity.verifyPackage(
        allocator,
        &file.file,
        .{},
    ) catch |err| {
        setError("verify package digests: {t}", .{err});
        return -1;
    };
    defer report.deinit(allocator);

    if (integrity.rpm6SuppressesLegacySignatureHeader(&file.file))
        report.suppressLegacySignatureHeader();
    out.* = @intFromEnum(classifyDigests(&report));
    return 0;
}

/// Verify every internal package digest on this parsed file.  The caller
/// chooses whether to enforce this result, so --skipdigest can bypass this
/// call without weakening parser validation.
export fn tdnf_rpm_file_verify_digests(
    fh: ?*FileHandle,
    outcome_out: ?*i32,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const out = outcome_out orelse {
        setError("null integrity outcome", .{});
        return -1;
    };

    return verifyFileDigests(std.heap.c_allocator, f, out);
}

fn verifyFileSignatures(
    allocator: std.mem.Allocator,
    file: *const FileHandle,
    key_blobs: []const []const u8,
    out: *i32,
) i32 {
    var report = integrity.verifySignatures(
        allocator,
        &file.file,
        .{},
        key_blobs,
    ) catch |err| {
        setError("verify package signatures: {t}", .{err});
        return -1;
    };
    defer report.deinit(allocator);

    out.* = @intFromEnum(classifySignatures(&report));
    return 0;
}

/// Verify all package signatures with the complete configured rpmdb trust
/// set plus the newly approved repository keys.  This intentionally gathers
/// every key before invoking integrity.verifySignatures exactly once.
export fn tdnf_rpm_file_verify_signatures_config(
    fh: ?*FileHandle,
    config: ?*const TxnConfig,
    fresh_key_blobs: ?[*]const ?*const anyopaque,
    fresh_key_lens: ?[*]const usize,
    fresh_key_count: usize,
    outcome_out: ?*i32,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const out = outcome_out orelse {
        setError("null integrity outcome", .{});
        return -1;
    };
    if (fresh_key_count > 0 and
        (fresh_key_blobs == null or fresh_key_lens == null))
    {
        setError("null fresh keys with non-zero key count", .{});
        return -1;
    }

    var key_blobs = std.ArrayList([]const u8).empty;
    defer key_blobs.deinit(std.heap.c_allocator);
    var rpmdb_keys = std.ArrayList([*:0]u8).empty;
    defer {
        for (rpmdb_keys.items) |key| libc.free(@ptrCast(key));
        rpmdb_keys.deinit(std.heap.c_allocator);
    }

    if (fresh_key_count > 0) {
        const fresh_ptrs = fresh_key_blobs.?;
        const fresh_lens = fresh_key_lens.?;
        for (0..fresh_key_count) |index| {
            const key = fresh_ptrs[index] orelse {
                setError("fresh key {d} is null", .{index});
                return -1;
            };
            if (fresh_lens[index] == 0) {
                setError("fresh key {d} is empty", .{index});
                return -1;
            }
            key_blobs.append(std.heap.c_allocator, @as([*]const u8, @ptrCast(key))[0..fresh_lens[index]]) catch {
                setError("out of memory collecting fresh keys", .{});
                return -1;
            };
        }
    }

    const iter = tdnf_rpmdb_pubkeys_open_config(cfg) orelse return -1;
    defer tdnf_rpmdb_pubkeys_close(iter);
    while (true) {
        var key: [*:0]u8 = undefined;
        var key_len: usize = 0;
        const next = tdnf_rpmdb_pubkeys_next(iter, &key, &key_len, null);
        if (next == 0) break;
        if (next < 0) return -1;
        rpmdb_keys.append(std.heap.c_allocator, key) catch {
            libc.free(@ptrCast(key));
            setError("out of memory collecting rpmdb keys", .{});
            return -1;
        };
        key_blobs.append(std.heap.c_allocator, key[0..key_len]) catch {
            setError("out of memory collecting rpmdb keys", .{});
            return -1;
        };
    }

    return verifyFileSignatures(
        std.heap.c_allocator,
        f,
        key_blobs.items,
        out,
    );
}

test "integrity ABI digest outcomes retain typed policy failures" {
    var bad_candidate = [_]integrity.Candidate{.{
        .kind = .header_sha256,
        .range = .header,
        .algorithm = .sha256,
        .tag = @intFromEnum(header.SigTagId.sha256),
        .disabler = .sha256_header,
        .outcome = .bad_digest,
    }};
    var malformed_candidate = [_]integrity.Candidate{.{
        .kind = .header_sha256,
        .range = .header,
        .algorithm = .sha256,
        .tag = @intFromEnum(header.SigTagId.sha256),
        .disabler = .sha256_header,
        .outcome = .malformed_tag,
    }};
    var unsupported_candidate = [_]integrity.Candidate{.{
        .kind = .header_sha3_256,
        .range = .header,
        .algorithm = .sha3_256,
        .tag = @intFromEnum(header.SigTagId.sha3_256),
        .disabler = .sha3_256_header,
        .outcome = .unsupported_digest,
    }};
    const verified_coverage = integrity.Coverage{
        .header_verified = true,
        .payload_verified = true,
        .no_digest_candidates = false,
        .any_enabled_present_bad_or_malformed = false,
    };

    try std.testing.expectEqual(
        IntegrityOutcome.bad,
        classifyDigests(&.{ .candidates = &bad_candidate, .coverage = verified_coverage }),
    );
    try std.testing.expectEqual(
        IntegrityOutcome.malformed,
        classifyDigests(&.{ .candidates = &malformed_candidate, .coverage = verified_coverage }),
    );
    try std.testing.expectEqual(
        IntegrityOutcome.unsupported,
        classifyDigests(&.{ .candidates = &unsupported_candidate, .coverage = verified_coverage }),
    );
    try std.testing.expectEqual(
        IntegrityOutcome.missing,
        classifyDigests(&.{ .candidates = &.{}, .coverage = .{
            .header_verified = false,
            .payload_verified = false,
            .no_digest_candidates = true,
            .any_enabled_present_bad_or_malformed = false,
        } }),
    );
}

test "digest ABI suppresses bad legacy MD5 for RPM6 coverage" {
    var file = FileHandle{
        .file = try integrity.makeRpm6BadLegacyDigestFixtureForTest(
            std.testing.allocator,
        ),
    };
    defer file.file.close(std.testing.allocator);

    var outcome: i32 = @intFromEnum(IntegrityOutcome.internal);
    try std.testing.expectEqual(
        @as(i32, 0),
        tdnf_rpm_file_verify_digests(&file, &outcome),
    );
    try std.testing.expectEqual(
        @intFromEnum(IntegrityOutcome.ok),
        outcome,
    );
}

test "digest ABI accepts verified compressed digest with unsupported alternate" {
    var file = FileHandle{
        .file = try integrity.makeLz4AlternateDigestFixtureForTest(
            std.testing.allocator,
        ),
    };
    defer file.file.close(std.testing.allocator);

    var outcome: i32 = @intFromEnum(IntegrityOutcome.internal);
    try std.testing.expectEqual(
        @as(i32, 0),
        tdnf_rpm_file_verify_digests(&file, &outcome),
    );
    try std.testing.expectEqual(
        @intFromEnum(IntegrityOutcome.ok),
        outcome,
    );
}

test "integrity ABI reports verifier allocation failures" {
    var file = FileHandle{
        .file = try integrity.makeRpm6BadLegacyDigestFixtureForTest(
            std.testing.allocator,
        ),
    };
    defer file.file.close(std.testing.allocator);

    var digest_allocator = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var outcome: i32 = 99;
    clearError();
    try std.testing.expectEqual(
        @as(i32, -1),
        verifyFileDigests(digest_allocator.allocator(), &file, &outcome),
    );
    try std.testing.expectEqual(@as(i32, 99), outcome);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            std.mem.span(tdnf_rpmdb_last_error()),
            "OutOfMemory",
        ) != null,
    );

    var signature_allocator = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    outcome = 99;
    clearError();
    try std.testing.expectEqual(
        @as(i32, -1),
        verifyFileSignatures(
            signature_allocator.allocator(),
            &file,
            &.{},
            &outcome,
        ),
    );
    try std.testing.expectEqual(@as(i32, 99), outcome);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            std.mem.span(tdnf_rpmdb_last_error()),
            "OutOfMemory",
        ) != null,
    );
}

test "integrity ABI signature outcomes retain typed policy failures" {
    var no_key_candidate = [_]integrity.SignatureCandidate{.{
        .kind = .header_rsa,
        .range = .header,
        .signed_start = 0,
        .signed_end = 1,
        .tag = @intFromEnum(header.SigTagId.rsa),
        .policy_enabled = true,
        .outcome = .no_key,
        .raw_outcome = .no_key,
    }};
    var malformed_candidate = [_]integrity.SignatureCandidate{.{
        .kind = .openpgp,
        .range = .header,
        .signed_start = 0,
        .signed_end = 1,
        .tag = @intFromEnum(header.SigTagId.openpgp),
        .policy_enabled = true,
        .outcome = .malformed_openpgp,
        .raw_outcome = .malformed_openpgp,
    }};
    var unsupported_candidate = [_]integrity.SignatureCandidate{.{
        .kind = .openpgp,
        .range = .header,
        .signed_start = 0,
        .signed_end = 1,
        .tag = @intFromEnum(header.SigTagId.openpgp),
        .policy_enabled = true,
        .outcome = .unsupported_openpgp,
        .raw_outcome = .unsupported_openpgp,
    }};
    var verified_candidate = [_]integrity.SignatureCandidate{.{
        .kind = .header_rsa,
        .range = .header,
        .signed_start = 0,
        .signed_end = 1,
        .tag = @intFromEnum(header.SigTagId.rsa),
        .policy_enabled = true,
        .outcome = .verified,
        .raw_outcome = .verified,
    }};
    const complete_coverage = integrity.SignatureCoverage{
        .header_relevant = true,
        .payload_relevant = false,
        .header_verified = true,
        .payload_verified = false,
        .no_signature_candidates = false,
        .any_enabled_unsuppressed_failure = false,
        .fully_verified = true,
    };

    try std.testing.expectEqual(
        IntegrityOutcome.missing,
        classifySignatures(&.{
            .candidates = &no_key_candidate,
            .coverage = complete_coverage,
            .openpgp_suppresses_legacy = false,
            .rpm6_suppresses_legacy_signature_header = false,
            .legacy_md5_suppressed = false,
        }),
    );
    try std.testing.expectEqual(
        IntegrityOutcome.malformed,
        classifySignatures(&.{
            .candidates = &malformed_candidate,
            .coverage = complete_coverage,
            .openpgp_suppresses_legacy = false,
            .rpm6_suppresses_legacy_signature_header = false,
            .legacy_md5_suppressed = false,
        }),
    );
    try std.testing.expectEqual(
        IntegrityOutcome.unsupported,
        classifySignatures(&.{
            .candidates = &unsupported_candidate,
            .coverage = complete_coverage,
            .openpgp_suppresses_legacy = false,
            .rpm6_suppresses_legacy_signature_header = false,
            .legacy_md5_suppressed = false,
        }),
    );
    try std.testing.expectEqual(
        IntegrityOutcome.ok,
        classifySignatures(&.{
            .candidates = &verified_candidate,
            .coverage = complete_coverage,
            .openpgp_suppresses_legacy = false,
            .rpm6_suppresses_legacy_signature_header = false,
            .legacy_md5_suppressed = false,
        }),
    );
}

/// Returns a static C string naming the kind of signature on this
/// rpm: "none", "rsa", "dsa", "pgp", "gpg", or "openpgp". Returns
/// "none" on a NULL handle.
export fn tdnf_rpm_file_signature_kind(fh: ?*FileHandle) [*:0]const u8 {
    const f = fh orelse return "none";
    return switch (f.file.signatureKind()) {
        .none => "none",
        .rsa => "rsa",
        .dsa => "dsa",
        .pgp => "pgp",
        .gpg => "gpg",
        .openpgp => "openpgp",
    };
}

/// Returns the signature payload + signed byte range. Both slices
/// alias into the file's owned buffer (do NOT free them).
///
/// Returns 0 on success, -1 on NULL handle or no signature.
export fn tdnf_rpm_file_signed_range(
    fh: ?*FileHandle,
    sig_out: ?*[*]const u8,
    sig_len_out: ?*usize,
    signed_out: ?*[*]const u8,
    signed_len_out: ?*usize,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const r = f.file.signatureSlice() orelse {
        setError("rpm carries no signature", .{});
        return -1;
    };
    if (sig_out) |p| p.* = r.sig.ptr;
    if (sig_len_out) |p| p.* = r.sig.len;
    if (signed_out) |p| p.* = r.signed.ptr;
    if (signed_len_out) |p| p.* = r.signed.len;
    return 0;
}

/// Decompress the payload (cpio archive) into a fresh malloc'd
/// buffer. On success, writes the pointer to `*out` and the byte
/// count to `*out_size`. Caller frees with tdnf_rpmdb_string_free
/// (it wraps `free(3)`).
///
/// Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error).
export fn tdnf_rpm_file_decompress_payload(
    fh: ?*FileHandle,
    out: ?*[*]u8,
    out_size: ?*usize,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const out_p = out orelse {
        setError("null out pointer", .{});
        return -1;
    };
    const out_sz = out_size orelse {
        setError("null out_size pointer", .{});
        return -1;
    };

    const bytes = f.file.decompressPayload(std.heap.c_allocator) catch |err| {
        setError("decompressPayload: {t}", .{err});
        return -1;
    };
    defer std.heap.c_allocator.free(bytes);

    const buf = libc.malloc(bytes.len) orelse {
        setError("out of memory", .{});
        return -1;
    };
    @memcpy(@as([*]u8, @ptrCast(buf))[0..bytes.len], bytes);
    out_p.* = @ptrCast(buf);
    out_sz.* = bytes.len;
    return 0;
}

export fn tdnf_rpm_file_extract_source_config(
    fh: ?*FileHandle,
    config: ?*const TxnConfig,
    trans_flags: u32,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    source_engine.extract(
        std.heap.c_allocator,
        &f.file,
        cfg,
        trans_flags,
    ) catch |err| {
        setError("source extraction: {t}", .{err});
        return -1;
    };
    return 0;
}

/// Install this rpm file's payload into install_root using the native
/// rpmzig file-installation engine.
export fn tdnf_rpm_file_install(
    fh: ?*FileHandle,
    options: ?*const CInstallOptions,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const opts = options orelse {
        setError("null install options", .{});
        return -1;
    };

    const install_root = if (opts.install_root) |p| std.mem.span(p) else "";

    const kind: install_engine.InstallKind = switch (opts.install_kind) {
        0 => .install,
        1 => .upgrade,
        2 => .reinstall,
        else => {
            setError("unsupported install_kind: {d}", .{opts.install_kind});
            return -1;
        },
    };

    var prior_headers = std.heap.c_allocator.alloc(header.Header, opts.prior_header_count) catch {
        setError("out of memory", .{});
        return -1;
    };
    defer std.heap.c_allocator.free(prior_headers);

    if (opts.prior_header_count > 0 and opts.prior_headers == null) {
        setError("null prior_headers with non-zero prior_header_count", .{});
        return -1;
    }

    for (0..opts.prior_header_count) |i| {
        const prior = opts.prior_headers.?[i];
        const blob_ptr = prior.blob orelse {
            setError("prior header {d} missing blob", .{i});
            return -1;
        };
        prior_headers[i] = header.Header.parse(blob_ptr[0..prior.len]) catch |err| {
            setError("prior header {d}: {t}", .{ i, err });
            return -1;
        };
    }

    var bridge = ConflictBridge{
        .cb = opts.conflict_fn,
        .data = opts.conflict_fn_data,
    };
    var changed_path_bridge = ChangedPathBridge{
        .cb = opts.changed_path_fn,
        .data = opts.changed_path_fn_data,
    };

    var ctx = install_engine.Context.init(std.heap.c_allocator, &f.file, .{
        .install_root = install_root,
        .config = opts.config,
        .trans_flags = opts.trans_flags,
        .install_kind = kind,
        .prior_headers = prior_headers,
        .conflict_fn = if (opts.conflict_fn != null) conflictBridge else null,
        .conflict_ctx = if (opts.conflict_fn != null) &bridge else null,
        .changed_path_fn = if (opts.changed_path_fn != null) changedPathBridge else null,
        .changed_path_ctx = if (opts.changed_path_fn != null) &changed_path_bridge else null,
    }) catch |err| {
        setError("install init: {t}", .{err});
        return -1;
    };
    defer ctx.deinit();

    ctx.install() catch |err| {
        if (ctx.last_path) |path| {
            setError("rpm_file_install({s}): {t}", .{ path, err });
        } else {
            setError("rpm_file_install: {t}", .{err});
        }
        return -1;
    };
    return 0;
}

/// Run one package/transaction scriptlet extracted from a raw
/// RPM main-header blob.
export fn tdnf_rpm_header_run_scriptlet(
    header_blob: ?[*]const u8,
    header_len: usize,
    phase: c_int,
    options: ?*const CScriptletOptions,
    result_out: ?*CScriptletResult,
) i32 {
    clearError();
    const blob_ptr = header_blob orelse {
        setError("null header_blob", .{});
        return -1;
    };
    const opts = options orelse {
        setError("null scriptlet options", .{});
        return -1;
    };
    const out = result_out orelse {
        setError("null scriptlet result", .{});
        return -1;
    };

    const script_phase: scriptlet_engine.Phase = switch (phase) {
        0 => .pre,
        1 => .post,
        2 => .preun,
        3 => .postun,
        4 => .pretrans,
        5 => .posttrans,
        else => {
            setError("unsupported scriptlet phase: {d}", .{phase});
            return -1;
        },
    };

    var rpmdefines = std.ArrayList([]const u8).empty;
    defer rpmdefines.deinit(std.heap.c_allocator);

    if (opts.rpmdefine_count > 0 and opts.rpmdefines == null) {
        setError("null rpmdefines with non-zero rpmdefine_count", .{});
        return -1;
    }
    if (opts.rpmdefines) |raw_defines| {
        for (0..opts.rpmdefine_count) |index| {
            const define_ptr = raw_defines[index] orelse {
                setError("scriptlet rpmdefine {d} is null", .{index});
                return -1;
            };
            rpmdefines.append(std.heap.c_allocator, std.mem.span(define_ptr)) catch {
                setError("out of memory", .{});
                return -1;
            };
        }
    }

    const hdr = header.Header.parse(blob_ptr[0..header_len]) catch |err| {
        setError("header.parse: {t}", .{err});
        return -1;
    };

    const install_root = if (opts.install_root) |p| std.mem.span(p) else "";
    const result = scriptlet_engine.runHeaderScript(std.heap.c_allocator, hdr, script_phase, .{
        .install_root = install_root,
        .config = opts.config,
        .trans_flags = opts.trans_flags,
        .rpmdefines = rpmdefines.items,
        .arg1 = if (opts.arg1 >= 0) opts.arg1 else null,
        .arg2 = if (opts.arg2 >= 0) opts.arg2 else null,
        .script_fd = if (opts.script_fd >= 0) opts.script_fd else null,
        .redirect_stdout_to_stderr = opts.redirect_stdout_to_stderr != 0,
        .pinned_root_fd = if (opts.install_root_fd > 2)
            opts.install_root_fd
        else
            null,
    }) catch |err| {
        setError("header_run_scriptlet: {t}", .{err});
        return -1;
    };

    out.* = .{
        .ran = if (result.ran) 1 else 0,
        .critical = if (result.critical) 1 else 0,
        .outcome = @intFromEnum(result.outcome),
        .exit_status = result.exit_status,
        .signal_number = result.signal_number,
    };
    return 0;
}

/// Run every installed-package trigger matching the given package
/// header and trigger phase.
export fn tdnf_rpm_header_run_triggers(
    header_blob: ?[*]const u8,
    header_len: usize,
    phase: c_int,
    options: ?*const CTriggerOptions,
    result_out: ?*CTriggerResult,
) i32 {
    clearError();
    const blob_ptr = header_blob orelse {
        setError("null header_blob", .{});
        return -1;
    };
    const opts = options orelse {
        setError("null trigger options", .{});
        return -1;
    };
    const out = result_out orelse {
        setError("null trigger result", .{});
        return -1;
    };

    const trigger_phase: trigger_engine.Phase = switch (phase) {
        0 => .triggerin,
        1 => .triggerun,
        2 => .triggerpostun,
        else => {
            setError("unsupported trigger phase: {d}", .{phase});
            return -1;
        },
    };

    var rpmdefines = std.ArrayList([]const u8).empty;
    defer rpmdefines.deinit(std.heap.c_allocator);

    if (opts.rpmdefine_count > 0 and opts.rpmdefines == null) {
        setError("null rpmdefines with non-zero rpmdefine_count", .{});
        return -1;
    }
    if (opts.rpmdefines) |raw_defines| {
        for (0..opts.rpmdefine_count) |index| {
            const define_ptr = raw_defines[index] orelse {
                setError("trigger rpmdefine {d} is null", .{index});
                return -1;
            };
            rpmdefines.append(std.heap.c_allocator, std.mem.span(define_ptr)) catch {
                setError("out of memory", .{});
                return -1;
            };
        }
    }

    const hdr = header.Header.parse(blob_ptr[0..header_len]) catch |err| {
        setError("header.parse: {t}", .{err});
        return -1;
    };

    var transaction_headers: ?[]header.Header = null;
    var parsed_headers: []header.Header = &.{};
    defer if (parsed_headers.len != 0) {
        std.heap.c_allocator.free(parsed_headers);
    };
    if (opts.transaction_view_present != 0) {
        if (opts.transaction_header_count != 0 and
            opts.transaction_headers == null)
        {
            setError("null transaction headers with non-zero count", .{});
            return -1;
        }
        if (opts.transaction_header_count != 0) {
            parsed_headers = std.heap.c_allocator.alloc(
                header.Header,
                opts.transaction_header_count,
            ) catch {
                setError("out of memory", .{});
                return -1;
            };
            for (0..opts.transaction_header_count) |index| {
                const raw = opts.transaction_headers.?[index];
                const raw_blob = raw.blob orelse {
                    setError("transaction header {d} is null", .{index});
                    return -1;
                };
                parsed_headers[index] = header.Header.parse(
                    raw_blob[0..raw.len],
                ) catch |err| {
                    setError("transaction header {d}: {t}", .{ index, err });
                    return -1;
                };
            }
        }
        transaction_headers = parsed_headers;
    }

    var trigger_owner_headers: ?[]header.Header = null;
    var parsed_owner_headers: []header.Header = &.{};
    defer if (parsed_owner_headers.len != 0) {
        std.heap.c_allocator.free(parsed_owner_headers);
    };
    if (opts.trigger_owner_view_present != 0) {
        if (opts.trigger_owner_header_count != 0 and
            opts.trigger_owner_headers == null)
        {
            setError("null trigger owner headers with non-zero count", .{});
            return -1;
        }
        if (opts.trigger_owner_header_count != 0) {
            parsed_owner_headers = std.heap.c_allocator.alloc(
                header.Header,
                opts.trigger_owner_header_count,
            ) catch {
                setError("out of memory", .{});
                return -1;
            };
            for (0..opts.trigger_owner_header_count) |index| {
                const raw = opts.trigger_owner_headers.?[index];
                const raw_blob = raw.blob orelse {
                    setError("trigger owner header {d} is null", .{index});
                    return -1;
                };
                parsed_owner_headers[index] = header.Header.parse(
                    raw_blob[0..raw.len],
                ) catch |err| {
                    setError(
                        "trigger owner header {d}: {t}",
                        .{ index, err },
                    );
                    return -1;
                };
            }
        }
        trigger_owner_headers = parsed_owner_headers;
    }

    const db_root = if (opts.db_root) |p| std.mem.span(p) else "";
    const install_root = if (opts.install_root) |p| std.mem.span(p) else "";
    const result = trigger_engine.runHeaderTriggers(std.heap.c_allocator, hdr, trigger_phase, .{
        .db_root = db_root,
        .install_root = install_root,
        .config = opts.config,
        .trans_flags = opts.trans_flags,
        .rpmdefines = rpmdefines.items,
        .script_fd = if (opts.script_fd >= 0) opts.script_fd else null,
        .redirect_stdout_to_stderr = opts.redirect_stdout_to_stderr != 0,
        .pinned_root_fd = if (opts.install_root_fd > 2)
            opts.install_root_fd
        else
            null,
        .arg2_override = if (opts.arg2_override_present != 0) opts.arg2_override_value else null,
        .transaction_headers = transaction_headers,
        .trigger_owner_headers = trigger_owner_headers,
    }) catch |err| {
        setError("header_run_triggers: {t}", .{err});
        return -1;
    };

    out.* = .{
        .ran = if (result.ran) 1 else 0,
        .critical = if (result.critical) 1 else 0,
        .outcome = @intFromEnum(result.outcome),
        .exit_status = result.exit_status,
        .signal_number = result.signal_number,
    };
    return 0;
}

export fn tdnf_rpm_header_validate_trigger_metadata(
    header_blob: ?[*]const u8,
    header_len: usize,
) i32 {
    clearError();
    const blob = header_blob orelse {
        setError("null trigger metadata header", .{});
        return -1;
    };
    const hdr = header.Header.parse(blob[0..header_len]) catch |err| {
        setError("trigger metadata header.parse: {t}", .{err});
        return -1;
    };
    trigger_engine.validateHeaderMetadata(hdr) catch |err| {
        setError("trigger metadata: {t}", .{err});
        return -1;
    };
    return 0;
}

export fn tdnf_rpm_header_validate_trigger_scripts_config(
    header_blob: ?[*]const u8,
    header_len: usize,
    config: ?*const TxnConfig,
) i32 {
    clearError();
    const blob = header_blob orelse {
        setError("null trigger script header", .{});
        return -1;
    };
    const cfg = config orelse {
        setError("null rpm config", .{});
        return -1;
    };
    const hdr = header.Header.parse(blob[0..header_len]) catch |err| {
        setError("trigger script header.parse: {t}", .{err});
        return -1;
    };
    trigger_engine.validateHeaderScripts(
        std.heap.c_allocator,
        hdr,
        cfg,
    ) catch |err| {
        setError("trigger script prevalidation: {t}", .{err});
        return -1;
    };
    return 0;
}

export fn tdnf_rpm_header_has_file_trigger_metadata(
    header_blob: ?[*]const u8,
    header_len: usize,
    kind: c_int,
) i32 {
    clearError();
    const blob = header_blob orelse {
        setError("null file trigger metadata header", .{});
        return -1;
    };
    const trigger_kind: trigger_engine.FileKind = switch (kind) {
        0 => .file,
        1 => .transaction,
        else => {
            setError("unsupported file trigger kind: {d}", .{kind});
            return -1;
        },
    };
    const hdr = header.Header.parse(blob[0..header_len]) catch |err| {
        setError("file trigger metadata header.parse: {t}", .{err});
        return -1;
    };
    return @intFromBool(trigger_engine.hasFileTriggerMetadata(
        hdr,
        trigger_kind,
    ));
}

export fn tdnf_rpm_header_foreach_trigger_file(
    header_blob: ?[*]const u8,
    header_len: usize,
    trans_flags: u32,
    callback: ?CChangedPathFn,
    callback_data: ?*anyopaque,
) i32 {
    clearError();
    const blob = header_blob orelse {
        setError("null trigger file header", .{});
        return -1;
    };
    const cb = callback orelse {
        setError("null trigger file callback", .{});
        return -1;
    };
    const hdr = header.Header.parse(blob[0..header_len]) catch |err| {
        setError("trigger file header.parse: {t}", .{err});
        return -1;
    };
    var bridge = ChangedPathBridge{
        .cb = cb,
        .data = callback_data,
    };
    trigger_engine.forEachTriggerFile(
        std.heap.c_allocator,
        hdr,
        trans_flags,
        changedPathBridge,
        &bridge,
    ) catch |err| {
        setError("trigger file iteration: {t}", .{err});
        return -1;
    };
    return 0;
}

export fn tdnf_rpm_run_file_triggers(
    raw_owners: ?[*]const CFileTriggerOwner,
    owner_count: usize,
    phase: c_int,
    kind: c_int,
    priority_class: c_int,
    options: ?*const CFileTriggerOptions,
    result_out: ?*CTriggerResult,
) i32 {
    clearError();
    const opts = options orelse {
        setError("null file trigger options", .{});
        return -1;
    };
    const out = result_out orelse {
        setError("null file trigger result", .{});
        return -1;
    };
    if (owner_count != 0 and raw_owners == null) {
        setError("null file trigger owners with non-zero count", .{});
        return -1;
    }

    const trigger_phase: trigger_engine.Phase = switch (phase) {
        0 => .triggerin,
        1 => .triggerun,
        2 => .triggerpostun,
        else => {
            setError("unsupported file trigger phase: {d}", .{phase});
            return -1;
        },
    };
    const trigger_kind: trigger_engine.FileKind = switch (kind) {
        0 => .file,
        1 => .transaction,
        else => {
            setError("unsupported file trigger kind: {d}", .{kind});
            return -1;
        },
    };
    const class: trigger_engine.PriorityClass = switch (priority_class) {
        0 => .all,
        1 => .high,
        2 => .low,
        else => {
            setError("unsupported file trigger priority class: {d}", .{priority_class});
            return -1;
        },
    };

    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const rpmdefines = allocator.alloc([]const u8, opts.rpmdefine_count) catch {
        setError("out of memory", .{});
        return -1;
    };
    if (opts.rpmdefine_count != 0 and opts.rpmdefines == null) {
        setError("null file trigger rpmdefines with non-zero count", .{});
        return -1;
    }
    for (0..opts.rpmdefine_count) |index| {
        const define = opts.rpmdefines.?[index] orelse {
            setError("file trigger rpmdefine {d} is null", .{index});
            return -1;
        };
        rpmdefines[index] = std.mem.span(define);
    }

    const owners = allocator.alloc(
        trigger_engine.FileOwner,
        owner_count,
    ) catch {
        setError("out of memory", .{});
        return -1;
    };
    const SourceHeaderKey = struct {
        address: usize,
        len: usize,
    };
    var source_headers = std.AutoHashMap(
        SourceHeaderKey,
        header.Header,
    ).init(allocator);
    defer source_headers.deinit();
    for (0..owner_count) |owner_index| {
        const raw_owner = raw_owners.?[owner_index];
        const owner_blob = raw_owner.header_blob orelse {
            setError("file trigger owner {d} header is null", .{owner_index});
            return -1;
        };
        if (raw_owner.path_count != 0 and raw_owner.paths == null) {
            setError("file trigger owner {d} paths are null", .{owner_index});
            return -1;
        }
        const paths = allocator.alloc(
            trigger_engine.TriggerPath,
            raw_owner.path_count,
        ) catch {
            setError("out of memory", .{});
            return -1;
        };
        for (0..raw_owner.path_count) |path_index| {
            const raw_path = raw_owner.paths.?[path_index];
            const path = raw_path.path orelse {
                setError(
                    "file trigger owner {d} path {d} is null",
                    .{ owner_index, path_index },
                );
                return -1;
            };
            var source_header: ?header.Header = null;
            if (raw_path.source_header_blob) |source_blob| {
                const key = SourceHeaderKey{
                    .address = @intFromPtr(source_blob),
                    .len = raw_path.source_header_len,
                };
                if (source_headers.get(key)) |cached| {
                    source_header = cached;
                } else {
                    const parsed = header.Header.parse(
                        source_blob[0..raw_path.source_header_len],
                    ) catch |err| {
                        setError(
                            "file trigger owner {d} path {d} source: {t}",
                            .{ owner_index, path_index, err },
                        );
                        return -1;
                    };
                    source_headers.put(key, parsed) catch {
                        setError("out of memory", .{});
                        return -1;
                    };
                    source_header = parsed;
                }
            } else if (raw_path.source_header_len != 0) {
                setError(
                    "file trigger owner {d} path {d} source is null",
                    .{ owner_index, path_index },
                );
                return -1;
            }
            paths[path_index] = .{
                .path = std.mem.span(path),
                .source_header = source_header,
            };
        }
        owners[owner_index] = .{
            .hdr = header.Header.parse(
                owner_blob[0..raw_owner.header_len],
            ) catch |err| {
                setError("file trigger owner {d}: {t}", .{ owner_index, err });
                return -1;
            },
            .paths = paths,
            .order = raw_owner.order,
        };
    }

    const install_root = if (opts.install_root) |root|
        std.mem.span(root)
    else
        "";
    const result = trigger_engine.runFileTriggers(
        std.heap.c_allocator,
        owners,
        trigger_phase,
        trigger_kind,
        class,
        .{
            .install_root = install_root,
            .config = opts.config,
            .trans_flags = opts.trans_flags,
            .rpmdefines = rpmdefines,
            .script_fd = if (opts.script_fd >= 0) opts.script_fd else null,
            .redirect_stdout_to_stderr = opts.redirect_stdout_to_stderr != 0,
            .suppress_stdin = opts.suppress_stdin != 0,
            .pinned_root_fd = if (opts.install_root_fd > 2)
                opts.install_root_fd
            else
                null,
        },
    ) catch |err| {
        setError("run_file_triggers: {t}", .{err});
        return -1;
    };

    out.* = .{
        .ran = if (result.ran) 1 else 0,
        .critical = if (result.critical) 1 else 0,
        .outcome = @intFromEnum(result.outcome),
        .exit_status = result.exit_status,
        .signal_number = result.signal_number,
    };
    return 0;
}

/// Erase one installed package's on-disk files, identified by its
/// rpmdb sqlite `hnum`, without removing the rpmdb row itself.
export fn tdnf_rpm_erase_hnum(
    root: ?[*:0]const u8,
    hnum: u32,
    options: ?*const CEraseOptions,
) i32 {
    clearError();
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";

    var default_opts = CEraseOptions{
        .config = null,
        .trans_flags = 0,
        .keep_path_fn = null,
        .keep_path_fn_data = null,
    };
    const opts = options orelse &default_opts;
    var writer = blk: {
        if (opts.config) |config| {
            break :blk rpmdb_write.Writer.openConfig(config) catch |err| {
                setError("Writer.openConfig: {t}", .{err});
                return -1;
            };
        }
        break :blk rpmdb_write.Writer.openRoot(root_slice) catch |err| {
            setError("Writer.openRoot: {t}", .{err});
            return -1;
        };
    };
    defer writer.close();

    const blob = writer.readHeaderBlobCopy(std.heap.c_allocator, hnum) catch |err| {
        setError("Writer.readHeaderBlobCopy({d}): {t}", .{ hnum, err });
        return -1;
    };
    defer std.heap.c_allocator.free(blob);

    const hdr = header.Header.parse(blob) catch |err| {
        setError("header.parse({d}): {t}", .{ hnum, err });
        return -1;
    };

    var custom_bridge = EraseKeepPathBridge{
        .cb = opts.keep_path_fn,
        .data = opts.keep_path_fn_data,
    };
    var default_keep_ctx = DefaultEraseKeepPathCtx{
        .writer = &writer,
        .hnum = hnum,
    };

    const keep_path_fn: erase_engine.KeepPathFn = if (opts.keep_path_fn != null)
        eraseKeepPathBridge
    else
        defaultEraseKeepPath;
    const keep_path_ctx: ?*anyopaque = if (opts.keep_path_fn != null)
        &custom_bridge
    else
        &default_keep_ctx;

    var ctx = erase_engine.Context.init(std.heap.c_allocator, hdr, .{
        .install_root = root_slice,
        .config = opts.config,
        .trans_flags = opts.trans_flags,
        .keep_path_fn = keep_path_fn,
        .keep_path_ctx = keep_path_ctx,
    }) catch |err| {
        setError("erase init: {t}", .{err});
        return -1;
    };
    defer ctx.deinit();

    ctx.erase() catch |err| {
        if (ctx.last_path) |path| {
            setError("rpm_erase_hnum({s}): {t}", .{ path, err });
        } else {
            setError("rpm_erase_hnum: {t}", .{err});
        }
        return -1;
    };
    return 0;
}

/// Erase on-disk files listed in a raw stored header blob, under
/// `root`, without touching the rpmdb rows themselves.
///
/// Unlike `tdnf_rpm_erase_hnum` (which looks up an existing rpmdb row
/// by hnum), this variant takes the header blob directly. It is used
/// on the UPGRADE path: after `tdnf_rpmdb_write_replace` has
/// atomically overwritten the OLD package's rpmdb row with the NEW
/// blob, we still need to clean up any files unique to the OLD
/// version (files that the NEW version does not ship). We call this
/// with the OLD header blob captured *before* write_replace.
///
/// The default keep-path probe queries the live rpmdb for ANY
/// installed package that owns each path (no hnum is excluded). By
/// the time this is called on upgrade, the rpmdb reflects the NEW
/// package's file list at the replaced hnum, so paths shared with
/// (or renamed-into) the NEW version are naturally preserved, and
/// paths owned by unrelated packages are preserved too.
/// With a caller-supplied keep-path callback, no rpmdb writer is opened.
export fn tdnf_rpm_erase_header_blob(
    root: ?[*:0]const u8,
    blob: ?[*]const u8,
    blob_len: usize,
    options: ?*const CEraseOptions,
) i32 {
    clearError();
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    const blob_ptr = blob orelse {
        setError("null header blob", .{});
        return -1;
    };
    if (blob_len == 0) {
        setError("empty header blob", .{});
        return -1;
    }
    const blob_slice = blob_ptr[0..blob_len];

    const hdr = header.Header.parse(blob_slice) catch |err| {
        setError("header.parse(blob): {t}", .{err});
        return -1;
    };

    var default_opts = CEraseOptions{
        .config = null,
        .trans_flags = 0,
        .keep_path_fn = null,
        .keep_path_fn_data = null,
    };
    const opts = options orelse &default_opts;
    var custom_bridge = EraseKeepPathBridge{
        .cb = opts.keep_path_fn,
        .data = opts.keep_path_fn_data,
    };
    var writer: ?rpmdb_write.Writer = null;
    defer if (writer) |*active_writer| active_writer.close();

    // hnum == 0 is not a valid rpmdb hnum (AUTOINCREMENT starts at 1),
    // so the default probe excludes nothing and the freshly-written
    // NEW row will be seen as an "other package" owning shared paths.
    var default_keep_ctx: DefaultEraseKeepPathCtx = undefined;
    const keep_path_fn: erase_engine.KeepPathFn =
        if (opts.keep_path_fn != null) eraseKeepPathBridge else defaultEraseKeepPath;
    const keep_path_ctx: ?*anyopaque = if (opts.keep_path_fn != null)
        &custom_bridge
    else blk: {
        writer = if (opts.config) |config|
            rpmdb_write.Writer.openConfig(config) catch |err| {
                setError("Writer.openConfig: {t}", .{err});
                return -1;
            }
        else
            rpmdb_write.Writer.openRoot(root_slice) catch |err| {
                setError("Writer.openRoot: {t}", .{err});
                return -1;
            };
        if (writer) |*active_writer| {
            default_keep_ctx = .{
                .writer = active_writer,
                .hnum = 0,
            };
        } else unreachable;
        break :blk &default_keep_ctx;
    };

    var ctx = erase_engine.Context.init(std.heap.c_allocator, hdr, .{
        .install_root = root_slice,
        .config = opts.config,
        .trans_flags = opts.trans_flags,
        .keep_path_fn = keep_path_fn,
        .keep_path_ctx = keep_path_ctx,
    }) catch |err| {
        setError("erase init: {t}", .{err});
        return -1;
    };
    defer ctx.deinit();

    ctx.erase() catch |err| {
        if (ctx.last_path) |path| {
            setError("rpm_erase_header_blob({s}): {t}", .{ path, err });
        } else {
            setError("rpm_erase_header_blob: {t}", .{err});
        }
        return -1;
    };
    return 0;
}

/// Files-in-package iterator state. Each call to
/// `tdnf_rpm_file_next_filename` returns the next file path or 0 at
/// end-of-archive.
pub const FilesIter = struct {
    /// Decompressed cpio payload owned by this iterator.
    cpio_bytes: []u8,
    walker: cpio.Walker,
    /// Stable scratch for returning a NUL-terminated copy of the
    /// current entry's name. Reused between calls.
    name_scratch: ?[*:0]u8 = null,
    name_scratch_cap: usize = 0,
};

/// Open a files-in-package iterator. Decompresses the payload up
/// front; large packages briefly hold the full cpio archive in
/// memory.
export fn tdnf_rpm_file_files_open(fh: ?*FileHandle) ?*FilesIter {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return null;
    };
    const bytes = f.file.decompressPayload(std.heap.c_allocator) catch |err| {
        setError("decompressPayload: {t}", .{err});
        return null;
    };
    const it = std.heap.c_allocator.create(FilesIter) catch {
        std.heap.c_allocator.free(bytes);
        setError("out of memory", .{});
        return null;
    };
    it.* = .{
        .cpio_bytes = bytes,
        .walker = cpio.Walker.init(bytes),
    };
    return it;
}

/// Free a files iterator. Accepts NULL.
export fn tdnf_rpm_file_files_close(it: ?*FilesIter) void {
    const i = it orelse return;
    std.heap.c_allocator.free(i.cpio_bytes);
    if (i.name_scratch) |p| libc.free(@ptrCast(p));
    std.heap.c_allocator.destroy(i);
}

/// Advance the iterator and write the next entry's name into
/// `*name_out` (stable until the next call; do NOT free) and its
/// mode into `*mode_out`. Returns 1 on hit, 0 on end, -1 on error.
export fn tdnf_rpm_file_files_next(
    it: ?*FilesIter,
    name_out: ?*[*:0]const u8,
    mode_out: ?*u32,
) i32 {
    clearError();
    const i = it orelse {
        setError("null files iterator", .{});
        return -1;
    };
    const np = name_out orelse {
        setError("null name out pointer", .{});
        return -1;
    };

    const maybe_entry = i.walker.next() catch |err| {
        setError("cpio walker: {t}", .{err});
        return -1;
    };
    const entry = maybe_entry orelse return 0;

    // Stash a NUL-terminated copy in the iterator's scratch.
    const needed = entry.name.len + 1;
    if (i.name_scratch == null or i.name_scratch_cap < needed) {
        if (i.name_scratch) |p| libc.free(@ptrCast(p));
        const buf = libc.malloc(needed) orelse {
            i.name_scratch = null;
            i.name_scratch_cap = 0;
            setError("out of memory", .{});
            return -1;
        };
        i.name_scratch = @ptrCast(@as([*]u8, @ptrCast(buf)));
        i.name_scratch_cap = needed;
    }
    const scratch_bytes = @as([*]u8, @ptrCast(i.name_scratch.?));
    @memcpy(scratch_bytes[0..entry.name.len], entry.name);
    scratch_bytes[entry.name.len] = 0;
    np.* = i.name_scratch.?;
    if (mode_out) |mo| mo.* = entry.mode;
    return 1;
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

fn buildDbPath(buf: []u8, root: []const u8) ![]const u8 {
    return txn_config.buildDefaultRpmDbSqlitePath(buf, root);
}

fn providerTestStringBytes(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) ![]u8 {
    var bytes = std.ArrayList(u8).empty;
    errdefer bytes.deinit(allocator);
    for (values) |value| {
        try bytes.appendSlice(allocator, value);
        try bytes.append(allocator, 0);
    }
    return bytes.toOwnedSlice(allocator);
}

fn providerTestFlagsBytes(
    allocator: std.mem.Allocator,
    values: []const u32,
) ![]u8 {
    const bytes = try allocator.alloc(u8, values.len * 4);
    for (values, 0..) |value, index| {
        const offset = index * 4;
        bytes[offset] = @intCast((value >> 24) & 0xff);
        bytes[offset + 1] = @intCast((value >> 16) & 0xff);
        bytes[offset + 2] = @intCast((value >> 8) & 0xff);
        bytes[offset + 3] = @intCast(value & 0xff);
    }
    return bytes;
}

fn insertProviderTestPackage(
    allocator: std.mem.Allocator,
    path: []const u8,
    package_name: []const u8,
    package_version: []const u8,
    provide_names: []const []const u8,
    provide_flags: []const u32,
    provide_versions: []const []const u8,
) !void {
    const names = try providerTestStringBytes(allocator, provide_names);
    defer allocator.free(names);
    const flags = try providerTestFlagsBytes(allocator, provide_flags);
    defer allocator.free(flags);
    const versions = try providerTestStringBytes(allocator, provide_versions);
    defer allocator.free(versions);
    const package_name_z = try allocator.dupeZ(u8, package_name);
    defer allocator.free(package_name_z);
    const package_version_z = try allocator.dupeZ(u8, package_version);
    defer allocator.free(package_version_z);

    const blob = try rpmdb_write.encodeImmutableHeader(allocator, &.{
        .{
            .tag = @intFromEnum(header.TagId.name),
            .typ = .string,
            .count = 1,
            .bytes = package_name_z[0 .. package_name_z.len + 1],
        },
        .{
            .tag = @intFromEnum(header.TagId.version),
            .typ = .string,
            .count = 1,
            .bytes = package_version_z[0 .. package_version_z.len + 1],
        },
        .{
            .tag = @intFromEnum(header.TagId.providename),
            .typ = .string_array,
            .count = @intCast(provide_names.len),
            .bytes = names,
        },
        .{
            .tag = @intFromEnum(header.TagId.provideflags),
            .typ = .int32,
            .count = @intCast(provide_flags.len),
            .bytes = flags,
        },
        .{
            .tag = @intFromEnum(header.TagId.provideversion),
            .typ = .string_array,
            .count = @intCast(provide_versions.len),
            .bytes = versions,
        },
    });
    defer allocator.free(blob);

    var writer = try rpmdb_write.Writer.openAtPath(path);
    defer writer.close();
    try writer.beginTransaction();
    errdefer writer.rollbackTransaction() catch {};
    _ = try writer.insertHeaderInTransaction(blob);
    try writer.commitTransaction();
}

fn createEmptyProviderTestDb(path: []const u8) !void {
    var writer = try rpmdb_write.Writer.openAtPath(path);
    writer.close();
}

fn corruptFirstProviderTestHeader(
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    var db: ?*c.sqlite3 = null;
    if (c.sqlite3_open_v2(
        path_z.ptr,
        &db,
        c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_NOMUTEX,
        null,
    ) != c.SQLITE_OK) {
        if (db != null) _ = c.sqlite3_close(db);
        return error.TestUnexpectedResult;
    }
    defer _ = c.sqlite3_close(db);

    const sql = "UPDATE Packages SET blob=X'00' WHERE hnum=(SELECT MIN(hnum) FROM Packages)";
    if (c.sqlite3_exec(db, sql, null, null, null) != c.SQLITE_OK) {
        return error.TestUnexpectedResult;
    }
}

fn expectProviderTestVersion(
    allocator: std.mem.Allocator,
    path: []const u8,
    provide_name: []const u8,
    expected: []const u8,
) !void {
    const version = (try resolveProviderVersionAtPath(
        allocator,
        path,
        provide_name,
    )) orelse return error.TestUnexpectedResult;
    defer allocator.free(version);
    try std.testing.expectEqualStrings(expected, version);
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

test "missing rpmdb is an empty installed-package iterator" {
    var iter = try Iter.openAtPath(
        ".zig-cache/tdnf-rpmdb-missing-test-does-not-exist/rpmdb.sqlite",
    );
    defer iter.close();
    try std.testing.expectEqual(null, try iter.nextHeaderBlob());
}

test "provider query preserves rpmdb order and version semantics" {
    const allocator = std.testing.allocator;
    const dir = ".zig-cache/rpmdb-provider-query";
    std.Io.Dir.cwd().deleteTree(std.testing.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, dir) catch {};

    const fallback_path = dir ++ "/fallback/rpmdb.sqlite";
    try insertProviderTestPackage(
        allocator,
        fallback_path,
        "fallback-package",
        "5.2",
        &.{"test-distrover"},
        &.{0},
        &.{""},
    );
    try expectProviderTestVersion(
        allocator,
        fallback_path,
        "test-distrover",
        "5.2",
    );

    const equal_path = dir ++ "/equal/rpmdb.sqlite";
    try insertProviderTestPackage(
        allocator,
        equal_path,
        "equal-package",
        "1.0",
        &.{ "other-provide", "test-distrover" },
        &.{ RPMSENSE_EQUAL, RPMSENSE_EQUAL },
        &.{ "wrong-index", "9.4-2" },
    );
    try expectProviderTestVersion(
        allocator,
        equal_path,
        "test-distrover",
        "9.4-2",
    );

    const non_equal_path = dir ++ "/non-equal/rpmdb.sqlite";
    try insertProviderTestPackage(
        allocator,
        non_equal_path,
        "non-equal-package",
        "7.1",
        &.{"test-distrover"},
        &.{1 << 2},
        &.{"99"},
    );
    try expectProviderTestVersion(
        allocator,
        non_equal_path,
        "test-distrover",
        "7.1",
    );

    const ordered_path = dir ++ "/ordered/rpmdb.sqlite";
    try insertProviderTestPackage(
        allocator,
        ordered_path,
        "first-package",
        "2.0",
        &.{"test-distrover"},
        &.{0},
        &.{""},
    );
    try insertProviderTestPackage(
        allocator,
        ordered_path,
        "second-package",
        "3.0",
        &.{"test-distrover"},
        &.{RPMSENSE_EQUAL},
        &.{"88"},
    );
    try expectProviderTestVersion(
        allocator,
        ordered_path,
        "test-distrover",
        "2.0",
    );
}

test "provider query distinguishes absence from malformed data" {
    const allocator = std.testing.allocator;
    const dir = ".zig-cache/rpmdb-provider-errors";
    std.Io.Dir.cwd().deleteTree(std.testing.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, dir) catch {};

    const empty_path = dir ++ "/empty/rpmdb.sqlite";
    try createEmptyProviderTestDb(empty_path);
    try std.testing.expectEqual(
        null,
        try resolveProviderVersionAtPath(
            allocator,
            empty_path,
            "test-distrover",
        ),
    );

    const mismatch_path = dir ++ "/mismatch/rpmdb.sqlite";
    try insertProviderTestPackage(
        allocator,
        mismatch_path,
        "mismatch-package",
        "1.0",
        &.{"test-distrover"},
        &.{RPMSENSE_EQUAL},
        &.{ "1.0", "extra" },
    );
    try std.testing.expectError(
        error.MalformedProvider,
        resolveProviderVersionAtPath(
            allocator,
            mismatch_path,
            "test-distrover",
        ),
    );

    const malformed_path = dir ++ "/malformed/rpmdb.sqlite";
    try insertProviderTestPackage(
        allocator,
        malformed_path,
        "malformed-package",
        "1.0",
        &.{"test-distrover"},
        &.{0},
        &.{""},
    );
    try corruptFirstProviderTestHeader(allocator, malformed_path);
    try std.testing.expectError(
        error.MalformedProvider,
        resolveProviderVersionAtPath(
            allocator,
            malformed_path,
            "test-distrover",
        ),
    );
}

test "configured provider query honors rooted recursive dbpath" {
    const allocator = std.testing.allocator;
    const relative_root = ".zig-cache/rpmdb-provider-config-root";
    std.Io.Dir.cwd().deleteTree(std.testing.io, relative_root) catch {};
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, relative_root) catch {};

    const cwd = try std.process.currentPathAlloc(std.testing.io, allocator);
    defer allocator.free(cwd);
    const root = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ cwd, relative_root },
    );
    defer allocator.free(root);

    var config = try TxnConfig.init(allocator, root);
    defer config.deinit();
    _ = try config.applyRpmDefine("_dbbase /native");
    _ = try config.applyRpmDefine("_dbpath %{_dbbase}/nested/rpm");

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try config.resolveRpmDbSqlitePath(&path_buf);
    try insertProviderTestPackage(
        allocator,
        path,
        "rooted-package",
        "4.0",
        &.{"test-distrover"},
        &.{RPMSENSE_EQUAL},
        &.{"12.3"},
    );

    const provide_name = "test-distrover";
    var version: ?[*:0]u8 = null;
    try std.testing.expectEqual(
        @as(i32, 1),
        tdnf_rpmdb_resolve_provider_version_config(
            &config,
            provide_name,
            &version,
        ),
    );
    defer tdnf_rpmdb_string_free(version);
    try std.testing.expect(version != null);
    try std.testing.expectEqualStrings("12.3", std.mem.span(version.?));
}

test "configured readers reject symlinked db parents and preserve absence" {
    const allocator = std.testing.allocator;
    const relative = ".zig-cache/rpmdb-reader-containment";
    std.Io.Dir.cwd().deleteTree(std.testing.io, relative) catch {};
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, relative) catch {};
    try std.Io.Dir.cwd().createDirPath(
        std.testing.io,
        relative ++ "/root",
    );
    try std.Io.Dir.cwd().createDirPath(
        std.testing.io,
        relative ++ "/outside/lib/rpm",
    );
    const cwd = try std.process.currentPathAlloc(std.testing.io, allocator);
    defer allocator.free(cwd);
    const root = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/root",
        .{ cwd, relative },
    );
    defer allocator.free(root);
    const outside = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/outside",
        .{ cwd, relative },
    );
    defer allocator.free(outside);
    const var_path = try std.fmt.allocPrint(
        allocator,
        "{s}/var",
        .{root},
    );
    defer allocator.free(var_path);
    const var_z = try allocator.dupeZ(u8, var_path);
    defer allocator.free(var_z);
    const outside_z = try allocator.dupeZ(u8, outside);
    defer allocator.free(outside_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        std.c.symlink(outside_z.ptr, var_z.ptr),
    );
    var config = try TxnConfig.init(allocator, root);
    defer config.deinit();
    try std.testing.expectEqual(
        @as(i64, -1),
        tdnf_rpmdb_count_packages_config(&config),
    );
    try std.testing.expect(tdnf_rpmdb_cookie_config(&config) == null);
    try std.testing.expect(tdnf_rpmdb_iter_open_config(&config) == null);
    try std.testing.expect(tdnf_rpmdb_pubkeys_open_config(&config) == null);
    var version: ?[*:0]u8 = null;
    try std.testing.expectEqual(
        @as(i32, -1),
        tdnf_rpmdb_resolve_provider_version_config(
            &config,
            "test-distrover",
            &version,
        ),
    );

    try std.Io.Dir.cwd().deleteFile(
        std.testing.io,
        relative ++ "/root/var",
    );
    try std.testing.expectEqual(
        @as(i64, 0),
        tdnf_rpmdb_count_packages_config(&config),
    );
    const cookie = tdnf_rpmdb_cookie_config(&config) orelse
        return error.TestUnexpectedResult;
    defer tdnf_rpmdb_string_free(cookie);
    try std.testing.expectEqualStrings("0:0", std.mem.span(cookie));
    const iter = tdnf_rpmdb_iter_open_config(&config) orelse
        return error.TestUnexpectedResult;
    defer tdnf_rpmdb_iter_close(iter);
    var blob: ?[*]const u8 = null;
    var blob_len: usize = 0;
    try std.testing.expectEqual(
        @as(i32, 0),
        tdnf_rpmdb_iter_next_header_blob(iter, &blob, &blob_len),
    );
    const pubkeys = tdnf_rpmdb_pubkeys_open_config(&config) orelse
        return error.TestUnexpectedResult;
    defer tdnf_rpmdb_pubkeys_close(pubkeys);
    var key: [*:0]u8 = undefined;
    try std.testing.expectEqual(
        @as(i32, 0),
        tdnf_rpmdb_pubkeys_next(pubkeys, &key, null, null),
    );
}

test "pubkey reader distinguishes empty rpmdb from corruption" {
    const dir = ".zig-cache/rpmdb-pubkey-reader-state";
    const path = dir ++ "/rpmdb.sqlite";
    std.Io.Dir.cwd().deleteTree(std.testing.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, dir) catch {};

    const missing = pubkeysOpenAtPath(path) orelse
        return error.TestUnexpectedResult;
    defer tdnf_rpmdb_pubkeys_close(missing);
    var key: [*:0]u8 = undefined;
    try std.testing.expectEqual(
        @as(i32, 0),
        tdnf_rpmdb_pubkeys_next(missing, &key, null, null),
    );

    try std.Io.Dir.cwd().createDirPath(std.testing.io, dir);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = "",
    });

    const empty = pubkeysOpenAtPath(path) orelse
        return error.TestUnexpectedResult;
    defer tdnf_rpmdb_pubkeys_close(empty);
    try std.testing.expectEqual(
        @as(i32, 0),
        tdnf_rpmdb_pubkeys_next(empty, &key, null, null),
    );

    try std.Io.Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = "not a sqlite database",
    });
    try std.testing.expectEqual(null, pubkeysOpenAtPath(path));
}

const PubkeyReaderVersion = enum {
    valid,
    missing,
    malformed,
};

const PubkeyReaderData = union(enum) {
    pubkeys: []const u8,
    description: []const u8,
};

test "pubkey iterator rejects malformed required fields and certificates" {
    const allocator = std.testing.allocator;
    const valid_key = @embedFile("pgp/testdata/microsoft-rpm-key.bin");
    const cases = [_]struct {
        name: []const u8,
        version: PubkeyReaderVersion,
        data: PubkeyReaderData,
    }{
        .{
            .name = "missing-version",
            .version = .missing,
            .data = .{ .pubkeys = valid_key },
        },
        .{
            .name = "malformed-version",
            .version = .malformed,
            .data = .{ .pubkeys = valid_key },
        },
        .{
            .name = "malformed-pubkeys",
            .version = .valid,
            .data = .{ .pubkeys = &.{0x98} },
        },
        .{
            .name = "malformed-description",
            .version = .valid,
            .data = .{ .description = "not an OpenPGP certificate" },
        },
    };

    for (cases) |case| {
        const dir = try std.fmt.allocPrint(
            allocator,
            ".zig-cache/rpmdb-pubkey-reader-{s}",
            .{case.name},
        );
        defer allocator.free(dir);
        defer std.Io.Dir.cwd().deleteTree(std.testing.io, dir) catch {};
        std.Io.Dir.cwd().deleteTree(std.testing.io, dir) catch {};
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}/rpmdb.sqlite",
            .{dir},
        );
        defer allocator.free(path);

        try insertPubkeyReaderTestRow(
            allocator,
            path,
            case.version,
            case.data,
        );
        const iter = pubkeysOpenAtPath(path) orelse
            return error.TestUnexpectedResult;
        defer tdnf_rpmdb_pubkeys_close(iter);
        var key: [*:0]u8 = undefined;
        try std.testing.expectEqual(
            @as(i32, -1),
            tdnf_rpmdb_pubkeys_next(iter, &key, null, null),
        );
        try std.testing.expect(last_error_len != 0);
    }
}

fn insertPubkeyReaderTestRow(
    allocator: std.mem.Allocator,
    path: []const u8,
    version_kind: PubkeyReaderVersion,
    data: PubkeyReaderData,
) !void {
    var fields = std.array_list.Managed(rpmdb_write.HeaderField).init(
        allocator,
    );
    defer fields.deinit();
    try fields.append(.{
        .tag = @intFromEnum(header.TagId.name),
        .typ = .string,
        .count = 1,
        .bytes = "gpg-pubkey\x00",
    });

    var malformed_version = [_]u8{ 0, 0, 0, 0 };
    switch (version_kind) {
        .valid => try fields.append(.{
            .tag = @intFromEnum(header.TagId.version),
            .typ = .string,
            .count = 1,
            .bytes = "3135ce90\x00",
        }),
        .missing => {},
        .malformed => try fields.append(.{
            .tag = @intFromEnum(header.TagId.version),
            .typ = .int32,
            .count = 1,
            .bytes = &malformed_version,
        }),
    }

    var owned_data: ?[]u8 = null;
    defer if (owned_data) |bytes| allocator.free(bytes);
    switch (data) {
        .pubkeys => |key| {
            const encoded_len = std.base64.standard.Encoder.calcSize(key.len);
            const bytes = try allocator.alloc(u8, encoded_len + 1);
            _ = std.base64.standard.Encoder.encode(
                bytes[0..encoded_len],
                key,
            );
            bytes[encoded_len] = 0;
            owned_data = bytes;
            try fields.append(.{
                .tag = @intFromEnum(header.TagId.pubkeys),
                .typ = .string_array,
                .count = 1,
                .bytes = bytes,
            });
        },
        .description => |description| {
            const bytes = try allocator.alloc(u8, description.len + 1);
            @memcpy(bytes[0..description.len], description);
            bytes[description.len] = 0;
            owned_data = bytes;
            try fields.append(.{
                .tag = @intFromEnum(header.TagId.description),
                .typ = .string,
                .count = 1,
                .bytes = bytes,
            });
        },
    }

    const blob = try rpmdb_write.encodeImmutableHeader(
        allocator,
        fields.items,
    );
    defer allocator.free(blob);
    var writer = try rpmdb_write.Writer.openAtPath(path);
    defer writer.close();
    try writer.beginTransaction();
    errdefer writer.rollbackTransaction() catch {};
    _ = try writer.insertHeaderInTransaction(blob);
    try writer.commitTransaction();
}

test {
    // pull in header.zig + pkgfile.zig + cpio.zig tests
    _ = header;
    _ = pkgfile;
    _ = rpmdb_write;
    _ = cpio;
    _ = install_engine;
    _ = txn_config;
    // PGP submodules (PR #1 of plan-pure-zig-pgp.md). Imported here
    // only for test discovery; no runtime dependency.
    _ = @import("pgp/armor.zig");
    _ = @import("pgp/certificate.zig");
    _ = @import("integrity.zig");
    _ = rpmdb_pubkey;
}

test {
    _ = @import("pgp/packet.zig");
    _ = @import("pgp/pubkey.zig");
    _ = @import("pgp/signature.zig");
    _ = @import("pgp/verify.zig");
    _ = @import("pgp/keyring.zig");
    _ = @import("checksum.zig");
}
