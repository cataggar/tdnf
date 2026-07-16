const std = @import("std");
const builtin = @import("builtin");
const sqlite = @import("sqlite");
const header = @import("rpm_header");
const install_engine = @import("install.zig");
const pkgfile = @import("rpm_pkgfile");
const txn_config = @import("txn_config.zig");

const c = sqlite.c;
const sysc = @cImport({
    @cInclude("errno.h");
    @cInclude("sqlite3.h");
    @cInclude("stdint.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

const PKG_TABLE = "Packages";
pub const DEFAULT_INSTALL_COLOR: u32 = 3;

const RPMTAG_FILESTATES: u32 = 1029;
const RPMTAG_INSTALLTIME: u32 = 1008;
const RPMTAG_INSTALLCOLOR: u32 = 1127;
const RPMTAG_INSTALLTID: u32 = 1128;
const RPMTAG_FILETRIGGERINDEX: u32 = 5070;
const RPMTAG_TRANSFILETRIGGERINDEX: u32 = 5080;
const RPMTAG_SIGMD5: u32 = 261;

const RPMSENSE_PREREQ: u32 = 1 << 6;
const RPMSENSE_PRETRANS: u32 = 1 << 7;
const RPMSENSE_INTERP: u32 = 1 << 8;
const RPMSENSE_SCRIPT_PRE: u32 = 1 << 9;
const RPMSENSE_SCRIPT_POST: u32 = 1 << 10;
const RPMSENSE_SCRIPT_PREUN: u32 = 1 << 11;
const RPMSENSE_SCRIPT_POSTUN: u32 = 1 << 12;
const RPMSENSE_SCRIPT_VERIFY: u32 = 1 << 13;
const RPMSENSE_FIND_REQUIRES: u32 = 1 << 14;
const RPMSENSE_POSTTRANS: u32 = 1 << 5;
const RPMSENSE_MISSINGOK: u32 = 1 << 19;
const RPMSENSE_PREUNTRANS: u32 = 1 << 20;
const RPMSENSE_POSTUNTRANS: u32 = 1 << 21;
const RPMSENSE_RPMLIB: u32 = 1 << 24;
const RPMSENSE_KEYRING: u32 = 1 << 26;
const RPMSENSE_META: u32 = 1 << 29;

fn notPre(value: u32) u32 {
    return value & ~RPMSENSE_PREREQ;
}

const INSTALL_ONLY_MASK: u32 = notPre(
    RPMSENSE_SCRIPT_PRE |
        RPMSENSE_SCRIPT_POST |
        RPMSENSE_RPMLIB |
        RPMSENSE_KEYRING |
        RPMSENSE_PRETRANS |
        RPMSENSE_POSTTRANS,
);

const ERASE_ONLY_MASK: u32 = notPre(
    RPMSENSE_SCRIPT_PREUN |
        RPMSENSE_SCRIPT_POSTUN |
        RPMSENSE_PREUNTRANS |
        RPMSENSE_POSTUNTRANS,
);

pub const Error = error{
    InvalidFileStates,
    InvalidHeaderField,
    InvalidHeaderBlob,
    InvalidRichDependency,
    InvalidSigTagCount,
    InvalidSigTagType,
    MissingImmutableRegion,
    NotFound,
    OutOfMemory,
    PathTooLong,
    SqliteBusyTimeoutFailed,
    SqliteExecFailed,
    SqliteOpenFailed,
    SqlitePrepareFailed,
    SqliteStepFailed,
    SyscallFailed,
    UnsafePath,
    UnsupportedBackend,
};

pub const InstallOptions = struct {
    install_tid: u32,
    install_time: ?u32 = null,
    install_color: u32 = DEFAULT_INSTALL_COLOR,
    file_states: ?[]const u8 = null,

    pub fn effectiveInstallTime(self: InstallOptions) u32 {
        return self.install_time orelse self.install_tid;
    }
};

const SigTagMap = struct {
    stag: u32,
    xtag: u32,
    expected_count: u32,
    quirk: bool,
};

const sig_tag_maps = [_]SigTagMap{
    .{ .stag = 1000, .xtag = @intFromEnum(header.TagId.sigsize), .expected_count = 1, .quirk = false },
    .{ .stag = 1002, .xtag = @intFromEnum(header.TagId.sigpgp), .expected_count = 0, .quirk = false },
    .{ .stag = 1004, .xtag = @intFromEnum(header.TagId.sigmd5), .expected_count = 16, .quirk = false },
    .{ .stag = 1005, .xtag = @intFromEnum(header.TagId.siggpg), .expected_count = 0, .quirk = false },
    .{ .stag = 1007, .xtag = @intFromEnum(header.TagId.archive_size), .expected_count = 1, .quirk = true },
    .{ .stag = 274, .xtag = @intFromEnum(header.TagId.filesignatures), .expected_count = 0, .quirk = true },
    .{ .stag = 275, .xtag = @intFromEnum(header.TagId.filesignaturelength), .expected_count = 1, .quirk = true },
    .{ .stag = 276, .xtag = 276, .expected_count = 0, .quirk = false },
    .{ .stag = 277, .xtag = 277, .expected_count = 1, .quirk = false },
    .{ .stag = 269, .xtag = @intFromEnum(header.TagId.sha1header), .expected_count = 1, .quirk = false },
    .{ .stag = 273, .xtag = @intFromEnum(header.TagId.sha256header), .expected_count = 1, .quirk = false },
    .{ .stag = 279, .xtag = @intFromEnum(header.TagId.sha3_256header), .expected_count = 1, .quirk = false },
    .{ .stag = 267, .xtag = @intFromEnum(header.TagId.dsaheader), .expected_count = 0, .quirk = false },
    .{ .stag = 268, .xtag = @intFromEnum(header.TagId.rsaheader), .expected_count = 0, .quirk = false },
    .{ .stag = 270, .xtag = @intFromEnum(header.TagId.longsigsize), .expected_count = 1, .quirk = false },
    .{ .stag = 271, .xtag = @intFromEnum(header.TagId.longarchivesize), .expected_count = 1, .quirk = false },
    .{ .stag = 278, .xtag = @intFromEnum(header.TagId.openpgp), .expected_count = 0, .quirk = false },
};

const SecondaryTable = struct {
    name: []const u8,
    key_sql_type: []const u8,
    key_index: bool,
    hnum_index: bool,
};

const secondary_tables = [_]SecondaryTable{
    .{ .name = "Name", .key_sql_type = "TEXT", .key_index = true, .hnum_index = false },
    .{ .name = "Basenames", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Group", .key_sql_type = "TEXT", .key_index = true, .hnum_index = false },
    .{ .name = "Requirename", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Providename", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Conflictname", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Obsoletename", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Triggername", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Dirnames", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Installtid", .key_sql_type = "BLOB", .key_index = false, .hnum_index = false },
    .{ .name = "Sigmd5", .key_sql_type = "BLOB", .key_index = false, .hnum_index = false },
    .{ .name = "Sha1header", .key_sql_type = "TEXT", .key_index = true, .hnum_index = false },
    .{ .name = "Filetriggername", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Transfiletriggername", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Recommendname", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Suggestname", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Supplementname", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
    .{ .name = "Enhancename", .key_sql_type = "TEXT", .key_index = true, .hnum_index = true },
};

pub const Writer = struct {
    db: ?*c.sqlite3,
    dir_fd: c_int,
    root: install_engine.RootDir,

    pub fn openRoot(root: []const u8) Error!Writer {
        var pinned_root = install_engine.RootDir.initCreating(
            std.heap.c_allocator,
            root,
        ) catch return error.UnsafePath;
        errdefer pinned_root.deinit();
        const dir_fd = (pinned_root.openDirectory(
            txn_config.DEFAULT_DBPATH,
            true,
        ) catch return error.UnsafePath) orelse
            return error.SyscallFailed;
        return openAtDirFd(
            pinned_root,
            dir_fd,
            txn_config.DEFAULT_RPMDB_BASENAME,
        );
    }

    pub fn openConfig(config: *const txn_config.TxnConfig) Error!Writer {
        const expanded = config.expandMacroAlloc(
            std.heap.c_allocator,
            .dbpath,
        ) catch return error.PathTooLong;
        defer std.heap.c_allocator.free(expanded);
        const db_dir = if (expanded.len != 0 and expanded[0] == '/')
            expanded
        else
            try std.fmt.allocPrint(
                std.heap.c_allocator,
                "/{s}",
                .{expanded},
            );
        defer if (db_dir.ptr != expanded.ptr)
            std.heap.c_allocator.free(db_dir);
        const trimmed_dir = std.mem.trimEnd(u8, db_dir, "/");
        const normalized_dir = if (trimmed_dir.len == 0)
            "/"
        else
            trimmed_dir;
        var root = install_engine.RootDir.init(
            std.heap.c_allocator,
            config.installRoot(),
            null,
            null,
        ) catch return error.UnsafePath;
        errdefer root.deinit();
        const dir_fd = (root.openDirectory(normalized_dir, true) catch
            return error.UnsafePath) orelse return error.SyscallFailed;
        return openAtDirFd(
            root,
            dir_fd,
            txn_config.DEFAULT_RPMDB_BASENAME,
        );
    }

    pub fn openAtPath(db_path: []const u8) Error!Writer {
        const slash_index = std.mem.lastIndexOfScalar(u8, db_path, '/');
        const slash = slash_index orelse 0;
        const absolute = db_path.len != 0 and db_path[0] == '/';
        const dir_path = if (slash_index == null or slash == 0)
            "/"
        else if (absolute)
            db_path[0..slash]
        else
            try std.fmt.allocPrint(
                std.heap.c_allocator,
                "/{s}",
                .{db_path[0..slash]},
            );
        defer if (!absolute and slash_index != null and slash != 0)
            std.heap.c_allocator.free(dir_path);
        const basename = if (slash_index != null)
            db_path[slash + 1 ..]
        else
            db_path;
        if (basename.len == 0 or
            std.mem.indexOfScalar(u8, basename, '/') != null)
        {
            return error.UnsafePath;
        }
        var root = if (absolute)
            install_engine.RootDir.init(
                std.heap.c_allocator,
                "/",
                null,
                null,
            ) catch return error.UnsafePath
        else blk: {
            const cwd_fd = std.c.open(".", .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            });
            if (cwd_fd < 0) return error.SyscallFailed;
            break :blk install_engine.RootDir.initFromOwnedFd(
                std.heap.c_allocator,
                cwd_fd,
                null,
                null,
            ) catch return error.UnsafePath;
        };
        errdefer root.deinit();
        const dir_fd = (root.openDirectory(dir_path, true) catch
            return error.UnsafePath) orelse return error.SyscallFailed;
        return openAtDirFd(root, dir_fd, basename);
    }

    fn openAtDirFd(
        root: install_engine.RootDir,
        dir_fd: c_int,
        basename: []const u8,
    ) Error!Writer {
        var owned_root = root;
        errdefer owned_root.deinit();
        errdefer _ = sysc.close(dir_fd);
        try ensureCompatibleBackendFd(dir_fd, basename);
        const db_path = try std.fmt.allocPrint(
            std.heap.c_allocator,
            "/proc/self/fd/{d}/{s}",
            .{ dir_fd, basename },
        );
        defer std.heap.c_allocator.free(db_path);
        const db_path_z = try std.heap.c_allocator.dupeZ(u8, db_path);
        defer std.heap.c_allocator.free(db_path_z);

        var db: ?*c.sqlite3 = null;
        const open_rc = c.sqlite3_open_v2(
            db_path_z.ptr,
            &db,
            c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE | c.SQLITE_OPEN_NOMUTEX,
            null,
        );
        if (open_rc != c.SQLITE_OK) {
            if (db != null) _ = c.sqlite3_close(db);
            return error.SqliteOpenFailed;
        }
        errdefer _ = c.sqlite3_close(db);

        if (c.sqlite3_busy_timeout(db, 10000) != c.SQLITE_OK) {
            return error.SqliteBusyTimeoutFailed;
        }

        var writer = Writer{
            .db = db,
            .dir_fd = dir_fd,
            .root = owned_root,
        };
        try writer.execSql("PRAGMA secure_delete = OFF");
        try writer.execSql("PRAGMA journal_mode = WAL");
        try writer.execSql("PRAGMA wal_autocheckpoint = 10000");
        try writer.initSchema();
        return writer;
    }

    pub fn close(self: *Writer) void {
        if (self.db != null) {
            _ = c.sqlite3_close(self.db);
            self.db = null;
        }
        if (self.dir_fd >= 0) {
            _ = sysc.close(self.dir_fd);
            self.dir_fd = -1;
        }
        self.root.deinit();
    }

    pub fn installRpmPath(self: *Writer, path: [:0]const u8, options: InstallOptions) Error!u32 {
        var rpm = pkgfile.RpmFile.open(std.heap.c_allocator, path) catch return error.InvalidHeaderBlob;
        defer rpm.close(std.heap.c_allocator);
        return self.installRpm(&rpm, options);
    }

    pub fn installRpm(self: *Writer, rpm: *const pkgfile.RpmFile, options: InstallOptions) Error!u32 {
        const blob = try buildInstalledHeaderBlob(std.heap.c_allocator, rpm, options);
        defer std.heap.c_allocator.free(blob);

        const hdr = header.Header.parse(blob) catch return error.InvalidHeaderBlob;

        try self.begin();
        errdefer self.rollback() catch {};

        const hnum = try self.insertPackage(blob);
        try self.populateSecondaryTables(hdr, hnum);
        try self.commit();
        return hnum;
    }

    pub fn replaceRpm(self: *Writer, old_hnum: u32, rpm: *const pkgfile.RpmFile, options: InstallOptions) Error!u32 {
        const blob = try buildInstalledHeaderBlob(std.heap.c_allocator, rpm, options);
        defer std.heap.c_allocator.free(blob);

        const hdr = header.Header.parse(blob) catch return error.InvalidHeaderBlob;

        try self.begin();
        errdefer self.rollback() catch {};

        try self.deletePackage(old_hnum);
        try self.deleteSecondaryRows(old_hnum);
        const new_hnum = try self.insertPackage(blob);
        try self.populateSecondaryTables(hdr, new_hnum);
        try self.commit();
        return new_hnum;
    }

    pub fn eraseHnum(self: *Writer, hnum: u32) Error!void {
        try self.begin();
        errdefer self.rollback() catch {};

        try self.deletePackage(hnum);
        try self.deleteSecondaryRows(hnum);
        try self.commit();
    }

    /// Start an explicit transaction for a composed rpmdb mutation.
    pub fn beginTransaction(self: *Writer) Error!void {
        try self.begin();
    }

    pub fn commitTransaction(self: *Writer) Error!void {
        try self.commit();
    }

    pub fn rollbackTransaction(self: *Writer) Error!void {
        try self.rollback();
    }

    /// Insert a pre-encoded installed header and all secondary indexes.
    /// The caller must hold an explicit transaction.
    pub fn insertHeaderInTransaction(
        self: *Writer,
        blob: []const u8,
    ) Error!u32 {
        const hdr = header.Header.parse(blob) catch return error.InvalidHeaderBlob;
        const hnum = try self.insertPackage(blob);
        try self.populateSecondaryTables(hdr, hnum);
        return hnum;
    }

    /// Remove an installed header and all its secondary index rows.
    /// The caller must hold an explicit transaction.
    pub fn eraseHeaderInTransaction(self: *Writer, hnum: u32) Error!void {
        try self.deleteSecondaryRows(hnum);
        try self.deletePackage(hnum);
    }

    pub fn findHnumByNevra(self: *Writer, allocator: std.mem.Allocator, wanted_nevra: []const u8) Error!?u32 {
        var stmt = try Statement.init(self.db, "SELECT hnum, blob FROM Packages ORDER BY hnum");
        defer stmt.deinit();

        while (true) {
            const rc = c.sqlite3_step(stmt.raw);
            if (rc == c.SQLITE_DONE) return null;
            if (rc != c.SQLITE_ROW) return error.SqliteStepFailed;

            const hnum: u32 = @intCast(c.sqlite3_column_int(stmt.raw, 0));
            const blob_ptr = c.sqlite3_column_blob(stmt.raw, 1);
            const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt.raw, 1));
            if (blob_ptr == null or blob_len == 0) continue;

            const blob = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];
            const hdr = header.Header.parse(blob) catch return error.InvalidHeaderBlob;
            const nevra = (try hdr.allocNevra(allocator)) orelse return error.InvalidHeaderBlob;
            defer allocator.free(nevra);
            if (std.mem.eql(u8, nevra, wanted_nevra)) {
                return hnum;
            }
        }
    }

    pub fn readHeaderBlobCopy(
        self: *Writer,
        allocator: std.mem.Allocator,
        hnum: u32,
    ) Error![]u8 {
        var stmt = try Statement.init(self.db, "SELECT blob FROM Packages WHERE hnum=?");
        defer stmt.deinit();
        try stmt.bindU32(1, hnum);

        const rc = c.sqlite3_step(stmt.raw);
        if (rc == c.SQLITE_DONE) return error.NotFound;
        if (rc != c.SQLITE_ROW) return error.SqliteStepFailed;

        const blob_ptr = c.sqlite3_column_blob(stmt.raw, 0);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt.raw, 0));
        if (blob_ptr == null or blob_len == 0) return error.InvalidHeaderBlob;

        const blob = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];
        return allocator.dupe(u8, blob);
    }

    /// Find every installed package hnum whose main-header NAME
    /// matches `wanted_name`. Caller owns the returned slice; free
    /// with the same allocator.
    pub fn findHnumsByName(
        self: *Writer,
        allocator: std.mem.Allocator,
        wanted_name: []const u8,
    ) Error![]u32 {
        var stmt = try Statement.init(
            self.db,
            "SELECT hnum FROM 'Name' WHERE key=? ORDER BY hnum",
        );
        defer stmt.deinit();
        try stmt.bindText(1, wanted_name);

        var hnums = std.ArrayList(u32).empty;
        errdefer hnums.deinit(allocator);

        while (true) {
            const rc = c.sqlite3_step(stmt.raw);
            if (rc == c.SQLITE_DONE) break;
            if (rc != c.SQLITE_ROW) return error.SqliteStepFailed;
            const hnum: u32 = @intCast(c.sqlite3_column_int(stmt.raw, 0));
            try hnums.append(allocator, hnum);
        }
        return hnums.toOwnedSlice(allocator);
    }

    pub fn pathOwnedByOtherPackage(self: *Writer, current_hnum: u32, path: []const u8) Error!bool {
        if (path.len == 0 or path[0] != '/') {
            return error.InvalidHeaderBlob;
        }
        if (std.mem.eql(u8, path, "/")) {
            return false;
        }

        const wanted = self.root.canonicalPathOwned(path) catch
            return error.UnsafePath;
        defer std.heap.c_allocator.free(wanted);
        var stmt = try Statement.init(
            self.db,
            "SELECT blob FROM 'Packages' WHERE hnum<>?",
        );
        defer stmt.deinit();
        try stmt.bindU32(1, current_hnum);

        while (true) {
            const rc = c.sqlite3_step(stmt.raw);
            if (rc == c.SQLITE_DONE) return false;
            if (rc != c.SQLITE_ROW) return error.SqliteStepFailed;

            const blob_ptr = c.sqlite3_column_blob(stmt.raw, 0);
            const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt.raw, 0));
            if (blob_ptr == null or blob_len == 0) continue;

            const blob = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];
            const hdr = header.Header.parse(blob) catch return error.InvalidHeaderBlob;
            if (try headerOwnsCanonicalPath(&self.root, hdr, wanted)) {
                return true;
            }
        }
    }

    fn initSchema(self: *Writer) Error!void {
        try self.execSql("CREATE TABLE IF NOT EXISTS 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)");
        inline for (secondary_tables) |table| {
            var create_buf: [256]u8 = undefined;
            const create_sql = std.fmt.bufPrint(
                &create_buf,
                "CREATE TABLE IF NOT EXISTS '{s}' (key '{s}' NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL, FOREIGN KEY (hnum) REFERENCES 'Packages'(hnum))",
                .{ table.name, table.key_sql_type },
            ) catch return error.PathTooLong;
            try self.execSql(create_sql);

            if (table.key_index) {
                var key_idx_buf: [256]u8 = undefined;
                const key_idx_sql = std.fmt.bufPrint(
                    &key_idx_buf,
                    "CREATE INDEX IF NOT EXISTS '{s}_key_idx' ON '{s}'(key ASC)",
                    .{ table.name, table.name },
                ) catch return error.PathTooLong;
                try self.execSql(key_idx_sql);
            }
            if (table.hnum_index) {
                var hnum_idx_buf: [256]u8 = undefined;
                const hnum_idx_sql = std.fmt.bufPrint(
                    &hnum_idx_buf,
                    "CREATE INDEX IF NOT EXISTS '{s}_hnum_idx' ON '{s}'(hnum ASC)",
                    .{ table.name, table.name },
                ) catch return error.PathTooLong;
                try self.execSql(hnum_idx_sql);
            }
        }
    }

    fn begin(self: *Writer) Error!void {
        try self.execSql("BEGIN IMMEDIATE TRANSACTION");
    }

    fn commit(self: *Writer) Error!void {
        try self.execSql("COMMIT");
    }

    fn rollback(self: *Writer) Error!void {
        try self.execSql("ROLLBACK");
    }

    fn execSql(self: *Writer, sql: []const u8) Error!void {
        const sql_z = try std.heap.c_allocator.dupeZ(u8, sql);
        defer std.heap.c_allocator.free(sql_z);

        var err: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql_z.ptr, null, null, @ptrCast(&err));
        defer if (err != null) c.sqlite3_free(err);
        if (rc != c.SQLITE_OK) return error.SqliteExecFailed;
    }

    fn insertPackage(self: *Writer, blob: []const u8) Error!u32 {
        var stmt = try Statement.init(self.db, "INSERT INTO 'Packages' (blob) VALUES (?)");
        defer stmt.deinit();
        try stmt.bindBlob(1, blob);
        try stmt.stepDone();
        return @intCast(c.sqlite3_last_insert_rowid(self.db));
    }

    fn deletePackage(self: *Writer, hnum: u32) Error!void {
        var stmt = try Statement.init(self.db, "DELETE FROM 'Packages' WHERE hnum=?");
        defer stmt.deinit();
        try stmt.bindU32(1, hnum);
        try stmt.stepDone();
        if (c.sqlite3_changes(self.db) == 0) return error.NotFound;
    }

    fn deleteSecondaryRows(self: *Writer, hnum: u32) Error!void {
        inline for (secondary_tables) |table| {
            var sql_buf: [128]u8 = undefined;
            const sql = std.fmt.bufPrint(&sql_buf, "DELETE FROM '{s}' WHERE hnum=?", .{table.name}) catch return error.PathTooLong;
            var stmt = try Statement.init(self.db, sql);
            defer stmt.deinit();
            try stmt.bindU32(1, hnum);
            try stmt.stepDone();
        }
    }

    fn populateSecondaryTables(self: *Writer, hdr: header.Header, hnum: u32) Error!void {
        const name = hdr.getString(.name) orelse return error.InvalidHeaderBlob;
        try self.insertSingleText("Name", name, hnum, 0);
        try self.insertStringArrayTable("Basenames", hdr, .basenames, hnum, false);
        try self.insertGroupTable(hdr, hnum);
        try self.insertDependencyTable("Requirename", hdr, .requirename, .requireflags, hnum, true, true);
        try self.insertDependencyTable("Providename", hdr, .providename, .provideflags, hnum, false, false);
        try self.insertDependencyTable("Conflictname", hdr, .conflictname, .conflictflags, hnum, false, true);
        try self.insertDependencyTable("Obsoletename", hdr, .obsoletename, .obsoleteflags, hnum, false, false);
        try self.insertTriggerTable(hdr, hnum);
        try self.insertStringArrayTable("Dirnames", hdr, .dirnames, hnum, false);
        try self.insertInstallTidTable(hdr, hnum);
        try self.insertSigMd5Table(hdr, hnum);
        try self.insertSha1HeaderTable(hdr, hnum);
        try self.insertIndexedTriggerTable("Filetriggername", hdr, .filetriggername, RPMTAG_FILETRIGGERINDEX, hnum);
        try self.insertIndexedTriggerTable("Transfiletriggername", hdr, .transfiletriggername, RPMTAG_TRANSFILETRIGGERINDEX, hnum);
        try self.insertDependencyTable("Recommendname", hdr, .recommendname, .recommendflags, hnum, false, true);
        try self.insertDependencyTable("Suggestname", hdr, .suggestname, .suggestflags, hnum, false, true);
        try self.insertDependencyTable("Supplementname", hdr, .supplementname, .supplementflags, hnum, false, true);
        try self.insertDependencyTable("Enhancename", hdr, .enhancename, .enhanceflags, hnum, false, true);
    }

    fn insertSingleText(self: *Writer, table: []const u8, value: []const u8, hnum: u32, idx: u32) Error!void {
        var stmt = try InsertStmt.init(self.db, table);
        defer stmt.deinit();
        try stmt.putText(value, hnum, idx);
    }

    fn insertStringArrayTable(
        self: *Writer,
        table: []const u8,
        hdr: header.Header,
        tag: header.TagId,
        hnum: u32,
        allow_rich: bool,
    ) Error!void {
        const count = hdr.stringArrayCount(tag);
        if (count == 0) return;

        var stmt = try InsertStmt.init(self.db, table);
        defer stmt.deinit();

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const key = hdr.stringArrayItem(tag, i) orelse continue;
            try stmt.putText(key, hnum, @intCast(i));
            if (allow_rich and key.len > 0 and key[0] == '(') {
                try appendRichDependencyRows(std.heap.c_allocator, &stmt, key, hnum, @intCast(i));
            }
        }
    }

    fn insertGroupTable(self: *Writer, hdr: header.Header, hnum: u32) Error!void {
        const group = hdr.getString(.group) orelse "Unknown";
        try self.insertSingleText("Group", group, hnum, 0);
    }

    fn insertDependencyTable(
        self: *Writer,
        table: []const u8,
        hdr: header.Header,
        name_tag: header.TagId,
        flags_tag: header.TagId,
        hnum: u32,
        filter_transient: bool,
        allow_rich: bool,
    ) Error!void {
        const count = hdr.stringArrayCount(name_tag);
        if (count == 0) return;

        var stmt = try InsertStmt.init(self.db, table);
        defer stmt.deinit();

        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (filter_transient) {
                if (hdr.u32ArrayItem(flags_tag, i)) |flags| {
                    if (isTransientReq(flags)) continue;
                }
            }
            const key = hdr.stringArrayItem(name_tag, i) orelse continue;
            try stmt.putText(key, hnum, @intCast(i));
            if (allow_rich and key.len > 0 and key[0] == '(') {
                try appendRichDependencyRows(std.heap.c_allocator, &stmt, key, hnum, @intCast(i));
            }
        }
    }

    fn insertTriggerTable(self: *Writer, hdr: header.Header, hnum: u32) Error!void {
        const count = hdr.stringArrayCount(.triggername);
        if (count == 0) return;

        var stmt = try InsertStmt.init(self.db, "Triggername");
        defer stmt.deinit();

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const key = hdr.stringArrayItem(.triggername, i) orelse continue;
            var duplicate = false;
            var j: usize = 0;
            while (j < i) : (j += 1) {
                const prev = hdr.stringArrayItem(.triggername, j) orelse continue;
                if (std.mem.eql(u8, prev, key)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            try stmt.putText(key, hnum, @intCast(i));
        }
    }

    fn insertIndexedTriggerTable(
        self: *Writer,
        table: []const u8,
        hdr: header.Header,
        name_tag: header.TagId,
        index_tag_raw: u32,
        hnum: u32,
    ) Error!void {
        const count = hdr.stringArrayCount(name_tag);
        if (count == 0) return;

        var stmt = try InsertStmt.init(self.db, table);
        defer stmt.deinit();

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const key = hdr.stringArrayItem(name_tag, i) orelse continue;
            const idx_value = hdr.u32ArrayItemRaw(index_tag_raw, i) orelse @as(u32, @intCast(i));
            try stmt.putText(key, hnum, idx_value);
        }
    }

    fn insertInstallTidTable(self: *Writer, hdr: header.Header, hnum: u32) Error!void {
        const value = hdr.getU32(.install_tid) orelse return;
        var native_value = value;
        try self.insertSingleBlob("Installtid", std.mem.asBytes(&native_value), hnum, 0);
    }

    fn insertSigMd5Table(self: *Writer, hdr: header.Header, hnum: u32) Error!void {
        const entry = hdr.findRaw(RPMTAG_SIGMD5) orelse return;
        const bytes = hdr.rawEntryBytes(entry) orelse return error.InvalidHeaderBlob;
        try self.insertSingleBlob("Sigmd5", bytes, hnum, 0);
    }

    fn insertSha1HeaderTable(self: *Writer, hdr: header.Header, hnum: u32) Error!void {
        const value = hdr.getString(.sha1header) orelse return;
        try self.insertSingleText("Sha1header", value, hnum, 0);
    }

    fn insertSingleBlob(self: *Writer, table: []const u8, value: []const u8, hnum: u32, idx: u32) Error!void {
        var stmt = try InsertStmt.init(self.db, table);
        defer stmt.deinit();
        try stmt.putBlob(value, hnum, idx);
    }
};

test "config resolves recursively expanded dbpath for Writer" {
    const allocator = std.testing.allocator;
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    switch (std.os.linux.errno(std.os.linux.getcwd(cwd_buf[0..].ptr, cwd_buf.len))) {
        .SUCCESS => {},
        else => return error.PathTooLong,
    }
    const cwd_len = std.mem.findScalar(u8, &cwd_buf, 0) orelse return error.PathTooLong;
    const cwd = cwd_buf[0..cwd_len];
    var config = try txn_config.TxnConfig.init(allocator, cwd);
    defer config.deinit();
    _ = try config.applyRpmDefine("_native_test_root .rpmdb-write-config-test");
    _ = try config.applyRpmDefine("_dbpath %{_native_test_root}/db");

    var db_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const db_path = try config.resolveRpmDbSqlitePath(&db_path_buf);
    var expected_buf: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        try std.fmt.bufPrint(
            &expected_buf,
            "{s}/.rpmdb-write-config-test/db/rpmdb.sqlite",
            .{cwd},
        ),
        db_path,
    );
}

test "rpmdb writer confines database and sidecars beneath pinned root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "root");
    try tmp.dir.createDirPath(std.testing.io, "outside");

    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    switch (std.os.linux.errno(std.os.linux.getcwd(
        cwd_buf[0..].ptr,
        cwd_buf.len,
    ))) {
        .SUCCESS => {},
        else => return error.PathTooLong,
    }
    const cwd_len = std.mem.findScalar(u8, &cwd_buf, 0) orelse
        return error.PathTooLong;
    const cwd = cwd_buf[0..cwd_len];
    const tmp_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ cwd, tmp.sub_path },
    );
    defer allocator.free(tmp_path);
    const root_path = try std.fmt.allocPrint(
        allocator,
        "{s}/root",
        .{tmp_path},
    );
    defer allocator.free(root_path);
    const outside_path = try std.fmt.allocPrint(
        allocator,
        "{s}/outside",
        .{tmp_path},
    );
    defer allocator.free(outside_path);
    const var_path = try std.fmt.allocPrint(
        allocator,
        "{s}/var",
        .{root_path},
    );
    defer allocator.free(var_path);
    const var_z = try allocator.dupeZ(u8, var_path);
    defer allocator.free(var_z);
    const outside_z = try allocator.dupeZ(u8, outside_path);
    defer allocator.free(outside_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        sysc.symlink(outside_z.ptr, var_z.ptr),
    );

    var config = try txn_config.TxnConfig.init(allocator, root_path);
    defer config.deinit();
    try std.testing.expectError(
        error.UnsafePath,
        Writer.openConfig(&config),
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.access(std.testing.io, "outside/rpmdb.sqlite", .{}),
    );

    try tmp.dir.deleteFile(std.testing.io, "root/var");
    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/rpm");
    var writer = try Writer.openConfig(&config);
    const db_dir = try std.fmt.allocPrint(
        allocator,
        "{s}/var/lib/rpm",
        .{root_path},
    );
    defer allocator.free(db_dir);
    const parked_db_dir = try std.fmt.allocPrint(
        allocator,
        "{s}/parked-rpm",
        .{root_path},
    );
    defer allocator.free(parked_db_dir);
    const db_dir_z = try allocator.dupeZ(u8, db_dir);
    defer allocator.free(db_dir_z);
    const parked_db_dir_z = try allocator.dupeZ(u8, parked_db_dir);
    defer allocator.free(parked_db_dir_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        std.c.rename(db_dir_z.ptr, parked_db_dir_z.ptr),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        std.c.symlink(outside_z.ptr, db_dir_z.ptr),
    );
    try writer.beginTransaction();
    try writer.commitTransaction();
    writer.close();
    try tmp.dir.access(
        std.testing.io,
        "root/parked-rpm/rpmdb.sqlite",
        .{},
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.access(std.testing.io, "outside/rpmdb.sqlite-wal", .{}),
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.access(std.testing.io, "outside/rpmdb.sqlite-shm", .{}),
    );
    try tmp.dir.deleteFile(std.testing.io, "root/var/lib/rpm");
    try std.testing.expectEqual(
        @as(c_int, 0),
        std.c.rename(parked_db_dir_z.ptr, db_dir_z.ptr),
    );

    if (sysc.geteuid() != 0) {
        tmp.dir.deleteFile(
            std.testing.io,
            "root/var/lib/rpm/rpmdb.sqlite",
        ) catch {};
        try std.testing.expectEqual(
            @as(c_int, 0),
            sysc.chmod(db_dir_z.ptr, 0o555),
        );
        defer _ = sysc.chmod(db_dir_z.ptr, 0o755);
        if (Writer.openConfig(&config)) |opened| {
            var unexpected = opened;
            unexpected.close();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

pub fn buildInstalledHeaderBlob(
    allocator: std.mem.Allocator,
    rpm: *const pkgfile.RpmFile,
    options: InstallOptions,
) Error![]u8 {
    const main = rpm.main;
    if (main.findRawIncludingRegions(63) == null) return error.MissingImmutableRegion;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var drips = std.array_list.Managed(HeaderField).init(allocator);
    defer drips.deinit();

    try collectTranslatedSignatureDrips(&drips, rpm.main, rpm.sig);

    const file_count = fileCountFromHeader(main);
    if (options.file_states) |states| {
        if (states.len != file_count) return error.InvalidFileStates;
    }
    if (file_count != 0) {
        const states = if (options.file_states) |provided|
            provided
        else blk: {
            const zeroes = try arena.alloc(u8, file_count);
            @memset(zeroes, 0);
            break :blk zeroes;
        };
        try drips.append(.{
            .tag = RPMTAG_FILESTATES,
            .typ = .char_type,
            .count = @intCast(states.len),
            .bytes = states,
        });
    }

    const install_time = options.effectiveInstallTime();
    try drips.append(try makeU32Drip(arena, RPMTAG_INSTALLTIME, install_time));
    try drips.append(try makeU32Drip(arena, RPMTAG_INSTALLCOLOR, options.install_color));
    try drips.append(try makeU32Drip(arena, RPMTAG_INSTALLTID, options.install_tid));

    sortDripsByTag(drips.items);
    return appendHeaderFields(allocator, rpm.main.bytes, drips.items);
}

/// Pre-encoded RPM header field. Integer bytes use big-endian storage;
/// string and string-array bytes include their terminating NULs.
pub const HeaderField = struct {
    tag: u32,
    typ: header.TypeId,
    count: u32,
    bytes: []const u8,
};

fn collectTranslatedSignatureDrips(
    drips: *std.array_list.Managed(HeaderField),
    main: header.Header,
    sig: header.Header,
) Error!void {
    const rpmformat = main.getU32(.rpmformat) orelse 0;

    for (sig_tag_maps) |mapping| {
        if (rpmformat >= 6 and mapping.stag >= 1000) continue;
        if (main.findRaw(mapping.xtag) != null) {
            if (rpmformat < 6 and mapping.quirk and sig.findRaw(mapping.stag) == null) {
                continue;
            }
            return error.InvalidHeaderBlob;
        }

        const entry = sig.findRaw(mapping.stag) orelse continue;
        if (mapping.expected_count != 0 and entry.count != mapping.expected_count) {
            return error.InvalidSigTagCount;
        }
        const bytes = sig.rawEntryBytes(entry) orelse return error.InvalidHeaderBlob;
        try drips.append(.{
            .tag = mapping.xtag,
            .typ = @enumFromInt(entry.typ),
            .count = entry.count,
            .bytes = bytes,
        });
    }
}

fn fileCountFromHeader(hdr: header.Header) usize {
    const by_name = hdr.stringArrayCount(.basenames);
    if (by_name != 0) return by_name;
    if (hdr.find(.filemodes)) |entry| return entry.count;
    if (hdr.findRaw(RPMTAG_FILESTATES)) |entry| return entry.count;
    return 0;
}

fn headerOwnsCanonicalPath(
    root: *const install_engine.RootDir,
    hdr: header.Header,
    wanted: []const u8,
) Error!bool {
    const count = hdr.stringArrayCount(.basenames);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const basename = hdr.stringArrayItem(.basenames, i) orelse continue;
        const dir_index = hdr.u32ArrayItem(.dirindexes, i) orelse continue;
        const dirname = hdr.stringArrayItem(.dirnames, dir_index) orelse continue;
        const logical = try std.fmt.allocPrint(
            std.heap.c_allocator,
            "{s}{s}",
            .{ dirname, basename },
        );
        defer std.heap.c_allocator.free(logical);
        const canonical = root.canonicalPathOwned(logical) catch
            return error.UnsafePath;
        defer std.heap.c_allocator.free(canonical);
        if (std.mem.eql(u8, canonical, wanted)) {
            return true;
        }
    }

    return false;
}

/// Encode a complete RPM immutable main-header region.
///
/// `fields` excludes RPMTAG_HEADERIMMUTABLE; this function emits that
/// marker first and writes its matching negative-offset trailer after all
/// immutable data. The result can be stored in Packages or prefixed with
/// the standalone header magic for SHA digest calculation.
pub fn encodeImmutableHeader(
    allocator: std.mem.Allocator,
    fields: []const HeaderField,
) Error![]u8 {
    const region_tag: u32 = 63;
    const index_count = std.math.add(usize, fields.len, 1) catch
        return error.InvalidHeaderField;
    const index_count_u32 = std.math.cast(u32, index_count) orelse
        return error.InvalidHeaderField;
    const index_span = std.math.mul(usize, index_count, 16) catch
        return error.InvalidHeaderField;
    const signed_span = std.math.cast(i32, index_span) orelse
        return error.InvalidHeaderField;

    var data_len: usize = 0;
    for (fields) |field| {
        if (field.tag == region_tag or field.count == 0)
            return error.InvalidHeaderField;
        data_len = std.math.add(
            usize,
            data_len,
            alignDiffForType(field.typ, data_len),
        ) catch return error.InvalidHeaderField;
        data_len = std.math.add(usize, data_len, field.bytes.len) catch
            return error.InvalidHeaderField;
    }
    const trailer_offset = data_len;
    data_len = std.math.add(usize, data_len, 16) catch
        return error.InvalidHeaderField;
    const data_len_u32 = std.math.cast(u32, data_len) orelse
        return error.InvalidHeaderField;
    const total_len = std.math.add(usize, 8 + index_span, data_len) catch
        return error.InvalidHeaderField;

    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    @memset(out, 0);
    writeU32BE(out, 0, index_count_u32);
    writeU32BE(out, 4, data_len_u32);

    writeEntry(
        out,
        8,
        region_tag,
        @intFromEnum(header.TypeId.bin),
        @intCast(trailer_offset),
        16,
    );

    const data_off = 8 + index_span;
    var cursor: usize = 0;
    for (fields, 0..) |field, index| {
        cursor += alignDiffForType(field.typ, cursor);
        writeEntry(
            out,
            8 + (index + 1) * 16,
            field.tag,
            @intFromEnum(field.typ),
            @intCast(cursor),
            field.count,
        );
        @memcpy(
            out[data_off + cursor .. data_off + cursor + field.bytes.len],
            field.bytes,
        );
        cursor += field.bytes.len;
    }
    if (cursor != trailer_offset) return error.InvalidHeaderField;

    writeEntry(
        out,
        data_off + trailer_offset,
        region_tag,
        @intFromEnum(header.TypeId.bin),
        @bitCast(-signed_span),
        16,
    );

    _ = header.Header.parseWithRegion(out, .immutable, true) catch
        return error.InvalidHeaderBlob;
    return out;
}

/// Append mutable fields after an existing immutable header region.
pub fn appendHeaderFields(
    allocator: std.mem.Allocator,
    base_blob: []const u8,
    drips: []const HeaderField,
) Error![]u8 {
    const base = header.Header.parse(base_blob) catch return error.InvalidHeaderBlob;
    const new_index_count = base.index_count + @as(u32, @intCast(drips.len));
    const data_len = computeExtendedDataLength(base.data_size, drips);
    const total_len = 8 + @as(usize, new_index_count) * 16 + data_len;

    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    @memset(out, 0);

    writeU32BE(out, 0, new_index_count);
    writeU32BE(out, 4, @intCast(data_len));

    const base_index_bytes = base_blob[8..base.data_off];
    @memcpy(out[8 .. 8 + base_index_bytes.len], base_index_bytes);

    const new_data_off = 8 + @as(usize, new_index_count) * 16;
    const base_data = base_blob[base.data_off .. base.data_off + base.data_size];
    @memcpy(out[new_data_off .. new_data_off + base_data.len], base_data);

    var data_cursor: usize = base.data_size;
    var drip_index: usize = 0;
    while (drip_index < drips.len) : (drip_index += 1) {
        const drip = drips[drip_index];
        data_cursor += alignDiffForType(drip.typ, data_cursor);
        const offset = data_cursor;
        @memcpy(out[new_data_off + offset .. new_data_off + offset + drip.bytes.len], drip.bytes);
        writeEntry(
            out,
            8 + (base.index_count + @as(u32, @intCast(drip_index))) * 16,
            drip.tag,
            @intFromEnum(drip.typ),
            @intCast(offset),
            drip.count,
        );
        data_cursor += drip.bytes.len;
    }

    if (data_cursor != data_len) return error.InvalidHeaderBlob;
    return out;
}

fn computeExtendedDataLength(base_data_size: u32, drips: []const HeaderField) usize {
    var data_len: usize = base_data_size;
    for (drips) |drip| {
        data_len += alignDiffForType(drip.typ, data_len);
        data_len += drip.bytes.len;
    }
    return data_len;
}

fn alignDiffForType(typ: header.TypeId, offset: usize) usize {
    const alignment: usize = switch (typ) {
        .int16 => 2,
        .int32 => 4,
        .int64 => 8,
        else => 1,
    };
    const rem = offset % alignment;
    return if (rem == 0) 0 else alignment - rem;
}

fn makeU32Drip(allocator: std.mem.Allocator, tag: u32, value: u32) Error!HeaderField {
    const bytes = try allocator.alloc(u8, 4);
    writeU32BE(bytes, 0, value);
    return .{
        .tag = tag,
        .typ = .int32,
        .count = 1,
        .bytes = bytes,
    };
}

fn writeEntry(buf: []u8, off: usize, tag: u32, typ: u32, data_off: u32, count: u32) void {
    writeU32BE(buf, off, tag);
    writeU32BE(buf, off + 4, typ);
    writeU32BE(buf, off + 8, data_off);
    writeU32BE(buf, off + 12, count);
}

fn writeU32BE(buf: []u8, off: usize, value: u32) void {
    buf[off] = @intCast((value >> 24) & 0xff);
    buf[off + 1] = @intCast((value >> 16) & 0xff);
    buf[off + 2] = @intCast((value >> 8) & 0xff);
    buf[off + 3] = @intCast(value & 0xff);
}

fn sortDripsByTag(drips: []HeaderField) void {
    var i: usize = 1;
    while (i < drips.len) : (i += 1) {
        var j = i;
        while (j > 0 and drips[j].tag < drips[j - 1].tag) : (j -= 1) {
            const tmp = drips[j - 1];
            drips[j - 1] = drips[j];
            drips[j] = tmp;
        }
    }
}

fn isTransientReq(flags: u32) bool {
    return (flags & INSTALL_ONLY_MASK) != 0 and
        (flags & ERASE_ONLY_MASK) == 0 and
        (flags & RPMSENSE_META) == 0;
}

const Statement = struct {
    db: ?*c.sqlite3,
    raw: ?*c.sqlite3_stmt,

    fn init(db: ?*c.sqlite3, sql: []const u8) Error!Statement {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql.ptr, @intCast(sql.len), &stmt, null) != c.SQLITE_OK) {
            return error.SqlitePrepareFailed;
        }
        return .{ .db = db, .raw = stmt };
    }

    fn deinit(self: *Statement) void {
        if (self.raw) |stmt| _ = c.sqlite3_finalize(stmt);
        self.raw = null;
    }

    fn reset(self: *Statement) void {
        _ = c.sqlite3_reset(self.raw);
        _ = c.sqlite3_clear_bindings(self.raw);
    }

    fn bindU32(self: *Statement, index: c_int, value: u32) Error!void {
        if (c.sqlite3_bind_int(self.raw, index, @intCast(value)) != c.SQLITE_OK) {
            return error.SqliteStepFailed;
        }
    }

    fn bindText(self: *Statement, index: c_int, value: []const u8) Error!void {
        if (c.sqlite3_bind_text(self.raw, index, value.ptr, @intCast(value.len), null) != c.SQLITE_OK) {
            return error.SqliteStepFailed;
        }
    }

    fn bindBlob(self: *Statement, index: c_int, value: []const u8) Error!void {
        if (c.sqlite3_bind_blob(self.raw, index, value.ptr, @intCast(value.len), null) != c.SQLITE_OK) {
            return error.SqliteStepFailed;
        }
    }

    fn stepDone(self: *Statement) Error!void {
        defer self.reset();
        const rc = c.sqlite3_step(self.raw);
        if (rc != c.SQLITE_DONE) return error.SqliteStepFailed;
    }
};

const InsertStmt = struct {
    stmt: Statement,

    fn init(db: ?*c.sqlite3, table: []const u8) Error!InsertStmt {
        var sql_buf: [96]u8 = undefined;
        const sql = std.fmt.bufPrint(&sql_buf, "INSERT INTO '{s}' VALUES(?, ?, ?)", .{table}) catch return error.PathTooLong;
        return .{ .stmt = try Statement.init(db, sql) };
    }

    fn deinit(self: *InsertStmt) void {
        self.stmt.deinit();
    }

    fn putText(self: *InsertStmt, key: []const u8, hnum: u32, idx: u32) Error!void {
        try self.stmt.bindText(1, key);
        try self.stmt.bindU32(2, hnum);
        try self.stmt.bindU32(3, idx);
        try self.stmt.stepDone();
    }

    fn putBlob(self: *InsertStmt, key: []const u8, hnum: u32, idx: u32) Error!void {
        try self.stmt.bindBlob(1, key);
        try self.stmt.bindU32(2, hnum);
        try self.stmt.bindU32(3, idx);
        try self.stmt.stepDone();
    }
};

const RichOp = enum {
    none,
    single,
    and_,
    or_,
    if_,
    else_,
    with_,
    without_,
    unless_,
};

const RichState = struct {
    allocator: std.mem.Allocator,
    names: std.array_list.Managed([]const u8),
    level_starts: std.array_list.Managed(usize),
    neg: bool,

    fn init(allocator: std.mem.Allocator) RichState {
        return .{
            .allocator = allocator,
            .names = std.array_list.Managed([]const u8).init(allocator),
            .level_starts = std.array_list.Managed(usize).init(allocator),
            .neg = false,
        };
    }

    fn deinit(self: *RichState) void {
        for (self.names.items) |item| {
            self.allocator.free(item);
        }
        self.names.deinit();
        self.level_starts.deinit();
    }

    fn onEnter(self: *RichState) !void {
        try self.level_starts.append(self.names.items.len);
    }

    fn onSimple(self: *RichState, name: []const u8) !void {
        if (name.len > 7 and std.mem.eql(u8, name[0..7], "rpmlib(")) return;
        const out = try self.allocator.alloc(u8, name.len + 1);
        out[0] = if (self.neg) '!' else ' ';
        @memcpy(out[1..], name);
        try self.names.append(out);
    }

    fn onOp(self: *RichState, op: RichOp) !void {
        switch (op) {
            .if_, .unless_ => {
                if (self.level_starts.items.len == 0) return error.InvalidRichDependency;
                self.level_starts.items[self.level_starts.items.len - 1] = self.names.items.len;
                self.neg = !self.neg;
            },
            .else_ => {
                if (self.level_starts.items.len == 0) return error.InvalidRichDependency;
                const start = self.level_starts.items[self.level_starts.items.len - 1];
                const end = self.names.items.len;
                var i: usize = start;
                while (i < end) : (i += 1) {
                    const current = self.names.items[i];
                    const dup = try self.allocator.alloc(u8, current.len);
                    dup[0] = if (current[0] == '!') ' ' else '!';
                    @memcpy(dup[1..], current[1..]);
                    try self.names.append(dup);
                }
                self.neg = !self.neg;
            },
            else => {},
        }
    }

    fn onLeave(self: *RichState, op: RichOp) void {
        if (op == .if_ or op == .unless_) {
            self.neg = !self.neg;
        }
        _ = self.level_starts.pop();
    }
};

fn appendRichDependencyRows(
    allocator: std.mem.Allocator,
    stmt: *InsertStmt,
    text: []const u8,
    hnum: u32,
    idx: u32,
) Error!void {
    var state = RichState.init(allocator);
    defer state.deinit();

    var pos: usize = 0;
    _ = try parseRichExpr(text, &pos, &state);
    skipRichWhitespace(text, &pos);
    if (pos != text.len) return error.InvalidRichDependency;

    sortOwnedByteSlices(state.names.items);
    var i: usize = 0;
    while (i < state.names.items.len) : (i += 1) {
        if (i > 0 and std.mem.eql(u8, state.names.items[i - 1], state.names.items[i])) continue;
        const key = state.names.items[i];
        if (key.len == 0) continue;
        try stmt.putText(if (key[0] == ' ') key[1..] else key, hnum, idx);
    }
}

fn parseRichExpr(text: []const u8, pos: *usize, state: *RichState) Error!RichOp {
    try state.onEnter();
    errdefer state.onLeave(.single);

    if (pos.* >= text.len or text[pos.*] != '(') return error.InvalidRichDependency;
    pos.* += 1;

    var op: RichOp = .single;
    var first_op: RichOp = .single;
    var chain_op: RichOp = .none;

    while (true) {
        skipRichWhitespace(text, pos);
        if (pos.* >= text.len) return error.InvalidRichDependency;
        if (text[pos.*] == ')') return error.InvalidRichDependency;

        if (text[pos.*] == '(') {
            _ = try parseRichExpr(text, pos, state);
        } else {
            try parseSimpleRichDependency(text, pos, state);
        }

        skipRichWhitespace(text, pos);
        if (pos.* >= text.len) return error.InvalidRichDependency;
        if (text[pos.*] == ')') break;

        op = try parseRichOp(text, pos);
        if (first_op == .single) first_op = op;
        if (op == .else_ and (chain_op == .if_ or chain_op == .unless_)) {
            chain_op = .none;
        }
        if (chain_op != .none and op != chain_op) return error.InvalidRichDependency;
        if (chain_op != .none and op != .and_ and op != .or_ and op != .with_) {
            return error.InvalidRichDependency;
        }
        try state.onOp(op);
        chain_op = op;
    }

    pos.* += 1;
    state.onLeave(op);
    return op;
}

fn skipRichWhitespace(text: []const u8, pos: *usize) void {
    while (pos.* < text.len) : (pos.* += 1) {
        const ch = text[pos.*];
        if (!std.ascii.isWhitespace(ch) and ch != ',') break;
    }
}

fn skipNonWhitespaceRich(text: []const u8, pos: *usize) void {
    var balance: i32 = 0;
    while (pos.* < text.len) {
        const ch = text[pos.*];
        if (std.ascii.isWhitespace(ch) or ch == ',') break;
        if (ch == ')') {
            if (balance <= 0) break;
            balance -= 1;
            pos.* += 1;
            continue;
        }
        if (ch == '(') balance += 1;
        pos.* += 1;
    }
}

fn parseSimpleRichDependency(text: []const u8, pos: *usize, state: *RichState) Error!void {
    const name_start = pos.*;
    skipNonWhitespaceRich(text, pos);
    if (pos.* == name_start) return error.InvalidRichDependency;
    const name = text[name_start..pos.*];

    skipRichWhitespace(text, pos);
    if (pos.* < text.len) {
        const op_start = pos.*;
        var op_end = pos.*;
        skipNonWhitespaceRich(text, &op_end);
        if (op_end > op_start and isSenseToken(text[op_start..op_end])) {
            pos.* = op_end;
            skipRichWhitespace(text, pos);
            const version_start = pos.*;
            skipNonWhitespaceRich(text, pos);
            if (pos.* == version_start) return error.InvalidRichDependency;
        }
    }

    try state.onSimple(name);
}

fn isSenseToken(token: []const u8) bool {
    return std.mem.eql(u8, token, "=") or
        std.mem.eql(u8, token, "<") or
        std.mem.eql(u8, token, ">") or
        std.mem.eql(u8, token, "<=") or
        std.mem.eql(u8, token, ">=");
}

fn parseRichOp(text: []const u8, pos: *usize) Error!RichOp {
    const start = pos.*;
    while (pos.* < text.len and !std.ascii.isWhitespace(text[pos.*]) and text[pos.*] != ')') : (pos.* += 1) {}
    const token = text[start..pos.*];
    if (std.mem.eql(u8, token, "and")) return .and_;
    if (std.mem.eql(u8, token, "or")) return .or_;
    if (std.mem.eql(u8, token, "if")) return .if_;
    if (std.mem.eql(u8, token, "unless")) return .unless_;
    if (std.mem.eql(u8, token, "else")) return .else_;
    if (std.mem.eql(u8, token, "with")) return .with_;
    if (std.mem.eql(u8, token, "without")) return .without_;
    return error.InvalidRichDependency;
}

fn sortOwnedByteSlices(items: [][]const u8) void {
    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        var j = i;
        while (j > 0 and byteSliceLess(items[j], items[j - 1])) : (j -= 1) {
            const tmp = items[j - 1];
            items[j - 1] = items[j];
            items[j] = tmp;
        }
    }
}

fn byteSliceLess(a: []const u8, b: []const u8) bool {
    const limit = if (a.len < b.len) a.len else b.len;
    var i: usize = 0;
    while (i < limit) : (i += 1) {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return a.len < b.len;
}

fn ensureCompatibleBackendFd(
    dir_fd: c_int,
    basename: []const u8,
) Error!void {
    const basename_z = try std.heap.c_allocator.dupeZ(u8, basename);
    defer std.heap.c_allocator.free(basename_z);
    var st: sysc.struct_stat = undefined;
    const db_rc = sysc.fstatat(
        dir_fd,
        basename_z.ptr,
        &st,
        0x100,
    );
    if (db_rc == 0) {
        if ((st.st_mode & sysc.S_IFMT) != sysc.S_IFREG) {
            return error.UnsafePath;
        }
        return;
    }
    if (std.c.errno(db_rc) != .NOENT) return error.SyscallFailed;
    const markers = [_][]const u8{ "Packages", "Packages.db", "Packages.db-wal", "Packages.db-shm" };
    for (markers) |marker| {
        const marker_z = try std.heap.c_allocator.dupeZ(u8, marker);
        defer std.heap.c_allocator.free(marker_z);
        if (sysc.fstatat(dir_fd, marker_z.ptr, &st, 0x100) == 0) {
            return error.UnsupportedBackend;
        }
    }
}

fn buildHeaderBlobForTest(
    allocator: std.mem.Allocator,
    entries: []const TestHeaderEntry,
) ![]u8 {
    var data = std.array_list.Managed(u8).init(allocator);
    defer data.deinit();

    var index = std.array_list.Managed(u8).init(allocator);
    defer index.deinit();

    for (entries) |entry| {
        const offset: u32 = @intCast(data.items.len);
        var tag: u32 = 0;
        var typ: header.TypeId = .string;
        var count: u32 = 0;

        switch (entry) {
            .string => |value| {
                tag = value.tag;
                typ = value.typ;
                count = 1;
                try data.appendSlice(value.value);
                try data.append(0);
            },
            .string_array => |value| {
                tag = value.tag;
                typ = .string_array;
                count = @intCast(value.values.len);
                for (value.values) |item| {
                    try data.appendSlice(item);
                    try data.append(0);
                }
            },
            .int32 => |value| {
                tag = value.tag;
                typ = .int32;
                count = 1;
                var bytes: [4]u8 = undefined;
                writeU32BE(&bytes, 0, value.value);
                try data.appendSlice(&bytes);
            },
            .bin => |value| {
                tag = value.tag;
                typ = .bin;
                count = @intCast(value.value.len);
                try data.appendSlice(value.value);
            },
        }

        try appendBeU32(&index, tag);
        try appendBeU32(&index, @intFromEnum(typ));
        try appendBeU32(&index, offset);
        try appendBeU32(&index, count);
    }

    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    try appendBeU32(&out, @intCast(entries.len));
    try appendBeU32(&out, @intCast(data.items.len));
    try out.appendSlice(index.items);
    try out.appendSlice(data.items);
    return out.toOwnedSlice();
}

fn appendBeU32(list: *std.array_list.Managed(u8), value: u32) !void {
    try list.append(@intCast((value >> 24) & 0xff));
    try list.append(@intCast((value >> 16) & 0xff));
    try list.append(@intCast((value >> 8) & 0xff));
    try list.append(@intCast(value & 0xff));
}

const TestHeaderEntry = union(enum) {
    string: struct {
        tag: u32,
        value: []const u8,
        typ: header.TypeId = .string,
    },
    string_array: struct {
        tag: u32,
        values: []const []const u8,
    },
    int32: struct {
        tag: u32,
        value: u32,
    },
    bin: struct {
        tag: u32,
        value: []const u8,
    },
};

test "appendHeaderFields appends aligned fields" {
    const base = try buildHeaderBlobForTest(std.testing.allocator, &.{
        .{ .string = .{ .tag = @intFromEnum(header.TagId.name), .value = "pkg" } },
        .{ .string = .{ .tag = @intFromEnum(header.TagId.version), .value = "1" } },
    });
    defer std.testing.allocator.free(base);

    var int_bytes: [4]u8 = undefined;
    writeU32BE(&int_bytes, 0, 42);
    const out = try appendHeaderFields(std.testing.allocator, base, &.{
        .{ .tag = @intFromEnum(header.TagId.install_time), .typ = .int32, .count = 1, .bytes = &int_bytes },
    });
    defer std.testing.allocator.free(out);

    const parsed = try header.Header.parse(out);
    try std.testing.expectEqual(@as(u32, 3), parsed.index_count);
    try std.testing.expectEqual(@as(?u32, 42), parsed.getU32(.install_time));
    try std.testing.expectEqualStrings("pkg", parsed.getString(.name).?);
}

test "encodeImmutableHeader emits a complete reusable region" {
    const name = "gpg-pubkey\x00";
    const version = "12345678\x00";
    const out = try encodeImmutableHeader(std.testing.allocator, &.{
        .{
            .tag = @intFromEnum(header.TagId.name),
            .typ = .string,
            .count = 1,
            .bytes = name,
        },
        .{
            .tag = @intFromEnum(header.TagId.version),
            .typ = .string,
            .count = 1,
            .bytes = version,
        },
    });
    defer std.testing.allocator.free(out);

    const parsed = try header.Header.parseWithRegion(out, .immutable, true);
    try std.testing.expectEqualStrings("gpg-pubkey", parsed.getString(.name).?);
    try std.testing.expectEqualStrings("12345678", parsed.getString(.version).?);
}

test "rich dependency extraction matches rpmdb negation semantics" {
    var stmt = RichState.init(std.testing.allocator);
    defer stmt.deinit();

    var pos: usize = 0;
    _ = try parseRichExpr("(foo if bar else baz)", &pos, &stmt);
    skipRichWhitespace("(foo if bar else baz)", &pos);
    try std.testing.expectEqual(@as(usize, 4), stmt.names.items.len);
    sortOwnedByteSlices(stmt.names.items);
    try std.testing.expectEqualStrings(" bar", stmt.names.items[0]);
    try std.testing.expectEqualStrings(" baz", stmt.names.items[1]);
    try std.testing.expectEqualStrings(" foo", stmt.names.items[2]);
    try std.testing.expectEqualStrings("!bar", stmt.names.items[3]);
}
