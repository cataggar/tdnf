const std = @import("std");
const builtin = @import("builtin");
const sqlite = @import("sqlite");
const header = @import("rpm_header");
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

    pub fn openRoot(root: []const u8) Error!Writer {
        var config = txn_config.TxnConfig.init(std.heap.c_allocator, root) catch |err| {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.InvalidInstallRoot => error.PathTooLong,
            };
        };
        defer config.deinit();
        return openConfig(&config);
    }

    pub fn openConfig(config: *const txn_config.TxnConfig) Error!Writer {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const db_path = config.resolveRpmDbSqlitePath(&buf) catch return error.PathTooLong;
        return openAtPath(db_path);
    }

    pub fn openAtPath(db_path: []const u8) Error!Writer {
        try ensureCompatibleBackend(db_path);
        try ensureParentDirectory(db_path);

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

        var writer = Writer{ .db = db };
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

    var drips = std.array_list.Managed(Drip).init(allocator);
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
    return appendDripsToHeader(allocator, rpm.main.bytes, drips.items);
}

const Drip = struct {
    tag: u32,
    typ: header.TypeId,
    count: u32,
    bytes: []const u8,
};

fn collectTranslatedSignatureDrips(
    drips: *std.array_list.Managed(Drip),
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

fn appendDripsToHeader(
    allocator: std.mem.Allocator,
    base_blob: []const u8,
    drips: []const Drip,
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

fn computeExtendedDataLength(base_data_size: u32, drips: []const Drip) usize {
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

fn makeU32Drip(allocator: std.mem.Allocator, tag: u32, value: u32) Error!Drip {
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

fn sortDripsByTag(drips: []Drip) void {
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

fn ensureCompatibleBackend(db_path: []const u8) Error!void {
    const dir_path = std.fs.path.dirname(db_path) orelse return error.PathTooLong;
    const db_path_z = try std.heap.c_allocator.dupeZ(u8, db_path);
    defer std.heap.c_allocator.free(db_path_z);
    if (sysc.access(db_path_z.ptr, sysc.F_OK) == 0) return;

    const markers = [_][]const u8{ "Packages", "Packages.db", "Packages.db-wal", "Packages.db-shm" };
    for (markers) |marker| {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const marker_path = std.fmt.bufPrintZ(&buf, "{s}/{s}", .{ dir_path, marker }) catch return error.PathTooLong;
        if (sysc.access(marker_path.ptr, sysc.F_OK) == 0) return error.UnsupportedBackend;
    }
}

fn ensureParentDirectory(path: []const u8) Error!void {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.PathTooLong;
    if (slash == 0) return;
    const dir_path = path[0..slash];
    const owned = try std.heap.c_allocator.dupeZ(u8, dir_path);
    defer std.heap.c_allocator.free(owned);

    var i: usize = 1;
    while (i < owned.len) : (i += 1) {
        if (owned[i] != '/') continue;
        const saved = owned[i];
        owned[i] = 0;
        const rc = sysc.mkdir(owned.ptr, 0o755);
        if (std.c.errno(rc) != .SUCCESS and std.c.errno(rc) != .EXIST) {
            owned[i] = saved;
            return error.PathTooLong;
        }
        owned[i] = saved;
    }
    const rc = sysc.mkdir(owned.ptr, 0o755);
    if (std.c.errno(rc) != .SUCCESS and std.c.errno(rc) != .EXIST) {
        return error.PathTooLong;
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

test "appendDripsToHeader appends aligned drips" {
    const base = try buildHeaderBlobForTest(std.testing.allocator, &.{
        .{ .string = .{ .tag = @intFromEnum(header.TagId.name), .value = "pkg" } },
        .{ .string = .{ .tag = @intFromEnum(header.TagId.version), .value = "1" } },
    });
    defer std.testing.allocator.free(base);

    var int_bytes: [4]u8 = undefined;
    writeU32BE(&int_bytes, 0, 42);
    const out = try appendDripsToHeader(std.testing.allocator, base, &.{
        .{ .tag = @intFromEnum(header.TagId.install_time), .typ = .int32, .count = 1, .bytes = &int_bytes },
    });
    defer std.testing.allocator.free(out);

    const parsed = try header.Header.parse(out);
    try std.testing.expectEqual(@as(u32, 3), parsed.index_count);
    try std.testing.expectEqual(@as(?u32, 42), parsed.getU32(.install_time));
    try std.testing.expectEqualStrings("pkg", parsed.getString(.name).?);
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
