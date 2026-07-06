const std = @import("std");
const sqlite = @import("sqlite");

const history_db = @import("db.zig");

pub const allocator = std.heap.c_allocator;

pub const history_trans_type_base: c_int = 0;
pub const history_trans_type_delta: c_int = 1;

pub const history_item_type_set: c_int = 0;
pub const history_item_type_add: c_int = 1;
pub const history_item_type_remove: c_int = 2;

pub const sql_create_table_rpms =
    "CREATE TABLE IF NOT EXISTS " ++
    "rpms(" ++
    "Id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "nevra TEXT);";

pub const sql_create_table_names =
    "CREATE TABLE IF NOT EXISTS " ++
    "names(" ++
    "Id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "name TEXT);";

pub const sql_create_table_flag_set =
    "CREATE TABLE IF NOT EXISTS " ++
    "flag_set(" ++
    "Id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "trans_id INTEGER," ++
    "name_id INTEGER," ++
    "value INTEGER);";

pub const sql_create_table_transactions =
    "CREATE TABLE IF NOT EXISTS " ++
    "transactions(" ++
    "Id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "cookie TEXT," ++
    "cmdline TEXT," ++
    "timestamp INTEGER, " ++
    "type INTEGER);";

pub const sql_create_table_trans_items =
    "CREATE TABLE IF NOT EXISTS " ++
    "trans_items(" ++
    "Id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "trans_id INTEGER," ++
    "type INTEGER," ++
    "rpm_id INTEGER);";

pub const DictTable = enum {
    rpms,
    names,
};

pub const MaxIdTable = enum {
    rpms,
    names,
    transactions,
};

pub const OwnedStringMap = struct {
    count: usize,
    entries: []?[*:0]u8,

    pub fn deinit(self: *OwnedStringMap) void {
        for (self.entries) |entry| {
            history_db.freeZ(entry);
        }
        allocator.free(self.entries);
        self.entries = &.{};
        self.count = 0;
    }
};

pub const DeltaItems = struct {
    added_ids: []c_int,
    removed_ids: []c_int,

    pub fn deinit(self: *DeltaItems) void {
        allocator.free(self.added_ids);
        allocator.free(self.removed_ids);
        self.added_ids = &.{};
        self.removed_ids = &.{};
    }
};

pub const TransactionRow = struct {
    id: c_int,
    cookie: ?[*:0]u8,
    cmdline: ?[*:0]u8,
    timestamp: i64,
    trans_type: c_int,

    pub fn deinit(self: *TransactionRow) void {
        history_db.freeZ(self.cookie);
        history_db.freeZ(self.cmdline);
        self.cookie = null;
        self.cmdline = null;
    }
};

pub fn ensureAllTables(db: history_db.Database) !void {
    try db.exec(sql_create_table_rpms, .{});
    try db.exec(sql_create_table_names, .{});
    try db.exec(sql_create_table_flag_set, .{});
    try db.exec(sql_create_table_transactions, .{});
    try db.exec(sql_create_table_trans_items, .{});
}

pub fn tableExists(db: history_db.Database, name: []const u8) !bool {
    const Params = struct { name: sqlite.Text };
    const Result = struct { name: sqlite.Text };
    const stmt = try db.prepare(
        Params,
        Result,
        "SELECT name AS name FROM sqlite_master WHERE type = 'table' AND name = :name;",
    );
    defer stmt.finalize();

    try stmt.bind(.{ .name = sqlite.text(name) });
    defer stmt.reset();

    return (try stmt.step()) != null;
}

pub fn rpmsCount(db: history_db.Database) !c_int {
    const Result = struct { count: i64 };
    const stmt = try db.prepare(struct {}, Result, "SELECT count(*) AS count FROM rpms;");
    defer stmt.finalize();

    try stmt.bind(.{});
    defer stmt.reset();

    if (try stmt.step()) |row| {
        return @intCast(row.count);
    }
    return 0;
}

pub fn maxId(db: history_db.Database, table: MaxIdTable) !c_int {
    const Result = struct { id: c_int };
    const stmt = try db.prepare(struct {}, Result, switch (table) {
        .rpms => "SELECT Id AS id FROM rpms ORDER BY id DESC LIMIT 1;",
        .names => "SELECT Id AS id FROM names ORDER BY id DESC LIMIT 1;",
        .transactions => "SELECT Id AS id FROM transactions ORDER BY id DESC LIMIT 1;",
    });
    defer stmt.finalize();

    try stmt.bind(.{});
    defer stmt.reset();

    if (try stmt.step()) |row| {
        return row.id;
    }
    return 0;
}

pub fn rpmsMaxId(db: history_db.Database) !c_int {
    return try maxId(db, .rpms);
}

pub fn stringMap(db: history_db.Database, table: DictTable) !OwnedStringMap {
    const count_i = try maxId(db, switch (table) {
        .rpms => .rpms,
        .names => .names,
    });
    const count: usize = @intCast(count_i);
    var entries = try allocator.alloc(?[*:0]u8, count);
    errdefer allocator.free(entries);
    for (entries) |*entry| {
        entry.* = null;
    }

    const Result = struct { id: c_int, value: sqlite.Text };
    const stmt = try db.prepare(struct {}, Result, switch (table) {
        .rpms => "SELECT Id AS id, nevra AS value FROM rpms;",
        .names => "SELECT Id AS id, name AS value FROM names;",
    });
    defer stmt.finalize();

    try stmt.bind(.{});
    defer stmt.reset();

    while (try stmt.step()) |row| {
        const idx: usize = @intCast(row.id - 1);
        entries[idx] = try history_db.dupeZ(row.value.data);
    }

    return .{
        .count = count,
        .entries = entries,
    };
}

pub fn nevraMap(db: history_db.Database) !OwnedStringMap {
    return try stringMap(db, .rpms);
}

pub fn getDictEntry(
    db: history_db.Database,
    table: DictTable,
    entry: []const u8,
    create: bool,
) !c_int {
    const Result = struct { id: c_int };
    const Params = struct { value: sqlite.Text };
    const select = try db.prepare(Params, Result, switch (table) {
        .rpms => "SELECT Id AS id FROM rpms WHERE nevra = :value;",
        .names => "SELECT Id AS id FROM names WHERE name = :value;",
    });
    defer select.finalize();

    try select.bind(.{ .value = sqlite.text(entry) });
    defer select.reset();

    if (try select.step()) |row| {
        return row.id;
    }

    if (!create) {
        return 0;
    }

    const insert = try db.prepare(Params, void, switch (table) {
        .rpms => "INSERT INTO rpms(nevra) VALUES (:value);",
        .names => "INSERT INTO names(name) VALUES (:value);",
    });
    defer insert.finalize();

    try insert.exec(.{ .value = sqlite.text(entry) });
    return @intCast(db.lastInsertRowId());
}

pub fn addNevra(db: history_db.Database, nevra: []const u8) !c_int {
    return try getDictEntry(db, .rpms, nevra, true);
}

pub fn getNevraById(db: history_db.Database, id: c_int) !?[*:0]u8 {
    const Result = struct { value: sqlite.Text };
    const stmt = try db.prepare(
        struct { id: c_int },
        Result,
        "SELECT nevra AS value FROM rpms WHERE Id = :id;",
    );
    defer stmt.finalize();

    try stmt.bind(.{ .id = id });
    defer stmt.reset();

    if (try stmt.step()) |row| {
        return try history_db.dupeZ(row.value.data);
    }
    return null;
}

pub fn readDelta(db: history_db.Database, trans_id: c_int) !DeltaItems {
    var added: std.ArrayList(c_int) = .empty;
    defer added.deinit(allocator);
    var removed: std.ArrayList(c_int) = .empty;
    defer removed.deinit(allocator);

    const Result = struct { item_type: c_int, rpm_id: c_int };
    const stmt = try db.prepare(
        struct { trans_id: c_int },
        Result,
        "SELECT type AS item_type, rpm_id AS rpm_id FROM trans_items WHERE trans_id = :trans_id ORDER BY rpm_id;",
    );
    defer stmt.finalize();

    try stmt.bind(.{ .trans_id = trans_id });
    defer stmt.reset();

    while (try stmt.step()) |row| {
        if (row.item_type == history_item_type_add or row.item_type == history_item_type_set) {
            try added.append(allocator, row.rpm_id);
        } else if (row.item_type == history_item_type_remove) {
            try removed.append(allocator, row.rpm_id);
        }
    }

    return .{
        .added_ids = try added.toOwnedSlice(allocator),
        .removed_ids = try removed.toOwnedSlice(allocator),
    };
}

pub fn playDelta(db: history_db.Database, trans_id: c_int, installed_map: []u8) !void {
    const Result = struct { item_type: c_int, rpm_id: c_int };
    const stmt = try db.prepare(
        struct { trans_id: c_int },
        Result,
        "SELECT type AS item_type, rpm_id AS rpm_id FROM trans_items WHERE trans_id = :trans_id ORDER BY rpm_id;",
    );
    defer stmt.finalize();

    try stmt.bind(.{ .trans_id = trans_id });
    defer stmt.reset();

    while (try stmt.step()) |row| {
        if (row.rpm_id <= 0) {
            continue;
        }
        const idx: usize = @intCast(row.rpm_id - 1);
        if (idx >= installed_map.len) {
            continue;
        }
        if (row.item_type == history_item_type_add) {
            installed_map[idx] = 1;
        } else if (row.item_type == history_item_type_remove) {
            installed_map[idx] = 0;
        }
    }
}

pub fn playSet(db: history_db.Database, trans_id: c_int, installed_map: []u8) !void {
    const Result = struct { item_type: c_int, rpm_id: c_int };
    const stmt = try db.prepare(
        struct { trans_id: c_int },
        Result,
        "SELECT type AS item_type, rpm_id AS rpm_id FROM trans_items WHERE trans_id = :trans_id ORDER BY rpm_id;",
    );
    defer stmt.finalize();

    try stmt.bind(.{ .trans_id = trans_id });
    defer stmt.reset();

    while (try stmt.step()) |row| {
        if (row.rpm_id <= 0) {
            continue;
        }
        const idx: usize = @intCast(row.rpm_id - 1);
        if (idx >= installed_map.len) {
            continue;
        }
        if (row.item_type == history_item_type_set) {
            installed_map[idx] = 1;
        }
    }
}

pub fn playTransaction(db: history_db.Database, trans_id: c_int, installed_map: []u8) !void {
    const Result = struct { id: c_int };
    const stmt = try db.prepare(
        struct { trans_type: c_int, trans_id: c_int },
        Result,
        "SELECT Id AS id FROM transactions WHERE type = :trans_type AND Id <= :trans_id ORDER BY Id DESC LIMIT 1;",
    );
    defer stmt.finalize();

    try stmt.bind(.{
        .trans_type = history_trans_type_base,
        .trans_id = trans_id,
    });
    defer stmt.reset();

    const base = (try stmt.step()) orelse return error.MissingBaseline;
    try playSet(db, base.id, installed_map);

    var id = base.id + 1;
    while (id <= trans_id) : (id += 1) {
        try playDelta(db, id, installed_map);
    }
}

pub fn addTransaction(
    db: history_db.Database,
    cmdline: ?[*:0]const u8,
    timestamp: i64,
    cookie: ?[*:0]const u8,
    trans_type: c_int,
) !c_int {
    const Params = struct {
        cmdline: ?sqlite.Text,
        cookie: ?sqlite.Text,
        timestamp: i64,
        trans_type: c_int,
    };
    const insert = try db.prepare(
        Params,
        void,
        "INSERT INTO transactions(cmdline, cookie, timestamp, type) VALUES (:cmdline, :cookie, :timestamp, :trans_type);",
    );
    defer insert.finalize();

    try insert.exec(.{
        .cmdline = history_db.textFromPtr(cmdline),
        .cookie = history_db.textFromPtr(cookie),
        .timestamp = timestamp,
        .trans_type = trans_type,
    });
    return @intCast(db.lastInsertRowId());
}

pub fn addTransItems(
    db: history_db.Database,
    trans_id: c_int,
    item_type: c_int,
    rpm_ids: []const c_int,
) !void {
    const Params = struct {
        trans_id: c_int,
        item_type: c_int,
        rpm_id: c_int,
    };
    const insert = try db.prepare(
        Params,
        void,
        "INSERT INTO trans_items(trans_id, type, rpm_id) VALUES (:trans_id, :item_type, :rpm_id);",
    );
    defer insert.finalize();

    for (rpm_ids) |rpm_id| {
        try insert.exec(.{
            .trans_id = trans_id,
            .item_type = item_type,
            .rpm_id = rpm_id,
        });
    }
}

pub fn setAutoFlagById(
    db: history_db.Database,
    trans_id: c_int,
    name_id: c_int,
    value: c_int,
) !void {
    const Params = struct {
        trans_id: c_int,
        name_id: c_int,
        value: c_int,
    };
    const insert = try db.prepare(
        Params,
        void,
        "INSERT INTO flag_set(trans_id, name_id, value) VALUES (:trans_id, :name_id, :value);",
    );
    defer insert.finalize();

    try insert.exec(.{
        .trans_id = trans_id,
        .name_id = name_id,
        .value = value,
    });
}

pub fn setAutoFlag(
    db: history_db.Database,
    trans_id: c_int,
    name: []const u8,
    value: c_int,
) !void {
    try db.exec(sql_create_table_names, .{});
    const name_id = try getDictEntry(db, .names, name, true);
    try db.exec(sql_create_table_flag_set, .{});
    try setAutoFlagById(db, trans_id, name_id, value);
}

pub fn getAutoFlagById(
    db: history_db.Database,
    trans_id: c_int,
    name_id: c_int,
) !c_int {
    const Result = struct { value: c_int };
    const stmt = try db.prepare(
        struct { name_id: c_int, trans_id: c_int },
        Result,
        "SELECT value AS value FROM flag_set WHERE name_id = :name_id AND trans_id <= :trans_id ORDER BY Id DESC LIMIT 1;",
    );
    defer stmt.finalize();

    try stmt.bind(.{
        .name_id = name_id,
        .trans_id = trans_id,
    });
    defer stmt.reset();

    if (try stmt.step()) |row| {
        return row.value;
    }
    return 0;
}

pub fn getAutoFlag(
    db: history_db.Database,
    trans_id: c_int,
    name: []const u8,
) !c_int {
    if (!try tableExists(db, "flag_set")) {
        return 0;
    }
    if (!try tableExists(db, "names")) {
        return 0;
    }

    const name_id = try getDictEntry(db, .names, name, false);
    if (name_id == 0) {
        return 0;
    }

    return try getAutoFlagById(db, trans_id, name_id);
}

pub fn latestTransaction(db: history_db.Database) !?TransactionRow {
    const Result = struct {
        id: c_int,
        cookie: ?sqlite.Text,
        cmdline: ?sqlite.Text,
        timestamp: i64,
        trans_type: c_int,
    };
    const stmt = try db.prepare(
        struct {},
        Result,
        "SELECT Id AS id, cookie AS cookie, cmdline AS cmdline, timestamp AS timestamp, type AS trans_type FROM transactions ORDER BY Id DESC LIMIT 1;",
    );
    defer stmt.finalize();

    try stmt.bind(.{});
    defer stmt.reset();

    if (try stmt.step()) |row| {
        return .{
            .id = row.id,
            .cookie = try history_db.dupeOptionalText(row.cookie),
            .cmdline = try history_db.dupeOptionalText(row.cmdline),
            .timestamp = row.timestamp,
            .trans_type = row.trans_type,
        };
    }
    return null;
}

pub fn listTransactions(
    db: history_db.Database,
    reverse: bool,
    from: c_int,
    to: c_int,
) ![]TransactionRow {
    var rows: std.ArrayList(TransactionRow) = .empty;
    errdefer {
        for (rows.items) |*row| {
            row.deinit();
        }
        rows.deinit(allocator);
    }

    if (from == 0 or to == 0) {
        const Result = struct {
            id: c_int,
            cookie: ?sqlite.Text,
            cmdline: ?sqlite.Text,
            timestamp: i64,
            trans_type: c_int,
        };
        const stmt = try db.prepare(struct {}, Result, if (reverse)
            "SELECT Id AS id, cookie AS cookie, cmdline AS cmdline, timestamp AS timestamp, type AS trans_type FROM transactions ORDER BY Id DESC;"
        else
            "SELECT Id AS id, cookie AS cookie, cmdline AS cmdline, timestamp AS timestamp, type AS trans_type FROM transactions ORDER BY Id;");
        defer stmt.finalize();

        try stmt.bind(.{});
        defer stmt.reset();

        while (try stmt.step()) |row| {
            try rows.append(allocator, .{
                .id = row.id,
                .cookie = try history_db.dupeOptionalText(row.cookie),
                .cmdline = try history_db.dupeOptionalText(row.cmdline),
                .timestamp = row.timestamp,
                .trans_type = row.trans_type,
            });
        }
    } else {
        const Params = struct { from: c_int, to: c_int };
        const Result = struct {
            id: c_int,
            cookie: ?sqlite.Text,
            cmdline: ?sqlite.Text,
            timestamp: i64,
            trans_type: c_int,
        };
        const stmt = try db.prepare(Params, Result, if (reverse)
            "SELECT Id AS id, cookie AS cookie, cmdline AS cmdline, timestamp AS timestamp, type AS trans_type FROM transactions WHERE Id BETWEEN :from AND :to ORDER BY Id DESC;"
        else
            "SELECT Id AS id, cookie AS cookie, cmdline AS cmdline, timestamp AS timestamp, type AS trans_type FROM transactions WHERE Id BETWEEN :from AND :to ORDER BY Id;");
        defer stmt.finalize();

        try stmt.bind(.{
            .from = from,
            .to = to,
        });
        defer stmt.reset();

        while (try stmt.step()) |row| {
            try rows.append(allocator, .{
                .id = row.id,
                .cookie = try history_db.dupeOptionalText(row.cookie),
                .cmdline = try history_db.dupeOptionalText(row.cmdline),
                .timestamp = row.timestamp,
                .trans_type = row.trans_type,
            });
        }
    }

    return try rows.toOwnedSlice(allocator);
}

pub fn freeTransactionRows(rows: []TransactionRow) void {
    for (rows) |*row| {
        row.deinit();
    }
    allocator.free(rows);
}
