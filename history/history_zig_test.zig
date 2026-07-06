const std = @import("std");
const sqlite = @import("sqlite");

const history_db = @import("db.zig");
const store = @import("store.zig");
const api = @import("api.zig");

const allocator = std.heap.c_allocator;

const MockRpmdb = struct {
    var cookie_value: ?[:0]u8 = null;
    var packages: std.ArrayList([:0]u8) = .empty;

    pub fn reset() void {
        if (cookie_value) |cookie_bytes| {
            allocator.free(cookie_bytes);
            cookie_value = null;
        }
        for (packages.items) |pkg| {
            allocator.free(pkg);
        }
        packages.deinit(allocator);
        packages = .empty;
    }

    pub fn setState(cookie_bytes: []const u8, nevras: []const []const u8) !void {
        reset();
        cookie_value = try allocator.dupeZ(u8, cookie_bytes);
        for (nevras) |nevra| {
            try packages.append(allocator, try allocator.dupeZ(u8, nevra));
        }
    }

    pub fn cookie(root: ?[*:0]const u8) ![:0]u8 {
        _ = root;
        return try allocator.dupeZ(u8, cookie_value orelse return error.NoCookie);
    }

    pub fn collectNevras(alloc: std.mem.Allocator, root: ?[*:0]const u8) ![][:0]u8 {
        _ = root;

        var nevras: std.ArrayList([:0]u8) = .empty;
        errdefer {
            for (nevras.items) |nevra| {
                alloc.free(nevra);
            }
            nevras.deinit(alloc);
        }

        for (packages.items) |pkg| {
            try nevras.append(alloc, try alloc.dupeZ(u8, pkg));
        }
        return try nevras.toOwnedSlice(alloc);
    }
};

const HistoryApi = api.Api(MockRpmdb);

fn dbPath(tmp: *std.testing.TmpDir, path_buf: *[std.Io.Dir.max_path_bytes]u8) [:0]u8 {
    return std.fmt.bufPrintZ(path_buf, ".zig-cache/tmp/{s}/history.db", .{&tmp.sub_path}) catch @panic("path too long");
}

fn openDbFromCtx(ctx: *api.HistoryCtx) history_db.Database {
    return history_db.Database.fromPtr(ctx.db);
}

fn expectString(ptr: ?[*:0]const u8, expected: []const u8) !void {
    try std.testing.expect(ptr != null);
    try std.testing.expectEqualSlices(u8, expected, std.mem.span(ptr.?));
}

test "db wrapper opens sqlite, preserves busy timeout, and handles transactions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = dbPath(&tmp, &path_buf);

    const db = try history_db.Database.init(path);
    defer db.close();

    {
        const Result = struct {
            timeout: c_int = 0,
            busy_timeout: c_int = 0,
        };
        const stmt = try db.prepare(struct {}, Result, "PRAGMA busy_timeout;");
        defer stmt.finalize();

        try stmt.bind(.{});
        defer stmt.reset();

        const row = (try stmt.step()) orelse return error.MissingPragmaRow;
        try std.testing.expect(row.timeout == history_db.busy_timeout_ms or row.busy_timeout == history_db.busy_timeout_ms);
    }

    try db.exec("CREATE TABLE items(id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT);", .{});

    try db.begin();
    try db.exec("INSERT INTO items(value) VALUES (:value);", .{ .value = sqlite.text("rolled-back") });
    try db.rollback();

    {
        const stmt = try db.prepare(struct {}, struct { count: c_int }, "SELECT count(*) AS count FROM items;");
        defer stmt.finalize();
        try stmt.bind(.{});
        defer stmt.reset();
        const row = (try stmt.step()) orelse return error.MissingCount;
        try std.testing.expectEqual(@as(c_int, 0), row.count);
    }

    try db.begin();
    try db.exec("INSERT INTO items(value) VALUES (:value);", .{ .value = sqlite.text("committed") });
    try db.commit();

    try std.testing.expectEqual(@as(i64, 1), db.lastInsertRowId());
}

test "store dictionary helpers deduplicate rpms and names" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = dbPath(&tmp, &path_buf);

    const db = try history_db.Database.init(path);
    defer db.close();

    try db.exec(store.sql_create_table_rpms, .{});
    try db.exec(store.sql_create_table_names, .{});

    const rpm_id1 = try store.addNevra(db, "pkgA-1:1.0-1.x86_64");
    const rpm_id2 = try store.addNevra(db, "pkgA-1:1.0-1.x86_64");
    const name_id1 = try store.getDictEntry(db, .names, "pkgA", true);
    const name_id2 = try store.getDictEntry(db, .names, "pkgA", true);

    try std.testing.expectEqual(rpm_id1, rpm_id2);
    try std.testing.expectEqual(name_id1, name_id2);
    try std.testing.expectEqual(@as(c_int, 1), try store.rpmsCount(db));

    var map = try store.nevraMap(db);
    defer map.deinit();

    try std.testing.expectEqual(@as(usize, 1), map.count);
    try expectString(map.entries[0], "pkgA-1:1.0-1.x86_64");
}

test "api sync creates schema and records baseline transaction" {
    defer MockRpmdb.reset();
    try MockRpmdb.setState("cookie-1", &.{
        "pkgA-1:1.0-1.x86_64",
        "pkgB-0:2.0-3.noarch",
    });

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = dbPath(&tmp, &path_buf);

    const ctx = try HistoryApi.createHistoryCtx(path);
    defer HistoryApi.destroyHistoryCtx(ctx);

    try HistoryApi.historySync(ctx, null);
    try std.testing.expectEqual(@as(c_int, 1), HistoryApi.historyGetCurrentTransactionId(ctx));

    try HistoryApi.historySetAutoFlag(ctx, "pkgA", 1);

    const db = openDbFromCtx(ctx);
    try std.testing.expect(try store.tableExists(db, "rpms"));
    try std.testing.expect(try store.tableExists(db, "names"));
    try std.testing.expect(try store.tableExists(db, "flag_set"));
    try std.testing.expect(try store.tableExists(db, "transactions"));
    try std.testing.expect(try store.tableExists(db, "trans_items"));
}

test "api records transaction deltas and reads them back" {
    defer MockRpmdb.reset();
    try MockRpmdb.setState("cookie-1", &.{
        "pkgA-1:1.0-1.x86_64",
        "pkgB-0:2.0-3.noarch",
    });

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = dbPath(&tmp, &path_buf);

    const ctx = try HistoryApi.createHistoryCtx(path);
    defer HistoryApi.destroyHistoryCtx(ctx);

    try HistoryApi.historySync(ctx, null);

    try MockRpmdb.setState("cookie-2", &.{
        "pkgB-0:2.0-3.noarch",
        "pkgC-0:3.1-4.x86_64",
    });

    try HistoryApi.historyUpdateState(ctx, null, "update-state");
    try std.testing.expectEqual(@as(c_int, 2), HistoryApi.historyGetCurrentTransactionId(ctx));

    var txs: ?[*]api.HistoryTransaction = null;
    var count: c_int = 0;
    try HistoryApi.historyGetTransactions(ctx, &txs, &count, 0, 0, 0);
    defer HistoryApi.historyFreeTransactions(txs, count);

    try std.testing.expectEqual(@as(c_int, 2), count);
    try std.testing.expectEqual(@as(c_int, 2), txs.?[1].id);
    try std.testing.expectEqual(@as(c_int, 1), txs.?[1].delta.added_count);
    try std.testing.expectEqual(@as(c_int, 1), txs.?[1].delta.removed_count);

    const added_nevra = try HistoryApi.historyNevraFromId(ctx, txs.?[1].delta.added_ids.?[0]);
    defer history_db.freeZ(added_nevra);
    try expectString(added_nevra, "pkgC-0:3.1-4.x86_64");

    const removed_nevra = try HistoryApi.historyNevraFromId(ctx, txs.?[1].delta.removed_ids.?[0]);
    defer history_db.freeZ(removed_nevra);
    try expectString(removed_nevra, "pkgA-1:1.0-1.x86_64");

    const rollback = try HistoryApi.historyGetDelta(ctx, 1);
    defer HistoryApi.historyFreeDelta(rollback);

    try std.testing.expectEqual(@as(c_int, 1), rollback.removed_count);
    try std.testing.expectEqual(@as(c_int, 1), rollback.added_count);

    const rollback_remove = try HistoryApi.historyNevraFromId(ctx, rollback.removed_ids.?[0]);
    defer history_db.freeZ(rollback_remove);
    try expectString(rollback_remove, "pkgC-0:3.1-4.x86_64");

    const rollback_add = try HistoryApi.historyNevraFromId(ctx, rollback.added_ids.?[0]);
    defer history_db.freeZ(rollback_add);
    try expectString(rollback_add, "pkgA-1:1.0-1.x86_64");
}

test "api flag_set restore replay and delta round-trip" {
    defer MockRpmdb.reset();
    try MockRpmdb.setState("cookie-1", &.{
        "pkgA-1:1.0-1.x86_64",
    });

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = dbPath(&tmp, &path_buf);

    const ctx = try HistoryApi.createHistoryCtx(path);
    defer HistoryApi.destroyHistoryCtx(ctx);

    try HistoryApi.historySync(ctx, null);

    try HistoryApi.historySetAutoFlag(ctx, "pkgA", 1);

    try HistoryApi.historyAddTransaction(ctx, "flags-2");
    try HistoryApi.historySetAutoFlag(ctx, "pkgA", 0);

    try HistoryApi.historyAddTransaction(ctx, "flags-3");
    try HistoryApi.historySetAutoFlag(ctx, "pkgA", 1);

    try HistoryApi.historyAddTransaction(ctx, "flags-4");
    try std.testing.expectEqual(@as(c_int, 4), HistoryApi.historyGetCurrentTransactionId(ctx));

    var value: c_int = -1;
    try HistoryApi.historyGetAutoFlag(ctx, "pkgA", &value);
    try std.testing.expectEqual(@as(c_int, 1), value);

    try HistoryApi.historyRestoreAutoFlags(ctx, 2);
    try HistoryApi.historyGetAutoFlag(ctx, "pkgA", &value);
    try std.testing.expectEqual(@as(c_int, 0), value);

    const delta = (try HistoryApi.historyGetFlagsDelta(ctx, 2, 3)).?;
    defer HistoryApi.historyFreeFlagsDelta(delta);

    try std.testing.expectEqual(@as(c_int, 1), delta.count);
    try std.testing.expectEqual(@as(c_int, 1), delta.changed_ids.?[0]);
    try std.testing.expectEqual(@as(c_int, 1), delta.values.?[0]);

    try HistoryApi.historyReplayAutoFlags(ctx, 2, 3);
    try HistoryApi.historyGetAutoFlag(ctx, "pkgA", &value);
    try std.testing.expectEqual(@as(c_int, 1), value);
}
