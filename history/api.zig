const std = @import("std");
const sqlite = @import("sqlite");

const history_db = @import("db.zig");
const store = @import("store.zig");

const allocator = std.heap.c_allocator;

extern fn time(tloc: ?*std.posix.time_t) std.posix.time_t;

pub const HistoryCtx = extern struct {
    db: ?*sqlite.c.sqlite3,
    installed_ids: ?[*]c_int,
    installed_count: c_int,
    cookie: ?[*:0]u8,
    trans_id: c_int,
};

pub const HistoryDelta = extern struct {
    added_ids: ?[*]c_int,
    added_count: c_int,
    removed_ids: ?[*]c_int,
    removed_count: c_int,
};

pub const HistoryFlagsDelta = extern struct {
    changed_ids: ?[*]c_int,
    values: ?[*]c_int,
    count: c_int,
};

pub const HistoryTransaction = extern struct {
    id: c_int,
    type: c_int,
    cmdline: ?[*:0]u8,
    timestamp: std.posix.time_t,
    cookie: ?[*:0]u8,
    delta: HistoryDelta,
    flags_delta: HistoryFlagsDelta,
};

pub const HistoryNevraMap = extern struct {
    count: c_int,
    idmap: ?[*]?[*:0]u8,
};

const DiffArraysResult = struct {
    only1: []c_int,
    only2: []c_int,

    fn deinit(self: *DiffArraysResult) void {
        allocator.free(self.only1);
        allocator.free(self.only2);
        self.only1 = &.{};
        self.only2 = &.{};
    }
};

fn ctxDb(ctx: *HistoryCtx) history_db.Database {
    return history_db.Database.fromPtr(ctx.db);
}

fn currentTime() i64 {
    return @intCast(time(null));
}

fn installedIdsSlice(ctx: *const HistoryCtx) []const c_int {
    if (ctx.installed_ids) |ids| {
        return ids[0..@intCast(ctx.installed_count)];
    }
    return &.{};
}

fn freeIntArray(ptr: ?[*]c_int, count: usize) void {
    if (ptr) |value| {
        allocator.free(value[0..count]);
    }
}

fn freeStringPointerArray(ptr: ?[*]?[*:0]u8, count: usize) void {
    if (ptr) |value| {
        allocator.free(value[0..count]);
    }
}

fn allocIntArray(values: []const c_int) !?[*]c_int {
    if (values.len == 0) {
        return null;
    }

    const out = try allocator.alloc(c_int, values.len);
    std.mem.copyForwards(c_int, out, values);
    return out.ptr;
}

fn getIdsFromMap(installed_map: []const u8) ![]c_int {
    var ids: std.ArrayList(c_int) = .empty;
    defer ids.deinit(allocator);

    for (installed_map, 0..) |value, idx| {
        if (value != 0) {
            try ids.append(allocator, @intCast(idx + 1));
        }
    }

    return try ids.toOwnedSlice(allocator);
}

fn sortIds(ids: []c_int) void {
    std.sort.pdq(c_int, ids, {}, struct {
        fn lessThan(_: void, lhs: c_int, rhs: c_int) bool {
            return lhs < rhs;
        }
    }.lessThan);
}

fn diffArrays(arr1: []const c_int, arr2: []const c_int) !DiffArraysResult {
    var only1: std.ArrayList(c_int) = .empty;
    defer only1.deinit(allocator);
    var only2: std.ArrayList(c_int) = .empty;
    defer only2.deinit(allocator);

    var idx1: usize = 0;
    var idx2: usize = 0;

    while (idx1 < arr1.len and idx2 < arr2.len) {
        if (arr1[idx1] != arr2[idx2]) {
            if (arr1[idx1] > arr2[idx2]) {
                try only2.append(allocator, arr2[idx2]);
                idx2 += 1;
            } else {
                try only1.append(allocator, arr1[idx1]);
                idx1 += 1;
            }
        } else {
            idx1 += 1;
            idx2 += 1;
        }
    }

    while (idx1 < arr1.len) : (idx1 += 1) {
        try only1.append(allocator, arr1[idx1]);
    }
    while (idx2 < arr2.len) : (idx2 += 1) {
        try only2.append(allocator, arr2[idx2]);
    }

    return .{
        .only1 = try only1.toOwnedSlice(allocator),
        .only2 = try only2.toOwnedSlice(allocator),
    };
}

fn replaceInstalledIds(ctx: *HistoryCtx, ids: []const c_int) !void {
    freeIntArray(ctx.installed_ids, @intCast(ctx.installed_count));
    ctx.installed_ids = try allocIntArray(ids);
    ctx.installed_count = @intCast(ids.len);
}

fn takeInstalledIds(ctx: *HistoryCtx, ids: []c_int) void {
    freeIntArray(ctx.installed_ids, @intCast(ctx.installed_count));
    if (ids.len == 0) {
        allocator.free(ids);
        ctx.installed_ids = null;
        ctx.installed_count = 0;
        return;
    }

    ctx.installed_ids = ids.ptr;
    ctx.installed_count = @intCast(ids.len);
}

fn setCookie(ctx: *HistoryCtx, cookie: []const u8) !void {
    history_db.freeZ(ctx.cookie);
    ctx.cookie = try history_db.dupeZ(cookie);
}

fn takeCookie(ctx: *HistoryCtx, cookie: [:0]u8) void {
    history_db.freeZ(ctx.cookie);
    ctx.cookie = cookie.ptr;
}

fn stateIdsAt(db: history_db.Database, trans_id: c_int) ![]c_int {
    const map_size: usize = @intCast(try store.rpmsMaxId(db));
    const installed_map = try allocator.alloc(u8, map_size);
    defer allocator.free(installed_map);
    @memset(installed_map, 0);

    try store.playTransaction(db, trans_id, installed_map);
    return try getIdsFromMap(installed_map);
}

pub fn Api(comptime Rpmdb: type) type {
    return struct {
        pub fn createHistoryCtx(db_filename: [*:0]const u8) !*HistoryCtx {
            var db = try history_db.Database.init(db_filename);
            errdefer db.close();

            const ctx = try allocator.create(HistoryCtx);
            errdefer allocator.destroy(ctx);

            ctx.* = .{
                .db = db.raw.ptr,
                .installed_ids = null,
                .installed_count = 0,
                .cookie = null,
                .trans_id = 0,
            };

            if (try store.tableExists(db, "transactions")) {
                if (try store.latestTransaction(db)) |latest_value| {
                    var latest = latest_value;
                    defer latest.deinit();

                    if (latest.cookie) |cookie| {
                        try setCookie(ctx, std.mem.span(cookie));
                    }
                    ctx.trans_id = latest.id;
                }
            }

            return ctx;
        }

        pub fn destroyHistoryCtx(ctx: ?*HistoryCtx) void {
            if (ctx) |value| {
                if (value.db != null) {
                    ctxDb(value).close();
                }
                freeIntArray(value.installed_ids, @intCast(value.installed_count));
                history_db.freeZ(value.cookie);
                allocator.destroy(value);
            }
        }

        pub fn historyGetCurrentTransactionId(ctx: *HistoryCtx) c_int {
            return ctx.trans_id;
        }

        pub fn historyNevraFromId(ctx: *HistoryCtx, id: c_int) !?[*:0]u8 {
            return try store.getNevraById(ctxDb(ctx), id);
        }

        pub fn historyNevraMap(ctx: *HistoryCtx) !*HistoryNevraMap {
            var owned = try store.nevraMap(ctxDb(ctx));
            errdefer owned.deinit();

            const result = try allocator.create(HistoryNevraMap);
            result.* = .{
                .count = @intCast(owned.count),
                .idmap = if (owned.entries.len == 0) null else owned.entries.ptr,
            };

            owned.entries = &.{};
            owned.count = 0;
            return result;
        }

        pub fn historyFreeNevraMap(map: ?*HistoryNevraMap) void {
            if (map) |value| {
                if (value.idmap) |entries| {
                    const count: usize = @intCast(value.count);
                    for (entries[0..count]) |entry| {
                        history_db.freeZ(entry);
                    }
                    freeStringPointerArray(entries, count);
                }
                allocator.destroy(value);
            }
        }

        pub fn historyGetNevra(map: ?*HistoryNevraMap, id: c_int) ?[*:0]u8 {
            if (map) |value| {
                if (id > 0 and id <= value.count and value.idmap != null) {
                    return value.idmap.?[@intCast(id - 1)];
                }
            }
            return null;
        }

        pub fn historyFreeDelta(delta: ?*HistoryDelta) void {
            if (delta) |value| {
                freeIntArray(value.added_ids, @intCast(value.added_count));
                freeIntArray(value.removed_ids, @intCast(value.removed_count));
                allocator.destroy(value);
            }
        }

        pub fn historyGetDelta(ctx: *HistoryCtx, trans_id: c_int) !*HistoryDelta {
            const old_ids = try stateIdsAt(ctxDb(ctx), trans_id);
            defer allocator.free(old_ids);

            var diff = try diffArrays(installedIdsSlice(ctx), old_ids);
            defer diff.deinit();

            const delta = try allocator.create(HistoryDelta);
            errdefer allocator.destroy(delta);

            delta.* = .{
                .added_ids = try allocIntArray(diff.only2),
                .added_count = @intCast(diff.only2.len),
                .removed_ids = try allocIntArray(diff.only1),
                .removed_count = @intCast(diff.only1.len),
            };

            return delta;
        }

        pub fn historyGetDeltaRange(
            ctx: *HistoryCtx,
            trans_id0: c_int,
            trans_id1: c_int,
        ) !*HistoryDelta {
            const ids0 = try stateIdsAt(ctxDb(ctx), trans_id0);
            defer allocator.free(ids0);

            const ids1 = try stateIdsAt(ctxDb(ctx), trans_id1);
            defer allocator.free(ids1);

            var diff = try diffArrays(ids1, ids0);
            defer diff.deinit();

            const delta = try allocator.create(HistoryDelta);
            errdefer allocator.destroy(delta);

            delta.* = .{
                .added_ids = try allocIntArray(diff.only2),
                .added_count = @intCast(diff.only2.len),
                .removed_ids = try allocIntArray(diff.only1),
                .removed_count = @intCast(diff.only1.len),
            };

            return delta;
        }

        fn historySetState(ctx: *HistoryCtx, trans_id: c_int) !void {
            const ids = try stateIdsAt(ctxDb(ctx), trans_id);
            takeInstalledIds(ctx, ids);
            ctx.trans_id = trans_id;
        }

        fn dbUpdateRpms(db: history_db.Database, root: Rpmdb.Source) ![]c_int {
            try db.exec(store.sql_create_table_rpms, .{});

            const nevras = try Rpmdb.collectNevras(allocator, root);
            defer {
                for (nevras) |nevra| {
                    allocator.free(nevra);
                }
                allocator.free(nevras);
            }

            var ids = try allocator.alloc(c_int, nevras.len);
            errdefer allocator.free(ids);

            for (nevras, 0..) |nevra, idx| {
                ids[idx] = try store.addNevra(db, std.mem.span(nevra.ptr));
            }

            sortIds(ids);
            return ids;
        }

        pub fn historyRecordState(ctx: *HistoryCtx) !void {
            const db = ctxDb(ctx);

            try db.begin();
            var committed = false;
            defer if (!committed) db.rollback() catch {};

            try db.exec(store.sql_create_table_transactions, .{});
            const trans_id = try store.addTransaction(
                db,
                "(set)",
                currentTime(),
                ctx.cookie,
                store.history_trans_type_base,
            );

            try db.exec(store.sql_create_table_trans_items, .{});
            try store.addTransItems(
                db,
                trans_id,
                store.history_item_type_set,
                installedIdsSlice(ctx),
            );

            ctx.trans_id = trans_id;
            try db.commit();
            committed = true;
        }

        pub fn historyAddTransaction(ctx: *HistoryCtx, cmdline: [*:0]const u8) !void {
            const trans_id = try store.addTransaction(
                ctxDb(ctx),
                cmdline,
                currentTime(),
                ctx.cookie,
                store.history_trans_type_delta,
            );
            ctx.trans_id = trans_id;
        }

        pub fn historyUpdateState(
            ctx: *HistoryCtx,
            root: Rpmdb.Source,
            cmdline: [*:0]const u8,
        ) !void {
            var cookie_opt: ?[:0]u8 = try Rpmdb.cookie(root);
            defer if (cookie_opt) |cookie| allocator.free(cookie);

            if (ctx.cookie != null and cookie_opt != null) {
                if (std.mem.eql(u8, std.mem.span(ctx.cookie.?), cookie_opt.?)) {
                    return;
                }
            }

            const current_ids = try dbUpdateRpms(ctxDb(ctx), root);
            var diff = try diffArrays(installedIdsSlice(ctx), current_ids);
            defer diff.deinit();

            const db = ctxDb(ctx);
            try db.begin();
            var committed = false;
            defer if (!committed) db.rollback() catch {};

            const trans_id = try store.addTransaction(
                db,
                cmdline,
                currentTime(),
                if (cookie_opt) |cookie| cookie.ptr else null,
                store.history_trans_type_delta,
            );

            if (diff.only2.len > 0) {
                try store.addTransItems(db, trans_id, store.history_item_type_add, diff.only2);
            }
            if (diff.only1.len > 0) {
                try store.addTransItems(db, trans_id, store.history_item_type_remove, diff.only1);
            }

            takeInstalledIds(ctx, current_ids);
            if (cookie_opt) |cookie| {
                takeCookie(ctx, cookie);
                cookie_opt = null;
            } else {
                history_db.freeZ(ctx.cookie);
                ctx.cookie = null;
            }
            ctx.trans_id = trans_id;

            try db.commit();
            committed = true;
        }

        pub fn historySync(ctx: *HistoryCtx, root: Rpmdb.Source) !void {
            const current_cookie = try Rpmdb.cookie(root);
            defer allocator.free(current_cookie);

            const db = ctxDb(ctx);
            var db_is_fresh = true;

            if (try store.tableExists(db, "transactions")) {
                if (try store.latestTransaction(db)) |latest_value| {
                    var latest = latest_value;
                    defer latest.deinit();

                    const latest_cookie = latest.cookie orelse return error.MissingCookie;

                    if (!std.mem.eql(u8, current_cookie, std.mem.span(latest_cookie))) {
                        try historySetState(ctx, latest.id);
                        try setCookie(ctx, std.mem.span(latest_cookie));
                        try historyUpdateState(ctx, root, "(unknown)");
                    } else {
                        const ids = try dbUpdateRpms(db, root);
                        takeInstalledIds(ctx, ids);
                        try setCookie(ctx, std.mem.span(latest_cookie));
                        ctx.trans_id = latest.id;
                    }
                    db_is_fresh = false;
                }
            }

            if (db_is_fresh) {
                try setCookie(ctx, current_cookie);
                const ids = try dbUpdateRpms(db, root);
                takeInstalledIds(ctx, ids);
                try historyRecordState(ctx);
            }
        }

        pub fn historyGetTransactions(
            ctx: *HistoryCtx,
            ptas: *?[*]HistoryTransaction,
            pcount: *c_int,
            reverse: c_int,
            from: c_int,
            to: c_int,
        ) !void {
            if (!try store.tableExists(ctxDb(ctx), "transactions")) {
                ptas.* = null;
                pcount.* = 0;
                return;
            }

            const rows = try store.listTransactions(ctxDb(ctx), reverse != 0, from, to);
            defer store.freeTransactionRows(rows);

            if (rows.len == 0) {
                ptas.* = null;
                pcount.* = 0;
                return;
            }

            const txs = try allocator.alloc(HistoryTransaction, rows.len);
            errdefer {
                for (txs[0..rows.len]) |*tx| {
                    history_db.freeZ(tx.cookie);
                    history_db.freeZ(tx.cmdline);
                    freeIntArray(tx.delta.added_ids, @intCast(tx.delta.added_count));
                    freeIntArray(tx.delta.removed_ids, @intCast(tx.delta.removed_count));
                    freeIntArray(tx.flags_delta.changed_ids, @intCast(tx.flags_delta.count));
                    freeIntArray(tx.flags_delta.values, @intCast(tx.flags_delta.count));
                }
                allocator.free(txs);
            }

            for (rows, 0..) |*row, idx| {
                var delta_items = try store.readDelta(ctxDb(ctx), row.id);
                defer delta_items.deinit();

                txs[idx] = .{
                    .id = row.id,
                    .type = row.trans_type,
                    .cmdline = row.cmdline,
                    .timestamp = @intCast(row.timestamp),
                    .cookie = row.cookie,
                    .delta = .{
                        .added_ids = try allocIntArray(delta_items.added_ids),
                        .added_count = @intCast(delta_items.added_ids.len),
                        .removed_ids = try allocIntArray(delta_items.removed_ids),
                        .removed_count = @intCast(delta_items.removed_ids.len),
                    },
                    .flags_delta = .{
                        .changed_ids = null,
                        .values = null,
                        .count = 0,
                    },
                };

                row.cmdline = null;
                row.cookie = null;
            }

            ptas.* = txs.ptr;
            pcount.* = @intCast(txs.len);
        }

        pub fn historyFreeTransactions(tas: ?[*]HistoryTransaction, count: c_int) void {
            if (tas) |value| {
                const slice = value[0..@intCast(count)];
                for (slice) |*tx| {
                    history_db.freeZ(tx.cookie);
                    history_db.freeZ(tx.cmdline);
                    freeIntArray(tx.delta.added_ids, @intCast(tx.delta.added_count));
                    freeIntArray(tx.delta.removed_ids, @intCast(tx.delta.removed_count));
                    freeIntArray(tx.flags_delta.changed_ids, @intCast(tx.flags_delta.count));
                    freeIntArray(tx.flags_delta.values, @intCast(tx.flags_delta.count));
                }
                allocator.free(slice);
            }
        }

        pub fn historySetAutoFlag(ctx: *HistoryCtx, name: [*:0]const u8, value: c_int) !void {
            const old_value = try store.getAutoFlag(ctxDb(ctx), ctx.trans_id, std.mem.span(name));
            if (old_value != value) {
                try store.setAutoFlag(ctxDb(ctx), ctx.trans_id, std.mem.span(name), value);
            }
        }

        pub fn historyGetAutoFlag(ctx: *HistoryCtx, name: [*:0]const u8, pvalue: *c_int) !void {
            pvalue.* = try store.getAutoFlag(ctxDb(ctx), ctx.trans_id, std.mem.span(name));
        }

        pub fn historyRestoreAutoFlags(ctx: *HistoryCtx, trans_id: c_int) !void {
            if (!try store.tableExists(ctxDb(ctx), "names")) {
                return;
            }

            const count = try store.maxId(ctxDb(ctx), .names);
            var idx: c_int = 1;
            while (idx <= count) : (idx += 1) {
                const value = try store.getAutoFlagById(ctxDb(ctx), trans_id, idx);
                const old_value = try store.getAutoFlagById(ctxDb(ctx), ctx.trans_id, idx);
                if (value != old_value) {
                    try store.setAutoFlagById(ctxDb(ctx), ctx.trans_id, idx, value);
                }
            }
        }

        pub fn historyReplayAutoFlags(ctx: *HistoryCtx, from: c_int, to: c_int) !void {
            if (!try store.tableExists(ctxDb(ctx), "names")) {
                return;
            }

            const count = try store.maxId(ctxDb(ctx), .names);
            var idx: c_int = 1;
            while (idx <= count) : (idx += 1) {
                const value_from = try store.getAutoFlagById(ctxDb(ctx), from, idx);
                const value_to = try store.getAutoFlagById(ctxDb(ctx), to, idx);
                if (value_from != value_to) {
                    const old_value = try store.getAutoFlagById(ctxDb(ctx), ctx.trans_id, idx);
                    if (value_to != old_value) {
                        try store.setAutoFlagById(ctxDb(ctx), ctx.trans_id, idx, value_to);
                    }
                }
            }
        }

        pub fn historyFreeFlagsDelta(hfd: ?*HistoryFlagsDelta) void {
            if (hfd) |value| {
                freeIntArray(value.changed_ids, @intCast(value.count));
                freeIntArray(value.values, @intCast(value.count));
                allocator.destroy(value);
            }
        }

        pub fn historyGetFlagsDelta(
            ctx: *HistoryCtx,
            from: c_int,
            to: c_int,
        ) !?*HistoryFlagsDelta {
            if (!try store.tableExists(ctxDb(ctx), "names")) {
                return null;
            }

            const count = try store.maxId(ctxDb(ctx), .names);
            var changed_ids: std.ArrayList(c_int) = .empty;
            defer changed_ids.deinit(allocator);
            var values: std.ArrayList(c_int) = .empty;
            defer values.deinit(allocator);

            var idx: c_int = 1;
            while (idx <= count) : (idx += 1) {
                const value_from = try store.getAutoFlagById(ctxDb(ctx), from, idx);
                const value_to = try store.getAutoFlagById(ctxDb(ctx), to, idx);
                if (value_from != value_to) {
                    const old_value = try store.getAutoFlagById(ctxDb(ctx), ctx.trans_id, idx);
                    if (value_to != old_value) {
                        try changed_ids.append(allocator, idx);
                        try values.append(allocator, value_to);
                    }
                }
            }

            const result = try allocator.create(HistoryFlagsDelta);
            errdefer allocator.destroy(result);

            result.* = .{
                .changed_ids = try allocIntArray(changed_ids.items),
                .values = try allocIntArray(values.items),
                .count = @intCast(changed_ids.items.len),
            };

            return result;
        }

        pub fn testSeedState(ctx: *HistoryCtx, ids: []const c_int, cookie: []const u8) !void {
            try replaceInstalledIds(ctx, ids);
            try setCookie(ctx, cookie);
        }
    };
}
