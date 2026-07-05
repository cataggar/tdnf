const std = @import("std");

const api = @import("api.zig");

const tdnf_rpmdb_iter = opaque {};

extern fn tdnf_rpmdb_cookie(root: ?[*:0]const u8) ?[*:0]u8;
extern fn tdnf_rpmdb_iter_open(root: ?[*:0]const u8) ?*tdnf_rpmdb_iter;
extern fn tdnf_rpmdb_iter_close(it: ?*tdnf_rpmdb_iter) void;
extern fn tdnf_rpmdb_iter_next_nevra(it: *tdnf_rpmdb_iter, nevra_out: *?[*:0]u8) c_int;
extern fn tdnf_rpmdb_string_free(s: ?[*:0]u8) void;

const RealRpmdb = struct {
    pub fn cookie(root: ?[*:0]const u8) ![:0]u8 {
        const raw = tdnf_rpmdb_cookie(root) orelse return error.RpmdbError;
        defer tdnf_rpmdb_string_free(raw);
        return try std.heap.c_allocator.dupeZ(u8, std.mem.span(raw));
    }

    pub fn collectNevras(allocator: std.mem.Allocator, root: ?[*:0]const u8) ![][:0]u8 {
        const iter = tdnf_rpmdb_iter_open(root) orelse return error.RpmdbError;
        defer tdnf_rpmdb_iter_close(iter);

        var nevras: std.ArrayList([:0]u8) = .empty;
        errdefer {
            for (nevras.items) |nevra| {
                allocator.free(nevra);
            }
            nevras.deinit(allocator);
        }

        while (true) {
            var raw: ?[*:0]u8 = null;
            const rc = tdnf_rpmdb_iter_next_nevra(iter, &raw);
            if (rc == 0) {
                break;
            }
            if (rc < 0 or raw == null) {
                return error.RpmdbError;
            }

            defer tdnf_rpmdb_string_free(raw);
            try nevras.append(allocator, try allocator.dupeZ(u8, std.mem.span(raw.?)));
        }

        return try nevras.toOwnedSlice(allocator);
    }
};

const Impl = api.Api(RealRpmdb);

pub const HistoryCtx = api.HistoryCtx;
pub const HistoryDelta = api.HistoryDelta;
pub const HistoryFlagsDelta = api.HistoryFlagsDelta;
pub const HistoryTransaction = api.HistoryTransaction;
pub const HistoryNevraMap = api.HistoryNevraMap;

pub export fn create_history_ctx(db_filename: ?[*:0]const u8) ?*HistoryCtx {
    const path = db_filename orelse return null;
    return Impl.createHistoryCtx(path) catch null;
}

pub export fn destroy_history_ctx(ctx: ?*HistoryCtx) void {
    Impl.destroyHistoryCtx(ctx);
}

pub export fn history_get_current_transaction_id(ctx: ?*HistoryCtx) c_int {
    const value = ctx orelse return 0;
    return Impl.historyGetCurrentTransactionId(value);
}

pub export fn history_sync(ctx: ?*HistoryCtx, root: ?[*:0]const u8) c_int {
    const value = ctx orelse return -1;
    Impl.historySync(value, root) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_nevra_from_id(ctx: ?*HistoryCtx, id: c_int) ?[*:0]u8 {
    const value = ctx orelse return null;
    return Impl.historyNevraFromId(value, id) catch null;
}

pub export fn history_nevra_map(ctx: ?*HistoryCtx) ?*HistoryNevraMap {
    const value = ctx orelse return null;
    return Impl.historyNevraMap(value) catch null;
}

pub export fn history_free_nevra_map(map: ?*HistoryNevraMap) void {
    Impl.historyFreeNevraMap(map);
}

pub export fn history_get_nevra(map: ?*HistoryNevraMap, id: c_int) ?[*:0]u8 {
    return Impl.historyGetNevra(map, id);
}

pub export fn history_free_delta(delta: ?*HistoryDelta) void {
    Impl.historyFreeDelta(delta);
}

pub export fn history_get_delta(ctx: ?*HistoryCtx, trans_id: c_int) ?*HistoryDelta {
    const value = ctx orelse return null;
    return Impl.historyGetDelta(value, trans_id) catch null;
}

pub export fn history_get_delta_range(
    ctx: ?*HistoryCtx,
    trans_id0: c_int,
    trans_id1: c_int,
) ?*HistoryDelta {
    const value = ctx orelse return null;
    return Impl.historyGetDeltaRange(value, trans_id0, trans_id1) catch null;
}

pub export fn history_add_transaction(ctx: ?*HistoryCtx, cmdline: ?[*:0]const u8) c_int {
    const value = ctx orelse return -1;
    const line = cmdline orelse return -1;
    Impl.historyAddTransaction(value, line) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_record_state(ctx: ?*HistoryCtx) c_int {
    const value = ctx orelse return -1;
    Impl.historyRecordState(value) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_update_state(
    ctx: ?*HistoryCtx,
    root: ?[*:0]const u8,
    cmdline: ?[*:0]const u8,
) c_int {
    const value = ctx orelse return -1;
    const line = cmdline orelse return -1;
    Impl.historyUpdateState(value, root, line) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_get_transactions(
    ctx: ?*HistoryCtx,
    ptas: *?[*]HistoryTransaction,
    pcount: *c_int,
    reverse: c_int,
    from: c_int,
    to: c_int,
) c_int {
    const value = ctx orelse return -1;
    Impl.historyGetTransactions(value, ptas, pcount, reverse, from, to) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_free_transactions(tas: ?[*]HistoryTransaction, count: c_int) void {
    Impl.historyFreeTransactions(tas, count);
}

pub export fn history_set_auto_flag(
    ctx: ?*HistoryCtx,
    name: ?[*:0]const u8,
    value: c_int,
) c_int {
    const value_ctx = ctx orelse return -1;
    const value_name = name orelse return -1;
    Impl.historySetAutoFlag(value_ctx, value_name, value) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_get_auto_flag(
    ctx: ?*HistoryCtx,
    name: ?[*:0]const u8,
    pvalue: *c_int,
) c_int {
    const value_ctx = ctx orelse return -1;
    const value_name = name orelse return -1;
    Impl.historyGetAutoFlag(value_ctx, value_name, pvalue) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_restore_auto_flags(ctx: ?*HistoryCtx, trans_id: c_int) c_int {
    const value = ctx orelse return -1;
    Impl.historyRestoreAutoFlags(value, trans_id) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_replay_auto_flags(ctx: ?*HistoryCtx, from: c_int, to: c_int) c_int {
    const value = ctx orelse return -1;
    Impl.historyReplayAutoFlags(value, from, to) catch |err| return @import("db.zig").errorToRc(err);
    return 0;
}

pub export fn history_free_flags_delta(hfd: ?*HistoryFlagsDelta) void {
    Impl.historyFreeFlagsDelta(hfd);
}

pub export fn history_get_flags_delta(
    ctx: ?*HistoryCtx,
    from: c_int,
    to: c_int,
) ?*HistoryFlagsDelta {
    const value = ctx orelse return null;
    return Impl.historyGetFlagsDelta(value, from, to) catch null;
}
