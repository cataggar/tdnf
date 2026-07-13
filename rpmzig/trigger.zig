const std = @import("std");
const sqlite = @import("sqlite");
const header = @import("rpm_header");
const scriptlet_engine = @import("scriptlet.zig");
const txn_config = @import("txn_config.zig");

const Allocator = std.mem.Allocator;
const c = sqlite.c;

const RPMTRANS_FLAG_NOSCRIPTS: u32 = 1 << 2;
const RPMTRANS_FLAG_NOTRIGGERS: u32 = 1 << 4;
const RPMTRANS_FLAG_NOTRIGGERIN: u32 = 1 << 19;
const RPMTRANS_FLAG_NOTRIGGERUN: u32 = 1 << 20;
const RPMTRANS_FLAG_NOTRIGGERPOSTUN: u32 = 1 << 23;

const RPMSENSE_LESS: u32 = 1 << 1;
const RPMSENSE_GREATER: u32 = 1 << 2;
const RPMSENSE_EQUAL: u32 = 1 << 3;
const RPMSENSE_SENSEMASK: u32 = 15;
const RPMSENSE_TRIGGERIN: u32 = 1 << 16;
const RPMSENSE_TRIGGERUN: u32 = 1 << 17;
const RPMSENSE_TRIGGERPOSTUN: u32 = 1 << 18;

pub const Phase = enum(u32) {
    triggerin = 0,
    triggerun = 1,
    triggerpostun = 2,
};

pub const Options = struct {
    db_root: []const u8 = "",
    install_root: []const u8,
    trans_flags: u32 = 0,
    rpmdefines: []const []const u8 = &.{},
    script_fd: ?c_int = null,
    redirect_stdout_to_stderr: bool = false,
};

pub const Result = scriptlet_engine.Result;

pub const Error = scriptlet_engine.RunError ||
    txn_config.InitError ||
    error{
        BadHeader,
        InvalidCount,
        PathTooLong,
        SqliteOpenFailed,
        SqlitePrepareFailed,
        SqliteStepFailed,
    };

pub fn runHeaderTriggers(
    allocator: Allocator,
    triggering_hdr: header.Header,
    phase: Phase,
    options: Options,
) Error!Result {
    if (shouldSkipPhase(phase, options.trans_flags)) {
        return .{
            .ran = false,
            .critical = false,
            .outcome = .not_run,
        };
    }

    const install_root = normalizeRoot(options.install_root);
    const db_root = normalizeRoot(if (options.db_root.len != 0) options.db_root else install_root);

    const triggering_name = triggering_hdr.getString(.name) orelse return error.BadHeader;

    var db = try Db.openRoot(allocator, db_root);
    defer db.close();

    const triggering_instances = try effectiveTriggeringInstanceCount(&db, triggering_name, phase);
    const arg2 = try castCount(triggering_instances);

    var result = Result{
        .ran = false,
        .critical = false,
        .outcome = .not_run,
    };

    var stmt = try Statement.init(
        db.db,
        "SELECT p.blob FROM 'Packages' p " ++
            "JOIN 'Triggername' t ON t.hnum = p.hnum " ++
            "WHERE t.key=? ORDER BY p.hnum",
    );
    defer stmt.deinit();
    try stmt.bindText(1, triggering_name);

    while (true) {
        const rc = c.sqlite3_step(stmt.raw);
        if (rc == c.SQLITE_DONE) {
            break;
        }
        if (rc != c.SQLITE_ROW) {
            return error.SqliteStepFailed;
        }

        const blob_ptr = c.sqlite3_column_blob(stmt.raw, 0);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt.raw, 0));
        if (blob_ptr == null or blob_len == 0) {
            continue;
        }

        const blob = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];
        const owner_hdr = header.Header.parse(blob) catch return error.BadHeader;
        const owner_name = owner_hdr.getString(.name) orelse return error.BadHeader;
        const triggered_instances = try db.countPackagesByName(owner_name);
        const arg1 = try castCount(triggered_instances);

        const script_indices = try collectMatchingTriggerScriptIndices(
            allocator,
            owner_hdr,
            phase,
            triggering_hdr,
        );
        defer allocator.free(script_indices);

        for (script_indices) |script_index| {
            const script_body = triggerScriptBody(owner_hdr, script_index) orelse return error.BadHeader;
            const interpreter = try collectTriggerInterpreterArgs(allocator, owner_hdr, script_index);
            defer allocator.free(interpreter);

            const script_result = try scriptlet_engine.runPreparedScript(
                allocator,
                interpreter,
                script_body,
                false,
                .{
                    .install_root = install_root,
                    .trans_flags = options.trans_flags,
                    .rpmdefines = options.rpmdefines,
                    .arg1 = arg1,
                    .arg2 = arg2,
                    .script_fd = options.script_fd,
                    .redirect_stdout_to_stderr = options.redirect_stdout_to_stderr,
                },
            );
            accumulateResult(&result, script_result);
        }
    }

    return result;
}

fn normalizeRoot(root: []const u8) []const u8 {
    return if (root.len == 0) "/" else root;
}

fn shouldSkipPhase(phase: Phase, trans_flags: u32) bool {
    if ((trans_flags & RPMTRANS_FLAG_NOSCRIPTS) != 0 or
        (trans_flags & RPMTRANS_FLAG_NOTRIGGERS) != 0)
    {
        return true;
    }

    return switch (phase) {
        .triggerin => (trans_flags & RPMTRANS_FLAG_NOTRIGGERIN) != 0,
        .triggerun => (trans_flags & RPMTRANS_FLAG_NOTRIGGERUN) != 0,
        .triggerpostun => (trans_flags & RPMTRANS_FLAG_NOTRIGGERPOSTUN) != 0,
    };
}

fn effectiveTriggeringInstanceCount(db: *Db, name: []const u8, phase: Phase) Error!u32 {
    const current = try db.countPackagesByName(name);
    return switch (phase) {
        .triggerin => current,
        .triggerun, .triggerpostun => if (current == 0) 0 else current - 1,
    };
}

fn castCount(count: u32) Error!i32 {
    return std.math.cast(i32, count) orelse error.InvalidCount;
}

fn collectMatchingTriggerScriptIndices(
    allocator: Allocator,
    owner_hdr: header.Header,
    phase: Phase,
    triggering_hdr: header.Header,
) Error![]u32 {
    const dep_count = owner_hdr.stringArrayCount(.triggername);
    if (dep_count == 0) {
        return allocator.alloc(u32, 0);
    }

    const triggering_name = triggering_hdr.getString(.name) orelse return error.BadHeader;
    var indices = std.ArrayList(u32).empty;
    defer indices.deinit(allocator);

    var i: usize = 0;
    while (i < dep_count) : (i += 1) {
        const dep_name = owner_hdr.stringArrayItem(.triggername, i) orelse return error.BadHeader;
        if (!std.mem.eql(u8, dep_name, triggering_name)) {
            continue;
        }

        const flags = owner_hdr.u32ArrayItem(.triggerflags, i) orelse return error.BadHeader;
        if (!phaseMatchesFlags(phase, flags)) {
            continue;
        }
        if (!try versionMatchesRequirement(triggering_hdr, owner_hdr.stringArrayItem(.triggerversion, i) orelse "", flags)) {
            continue;
        }

        const script_index = owner_hdr.u32ArrayItem(.triggerindex, i) orelse @as(u32, @intCast(i));
        if (!containsIndex(indices.items, script_index)) {
            try indices.append(allocator, script_index);
        }
    }

    return indices.toOwnedSlice(allocator);
}

fn phaseMatchesFlags(phase: Phase, flags: u32) bool {
    const phase_bit = switch (phase) {
        .triggerin => RPMSENSE_TRIGGERIN,
        .triggerun => RPMSENSE_TRIGGERUN,
        .triggerpostun => RPMSENSE_TRIGGERPOSTUN,
    };
    return (flags & phase_bit) != 0;
}

fn versionMatchesRequirement(
    triggering_hdr: header.Header,
    required_evr: []const u8,
    flags: u32,
) Error!bool {
    const sense = flags & RPMSENSE_SENSEMASK;
    if (sense == 0 or required_evr.len == 0) {
        return true;
    }

    const triggering_version = triggering_hdr.getString(.version) orelse return error.BadHeader;
    const triggering_release = triggering_hdr.getString(.release) orelse return error.BadHeader;
    const required = splitEvr(required_evr);

    const cmp = compareEvr(
        triggering_hdr.getU32(.epoch),
        triggering_version,
        triggering_release,
        required.epoch,
        required.version,
        required.release,
    );
    return compareMatchesSense(cmp, sense);
}

fn compareMatchesSense(cmp: i32, sense: u32) bool {
    return switch (sense) {
        RPMSENSE_LESS => cmp < 0,
        RPMSENSE_GREATER => cmp > 0,
        RPMSENSE_EQUAL => cmp == 0,
        RPMSENSE_LESS | RPMSENSE_EQUAL => cmp <= 0,
        RPMSENSE_GREATER | RPMSENSE_EQUAL => cmp >= 0,
        else => false,
    };
}

fn containsIndex(items: []const u32, wanted: u32) bool {
    for (items) |item| {
        if (item == wanted) {
            return true;
        }
    }
    return false;
}

fn triggerScriptBody(hdr: header.Header, script_index: u32) ?[]const u8 {
    const count = hdr.stringArrayCount(.triggerscripts);
    if (count > 0) {
        return hdr.stringArrayItem(.triggerscripts, @intCast(script_index));
    }
    if (script_index == 0) {
        return hdr.getString(.triggerscripts);
    }
    return null;
}

fn collectTriggerInterpreterArgs(
    allocator: Allocator,
    hdr: header.Header,
    script_index: u32,
) Error![]const []const u8 {
    var args = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(args);

    const count = hdr.stringArrayCount(.triggerscriptprog);
    if (count > 0) {
        const value = hdr.stringArrayItem(.triggerscriptprog, @intCast(script_index)) orelse return error.BadHeader;
        args[0] = value;
        return args;
    }

    if (hdr.getString(.triggerscriptprog)) |value| {
        args[0] = value;
        return args;
    }

    args[0] = txn_config.DEFAULT_SCRIPT_INTERPRETER;
    return args;
}

fn accumulateResult(result: *Result, script_result: Result) void {
    if (!script_result.ran) {
        return;
    }

    result.ran = true;
    result.critical = false;

    switch (script_result.outcome) {
        .not_run => {},
        .ok => {
            if (result.outcome == .not_run) {
                result.outcome = .ok;
            }
        },
        .exited => {
            if (result.outcome == .not_run or result.outcome == .ok) {
                result.outcome = .exited;
                result.exit_status = script_result.exit_status;
            }
        },
        .signaled => {
            result.outcome = .signaled;
            result.signal_number = script_result.signal_number;
        },
    }
}

const Db = struct {
    db: ?*c.sqlite3,

    fn openRoot(allocator: Allocator, root: []const u8) Error!Db {
        var config = try txn_config.TxnConfig.init(allocator, root);
        defer config.deinit();

        var db_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const db_path = config.resolveRpmDbSqlitePath(&db_path_buf) catch return error.PathTooLong;
        const db_path_z = try allocator.dupeZ(u8, db_path);
        defer allocator.free(db_path_z);

        var db: ?*c.sqlite3 = null;
        const open_rc = c.sqlite3_open_v2(
            db_path_z.ptr,
            &db,
            c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
            null,
        );
        if (open_rc != c.SQLITE_OK) {
            if (db != null) {
                _ = c.sqlite3_close(db);
            }
            return error.SqliteOpenFailed;
        }

        return .{ .db = db };
    }

    fn close(self: *Db) void {
        if (self.db != null) {
            _ = c.sqlite3_close(self.db);
            self.db = null;
        }
    }

    fn countPackagesByName(self: *Db, name: []const u8) Error!u32 {
        var stmt = try Statement.init(
            self.db,
            "SELECT COUNT(*) FROM 'Name' WHERE key=?",
        );
        defer stmt.deinit();
        try stmt.bindText(1, name);

        const rc = c.sqlite3_step(stmt.raw);
        if (rc != c.SQLITE_ROW) {
            return error.SqliteStepFailed;
        }

        const count = c.sqlite3_column_int64(stmt.raw, 0);
        return std.math.cast(u32, count) orelse error.InvalidCount;
    }
};

const Statement = struct {
    db: ?*c.sqlite3,
    raw: ?*c.sqlite3_stmt,

    fn init(db: ?*c.sqlite3, sql: []const u8) Error!Statement {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, @ptrCast(sql.ptr), @intCast(sql.len), &stmt, null) != c.SQLITE_OK) {
            return error.SqlitePrepareFailed;
        }
        return .{
            .db = db,
            .raw = stmt,
        };
    }

    fn deinit(self: *Statement) void {
        if (self.raw != null) {
            _ = c.sqlite3_finalize(self.raw);
            self.raw = null;
        }
    }

    fn bindText(self: *Statement, index: c_int, value: []const u8) Error!void {
        if (c.sqlite3_bind_text(self.raw, index, value.ptr, @intCast(value.len), null) != c.SQLITE_OK) {
            return error.SqliteStepFailed;
        }
    }
};

const EvrParts = struct {
    epoch: ?u32 = null,
    version: ?[]const u8 = null,
    release: ?[]const u8 = null,
};

fn compareEvr(
    left_epoch: ?u32,
    left_version: ?[]const u8,
    left_release: ?[]const u8,
    right_epoch: ?u32,
    right_version: ?[]const u8,
    right_release: ?[]const u8,
) i32 {
    const left_epoch_value = left_epoch orelse 0;
    const right_epoch_value = right_epoch orelse 0;
    if (left_epoch_value < right_epoch_value) return -1;
    if (left_epoch_value > right_epoch_value) return 1;

    const version_cmp = compareRpmVersion(left_version orelse "", right_version orelse "");
    if (version_cmp != 0) return version_cmp;

    return compareRpmVersion(left_release orelse "", right_release orelse "");
}

fn compareRpmVersion(left_raw: []const u8, right_raw: []const u8) i32 {
    var left = left_raw;
    var right = right_raw;

    while (true) {
        while (left.len != 0 and !isRpmTokenByte(left[0])) {
            left = left[1..];
        }
        while (right.len != 0 and !isRpmTokenByte(right[0])) {
            right = right[1..];
        }

        if ((left.len != 0 and left[0] == '~') or (right.len != 0 and right[0] == '~')) {
            if (left.len == 0 or left[0] != '~') return 1;
            if (right.len == 0 or right[0] != '~') return -1;
            left = left[1..];
            right = right[1..];
            continue;
        }

        if ((left.len != 0 and left[0] == '^') or (right.len != 0 and right[0] == '^')) {
            if (left.len == 0) return -1;
            if (right.len == 0) return 1;
            if (left[0] != '^') return 1;
            if (right[0] != '^') return -1;
            left = left[1..];
            right = right[1..];
            continue;
        }

        if (left.len == 0 and right.len == 0) {
            return 0;
        }
        if (left.len == 0) {
            return -1;
        }
        if (right.len == 0) {
            return 1;
        }

        const left_is_digit = std.ascii.isDigit(left[0]);
        const right_is_digit = std.ascii.isDigit(right[0]);
        if (left_is_digit != right_is_digit) {
            return if (left_is_digit) 1 else -1;
        }

        if (left_is_digit) {
            const left_end = digitRunEnd(left);
            const right_end = digitRunEnd(right);

            var left_digits = left[0..left_end];
            var right_digits = right[0..right_end];
            left = left[left_end..];
            right = right[right_end..];

            left_digits = trimLeadingZeros(left_digits);
            right_digits = trimLeadingZeros(right_digits);

            if (left_digits.len < right_digits.len) return -1;
            if (left_digits.len > right_digits.len) return 1;

            const cmp = std.mem.order(u8, left_digits, right_digits);
            if (cmp != .eq) {
                return switch (cmp) {
                    .lt => -1,
                    .gt => 1,
                    .eq => unreachable,
                };
            }
            continue;
        }

        const left_end = alphaRunEnd(left);
        const right_end = alphaRunEnd(right);
        const left_alpha = left[0..left_end];
        const right_alpha = right[0..right_end];
        left = left[left_end..];
        right = right[right_end..];

        const cmp = std.mem.order(u8, left_alpha, right_alpha);
        if (cmp != .eq) {
            return switch (cmp) {
                .lt => -1,
                .gt => 1,
                .eq => unreachable,
            };
        }
    }
}

fn trimLeadingZeros(value: []const u8) []const u8 {
    var index: usize = 0;
    while (index + 1 < value.len and value[index] == '0') : (index += 1) {}
    return value[index..];
}

fn digitRunEnd(value: []const u8) usize {
    var index: usize = 0;
    while (index < value.len and std.ascii.isDigit(value[index])) : (index += 1) {}
    return index;
}

fn alphaRunEnd(value: []const u8) usize {
    var index: usize = 0;
    while (index < value.len and std.ascii.isAlphabetic(value[index])) : (index += 1) {}
    return index;
}

fn isRpmTokenByte(value: u8) bool {
    return std.ascii.isAlphanumeric(value) or value == '~' or value == '^';
}

fn splitEvr(evr: []const u8) EvrParts {
    if (evr.len == 0) {
        return .{};
    }

    var epoch: ?u32 = null;
    var body = evr;
    if (std.mem.indexOfScalar(u8, evr, ':')) |separator| {
        if (separator != 0) {
            const candidate = evr[0..separator];
            epoch = std.fmt.parseInt(u32, candidate, 10) catch null;
            if (epoch != null) {
                body = evr[separator + 1 ..];
            }
        }
    }

    if (body.len == 0) {
        return .{ .epoch = epoch };
    }

    if (std.mem.lastIndexOfScalar(u8, body, '-')) |separator| {
        if (separator != 0 and separator + 1 < body.len) {
            return .{
                .epoch = epoch,
                .version = body[0..separator],
                .release = body[separator + 1 ..],
            };
        }
    }

    return .{
        .epoch = epoch,
        .version = body,
    };
}

const TestHeaderEntry = struct {
    tag: u32,
    typ: u32,
    count: u32,
    data: []const u8,
};

fn buildTestHeaderBlob(
    allocator: Allocator,
    entries: []const TestHeaderEntry,
) ![]u8 {
    const IndexSpec = struct { tag: u32, typ: u32, offset: u32, count: u32 };

    var index_specs = std.ArrayList(IndexSpec).empty;
    defer index_specs.deinit(allocator);
    var data = std.ArrayList(u8).empty;
    defer data.deinit(allocator);

    for (entries) |entry| {
        try index_specs.append(allocator, .{
            .tag = entry.tag,
            .typ = entry.typ,
            .offset = @intCast(data.items.len),
            .count = entry.count,
        });
        try data.appendSlice(allocator, entry.data);
    }

    const total_len = 8 + index_specs.items.len * 16 + data.items.len;
    const blob = try allocator.alloc(u8, total_len);

    writeBeU32(blob[0..4], @intCast(index_specs.items.len));
    writeBeU32(blob[4..8], @intCast(data.items.len));

    var cursor: usize = 8;
    for (index_specs.items) |entry| {
        writeBeU32(blob[cursor .. cursor + 4], entry.tag);
        writeBeU32(blob[cursor + 4 .. cursor + 8], entry.typ);
        writeBeU32(blob[cursor + 8 .. cursor + 12], entry.offset);
        writeBeU32(blob[cursor + 12 .. cursor + 16], entry.count);
        cursor += 16;
    }
    @memcpy(blob[cursor..], data.items);
    return blob;
}

fn writeBeU32(buf: []u8, value: u32) void {
    buf[0] = @intCast((value >> 24) & 0xff);
    buf[1] = @intCast((value >> 16) & 0xff);
    buf[2] = @intCast((value >> 8) & 0xff);
    buf[3] = @intCast(value & 0xff);
}

fn testStringArrayBytes(allocator: Allocator, values: []const []const u8) ![]u8 {
    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(allocator);

    for (values) |value| {
        try bytes.appendSlice(allocator, value);
        try bytes.append(allocator, 0);
    }

    return bytes.toOwnedSlice(allocator);
}

fn testU32ArrayBytes(allocator: Allocator, values: []const u32) ![]u8 {
    const bytes = try allocator.alloc(u8, values.len * 4);
    for (values, 0..) |value, index| {
        writeBeU32(bytes[index * 4 ..][0..4], value);
    }
    return bytes;
}

test "collectMatchingTriggerScriptIndices deduplicates and filters by version" {
    const allocator = std.testing.allocator;

    const trigger_names = try testStringArrayBytes(allocator, &.{ "alpha", "alpha", "alpha" });
    defer allocator.free(trigger_names);
    const trigger_versions = try testStringArrayBytes(allocator, &.{ "", "", "2.0-1" });
    defer allocator.free(trigger_versions);
    const trigger_flags = try testU32ArrayBytes(allocator, &.{
        RPMSENSE_TRIGGERIN,
        RPMSENSE_TRIGGERIN,
        RPMSENSE_TRIGGERIN | RPMSENSE_GREATER | RPMSENSE_EQUAL,
    });
    defer allocator.free(trigger_flags);
    const trigger_indices = try testU32ArrayBytes(allocator, &.{ 0, 0, 1 });
    defer allocator.free(trigger_indices);
    const trigger_scripts = try testStringArrayBytes(allocator, &.{ "echo first", "echo second" });
    defer allocator.free(trigger_scripts);
    const trigger_progs = try testStringArrayBytes(allocator, &.{ "/bin/sh", "/bin/sh" });
    defer allocator.free(trigger_progs);

    const owner_blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = 6, .count = 1, .data = "owner\x00" },
        .{ .tag = @intFromEnum(header.TagId.triggerscripts), .typ = 8, .count = 2, .data = trigger_scripts },
        .{ .tag = @intFromEnum(header.TagId.triggername), .typ = 8, .count = 3, .data = trigger_names },
        .{ .tag = @intFromEnum(header.TagId.triggerversion), .typ = 8, .count = 3, .data = trigger_versions },
        .{ .tag = @intFromEnum(header.TagId.triggerflags), .typ = 4, .count = 3, .data = trigger_flags },
        .{ .tag = @intFromEnum(header.TagId.triggerindex), .typ = 4, .count = 3, .data = trigger_indices },
        .{ .tag = @intFromEnum(header.TagId.triggerscriptprog), .typ = 8, .count = 2, .data = trigger_progs },
    });
    defer allocator.free(owner_blob);

    const triggering_blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = 6, .count = 1, .data = "alpha\x00" },
        .{ .tag = @intFromEnum(header.TagId.version), .typ = 6, .count = 1, .data = "2.1\x00" },
        .{ .tag = @intFromEnum(header.TagId.release), .typ = 6, .count = 1, .data = "1\x00" },
    });
    defer allocator.free(triggering_blob);

    const owner_hdr = try header.Header.parse(owner_blob);
    const triggering_hdr = try header.Header.parse(triggering_blob);

    const matches = try collectMatchingTriggerScriptIndices(
        allocator,
        owner_hdr,
        .triggerin,
        triggering_hdr,
    );
    defer allocator.free(matches);

    try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1 }, matches);
}

test "versionMatchesRequirement honours comparison sense bits" {
    const allocator = std.testing.allocator;
    const triggering_blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = 6, .count = 1, .data = "alpha\x00" },
        .{ .tag = @intFromEnum(header.TagId.epoch), .typ = 4, .count = 1, .data = "\x00\x00\x00\x01" },
        .{ .tag = @intFromEnum(header.TagId.version), .typ = 6, .count = 1, .data = "2.0\x00" },
        .{ .tag = @intFromEnum(header.TagId.release), .typ = 6, .count = 1, .data = "3\x00" },
    });
    defer allocator.free(triggering_blob);

    const triggering_hdr = try header.Header.parse(triggering_blob);

    try std.testing.expect(try versionMatchesRequirement(
        triggering_hdr,
        "1:2.0-3",
        RPMSENSE_TRIGGERIN | RPMSENSE_EQUAL,
    ));
    try std.testing.expect(try versionMatchesRequirement(
        triggering_hdr,
        "1:1.9-9",
        RPMSENSE_TRIGGERIN | RPMSENSE_GREATER,
    ));
    try std.testing.expect(!(try versionMatchesRequirement(
        triggering_hdr,
        "1:2.1-0",
        RPMSENSE_TRIGGERIN | RPMSENSE_GREATER | RPMSENSE_EQUAL,
    )));
}
