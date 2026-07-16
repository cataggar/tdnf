const std = @import("std");
const sqlite = @import("sqlite");
const header = @import("rpm_header");
const install_engine = @import("install.zig");
const query_format = @import("queryformat.zig");
const scriptlet_engine = @import("scriptlet.zig");
const txn_config = @import("txn_config.zig");
const rpmtrans = @cImport({
    @cInclude("tdnfrpmtrans.h");
});

const Allocator = std.mem.Allocator;
const c = sqlite.c;

const RPMSENSE_LESS: u32 = 1 << 1;
const RPMSENSE_GREATER: u32 = 1 << 2;
const RPMSENSE_EQUAL: u32 = 1 << 3;
const RPMSENSE_SENSEMASK: u32 = 15;
const RPMSENSE_TRIGGERIN: u32 = 1 << 16;
const RPMSENSE_TRIGGERUN: u32 = 1 << 17;
const RPMSENSE_TRIGGERPOSTUN: u32 = 1 << 18;
const RPMSENSE_TRIGGER_MASK: u32 =
    RPMSENSE_TRIGGERIN | RPMSENSE_TRIGGERUN | RPMSENSE_TRIGGERPOSTUN;
const TRIGGER_PRIORITY_BOUND: u32 = 10_000;
const DEFAULT_TRIGGER_PRIORITY: u32 = 1_000_000;
const RPMFILE_STATE_NORMAL: u8 = 0;
const RPMFILE_STATE_NETSHARED: u8 = 3;
const RPMFILE_CONFIG: u32 = 1 << 0;
const RPMFILE_DOC: u32 = 1 << 1;
const RPMFILE_GHOST: u32 = 1 << 6;
const RPMFILE_README: u32 = 1 << 8;
const RPMSCRIPT_FLAG_EXPAND: u32 = 1 << 0;
const RPMSCRIPT_FLAG_QFORMAT: u32 = 1 << 1;

pub const Phase = enum(u32) {
    triggerin = 0,
    triggerun = 1,
    triggerpostun = 2,
};

pub const FileKind = enum(u32) {
    file = 0,
    transaction = 1,
};

pub const PriorityClass = enum(u32) {
    all = 0,
    high = 1,
    low = 2,
};

pub const TriggerPath = struct {
    path: []const u8,
    source_header: ?header.Header = null,
};

pub const FileOwner = struct {
    hdr: header.Header,
    paths: []const TriggerPath,
    order: u64,
};

pub const FileOptions = struct {
    install_root: []const u8,
    config: ?*const txn_config.TxnConfig = null,
    trans_flags: u32 = 0,
    rpmdefines: []const []const u8 = &.{},
    script_fd: ?c_int = null,
    redirect_stdout_to_stderr: bool = false,
    suppress_stdin: bool = false,
    pinned_root_fd: ?c_int = null,
};

pub const Options = struct {
    db_root: []const u8 = "",
    install_root: []const u8,
    config: ?*const txn_config.TxnConfig = null,
    trans_flags: u32 = 0,
    rpmdefines: []const []const u8 = &.{},
    script_fd: ?c_int = null,
    redirect_stdout_to_stderr: bool = false,
    pinned_root_fd: ?c_int = null,
    /// Optional explicit `$2` argument for the trigger scripts.
    ///
    /// When null (the default), the engine derives `$2` from the
    /// current triggering-package instance count in the rpmdb, using
    /// the phase-specific formula in `effectiveTriggeringInstanceCount`:
    /// this matches real rpm for plain install / plain erase where
    /// the rpmdb state is consistent with the transaction step.
    ///
    /// For upgrade, the native executor uses `write_replace` to swap
    /// the old row atomically, so at the moment the engine is invoked
    /// the rpmdb count no longer reflects real rpm's transient two-
    /// instance state. Callers pass an override for those phases:
    ///
    ///   * %triggerin on the NEW package during upgrade: override
    ///     with `nPriors + 1` (real rpm treats both old and new as
    ///     briefly co-installed).
    ///   * %triggerun / %triggerpostun on the OLD package during
    ///     upgrade cleanup: override with `1` (the new instance
    ///     survives).
    arg2_override: ?i32 = null,
    /// Phase-aware transaction view. When non-null, candidates and instance
    /// counts come from these active headers.
    transaction_headers: ?[]const header.Header = null,
    /// Optional rpmdb-index-visible subset used for trigger-owner discovery.
    /// Counts still come from `transaction_headers`.
    trigger_owner_headers: ?[]const header.Header = null,
};

pub const Result = scriptlet_engine.Result;

pub const Error = scriptlet_engine.RunError ||
    txn_config.InitError ||
    query_format.Error ||
    error{
        BadHeader,
        InvalidCount,
        InvalidMetadata,
        CallbackFailed,
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

    var config = if (options.config) |supplied|
        try supplied.clone(allocator)
    else
        try txn_config.TxnConfig.init(allocator, normalizeRoot(options.install_root));
    defer config.deinit();
    for (options.rpmdefines) |define| {
        _ = try config.applyRpmDefine(define);
    }
    var pinned_root = if (options.pinned_root_fd) |root_fd| blk: {
        const duplicate = std.c.fcntl(
            root_fd,
            std.c.F.DUPFD_CLOEXEC,
            @as(c_int, 0),
        );
        if (duplicate < 0) return error.SyscallFailed;
        break :blk try install_engine.RootDir.initFromOwnedFd(
            allocator,
            duplicate,
            null,
            null,
        );
    } else try install_engine.RootDir.init(
        allocator,
        config.installRoot(),
        null,
        null,
    );
    defer pinned_root.deinit();
    const install_root = config.installRoot();

    const triggering_name = triggering_hdr.getString(.name) orelse return error.BadHeader;

    var result = Result{
        .ran = false,
        .critical = false,
        .outcome = .not_run,
    };

    if (options.transaction_headers) |transaction_headers| {
        const owner_headers = options.trigger_owner_headers orelse
            transaction_headers;
        for (owner_headers) |owner_hdr| {
            if (!hasAnyTriggerMetadata(owner_hdr)) {
                continue;
            }
            try validateHeaderScripts(allocator, owner_hdr, &config);
        }
        const triggering_instances = countHeadersByName(
            transaction_headers,
            triggering_name,
        );
        const arg2 = if (options.arg2_override) |ov|
            ov
        else
            try castCount(effectiveTriggeringInstanceCountValue(
                triggering_instances,
                phase,
            ));
        for (owner_headers) |owner_hdr| {
            if (!hasTriggerMetadata(owner_hdr, ordinary_trigger_tags)) {
                continue;
            }
            const owner_name = owner_hdr.getString(.name) orelse
                return error.BadHeader;
            const arg1 = try castCount(countHeadersByName(
                transaction_headers,
                owner_name,
            ));
            try runOwnerTriggers(
                allocator,
                owner_hdr,
                triggering_hdr,
                phase,
                install_root,
                &pinned_root,
                &config,
                options,
                arg1,
                arg2,
                &result,
            );
        }
        return result;
    }

    var db_config_storage: ?txn_config.TxnConfig = null;
    defer if (db_config_storage) |*db_config| {
        db_config.deinit();
    };
    const db_config = if (options.config != null)
        &config
    else blk: {
        const db_root = if (options.db_root.len != 0)
            options.db_root
        else
            options.install_root;
        db_config_storage = try txn_config.TxnConfig.init(
            allocator,
            normalizeRoot(db_root),
        );
        break :blk &db_config_storage.?;
    };

    var db = try Db.openConfig(allocator, db_config);
    defer db.close();

    const triggering_instances = try effectiveTriggeringInstanceCount(
        &db,
        triggering_name,
        phase,
    );
    const arg2 = if (options.arg2_override) |ov| ov else try castCount(triggering_instances);

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
        const owner_hdr = header.Header.parse(blob) catch
            return error.BadHeader;
        try validateHeaderScripts(allocator, owner_hdr, &config);
    }
    try stmt.reset();

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
        const owner_name = owner_hdr.getString(.name) orelse
            return error.BadHeader;
        const arg1 = try castCount(try db.countPackagesByName(owner_name));
        try runOwnerTriggers(
            allocator,
            owner_hdr,
            triggering_hdr,
            phase,
            install_root,
            &pinned_root,
            &config,
            options,
            arg1,
            arg2,
            &result,
        );
    }

    return result;
}

fn runOwnerTriggers(
    allocator: Allocator,
    owner_hdr: header.Header,
    triggering_hdr: header.Header,
    phase: Phase,
    install_root: []const u8,
    pinned_root: *const install_engine.RootDir,
    config: *const txn_config.TxnConfig,
    options: Options,
    arg1: i32,
    arg2: i32,
    result: *Result,
) Error!void {
    const script_indices = try collectMatchingTriggerScriptIndices(
        allocator,
        owner_hdr,
        phase,
        triggering_hdr,
    );
    defer allocator.free(script_indices);

    for (script_indices) |script_index| {
        const raw_script_body = triggerScriptBody(owner_hdr, script_index) orelse
            return error.BadHeader;
        const script_flags = owner_hdr.u32ArrayItem(
            .triggerscriptflags,
            script_index,
        ) orelse 0;
        const script_body = try prepareTriggerScriptBody(
            allocator,
            owner_hdr,
            raw_script_body,
            script_flags,
            config,
        );
        defer allocator.free(script_body);
        const interpreter = try collectTriggerInterpreterArgs(
            allocator,
            owner_hdr,
            script_index,
        );
        defer allocator.free(interpreter);

        const script_result = try scriptlet_engine.runPreparedScript(
            allocator,
            interpreter,
            script_body,
            false,
            .{
                .install_root = install_root,
                .config = config,
                .trans_flags = options.trans_flags,
                .arg1 = arg1,
                .arg2 = arg2,
                .script_fd = options.script_fd,
                .redirect_stdout_to_stderr = options.redirect_stdout_to_stderr,
                .pinned_root_fd = pinned_root.fd,
            },
        );
        accumulateResult(result, script_result);
    }
}

fn countHeadersByName(headers: []const header.Header, name: []const u8) u32 {
    var count: u32 = 0;
    for (headers) |hdr| {
        const candidate = hdr.getString(.name) orelse continue;
        if (std.mem.eql(u8, candidate, name)) {
            count += 1;
        }
    }
    return count;
}

fn normalizeRoot(root: []const u8) []const u8 {
    return if (root.len == 0) "/" else root;
}

fn shouldSkipPhase(phase: Phase, trans_flags: u32) bool {
    if ((trans_flags & (rpmtrans.TDNF_RPMTRANS_FLAG_NOSCRIPTS |
        rpmtrans.TDNF_RPMTRANS_FLAG_JUSTDB)) != 0 or
        (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOTRIGGERS) != 0)
    {
        return true;
    }

    return switch (phase) {
        .triggerin => (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOTRIGGERIN) != 0,
        .triggerun => (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOTRIGGERUN) != 0,
        .triggerpostun => (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOTRIGGERPOSTUN) != 0,
    };
}

fn effectiveTriggeringInstanceCount(db: *Db, name: []const u8, phase: Phase) Error!u32 {
    const current = try db.countPackagesByName(name);
    return effectiveTriggeringInstanceCountValue(current, phase);
}

fn effectiveTriggeringInstanceCountValue(current: u32, phase: Phase) u32 {
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

    return error.BadHeader;
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

const TriggerGroupTags = struct {
    scripts: header.TagId,
    programs: header.TagId,
    script_flags: header.TagId,
    priorities: ?header.TagId = null,
    names: header.TagId,
    versions: header.TagId,
    flags: header.TagId,
    indexes: header.TagId,
    conditions: header.TagId,
    types: header.TagId,
    require_path_prefix: bool = false,
};

const ordinary_trigger_tags = TriggerGroupTags{
    .scripts = .triggerscripts,
    .programs = .triggerscriptprog,
    .script_flags = .triggerscriptflags,
    .names = .triggername,
    .versions = .triggerversion,
    .flags = .triggerflags,
    .indexes = .triggerindex,
    .conditions = .triggerconds,
    .types = .triggertype,
};

const file_trigger_tags = TriggerGroupTags{
    .scripts = .filetriggerscripts,
    .programs = .filetriggerscriptprog,
    .script_flags = .filetriggerscriptflags,
    .priorities = .filetriggerpriorities,
    .names = .filetriggername,
    .versions = .filetriggerversion,
    .flags = .filetriggerflags,
    .indexes = .filetriggerindex,
    .conditions = .filetriggerconds,
    .types = .filetriggertype,
    .require_path_prefix = true,
};

const trans_file_trigger_tags = TriggerGroupTags{
    .scripts = .transfiletriggerscripts,
    .programs = .transfiletriggerscriptprog,
    .script_flags = .transfiletriggerscriptflags,
    .priorities = .transfiletriggerpriorities,
    .names = .transfiletriggername,
    .versions = .transfiletriggerversion,
    .flags = .transfiletriggerflags,
    .indexes = .transfiletriggerindex,
    .conditions = .transfiletriggerconds,
    .types = .transfiletriggertype,
    .require_path_prefix = true,
};

fn tagsForKind(kind: FileKind) TriggerGroupTags {
    return switch (kind) {
        .file => file_trigger_tags,
        .transaction => trans_file_trigger_tags,
    };
}

pub fn hasFileTriggerMetadata(hdr: header.Header, kind: FileKind) bool {
    return hasTriggerMetadata(hdr, tagsForKind(kind));
}

fn hasAnyTriggerMetadata(hdr: header.Header) bool {
    return hasTriggerMetadata(hdr, ordinary_trigger_tags) or
        hasTriggerMetadata(hdr, file_trigger_tags) or
        hasTriggerMetadata(hdr, trans_file_trigger_tags);
}

fn hasTriggerMetadata(
    hdr: header.Header,
    tags: TriggerGroupTags,
) bool {
    return hdr.find(tags.scripts) != null or
        hdr.find(tags.programs) != null or
        hdr.find(tags.script_flags) != null or
        (tags.priorities != null and hdr.find(tags.priorities.?) != null) or
        hdr.find(tags.names) != null or
        hdr.find(tags.versions) != null or
        hdr.find(tags.flags) != null or
        hdr.find(tags.indexes) != null or
        hdr.find(tags.conditions) != null or
        hdr.find(tags.types) != null;
}

pub fn validateHeaderMetadata(hdr: header.Header) Error!void {
    try validateTriggerGroup(hdr, ordinary_trigger_tags);
    try validateTriggerGroup(hdr, file_trigger_tags);
    try validateTriggerGroup(hdr, trans_file_trigger_tags);
    try validateHeaderPaths(hdr);
}

pub fn validateHeaderScripts(
    allocator: Allocator,
    hdr: header.Header,
    config: *const txn_config.TxnConfig,
) Error!void {
    try validateHeaderMetadata(hdr);
    const groups = [_]TriggerGroupTags{
        ordinary_trigger_tags,
        file_trigger_tags,
        trans_file_trigger_tags,
    };
    for (groups) |tags| {
        const script_count = hdr.stringArrayCount(tags.scripts);
        for (0..script_count) |script_index| {
            const flags = hdr.u32ArrayItem(
                tags.script_flags,
                script_index,
            ) orelse 0;
            if ((flags &
                (RPMSCRIPT_FLAG_EXPAND | RPMSCRIPT_FLAG_QFORMAT)) == 0)
            {
                continue;
            }
            const raw_body = hdr.stringArrayItem(
                tags.scripts,
                script_index,
            ) orelse return error.InvalidMetadata;
            const body = try prepareTriggerScriptBody(
                allocator,
                hdr,
                raw_body,
                flags,
                config,
            );
            allocator.free(body);
        }
    }
}

fn validateTriggerGroup(hdr: header.Header, tags: TriggerGroupTags) Error!void {
    const names = try optionalTagCount(hdr, tags.names, .string_array);
    const versions = try optionalTagCount(hdr, tags.versions, .string_array);
    const flags = try optionalTagCount(hdr, tags.flags, .int32);
    const indexes = try optionalTagCount(hdr, tags.indexes, .int32);
    const scripts = try optionalTagCount(hdr, tags.scripts, .string_array);
    if (names == null and versions == null and flags == null and
        indexes == null and scripts == null)
    {
        if (hdr.find(tags.programs) != null or
            hdr.find(tags.script_flags) != null or
            (tags.priorities != null and hdr.find(tags.priorities.?) != null) or
            hdr.find(tags.conditions) != null or
            hdr.find(tags.types) != null)
        {
            return error.InvalidMetadata;
        }
        return;
    }
    if (names == null or versions == null or flags == null or
        indexes == null or scripts == null or scripts.? == 0 or
        names.? != versions.? or names.? != flags.? or
        names.? != indexes.?)
    {
        return error.InvalidMetadata;
    }

    const programs = try optionalTagCount(hdr, tags.programs, .string_array);
    if (programs == null or programs.? != scripts.?) {
        return error.InvalidMetadata;
    }
    const script_flags = try optionalTagCount(hdr, tags.script_flags, .int32);
    if (script_flags != null and script_flags.? != scripts.?) {
        return error.InvalidMetadata;
    }
    if (tags.priorities) |priority_tag| {
        const priorities = try optionalTagCount(hdr, priority_tag, .int32);
        if (priorities != null and priorities.? != scripts.?) {
            return error.InvalidMetadata;
        }
    }
    const conditions = try optionalTagCount(hdr, tags.conditions, .string_array);
    if (conditions != null and conditions.? != names.?) {
        return error.InvalidMetadata;
    }
    const types = try optionalTagCount(hdr, tags.types, .string_array);
    if (types != null and types.? != names.?) {
        return error.InvalidMetadata;
    }

    const script_phases = try std.heap.c_allocator.alloc(u32, scripts.?);
    defer std.heap.c_allocator.free(script_phases);
    @memset(script_phases, 0);

    for (0..names.?) |index| {
        const name = hdr.stringArrayItem(tags.names, index) orelse
            return error.InvalidMetadata;
        const script_index = hdr.u32ArrayItem(tags.indexes, index) orelse
            return error.InvalidMetadata;
        if (script_index >= scripts.?) {
            return error.InvalidMetadata;
        }
        const trigger_flags = hdr.u32ArrayItem(tags.flags, index) orelse
            return error.InvalidMetadata;
        const phase_bits = trigger_flags & RPMSENSE_TRIGGER_MASK;
        if (phase_bits == 0 or (phase_bits & (phase_bits - 1)) != 0) {
            return error.InvalidMetadata;
        }
        if (script_phases[script_index] != 0 and
            script_phases[script_index] != phase_bits)
        {
            return error.InvalidMetadata;
        }
        script_phases[script_index] = phase_bits;

        if (tags.require_path_prefix and !isValidTriggerPrefix(name)) {
            return error.InvalidMetadata;
        }
    }

    for (0..scripts.?) |script_index| {
        _ = hdr.stringArrayItem(tags.scripts, script_index) orelse
            return error.InvalidMetadata;
        const program = hdr.stringArrayItem(tags.programs, script_index) orelse
            return error.InvalidMetadata;
        if (program.len == 0) return error.InvalidMetadata;
    }
}

fn optionalTagCount(
    hdr: header.Header,
    tag: header.TagId,
    typ: header.TypeId,
) Error!?usize {
    const entry = hdr.find(tag) orelse return null;
    if (entry.typ != @intFromEnum(typ)) return error.InvalidMetadata;
    return std.math.cast(usize, entry.count) orelse error.InvalidMetadata;
}

fn validateHeaderPaths(hdr: header.Header) Error!void {
    const basenames = try optionalTagCount(hdr, .basenames, .string_array);
    const dirindexes = try optionalTagCount(hdr, .dirindexes, .int32);
    const dirnames = try optionalTagCount(hdr, .dirnames, .string_array);
    if (basenames == null and dirindexes == null and dirnames == null) {
        return;
    }
    if (basenames == null or dirindexes == null or dirnames == null or
        basenames.? != dirindexes.?)
    {
        return error.InvalidMetadata;
    }

    if (hdr.find(.file_states)) |entry| {
        if ((entry.typ != @intFromEnum(header.TypeId.char_type) and
            entry.typ != @intFromEnum(header.TypeId.int8)) or
            entry.count != basenames.?)
        {
            return error.InvalidMetadata;
        }
    }
    if (hdr.find(.fileflags)) |entry| {
        if (entry.typ != @intFromEnum(header.TypeId.int32) or
            entry.count != basenames.?)
        {
            return error.InvalidMetadata;
        }
    }

    const dirname_values = try std.heap.c_allocator.alloc(
        []const u8,
        dirnames.?,
    );
    defer std.heap.c_allocator.free(dirname_values);
    var dirname_iter = (hdr.stringArrayIteratorChecked(.dirnames) catch
        return error.InvalidMetadata) orelse return error.InvalidMetadata;
    for (dirname_values) |*dirname| {
        dirname.* = (dirname_iter.next() catch
            return error.InvalidMetadata) orelse return error.InvalidMetadata;
    }
    var basename_iter = (hdr.stringArrayIteratorChecked(.basenames) catch
        return error.InvalidMetadata) orelse return error.InvalidMetadata;

    for (0..basenames.?) |index| {
        const basename = (basename_iter.next() catch
            return error.InvalidMetadata) orelse return error.InvalidMetadata;
        const dir_index = hdr.u32ArrayItem(.dirindexes, index) orelse
            return error.InvalidMetadata;
        if (dir_index >= dirnames.?) return error.InvalidMetadata;
        const dirname = dirname_values[dir_index];
        if (dirname.len == 0 or dirname[0] != '/' or
            std.mem.indexOfScalar(u8, basename, '/') != null)
        {
            return error.InvalidMetadata;
        }
        if (!isSafeJoinedPath(dirname, basename)) {
            return error.InvalidMetadata;
        }
    }
}

fn isValidTriggerPrefix(prefix: []const u8) bool {
    return prefix.len != 0 and prefix[0] == '/' and
        isSafeAbsolutePath(prefix);
}

fn isSafeJoinedPath(dirname: []const u8, basename: []const u8) bool {
    if (basename.len == 0) return std.mem.eql(u8, dirname, "/");
    var dirname_parts = std.mem.splitScalar(u8, dirname[1..], '/');
    while (dirname_parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return !std.mem.eql(u8, basename, ".") and
        !std.mem.eql(u8, basename, "..");
}

fn isSafeAbsolutePath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

pub const FilePathFn = *const fn (
    ctx: ?*anyopaque,
    path: []const u8,
) i32;

pub fn forEachTriggerFile(
    allocator: Allocator,
    hdr: header.Header,
    trans_flags: u32,
    callback: FilePathFn,
    callback_ctx: ?*anyopaque,
) Error!void {
    try validateHeaderMetadata(hdr);
    const count = hdr.stringArrayCount(.basenames);
    if (count == 0) return;

    const states = if (hdr.find(.file_states)) |entry|
        hdr.rawEntryBytes(entry) orelse return error.InvalidMetadata
    else
        null;
    const dirname_count = hdr.stringArrayCount(.dirnames);
    const dirname_values = try allocator.alloc([]const u8, dirname_count);
    defer allocator.free(dirname_values);
    var dirname_iter = (hdr.stringArrayIteratorChecked(.dirnames) catch
        return error.InvalidMetadata) orelse return error.InvalidMetadata;
    for (dirname_values) |*dirname| {
        dirname.* = (dirname_iter.next() catch
            return error.InvalidMetadata) orelse return error.InvalidMetadata;
    }
    var basename_iter = (hdr.stringArrayIteratorChecked(.basenames) catch
        return error.InvalidMetadata) orelse return error.InvalidMetadata;

    for (0..count) |index| {
        const basename = (basename_iter.next() catch
            return error.InvalidMetadata) orelse return error.InvalidMetadata;
        if (states) |values| {
            if (!isTriggerVisibleFileState(values[index])) continue;
        }
        const flags = hdr.u32ArrayItem(.fileflags, index) orelse 0;
        if ((flags & RPMFILE_GHOST) != 0 or
            ((trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOCONFIGS) != 0 and
                (flags & RPMFILE_CONFIG) != 0) or
            ((trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NODOCS) != 0 and
                (flags & (RPMFILE_DOC | RPMFILE_README)) != 0))
        {
            continue;
        }

        const dir_index = hdr.u32ArrayItem(.dirindexes, index) orelse
            return error.InvalidMetadata;
        if (dir_index >= dirname_values.len) return error.InvalidMetadata;
        const dirname = dirname_values[dir_index];
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ dirname, basename },
        );
        defer allocator.free(path);
        if (callback(callback_ctx, path) != 0) {
            return error.CallbackFailed;
        }
    }
}

fn isTriggerVisibleFileState(state: u8) bool {
    return state == RPMFILE_STATE_NORMAL or
        state == RPMFILE_STATE_NETSHARED;
}

fn rejectUnexpectedFilePath(
    _: ?*anyopaque,
    _: []const u8,
) i32 {
    return -1;
}

const MatchedPath = struct {
    path: []const u8,
    source_header: ?header.Header,
};

const FileCandidate = struct {
    owner_index: usize,
    script_index: u32,
    priority: u32,
    matches: []MatchedPath,
};

pub fn runFileTriggers(
    allocator: Allocator,
    owners: []const FileOwner,
    phase: Phase,
    kind: FileKind,
    priority_class: PriorityClass,
    options: FileOptions,
) Error!Result {
    if (shouldSkipFilePhase(phase, kind, options.trans_flags)) {
        return .{
            .ran = false,
            .critical = false,
            .outcome = .not_run,
        };
    }

    var config = if (options.config) |supplied|
        try supplied.clone(allocator)
    else
        try txn_config.TxnConfig.init(allocator, normalizeRoot(options.install_root));
    defer config.deinit();
    for (options.rpmdefines) |define| {
        _ = try config.applyRpmDefine(define);
    }
    var identity_arena = std.heap.ArenaAllocator.init(allocator);
    defer identity_arena.deinit();
    const identity_allocator = identity_arena.allocator();
    var root = if (options.pinned_root_fd) |root_fd| blk: {
        const duplicate = std.c.fcntl(
            root_fd,
            std.c.F.DUPFD_CLOEXEC,
            @as(c_int, 0),
        );
        if (duplicate < 0) return error.SyscallFailed;
        break :blk try install_engine.RootDir.initFromOwnedFd(
            identity_allocator,
            duplicate,
            null,
            null,
        );
    } else try install_engine.RootDir.init(
        identity_allocator,
        config.installRoot(),
        null,
        null,
    );
    defer root.deinit();

    const tags = tagsForKind(kind);
    var candidates = std.ArrayList(FileCandidate).empty;
    defer {
        for (candidates.items) |candidate| {
            allocator.free(candidate.matches);
        }
        candidates.deinit(allocator);
    }

    for (owners, 0..) |owner, owner_index| {
        if (!hasAnyTriggerMetadata(owner.hdr)) continue;
        try validateHeaderScripts(allocator, owner.hdr, &config);
        if (!hasFileTriggerMetadata(owner.hdr, kind)) continue;
        const script_count = owner.hdr.stringArrayCount(tags.scripts);
        for (0..script_count) |script_index| {
            const priority = if (tags.priorities) |priority_tag|
                owner.hdr.u32ArrayItem(priority_tag, script_index) orelse
                    DEFAULT_TRIGGER_PRIORITY
            else
                DEFAULT_TRIGGER_PRIORITY;
            if (!priorityMatchesClass(priority, priority_class)) continue;

            const matches = try collectFileTriggerMatches(
                allocator,
                &root,
                owner,
                tags,
                @intCast(script_index),
                phase,
            );
            if (matches.len == 0) {
                allocator.free(matches);
                continue;
            }
            try candidates.append(allocator, .{
                .owner_index = owner_index,
                .script_index = @intCast(script_index),
                .priority = priority,
                .matches = matches,
            });
        }
    }
    sortFileCandidates(candidates.items, owners);

    var result = Result{
        .ran = false,
        .critical = false,
        .outcome = .not_run,
    };
    for (candidates.items) |candidate| {
        const owner = owners[candidate.owner_index];
        const raw_script_body = owner.hdr.stringArrayItem(
            tags.scripts,
            candidate.script_index,
        ) orelse return error.InvalidMetadata;
        const script_flags = owner.hdr.u32ArrayItem(
            tags.script_flags,
            candidate.script_index,
        ) orelse 0;
        const script_body = try prepareTriggerScriptBody(
            allocator,
            owner.hdr,
            raw_script_body,
            script_flags,
            &config,
        );
        defer allocator.free(script_body);
        const interpreter = try collectFileTriggerInterpreterArgs(
            allocator,
            owner.hdr,
            tags,
            candidate.script_index,
        );
        defer allocator.free(interpreter);

        const input = if (options.suppress_stdin)
            null
        else
            try buildTriggerInput(allocator, candidate.matches);
        defer if (input) |bytes| allocator.free(bytes);

        const script_result = try scriptlet_engine.runPreparedScript(
            allocator,
            interpreter,
            script_body,
            false,
            .{
                .install_root = config.installRoot(),
                .config = &config,
                .trans_flags = options.trans_flags,
                .arg1 = 0,
                .arg2 = null,
                .stdin_data = input,
                .script_fd = options.script_fd,
                .redirect_stdout_to_stderr = options.redirect_stdout_to_stderr,
                .pinned_root_fd = root.fd,
            },
        );
        accumulateResult(&result, script_result);
    }

    return result;
}

fn collectFileTriggerMatches(
    allocator: Allocator,
    root: *const install_engine.RootDir,
    owner: FileOwner,
    tags: TriggerGroupTags,
    script_index: u32,
    phase: Phase,
) Error![]MatchedPath {
    var matches = std.ArrayList(MatchedPath).empty;
    defer matches.deinit(allocator);
    const dependency_count = owner.hdr.stringArrayCount(tags.names);
    const wanted_phase = phaseBit(phase);

    for (0..dependency_count) |dependency_index| {
        const index = owner.hdr.u32ArrayItem(
            tags.indexes,
            dependency_index,
        ) orelse return error.InvalidMetadata;
        if (index != script_index) continue;
        const flags = owner.hdr.u32ArrayItem(
            tags.flags,
            dependency_index,
        ) orelse return error.InvalidMetadata;
        if ((flags & wanted_phase) == 0) continue;
        const prefix = owner.hdr.stringArrayItem(
            tags.names,
            dependency_index,
        ) orelse return error.InvalidMetadata;
        const canonical_prefix = try root.canonicalPathOwned(prefix);

        for (owner.paths) |path| {
            const canonical_path = try root.canonicalPathOwned(path.path);
            if (!std.mem.startsWith(
                u8,
                canonical_path,
                canonical_prefix,
            )) {
                continue;
            }
            try matches.append(allocator, .{
                .path = canonical_path,
                .source_header = path.source_header,
            });
        }
    }

    return matches.toOwnedSlice(allocator);
}

fn priorityMatchesClass(priority: u32, priority_class: PriorityClass) bool {
    return switch (priority_class) {
        .all => true,
        .high => priority >= TRIGGER_PRIORITY_BOUND,
        .low => priority < TRIGGER_PRIORITY_BOUND,
    };
}

fn sortFileCandidates(candidates: []FileCandidate, owners: []const FileOwner) void {
    var index: usize = 1;
    while (index < candidates.len) : (index += 1) {
        var cursor = index;
        while (cursor > 0 and fileCandidateBefore(
            candidates[cursor],
            candidates[cursor - 1],
            owners,
        )) : (cursor -= 1) {
            const previous = candidates[cursor - 1];
            candidates[cursor - 1] = candidates[cursor];
            candidates[cursor] = previous;
        }
    }
}

fn fileCandidateBefore(
    left: FileCandidate,
    right: FileCandidate,
    owners: []const FileOwner,
) bool {
    if (left.priority != right.priority) {
        return left.priority > right.priority;
    }
    const left_order = owners[left.owner_index].order;
    const right_order = owners[right.owner_index].order;
    if (left_order != right_order) {
        return left_order < right_order;
    }
    return left.script_index < right.script_index;
}

fn collectFileTriggerInterpreterArgs(
    allocator: Allocator,
    hdr: header.Header,
    tags: TriggerGroupTags,
    script_index: u32,
) Error![]const []const u8 {
    const args = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(args);
    args[0] = hdr.stringArrayItem(tags.programs, script_index) orelse
        return error.InvalidMetadata;
    return args;
}

fn prepareTriggerScriptBody(
    allocator: Allocator,
    hdr: header.Header,
    raw_body: []const u8,
    flags: u32,
    config: *const txn_config.TxnConfig,
) Error![]u8 {
    var body = try allocator.dupe(u8, raw_body);
    errdefer allocator.free(body);

    if ((flags & RPMSCRIPT_FLAG_EXPAND) != 0) {
        const expanded = try config.expandTextAlloc(allocator, body);
        allocator.free(body);
        body = expanded;
    }
    if ((flags & RPMSCRIPT_FLAG_QFORMAT) != 0) {
        const formatted = try query_format.format(
            allocator,
            hdr,
            body,
            .{ .config = config },
        );
        allocator.free(body);
        body = formatted;
    }
    return body;
}

fn buildTriggerInput(
    allocator: Allocator,
    matches: []const MatchedPath,
) Error![]u8 {
    var total: usize = 0;
    for (matches) |match| {
        total = std.math.add(usize, total, match.path.len) catch
            return error.InvalidCount;
        total = std.math.add(usize, total, 1) catch
            return error.InvalidCount;
    }
    const input = try allocator.alloc(u8, total);
    var offset: usize = 0;
    for (matches) |match| {
        @memcpy(input[offset .. offset + match.path.len], match.path);
        offset += match.path.len;
        input[offset] = '\n';
        offset += 1;
    }
    return input;
}

fn phaseBit(phase: Phase) u32 {
    return switch (phase) {
        .triggerin => RPMSENSE_TRIGGERIN,
        .triggerun => RPMSENSE_TRIGGERUN,
        .triggerpostun => RPMSENSE_TRIGGERPOSTUN,
    };
}

fn shouldSkipFilePhase(
    phase: Phase,
    kind: FileKind,
    trans_flags: u32,
) bool {
    if ((trans_flags & (rpmtrans.TDNF_RPMTRANS_FLAG_TEST |
        rpmtrans.TDNF_RPMTRANS_FLAG_NOSCRIPTS |
        rpmtrans.TDNF_RPMTRANS_FLAG_JUSTDB |
        rpmtrans.TDNF_RPMTRANS_FLAG_NOTRIGGERS)) != 0)
    {
        return true;
    }
    if (switch (phase) {
        .triggerin => (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOTRIGGERIN) != 0,
        .triggerun => (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOTRIGGERUN) != 0,
        .triggerpostun => (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOTRIGGERPOSTUN) != 0,
    }) {
        return true;
    }
    if (kind == .transaction) {
        return switch (phase) {
            .triggerun => (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOPRETRANS) != 0,
            .triggerin, .triggerpostun => (trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOPOSTTRANS) != 0,
        };
    }
    return false;
}

const Db = struct {
    db: ?*c.sqlite3,

    fn openConfig(allocator: Allocator, config: *const txn_config.TxnConfig) Error!Db {
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

    fn reset(self: *Statement) Error!void {
        if (c.sqlite3_reset(self.raw) != c.SQLITE_OK) {
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
        const alignment: usize = switch (entry.typ) {
            @intFromEnum(header.TypeId.int16) => 2,
            @intFromEnum(header.TypeId.int32) => 4,
            @intFromEnum(header.TypeId.int64) => 8,
            else => 1,
        };
        while (data.items.len % alignment != 0) {
            try data.append(allocator, 0);
        }
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

test "file trigger matching preserves overlapping prefix lines" {
    const allocator = std.testing.allocator;
    const scripts = try testStringArrayBytes(allocator, &.{"echo trigger"});
    defer allocator.free(scripts);
    const programs = try testStringArrayBytes(allocator, &.{"/bin/sh"});
    defer allocator.free(programs);
    const names = try testStringArrayBytes(allocator, &.{ "/usr/share/example", "/usr/share/example/file" });
    defer allocator.free(names);
    const versions = try testStringArrayBytes(allocator, &.{ "", "" });
    defer allocator.free(versions);
    const flags = try testU32ArrayBytes(allocator, &.{
        RPMSENSE_TRIGGERIN,
        RPMSENSE_TRIGGERIN,
    });
    defer allocator.free(flags);
    const indexes = try testU32ArrayBytes(allocator, &.{ 0, 0 });
    defer allocator.free(indexes);
    const priorities = try testU32ArrayBytes(allocator, &.{200_000});
    defer allocator.free(priorities);

    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = 6, .count = 1, .data = "owner\x00" },
        .{ .tag = @intFromEnum(header.TagId.filetriggerscripts), .typ = 8, .count = 1, .data = scripts },
        .{ .tag = @intFromEnum(header.TagId.filetriggerscriptprog), .typ = 8, .count = 1, .data = programs },
        .{ .tag = @intFromEnum(header.TagId.filetriggername), .typ = 8, .count = 2, .data = names },
        .{ .tag = @intFromEnum(header.TagId.filetriggerversion), .typ = 8, .count = 2, .data = versions },
        .{ .tag = @intFromEnum(header.TagId.filetriggerflags), .typ = 4, .count = 2, .data = flags },
        .{ .tag = @intFromEnum(header.TagId.filetriggerindex), .typ = 4, .count = 2, .data = indexes },
        .{ .tag = @intFromEnum(header.TagId.filetriggerpriorities), .typ = 4, .count = 1, .data = priorities },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    try validateHeaderMetadata(hdr);
    const paths = [_]TriggerPath{
        .{ .path = "/usr/share/example/file" },
        .{ .path = "/usr/share/example/other" },
    };
    var identity_arena = std.heap.ArenaAllocator.init(allocator);
    defer identity_arena.deinit();
    var root = try install_engine.RootDir.init(
        identity_arena.allocator(),
        "/",
        null,
        null,
    );
    defer root.deinit();
    const matches = try collectFileTriggerMatches(
        allocator,
        &root,
        .{
            .hdr = hdr,
            .paths = &paths,
            .order = 0,
        },
        file_trigger_tags,
        0,
        .triggerin,
    );
    defer allocator.free(matches);

    try std.testing.expectEqual(@as(usize, 3), matches.len);
    try std.testing.expectEqualStrings(paths[0].path, matches[0].path);
    try std.testing.expectEqualStrings(paths[1].path, matches[1].path);
    try std.testing.expectEqualStrings(paths[0].path, matches[2].path);
}

test "file trigger matching canonicalizes trusted root aliases" {
    const allocator = std.testing.allocator;
    var identity_arena = std.heap.ArenaAllocator.init(allocator);
    defer identity_arena.deinit();
    var root = try install_engine.RootDir.init(
        identity_arena.allocator(),
        "/",
        null,
        null,
    );
    defer root.deinit();
    const probe = try root.canonicalPathOwned("/lib/alias-trigger");
    if (!std.mem.eql(u8, probe, "/usr/lib/alias-trigger")) {
        return error.SkipZigTest;
    }
    const names = try testStringArrayBytes(
        allocator,
        &.{"/lib/alias-trigger"},
    );
    defer allocator.free(names);
    const flags = try testU32ArrayBytes(
        allocator,
        &.{RPMSENSE_TRIGGERIN},
    );
    defer allocator.free(flags);
    const indexes = try testU32ArrayBytes(allocator, &.{0});
    defer allocator.free(indexes);
    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.filetriggername), .typ = 8, .count = 1, .data = names },
        .{ .tag = @intFromEnum(header.TagId.filetriggerflags), .typ = 4, .count = 1, .data = flags },
        .{ .tag = @intFromEnum(header.TagId.filetriggerindex), .typ = 4, .count = 1, .data = indexes },
    });
    defer allocator.free(blob);
    const hdr = try header.Header.parse(blob);
    const paths = [_]TriggerPath{
        .{ .path = "/usr/lib/alias-trigger/file" },
    };
    const matches = try collectFileTriggerMatches(
        allocator,
        &root,
        .{ .hdr = hdr, .paths = &paths, .order = 0 },
        file_trigger_tags,
        0,
        .triggerin,
    );
    defer allocator.free(matches);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings(
        "/usr/lib/alias-trigger/file",
        matches[0].path,
    );
}

test "trigger metadata validation rejects mismatched file trigger arrays" {
    const allocator = std.testing.allocator;
    const scripts = try testStringArrayBytes(allocator, &.{"echo trigger"});
    defer allocator.free(scripts);
    const names = try testStringArrayBytes(allocator, &.{"/usr/share/example"});
    defer allocator.free(names);
    const versions = try testStringArrayBytes(allocator, &.{""});
    defer allocator.free(versions);
    const flags = try testU32ArrayBytes(allocator, &.{RPMSENSE_TRIGGERIN});
    defer allocator.free(flags);
    const indexes = try testU32ArrayBytes(allocator, &.{ 0, 0 });
    defer allocator.free(indexes);

    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.filetriggerscripts), .typ = 8, .count = 1, .data = scripts },
        .{ .tag = @intFromEnum(header.TagId.filetriggername), .typ = 8, .count = 1, .data = names },
        .{ .tag = @intFromEnum(header.TagId.filetriggerversion), .typ = 8, .count = 1, .data = versions },
        .{ .tag = @intFromEnum(header.TagId.filetriggerflags), .typ = 4, .count = 1, .data = flags },
        .{ .tag = @intFromEnum(header.TagId.filetriggerindex), .typ = 4, .count = 2, .data = indexes },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    try std.testing.expectError(
        error.InvalidMetadata,
        validateHeaderMetadata(hdr),
    );
}

test "trigger metadata validation requires a program per script" {
    const allocator = std.testing.allocator;
    const scripts = try testStringArrayBytes(allocator, &.{"echo trigger"});
    defer allocator.free(scripts);
    const names = try testStringArrayBytes(allocator, &.{"/usr/share/example"});
    defer allocator.free(names);
    const versions = try testStringArrayBytes(allocator, &.{""});
    defer allocator.free(versions);
    const flags = try testU32ArrayBytes(allocator, &.{RPMSENSE_TRIGGERIN});
    defer allocator.free(flags);
    const indexes = try testU32ArrayBytes(allocator, &.{0});
    defer allocator.free(indexes);

    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.filetriggerscripts), .typ = 8, .count = 1, .data = scripts },
        .{ .tag = @intFromEnum(header.TagId.filetriggername), .typ = 8, .count = 1, .data = names },
        .{ .tag = @intFromEnum(header.TagId.filetriggerversion), .typ = 8, .count = 1, .data = versions },
        .{ .tag = @intFromEnum(header.TagId.filetriggerflags), .typ = 4, .count = 1, .data = flags },
        .{ .tag = @intFromEnum(header.TagId.filetriggerindex), .typ = 4, .count = 1, .data = indexes },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    try std.testing.expectError(
        error.InvalidMetadata,
        validateHeaderMetadata(hdr),
    );
}

test "fileless header has no trigger files" {
    const allocator = std.testing.allocator;
    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = 6, .count = 1, .data = "fileless\x00" },
    });
    defer allocator.free(blob);

    const hdr = try header.Header.parse(blob);
    try forEachTriggerFile(
        allocator,
        hdr,
        0,
        rejectUnexpectedFilePath,
        null,
    );
}

test "trigger script flags expand macros before query format" {
    const allocator = std.testing.allocator;
    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = 6, .count = 1, .data = "flag-owner\x00" },
        .{ .tag = @intFromEnum(header.TagId.version), .typ = 6, .count = 1, .data = "2.0\x00" },
        .{ .tag = @intFromEnum(header.TagId.release), .typ = 6, .count = 1, .data = "1\x00" },
        .{ .tag = @intFromEnum(header.TagId.arch), .typ = 6, .count = 1, .data = "noarch\x00" },
    });
    defer allocator.free(blob);
    const hdr = try header.Header.parse(blob);

    var config = try txn_config.TxnConfig.init(allocator, "/");
    defer config.deinit();
    try config.setMacroByName("trigger_value", "expanded");

    const body = try prepareTriggerScriptBody(
        allocator,
        hdr,
        "echo %{trigger_value} %{NAME}-%{VERSION} %%done",
        RPMSCRIPT_FLAG_EXPAND | RPMSCRIPT_FLAG_QFORMAT,
        &config,
    );
    defer allocator.free(body);
    try std.testing.expectEqualStrings(
        "echo expanded flag-owner-2.0 %done",
        body,
    );
}

test "trigger query format supports modifiers iterators and conditionals" {
    const allocator = std.testing.allocator;
    const basenames = try testStringArrayBytes(
        allocator,
        &.{ "alpha", "beta" },
    );
    defer allocator.free(basenames);
    const dirnames = try testStringArrayBytes(allocator, &.{"/opt/test/"});
    defer allocator.free(dirnames);
    const dirindexes = try testU32ArrayBytes(allocator, &.{ 0, 0 });
    defer allocator.free(dirindexes);
    const filemodes = try testU32ArrayBytes(
        allocator,
        &.{ 0o100644, 0o040755 },
    );
    defer allocator.free(filemodes);
    const fileflags = try testU32ArrayBytes(allocator, &.{ 17, 0 });
    defer allocator.free(fileflags);
    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = 6, .count = 1, .data = "owner's\x00" },
        .{ .tag = @intFromEnum(header.TagId.version), .typ = 6, .count = 1, .data = "2.0\x00" },
        .{ .tag = @intFromEnum(header.TagId.release), .typ = 6, .count = 1, .data = "1\x00" },
        .{ .tag = @intFromEnum(header.TagId.build_time), .typ = 4, .count = 1, .data = "\x00\x00\x03\xe8" },
        .{ .tag = @intFromEnum(header.TagId.basenames), .typ = 8, .count = 2, .data = basenames },
        .{ .tag = @intFromEnum(header.TagId.dirnames), .typ = 8, .count = 1, .data = dirnames },
        .{ .tag = @intFromEnum(header.TagId.dirindexes), .typ = 4, .count = 2, .data = dirindexes },
        .{ .tag = @intFromEnum(header.TagId.filemodes), .typ = 4, .count = 2, .data = filemodes },
        .{ .tag = @intFromEnum(header.TagId.fileflags), .typ = 4, .count = 2, .data = fileflags },
    });
    defer allocator.free(blob);
    const hdr = try header.Header.parse(blob);

    const rendered = try query_format.format(
        allocator,
        hdr,
        "[%{=NAME:shescape}|%{FILENAMES}|%{FILEMODES:perms}|" ++
            "%{FILEFLAGS:fflags}\\n]" ++
            "%|EPOCH?{epoch}:{%|NAME?{none}:{missing}|}|:" ++
            "%{BUILDTIME:hex}:%{BUILDTIME:octal}:" ++
            "%{BASENAMES:arraysize}",
        .{},
    );
    defer allocator.free(rendered);
    try std.testing.expectEqualStrings(
        "'owner'\\''s'|/opt/test/alpha|-rw-r--r--|cn\n" ++
            "'owner'\\''s'|/opt/test/beta|drwxr-xr-x|\n" ++
            "none:3e8:1750:2",
        rendered,
    );
}

test "trigger query format rejects invalid input explicitly" {
    const allocator = std.testing.allocator;
    const basenames = try testStringArrayBytes(
        allocator,
        &.{ "alpha", "beta" },
    );
    defer allocator.free(basenames);
    const blob = try buildTestHeaderBlob(allocator, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = 6, .count = 1, .data = "owner\x00" },
        .{ .tag = @intFromEnum(header.TagId.basenames), .typ = 8, .count = 2, .data = basenames },
    });
    defer allocator.free(blob);
    const hdr = try header.Header.parse(blob);

    try std.testing.expectError(
        error.MismatchedQueryArrays,
        query_format.validate(
            allocator,
            hdr,
            "[%{NAME}%{BASENAMES}]",
            .{},
        ),
    );
    try std.testing.expectError(
        error.UnsupportedQueryModifier,
        query_format.validate(
            allocator,
            hdr,
            "%{NAME:not-a-format}",
            .{},
        ),
    );
    try std.testing.expectError(
        error.MalformedQueryFormat,
        query_format.validate(
            allocator,
            hdr,
            "%|NAME?{present}:{absent}",
            .{},
        ),
    );
}

test "normal and netshared file states are trigger visible" {
    try std.testing.expect(isTriggerVisibleFileState(RPMFILE_STATE_NORMAL));
    try std.testing.expect(isTriggerVisibleFileState(RPMFILE_STATE_NETSHARED));
    try std.testing.expect(!isTriggerVisibleFileState(1));
    try std.testing.expect(!isTriggerVisibleFileState(2));
}
