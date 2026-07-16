const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("tdnferror.h");
    @cInclude("tdnfrepomd.h");
    @cInclude("rpmdb.h");
});

const model = @import("model.zig");
const pkgquery = @import("pkgquery.zig");
const query_index = @import("index.zig");
const rpmpkg = @import("rpmpkg.zig");
const rpm_header = @import("rpm_header");
const rpm_pkgfile = @import("rpm_pkgfile");

threadlocal var last_error_buf: [512]u8 = undefined;
threadlocal var last_error_len: usize = 0;

const sense_posttrans: u32 = 1 << 5;
const sense_prereq: u32 = 1 << 6;
const sense_pretrans: u32 = 1 << 7;
const sense_script_pre: u32 = 1 << 9;
const sense_script_post: u32 = 1 << 10;
const sense_script_preun: u32 = 1 << 11;
const sense_script_postun: u32 = 1 << 12;
const sense_script_verify: u32 = 1 << 13;
const sense_preuntrans: u32 = 1 << 20;
const sense_postuntrans: u32 = 1 << 21;
const sense_rpmlib: u32 = 1 << 24;
const sense_keyring: u32 = 1 << 26;
const sense_config: u32 = 1 << 28;
const sense_meta: u32 = 1 << 29;

const force_order_only_mask: u32 =
    sense_script_pre |
    sense_script_post |
    sense_script_preun |
    sense_script_postun;
const unordered_only_mask: u32 =
    sense_rpmlib |
    sense_config |
    sense_pretrans |
    sense_posttrans |
    sense_preuntrans |
    sense_postuntrans |
    sense_script_verify |
    sense_meta;
const special_final_check_mask: u32 =
    sense_rpmlib |
    sense_keyring |
    sense_config |
    sense_script_verify |
    sense_meta |
    sense_preuntrans |
    sense_postuntrans;

const order_dep_kinds = [_]model.DependencyKind{
    .requires,
};

const all_dep_kinds = [_]model.DependencyKind{
    .provides,
    .requires,
    .conflicts,
    .obsoletes,
    .recommends,
    .suggests,
    .supplements,
    .enhances,
};

const TransactionError = error{
    OutOfMemory,
    InvalidParameter,
    InvalidRpmHeader,
    FileNotFound,
    AccessDenied,
    NameTooLong,
    BadPathName,
    NotDir,
    IsDir,
    FileTooBig,
    StreamTooLong,
    FileSystemIo,
    UnsupportedCompressor,
    DecompressFailed,
    RpmDbOpenFailed,
    RpmDbReadFailed,
};

const PackageView = struct {
    pkg: model.Package,
    relations: []const model.Relation,
    files: []const model.FileEntry,

    fn relationEntries(self: PackageView, kind: model.DependencyKind) []const model.Relation {
        return self.pkg.relationsFor(kind, self.relations);
    }

    fn fileEntries(self: PackageView) []const model.FileEntry {
        return self.pkg.fileEntries(self.files);
    }
};

const TransactionOperation = enum(u32) {
    install = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_INSTALL,
    reinstall = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_REINSTALL,
    erase = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE,
    upgrade = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_UPGRADE,
};

const TransactionInput = struct {
    operation: u32,
    path: ?[]const u8,
    name: ?[]const u8,
    evr: ?[]const u8,
    arch: ?[]const u8,
    rpmdb_hnum: u32,
    header_blob: ?[]const u8 = null,
    package_size: ?u64 = null,
};

const VerifiedTransactionItems = struct {
    items: []const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    headers: []const ?[*]const u8,
    header_lengths: []const usize,
    package_sizes: []const u64,
};

const RawTransactionItems = union(enum) {
    legacy_paths: []const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    paths_v2: []const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    verified: VerifiedTransactionItems,
};

const TransactionPackage = struct {
    input_index: usize,
    op: TransactionOperation,
    view: PackageView,
};

const EvrParts = struct {
    epoch: ?u32 = null,
    version: []const u8 = "",
    release: ?[]const u8 = null,
};

const EraseQuery = struct {
    name: []const u8,
    evr: EvrParts,
    arch: ?[]const u8 = null,
};

const ParsedTransaction = struct {
    added: std.array_list.Managed(TransactionPackage),
    erased: std.array_list.Managed(TransactionPackage),
    erase_mask: []bool,
    replace_mask: []bool,
    priors: []std.array_list.Managed(u32),

    fn init(
        allocator: std.mem.Allocator,
        installed_count: usize,
        input_count: usize,
    ) !ParsedTransaction {
        const priors = try allocator.alloc(std.array_list.Managed(u32), input_count);
        for (priors) |*prior| {
            prior.* = std.array_list.Managed(u32).init(allocator);
        }
        return .{
            .added = std.array_list.Managed(TransactionPackage).init(allocator),
            .erased = std.array_list.Managed(TransactionPackage).init(allocator),
            .erase_mask = try allocator.alloc(bool, installed_count),
            .replace_mask = try allocator.alloc(bool, installed_count),
            .priors = priors,
        };
    }
};

const InstalledRepository = struct {
    repository: model.RepositoryModel,
    hnums: []const u32,
};

const FinalBuildResult = struct {
    repository: model.RepositoryModel,
    installed_to_final: []?usize,
    added_to_final: []usize,
    added_base: usize,
};

const RepositoryBuilder = struct {
    allocator: std.mem.Allocator,
    packages: std.array_list.Managed(model.Package),
    relations: std.array_list.Managed(model.Relation),
    files: std.array_list.Managed(model.FileEntry),

    fn init(allocator: std.mem.Allocator) RepositoryBuilder {
        return .{
            .allocator = allocator,
            .packages = std.array_list.Managed(model.Package).init(allocator),
            .relations = std.array_list.Managed(model.Relation).init(allocator),
            .files = std.array_list.Managed(model.FileEntry).init(allocator),
        };
    }

    fn appendPackageView(self: *RepositoryBuilder, view: PackageView) !usize {
        var pkg = view.pkg;
        inline for (all_dep_kinds) |kind| {
            const entries = view.relationEntries(kind);
            pkg.rangePtr(kind).* = .{
                .start = self.relations.items.len,
                .len = entries.len,
            };
            try self.relations.appendSlice(entries);
        }

        const file_entries = view.fileEntries();
        pkg.files = .{
            .start = self.files.items.len,
            .len = file_entries.len,
        };
        try self.files.appendSlice(file_entries);

        const index = self.packages.items.len;
        try self.packages.append(pkg);
        return index;
    }

    fn finish(self: *RepositoryBuilder) !model.RepositoryModel {
        return .{
            .packages = try self.packages.toOwnedSlice(),
            .relations = try self.relations.toOwnedSlice(),
            .files = try self.files.toOwnedSlice(),
        };
    }
};

const ProblemKind = enum(u32) {
    dependency = c.TDNF_REPOMD_NATIVE_PROBLEM_DEPENDENCY,
    pretrans = c.TDNF_REPOMD_NATIVE_PROBLEM_PRETRANS,
    conflict = c.TDNF_REPOMD_NATIVE_PROBLEM_CONFLICT,
    obsoletes = c.TDNF_REPOMD_NATIVE_PROBLEM_OBSOLETES,
    file_conflict = c.TDNF_REPOMD_NATIVE_PROBLEM_FILE_CONFLICT,
    unsupported_multiple = c.TDNF_REPOMD_NATIVE_PROBLEM_UNSUPPORTED_MULTIPLE,
};

const NativeProblem = struct {
    kind: ProblemKind,
    input_index: usize,
    package: []const u8,
    related_package: ?[]const u8 = null,
    subject: []const u8,
    count: u32 = 0,
};

const ProblemCollector = struct {
    problems: std.array_list.Managed(NativeProblem),

    fn init(allocator: std.mem.Allocator) ProblemCollector {
        return .{
            .problems = std.array_list.Managed(NativeProblem).init(allocator),
        };
    }

    fn add(self: *ProblemCollector, problem: NativeProblem) !void {
        for (self.problems.items) |existing| {
            if (existing.kind == problem.kind and
                existing.input_index == problem.input_index and
                existing.count == problem.count and
                std.mem.eql(u8, existing.package, problem.package) and
                optionalStringEqual(existing.related_package, problem.related_package) and
                std.mem.eql(u8, existing.subject, problem.subject))
            {
                return;
            }
        }
        try self.problems.append(problem);
    }
};

fn optionalStringEqual(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null or right == null) {
        return left == null and right == null;
    }
    return std.mem.eql(u8, left.?, right.?);
}

fn clearError() void {
    last_error_len = 0;
}

fn setError(comptime fmt: []const u8, args: anytype) void {
    const msg = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
        const fallback = "(rpmzig transaction error truncated)";
        @memcpy(last_error_buf[0..fallback.len], fallback);
        break :blk last_error_buf[0..fallback.len];
    };
    last_error_len = msg.len;
}

pub export fn TDNFRepoMdNativeTransactionLastError() [*:0]const u8 {
    if (last_error_len >= last_error_buf.len) {
        last_error_len = last_error_buf.len - 1;
    }
    last_error_buf[last_error_len] = 0;
    return @ptrCast(&last_error_buf);
}

pub export fn TDNFRepoMdNativeTransactionSolve(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    out_order_lines: ?*[*c][*c]u8,
    out_order_count: ?*u32,
    out_problem_lines: ?*[*c][*c]u8,
    out_problem_count: ?*u32,
) u32 {
    return transactionSolveLegacy(
        raw_items,
        item_count,
        root_dir,
        null,
        false,
        out_order_lines,
        out_order_count,
        out_problem_lines,
        out_problem_count,
    );
}

pub export fn TDNFRepoMdNativeTransactionSolveV2(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    out_order_lines: ?*[*c][*c]u8,
    out_order_count: ?*u32,
    out_problem_lines: ?*[*c][*c]u8,
    out_problem_count: ?*u32,
) u32 {
    return transactionSolveV2(
        raw_items,
        item_count,
        root_dir,
        null,
        false,
        out_order_lines,
        out_order_count,
        out_problem_lines,
        out_problem_count,
    );
}

pub export fn TDNFRepoMdNativeTransactionSolveConfig(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    item_count: u32,
    config: ?*const c.tdnf_rpm_config,
    out_order_lines: ?*[*c][*c]u8,
    out_order_count: ?*u32,
    out_problem_lines: ?*[*c][*c]u8,
    out_problem_count: ?*u32,
) u32 {
    return transactionSolveLegacy(
        raw_items,
        item_count,
        null,
        config,
        true,
        out_order_lines,
        out_order_count,
        out_problem_lines,
        out_problem_count,
    );
}

pub export fn TDNFRepoMdNativeTransactionSolveConfigV2(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    item_count: u32,
    config: ?*const c.tdnf_rpm_config,
    out_order_lines: ?*[*c][*c]u8,
    out_order_count: ?*u32,
    out_problem_lines: ?*[*c][*c]u8,
    out_problem_count: ?*u32,
) u32 {
    return transactionSolveV2(
        raw_items,
        item_count,
        null,
        config,
        true,
        out_order_lines,
        out_order_count,
        out_problem_lines,
        out_problem_count,
    );
}

pub export fn TDNFRepoMdNativeTransactionPlanSolve(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    out_plan: ?*?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) u32 {
    return transactionPlanSolveLegacy(
        raw_items,
        item_count,
        root_dir,
        null,
        false,
        out_plan,
    );
}

pub export fn TDNFRepoMdNativeTransactionPlanSolveV2(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    out_plan: ?*?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) u32 {
    return transactionPlanSolveV2(
        raw_items,
        item_count,
        root_dir,
        null,
        false,
        out_plan,
    );
}

pub export fn TDNFRepoMdNativeTransactionPlanSolveConfig(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    item_count: u32,
    config: ?*const c.tdnf_rpm_config,
    out_plan: ?*?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) u32 {
    return transactionPlanSolveLegacy(
        raw_items,
        item_count,
        null,
        config,
        true,
        out_plan,
    );
}

pub export fn TDNFRepoMdNativeTransactionPlanSolveConfigV2(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    item_count: u32,
    config: ?*const c.tdnf_rpm_config,
    out_plan: ?*?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) u32 {
    return transactionPlanSolveV2(
        raw_items,
        item_count,
        null,
        config,
        true,
        out_plan,
    );
}

fn verifiedTransactionSolveConfig(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    raw_headers: ?[*]const ?[*]const u8,
    raw_header_lengths: ?[*]const usize,
    raw_package_sizes: ?[*]const u64,
    item_count: u32,
    config: ?*const c.tdnf_rpm_config,
    out_plan: ?*?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) callconv(.c) u32 {
    clearError();
    const plan_out = out_plan orelse
        return invalidParameter("null verified transaction plan output", .{});
    plan_out.* = null;
    if (config == null) {
        return invalidParameter("null rpm config", .{});
    }
    const items = if (raw_items) |ptr|
        ptr[0..item_count]
    else if (item_count == 0)
        &[_]c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2{}
    else
        return invalidParameter("null verified transaction input", .{});
    const headers = if (raw_headers) |ptr|
        ptr[0..item_count]
    else if (item_count == 0)
        &[_]?[*]const u8{}
    else
        return invalidParameter("null verified transaction headers", .{});
    const header_lengths = if (raw_header_lengths) |ptr|
        ptr[0..item_count]
    else if (item_count == 0)
        &[_]usize{}
    else
        return invalidParameter("null verified transaction header lengths", .{});
    const package_sizes = if (raw_package_sizes) |ptr|
        ptr[0..item_count]
    else if (item_count == 0)
        &[_]u64{}
    else
        return invalidParameter("null verified transaction package sizes", .{});
    return buildOwnedPlan(
        .{ .verified = .{
            .items = items,
            .headers = headers,
            .header_lengths = header_lengths,
            .package_sizes = package_sizes,
        } },
        null,
        config,
        plan_out,
    );
}

comptime {
    @export(&verifiedTransactionSolveConfig, .{
        .name = "tdnf_repomd_native_verified_transaction_solve_config",
        .visibility = .hidden,
    });
}

fn transactionSolveLegacy(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
    config_required: bool,
    out_order_lines: ?*[*c][*c]u8,
    out_order_count: ?*u32,
    out_problem_lines: ?*[*c][*c]u8,
    out_problem_count: ?*u32,
) u32 {
    return transactionSolveTyped(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
        raw_items,
        item_count,
        root_dir,
        config,
        config_required,
        out_order_lines,
        out_order_count,
        out_problem_lines,
        out_problem_count,
    );
}

fn transactionSolveV2(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
    config_required: bool,
    out_order_lines: ?*[*c][*c]u8,
    out_order_count: ?*u32,
    out_problem_lines: ?*[*c][*c]u8,
    out_problem_count: ?*u32,
) u32 {
    return transactionSolveTyped(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
        raw_items,
        item_count,
        root_dir,
        config,
        config_required,
        out_order_lines,
        out_order_count,
        out_problem_lines,
        out_problem_count,
    );
}

fn transactionSolveTyped(
    comptime Item: type,
    raw_items: ?[*]const Item,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
    config_required: bool,
    out_order_lines: ?*[*c][*c]u8,
    out_order_count: ?*u32,
    out_problem_lines: ?*[*c][*c]u8,
    out_problem_count: ?*u32,
) u32 {
    clearError();
    if (out_order_lines) |out| out.* = null;
    if (out_order_count) |out| out.* = 0;
    if (out_problem_lines) |out| out.* = null;
    if (out_problem_count) |out| out.* = 0;
    const order_out = out_order_lines orelse return invalidParameter("null order output", .{});
    const order_count_out = out_order_count orelse return invalidParameter("null order count output", .{});
    const problem_out = out_problem_lines orelse return invalidParameter("null problem output", .{});
    const problem_count_out = out_problem_count orelse return invalidParameter("null problem count output", .{});
    if (config_required and config == null) {
        return invalidParameter("null rpm config", .{});
    }
    const items = if (raw_items) |ptr|
        ptr[0..item_count]
    else if (item_count == 0)
        &[_]Item{}
    else
        return invalidParameter("null transaction input", .{});
    const normalized_items: RawTransactionItems =
        if (Item == c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM)
            .{ .legacy_paths = items }
        else
            .{ .paths_v2 = items };

    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const result = solveTransaction(
        arena,
        normalized_items,
        root_dir,
        config,
    ) catch |err| {
        return mapTransactionError(err);
    };

    const problem_lines = formatProblemLines(arena, result.problems) catch {
        return mapTransactionError(error.OutOfMemory);
    };
    const problem_array = (tryBuildCStringArray(problem_lines) catch |err| {
        return mapTransactionError(err);
    }) orelse null;

    const order_lines = buildIndexLines(arena, result.order) catch |err| {
        freeCStringArray(problem_array);
        return mapTransactionError(err);
    };
    const order_array = (tryBuildCStringArray(order_lines) catch |err| {
        freeCStringArray(problem_array);
        return mapTransactionError(err);
    }) orelse null;
    order_out.* = order_array;
    order_count_out.* = @intCast(result.order.len);

    problem_out.* = problem_array;
    problem_count_out.* = @intCast(problem_lines.len);
    return 0;
}

fn transactionPlanSolveLegacy(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
    config_required: bool,
    out_plan: ?*?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) u32 {
    return transactionPlanSolveTyped(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
        raw_items,
        item_count,
        root_dir,
        config,
        config_required,
        out_plan,
    );
}

fn transactionPlanSolveV2(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
    config_required: bool,
    out_plan: ?*?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) u32 {
    return transactionPlanSolveTyped(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
        raw_items,
        item_count,
        root_dir,
        config,
        config_required,
        out_plan,
    );
}

fn transactionPlanSolveTyped(
    comptime Item: type,
    raw_items: ?[*]const Item,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
    config_required: bool,
    out_plan: ?*?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) u32 {
    clearError();
    const plan_out = out_plan orelse
        return invalidParameter("null transaction plan output", .{});
    plan_out.* = null;
    if (config_required and config == null) {
        return invalidParameter("null rpm config", .{});
    }
    const items = if (raw_items) |ptr|
        ptr[0..item_count]
    else if (item_count == 0)
        &[_]Item{}
    else
        return invalidParameter("null transaction input", .{});
    const normalized_items: RawTransactionItems =
        if (Item == c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM)
            .{ .legacy_paths = items }
        else
            .{ .paths_v2 = items };
    return buildOwnedPlan(normalized_items, root_dir, config, plan_out);
}

const SolveResult = struct {
    order: []const usize,
    problems: []const NativeProblem,
    priors: []const std.array_list.Managed(u32),
};

fn solveTransaction(
    arena: std.mem.Allocator,
    raw_items: RawTransactionItems,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
) TransactionError!SolveResult {
    const items = try normalizeTransactionItems(arena, raw_items);
    const installed = try loadInstalledRepositoryModel(arena, root_dir, config);
    var tx = try parseTransaction(arena, items, installed);
    const final_build = try buildFinalRepository(arena, installed.repository, &tx);

    var installed_index = query_index.RepositoryIndex.init(
        arena,
        &installed.repository,
    ) catch return error.OutOfMemory;
    var final_index = query_index.RepositoryIndex.init(
        arena,
        &final_build.repository,
    ) catch return error.OutOfMemory;
    var problems = ProblemCollector.init(arena);
    try collectNativeProblems(
        arena,
        &problems,
        &tx,
        installed.repository,
        final_build,
        &installed_index,
        &final_index,
        config,
    );
    try collectMultiplicityProblems(arena, &problems, &tx);

    const order = try buildNativeOrder(arena, tx.added.items, tx.erased.items);
    try validateOrderPermutation(arena, order, items.len);

    return .{
        .order = order,
        .problems = try problems.problems.toOwnedSlice(),
        .priors = tx.priors,
    };
}

fn buildOwnedPlan(
    raw_items: RawTransactionItems,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
    out_plan: *?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) u32 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const result = solveTransaction(arena, raw_items, root_dir, config) catch |err| {
        return mapTransactionError(err);
    };
    const plan = createOwnedPlan(result) catch |err| {
        return mapTransactionError(err);
    };
    out_plan.* = plan;
    return 0;
}

fn createOwnedPlan(
    result: SolveResult,
) TransactionError!*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN {
    const raw_plan = c.calloc(
        1,
        @sizeOf(c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN),
    ) orelse return error.OutOfMemory;
    const plan: *c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN =
        @ptrCast(@alignCast(raw_plan));
    errdefer freeOwnedPlan(plan);

    plan.dwItemCount = std.math.cast(u32, result.order.len) orelse
        return error.InvalidParameter;
    plan.pdwOrderIndices = (tryBuildIndexArray(result.order) catch |err|
        return mapPlanBuildError(err)) orelse null;

    if (result.priors.len != result.order.len) {
        return error.InvalidParameter;
    }
    if (result.priors.len != 0) {
        const raw_items = c.calloc(
            result.priors.len,
            @sizeOf(c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN_ITEM),
        ) orelse return error.OutOfMemory;
        plan.pItems = @ptrCast(@alignCast(raw_items));
    }

    var prior_count: usize = 0;
    for (result.priors) |prior| {
        prior_count = std.math.add(usize, prior_count, prior.items.len) catch
            return error.OutOfMemory;
    }
    plan.dwPriorHnumCount = std.math.cast(u32, prior_count) orelse
        return error.InvalidParameter;
    if (prior_count != 0) {
        const raw_priors = c.calloc(prior_count, @sizeOf(u32)) orelse
            return error.OutOfMemory;
        plan.pdwPriorHnums = @ptrCast(@alignCast(raw_priors));
    }

    var prior_offset: usize = 0;
    for (result.priors, 0..) |prior, index| {
        plan.pItems[index].dwPriorOffset = @intCast(prior_offset);
        plan.pItems[index].dwPriorCount = @intCast(prior.items.len);
        for (prior.items) |hnum| {
            plan.pdwPriorHnums[prior_offset] = hnum;
            prior_offset += 1;
        }
    }

    plan.dwProblemCount = std.math.cast(u32, result.problems.len) orelse
        return error.InvalidParameter;
    if (result.problems.len != 0) {
        const raw_problems = c.calloc(
            result.problems.len,
            @sizeOf(c.TDNF_REPOMD_NATIVE_TRANSACTION_PROBLEM),
        ) orelse return error.OutOfMemory;
        plan.pProblems = @ptrCast(@alignCast(raw_problems));
    }
    for (result.problems, 0..) |problem, index| {
        const out = &plan.pProblems[index];
        out.nType = @intFromEnum(problem.kind);
        out.dwInputIndex = std.math.cast(u32, problem.input_index) orelse
            std.math.maxInt(u32);
        out.pszPackage = try dupCString(problem.package);
        if (problem.related_package) |related| {
            out.pszRelatedPackage = try dupCString(related);
        }
        out.pszSubject = try dupCString(problem.subject);
        out.dwCount = problem.count;
    }
    return plan;
}

fn mapPlanBuildError(err: anyerror) TransactionError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidParameter,
    };
}

pub export fn TDNFRepoMdNativeTransactionPlanFree(
    plan: ?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN,
) void {
    freeOwnedPlan(plan);
}

fn freeOwnedPlan(plan_raw: ?*c.TDNF_REPOMD_NATIVE_TRANSACTION_PLAN) void {
    const plan = plan_raw orelse return;
    if (plan.pProblems != null) {
        for (plan.pProblems[0..plan.dwProblemCount]) |problem| {
            if (problem.pszPackage != null) c.free(@constCast(problem.pszPackage));
            if (problem.pszRelatedPackage != null) c.free(@constCast(problem.pszRelatedPackage));
            if (problem.pszSubject != null) c.free(@constCast(problem.pszSubject));
        }
        c.free(plan.pProblems);
    }
    if (plan.pdwPriorHnums != null) c.free(plan.pdwPriorHnums);
    if (plan.pItems != null) c.free(plan.pItems);
    if (plan.pdwOrderIndices != null) c.free(plan.pdwOrderIndices);
    c.free(plan);
}

fn invalidParameter(comptime fmt: []const u8, args: anytype) u32 {
    setError(fmt, args);
    return c.ERROR_TDNF_INVALID_PARAMETER;
}

fn mapTransactionError(err: anyerror) u32 {
    return switch (err) {
        error.OutOfMemory => c.ERROR_TDNF_OUT_OF_MEMORY,
        error.InvalidParameter => blk: {
            if (last_error_len == 0) {
                setError("invalid transaction input", .{});
            }
            break :blk c.ERROR_TDNF_INVALID_PARAMETER;
        },
        error.InvalidRpmHeader => blk: {
            if (last_error_len == 0) {
                setError("invalid rpm header", .{});
            }
            break :blk c.ERROR_TDNF_RPM_HEADER_CONVERT_FAILED;
        },
        error.FileNotFound => blk: {
            if (last_error_len == 0) {
                setError("file not found", .{});
            }
            break :blk c.ERROR_TDNF_FILE_NOT_FOUND;
        },
        error.AccessDenied => blk: {
            if (last_error_len == 0) {
                setError("access denied", .{});
            }
            break :blk c.ERROR_TDNF_ACCESS_DENIED;
        },
        error.NameTooLong => blk: {
            if (last_error_len == 0) {
                setError("path too long", .{});
            }
            break :blk c.ERROR_TDNF_NAME_TOO_LONG;
        },
        error.BadPathName => blk: {
            if (last_error_len == 0) {
                setError("bad path", .{});
            }
            break :blk c.ERROR_TDNF_INVALID_PARAMETER;
        },
        error.NotDir, error.IsDir => blk: {
            if (last_error_len == 0) {
                setError("invalid directory", .{});
            }
            break :blk c.ERROR_TDNF_INVALID_DIR;
        },
        error.FileTooBig, error.StreamTooLong => blk: {
            if (last_error_len == 0) {
                setError("file too large", .{});
            }
            break :blk c.ERROR_TDNF_OVERFLOW;
        },
        error.UnsupportedCompressor, error.DecompressFailed => blk: {
            if (last_error_len == 0) {
                setError("failed to parse rpm payload", .{});
            }
            break :blk c.ERROR_TDNF_INVALID_REPO_FILE;
        },
        error.FileSystemIo => blk: {
            if (last_error_len == 0) {
                setError("filesystem io error", .{});
            }
            break :blk c.ERROR_TDNF_FILESYS_IO;
        },
        error.RpmDbOpenFailed => blk: {
            if (last_error_len == 0) {
                setError("failed to open rpmdb: {s}", .{std.mem.span(c.tdnf_rpmdb_last_error())});
            }
            break :blk c.ERROR_TDNF_RPMTS_OPENDB_FAILED;
        },
        error.RpmDbReadFailed => blk: {
            if (last_error_len == 0) {
                setError("failed to read rpmdb: {s}", .{std.mem.span(c.tdnf_rpmdb_last_error())});
            }
            break :blk c.ERROR_TDNF_SOLV_IO;
        },
        else => blk: {
            if (last_error_len == 0) {
                setError("native transaction failure: {t}", .{err});
            }
            break :blk c.ERROR_TDNF_SOLV_IO;
        },
    };
}

fn loadInstalledRepositoryModel(
    arena: std.mem.Allocator,
    root_dir: ?[*:0]const u8,
    config: ?*const c.tdnf_rpm_config,
) TransactionError!InstalledRepository {
    var builder = RepositoryBuilder.init(arena);
    var hnums = std.array_list.Managed(u32).init(arena);
    const iter = if (config) |rpm_config|
        c.tdnf_rpmdb_iter_open_config(rpm_config)
    else
        c.tdnf_rpmdb_iter_open(root_dir) orelse return error.RpmDbOpenFailed;
    defer c.tdnf_rpmdb_iter_close(iter);

    while (true) {
        var blob_ptr: ?[*]const u8 = null;
        var blob_len: usize = 0;
        var hnum: u32 = 0;
        const rc = c.tdnf_rpmdb_iter_next_header_blob_hnum(
            iter,
            &hnum,
            &blob_ptr,
            &blob_len,
        );
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            return error.RpmDbReadFailed;
        }
        const ptr = blob_ptr orelse continue;
        if (blob_len == 0) {
            continue;
        }

        const header = rpm_header.Header.parse(ptr[0..blob_len]) catch return error.InvalidRpmHeader;
        if (header.getString(.name)) |name| {
            if (std.mem.eql(u8, name, "gpg-pubkey")) {
                continue;
            }
        }

        const built = rpmpkg.buildFromHeader(arena, header, .{
            .include_relations = true,
            .include_files = true,
            .include_changelogs = false,
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRpmHeader,
        };
        _ = try builder.appendPackageView(.{
            .pkg = built.package,
            .relations = built.relations,
            .files = built.files,
        });
        try hnums.append(hnum);
    }

    return .{
        .repository = try builder.finish(),
        .hnums = try hnums.toOwnedSlice(),
    };
}

fn normalizeTransactionItems(
    allocator: std.mem.Allocator,
    raw_items: RawTransactionItems,
) TransactionError![]TransactionInput {
    const item_count = switch (raw_items) {
        .legacy_paths => |items| items.len,
        .paths_v2 => |items| items.len,
        .verified => |items| items.items.len,
    };
    const inputs = try allocator.alloc(TransactionInput, item_count);

    switch (raw_items) {
        .legacy_paths => |items| {
            for (items, inputs) |item, *input| {
                input.* = .{
                    .operation = item.dwOperation,
                    .path = if (item.pszPath) |value| std.mem.span(value) else null,
                    .name = if (item.pszName) |value| std.mem.span(value) else null,
                    .evr = if (item.pszEVR) |value| std.mem.span(value) else null,
                    .arch = if (item.pszArch) |value| std.mem.span(value) else null,
                    .rpmdb_hnum = 0,
                };
            }
        },
        .paths_v2 => |items| {
            for (items, inputs) |item, *input| {
                input.* = .{
                    .operation = item.dwOperation,
                    .path = if (item.pszPath) |value| std.mem.span(value) else null,
                    .name = if (item.pszName) |value| std.mem.span(value) else null,
                    .evr = if (item.pszEVR) |value| std.mem.span(value) else null,
                    .arch = if (item.pszArch) |value| std.mem.span(value) else null,
                    .rpmdb_hnum = item.dwRpmDbHnum,
                };
            }
        },
        .verified => |items| {
            for (items.items, inputs, 0..) |item, *input, index| {
                const header_length = items.header_lengths[index];
                const needs_header =
                    item.dwOperation == c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_INSTALL or
                    item.dwOperation == c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_REINSTALL or
                    item.dwOperation == c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_UPGRADE;
                if (needs_header and header_length == 0) {
                    setError(
                        "verified transaction item {d} has no header bytes",
                        .{index},
                    );
                    return error.InvalidParameter;
                }
                const header_blob = if (header_length == 0)
                    null
                else if (items.headers[index]) |value|
                    value[0..header_length]
                else {
                    setError(
                        "verified transaction item {d} has a header length " ++ "but no header bytes",
                        .{index},
                    );
                    return error.InvalidParameter;
                };
                input.* = .{
                    .operation = item.dwOperation,
                    .path = if (item.pszPath) |value| std.mem.span(value) else null,
                    .name = if (item.pszName) |value| std.mem.span(value) else null,
                    .evr = if (item.pszEVR) |value| std.mem.span(value) else null,
                    .arch = if (item.pszArch) |value| std.mem.span(value) else null,
                    .rpmdb_hnum = item.dwRpmDbHnum,
                    .header_blob = header_blob,
                    .package_size = items.package_sizes[index],
                };
            }
        },
    }
    return inputs;
}

fn parseTransaction(
    arena: std.mem.Allocator,
    items: []const TransactionInput,
    installed: InstalledRepository,
) TransactionError!ParsedTransaction {
    const installed_repo = installed.repository;
    if (installed.hnums.len != installed_repo.packages.len) {
        setError("installed rpmdb hnum/package count mismatch", .{});
        return error.InvalidParameter;
    }
    var tx = try ParsedTransaction.init(
        arena,
        installed_repo.packages.len,
        items.len,
    );
    @memset(tx.erase_mask, false);
    @memset(tx.replace_mask, false);

    for (items, 0..) |item, input_index| {
        const op = switch (item.operation) {
            c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_INSTALL => TransactionOperation.install,
            c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_REINSTALL => TransactionOperation.reinstall,
            c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE => TransactionOperation.erase,
            c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_UPGRADE => TransactionOperation.upgrade,
            else => return error.InvalidParameter,
        };
        switch (op) {
            .install, .reinstall, .upgrade => {
                const path_text = item.path orelse "";
                const built = if (item.header_blob) |blob| blk: {
                    const hdr = rpm_header.Header.parseWithRegion(
                        blob,
                        .immutable,
                        true,
                    ) catch {
                        setError(
                            "verified transaction item {d} has an invalid " ++ "rpm header",
                            .{input_index},
                        );
                        return error.InvalidRpmHeader;
                    };
                    break :blk rpmpkg.buildFromHeader(arena, hdr, .{
                        .location = .{ .href = path_text },
                        .package_size = item.package_size,
                    }) catch |err| return switch (err) {
                        error.OutOfMemory => error.OutOfMemory,
                        else => error.InvalidRpmHeader,
                    };
                } else blk: {
                    if (item.path == null) {
                        setError("transaction item {d} missing rpm path", .{input_index});
                        return error.InvalidParameter;
                    }
                    const path_z = std.heap.c_allocator.dupeZ(u8, path_text) catch
                        return error.OutOfMemory;
                    defer std.heap.c_allocator.free(path_z);

                    var rpm = rpm_pkgfile.RpmFile.open(
                        std.heap.c_allocator,
                        path_z,
                    ) catch |err| {
                        setError("failed to open rpm {s}: {t}", .{ path_text, err });
                        return switch (err) {
                            error.OutOfMemory => error.OutOfMemory,
                            error.OpenFailed, error.StatFailed, error.ReadFailed => error.FileSystemIo,
                            error.BadLeadMagic, error.HeaderParseFailed => error.InvalidRpmHeader,
                            error.UnsupportedCompressor => error.UnsupportedCompressor,
                            error.DecompressFailed => error.DecompressFailed,
                        };
                    };
                    defer rpm.close(std.heap.c_allocator);
                    break :blk rpmpkg.buildFromRpmFile(arena, &rpm, path_text) catch |err| return switch (err) {
                        error.OutOfMemory => error.OutOfMemory,
                        else => error.InvalidRpmHeader,
                    };
                };
                try tx.added.append(.{
                    .input_index = input_index,
                    .op = op,
                    .view = .{
                        .pkg = built.package,
                        .relations = built.relations,
                        .files = built.files,
                    },
                });
            },
            .erase => {
                const query = try parseEraseQuery(item, input_index);
                const match_index = findInstalledEraseMatch(
                    installed,
                    query,
                    item.rpmdb_hnum,
                    tx.erase_mask,
                ) orelse {
                    setError(
                        "failed to match erase target hnum {d} " ++ "{s}-{s}.{s} in installed rpmdb",
                        .{
                            item.rpmdb_hnum,
                            query.name,
                            formatEvrForError(query.evr),
                            query.arch orelse "",
                        },
                    );
                    return error.InvalidParameter;
                };
                tx.erase_mask[match_index] = true;
                try tx.erased.append(.{
                    .input_index = input_index,
                    .op = .erase,
                    .view = installedPackageView(installed_repo, match_index),
                });
            },
        }
    }

    // Select exact prior Packages rows for every replacement operation.
    // Reinstalls supersede every duplicate exact NEVRA+arch row. Upgrades
    // select name+arch only, so a normal multilib transaction gets one
    // independent prior per architecture. Multiple same-arch upgrade priors
    // are retained in the plan and reported before execution can start.
    for (tx.added.items) |added| {
        if (added.op != .reinstall and added.op != .upgrade) {
            continue;
        }
        for (installed_repo.packages, 0..) |pkg, installed_index| {
            if (tx.erase_mask[installed_index]) {
                continue;
            }
            const selected = switch (added.op) {
                .reinstall => sameNevra(pkg, added.view.pkg),
                .upgrade => sameNameArch(pkg, added.view.pkg),
                else => false,
            };
            if (!selected) {
                continue;
            }
            if (tx.replace_mask[installed_index]) {
                setError(
                    "installed hnum {d} is selected by multiple replacement items",
                    .{installed.hnums[installed_index]},
                );
                return error.InvalidParameter;
            }
            tx.replace_mask[installed_index] = true;
            try tx.priors[added.input_index].append(installed.hnums[installed_index]);
        }
    }

    return tx;
}

fn buildFinalRepository(
    arena: std.mem.Allocator,
    installed_repo: model.RepositoryModel,
    tx: *const ParsedTransaction,
) TransactionError!FinalBuildResult {
    var builder = RepositoryBuilder.init(arena);
    const installed_to_final = try arena.alloc(?usize, installed_repo.packages.len);
    const added_to_final = try arena.alloc(usize, tx.added.items.len);

    for (installed_to_final) |*entry| {
        entry.* = null;
    }

    for (installed_repo.packages, 0..) |pkg, installed_index| {
        if (tx.erase_mask[installed_index] or tx.replace_mask[installed_index]) {
            continue;
        }
        installed_to_final[installed_index] = try builder.appendPackageView(.{
            .pkg = pkg,
            .relations = installed_repo.relations,
            .files = installed_repo.files,
        });
    }

    const added_base = builder.packages.items.len;

    for (tx.added.items, 0..) |added, added_index| {
        added_to_final[added_index] = try builder.appendPackageView(added.view);
    }

    return .{
        .repository = try builder.finish(),
        .installed_to_final = installed_to_final,
        .added_to_final = added_to_final,
        .added_base = added_base,
    };
}

fn collectNativeProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    tx: *const ParsedTransaction,
    installed_repo: model.RepositoryModel,
    final_build: FinalBuildResult,
    installed_index: *const query_index.RepositoryIndex,
    final_index: *const query_index.RepositoryIndex,
    config: ?*const c.tdnf_rpm_config,
) TransactionError!void {
    for (tx.added.items, 0..) |added, added_index| {
        const source_final = final_build.added_to_final[added_index];
        try collectAddedPackageProblems(
            arena,
            problems,
            added.input_index,
            added.view,
            source_final,
            installed_index,
            final_index,
            final_build.added_base,
            config,
        );
    }

    for (installed_repo.packages, 0..) |pkg, installed_index_raw| {
        if (tx.erase_mask[installed_index_raw] or tx.replace_mask[installed_index_raw]) {
            continue;
        }
        const source_final = final_build.installed_to_final[installed_index_raw] orelse continue;
        const source = PackageView{
            .pkg = pkg,
            .relations = installed_repo.relations,
            .files = installed_repo.files,
        };
        try collectRemainingPackageProblems(
            arena,
            problems,
            source,
            source_final,
            tx,
            installed_repo,
            final_index,
        );
    }
}

fn collectAddedPackageProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    input_index: usize,
    source: PackageView,
    source_final_index: usize,
    installed_index: *const query_index.RepositoryIndex,
    final_index: *const query_index.RepositoryIndex,
    added_base: usize,
    config: ?*const c.tdnf_rpm_config,
) TransactionError!void {
    for (source.relationEntries(.requires)) |relation| {
        if (shouldSkipFinalRequire(relation)) {
            continue;
        }
        const active_index: *const query_index.RepositoryIndex = if ((relation.sense & sense_pretrans) != 0)
            installed_index
        else
            final_index;

        const matches = try collectMatchingPackageIndices(arena, active_index, relation, null);
        if (matches.len != 0) {
            continue;
        }

        try problems.add(try makeMissingRequireProblem(
            arena,
            input_index,
            source,
            relation,
            (relation.sense & sense_pretrans) != 0,
        ));
    }

    try collectConflictStyleProblems(arena, problems, input_index, source, source_final_index, final_index, .conflicts);
    try collectConflictStyleProblems(arena, problems, input_index, source, source_final_index, final_index, .obsoletes);
    try collectFileConflictProblems(
        arena,
        problems,
        input_index,
        source,
        source_final_index,
        final_index,
        added_base,
        config,
    );
}

fn collectRemainingPackageProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    source: PackageView,
    source_final_index: usize,
    tx: *const ParsedTransaction,
    installed_repo: model.RepositoryModel,
    final_index: *const query_index.RepositoryIndex,
) TransactionError!void {
    for (source.relationEntries(.requires)) |relation| {
        if (shouldSkipFinalRequire(relation)) {
            continue;
        }

        if (!relationMatchesRemovedOrReplacedPackage(
            relation,
            installed_repo,
            tx,
        )) {
            continue;
        }

        const matches = try collectMatchingPackageIndices(
            arena,
            final_index,
            relation,
            null,
        );
        if (matches.len != 0) {
            continue;
        }

        try problems.add(try makeMissingRequireProblem(
            arena,
            std.math.maxInt(u32),
            source,
            relation,
            false,
        ));
    }

    try collectTransitionConflictProblems(arena, problems, source, source_final_index, tx.added.items, .conflicts);
    try collectTransitionConflictProblems(arena, problems, source, source_final_index, tx.added.items, .obsoletes);
}

fn relationMatchesRemovedOrReplacedPackage(
    relation: model.Relation,
    installed_repo: model.RepositoryModel,
    tx: *const ParsedTransaction,
) bool {
    for (installed_repo.packages, 0..) |_, index| {
        if (!tx.erase_mask[index] and !tx.replace_mask[index]) {
            continue;
        }
        if (relationMatchesPackage(
            relation,
            installedPackageView(installed_repo, index),
        )) {
            return true;
        }
    }
    return false;
}

fn collectConflictStyleProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    input_index: usize,
    source: PackageView,
    source_final_index: usize,
    final_index: *const query_index.RepositoryIndex,
    kind: model.DependencyKind,
) TransactionError!void {
    for (source.relationEntries(kind)) |relation| {
        const matches = try collectMatchingPackageIndices(arena, final_index, relation, source_final_index);
        for (matches) |candidate_index| {
            const candidate = PackageView{
                .pkg = final_index.repository.packages[candidate_index],
                .relations = final_index.repository.relations,
                .files = final_index.repository.files,
            };
            if (sameNevra(source.pkg, candidate.pkg)) {
                continue;
            }
            try problems.add(try makeConflictStyleProblem(
                arena,
                input_index,
                source,
                candidate,
                kind,
            ));
        }
    }
}

fn collectTransitionConflictProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    source: PackageView,
    source_final_index: usize,
    added_items: []const TransactionPackage,
    kind: model.DependencyKind,
) TransactionError!void {
    _ = source_final_index;

    for (source.relationEntries(kind)) |relation| {
        for (added_items) |added| {
            if (!relationMatchesPackage(relation, added.view)) {
                continue;
            }
            try problems.add(try makeConflictStyleProblem(
                arena,
                added.input_index,
                source,
                added.view,
                kind,
            ));
        }
    }
}

fn collectFileConflictProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    input_index: usize,
    source: PackageView,
    source_final_index: usize,
    final_index: *const query_index.RepositoryIndex,
    added_base: usize,
    config: ?*const c.tdnf_rpm_config,
) TransactionError!void {
    for (source.fileEntries()) |source_file| {
        if (source_file.kind == .dir) {
            continue;
        }

        if (config != null) {
            const source_identity = try canonicalPathForTransaction(
                arena,
                config,
                source_file.path,
            );
            for (final_index.repository.packages, 0..) |pkg, candidate_index| {
                if (candidate_index == source_final_index or
                    (candidate_index >= added_base and
                        candidate_index < source_final_index))
                {
                    continue;
                }
                const candidate = PackageView{
                    .pkg = pkg,
                    .relations = final_index.repository.relations,
                    .files = final_index.repository.files,
                };
                if (sameNevra(source.pkg, candidate.pkg)) continue;
                for (candidate.fileEntries()) |candidate_file| {
                    const candidate_identity = try canonicalPathForTransaction(
                        arena,
                        config,
                        candidate_file.path,
                    );
                    if (!std.mem.eql(
                        u8,
                        source_identity,
                        candidate_identity,
                    ) or !fileEntriesConflict(source_file, candidate_file)) {
                        continue;
                    }
                    try problems.add(try makeFileConflictProblem(
                        arena,
                        input_index,
                        source,
                        candidate,
                        source_file.path,
                    ));
                    break;
                }
            }
            continue;
        }

        for (final_index.packagesProvidingFile(source_file.path)) |candidate_index| {
            if (candidate_index == source_final_index) {
                continue;
            }
            if (candidate_index >= added_base and candidate_index < source_final_index) {
                continue;
            }

            const candidate = PackageView{
                .pkg = final_index.repository.packages[candidate_index],
                .relations = final_index.repository.relations,
                .files = final_index.repository.files,
            };
            if (sameNevra(source.pkg, candidate.pkg)) {
                continue;
            }

            const candidate_file = findFileEntry(candidate.fileEntries(), source_file.path) orelse continue;
            if (!fileEntriesConflict(source_file, candidate_file)) {
                continue;
            }

            try problems.add(try makeFileConflictProblem(
                arena,
                input_index,
                source,
                candidate,
                source_file.path,
            ));
        }
    }
}

fn canonicalPathForTransaction(
    arena: std.mem.Allocator,
    config: ?*const c.tdnf_rpm_config,
    path: []const u8,
) TransactionError![]const u8 {
    const cfg = config orelse return path;
    const path_z = try arena.dupeZ(u8, path);
    var output: [4096]u8 = undefined;
    if (c.tdnf_rpm_canonical_path_config(
        cfg,
        path_z.ptr,
        &output,
        output.len,
    ) != 0) {
        setError("canonical transaction path failed: {s}", .{path});
        return error.InvalidParameter;
    }
    return arena.dupe(u8, std.mem.sliceTo(&output, 0)) catch
        return error.OutOfMemory;
}

fn buildNativeOrder(
    arena: std.mem.Allocator,
    added_items: []const TransactionPackage,
    erased_items: []const TransactionPackage,
) TransactionError![]usize {
    var results = std.array_list.Managed(usize).init(arena);

    const added_order = try topoOrderPhase(arena, added_items, false);
    try results.appendSlice(added_order);

    const erased_order = try topoOrderPhase(arena, erased_items, true);
    try results.appendSlice(erased_order);

    return try results.toOwnedSlice();
}

fn topoOrderPhase(
    arena: std.mem.Allocator,
    items: []const TransactionPackage,
    reverse: bool,
) TransactionError![]usize {
    if (items.len == 0) {
        return try arena.alloc(usize, 0);
    }

    const adjacency = try arena.alloc(std.array_list.Managed(usize), items.len);
    const indegree = try arena.alloc(usize, items.len);
    const incoming_pre = try arena.alloc(usize, items.len);
    const remaining = try arena.alloc(bool, items.len);
    const outgoing_count = try arena.alloc(usize, items.len);
    for (adjacency) |*list| {
        list.* = std.array_list.Managed(usize).init(arena);
    }
    @memset(indegree, 0);
    @memset(incoming_pre, 0);
    @memset(remaining, true);
    @memset(outgoing_count, 0);

    for (items, 0..) |consumer, consumer_index| {
        for (order_dep_kinds) |kind| {
            for (consumer.view.relationEntries(kind)) |relation| {
                if (isUnorderedReq(relation.sense)) {
                    continue;
                }
                const provider_index = findMatchingTransactionProvider(items, consumer.input_index, relation) orelse continue;

                const from = if (reverse) consumer_index else provider_index;
                const to = if (reverse) provider_index else consumer_index;
                if (from == to) {
                    continue;
                }
                if (containsIndex(adjacency[from].items, to)) {
                    continue;
                }

                try adjacency[from].append(to);
                indegree[to] += 1;
                outgoing_count[from] += 1;
                if (relation.pre) {
                    incoming_pre[to] += 1;
                }
            }
        }
    }

    var order = std.array_list.Managed(usize).init(arena);
    var scratch = std.array_list.Managed(usize).init(arena);

    while (order.items.len < items.len) {
        scratch.clearRetainingCapacity();
        for (remaining, 0..) |is_remaining, index| {
            if (is_remaining and indegree[index] == 0) {
                try scratch.append(index);
            }
        }

        if (scratch.items.len == 0) {
            const breaker = chooseCycleBreak(items, remaining, incoming_pre, outgoing_count) orelse return error.InvalidParameter;
            try scratch.append(breaker);
        } else {
            std.sort.pdq(usize, scratch.items, PhaseSortContext{
                .items = items,
                .outgoing_count = outgoing_count,
                .incoming_pre = incoming_pre,
            }, lessPhaseNode);
        }

        const next = scratch.items[0];
        remaining[next] = false;
        try order.append(items[next].input_index);

        for (adjacency[next].items) |dest| {
            if (indegree[dest] > 0) {
                indegree[dest] -= 1;
            }
        }
    }

    return try order.toOwnedSlice();
}

const PhaseSortContext = struct {
    items: []const TransactionPackage,
    outgoing_count: []const usize,
    incoming_pre: []const usize,
};

fn lessPhaseNode(ctx: PhaseSortContext, left: usize, right: usize) bool {
    if (ctx.outgoing_count[left] != ctx.outgoing_count[right]) {
        return ctx.outgoing_count[left] > ctx.outgoing_count[right];
    }
    if (ctx.incoming_pre[left] != ctx.incoming_pre[right]) {
        return ctx.incoming_pre[left] < ctx.incoming_pre[right];
    }
    return ctx.items[left].input_index < ctx.items[right].input_index;
}

fn chooseCycleBreak(
    items: []const TransactionPackage,
    remaining: []const bool,
    incoming_pre: []const usize,
    outgoing_count: []const usize,
) ?usize {
    var best: ?usize = null;

    for (remaining, 0..) |is_remaining, index| {
        if (!is_remaining) {
            continue;
        }
        if (best == null) {
            best = index;
            continue;
        }
        const current = best.?;
        if (incoming_pre[index] < incoming_pre[current] or
            (incoming_pre[index] == incoming_pre[current] and outgoing_count[index] > outgoing_count[current]) or
            (incoming_pre[index] == incoming_pre[current] and outgoing_count[index] == outgoing_count[current] and items[index].input_index < items[current].input_index))
        {
            best = index;
        }
    }

    return best;
}

fn findMatchingTransactionProvider(
    items: []const TransactionPackage,
    source_input_index: usize,
    relation: model.Relation,
) ?usize {
    var by_name: ?usize = null;
    var by_file: ?usize = null;
    var by_provide: ?usize = null;

    for (items, 0..) |candidate, index| {
        if (candidate.input_index == source_input_index) {
            continue;
        }
        if (by_name == null and relationMatchesCandidateName(relation, candidate.view.pkg.nevra.name)) {
            by_name = index;
            continue;
        }
        if (by_file == null and relationMatchesCandidateFiles(relation, candidate.view.fileEntries())) {
            by_file = index;
            continue;
        }
        if (by_provide == null and relationMatchesCandidateProvides(relation, candidate.view.relationEntries(.provides))) {
            by_provide = index;
        }
    }

    return by_name orelse by_file orelse by_provide;
}

fn collectMatchingPackageIndices(
    arena: std.mem.Allocator,
    index: *const query_index.RepositoryIndex,
    relation: model.Relation,
    skip_index: ?usize,
) TransactionError![]usize {
    var results = std.array_list.Managed(usize).init(arena);
    const seen = try arena.alloc(bool, index.repository.packages.len);
    @memset(seen, false);

    if (relationMatchesCandidateName(relation, relation.name)) {
        for (index.packagesNamed(relation.name)) |candidate_index| {
            if (skip_index != null and candidate_index == skip_index.?) {
                continue;
            }
            if (seen[candidate_index]) {
                continue;
            }
            seen[candidate_index] = true;
            try results.append(candidate_index);
        }
    }

    if (relation.name.len != 0 and relation.name[0] == '/') {
        for (index.packagesProvidingFile(relation.name)) |candidate_index| {
            if (skip_index != null and candidate_index == skip_index.?) {
                continue;
            }
            if (seen[candidate_index]) {
                continue;
            }
            seen[candidate_index] = true;
            try results.append(candidate_index);
        }
    }

    const provided = index.packagesProvidingQuery(arena, dependencyQueryFromRelation(relation)) catch return error.OutOfMemory;
    for (provided.items) |candidate_index| {
        if (skip_index != null and candidate_index == skip_index.?) {
            continue;
        }
        if (seen[candidate_index]) {
            continue;
        }
        seen[candidate_index] = true;
        try results.append(candidate_index);
    }

    return try results.toOwnedSlice();
}

fn relationMatchesPackage(
    relation: model.Relation,
    candidate: PackageView,
) bool {
    return relationMatchesCandidateName(relation, candidate.pkg.nevra.name) or
        relationMatchesCandidateFiles(relation, candidate.fileEntries()) or
        relationMatchesCandidateProvides(relation, candidate.relationEntries(.provides));
}

fn relationMatchesCandidateName(relation: model.Relation, candidate_name: []const u8) bool {
    return std.mem.eql(u8, relation.name, candidate_name) and
        relation.comparison == .none and
        !relationHasVersion(relation);
}

fn relationMatchesCandidateFiles(relation: model.Relation, candidate_files: []const model.FileEntry) bool {
    for (candidate_files) |file_entry| {
        if (std.mem.eql(u8, relation.name, file_entry.path)) {
            return true;
        }
    }
    return false;
}

fn relationMatchesCandidateProvides(relation: model.Relation, candidate_provides: []const model.Relation) bool {
    const query = dependencyQueryFromRelation(relation);
    for (candidate_provides) |provide| {
        if (query_index.relationMatchesQuery(provide, query)) {
            return true;
        }
    }
    return false;
}

fn dependencyQueryFromRelation(relation: model.Relation) query_index.DependencyQuery {
    return .{
        .name = relation.name,
        .comparison = relation.comparison,
        .epoch = relation.epoch,
        .version = relation.version,
        .release = relation.release,
    };
}

fn relationHasVersion(relation: model.Relation) bool {
    return relation.epoch != null or
        (relation.version != null and relation.version.?.len != 0) or
        (relation.release != null and relation.release.?.len != 0);
}

fn shouldSkipFinalRequire(relation: model.Relation) bool {
    if (relation.name.len == 0) {
        return true;
    }
    if (std.mem.startsWith(u8, relation.name, "rpmlib(")) {
        return true;
    }
    return (relation.sense & special_final_check_mask) != 0;
}

fn isUnorderedReq(sense: u32) bool {
    return (sense & unordered_only_mask) != 0 and (sense & force_order_only_mask) == 0;
}

fn makeMissingRequireProblem(
    arena: std.mem.Allocator,
    input_index: usize,
    source: PackageView,
    relation: model.Relation,
    pretrans_hint: bool,
) TransactionError!NativeProblem {
    const source_nevra = try pkgquery.nevraString(arena, source.pkg);
    const relation_text = try pkgquery.formatRelation(arena, relation);
    return .{
        .kind = if (pretrans_hint) .pretrans else .dependency,
        .input_index = input_index,
        .package = source_nevra,
        .subject = relation_text,
    };
}

fn makeConflictStyleProblem(
    arena: std.mem.Allocator,
    input_index: usize,
    source: PackageView,
    candidate: PackageView,
    kind: model.DependencyKind,
) TransactionError!NativeProblem {
    const source_nevra = try pkgquery.nevraString(arena, source.pkg);
    const candidate_nevra = try pkgquery.nevraString(arena, candidate.pkg);
    return .{
        .kind = switch (kind) {
            .conflicts => .conflict,
            .obsoletes => .obsoletes,
            else => unreachable,
        },
        .input_index = input_index,
        .package = source_nevra,
        .related_package = candidate_nevra,
        .subject = "",
    };
}

fn makeFileConflictProblem(
    arena: std.mem.Allocator,
    input_index: usize,
    source: PackageView,
    candidate: PackageView,
    path: []const u8,
) TransactionError!NativeProblem {
    return .{
        .kind = .file_conflict,
        .input_index = input_index,
        .package = try pkgquery.nevraString(arena, source.pkg),
        .related_package = try pkgquery.nevraString(arena, candidate.pkg),
        .subject = path,
    };
}

fn formatProblemLines(
    arena: std.mem.Allocator,
    problems: []const NativeProblem,
) TransactionError![][]const u8 {
    const lines = try arena.alloc([]const u8, problems.len);
    for (problems, lines) |problem, *line| {
        line.* = switch (problem.kind) {
            .dependency => try std.fmt.allocPrint(
                arena,
                "nothing provides {s} needed by {s}",
                .{ problem.subject, problem.package },
            ),
            .pretrans => try std.fmt.allocPrint(
                arena,
                "nothing provides {s} needed by {s}. Detected rpm pre-transaction dependency errors. Install {s} first to resolve this failure.",
                .{ problem.subject, problem.package, problem.subject },
            ),
            .conflict => try std.fmt.allocPrint(
                arena,
                "package {s} conflicts with {s}",
                .{ problem.package, problem.related_package orelse "" },
            ),
            .obsoletes => try std.fmt.allocPrint(
                arena,
                "package {s} obsoletes {s}",
                .{ problem.package, problem.related_package orelse "" },
            ),
            .file_conflict => try std.fmt.allocPrint(
                arena,
                "file {s} from install of {s} conflicts with file from package {s}",
                .{
                    problem.subject,
                    problem.package,
                    problem.related_package orelse "",
                },
            ),
            .unsupported_multiple => try std.fmt.allocPrint(
                arena,
                "package {s} has {d} installed {s} instances selected for one upgrade; remove extra instances or configure the package as installonly",
                .{ problem.package, problem.count, problem.subject },
            ),
        };
    }
    return lines;
}

fn collectMultiplicityProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    tx: *const ParsedTransaction,
) TransactionError!void {
    for (tx.added.items) |added| {
        if (added.op != .upgrade) {
            continue;
        }
        const priors = tx.priors[added.input_index].items;
        if (priors.len <= 1) {
            continue;
        }
        try problems.add(.{
            .kind = .unsupported_multiple,
            .input_index = added.input_index,
            .package = try pkgquery.nevraString(arena, added.view.pkg),
            .subject = added.view.pkg.nevra.name,
            .count = @intCast(priors.len),
        });
    }
}

fn buildIndexLines(arena: std.mem.Allocator, indexes: []const usize) TransactionError![][]const u8 {
    const out = try arena.alloc([]const u8, indexes.len);
    for (indexes, 0..) |value, index| {
        out[index] = try std.fmt.allocPrint(arena, "{d}", .{value});
    }
    return out;
}

fn validateOrderPermutation(
    arena: std.mem.Allocator,
    indexes: []const usize,
    item_count: usize,
) TransactionError!void {
    if (indexes.len != item_count) {
        setError(
            "native transaction order has {d} entries for {d} inputs",
            .{ indexes.len, item_count },
        );
        return error.InvalidParameter;
    }

    const seen = try arena.alloc(bool, item_count);
    @memset(seen, false);
    for (indexes) |index| {
        if (index >= item_count) {
            setError(
                "native transaction order index {d} is out of range",
                .{index},
            );
            return error.InvalidParameter;
        }
        if (seen[index]) {
            setError(
                "native transaction order repeats input index {d}",
                .{index},
            );
            return error.InvalidParameter;
        }
        seen[index] = true;
    }
}

fn tryBuildIndexArray(indexes: []const usize) !?[*c]u32 {
    if (indexes.len == 0) return null;
    const raw = c.calloc(indexes.len, @sizeOf(u32)) orelse
        return error.OutOfMemory;
    const out: [*c]u32 = @ptrCast(@alignCast(raw));
    errdefer c.free(raw);
    for (indexes, 0..) |value, index| {
        out[index] = std.math.cast(u32, value) orelse
            return error.InvalidParameter;
    }
    return out;
}

fn freeCStringArray(items: ?[*c][*c]u8) void {
    const array = items orelse return;
    var index: usize = 0;
    while (array[index] != null) : (index += 1) {
        c.free(@ptrCast(array[index]));
    }
    c.free(@ptrCast(array));
}

fn tryBuildCStringArray(items: []const []const u8) !?[*c][*c]u8 {
    const raw = c.calloc(items.len + 1, @sizeOf([*c]u8)) orelse return error.OutOfMemory;
    const out: [*c][*c]u8 = @ptrCast(@alignCast(raw));
    var populated: usize = 0;
    errdefer {
        var index: usize = 0;
        while (index < populated) : (index += 1) {
            if (out[index] != null) {
                _ = c.free(out[index]);
            }
        }
        c.free(raw);
    }

    for (items, 0..) |item, index| {
        out[index] = try dupCString(item);
        populated += 1;
    }
    return out;
}

fn dupCString(text: []const u8) ![*:0]u8 {
    return try std.heap.c_allocator.dupeZ(u8, text);
}

fn parseEraseQuery(
    item: TransactionInput,
    input_index: usize,
) TransactionError!EraseQuery {
    const name = item.name orelse {
        setError("transaction erase item {d} missing name", .{input_index});
        return error.InvalidParameter;
    };
    const evr_text = item.evr orelse {
        setError("transaction erase item {d} missing evr", .{input_index});
        return error.InvalidParameter;
    };
    return .{
        .name = name,
        .evr = splitEvr(evr_text),
        .arch = item.arch,
    };
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

fn findInstalledEraseMatch(
    installed: InstalledRepository,
    query: EraseQuery,
    wanted_hnum: u32,
    selected: []const bool,
) ?usize {
    const repo = installed.repository;
    for (repo.packages, 0..) |pkg, index| {
        if (selected[index]) {
            continue;
        }
        if (wanted_hnum != 0 and installed.hnums[index] != wanted_hnum) {
            continue;
        }
        if (!std.mem.eql(u8, pkg.nevra.name, query.name)) {
            continue;
        }
        if (query.arch) |arch| {
            if (!std.mem.eql(u8, pkg.nevra.arch, arch)) {
                continue;
            }
        }
        if (query_index.compareEvr(
            pkg.nevra.epoch,
            pkg.nevra.version,
            if (pkg.nevra.release.len == 0) null else pkg.nevra.release,
            query.evr.epoch,
            query.evr.version,
            query.evr.release,
        ) == 0) {
            return index;
        }
    }
    return null;
}

fn installedPackageView(repo: model.RepositoryModel, index: usize) PackageView {
    return .{
        .pkg = repo.packages[index],
        .relations = repo.relations,
        .files = repo.files,
    };
}

fn sameNevra(left: model.Package, right: model.Package) bool {
    return std.mem.eql(u8, left.nevra.name, right.nevra.name) and
        std.mem.eql(u8, left.nevra.arch, right.nevra.arch) and
        query_index.comparePackageVersions(left, right) == 0;
}

fn sameNameArch(left: model.Package, right: model.Package) bool {
    return std.mem.eql(u8, left.nevra.name, right.nevra.name) and
        std.mem.eql(u8, left.nevra.arch, right.nevra.arch);
}

fn containsIndex(items: []const usize, wanted: usize) bool {
    for (items) |item| {
        if (item == wanted) {
            return true;
        }
    }
    return false;
}

fn findFileEntry(files: []const model.FileEntry, wanted_path: []const u8) ?model.FileEntry {
    for (files) |file_entry| {
        if (std.mem.eql(u8, file_entry.path, wanted_path)) {
            return file_entry;
        }
    }
    return null;
}

fn fileEntriesConflict(left: model.FileEntry, right: model.FileEntry) bool {
    return left.kind != .dir or right.kind != .dir;
}

fn formatEvrForError(parts: EvrParts) []const u8 {
    _ = parts;
    return "(unknown)";
}

test "verified transaction input never reopens diagnostic path" {
    const header_blob = try rpmpkg.makeMinimalTransactionHeaderForTest(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(header_blob);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const raw_items = [_]c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2{.{
        .dwOperation = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_INSTALL,
        .pszPath = "/path/replaced-after-verification.rpm",
        .pszName = "verified-package",
        .pszEVR = "1.0-1",
        .pszArch = "noarch",
        .dwRpmDbHnum = 0,
    }};
    const headers = [_]?[*]const u8{header_blob.ptr};
    const header_lengths = [_]usize{header_blob.len};
    const package_sizes = [_]u64{1234};
    const inputs = try normalizeTransactionItems(
        arena_state.allocator(),
        .{ .verified = .{
            .items = &raw_items,
            .headers = &headers,
            .header_lengths = &header_lengths,
            .package_sizes = &package_sizes,
        } },
    );

    const tx = try parseTransaction(
        arena_state.allocator(),
        inputs,
        .{ .repository = .{}, .hnums = &.{} },
    );
    try std.testing.expectEqual(@as(usize, 1), tx.added.items.len);
    try std.testing.expectEqualStrings(
        "verified-package",
        tx.added.items[0].view.pkg.nevra.name,
    );
    try std.testing.expectEqualStrings(
        inputs[0].path.?,
        tx.added.items[0].view.pkg.location.href,
    );
}

test "duplicate NEVRA erases map and validate by exact rpmdb hnum" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const relations = [_]model.Relation{
        .{ .name = "duplicate-provider" },
        .{ .name = "duplicate-provider" },
    };
    const provider = model.Package{
        .pkg_id = "duplicate-provider",
        .nevra = .{
            .name = "duplicate-provider",
            .version = "1.0",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "provider" },
        .location = .{ .href = "installed" },
        .provides = .{ .start = 0, .len = 1 },
    };
    const consumer = model.Package{
        .pkg_id = "remaining-consumer",
        .nevra = .{
            .name = "remaining-consumer",
            .version = "1.0",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "consumer" },
        .location = .{ .href = "installed" },
        .requires = .{ .start = 1, .len = 1 },
    };
    const installed_packages = [_]model.Package{
        provider,
        provider,
        consumer,
    };
    const installed_hnums = [_]u32{ 41, 73, 89 };
    const installed = InstalledRepository{
        .repository = .{
            .packages = @constCast(&installed_packages),
            .relations = @constCast(&relations),
        },
        .hnums = &installed_hnums,
    };

    const second_only = [_]TransactionInput{.{
        .operation = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE,
        .path = null,
        .name = "duplicate-provider",
        .evr = "1.0-1",
        .arch = "noarch",
        .rpmdb_hnum = 73,
    }};
    const second_tx = try parseTransaction(arena, &second_only, installed);
    try testing.expect(!second_tx.erase_mask[0]);
    try testing.expect(second_tx.erase_mask[1]);
    try testing.expect(!second_tx.erase_mask[2]);

    const both = [_]TransactionInput{
        .{
            .operation = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE,
            .path = null,
            .name = "duplicate-provider",
            .evr = "1.0-1",
            .arch = "noarch",
            .rpmdb_hnum = 73,
        },
        .{
            .operation = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE,
            .path = null,
            .name = "duplicate-provider",
            .evr = "1.0-1",
            .arch = "noarch",
            .rpmdb_hnum = 41,
        },
    };
    var tx = try parseTransaction(arena, &both, installed);
    try testing.expect(tx.erase_mask[0]);
    try testing.expect(tx.erase_mask[1]);
    try testing.expect(!tx.erase_mask[2]);

    const final_build = try buildFinalRepository(
        arena,
        installed.repository,
        &tx,
    );
    var installed_index = try query_index.RepositoryIndex.init(
        arena,
        &installed.repository,
    );
    var final_index = try query_index.RepositoryIndex.init(
        arena,
        &final_build.repository,
    );
    var problems = ProblemCollector.init(arena);
    try collectNativeProblems(
        arena,
        &problems,
        &tx,
        installed.repository,
        final_build,
        &installed_index,
        &final_index,
        null,
    );
    try testing.expectEqual(@as(usize, 1), problems.problems.items.len);
    try testing.expect(std.mem.containsAtLeast(
        u8,
        problems.problems.items[0].subject,
        1,
        "duplicate-provider",
    ));
}

test "install ignores unrelated pre-existing unsatisfied requirement" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const missing_capability = "pre-existing-missing-capability";
    const relations = [_]model.Relation{
        .{ .name = missing_capability },
    };
    const retained_consumer = model.Package{
        .pkg_id = "retained-consumer",
        .nevra = .{
            .name = "retained-consumer",
            .version = "1.0",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "consumer" },
        .location = .{ .href = "installed" },
        .requires = .{ .start = 0, .len = 1 },
    };
    const unrelated_package = model.Package{
        .pkg_id = "unrelated-package",
        .nevra = .{
            .name = "unrelated-package",
            .version = "1.0",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "unrelated" },
        .location = .{ .href = "unrelated-package-1.0-1.noarch.rpm" },
    };
    const installed_packages = [_]model.Package{retained_consumer};
    const installed_repo = model.RepositoryModel{
        .packages = @constCast(&installed_packages),
        .relations = @constCast(&relations),
    };

    var tx = try ParsedTransaction.init(arena, installed_packages.len, 1);
    @memset(tx.erase_mask, false);
    @memset(tx.replace_mask, false);
    try tx.added.append(.{
        .input_index = 0,
        .op = .install,
        .view = .{
            .pkg = unrelated_package,
            .relations = &.{},
            .files = &.{},
        },
    });

    const final_build = try buildFinalRepository(arena, installed_repo, &tx);
    var installed_index = try query_index.RepositoryIndex.init(
        arena,
        &installed_repo,
    );
    var final_index = try query_index.RepositoryIndex.init(
        arena,
        &final_build.repository,
    );
    var problems = ProblemCollector.init(arena);
    try collectNativeProblems(
        arena,
        &problems,
        &tx,
        installed_repo,
        final_build,
        &installed_index,
        &final_index,
        null,
    );

    try testing.expectEqual(@as(usize, 0), problems.problems.items.len);
}

test "upgrade reports retained consumer requirement dropped by replacement" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const capability = "phase7-capability-x";
    const relations = [_]model.Relation{
        .{ .name = capability },
        .{ .name = capability },
    };
    const old_provider = model.Package{
        .pkg_id = "phase7-provider-old",
        .nevra = .{
            .name = "phase7-provider",
            .version = "1.0",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "old-provider" },
        .location = .{ .href = "installed" },
        .provides = .{ .start = 0, .len = 1 },
    };
    const consumer = model.Package{
        .pkg_id = "phase7-consumer",
        .nevra = .{
            .name = "phase7-consumer",
            .version = "1.0",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "consumer" },
        .location = .{ .href = "installed" },
        .requires = .{ .start = 1, .len = 1 },
    };
    const new_provider = model.Package{
        .pkg_id = "phase7-provider-new",
        .nevra = .{
            .name = "phase7-provider",
            .version = "2.0",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "new-provider" },
        .location = .{ .href = "phase7-provider-2.0-1.noarch.rpm" },
    };
    const installed_packages = [_]model.Package{ old_provider, consumer };
    const installed_repo = model.RepositoryModel{
        .packages = @constCast(&installed_packages),
        .relations = @constCast(&relations),
    };

    var tx = try ParsedTransaction.init(arena, installed_packages.len, 1);
    @memset(tx.erase_mask, false);
    @memset(tx.replace_mask, false);
    tx.replace_mask[0] = true;
    try tx.added.append(.{
        .input_index = 0,
        .op = .upgrade,
        .view = .{
            .pkg = new_provider,
            .relations = &.{},
            .files = &.{},
        },
    });

    const final_build = try buildFinalRepository(arena, installed_repo, &tx);
    var installed_index = try query_index.RepositoryIndex.init(
        arena,
        &installed_repo,
    );
    var final_index = try query_index.RepositoryIndex.init(
        arena,
        &final_build.repository,
    );
    var problems = ProblemCollector.init(arena);
    try collectNativeProblems(
        arena,
        &problems,
        &tx,
        installed_repo,
        final_build,
        &installed_index,
        &final_index,
        null,
    );

    try testing.expectEqual(@as(usize, 1), problems.problems.items.len);
    try testing.expectEqual(ProblemKind.dependency, problems.problems.items[0].kind);
    try testing.expectEqualStrings(capability, problems.problems.items[0].subject);
    try testing.expect(std.mem.startsWith(
        u8,
        problems.problems.items[0].package,
        "phase7-consumer-",
    ));
}

test "native transaction order puts providers before install prereqs and consumers before erase prereqs" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const helper_file = [_]model.FileEntry{.{ .path = "/usr/bin/helper" }};
    const helper_pkg = model.Package{
        .pkg_id = "helper",
        .nevra = .{ .name = "helper", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "a" },
        .location = .{ .href = "helper.rpm" },
        .files = .{ .start = 0, .len = 1 },
    };

    const pre_rel = [_]model.Relation{.{ .name = "/usr/bin/helper", .pre = true, .sense = sense_script_pre }};
    const pre_pkg = model.Package{
        .pkg_id = "pre",
        .nevra = .{ .name = "pre", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "b" },
        .location = .{ .href = "pre.rpm" },
        .requires = .{ .start = 0, .len = 1 },
    };

    const postun_rel = [_]model.Relation{.{ .name = "/usr/bin/helper", .pre = true, .sense = sense_script_postun }};
    const postun_pkg = model.Package{
        .pkg_id = "postun",
        .nevra = .{ .name = "postun", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "c" },
        .location = .{ .href = "postun.rpm" },
        .requires = .{ .start = 0, .len = 1 },
    };

    const added = [_]TransactionPackage{
        .{ .input_index = 1, .op = .install, .view = .{ .pkg = pre_pkg, .relations = &pre_rel, .files = &[_]model.FileEntry{} } },
        .{ .input_index = 0, .op = .install, .view = .{ .pkg = helper_pkg, .relations = &[_]model.Relation{}, .files = &helper_file } },
    };
    const erased = [_]TransactionPackage{
        .{ .input_index = 2, .op = .erase, .view = .{ .pkg = postun_pkg, .relations = &postun_rel, .files = &[_]model.FileEntry{} } },
        .{ .input_index = 3, .op = .erase, .view = .{ .pkg = helper_pkg, .relations = &[_]model.Relation{}, .files = &helper_file } },
    };

    const order = try buildNativeOrder(arena, &added, &erased);
    try testing.expectEqual(@as(usize, 4), order.len);
    try testing.expectEqual(@as(usize, 0), order[0]);
    try testing.expectEqual(@as(usize, 1), order[1]);
    try testing.expectEqual(@as(usize, 2), order[2]);
    try testing.expectEqual(@as(usize, 3), order[3]);
}

test "typed order preserves a complete mixed binary-item permutation" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const pkg = model.Package{
        .pkg_id = "mixed",
        .nevra = .{
            .name = "mixed",
            .version = "1.0",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "mixed" },
        .location = .{ .href = "mixed.rpm" },
    };
    const view = PackageView{
        .pkg = pkg,
        .relations = &.{},
        .files = &.{},
    };
    const added = [_]TransactionPackage{
        .{ .input_index = 2, .op = .install, .view = view },
        .{ .input_index = 0, .op = .install, .view = view },
    };
    const erased = [_]TransactionPackage{
        .{ .input_index = 1, .op = .erase, .view = view },
    };

    const order = try buildNativeOrder(arena, &added, &erased);
    try validateOrderPermutation(arena, order, 3);
    try testing.expectEqualSlices(usize, &.{ 0, 2, 1 }, order);

    try testing.expectError(
        error.InvalidParameter,
        validateOrderPermutation(arena, &.{ 0, 0, 1 }, 3),
    );
    try testing.expectError(
        error.InvalidParameter,
        validateOrderPermutation(arena, &.{ 0, 1, 3 }, 3),
    );
}

test "native transaction reports unmet pretrans requirements with guidance" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source_rel = [_]model.Relation{.{
        .name = "helper",
        .comparison = .ge,
        .version = "1.0",
        .release = "1",
        .sense = sense_pretrans,
    }};
    const source_pkg = model.Package{
        .pkg_id = "consumer",
        .nevra = .{ .name = "consumer", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "x" },
        .location = .{ .href = "consumer.rpm" },
        .requires = .{ .start = 0, .len = 1 },
    };

    const repo = model.RepositoryModel{
        .packages = @constCast(&[_]model.Package{source_pkg}),
        .relations = @constCast(&source_rel),
    };
    var installed_index = try query_index.RepositoryIndex.init(arena, &model.RepositoryModel{});
    var final_index = try query_index.RepositoryIndex.init(arena, &repo);
    var problems = ProblemCollector.init(arena);

    try collectAddedPackageProblems(
        arena,
        &problems,
        0,
        .{ .pkg = source_pkg, .relations = &source_rel, .files = &[_]model.FileEntry{} },
        0,
        &installed_index,
        &final_index,
        0,
        null,
    );
    try testing.expectEqual(@as(usize, 1), problems.problems.items.len);
    try testing.expectEqual(ProblemKind.pretrans, problems.problems.items[0].kind);
    const lines = try formatProblemLines(arena, problems.problems.items);
    try testing.expect(std.mem.containsAtLeast(u8, lines[0], 1, "Detected rpm pre-transaction dependency errors."));
}

test "native transaction reports duplicate file ownership conflicts" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const shared_files = [_]model.FileEntry{
        .{ .path = "/usr/lib/conflict/shared", .kind = .plain },
        .{ .path = "/usr/lib/conflict/shared", .kind = .plain },
    };
    const pkg0 = model.Package{
        .pkg_id = "conflict0",
        .nevra = .{ .name = "conflict0", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "0" },
        .location = .{ .href = "conflict0.rpm" },
        .files = .{ .start = 0, .len = 1 },
    };
    const pkg1 = model.Package{
        .pkg_id = "conflict1",
        .nevra = .{ .name = "conflict1", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "1" },
        .location = .{ .href = "conflict1.rpm" },
        .files = .{ .start = 1, .len = 1 },
    };
    const repo = model.RepositoryModel{
        .packages = @constCast(&[_]model.Package{ pkg0, pkg1 }),
        .files = @constCast(&shared_files),
    };

    var installed_index = try query_index.RepositoryIndex.init(arena, &model.RepositoryModel{});
    var final_index = try query_index.RepositoryIndex.init(arena, &repo);
    var problems = ProblemCollector.init(arena);

    try collectAddedPackageProblems(
        arena,
        &problems,
        0,
        .{ .pkg = pkg0, .relations = &[_]model.Relation{}, .files = &shared_files },
        0,
        &installed_index,
        &final_index,
        0,
        null,
    );
    try testing.expectEqual(@as(usize, 1), problems.problems.items.len);
    const lines = try formatProblemLines(arena, problems.problems.items);
    try testing.expect(std.mem.containsAtLeast(
        u8,
        lines[0],
        1,
        "file /usr/lib/conflict/shared from install of conflict0-1.0-1.noarch conflicts with file from package conflict1-1.0-1.noarch",
    ));
}

test "native transaction detects conflicts across trusted root aliases" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const config = c.tdnf_rpm_config_create("/") orelse
        return error.TestUnexpectedResult;
    defer c.tdnf_rpm_config_destroy(config);
    var canonical_buf: [4096]u8 = undefined;
    if (c.tdnf_rpm_canonical_path_config(
        config,
        "/lib/alias-conflict",
        &canonical_buf,
        canonical_buf.len,
    ) != 0) {
        return error.TestUnexpectedResult;
    }
    if (!std.mem.eql(
        u8,
        std.mem.sliceTo(&canonical_buf, 0),
        "/usr/lib/alias-conflict",
    )) {
        return error.SkipZigTest;
    }

    const files = [_]model.FileEntry{
        .{ .path = "/lib/alias-conflict", .kind = .plain },
        .{ .path = "/usr/lib/alias-conflict", .kind = .plain },
    };
    const pkg0 = model.Package{
        .pkg_id = "alias-conflict0",
        .nevra = .{ .name = "alias-conflict0", .version = "1", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "0" },
        .location = .{ .href = "alias-conflict0.rpm" },
        .files = .{ .start = 0, .len = 1 },
    };
    const pkg1 = model.Package{
        .pkg_id = "alias-conflict1",
        .nevra = .{ .name = "alias-conflict1", .version = "1", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "1" },
        .location = .{ .href = "alias-conflict1.rpm" },
        .files = .{ .start = 1, .len = 1 },
    };
    const repo = model.RepositoryModel{
        .packages = @constCast(&[_]model.Package{ pkg0, pkg1 }),
        .files = @constCast(&files),
    };
    var installed_index = try query_index.RepositoryIndex.init(
        arena,
        &model.RepositoryModel{},
    );
    var final_index = try query_index.RepositoryIndex.init(arena, &repo);
    var problems = ProblemCollector.init(arena);
    try collectAddedPackageProblems(
        arena,
        &problems,
        0,
        .{ .pkg = pkg0, .relations = &.{}, .files = &files },
        0,
        &installed_index,
        &final_index,
        0,
        config,
    );
    try testing.expectEqual(@as(usize, 1), problems.problems.items.len);
}
