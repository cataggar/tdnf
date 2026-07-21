const std = @import("std");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");
const solver_rules = @import("solver_rules.zig");
const solver_visibility = @import("solver_visibility.zig");
const solv_bridge = @import("solvbridge.zig");

const c = solv_bridge.libsolv;

pub const SolveError = error{
    OutOfMemory,
    InvalidModel,
    UnsupportedPolicy,
    UnsupportedResult,
    SolverFailed,
};

pub const OrderOperation = enum {
    install,
    erase,
};

pub const OrderStep = struct {
    operation: OrderOperation,
    package: solver_model.PackageId,
};

pub const SolverFlag = enum {
    allow_downgrade,
    allow_uninstall,
    allow_vendor_change,
    best_obey_policy,
    ignore_recommended,
    install_also_updates,
    keep_orphans,
    yum_obsoletes,
};

pub const EffectiveJob = struct {
    id: ?solver_model.JobId,
    action: solver_model.JobAction,
    selection: solver_model.Selection,
    flags: solver_model.JobFlags,
};

pub const OwnedObservation = struct {
    arena_state: std.heap.ArenaAllocator,
    outcome: solver_model.Outcome,
    selected: []const solver_model.PackageId,
    order: []const OrderStep,
    effective_jobs: []const EffectiveJob,
    effective_solver_flags: []const SolverFlag,

    pub fn deinit(self: *OwnedObservation) void {
        self.arena_state.deinit();
        self.* = undefined;
    }
};

const PoolState = struct {
    pool: *c.Pool,
    package_solvids: []c.Id,
    job_ids: std.array_list.Managed(?solver_model.JobId),
    considered: ?*c.Map,

    fn deinit(self: *PoolState) void {
        self.job_ids.deinit();
        if (self.considered) |considered| {
            self.pool.*.considered = null;
            c.map_free(considered);
        }
        c.pool_free(self.pool);
    }
};

pub fn solve(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!OwnedObservation {
    return solveInternal(
        allocator,
        universe,
        null,
        goal,
        policy,
    );
}

pub fn solveProjected(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    visibility: *const solver_visibility.Projection,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!OwnedObservation {
    if (visibility.visible.len != universe.packages.len or
        visibility.hidden_reasons.len != universe.packages.len)
    {
        return error.InvalidModel;
    }
    return solveInternal(
        allocator,
        universe,
        visibility,
        goal,
        policy,
    );
}

fn solveInternal(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    visibility: ?*const solver_visibility.Projection,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!OwnedObservation {
    try validateInputs(universe, goal, policy);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    var state = try buildPool(
        arena,
        universe,
        policy,
        visibility,
    );
    defer state.deinit();

    var jobs: c.Queue = undefined;
    c.queue_init(&jobs);
    defer c.queue_free(&jobs);

    try encodeJobs(arena, &state, universe, goal, policy, &jobs);

    const solver = c.solver_create(state.pool) orelse return error.OutOfMemory;
    defer c.solver_free(solver);
    const solver_flags = try configureSolver(arena, solver, policy);

    const installonly_evictions = try arena.alloc(bool, universe.packages.len);
    @memset(installonly_evictions, false);
    var problem_count: c.Id = 0;
    var skip_broken = false;
    var transaction: ?*c.Transaction = null;
    defer if (transaction) |value| c.transaction_free(value);
    var actions: []const solver_model.Action = &.{};
    var synthesized_problem: ?solver_model.Problem = null;
    var installonly_retries: u8 = 0;

    while (true) {
        if (transaction) |value| {
            c.transaction_free(value);
            transaction = null;
        }
        problem_count = c.solver_solve(solver, &jobs);
        if (problem_count < 0) return error.SolverFailed;

        skip_broken = problem_count != 0 and policy.skip_broken and
            problemsAreSkippable(solver);
        if (problem_count != 0 and !skip_broken) break;

        transaction = c.solver_create_transaction(solver) orelse
            return error.OutOfMemory;
        actions = try collectActions(
            arena,
            &state,
            universe,
            goal,
            solver,
            transaction.?,
            installonly_evictions,
        );
        if (protectedRemoval(universe, policy.protected_names, actions)) |package_id| {
            synthesized_problem = .{
                .kind = .protected_package,
                .package = package_id,
            };
            break;
        }
        switch (try checkInstallonlyLimit(
            arena,
            &state,
            universe,
            policy,
            transaction.?,
            &jobs,
            installonly_evictions,
            installonly_retries != 0,
        )) {
            .satisfied => break,
            .retry => {
                installonly_retries += 1;
                continue;
            },
            .exceeded => |problem| {
                synthesized_problem = problem;
                break;
            },
        }
    }

    const effective_jobs = try collectEffectiveJobs(
        arena,
        &state,
        goal,
        &jobs,
    );
    if (problem_count != 0 and !skip_broken) {
        const problems = try collectProblems(arena, &state, universe, goal, solver);
        return .{
            .arena_state = arena_state,
            .outcome = .{
                .actions = &.{},
                .problems = problems,
                .skipped_jobs = &.{},
            },
            .selected = &.{},
            .order = &.{},
            .effective_jobs = effective_jobs,
            .effective_solver_flags = solver_flags,
        };
    }

    const skipped_jobs = if (skip_broken)
        try collectSkippedJobs(arena, &state, goal, solver)
    else
        &.{};
    if (synthesized_problem) |problem| {
        const problems = try arena.alloc(solver_model.Problem, 1);
        problems[0] = problem;
        return .{
            .arena_state = arena_state,
            .outcome = .{
                .actions = &.{},
                .problems = problems,
                .skipped_jobs = skipped_jobs,
            },
            .selected = &.{},
            .order = &.{},
            .effective_jobs = effective_jobs,
            .effective_solver_flags = solver_flags,
        };
    }
    const final_transaction = transaction orelse return error.UnsupportedResult;
    const selected = try collectSelected(arena, &state, final_transaction);
    const order = try collectOrder(arena, &state, final_transaction);

    return .{
        .arena_state = arena_state,
        .outcome = .{
            .actions = actions,
            .problems = &.{},
            .skipped_jobs = skipped_jobs,
        },
        .selected = selected,
        .order = order,
        .effective_jobs = effective_jobs,
        .effective_solver_flags = solver_flags,
    };
}

fn validateInputs(
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!void {
    if (!policy.architecture.allow_multilib) {
        return error.UnsupportedPolicy;
    }
    var clean_deps = policy.clean_deps;
    for (goal.jobs) |job| {
        clean_deps = clean_deps or job.flags.clean_deps;
    }
    if (clean_deps and
        policy.protected_names.len != 0 and
        !policy.allow_erasing)
    {
        return error.UnsupportedPolicy;
    }
    if (goal.jobs.len > std.math.maxInt(u32)) {
        return error.InvalidModel;
    }
    if (policy.skip_broken) {
        if (policy.best or
            policy.clean_deps or
            policy.protected_names.len != 0 or
            policy.installonly_names.len != 0 or
            goal.jobs.len > solver_model.max_skip_broken_jobs)
        {
            return error.UnsupportedPolicy;
        }
        for (goal.jobs) |job| {
            if (job.action != .install or
                std.meta.activeTag(job.selection) != .package or
                job.flags.clean_deps or
                job.flags.force_best or
                job.flags.targeted or
                job.flags.not_by_user or
                job.flags.weak)
            {
                return error.UnsupportedPolicy;
            }
        }
    }
    for (policy.protected_names) |name| {
        var installed_count: usize = 0;
        for (universe.packages) |package| {
            if (package.installed != null and
                std.mem.eql(u8, package.source.nevra.name, name))
            {
                installed_count += 1;
                if (installed_count > 1) return error.UnsupportedPolicy;
            }
        }
    }
    for (universe.repositories) |repository| {
        if (repository.priority == std.math.minInt(i32)) {
            return error.InvalidModel;
        }
        if (repository.cost != 1000) {
            return error.UnsupportedPolicy;
        }
    }
    for (goal.jobs) |job| {
        if ((job.action == .downgrade or job.action == .reinstall) and
            std.meta.activeTag(job.selection) != .package)
        {
            return error.UnsupportedPolicy;
        }
    }
}

fn buildPool(
    arena: std.mem.Allocator,
    universe: *const solver_model.Universe,
    policy: solver_model.SolvePolicy,
    visibility: ?*const solver_visibility.Projection,
) SolveError!PoolState {
    const pool = c.pool_create() orelse return error.OutOfMemory;
    errdefer c.pool_free(pool);

    if (c.pool_setdisttype(pool, c.DISTTYPE_RPM) < 0) {
        return error.InvalidModel;
    }
    const arch = policy.architecture.force_arch orelse policy.architecture.native_arch;
    c.pool_setarch(pool, try dupZ(arena, arch));
    _ = c.pool_set_flag(pool, c.POOL_FLAG_ADDFILEPROVIDESFILTERED, 1);

    const package_solvids = try arena.alloc(c.Id, universe.packages.len);
    @memset(package_solvids, 0);

    for (universe.repositories) |repository| {
        const repo = c.repo_create(pool, try dupZ(arena, repository.name)) orelse return error.OutOfMemory;
        repo.*.priority = switch (repository.kind) {
            .available => -repository.priority,
            .installed, .command_line => 0,
        };

        solv_bridge.buildRepositoryIntoRepo(
            arena,
            @ptrCast(repo),
            repository.source,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidRepoMetadata => error.InvalidModel,
        };
        c.repo_internalize(repo);

        const packages = repository.packages.slice(universe.packages);
        if (packages.len != 0 and repo.*.end - repo.*.start < packages.len) {
            return error.InvalidModel;
        }
        for (packages, 0..) |package, index| {
            package_solvids[@intFromEnum(package.id)] =
                repo.*.start + @as(c.Id, @intCast(index));
        }
        if (repository.kind == .installed) {
            c.pool_set_installed(pool, repo);
        }
    }

    c.pool_addfileprovides(pool);
    c.pool_createwhatprovides(pool);

    const considered = if (visibility) |projection| blk: {
        const map = try arena.create(c.Map);
        c.map_init(map, pool.*.nsolvables);
        c.map_setall(map);
        for (projection.visible, package_solvids) |
            is_visible,
            solvid,
        | {
            if (!is_visible) c.map_clr(map, solvid);
        }
        pool.*.considered = map;
        break :blk map;
    } else null;

    return .{
        .pool = pool,
        .package_solvids = package_solvids,
        .job_ids = std.array_list.Managed(?solver_model.JobId).init(std.heap.c_allocator),
        .considered = considered,
    };
}

fn encodeJobs(
    arena: std.mem.Allocator,
    state: *PoolState,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
    jobs: *c.Queue,
) SolveError!void {
    for (goal.jobs, 0..) |job, index| {
        var how = try actionFlags(job.action);
        const encoded_selection = try encodeSelection(arena, state, job.selection);
        how |= encoded_selection.flags;
        how |= jobFlags(job.flags);
        c.queue_push2(jobs, how, encoded_selection.what);
        try state.job_ids.append(@enumFromInt(@as(u32, @intCast(index))));
    }
    const installonly_job_start = state.job_ids.items.len;
    for (policy.installonly_names, 0..) |name, name_index| {
        if (!firstNameOccurrence(policy.installonly_names, name_index)) {
            continue;
        }
        if (!hasInstalledName(universe, name)) continue;
        c.queue_push2(
            jobs,
            c.SOLVER_SOLVABLE_NAME | c.SOLVER_MULTIVERSION,
            c.pool_str2id(state.pool, try dupZ(arena, name), 1),
        );
        try state.job_ids.append(null);
    }
    const installonly_job_end = state.job_ids.items.len;

    if (policy.allow_erasing) {
        for (universe.packages) |package| {
            const installed = package.installed orelse continue;
            if (installed.reason == .automatic) continue;
            c.queue_push2(
                jobs,
                c.SOLVER_SOLVABLE | c.SOLVER_USERINSTALLED,
                state.package_solvids[@intFromEnum(package.id)],
            );
            try state.job_ids.append(null);
        }
        if (policy.protected_names.len != 0) {
            for (universe.packages) |package| {
                if (package.installed == null) continue;
                const action = if (nameInList(
                    package.source.nevra.name,
                    policy.protected_names,
                ))
                    c.SOLVER_USERINSTALLED
                else
                    c.SOLVER_ALLOWUNINSTALL;
                c.queue_push2(
                    jobs,
                    c.SOLVER_SOLVABLE | action,
                    state.package_solvids[@intFromEnum(package.id)],
                );
                try state.job_ids.append(null);
            }
        }
    }
    for (0..state.job_ids.items.len) |index| {
        if (index >= installonly_job_start and index < installonly_job_end) {
            continue;
        }
        if (policy.best) jobs.elements[index * 2] |= c.SOLVER_FORCEBEST;
        if (policy.clean_deps) jobs.elements[index * 2] |= c.SOLVER_CLEANDEPS;
    }
}

fn collectEffectiveJobs(
    arena: std.mem.Allocator,
    state: *const PoolState,
    goal: solver_model.Goal,
    jobs: *const c.Queue,
) SolveError![]const EffectiveJob {
    if (jobs.count < 0 or
        @as(usize, @intCast(jobs.count)) != state.job_ids.items.len * 2)
    {
        return error.InvalidModel;
    }
    const effective_jobs = try arena.alloc(
        EffectiveJob,
        state.job_ids.items.len,
    );
    for (effective_jobs, 0..) |*effective, index| {
        const how = jobs.elements[index * 2];
        const job_id = state.job_ids.items[index];
        const input_job = if (job_id) |id|
            goal.jobs[@intFromEnum(id)]
        else
            null;
        effective.* = .{
            .id = job_id,
            .action = if (input_job) |job|
                job.action
            else
                try actionFromFlags(how),
            .selection = if (input_job) |job|
                try cloneSelection(arena, job.selection)
            else
                try selectionFromFlags(
                    arena,
                    state,
                    how,
                    jobs.elements[index * 2 + 1],
                ),
            .flags = .{
                .clean_deps = how & c.SOLVER_CLEANDEPS != 0,
                .force_best = how & c.SOLVER_FORCEBEST != 0,
                .targeted = how & c.SOLVER_TARGETED != 0,
                .not_by_user = how & c.SOLVER_NOTBYUSER != 0,
                .weak = how & c.SOLVER_WEAK != 0,
            },
        };
    }
    return effective_jobs;
}

const InstallonlyLimitCheck = union(enum) {
    satisfied,
    retry,
    exceeded: solver_model.Problem,
};

fn checkInstallonlyLimit(
    arena: std.mem.Allocator,
    state: *PoolState,
    universe: *const solver_model.Universe,
    policy: solver_model.SolvePolicy,
    transaction: *c.Transaction,
    jobs: *c.Queue,
    installonly_evictions: []bool,
    retried: bool,
) SolveError!InstallonlyLimitCheck {
    if (policy.installonly_names.len == 0) return .satisfied;
    if (installonly_evictions.len != universe.packages.len) {
        return error.InvalidModel;
    }

    const removed = try arena.alloc(bool, universe.packages.len);
    @memset(removed, false);
    var exceeded_name: ?[]const u8 = null;
    var exceeded_package: ?solver_model.PackageId = null;
    var exceeded_count: u64 = 0;

    for (policy.installonly_names, 0..) |name, name_index| {
        if (!firstNameOccurrence(policy.installonly_names, name_index)) {
            continue;
        }
        var count: u64 = 0;
        var name_package: ?solver_model.PackageId = null;
        for (universe.packages) |package| {
            if (package.installed != null and
                std.mem.eql(u8, package.source.nevra.name, name))
            {
                count += 1;
                if (name_package == null) name_package = package.id;
            }
        }
        for (queueElements(&transaction.*.steps)) |solvid| {
            const package_id = packageIdForSolvid(state, solvid) orelse {
                if (isResultSentinel(solvid)) continue;
                return error.UnsupportedResult;
            };
            const package = universe.package(package_id) orelse
                return error.InvalidModel;
            if (!std.mem.eql(u8, package.source.nevra.name, name)) continue;
            const raw_type = c.transaction_type(
                transaction,
                solvid,
                c.SOLVER_TRANSACTION_SHOW_MULTIINSTALL,
            );
            if (raw_type == c.SOLVER_TRANSACTION_MULTIINSTALL) {
                count += 1;
            } else if (raw_type == c.SOLVER_TRANSACTION_ERASE) {
                if (count == 0) return error.UnsupportedResult;
                removed[@intFromEnum(package_id)] = true;
                count -= 1;
            }
        }

        const limit: u64 = policy.installonly_limit;
        if (count <= limit) continue;
        var excess = count - limit;
        if (exceeded_name == null) {
            exceeded_name = name;
            exceeded_package = name_package;
            exceeded_count = excess;
        }
        if (retried) continue;

        var candidates = std.array_list.Managed(
            solver_model.PackageId,
        ).init(arena);
        for (universe.packages) |package| {
            if (package.installed == null or
                removed[@intFromEnum(package.id)] or
                !std.mem.eql(u8, package.source.nevra.name, name))
            {
                continue;
            }
            try candidates.append(package.id);
        }
        std.sort.pdq(
            solver_model.PackageId,
            candidates.items,
            universe,
            installedOrderLessThan,
        );
        for (candidates.items) |package_id| {
            if (excess == 0) break;
            const package_index: usize = @intFromEnum(package_id);
            removed[package_index] = true;
            installonly_evictions[package_index] = true;
            c.queue_push2(
                jobs,
                c.SOLVER_SOLVABLE | c.SOLVER_ERASE,
                state.package_solvids[package_index],
            );
            try state.job_ids.append(null);
            excess -= 1;
        }
    }

    const name = exceeded_name orelse return .satisfied;
    if (!retried) return .retry;
    return .{ .exceeded = .{
        .kind = .installonly_limit,
        .package = exceeded_package,
        .capability = .{ .name = try cloneString(arena, name) },
        .count = @intCast(exceeded_count),
    } };
}

fn installedOrderLessThan(
    universe: *const solver_model.Universe,
    left_id: solver_model.PackageId,
    right_id: solver_model.PackageId,
) bool {
    const left = universe.package(left_id).?.installed.?;
    const right = universe.package(right_id).?.installed.?;
    if (left.install_order != right.install_order) {
        return left.install_order < right.install_order;
    }
    if (left.rpmdb_hnum != right.rpmdb_hnum) {
        return left.rpmdb_hnum < right.rpmdb_hnum;
    }
    return @intFromEnum(left_id) < @intFromEnum(right_id);
}

fn hasInstalledName(
    universe: *const solver_model.Universe,
    name: []const u8,
) bool {
    for (universe.packages) |package| {
        if (package.installed != null and
            std.mem.eql(u8, package.source.nevra.name, name))
        {
            return true;
        }
    }
    return false;
}

fn firstNameOccurrence(names: []const []const u8, index: usize) bool {
    for (names[0..index]) |name| {
        if (std.mem.eql(u8, name, names[index])) return false;
    }
    return true;
}

const EncodedSelection = struct {
    flags: c.Id,
    what: c.Id,
};

fn encodeSelection(
    arena: std.mem.Allocator,
    state: *const PoolState,
    selection: solver_model.Selection,
) SolveError!EncodedSelection {
    return switch (selection) {
        .all => .{ .flags = c.SOLVER_SOLVABLE_ALL, .what = 0 },
        .package => |package_id| blk: {
            const index: usize = @intFromEnum(package_id);
            if (index >= state.package_solvids.len) return error.InvalidModel;
            break :blk .{
                .flags = c.SOLVER_SOLVABLE,
                .what = state.package_solvids[index],
            };
        },
        .name => |name| .{
            .flags = c.SOLVER_SOLVABLE_NAME,
            .what = c.pool_str2id(state.pool, try dupZ(arena, name), 1),
        },
        .capability => |relation| .{
            .flags = c.SOLVER_SOLVABLE_PROVIDES,
            .what = try relationId(arena, state.pool, relation),
        },
    };
}

fn actionFlags(action: solver_model.JobAction) SolveError!c.Id {
    return switch (action) {
        .install, .downgrade, .reinstall => c.SOLVER_INSTALL,
        .erase => c.SOLVER_ERASE,
        .update => c.SOLVER_UPDATE,
        .dist_sync => c.SOLVER_DISTUPGRADE,
        .lock => c.SOLVER_LOCK,
        .multiversion => c.SOLVER_MULTIVERSION,
        .user_installed => c.SOLVER_USERINSTALLED,
        .allow_uninstall => c.SOLVER_ALLOWUNINSTALL,
    };
}

fn actionFromFlags(how: c.Id) SolveError!solver_model.JobAction {
    return switch (how & c.SOLVER_JOBMASK) {
        c.SOLVER_INSTALL => .install,
        c.SOLVER_ERASE => .erase,
        c.SOLVER_UPDATE => .update,
        c.SOLVER_DISTUPGRADE => .dist_sync,
        c.SOLVER_LOCK => .lock,
        c.SOLVER_MULTIVERSION => .multiversion,
        c.SOLVER_USERINSTALLED => .user_installed,
        c.SOLVER_ALLOWUNINSTALL => .allow_uninstall,
        else => error.InvalidModel,
    };
}

fn selectionFromFlags(
    arena: std.mem.Allocator,
    state: *const PoolState,
    how: c.Id,
    what: c.Id,
) SolveError!solver_model.Selection {
    return switch (how & c.SOLVER_SELECTMASK) {
        c.SOLVER_SOLVABLE_ALL => .all,
        c.SOLVER_SOLVABLE => .{
            .package = packageIdForSolvid(state, what) orelse return error.UnsupportedResult,
        },
        c.SOLVER_SOLVABLE_NAME => .{
            .name = try cloneString(
                arena,
                std.mem.span(c.pool_id2str(state.pool, what)),
            ),
        },
        else => error.UnsupportedResult,
    };
}

fn cloneSelection(
    arena: std.mem.Allocator,
    selection: solver_model.Selection,
) SolveError!solver_model.Selection {
    return switch (selection) {
        .all => .all,
        .package => |package| .{ .package = package },
        .name => |name| .{ .name = try cloneString(arena, name) },
        .capability => |capability| .{
            .capability = try cloneRelation(arena, capability),
        },
    };
}

fn jobFlags(flags: solver_model.JobFlags) c.Id {
    var out: c.Id = 0;
    if (flags.clean_deps) out |= c.SOLVER_CLEANDEPS;
    if (flags.force_best) out |= c.SOLVER_FORCEBEST;
    if (flags.targeted) out |= c.SOLVER_TARGETED;
    if (flags.not_by_user) out |= c.SOLVER_NOTBYUSER;
    if (flags.weak) out |= c.SOLVER_WEAK;
    return out;
}

fn configureSolver(
    arena: std.mem.Allocator,
    solver: *c.Solver,
    policy: solver_model.SolvePolicy,
) SolveError![]const SolverFlag {
    var flags = std.array_list.Managed(SolverFlag).init(arena);

    try setSolverFlag(solver, &flags, c.SOLVER_FLAG_BEST_OBEY_POLICY, .best_obey_policy, true);
    try setSolverFlag(solver, &flags, c.SOLVER_FLAG_ALLOW_VENDORCHANGE, .allow_vendor_change, true);
    try setSolverFlag(solver, &flags, c.SOLVER_FLAG_KEEP_ORPHANS, .keep_orphans, policy.keep_orphans);
    try setSolverFlag(solver, &flags, c.SOLVER_FLAG_YUM_OBSOLETES, .yum_obsoletes, true);
    try setSolverFlag(solver, &flags, c.SOLVER_FLAG_ALLOW_DOWNGRADE, .allow_downgrade, true);
    try setSolverFlag(solver, &flags, c.SOLVER_FLAG_INSTALL_ALSO_UPDATES, .install_also_updates, true);
    try setSolverFlag(
        solver,
        &flags,
        c.SOLVER_FLAG_ALLOW_UNINSTALL,
        .allow_uninstall,
        policy.allow_erasing and policy.protected_names.len == 0,
    );
    try setSolverFlag(solver, &flags, c.SOLVER_FLAG_IGNORE_RECOMMENDED, .ignore_recommended, !policy.install_weak_deps);

    std.sort.pdq(SolverFlag, flags.items, {}, solverFlagLessThan);
    return flags.toOwnedSlice();
}

fn nameInList(name: []const u8, names: []const []const u8) bool {
    for (names) |candidate| {
        if (std.mem.eql(u8, name, candidate)) return true;
    }
    return false;
}

fn protectedRemoval(
    universe: *const solver_model.Universe,
    protected_names: []const []const u8,
    actions: []const solver_model.Action,
) ?solver_model.PackageId {
    for (actions) |action| {
        if (action.kind == .erase) {
            const package = universe.package(action.package) orelse
                continue;
            if (package.installed != null and
                nameInList(
                    package.source.nevra.name,
                    protected_names,
                ))
            {
                return action.package;
            }
        }
        const replacement = universe.package(action.package) orelse continue;
        for (action.priors) |package_id| {
            const package = universe.package(package_id) orelse continue;
            if (package.installed == null or
                !nameInList(
                    package.source.nevra.name,
                    protected_names,
                ))
            {
                continue;
            }
            if (!solver_rules.isSource(
                replacement.source.nevra.arch,
            ) and std.mem.eql(
                u8,
                package.source.nevra.name,
                replacement.source.nevra.name,
            )) {
                continue;
            }
            return package_id;
        }
    }
    return null;
}

fn setSolverFlag(
    solver: *c.Solver,
    flags: *std.array_list.Managed(SolverFlag),
    raw_flag: c_int,
    flag: SolverFlag,
    enabled: bool,
) SolveError!void {
    _ = c.solver_set_flag(solver, raw_flag, @intFromBool(enabled));
    if (enabled) try flags.append(flag);
}

fn queueElements(queue: *const c.Queue) []const c.Id {
    if (queue.count == 0) return &.{};
    return queue.elements[0..@intCast(queue.count)];
}

fn collectSelected(
    arena: std.mem.Allocator,
    state: *const PoolState,
    transaction: *c.Transaction,
) SolveError![]const solver_model.PackageId {
    var raw: c.Queue = undefined;
    c.queue_init(&raw);
    defer c.queue_free(&raw);
    _ = c.transaction_installedresult(transaction, &raw);

    var selected = std.array_list.Managed(solver_model.PackageId).init(arena);
    for (queueElements(&raw)) |solvid| {
        const package = packageIdForSolvid(state, solvid) orelse {
            if (isResultSentinel(solvid)) continue;
            return error.UnsupportedResult;
        };
        try selected.append(package);
    }
    std.sort.pdq(solver_model.PackageId, selected.items, {}, packageIdLessThan);
    return selected.toOwnedSlice();
}

fn collectActions(
    arena: std.mem.Allocator,
    state: *const PoolState,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    solver: *c.Solver,
    transaction: *c.Transaction,
    installonly_evictions: []const bool,
) SolveError![]const solver_model.Action {
    if (installonly_evictions.len != universe.packages.len) {
        return error.InvalidModel;
    }
    var actions = std.array_list.Managed(solver_model.Action).init(arena);
    const mode = c.SOLVER_TRANSACTION_SHOW_ACTIVE |
        c.SOLVER_TRANSACTION_SHOW_ALL |
        c.SOLVER_TRANSACTION_SHOW_OBSOLETES |
        c.SOLVER_TRANSACTION_CHANGE_IS_REINSTALL;

    for (queueElements(&transaction.*.steps)) |solvid| {
        const package_id = packageIdForSolvid(state, solvid) orelse {
            if (isResultSentinel(solvid)) continue;
            return error.UnsupportedResult;
        };
        const package = universe.package(package_id) orelse return error.InvalidModel;
        const raw_type = c.transaction_type(transaction, solvid, mode);

        var kind: solver_model.ActionKind = undefined;
        if (raw_type == c.SOLVER_TRANSACTION_INSTALL or
            raw_type == c.SOLVER_TRANSACTION_MULTIINSTALL)
        {
            kind = .install;
        } else if (raw_type == c.SOLVER_TRANSACTION_UPGRADE) {
            kind = .upgrade;
        } else if (raw_type == c.SOLVER_TRANSACTION_DOWNGRADE) {
            kind = .downgrade;
        } else if (raw_type == c.SOLVER_TRANSACTION_REINSTALL or
            raw_type == c.SOLVER_TRANSACTION_CHANGE)
        {
            kind = .reinstall;
        } else if (raw_type == c.SOLVER_TRANSACTION_OBSOLETES) {
            kind = .obsolete;
        } else if (raw_type == c.SOLVER_TRANSACTION_ERASE and package.installed != null) {
            kind = .erase;
        } else {
            continue;
        }

        var priors =
            std.array_list.Managed(solver_model.PackageId).init(arena);
        if (kind != .install and kind != .erase) {
            var prior_queue: c.Queue = undefined;
            c.queue_init(&prior_queue);
            defer c.queue_free(&prior_queue);
            c.transaction_all_obs_pkgs(transaction, solvid, &prior_queue);
            for (queueElements(&prior_queue)) |prior_solvid| {
                const candidate = packageIdForSolvid(state, prior_solvid) orelse {
                    if (isResultSentinel(prior_solvid)) continue;
                    return error.UnsupportedResult;
                };
                try priors.append(candidate);
            }
            std.sort.pdq(
                solver_model.PackageId,
                priors.items,
                {},
                packageIdLessThan,
            );
        }

        const decision = decisionReason(state, goal, solver, solvid);
        const installonly_eviction = kind == .erase and
            installonly_evictions[@intFromEnum(package_id)];
        try actions.append(.{
            .package = package_id,
            .priors = try priors.toOwnedSlice(),
            .kind = kind,
            .reason = if (kind == .obsolete)
                .obsoletes
            else if (installonly_eviction)
                .installonly_limit
            else
                decision.reason,
            .requested_by = if (installonly_eviction)
                null
            else
                decision.requested_by,
        });
    }

    std.sort.pdq(solver_model.Action, actions.items, {}, actionLessThan);
    return actions.toOwnedSlice();
}

const DecisionReason = struct {
    reason: solver_model.TransactionReason,
    requested_by: ?solver_model.JobId = null,
};

fn decisionReason(
    state: *const PoolState,
    goal: solver_model.Goal,
    solver: *c.Solver,
    solvid: c.Id,
) DecisionReason {
    var info: c.Id = 0;
    const raw_reason = c.solver_describe_decision(solver, solvid, &info);
    if (raw_reason == c.SOLVER_REASON_WEAKDEP) {
        return .{ .reason = .weak_dependency };
    }
    if (raw_reason == c.SOLVER_REASON_CLEANDEPS_ERASE) {
        return .{ .reason = .cleanup };
    }
    if (raw_reason == c.SOLVER_REASON_UPDATE_INSTALLED or
        raw_reason == c.SOLVER_REASON_KEEP_INSTALLED or
        raw_reason == c.SOLVER_REASON_RESOLVE_ORPHAN)
    {
        return .{ .reason = .policy };
    }
    if (info != 0) {
        var from: c.Id = 0;
        var to: c.Id = 0;
        var dep: c.Id = 0;
        var rule_type = c.solver_ruleinfo(solver, info, &from, &to, &dep);
        if (rule_type == c.SOLVER_RULE_BEST and to > 0) {
            const job_rule = to;
            rule_type = c.solver_ruleinfo(
                solver,
                job_rule,
                &from,
                &to,
                &dep,
            );
        }
        if ((rule_type == c.SOLVER_RULE_JOB or
            rule_type == c.SOLVER_RULE_JOB_NOTHING_PROVIDES_DEP or
            rule_type == c.SOLVER_RULE_JOB_UNKNOWN_PACKAGE) and from >= 0)
        {
            const job_index: usize = @intCast(@divTrunc(from, 2));
            if (job_index < state.job_ids.items.len) {
                if (state.job_ids.items[job_index]) |job_id| {
                    const input_index: usize = @intFromEnum(job_id);
                    if (input_index < goal.jobs.len) {
                        return .{
                            .reason = requestReason(goal.jobs[input_index].reason),
                            .requested_by = job_id,
                        };
                    }
                }
            }
        }
    }
    return .{ .reason = .dependency };
}

fn requestReason(reason: solver_model.RequestReason) solver_model.TransactionReason {
    return switch (reason) {
        .user => .user,
        .dependency => .dependency,
        .weak_dependency => .weak_dependency,
        .cleanup => .cleanup,
        .installonly_limit => .installonly_limit,
        .policy => .policy,
    };
}

fn collectProblems(
    arena: std.mem.Allocator,
    state: *const PoolState,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    solver: *c.Solver,
) SolveError![]const solver_model.Problem {
    var problems = std.array_list.Managed(solver_model.Problem).init(arena);
    const count = c.solver_problem_count(solver);

    var problem_number: c.Id = 1;
    while (problem_number <= count) : (problem_number += 1) {
        const rule = c.solver_findproblemrule(solver, problem_number);
        var source: c.Id = 0;
        var target: c.Id = 0;
        var dep: c.Id = 0;
        const rule_type = c.solver_ruleinfo(solver, rule, &source, &target, &dep);

        const job_id = if (isJobRule(rule_type) and source >= 0)
            jobIdForQueueOffset(state, source)
        else
            null;
        const package_id = if (isJobRule(rule_type))
            null
        else
            packageIdForSolvid(state, source);
        try problems.append(.{
            .kind = problemKind(rule_type),
            .package = package_id,
            .related_package = try relatedPackageForRule(
                state,
                rule_type,
                target,
            ),
            .capability = try findProblemRelation(
                arena,
                state,
                universe,
                goal,
                rule_type,
                source,
                dep,
                job_id,
            ),
            .job = job_id,
            .count = 1,
        });
    }

    std.sort.pdq(solver_model.Problem, problems.items, {}, problemLessThan);
    var write_index: usize = 0;
    for (problems.items) |problem| {
        if (write_index != 0 and sameProblem(problems.items[write_index - 1], problem)) {
            problems.items[write_index - 1].count += 1;
            continue;
        }
        problems.items[write_index] = problem;
        write_index += 1;
    }
    problems.items.len = write_index;
    return problems.toOwnedSlice();
}

fn problemsAreSkippable(solver: *c.Solver) bool {
    const count = c.solver_problem_count(solver);
    var problem_number: c.Id = 1;
    while (problem_number <= count) : (problem_number += 1) {
        const rule = c.solver_findproblemrule(solver, problem_number);
        var source: c.Id = 0;
        var target: c.Id = 0;
        var dep: c.Id = 0;
        const rule_type = c.solver_ruleinfo(
            solver,
            rule,
            &source,
            &target,
            &dep,
        );
        if (rule_type & c.SOLVER_RULE_PKG == 0) return false;
    }
    return true;
}

fn collectSkippedJobs(
    arena: std.mem.Allocator,
    state: *const PoolState,
    goal: solver_model.Goal,
    solver: *c.Solver,
) SolveError![]const solver_model.JobId {
    const skipped = try arena.alloc(bool, goal.jobs.len);
    @memset(skipped, false);

    var rules: c.Queue = undefined;
    c.queue_init(&rules);
    defer c.queue_free(&rules);

    const count = c.solver_problem_count(solver);
    var problem_number: c.Id = 1;
    while (problem_number <= count) : (problem_number += 1) {
        c.solver_findallproblemrules(solver, problem_number, &rules);
        for (queueElements(&rules)) |rule| {
            const raw_job_index = c.solver_rule2jobidx(solver, rule);
            if (raw_job_index == 0) continue;
            const queue_offset = raw_job_index - 1;
            if (queue_offset < 0 or queue_offset & 1 != 0) {
                return error.UnsupportedResult;
            }
            const queue_index: usize = @intCast(@divTrunc(queue_offset, 2));
            if (queue_index >= state.job_ids.items.len) {
                return error.UnsupportedResult;
            }
            const job_id = state.job_ids.items[queue_index] orelse continue;
            const job_index: usize = @intFromEnum(job_id);
            if (job_index >= skipped.len) return error.UnsupportedResult;
            skipped[job_index] = true;
        }
    }

    var skipped_jobs = std.array_list.Managed(solver_model.JobId).init(arena);
    for (skipped, 0..) |is_skipped, job_index| {
        if (!is_skipped) continue;
        try skipped_jobs.append(@enumFromInt(@as(u32, @intCast(job_index))));
    }
    if (skipped_jobs.items.len == 0) return error.UnsupportedResult;
    return skipped_jobs.toOwnedSlice();
}

fn relatedPackageForRule(
    state: *const PoolState,
    rule_type: c.SolverRuleinfo,
    target: c.Id,
) SolveError!?solver_model.PackageId {
    const target_is_solvable = rule_type == c.SOLVER_RULE_PKG_SAME_NAME or
        rule_type == c.SOLVER_RULE_PKG_CONFLICTS or
        rule_type == c.SOLVER_RULE_PKG_OBSOLETES or
        rule_type == c.SOLVER_RULE_PKG_IMPLICIT_OBSOLETES or
        rule_type == c.SOLVER_RULE_PKG_INSTALLED_OBSOLETES or
        rule_type == c.SOLVER_RULE_PKG_CONSTRAINS or
        rule_type == c.SOLVER_RULE_PKG_SUPPLEMENTS or
        rule_type == c.SOLVER_RULE_YUMOBS;
    if (!target_is_solvable or target == 0) return null;
    return packageIdForSolvid(state, target) orelse {
        if (isResultSentinel(target)) return null;
        return error.UnsupportedResult;
    };
}

fn isJobRule(rule_type: c.SolverRuleinfo) bool {
    return rule_type == c.SOLVER_RULE_JOB or
        rule_type == c.SOLVER_RULE_JOB_NOTHING_PROVIDES_DEP or
        rule_type == c.SOLVER_RULE_JOB_PROVIDED_BY_SYSTEM or
        rule_type == c.SOLVER_RULE_JOB_UNKNOWN_PACKAGE or
        rule_type == c.SOLVER_RULE_JOB_UNSUPPORTED;
}

fn jobIdForQueueOffset(
    state: *const PoolState,
    offset: c.Id,
) ?solver_model.JobId {
    const index: usize = @intCast(@divTrunc(offset, 2));
    if (index >= state.job_ids.items.len) return null;
    return state.job_ids.items[index];
}

fn problemKind(rule_type: c.SolverRuleinfo) solver_model.ProblemKind {
    if (rule_type == c.SOLVER_RULE_PKG_REQUIRES or
        rule_type == c.SOLVER_RULE_PKG_NOTHING_PROVIDES_DEP)
    {
        return .unsatisfied_requirement;
    }
    if (rule_type == c.SOLVER_RULE_PKG_CONFLICTS or
        rule_type == c.SOLVER_RULE_PKG_SELF_CONFLICT or
        rule_type == c.SOLVER_RULE_PKG_SAME_NAME)
    {
        return .conflict;
    }
    if (rule_type == c.SOLVER_RULE_PKG_OBSOLETES or
        rule_type == c.SOLVER_RULE_PKG_IMPLICIT_OBSOLETES or
        rule_type == c.SOLVER_RULE_PKG_INSTALLED_OBSOLETES or
        rule_type == c.SOLVER_RULE_YUMOBS)
    {
        return .obsoletes;
    }
    if (isJobRule(rule_type)) {
        return .no_candidate;
    }
    return .not_installable;
}

fn collectOrder(
    arena: std.mem.Allocator,
    state: *const PoolState,
    transaction: *c.Transaction,
) SolveError![]const OrderStep {
    c.transaction_order(transaction, 0);
    var order = std.array_list.Managed(OrderStep).init(arena);
    for (queueElements(&transaction.*.steps)) |solvid| {
        const package_id = packageIdForSolvid(state, solvid) orelse {
            if (isResultSentinel(solvid)) continue;
            return error.UnsupportedResult;
        };
        const solvable = c.pool_id2solvable(state.pool, solvid) orelse return error.InvalidModel;
        try order.append(.{
            .operation = if (state.pool.*.installed != null and
                solvable.*.repo == state.pool.*.installed)
                .erase
            else
                .install,
            .package = package_id,
        });
    }
    return order.toOwnedSlice();
}

fn findProblemRelation(
    arena: std.mem.Allocator,
    state: *const PoolState,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    rule_type: c.SolverRuleinfo,
    source: c.Id,
    dep: c.Id,
    job_id: ?solver_model.JobId,
) SolveError!?metadata.Relation {
    if (dep == 0) return null;

    if (isJobRule(rule_type)) {
        const id = job_id orelse return null;
        const index: usize = @intFromEnum(id);
        if (index >= goal.jobs.len) return error.InvalidModel;
        const relation = switch (goal.jobs[index].selection) {
            .name => |name| metadata.Relation{ .name = name },
            .capability => |capability| capability,
            else => return null,
        };
        if (try relationId(arena, state.pool, relation) != dep) return null;
        return try cloneRelation(arena, relation);
    }

    const kind = dependencyKindForRule(rule_type) orelse return null;
    const package_id = packageIdForSolvid(state, source) orelse {
        if (isResultSentinel(source)) return null;
        return error.UnsupportedResult;
    };
    const package = universe.package(package_id) orelse return error.InvalidModel;

    var best: ?metadata.Relation = null;
    for (package.relationEntries(universe, kind)) |relation| {
        if (try relationId(arena, state.pool, relation) != dep) continue;
        if (best == null or relationOrder(relation, best.?) == .lt) {
            best = relation;
        }
    }
    return if (best) |relation| try cloneRelation(arena, relation) else null;
}

fn dependencyKindForRule(
    rule_type: c.SolverRuleinfo,
) ?metadata.DependencyKind {
    return switch (rule_type) {
        c.SOLVER_RULE_PKG_NOTHING_PROVIDES_DEP,
        c.SOLVER_RULE_PKG_REQUIRES,
        => .requires,
        c.SOLVER_RULE_PKG_SELF_CONFLICT,
        c.SOLVER_RULE_PKG_CONFLICTS,
        => .conflicts,
        c.SOLVER_RULE_PKG_OBSOLETES,
        c.SOLVER_RULE_PKG_IMPLICIT_OBSOLETES,
        c.SOLVER_RULE_PKG_INSTALLED_OBSOLETES,
        c.SOLVER_RULE_YUMOBS,
        => .obsoletes,
        c.SOLVER_RULE_PKG_RECOMMENDS => .recommends,
        c.SOLVER_RULE_PKG_SUPPLEMENTS => .supplements,
        else => null,
    };
}

fn packageIdForSolvid(
    state: *const PoolState,
    solvid: c.Id,
) ?solver_model.PackageId {
    for (state.package_solvids, 0..) |candidate, index| {
        if (candidate == solvid) {
            return @enumFromInt(@as(u32, @intCast(index)));
        }
    }
    return null;
}

fn isResultSentinel(solvid: c.Id) bool {
    return solvid == 0 or solvid == c.SYSTEMSOLVABLE;
}

fn relationId(
    arena: std.mem.Allocator,
    pool: *c.Pool,
    relation: metadata.Relation,
) SolveError!c.Id {
    const name = c.pool_str2id(pool, try dupZ(arena, relation.name), 1);
    if (relation.flags == null or relation.comparison == .none) return name;

    const evr_id = try evrIdOptional(
        arena,
        pool,
        relation.epoch,
        relation.version,
        relation.release,
    );
    const flags: c_int = switch (relation.comparison) {
        .none => 0,
        .eq => c.REL_EQ,
        .lt => c.REL_LT,
        .le => c.REL_LT | c.REL_EQ,
        .gt => c.REL_GT,
        .ge => c.REL_GT | c.REL_EQ,
    };
    return c.pool_rel2id(pool, name, evr_id, flags, 1);
}

fn evrIdOptional(
    arena: std.mem.Allocator,
    pool: *c.Pool,
    epoch: ?u32,
    version: ?[]const u8,
    release: ?[]const u8,
) SolveError!c.Id {
    if (epoch == null and version == null and release == null) return 0;

    const normalized_epoch = epoch orelse if (version) |value|
        if (needsZeroEpoch(value)) @as(?u32, 0) else null
    else
        null;
    const evr = std.fmt.allocPrint(
        arena,
        "{s}{s}{s}",
        .{
            if (normalized_epoch) |value|
                try std.fmt.allocPrint(arena, "{d}:", .{value})
            else
                "",
            version orelse "",
            if (release) |value|
                try std.fmt.allocPrint(arena, "-{s}", .{value})
            else
                "",
        },
    ) catch return error.OutOfMemory;
    if (evr.len == 0) return 0;
    return c.pool_str2id(pool, try dupZ(arena, evr), 1);
}

fn needsZeroEpoch(version: []const u8) bool {
    var index: usize = 0;
    while (index < version.len and std.ascii.isDigit(version[index])) : (index += 1) {}
    return index > 0 and index < version.len and version[index] == ':';
}

fn cloneRelation(
    arena: std.mem.Allocator,
    relation: metadata.Relation,
) SolveError!metadata.Relation {
    var cloned = relation;
    cloned.name = try cloneString(arena, relation.name);
    cloned.flags = try cloneOptionalString(arena, relation.flags);
    cloned.version = try cloneOptionalString(arena, relation.version);
    cloned.release = try cloneOptionalString(arena, relation.release);
    return cloned;
}

fn cloneString(
    arena: std.mem.Allocator,
    value: []const u8,
) SolveError![]const u8 {
    return arena.dupe(u8, value) catch return error.OutOfMemory;
}

fn cloneOptionalString(
    arena: std.mem.Allocator,
    value: ?[]const u8,
) SolveError!?[]const u8 {
    return if (value) |text| try cloneString(arena, text) else null;
}

fn dupZ(arena: std.mem.Allocator, value: []const u8) SolveError![:0]const u8 {
    return arena.dupeZ(u8, value) catch return error.OutOfMemory;
}

fn packageIdLessThan(
    _: void,
    left: solver_model.PackageId,
    right: solver_model.PackageId,
) bool {
    return @intFromEnum(left) < @intFromEnum(right);
}

fn solverFlagLessThan(_: void, left: SolverFlag, right: SolverFlag) bool {
    return @intFromEnum(left) < @intFromEnum(right);
}

fn actionLessThan(_: void, left: solver_model.Action, right: solver_model.Action) bool {
    return @intFromEnum(left.package) < @intFromEnum(right.package);
}

fn problemLessThan(_: void, left: solver_model.Problem, right: solver_model.Problem) bool {
    if (@intFromEnum(left.kind) != @intFromEnum(right.kind)) {
        return @intFromEnum(left.kind) < @intFromEnum(right.kind);
    }
    const left_package = if (left.package) |value| @intFromEnum(value) else std.math.maxInt(u32);
    const right_package = if (right.package) |value| @intFromEnum(value) else std.math.maxInt(u32);
    if (left_package != right_package) return left_package < right_package;
    const left_related = if (left.related_package) |value| @intFromEnum(value) else std.math.maxInt(u32);
    const right_related = if (right.related_package) |value| @intFromEnum(value) else std.math.maxInt(u32);
    if (left_related != right_related) return left_related < right_related;
    const capability_order = optionalRelationOrder(left.capability, right.capability);
    if (capability_order != .eq) return capability_order == .lt;
    const left_job = if (left.job) |value| @intFromEnum(value) else std.math.maxInt(u32);
    const right_job = if (right.job) |value| @intFromEnum(value) else std.math.maxInt(u32);
    return left_job < right_job;
}

fn sameProblem(left: solver_model.Problem, right: solver_model.Problem) bool {
    if (left.kind != right.kind or
        left.package != right.package or
        left.related_package != right.related_package or
        left.job != right.job)
    {
        return false;
    }
    if (left.capability == null or right.capability == null) {
        return left.capability == null and right.capability == null;
    }
    const left_capability = left.capability.?;
    const right_capability = right.capability.?;
    return relationOrder(left_capability, right_capability) == .eq;
}

fn optionalRelationOrder(
    left: ?metadata.Relation,
    right: ?metadata.Relation,
) std.math.Order {
    if (left == null or right == null) {
        if (left == null and right == null) return .eq;
        return if (left == null) .lt else .gt;
    }
    return relationOrder(left.?, right.?);
}

fn relationOrder(left: metadata.Relation, right: metadata.Relation) std.math.Order {
    var order = std.mem.order(u8, left.name, right.name);
    if (order != .eq) return order;
    order = std.math.order(@intFromEnum(left.comparison), @intFromEnum(right.comparison));
    if (order != .eq) return order;
    order = optionalU32Order(left.epoch, right.epoch);
    if (order != .eq) return order;
    order = optionalStringOrder(left.version, right.version);
    if (order != .eq) return order;
    order = optionalStringOrder(left.release, right.release);
    if (order != .eq) return order;
    order = optionalStringOrder(left.flags, right.flags);
    if (order != .eq) return order;
    order = std.math.order(@intFromBool(left.pre), @intFromBool(right.pre));
    if (order != .eq) return order;
    return std.math.order(left.sense, right.sense);
}

fn optionalU32Order(left: ?u32, right: ?u32) std.math.Order {
    if (left == null or right == null) {
        if (left == null and right == null) return .eq;
        return if (left == null) .lt else .gt;
    }
    return std.math.order(left.?, right.?);
}

fn optionalStringOrder(
    left: ?[]const u8,
    right: ?[]const u8,
) std.math.Order {
    if (left == null or right == null) {
        if (left == null and right == null) return .eq;
        return if (left == null) .lt else .gt;
    }
    return std.mem.order(u8, left.?, right.?);
}
