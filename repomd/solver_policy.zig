//! Package-policy preparation for the native solver.
//!
//! This slice preserves installed packages unless a same-name or explicit
//! obsoleting replacement is selected and ranks ordinary job and requirement
//! candidates by repository priority, architecture, same-name package EVR,
//! and common versioned provides. It also handles update-all, distro-sync-all,
//! weak dependency selection, ordinary allow-erasing, and rule-class-aware
//! skipping of broken exact install jobs. Cleanup policy remains separate
//! follow-up work.

const std = @import("std");
const query_index = @import("index.zig");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");
const solver_rules = @import("solver_rules.zig");
const solver_search = @import("solver_search.zig");

const PackageIdList = std.array_list.Managed(solver_model.PackageId);
const CandidateGroupList =
    std.array_list.Managed(solver_search.CandidateGroup);
const ReplacementGroup = struct {
    candidates: solver_rules.PackageIdRange,
    installed: solver_model.PackageId,
    kind: solver_rules.ReplacementKind,
    job: solver_model.JobId,
    force_best: bool,
    installed_obsoleted: bool,
};
const ReplacementGroupList = std.array_list.Managed(ReplacementGroup);

pub const WeakOptions = struct {
    enabled: bool = true,
    add_already_recommended: bool = false,
};

pub const AcceptedWeak = struct {
    package: solver_model.PackageId,
    dependency: solver_rules.DependencyRef,
};

pub const WeakResult = struct {
    allocator: std.mem.Allocator,
    result: solver_search.Result,
    accepted: []const AcceptedWeak,

    pub fn deinit(self: *WeakResult) void {
        self.allocator.free(self.accepted);
        self.result.deinit();
        self.* = undefined;
    }
};

pub const SkipBrokenResult = struct {
    allocator: std.mem.Allocator,
    result: solver_search.Result,
    skipped_jobs: []const solver_model.JobId,

    pub fn deinit(self: *SkipBrokenResult) void {
        self.allocator.free(self.skipped_jobs);
        self.result.deinit();
        self.* = undefined;
    }
};

pub const SkipBrokenError = solver_search.SolveError || error{
    UnsupportedPolicy,
};

pub const PrepareError = error{
    OutOfMemory,
    InvalidFormula,
    UnsupportedPolicy,
    TooManyClauses,
    TooManyLiterals,
};

pub const PrepareOptions = struct {
    best: bool = false,
    allow_erasing: bool = false,
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    formula: solver_rules.OwnedFormula,
    decision_policy: solver_search.CandidateDecisionPolicy,
    best: bool = false,

    pub fn solve(
        self: *const Prepared,
        allocator: std.mem.Allocator,
    ) solver_search.SolveError!solver_search.Result {
        return self.solveAssuming(allocator, &.{});
    }

    pub fn solveAssuming(
        self: *const Prepared,
        allocator: std.mem.Allocator,
        assumptions: []const solver_rules.Literal,
    ) solver_search.SolveError!solver_search.Result {
        return solver_search.solveWithCandidatePolicy(
            allocator,
            &self.formula,
            assumptions,
            self.decision_policy,
        ) catch |err| switch (err) {
            error.InvalidCandidatePolicy => return error.InvalidDecisionPolicy,
            else => |solve_error| return solve_error,
        };
    }

    /// Skip up to `max_skip_broken_jobs` exact install jobs whose
    /// unsatisfiable cores require package rules.
    ///
    /// Job-only contradictions and hard policy failures remain unsatisfiable.
    pub fn solveSkipBroken(
        self: *const Prepared,
        allocator: std.mem.Allocator,
    ) SkipBrokenError!SkipBrokenResult {
        return solveSkippingBrokenJobs(self, allocator);
    }

    /// Resolve ordinary recommends and supplements after the hard solution.
    ///
    /// Suggestions and enhances remain ordering metadata and do not directly
    /// install packages.
    pub fn solveWeak(
        self: *const Prepared,
        allocator: std.mem.Allocator,
        options: WeakOptions,
    ) solver_search.SolveError!WeakResult {
        return self.solveWeakAssuming(allocator, &.{}, options);
    }

    pub fn solveWeakAssuming(
        self: *const Prepared,
        allocator: std.mem.Allocator,
        assumptions: []const solver_rules.Literal,
        options: WeakOptions,
    ) solver_search.SolveError!WeakResult {
        var session = solver_search.IncrementalSolver.init(
            allocator,
            &self.formula,
            assumptions,
            self.decision_policy,
        ) catch |err| switch (err) {
            error.InvalidCandidatePolicy => return error.InvalidDecisionPolicy,
            else => |solve_error| return solve_error,
        };
        defer session.deinit();

        var accepted = std.array_list.Managed(AcceptedWeak).init(allocator);
        defer accepted.deinit();
        if (try session.solveHard() and options.enabled) {
            try resolveWeakRequests(
                allocator,
                &self.formula,
                &session,
                options,
                &accepted,
            );
        }
        const result = try session.finish();
        errdefer {
            var owned_result = result;
            owned_result.deinit();
        }
        return .{
            .allocator = allocator,
            .result = result,
            .accepted = try accepted.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.decision_policy.candidates);
        self.allocator.free(self.decision_policy.groups);
        self.allocator.free(
            self.decision_policy.fallback.preferred_values,
        );
        self.allocator.free(self.decision_policy.fallback.order);
        self.formula.deinit();
        self.* = undefined;
    }
};

/// Copy a base formula and append installed-retention clauses.
///
/// The returned formula still borrows the universe, source jobs, repository
/// metadata, and architecture policy strings.
pub fn prepareInstalledRetention(
    allocator: std.mem.Allocator,
    base: *const solver_rules.OwnedFormula,
) PrepareError!Prepared {
    return prepareWithOptions(allocator, base, .{});
}

pub fn prepareWithOptions(
    allocator: std.mem.Allocator,
    base: *const solver_rules.OwnedFormula,
    options: PrepareOptions,
) PrepareError!Prepared {
    const package_count = base.universe.packages.len;
    try validateBaseFormula(base);
    if (base.architecture) |architecture| {
        if (!architecture.allow_multilib) return error.UnsupportedPolicy;
    }
    if (options.allow_erasing and base.replacement_kind != .none) {
        return error.UnsupportedPolicy;
    }
    for (base.package_states) |state| {
        if (state.multiversion) return error.UnsupportedPolicy;
        if (state.replacement.kind != .none and
            (state.allow_uninstall or options.allow_erasing))
        {
            return error.UnsupportedPolicy;
        }
    }

    const not_installable = try allocator.alloc(bool, package_count);
    defer allocator.free(not_installable);
    @memset(not_installable, false);
    const directly_erased = try allocator.alloc(bool, package_count);
    defer allocator.free(directly_erased);
    @memset(directly_erased, false);

    const replacement_candidates = try allocator.alloc(
        PackageIdList,
        package_count,
    );
    defer allocator.free(replacement_candidates);
    for (replacement_candidates) |*list| {
        list.* = PackageIdList.init(allocator);
    }
    defer for (replacement_candidates) |*list| list.deinit();
    const obsolete_candidates = try allocator.alloc(
        PackageIdList,
        package_count,
    );
    defer allocator.free(obsolete_candidates);
    for (obsolete_candidates) |*list| {
        list.* = PackageIdList.init(allocator);
    }
    defer for (obsolete_candidates) |*list| list.deinit();

    var candidate_groups = CandidateGroupList.init(allocator);
    defer candidate_groups.deinit();
    var replacement_groups = ReplacementGroupList.init(allocator);
    defer replacement_groups.deinit();
    var policy_candidates = PackageIdList.init(allocator);
    defer policy_candidates.deinit();
    const candidate_seen = try allocator.alloc(bool, package_count);
    defer allocator.free(candidate_seen);
    @memset(candidate_seen, false);

    for (base.clauses, 0..) |clause, clause_index| {
        const literals = try checkedClauseLiterals(base, clause);
        switch (clause.origin) {
            .not_installable => |package_id| {
                const package_index = try packageIndex(package_id, package_count);
                not_installable[package_index] = true;
            },
            .same_name => |origin| {
                const left_index = try packageIndex(origin.left, package_count);
                const right_index = try packageIndex(origin.right, package_count);
                if (base.universe.packages[left_index].installed != null) {
                    try replacement_candidates[left_index].append(
                        origin.right,
                    );
                }
                if (base.universe.packages[right_index].installed != null) {
                    try replacement_candidates[right_index].append(
                        origin.left,
                    );
                }
            },
            .obsoletes => |origin| {
                const target_index = try packageIndex(
                    origin.target,
                    package_count,
                );
                _ = try packageIndex(
                    origin.dependency.package,
                    package_count,
                );
                if (base.universe.packages[target_index].installed != null) {
                    try replacement_candidates[target_index].append(
                        origin.dependency.package,
                    );
                    try obsolete_candidates[target_index].append(
                        origin.dependency.package,
                    );
                }
            },
            .job => {
                if (literals.len == 1 and !literals[0].positive()) {
                    const package_index = try packageIndex(
                        literals[0].package(),
                        package_count,
                    );
                    if (base.universe.packages[package_index].installed != null) {
                        directly_erased[package_index] = true;
                    }
                }
            },
            .requirement, .conflict, .installed_keep => {},
        }
        try appendCandidateGroup(
            clause,
            clause_index,
            literals,
            candidate_seen,
            &candidate_groups,
            &policy_candidates,
        );
    }
    var clauses = std.array_list.Managed(solver_rules.Clause).init(allocator);
    defer clauses.deinit();
    try clauses.appendSlice(base.clauses);
    var literals = std.array_list.Managed(solver_rules.Literal).init(allocator);
    defer literals.deinit();
    try literals.appendSlice(base.literals);
    var replacement_obsolete_graph = try WeakObsoleteGraph.init(
        allocator,
        base,
    );
    defer replacement_obsolete_graph.deinit();

    for (base.universe.packages) |package| {
        const installed = package.installed orelse continue;
        _ = installed;
        const package_index: usize = @intFromEnum(package.id);
        if (directly_erased[package_index] or
            ((options.allow_erasing or
                base.package_states[package_index].allow_uninstall) and
                base.package_states[package_index].replacement.kind == .none))
        {
            continue;
        }

        const package_candidates = &replacement_candidates[package_index];
        try normalizeReplacementCandidates(
            package_candidates,
            package.id,
            not_installable,
        );

        const replacement = base.package_states[package_index].replacement;
        if (replacement.kind == .none) {
            try appendRetentionClause(
                &clauses,
                &literals,
                package.id,
                package_candidates.items,
            );
            continue;
        }

        std.sort.heap(
            solver_model.PackageId,
            obsolete_candidates[package_index].items,
            {},
            packageIdLessThan,
        );
        filterUpdateCandidates(
            base.universe,
            package,
            obsolete_candidates[package_index].items,
            replacement.kind == .dist_sync,
            package_candidates,
        );
        package_candidates.shrinkRetainingCapacity(
            replacement_obsolete_graph.prune(package_candidates.items),
        );
        const installed_obsoleted = anyPackageInSortedSet(
            package_candidates.items,
            obsolete_candidates[package_index].items,
        );
        if (package_candidates.items.len == 0) {
            try appendRetentionClause(
                &clauses,
                &literals,
                package.id,
                &.{},
            );
            continue;
        }

        const include_installed = replacement.kind == .update or
            hasIdenticalBestReplacement(
                base.universe,
                package,
                package_candidates.items,
            );
        const candidate_start = policy_candidates.items.len;
        if (include_installed) {
            try policy_candidates.append(package.id);
        }
        try policy_candidates.appendSlice(package_candidates.items);
        const candidate_count =
            policy_candidates.items.len - candidate_start;
        if (candidate_start > std.math.maxInt(u32) or
            candidate_count > std.math.maxInt(u32))
        {
            return error.TooManyLiterals;
        }
        if (clauses.items.len == std.math.maxInt(u32)) {
            return error.TooManyClauses;
        }
        if (literals.items.len > std.math.maxInt(u32) or
            candidate_count > std.math.maxInt(u32) - literals.items.len)
        {
            return error.TooManyLiterals;
        }
        const literal_start = literals.items.len;
        for (policy_candidates.items[candidate_start .. candidate_start + candidate_count]) |candidate| {
            try literals.append(solver_rules.Literal.init(candidate, true));
        }
        const clause_index = clauses.items.len;
        try clauses.append(.{
            .literals = .{
                .start = @intCast(literal_start),
                .len = @intCast(candidate_count),
            },
            .origin = .{ .job = replacement.job },
        });
        const candidate_range = solver_rules.PackageIdRange{
            .start = @intCast(candidate_start),
            .len = @intCast(candidate_count),
        };
        try candidate_groups.append(.{
            .clause_index = @intCast(clause_index),
            .candidates = candidate_range,
        });
        try replacement_groups.append(.{
            .candidates = candidate_range,
            .installed = package.id,
            .kind = replacement.kind,
            .job = replacement.job,
            .force_best = options.best or replacement.force_best,
            .installed_obsoleted = installed_obsoleted,
        });
    }

    try rankCandidateGroups(
        allocator,
        base.universe,
        base.architecture,
        candidate_groups.items,
        policy_candidates.items,
    );
    for (replacement_groups.items) |group| {
        rankReplacementGroup(
            base.universe,
            group,
            policy_candidates.items,
        );
        if (!group.force_best) continue;
        const ranked = group.candidates.slice(policy_candidates.items);
        if (ranked.len == 0) return error.InvalidFormula;
        try appendBestReplacementClause(
            allocator,
            &clauses,
            &literals,
            base.universe,
            base.architecture,
            group,
            ranked,
        );
    }

    const owned_clauses = try clauses.toOwnedSlice();
    errdefer allocator.free(owned_clauses);
    const owned_literals = try literals.toOwnedSlice();
    errdefer allocator.free(owned_literals);
    const weak_requests = try allocator.dupe(
        solver_rules.WeakRequest,
        base.weak_requests,
    );
    errdefer allocator.free(weak_requests);
    const weak_candidates = try allocator.dupe(
        solver_model.PackageId,
        base.weak_candidates,
    );
    errdefer allocator.free(weak_candidates);
    var weak_candidate_groups = CandidateGroupList.init(allocator);
    defer weak_candidate_groups.deinit();
    for (weak_requests) |request| {
        if (request.direction == .forward and
            request.dependency.kind == .recommends and
            request.candidates.len != 0)
        {
            try weak_candidate_groups.append(.{
                .clause_index = 0,
                .candidates = request.candidates,
            });
        }
    }
    try rankCandidateGroups(
        allocator,
        base.universe,
        base.architecture,
        weak_candidate_groups.items,
        weak_candidates,
    );
    const package_states = try allocator.dupe(
        solver_rules.PackageState,
        base.package_states,
    );
    errdefer allocator.free(package_states);
    const owned_candidate_groups = try candidate_groups.toOwnedSlice();
    errdefer allocator.free(owned_candidate_groups);
    const owned_policy_candidates = try policy_candidates.toOwnedSlice();
    errdefer allocator.free(owned_policy_candidates);

    const decision_order = try allocator.alloc(
        solver_model.PackageId,
        package_count,
    );
    errdefer allocator.free(decision_order);
    const preferred_values = try allocator.alloc(bool, package_count);
    errdefer allocator.free(preferred_values);
    for (
        base.universe.packages,
        decision_order,
        preferred_values,
    ) |package, *decision, *preferred| {
        decision.* = package.id;
        preferred.* = package.installed != null;
    }

    return .{
        .allocator = allocator,
        .formula = .{
            .allocator = allocator,
            .universe = base.universe,
            .jobs = base.jobs,
            .architecture = base.architecture,
            .replacement_kind = base.replacement_kind,
            .clauses = owned_clauses,
            .literals = owned_literals,
            .weak_requests = weak_requests,
            .weak_candidates = weak_candidates,
            .package_states = package_states,
        },
        .decision_policy = .{
            .fallback = .{
                .order = decision_order,
                .preferred_values = preferred_values,
            },
            .groups = owned_candidate_groups,
            .candidates = owned_policy_candidates,
        },
        .best = options.best,
    };
}

const PackageRuleMode = enum {
    include,
    omit,
};

fn solveSkippingBrokenJobs(
    prepared: *const Prepared,
    allocator: std.mem.Allocator,
) SkipBrokenError!SkipBrokenResult {
    if (prepared.best or
        prepared.formula.jobs.len > solver_model.max_skip_broken_jobs or
        prepared.formula.replacement_kind != .none)
    {
        return error.UnsupportedPolicy;
    }
    const skipped = try allocator.alloc(bool, prepared.formula.jobs.len);
    defer allocator.free(skipped);
    @memset(skipped, false);
    try validateSkipBrokenGoal(prepared, skipped);
    @memset(skipped, false);

    const trial = try allocator.alloc(bool, prepared.formula.jobs.len);
    defer allocator.free(trial);

    while (true) {
        var result = try solveFiltered(
            prepared,
            allocator,
            skipped,
            .include,
        );
        errdefer result.deinit();
        if (result == .satisfiable) {
            const skipped_jobs = try collectSkippedJobIds(
                allocator,
                skipped,
                true,
            );
            return .{
                .allocator = allocator,
                .result = result,
                .skipped_jobs = skipped_jobs,
            };
        }

        @memcpy(trial, skipped);
        for (trial, skipped) |*excluded, already_skipped| {
            if (!already_skipped) excluded.* = true;
        }
        var hard_result = try solveFiltered(
            prepared,
            allocator,
            trial,
            .include,
        );
        const hard_satisfiable = hard_result == .satisfiable;
        hard_result.deinit();
        if (!hard_satisfiable) {
            const skipped_jobs = try collectSkippedJobIds(
                allocator,
                skipped,
                false,
            );
            return .{
                .allocator = allocator,
                .result = result,
                .skipped_jobs = skipped_jobs,
            };
        }

        var found_individually_broken = false;
        for (skipped, 0..) |already_skipped, job_index| {
            if (already_skipped) continue;
            @memset(trial, true);
            trial[job_index] = false;
            var probe = try solveFiltered(
                prepared,
                allocator,
                trial,
                .include,
            );
            const probe_satisfiable = probe == .satisfiable;
            probe.deinit();
            if (probe_satisfiable) continue;

            var package_free = try solveFiltered(
                prepared,
                allocator,
                trial,
                .omit,
            );
            const package_free_satisfiable =
                package_free == .satisfiable;
            package_free.deinit();
            if (!package_free_satisfiable) {
                const skipped_jobs = try collectSkippedJobIds(
                    allocator,
                    skipped,
                    false,
                );
                return .{
                    .allocator = allocator,
                    .result = result,
                    .skipped_jobs = skipped_jobs,
                };
            }
            skipped[job_index] = true;
            found_individually_broken = true;
        }
        if (found_individually_broken) {
            result.deinit();
            continue;
        }

        @memcpy(trial, skipped);
        for (trial, skipped) |*excluded, already_skipped| {
            if (already_skipped) continue;
            excluded.* = true;
            var probe = try solveFiltered(
                prepared,
                allocator,
                trial,
                .include,
            );
            const probe_satisfiable = probe == .satisfiable;
            probe.deinit();
            if (probe_satisfiable) excluded.* = false;
        }

        var package_free = try solveFiltered(
            prepared,
            allocator,
            trial,
            .omit,
        );
        const package_free_satisfiable = package_free == .satisfiable;
        package_free.deinit();
        if (!package_free_satisfiable) {
            const skipped_jobs = try collectSkippedJobIds(
                allocator,
                skipped,
                false,
            );
            return .{
                .allocator = allocator,
                .result = result,
                .skipped_jobs = skipped_jobs,
            };
        }

        var found_core_job = false;
        for (skipped, trial) |*is_skipped, excluded| {
            if (is_skipped.* or excluded) continue;
            is_skipped.* = true;
            found_core_job = true;
        }
        if (!found_core_job) {
            return error.InternalSolverFailure;
        }
        result.deinit();
    }
}

fn validateSkipBrokenGoal(
    prepared: *const Prepared,
    seen_jobs: []bool,
) SkipBrokenError!void {
    if (seen_jobs.len != prepared.formula.jobs.len) {
        return error.InvalidFormula;
    }
    for (prepared.formula.jobs) |job| {
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
        const package_id = job.selection.package;
        if (@intFromEnum(package_id) >= prepared.formula.universe.packages.len) {
            return error.InvalidFormula;
        }
    }
    for (prepared.formula.clauses) |clause| {
        const job_id = switch (clause.origin) {
            .job => |value| value,
            else => continue,
        };
        const job_index: usize = @intFromEnum(job_id);
        if (job_index >= seen_jobs.len or
            seen_jobs[job_index] or
            clause.disposition != .hard)
        {
            return error.InvalidFormula;
        }
        const literals = checkedClauseLiterals(
            &prepared.formula,
            clause,
        ) catch return error.InvalidFormula;
        const selected_package = switch (prepared.formula.jobs[job_index].selection) {
            .package => |package_id| package_id,
            else => unreachable,
        };
        if (literals.len != 1 or
            !literals[0].positive() or
            literals[0].package() != selected_package)
        {
            return error.InvalidFormula;
        }
        seen_jobs[job_index] = true;
    }
    for (seen_jobs) |seen| {
        if (!seen) return error.InvalidFormula;
    }
}

fn solveFiltered(
    prepared: *const Prepared,
    allocator: std.mem.Allocator,
    excluded_jobs: []const bool,
    package_rules: PackageRuleMode,
) SkipBrokenError!solver_search.Result {
    const clause_mapping = try allocator.alloc(
        ?u32,
        prepared.formula.clauses.len,
    );
    defer allocator.free(clause_mapping);
    @memset(clause_mapping, null);

    var clauses = std.array_list.Managed(solver_rules.Clause).init(allocator);
    defer clauses.deinit();
    for (prepared.formula.clauses, 0..) |clause, clause_index| {
        if (clause.origin == .job) {
            const job_index: usize = @intFromEnum(clause.origin.job);
            if (job_index >= excluded_jobs.len) return error.InvalidFormula;
            if (excluded_jobs[job_index]) continue;
        } else if (package_rules == .omit and
            isIntrinsicPackageRule(clause.origin))
        {
            continue;
        }
        if (clauses.items.len == std.math.maxInt(u32)) {
            return error.FormulaTooLarge;
        }
        clause_mapping[clause_index] = @intCast(clauses.items.len);
        try clauses.append(clause);
    }

    var groups = CandidateGroupList.init(allocator);
    defer groups.deinit();
    var candidates = PackageIdList.init(allocator);
    defer candidates.deinit();
    for (prepared.decision_policy.groups) |group| {
        const clause_index: usize = @intCast(group.clause_index);
        if (clause_index >= clause_mapping.len) {
            return error.InvalidDecisionPolicy;
        }
        const filtered_clause = clause_mapping[clause_index] orelse continue;
        const source_start: usize = @intCast(group.candidates.start);
        const source_len: usize = @intCast(group.candidates.len);
        if (source_start > prepared.decision_policy.candidates.len or
            source_len >
                prepared.decision_policy.candidates.len - source_start)
        {
            return error.InvalidDecisionPolicy;
        }
        const source = prepared.decision_policy.candidates[source_start .. source_start + source_len];
        if (candidates.items.len > std.math.maxInt(u32) or
            source.len > std.math.maxInt(u32) - candidates.items.len)
        {
            return error.FormulaTooLarge;
        }
        const start = candidates.items.len;
        try candidates.appendSlice(source);
        try groups.append(.{
            .clause_index = filtered_clause,
            .candidates = .{
                .start = @intCast(start),
                .len = @intCast(source.len),
            },
        });
    }

    const formula = solver_rules.OwnedFormula{
        .allocator = allocator,
        .universe = prepared.formula.universe,
        .jobs = prepared.formula.jobs,
        .architecture = prepared.formula.architecture,
        .replacement_kind = prepared.formula.replacement_kind,
        .clauses = clauses.items,
        .literals = prepared.formula.literals,
        .weak_requests = prepared.formula.weak_requests,
        .weak_candidates = prepared.formula.weak_candidates,
        .package_states = prepared.formula.package_states,
    };
    return solver_search.solveWithCandidatePolicy(
        allocator,
        &formula,
        &.{},
        .{
            .fallback = prepared.decision_policy.fallback,
            .groups = groups.items,
            .candidates = candidates.items,
        },
    ) catch |err| switch (err) {
        error.InvalidCandidatePolicy => return error.InvalidDecisionPolicy,
        else => |solve_error| return solve_error,
    };
}

fn isIntrinsicPackageRule(origin: solver_rules.RuleOrigin) bool {
    return switch (origin) {
        .not_installable,
        .requirement,
        .conflict,
        .obsoletes,
        .same_name,
        => true,
        .installed_keep, .job => false,
    };
}

fn collectSkippedJobIds(
    allocator: std.mem.Allocator,
    skipped: []const bool,
    include_skipped: bool,
) error{OutOfMemory}![]const solver_model.JobId {
    var count: usize = 0;
    if (include_skipped) {
        for (skipped) |is_skipped| count += @intFromBool(is_skipped);
    }
    const ids = try allocator.alloc(solver_model.JobId, count);
    var cursor: usize = 0;
    if (include_skipped) {
        for (skipped, 0..) |is_skipped, job_index| {
            if (!is_skipped) continue;
            ids[cursor] = @enumFromInt(@as(u32, @intCast(job_index)));
            cursor += 1;
        }
    }
    return ids;
}

fn rankReplacementGroup(
    universe: *const solver_model.Universe,
    group: ReplacementGroup,
    candidates: []solver_model.PackageId,
) void {
    if (group.kind != .update) return;
    const start: usize = @intCast(group.candidates.start);
    const len: usize = @intCast(group.candidates.len);
    const ranked = candidates[start .. start + len];
    const installed = universe.package(group.installed).?;
    var installed_index: ?usize = null;
    var has_same_name_replacement = false;
    for (ranked, 0..) |candidate_id, index| {
        if (candidate_id == group.installed) {
            installed_index = index;
            continue;
        }
        const candidate = universe.package(candidate_id).?;
        if (std.mem.eql(
            u8,
            candidate.source.nevra.name,
            installed.source.nevra.name,
        )) {
            has_same_name_replacement = true;
        }
    }
    if (has_same_name_replacement and !group.installed_obsoleted) return;

    const installed_position = installed_index orelse return;
    for (installed_position..ranked.len - 1) |index| {
        ranked[index] = ranked[index + 1];
    }
    ranked[ranked.len - 1] = group.installed;
}

fn normalizeReplacementCandidates(
    candidates: *PackageIdList,
    installed: solver_model.PackageId,
    not_installable: []const bool,
) PrepareError!void {
    std.sort.heap(
        solver_model.PackageId,
        candidates.items,
        {},
        packageIdLessThan,
    );
    var write_index: usize = 0;
    for (candidates.items) |candidate| {
        const candidate_index = try packageIndex(
            candidate,
            not_installable.len,
        );
        if (candidate == installed or
            not_installable[candidate_index] or
            (write_index != 0 and
                candidates.items[write_index - 1] == candidate))
        {
            continue;
        }
        candidates.items[write_index] = candidate;
        write_index += 1;
    }
    candidates.shrinkRetainingCapacity(write_index);
}

fn filterUpdateCandidates(
    universe: *const solver_model.Universe,
    installed: solver_model.UniversePackage,
    obsoleters: []const solver_model.PackageId,
    allow_architecture_change: bool,
    candidates: *PackageIdList,
) void {
    if (!allow_architecture_change) {
        var architecture_count: usize = 0;
        for (candidates.items) |candidate_id| {
            const candidate = universe.package(candidate_id).?;
            if (!architectureColorsMatch(
                installed.source.nevra.arch,
                candidate.source.nevra.arch,
            )) {
                continue;
            }
            candidates.items[architecture_count] = candidate_id;
            architecture_count += 1;
        }
        candidates.shrinkRetainingCapacity(architecture_count);
    }

    var has_renamed_provider = false;
    for (candidates.items) |candidate_id| {
        const candidate = universe.package(candidate_id).?;
        if (!std.mem.eql(
            u8,
            candidate.source.nevra.name,
            installed.source.nevra.name,
        ) and containsPackageId(
            obsoleters,
            candidate_id,
        ) and updateCandidateProvidesName(
            universe,
            candidate.*,
            installed.source.nevra.name,
        )) {
            has_renamed_provider = true;
            break;
        }
    }
    if (!has_renamed_provider) return;

    var write_index: usize = 0;
    for (candidates.items) |candidate_id| {
        const candidate = universe.package(candidate_id).?;
        const same_name = std.mem.eql(
            u8,
            candidate.source.nevra.name,
            installed.source.nevra.name,
        );
        const renamed_provider = containsPackageId(
            obsoleters,
            candidate_id,
        ) and updateCandidateProvidesName(
            universe,
            candidate.*,
            installed.source.nevra.name,
        );
        if (!same_name and !renamed_provider) continue;
        candidates.items[write_index] = candidate_id;
        write_index += 1;
    }
    candidates.shrinkRetainingCapacity(write_index);
}

fn updateCandidateProvidesName(
    universe: *const solver_model.Universe,
    candidate: solver_model.UniversePackage,
    name: []const u8,
) bool {
    if (std.mem.eql(u8, candidate.source.nevra.name, name)) return true;
    for (candidate.relationEntries(universe, .provides)) |provided| {
        if (std.mem.eql(u8, provided.name, name)) return true;
    }
    return false;
}

fn containsPackageId(
    packages: []const solver_model.PackageId,
    target: solver_model.PackageId,
) bool {
    var low: usize = 0;
    var high = packages.len;
    const target_value = @intFromEnum(target);
    while (low < high) {
        const middle = low + (high - low) / 2;
        const value = @intFromEnum(packages[middle]);
        if (value < target_value) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return low < packages.len and packages[low] == target;
}

fn anyPackageInSortedSet(
    packages: []const solver_model.PackageId,
    sorted_set: []const solver_model.PackageId,
) bool {
    for (packages) |package| {
        if (containsPackageId(sorted_set, package)) return true;
    }
    return false;
}

const ArchitectureColor = enum {
    all,
    bits32,
    bits64,
};

fn architectureColorsMatch(left: []const u8, right: []const u8) bool {
    if (std.mem.eql(u8, left, right)) return true;
    const left_color = architectureColor(left);
    const right_color = architectureColor(right);
    return left_color == .all or
        right_color == .all or
        left_color == right_color;
}

fn architectureColor(architecture: []const u8) ArchitectureColor {
    if (std.mem.eql(u8, architecture, "noarch") or
        std.mem.eql(u8, architecture, "all") or
        std.mem.eql(u8, architecture, "any"))
    {
        return .all;
    }
    if (std.mem.eql(u8, architecture, "s390x") or
        std.mem.indexOf(u8, architecture, "64") != null)
    {
        return .bits64;
    }
    return .bits32;
}

fn hasIdenticalBestReplacement(
    universe: *const solver_model.Universe,
    installed: solver_model.UniversePackage,
    candidates: []const solver_model.PackageId,
) bool {
    var best_priority: ?i64 = null;
    for (candidates) |candidate_id| {
        const candidate = universe.package(candidate_id).?;
        if (candidate.installed != null) continue;
        const priority = globalRepositoryPriority(universe, candidate.*);
        best_priority = if (best_priority) |best|
            @min(best, priority)
        else
            priority;
    }
    const best = best_priority orelse return false;
    for (candidates) |candidate_id| {
        const candidate = universe.package(candidate_id).?;
        if (candidate.installed != null or
            globalRepositoryPriority(universe, candidate.*) != best or
            !std.mem.eql(
                u8,
                candidate.source.nevra.name,
                installed.source.nevra.name,
            ) or
            !std.mem.eql(
                u8,
                candidate.source.nevra.arch,
                installed.source.nevra.arch,
            ))
        {
            continue;
        }
        if (query_index.comparePackageVersions(
            candidate.source.*,
            installed.source.*,
        ) == 0 and packagesIdentical(
            universe,
            installed,
            candidate.*,
        )) {
            return true;
        }
    }
    return false;
}

fn packagesIdentical(
    universe: *const solver_model.Universe,
    left: solver_model.UniversePackage,
    right: solver_model.UniversePackage,
) bool {
    const product = std.mem.startsWith(
        u8,
        left.source.nevra.name,
        "product:",
    );
    if (!optionalStringEqual(left.source.rpm.vendor, right.source.rpm.vendor)) {
        return product;
    }
    const left_build = left.source.time.build orelse 0;
    const right_build = right.source.time.build orelse 0;
    if (left_build != 0 and right_build != 0) {
        return left_build == right_build;
    }
    if (product or std.mem.startsWith(
        u8,
        left.source.nevra.name,
        "application:",
    )) {
        return true;
    }
    return relationSetFingerprint(
        left.relationEntries(universe, .requires),
    ) == relationSetFingerprint(
        right.relationEntries(universe, .requires),
    );
}

fn optionalStringEqual(left: ?[]const u8, right: ?[]const u8) bool {
    return std.mem.eql(u8, left orelse "", right orelse "");
}

fn relationSetFingerprint(relations: []const metadata.Relation) u64 {
    var fingerprint: u64 = 0;
    var has_prerequisite = false;
    for (relations) |relation| {
        var hash = std.hash.Wyhash.init(0);
        hash.update(relation.name);
        hash.update(&.{@intFromEnum(relation.comparison)});
        const epoch = relation.epoch orelse 0;
        hash.update(std.mem.asBytes(&epoch));
        if (relation.version) |version| hash.update(version);
        hash.update(&.{0});
        if (relation.release) |release| hash.update(release);
        fingerprint ^= hash.final();
        has_prerequisite = has_prerequisite or relation.pre;
    }
    if (has_prerequisite) {
        fingerprint ^= std.hash.Wyhash.hash(
            0,
            "SOLVABLE_PREREQMARKER",
        );
    }
    return fingerprint;
}

fn appendRetentionClause(
    clauses: *std.array_list.Managed(solver_rules.Clause),
    literals: *std.array_list.Managed(solver_rules.Literal),
    installed: solver_model.PackageId,
    candidates: []const solver_model.PackageId,
) PrepareError!void {
    if (clauses.items.len == std.math.maxInt(u32)) {
        return error.TooManyClauses;
    }
    if (literals.items.len > std.math.maxInt(u32) or
        candidates.len + 1 > std.math.maxInt(u32) - literals.items.len)
    {
        return error.TooManyLiterals;
    }
    const start = literals.items.len;
    try literals.append(solver_rules.Literal.init(installed, true));
    for (candidates) |candidate| {
        try literals.append(solver_rules.Literal.init(candidate, true));
    }
    try clauses.append(.{
        .literals = .{
            .start = @intCast(start),
            .len = @intCast(candidates.len + 1),
        },
        .origin = .{ .installed_keep = installed },
    });
}

fn appendBestReplacementClause(
    allocator: std.mem.Allocator,
    clauses: *std.array_list.Managed(solver_rules.Clause),
    literals: *std.array_list.Managed(solver_rules.Literal),
    universe: *const solver_model.Universe,
    architecture: ?solver_model.ArchitecturePolicy,
    group: ReplacementGroup,
    ranked: []const solver_model.PackageId,
) PrepareError!void {
    if (clauses.items.len == std.math.maxInt(u32)) {
        return error.TooManyClauses;
    }
    const first = ranked[0];
    const start = literals.items.len;
    if (first == group.installed) {
        if (start == std.math.maxInt(u32)) return error.TooManyLiterals;
        try literals.append(solver_rules.Literal.init(first, true));
    } else {
        const top = universe.package(first).?;
        const best_priority = globalRepositoryPriority(universe, top.*);
        var best_machine_rank: ?usize = null;
        if (architecture) |policy| {
            const target = policy.force_arch orelse policy.native_arch;
            for (ranked) |candidate_id| {
                if (candidate_id == group.installed) continue;
                const candidate = universe.package(candidate_id).?;
                if (globalRepositoryPriority(
                    universe,
                    candidate.*,
                ) != best_priority) {
                    continue;
                }
                const rank = solver_rules.architectureRank(
                    target,
                    candidate.source.nevra.arch,
                ) orelse continue;
                if (rank == 0) continue;
                best_machine_rank = if (best_machine_rank) |best|
                    @min(best, rank)
                else
                    rank;
            }
        }

        var best_by_name =
            std.StringHashMap(solver_model.PackageId).init(allocator);
        defer best_by_name.deinit();
        for (ranked) |candidate_id| {
            if (candidate_id == group.installed) continue;
            const candidate = universe.package(candidate_id).?;
            if (!bestReplacementTier(
                universe,
                architecture,
                best_priority,
                best_machine_rank,
                top.*,
                candidate.*,
            )) {
                continue;
            }
            const entry = try best_by_name.getOrPut(
                candidate.source.nevra.name,
            );
            if (!entry.found_existing or
                query_index.comparePackageVersions(
                    candidate.source.*,
                    universe.package(entry.value_ptr.*).?.source.*,
                ) > 0)
            {
                entry.value_ptr.* = candidate_id;
            }
        }
        for (ranked) |candidate_id| {
            if (candidate_id == group.installed) continue;
            const candidate = universe.package(candidate_id).?;
            const best_id = best_by_name.get(
                candidate.source.nevra.name,
            ) orelse continue;
            const best = universe.package(best_id).?;
            if (query_index.comparePackageVersions(
                candidate.source.*,
                best.source.*,
            ) != 0) {
                continue;
            }
            if (literals.items.len == std.math.maxInt(u32)) {
                return error.TooManyLiterals;
            }
            try literals.append(solver_rules.Literal.init(
                candidate_id,
                true,
            ));
        }
    }
    const count = literals.items.len - start;
    if (count == 0) return error.InvalidFormula;
    try clauses.append(.{
        .literals = .{
            .start = @intCast(start),
            .len = @intCast(count),
        },
        .origin = .{ .job = group.job },
    });
}

fn bestReplacementTier(
    universe: *const solver_model.Universe,
    architecture: ?solver_model.ArchitecturePolicy,
    best_priority: i64,
    best_machine_rank: ?usize,
    top: solver_model.UniversePackage,
    candidate: solver_model.UniversePackage,
) bool {
    if (globalRepositoryPriority(universe, candidate) != best_priority) {
        return false;
    }
    if (architecture) |policy| {
        const rank = solver_rules.architectureRank(
            policy.force_arch orelse policy.native_arch,
            candidate.source.nevra.arch,
        ) orelse return false;
        return rank == 0 or
            (best_machine_rank != null and
                rank == best_machine_rank.?);
    }
    return std.mem.eql(
        u8,
        top.source.nevra.arch,
        candidate.source.nevra.arch,
    );
}

const RankedCandidate = struct {
    package: solver_model.PackageId,
    original_order: usize,
    installed: bool,
    priority: i64,
    architecture_rank: ?usize,
    architecture_tier: usize,
};

const CommonCandidate = struct {
    package: solver_model.PackageId,
    original_order: usize,
    badness: usize = 0,
    old_version: bool,
    installed_name: bool,
};

const CommonProvide = struct {
    candidate_index: usize,
    relation: metadata.Relation,
    strict_less: bool,
    ordinal: usize,
};

const CommonCandidateList = std.array_list.Managed(CommonCandidate);
const CommonProvideList = std.array_list.Managed(CommonProvide);

const UniverseVersionCandidate = struct {
    package: solver_model.PackageId,
    priority: i64,
};

const RankingContext = struct {
    universe: *const solver_model.Universe,
    architecture: ?solver_model.ArchitecturePolicy,
};

const WeakDfsFrame = struct {
    package: solver_model.PackageId,
    next_target: usize = 0,
};

const WeakObsoleteGraph = struct {
    allocator: std.mem.Allocator,
    targets: []PackageIdList,
    sources: []PackageIdList,
    active: []bool,
    visited: []bool,
    component: []usize,
    component_incoming: []bool,
    finish_order: PackageIdList,
    node_stack: PackageIdList,
    dfs_stack: std.array_list.Managed(WeakDfsFrame),

    fn init(
        allocator: std.mem.Allocator,
        formula: *const solver_rules.OwnedFormula,
    ) error{OutOfMemory}!WeakObsoleteGraph {
        const package_count = formula.universe.packages.len;
        const targets = try allocator.alloc(PackageIdList, package_count);
        errdefer allocator.free(targets);
        for (targets) |*list| list.* = PackageIdList.init(allocator);
        errdefer for (targets) |*list| list.deinit();
        const sources = try allocator.alloc(PackageIdList, package_count);
        errdefer allocator.free(sources);
        for (sources) |*list| list.* = PackageIdList.init(allocator);
        errdefer for (sources) |*list| list.deinit();
        for (formula.clauses) |clause| {
            switch (clause.origin) {
                .obsoletes => |origin| {
                    const source = formula.universe.package(
                        origin.dependency.package,
                    ).?;
                    const target = formula.universe.package(origin.target).?;
                    if (std.mem.eql(
                        u8,
                        source.source.nevra.name,
                        target.source.nevra.name,
                    )) {
                        continue;
                    }
                    try targets[
                        @intFromEnum(
                            origin.dependency.package,
                        )
                    ].append(origin.target);
                    try sources[@intFromEnum(origin.target)].append(
                        origin.dependency.package,
                    );
                },
                else => {},
            }
        }

        const active = try allocator.alloc(bool, package_count);
        errdefer allocator.free(active);
        const visited = try allocator.alloc(bool, package_count);
        errdefer allocator.free(visited);
        const component = try allocator.alloc(usize, package_count);
        errdefer allocator.free(component);
        const component_incoming = try allocator.alloc(bool, package_count);
        errdefer allocator.free(component_incoming);
        @memset(active, false);
        @memset(visited, false);
        @memset(component, std.math.maxInt(usize));
        @memset(component_incoming, false);
        var finish_order = PackageIdList.init(allocator);
        errdefer finish_order.deinit();
        try finish_order.ensureTotalCapacity(package_count);
        var node_stack = PackageIdList.init(allocator);
        errdefer node_stack.deinit();
        try node_stack.ensureTotalCapacity(package_count);
        var dfs_stack = std.array_list.Managed(WeakDfsFrame).init(allocator);
        errdefer dfs_stack.deinit();
        try dfs_stack.ensureTotalCapacity(package_count);
        return .{
            .allocator = allocator,
            .targets = targets,
            .sources = sources,
            .active = active,
            .visited = visited,
            .component = component,
            .component_incoming = component_incoming,
            .finish_order = finish_order,
            .node_stack = node_stack,
            .dfs_stack = dfs_stack,
        };
    }

    fn deinit(self: *WeakObsoleteGraph) void {
        self.dfs_stack.deinit();
        self.node_stack.deinit();
        self.finish_order.deinit();
        self.allocator.free(self.component_incoming);
        self.allocator.free(self.component);
        self.allocator.free(self.visited);
        self.allocator.free(self.active);
        for (self.sources) |*list| list.deinit();
        self.allocator.free(self.sources);
        for (self.targets) |*list| list.deinit();
        self.allocator.free(self.targets);
        self.* = undefined;
    }

    fn prune(
        self: *WeakObsoleteGraph,
        candidates: []solver_model.PackageId,
    ) usize {
        if (candidates.len < 2) return candidates.len;
        self.finish_order.clearRetainingCapacity();
        self.node_stack.clearRetainingCapacity();
        self.dfs_stack.clearRetainingCapacity();
        for (candidates) |candidate| {
            self.active[@intFromEnum(candidate)] = true;
        }

        for (candidates) |root| {
            if (self.visited[@intFromEnum(root)]) continue;
            self.visited[@intFromEnum(root)] = true;
            self.dfs_stack.appendAssumeCapacity(.{ .package = root });
            while (self.dfs_stack.items.len != 0) {
                const frame = &self.dfs_stack.items[
                    self.dfs_stack.items.len - 1
                ];
                const edges = self.targets[
                    @intFromEnum(
                        frame.package,
                    )
                ].items;
                var descended = false;
                while (frame.next_target < edges.len) {
                    const target = edges[frame.next_target];
                    frame.next_target += 1;
                    const target_index: usize = @intFromEnum(target);
                    if (!self.active[target_index] or
                        self.visited[target_index])
                    {
                        continue;
                    }
                    self.visited[target_index] = true;
                    self.dfs_stack.appendAssumeCapacity(.{
                        .package = target,
                    });
                    descended = true;
                    break;
                }
                if (descended) continue;
                self.finish_order.appendAssumeCapacity(frame.package);
                _ = self.dfs_stack.pop();
            }
        }

        var component_count: usize = 0;
        var finish_index = self.finish_order.items.len;
        while (finish_index != 0) {
            finish_index -= 1;
            const root = self.finish_order.items[finish_index];
            if (self.component[@intFromEnum(root)] !=
                std.math.maxInt(usize))
            {
                continue;
            }
            self.component[@intFromEnum(root)] = component_count;
            self.node_stack.appendAssumeCapacity(root);
            while (self.node_stack.items.len != 0) {
                const package = self.node_stack.pop().?;
                for (self.sources[@intFromEnum(package)].items) |source| {
                    const source_index: usize = @intFromEnum(source);
                    if (!self.active[source_index] or
                        self.component[source_index] !=
                            std.math.maxInt(usize))
                    {
                        continue;
                    }
                    self.component[source_index] = component_count;
                    self.node_stack.appendAssumeCapacity(source);
                }
            }
            component_count += 1;
        }

        for (candidates) |source| {
            const source_component = self.component[@intFromEnum(source)];
            for (self.targets[@intFromEnum(source)].items) |target| {
                if (!self.active[@intFromEnum(target)]) continue;
                const target_component =
                    self.component[@intFromEnum(target)];
                if (source_component != target_component) {
                    self.component_incoming[target_component] = true;
                }
            }
        }
        var write_index: usize = 0;
        for (candidates) |candidate| {
            const candidate_component =
                self.component[@intFromEnum(candidate)];
            if (self.component_incoming[candidate_component]) continue;
            candidates[write_index] = candidate;
            write_index += 1;
        }
        for (self.finish_order.items) |candidate| {
            const candidate_index: usize = @intFromEnum(candidate);
            self.active[candidate_index] = false;
            self.visited[candidate_index] = false;
            self.component[candidate_index] = std.math.maxInt(usize);
        }
        @memset(self.component_incoming[0..component_count], false);
        return write_index;
    }
};

fn resolveWeakRequests(
    allocator: std.mem.Allocator,
    formula: *const solver_rules.OwnedFormula,
    session: *solver_search.IncrementalSolver,
    options: WeakOptions,
    accepted: *std.array_list.Managed(AcceptedWeak),
) solver_search.SolveError!void {
    const package_count = formula.universe.packages.len;
    const probed = try allocator.alloc(bool, package_count);
    defer allocator.free(probed);
    @memset(probed, false);
    const not_installable = try allocator.alloc(bool, package_count);
    defer allocator.free(not_installable);
    @memset(not_installable, false);
    for (formula.clauses) |clause| {
        switch (clause.origin) {
            .not_installable => |package_id| {
                not_installable[@intFromEnum(package_id)] = true;
            },
            else => {},
        }
    }
    const old_versions = try allocator.alloc(bool, package_count);
    defer allocator.free(old_versions);
    @memset(old_versions, false);
    try identifyOldVersions(allocator, formula.universe, old_versions);
    var obsolete_graph = try WeakObsoleteGraph.init(allocator, formula);
    defer obsolete_graph.deinit();
    const pool_seen = try allocator.alloc(bool, package_count);
    defer allocator.free(pool_seen);
    const eligible = try allocator.alloc(bool, package_count);
    defer allocator.free(eligible);
    const preferred = try allocator.alloc(bool, package_count);
    defer allocator.free(preferred);
    const active_recommendations = try allocator.alloc(
        bool,
        formula.weak_requests.len,
    );
    defer allocator.free(active_recommendations);
    const supplement_dependencies = try allocator.alloc(
        ?solver_rules.DependencyRef,
        package_count,
    );
    defer allocator.free(supplement_dependencies);
    var weak_pool = PackageIdList.init(allocator);
    defer weak_pool.deinit();
    var supplements = PackageIdList.init(allocator);
    defer supplements.deinit();
    var recommendation_candidates = PackageIdList.init(allocator);
    defer recommendation_candidates.deinit();
    var common_candidates = CommonCandidateList.init(allocator);
    defer common_candidates.deinit();
    var common_provides = CommonProvideList.init(allocator);
    defer common_provides.deinit();

    while (true) {
        var changed = false;
        weak_pool.clearRetainingCapacity();
        supplements.clearRetainingCapacity();
        @memset(pool_seen, false);
        @memset(active_recommendations, false);
        @memset(supplement_dependencies, null);

        for (formula.weak_requests) |request| {
            if (request.direction != .reverse or
                request.dependency.kind != .supplements or
                session.selected(request.owner).?)
            {
                continue;
            }
            const owner_index: usize = @intFromEnum(request.owner);
            if (not_installable[owner_index] or
                !supplementActive(formula, request, session, options))
            {
                continue;
            }
            if (!pool_seen[owner_index]) {
                pool_seen[owner_index] = true;
                try weak_pool.append(request.owner);
                try supplements.append(request.owner);
            }
            if (supplement_dependencies[owner_index] == null) {
                supplement_dependencies[owner_index] = request.dependency;
            }
        }

        for (formula.weak_requests, 0..) |request, request_index| {
            if (request.direction != .forward or
                request.dependency.kind != .recommends or
                !session.selected(request.owner).?)
            {
                continue;
            }
            const owner = formula.universe.package(request.owner).?;
            if (!options.add_already_recommended and
                owner.installed != null)
            {
                continue;
            }
            const candidates = formula.weakCandidates(request);
            if (request.system_satisfied or
                anySelected(candidates, session))
            {
                continue;
            }
            active_recommendations[request_index] = true;
            for (candidates) |candidate| {
                const candidate_index: usize = @intFromEnum(candidate);
                if (not_installable[candidate_index] or
                    pool_seen[candidate_index])
                {
                    continue;
                }
                pool_seen[candidate_index] = true;
                try weak_pool.append(candidate);
            }
        }
        if (weak_pool.items.len == 0) break;

        weak_pool.shrinkRetainingCapacity(
            pruneWeakPool(
                formula.universe,
                formula.architecture,
                &obsolete_graph,
                weak_pool.items,
            ),
        );
        @memset(eligible, false);
        for (weak_pool.items) |candidate| {
            eligible[@intFromEnum(candidate)] = true;
        }
        var write_index: usize = 0;
        for (supplements.items) |candidate| {
            const candidate_index: usize = @intFromEnum(candidate);
            if (!eligible[candidate_index] or probed[candidate_index]) {
                continue;
            }
            supplements.items[write_index] = candidate;
            write_index += 1;
        }
        supplements.shrinkRetainingCapacity(write_index);
        if (supplements.items.len > 1) {
            try rankSupplementCandidates(
                formula.universe,
                formula.architecture,
                supplements.items,
                old_versions,
                &common_candidates,
                &common_provides,
            );
        }
        markWeakPreferred(formula, session, preferred);
        std.sort.block(
            solver_model.PackageId,
            supplements.items,
            preferred,
            weakPreferredLessThan,
        );
        for (supplements.items) |candidate| {
            const candidate_index: usize = @intFromEnum(candidate);
            probed[candidate_index] = true;
            if (!try session.trySelect(candidate)) continue;
            try accepted.append(.{
                .package = candidate,
                .dependency = supplement_dependencies[candidate_index].?,
            });
            changed = true;
        }

        markWeakPreferred(formula, session, preferred);
        for (formula.weak_requests, 0..) |request, request_index| {
            if (!active_recommendations[request_index] or
                !session.selected(request.owner).?)
            {
                continue;
            }
            const candidates = formula.weakCandidates(request);
            if (request.system_satisfied or
                anySelected(candidates, session))
            {
                continue;
            }
            recommendation_candidates.clearRetainingCapacity();
            for (candidates) |candidate| {
                const candidate_index: usize = @intFromEnum(candidate);
                if (!eligible[candidate_index] or probed[candidate_index]) {
                    continue;
                }
                try recommendation_candidates.append(candidate);
            }
            std.sort.block(
                solver_model.PackageId,
                recommendation_candidates.items,
                preferred,
                weakPreferredLessThan,
            );
            for (recommendation_candidates.items) |candidate| {
                const candidate_index: usize = @intFromEnum(candidate);
                probed[candidate_index] = true;
                if (!try session.trySelect(candidate)) continue;
                try accepted.append(.{
                    .package = candidate,
                    .dependency = request.dependency,
                });
                changed = true;
                break;
            }
        }

        if (!changed) break;
    }

    var write_index: usize = 0;
    for (accepted.items) |entry| {
        if (!session.selected(entry.package).?) continue;
        accepted.items[write_index] = entry;
        write_index += 1;
    }
    accepted.shrinkRetainingCapacity(write_index);
}

fn rankSupplementCandidates(
    universe: *const solver_model.Universe,
    architecture: ?solver_model.ArchitecturePolicy,
    candidates: []solver_model.PackageId,
    old_versions: []const bool,
    ranked: *CommonCandidateList,
    provides: *CommonProvideList,
) error{OutOfMemory}!void {
    if (architecture == null) return;
    ranked.clearRetainingCapacity();
    provides.clearRetainingCapacity();
    for (candidates, 0..) |candidate, original_order| {
        try ranked.append(.{
            .package = candidate,
            .original_order = original_order,
            .old_version = old_versions[@intFromEnum(candidate)],
            .installed_name = false,
        });
    }
    std.sort.block(
        CommonCandidate,
        ranked.items,
        {},
        currentVersionLessThan,
    );
    for (ranked.items, 0..) |*candidate, original_order| {
        candidate.original_order = original_order;
    }
    try collectCommonProvides(universe, ranked.items, provides);
    std.sort.heap(
        CommonProvide,
        provides.items,
        {},
        commonProvideLessThan,
    );
    scoreCommonProvides(ranked.items, provides.items, universe);
    std.sort.heap(
        CommonCandidate,
        ranked.items,
        {},
        commonCandidateLessThan,
    );
    for (ranked.items, candidates) |candidate, *output| {
        output.* = candidate.package;
    }
}

fn pruneWeakPool(
    universe: *const solver_model.Universe,
    architecture: ?solver_model.ArchitecturePolicy,
    obsolete_graph: *WeakObsoleteGraph,
    candidates: []solver_model.PackageId,
) usize {
    var best_priority: ?i64 = null;
    for (candidates) |candidate| {
        const package = universe.package(candidate).?;
        if (package.installed != null) continue;
        const priority = globalRepositoryPriority(universe, package.*);
        best_priority = if (best_priority) |best|
            @min(best, priority)
        else
            priority;
    }
    var write_index: usize = 0;
    for (candidates) |candidate| {
        const package = universe.package(candidate).?;
        if (package.installed == null and
            best_priority != null and
            globalRepositoryPriority(universe, package.*) != best_priority.?)
        {
            continue;
        }
        candidates[write_index] = candidate;
        write_index += 1;
    }
    if (architecture) |policy| {
        const target_architecture =
            policy.force_arch orelse policy.native_arch;
        var best_machine_rank: ?usize = null;
        for (candidates[0..write_index]) |candidate| {
            const package = universe.package(candidate).?;
            const rank = solver_rules.architectureRank(
                target_architecture,
                package.source.nevra.arch,
            ) orelse continue;
            if (rank == 0) continue;
            best_machine_rank = if (best_machine_rank) |best|
                @min(best, rank)
            else
                rank;
        }
        if (best_machine_rank) |best| {
            const priority_count = write_index;
            write_index = 0;
            for (candidates[0..priority_count]) |candidate| {
                const package = universe.package(candidate).?;
                const rank = solver_rules.architectureRank(
                    target_architecture,
                    package.source.nevra.arch,
                ) orelse continue;
                if (rank != 0 and rank != best) continue;
                candidates[write_index] = candidate;
                write_index += 1;
            }
        }
    }
    const retained = candidates[0..write_index];
    std.sort.heap(
        solver_model.PackageId,
        retained,
        universe,
        weakVersionLessThan,
    );
    write_index = 0;
    for (retained, 0..) |candidate, candidate_index| {
        if (candidate_index != 0) {
            const package = universe.package(candidate).?;
            const previous = universe.package(retained[candidate_index - 1]).?;
            if (std.mem.eql(
                u8,
                package.source.nevra.name,
                previous.source.nevra.name,
            )) {
                continue;
            }
        }
        candidates[write_index] = candidate;
        write_index += 1;
    }
    return obsolete_graph.prune(candidates[0..write_index]);
}

fn weakVersionLessThan(
    universe: *const solver_model.Universe,
    left: solver_model.PackageId,
    right: solver_model.PackageId,
) bool {
    const left_package = universe.package(left).?;
    const right_package = universe.package(right).?;
    const name_order = std.mem.order(
        u8,
        left_package.source.nevra.name,
        right_package.source.nevra.name,
    );
    if (name_order != .eq) return name_order == .lt;
    const version_order = query_index.comparePackageVersions(
        left_package.source.*,
        right_package.source.*,
    );
    if (version_order != 0) return version_order > 0;
    if ((left_package.installed != null) !=
        (right_package.installed != null))
    {
        return left_package.installed != null;
    }
    return @intFromEnum(left) < @intFromEnum(right);
}

fn markWeakPreferred(
    formula: *const solver_rules.OwnedFormula,
    session: *const solver_search.IncrementalSolver,
    preferred: []bool,
) void {
    @memset(preferred, false);
    for (formula.universe.packages) |package| {
        if (package.installed != null) {
            preferred[@intFromEnum(package.id)] = true;
        }
    }
    for (formula.weak_requests) |request| {
        switch (request.dependency.kind) {
            .suggests => {
                if (!session.selected(request.owner).?) continue;
                for (formula.weakCandidates(request)) |candidate| {
                    preferred[@intFromEnum(candidate)] = true;
                }
            },
            .enhances => {
                if (request.system_satisfied or
                    anySelected(formula.weakCandidates(request), session))
                {
                    preferred[@intFromEnum(request.owner)] = true;
                }
            },
            else => {},
        }
    }
}

fn weakPreferredLessThan(
    preferred: []const bool,
    left: solver_model.PackageId,
    right: solver_model.PackageId,
) bool {
    return preferred[@intFromEnum(left)] and
        !preferred[@intFromEnum(right)];
}

fn supplementActive(
    formula: *const solver_rules.OwnedFormula,
    request: solver_rules.WeakRequest,
    session: *const solver_search.IncrementalSolver,
    options: WeakOptions,
) bool {
    if (request.system_satisfied and options.add_already_recommended) {
        return true;
    }
    for (formula.weakCandidates(request)) |candidate| {
        if (!session.selected(candidate).?) continue;
        if (options.add_already_recommended or
            formula.universe.package(candidate).?.installed == null)
        {
            return true;
        }
    }
    return false;
}

fn anySelected(
    candidates: []const solver_model.PackageId,
    session: *const solver_search.IncrementalSolver,
) bool {
    for (candidates) |candidate| {
        if (session.selected(candidate).?) return true;
    }
    return false;
}

fn appendCandidateGroup(
    clause: solver_rules.Clause,
    clause_index: usize,
    literals: []const solver_rules.Literal,
    seen: []bool,
    groups: *CandidateGroupList,
    candidates: *PackageIdList,
) PrepareError!void {
    const start = candidates.items.len;
    errdefer candidates.shrinkRetainingCapacity(start);
    defer for (literals) |literal| {
        if (literal.positive()) {
            seen[@intFromEnum(literal.package())] = false;
        }
    };

    var control_count: usize = 0;
    for (literals) |literal| {
        const package_id = literal.package();
        const package_index: usize = @intFromEnum(package_id);
        if (literal.positive()) {
            if (seen[package_index]) return error.InvalidFormula;
            seen[package_index] = true;
            try candidates.append(package_id);
        } else {
            control_count += 1;
        }
    }
    switch (clause.origin) {
        .requirement => |origin| {
            if (control_count != 1 or
                seen[@intFromEnum(origin.package)])
            {
                return error.InvalidFormula;
            }
            for (literals) |literal| {
                if (!literal.positive() and
                    literal.package() != origin.package)
                {
                    return error.InvalidFormula;
                }
            }
        },
        .job => {
            if (control_count != 0) {
                candidates.shrinkRetainingCapacity(start);
                return;
            }
        },
        else => {
            candidates.shrinkRetainingCapacity(start);
            return;
        },
    }

    const candidate_count = candidates.items.len - start;
    if (candidate_count == 0) return;
    if (clause_index > std.math.maxInt(u32)) {
        return error.TooManyClauses;
    }
    if (start > std.math.maxInt(u32) or
        candidate_count > std.math.maxInt(u32))
    {
        return error.TooManyLiterals;
    }
    try groups.append(.{
        .clause_index = @intCast(clause_index),
        .candidates = .{
            .start = @intCast(start),
            .len = @intCast(candidate_count),
        },
    });
}

fn rankCandidateGroups(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    architecture: ?solver_model.ArchitecturePolicy,
    groups: []const solver_search.CandidateGroup,
    candidates: []solver_model.PackageId,
) error{OutOfMemory}!void {
    var max_candidates: usize = 0;
    for (groups) |group| {
        max_candidates = @max(
            max_candidates,
            @as(usize, @intCast(group.candidates.len)),
        );
    }
    if (max_candidates < 2) return;

    const priority_ranked = try allocator.alloc(
        RankedCandidate,
        max_candidates,
    );
    defer allocator.free(priority_ranked);
    const version_ranked = try allocator.alloc(
        RankedCandidate,
        max_candidates,
    );
    defer allocator.free(version_ranked);
    const group_by_package = try allocator.alloc(
        usize,
        universe.packages.len,
    );
    defer allocator.free(group_by_package);
    const group_cursors = try allocator.alloc(usize, max_candidates);
    defer allocator.free(group_cursors);
    var common_candidates = CommonCandidateList.init(allocator);
    defer common_candidates.deinit();
    var common_fallbacks = PackageIdList.init(allocator);
    defer common_fallbacks.deinit();
    var common_provides = CommonProvideList.init(allocator);
    defer common_provides.deinit();
    var common_names = std.StringHashMap(void).init(allocator);
    defer common_names.deinit();
    var installed_names = std.StringHashMap(void).init(allocator);
    defer installed_names.deinit();
    const old_versions = try allocator.alloc(bool, universe.packages.len);
    defer allocator.free(old_versions);
    @memset(old_versions, false);
    if (architecture != null) {
        try identifyOldVersions(allocator, universe, old_versions);
        for (universe.packages) |package| {
            if (package.installed != null) {
                try installed_names.put(package.source.nevra.name, {});
            }
        }
    }
    const context = RankingContext{
        .universe = universe,
        .architecture = architecture,
    };

    for (groups) |group| {
        const start: usize = @intCast(group.candidates.start);
        const len: usize = @intCast(group.candidates.len);
        const group_candidates = candidates[start .. start + len];
        var best_available_priority: ?i64 = null;
        for (group_candidates) |package_id| {
            const package = universe.package(package_id) orelse unreachable;
            const repository = universe.repository(
                package.repository,
            ) orelse unreachable;
            const priority: i64 = switch (repository.kind) {
                .installed => continue,
                .available => repository.priority,
                .command_line => 0,
            };
            best_available_priority = if (best_available_priority) |best|
                @min(best, priority)
            else
                priority;
        }
        for (group_candidates, priority_ranked[0..group_candidates.len], 0..) |
            package_id,
            *ranked,
            original_order,
        | {
            const package = universe.package(package_id) orelse unreachable;
            const repository = universe.repository(
                package.repository,
            ) orelse unreachable;
            ranked.* = .{
                .package = package_id,
                .original_order = original_order,
                .installed = repository.kind == .installed,
                .priority = switch (repository.kind) {
                    .installed => best_available_priority orelse 0,
                    .available => repository.priority,
                    .command_line => 0,
                },
                .architecture_rank = if (architecture) |policy|
                    solver_rules.architectureRank(
                        policy.force_arch orelse policy.native_arch,
                        package.source.nevra.arch,
                    )
                else
                    null,
                .architecture_tier = 0,
            };
        }
        const ranked = priority_ranked[0..group_candidates.len];
        std.sort.heap(
            RankedCandidate,
            ranked,
            context,
            priorityCandidateLessThan,
        );
        if (architecture != null) {
            assignArchitectureTiers(ranked);
            std.sort.heap(
                RankedCandidate,
                ranked,
                context,
                priorityCandidateLessThan,
            );
        }
        const by_version = version_ranked[0..group_candidates.len];
        @memcpy(by_version, ranked);
        std.sort.heap(
            RankedCandidate,
            by_version,
            context,
            versionCandidateLessThan,
        );

        var group_count: usize = 0;
        for (by_version, 0..) |candidate, candidate_index| {
            if (candidate_index == 0 or
                !sameVersionGroup(
                    context,
                    by_version[candidate_index - 1],
                    candidate,
                ))
            {
                group_cursors[group_count] = candidate_index;
                group_count += 1;
            }
            group_by_package[@intFromEnum(candidate.package)] =
                group_count - 1;
        }
        for (ranked, group_candidates) |candidate, *output| {
            const version_group =
                group_by_package[@intFromEnum(candidate.package)];
            output.* = by_version[group_cursors[version_group]].package;
            group_cursors[version_group] += 1;
        }
        for (ranked) |candidate| {
            group_by_package[@intFromEnum(candidate.package)] =
                candidate.architecture_tier;
        }
        try rankCommonProvides(
            universe,
            architecture,
            group_candidates,
            best_available_priority,
            group_by_package,
            &common_candidates,
            &common_fallbacks,
            &common_provides,
            &common_names,
            old_versions,
            &installed_names,
            true,
        );
    }
}

fn rankCommonProvides(
    universe: *const solver_model.Universe,
    architecture: ?solver_model.ArchitecturePolicy,
    candidates: []solver_model.PackageId,
    best_available_priority: ?i64,
    architecture_tiers: []const usize,
    frontier: *CommonCandidateList,
    fallbacks: *PackageIdList,
    provides: *CommonProvideList,
    names: *std.StringHashMap(void),
    old_versions: []const bool,
    installed_names: *const std.StringHashMap(void),
    promote_installed_names: bool,
) error{OutOfMemory}!void {
    if (architecture == null) return;
    var bucket_start: usize = 0;
    while (bucket_start < candidates.len) {
        const first = universe.package(
            candidates[bucket_start],
        ) orelse unreachable;
        const bucket_priority = candidatePriority(
            universe,
            first.*,
            best_available_priority,
        );
        const bucket_architecture =
            architecture_tiers[@intFromEnum(first.id)];
        var bucket_end = bucket_start + 1;
        while (bucket_end < candidates.len) : (bucket_end += 1) {
            const package = universe.package(
                candidates[bucket_end],
            ) orelse unreachable;
            if (candidatePriority(
                universe,
                package.*,
                best_available_priority,
            ) != bucket_priority or
                architecture_tiers[@intFromEnum(package.id)] !=
                    bucket_architecture)
            {
                break;
            }
        }

        frontier.clearRetainingCapacity();
        fallbacks.clearRetainingCapacity();
        provides.clearRetainingCapacity();
        names.clearRetainingCapacity();
        for (candidates[bucket_start..bucket_end], 0..) |
            package_id,
            original_order,
        | {
            const package = universe.package(package_id) orelse unreachable;
            const entry = try names.getOrPut(package.source.nevra.name);
            if (entry.found_existing) {
                try fallbacks.append(package_id);
            } else {
                try frontier.append(.{
                    .package = package_id,
                    .original_order = original_order,
                    .old_version = old_versions[@intFromEnum(package_id)],
                    .installed_name = installed_names.contains(
                        package.source.nevra.name,
                    ),
                });
            }
        }

        std.sort.block(
            CommonCandidate,
            frontier.items,
            {},
            currentVersionLessThan,
        );
        for (frontier.items, 0..) |*candidate, original_order| {
            candidate.original_order = original_order;
        }
        try collectCommonProvides(universe, frontier.items, provides);
        std.sort.heap(
            CommonProvide,
            provides.items,
            {},
            commonProvideLessThan,
        );
        scoreCommonProvides(frontier.items, provides.items, universe);
        std.sort.heap(
            CommonCandidate,
            frontier.items,
            {},
            commonCandidateLessThan,
        );
        if (promote_installed_names) {
            std.sort.block(
                CommonCandidate,
                frontier.items,
                {},
                installedNameLessThan,
            );
        }

        var output = bucket_start;
        for (frontier.items) |candidate| {
            candidates[output] = candidate.package;
            output += 1;
        }
        for (fallbacks.items) |package_id| {
            candidates[output] = package_id;
            output += 1;
        }
        bucket_start = bucket_end;
    }
}

fn collectCommonProvides(
    universe: *const solver_model.Universe,
    candidates: []const CommonCandidate,
    provides: *CommonProvideList,
) error{OutOfMemory}!void {
    for (candidates, 0..) |candidate, candidate_index| {
        const package = universe.package(
            candidate.package,
        ) orelse unreachable;
        const self_provide = packageSelfProvide(package.source.*);
        var has_self_provide = false;
        for (package.relationEntries(universe, .provides)) |relation| {
            if (equivalentSelfProvide(relation, self_provide)) {
                has_self_provide = true;
            }
            if (!comparableCommonProvide(relation)) continue;
            try provides.append(.{
                .candidate_index = candidate_index,
                .relation = relation,
                .strict_less = relation.comparison == .lt,
                .ordinal = provides.items.len,
            });
        }
        if (!has_self_provide and
            !sourceArchitecture(package.source.nevra.arch) and
            comparableCommonProvide(self_provide))
        {
            try provides.append(.{
                .candidate_index = candidate_index,
                .relation = self_provide,
                .strict_less = false,
                .ordinal = provides.items.len,
            });
        }
    }
}

fn identifyOldVersions(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    old_versions: []bool,
) error{OutOfMemory}!void {
    const ranked = try allocator.alloc(
        UniverseVersionCandidate,
        universe.packages.len,
    );
    defer allocator.free(ranked);
    for (universe.packages, ranked) |package, *candidate| {
        candidate.* = .{
            .package = package.id,
            .priority = globalRepositoryPriority(universe, package),
        };
    }
    std.sort.heap(
        UniverseVersionCandidate,
        ranked,
        universe,
        universeVersionLessThan,
    );

    var group_start: usize = 0;
    while (group_start < ranked.len) {
        const best = ranked[group_start];
        const best_package = universe.package(best.package).?;
        var group_end = group_start + 1;
        while (group_end < ranked.len) : (group_end += 1) {
            const package = universe.package(ranked[group_end].package).?;
            if (!std.mem.eql(
                u8,
                package.source.nevra.name,
                best_package.source.nevra.name,
            ) or !std.mem.eql(
                u8,
                package.source.nevra.arch,
                best_package.source.nevra.arch,
            )) {
                break;
            }
        }
        for (ranked[group_start..group_end]) |candidate| {
            const package = universe.package(candidate.package).?;
            if (package.installed != null) continue;
            old_versions[@intFromEnum(candidate.package)] =
                candidate.priority > best.priority or
                (candidate.priority == best.priority and
                    query_index.comparePackageVersions(
                        best_package.source.*,
                        package.source.*,
                    ) > 0);
        }
        group_start = group_end;
    }
}

fn globalRepositoryPriority(
    universe: *const solver_model.Universe,
    package: solver_model.UniversePackage,
) i64 {
    const repository = universe.repository(package.repository).?;
    return switch (repository.kind) {
        .installed, .command_line => 0,
        .available => repository.priority,
    };
}

fn candidatePriority(
    universe: *const solver_model.Universe,
    package: solver_model.UniversePackage,
    best_available_priority: ?i64,
) i64 {
    const repository = universe.repository(
        package.repository,
    ) orelse unreachable;
    return switch (repository.kind) {
        .installed => best_available_priority orelse 0,
        .available => repository.priority,
        .command_line => 0,
    };
}

fn universeVersionLessThan(
    universe: *const solver_model.Universe,
    left: UniverseVersionCandidate,
    right: UniverseVersionCandidate,
) bool {
    const left_package = universe.package(left.package).?;
    const right_package = universe.package(right.package).?;
    const name_order = std.mem.order(
        u8,
        left_package.source.nevra.name,
        right_package.source.nevra.name,
    );
    if (name_order != .eq) return name_order == .lt;
    const arch_order = std.mem.order(
        u8,
        left_package.source.nevra.arch,
        right_package.source.nevra.arch,
    );
    if (arch_order != .eq) return arch_order == .lt;
    if (left.priority != right.priority) return left.priority < right.priority;
    const version_order = query_index.comparePackageVersions(
        left_package.source.*,
        right_package.source.*,
    );
    if (version_order != 0) return version_order > 0;
    return @intFromEnum(left.package) < @intFromEnum(right.package);
}

fn currentVersionLessThan(
    _: void,
    left: CommonCandidate,
    right: CommonCandidate,
) bool {
    return !left.old_version and right.old_version;
}

fn installedNameLessThan(
    _: void,
    left: CommonCandidate,
    right: CommonCandidate,
) bool {
    return left.installed_name and !right.installed_name;
}

fn comparableCommonProvide(relation: metadata.Relation) bool {
    if (relation.flags == null or relation.version == null) return false;
    switch (relation.comparison) {
        .eq, .le, .lt => {},
        .none, .gt, .ge => return false,
    }
    if (relation.comparison != .eq or
        relation.epoch != null or
        relation.release != null)
    {
        return true;
    }
    const version = relation.version.?;
    if (version.len < 4) return true;
    for (version) |character| {
        if (!std.ascii.isDigit(character) and
            !(character >= 'a' and character <= 'f'))
        {
            return true;
        }
    }
    return false;
}

fn packageSelfProvide(package: metadata.Package) metadata.Relation {
    return .{
        .name = package.nevra.name,
        .flags = "EQ",
        .comparison = .eq,
        .epoch = package.nevra.epoch,
        .version = package.nevra.version,
        .release = if (package.nevra.release.len == 0)
            null
        else
            package.nevra.release,
    };
}

fn equivalentSelfProvide(
    relation: metadata.Relation,
    self_provide: metadata.Relation,
) bool {
    return relation.flags != null and
        relation.comparison == .eq and
        std.mem.eql(u8, relation.name, self_provide.name) and
        solver_rules.compareRelationEvr(relation, self_provide) == 0;
}

fn sourceArchitecture(architecture: []const u8) bool {
    return std.mem.eql(u8, architecture, "src") or
        std.mem.eql(u8, architecture, "nosrc");
}

fn commonProvideLessThan(
    _: void,
    left: CommonProvide,
    right: CommonProvide,
) bool {
    const name_order = std.mem.order(
        u8,
        left.relation.name,
        right.relation.name,
    );
    if (name_order != .eq) return name_order == .lt;
    const evr_order = solver_rules.compareRelationEvr(
        left.relation,
        right.relation,
    );
    if (evr_order != 0) return evr_order > 0;
    if (left.strict_less != right.strict_less) {
        return !left.strict_less;
    }
    return left.ordinal < right.ordinal;
}

fn commonProvideValuePrecedes(
    left: CommonProvide,
    right: CommonProvide,
) bool {
    const evr_order = solver_rules.compareRelationEvr(
        left.relation,
        right.relation,
    );
    if (evr_order != 0) return evr_order == 1;
    return !left.strict_less and right.strict_less;
}

fn scoreCommonProvides(
    candidates: []CommonCandidate,
    provides: []const CommonProvide,
    universe: *const solver_model.Universe,
) void {
    var badness: usize = 0;
    for (provides, 0..) |provide, index| {
        if (index == 0 or
            !std.mem.eql(
                u8,
                provides[index - 1].relation.name,
                provide.relation.name,
            ))
        {
            badness = 0;
        } else if (provide.candidate_index !=
            provides[index - 1].candidate_index and
            commonProvideValuePrecedes(provides[index - 1], provide))
        {
            badness +|= 1;
        }
        candidates[provide.candidate_index].badness +|= badness;
    }
    for (candidates) |*candidate| {
        if (universe.package(candidate.package).?.installed != null) {
            candidate.badness = 0;
        }
    }
}

fn commonCandidateLessThan(
    _: void,
    left: CommonCandidate,
    right: CommonCandidate,
) bool {
    if (left.badness != right.badness) return left.badness < right.badness;
    return left.original_order < right.original_order;
}

fn assignArchitectureTiers(candidates: []RankedCandidate) void {
    var start: usize = 0;
    while (start < candidates.len) {
        var end = start + 1;
        while (end < candidates.len and
            candidates[end].priority == candidates[start].priority)
        {
            end += 1;
        }

        var best_machine_rank: ?usize = null;
        for (candidates[start..end]) |candidate| {
            const rank = candidate.architecture_rank orelse continue;
            if (rank == 0) continue;
            best_machine_rank = if (best_machine_rank) |best|
                @min(best, rank)
            else
                rank;
        }
        if (best_machine_rank) |best| {
            for (candidates[start..end]) |*candidate| {
                candidate.architecture_tier =
                    if (candidate.architecture_rank) |rank|
                        if (rank == 0) 0 else rank - best
                    else
                        std.math.maxInt(usize);
            }
        }
        start = end;
    }
}

fn priorityCandidateLessThan(
    _: RankingContext,
    left: RankedCandidate,
    right: RankedCandidate,
) bool {
    if (left.priority != right.priority) {
        return left.priority < right.priority;
    }
    if (left.architecture_tier != right.architecture_tier) {
        return left.architecture_tier < right.architecture_tier;
    }
    if (left.installed != right.installed) return left.installed;
    return left.original_order < right.original_order;
}

fn versionCandidateLessThan(
    context: RankingContext,
    left: RankedCandidate,
    right: RankedCandidate,
) bool {
    if (left.priority != right.priority) {
        return left.priority < right.priority;
    }
    if (left.architecture_tier != right.architecture_tier) {
        return left.architecture_tier < right.architecture_tier;
    }
    const left_package = context.universe.package(left.package).?;
    const right_package = context.universe.package(right.package).?;
    const name_order = std.mem.order(
        u8,
        left_package.source.nevra.name,
        right_package.source.nevra.name,
    );
    if (name_order != .eq) return name_order == .lt;
    if (context.architecture == null) {
        const arch_order = std.mem.order(
            u8,
            left_package.source.nevra.arch,
            right_package.source.nevra.arch,
        );
        if (arch_order != .eq) return arch_order == .lt;
    }
    const version_order = query_index.comparePackageVersions(
        left_package.source.*,
        right_package.source.*,
    );
    if (version_order != 0) return version_order > 0;
    if (left.installed != right.installed) return left.installed;
    return left.original_order < right.original_order;
}

fn sameVersionGroup(
    context: RankingContext,
    left: RankedCandidate,
    right: RankedCandidate,
) bool {
    if (left.priority != right.priority) {
        return false;
    }
    if (left.architecture_tier != right.architecture_tier) {
        return false;
    }
    const left_package = context.universe.package(left.package).?;
    const right_package = context.universe.package(right.package).?;
    return std.mem.eql(
        u8,
        left_package.source.nevra.name,
        right_package.source.nevra.name,
    ) and (context.architecture != null or std.mem.eql(
        u8,
        left_package.source.nevra.arch,
        right_package.source.nevra.arch,
    ));
}

fn checkedClauseLiterals(
    formula: *const solver_rules.OwnedFormula,
    clause: solver_rules.Clause,
) PrepareError![]const solver_rules.Literal {
    const start: usize = @intCast(clause.literals.start);
    const len: usize = @intCast(clause.literals.len);
    if (start > formula.literals.len or len > formula.literals.len - start) {
        return error.InvalidFormula;
    }
    return formula.literals[start .. start + len];
}

fn validateBaseFormula(
    formula: *const solver_rules.OwnedFormula,
) PrepareError!void {
    const package_count = formula.universe.packages.len;
    if (package_count > std.math.maxInt(u32) or
        formula.package_states.len != package_count)
    {
        return error.InvalidFormula;
    }
    var package_cursor: usize = 0;
    for (formula.universe.repositories, 0..) |repository, repository_index| {
        if (@intFromEnum(repository.id) != repository_index) {
            return error.InvalidFormula;
        }
        const start: usize = @intCast(repository.packages.start);
        const len: usize = @intCast(repository.packages.len);
        if (start != package_cursor or len > package_count - start) {
            return error.InvalidFormula;
        }
        for (formula.universe.packages[start .. start + len], 0..) |
            package,
            repository_package_index,
        | {
            if (package.repository != repository.id or
                package.repository_package_index != repository_package_index)
            {
                return error.InvalidFormula;
            }
        }
        package_cursor += len;
    }
    if (package_cursor != package_count) return error.InvalidFormula;
    for (formula.universe.packages, 0..) |package, package_index| {
        if (@intFromEnum(package.id) != package_index) {
            return error.InvalidFormula;
        }
        const repository = formula.universe.repository(package.repository) orelse
            return error.InvalidFormula;
        const start: usize = @intCast(repository.packages.start);
        const len: usize = @intCast(repository.packages.len);
        if (package_index < start or package_index >= start + len) {
            return error.InvalidFormula;
        }
    }
    for (formula.literals) |literal| {
        if (@intFromEnum(literal) >> 1 >= package_count) {
            return error.InvalidFormula;
        }
    }
    for (formula.clauses) |clause| {
        _ = try checkedClauseLiterals(formula, clause);
        switch (clause.origin) {
            .not_installable, .installed_keep => |package_id| {
                _ = try packageIndex(package_id, package_count);
            },
            .requirement => |origin| {
                _ = try packageIndex(origin.package, package_count);
            },
            .conflict => |origin| {
                _ = try packageIndex(
                    origin.dependency.package,
                    package_count,
                );
                if (origin.target) |target| {
                    _ = try packageIndex(target, package_count);
                }
            },
            .obsoletes => |origin| {
                _ = try packageIndex(
                    origin.dependency.package,
                    package_count,
                );
                _ = try packageIndex(origin.target, package_count);
            },
            .same_name => |origin| {
                _ = try packageIndex(origin.left, package_count);
                _ = try packageIndex(origin.right, package_count);
            },
            .job => {},
        }
    }
    for (formula.weak_candidates) |candidate| {
        _ = try packageIndex(candidate, package_count);
    }
    for (formula.weak_requests) |request| {
        _ = try packageIndex(request.owner, package_count);
        if (request.dependency.package != request.owner) {
            return error.InvalidFormula;
        }
        const owner = formula.universe.package(request.owner).?;
        const relations = switch (request.direction) {
            .forward => switch (request.dependency.kind) {
                .recommends, .suggests => owner.relationEntries(
                    formula.universe,
                    request.dependency.kind,
                ),
                else => return error.InvalidFormula,
            },
            .reverse => switch (request.dependency.kind) {
                .supplements, .enhances => owner.relationEntries(
                    formula.universe,
                    request.dependency.kind,
                ),
                else => return error.InvalidFormula,
            },
        };
        if (request.dependency.index >= relations.len) {
            return error.InvalidFormula;
        }
        const start: usize = @intCast(request.candidates.start);
        const len: usize = @intCast(request.candidates.len);
        if (start > formula.weak_candidates.len or
            len > formula.weak_candidates.len - start)
        {
            return error.InvalidFormula;
        }
    }
}

fn packageIndex(
    package_id: solver_model.PackageId,
    package_count: usize,
) PrepareError!usize {
    const package_index: usize = @intFromEnum(package_id);
    if (package_index >= package_count) return error.InvalidFormula;
    return package_index;
}

fn packageIdLessThan(
    _: void,
    left: solver_model.PackageId,
    right: solver_model.PackageId,
) bool {
    return @intFromEnum(left) < @intFromEnum(right);
}

fn testPackage(
    name: []const u8,
    version: []const u8,
) metadata.Package {
    return .{
        .pkg_id = name,
        .nevra = .{
            .name = name,
            .version = version,
            .release = "1",
            .arch = "x86_64",
        },
        .checksum = .{ .kind = "sha256", .value = "" },
        .location = .{ .href = "" },
    };
}

fn testArchitecture() solver_model.ArchitecturePolicy {
    return .{ .native_arch = "x86_64" };
}

fn versionedTestRelation(
    name: []const u8,
    comparison: metadata.CompareOp,
    version: []const u8,
) metadata.Relation {
    return .{
        .name = name,
        .flags = "versioned",
        .comparison = comparison,
        .version = version,
    };
}

test "contextual install ranking applies repository priority before EVR" {
    var worse_packages = [_]metadata.Package{
        testPackage("package", "9"),
    };
    var better_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    const worse_model = metadata.RepositoryModel{
        .packages = &worse_packages,
    };
    const better_model = metadata.RepositoryModel{
        .packages = &better_packages,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "worse",
                .model = &worse_model,
                .priority = 90,
            },
            .{
                .id = "better",
                .model = &better_model,
                .priority = 10,
            },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "package" },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    try std.testing.expectEqual(
        @as(usize, 1),
        prepared.decision_policy.groups.len,
    );
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(0) },
        prepared.decision_policy.groups[0].candidates.slice(
            prepared.decision_policy.candidates,
        ),
    );
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        result.satisfiable.values,
    );
}

test "installed candidate competes by EVR with the best repository tier" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    var worse_packages = [_]metadata.Package{
        testPackage("package", "9"),
    };
    var better_packages = [_]metadata.Package{
        testPackage("package", "2"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const worse_model = metadata.RepositoryModel{
        .packages = &worse_packages,
    };
    const better_model = metadata.RepositoryModel{
        .packages = &better_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{
                .id = "worse",
                .model = &worse_model,
                .priority = 90,
            },
            .{
                .id = "better",
                .model = &better_model,
                .priority = 10,
            },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "package" },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(2), @enumFromInt(0), @enumFromInt(1) },
        prepared.decision_policy.groups[0].candidates.slice(
            prepared.decision_policy.candidates,
        ),
    );
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, true },
        result.satisfiable.values,
    );
}

test "contextual requirement ranks package EVR not provide EVR" {
    var relations = [_]metadata.Relation{
        .{
            .name = "virtual-api",
            .flags = "versioned",
            .comparison = .eq,
            .version = "100",
        },
        .{
            .name = "virtual-api",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
        },
        .{
            .name = "virtual-api",
            .flags = "versioned",
            .comparison = .ge,
            .version = "1",
        },
    };
    var packages = [_]metadata.Package{
        testPackage("provider", "1"),
        testPackage("provider", "2"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 1 };
    packages[2].requires = .{ .start = 2, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(0) },
        requirement_candidates.?,
    );
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true },
        result.satisfiable.values,
    );
}

test "contextual ranking uses common provide EVR across package names" {
    var relations = [_]metadata.Relation{
        .{
            .name = "virtual-api",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
        },
        .{
            .name = "virtual-api",
            .flags = "versioned",
            .comparison = .eq,
            .version = "2",
        },
        .{
            .name = "virtual-api",
            .flags = "versioned",
            .comparison = .ge,
            .version = "1",
        },
    };
    var packages = [_]metadata.Package{
        testPackage("old-nevra", "99"),
        testPackage("new-nevra", "1"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 1 };
    packages[2].requires = .{ .start = 2, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(0) },
        requirement_candidates.?,
    );
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true },
        result.satisfiable.values,
    );
}

test "common provide ranking is not limited to the required capability" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
        },
        .{ .name = "virtual-api" },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "2",
        },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("first-provider", "1"),
        testPackage("second-provider", "1"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 2 };
    packages[1].provides = .{ .start = 2, .len = 2 };
    packages[2].requires = .{ .start = 4, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(0) },
        requirement_candidates.?,
    );
}

test "common provide ranking includes implicit package self provides" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{
            .name = "alpha-provider",
            .flags = "versioned",
            .comparison = .eq,
            .version = "2",
        },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("alpha-provider", "1"),
        testPackage("beta-provider", "1"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 2 };
    packages[2].requires = .{ .start = 3, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(0) },
        requirement_candidates.?,
    );
}

test "explicit package self provides are not scored twice" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{
            .name = "alpha-provider",
            .flags = "versioned",
            .comparison = .eq,
            .version = "2",
            .release = "1",
        },
        .{ .name = "virtual-api" },
        .{
            .name = "charlie-provider",
            .flags = "versioned",
            .comparison = .eq,
            .version = "2",
            .release = "1",
        },
        .{ .name = "virtual-api" },
        .{
            .name = "alpha-provider",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
            .release = "1",
        },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("bravo-provider", "1"),
        testPackage("delta-provider", "1"),
        testPackage("alpha-provider", "1"),
        testPackage("charlie-provider", "1"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 2 };
    packages[1].provides = .{ .start = 2, .len = 2 };
    packages[2].provides = .{ .start = 4, .len = 2 };
    packages[3].provides = .{ .start = 6, .len = 1 };
    packages[4].requires = .{ .start = 7, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(4) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{
            @enumFromInt(0),
            @enumFromInt(1),
            @enumFromInt(2),
            @enumFromInt(3),
        },
        requirement_candidates.?,
    );
}

test "synthetic self provides exclude source architectures" {
    try std.testing.expect(sourceArchitecture("src"));
    try std.testing.expect(sourceArchitecture("nosrc"));
    try std.testing.expect(!sourceArchitecture("noarch"));
    try std.testing.expect(!sourceArchitecture("x86_64"));
}

test "common provide ranking ignores hexadecimal equality hashes" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
        },
        .{ .name = "virtual-api" },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "deadbeef",
        },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("first-provider", "1"),
        testPackage("second-provider", "1"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 2 };
    packages[1].provides = .{ .start = 2, .len = 2 };
    packages[2].requires = .{ .start = 4, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        requirement_candidates.?,
    );
}

test "common provide badness ignores missing-release boundaries" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
        },
        .{ .name = "virtual-api" },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
            .release = "1",
        },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("first-provider", "1"),
        testPackage("second-provider", "1"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 2 };
    packages[1].provides = .{ .start = 2, .len = 2 };
    packages[2].requires = .{ .start = 4, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        requirement_candidates.?,
    );
}

test "installed package names move matching available providers to front" {
    var installed_packages = [_]metadata.Package{
        testPackage("sticky-provider", "1"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "2",
        },
        .{ .name = "virtual-api" },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
        },
        .{ .name = "virtual-api" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("other-provider", "1"),
        testPackage("sticky-provider", "2"),
        testPackage("consumer", "1"),
    };
    available_packages[0].provides = .{ .start = 0, .len = 2 };
    available_packages[1].provides = .{ .start = 2, .len = 2 };
    available_packages[2].requires = .{ .start = 4, .len = 1 };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(3) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(2), @enumFromInt(1) },
        requirement_candidates.?,
    );
}

test "installed-name movement leaves old same-name versions as fallbacks" {
    var installed_packages = [_]metadata.Package{
        testPackage("sticky-provider", "1"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("other-provider", "1"),
        testPackage("sticky-provider", "2"),
        testPackage("sticky-provider", "3"),
        testPackage("consumer", "1"),
    };
    available_packages[0].provides = .{ .start = 0, .len = 1 };
    available_packages[1].provides = .{ .start = 1, .len = 1 };
    available_packages[2].provides = .{ .start = 2, .len = 1 };
    available_packages[3].requires = .{ .start = 3, .len = 1 };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(4) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(3), @enumFromInt(1), @enumFromInt(2) },
        requirement_candidates.?,
    );
}

test "newer package outside the candidate queue demotes an old provider" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("versioned-provider", "1"),
        testPackage("other-provider", "1"),
        testPackage("versioned-provider", "2"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 1 };
    packages[3].requires = .{ .start = 2, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(3) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(0) },
        requirement_candidates.?,
    );
}

test "weak recommendations are optional and policy controlled" {
    var relations = [_]metadata.Relation{
        .{ .name = "addon" },
    };
    var packages = [_]metadata.Package{
        testPackage("addon", "1"),
        testPackage("application", "1"),
    };
    packages[1].recommends = .{ .start = 0, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var enabled = try prepared.solveWeak(
        std.testing.allocator,
        .{},
    );
    defer enabled.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, true },
        enabled.result.satisfiable.values,
    );
    try std.testing.expectEqual(@as(usize, 1), enabled.accepted.len);
    try std.testing.expectEqual(
        @as(solver_model.PackageId, @enumFromInt(0)),
        enabled.accepted[0].package,
    );
    try std.testing.expectEqual(
        metadata.DependencyKind.recommends,
        enabled.accepted[0].dependency.kind,
    );

    var disabled = try prepared.solveWeak(
        std.testing.allocator,
        .{ .enabled = false },
    );
    defer disabled.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        disabled.result.satisfiable.values,
    );
    try std.testing.expectEqual(@as(usize, 0), disabled.accepted.len);
}

test "installed owners do not add old recommendations by default" {
    var installed_relations = [_]metadata.Relation{
        .{ .name = "addon" },
    };
    var installed_packages = [_]metadata.Package{
        testPackage("application", "1"),
    };
    installed_packages[0].recommends = .{ .start = 0, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
        .relations = &installed_relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var available_packages = [_]metadata.Package{
        testPackage("addon", "1"),
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var default_result = try prepared.solveWeak(
        std.testing.allocator,
        .{},
    );
    defer default_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false },
        default_result.result.satisfiable.values,
    );

    var add_existing = try prepared.solveWeak(
        std.testing.allocator,
        .{ .add_already_recommended = true },
    );
    defer add_existing.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, true },
        add_existing.result.satisfiable.values,
    );
}

test "weak recommendation falls back after its best provider conflicts" {
    var relations = [_]metadata.Relation{
        versionedTestRelation("addon-api", .eq, "2"),
        .{ .name = "blocker" },
        versionedTestRelation("addon-api", .eq, "1"),
        versionedTestRelation("addon-api", .ge, "1"),
    };
    var packages = [_]metadata.Package{
        testPackage("best-addon", "1"),
        testPackage("fallback-addon", "1"),
        testPackage("blocker", "1"),
        testPackage("application", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[0].conflicts = .{ .start = 1, .len = 1 };
    packages[1].provides = .{ .start = 2, .len = 1 };
    packages[3].recommends = .{ .start = 3, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(2) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(3) },
            },
        } },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solveWeak(std.testing.allocator, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true, true },
        result.result.satisfiable.values,
    );
    try std.testing.expectEqual(
        @as(solver_model.PackageId, @enumFromInt(1)),
        result.accepted[0].package,
    );
}

test "weak recommendations do not cross repository or version pruning" {
    var preferred_relations = [_]metadata.Relation{
        versionedTestRelation("addon-api", .eq, "2"),
        .{ .name = "blocker" },
        versionedTestRelation("addon-api", .ge, "1"),
    };
    var preferred_packages = [_]metadata.Package{
        testPackage("best-addon", "2"),
        testPackage("blocker", "1"),
        testPackage("application", "1"),
    };
    preferred_packages[0].provides = .{ .start = 0, .len = 1 };
    preferred_packages[0].conflicts = .{ .start = 1, .len = 1 };
    preferred_packages[2].recommends = .{ .start = 2, .len = 1 };
    const preferred_model = metadata.RepositoryModel{
        .packages = &preferred_packages,
        .relations = &preferred_relations,
    };
    var fallback_relations = [_]metadata.Relation{
        versionedTestRelation("addon-api", .eq, "1"),
    };
    var fallback_packages = [_]metadata.Package{
        testPackage("fallback-addon", "1"),
    };
    fallback_packages[0].provides = .{ .start = 0, .len = 1 };
    const fallback_model = metadata.RepositoryModel{
        .packages = &fallback_packages,
        .relations = &fallback_relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "preferred",
                .model = &preferred_model,
                .priority = 10,
            },
            .{
                .id = "fallback",
                .model = &fallback_model,
                .priority = 50,
            },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(1) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(2) },
            },
        } },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solveWeak(std.testing.allocator, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true, false },
        result.result.satisfiable.values,
    );
    try std.testing.expectEqual(@as(usize, 0), result.accepted.len);

    var same_name_relations = [_]metadata.Relation{
        .{ .name = "blocker" },
        .{ .name = "addon" },
    };
    var same_name_packages = [_]metadata.Package{
        testPackage("addon", "2"),
        testPackage("addon", "1"),
        testPackage("blocker", "1"),
        testPackage("application", "1"),
    };
    same_name_packages[0].conflicts = .{ .start = 0, .len = 1 };
    same_name_packages[3].recommends = .{ .start = 1, .len = 1 };
    const same_name_model = metadata.RepositoryModel{
        .packages = &same_name_packages,
        .relations = &same_name_relations,
    };
    var same_name_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &same_name_model }},
    );
    defer same_name_universe.deinit();
    var same_name_base = try solver_rules.generateBase(
        std.testing.allocator,
        &same_name_universe,
        .{ .jobs = &.{
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(2) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(3) },
            },
        } },
        testArchitecture(),
    );
    defer same_name_base.deinit();
    var same_name_prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &same_name_base,
    );
    defer same_name_prepared.deinit();

    var same_name_result = try same_name_prepared.solveWeak(
        std.testing.allocator,
        .{},
    );
    defer same_name_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, true, true },
        same_name_result.result.satisfiable.values,
    );
}

test "rejected weak candidates remain in later pruning frontiers" {
    var preferred_relations = [_]metadata.Relation{
        versionedTestRelation("addon-api", .eq, "2"),
        .{ .name = "blocker" },
        versionedTestRelation("addon-api", .ge, "1"),
        .{ .name = "good-addon" },
    };
    var preferred_packages = [_]metadata.Package{
        testPackage("best-addon", "1"),
        testPackage("good-addon", "1"),
        testPackage("blocker", "1"),
        testPackage("application", "1"),
    };
    preferred_packages[0].provides = .{ .start = 0, .len = 1 };
    preferred_packages[0].conflicts = .{ .start = 1, .len = 1 };
    preferred_packages[3].recommends = .{ .start = 2, .len = 2 };
    const preferred_model = metadata.RepositoryModel{
        .packages = &preferred_packages,
        .relations = &preferred_relations,
    };
    var fallback_relations = [_]metadata.Relation{
        versionedTestRelation("addon-api", .eq, "1"),
    };
    var fallback_packages = [_]metadata.Package{
        testPackage("fallback-addon", "1"),
    };
    fallback_packages[0].provides = .{ .start = 0, .len = 1 };
    const fallback_model = metadata.RepositoryModel{
        .packages = &fallback_packages,
        .relations = &fallback_relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "preferred",
                .model = &preferred_model,
                .priority = 10,
            },
            .{
                .id = "fallback",
                .model = &fallback_model,
                .priority = 50,
            },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(2) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(3) },
            },
        } },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solveWeak(std.testing.allocator, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true, true, false },
        result.result.satisfiable.values,
    );
    try std.testing.expectEqual(@as(usize, 1), result.accepted.len);
    try std.testing.expectEqual(
        @as(solver_model.PackageId, @enumFromInt(1)),
        result.accepted[0].package,
    );
}

test "weak pruning applies architecture and obsoletes policy" {
    var architecture_relations = [_]metadata.Relation{
        .{ .name = "addon" },
    };
    var architecture_packages = [_]metadata.Package{
        testPackage("addon", "1"),
        testPackage("addon", "99"),
        testPackage("application", "1"),
    };
    architecture_packages[1].nevra.arch = "i686";
    architecture_packages[2].recommends = .{ .start = 0, .len = 1 };
    const architecture_model = metadata.RepositoryModel{
        .packages = &architecture_packages,
        .relations = &architecture_relations,
    };
    var architecture_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &architecture_model }},
    );
    defer architecture_universe.deinit();
    var architecture_base = try solver_rules.generateBase(
        std.testing.allocator,
        &architecture_universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer architecture_base.deinit();
    var architecture_prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &architecture_base,
    );
    defer architecture_prepared.deinit();

    var architecture_result = try architecture_prepared.solveWeak(
        std.testing.allocator,
        .{},
    );
    defer architecture_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, true },
        architecture_result.result.satisfiable.values,
    );

    var obsolete_relations = [_]metadata.Relation{
        .{ .name = "addon-api" },
        .{ .name = "old-addon" },
        .{ .name = "addon-api" },
        .{ .name = "addon-api" },
    };
    var obsolete_packages = [_]metadata.Package{
        testPackage("replacement-addon", "1"),
        testPackage("old-addon", "1"),
        testPackage("application", "1"),
    };
    obsolete_packages[0].provides = .{ .start = 0, .len = 1 };
    obsolete_packages[0].obsoletes = .{ .start = 1, .len = 1 };
    obsolete_packages[1].provides = .{ .start = 2, .len = 1 };
    obsolete_packages[2].recommends = .{ .start = 3, .len = 1 };
    const obsolete_model = metadata.RepositoryModel{
        .packages = &obsolete_packages,
        .relations = &obsolete_relations,
    };
    var obsolete_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &obsolete_model }},
    );
    defer obsolete_universe.deinit();
    var obsolete_base = try solver_rules.generateBase(
        std.testing.allocator,
        &obsolete_universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer obsolete_base.deinit();
    var obsolete_prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &obsolete_base,
    );
    defer obsolete_prepared.deinit();

    var obsolete_result = try obsolete_prepared.solveWeak(
        std.testing.allocator,
        .{},
    );
    defer obsolete_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, true },
        obsolete_result.result.satisfiable.values,
    );
}

test "weak obsoletes pruning preserves mutual replacement cycles" {
    var relations = [_]metadata.Relation{
        .{ .name = "addon-api" },
        .{ .name = "second-addon" },
        .{ .name = "addon-api" },
        .{ .name = "first-addon" },
        .{ .name = "addon-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("first-addon", "1"),
        testPackage("second-addon", "1"),
        testPackage("application", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[0].obsoletes = .{ .start = 1, .len = 1 };
    packages[1].provides = .{ .start = 2, .len = 1 };
    packages[1].obsoletes = .{ .start = 3, .len = 1 };
    packages[2].recommends = .{ .start = 4, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solveWeak(std.testing.allocator, .{});
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.accepted.len);
    try std.testing.expect(
        result.result.satisfiable.values[0] or
            result.result.satisfiable.values[1],
    );
}

test "weak supplements require a newly selected condition by default" {
    var available_relations = [_]metadata.Relation{
        .{ .name = "application" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("addon", "1"),
        testPackage("application", "1"),
    };
    available_packages[0].supplements = .{ .start = 0, .len = 1 };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    var available_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &available_model }},
    );
    defer available_universe.deinit();
    var available_base = try solver_rules.generateBase(
        std.testing.allocator,
        &available_universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        testArchitecture(),
    );
    defer available_base.deinit();
    var available_prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &available_base,
    );
    defer available_prepared.deinit();

    var selected = try available_prepared.solveWeak(
        std.testing.allocator,
        .{},
    );
    defer selected.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, true },
        selected.result.satisfiable.values,
    );
    try std.testing.expectEqual(
        metadata.DependencyKind.supplements,
        selected.accepted[0].dependency.kind,
    );

    var installed_packages = [_]metadata.Package{
        testPackage("application", "1"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var installed_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer installed_universe.deinit();
    var installed_base = try solver_rules.generateBase(
        std.testing.allocator,
        &installed_universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer installed_base.deinit();
    var installed_prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &installed_base,
    );
    defer installed_prepared.deinit();

    var suppressed = try installed_prepared.solveWeak(
        std.testing.allocator,
        .{},
    );
    defer suppressed.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, false },
        suppressed.result.satisfiable.values,
    );
}

test "suggestions order conflicting active supplements" {
    var relations = [_]metadata.Relation{
        .{ .name = "application" },
        .{ .name = "preferred-addon" },
        .{ .name = "application" },
        .{ .name = "preferred-addon" },
    };
    var packages = [_]metadata.Package{
        testPackage("first-addon", "1"),
        testPackage("preferred-addon", "1"),
        testPackage("application", "1"),
    };
    packages[0].supplements = .{ .start = 0, .len = 1 };
    packages[0].conflicts = .{ .start = 1, .len = 1 };
    packages[1].supplements = .{ .start = 2, .len = 1 };
    packages[2].suggests = .{ .start = 3, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solveWeak(std.testing.allocator, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true },
        result.result.satisfiable.values,
    );
    try std.testing.expectEqual(
        @as(solver_model.PackageId, @enumFromInt(1)),
        result.accepted[0].package,
    );
}

test "weak recommendation closure ignores suggestions and enhances" {
    var relations = [_]metadata.Relation{
        .{ .name = "helper" },
        .{ .name = "addon" },
        .{ .name = "suggested" },
        .{ .name = "application" },
    };
    var packages = [_]metadata.Package{
        testPackage("helper", "1"),
        testPackage("addon", "1"),
        testPackage("suggested", "1"),
        testPackage("enhanced", "1"),
        testPackage("application", "1"),
    };
    packages[1].recommends = .{ .start = 0, .len = 1 };
    packages[3].enhances = .{ .start = 3, .len = 1 };
    packages[4].recommends = .{ .start = 1, .len = 1 };
    packages[4].suggests = .{ .start = 2, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(4) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solveWeak(std.testing.allocator, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, true, false, false, true },
        result.result.satisfiable.values,
    );
    try std.testing.expectEqual(@as(usize, 2), result.accepted.len);
}

test "contextual requirement falls back after the best provider conflicts" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "blocker" },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("provider", "1"),
        testPackage("provider", "2"),
        testPackage("consumer", "1"),
        testPackage("blocker", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 1 };
    packages[1].conflicts = .{ .start = 2, .len = 1 };
    packages[2].requires = .{ .start = 3, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    const jobs = [_]solver_model.Job{
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(3) },
        },
    };
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &jobs },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, true, true },
        result.satisfiable.values,
    );
}

test "contextual ranking keeps unrelated provider names stable" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("z-provider", "1"),
        testPackage("a-provider", "9"),
        testPackage("consumer", "1"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 1 };
    packages[2].requires = .{ .start = 2, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        requirement_candidates.?,
    );
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, true },
        result.satisfiable.values,
    );
}

test "contextual ranking co-ranks noarch and best machine architecture" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("provider", "2"),
        testPackage("provider", "1"),
        testPackage("provider", "99"),
        testPackage("consumer", "1"),
    };
    packages[0].nevra.arch = "noarch";
    packages[2].nevra.arch = "i686";
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 1 };
    packages[2].provides = .{ .start = 2, .len = 1 };
    packages[3].requires = .{ .start = 3, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(3) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1), @enumFromInt(2) },
        requirement_candidates.?,
    );
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, false, true },
        result.satisfiable.values,
    );
}

test "contextual ranking honors forced architecture policy" {
    var relations = [_]metadata.Relation{
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
        .{ .name = "virtual-api" },
    };
    var packages = [_]metadata.Package{
        testPackage("provider", "99"),
        testPackage("provider", "2"),
        testPackage("provider", "1"),
        testPackage("consumer", "1"),
    };
    packages[1].nevra.arch = "i686";
    packages[2].nevra.arch = "noarch";
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 1 };
    packages[2].provides = .{ .start = 2, .len = 1 };
    packages[3].requires = .{ .start = 3, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    const architecture = solver_model.ArchitecturePolicy{
        .native_arch = "x86_64",
        .force_arch = "i686",
    };
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(3) },
        }} },
        architecture,
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    try std.testing.expectEqualStrings(
        "i686",
        prepared.formula.architecture.?.force_arch.?,
    );
    var requirement_candidates: ?[]const solver_model.PackageId = null;
    for (prepared.decision_policy.groups) |group| {
        if (std.meta.activeTag(
            prepared.formula.clauses[group.clause_index].origin,
        ) == .requirement) {
            requirement_candidates = group.candidates.slice(
                prepared.decision_policy.candidates,
            );
        }
    }
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(2) },
        requirement_candidates.?,
    );
}

test "contextual ranking maps command-line repository priority to zero" {
    var available_packages = [_]metadata.Package{
        testPackage("package", "9"),
    };
    var command_line_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const command_line_model = metadata.RepositoryModel{
        .packages = &command_line_packages,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "available",
                .model = &available_model,
                .priority = 10,
            },
            .{
                .id = "@commandline",
                .model = &command_line_model,
                .kind = .command_line,
                .priority = 500,
            },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "package" },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(0) },
        prepared.decision_policy.groups[0].candidates.slice(
            prepared.decision_policy.candidates,
        ),
    );
}

test "clauses without positive candidates do not create contextual groups" {
    var relations = [_]metadata.Relation{
        .{ .name = "missing-provider" },
    };
    var packages = [_]metadata.Package{
        testPackage("consumer", "1"),
    };
    packages[0].requires = .{ .start = 0, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    try std.testing.expectEqual(
        @as(usize, 0),
        prepared.decision_policy.groups.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        prepared.decision_policy.candidates.len,
    );

    const valid_policy = prepared.decision_policy;
    prepared.decision_policy = .{
        .candidates = &.{@enumFromInt(0)},
    };
    try std.testing.expectError(
        error.InvalidDecisionPolicy,
        prepared.solve(std.testing.allocator),
    );
    prepared.decision_policy = valid_policy;
}

test "formula without architecture policy preserves raw architecture order" {
    var packages = [_]metadata.Package{
        testPackage("provider", "1"),
        testPackage("provider", "2"),
        testPackage("unrelated", "1"),
    };
    packages[1].nevra.arch = "noarch";
    const repository = metadata.RepositoryModel{
        .packages = &packages,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var states = [_]solver_rules.PackageState{ .{}, .{}, .{} };
    states[0].replacement = .{
        .kind = .update,
        .job = @enumFromInt(0),
        .force_best = true,
    };
    const literals = [_]solver_rules.Literal{
        solver_rules.Literal.init(@enumFromInt(0), true),
        solver_rules.Literal.init(@enumFromInt(1), true),
        solver_rules.Literal.init(@enumFromInt(2), true),
    };
    const clauses = [_]solver_rules.Clause{.{
        .literals = .{ .start = 0, .len = 3 },
        .origin = .{ .job = @enumFromInt(0) },
    }};
    const formula = solver_rules.OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &clauses,
        .literals = &literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &formula,
    );
    defer prepared.deinit();

    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1), @enumFromInt(2) },
        prepared.decision_policy.candidates,
    );
}

test "malformed contextual source clauses are rejected during preparation" {
    var packages = [_]metadata.Package{
        testPackage("one", "1"),
        testPackage("two", "1"),
    };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var states = [_]solver_rules.PackageState{ .{}, .{} };
    const duplicate_literals = [_]solver_rules.Literal{
        solver_rules.Literal.init(@enumFromInt(0), true),
        solver_rules.Literal.init(@enumFromInt(0), true),
    };
    const duplicate_clause = [_]solver_rules.Clause{.{
        .literals = .{ .start = 0, .len = 2 },
        .origin = .{ .job = @enumFromInt(0) },
    }};
    var formula = solver_rules.OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &duplicate_clause,
        .literals = &duplicate_literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    try std.testing.expectError(
        error.InvalidFormula,
        prepareInstalledRetention(std.testing.allocator, &formula),
    );

    formula.clauses = &.{.{
        .literals = .{ .start = 0, .len = 1 },
        .origin = .{ .requirement = .{
            .package = @enumFromInt(0),
            .kind = .requires,
            .index = 0,
        } },
    }};
    formula.literals = &.{solver_rules.Literal.init(
        @enumFromInt(1),
        true,
    )};
    try std.testing.expectError(
        error.InvalidFormula,
        prepareInstalledRetention(std.testing.allocator, &formula),
    );
}

test "installed orphan is retained" {
    var installed_packages = [_]metadata.Package{
        testPackage("installed", "1"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{
            .id = "@System",
            .model = &installed_model,
            .kind = .installed,
            .installed_states = &installed_states,
        }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    try std.testing.expectEqual(
        @as(usize, base.clauses.len + 1),
        prepared.formula.clauses.len,
    );
    const retention = prepared.formula.clauses[
        prepared.formula.clauses.len - 1
    ];
    try std.testing.expectEqual(
        @as(solver_model.PackageId, @enumFromInt(0)),
        retention.origin.installed_keep,
    );
    try std.testing.expectEqualSlices(
        solver_rules.Literal,
        &.{solver_rules.Literal.init(@enumFromInt(0), true)},
        prepared.formula.clauseLiterals(retention),
    );

    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expect(result.satisfiable.values[0]);
}

test "exact replacement satisfies installed retention" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("package", "2"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    const retention = prepared.formula.clauses[
        prepared.formula.clauses.len - 1
    ];
    try std.testing.expectEqualSlices(
        solver_rules.Literal,
        &.{
            solver_rules.Literal.init(@enumFromInt(0), true),
            solver_rules.Literal.init(@enumFromInt(1), true),
        },
        prepared.formula.clauseLiterals(retention),
    );
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        result.satisfiable.values,
    );
}

test "update all prefers upgrades and falls back to installed" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "2"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("package", "1"),
        testPackage("package", "3"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    try std.testing.expectEqual(
        solver_rules.ReplacementKind.update,
        base.package_states[0].replacement.kind,
    );

    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, true },
        result.satisfiable.values,
    );

    var fallback = try prepared.solveAssuming(
        std.testing.allocator,
        &.{solver_rules.Literal.init(@enumFromInt(2), false)},
    );
    defer fallback.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, false },
        fallback.satisfiable.values,
    );

    var best = try prepareWithOptions(
        std.testing.allocator,
        &base,
        .{ .best = true },
    );
    defer best.deinit();
    var blocked = try best.solveAssuming(
        std.testing.allocator,
        &.{solver_rules.Literal.init(@enumFromInt(2), false)},
    );
    defer blocked.deinit();
    try std.testing.expect(blocked == .unsatisfiable);
}

test "force best retains equivalent update alternatives" {
    var installed_packages = [_]metadata.Package{
        testPackage("old-package", "1"),
    };
    var available_relations = [_]metadata.Relation{
        .{ .name = "old-package" },
        .{ .name = "old-package" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("new-a", "1"),
        testPackage("new-b", "1"),
    };
    available_packages[0].obsoletes = .{ .start = 0, .len = 1 };
    available_packages[1].obsoletes = .{ .start = 1, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareWithOptions(
        std.testing.allocator,
        &base,
        .{ .best = true },
    );
    defer prepared.deinit();

    var result = try prepared.solveAssuming(
        std.testing.allocator,
        &.{solver_rules.Literal.init(@enumFromInt(1), false)},
    );
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, true },
        result.satisfiable.values,
    );
}

test "force best prevents distro sync version fallback" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "3"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("package", "2"),
        testPackage("package", "1"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareWithOptions(
        std.testing.allocator,
        &base,
        .{ .best = true },
    );
    defer prepared.deinit();

    var result = try prepared.solveAssuming(
        std.testing.allocator,
        &.{solver_rules.Literal.init(@enumFromInt(1), false)},
    );
    defer result.deinit();
    try std.testing.expect(result == .unsatisfiable);
}

test "force best does not retain an explicitly obsoleted install" {
    var available_relations = [_]metadata.Relation{
        .{ .name = "old-package" },
        versionedTestRelation("old-package", .eq, "2"),
    };
    var installed_packages = [_]metadata.Package{
        testPackage("old-package", "2"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("old-package", "1"),
        testPackage("renamed-package", "1"),
    };
    available_packages[1].provides = .{ .start = 0, .len = 1 };
    available_packages[1].obsoletes = .{ .start = 1, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareWithOptions(
        std.testing.allocator,
        &base,
        .{ .best = true },
    );
    defer prepared.deinit();

    var result = try prepared.solveAssuming(
        std.testing.allocator,
        &.{solver_rules.Literal.init(@enumFromInt(1), false)},
    );
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, true },
        result.satisfiable.values,
    );
}

test "update preserves architecture color while distro sync may change it" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("package", "2"),
    };
    available_packages[0].nevra.arch = "i686";
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();

    inline for ([_]struct {
        action: solver_model.JobAction,
        expected: [2]bool,
    }{
        .{ .action = .update, .expected = .{ true, false } },
        .{ .action = .dist_sync, .expected = .{ false, true } },
    }) |entry| {
        var base = try solver_rules.generateBase(
            std.testing.allocator,
            &universe,
            .{ .jobs = &.{.{
                .action = entry.action,
                .selection = .all,
            }} },
            testArchitecture(),
        );
        defer base.deinit();
        var prepared = try prepareInstalledRetention(
            std.testing.allocator,
            &base,
        );
        defer prepared.deinit();
        var result = try prepared.solve(std.testing.allocator);
        defer result.deinit();
        try std.testing.expectEqualSlices(
            bool,
            &entry.expected,
            result.satisfiable.values,
        );
    }
}

test "update with allow uninstall remains an explicit policy boundary" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("package", "2"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    const jobs = [_]solver_model.Job{
        .{ .action = .update, .selection = .all },
        .{
            .action = .allow_uninstall,
            .selection = .{ .package = @enumFromInt(0) },
        },
    };
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &jobs },
        testArchitecture(),
    );
    defer base.deinit();
    try std.testing.expectError(
        error.UnsupportedPolicy,
        prepareInstalledRetention(std.testing.allocator, &base),
    );
    try std.testing.expectError(
        error.UnsupportedPolicy,
        prepareWithOptions(
            std.testing.allocator,
            &base,
            .{ .allow_erasing = true },
        ),
    );
}

test "allow erasing rejects replacement jobs without installed packages" {
    const empty_model = metadata.RepositoryModel{};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{
            .id = "available",
            .model = &empty_model,
        }},
    );
    defer universe.deinit();

    inline for ([_]solver_model.JobAction{ .update, .dist_sync }) |action| {
        var base = try solver_rules.generateBase(
            std.testing.allocator,
            &universe,
            .{ .jobs = &.{.{
                .action = action,
                .selection = .all,
            }} },
            testArchitecture(),
        );
        defer base.deinit();
        try std.testing.expectError(
            error.UnsupportedPolicy,
            prepareWithOptions(
                std.testing.allocator,
                &base,
                .{ .allow_erasing = true },
            ),
        );
    }
}

test "distro sync obeys repository priority and retains orphans" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "3"),
        testPackage("orphan", "1"),
    };
    var preferred_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    var fallback_packages = [_]metadata.Package{
        testPackage("package", "4"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const preferred_model = metadata.RepositoryModel{
        .packages = &preferred_packages,
    };
    const fallback_model = metadata.RepositoryModel{
        .packages = &fallback_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
        .{ .rpmdb_hnum = 2 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{
                .id = "preferred",
                .model = &preferred_model,
                .priority = 10,
            },
            .{
                .id = "fallback",
                .model = &fallback_model,
                .priority = 90,
            },
        },
    );
    defer universe.deinit();

    var update_base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer update_base.deinit();
    var update = try prepareInstalledRetention(
        std.testing.allocator,
        &update_base,
    );
    defer update.deinit();
    var update_result = try update.solve(std.testing.allocator);
    defer update_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, true, false, false },
        update_result.satisfiable.values,
    );

    var sync_base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer sync_base.deinit();
    var sync = try prepareInstalledRetention(
        std.testing.allocator,
        &sync_base,
    );
    defer sync.deinit();
    var sync_result = try sync.solve(std.testing.allocator);
    defer sync_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true, false },
        sync_result.satisfiable.values,
    );
}

test "distro sync retains fallback obsoleters beside same-name candidates" {
    var preferred_relations = [_]metadata.Relation{
        .{ .name = "old-package" },
    };
    var installed_packages = [_]metadata.Package{
        testPackage("old-package", "1"),
    };
    var preferred_packages = [_]metadata.Package{
        testPackage("replacement", "1"),
    };
    preferred_packages[0].obsoletes = .{ .start = 0, .len = 1 };
    var fallback_packages = [_]metadata.Package{
        testPackage("old-package", "2"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const preferred_model = metadata.RepositoryModel{
        .packages = &preferred_packages,
        .relations = &preferred_relations,
    };
    const fallback_model = metadata.RepositoryModel{
        .packages = &fallback_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{
                .id = "preferred",
                .model = &preferred_model,
                .priority = 10,
            },
            .{
                .id = "fallback",
                .model = &fallback_model,
                .priority = 90,
            },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, false },
        result.satisfiable.values,
    );
}

test "distro sync replaces equal EVR packages with changed identity" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    installed_packages[0].rpm.vendor = "old-vendor";
    var available_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    available_packages[0].rpm.vendor = "new-vendor";
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        result.satisfiable.values,
    );
}

test "distro sync preserves libsolv product identity exceptions" {
    var installed_packages = [_]metadata.Package{
        testPackage("product:package", "1"),
    };
    installed_packages[0].rpm.vendor = "old-vendor";
    var available_packages = [_]metadata.Package{
        testPackage("product:package", "1"),
    };
    available_packages[0].rpm.vendor = "new-vendor";
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false },
        result.satisfiable.values,
    );
}

test "distro sync identity includes prerequisite markers" {
    var installed_relations = [_]metadata.Relation{
        versionedTestRelation("rpmlib(Test)", .eq, "1"),
    };
    var available_relations = installed_relations;
    available_relations[0].pre = true;
    var installed_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    installed_packages[0].requires = .{ .start = 0, .len = 1 };
    var available_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    available_packages[0].requires = .{ .start = 0, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
        .relations = &installed_relations,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        result.satisfiable.values,
    );
}

test "update uses provide and obsolete renames before fallback obsoleters" {
    var relations = [_]metadata.Relation{
        .{ .name = "old-package" },
        .{ .name = "old-package" },
        .{ .name = "old-package" },
    };
    var installed_packages = [_]metadata.Package{
        testPackage("old-package", "1"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("fallback-replacement", "1"),
        testPackage("provided-replacement", "1"),
    };
    available_packages[0].obsoletes = .{ .start = 0, .len = 1 };
    available_packages[1].provides = .{ .start = 1, .len = 1 };
    available_packages[1].obsoletes = .{ .start = 2, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, true },
        result.satisfiable.values,
    );
}

test "direct erase disables retention and blocks implicit replacement" {
    var installed_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("package", "2"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    for (prepared.formula.clauses) |clause| {
        try std.testing.expect(
            std.meta.activeTag(clause.origin) != .installed_keep,
        );
    }
    var result = try prepared.solve(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false },
        result.satisfiable.values,
    );
}

test "retention blocks conflicts unless uninstall is explicitly allowed" {
    var installed_packages = [_]metadata.Package{
        testPackage("protected-by-retention", "1"),
    };
    var available_relations = [_]metadata.Relation{
        .{ .name = "protected-by-retention" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("request", "1"),
    };
    available_packages[0].conflicts = .{ .start = 0, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();

    const install_job = solver_model.Job{
        .action = .install,
        .selection = .{ .package = @enumFromInt(1) },
    };
    var blocked_base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{install_job} },
        testArchitecture(),
    );
    defer blocked_base.deinit();
    var blocked = try prepareInstalledRetention(
        std.testing.allocator,
        &blocked_base,
    );
    defer blocked.deinit();
    var blocked_result = try blocked.solve(std.testing.allocator);
    defer blocked_result.deinit();
    try std.testing.expect(blocked_result == .unsatisfiable);

    const jobs = [_]solver_model.Job{
        install_job,
        .{
            .action = .allow_uninstall,
            .selection = .{ .package = @enumFromInt(0) },
        },
    };
    var allowed_base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &jobs },
        testArchitecture(),
    );
    defer allowed_base.deinit();
    var allowed = try prepareInstalledRetention(
        std.testing.allocator,
        &allowed_base,
    );
    defer allowed.deinit();
    var allowed_result = try allowed.solve(std.testing.allocator);
    defer allowed_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        allowed_result.satisfiable.values,
    );
}

test "global allow erasing removes conflicts and retains unrelated packages" {
    var installed_packages = [_]metadata.Package{
        testPackage("conflicting", "1"),
        testPackage("unrelated", "1"),
    };
    var available_relations = [_]metadata.Relation{
        .{ .name = "conflicting" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("requested", "1"),
    };
    available_packages[0].conflicts = .{ .start = 0, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1, .reason = .user },
        .{ .rpmdb_hnum = 2, .reason = .automatic },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();

    var blocked = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer blocked.deinit();
    var blocked_result = try blocked.solve(std.testing.allocator);
    defer blocked_result.deinit();
    try std.testing.expect(blocked_result == .unsatisfiable);

    var allowed = try prepareWithOptions(
        std.testing.allocator,
        &base,
        .{ .allow_erasing = true },
    );
    defer allowed.deinit();
    var allowed_result = try allowed.solve(std.testing.allocator);
    defer allowed_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true },
        allowed_result.satisfiable.values,
    );
}

test "global allow erasing permits reverse dependency cascades" {
    var installed_relations = [_]metadata.Relation{
        .{ .name = "dependency" },
    };
    var installed_packages = [_]metadata.Package{
        testPackage("dependency", "1"),
        testPackage("application", "1"),
    };
    installed_packages[1].requires = .{ .start = 0, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
        .relations = &installed_relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1, .reason = .automatic },
        .{ .rpmdb_hnum = 2, .reason = .user },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{
            .id = "@System",
            .model = &installed_model,
            .kind = .installed,
            .installed_states = &installed_states,
        }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();

    var blocked = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer blocked.deinit();
    var blocked_result = try blocked.solve(std.testing.allocator);
    defer blocked_result.deinit();
    try std.testing.expect(blocked_result == .unsatisfiable);

    var allowed = try prepareWithOptions(
        std.testing.allocator,
        &base,
        .{ .allow_erasing = true },
    );
    defer allowed.deinit();
    var allowed_result = try allowed.solve(std.testing.allocator);
    defer allowed_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false },
        allowed_result.satisfiable.values,
    );
}

test "skip broken keeps satisfiable exact install jobs" {
    var available_relations = [_]metadata.Relation{
        .{ .name = "missing-capability" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("good", "1"),
        testPackage("broken", "1"),
    };
    available_packages[1].requires = .{ .start = 0, .len = 1 };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &available_model }},
    );
    defer universe.deinit();
    const goal = solver_model.Goal{ .jobs = &.{
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        },
    } };
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        goal,
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var blocked = try prepared.solve(std.testing.allocator);
    defer blocked.deinit();
    try std.testing.expect(blocked == .unsatisfiable);

    var skipped = try prepared.solveSkipBroken(
        std.testing.allocator,
    );
    defer skipped.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false },
        skipped.result.satisfiable.values,
    );
    try std.testing.expectEqualSlices(
        solver_model.JobId,
        &.{@enumFromInt(1)},
        skipped.skipped_jobs,
    );
}

test "skip broken drops every exact install job in a package conflict" {
    var available_relations = [_]metadata.Relation{
        .{ .name = "second" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("first", "1"),
        testPackage("second", "1"),
    };
    available_packages[0].conflicts = .{ .start = 0, .len = 1 };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &available_model }},
    );
    defer universe.deinit();
    const goal = solver_model.Goal{ .jobs = &.{
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        },
    } };
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        goal,
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var skipped = try prepared.solveSkipBroken(
        std.testing.allocator,
    );
    defer skipped.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false },
        skipped.result.satisfiable.values,
    );
    try std.testing.expectEqualSlices(
        solver_model.JobId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        skipped.skipped_jobs,
    );
}

test "skip broken resolves multiple independent package failures" {
    var available_relations = [_]metadata.Relation{
        .{ .name = "missing-one" },
        .{ .name = "missing-two" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("broken-one", "1"),
        testPackage("good", "1"),
        testPackage("broken-two", "1"),
    };
    available_packages[0].requires = .{ .start = 0, .len = 1 };
    available_packages[2].requires = .{ .start = 1, .len = 1 };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &available_model }},
    );
    defer universe.deinit();
    const goal = solver_model.Goal{ .jobs = &.{
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        },
    } };
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        goal,
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var skipped = try prepared.solveSkipBroken(
        std.testing.allocator,
    );
    defer skipped.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, false },
        skipped.result.satisfiable.values,
    );
    try std.testing.expectEqualSlices(
        solver_model.JobId,
        &.{ @enumFromInt(0), @enumFromInt(2) },
        skipped.skipped_jobs,
    );
}

test "skip broken resolves independent conflicting job cores" {
    var available_relations = [_]metadata.Relation{
        .{ .name = "second-a" },
        .{ .name = "second-b" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("first-a", "1"),
        testPackage("second-a", "1"),
        testPackage("first-b", "1"),
        testPackage("second-b", "1"),
        testPackage("good", "1"),
    };
    available_packages[0].conflicts = .{ .start = 0, .len = 1 };
    available_packages[2].conflicts = .{ .start = 1, .len = 1 };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &available_model }},
    );
    defer universe.deinit();
    const goal = solver_model.Goal{ .jobs = &.{
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(3) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(4) },
        },
    } };
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        goal,
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();

    var skipped = try prepared.solveSkipBroken(
        std.testing.allocator,
    );
    defer skipped.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, false, false, true },
        skipped.result.satisfiable.values,
    );
    try std.testing.expectEqualSlices(
        solver_model.JobId,
        &.{
            @enumFromInt(0),
            @enumFromInt(1),
            @enumFromInt(2),
            @enumFromInt(3),
        },
        skipped.skipped_jobs,
    );
}

test "allow erasing resolves package conflicts before skip broken" {
    var installed_packages = [_]metadata.Package{
        testPackage("installed", "1"),
    };
    var available_relations = [_]metadata.Relation{
        .{ .name = "installed" },
    };
    var available_packages = [_]metadata.Package{
        testPackage("requested", "1"),
    };
    available_packages[0].conflicts = .{ .start = 0, .len = 1 };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
        .relations = &available_relations,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1, .reason = .automatic },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "@System",
                .model = &installed_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{ .id = "available", .model = &available_model },
        },
    );
    defer universe.deinit();
    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .install,
        .selection = .{ .package = @enumFromInt(1) },
    }} };
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        goal,
        testArchitecture(),
    );
    defer base.deinit();
    var prepared = try prepareWithOptions(
        std.testing.allocator,
        &base,
        .{ .allow_erasing = true },
    );
    defer prepared.deinit();

    var skipped = try prepared.solveSkipBroken(
        std.testing.allocator,
    );
    defer skipped.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        skipped.result.satisfiable.values,
    );
    try std.testing.expectEqual(@as(usize, 0), skipped.skipped_jobs.len);
}

test "skip broken rejects non-exact and policy-changing jobs" {
    var available_packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &available_model }},
    );
    defer universe.deinit();

    const cases = [_]solver_model.Job{
        .{ .action = .install, .selection = .{ .name = "package" } },
        .{ .action = .erase, .selection = .{ .package = @enumFromInt(0) } },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
            .flags = .{ .force_best = true },
        },
    };
    for (cases) |job| {
        const goal = solver_model.Goal{ .jobs = &.{job} };
        var base = try solver_rules.generateBase(
            std.testing.allocator,
            &universe,
            goal,
            testArchitecture(),
        );
        defer base.deinit();
        var prepared = try prepareInstalledRetention(
            std.testing.allocator,
            &base,
        );
        defer prepared.deinit();
        try std.testing.expectError(
            error.UnsupportedPolicy,
            prepared.solveSkipBroken(std.testing.allocator),
        );
    }

    const best_goal = solver_model.Goal{ .jobs = &.{.{
        .action = .install,
        .selection = .{ .package = @enumFromInt(0) },
    }} };
    var best_base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        best_goal,
        testArchitecture(),
    );
    defer best_base.deinit();
    var best_prepared = try prepareWithOptions(
        std.testing.allocator,
        &best_base,
        .{ .best = true },
    );
    defer best_prepared.deinit();
    try std.testing.expectError(
        error.UnsupportedPolicy,
        best_prepared.solveSkipBroken(std.testing.allocator),
    );

    var too_many_jobs: [solver_model.max_skip_broken_jobs + 1]solver_model.Job = undefined;
    for (&too_many_jobs) |*job| {
        job.* = .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        };
    }
    var too_many_base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &too_many_jobs },
        testArchitecture(),
    );
    defer too_many_base.deinit();
    var too_many_prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &too_many_base,
    );
    defer too_many_prepared.deinit();
    try std.testing.expectError(
        error.UnsupportedPolicy,
        too_many_prepared.solveSkipBroken(std.testing.allocator),
    );

    var malformed_states = [_]solver_rules.PackageState{.{}};
    const malformed_literals = [_]solver_rules.Literal{
        solver_rules.Literal.init(@enumFromInt(0), false),
    };
    const malformed_clauses = [_]solver_rules.Clause{.{
        .literals = .{ .start = 0, .len = 1 },
        .origin = .{ .job = @enumFromInt(0) },
    }};
    const malformed_base = solver_rules.OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .jobs = best_goal.jobs,
        .architecture = testArchitecture(),
        .clauses = &malformed_clauses,
        .literals = &malformed_literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &malformed_states,
    };
    var malformed_prepared = try prepareInstalledRetention(
        std.testing.allocator,
        &malformed_base,
    );
    defer malformed_prepared.deinit();
    try std.testing.expectError(
        error.InvalidFormula,
        malformed_prepared.solveSkipBroken(std.testing.allocator),
    );
}

test "multiversion state remains an explicit policy boundary" {
    var installed_packages = [_]metadata.Package{
        testPackage("parallel", "1"),
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{
            .id = "@System",
            .model = &installed_model,
            .kind = .installed,
            .installed_states = &installed_states,
        }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .multiversion,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        testArchitecture(),
    );
    defer base.deinit();
    try std.testing.expectError(
        error.UnsupportedPolicy,
        prepareInstalledRetention(std.testing.allocator, &base),
    );
}

test "disabled multilib remains an explicit policy boundary" {
    var packages = [_]metadata.Package{
        testPackage("package", "1"),
    };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &repository }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer base.deinit();
    base.architecture = .{
        .native_arch = "x86_64",
        .allow_multilib = false,
    };
    try std.testing.expectError(
        error.UnsupportedPolicy,
        prepareInstalledRetention(std.testing.allocator, &base),
    );
}

test "malformed package IDs and literal encodings are rejected" {
    var sources = [_]metadata.Package{testPackage("package", "1")};
    var source_model = metadata.RepositoryModel{ .packages = &sources };
    var repositories = [_]solver_model.UniverseRepository{.{
        .id = @enumFromInt(0),
        .input_index = 0,
        .name = "@System",
        .kind = .installed,
        .priority = 50,
        .cost = 1000,
        .source = &source_model,
        .packages = .{ .start = 0, .len = 1 },
    }};
    var packages = [_]solver_model.UniversePackage{.{
        .id = @enumFromInt(1),
        .repository = @enumFromInt(0),
        .repository_package_index = 0,
        .source = &sources[0],
        .installed = .{ .rpmdb_hnum = 1 },
    }};
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &repositories,
        .packages = &packages,
        .input_to_repository = &.{},
    };
    var states = [_]solver_rules.PackageState{.{}};
    var formula = solver_rules.OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &.{},
        .literals = &.{},
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    try std.testing.expectError(
        error.InvalidFormula,
        prepareInstalledRetention(std.testing.allocator, &formula),
    );

    packages[0].id = @enumFromInt(0);
    formula.literals = &.{@enumFromInt(std.math.maxInt(u64))};
    try std.testing.expectError(
        error.InvalidFormula,
        prepareInstalledRetention(std.testing.allocator, &formula),
    );
}

test "overlapping repository package ranges are rejected" {
    var sources = [_]metadata.Package{
        testPackage("one", "1"),
        testPackage("two", "1"),
    };
    var repository_models = [_]metadata.RepositoryModel{
        .{ .packages = sources[0..1] },
        .{ .packages = sources[1..2] },
    };
    var repositories = [_]solver_model.UniverseRepository{
        .{
            .id = @enumFromInt(0),
            .input_index = 0,
            .name = "one",
            .kind = .available,
            .priority = 50,
            .cost = 1000,
            .source = &repository_models[0],
            .packages = .{ .start = 0, .len = 2 },
        },
        .{
            .id = @enumFromInt(1),
            .input_index = 1,
            .name = "two",
            .kind = .available,
            .priority = 50,
            .cost = 1000,
            .source = &repository_models[1],
            .packages = .{ .start = 1, .len = 1 },
        },
    };
    var packages = [_]solver_model.UniversePackage{
        .{
            .id = @enumFromInt(0),
            .repository = @enumFromInt(0),
            .repository_package_index = 0,
            .source = &sources[0],
            .installed = null,
        },
        .{
            .id = @enumFromInt(1),
            .repository = @enumFromInt(1),
            .repository_package_index = 0,
            .source = &sources[1],
            .installed = null,
        },
    };
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &repositories,
        .packages = &packages,
        .input_to_repository = &.{},
    };
    var states = [_]solver_rules.PackageState{ .{}, .{} };
    const formula = solver_rules.OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &.{},
        .literals = &.{},
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    try std.testing.expectError(
        error.InvalidFormula,
        prepareInstalledRetention(std.testing.allocator, &formula),
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var available_relations = [_]metadata.Relation{
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "1",
        },
        .{
            .name = "shared-abi",
            .flags = "versioned",
            .comparison = .eq,
            .version = "2",
        },
    };
    var sources = [_]metadata.Package{
        testPackage("package", "1"),
        testPackage("provider-one", "2"),
        testPackage("provider-two", "3"),
    };
    sources[1].provides = .{ .start = 0, .len = 1 };
    sources[2].provides = .{ .start = 1, .len = 1 };
    var packages = [_]solver_model.UniversePackage{
        .{
            .id = @enumFromInt(0),
            .repository = @enumFromInt(0),
            .repository_package_index = 0,
            .source = &sources[0],
            .installed = .{ .rpmdb_hnum = 1 },
        },
        .{
            .id = @enumFromInt(1),
            .repository = @enumFromInt(1),
            .repository_package_index = 0,
            .source = &sources[1],
            .installed = null,
        },
        .{
            .id = @enumFromInt(2),
            .repository = @enumFromInt(1),
            .repository_package_index = 1,
            .source = &sources[2],
            .installed = null,
        },
    };
    var repository_models = [_]metadata.RepositoryModel{
        .{ .packages = sources[0..1] },
        .{
            .packages = sources[1..3],
            .relations = &available_relations,
        },
    };
    var repositories = [_]solver_model.UniverseRepository{
        .{
            .id = @enumFromInt(0),
            .input_index = 0,
            .name = "@System",
            .kind = .installed,
            .priority = 50,
            .cost = 1000,
            .source = &repository_models[0],
            .packages = .{ .start = 0, .len = 1 },
        },
        .{
            .id = @enumFromInt(1),
            .input_index = 1,
            .name = "available",
            .kind = .available,
            .priority = 50,
            .cost = 1000,
            .source = &repository_models[1],
            .packages = .{ .start = 1, .len = 2 },
        },
    };
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &repositories,
        .packages = &packages,
        .input_to_repository = &.{},
    };
    var states = [_]solver_rules.PackageState{ .{}, .{}, .{} };
    const literals = [_]solver_rules.Literal{
        solver_rules.Literal.init(@enumFromInt(0), false),
        solver_rules.Literal.init(@enumFromInt(1), false),
        solver_rules.Literal.init(@enumFromInt(1), true),
        solver_rules.Literal.init(@enumFromInt(2), true),
    };
    const clauses = [_]solver_rules.Clause{
        .{
            .literals = .{ .start = 0, .len = 2 },
            .origin = .{
                .same_name = .{
                    .left = @enumFromInt(0),
                    .right = @enumFromInt(1),
                },
            },
        },
        .{
            .literals = .{ .start = 2, .len = 1 },
            .origin = .{ .job = @enumFromInt(0) },
        },
    };
    const base = solver_rules.OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }},
        .architecture = testArchitecture(),
        .clauses = &clauses,
        .literals = &literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    var prepared = try prepareInstalledRetention(allocator, &base);
    defer prepared.deinit();
    var result = try prepared.solve(allocator);
    defer result.deinit();
    var skip_broken = try prepared.solveSkipBroken(
        allocator,
    );
    defer skip_broken.deinit();
    var weak_result = try prepared.solveWeak(allocator, .{});
    defer weak_result.deinit();
}

test "policy preparation cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
