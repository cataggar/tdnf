//! Package-policy preparation for the native solver.
//!
//! This slice preserves installed packages unless a same-name or explicit
//! obsoleting replacement is selected and ranks ordinary job and requirement
//! candidates by repository priority, architecture, same-name package EVR,
//! and common versioned provides. Update jobs, allow-erasing, recommendation
//! policy, and cleanup policy remain separate follow-up work.

const std = @import("std");
const query_index = @import("index.zig");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");
const solver_rules = @import("solver_rules.zig");
const solver_search = @import("solver_search.zig");

const PackageIdList = std.array_list.Managed(solver_model.PackageId);
const CandidateGroupList =
    std.array_list.Managed(solver_search.CandidateGroup);

pub const PrepareError = error{
    OutOfMemory,
    InvalidFormula,
    UnsupportedPolicy,
    TooManyClauses,
    TooManyLiterals,
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    formula: solver_rules.OwnedFormula,
    decision_policy: solver_search.CandidateDecisionPolicy,

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
            error.InvalidCandidatePolicy => error.InvalidDecisionPolicy,
            else => |solve_error| return solve_error,
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
/// The returned formula still borrows the universe, repository metadata, and
/// architecture policy strings.
pub fn prepareInstalledRetention(
    allocator: std.mem.Allocator,
    base: *const solver_rules.OwnedFormula,
) PrepareError!Prepared {
    const package_count = base.universe.packages.len;
    try validateBaseFormula(base);
    if (base.architecture) |architecture| {
        if (!architecture.allow_multilib) return error.UnsupportedPolicy;
    }
    for (base.package_states) |state| {
        if (state.multiversion) return error.UnsupportedPolicy;
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

    var candidate_groups = CandidateGroupList.init(allocator);
    defer candidate_groups.deinit();
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
    try rankCandidateGroups(
        allocator,
        base.universe,
        base.architecture,
        candidate_groups.items,
        policy_candidates.items,
    );

    var clauses = std.array_list.Managed(solver_rules.Clause).init(allocator);
    defer clauses.deinit();
    try clauses.appendSlice(base.clauses);
    var literals = std.array_list.Managed(solver_rules.Literal).init(allocator);
    defer literals.deinit();
    try literals.appendSlice(base.literals);

    for (base.universe.packages) |package| {
        const installed = package.installed orelse continue;
        _ = installed;
        const package_index: usize = @intFromEnum(package.id);
        if (directly_erased[package_index] or
            base.package_states[package_index].allow_uninstall)
        {
            continue;
        }

        const package_candidates = &replacement_candidates[package_index];
        std.sort.heap(
            solver_model.PackageId,
            package_candidates.items,
            {},
            packageIdLessThan,
        );
        var write_index: usize = 0;
        for (package_candidates.items) |candidate| {
            const candidate_index = try packageIndex(
                candidate,
                package_count,
            );
            if (candidate == package.id or
                not_installable[candidate_index] or
                (write_index != 0 and
                    package_candidates.items[write_index - 1] == candidate))
            {
                continue;
            }
            package_candidates.items[write_index] = candidate;
            write_index += 1;
        }
        package_candidates.shrinkRetainingCapacity(write_index);

        if (clauses.items.len == std.math.maxInt(u32)) {
            return error.TooManyClauses;
        }
        if (literals.items.len > std.math.maxInt(u32) or
            package_candidates.items.len + 1 >
                std.math.maxInt(u32) - literals.items.len)
        {
            return error.TooManyLiterals;
        }
        const start = literals.items.len;
        try literals.append(solver_rules.Literal.init(package.id, true));
        for (package_candidates.items) |candidate| {
            try literals.append(solver_rules.Literal.init(candidate, true));
        }
        try clauses.append(.{
            .literals = .{
                .start = @intCast(start),
                .len = @intCast(package_candidates.items.len + 1),
            },
            .origin = .{ .installed_keep = package.id },
        });
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
            .architecture = base.architecture,
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
    };
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
        for (frontier.items, 0..) |candidate, candidate_index| {
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
        std.sort.block(
            CommonCandidate,
            frontier.items,
            {},
            installedNameLessThan,
        );

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
        _ = try packageIndex(request.dependency.package, package_count);
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
            .literals = .{ .start = 2, .len = 2 },
            .origin = .{ .job = @enumFromInt(0) },
        },
    };
    const base = solver_rules.OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
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
}

test "policy preparation cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
