//! Canonical result materialization for completed native solver models.

const std = @import("std");
const query_index = @import("index.zig");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");
const solver_policy = @import("solver_policy.zig");
const solver_rules = @import("solver_rules.zig");
const solver_search = @import("solver_search.zig");

const ActionList = std.array_list.Managed(solver_model.Action);
const PackageIdList = std.array_list.Managed(solver_model.PackageId);

pub const Input = struct {
    prepared: *const solver_policy.Prepared,
    model: solver_search.Model,
    accepted_weak: []const solver_policy.AcceptedWeak = &.{},
    eviction_packages: []const solver_model.PackageId = &.{},
    skipped_jobs: []const solver_model.JobId = &.{},
};

pub const OwnedResult = struct {
    arena_state: std.heap.ArenaAllocator,
    selected: []const solver_model.PackageId,
    outcome: solver_model.Outcome,

    pub fn deinit(self: *OwnedResult) void {
        self.arena_state.deinit();
        self.* = undefined;
    }
};

pub const MaterializeError = error{
    OutOfMemory,
    InvalidInput,
};

/// Convert a complete satisfiable model into canonical package actions.
///
/// This does not derive transaction execution order. Verified RPM inputs
/// continue through transaction_native.zig after result materialization.
pub fn materialize(
    allocator: std.mem.Allocator,
    input: Input,
) MaterializeError!OwnedResult {
    const formula = &input.prepared.formula;
    const universe = formula.universe;
    const package_count = universe.packages.len;
    if (input.model.values.len != package_count or
        formula.package_states.len != package_count)
    {
        return error.InvalidInput;
    }
    try validatePackageIds(
        universe,
        input.prepared.cleanup_packages,
        true,
    );
    try validatePackageIds(universe, input.eviction_packages, true);
    for (input.accepted_weak) |accepted| {
        if (universe.package(accepted.package) == null) {
            return error.InvalidInput;
        }
    }
    for (input.skipped_jobs) |job_id| {
        if (@intFromEnum(job_id) >= formula.jobs.len) {
            return error.InvalidInput;
        }
    }

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    var selected = PackageIdList.init(arena);
    var removed = try arena.alloc(bool, package_count);
    @memset(removed, false);
    for (universe.packages) |package| {
        const package_index: usize = @intFromEnum(package.id);
        if (input.model.values[package_index]) {
            try selected.append(package.id);
        } else if (package.installed != null) {
            removed[package_index] = true;
        }
    }

    var referenced_priors = try arena.alloc(bool, package_count);
    @memset(referenced_priors, false);
    var actions = ActionList.init(arena);
    for (universe.packages) |package| {
        const package_index: usize = @intFromEnum(package.id);
        if (package.installed != null or
            !input.model.values[package_index])
        {
            continue;
        }

        var priors = PackageIdList.init(arena);
        var has_same_name_prior = false;
        var has_exact_multiversion_prior = false;
        const multiversion =
            formula.package_states[package_index].multiversion;
        if (!multiversion) {
            for (universe.packages) |installed| {
                const installed_index: usize =
                    @intFromEnum(installed.id);
                if (!removed[installed_index]) continue;
                if (packageObsoletes(
                    universe,
                    package,
                    installed,
                )) {
                    referenced_priors[installed_index] = true;
                    try priors.append(installed.id);
                }
            }
        }
        if (multiversion) {
            for (universe.packages) |installed| {
                const installed_index: usize = @intFromEnum(installed.id);
                if (!removed[installed_index] or
                    !sameMultiversionIdentity(package, installed))
                {
                    continue;
                }
                referenced_priors[installed_index] = true;
                has_exact_multiversion_prior = true;
                has_same_name_prior = true;
                if (!containsPackage(priors.items, installed.id)) {
                    try priors.append(installed.id);
                }
            }
            if (!has_exact_multiversion_prior) priors.clearRetainingCapacity();
        } else {
            for (universe.packages) |installed| {
                const installed_index: usize = @intFromEnum(installed.id);
                if (!removed[installed_index] or
                    solver_rules.isSource(
                        package.source.nevra.arch,
                    ) or
                    solver_rules.isSource(
                        installed.source.nevra.arch,
                    ) or
                    !std.mem.eql(
                        u8,
                        package.source.nevra.name,
                        installed.source.nevra.name,
                    ))
                {
                    continue;
                }
                referenced_priors[installed_index] = true;
                has_same_name_prior = true;
                if (!containsPackage(priors.items, installed.id)) {
                    try priors.append(installed.id);
                }
            }
            if (!has_same_name_prior) {
                for (priors.items) |prior_id| {
                    const prior = universe.package(prior_id) orelse
                        return error.InvalidInput;
                    if (std.mem.eql(
                        u8,
                        package.source.nevra.name,
                        prior.source.nevra.name,
                    )) {
                        has_same_name_prior = true;
                        break;
                    }
                }
            }
        }
        std.sort.pdq(
            solver_model.PackageId,
            priors.items,
            {},
            packageIdLessThan,
        );

        const kind = if (priors.items.len == 0)
            solver_model.ActionKind.install
        else if (!has_same_name_prior)
            solver_model.ActionKind.obsolete
        else
            try replacementKind(universe, package, priors.items);
        const decision = decisionReason(input, package.id);
        const policy_replacement = decisionPolicyReason(
            formula,
            decision,
        );
        try actions.append(.{
            .package = package.id,
            .priors = try priors.toOwnedSlice(),
            .kind = kind,
            .reason = if (kind == .obsolete)
                .obsoletes
            else if (policy_replacement)
                .policy
            else
                decision.reason,
            .requested_by = if (policy_replacement)
                null
            else
                decision.requested_by,
        });
    }

    for (universe.packages) |package| {
        const package_index: usize = @intFromEnum(package.id);
        if (!removed[package_index] or referenced_priors[package_index]) {
            continue;
        }
        const decision = decisionReason(input, package.id);
        try actions.append(.{
            .package = package.id,
            .kind = .erase,
            .reason = if (containsPackage(
                input.eviction_packages,
                package.id,
            ))
                .installonly_limit
            else if (containsPackage(
                input.prepared.cleanup_packages,
                package.id,
            ))
                .cleanup
            else
                decision.reason,
            .requested_by = if (containsPackage(
                input.eviction_packages,
                package.id,
            ) or containsPackage(
                input.prepared.cleanup_packages,
                package.id,
            ))
                null
            else
                decision.requested_by,
        });
    }
    std.sort.pdq(
        solver_model.Action,
        actions.items,
        {},
        actionLessThan,
    );

    const owned_selected = try selected.toOwnedSlice();
    const owned_actions = try actions.toOwnedSlice();
    const owned_skipped = try arena.dupe(
        solver_model.JobId,
        input.skipped_jobs,
    );
    return .{
        .arena_state = arena_state,
        .selected = owned_selected,
        .outcome = .{
            .actions = owned_actions,
            .problems = &.{},
            .skipped_jobs = owned_skipped,
        },
    };
}

const DecisionReason = struct {
    reason: solver_model.TransactionReason,
    requested_by: ?solver_model.JobId = null,
};

fn decisionReason(
    input: Input,
    package_id: solver_model.PackageId,
) DecisionReason {
    if (containsAcceptedWeak(input.accepted_weak, package_id)) {
        return .{ .reason = .weak_dependency };
    }
    const prepared = input.prepared;
    var group_job: ?solver_model.JobId = null;
    var group_matches: usize = 0;
    for (prepared.decision_policy.groups) |group| {
        var chosen: ?solver_model.PackageId = null;
        for (group.candidates.slice(
            prepared.decision_policy.candidates,
        )) |candidate| {
            if (input.model.value(candidate) orelse false) {
                chosen = candidate;
                break;
            }
        }
        if (chosen != package_id or
            group.clause_index >= prepared.formula.clauses.len)
        {
            continue;
        }
        const job_id = switch (prepared.formula.clauses[
            group.clause_index
        ].origin) {
            .job => |value| value,
            else => continue,
        };
        if (group_job == null) group_job = job_id;
        if (group_job == job_id) group_matches += 1;
    }
    if (group_job) |job_id| {
        const job_index: usize = @intFromEnum(job_id);
        if (job_index < prepared.formula.jobs.len) {
            const job = prepared.formula.jobs[job_index];
            if (group_matches > 1 and job.action == .dist_sync) {
                return .{ .reason = .dependency };
            }
            return .{
                .reason = requestReason(job.reason),
                .requested_by = job_id,
            };
        }
    }
    for (prepared.formula.clauses, 0..) |clause, clause_index| {
        const job_id = switch (clause.origin) {
            .job => |value| value,
            else => continue,
        };
        if (isCandidateGroupClause(prepared, clause_index)) continue;
        if (!packageSatisfiesJobClause(
            prepared,
            input.model,
            package_id,
            clause,
        )) {
            continue;
        }
        const job_index: usize = @intFromEnum(job_id);
        if (job_index >= prepared.formula.jobs.len) continue;
        return .{
            .reason = requestReason(
                prepared.formula.jobs[job_index].reason,
            ),
            .requested_by = job_id,
        };
    }
    return .{ .reason = .dependency };
}

fn isCandidateGroupClause(
    prepared: *const solver_policy.Prepared,
    clause_index: usize,
) bool {
    for (prepared.decision_policy.groups) |group| {
        if (group.clause_index == clause_index) return true;
    }
    return false;
}

fn packageSatisfiesJobClause(
    prepared: *const solver_policy.Prepared,
    model: solver_search.Model,
    package_id: solver_model.PackageId,
    clause: solver_rules.Clause,
) bool {
    const value = model.value(package_id) orelse return false;
    for (prepared.formula.clauseLiterals(clause)) |literal| {
        if (literal.package() == package_id and
            literal.positive() == value)
        {
            return true;
        }
    }
    return false;
}

fn packageObsoletes(
    universe: *const solver_model.Universe,
    package: solver_model.UniversePackage,
    installed: solver_model.UniversePackage,
) bool {
    if (installed.installed == null) return false;
    for (package.relationEntries(universe, .obsoletes)) |relation| {
        if (solver_rules.packageMatchesNevr(
            installed.source.*,
            relation,
        )) {
            return true;
        }
    }
    return false;
}

fn sameMultiversionIdentity(
    package: solver_model.UniversePackage,
    installed: solver_model.UniversePackage,
) bool {
    return installed.installed != null and
        !solver_rules.isSource(package.source.nevra.arch) and
        !solver_rules.isSource(installed.source.nevra.arch) and
        std.mem.eql(
            u8,
            package.source.nevra.name,
            installed.source.nevra.name,
        ) and
        std.mem.eql(
            u8,
            package.source.nevra.arch,
            installed.source.nevra.arch,
        ) and
        comparePackageEvr(package, installed) == 0;
}

fn decisionPolicyReason(
    formula: *const solver_rules.OwnedFormula,
    decision: DecisionReason,
) bool {
    const job_id = decision.requested_by orelse return false;
    const job_index: usize = @intFromEnum(job_id);
    if (job_index >= formula.jobs.len) return false;
    return switch (formula.jobs[job_index].action) {
        .update, .dist_sync => true,
        else => false,
    };
}

fn replacementKind(
    universe: *const solver_model.Universe,
    package: solver_model.UniversePackage,
    priors: []const solver_model.PackageId,
) MaterializeError!solver_model.ActionKind {
    var reference: ?solver_model.UniversePackage = null;
    for (priors) |prior_id| {
        const prior = universe.package(prior_id) orelse
            return error.InvalidInput;
        if (!std.mem.eql(
            u8,
            package.source.nevra.name,
            prior.source.nevra.name,
        )) {
            continue;
        }
        if (reference) |current| {
            const evr_order = comparePackageEvr(prior.*, current);
            if (evr_order < 0) continue;
            if (evr_order == 0) {
                const prior_same_arch = std.mem.eql(
                    u8,
                    prior.source.nevra.arch,
                    package.source.nevra.arch,
                );
                const current_same_arch = std.mem.eql(
                    u8,
                    current.source.nevra.arch,
                    package.source.nevra.arch,
                );
                if (!prior_same_arch and current_same_arch) continue;
                if (prior_same_arch == current_same_arch and
                    @intFromEnum(prior.id) > @intFromEnum(current.id))
                {
                    continue;
                }
            }
        }
        reference = prior.*;
    }
    const prior = reference orelse return error.InvalidInput;
    return switch (std.math.sign(comparePackageEvr(package, prior))) {
        -1 => .downgrade,
        0 => .reinstall,
        1 => .upgrade,
        else => unreachable,
    };
}

fn comparePackageEvr(
    left: solver_model.UniversePackage,
    right: solver_model.UniversePackage,
) i32 {
    return query_index.compareEvr(
        left.source.nevra.epoch,
        left.source.nevra.version,
        left.source.nevra.release,
        right.source.nevra.epoch,
        right.source.nevra.version,
        right.source.nevra.release,
    );
}

fn requestReason(
    reason: solver_model.RequestReason,
) solver_model.TransactionReason {
    return switch (reason) {
        .user => .user,
        .dependency => .dependency,
        .weak_dependency => .weak_dependency,
        .cleanup => .cleanup,
        .installonly_limit => .installonly_limit,
        .policy => .policy,
    };
}

fn validatePackageIds(
    universe: *const solver_model.Universe,
    package_ids: []const solver_model.PackageId,
    require_installed: bool,
) MaterializeError!void {
    for (package_ids) |package_id| {
        const package = universe.package(package_id) orelse
            return error.InvalidInput;
        if (require_installed and package.installed == null) {
            return error.InvalidInput;
        }
    }
}

fn containsAcceptedWeak(
    accepted: []const solver_policy.AcceptedWeak,
    package_id: solver_model.PackageId,
) bool {
    for (accepted) |entry| {
        if (entry.package == package_id) return true;
    }
    return false;
}

fn containsPackage(
    packages: []const solver_model.PackageId,
    package_id: solver_model.PackageId,
) bool {
    for (packages) |candidate| {
        if (candidate == package_id) return true;
    }
    return false;
}

fn packageIdLessThan(
    _: void,
    left: solver_model.PackageId,
    right: solver_model.PackageId,
) bool {
    return @intFromEnum(left) < @intFromEnum(right);
}

fn actionLessThan(
    _: void,
    left: solver_model.Action,
    right: solver_model.Action,
) bool {
    return @intFromEnum(left.package) < @intFromEnum(right.package);
}

test "materializer rejects a model with the wrong package count" {
    const repository_model = metadata.RepositoryModel{};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{
            .id = "available",
            .model = &repository_model,
        }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{} },
        .{ .native_arch = "x86_64" },
    );
    defer base.deinit();
    var prepared = try solver_policy.prepareInstalledRetention(
        std.testing.allocator,
        &base,
    );
    defer prepared.deinit();
    var values = [_]bool{true};

    try std.testing.expectError(
        error.InvalidInput,
        materialize(std.testing.allocator, .{
            .prepared = &prepared,
            .model = .{
                .allocator = std.testing.allocator,
                .values = &values,
            },
        }),
    );
}

fn materializerAllocationFailureCase(
    allocator: std.mem.Allocator,
) !void {
    var packages = [_]metadata.Package{.{
        .pkg_id = "application-1",
        .nevra = .{
            .name = "application",
            .version = "1",
            .release = "1",
            .arch = "x86_64",
        },
        .checksum = .{
            .kind = "sha256",
            .value = "application-1",
            .is_pkgid = true,
        },
        .location = .{ .href = "application-1" },
    }};
    const repository_model = metadata.RepositoryModel{
        .packages = &packages,
    };
    var universe = try solver_model.Universe.init(
        allocator,
        &.{.{
            .id = "available",
            .model = &repository_model,
        }},
    );
    defer universe.deinit();
    var base = try solver_rules.generateBase(
        allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        .{ .native_arch = "x86_64" },
    );
    defer base.deinit();
    var prepared = try solver_policy.prepareInstalledRetention(
        allocator,
        &base,
    );
    defer prepared.deinit();
    var solved = try prepared.solve(allocator);
    defer solved.deinit();
    var materialized = switch (solved) {
        .satisfiable => |model| try materialize(
            allocator,
            .{
                .prepared = &prepared,
                .model = model,
            },
        ),
        .unsatisfiable => return error.TestUnexpectedResult,
    };
    defer materialized.deinit();

    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        materialized.selected,
    );
    try std.testing.expectEqual(@as(usize, 1), materialized.outcome.actions.len);
    const action = materialized.outcome.actions[0];
    try std.testing.expectEqual(
        solver_model.ActionKind.install,
        action.kind,
    );
    try std.testing.expectEqual(
        solver_model.TransactionReason.user,
        action.reason,
    );
    try std.testing.expectEqual(
        @as(?solver_model.JobId, @enumFromInt(0)),
        action.requested_by,
    );
}

test "materializer cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        materializerAllocationFailureCase,
        .{},
    );
}
