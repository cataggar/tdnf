//! Reusable native solve and canonical result materialization.

const std = @import("std");
const solver_coordinator = @import("solver_coordinator.zig");
const solver_identity = @import("solver_identity.zig");
const solver_model = @import("solver_model.zig");
const solver_policy = @import("solver_policy.zig");
const solver_result = @import("solver_result.zig");
const solver_result_abi = @import("solver_result_abi.zig");
const solver_result_c = @import("solver_result_c.zig");
const solver_rules = @import("solver_rules.zig");
const solver_search = @import("solver_search.zig");
const solver_visibility = @import("solver_visibility.zig");

pub const SolveError =
    solver_coordinator.SolveError ||
    solver_rules.GenerateError ||
    solver_policy.PrepareError ||
    solver_policy.SkipBrokenError ||
    solver_search.SolveError ||
    solver_result.MaterializeError ||
    error{
        Unsatisfiable,
        ProtectedPackage,
        InstallonlyLimit,
    };

pub const ProjectedSolveError =
    SolveError ||
    solver_identity.InitError ||
    error{
        InvalidVisibility,
        UnsupportedVisibility,
    };

/// The originating universe must outlive this result and C materialization.
pub const OwnedSolveResult = struct {
    universe: *const solver_model.Universe,
    result: solver_result.OwnedResult,
    effective_job_count: usize,

    pub fn deinit(self: *OwnedSolveResult) void {
        self.result.deinit();
        self.* = undefined;
    }

    pub fn takeResult(self: *OwnedSolveResult) solver_result.OwnedResult {
        const result = self.result;
        self.* = undefined;
        return result;
    }

    pub fn buildOwnedC(
        self: *const OwnedSolveResult,
    ) solver_result_c.BuildError!*solver_result_abi.Result {
        return solver_result_c.buildOwned(.{
            .universe = self.universe,
            .job_count = self.effective_job_count,
            .selected = self.result.selected,
            .outcome = &self.result.outcome,
        });
    }
};

pub fn solve(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!OwnedSolveResult {
    if (policy.installonly_names.len != 0) {
        return solveInstallonly(allocator, universe, goal, policy);
    }
    return solveOrdinary(allocator, universe, goal, policy);
}

/// Strict pre-runtime entry point for already translated live inputs.
pub fn solveProjected(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    visibility: *const solver_visibility.Projection,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) ProjectedSolveError!OwnedSolveResult {
    if (visibility.visible.len != universe.packages.len or
        visibility.hidden_reasons.len != universe.packages.len)
    {
        return error.InvalidVisibility;
    }
    var identity = try solver_identity.Index.init(allocator, universe);
    defer identity.deinit();
    if (!hasHiddenPackages(visibility)) {
        return solve(allocator, universe, goal, policy);
    }
    if (policy.installonly_names.len != 0) {
        return error.UnsupportedVisibility;
    }
    return solveOrdinaryProjected(
        allocator,
        universe,
        visibility,
        goal,
        policy,
    );
}

fn solveOrdinary(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!OwnedSolveResult {
    return solveOrdinaryProjected(
        allocator,
        universe,
        null,
        goal,
        policy,
    );
}

fn solveOrdinaryProjected(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    visibility: ?*const solver_visibility.Projection,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!OwnedSolveResult {
    var base = if (visibility) |projection|
        try solver_rules.generateProjectedBase(
            allocator,
            universe,
            projection,
            goal,
            policy.architecture,
        )
    else
        try solver_rules.generateBase(
            allocator,
            universe,
            goal,
            policy.architecture,
        );
    defer base.deinit();
    var prepared = try solver_policy.prepareWithOptions(
        allocator,
        &base,
        .{
            .best = policy.best,
            .allow_erasing = policy.allow_erasing,
            .clean_deps = policy.clean_deps,
            .protected_names = policy.protected_names,
        },
    );
    defer prepared.deinit();

    if (policy.skip_broken) {
        var skipped = try prepared.solveSkipBroken(allocator);
        defer skipped.deinit();
        const model = switch (skipped.result) {
            .satisfiable => |value| value,
            .unsatisfiable => return error.Unsatisfiable,
        };
        if (prepared.protectedRemoval(model) != null) {
            return error.ProtectedPackage;
        }

        var result = try solver_result.materialize(allocator, .{
            .prepared = &prepared,
            .model = model,
            .skipped_jobs = skipped.skipped_jobs,
        });
        errdefer result.deinit();
        try validateInstallCleanDepsNoOp(goal, policy, &result);
        return .{
            .universe = universe,
            .result = result,
            .effective_job_count = goal.jobs.len,
        };
    }

    var weak = try prepared.solveWeak(
        allocator,
        .{ .enabled = policy.install_weak_deps },
    );
    defer weak.deinit();
    const model = switch (weak.result) {
        .satisfiable => |value| value,
        .unsatisfiable => return error.Unsatisfiable,
    };
    if (prepared.protectedRemoval(model) != null) {
        return error.ProtectedPackage;
    }
    var result = try solver_result.materialize(allocator, .{
        .prepared = &prepared,
        .model = model,
        .accepted_weak = weak.accepted,
    });
    errdefer result.deinit();
    try validateInstallCleanDepsNoOp(goal, policy, &result);
    return .{
        .universe = universe,
        .result = result,
        .effective_job_count = goal.jobs.len,
    };
}

fn validateInstallCleanDepsNoOp(
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
    result: *const solver_result.OwnedResult,
) error{UnsupportedPolicy}!void {
    if (!policy.clean_deps or goal.jobs.len == 0) return;
    for (goal.jobs) |job| {
        if (job.action != .install or
            std.meta.activeTag(job.selection) != .package)
        {
            return;
        }
    }
    for (result.outcome.actions) |action| {
        if (action.kind != .install) return error.UnsupportedPolicy;
    }
}

fn hasHiddenPackages(
    visibility: *const solver_visibility.Projection,
) bool {
    for (visibility.visible) |is_visible| {
        if (!is_visible) return true;
    }
    return false;
}

fn solveInstallonly(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!OwnedSolveResult {
    var coordinated = try solver_coordinator.solveInstallonly(
        allocator,
        universe,
        goal,
        policy,
    );
    defer coordinated.deinit();
    if (coordinated.problem) |problem| {
        return switch (problem) {
            .protected_package => error.ProtectedPackage,
            .installonly_limit => error.InstallonlyLimit,
        };
    }
    const model = switch (coordinated.weak_result.result) {
        .satisfiable => |value| value,
        .unsatisfiable => return error.Unsatisfiable,
    };
    return .{
        .universe = universe,
        .result = try solver_result.materialize(allocator, .{
            .prepared = &coordinated.prepared,
            .model = model,
            .accepted_weak = coordinated.weak_result.accepted,
            .eviction_packages = coordinated.eviction_packages,
        }),
        .effective_job_count = coordinated.jobs.len,
    };
}

fn testPackage(name: []const u8) @import("model.zig").Package {
    return testPackageVersion(name, "1");
}

fn testPackageVersion(
    name: []const u8,
    version: []const u8,
) @import("model.zig").Package {
    return .{
        .pkg_id = name,
        .nevra = .{
            .name = name,
            .version = version,
            .release = "1",
            .arch = "x86_64",
        },
        .checksum = .{
            .kind = "sha256",
            .value = name,
            .is_pkgid = true,
        },
        .location = .{},
    };
}

fn testPolicy() solver_model.SolvePolicy {
    return .{
        .architecture = .{ .native_arch = "x86_64" },
    };
}

test "projected solve materializes and deep copies an exact install" {
    var packages = [_]@import("model.zig").Package{
        testPackage("candidate"),
    };
    const inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &packages },
    }};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();
    var visibility = try solver_visibility.Projection.init(
        std.testing.allocator,
        &universe,
        .{},
    );
    defer visibility.deinit();

    var solved = try solveProjected(
        std.testing.allocator,
        &universe,
        &visibility,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        testPolicy(),
    );
    defer solved.deinit();
    try std.testing.expectEqual(@as(usize, 1), solved.result.selected.len);
    try std.testing.expectEqual(@as(usize, 1), solved.result.outcome.actions.len);
    try std.testing.expectEqual(
        solver_model.ActionKind.install,
        solved.result.outcome.actions[0].kind,
    );

    const c_result = try solved.buildOwnedC();
    defer solver_result_c.freeOwnedResult(c_result);
    try std.testing.expectEqual(
        @as(u32, 1),
        c_result.dwSelectedPackageCount,
    );
    try std.testing.expectEqual(@as(u32, 1), c_result.dwActionCount);
}

test "projected solve rejects an exact hidden available install" {
    var packages = [_]@import("model.zig").Package{
        testPackage("candidate"),
    };
    const inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &packages },
    }};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();
    var hidden = try solver_visibility.Projection.init(
        std.testing.allocator,
        &universe,
        .{ .exclude_name_patterns = &.{"candidate"} },
    );
    defer hidden.deinit();
    try std.testing.expectError(
        error.Unsatisfiable,
        solveProjected(
            std.testing.allocator,
            &universe,
            &hidden,
            .{ .jobs = &.{.{
                .action = .install,
                .selection = .{ .package = @enumFromInt(0) },
            }} },
            testPolicy(),
        ),
    );
}

test "projected solve rejects misaligned visibility" {
    var packages = [_]@import("model.zig").Package{
        testPackage("candidate"),
    };
    const inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &packages },
    }};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();
    const invalid = solver_visibility.Projection{
        .allocator = std.testing.allocator,
        .visible = &.{},
        .hidden_reasons = &.{},
    };
    try std.testing.expectError(
        error.InvalidVisibility,
        solveProjected(
            std.testing.allocator,
            &universe,
            &invalid,
            .{ .jobs = &.{} },
            testPolicy(),
        ),
    );
}

test "projected solve keeps a hidden installed package" {
    var packages = [_]@import("model.zig").Package{
        testPackage("installed"),
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    const inputs = [_]solver_model.RepositoryInput{.{
        .id = "@System",
        .model = &.{ .packages = &packages },
        .kind = .installed,
        .installed_states = &installed_states,
    }};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();
    var hidden = try solver_visibility.Projection.initConsidered(
        std.testing.allocator,
        &universe,
        &.{false},
    );
    defer hidden.deinit();

    var solved = try solveProjected(
        std.testing.allocator,
        &universe,
        &hidden,
        .{ .jobs = &.{} },
        testPolicy(),
    );
    defer solved.deinit();
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        solved.result.selected,
    );

    var erase_policy = testPolicy();
    erase_policy.allow_erasing = true;
    var erased = try solveProjected(
        std.testing.allocator,
        &universe,
        &hidden,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        erase_policy,
    );
    defer erased.deinit();
    try std.testing.expectEqual(@as(usize, 0), erased.result.selected.len);
    try std.testing.expectEqual(
        solver_model.ActionKind.erase,
        erased.result.outcome.actions[0].kind,
    );
}

test "native solve reports an unsatisfiable exact job conflict" {
    var packages = [_]@import("model.zig").Package{
        testPackage("candidate"),
    };
    const inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &packages },
    }};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();

    try std.testing.expectError(
        error.Unsatisfiable,
        solve(
            std.testing.allocator,
            &universe,
            .{ .jobs = &.{
                .{
                    .action = .install,
                    .selection = .{ .package = @enumFromInt(0) },
                },
                .{
                    .action = .erase,
                    .selection = .{ .package = @enumFromInt(0) },
                },
            } },
            testPolicy(),
        ),
    );
}

test "installonly solve retains effective synthetic job count" {
    var installed_packages = [_]@import("model.zig").Package{
        testPackageVersion("kernel", "1"),
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var available_packages = [_]@import("model.zig").Package{
        testPackageVersion("kernel", "2"),
    };
    const inputs = [_]solver_model.RepositoryInput{
        .{
            .id = "@System",
            .model = &.{ .packages = &installed_packages },
            .kind = .installed,
            .installed_states = &installed_states,
        },
        .{
            .id = "repo",
            .model = &.{ .packages = &available_packages },
        },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();
    var policy = testPolicy();
    policy.installonly_names = &.{"kernel"};
    policy.installonly_limit = 2;

    var solved = try solve(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        policy,
    );
    defer solved.deinit();
    try std.testing.expectEqual(
        @as(usize, 2),
        solved.effective_job_count,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        solved.result.selected.len,
    );
    const c_result = try solved.buildOwnedC();
    defer solver_result_c.freeOwnedResult(c_result);
    try std.testing.expectEqual(@as(u32, 2), c_result.dwSelectedPackageCount);
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    visibility: *const solver_visibility.Projection,
) !void {
    var solved = try solveProjected(
        allocator,
        universe,
        visibility,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        testPolicy(),
    );
    defer solved.deinit();
    try std.testing.expectEqual(@as(usize, 1), solved.result.selected.len);
}

test "projected solve cleans every allocation failure" {
    var packages = [_]@import("model.zig").Package{
        testPackage("candidate"),
    };
    const inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &packages },
    }};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();
    var visibility = try solver_visibility.Projection.init(
        std.testing.allocator,
        &universe,
        .{},
    );
    defer visibility.deinit();

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{ &universe, &visibility },
    );
}
