//! Multi-round policy coordination for the native package solver.

const std = @import("std");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");
const solver_policy = @import("solver_policy.zig");
const solver_rules = @import("solver_rules.zig");
const solver_search = @import("solver_search.zig");

const JobList = std.array_list.Managed(solver_model.Job);
const PackageIdList = std.array_list.Managed(solver_model.PackageId);
const StringList = std.array_list.Managed([]const u8);

pub const InstallonlyOverflow = struct {
    name: []const u8,
    limit: u32,
    final_count: u32,
    excess: u32,
};

pub const PolicyProblem = union(enum) {
    protected_package: solver_model.PackageId,
    installonly_limit: InstallonlyOverflow,
};

pub const OwnedSolve = struct {
    arena_state: std.heap.ArenaAllocator,
    prepared: solver_policy.Prepared,
    weak_result: solver_policy.WeakResult,
    jobs: []const solver_model.Job,
    installonly_names: []const []const u8,
    eviction_packages: []const solver_model.PackageId,
    rounds: u2,
    problem: ?PolicyProblem = null,

    pub fn deinit(self: *OwnedSolve) void {
        self.weak_result.deinit();
        self.prepared.deinit();
        self.arena_state.deinit();
        self.* = undefined;
    }
};

pub const SolveError =
    solver_rules.GenerateError ||
    solver_policy.PrepareError ||
    solver_search.SolveError ||
    error{
        InvalidModel,
        UnsupportedPolicy,
    };

/// Solve configured install-only policy with at most one limit-eviction retry.
///
/// The universe and architecture policy strings remain borrowed and must
/// outlive the returned result.
pub fn solveInstallonly(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    policy: solver_model.SolvePolicy,
) SolveError!OwnedSolve {
    if (policy.installonly_names.len == 0 or
        policy.skip_broken or
        !policy.keep_orphans)
    {
        return error.UnsupportedPolicy;
    }

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    var jobs = JobList.init(arena);
    for (goal.jobs) |job| {
        try jobs.append(try cloneJob(arena, job));
    }

    var installonly_names = StringList.init(arena);
    var active_names = StringList.init(arena);
    for (policy.installonly_names) |name| {
        if (nameInList(name, installonly_names.items)) continue;
        const owned_name = try arena.dupe(u8, name);
        try installonly_names.append(owned_name);
        if (!hasInstalledName(universe, owned_name)) continue;
        try active_names.append(owned_name);
        try jobs.append(.{
            .action = .multiversion,
            .selection = .{ .name = owned_name },
            .reason = .policy,
        });
    }

    var round = try runRound(
        allocator,
        universe,
        jobs.items,
        policy,
    );
    var round_owned = true;
    errdefer if (round_owned) round.deinit();

    if (round.weak_result.result == .unsatisfiable) {
        return .{
            .arena_state = arena_state,
            .prepared = round.prepared,
            .weak_result = round.weak_result,
            .jobs = jobs.items,
            .installonly_names = installonly_names.items,
            .eviction_packages = &.{},
            .rounds = 1,
        };
    }
    const first_model = round.weak_result.result.satisfiable;
    if (unexpectedInstallonlyRemoval(
        universe,
        active_names.items,
        goal,
        &.{},
        first_model,
    )) {
        return error.UnsupportedPolicy;
    }
    if (round.prepared.protectedRemoval(first_model)) |package_id| {
        return .{
            .arena_state = arena_state,
            .prepared = round.prepared,
            .weak_result = round.weak_result,
            .jobs = jobs.items,
            .installonly_names = installonly_names.items,
            .eviction_packages = &.{},
            .rounds = 1,
            .problem = .{ .protected_package = package_id },
        };
    }

    const first_limit = try planInstallonlyLimit(
        arena,
        universe,
        active_names.items,
        policy.installonly_limit,
        first_model,
    );
    if (!first_limit.needs_retry) {
        return .{
            .arena_state = arena_state,
            .prepared = round.prepared,
            .weak_result = round.weak_result,
            .jobs = jobs.items,
            .installonly_names = installonly_names.items,
            .eviction_packages = first_limit.evictions,
            .rounds = 1,
        };
    }

    round.deinit();
    round_owned = false;
    for (first_limit.evictions) |package_id| {
        try jobs.append(.{
            .action = .erase,
            .selection = .{ .package = package_id },
            .reason = .installonly_limit,
        });
    }

    round = try runRound(
        allocator,
        universe,
        jobs.items,
        policy,
    );
    round_owned = true;
    if (round.weak_result.result == .unsatisfiable) {
        return .{
            .arena_state = arena_state,
            .prepared = round.prepared,
            .weak_result = round.weak_result,
            .jobs = jobs.items,
            .installonly_names = installonly_names.items,
            .eviction_packages = first_limit.evictions,
            .rounds = 2,
        };
    }
    const final_model = round.weak_result.result.satisfiable;
    if (unexpectedInstallonlyRemoval(
        universe,
        active_names.items,
        goal,
        first_limit.evictions,
        final_model,
    )) {
        return error.UnsupportedPolicy;
    }
    if (protectedEviction(
        universe,
        policy.protected_names,
        first_limit.evictions,
        final_model,
    ) orelse round.prepared.protectedRemoval(final_model)) |package_id| {
        return .{
            .arena_state = arena_state,
            .prepared = round.prepared,
            .weak_result = round.weak_result,
            .jobs = jobs.items,
            .installonly_names = installonly_names.items,
            .eviction_packages = first_limit.evictions,
            .rounds = 2,
            .problem = .{ .protected_package = package_id },
        };
    }

    const final_limit = try planInstallonlyLimit(
        arena,
        universe,
        active_names.items,
        policy.installonly_limit,
        final_model,
    );
    return .{
        .arena_state = arena_state,
        .prepared = round.prepared,
        .weak_result = round.weak_result,
        .jobs = jobs.items,
        .installonly_names = installonly_names.items,
        .eviction_packages = first_limit.evictions,
        .rounds = 2,
        .problem = if (final_limit.overflow) |overflow|
            .{ .installonly_limit = overflow }
        else
            null,
    };
}

const Round = struct {
    prepared: solver_policy.Prepared,
    weak_result: solver_policy.WeakResult,

    fn deinit(self: *Round) void {
        self.weak_result.deinit();
        self.prepared.deinit();
        self.* = undefined;
    }
};

fn runRound(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    jobs: []const solver_model.Job,
    policy: solver_model.SolvePolicy,
) SolveError!Round {
    var base = try solver_rules.generateBase(
        allocator,
        universe,
        .{ .jobs = jobs },
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
            .installonly_policy = true,
        },
    );
    errdefer prepared.deinit();
    const weak_result = try prepared.solveWeak(
        allocator,
        .{ .enabled = policy.install_weak_deps },
    );
    return .{
        .prepared = prepared,
        .weak_result = weak_result,
    };
}

const LimitPlan = struct {
    evictions: []const solver_model.PackageId,
    needs_retry: bool,
    overflow: ?InstallonlyOverflow = null,
};

fn planInstallonlyLimit(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    names: []const []const u8,
    limit: u32,
    model: solver_search.Model,
) SolveError!LimitPlan {
    var evictions = PackageIdList.init(allocator);
    var planned = try allocator.alloc(bool, universe.packages.len);
    @memset(planned, false);
    var overflow: ?InstallonlyOverflow = null;
    var needs_retry = false;

    for (names) |name| {
        var selected_count: u64 = 0;
        for (universe.packages) |package| {
            if (std.mem.eql(u8, package.source.nevra.name, name) and
                (model.value(package.id) orelse return error.InvalidModel))
            {
                selected_count += 1;
            }
        }
        if (selected_count <= limit) continue;
        needs_retry = true;
        var excess = selected_count - limit;

        var candidates = PackageIdList.init(allocator);
        for (universe.packages) |package| {
            const package_index: usize = @intFromEnum(package.id);
            if (package.installed == null or
                planned[package_index] or
                !std.mem.eql(u8, package.source.nevra.name, name) or
                !(model.value(package.id) orelse return error.InvalidModel))
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
            planned[@intFromEnum(package_id)] = true;
            try evictions.append(package_id);
            excess -= 1;
        }
        if (overflow == null) {
            overflow = .{
                .name = name,
                .limit = limit,
                .final_count = @intCast(selected_count),
                .excess = @intCast(selected_count - limit),
            };
        }
    }
    return .{
        .evictions = try evictions.toOwnedSlice(),
        .needs_retry = needs_retry,
        .overflow = overflow,
    };
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

fn protectedEviction(
    universe: *const solver_model.Universe,
    protected_names: []const []const u8,
    evictions: []const solver_model.PackageId,
    model: solver_search.Model,
) ?solver_model.PackageId {
    for (evictions) |package_id| {
        if (model.value(package_id) orelse return package_id) continue;
        const package = universe.package(package_id) orelse return package_id;
        for (protected_names) |name| {
            if (std.mem.eql(u8, package.source.nevra.name, name)) {
                return package_id;
            }
        }
    }
    return null;
}

fn unexpectedInstallonlyRemoval(
    universe: *const solver_model.Universe,
    installonly_names: []const []const u8,
    goal: solver_model.Goal,
    allowed_evictions: []const solver_model.PackageId,
    model: solver_search.Model,
) bool {
    for (universe.packages) |package| {
        if (package.installed == null or
            !nameInList(package.source.nevra.name, installonly_names) or
            (model.value(package.id) orelse return true) or
            containsPackage(allowed_evictions, package.id) or
            explicitlyErased(goal, package))
        {
            continue;
        }
        return true;
    }
    return false;
}

fn explicitlyErased(
    goal: solver_model.Goal,
    package: solver_model.UniversePackage,
) bool {
    for (goal.jobs) |job| {
        if (job.action != .erase) continue;
        switch (job.selection) {
            .all => return true,
            .package => |package_id| {
                if (package_id == package.id) return true;
            },
            .name => |name| {
                if (std.mem.eql(u8, name, package.source.nevra.name)) {
                    return true;
                }
            },
            .capability => {},
        }
    }
    return false;
}

fn nameInList(name: []const u8, names: []const []const u8) bool {
    for (names) |candidate| {
        if (std.mem.eql(u8, name, candidate)) return true;
    }
    return false;
}

fn containsPackage(
    packages: []const solver_model.PackageId,
    wanted: solver_model.PackageId,
) bool {
    for (packages) |package_id| {
        if (package_id == wanted) return true;
    }
    return false;
}

fn cloneJob(
    allocator: std.mem.Allocator,
    job: solver_model.Job,
) error{OutOfMemory}!solver_model.Job {
    var cloned = job;
    cloned.selection = switch (job.selection) {
        .all => .all,
        .package => |package| .{ .package = package },
        .name => |name| .{ .name = try allocator.dupe(u8, name) },
        .capability => |relation| .{
            .capability = try cloneRelation(allocator, relation),
        },
    };
    return cloned;
}

fn cloneRelation(
    allocator: std.mem.Allocator,
    relation: metadata.Relation,
) error{OutOfMemory}!metadata.Relation {
    var cloned = relation;
    cloned.name = try allocator.dupe(u8, relation.name);
    cloned.flags = try cloneOptionalString(allocator, relation.flags);
    cloned.version = try cloneOptionalString(allocator, relation.version);
    cloned.release = try cloneOptionalString(allocator, relation.release);
    return cloned;
}

fn cloneOptionalString(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) error{OutOfMemory}!?[]const u8 {
    return if (value) |text| try allocator.dupe(u8, text) else null;
}

const TestPackage = struct {
    name: []const u8,
    version: []const u8,
    arch: []const u8 = "x86_64",
};

const TestRepo = struct {
    id: []const u8,
    kind: solver_model.RepositoryKind,
    packages: std.array_list.Managed(metadata.Package),
    installed_states: std.array_list.Managed(solver_model.InstalledState),
};

const TestGraphBuilder = struct {
    arena: std.mem.Allocator,
    repositories: std.array_list.Managed(TestRepo),

    fn init(arena: std.mem.Allocator) TestGraphBuilder {
        return .{
            .arena = arena,
            .repositories = std.array_list.Managed(TestRepo).init(arena),
        };
    }

    fn addRepository(
        self: *TestGraphBuilder,
        id: []const u8,
        kind: solver_model.RepositoryKind,
    ) !usize {
        const index = self.repositories.items.len;
        try self.repositories.append(.{
            .id = id,
            .kind = kind,
            .packages = std.array_list.Managed(metadata.Package).init(
                self.arena,
            ),
            .installed_states = std.array_list.Managed(
                solver_model.InstalledState,
            ).init(self.arena),
        });
        return index;
    }

    fn addPackage(
        self: *TestGraphBuilder,
        repository_index: usize,
        package: TestPackage,
    ) !solver_model.PackageId {
        var repository = &self.repositories.items[repository_index];
        const id: solver_model.PackageId = @enumFromInt(@as(
            u32,
            @intCast(totalPackages(self.repositories.items)),
        ));
        try repository.packages.append(.{
            .pkg_id = package.name,
            .nevra = .{
                .name = package.name,
                .version = package.version,
                .release = "1",
                .arch = package.arch,
            },
            .checksum = .{
                .kind = "sha256",
                .value = package.name,
                .is_pkgid = true,
            },
            .location = .{ .href = package.name },
        });
        if (repository.kind == .installed) {
            const order = repository.installed_states.items.len + 1;
            try repository.installed_states.append(.{
                .rpmdb_hnum = @intCast(order),
                .reason = .user,
                .install_order = order,
            });
        }
        return id;
    }

    fn finish(
        self: *TestGraphBuilder,
        arena_state: *std.heap.ArenaAllocator,
    ) !TestGraph {
        const models = try self.arena.alloc(
            metadata.RepositoryModel,
            self.repositories.items.len,
        );
        const inputs = try self.arena.alloc(
            solver_model.RepositoryInput,
            self.repositories.items.len,
        );
        for (self.repositories.items, 0..) |*repository, index| {
            models[index] = .{
                .packages = try repository.packages.toOwnedSlice(),
            };
            inputs[index] = .{
                .id = repository.id,
                .model = &models[index],
                .kind = repository.kind,
                .installed_states = if (repository.kind == .installed)
                    try repository.installed_states.toOwnedSlice()
                else
                    &.{},
            };
        }
        return .{
            .arena_state = arena_state,
            .universe = try solver_model.Universe.init(self.arena, inputs),
        };
    }
};

const TestGraph = struct {
    arena_state: *std.heap.ArenaAllocator,
    universe: solver_model.Universe,

    fn deinit(self: *TestGraph) void {
        self.universe.deinit();
        self.arena_state.deinit();
        self.* = undefined;
    }
};

fn totalPackages(repositories: []const TestRepo) usize {
    var count: usize = 0;
    for (repositories) |repository| count += repository.packages.items.len;
    return count;
}

fn testPolicy(limit: u32) solver_model.SolvePolicy {
    return .{
        .architecture = .{ .native_arch = "x86_64" },
        .installonly_limit = limit,
        .installonly_names = &.{"kernel"},
    };
}

test "first install does not activate install-only limit" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var builder = TestGraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepository("available", .available);
    _ = try builder.addPackage(available, .{
        .name = "kernel",
        .version = "1",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var solved = try solveInstallonly(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        testPolicy(0),
    );
    defer solved.deinit();

    try std.testing.expectEqual(@as(u2, 1), solved.rounds);
    try std.testing.expect(solved.problem == null);
    try std.testing.expectEqual(@as(usize, 1), solved.jobs.len);
    try std.testing.expectEqualSlices(
        bool,
        &.{true},
        solved.weak_result.result.satisfiable.values,
    );
}

test "install-only coordinator rejects unsupported policy boundaries" {
    var available_packages = [_]metadata.Package{.{
        .pkg_id = "kernel",
        .nevra = .{
            .name = "kernel",
            .version = "1",
            .release = "1",
            .arch = "x86_64",
        },
        .checksum = .{
            .kind = "sha256",
            .value = "kernel",
            .is_pkgid = true,
        },
        .location = .{ .href = "kernel" },
    }};
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{ .id = "available", .model = &available_model }},
    );
    defer universe.deinit();
    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .install,
        .selection = .{ .package = @enumFromInt(0) },
    }} };

    var unsupported = testPolicy(1);
    unsupported.skip_broken = true;
    try std.testing.expectError(
        error.UnsupportedPolicy,
        solveInstallonly(
            std.testing.allocator,
            &universe,
            goal,
            unsupported,
        ),
    );
    unsupported.skip_broken = false;
    unsupported.keep_orphans = false;
    try std.testing.expectError(
        error.UnsupportedPolicy,
        solveInstallonly(
            std.testing.allocator,
            &universe,
            goal,
            unsupported,
        ),
    );
    unsupported.keep_orphans = true;
    unsupported.installonly_names = &.{};
    try std.testing.expectError(
        error.UnsupportedPolicy,
        solveInstallonly(
            std.testing.allocator,
            &universe,
            goal,
            unsupported,
        ),
    );
}

test "install-only limit evicts install order across architectures" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepository("@System", .installed);
    const available = try builder.addRepository("available", .available);
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "9",
    });
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
        .arch = "i686",
    });
    _ = try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
        .arch = "noarch",
    });
    builder.repositories.items[installed]
        .installed_states.items[0].install_order = 10;
    builder.repositories.items[installed]
        .installed_states.items[1].install_order = 20;
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var solved = try solveInstallonly(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        testPolicy(2),
    );
    defer solved.deinit();

    try std.testing.expectEqual(@as(u2, 2), solved.rounds);
    try std.testing.expect(solved.problem == null);
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        solved.eviction_packages,
    );
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true },
        solved.weak_result.result.satisfiable.values,
    );
}

test "install-only update retains the new package after eviction retry" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepository("@System", .installed);
    const available = try builder.addRepository("available", .available);
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    _ = try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var solved = try solveInstallonly(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        testPolicy(1),
    );
    defer solved.deinit();

    try std.testing.expectEqual(@as(u2, 2), solved.rounds);
    try std.testing.expect(solved.problem == null);
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        solved.eviction_packages,
    );
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        solved.weak_result.result.satisfiable.values,
    );
}

test "install-only update without a replacement still enforces the limit" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepository("@System", .installed);
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    inline for ([_]solver_model.JobAction{ .update, .dist_sync }) |action| {
        var solved = try solveInstallonly(
            std.testing.allocator,
            &graph.universe,
            .{ .jobs = &.{.{
                .action = action,
                .selection = .all,
            }} },
            testPolicy(1),
        );
        defer solved.deinit();

        try std.testing.expectEqual(@as(u2, 2), solved.rounds);
        try std.testing.expect(solved.problem == null);
        try std.testing.expectEqualSlices(
            solver_model.PackageId,
            &.{@enumFromInt(0)},
            solved.eviction_packages,
        );
        try std.testing.expectEqualSlices(
            bool,
            &.{ false, true },
            solved.weak_result.result.satisfiable.values,
        );
    }
}

test "explicit erase is not selected again for install-only eviction" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepository("@System", .installed);
    const available = try builder.addRepository("available", .available);
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "2",
    });
    _ = try builder.addPackage(available, .{
        .name = "kernel",
        .version = "3",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var solved = try solveInstallonly(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{
                .action = .erase,
                .selection = .{ .package = @enumFromInt(0) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(2) },
            },
        } },
        testPolicy(1),
    );
    defer solved.deinit();

    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(1)},
        solved.eviction_packages,
    );
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, true },
        solved.weak_result.result.satisfiable.values,
    );
}

test "zero install-only limit reports residual overflow after one retry" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepository("@System", .installed);
    const available = try builder.addRepository("available", .available);
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    _ = try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var solved = try solveInstallonly(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        testPolicy(0),
    );
    defer solved.deinit();

    try std.testing.expectEqual(@as(u2, 2), solved.rounds);
    const overflow = switch (solved.problem orelse
        return error.TestUnexpectedResult) {
        .installonly_limit => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("kernel", overflow.name);
    try std.testing.expectEqual(@as(u32, 0), overflow.limit);
    try std.testing.expectEqual(@as(u32, 1), overflow.final_count);
    try std.testing.expectEqual(@as(u32, 1), overflow.excess);
}

test "protected package blocks an install-only eviction" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepository("@System", .installed);
    const available = try builder.addRepository("available", .available);
    _ = try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    _ = try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var policy = testPolicy(1);
    policy.protected_names = &.{"kernel"};
    var solved = try solveInstallonly(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        policy,
    );
    defer solved.deinit();

    try std.testing.expectEqual(@as(u2, 2), solved.rounds);
    const package_id = switch (solved.problem orelse
        return error.TestUnexpectedResult) {
        .protected_package => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(
        @as(solver_model.PackageId, @enumFromInt(0)),
        package_id,
    );
}

fn coordinatorAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var installed_packages = [_]metadata.Package{.{
        .pkg_id = "kernel-1",
        .nevra = .{
            .name = "kernel",
            .version = "1",
            .release = "1",
            .arch = "x86_64",
        },
        .checksum = .{
            .kind = "sha256",
            .value = "kernel-1",
            .is_pkgid = true,
        },
        .location = .{ .href = "kernel-1" },
    }};
    var available_packages = [_]metadata.Package{.{
        .pkg_id = "kernel-2",
        .nevra = .{
            .name = "kernel",
            .version = "2",
            .release = "1",
            .arch = "x86_64",
        },
        .checksum = .{
            .kind = "sha256",
            .value = "kernel-2",
            .is_pkgid = true,
        },
        .location = .{ .href = "kernel-2" },
    }};
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const installed_states = [_]solver_model.InstalledState{.{
        .rpmdb_hnum = 1,
        .reason = .user,
        .install_order = 1,
    }};
    var universe = try solver_model.Universe.init(
        allocator,
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
    var solved = try solveInstallonly(
        allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        testPolicy(1),
    );
    defer solved.deinit();
}

test "install-only coordinator cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        coordinatorAllocationFailureCase,
        .{},
    );
}
