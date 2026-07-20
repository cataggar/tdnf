const std = @import("std");
const metadata = @import("model.zig");
const coordinator = @import("solver_coordinator.zig");
const solver_model = @import("solver_model.zig");
const oracle = @import("solver_oracle.zig");
const solver_policy = @import("solver_policy.zig");
const solver_result = @import("solver_result.zig");
const solver_rules = @import("solver_rules.zig");

const testing = std.testing;
const golden_schema = "tdnf-libsolv-oracle-v1";
const checksum = "0000000000000000000000000000000000000000000000000000000000000000";

const PackageSpec = struct {
    name: []const u8,
    version: []const u8 = "1",
    release: []const u8 = "1",
    arch: []const u8 = "x86_64",
    vendor: ?[]const u8 = null,
    provides: []const metadata.Relation = &.{},
    requires: []const metadata.Relation = &.{},
    conflicts: []const metadata.Relation = &.{},
    obsoletes: []const metadata.Relation = &.{},
    recommends: []const metadata.Relation = &.{},
    suggests: []const metadata.Relation = &.{},
    supplements: []const metadata.Relation = &.{},
    enhances: []const metadata.Relation = &.{},
};

const RepoBuild = struct {
    id: []const u8,
    kind: solver_model.RepositoryKind,
    priority: i32,
    cost: u32,
    packages: std.array_list.Managed(metadata.Package),
    relations: std.array_list.Managed(metadata.Relation),
    installed_states: std.array_list.Managed(solver_model.InstalledState),
};

const GraphBuilder = struct {
    arena: std.mem.Allocator,
    repos: std.array_list.Managed(RepoBuild),

    fn init(arena: std.mem.Allocator) GraphBuilder {
        return .{
            .arena = arena,
            .repos = std.array_list.Managed(RepoBuild).init(arena),
        };
    }

    fn addRepo(
        self: *GraphBuilder,
        id: []const u8,
        kind: solver_model.RepositoryKind,
        priority: i32,
    ) !usize {
        const index = self.repos.items.len;
        try self.repos.append(.{
            .id = id,
            .kind = kind,
            .priority = priority,
            .cost = 1000,
            .packages = std.array_list.Managed(metadata.Package).init(self.arena),
            .relations = std.array_list.Managed(metadata.Relation).init(self.arena),
            .installed_states = std.array_list.Managed(solver_model.InstalledState).init(self.arena),
        });
        return index;
    }

    fn addPackage(self: *GraphBuilder, repo_index: usize, spec: PackageSpec) !void {
        var repo = &self.repos.items[repo_index];
        var package = metadata.Package{
            .pkg_id = spec.name,
            .nevra = .{
                .name = spec.name,
                .version = spec.version,
                .release = spec.release,
                .arch = spec.arch,
            },
            .checksum = .{
                .kind = "sha256",
                .value = checksum,
                .is_pkgid = true,
            },
            .location = .{ .href = spec.name },
            .rpm = .{ .vendor = spec.vendor },
        };

        inline for ([_]struct {
            kind: metadata.DependencyKind,
            relations: []const metadata.Relation,
        }{
            .{ .kind = .provides, .relations = spec.provides },
            .{ .kind = .requires, .relations = spec.requires },
            .{ .kind = .conflicts, .relations = spec.conflicts },
            .{ .kind = .obsoletes, .relations = spec.obsoletes },
            .{ .kind = .recommends, .relations = spec.recommends },
            .{ .kind = .suggests, .relations = spec.suggests },
            .{ .kind = .supplements, .relations = spec.supplements },
            .{ .kind = .enhances, .relations = spec.enhances },
        }) |entry| {
            package.rangePtr(entry.kind).* = .{
                .start = repo.relations.items.len,
                .len = entry.relations.len,
            };
            try repo.relations.appendSlice(entry.relations);
        }
        try repo.packages.append(package);
        if (repo.kind == .installed) {
            try repo.installed_states.append(.{
                .rpmdb_hnum = @intCast(repo.installed_states.items.len + 1),
                .reason = .user,
                .install_order = repo.installed_states.items.len + 1,
            });
        }
    }

    fn finish(
        self: *GraphBuilder,
        arena_state: *std.heap.ArenaAllocator,
    ) !OwnedGraph {
        const models = try self.arena.alloc(metadata.RepositoryModel, self.repos.items.len);
        const inputs = try self.arena.alloc(solver_model.RepositoryInput, self.repos.items.len);
        for (self.repos.items, 0..) |*repo, index| {
            models[index] = .{
                .packages = try repo.packages.toOwnedSlice(),
                .relations = try repo.relations.toOwnedSlice(),
            };
            inputs[index] = .{
                .id = repo.id,
                .model = &models[index],
                .kind = repo.kind,
                .priority = repo.priority,
                .cost = repo.cost,
                .installed_states = if (repo.kind == .installed)
                    try repo.installed_states.toOwnedSlice()
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

const OwnedGraph = struct {
    arena_state: *std.heap.ArenaAllocator,
    universe: solver_model.Universe,

    fn deinit(self: *OwnedGraph) void {
        self.universe.deinit();
        self.arena_state.deinit();
        self.* = undefined;
    }
};

fn policy() solver_model.SolvePolicy {
    return .{
        .architecture = .{
            .native_arch = "x86_64",
        },
    };
}

fn solveNative(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    solve_policy: solver_model.SolvePolicy,
) !solver_result.OwnedResult {
    var base = try solver_rules.generateBase(
        allocator,
        universe,
        goal,
        solve_policy.architecture,
    );
    defer base.deinit();
    var prepared = try solver_policy.prepareWithOptions(
        allocator,
        &base,
        .{
            .best = solve_policy.best,
            .allow_erasing = solve_policy.allow_erasing,
            .clean_deps = solve_policy.clean_deps,
            .protected_names = solve_policy.protected_names,
        },
    );
    defer prepared.deinit();

    if (solve_policy.skip_broken) {
        var skipped = try prepared.solveSkipBroken(allocator);
        defer skipped.deinit();
        return switch (skipped.result) {
            .satisfiable => |model| try solver_result.materialize(
                allocator,
                .{
                    .prepared = &prepared,
                    .model = model,
                    .skipped_jobs = skipped.skipped_jobs,
                },
            ),
            .unsatisfiable => error.TestUnexpectedResult,
        };
    }

    var weak = try prepared.solveWeak(
        allocator,
        .{ .enabled = solve_policy.install_weak_deps },
    );
    defer weak.deinit();
    return switch (weak.result) {
        .satisfiable => |model| try solver_result.materialize(
            allocator,
            .{
                .prepared = &prepared,
                .model = model,
                .accepted_weak = weak.accepted,
            },
        ),
        .unsatisfiable => error.TestUnexpectedResult,
    };
}

fn expectNativeMatchesOracle(
    native: *const solver_result.OwnedResult,
    observation: *const oracle.OwnedObservation,
) !void {
    try testing.expectEqualSlices(
        solver_model.PackageId,
        observation.selected,
        native.selected,
    );
    try testing.expectEqualSlices(
        solver_model.JobId,
        observation.outcome.skipped_jobs,
        native.outcome.skipped_jobs,
    );
    try testing.expectEqual(
        observation.outcome.actions.len,
        native.outcome.actions.len,
    );
    for (observation.outcome.actions, native.outcome.actions) |
        expected,
        actual,
    | {
        try testing.expectEqual(expected.package, actual.package);
        try testing.expectEqual(expected.kind, actual.kind);
        try testing.expectEqual(expected.reason, actual.reason);
        try testing.expectEqual(
            expected.requested_by,
            actual.requested_by,
        );
        try testing.expectEqualSlices(
            solver_model.PackageId,
            expected.priors,
            actual.priors,
        );
    }
}

fn materializeInstallonly(
    allocator: std.mem.Allocator,
    solved: *const coordinator.OwnedSolve,
) !solver_result.OwnedResult {
    if (solved.problem != null) return error.TestUnexpectedResult;
    return switch (solved.weak_result.result) {
        .satisfiable => |model| try solver_result.materialize(
            allocator,
            .{
                .prepared = &solved.prepared,
                .model = model,
                .accepted_weak = solved.weak_result.accepted,
                .eviction_packages = solved.eviction_packages,
            },
        ),
        .unsatisfiable => error.TestUnexpectedResult,
    };
}

fn relation(name: []const u8) metadata.Relation {
    return .{ .name = name };
}

fn versionedRelation(
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

fn containsSelectedName(
    graph: *const OwnedGraph,
    observation: *const oracle.OwnedObservation,
    name: []const u8,
) bool {
    for (observation.selected) |package_id| {
        const package = graph.universe.package(package_id) orelse continue;
        if (std.mem.eql(u8, package.source.nevra.name, name)) return true;
    }
    return false;
}

fn selectedPackageByName(
    graph: *const OwnedGraph,
    observation: *const oracle.OwnedObservation,
    name: []const u8,
) ?*const solver_model.UniversePackage {
    for (observation.selected) |package_id| {
        const package = graph.universe.package(package_id) orelse continue;
        if (std.mem.eql(u8, package.source.nevra.name, name)) return package;
    }
    return null;
}

fn actionForName(
    graph: *const OwnedGraph,
    observation: *const oracle.OwnedObservation,
    name: []const u8,
) ?solver_model.Action {
    for (observation.outcome.actions) |action| {
        const package = graph.universe.package(action.package) orelse continue;
        if (std.mem.eql(u8, package.source.nevra.name, name)) return action;
    }
    return null;
}

fn actionForPackage(
    observation: *const oracle.OwnedObservation,
    package_id: solver_model.PackageId,
) ?solver_model.Action {
    for (observation.outcome.actions) |action| {
        if (action.package == package_id) return action;
    }
    return null;
}

fn canonicalText(
    allocator: std.mem.Allocator,
    graph: *const OwnedGraph,
    observation: *const oracle.OwnedObservation,
) ![]const u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    try appendFmt(&out, allocator, "schema {s}\n", .{golden_schema});
    for (observation.effective_jobs) |job| {
        try appendFmt(
            &out,
            allocator,
            "job {any} {t} selection=",
            .{
                if (job.id) |value| @as(?u32, @intFromEnum(value)) else null,
                job.action,
            },
        );
        try appendSelection(&out, allocator, job.selection);
        try appendFmt(
            &out,
            allocator,
            " clean={any} best={any} targeted={any} not_by_user={any} weak={any}\n",
            .{
                job.flags.clean_deps,
                job.flags.force_best,
                job.flags.targeted,
                job.flags.not_by_user,
                job.flags.weak,
            },
        );
    }
    for (observation.effective_solver_flags) |flag| {
        try appendFmt(&out, allocator, "solver_flag {t}\n", .{flag});
    }
    for (observation.selected) |package_id| {
        const package = graph.universe.package(package_id).?;
        try appendFmt(
            &out,
            allocator,
            "selected {d} {s}-{s}-{s}.{s}\n",
            .{
                @intFromEnum(package_id),
                package.source.nevra.name,
                package.source.nevra.version,
                package.source.nevra.release,
                package.source.nevra.arch,
            },
        );
    }
    for (observation.outcome.actions) |action| {
        try appendFmt(
            &out,
            allocator,
            "action {d} {t} priors=[",
            .{
                @intFromEnum(action.package),
                action.kind,
            },
        );
        for (action.priors, 0..) |prior, index| {
            try appendFmt(
                &out,
                allocator,
                "{s}{d}",
                .{
                    if (index == 0) "" else ",",
                    @intFromEnum(prior),
                },
            );
        }
        try appendFmt(
            &out,
            allocator,
            "] reason={t} job={any}\n",
            .{
                action.reason,
                if (action.requested_by) |value|
                    @as(?u32, @intFromEnum(value))
                else
                    null,
            },
        );
    }
    for (observation.outcome.problems) |problem| {
        try appendFmt(
            &out,
            allocator,
            "problem {t} package={any} related={any} capability=",
            .{
                problem.kind,
                if (problem.package) |value| @as(?u32, @intFromEnum(value)) else null,
                if (problem.related_package) |value| @as(?u32, @intFromEnum(value)) else null,
            },
        );
        if (problem.capability) |capability| {
            try appendRelation(&out, allocator, capability);
        } else {
            try out.appendSlice("null");
        }
        try appendFmt(
            &out,
            allocator,
            " job={any} count={d}\n",
            .{
                if (problem.job) |value| @as(?u32, @intFromEnum(value)) else null,
                problem.count,
            },
        );
    }
    for (observation.outcome.skipped_jobs) |job_id| {
        try appendFmt(
            &out,
            allocator,
            "skipped_job {d}\n",
            .{@intFromEnum(job_id)},
        );
    }
    for (observation.order, 0..) |step, index| {
        try appendFmt(
            &out,
            allocator,
            "order {d} {t} {d}\n",
            .{ index, step.operation, @intFromEnum(step.package) },
        );
    }
    return out.toOwnedSlice();
}

fn appendSelection(
    out: *std.array_list.Managed(u8),
    allocator: std.mem.Allocator,
    selection: solver_model.Selection,
) !void {
    switch (selection) {
        .all => try out.appendSlice("all"),
        .package => |package| try appendFmt(
            out,
            allocator,
            "package:{d}",
            .{@intFromEnum(package)},
        ),
        .name => |name| try appendFmt(
            out,
            allocator,
            "name:{d}:{s}",
            .{ name.len, name },
        ),
        .capability => |capability| {
            try out.appendSlice("capability:");
            try appendRelation(out, allocator, capability);
        },
    }
}

fn appendRelation(
    out: *std.array_list.Managed(u8),
    allocator: std.mem.Allocator,
    relation_value: metadata.Relation,
) !void {
    try appendFmt(
        out,
        allocator,
        "name:{d}:{s},comparison:{t},epoch:{any},version:",
        .{
            relation_value.name.len,
            relation_value.name,
            relation_value.comparison,
            relation_value.epoch,
        },
    );
    try appendOptionalString(out, allocator, relation_value.version);
    try out.appendSlice(",release:");
    try appendOptionalString(out, allocator, relation_value.release);
    try out.appendSlice(",flags:");
    try appendOptionalString(out, allocator, relation_value.flags);
    try appendFmt(
        out,
        allocator,
        ",pre:{any},sense:{d}",
        .{ relation_value.pre, relation_value.sense },
    );
}

fn appendOptionalString(
    out: *std.array_list.Managed(u8),
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) !void {
    if (value) |text| {
        try appendFmt(out, allocator, "{d}:{s}", .{ text.len, text });
    } else {
        try out.appendSlice("null");
    }
}

fn appendFmt(
    out: *std.array_list.Managed(u8),
    allocator: std.mem.Allocator,
    comptime format: []const u8,
    args: anytype,
) !void {
    const text = try std.fmt.allocPrint(allocator, format, args);
    defer allocator.free(text);
    try out.appendSlice(text);
}

test "oracle rejects policies whose semantics are not implemented" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{ .name = "package" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var unsupported = policy();
    unsupported.skip_broken = true;
    try testing.expectError(
        error.UnsupportedPolicy,
        oracle.solve(
            testing.allocator,
            &graph.universe,
            .{ .jobs = &.{.{
                .action = .erase,
                .selection = .{ .package = @enumFromInt(0) },
            }} },
            unsupported,
        ),
    );

    unsupported.best = true;
    try testing.expectError(
        error.UnsupportedPolicy,
        oracle.solve(
            testing.allocator,
            &graph.universe,
            .{ .jobs = &.{.{
                .action = .install,
                .selection = .{ .package = @enumFromInt(0) },
            }} },
            unsupported,
        ),
    );

    unsupported.best = false;
    var too_many_jobs: [solver_model.max_skip_broken_jobs + 1]solver_model.Job = undefined;
    for (&too_many_jobs) |*job| {
        job.* = .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        };
    }
    try testing.expectError(
        error.UnsupportedPolicy,
        oracle.solve(
            testing.allocator,
            &graph.universe,
            .{ .jobs = &too_many_jobs },
            unsupported,
        ),
    );
}

test "skip broken keeps satisfiable exact install jobs" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{ .name = "good" });
    try builder.addPackage(available, .{
        .name = "broken",
        .requires = &.{relation("missing-capability")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var skip_policy = policy();
    skip_policy.skip_broken = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(0) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(1) },
            },
        } },
        skip_policy,
    );
    defer observation.deinit();

    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        observation.selected,
    );
    try testing.expectEqualSlices(
        solver_model.JobId,
        &.{@enumFromInt(1)},
        observation.outcome.skipped_jobs,
    );
    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
    const canonical = try canonicalText(
        testing.allocator,
        &graph,
        &observation,
    );
    defer testing.allocator.free(canonical);
    try testing.expect(std.mem.indexOf(
        u8,
        canonical,
        "skipped_job 1\n",
    ) != null);
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(0) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(1) },
            },
        } },
        skip_policy,
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "skip broken drops every exact install job in a package conflict" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "first",
        .conflicts = &.{relation("second")},
    });
    try builder.addPackage(available, .{ .name = "second" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var skip_policy = policy();
    skip_policy.skip_broken = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(0) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(1) },
            },
        } },
        skip_policy,
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 0), observation.selected.len);
    try testing.expectEqualSlices(
        solver_model.JobId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        observation.outcome.skipped_jobs,
    );
    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
}

test "skip broken resolves multiple independent package failures" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "broken-one",
        .requires = &.{relation("missing-one")},
    });
    try builder.addPackage(available, .{ .name = "good" });
    try builder.addPackage(available, .{
        .name = "broken-two",
        .requires = &.{relation("missing-two")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var skip_policy = policy();
    skip_policy.skip_broken = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
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
        } },
        skip_policy,
    );
    defer observation.deinit();

    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(1)},
        observation.selected,
    );
    try testing.expectEqualSlices(
        solver_model.JobId,
        &.{ @enumFromInt(0), @enumFromInt(2) },
        observation.outcome.skipped_jobs,
    );
    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
}

test "skip broken resolves independent conflicting job cores" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "first-a",
        .conflicts = &.{relation("second-a")},
    });
    try builder.addPackage(available, .{ .name = "second-a" });
    try builder.addPackage(available, .{
        .name = "first-b",
        .conflicts = &.{relation("second-b")},
    });
    try builder.addPackage(available, .{ .name = "second-b" });
    try builder.addPackage(available, .{ .name = "good" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var skip_policy = policy();
    skip_policy.skip_broken = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
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
        } },
        skip_policy,
    );
    defer observation.deinit();

    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(4)},
        observation.selected,
    );
    try testing.expectEqualSlices(
        solver_model.JobId,
        &.{
            @enumFromInt(0),
            @enumFromInt(1),
            @enumFromInt(2),
            @enumFromInt(3),
        },
        observation.outcome.skipped_jobs,
    );
    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
}

test "oracle rejects repository cost until tdnf implements it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    builder.repos.items[available].cost = 500;
    try builder.addPackage(available, .{ .name = "package" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    try testing.expectError(
        error.UnsupportedPolicy,
        oracle.solve(
            testing.allocator,
            &graph.universe,
            .{ .jobs = &.{} },
            policy(),
        ),
    );
}

test "effective jobs own exact selections including synthetic user-installed jobs" {
    var selection_name = "virtual-api".*;
    var selection_flags = "EQ".*;
    var selection_version = "2".*;
    var selection_release = "3".*;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "installed" });
    try builder.addPackage(available, .{
        .name = "provider",
        .provides = &.{.{
            .name = "virtual-api",
            .flags = "EQ",
            .comparison = .eq,
            .epoch = 1,
            .version = "2",
            .release = "3",
            .pre = true,
            .sense = 7,
        }},
    });
    builder.repos.items[installed].installed_states.items[0].reason = .unknown;
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var allow_erasing_policy = policy();
    allow_erasing_policy.allow_erasing = true;
    allow_erasing_policy.best = true;
    allow_erasing_policy.clean_deps = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .capability = .{
                .name = &selection_name,
                .flags = &selection_flags,
                .comparison = .eq,
                .epoch = 1,
                .version = &selection_version,
                .release = &selection_release,
                .pre = true,
                .sense = 7,
            } },
        }} },
        allow_erasing_policy,
    );
    defer observation.deinit();

    @memset(&selection_name, 'x');
    @memset(&selection_flags, 'x');
    @memset(&selection_version, 'x');
    @memset(&selection_release, 'x');

    try testing.expectEqual(@as(usize, 2), observation.effective_jobs.len);
    const capability = switch (observation.effective_jobs[0].selection) {
        .capability => |value| value,
        else => return error.TestExpectedEqual,
    };
    try testing.expectEqualStrings("virtual-api", capability.name);
    try testing.expectEqualStrings("EQ", capability.flags.?);
    try testing.expectEqual(metadata.CompareOp.eq, capability.comparison);
    try testing.expectEqual(@as(?u32, 1), capability.epoch);
    try testing.expectEqualStrings("2", capability.version.?);
    try testing.expectEqualStrings("3", capability.release.?);
    try testing.expect(capability.pre);
    try testing.expectEqual(@as(u32, 7), capability.sense);

    const synthetic = observation.effective_jobs[1];
    try testing.expect(synthetic.id == null);
    try testing.expectEqual(solver_model.JobAction.user_installed, synthetic.action);
    try testing.expect(synthetic.flags.force_best);
    try testing.expect(synthetic.flags.clean_deps);
    try testing.expectEqual(
        @as(u32, 0),
        @intFromEnum(switch (synthetic.selection) {
            .package => |package| package,
            else => return error.TestExpectedEqual,
        }),
    );

    const canonical = try canonicalText(testing.allocator, &graph, &observation);
    defer testing.allocator.free(canonical);
    try testing.expect(std.mem.indexOf(
        u8,
        canonical,
        "selection=capability:name:11:virtual-api,comparison:eq,epoch:1,version:1:2,release:1:3,flags:2:EQ,pre:true,sense:7",
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        canonical,
        "job null user_installed selection=package:0",
    ) != null);
}

test "clean deps removes only the automatic dependency closure of an exact erase" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    try builder.addPackage(installed, .{
        .name = "requested",
        .requires = &.{relation("dependency")},
        .recommends = &.{relation("recommended")},
    });
    try builder.addPackage(installed, .{
        .name = "dependency",
        .requires = &.{relation("transitive")},
    });
    try builder.addPackage(installed, .{ .name = "transitive" });
    try builder.addPackage(installed, .{ .name = "unrelated-orphan" });
    try builder.addPackage(installed, .{ .name = "recommended" });
    builder.repos.items[installed].installed_states.items[0].reason = .user;
    builder.repos.items[installed].installed_states.items[1].reason = .automatic;
    builder.repos.items[installed].installed_states.items[2].reason = .automatic;
    builder.repos.items[installed].installed_states.items[3].reason = .automatic;
    builder.repos.items[installed].installed_states.items[4].reason = .automatic;
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var cleanup_policy = policy();
    cleanup_policy.allow_erasing = true;
    cleanup_policy.clean_deps = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
            .flags = .{ .clean_deps = true },
        }} },
        cleanup_policy,
    );
    defer observation.deinit();

    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(3)},
        observation.selected,
    );
    const requested = actionForName(&graph, &observation, "requested").?;
    try testing.expectEqual(solver_model.TransactionReason.user, requested.reason);
    try testing.expectEqual(
        @as(?solver_model.JobId, @enumFromInt(0)),
        requested.requested_by,
    );
    const dependency = actionForName(&graph, &observation, "dependency").?;
    try testing.expectEqual(solver_model.TransactionReason.cleanup, dependency.reason);
    try testing.expectEqual(@as(?solver_model.JobId, null), dependency.requested_by);
    try testing.expectEqual(
        solver_model.TransactionReason.cleanup,
        actionForName(&graph, &observation, "transitive").?.reason,
    );
    try testing.expectEqual(
        solver_model.TransactionReason.cleanup,
        actionForName(&graph, &observation, "recommended").?.reason,
    );
    try testing.expect(actionForName(&graph, &observation, "unrelated-orphan") == null);
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
            .flags = .{ .clean_deps = true },
        }} },
        cleanup_policy,
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "clean deps adds back every installed provider needed by a survivor" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    try builder.addPackage(installed, .{
        .name = "requested",
        .requires = &.{relation("virtual")},
    });
    try builder.addPackage(installed, .{
        .name = "provider-one",
        .provides = &.{relation("virtual")},
    });
    try builder.addPackage(installed, .{
        .name = "provider-two",
        .provides = &.{relation("virtual")},
    });
    try builder.addPackage(installed, .{
        .name = "survivor",
        .requires = &.{relation("virtual")},
    });
    builder.repos.items[installed].installed_states.items[0].reason = .user;
    builder.repos.items[installed].installed_states.items[1].reason = .automatic;
    builder.repos.items[installed].installed_states.items[2].reason = .automatic;
    builder.repos.items[installed].installed_states.items[3].reason = .user;
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var cleanup_policy = policy();
    cleanup_policy.allow_erasing = true;
    cleanup_policy.clean_deps = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
            .flags = .{ .clean_deps = true },
        }} },
        cleanup_policy,
    );
    defer observation.deinit();

    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{
            @enumFromInt(1),
            @enumFromInt(2),
            @enumFromInt(3),
        },
        observation.selected,
    );
}

test "protected policy rejects unsupported boundaries" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "protected" });
    try builder.addPackage(installed, .{ .name = "protected" });
    try builder.addPackage(available, .{ .name = "request" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var protected_policy = policy();
    protected_policy.protected_names = &.{"protected"};
    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .install,
        .selection = .{ .package = @enumFromInt(2) },
    }} };
    try testing.expectError(
        error.UnsupportedPolicy,
        oracle.solve(
            testing.allocator,
            &graph.universe,
            goal,
            protected_policy,
        ),
    );

    protected_policy.protected_names = &.{"missing"};
    protected_policy.skip_broken = true;
    try testing.expectError(
        error.UnsupportedPolicy,
        oracle.solve(
            testing.allocator,
            &graph.universe,
            goal,
            protected_policy,
        ),
    );

    protected_policy.skip_broken = false;
    const clean_goal = solver_model.Goal{ .jobs = &.{.{
        .action = .erase,
        .selection = .{ .package = @enumFromInt(0) },
        .flags = .{ .clean_deps = true },
    }} };
    try testing.expectError(
        error.UnsupportedPolicy,
        oracle.solve(
            testing.allocator,
            &graph.universe,
            clean_goal,
            protected_policy,
        ),
    );
}

test "protected direct erase and obsoletion become protected problems" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "protected" });
    try builder.addPackage(available, .{
        .name = "obsoleter",
        .obsoletes = &.{relation("protected")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var protected_policy = policy();
    protected_policy.allow_erasing = true;
    protected_policy.protected_names = &.{"protected"};
    var erased = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        protected_policy,
    );
    defer erased.deinit();
    try testing.expectEqual(@as(usize, 1), erased.outcome.problems.len);
    try testing.expectEqual(
        solver_model.ProblemKind.protected_package,
        erased.outcome.problems[0].kind,
    );
    try testing.expectEqual(
        @as(?solver_model.PackageId, @enumFromInt(0)),
        erased.outcome.problems[0].package,
    );

    protected_policy.allow_erasing = false;
    var obsoleted = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        protected_policy,
    );
    defer obsoleted.deinit();
    try testing.expectEqual(@as(usize, 1), obsoleted.outcome.problems.len);
    try testing.expectEqual(
        solver_model.ProblemKind.protected_package,
        obsoleted.outcome.problems[0].kind,
    );
}

test "protected allow erasing releases only unprotected packages" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "protected" });
    try builder.addPackage(installed, .{ .name = "unprotected" });
    try builder.addPackage(available, .{
        .name = "allowed-request",
        .conflicts = &.{relation("unprotected")},
    });
    try builder.addPackage(available, .{
        .name = "blocked-request",
        .conflicts = &.{relation("protected")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var protected_policy = policy();
    protected_policy.allow_erasing = true;
    protected_policy.protected_names = &.{"protected"};
    var allowed = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        protected_policy,
    );
    defer allowed.deinit();
    try testing.expectEqual(@as(usize, 0), allowed.outcome.problems.len);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(2) },
        allowed.selected,
    );

    var blocked = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(3) },
        }} },
        protected_policy,
    );
    defer blocked.deinit();
    try testing.expect(blocked.outcome.problems.len != 0);
    try testing.expectEqual(@as(usize, 0), blocked.selected.len);
}

test "protected same-name replacement remains allowed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "protected",
        .version = "1",
    });
    try builder.addPackage(available, .{
        .name = "protected",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var protected_policy = policy();
    protected_policy.allow_erasing = true;
    protected_policy.protected_names = &.{"protected"};
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{
                .action = .erase,
                .selection = .{ .package = @enumFromInt(0) },
            },
            .{
                .action = .install,
                .selection = .{ .package = @enumFromInt(1) },
            },
        } },
        protected_policy,
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(1)},
        observation.selected,
    );
    try testing.expectEqual(
        solver_model.ActionKind.upgrade,
        actionForName(&graph, &observation, "protected").?.kind,
    );
}

test "protected automatic dependency is a clean-deps root" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    try builder.addPackage(installed, .{
        .name = "requested",
        .requires = &.{relation("protected")},
    });
    try builder.addPackage(installed, .{ .name = "protected" });
    builder.repos.items[installed].installed_states.items[0].reason = .user;
    builder.repos.items[installed].installed_states.items[1].reason = .automatic;
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var protected_policy = policy();
    protected_policy.allow_erasing = true;
    protected_policy.clean_deps = true;
    protected_policy.protected_names = &.{"protected"};
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
            .flags = .{ .clean_deps = true },
        }} },
        protected_policy,
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(1)},
        observation.selected,
    );
}

test "install-only first install is ordinary even with a zero limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "kernel",
        .version = "1",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var installonly_policy = policy();
    installonly_policy.installonly_names = &.{"kernel"};
    installonly_policy.installonly_limit = 0;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        installonly_policy,
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        observation.selected,
    );
    try testing.expectEqual(@as(usize, 1), observation.effective_jobs.len);
    var native = try coordinator.solveInstallonly(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        installonly_policy,
    );
    defer native.deinit();
    var materialized = try materializeInstallonly(
        testing.allocator,
        &native,
    );
    defer materialized.deinit();
    try expectNativeMatchesOracle(&materialized, &observation);

    installonly_policy.skip_broken = true;
    try testing.expectError(
        error.UnsupportedPolicy,
        oracle.solve(
            testing.allocator,
            &graph.universe,
            .{ .jobs = &.{.{
                .action = .install,
                .selection = .{ .package = @enumFromInt(0) },
            }} },
            installonly_policy,
        ),
    );
}

test "install-only install and update retain the installed instance" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var installonly_policy = policy();
    installonly_policy.installonly_names = &.{"kernel"};
    installonly_policy.installonly_limit = 3;
    var installed_observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        installonly_policy,
    );
    defer installed_observation.deinit();
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        installed_observation.selected,
    );
    try testing.expectEqual(@as(usize, 2), installed_observation.effective_jobs.len);
    const multiversion = installed_observation.effective_jobs[1];
    try testing.expectEqual(
        solver_model.JobAction.multiversion,
        multiversion.action,
    );
    try testing.expect(multiversion.id == null);
    switch (multiversion.selection) {
        .name => |name| try testing.expectEqualStrings("kernel", name),
        else => return error.TestUnexpectedResult,
    }

    var updated_observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        installonly_policy,
    );
    defer updated_observation.deinit();
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        updated_observation.selected,
    );
    var native = try coordinator.solveInstallonly(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        installonly_policy,
    );
    defer native.deinit();
    try testing.expectEqualSlices(
        bool,
        &.{ true, true },
        native.weak_result.result.satisfiable.values,
    );
    var materialized = try materializeInstallonly(
        testing.allocator,
        &native,
    );
    defer materialized.deinit();
    try expectNativeMatchesOracle(
        &materialized,
        &updated_observation,
    );
}

test "install-only exact replacement materializes as reinstall" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    try builder.addPackage(available, .{
        .name = "kernel",
        .version = "1",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .reinstall,
        .selection = .{ .package = @enumFromInt(1) },
    }} };
    var installonly_policy = policy();
    installonly_policy.installonly_names = &.{"kernel"};
    installonly_policy.installonly_limit = 2;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        installonly_policy,
    );
    defer observation.deinit();

    const effective_jobs = [_]solver_model.Job{
        goal.jobs[0],
        .{
            .action = .multiversion,
            .selection = .{ .name = "kernel" },
            .reason = .policy,
        },
    };
    var base = try solver_rules.generateBase(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &effective_jobs },
        installonly_policy.architecture,
    );
    defer base.deinit();
    var prepared = try solver_policy.prepareWithOptions(
        testing.allocator,
        &base,
        .{ .installonly_policy = true },
    );
    defer prepared.deinit();
    var weak = try prepared.solveWeak(
        testing.allocator,
        .{ .enabled = true },
    );
    defer weak.deinit();
    var native = switch (weak.result) {
        .satisfiable => |model| try solver_result.materialize(
            testing.allocator,
            .{
                .prepared = &prepared,
                .model = model,
                .accepted_weak = weak.accepted,
            },
        ),
        .unsatisfiable => return error.TestUnexpectedResult,
    };
    defer native.deinit();

    try expectNativeMatchesOracle(&native, &observation);
    const action = native.outcome.actions[0];
    try testing.expectEqual(solver_model.ActionKind.reinstall, action.kind);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        action.priors,
    );
}

test "install-only obsoletes materialize as install plus erase" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    try builder.addPackage(installed, .{ .name = "legacy-helper" });
    try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
        .obsoletes = &.{relation("legacy-helper")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .install,
        .selection = .{ .package = @enumFromInt(2) },
    }} };
    var installonly_policy = policy();
    installonly_policy.installonly_names = &.{"kernel"};
    installonly_policy.installonly_limit = 3;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        installonly_policy,
    );
    defer observation.deinit();
    var solved = try coordinator.solveInstallonly(
        testing.allocator,
        &graph.universe,
        goal,
        installonly_policy,
    );
    defer solved.deinit();
    var native = try materializeInstallonly(
        testing.allocator,
        &solved,
    );
    defer native.deinit();

    try expectNativeMatchesOracle(&native, &observation);
    try testing.expectEqual(
        solver_model.ActionKind.erase,
        actionForPackage(
            &observation,
            @enumFromInt(1),
        ).?.kind,
    );
    try testing.expectEqual(
        solver_model.ActionKind.install,
        actionForPackage(
            &observation,
            @enumFromInt(2),
        ).?.kind,
    );
}

test "install-only update without a replacement still enforces the limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var installonly_policy = policy();
    installonly_policy.installonly_names = &.{"kernel"};
    installonly_policy.installonly_limit = 1;
    inline for ([_]solver_model.JobAction{ .update, .dist_sync }) |action| {
        const goal = solver_model.Goal{ .jobs = &.{.{
            .action = action,
            .selection = .all,
        }} };
        var observation = try oracle.solve(
            testing.allocator,
            &graph.universe,
            goal,
            installonly_policy,
        );
        defer observation.deinit();
        try testing.expectEqualSlices(
            solver_model.PackageId,
            &.{@enumFromInt(1)},
            observation.selected,
        );
        const eviction = actionForPackage(
            &observation,
            @enumFromInt(0),
        ) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(
            solver_model.TransactionReason.installonly_limit,
            eviction.reason,
        );

        var native = try coordinator.solveInstallonly(
            testing.allocator,
            &graph.universe,
            goal,
            installonly_policy,
        );
        defer native.deinit();
        try testing.expectEqualSlices(
            bool,
            &.{ false, true },
            native.weak_result.result.satisfiable.values,
        );
    }
}

test "install-only limit evicts install order across architectures" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "9",
        .arch = "x86_64",
    });
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
        .arch = "i686",
    });
    try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
        .arch = "noarch",
    });
    builder.repos.items[installed].installed_states.items[0].install_order = 10;
    builder.repos.items[installed].installed_states.items[1].install_order = 20;
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var installonly_policy = policy();
    installonly_policy.installonly_names = &.{ "kernel", "kernel" };
    installonly_policy.installonly_limit = 2;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        installonly_policy,
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(1), @enumFromInt(2) },
        observation.selected,
    );
    const eviction = actionForPackage(
        &observation,
        @enumFromInt(0),
    ) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(solver_model.ActionKind.erase, eviction.kind);
    try testing.expectEqual(
        solver_model.TransactionReason.installonly_limit,
        eviction.reason,
    );
    try testing.expect(eviction.requested_by == null);
    var native = try coordinator.solveInstallonly(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        installonly_policy,
    );
    defer native.deinit();
    try testing.expectEqualSlices(
        bool,
        &.{ false, true, true },
        native.weak_result.result.satisfiable.values,
    );
    var materialized = try materializeInstallonly(
        testing.allocator,
        &native,
    );
    defer materialized.deinit();
    try expectNativeMatchesOracle(&materialized, &observation);

    installonly_policy.installonly_limit = 1;
    const explicit_goal = solver_model.Goal{ .jobs = &.{
        .{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        },
    } };
    var explicit = try oracle.solve(
        testing.allocator,
        &graph.universe,
        explicit_goal,
        installonly_policy,
    );
    defer explicit.deinit();
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(2)},
        explicit.selected,
    );
    const second_eviction = actionForPackage(
        &explicit,
        @enumFromInt(1),
    ) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(
        solver_model.TransactionReason.installonly_limit,
        second_eviction.reason,
    );
    var explicit_native = try coordinator.solveInstallonly(
        testing.allocator,
        &graph.universe,
        explicit_goal,
        installonly_policy,
    );
    defer explicit_native.deinit();
    try testing.expectEqualSlices(
        bool,
        &.{ false, false, true },
        explicit_native.weak_result.result.satisfiable.values,
    );
    var explicit_materialized = try materializeInstallonly(
        testing.allocator,
        &explicit_native,
    );
    defer explicit_materialized.deinit();
    try expectNativeMatchesOracle(
        &explicit_materialized,
        &explicit,
    );
}

test "install-only residual overflow becomes a limit problem after one retry" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var installonly_policy = policy();
    installonly_policy.installonly_names = &.{"kernel"};
    installonly_policy.installonly_limit = 0;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        installonly_policy,
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 1), observation.outcome.problems.len);
    const problem = observation.outcome.problems[0];
    try testing.expectEqual(
        solver_model.ProblemKind.installonly_limit,
        problem.kind,
    );
    try testing.expectEqual(@as(u32, 1), problem.count);
    try testing.expectEqualStrings("kernel", problem.capability.?.name);
    try testing.expectEqual(@as(usize, 0), observation.selected.len);
    try testing.expectEqual(@as(usize, 3), observation.effective_jobs.len);
    var native = try coordinator.solveInstallonly(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        installonly_policy,
    );
    defer native.deinit();
    const overflow = switch (native.problem orelse
        return error.TestUnexpectedResult) {
        .installonly_limit => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(problem.count, overflow.excess);
}

test "protected package takes precedence over install-only eviction" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "kernel",
        .version = "1",
    });
    try builder.addPackage(available, .{
        .name = "kernel",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var combined_policy = policy();
    combined_policy.installonly_names = &.{"kernel"};
    combined_policy.installonly_limit = 1;
    combined_policy.protected_names = &.{"kernel"};
    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .install,
        .selection = .{ .package = @enumFromInt(1) },
    }} };
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        combined_policy,
    );
    defer observation.deinit();
    try testing.expectEqual(@as(usize, 1), observation.outcome.problems.len);
    try testing.expectEqual(
        solver_model.ProblemKind.protected_package,
        observation.outcome.problems[0].kind,
    );

    var native = try coordinator.solveInstallonly(
        testing.allocator,
        &graph.universe,
        goal,
        combined_policy,
    );
    defer native.deinit();
    const package_id = switch (native.problem orelse
        return error.TestUnexpectedResult) {
        .protected_package => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(
        @as(solver_model.PackageId, @enumFromInt(0)),
        package_id,
    );
}

test "allow erasing replaces an installed conflict and preserves unrelated packages" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "conflicting" });
    try builder.addPackage(installed, .{ .name = "unrelated" });
    try builder.addPackage(available, .{
        .name = "requested",
        .conflicts = &.{relation("conflicting")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var allow_erasing = policy();
    allow_erasing.allow_erasing = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        allow_erasing,
    );
    defer observation.deinit();

    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "conflicting",
    ));
    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "unrelated",
    ));
    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "requested",
    ));
    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
    try testing.expectEqual(@as(usize, 0), observation.outcome.skipped_jobs.len);
}

test "allow erasing permits reverse dependency cascades" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    try builder.addPackage(installed, .{ .name = "dependency" });
    try builder.addPackage(installed, .{
        .name = "application",
        .requires = &.{relation("dependency")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var allow_erasing = policy();
    allow_erasing.allow_erasing = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .erase,
            .selection = .{ .package = @enumFromInt(0) },
        }} },
        allow_erasing,
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 0), observation.selected.len);
    try testing.expectEqual(@as(usize, 0), observation.outcome.problems.len);
    try testing.expectEqual(@as(usize, 0), observation.outcome.skipped_jobs.len);
}

test "downgrade and reinstall require exact package selections" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{ .name = "candidate" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    inline for ([_]solver_model.JobAction{ .downgrade, .reinstall }) |action| {
        try testing.expectError(
            error.UnsupportedPolicy,
            oracle.solve(
                testing.allocator,
                &graph.universe,
                .{ .jobs = &.{.{
                    .action = action,
                    .selection = .{ .name = "candidate" },
                }} },
                policy(),
            ),
        );
    }
}

test "versioned capability without EVR matches solvbridge encoding" {
    const capabilities = [_]metadata.Relation{
        .{
            .name = "versioned-without-evr",
            .flags = "EQ",
            .comparison = .eq,
        },
        .{
            .name = "empty-version",
            .flags = "EQ",
            .comparison = .eq,
            .version = "",
        },
        .{
            .name = "empty-release",
            .flags = "EQ",
            .comparison = .eq,
            .version = "1",
            .release = "",
        },
    };
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "provider",
        .provides = &capabilities,
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const jobs = [_]solver_model.Job{
        .{
            .action = .install,
            .selection = .{ .capability = capabilities[0] },
        },
        .{
            .action = .install,
            .selection = .{ .capability = capabilities[1] },
        },
        .{
            .action = .install,
            .selection = .{ .capability = capabilities[2] },
        },
    };
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &jobs },
        policy(),
    );
    defer observation.deinit();
    try testing.expect(containsSelectedName(&graph, &observation, "provider"));
}

test "oracle preserves RPM missing-release and unversioned-provider matching" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "self-provider",
        .version = "1",
        .release = "2",
    });
    try builder.addPackage(available, .{
        .name = "explicit-provider",
        .provides = &.{relation("virtual-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const jobs = [_]solver_model.Job{
        .{
            .action = .install,
            .selection = .{ .capability = versionedRelation(
                "self-provider",
                .eq,
                "1",
            ) },
        },
        .{
            .action = .install,
            .selection = .{ .capability = versionedRelation(
                "virtual-api",
                .eq,
                "999",
            ) },
        },
    };
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &jobs },
        policy(),
    );
    defer observation.deinit();
    try testing.expect(containsSelectedName(&graph, &observation, "self-provider"));
    try testing.expect(containsSelectedName(&graph, &observation, "explicit-provider"));

    var greater_observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .capability = versionedRelation(
                "self-provider",
                .gt,
                "1",
            ) },
        }} },
        policy(),
    );
    defer greater_observation.deinit();
    try testing.expect(!containsSelectedName(
        &graph,
        &greater_observation,
        "self-provider",
    ));
}

test "force-best preserves direct request provenance" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{ .name = "requested", .version = "1" });
    try builder.addPackage(available, .{ .name = "requested", .version = "2" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var best_policy = policy();
    best_policy.best = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "requested" },
        }} },
        best_policy,
    );
    defer observation.deinit();

    const action = actionForName(&graph, &observation, "requested").?;
    try testing.expectEqual(solver_model.TransactionReason.user, action.reason);
    try testing.expectEqual(@as(u32, 0), @intFromEnum(action.requested_by.?));
}

test "job problem flags never alias a related package" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    for (0..257) |index| {
        const name = try std.fmt.allocPrint(
            arena_state.allocator(),
            "filler-{d}",
            .{index},
        );
        try builder.addPackage(available, .{ .name = name });
    }
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "missing" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 1), observation.outcome.problems.len);
    try testing.expect(observation.outcome.problems[0].related_package == null);
}

test "oracle resolves dependency chain with versioned requirement" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{ .name = "base" });
    try builder.addPackage(available, .{
        .name = "library",
        .requires = &.{relation("base")},
    });
    try builder.addPackage(available, .{
        .name = "application",
        .requires = &.{versionedRelation("library", .ge, "1")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "application" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 3), observation.selected.len);
    try testing.expect(containsSelectedName(&graph, &observation, "base"));
    try testing.expect(containsSelectedName(&graph, &observation, "library"));
    try testing.expect(containsSelectedName(&graph, &observation, "application"));
    const golden = try canonicalText(testing.allocator, &graph, &observation);
    defer testing.allocator.free(golden);
    try testing.expectEqualStrings(
        \\schema tdnf-libsolv-oracle-v1
        \\job 0 install selection=name:11:application clean=false best=false targeted=false not_by_user=false weak=false
        \\solver_flag allow_downgrade
        \\solver_flag allow_vendor_change
        \\solver_flag best_obey_policy
        \\solver_flag install_also_updates
        \\solver_flag keep_orphans
        \\solver_flag yum_obsoletes
        \\selected 0 base-1-1.x86_64
        \\selected 1 library-1-1.x86_64
        \\selected 2 application-1-1.x86_64
        \\action 0 install priors=[] reason=dependency job=null
        \\action 1 install priors=[] reason=dependency job=null
        \\action 2 install priors=[] reason=user job=0
        \\order 0 install 0
        \\order 1 install 1
        \\order 2 install 2
        \\
    ,
        golden,
    );
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "application" },
        }} },
        policy(),
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "oracle deterministically chooses the best alternative provider" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "provider-low",
        .version = "99",
        .provides = &.{versionedRelation("virtual-api", .eq, "1")},
    });
    try builder.addPackage(available, .{
        .name = "provider-high",
        .version = "1",
        .provides = &.{versionedRelation("virtual-api", .eq, "2")},
    });
    try builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{versionedRelation("virtual-api", .ge, "1")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(&graph, &observation, "provider-high"));
    try testing.expect(!containsSelectedName(&graph, &observation, "provider-low"));
}

test "oracle common-provider ordering considers unrelated capabilities" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "first-provider",
        .provides = &.{
            relation("virtual-api"),
            versionedRelation("shared-abi", .eq, "1"),
        },
    });
    try builder.addPackage(available, .{
        .name = "second-provider",
        .provides = &.{
            relation("virtual-api"),
            versionedRelation("shared-abi", .eq, "2"),
        },
    });
    try builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{relation("virtual-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "second-provider",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "first-provider",
    ));
}

test "oracle common-provider ordering includes self provides" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "alpha-provider",
        .provides = &.{relation("virtual-api")},
    });
    try builder.addPackage(available, .{
        .name = "beta-provider",
        .provides = &.{
            relation("virtual-api"),
            versionedRelation("alpha-provider", .eq, "2"),
        },
    });
    try builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{relation("virtual-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "beta-provider",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "alpha-provider",
    ));
}

test "oracle moves providers with installed package names to front" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "sticky-provider",
        .version = "1",
    });
    try builder.addPackage(available, .{
        .name = "other-provider",
        .provides = &.{
            relation("virtual-api"),
            versionedRelation("shared-abi", .eq, "2"),
        },
    });
    try builder.addPackage(available, .{
        .name = "sticky-provider",
        .version = "2",
        .provides = &.{
            relation("virtual-api"),
            versionedRelation("shared-abi", .eq, "1"),
        },
    });
    try builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{relation("virtual-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(
        &graph,
        &observation,
        "sticky-provider",
    ).?;
    try testing.expectEqualStrings("2", selected.source.nevra.version);
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "other-provider",
    ));
}

test "oracle demotes old providers using packages outside the candidate queue" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "versioned-provider",
        .version = "1",
        .provides = &.{relation("virtual-api")},
    });
    try builder.addPackage(available, .{
        .name = "other-provider",
        .provides = &.{relation("virtual-api")},
    });
    try builder.addPackage(available, .{
        .name = "versioned-provider",
        .version = "2",
    });
    try builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{relation("virtual-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "other-provider",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "versioned-provider",
    ));
}

test "oracle installed-name movement ignores provide aliases" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "installed-anchor",
        .provides = &.{relation("aliased-provider")},
    });
    try builder.addPackage(available, .{
        .name = "other-provider",
        .provides = &.{
            relation("virtual-api"),
            versionedRelation("shared-abi", .eq, "2"),
        },
    });
    try builder.addPackage(available, .{
        .name = "aliased-provider",
        .provides = &.{
            relation("virtual-api"),
            versionedRelation("shared-abi", .eq, "1"),
        },
    });
    try builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{relation("virtual-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "other-provider",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "aliased-provider",
    ));
}

test "oracle ranks same-name providers by package EVR" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "provider",
        .version = "1",
        .provides = &.{versionedRelation("virtual-api", .eq, "100")},
    });
    try builder.addPackage(available, .{
        .name = "provider",
        .version = "2",
        .provides = &.{versionedRelation("virtual-api", .eq, "1")},
    });
    try builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{versionedRelation("virtual-api", .ge, "1")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(
        &graph,
        &observation,
        "provider",
    ).?;
    try testing.expectEqualStrings("2", selected.source.nevra.version);
}

test "oracle co-ranks noarch with the best machine architecture" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "provider",
        .version = "2",
        .arch = "noarch",
        .provides = &.{relation("virtual-api")},
    });
    try builder.addPackage(available, .{
        .name = "provider",
        .version = "1",
        .arch = "x86_64",
        .provides = &.{relation("virtual-api")},
    });
    try builder.addPackage(available, .{
        .name = "provider",
        .version = "99",
        .arch = "i686",
        .provides = &.{relation("virtual-api")},
    });
    try builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{relation("virtual-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(
        &graph,
        &observation,
        "provider",
    ).?;
    try testing.expectEqualStrings("noarch", selected.source.nevra.arch);
    try testing.expectEqualStrings("2", selected.source.nevra.version);
}

test "oracle applies tdnf repository priority semantics" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const lower_priority_value = try builder.addRepo("preferred", .available, 10);
    const higher_priority_value = try builder.addRepo("fallback", .available, 90);
    try builder.addPackage(lower_priority_value, .{ .name = "choice" });
    try builder.addPackage(higher_priority_value, .{ .name = "choice" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "choice" },
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(&graph, &observation, "choice").?;
    try testing.expectEqualStrings(
        "preferred",
        graph.universe.repository(selected.repository).?.name,
    );
}

test "oracle preserves command-line repository priority" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 10);
    const command_line = try builder.addRepo("command-line", .command_line, 50);
    try builder.addPackage(available, .{ .name = "choice" });
    try builder.addPackage(command_line, .{ .name = "choice" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "choice" },
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(&graph, &observation, "choice").?;
    try testing.expectEqualStrings(
        "command-line",
        graph.universe.repository(selected.repository).?.name,
    );
}

test "oracle records upgrade prior and newly required dependency" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "application", .version = "1" });
    try builder.addPackage(available, .{ .name = "helper" });
    try builder.addPackage(available, .{
        .name = "application",
        .version = "2",
        .requires = &.{relation("helper")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(&graph, &observation, "helper"));
    const action = actionForName(&graph, &observation, "application").?;
    try testing.expectEqual(solver_model.ActionKind.upgrade, action.kind);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        action.priors,
    );
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        policy(),
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "oracle exact replacement actions follow EVR rather than request label" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "package", .version = "2" });
    try builder.addPackage(available, .{ .name = "package", .version = "1" });
    try builder.addPackage(available, .{ .name = "package", .version = "2" });
    try builder.addPackage(available, .{ .name = "package", .version = "3" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var downgrade = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .downgrade,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        policy(),
    );
    defer downgrade.deinit();
    try testing.expectEqual(
        solver_model.ActionKind.downgrade,
        actionForName(&graph, &downgrade, "package").?.kind,
    );
    var native_downgrade = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .downgrade,
            .selection = .{ .package = @enumFromInt(1) },
        }} },
        policy(),
    );
    defer native_downgrade.deinit();
    try expectNativeMatchesOracle(&native_downgrade, &downgrade);

    var reinstall = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .reinstall,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        policy(),
    );
    defer reinstall.deinit();
    try testing.expectEqual(
        solver_model.ActionKind.reinstall,
        actionForName(&graph, &reinstall, "package").?.kind,
    );
    var native_reinstall = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .reinstall,
            .selection = .{ .package = @enumFromInt(2) },
        }} },
        policy(),
    );
    defer native_reinstall.deinit();
    try expectNativeMatchesOracle(&native_reinstall, &reinstall);

    var mislabeled = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .downgrade,
            .selection = .{ .package = @enumFromInt(3) },
        }} },
        policy(),
    );
    defer mislabeled.deinit();
    try testing.expectEqual(
        solver_model.ActionKind.upgrade,
        actionForName(&graph, &mislabeled, "package").?.kind,
    );
    var native_mislabeled = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .downgrade,
            .selection = .{ .package = @enumFromInt(3) },
        }} },
        policy(),
    );
    defer native_mislabeled.deinit();
    try expectNativeMatchesOracle(&native_mislabeled, &mislabeled);
}

test "native and oracle retain every exact installed upgrade prior" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "duplicate",
        .version = "1",
    });
    try builder.addPackage(installed, .{
        .name = "duplicate",
        .version = "1",
    });
    try builder.addPackage(available, .{
        .name = "duplicate",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .update,
        .selection = .all,
    }} };
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer observation.deinit();

    const action = actionForPackage(
        &observation,
        @enumFromInt(2),
    ) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(solver_model.ActionKind.upgrade, action.kind);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        action.priors,
    );
    try testing.expectEqual(
        @as(u32, 1),
        graph.universe.package(action.priors[0]).?.installed.?.rpmdb_hnum,
    );
    try testing.expectEqual(
        @as(u32, 2),
        graph.universe.package(action.priors[1]).?.installed.?.rpmdb_hnum,
    );
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "replacement kind follows the highest same-name installed prior" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "duplicate",
        .version = "1",
    });
    try builder.addPackage(installed, .{
        .name = "duplicate",
        .version = "3",
    });
    try builder.addPackage(available, .{
        .name = "duplicate",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .dist_sync,
        .selection = .all,
    }} };
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer observation.deinit();

    const action = actionForPackage(
        &observation,
        @enumFromInt(2),
    ) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(solver_model.ActionKind.downgrade, action.kind);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        action.priors,
    );
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "same-name replacement kind takes precedence over extra obsoletes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "application",
        .version = "1",
    });
    try builder.addPackage(installed, .{ .name = "legacy-helper" });
    try builder.addPackage(available, .{
        .name = "application",
        .version = "2",
        .obsoletes = &.{relation("legacy-helper")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .install,
        .selection = .{ .package = @enumFromInt(2) },
    }} };
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer observation.deinit();

    const action = actionForPackage(
        &observation,
        @enumFromInt(2),
    ) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(solver_model.ActionKind.upgrade, action.kind);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{ @enumFromInt(0), @enumFromInt(1) },
        action.priors,
    );
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);

    var protected_policy = policy();
    protected_policy.protected_names = &.{"legacy-helper"};
    var protected = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        protected_policy,
    );
    defer protected.deinit();
    try testing.expectEqual(@as(usize, 1), protected.outcome.problems.len);
    try testing.expectEqual(
        solver_model.ProblemKind.protected_package,
        protected.outcome.problems[0].kind,
    );
    try testing.expectEqual(
        @as(?solver_model.PackageId, @enumFromInt(1)),
        protected.outcome.problems[0].package,
    );
}

test "oracle distro sync downgrades to preferred repo and keeps orphans" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const preferred = try builder.addRepo("preferred", .available, 10);
    const fallback = try builder.addRepo("fallback", .available, 90);
    try builder.addPackage(installed, .{ .name = "package", .version = "3" });
    try builder.addPackage(installed, .{ .name = "orphan" });
    try builder.addPackage(preferred, .{ .name = "package", .version = "1" });
    try builder.addPackage(fallback, .{ .name = "package", .version = "4" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(
        &graph,
        &observation,
        "package",
    ).?;
    try testing.expectEqualStrings("1", selected.source.nevra.version);
    try testing.expect(containsSelectedName(&graph, &observation, "orphan"));
    try testing.expectEqual(
        solver_model.ActionKind.downgrade,
        actionForName(&graph, &observation, "package").?.kind,
    );
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        policy(),
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "oracle force best prevents distro sync version fallback" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "package", .version = "3" });
    try builder.addPackage(available, .{
        .name = "package",
        .version = "2",
        .requires = &.{relation("missing-capability")},
    });
    try builder.addPackage(available, .{
        .name = "package",
        .version = "1",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var fallback = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        policy(),
    );
    defer fallback.deinit();
    try testing.expectEqualStrings(
        "1",
        selectedPackageByName(
            &graph,
            &fallback,
            "package",
        ).?.source.nevra.version,
    );

    var best_policy = policy();
    best_policy.best = true;
    var best = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        best_policy,
    );
    defer best.deinit();
    try testing.expect(best.outcome.problems.len != 0);
}

test "oracle distro sync retains preferred fallback obsoleters" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const preferred = try builder.addRepo("preferred", .available, 10);
    const fallback = try builder.addRepo("fallback", .available, 90);
    try builder.addPackage(installed, .{ .name = "old-package" });
    try builder.addPackage(preferred, .{
        .name = "replacement",
        .obsoletes = &.{relation("old-package")},
    });
    try builder.addPackage(fallback, .{
        .name = "old-package",
        .version = "2",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "replacement",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "old-package",
    ));
}

test "oracle distro sync replaces equal EVR packages with changed vendor" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "package",
        .vendor = "old-vendor",
    });
    try builder.addPackage(available, .{
        .name = "package",
        .vendor = "new-vendor",
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(
        &graph,
        &observation,
        "package",
    ).?;
    try testing.expectEqualStrings(
        "new-vendor",
        selected.source.rpm.vendor.?,
    );
    try testing.expectEqual(
        solver_model.ActionKind.reinstall,
        actionForName(&graph, &observation, "package").?.kind,
    );
}

test "oracle distro sync preserves product identity exceptions" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "product:package",
        .vendor = "old-vendor",
    });
    try builder.addPackage(available, .{
        .name = "product:package",
        .vendor = "new-vendor",
    });
    try builder.addPackage(available, .{ .name = "requested" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{
                .action = .dist_sync,
                .selection = .all,
            },
            .{
                .action = .install,
                .selection = .{ .name = "requested" },
            },
        } },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(
        &graph,
        &observation,
        "product:package",
    ).?;
    try testing.expectEqualStrings(
        "old-vendor",
        selected.source.rpm.vendor.?,
    );
}

test "oracle distro sync identity includes prerequisite markers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "package",
        .requires = &.{.{
            .name = "rpmlib(Test)",
            .flags = "EQ",
            .comparison = .eq,
            .version = "1",
        }},
    });
    try builder.addPackage(available, .{
        .name = "package",
        .requires = &.{.{
            .name = "rpmlib(Test)",
            .flags = "EQ",
            .comparison = .eq,
            .version = "1",
            .pre = true,
        }},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(
        &graph,
        &observation,
        "package",
    ).?;
    try testing.expect(selected.relationEntries(
        &graph.universe,
        .requires,
    )[0].pre);
}

test "oracle update preserves architecture color and distro sync changes it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "package",
        .version = "1",
        .arch = "x86_64",
    });
    try builder.addPackage(available, .{
        .name = "package",
        .version = "2",
        .arch = "i686",
    });
    try builder.addPackage(available, .{ .name = "requested" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var update = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{
                .action = .update,
                .selection = .all,
            },
            .{
                .action = .install,
                .selection = .{ .name = "requested" },
            },
        } },
        policy(),
    );
    defer update.deinit();
    try testing.expectEqualStrings(
        "x86_64",
        selectedPackageByName(
            &graph,
            &update,
            "package",
        ).?.source.nevra.arch,
    );

    var sync = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .dist_sync,
            .selection = .all,
        }} },
        policy(),
    );
    defer sync.deinit();
    try testing.expectEqualStrings(
        "i686",
        selectedPackageByName(
            &graph,
            &sync,
            "package",
        ).?.source.nevra.arch,
    );
}

test "oracle update accepts renamed provide and obsolete replacement" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "old-package" });
    try builder.addPackage(available, .{
        .name = "replacement",
        .provides = &.{relation("old-package")},
        .obsoletes = &.{relation("old-package")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "replacement",
    ));
    try testing.expectEqual(
        solver_model.ActionKind.obsolete,
        actionForName(&graph, &observation, "replacement").?.kind,
    );
}

test "oracle force best removes explicitly obsoleted installed candidates" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "old-package",
        .version = "2",
    });
    try builder.addPackage(available, .{
        .name = "old-package",
        .version = "1",
        .requires = &.{relation("missing-capability")},
    });
    try builder.addPackage(available, .{
        .name = "renamed-package",
        .provides = &.{relation("old-package")},
        .obsoletes = &.{versionedRelation(
            "old-package",
            .eq,
            "2",
        )},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var best_policy = policy();
    best_policy.best = true;
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .update,
            .selection = .all,
        }} },
        best_policy,
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "renamed-package",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "old-package",
    ));
}

test "oracle records replacement as an obsolete action" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "old-package" });
    try builder.addPackage(available, .{
        .name = "replacement",
        .obsoletes = &.{relation("old-package")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "replacement" },
        }} },
        policy(),
    );
    defer observation.deinit();

    const action = actionForName(&graph, &observation, "replacement").?;
    try testing.expectEqual(solver_model.ActionKind.obsolete, action.kind);
    try testing.expectEqualSlices(
        solver_model.PackageId,
        &.{@enumFromInt(0)},
        action.priors,
    );
    try testing.expectEqual(solver_model.TransactionReason.obsoletes, action.reason);
    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "replacement" },
        }} },
        policy(),
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "each selected obsoleter retains a shared installed prior" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{ .name = "old-package" });
    try builder.addPackage(available, .{
        .name = "replacement-one",
        .obsoletes = &.{relation("old-package")},
    });
    try builder.addPackage(available, .{
        .name = "replacement-two",
        .obsoletes = &.{relation("old-package")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const goal = solver_model.Goal{ .jobs = &.{
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(1) },
        },
        .{
            .action = .install,
            .selection = .{ .package = @enumFromInt(2) },
        },
    } };
    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer observation.deinit();
    for (observation.outcome.actions) |action| {
        try testing.expectEqual(
            solver_model.ActionKind.obsolete,
            action.kind,
        );
        try testing.expectEqualSlices(
            solver_model.PackageId,
            &.{@enumFromInt(0)},
            action.priors,
        );
    }

    var native = try solveNative(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer native.deinit();
    try expectNativeMatchesOracle(&native, &observation);
}

test "oracle normalizes missing requirements without English diagnostics" {
    var missing_capability = "missing-capability".*;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "unrelated",
        .conflicts = &.{.{
            .name = "missing-capability",
            .pre = false,
            .sense = 99,
        }},
    });
    try builder.addPackage(available, .{
        .name = "broken",
        .requires = &.{.{
            .name = &missing_capability,
            .pre = true,
            .sense = 7,
        }},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "broken" },
        }} },
        policy(),
    );
    defer observation.deinit();
    @memset(&missing_capability, 'x');

    try testing.expectEqual(@as(usize, 1), observation.outcome.problems.len);
    try testing.expectEqual(
        solver_model.ProblemKind.unsatisfied_requirement,
        observation.outcome.problems[0].kind,
    );
    try testing.expectEqualStrings(
        "missing-capability",
        observation.outcome.problems[0].capability.?.name,
    );
    try testing.expect(observation.outcome.problems[0].capability.?.pre);
    try testing.expectEqual(
        @as(u32, 7),
        observation.outcome.problems[0].capability.?.sense,
    );
    const canonical = try canonicalText(testing.allocator, &graph, &observation);
    defer testing.allocator.free(canonical);
    try testing.expect(std.mem.indexOf(
        u8,
        canonical,
        "capability=name:18:missing-capability,comparison:none,epoch:null,version:null,release:null,flags:null,pre:true,sense:7",
    ) != null);
}

test "oracle normalizes conflicts" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "first",
        .conflicts = &.{relation("second")},
    });
    try builder.addPackage(available, .{ .name = "second" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{ .action = .install, .selection = .{ .name = "first" } },
            .{ .action = .install, .selection = .{ .name = "second" } },
        } },
        policy(),
    );
    defer observation.deinit();

    try testing.expectEqual(@as(usize, 1), observation.outcome.problems.len);
    try testing.expectEqual(
        solver_model.ProblemKind.conflict,
        observation.outcome.problems[0].kind,
    );
}

test "oracle weak dependency policy is observable" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{ .name = "addon" });
    try builder.addPackage(available, .{
        .name = "application",
        .recommends = &.{relation("addon")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    const goal = solver_model.Goal{ .jobs = &.{.{
        .action = .install,
        .selection = .{ .name = "application" },
    }} };
    var with_weak = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer with_weak.deinit();
    try testing.expect(containsSelectedName(&graph, &with_weak, "addon"));
    var native_with_weak = try solveNative(
        testing.allocator,
        &graph.universe,
        goal,
        policy(),
    );
    defer native_with_weak.deinit();
    try expectNativeMatchesOracle(&native_with_weak, &with_weak);

    var without_weak_policy = policy();
    without_weak_policy.install_weak_deps = false;
    var without_weak = try oracle.solve(
        testing.allocator,
        &graph.universe,
        goal,
        without_weak_policy,
    );
    defer without_weak.deinit();
    try testing.expect(!containsSelectedName(&graph, &without_weak, "addon"));
    var native_without_weak = try solveNative(
        testing.allocator,
        &graph.universe,
        goal,
        without_weak_policy,
    );
    defer native_without_weak.deinit();
    try expectNativeMatchesOracle(&native_without_weak, &without_weak);
}

test "oracle weak pruning prefers the best machine architecture" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "addon",
        .version = "99",
        .arch = "i686",
    });
    try builder.addPackage(available, .{
        .name = "addon",
        .version = "1",
        .arch = "x86_64",
    });
    try builder.addPackage(available, .{
        .name = "application",
        .recommends = &.{relation("addon")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "application" },
        }} },
        policy(),
    );
    defer observation.deinit();

    const selected = selectedPackageByName(&graph, &observation, "addon").?;
    try testing.expectEqualStrings("x86_64", selected.source.nevra.arch);
}

test "oracle weak pruning removes one-way obsoleted providers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "old-addon",
        .provides = &.{relation("addon-api")},
    });
    try builder.addPackage(available, .{
        .name = "replacement-addon",
        .provides = &.{relation("addon-api")},
        .obsoletes = &.{relation("old-addon")},
    });
    try builder.addPackage(available, .{
        .name = "application",
        .recommends = &.{relation("addon-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "application" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "replacement-addon",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "old-addon",
    ));
}

test "oracle weak pruning preserves mutual obsoletes cycles" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "first-addon",
        .provides = &.{relation("addon-api")},
        .obsoletes = &.{relation("second-addon")},
    });
    try builder.addPackage(available, .{
        .name = "second-addon",
        .provides = &.{relation("addon-api")},
        .obsoletes = &.{relation("first-addon")},
    });
    try builder.addPackage(available, .{
        .name = "application",
        .recommends = &.{relation("addon-api")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "application" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(
        containsSelectedName(&graph, &observation, "first-addon") or
            containsSelectedName(&graph, &observation, "second-addon"),
    );
}

test "oracle installs supplements for newly selected conditions" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "addon",
        .supplements = &.{relation("application")},
    });
    try builder.addPackage(available, .{ .name = "application" });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "application" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(&graph, &observation, "addon"));
    try testing.expectEqual(
        solver_model.TransactionReason.weak_dependency,
        actionForName(&graph, &observation, "addon").?.reason,
    );
}

test "oracle suggestions order conflicting active supplements" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "first-addon",
        .conflicts = &.{relation("preferred-addon")},
        .supplements = &.{relation("application")},
    });
    try builder.addPackage(available, .{
        .name = "preferred-addon",
        .supplements = &.{relation("application")},
    });
    try builder.addPackage(available, .{
        .name = "application",
        .suggests = &.{relation("preferred-addon")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "application" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(containsSelectedName(
        &graph,
        &observation,
        "preferred-addon",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "first-addon",
    ));
}

test "oracle suppresses old installed weak dependencies by default" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const installed = try builder.addRepo("@System", .installed, 50);
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(installed, .{
        .name = "application",
        .recommends = &.{relation("recommended-addon")},
    });
    try builder.addPackage(available, .{ .name = "requested" });
    try builder.addPackage(available, .{ .name = "recommended-addon" });
    try builder.addPackage(available, .{
        .name = "supplement-addon",
        .supplements = &.{relation("application")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "requested" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "recommended-addon",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "supplement-addon",
    ));
}

test "oracle suggestions and enhances do not directly install packages" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{ .name = "suggested-addon" });
    try builder.addPackage(available, .{
        .name = "enhanced-addon",
        .enhances = &.{relation("application")},
    });
    try builder.addPackage(available, .{
        .name = "application",
        .suggests = &.{relation("suggested-addon")},
    });
    var graph = try builder.finish(&arena_state);
    defer graph.deinit();

    var observation = try oracle.solve(
        testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "application" },
        }} },
        policy(),
    );
    defer observation.deinit();

    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "suggested-addon",
    ));
    try testing.expect(!containsSelectedName(
        &graph,
        &observation,
        "enhanced-addon",
    ));
}

const SplitMix64 = struct {
    state: u64,

    fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e3779b97f4a7c15;
        var value = self.state;
        value = (value ^ (value >> 30)) *% 0xbf58476d1ce4e5b9;
        value = (value ^ (value >> 27)) *% 0x94d049bb133111eb;
        return value ^ (value >> 31);
    }
};

test "generated acyclic graphs are deterministic against the canonical observation" {
    const seeds = [_]u64{
        0x13600001,
        0x13600002,
        0x13600003,
        0x13600004,
        0x13600005,
        0x13600006,
        0x13600007,
        0x13600008,
    };
    for (seeds) |seed| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        var builder = GraphBuilder.init(arena_state.allocator());
        const available = try builder.addRepo("generated", .available, 50);
        var random = SplitMix64{ .state = seed };
        const package_count: usize = 6 + @as(usize, @intCast(random.next() % 5));
        for (0..package_count) |index| {
            const name = try std.fmt.allocPrint(
                arena_state.allocator(),
                "node-{d}",
                .{index},
            );
            if (index == 0) {
                try builder.addPackage(available, .{ .name = name });
            } else {
                const dependency_index = @as(usize, @intCast(random.next() % index));
                const dependency = try std.fmt.allocPrint(
                    arena_state.allocator(),
                    "node-{d}",
                    .{dependency_index},
                );
                try builder.addPackage(available, .{
                    .name = name,
                    .requires = try arena_state.allocator().dupe(
                        metadata.Relation,
                        &.{relation(dependency)},
                    ),
                });
            }
        }
        var graph = try builder.finish(&arena_state);
        defer graph.deinit();

        const root_name = try std.fmt.allocPrint(
            graph.arena_state.allocator(),
            "node-{d}",
            .{package_count - 1},
        );
        const goal = solver_model.Goal{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = root_name },
        }} };
        var first = try oracle.solve(testing.allocator, &graph.universe, goal, policy());
        defer first.deinit();
        var second = try oracle.solve(testing.allocator, &graph.universe, goal, policy());
        defer second.deinit();

        const first_text = try canonicalText(testing.allocator, &graph, &first);
        defer testing.allocator.free(first_text);
        const second_text = try canonicalText(testing.allocator, &graph, &second);
        defer testing.allocator.free(second_text);
        try testing.expectEqualStrings(first_text, second_text);
        try testing.expect(std.mem.startsWith(u8, first_text, "schema " ++ golden_schema));
    }
}
