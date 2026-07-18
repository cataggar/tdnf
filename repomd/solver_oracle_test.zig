const std = @import("std");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");
const oracle = @import("solver_oracle.zig");

const testing = std.testing;
const golden_schema = "tdnf-libsolv-oracle-v1";
const checksum = "0000000000000000000000000000000000000000000000000000000000000000";

const PackageSpec = struct {
    name: []const u8,
    version: []const u8 = "1",
    release: []const u8 = "1",
    arch: []const u8 = "x86_64",
    provides: []const metadata.Relation = &.{},
    requires: []const metadata.Relation = &.{},
    conflicts: []const metadata.Relation = &.{},
    obsoletes: []const metadata.Relation = &.{},
    recommends: []const metadata.Relation = &.{},
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
            "action {d} {t} prior={any} reason={t} job={any}\n",
            .{
                @intFromEnum(action.package),
                action.kind,
                if (action.prior) |value| @as(?u32, @intFromEnum(value)) else null,
                action.reason,
                if (action.requested_by) |value| @as(?u32, @intFromEnum(value)) else null,
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
            .{ .jobs = &.{} },
            unsupported,
        ),
    );
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
        \\action 0 install prior=null reason=dependency job=null
        \\action 1 install prior=null reason=dependency job=null
        \\action 2 install prior=null reason=user job=0
        \\order 0 install 0
        \\order 1 install 1
        \\order 2 install 2
        \\
    ,
        golden,
    );
}

test "oracle deterministically chooses the best alternative provider" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    var builder = GraphBuilder.init(arena_state.allocator());
    const available = try builder.addRepo("available", .available, 50);
    try builder.addPackage(available, .{
        .name = "provider-low",
        .version = "1",
        .provides = &.{versionedRelation("virtual-api", .eq, "1")},
    });
    try builder.addPackage(available, .{
        .name = "provider-high",
        .version = "2",
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
    try testing.expectEqual(@as(u32, 0), @intFromEnum(action.prior.?));
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
    try testing.expectEqual(@as(u32, 0), @intFromEnum(action.prior.?));
    try testing.expectEqual(solver_model.TransactionReason.obsoletes, action.reason);
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
