//! Initial package-policy preparation for the native solver.
//!
//! This slice preserves installed packages unless a same-name or explicit
//! obsoleting replacement is selected. Candidate ranking, update jobs,
//! allow-erasing, and cleanup policy remain separate follow-up work.

const std = @import("std");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");
const solver_rules = @import("solver_rules.zig");
const solver_search = @import("solver_search.zig");

const PackageIdList = std.array_list.Managed(solver_model.PackageId);

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
    decision_order: []const solver_model.PackageId,
    preferred_values: []const bool,

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
        return solver_search.solveWithDecisionPolicy(
            allocator,
            &self.formula,
            assumptions,
            .{
                .order = self.decision_order,
                .preferred_values = self.preferred_values,
            },
        );
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.preferred_values);
        self.allocator.free(self.decision_order);
        self.formula.deinit();
        self.* = undefined;
    }
};

/// Copy a base formula and append installed-retention clauses.
///
/// The returned formula still borrows the universe and repository metadata.
pub fn prepareInstalledRetention(
    allocator: std.mem.Allocator,
    base: *const solver_rules.OwnedFormula,
) PrepareError!Prepared {
    const package_count = base.universe.packages.len;
    try validateBaseFormula(base);
    for (base.package_states) |state| {
        if (state.multiversion) return error.UnsupportedPolicy;
    }

    const not_installable = try allocator.alloc(bool, package_count);
    defer allocator.free(not_installable);
    @memset(not_installable, false);
    const directly_erased = try allocator.alloc(bool, package_count);
    defer allocator.free(directly_erased);
    @memset(directly_erased, false);

    const candidates = try allocator.alloc(PackageIdList, package_count);
    defer allocator.free(candidates);
    for (candidates) |*list| {
        list.* = PackageIdList.init(allocator);
    }
    defer for (candidates) |*list| list.deinit();

    for (base.clauses) |clause| {
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
                    try candidates[left_index].append(origin.right);
                }
                if (base.universe.packages[right_index].installed != null) {
                    try candidates[right_index].append(origin.left);
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
                    try candidates[target_index].append(
                        origin.dependency.package,
                    );
                }
            },
            .job => {
                if (literals.len != 1 or literals[0].positive()) continue;
                const package_index = try packageIndex(
                    literals[0].package(),
                    package_count,
                );
                if (base.universe.packages[package_index].installed != null) {
                    directly_erased[package_index] = true;
                }
            },
            .requirement, .conflict, .installed_keep => {},
        }
    }

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

        const package_candidates = &candidates[package_index];
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
            .clauses = owned_clauses,
            .literals = owned_literals,
            .weak_requests = weak_requests,
            .weak_candidates = weak_candidates,
            .package_states = package_states,
        },
        .decision_order = decision_order,
        .preferred_values = preferred_values,
    };
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
    for (formula.universe.packages, 0..) |package, package_index| {
        if (@intFromEnum(package.id) != package_index) {
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

test "malformed package IDs and literal encodings are rejected" {
    var source = testPackage("package", "1");
    var packages = [_]solver_model.UniversePackage{.{
        .id = @enumFromInt(1),
        .repository = @enumFromInt(0),
        .repository_package_index = 0,
        .source = &source,
        .installed = .{ .rpmdb_hnum = 1 },
    }};
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &.{},
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

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var sources = [_]metadata.Package{
        testPackage("package", "1"),
        testPackage("package", "2"),
    };
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
    };
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &.{},
        .packages = &packages,
        .input_to_repository = &.{},
    };
    var states = [_]solver_rules.PackageState{ .{}, .{} };
    const literals = [_]solver_rules.Literal{
        solver_rules.Literal.init(@enumFromInt(0), false),
        solver_rules.Literal.init(@enumFromInt(1), false),
        solver_rules.Literal.init(@enumFromInt(1), true),
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
