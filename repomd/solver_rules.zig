//! Deterministic base CNF generation for the native package solver.
//!
//! This module encodes intrinsic package consistency and mechanical jobs only.
//! Search and package-policy layers append their own rules without changing
//! this immutable representation.

const std = @import("std");
const metadata = @import("model.zig");
const query_index = @import("index.zig");
const solver_model = @import("solver_model.zig");

pub const Literal = enum(u64) {
    _,

    pub fn init(package_id: solver_model.PackageId, positive_value: bool) Literal {
        const package_value: u64 = @intFromEnum(package_id);
        return @enumFromInt((package_value << 1) | @intFromBool(!positive_value));
    }

    pub fn package(self: Literal) solver_model.PackageId {
        return @enumFromInt(@as(u32, @intCast(@intFromEnum(self) >> 1)));
    }

    pub fn positive(self: Literal) bool {
        return @intFromEnum(self) & 1 == 0;
    }

    pub fn negated(self: Literal) Literal {
        return @enumFromInt(@intFromEnum(self) ^ 1);
    }
};

pub const LiteralRange = struct {
    start: u32 = 0,
    len: u32 = 0,

    pub fn slice(self: LiteralRange, literals: []const Literal) []const Literal {
        const start: usize = @intCast(self.start);
        const len: usize = @intCast(self.len);
        return literals[start .. start + len];
    }
};

pub const PackageIdRange = struct {
    start: u32 = 0,
    len: u32 = 0,

    pub fn slice(
        self: PackageIdRange,
        packages: []const solver_model.PackageId,
    ) []const solver_model.PackageId {
        const start: usize = @intCast(self.start);
        const len: usize = @intCast(self.len);
        return packages[start .. start + len];
    }
};

pub const DependencyRef = struct {
    package: solver_model.PackageId,
    kind: metadata.DependencyKind,
    index: u32,
};

pub const RuleOrigin = union(enum) {
    not_installable: solver_model.PackageId,
    requirement: DependencyRef,
    conflict: struct {
        dependency: DependencyRef,
        target: ?solver_model.PackageId,
    },
    obsoletes: struct {
        dependency: DependencyRef,
        target: solver_model.PackageId,
    },
    same_name: struct {
        left: solver_model.PackageId,
        right: solver_model.PackageId,
    },
    installed_keep: solver_model.PackageId,
    job: solver_model.JobId,
};

pub const ClauseDisposition = enum {
    hard,
    relaxable_job,
};

pub const Clause = struct {
    literals: LiteralRange,
    origin: RuleOrigin,
    disposition: ClauseDisposition = .hard,
};

pub const WeakDirection = enum {
    forward,
    reverse,
};

pub const WeakRequest = struct {
    owner: solver_model.PackageId,
    dependency: DependencyRef,
    candidates: PackageIdRange,
    direction: WeakDirection,
    system_satisfied: bool = false,
};

pub const PackageState = struct {
    multiversion: bool = false,
    user_installed: bool = false,
    allow_uninstall: bool = false,
    replacement: ReplacementState = .{},
};

pub const ReplacementKind = enum {
    none,
    update,
    dist_sync,
};

pub const ReplacementState = struct {
    kind: ReplacementKind = .none,
    job: solver_model.JobId = @enumFromInt(0),
    force_best: bool = false,
};

pub const OwnedFormula = struct {
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    architecture: ?solver_model.ArchitecturePolicy = null,
    clauses: []const Clause,
    literals: []const Literal,
    weak_requests: []const WeakRequest,
    weak_candidates: []const solver_model.PackageId,
    package_states: []const PackageState,

    pub fn clauseLiterals(self: *const OwnedFormula, clause: Clause) []const Literal {
        return clause.literals.slice(self.literals);
    }

    pub fn weakCandidates(
        self: *const OwnedFormula,
        request: WeakRequest,
    ) []const solver_model.PackageId {
        return request.candidates.slice(self.weak_candidates);
    }

    pub fn packageState(
        self: *const OwnedFormula,
        package_id: solver_model.PackageId,
    ) ?PackageState {
        const package_index: usize = @intFromEnum(package_id);
        if (package_index >= self.package_states.len) return null;
        return self.package_states[package_index];
    }

    pub fn deinit(self: *OwnedFormula) void {
        self.allocator.free(self.package_states);
        self.allocator.free(self.weak_candidates);
        self.allocator.free(self.weak_requests);
        self.allocator.free(self.literals);
        self.allocator.free(self.clauses);
        self.* = undefined;
    }
};

pub const GenerateError = error{
    OutOfMemory,
    InvalidPackageId,
    TooManyClauses,
    TooManyLiterals,
    TooManyWeakCandidates,
    TooManyRelations,
    UnsupportedJob,
    UnsupportedPolicy,
};

const ProviderEntry = struct {
    package: solver_model.PackageId,
    relation: metadata.Relation,
};

const PackageIdList = std.array_list.Managed(solver_model.PackageId);
const ProviderList = std.array_list.Managed(ProviderEntry);

const ProviderLookup = struct {
    allocator: std.mem.Allocator,
    packages: []solver_model.PackageId,
    system: bool,

    fn deinit(self: ProviderLookup) void {
        self.allocator.free(self.packages);
    }
};

const UniverseIndex = struct {
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    architecture: solver_model.ArchitecturePolicy,
    names: std.StringHashMap(PackageIdList),
    provides: std.StringHashMap(ProviderList),
    files: std.StringHashMap(PackageIdList),

    fn init(
        allocator: std.mem.Allocator,
        universe: *const solver_model.Universe,
        architecture: solver_model.ArchitecturePolicy,
    ) error{OutOfMemory}!UniverseIndex {
        var index = UniverseIndex{
            .allocator = allocator,
            .universe = universe,
            .architecture = architecture,
            .names = std.StringHashMap(PackageIdList).init(allocator),
            .provides = std.StringHashMap(ProviderList).init(allocator),
            .files = std.StringHashMap(PackageIdList).init(allocator),
        };
        errdefer index.deinit();

        var referenced_files = std.StringHashMap(void).init(allocator);
        defer referenced_files.deinit();
        for (universe.packages) |package| {
            try appendPackageId(
                &index.names,
                allocator,
                package.source.nevra.name,
                package.id,
            );
            for (package.relationEntries(universe, .provides)) |relation| {
                try appendProvider(
                    &index.provides,
                    allocator,
                    relation.name,
                    .{
                        .package = package.id,
                        .relation = relation,
                    },
                );
            }
            inline for ([_]metadata.DependencyKind{
                .requires,
                .conflicts,
                .obsoletes,
                .recommends,
                .suggests,
                .supplements,
                .enhances,
            }) |kind| {
                for (package.relationEntries(universe, kind)) |dependency| {
                    if (dependency.name.len != 0 and dependency.name[0] == '/') {
                        try referenced_files.put(dependency.name, {});
                    }
                }
            }
        }
        for (universe.packages) |package| {
            for (package.fileEntries(universe)) |file| {
                if (!referenced_files.contains(file.path)) continue;
                try appendUniquePackageId(
                    &index.files,
                    allocator,
                    file.path,
                    package.id,
                );
            }
        }
        return index;
    }

    fn deinit(self: *UniverseIndex) void {
        deinitPackageMap(&self.names);
        deinitProviderMap(&self.provides);
        deinitPackageMap(&self.files);
        self.* = undefined;
    }

    fn providers(
        self: *const UniverseIndex,
        allocator: std.mem.Allocator,
        relation: metadata.Relation,
    ) error{OutOfMemory}!ProviderLookup {
        var packages = PackageIdList.init(allocator);
        defer packages.deinit();

        if (self.provides.get(relation.name)) |entries| {
            for (entries.items) |entry| {
                const package = self.universe.package(entry.package) orelse unreachable;
                if (!self.canProvide(package.*)) continue;
                if (!rpmProvideMatches(entry.relation, relation)) continue;
                try packages.append(entry.package);
            }
        }

        if (self.names.get(relation.name)) |named_packages| {
            for (named_packages.items) |package_id| {
                const package = self.universe.package(package_id) orelse unreachable;
                if (!self.canProvide(package.*) or isSource(package.source.nevra.arch)) {
                    continue;
                }
                if (!rpmProvideMatches(selfProvide(package.source.*), relation)) {
                    continue;
                }
                try packages.append(package_id);
            }
        }

        if (relation.name.len != 0 and relation.name[0] == '/') {
            if (self.files.get(relation.name)) |file_packages| {
                for (file_packages.items) |package_id| {
                    const package = self.universe.package(package_id) orelse unreachable;
                    if (self.canProvide(package.*)) {
                        try packages.append(package_id);
                    }
                }
            }
        }

        sortAndDeduplicatePackageIds(&packages);
        const owned = try packages.toOwnedSlice();
        return .{
            .allocator = allocator,
            .packages = owned,
            .system = owned.len == 0 and
                !relationIsUnversioned(relation) and
                std.mem.startsWith(u8, relation.name, "rpmlib("),
        };
    }

    fn matchingNames(
        self: *const UniverseIndex,
        allocator: std.mem.Allocator,
        name: []const u8,
    ) error{OutOfMemory}!ProviderLookup {
        var packages = PackageIdList.init(allocator);
        defer packages.deinit();

        if (self.names.get(name)) |named_packages| {
            for (named_packages.items) |package_id| {
                const package = self.universe.package(package_id) orelse unreachable;
                if (self.canProvide(package.*) and !isSource(package.source.nevra.arch)) {
                    try packages.append(package_id);
                }
            }
        }
        return .{
            .allocator = allocator,
            .packages = try packages.toOwnedSlice(),
            .system = false,
        };
    }

    fn matchingNevr(
        self: *const UniverseIndex,
        allocator: std.mem.Allocator,
        relation: metadata.Relation,
    ) error{OutOfMemory}!ProviderLookup {
        var packages = PackageIdList.init(allocator);
        defer packages.deinit();

        if (self.names.get(relation.name)) |named_packages| {
            for (named_packages.items) |package_id| {
                const package = self.universe.package(package_id) orelse unreachable;
                if (!self.canProvide(package.*) or isSource(package.source.nevra.arch)) {
                    continue;
                }
                if (rpmProvideMatches(selfProvide(package.source.*), relation)) {
                    try packages.append(package_id);
                }
            }
        }
        return .{
            .allocator = allocator,
            .packages = try packages.toOwnedSlice(),
            .system = false,
        };
    }

    fn selection(
        self: *const UniverseIndex,
        allocator: std.mem.Allocator,
        selected: solver_model.Selection,
    ) GenerateError!ProviderLookup {
        return switch (selected) {
            .all => blk: {
                const packages = try allocator.alloc(
                    solver_model.PackageId,
                    self.universe.packages.len,
                );
                for (self.universe.packages, packages) |package, *package_id| {
                    package_id.* = package.id;
                }
                break :blk .{
                    .allocator = allocator,
                    .packages = packages,
                    .system = false,
                };
            },
            .package => |package_id| blk: {
                if (self.universe.package(package_id) == null) {
                    return error.InvalidPackageId;
                }
                const packages = try allocator.alloc(solver_model.PackageId, 1);
                packages[0] = package_id;
                break :blk .{
                    .allocator = allocator,
                    .packages = packages,
                    .system = false,
                };
            },
            .name => |name| try self.matchingNames(allocator, name),
            .capability => |relation| try self.providers(allocator, relation),
        };
    }

    fn canProvide(
        self: *const UniverseIndex,
        package: solver_model.UniversePackage,
    ) bool {
        if (package.installed != null) return true;
        if (isSource(package.source.nevra.arch)) return false;
        return architectureAllows(
            self.architecture.force_arch orelse self.architecture.native_arch,
            package.source.nevra.arch,
        );
    }
};

const FormulaBuilder = struct {
    allocator: std.mem.Allocator,
    clauses: std.array_list.Managed(Clause),
    literals: std.array_list.Managed(Literal),
    weak_requests: std.array_list.Managed(WeakRequest),
    weak_candidates: PackageIdList,
    scratch_literals: std.array_list.Managed(Literal),

    fn init(allocator: std.mem.Allocator) FormulaBuilder {
        return .{
            .allocator = allocator,
            .clauses = std.array_list.Managed(Clause).init(allocator),
            .literals = std.array_list.Managed(Literal).init(allocator),
            .weak_requests = std.array_list.Managed(WeakRequest).init(allocator),
            .weak_candidates = PackageIdList.init(allocator),
            .scratch_literals = std.array_list.Managed(Literal).init(allocator),
        };
    }

    fn deinit(self: *FormulaBuilder) void {
        self.scratch_literals.deinit();
        self.weak_candidates.deinit();
        self.weak_requests.deinit();
        self.literals.deinit();
        self.clauses.deinit();
        self.* = undefined;
    }

    fn addClause(
        self: *FormulaBuilder,
        input_literals: []const Literal,
        origin: RuleOrigin,
        disposition: ClauseDisposition,
    ) GenerateError!void {
        self.scratch_literals.clearRetainingCapacity();
        try self.scratch_literals.appendSlice(input_literals);
        std.sort.heap(
            Literal,
            self.scratch_literals.items,
            {},
            literalLessThan,
        );

        var write_index: usize = 0;
        for (self.scratch_literals.items) |literal| {
            if (write_index != 0) {
                const previous = self.scratch_literals.items[write_index - 1];
                if (literal == previous) continue;
                if (literal == previous.negated()) return;
            }
            self.scratch_literals.items[write_index] = literal;
            write_index += 1;
        }
        self.scratch_literals.shrinkRetainingCapacity(write_index);

        if (self.clauses.items.len >= std.math.maxInt(u32)) {
            return error.TooManyClauses;
        }
        if (self.literals.items.len > std.math.maxInt(u32) or
            self.scratch_literals.items.len >
                std.math.maxInt(u32) - self.literals.items.len)
        {
            return error.TooManyLiterals;
        }

        const literal_start = self.literals.items.len;
        try self.literals.appendSlice(self.scratch_literals.items);
        errdefer self.literals.shrinkRetainingCapacity(literal_start);
        try self.clauses.append(.{
            .literals = .{
                .start = @intCast(literal_start),
                .len = @intCast(self.scratch_literals.items.len),
            },
            .origin = origin,
            .disposition = disposition,
        });
    }

    fn addWeakRequest(
        self: *FormulaBuilder,
        owner: solver_model.PackageId,
        dependency: DependencyRef,
        candidates: []const solver_model.PackageId,
        direction: WeakDirection,
        system_satisfied: bool,
    ) GenerateError!void {
        if (self.weak_candidates.items.len > std.math.maxInt(u32) or
            candidates.len > std.math.maxInt(u32) - self.weak_candidates.items.len)
        {
            return error.TooManyWeakCandidates;
        }
        const start = self.weak_candidates.items.len;
        try self.weak_candidates.appendSlice(candidates);
        errdefer self.weak_candidates.shrinkRetainingCapacity(start);
        try self.weak_requests.append(.{
            .owner = owner,
            .dependency = dependency,
            .candidates = .{
                .start = @intCast(start),
                .len = @intCast(candidates.len),
            },
            .direction = direction,
            .system_satisfied = system_satisfied,
        });
    }
};

pub fn generateBase(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
    goal: solver_model.Goal,
    architecture: solver_model.ArchitecturePolicy,
) GenerateError!OwnedFormula {
    if (!architecture.allow_multilib) return error.UnsupportedPolicy;
    if (goal.jobs.len > std.math.maxInt(u32)) return error.TooManyClauses;

    var universe_index = try UniverseIndex.init(allocator, universe, architecture);
    defer universe_index.deinit();

    const package_states = try allocator.alloc(PackageState, universe.packages.len);
    errdefer allocator.free(package_states);
    @memset(package_states, .{});
    try collectPackageStates(
        allocator,
        &universe_index,
        goal,
        package_states,
    );

    const install_candidates = try allocator.alloc(bool, universe.packages.len);
    defer allocator.free(install_candidates);
    @memset(install_candidates, false);
    try collectInstallCandidates(
        allocator,
        &universe_index,
        goal,
        install_candidates,
    );

    var builder = FormulaBuilder.init(allocator);
    defer builder.deinit();

    try generateNotInstallable(&builder, universe, architecture);
    try generateRequirements(&builder, &universe_index);
    try generateConflicts(&builder, &universe_index);
    try generateObsoletes(&builder, &universe_index);
    try generateSameName(
        &builder,
        &universe_index,
        package_states,
    );
    try generateJobs(
        allocator,
        &builder,
        &universe_index,
        goal,
        install_candidates,
    );
    try generateWeakRequests(&builder, &universe_index);

    const clauses = try builder.clauses.toOwnedSlice();
    errdefer allocator.free(clauses);
    const literals = try builder.literals.toOwnedSlice();
    errdefer allocator.free(literals);
    const weak_requests = try builder.weak_requests.toOwnedSlice();
    errdefer allocator.free(weak_requests);
    const weak_candidates = try builder.weak_candidates.toOwnedSlice();
    errdefer allocator.free(weak_candidates);

    return .{
        .allocator = allocator,
        .universe = universe,
        .architecture = architecture,
        .clauses = clauses,
        .literals = literals,
        .weak_requests = weak_requests,
        .weak_candidates = weak_candidates,
        .package_states = package_states,
    };
}

fn collectPackageStates(
    allocator: std.mem.Allocator,
    index: *const UniverseIndex,
    goal: solver_model.Goal,
    states: []PackageState,
) GenerateError!void {
    for (goal.jobs, 0..) |job, job_index| {
        switch (job.action) {
            .update, .dist_sync => {
                if (std.meta.activeTag(job.selection) != .all) {
                    return error.UnsupportedJob;
                }
                if (job.flags.clean_deps or
                    job.flags.targeted or
                    job.flags.weak)
                {
                    return error.UnsupportedJob;
                }
                const kind: ReplacementKind = switch (job.action) {
                    .update => .update,
                    .dist_sync => .dist_sync,
                    else => unreachable,
                };
                for (index.universe.packages, states) |package, *state| {
                    if (package.installed == null) continue;
                    if (state.replacement.kind != .none and
                        state.replacement.kind != kind)
                    {
                        return error.UnsupportedJob;
                    }
                    state.replacement = .{
                        .kind = kind,
                        .job = @enumFromInt(@as(u32, @intCast(job_index))),
                        .force_best = state.replacement.force_best or
                            job.flags.force_best,
                    };
                }
                continue;
            },
            else => {},
        }
        const state_kind: enum {
            multiversion,
            user_installed,
            allow_uninstall,
        } = switch (job.action) {
            .multiversion => .multiversion,
            .user_installed => .user_installed,
            .allow_uninstall => .allow_uninstall,
            else => continue,
        };
        var selected = try index.selection(allocator, job.selection);
        defer selected.deinit();
        for (selected.packages) |package_id| {
            const package_index: usize = @intFromEnum(package_id);
            if (state_kind != .multiversion and
                index.universe.packages[package_index].installed == null)
            {
                continue;
            }
            switch (state_kind) {
                .multiversion => states[package_index].multiversion = true,
                .user_installed => states[package_index].user_installed = true,
                .allow_uninstall => states[package_index].allow_uninstall = true,
            }
        }
    }
}

fn collectInstallCandidates(
    allocator: std.mem.Allocator,
    index: *const UniverseIndex,
    goal: solver_model.Goal,
    install_candidates: []bool,
) GenerateError!void {
    for (goal.jobs) |job| {
        switch (job.action) {
            .install => {
                if (std.meta.activeTag(job.selection) == .all) continue;
            },
            .downgrade, .reinstall => {
                if (std.meta.activeTag(job.selection) != .package) {
                    return error.UnsupportedJob;
                }
            },
            else => continue,
        }
        var selected = try index.selection(allocator, job.selection);
        defer selected.deinit();
        for (selected.packages) |package_id| {
            install_candidates[@intFromEnum(package_id)] = true;
        }
    }
}

fn generateNotInstallable(
    builder: *FormulaBuilder,
    universe: *const solver_model.Universe,
    architecture: solver_model.ArchitecturePolicy,
) GenerateError!void {
    const wanted_arch = architecture.force_arch orelse architecture.native_arch;
    for (universe.packages) |package| {
        if (package.installed != null or isSource(package.source.nevra.arch) or
            architectureAllows(wanted_arch, package.source.nevra.arch))
        {
            continue;
        }
        try builder.addClause(
            &.{Literal.init(package.id, false)},
            .{ .not_installable = package.id },
            .hard,
        );
    }
}

fn generateRequirements(
    builder: *FormulaBuilder,
    index: *const UniverseIndex,
) GenerateError!void {
    var clause = std.array_list.Managed(Literal).init(builder.allocator);
    defer clause.deinit();

    for (index.universe.packages) |package| {
        for (package.relationEntries(index.universe, .requires), 0..) |
            relation,
            relation_index,
        | {
            const dependency = try dependencyRef(
                package.id,
                .requires,
                relation_index,
            );
            var providers = try index.providers(builder.allocator, relation);
            defer providers.deinit();
            if (providers.system or containsPackage(providers.packages, package.id)) {
                continue;
            }
            if (package.installed != null and
                !containsInstalled(index.universe, providers.packages))
            {
                continue;
            }

            clause.clearRetainingCapacity();
            try clause.append(Literal.init(package.id, false));
            for (providers.packages) |provider| {
                try clause.append(Literal.init(provider, true));
            }
            try builder.addClause(
                clause.items,
                .{ .requirement = dependency },
                .hard,
            );
        }
    }
}

fn generateConflicts(
    builder: *FormulaBuilder,
    index: *const UniverseIndex,
) GenerateError!void {
    for (index.universe.packages) |package| {
        if (isSource(package.source.nevra.arch)) continue;
        for (package.relationEntries(index.universe, .conflicts), 0..) |
            relation,
            relation_index,
        | {
            const dependency = try dependencyRef(
                package.id,
                .conflicts,
                relation_index,
            );
            var providers = try index.providers(builder.allocator, relation);
            defer providers.deinit();

            if (providers.system) {
                try builder.addClause(
                    &.{Literal.init(package.id, false)},
                    .{ .conflict = .{
                        .dependency = dependency,
                        .target = null,
                    } },
                    .hard,
                );
            }
            for (providers.packages) |target_id| {
                if (target_id == package.id) continue;
                const target = index.universe.package(target_id) orelse unreachable;
                if (package.installed != null and target.installed != null) continue;
                try builder.addClause(
                    &.{
                        Literal.init(package.id, false),
                        Literal.init(target_id, false),
                    },
                    .{ .conflict = .{
                        .dependency = dependency,
                        .target = target_id,
                    } },
                    .hard,
                );
            }
        }
    }
}

fn generateObsoletes(
    builder: *FormulaBuilder,
    index: *const UniverseIndex,
) GenerateError!void {
    for (index.universe.packages) |package| {
        if (isSource(package.source.nevra.arch)) continue;
        for (package.relationEntries(index.universe, .obsoletes), 0..) |
            relation,
            relation_index,
        | {
            const dependency = try dependencyRef(
                package.id,
                .obsoletes,
                relation_index,
            );
            var targets = try index.matchingNevr(builder.allocator, relation);
            defer targets.deinit();
            for (targets.packages) |target_id| {
                if (target_id == package.id) continue;
                const target = index.universe.package(target_id) orelse unreachable;
                if (package.installed != null and target.installed != null) continue;
                try builder.addClause(
                    &.{
                        Literal.init(package.id, false),
                        Literal.init(target_id, false),
                    },
                    .{ .obsoletes = .{
                        .dependency = dependency,
                        .target = target_id,
                    } },
                    .hard,
                );
            }
        }
    }
}

fn generateSameName(
    builder: *FormulaBuilder,
    index: *const UniverseIndex,
    package_states: []const PackageState,
) GenerateError!void {
    for (index.universe.packages) |left| {
        if (isSource(left.source.nevra.arch)) continue;
        const same_name_packages = index.names.get(
            left.source.nevra.name,
        ) orelse continue;
        for (same_name_packages.items) |right_id| {
            if (@intFromEnum(right_id) <= @intFromEnum(left.id)) continue;
            const right = index.universe.package(right_id).?.*;
            if (isSource(right.source.nevra.arch) or
                !std.mem.eql(u8, left.source.nevra.name, right.source.nevra.name))
            {
                continue;
            }
            if (left.installed != null and right.installed != null) continue;
            if (!index.canProvide(left) and !index.canProvide(right)) continue;

            const left_state = package_states[@intFromEnum(left.id)];
            const right_state = package_states[@intFromEnum(right.id)];
            if (left_state.multiversion and right_state.multiversion and
                !sameEvra(left.source.*, right.source.*))
            {
                continue;
            }

            try builder.addClause(
                &.{
                    Literal.init(left.id, false),
                    Literal.init(right.id, false),
                },
                .{ .same_name = .{
                    .left = left.id,
                    .right = right.id,
                } },
                .hard,
            );
        }
    }
}

fn generateJobs(
    allocator: std.mem.Allocator,
    builder: *FormulaBuilder,
    index: *const UniverseIndex,
    goal: solver_model.Goal,
    install_candidates: []const bool,
) GenerateError!void {
    var literals = std.array_list.Managed(Literal).init(allocator);
    defer literals.deinit();

    for (goal.jobs, 0..) |job, job_index| {
        const job_id: solver_model.JobId = @enumFromInt(
            @as(u32, @intCast(job_index)),
        );
        const disposition: ClauseDisposition = if (job.flags.weak)
            .relaxable_job
        else
            .hard;

        switch (job.action) {
            .install => {
                literals.clearRetainingCapacity();
                if (std.meta.activeTag(job.selection) != .all) {
                    var selected = try index.selection(allocator, job.selection);
                    defer selected.deinit();
                    if (selected.system) continue;
                    for (selected.packages) |package_id| {
                        try literals.append(Literal.init(package_id, true));
                    }
                }
                try builder.addClause(
                    literals.items,
                    .{ .job = job_id },
                    disposition,
                );
            },
            .downgrade, .reinstall => {
                const package_id = switch (job.selection) {
                    .package => |value| value,
                    else => return error.UnsupportedJob,
                };
                if (index.universe.package(package_id) == null) {
                    return error.InvalidPackageId;
                }
                try builder.addClause(
                    &.{Literal.init(package_id, true)},
                    .{ .job = job_id },
                    disposition,
                );
            },
            .erase => {
                var selected = try index.selection(allocator, job.selection);
                defer selected.deinit();
                if (selected.system) {
                    try builder.addClause(
                        &.{},
                        .{ .job = job_id },
                        disposition,
                    );
                }
                for (selected.packages) |package_id| {
                    try builder.addClause(
                        &.{Literal.init(package_id, false)},
                        .{ .job = job_id },
                        disposition,
                    );
                }
                if (std.meta.activeTag(job.selection) == .package and
                    selected.packages.len == 1)
                {
                    const erased = index.universe.package(
                        selected.packages[0],
                    ) orelse unreachable;
                    if (erased.installed != null) {
                        var replacements = try index.matchingNames(
                            allocator,
                            erased.source.nevra.name,
                        );
                        defer replacements.deinit();
                        for (replacements.packages) |replacement_id| {
                            const replacement = index.universe.package(
                                replacement_id,
                            ) orelse unreachable;
                            if (replacement.installed != null or
                                install_candidates[@intFromEnum(replacement_id)])
                            {
                                continue;
                            }
                            try builder.addClause(
                                &.{Literal.init(replacement_id, false)},
                                .{ .job = job_id },
                                disposition,
                            );
                        }
                    }
                }
            },
            .lock => {
                var selected = try index.selection(allocator, job.selection);
                defer selected.deinit();
                if (selected.system) {
                    try builder.addClause(
                        &.{},
                        .{ .job = job_id },
                        disposition,
                    );
                }
                for (selected.packages) |package_id| {
                    const package = index.universe.package(package_id) orelse unreachable;
                    try builder.addClause(
                        &.{Literal.init(package_id, package.installed != null)},
                        .{ .job = job_id },
                        disposition,
                    );
                }
            },
            .multiversion, .user_installed, .allow_uninstall => {},
            .update, .dist_sync => {
                if (std.meta.activeTag(job.selection) != .all) {
                    return error.UnsupportedJob;
                }
            },
        }
    }
}

fn generateWeakRequests(
    builder: *FormulaBuilder,
    index: *const UniverseIndex,
) GenerateError!void {
    inline for ([_]struct {
        kind: metadata.DependencyKind,
        direction: WeakDirection,
    }{
        .{ .kind = .recommends, .direction = .forward },
        .{ .kind = .suggests, .direction = .forward },
        .{ .kind = .supplements, .direction = .reverse },
        .{ .kind = .enhances, .direction = .reverse },
    }) |weak_kind| {
        for (index.universe.packages) |package| {
            for (package.relationEntries(index.universe, weak_kind.kind), 0..) |
                relation,
                relation_index,
            | {
                var providers = try index.providers(builder.allocator, relation);
                defer providers.deinit();
                try builder.addWeakRequest(
                    package.id,
                    try dependencyRef(
                        package.id,
                        weak_kind.kind,
                        relation_index,
                    ),
                    providers.packages,
                    weak_kind.direction,
                    providers.system,
                );
            }
        }
    }
}

fn dependencyRef(
    package: solver_model.PackageId,
    kind: metadata.DependencyKind,
    relation_index: usize,
) GenerateError!DependencyRef {
    if (relation_index > std.math.maxInt(u32)) return error.TooManyRelations;
    return .{
        .package = package,
        .kind = kind,
        .index = @intCast(relation_index),
    };
}

fn relationIsUnversioned(relation: metadata.Relation) bool {
    return relation.flags == null or relation.comparison == .none;
}

const relation_gt: u8 = 1;
const relation_eq: u8 = 2;
const relation_lt: u8 = 4;

fn rpmProvideMatches(
    provider: metadata.Relation,
    dependency: metadata.Relation,
) bool {
    if (!std.mem.eql(u8, provider.name, dependency.name)) return false;
    if (relationIsUnversioned(dependency) or relationIsUnversioned(provider)) {
        return true;
    }

    const provider_flags = relationFlags(provider.comparison);
    const dependency_flags = relationFlags(dependency.comparison);
    if (provider_flags == 0 or dependency_flags == 0) return false;
    if (provider_flags == 7 or dependency_flags == 7) return true;
    if (provider_flags & dependency_flags & (relation_lt | relation_gt) != 0) {
        return true;
    }

    return switch (compareRelationEvr(provider, dependency)) {
        -2 => provider_flags & relation_eq != 0,
        -1 => dependency_flags & relation_lt != 0 or
            provider_flags & relation_gt != 0,
        0 => dependency_flags & provider_flags & relation_eq != 0,
        1 => dependency_flags & relation_gt != 0 or
            provider_flags & relation_lt != 0,
        2 => dependency_flags & relation_eq != 0,
        else => false,
    };
}

fn relationFlags(comparison: metadata.CompareOp) u8 {
    return switch (comparison) {
        .none => 0,
        .eq => relation_eq,
        .lt => relation_lt,
        .le => relation_lt | relation_eq,
        .gt => relation_gt,
        .ge => relation_gt | relation_eq,
    };
}

pub fn compareRelationEvr(
    left: metadata.Relation,
    right: metadata.Relation,
) i32 {
    const version_comparison = query_index.compareEvr(
        left.epoch,
        left.version,
        null,
        right.epoch,
        right.version,
        null,
    );
    if (version_comparison != 0) return version_comparison;

    const left_release = nonEmpty(left.release);
    const right_release = nonEmpty(right.release);
    if (left_release == null and right_release != null) return -2;
    if (left_release != null and right_release == null) return 2;
    if (left_release == null) return 0;
    return query_index.compareEvr(
        null,
        "",
        left_release,
        null,
        "",
        right_release,
    );
}

fn nonEmpty(value: ?[]const u8) ?[]const u8 {
    const text = value orelse return null;
    return if (text.len == 0) null else text;
}

fn selfProvide(package: metadata.Package) metadata.Relation {
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

fn containsPackage(
    packages: []const solver_model.PackageId,
    wanted: solver_model.PackageId,
) bool {
    for (packages) |package| {
        if (package == wanted) return true;
    }
    return false;
}

fn containsInstalled(
    universe: *const solver_model.Universe,
    packages: []const solver_model.PackageId,
) bool {
    for (packages) |package_id| {
        if (universe.package(package_id).?.installed != null) return true;
    }
    return false;
}

fn sameEvra(left: metadata.Package, right: metadata.Package) bool {
    return left.nevra.epoch == right.nevra.epoch and
        std.mem.eql(u8, left.nevra.version, right.nevra.version) and
        std.mem.eql(u8, left.nevra.release, right.nevra.release) and
        std.mem.eql(u8, left.nevra.arch, right.nevra.arch);
}

fn isSource(architecture: []const u8) bool {
    return std.mem.eql(u8, architecture, "src") or
        std.mem.eql(u8, architecture, "nosrc");
}

const ArchitectureEntry = struct {
    native: []const u8,
    policy: []const u8,
};

const architecture_entries = [_]ArchitectureEntry{
    .{ .native = "x86_64_v4", .policy = "x86_64_v4:x86_64_v3:x86_64_v2:x86_64:i686:i586:i486:i386" },
    .{ .native = "x86_64_v3", .policy = "x86_64_v3:x86_64_v2:x86_64:i686:i586:i486:i386" },
    .{ .native = "x86_64_v2", .policy = "x86_64_v2:x86_64:i686:i586:i486:i386" },
    .{ .native = "x86_64", .policy = "x86_64:i686:i586:i486:i386" },
    .{ .native = "i686", .policy = "i686:i586:i486:i386" },
    .{ .native = "i586", .policy = "i586:i486:i386" },
    .{ .native = "i486", .policy = "i486:i386" },
    .{ .native = "s390x", .policy = "s390x:s390" },
    .{ .native = "ppc64", .policy = "ppc64:ppc" },
    .{ .native = "ppc64p7", .policy = "ppc64p7:ppc64:ppc" },
    .{ .native = "ia64", .policy = "ia64:i686:i586:i486:i386" },
    .{ .native = "armv8hcnl", .policy = "armv8hcnl:armv8hnl:armv8hl:armv7hnl:armv7hl:armv6hl" },
    .{ .native = "armv8hnl", .policy = "armv8hnl:armv8hl:armv7hnl:armv7hl:armv6hl" },
    .{ .native = "armv8hl", .policy = "armv8hl:armv7hl:armv6hl" },
    .{ .native = "armv8l", .policy = "armv8l:armv7l:armv6l:armv5tejl:armv5tel:armv5tl:armv5l:armv4tl:armv4l:armv3l" },
    .{ .native = "armv7hnl", .policy = "armv7hnl:armv7hl:armv6hl" },
    .{ .native = "armv7hl", .policy = "armv7hl:armv6hl" },
    .{ .native = "armv7l", .policy = "armv7l:armv6l:armv5tejl:armv5tel:armv5tl:armv5l:armv4tl:armv4l:armv3l" },
    .{ .native = "armv6l", .policy = "armv6l:armv5tejl:armv5tel:armv5tl:armv5l:armv4tl:armv4l:armv3l" },
    .{ .native = "armv5tejl", .policy = "armv5tejl:armv5tel:armv5tl:armv5l:armv4tl:armv4l:armv3l" },
    .{ .native = "armv5tel", .policy = "armv5tel:armv5tl:armv5l:armv4tl:armv4l:armv3l" },
    .{ .native = "armv5tl", .policy = "armv5tl:armv5l:armv4tl:armv4l:armv3l" },
    .{ .native = "armv5l", .policy = "armv5l:armv4tl:armv4l:armv3l" },
    .{ .native = "armv4tl", .policy = "armv4tl:armv4l:armv3l" },
    .{ .native = "armv4l", .policy = "armv4l:armv3l" },
    .{ .native = "sh4a", .policy = "sh4a:sh4" },
    .{ .native = "sparc64v", .policy = "sparc64v:sparc64:sparcv9v:sparcv9:sparcv8:sparc" },
    .{ .native = "sparc64", .policy = "sparc64:sparcv9:sparcv8:sparc" },
    .{ .native = "sparcv9v", .policy = "sparcv9v:sparcv9:sparcv8:sparc" },
    .{ .native = "sparcv9", .policy = "sparcv9:sparcv8:sparc" },
    .{ .native = "sparcv8", .policy = "sparcv8:sparc" },
    .{ .native = "e2kv6", .policy = "e2kv6:e2kv5:e2kv4:e2k" },
    .{ .native = "e2kv5", .policy = "e2kv5:e2kv4:e2k" },
    .{ .native = "e2kv4", .policy = "e2kv4:e2k" },
};

pub fn architectureRank(
    native: []const u8,
    candidate: []const u8,
) ?usize {
    if (std.mem.eql(u8, candidate, "noarch")) return 0;
    if (native.len == 0 or candidate.len == 0) return null;

    var policy = native;
    for (architecture_entries) |entry| {
        if (std.mem.eql(u8, native, entry.native)) {
            policy = entry.policy;
            break;
        }
    }
    var architectures = std.mem.splitScalar(u8, policy, ':');
    var rank: usize = 1;
    while (architectures.next()) |architecture| {
        if (std.mem.eql(u8, architecture, candidate)) return rank;
        rank += 1;
    }
    return null;
}

fn architectureAllows(native: []const u8, candidate: []const u8) bool {
    return architectureRank(native, candidate) != null;
}

fn appendPackageId(
    map: *std.StringHashMap(PackageIdList),
    allocator: std.mem.Allocator,
    key: []const u8,
    package_id: solver_model.PackageId,
) error{OutOfMemory}!void {
    const gop = try map.getOrPut(key);
    if (!gop.found_existing) {
        gop.value_ptr.* = PackageIdList.init(allocator);
    }
    try gop.value_ptr.append(package_id);
}

fn appendUniquePackageId(
    map: *std.StringHashMap(PackageIdList),
    allocator: std.mem.Allocator,
    key: []const u8,
    package_id: solver_model.PackageId,
) error{OutOfMemory}!void {
    const gop = try map.getOrPut(key);
    if (!gop.found_existing) {
        gop.value_ptr.* = PackageIdList.init(allocator);
    }
    if (!containsPackage(gop.value_ptr.items, package_id)) {
        try gop.value_ptr.append(package_id);
    }
}

fn appendProvider(
    map: *std.StringHashMap(ProviderList),
    allocator: std.mem.Allocator,
    key: []const u8,
    provider: ProviderEntry,
) error{OutOfMemory}!void {
    const gop = try map.getOrPut(key);
    if (!gop.found_existing) {
        gop.value_ptr.* = ProviderList.init(allocator);
    }
    try gop.value_ptr.append(provider);
}

fn deinitPackageMap(map: *std.StringHashMap(PackageIdList)) void {
    var values = map.valueIterator();
    while (values.next()) |list| list.deinit();
    map.deinit();
}

fn deinitProviderMap(map: *std.StringHashMap(ProviderList)) void {
    var values = map.valueIterator();
    while (values.next()) |list| list.deinit();
    map.deinit();
}

fn sortAndDeduplicatePackageIds(packages: *PackageIdList) void {
    std.sort.heap(
        solver_model.PackageId,
        packages.items,
        {},
        packageIdLessThan,
    );
    var write_index: usize = 0;
    for (packages.items) |package_id| {
        if (write_index != 0 and packages.items[write_index - 1] == package_id) {
            continue;
        }
        packages.items[write_index] = package_id;
        write_index += 1;
    }
    packages.shrinkRetainingCapacity(write_index);
}

fn packageIdLessThan(
    _: void,
    left: solver_model.PackageId,
    right: solver_model.PackageId,
) bool {
    return @intFromEnum(left) < @intFromEnum(right);
}

fn literalLessThan(_: void, left: Literal, right: Literal) bool {
    return @intFromEnum(left) < @intFromEnum(right);
}

const checksum = "0000000000000000000000000000000000000000000000000000000000000000";

const TestPackage = struct {
    name: []const u8,
    version: []const u8 = "1",
    release: []const u8 = "1",
    arch: []const u8 = "x86_64",
    provides: []const metadata.Relation = &.{},
    requires: []const metadata.Relation = &.{},
    conflicts: []const metadata.Relation = &.{},
    obsoletes: []const metadata.Relation = &.{},
    recommends: []const metadata.Relation = &.{},
    suggests: []const metadata.Relation = &.{},
    supplements: []const metadata.Relation = &.{},
    enhances: []const metadata.Relation = &.{},
    files: []const metadata.FileEntry = &.{},
};

const TestRepository = struct {
    id: []const u8,
    kind: solver_model.RepositoryKind,
    packages: std.array_list.Managed(metadata.Package),
    relations: std.array_list.Managed(metadata.Relation),
    files: std.array_list.Managed(metadata.FileEntry),
    installed_states: std.array_list.Managed(solver_model.InstalledState),
};

const TestGraphBuilder = struct {
    allocator: std.mem.Allocator,
    repositories: std.array_list.Managed(TestRepository),

    fn init(allocator: std.mem.Allocator) TestGraphBuilder {
        return .{
            .allocator = allocator,
            .repositories = std.array_list.Managed(TestRepository).init(allocator),
        };
    }

    fn addRepository(
        self: *TestGraphBuilder,
        id: []const u8,
        kind: solver_model.RepositoryKind,
    ) !usize {
        const repository_index = self.repositories.items.len;
        try self.repositories.append(.{
            .id = id,
            .kind = kind,
            .packages = std.array_list.Managed(metadata.Package).init(self.allocator),
            .relations = std.array_list.Managed(metadata.Relation).init(self.allocator),
            .files = std.array_list.Managed(metadata.FileEntry).init(self.allocator),
            .installed_states = std.array_list.Managed(
                solver_model.InstalledState,
            ).init(self.allocator),
        });
        return repository_index;
    }

    fn addPackage(
        self: *TestGraphBuilder,
        repository_index: usize,
        spec: TestPackage,
    ) !solver_model.PackageId {
        var repository = &self.repositories.items[repository_index];
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
            .{ .kind = .suggests, .relations = spec.suggests },
            .{ .kind = .supplements, .relations = spec.supplements },
            .{ .kind = .enhances, .relations = spec.enhances },
        }) |entry| {
            package.rangePtr(entry.kind).* = .{
                .start = repository.relations.items.len,
                .len = entry.relations.len,
            };
            try repository.relations.appendSlice(entry.relations);
        }
        package.files = .{
            .start = repository.files.items.len,
            .len = spec.files.len,
        };
        try repository.files.appendSlice(spec.files);
        try repository.packages.append(package);
        if (repository.kind == .installed) {
            try repository.installed_states.append(.{
                .rpmdb_hnum = @intCast(repository.installed_states.items.len + 1),
                .reason = .user,
                .install_order = repository.installed_states.items.len + 1,
            });
        }
        return @enumFromInt(@as(u32, @intCast(
            totalPackages(self.repositories.items) - 1,
        )));
    }

    fn finish(
        self: *TestGraphBuilder,
        arena_state: *std.heap.ArenaAllocator,
    ) !TestGraph {
        const models = try self.allocator.alloc(
            metadata.RepositoryModel,
            self.repositories.items.len,
        );
        const inputs = try self.allocator.alloc(
            solver_model.RepositoryInput,
            self.repositories.items.len,
        );
        for (self.repositories.items, 0..) |*repository, repository_index| {
            models[repository_index] = .{
                .packages = try repository.packages.toOwnedSlice(),
                .relations = try repository.relations.toOwnedSlice(),
                .files = try repository.files.toOwnedSlice(),
            };
            inputs[repository_index] = .{
                .id = repository.id,
                .model = &models[repository_index],
                .kind = repository.kind,
                .installed_states = if (repository.kind == .installed)
                    try repository.installed_states.toOwnedSlice()
                else
                    &.{},
            };
        }
        return .{
            .arena_state = arena_state,
            .universe = try solver_model.Universe.init(self.allocator, inputs),
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

fn totalPackages(repositories: []const TestRepository) usize {
    var total: usize = 0;
    for (repositories) |repository| total += repository.packages.items.len;
    return total;
}

fn testArchitecture() solver_model.ArchitecturePolicy {
    return .{ .native_arch = "x86_64" };
}

fn testRelation(name: []const u8) metadata.Relation {
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

test "architecture rank follows libsolv policy order" {
    try std.testing.expectEqual(
        @as(?usize, 0),
        architectureRank("x86_64", "noarch"),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        architectureRank("x86_64", "x86_64"),
    );
    try std.testing.expectEqual(
        @as(?usize, 2),
        architectureRank("x86_64", "i686"),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        architectureRank("x86_64", "aarch64"),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        architectureRank("aarch64", "aarch64"),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        architectureRank("aarch64", "armv7hl"),
    );
}

test "RPM provider matching treats missing releases and unversioned provides compatibly" {
    const provider = metadata.Relation{
        .name = "library",
        .flags = "EQ",
        .comparison = .eq,
        .version = "1.0",
        .release = "2",
    };
    try std.testing.expect(rpmProvideMatches(
        provider,
        versionedRelation("library", .eq, "1.0"),
    ));
    try std.testing.expect(!rpmProvideMatches(
        provider,
        versionedRelation("library", .gt, "1.0"),
    ));
    try std.testing.expect(rpmProvideMatches(
        provider,
        versionedRelation("library", .ge, "1.0"),
    ));
    try std.testing.expect(!rpmProvideMatches(
        provider,
        .{
            .name = "library",
            .flags = "EQ",
            .comparison = .eq,
            .version = "1.0",
            .release = "3",
        },
    ));
    try std.testing.expect(rpmProvideMatches(
        testRelation("library"),
        versionedRelation("library", .eq, "999"),
    ));
}

fn findClause(
    formula: *const OwnedFormula,
    origin_tag: std.meta.Tag(RuleOrigin),
    package: solver_model.PackageId,
) ?Clause {
    for (formula.clauses) |clause| {
        if (std.meta.activeTag(clause.origin) != origin_tag) continue;
        const origin_package = switch (clause.origin) {
            .not_installable => |value| value,
            .requirement => |value| value.package,
            .conflict => |value| value.dependency.package,
            .obsoletes => |value| value.dependency.package,
            .same_name => |value| value.left,
            .installed_keep => |value| value,
            .job => continue,
        };
        if (origin_package == package) return clause;
    }
    return null;
}

fn assignmentSatisfies(
    formula: *const OwnedFormula,
    assignment: usize,
) bool {
    for (formula.clauses) |clause| {
        var satisfied = false;
        for (formula.clauseLiterals(clause)) |literal| {
            const selected = assignment &
                (@as(usize, 1) << @as(u6, @intCast(@intFromEnum(literal.package())))) != 0;
            if (selected == literal.positive()) {
                satisfied = true;
                break;
            }
        }
        if (!satisfied) return false;
    }
    return true;
}

test "literal round trips package and polarity" {
    const package_id: solver_model.PackageId = @enumFromInt(42);
    const positive = Literal.init(package_id, true);
    try std.testing.expectEqual(package_id, positive.package());
    try std.testing.expect(positive.positive());
    try std.testing.expectEqual(package_id, positive.negated().package());
    try std.testing.expect(!positive.negated().positive());
    try std.testing.expectEqual(positive, positive.negated().negated());
}

test "global providers include explicit self and file capabilities" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(available, .{
        .name = "explicit-provider",
        .provides = &.{versionedRelation("virtual-api", .eq, "2")},
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "self-provider",
        .version = "3",
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "file-provider",
        .files = &.{
            .{ .path = "/usr/bin/tool" },
            .{ .path = "/opt/unreferenced" },
        },
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{
            versionedRelation("virtual-api", .ge, "1"),
            versionedRelation("self-provider", .eq, "3"),
            testRelation("/usr/bin/tool"),
        },
    });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    var formula = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{
            .{
                .action = .install,
                .selection = .{ .capability = testRelation("/opt/unreferenced") },
            },
            .{
                .action = .install,
                .selection = .{ .capability = versionedRelation(
                    "/opt/unreferenced",
                    .eq,
                    "999",
                ) },
            },
        } },
        testArchitecture(),
    );
    defer formula.deinit();

    const consumer_id: solver_model.PackageId = @enumFromInt(3);
    var requirement_count: usize = 0;
    for (formula.clauses) |clause| {
        const dependency = switch (clause.origin) {
            .requirement => |value| value,
            else => continue,
        };
        if (dependency.package != consumer_id) continue;
        requirement_count += 1;
        const literals = formula.clauseLiterals(clause);
        try std.testing.expectEqual(@as(usize, 2), literals.len);
        try std.testing.expectEqual(consumer_id, literals[1].package());
        try std.testing.expect(!literals[1].positive());
    }
    try std.testing.expectEqual(@as(usize, 3), requirement_count);
    var missing_file_job_count: usize = 0;
    for (formula.clauses) |clause| {
        const job_id = switch (clause.origin) {
            .job => |value| value,
            else => continue,
        };
        if (@intFromEnum(job_id) <= 1) {
            const job_literals = formula.clauseLiterals(clause);
            if (job_literals.len == 0) missing_file_job_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), missing_file_job_count);
}

test "installed broken state and bad architecture match base boundaries" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try graph_builder.addRepository("@System", .installed);
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(installed, .{
        .name = "installed-bad-arch-provider",
        .arch = "s390x",
        .provides = &.{testRelation("installed-capability")},
        .requires = &.{testRelation("already-missing")},
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "available-bad-arch",
        .arch = "s390x",
        .provides = &.{testRelation("ignored-capability")},
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{
            testRelation("installed-capability"),
            testRelation("ignored-capability"),
        },
    });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    var formula = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer formula.deinit();

    const installed_id: solver_model.PackageId = @enumFromInt(0);
    const bad_available_id: solver_model.PackageId = @enumFromInt(1);
    const consumer_id: solver_model.PackageId = @enumFromInt(2);
    try std.testing.expect(
        findClause(&formula, .requirement, installed_id) == null,
    );
    const not_installable = findClause(
        &formula,
        .not_installable,
        bad_available_id,
    ) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(
        bad_available_id,
        formula.clauseLiterals(not_installable)[0].package(),
    );

    var saw_installed_provider = false;
    var saw_missing_provider = false;
    for (formula.clauses) |clause| {
        const dependency = switch (clause.origin) {
            .requirement => |value| value,
            else => continue,
        };
        if (dependency.package != consumer_id) continue;
        const literals = formula.clauseLiterals(clause);
        if (literals.len == 2) {
            saw_installed_provider =
                literals[0].package() == installed_id and literals[0].positive();
        } else if (literals.len == 1) {
            saw_missing_provider = true;
        }
    }
    try std.testing.expect(saw_installed_provider);
    try std.testing.expect(saw_missing_provider);
}

test "only versioned unknown rpmlib dependencies use the system provider" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(available, .{
        .name = "unversioned-consumer",
        .requires = &.{testRelation("rpmlib(UnversionedFeature)")},
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "versioned-consumer",
        .requires = &.{versionedRelation(
            "rpmlib(VersionedFeature)",
            .eq,
            "1",
        )},
    });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    var formula = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer formula.deinit();

    const unversioned_id: solver_model.PackageId = @enumFromInt(0);
    const missing_requirement = findClause(
        &formula,
        .requirement,
        unversioned_id,
    ) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(
        @as(usize, 1),
        formula.clauseLiterals(missing_requirement).len,
    );
    try std.testing.expect(
        findClause(&formula, .requirement, @enumFromInt(1)) == null,
    );
}

test "conflicts obsoletes and multiversion same-name rules retain origins" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try graph_builder.addRepository("@System", .installed);
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(installed, .{ .name = "old" });
    _ = try graph_builder.addPackage(available, .{
        .name = "replacement",
        .conflicts = &.{testRelation("peer")},
        .obsoletes = &.{testRelation("old")},
    });
    _ = try graph_builder.addPackage(available, .{ .name = "peer" });
    _ = try graph_builder.addPackage(available, .{
        .name = "parallel",
        .version = "1",
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "parallel",
        .version = "2",
    });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    const jobs = [_]solver_model.Job{
        .{ .action = .multiversion, .selection = .{ .package = @enumFromInt(3) } },
        .{ .action = .multiversion, .selection = .{ .package = @enumFromInt(4) } },
    };
    var formula = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &jobs },
        testArchitecture(),
    );
    defer formula.deinit();

    const replacement_id: solver_model.PackageId = @enumFromInt(1);
    try std.testing.expect(findClause(
        &formula,
        .conflict,
        replacement_id,
    ) != null);
    try std.testing.expect(findClause(
        &formula,
        .obsoletes,
        replacement_id,
    ) != null);
    for (formula.clauses) |clause| {
        if (std.meta.activeTag(clause.origin) != .same_name) continue;
        const origin = clause.origin.same_name;
        try std.testing.expect(
            !((origin.left == @as(solver_model.PackageId, @enumFromInt(3)) and
                origin.right == @as(solver_model.PackageId, @enumFromInt(4))) or
                (origin.left == @as(solver_model.PackageId, @enumFromInt(4)) and
                    origin.right == @as(solver_model.PackageId, @enumFromInt(3)))),
        );
    }
}

test "mechanical jobs emit clauses and preserve package policy state" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try graph_builder.addRepository("@System", .installed);
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(installed, .{ .name = "installed" });
    _ = try graph_builder.addPackage(available, .{
        .name = "installed",
        .version = "2",
    });
    _ = try graph_builder.addPackage(available, .{ .name = "requested" });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    const jobs = [_]solver_model.Job{
        .{ .action = .install, .selection = .{ .name = "requested" } },
        .{ .action = .erase, .selection = .{ .package = @enumFromInt(0) } },
        .{
            .action = .lock,
            .selection = .{ .package = @enumFromInt(2) },
            .flags = .{ .weak = true },
        },
        .{ .action = .user_installed, .selection = .{ .package = @enumFromInt(0) } },
        .{ .action = .allow_uninstall, .selection = .{ .package = @enumFromInt(0) } },
        .{
            .action = .erase,
            .selection = .{
                .capability = versionedRelation(
                    "rpmlib(EraseSystem)",
                    .eq,
                    "1",
                ),
            },
        },
        .{
            .action = .lock,
            .selection = .{
                .capability = versionedRelation(
                    "rpmlib(LockSystem)",
                    .eq,
                    "1",
                ),
            },
        },
    };
    var formula = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &jobs },
        testArchitecture(),
    );
    defer formula.deinit();

    try std.testing.expect(formula.packageState(@enumFromInt(0)).?.user_installed);
    try std.testing.expect(formula.packageState(@enumFromInt(0)).?.allow_uninstall);
    var saw_requested = false;
    var saw_erased = false;
    var saw_replacement_block = false;
    var saw_weak_lock = false;
    var system_job_failures: usize = 0;
    for (formula.clauses) |clause| {
        const job_id = switch (clause.origin) {
            .job => |value| @intFromEnum(value),
            else => continue,
        };
        const clause_literals = formula.clauseLiterals(clause);
        if (job_id == 0 and clause_literals.len == 1 and
            clause_literals[0] == Literal.init(@enumFromInt(2), true))
        {
            saw_requested = true;
        }
        if (job_id == 1 and clause_literals.len == 1) {
            if (clause_literals[0] == Literal.init(@enumFromInt(0), false)) {
                saw_erased = true;
            }
            if (clause_literals[0] == Literal.init(@enumFromInt(1), false)) {
                saw_replacement_block = true;
            }
        }
        if (job_id == 2 and clause.disposition == .relaxable_job) {
            saw_weak_lock = true;
        }
        if ((job_id == 5 or job_id == 6) and clause_literals.len == 0) {
            system_job_failures += 1;
        }
    }
    try std.testing.expect(saw_requested);
    try std.testing.expect(saw_erased);
    try std.testing.expect(saw_replacement_block);
    try std.testing.expect(saw_weak_lock);
    try std.testing.expectEqual(@as(usize, 2), system_job_failures);
}

test "update and distro sync mark installed replacement intent" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const installed = try graph_builder.addRepository("@System", .installed);
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(installed, .{ .name = "installed" });
    _ = try graph_builder.addPackage(available, .{
        .name = "installed",
        .version = "2",
    });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    inline for ([_]struct {
        action: solver_model.JobAction,
        kind: ReplacementKind,
    }{
        .{ .action = .update, .kind = .update },
        .{ .action = .dist_sync, .kind = .dist_sync },
    }) |entry| {
        var formula = try generateBase(
            std.testing.allocator,
            &graph.universe,
            .{ .jobs = &.{.{
                .action = entry.action,
                .selection = .all,
                .flags = .{ .force_best = true },
            }} },
            testArchitecture(),
        );
        defer formula.deinit();
        try std.testing.expectEqual(
            entry.kind,
            formula.package_states[0].replacement.kind,
        );
        try std.testing.expect(
            formula.package_states[0].replacement.force_best,
        );
        for (formula.clauses) |clause| {
            try std.testing.expect(std.meta.activeTag(clause.origin) != .job);
        }

        try std.testing.expectError(
            error.UnsupportedJob,
            generateBase(
                std.testing.allocator,
                &graph.universe,
                .{ .jobs = &.{.{
                    .action = entry.action,
                    .selection = .{ .name = "installed" },
                }} },
                testArchitecture(),
            ),
        );
        try std.testing.expectError(
            error.UnsupportedJob,
            generateBase(
                std.testing.allocator,
                &graph.universe,
                .{ .jobs = &.{.{
                    .action = entry.action,
                    .selection = .all,
                    .flags = .{ .clean_deps = true },
                }} },
                testArchitecture(),
            ),
        );
    }
}

test "weak metadata records deterministic descriptors without hard implications" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(available, .{ .name = "optional" });
    _ = try graph_builder.addPackage(available, .{
        .name = "consumer",
        .recommends = &.{testRelation("optional")},
        .supplements = &.{testRelation("optional")},
        .enhances = &.{versionedRelation(
            "rpmlib(SystemFeature)",
            .eq,
            "1",
        )},
    });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    var formula = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer formula.deinit();

    try std.testing.expectEqual(@as(usize, 3), formula.weak_requests.len);
    try std.testing.expectEqual(
        WeakDirection.forward,
        formula.weak_requests[0].direction,
    );
    try std.testing.expectEqual(
        WeakDirection.reverse,
        formula.weak_requests[1].direction,
    );
    try std.testing.expect(!formula.weak_requests[1].system_satisfied);
    try std.testing.expect(formula.weak_requests[2].system_satisfied);
    for (formula.clauses) |clause| {
        try std.testing.expect(
            std.meta.activeTag(clause.origin) != .requirement,
        );
    }
}

test "small formula agrees with independent exhaustive package semantics" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(available, .{
        .name = "provider-a",
        .provides = &.{testRelation("choice")},
        .conflicts = &.{testRelation("provider-b")},
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "provider-b",
        .provides = &.{testRelation("choice")},
    });
    _ = try graph_builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{testRelation("choice")},
    });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    var formula = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        testArchitecture(),
    );
    defer formula.deinit();

    for (0..(@as(usize, 1) << 3)) |assignment| {
        const provider_a = assignment & 1 != 0;
        const provider_b = assignment & 2 != 0;
        const consumer = assignment & 4 != 0;
        const expected = consumer and (provider_a or provider_b) and
            !(provider_a and provider_b);
        try std.testing.expectEqual(
            expected,
            assignmentSatisfies(&formula, assignment),
        );
    }
}

test "base generation is deterministic" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    var graph_builder = TestGraphBuilder.init(arena_state.allocator());
    const available = try graph_builder.addRepository("available", .available);
    _ = try graph_builder.addPackage(available, .{ .name = "provider" });
    _ = try graph_builder.addPackage(available, .{
        .name = "consumer",
        .requires = &.{testRelation("provider")},
    });
    var graph = try graph_builder.finish(&arena_state);
    defer graph.deinit();

    var first = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer first.deinit();
    var second = try generateBase(
        std.testing.allocator,
        &graph.universe,
        .{ .jobs = &.{} },
        testArchitecture(),
    );
    defer second.deinit();

    try std.testing.expectEqualDeep(first.clauses, second.clauses);
    try std.testing.expectEqualSlices(Literal, first.literals, second.literals);
    try std.testing.expectEqualDeep(first.weak_requests, second.weak_requests);
    try std.testing.expectEqualSlices(
        solver_model.PackageId,
        first.weak_candidates,
        second.weak_candidates,
    );
    try std.testing.expectEqualDeep(first.package_states, second.package_states);
}
