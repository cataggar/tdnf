const std = @import("std");
const builtin = @import("builtin");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");

const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("tdnfrepomd.h");
});

pub const BuildError = error{
    InvalidInput,
    OutOfMemory,
};

pub const Input = struct {
    universe: *const solver_model.Universe,
    job_count: usize,
    selected: []const solver_model.PackageId,
    outcome: *const solver_model.Outcome,
};

const invalid_package_ref = std.math.maxInt(u32);

var alloc_test_enabled = false;
var alloc_test_fail_after: ?usize = null;
var alloc_test_call_count: usize = 0;
var alloc_test_active_count: usize = 0;

pub fn buildOwned(input: Input) BuildError!*c.TDNF_REPOMD_NATIVE_SOLVER_RESULT {
    const package_total = input.universe.packages.len;
    _ = try countU32(package_total);
    const selected_count = try countU32(input.selected.len);
    const action_count = try countU32(input.outcome.actions.len);
    const problem_count = try countU32(input.outcome.problems.len);
    const skipped_count = try countU32(input.outcome.skipped_jobs.len);

    const referenced_raw = try callocArray(u8, package_total);
    defer freeAllocation(referenced_raw);
    const referenced: []u8 = if (referenced_raw != null)
        referenced_raw[0..package_total]
    else
        @constCast(&[_]u8{});

    for (input.selected) |package_id| {
        try markPackage(input.universe, referenced, package_id, false);
    }

    var prior_count: u32 = 0;
    for (input.outcome.actions) |action| {
        try markPackage(input.universe, referenced, action.package, false);
        prior_count = std.math.add(
            u32,
            prior_count,
            try countU32(action.priors.len),
        ) catch return error.InvalidInput;
        for (action.priors) |prior| {
            try markPackage(input.universe, referenced, prior, true);
        }
        if (action.requested_by) |job_id| {
            try validateJobId(input.job_count, job_id);
        }
    }

    for (input.outcome.problems) |problem| {
        if (problem.package) |package_id| {
            try markPackage(input.universe, referenced, package_id, false);
        }
        if (problem.related_package) |package_id| {
            try markPackage(input.universe, referenced, package_id, false);
        }
        if (problem.job) |job_id| {
            try validateJobId(input.job_count, job_id);
        }
        if (problem.capability) |relation| {
            try validateRelation(relation);
        }
    }

    for (input.outcome.skipped_jobs) |job_id| {
        try validateJobId(input.job_count, job_id);
    }

    var package_count: u32 = 0;
    for (referenced, 0..) |is_referenced, package_index| {
        if (is_referenced == 0) continue;
        const package = &input.universe.packages[package_index];
        const repository = input.universe.repository(package.repository) orelse
            return error.InvalidInput;
        try validatePackage(repository, package.source);
        package_count = std.math.add(u32, package_count, 1) catch
            return error.InvalidInput;
    }

    const package_refs_raw = try callocArray(u32, package_total);
    defer freeAllocation(package_refs_raw);
    const package_refs: []u32 = if (package_refs_raw != null)
        package_refs_raw[0..package_total]
    else
        @constCast(&[_]u32{});
    @memset(package_refs, invalid_package_ref);

    const result = try callocOne(c.TDNF_REPOMD_NATIVE_SOLVER_RESULT);
    result.dwPackageCount = package_count;
    result.dwSelectedPackageCount = selected_count;
    result.dwActionCount = action_count;
    result.dwPriorPackageRefCount = prior_count;
    result.dwProblemCount = problem_count;
    result.dwSkippedJobCount = skipped_count;
    errdefer freeOwned(result);

    result.pPackages = try callocArray(
        c.TDNF_REPOMD_NATIVE_SOLVER_PACKAGE,
        package_count,
    );
    result.pdwSelectedPackageRefs = try callocArray(u32, selected_count);
    result.pActions = try callocArray(
        c.TDNF_REPOMD_NATIVE_SOLVER_ACTION,
        action_count,
    );
    result.pdwPriorPackageRefs = try callocArray(u32, prior_count);
    result.pdwPriorHnums = try callocArray(u32, prior_count);
    result.pProblems = try callocArray(
        c.TDNF_REPOMD_NATIVE_SOLVER_PROBLEM,
        problem_count,
    );
    result.pdwSkippedJobIds = try callocArray(u32, skipped_count);

    var package_ref: u32 = 0;
    for (referenced, 0..) |is_referenced, package_index| {
        if (is_referenced == 0) continue;
        package_refs[package_index] = package_ref;
        try fillPackage(
            @ptrCast(&result.pPackages[package_ref]),
            input.universe,
            &input.universe.packages[package_index],
        );
        package_ref += 1;
    }

    for (input.selected, 0..) |package_id, index| {
        result.pdwSelectedPackageRefs[index] = try getPackageRef(
            package_refs,
            package_id,
        );
    }

    var prior_offset: u32 = 0;
    for (input.outcome.actions, 0..) |action, index| {
        const out: *c.TDNF_REPOMD_NATIVE_SOLVER_ACTION =
            @ptrCast(&result.pActions[index]);
        out.dwPackageRef = try getPackageRef(package_refs, action.package);
        out.dwKind = mapActionKind(action.kind);
        out.dwReason = mapActionReason(action.reason);
        out.dwPriorOffset = prior_offset;
        out.dwPriorCount = @intCast(action.priors.len);
        if (action.requested_by) |job_id| {
            out.dwRequestedJobId = @intFromEnum(job_id);
            out.nHasRequestedJobId = 1;
        }
        for (action.priors) |prior| {
            result.pdwPriorPackageRefs[prior_offset] = try getPackageRef(
                package_refs,
                prior,
            );
            result.pdwPriorHnums[prior_offset] = input.universe
                .package(prior).?.installed.?.rpmdb_hnum;
            prior_offset += 1;
        }
    }

    for (input.outcome.problems, 0..) |problem, index| {
        const out: *c.TDNF_REPOMD_NATIVE_SOLVER_PROBLEM =
            @ptrCast(&result.pProblems[index]);
        out.dwKind = mapProblemKind(problem.kind);
        out.dwCount = problem.count;
        if (problem.package) |package_id| {
            out.dwPackageRef = try getPackageRef(package_refs, package_id);
            out.nHasPackageRef = 1;
        }
        if (problem.related_package) |package_id| {
            out.dwRelatedPackageRef = try getPackageRef(
                package_refs,
                package_id,
            );
            out.nHasRelatedPackageRef = 1;
        }
        if (problem.capability) |relation| {
            try fillRelation(&out.capability, relation);
            out.nHasCapability = 1;
        }
        if (problem.job) |job_id| {
            out.dwJobId = @intFromEnum(job_id);
            out.nHasJobId = 1;
        }
    }

    for (input.outcome.skipped_jobs, 0..) |job_id, index| {
        result.pdwSkippedJobIds[index] = @intFromEnum(job_id);
    }

    return result;
}

pub fn freeOwnedResult(
    result: ?*c.TDNF_REPOMD_NATIVE_SOLVER_RESULT,
) void {
    freeOwned(result);
}

fn fillPackage(
    out: *c.TDNF_REPOMD_NATIVE_SOLVER_PACKAGE,
    universe: *const solver_model.Universe,
    package: *const solver_model.UniversePackage,
) BuildError!void {
    const repository = universe.repository(package.repository) orelse
        return error.InvalidInput;
    const source = package.source;

    out.pszRepository = try dupCString(repository.name);
    out.pszName = try dupCString(source.nevra.name);
    out.pszVersion = try dupCString(source.nevra.version);
    out.pszRelease = try dupCString(source.nevra.release);
    out.pszArch = try dupCString(source.nevra.arch);
    out.pszChecksumType = try dupCString(source.checksum.kind);
    out.pszChecksumValue = try dupCString(source.checksum.value);
    out.pszLocationHref = try dupCString(source.location.href);
    out.pszLocationBase = try dupOptionalCString(source.location.xml_base);
    out.pszSummary = try dupOptionalCString(source.summary);
    out.dwPackageId = @intFromEnum(package.id);
    out.dwRepositoryId = @intFromEnum(package.repository);
    out.nRepositoryKind = mapRepositoryKind(repository.kind);
    if (source.nevra.epoch) |epoch| {
        out.dwEpoch = epoch;
        out.nHasEpoch = 1;
    }
    if (package.installed) |installed| {
        out.dwRpmDbHnum = installed.rpmdb_hnum;
        out.nHasRpmDbHnum = 1;
    }
    out.nChecksumIsPkgId = @intFromBool(source.checksum.is_pkgid);
    if (source.size.package) |size| {
        out.nPackageSize = size;
        out.nHasPackageSize = 1;
    }
    if (source.size.installed) |size| {
        out.nInstalledSize = size;
        out.nHasInstalledSize = 1;
    }
}

fn fillRelation(
    out: *c.TDNF_REPOMD_NATIVE_SOLVER_RELATION,
    relation: metadata.Relation,
) BuildError!void {
    out.pszName = try dupCString(relation.name);
    out.pszVersion = try dupOptionalCString(relation.version);
    out.pszRelease = try dupOptionalCString(relation.release);
    out.pszFlags = try dupOptionalCString(relation.flags);
    out.dwComparison = mapComparison(relation.comparison);
    if (relation.epoch) |epoch| {
        out.dwEpoch = epoch;
        out.nHasEpoch = 1;
    }
    out.dwSense = relation.sense;
    out.nPre = @intFromBool(relation.pre);
}

fn validatePackage(
    repository: *const solver_model.UniverseRepository,
    package: *const metadata.Package,
) BuildError!void {
    try validateCString(repository.name);
    try validateCString(package.nevra.name);
    try validateCString(package.nevra.version);
    try validateCString(package.nevra.release);
    try validateCString(package.nevra.arch);
    try validateCString(package.checksum.kind);
    try validateCString(package.checksum.value);
    try validateCString(package.location.href);
    try validateOptionalCString(package.location.xml_base);
    try validateOptionalCString(package.summary);
}

fn validateRelation(relation: metadata.Relation) BuildError!void {
    try validateCString(relation.name);
    try validateOptionalCString(relation.version);
    try validateOptionalCString(relation.release);
    try validateOptionalCString(relation.flags);
}

fn validateCString(text: []const u8) BuildError!void {
    if (std.mem.indexOfScalar(u8, text, 0) != null) {
        return error.InvalidInput;
    }
}

fn validateOptionalCString(text: ?[]const u8) BuildError!void {
    if (text) |value| try validateCString(value);
}

fn markPackage(
    universe: *const solver_model.Universe,
    referenced: []u8,
    package_id: solver_model.PackageId,
    require_installed: bool,
) BuildError!void {
    const package = universe.package(package_id) orelse
        return error.InvalidInput;
    if (require_installed and package.installed == null) {
        return error.InvalidInput;
    }
    referenced[@intFromEnum(package_id)] = 1;
}

fn validateJobId(
    job_count: usize,
    job_id: solver_model.JobId,
) BuildError!void {
    if (@intFromEnum(job_id) >= job_count) return error.InvalidInput;
}

fn getPackageRef(
    package_refs: []const u32,
    package_id: solver_model.PackageId,
) BuildError!u32 {
    const package_index = @intFromEnum(package_id);
    if (package_index >= package_refs.len) return error.InvalidInput;
    const package_ref = package_refs[package_index];
    if (package_ref == invalid_package_ref) return error.InvalidInput;
    return package_ref;
}

fn countU32(count: usize) BuildError!u32 {
    return std.math.cast(u32, count) orelse error.InvalidInput;
}

fn mapActionKind(kind: solver_model.ActionKind) u32 {
    return switch (kind) {
        .install => 1,
        .erase => 2,
        .upgrade => 3,
        .downgrade => 4,
        .reinstall => 5,
        .obsolete => 6,
    };
}

fn mapActionReason(reason: solver_model.TransactionReason) u32 {
    return switch (reason) {
        .user => 1,
        .dependency => 2,
        .weak_dependency => 3,
        .cleanup => 4,
        .obsoletes => 5,
        .installonly_limit => 6,
        .policy => 7,
    };
}

fn mapProblemKind(kind: solver_model.ProblemKind) u32 {
    return switch (kind) {
        .unsatisfied_requirement => 1,
        .conflict => 2,
        .obsoletes => 3,
        .no_candidate => 4,
        .not_installable => 5,
        .protected_package => 6,
        .installonly_limit => 7,
    };
}

fn mapRepositoryKind(kind: solver_model.RepositoryKind) c_int {
    return switch (kind) {
        .installed => 1,
        .available => 2,
        .command_line => 3,
    };
}

fn mapComparison(comparison: metadata.CompareOp) u32 {
    return switch (comparison) {
        .none => 0,
        .eq => 1,
        .lt => 2,
        .le => 3,
        .gt => 4,
        .ge => 5,
    };
}

fn callocOne(comptime T: type) BuildError!*T {
    const raw = adapterCalloc(1, @sizeOf(T)) orelse
        return error.OutOfMemory;
    return @ptrCast(@alignCast(raw));
}

fn callocArray(comptime T: type, count: usize) BuildError![*c]T {
    if (count == 0) return null;
    if (count > std.math.maxInt(usize) / @sizeOf(T)) {
        return error.OutOfMemory;
    }
    const raw = adapterCalloc(count, @sizeOf(T)) orelse
        return error.OutOfMemory;
    return @ptrCast(@alignCast(raw));
}

fn dupCString(text: []const u8) BuildError![*:0]const u8 {
    const size = std.math.add(usize, text.len, 1) catch
        return error.OutOfMemory;
    const raw = adapterCalloc(size, 1) orelse return error.OutOfMemory;
    const out: [*:0]u8 = @ptrCast(raw);
    @memcpy(out[0..text.len], text);
    out[text.len] = 0;
    return out;
}

fn dupOptionalCString(
    text: ?[]const u8,
) BuildError!?[*:0]const u8 {
    if (text) |value| return try dupCString(value);
    return null;
}

fn freeOwned(
    result_raw: ?*c.TDNF_REPOMD_NATIVE_SOLVER_RESULT,
) void {
    const result = result_raw orelse return;
    if (result.pProblems != null) {
        for (result.pProblems[0..result.dwProblemCount]) |problem| {
            freeCString(problem.capability.pszName);
            freeCString(problem.capability.pszVersion);
            freeCString(problem.capability.pszRelease);
            freeCString(problem.capability.pszFlags);
        }
        freeAllocation(result.pProblems);
    }
    if (result.pPackages != null) {
        for (result.pPackages[0..result.dwPackageCount]) |package| {
            freeCString(package.pszRepository);
            freeCString(package.pszName);
            freeCString(package.pszVersion);
            freeCString(package.pszRelease);
            freeCString(package.pszArch);
            freeCString(package.pszChecksumType);
            freeCString(package.pszChecksumValue);
            freeCString(package.pszLocationHref);
            freeCString(package.pszLocationBase);
            freeCString(package.pszSummary);
        }
        freeAllocation(result.pPackages);
    }
    freeAllocation(result.pdwSelectedPackageRefs);
    freeAllocation(result.pActions);
    freeAllocation(result.pdwPriorPackageRefs);
    freeAllocation(result.pdwPriorHnums);
    freeAllocation(result.pdwSkippedJobIds);
    freeAllocation(result);
}

fn freeCString(text: ?[*:0]const u8) void {
    if (text) |value| {
        freeAllocation(@constCast(value));
    }
}

fn adapterCalloc(count: usize, size: usize) ?*anyopaque {
    if (builtin.is_test and alloc_test_enabled) {
        const call_index = alloc_test_call_count;
        alloc_test_call_count += 1;
        if (alloc_test_fail_after) |fail_after| {
            if (call_index == fail_after) return null;
        }
    }

    const raw = c.calloc(count, size);
    if (raw != null and builtin.is_test and alloc_test_enabled) {
        alloc_test_active_count += 1;
    }
    return raw;
}

fn freeAllocation(pointer_raw: ?*anyopaque) void {
    const pointer = pointer_raw orelse return;
    c.free(pointer);
    if (builtin.is_test and alloc_test_enabled) {
        std.debug.assert(alloc_test_active_count > 0);
        alloc_test_active_count -= 1;
    }
}

const TestFixture = struct {
    installed_name: [7]u8 = "library".*,
    summary: [9]u8 = "new build".*,
    relation_name: [11]u8 = "library-api".*,
    installed_packages: [1]metadata.Package = undefined,
    available_packages: [1]metadata.Package = undefined,
    installed_states: [1]solver_model.InstalledState = .{.{
        .rpmdb_hnum = 42,
        .reason = .user,
    }},
    installed_model: metadata.RepositoryModel = undefined,
    available_model: metadata.RepositoryModel = undefined,
    universe: solver_model.Universe = undefined,
    priors: [1]solver_model.PackageId = .{@enumFromInt(0)},
    selected: [1]solver_model.PackageId = .{@enumFromInt(1)},
    actions: [1]solver_model.Action = undefined,
    problems: [1]solver_model.Problem = undefined,
    skipped_jobs: [1]solver_model.JobId = .{@enumFromInt(1)},
    outcome: solver_model.Outcome = undefined,

    fn init(self: *TestFixture, allocator: std.mem.Allocator) !void {
        self.installed_packages = .{.{
            .pkg_id = "installed-library",
            .nevra = .{
                .name = &self.installed_name,
                .epoch = 1,
                .version = "1",
                .release = "1",
                .arch = "x86_64",
            },
            .checksum = .{
                .kind = "sha256",
                .value = "installed",
                .is_pkgid = true,
            },
            .size = .{
                .package = 100,
                .installed = 200,
            },
            .location = .{ .href = "old.rpm" },
        }};
        self.available_packages = .{.{
            .pkg_id = "available-library",
            .nevra = .{
                .name = "library",
                .epoch = 1,
                .version = "2",
                .release = "1",
                .arch = "x86_64",
            },
            .checksum = .{
                .kind = "sha256",
                .value = "available",
                .is_pkgid = true,
            },
            .summary = &self.summary,
            .size = .{
                .package = 300,
                .installed = 400,
            },
            .location = .{
                .href = "new.rpm",
                .xml_base = "packages",
            },
        }};
        self.installed_model = .{ .packages = &self.installed_packages };
        self.available_model = .{ .packages = &self.available_packages };
        self.actions = .{.{
            .kind = .upgrade,
            .package = @enumFromInt(1),
            .priors = &self.priors,
            .reason = .policy,
            .requested_by = @enumFromInt(0),
        }};
        self.problems = .{.{
            .kind = .conflict,
            .package = @enumFromInt(1),
            .related_package = @enumFromInt(0),
            .capability = .{
                .name = &self.relation_name,
                .comparison = .ge,
                .epoch = 1,
                .version = "2",
                .release = "1",
                .flags = "GE",
                .pre = true,
                .sense = 7,
            },
            .job = @enumFromInt(0),
        }};
        self.outcome = .{
            .actions = &self.actions,
            .problems = &self.problems,
            .skipped_jobs = &self.skipped_jobs,
        };
        self.universe = try solver_model.Universe.init(
            allocator,
            &.{
                .{
                    .id = "installed",
                    .model = &self.installed_model,
                    .kind = .installed,
                    .installed_states = &self.installed_states,
                },
                .{
                    .id = "available",
                    .model = &self.available_model,
                },
            },
        );
    }

    fn deinit(self: *TestFixture) void {
        self.universe.deinit();
    }

    fn input(self: *TestFixture) Input {
        return .{
            .universe = &self.universe,
            .job_count = 2,
            .selected = &self.selected,
            .outcome = &self.outcome,
        };
    }
};

test "C adapter owns canonical package action problem and skipped-job data" {
    var fixture: TestFixture = .{};
    try fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const result = try buildOwned(fixture.input());
    defer freeOwnedResult(result);

    try std.testing.expectEqual(@as(u32, 2), result.dwPackageCount);
    try std.testing.expectEqual(@as(u32, 1), result.dwSelectedPackageCount);
    try std.testing.expectEqual(@as(u32, 1), result.dwActionCount);
    try std.testing.expectEqual(@as(u32, 1), result.dwPriorPackageRefCount);
    try std.testing.expectEqual(@as(u32, 1), result.dwProblemCount);
    try std.testing.expectEqual(@as(u32, 1), result.dwSkippedJobCount);
    try std.testing.expectEqual(@as(u32, 1), result.pdwSelectedPackageRefs[0]);

    const installed = result.pPackages[0];
    try std.testing.expectEqual(@as(c_int, 1), installed.nRepositoryKind);
    try std.testing.expectEqual(@as(c_int, 1), installed.nHasRpmDbHnum);
    try std.testing.expectEqual(@as(u32, 42), installed.dwRpmDbHnum);
    try std.testing.expectEqualStrings(
        "library",
        std.mem.span(installed.pszName),
    );

    const available = result.pPackages[1];
    try std.testing.expectEqualStrings(
        "new build",
        std.mem.span(available.pszSummary),
    );
    try std.testing.expectEqual(@as(u64, 300), available.nPackageSize);
    try std.testing.expectEqual(@as(c_int, 1), available.nHasPackageSize);

    const action = result.pActions[0];
    try std.testing.expectEqual(@as(u32, 1), action.dwPackageRef);
    try std.testing.expectEqual(@as(u32, 3), action.dwKind);
    try std.testing.expectEqual(@as(u32, 7), action.dwReason);
    try std.testing.expectEqual(@as(c_int, 1), action.nHasRequestedJobId);
    try std.testing.expectEqual(
        @as(u32, 0),
        result.pdwPriorPackageRefs[action.dwPriorOffset],
    );
    try std.testing.expectEqual(
        @as(u32, 42),
        result.pdwPriorHnums[action.dwPriorOffset],
    );

    const problem = result.pProblems[0];
    try std.testing.expectEqual(@as(u32, 2), problem.dwKind);
    try std.testing.expectEqual(@as(c_int, 1), problem.nHasCapability);
    try std.testing.expectEqual(@as(u32, 5), problem.capability.dwComparison);
    try std.testing.expectEqualStrings(
        "library-api",
        std.mem.span(problem.capability.pszName),
    );
    try std.testing.expectEqual(@as(u32, 1), result.pdwSkippedJobIds[0]);

    fixture.installed_name[0] = 'X';
    fixture.summary[0] = 'X';
    fixture.relation_name[0] = 'X';
    try std.testing.expectEqualStrings(
        "library",
        std.mem.span(installed.pszName),
    );
    try std.testing.expectEqualStrings(
        "new build",
        std.mem.span(available.pszSummary),
    );
    try std.testing.expectEqualStrings(
        "library-api",
        std.mem.span(problem.capability.pszName),
    );
}

test "C adapter rejects invalid exact prior and job identities" {
    var fixture: TestFixture = .{};
    try fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const available_prior = [_]solver_model.PackageId{@enumFromInt(1)};
    const actions = [_]solver_model.Action{.{
        .kind = .upgrade,
        .package = @enumFromInt(1),
        .priors = &available_prior,
        .reason = .policy,
    }};
    var outcome = solver_model.Outcome{
        .actions = &actions,
        .problems = &.{},
        .skipped_jobs = &.{},
    };
    try std.testing.expectError(error.InvalidInput, buildOwned(.{
        .universe = &fixture.universe,
        .job_count = 0,
        .selected = &.{@enumFromInt(1)},
        .outcome = &outcome,
    }));

    outcome = .{
        .actions = &.{},
        .problems = &.{},
        .skipped_jobs = &.{@enumFromInt(0)},
    };
    try std.testing.expectError(error.InvalidInput, buildOwned(.{
        .universe = &fixture.universe,
        .job_count = 0,
        .selected = &.{},
        .outcome = &outcome,
    }));

    try std.testing.expectError(error.InvalidInput, buildOwned(.{
        .universe = &fixture.universe,
        .job_count = 0,
        .selected = &.{@enumFromInt(99)},
        .outcome = &outcome,
    }));
}

test "C adapter rejects strings containing an embedded NUL" {
    var fixture: TestFixture = .{};
    try fixture.init(std.testing.allocator);
    defer fixture.deinit();

    fixture.available_packages[0].summary = "bad\x00summary";
    const selected = [_]solver_model.PackageId{@enumFromInt(1)};
    const outcome = solver_model.Outcome{
        .actions = &.{},
        .problems = &.{},
        .skipped_jobs = &.{},
    };
    try std.testing.expectError(error.InvalidInput, buildOwned(.{
        .universe = &fixture.universe,
        .job_count = 0,
        .selected = &selected,
        .outcome = &outcome,
    }));
}

test "C adapter cleans every partial allocation failure" {
    var fixture: TestFixture = .{};
    try fixture.init(std.testing.allocator);
    defer fixture.deinit();

    alloc_test_enabled = true;
    defer {
        alloc_test_enabled = false;
        alloc_test_fail_after = null;
        alloc_test_call_count = 0;
        alloc_test_active_count = 0;
    }

    var fail_after: usize = 0;
    while (true) : (fail_after += 1) {
        alloc_test_fail_after = fail_after;
        alloc_test_call_count = 0;
        alloc_test_active_count = 0;

        const result = buildOwned(fixture.input()) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 0), alloc_test_active_count);
            continue;
        };
        freeOwnedResult(result);
        try std.testing.expectEqual(@as(usize, 0), alloc_test_active_count);
        break;
    }
}

test "C adapter represents an empty outcome with null arrays" {
    const repository_model = metadata.RepositoryModel{};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{
            .id = "available",
            .model = &repository_model,
        }},
    );
    defer universe.deinit();
    const outcome = solver_model.Outcome{
        .actions = &.{},
        .problems = &.{},
        .skipped_jobs = &.{},
    };

    const result = try buildOwned(.{
        .universe = &universe,
        .job_count = 0,
        .selected = &.{},
        .outcome = &outcome,
    });
    defer freeOwnedResult(result);

    try std.testing.expectEqual(@as(u32, 0), result.dwPackageCount);
    try std.testing.expectEqual(@as(u32, 0), result.dwActionCount);
    try std.testing.expectEqual(@as(u32, 0), result.dwProblemCount);
    try std.testing.expect(result.pPackages == null);
    try std.testing.expect(result.pdwSelectedPackageRefs == null);
    try std.testing.expect(result.pActions == null);
    try std.testing.expect(result.pdwPriorPackageRefs == null);
    try std.testing.expect(result.pdwPriorHnums == null);
    try std.testing.expect(result.pProblems == null);
    try std.testing.expect(result.pdwSkippedJobIds == null);
}

test "native solver result free accepts null" {
    freeOwnedResult(null);
}
