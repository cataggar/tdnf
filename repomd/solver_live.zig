//! Owning live-input adapter for strict native shadow solves.

const std = @import("std");
const available_loader = @import("available_loader.zig");
const installed_repository = @import("installed_repository.zig");
const solver_identity = @import("solver_identity.zig");
const solver_model = @import("solver_model.zig");
const solver_native = @import("solver_native.zig");
const solver_result_abi = @import("solver_result_abi.zig");
const solver_result_c = @import("solver_result_c.zig");
const solver_shadow = @import("solver_shadow.zig");
const solver_shadow_abi = @import("solver_shadow_abi.zig");
const solver_visibility = @import("solver_visibility.zig");

pub const system_repository_id = "@System";

pub const RepositoryInput = struct {
    id: []const u8,
    cache_dir: []const u8,
    snapshot_file: ?[]const u8 = null,
    priority: i32 = solver_model.default_repository_priority,
    cost: u32 = solver_model.default_repository_cost,
};

pub const JobInput = struct {
    selector: solver_identity.AvailableSelector,
};

pub const Input = struct {
    repositories: []const RepositoryInput,
    rpmdb: installed_repository.Source,
    native_arch: []const u8,
    jobs: []const JobInput,
    /// Null means the caller did not provide an authoritative considered map.
    hidden_available: ?[]const JobInput = null,
    include_installed: bool = true,
    best: bool = false,
    clean_deps: bool = false,
    skip_broken: bool = false,
};

pub const ProduceError =
    available_loader.LoadError ||
    installed_repository.LoadError ||
    solver_model.UniverseInitError ||
    solver_identity.InitError ||
    solver_identity.ResolveError ||
    solver_visibility.BuildError ||
    solver_native.ProjectedSolveError ||
    error{
        InvalidInput,
        UnsupportedInput,
    };

/// Move-only owner for every model used by a strict live shadow solve.
pub const OwnedSolve = struct {
    arena_state: std.heap.ArenaAllocator,
    universe: *solver_model.Universe,
    solved: solver_native.OwnedSolveResult,

    pub fn deinit(self: *OwnedSolve) void {
        self.solved.deinit();
        // Universe arrays share the enclosing arena and are released below.
        self.arena_state.deinit();
        self.* = undefined;
    }

    pub fn buildOwnedC(
        self: *const OwnedSolve,
    ) solver_result_c.BuildError!*solver_result_abi.Result {
        return self.solved.buildOwnedC();
    }
};

pub fn produce(
    parent_allocator: std.mem.Allocator,
    input: Input,
) ProduceError!OwnedSolve {
    if (input.repositories.len == 0 or
        input.jobs.len == 0 or
        input.native_arch.len == 0)
    {
        return error.InvalidInput;
    }

    var arena_state = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();
    const available_offset: usize = @intFromBool(input.include_installed);
    const repository_inputs = try arena.alloc(
        solver_model.RepositoryInput,
        input.repositories.len + available_offset,
    );
    const models = try arena.alloc(
        @import("model.zig").RepositoryModel,
        input.repositories.len + available_offset,
    );

    if (input.include_installed) {
        const installed = try installed_repository.loadModel(
            arena,
            input.rpmdb,
            .{
                .include_relations = true,
                .include_files = true,
                .include_changelogs = false,
            },
        );
        models[0] = installed.repository;
        repository_inputs[0] = .{
            .id = system_repository_id,
            .model = &models[0],
            .kind = .installed,
            .installed_states = installed.installed_states,
        };
    }

    for (input.repositories, models[available_offset..], 0..) |
        repository,
        *loaded,
        index,
    | {
        if (repository.id.len == 0 or
            repository.cache_dir.len == 0)
        {
            return error.InvalidInput;
        }
        if (repository.snapshot_file != null and
            input.hidden_available == null)
        {
            return error.UnsupportedInput;
        }
        if (repository.priority == std.math.minInt(i32)) {
            return error.UnsupportedInput;
        }
        loaded.* = try available_loader.loadCacheModel(
            arena,
            repository.cache_dir,
            .{
                .include_filelists = true,
                .include_updateinfo = false,
                .include_other = false,
            },
        );
        repository_inputs[index + available_offset] = .{
            .id = try arena.dupe(u8, repository.id),
            .model = loaded,
            .priority = repository.priority,
            .cost = repository.cost,
        };
    }

    const universe = try arena.create(solver_model.Universe);
    universe.* = try solver_model.Universe.init(arena, repository_inputs);
    errdefer universe.deinit();

    var identity = try solver_identity.Index.init(
        parent_allocator,
        universe,
    );
    defer identity.deinit();
    const jobs = try arena.alloc(solver_model.Job, input.jobs.len);
    for (input.jobs, jobs) |job, *translated| {
        translated.* = .{
            .action = .install,
            .selection = .{
                .package = try identity.resolveAvailable(job.selector),
            },
            .reason = .user,
        };
    }

    var visibility = if (input.hidden_available) |hidden| blk: {
        const considered = try arena.alloc(bool, universe.packages.len);
        @memset(considered, true);
        for (hidden) |item| {
            const package = try identity.resolveAvailable(item.selector);
            const package_index: usize = @intFromEnum(package);
            if (!considered[package_index]) return error.InvalidInput;
            considered[package_index] = false;
        }
        break :blk try solver_visibility.Projection.initConsidered(
            parent_allocator,
            universe,
            considered,
        );
    } else try solver_visibility.Projection.init(
        parent_allocator,
        universe,
        .{},
    );
    defer visibility.deinit();
    const native_arch = try arena.dupe(u8, input.native_arch);
    var solved = try solver_native.solveProjected(
        parent_allocator,
        universe,
        &visibility,
        .{ .jobs = jobs },
        .{
            .architecture = .{ .native_arch = native_arch },
            .best = input.best,
            .clean_deps = input.clean_deps,
            .skip_broken = input.skip_broken,
        },
    );
    errdefer solved.deinit();

    return .{
        .arena_state = arena_state,
        .universe = universe,
        .solved = solved,
    };
}

pub fn compare(
    parent_allocator: std.mem.Allocator,
    input: Input,
    legacy: *const solver_shadow_abi.LegacyResult,
    comparison: *solver_shadow_abi.Comparison,
) (ProduceError ||
    solver_result_c.BuildError ||
    solver_shadow.CompareError)!void {
    var solved = try produce(parent_allocator, input);
    defer solved.deinit();
    const native = try solved.buildOwnedC();
    defer solver_result_c.freeOwnedResult(native);
    try solver_shadow.compare(
        parent_allocator,
        native,
        legacy,
        comparison,
    );
}

const fixture_repomd =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<repomd xmlns="http://linux.duke.edu/metadata/repo">
    \\  <data type="primary">
    \\    <checksum type="sha256">f20a7a5300215ee0935c234e6dbb8cca7d8d2dbbed137fc002d502b0bfbd7f8a</checksum>
    \\    <location href="repodata/primary.xml"/>
    \\    <size>809</size>
    \\  </data>
    \\</repomd>
;

const fixture_primary =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">
    \\  <package type="rpm">
    \\    <name>candidate</name>
    \\    <arch>x86_64</arch>
    \\    <version epoch="0" ver="1.0" rel="1"/>
    \\    <checksum type="sha256" pkgid="YES">abcdef</checksum>
    \\    <summary>candidate</summary>
    \\    <location href="packages/candidate.rpm"/>
    \\  </package>
    \\  <package type="rpm">
    \\    <name>broken</name>
    \\    <arch>x86_64</arch>
    \\    <version epoch="0" ver="1.0" rel="1"/>
    \\    <checksum type="sha256" pkgid="YES">fedcba</checksum>
    \\    <summary>broken</summary>
    \\    <location href="packages/broken.rpm"/>
    \\    <format>
    \\      <rpm:requires>
    \\        <rpm:entry name="missing-capability"/>
    \\      </rpm:requires>
    \\    </format>
    \\  </package>
    \\</metadata>
;

const Fixture = struct {
    tmp: std.testing.TmpDir,

    fn create() !Fixture {
        var fixture = Fixture{ .tmp = std.testing.tmpDir(.{}) };
        errdefer fixture.tmp.cleanup();
        try fixture.tmp.dir.createDirPath(
            std.testing.io,
            "cache/repodata",
        );
        try fixture.tmp.dir.writeFile(
            std.testing.io,
            .{
                .sub_path = "cache/repodata/repomd.xml",
                .data = fixture_repomd,
            },
        );
        try fixture.tmp.dir.writeFile(
            std.testing.io,
            .{
                .sub_path = "cache/repodata/primary.xml",
                .data = fixture_primary,
            },
        );
        return fixture;
    }

    fn cleanup(self: *Fixture) void {
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn path(
        self: *const Fixture,
        buffer: *[std.Io.Dir.max_path_bytes]u8,
        suffix: []const u8,
    ) [:0]const u8 {
        return std.fmt.bufPrintZ(
            buffer,
            ".zig-cache/tmp/{s}/{s}",
            .{ &self.tmp.sub_path, suffix },
        ) catch @panic("fixture path too long");
    }
};

fn fixtureInput(
    fixture: *const Fixture,
    root_buffer: *[std.Io.Dir.max_path_bytes]u8,
    cache_buffer: *[std.Io.Dir.max_path_bytes]u8,
    repositories: *[1]RepositoryInput,
    jobs: *[1]JobInput,
) Input {
    repositories[0] = .{
        .id = "repo",
        .cache_dir = fixture.path(cache_buffer, "cache"),
    };
    jobs[0] = .{
        .selector = .{
            .repository = "repo",
            .name = "candidate",
            .epoch = null,
            .version = "1.0",
            .release = "1",
            .arch = "x86_64",
        },
    };
    return .{
        .repositories = repositories,
        .rpmdb = .{ .root_dir = fixture.path(root_buffer, "") },
        .native_arch = "x86_64",
        .jobs = jobs,
    };
}

test "live producer owns loaded inputs and exact install result" {
    var fixture = try Fixture.create();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var jobs: [1]JobInput = undefined;
    var solved = try produce(
        std.testing.allocator,
        fixtureInput(
            &fixture,
            &root_buffer,
            &cache_buffer,
            &repositories,
            &jobs,
        ),
    );
    fixture.cleanup();
    defer solved.deinit();

    try std.testing.expectEqual(
        @as(usize, 1),
        solved.solved.result.selected.len,
    );
    const selected = solved.universe.package(
        solved.solved.result.selected[0],
    ).?;
    try std.testing.expectEqualStrings(
        "candidate",
        selected.source.nevra.name,
    );
    const c_result = try solved.buildOwnedC();
    defer solver_result_c.freeOwnedResult(c_result);
    try std.testing.expectEqual(
        @as(u32, 1),
        c_result.dwSelectedPackageCount,
    );
}

test "live producer can omit the installed repository" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var jobs: [1]JobInput = undefined;
    var input = fixtureInput(
        &fixture,
        &root_buffer,
        &cache_buffer,
        &repositories,
        &jobs,
    );
    input.rpmdb = .{ .root_dir = "/native-solver-alldeps-no-rpmdb" };
    input.include_installed = false;
    var solved = try produce(std.testing.allocator, input);
    defer solved.deinit();

    try std.testing.expectEqual(@as(usize, 1), solved.universe.repositories.len);
    try std.testing.expectEqual(
        solver_model.RepositoryKind.available,
        solved.universe.repositories[0].kind,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        solved.solved.result.selected.len,
    );
}

test "live producer accepts force-best and clean-deps policy" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var jobs: [1]JobInput = undefined;
    var input = fixtureInput(
        &fixture,
        &root_buffer,
        &cache_buffer,
        &repositories,
        &jobs,
    );
    input.best = true;
    input.clean_deps = true;
    var solved = try produce(std.testing.allocator, input);
    defer solved.deinit();

    try std.testing.expectEqual(
        @as(usize, 1),
        solved.solved.result.selected.len,
    );
}

test "live producer records broken exact jobs under skip-broken policy" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var base_jobs: [1]JobInput = undefined;
    var input = fixtureInput(
        &fixture,
        &root_buffer,
        &cache_buffer,
        &repositories,
        &base_jobs,
    );
    var jobs = [_]JobInput{
        base_jobs[0],
        .{ .selector = .{
            .repository = "repo",
            .name = "broken",
            .epoch = null,
            .version = "1.0",
            .release = "1",
            .arch = "x86_64",
        } },
    };
    input.jobs = &jobs;
    input.skip_broken = true;
    var solved = try produce(std.testing.allocator, input);
    defer solved.deinit();

    try std.testing.expectEqual(
        @as(usize, 1),
        solved.solved.result.outcome.skipped_jobs.len,
    );
    try std.testing.expectEqual(
        @as(solver_model.JobId, @enumFromInt(1)),
        solved.solved.result.outcome.skipped_jobs[0],
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        solved.solved.result.selected.len,
    );
}

test "live comparison observes the exact legacy install projection" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var jobs: [1]JobInput = undefined;
    const input = fixtureInput(
        &fixture,
        &root_buffer,
        &cache_buffer,
        &repositories,
        &jobs,
    );
    var legacy_package = std.mem.zeroes(
        solver_shadow_abi.LegacyPackage,
    );
    legacy_package.pszName = "candidate";
    legacy_package.pszRepoName = "repo";
    legacy_package.pszVersion = "1.0";
    legacy_package.pszRelease = "1";
    legacy_package.pszArch = "x86_64";
    var legacy = std.mem.zeroes(solver_shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_package);
    var comparison = std.mem.zeroes(solver_shadow_abi.Comparison);

    try compare(
        std.testing.allocator,
        input,
        &legacy,
        &comparison,
    );
    try std.testing.expectEqual(@as(u32, 1), comparison.dwStatus);
}

test "live producer fails closed on unsupported and ambiguous input" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var jobs: [1]JobInput = undefined;
    const input = fixtureInput(
        &fixture,
        &root_buffer,
        &cache_buffer,
        &repositories,
        &jobs,
    );
    var repository = input.repositories[0];
    repository.snapshot_file = "snapshot";
    repositories[0] = repository;
    try std.testing.expectError(
        error.UnsupportedInput,
        produce(std.testing.allocator, input),
    );

    repository.snapshot_file = null;
    repository.cost = solver_model.default_repository_cost + 1;
    repositories[0] = repository;
    try std.testing.expectError(
        error.UnsupportedRepositoryCost,
        produce(std.testing.allocator, input),
    );

    repository.cost = solver_model.default_repository_cost;
    repository.priority = std.math.minInt(i32);
    repositories[0] = repository;
    try std.testing.expectError(
        error.UnsupportedInput,
        produce(std.testing.allocator, input),
    );

    repository.priority = solver_model.default_repository_priority;
    repositories[0] = repository;
    var job = input.jobs[0];
    job.selector.name = "missing";
    jobs[0] = job;
    try std.testing.expectError(
        error.PackageNotFound,
        produce(std.testing.allocator, input),
    );
}

test "live producer applies an authoritative considered projection" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var jobs: [1]JobInput = undefined;
    var input = fixtureInput(
        &fixture,
        &root_buffer,
        &cache_buffer,
        &repositories,
        &jobs,
    );
    input.hidden_available = input.jobs;
    try std.testing.expectError(
        error.Unsatisfiable,
        produce(std.testing.allocator, input),
    );

    var repository = input.repositories[0];
    repository.snapshot_file = "authoritative-considered";
    repositories[0] = repository;
    input.hidden_available = &.{};
    var solved = try produce(std.testing.allocator, input);
    defer solved.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        solved.solved.result.selected.len,
    );

    input.hidden_available = &.{ jobs[0], jobs[0] };
    try std.testing.expectError(
        error.InvalidInput,
        produce(std.testing.allocator, input),
    );
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    input: Input,
) !void {
    var solved = try produce(allocator, input);
    defer solved.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        solved.solved.result.selected.len,
    );
}

fn comparisonAllocationFailureCase(
    allocator: std.mem.Allocator,
    input: Input,
    legacy: *const solver_shadow_abi.LegacyResult,
) !void {
    var comparison = std.mem.zeroes(solver_shadow_abi.Comparison);
    try compare(allocator, input, legacy, &comparison);
    try std.testing.expectEqual(@as(u32, 1), comparison.dwStatus);
}

test "live producer cleans every allocation failure" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var jobs: [1]JobInput = undefined;
    var input = fixtureInput(
        &fixture,
        &root_buffer,
        &cache_buffer,
        &repositories,
        &jobs,
    );
    input.hidden_available = &.{};
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{input},
    );
}

test "live comparison cleans every allocation failure" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var cache_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var repositories: [1]RepositoryInput = undefined;
    var jobs: [1]JobInput = undefined;
    var input = fixtureInput(
        &fixture,
        &root_buffer,
        &cache_buffer,
        &repositories,
        &jobs,
    );
    input.hidden_available = &.{};
    var legacy_package = std.mem.zeroes(
        solver_shadow_abi.LegacyPackage,
    );
    legacy_package.pszName = "candidate";
    legacy_package.pszRepoName = "repo";
    legacy_package.pszVersion = "1.0";
    legacy_package.pszRelease = "1";
    legacy_package.pszArch = "x86_64";
    var legacy = std.mem.zeroes(solver_shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_package);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        comparisonAllocationFailureCase,
        .{ input, &legacy },
    );
}
