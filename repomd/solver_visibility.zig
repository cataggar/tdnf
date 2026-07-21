const std = @import("std");
const model = @import("model.zig");
const query_index = @import("index.zig");
const solver_model = @import("solver_model.zig");

pub const NameEvr = struct {
    name: []const u8,
    epoch: ?u32,
    version: []const u8,
    release: ?[]const u8,
};

pub const Snapshot = struct {
    repository: []const u8,
    /// An explicitly configured snapshot with no entries hides the repository.
    entries: []const NameEvr,
};

/// Locks are intentionally absent because they remain solver jobs.
pub const Policy = struct {
    snapshots: []const Snapshot = &.{},
    exclude_name_patterns: []const []const u8 = &.{},
    minimum_versions: []const NameEvr = &.{},
};

pub const HiddenReason = packed struct {
    snapshot: bool = false,
    exclude: bool = false,
    minimum_version: bool = false,

    pub fn any(self: HiddenReason) bool {
        return self.snapshot or self.exclude or self.minimum_version;
    }
};

pub const BuildError = error{
    OutOfMemory,
    InvalidSnapshot,
    DuplicateSnapshotRepository,
    UnknownSnapshotRepository,
    SnapshotRepositoryNotAvailable,
    InvalidExcludePattern,
    InvalidMinimumVersion,
};

/// Move-only PackageId-aligned visibility projection.
pub const Projection = struct {
    allocator: std.mem.Allocator,
    visible: []const bool,
    hidden_reasons: []const HiddenReason,

    pub fn init(
        allocator: std.mem.Allocator,
        universe: *const solver_model.Universe,
        policy: Policy,
    ) BuildError!Projection {
        try validatePolicy(universe, policy);

        const visible = try allocator.alloc(bool, universe.packages.len);
        errdefer allocator.free(visible);
        const hidden_reasons = try allocator.alloc(
            HiddenReason,
            universe.packages.len,
        );
        errdefer allocator.free(hidden_reasons);

        for (universe.packages, visible, hidden_reasons) |
            package,
            *is_visible,
            *reasons,
        | {
            const repository = universe.repository(package.repository) orelse
                unreachable;
            reasons.* = .{};

            if (repository.kind == .available) {
                if (snapshotForRepository(
                    policy.snapshots,
                    repository.name,
                )) |snapshot| {
                    reasons.snapshot = !matchesAnyNameEvr(
                        package.source,
                        snapshot.entries,
                    );
                }
            }
            for (policy.exclude_name_patterns) |pattern| {
                if (query_index.nameMatchesPattern(
                    pattern,
                    package.source.nevra.name,
                    .{},
                )) {
                    reasons.exclude = true;
                }
            }
            for (policy.minimum_versions) |minimum| {
                if (!std.mem.eql(
                    u8,
                    package.source.nevra.name,
                    minimum.name,
                )) {
                    continue;
                }
                if (comparePackageNameEvr(package.source, minimum) < 0) {
                    reasons.minimum_version = true;
                }
            }
            is_visible.* = !reasons.any();
        }

        return .{
            .allocator = allocator,
            .visible = visible,
            .hidden_reasons = hidden_reasons,
        };
    }

    pub fn deinit(self: *Projection) void {
        self.allocator.free(self.hidden_reasons);
        self.allocator.free(self.visible);
        self.* = undefined;
    }

    pub fn isVisible(
        self: *const Projection,
        package: solver_model.PackageId,
    ) ?bool {
        const index: usize = @intFromEnum(package);
        if (index >= self.visible.len) return null;
        return self.visible[index];
    }

    pub fn hiddenReason(
        self: *const Projection,
        package: solver_model.PackageId,
    ) ?HiddenReason {
        const index: usize = @intFromEnum(package);
        if (index >= self.hidden_reasons.len) return null;
        return self.hidden_reasons[index];
    }
};

fn validatePolicy(
    universe: *const solver_model.Universe,
    policy: Policy,
) BuildError!void {
    for (policy.snapshots, 0..) |snapshot, snapshot_index| {
        if (snapshot.repository.len == 0) return error.InvalidSnapshot;
        for (policy.snapshots[0..snapshot_index]) |previous| {
            if (std.mem.eql(
                u8,
                previous.repository,
                snapshot.repository,
            )) {
                return error.DuplicateSnapshotRepository;
            }
        }
        const repository = findRepository(universe, snapshot.repository) orelse
            return error.UnknownSnapshotRepository;
        if (repository.kind != .available) {
            return error.SnapshotRepositoryNotAvailable;
        }
        for (snapshot.entries) |entry| {
            if (!validNameEvr(entry)) return error.InvalidSnapshot;
        }
    }
    for (policy.exclude_name_patterns) |pattern| {
        if (std.mem.trim(u8, pattern, " \t\r\n").len == 0) {
            return error.InvalidExcludePattern;
        }
    }
    for (policy.minimum_versions) |minimum| {
        if (!validNameEvr(minimum)) {
            return error.InvalidMinimumVersion;
        }
    }
}

fn validNameEvr(value: NameEvr) bool {
    return value.name.len != 0 and value.version.len != 0;
}

fn findRepository(
    universe: *const solver_model.Universe,
    name: []const u8,
) ?*const solver_model.UniverseRepository {
    for (universe.repositories) |*repository| {
        if (std.mem.eql(u8, repository.name, name)) return repository;
    }
    return null;
}

fn snapshotForRepository(
    snapshots: []const Snapshot,
    repository: []const u8,
) ?Snapshot {
    for (snapshots) |snapshot| {
        if (std.mem.eql(u8, snapshot.repository, repository)) {
            return snapshot;
        }
    }
    return null;
}

fn matchesAnyNameEvr(
    package: *const model.Package,
    entries: []const NameEvr,
) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, package.nevra.name, entry.name) and
            comparePackageNameEvr(package, entry) == 0)
        {
            return true;
        }
    }
    return false;
}

fn comparePackageNameEvr(
    package: *const model.Package,
    value: NameEvr,
) i32 {
    return query_index.compareEvr(
        package.nevra.epoch,
        package.nevra.version,
        if (package.nevra.release.len == 0)
            null
        else
            package.nevra.release,
        value.epoch,
        value.version,
        value.release,
    );
}

fn testPackage(
    name: []const u8,
    epoch: ?u32,
    version: []const u8,
    release: []const u8,
    arch: []const u8,
) model.Package {
    return .{
        .pkg_id = name,
        .nevra = .{
            .name = name,
            .epoch = epoch,
            .version = version,
            .release = release,
            .arch = arch,
        },
        .checksum = .{
            .kind = "sha256",
            .value = name,
            .is_pkgid = true,
        },
        .location = .{},
    };
}

fn findPackage(
    universe: *const solver_model.Universe,
    repository_name: []const u8,
    name: []const u8,
    arch: []const u8,
) solver_model.PackageId {
    for (universe.packages) |package| {
        const repository = universe.repository(package.repository) orelse
            unreachable;
        if (std.mem.eql(u8, repository.name, repository_name) and
            std.mem.eql(u8, package.source.nevra.name, name) and
            std.mem.eql(u8, package.source.nevra.arch, arch))
        {
            return package.id;
        }
    }
    unreachable;
}

test "visibility composes snapshots excludes and minimum versions" {
    var installed_packages = [_]model.Package{
        testPackage("foo", null, "0.5", "1", "x86_64"),
        testPackage("keep", null, "1.0", "1", "x86_64"),
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
        .{ .rpmdb_hnum = 2 },
    };
    var repository_a_packages = [_]model.Package{
        testPackage("foo", null, "1.0", "1", "x86_64"),
        testPackage("foo", null, "1.0", "1", "noarch"),
        testPackage("bar", null, "1.0", "1", "x86_64"),
        testPackage("other", null, "1.0", "1", "x86_64"),
    };
    var repository_b_packages = [_]model.Package{
        testPackage("foo", null, "1.0", "1", "x86_64"),
        testPackage("baz", null, "1.0", "1", "x86_64"),
    };
    const inputs = [_]solver_model.RepositoryInput{
        .{
            .id = "@System",
            .model = &.{ .packages = &installed_packages },
            .kind = .installed,
            .installed_states = &installed_states,
        },
        .{
            .id = "repo-a",
            .model = &.{ .packages = &repository_a_packages },
        },
        .{
            .id = "repo-b",
            .model = &.{ .packages = &repository_b_packages },
        },
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();

    const repository_a_snapshot = [_]NameEvr{
        .{
            .name = "foo",
            .epoch = null,
            .version = "1.0",
            .release = "1",
        },
        .{
            .name = "bar",
            .epoch = null,
            .version = "1.0",
            .release = "1",
        },
    };
    const minimum_versions = [_]NameEvr{.{
        .name = "foo",
        .epoch = null,
        .version = "1.0",
        .release = "1",
    }};
    var projection = try Projection.init(
        std.testing.allocator,
        &universe,
        .{
            .snapshots = &.{
                .{
                    .repository = "repo-a",
                    .entries = &repository_a_snapshot,
                },
                .{
                    .repository = "repo-b",
                    .entries = &.{},
                },
            },
            .exclude_name_patterns = &.{"ba?"},
            .minimum_versions = &minimum_versions,
        },
    );
    defer projection.deinit();

    const installed_foo = findPackage(
        &universe,
        "@System",
        "foo",
        "x86_64",
    );
    try std.testing.expect(!projection.isVisible(installed_foo).?);
    const installed_reason = projection.hiddenReason(installed_foo).?;
    try std.testing.expect(installed_reason.minimum_version);
    try std.testing.expect(!installed_reason.snapshot);
    try std.testing.expect(!installed_reason.exclude);
    try std.testing.expect(projection.isVisible(findPackage(
        &universe,
        "@System",
        "keep",
        "x86_64",
    )).?);

    try std.testing.expect(projection.isVisible(findPackage(
        &universe,
        "repo-a",
        "foo",
        "x86_64",
    )).?);
    try std.testing.expect(projection.isVisible(findPackage(
        &universe,
        "repo-a",
        "foo",
        "noarch",
    )).?);
    const bar = findPackage(&universe, "repo-a", "bar", "x86_64");
    try std.testing.expect(!projection.isVisible(bar).?);
    try std.testing.expect(projection.hiddenReason(bar).?.exclude);
    try std.testing.expect(!projection.hiddenReason(bar).?.snapshot);
    const other = findPackage(
        &universe,
        "repo-a",
        "other",
        "x86_64",
    );
    try std.testing.expect(!projection.isVisible(other).?);
    try std.testing.expect(projection.hiddenReason(other).?.snapshot);

    const repository_b_foo = findPackage(
        &universe,
        "repo-b",
        "foo",
        "x86_64",
    );
    try std.testing.expect(!projection.isVisible(repository_b_foo).?);
    try std.testing.expect(
        projection.hiddenReason(repository_b_foo).?.snapshot,
    );
    const baz = findPackage(&universe, "repo-b", "baz", "x86_64");
    const baz_reason = projection.hiddenReason(baz).?;
    try std.testing.expect(!projection.isVisible(baz).?);
    try std.testing.expect(baz_reason.snapshot);
    try std.testing.expect(baz_reason.exclude);
}

test "visibility rejects invalid snapshot and policy inputs" {
    var installed_packages = [_]model.Package{
        testPackage("installed", null, "1", "1", "x86_64"),
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 1 },
    };
    var available_packages = [_]model.Package{
        testPackage("available", null, "1", "1", "x86_64"),
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

    try std.testing.expectError(
        error.DuplicateSnapshotRepository,
        Projection.init(std.testing.allocator, &universe, .{
            .snapshots = &.{
                .{ .repository = "repo", .entries = &.{} },
                .{ .repository = "repo", .entries = &.{} },
            },
        }),
    );
    try std.testing.expectError(
        error.UnknownSnapshotRepository,
        Projection.init(std.testing.allocator, &universe, .{
            .snapshots = &.{
                .{ .repository = "missing", .entries = &.{} },
            },
        }),
    );
    try std.testing.expectError(
        error.SnapshotRepositoryNotAvailable,
        Projection.init(std.testing.allocator, &universe, .{
            .snapshots = &.{
                .{ .repository = "@System", .entries = &.{} },
            },
        }),
    );
    try std.testing.expectError(
        error.InvalidExcludePattern,
        Projection.init(std.testing.allocator, &universe, .{
            .exclude_name_patterns = &.{" \t"},
        }),
    );
    try std.testing.expectError(
        error.InvalidMinimumVersion,
        Projection.init(std.testing.allocator, &universe, .{
            .minimum_versions = &.{.{
                .name = "available",
                .epoch = null,
                .version = "",
                .release = null,
            }},
        }),
    );
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
) !void {
    var projection = try Projection.init(
        allocator,
        universe,
        .{ .exclude_name_patterns = &.{"package*"} },
    );
    defer projection.deinit();
    try std.testing.expectEqual(
        universe.packages.len,
        projection.visible.len,
    );
}

test "visibility projection cleans every allocation failure" {
    var packages = [_]model.Package{
        testPackage("package-one", null, "1", "1", "x86_64"),
        testPackage("package-two", null, "1", "1", "x86_64"),
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

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{&universe},
    );
}
