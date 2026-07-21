const std = @import("std");
const metadata = @import("model.zig");

pub const RepositoryId = enum(u32) { _ };
pub const PackageId = enum(u32) { _ };
pub const JobId = enum(u32) { _ };

/// Temporary bound for the first exact-install skip-broken policy slice.
pub const max_skip_broken_jobs: usize = 64;

pub const RepositoryKind = enum {
    installed,
    available,
    command_line,
};

pub const default_repository_priority: i32 = 50;
pub const default_repository_cost: u32 = 1000;

pub const InstallReason = enum {
    unknown,
    user,
    automatic,
};

pub const InstalledState = struct {
    rpmdb_hnum: u32,
    reason: InstallReason = .unknown,
    install_order: u64 = 0,
};

pub const RepositoryInput = struct {
    id: []const u8,
    model: *const metadata.RepositoryModel,
    kind: RepositoryKind = .available,
    /// Lower values are preferred, matching tdnf repository priority.
    priority: i32 = default_repository_priority,
    cost: u32 = default_repository_cost,
    installed_states: []const InstalledState = &.{},
};

pub const PackageRange = struct {
    start: u32 = 0,
    len: u32 = 0,

    pub fn slice(
        self: PackageRange,
        packages: []const UniversePackage,
    ) []const UniversePackage {
        const start: usize = @intCast(self.start);
        const len: usize = @intCast(self.len);
        return packages[start .. start + len];
    }
};

pub const UniverseRepository = struct {
    id: RepositoryId,
    input_index: u32,
    name: []const u8,
    kind: RepositoryKind,
    priority: i32,
    cost: u32,
    source: *const metadata.RepositoryModel,
    packages: PackageRange,
};

pub const UniversePackage = struct {
    id: PackageId,
    repository: RepositoryId,
    repository_package_index: u32,
    source: *const metadata.Package,
    installed: ?InstalledState,

    pub fn relationEntries(
        self: UniversePackage,
        universe: *const Universe,
        kind: metadata.DependencyKind,
    ) []const metadata.Relation {
        const repository = universe.repository(self.repository) orelse unreachable;
        return self.source.relationsFor(kind, repository.source.relations);
    }

    pub fn fileEntries(
        self: UniversePackage,
        universe: *const Universe,
    ) []const metadata.FileEntry {
        const repository = universe.repository(self.repository) orelse unreachable;
        return self.source.fileEntries(repository.source.files);
    }
};

pub const UniverseInitError = error{
    OutOfMemory,
    DuplicateRepositoryId,
    MultipleInstalledRepositories,
    InstalledStateCountMismatch,
    UnexpectedInstalledState,
    TooManyRepositories,
    TooManyPackages,
};

/// A deterministic view over borrowed repository models.
///
/// The input repository models, their package metadata, repository IDs, and
/// all strings referenced by them must outlive the universe.
pub const Universe = struct {
    allocator: std.mem.Allocator,
    repositories: []const UniverseRepository,
    packages: []const UniversePackage,
    input_to_repository: []const RepositoryId,

    pub fn init(
        allocator: std.mem.Allocator,
        inputs: []const RepositoryInput,
    ) UniverseInitError!Universe {
        if (inputs.len > std.math.maxInt(u32)) {
            return error.TooManyRepositories;
        }

        var installed_count: usize = 0;
        var package_count: usize = 0;
        for (inputs, 0..) |input, input_index| {
            for (inputs[0..input_index]) |prior| {
                if (std.mem.eql(u8, input.id, prior.id)) {
                    return error.DuplicateRepositoryId;
                }
            }

            if (input.model.packages.len > std.math.maxInt(u32) or
                package_count > std.math.maxInt(u32) - input.model.packages.len)
            {
                return error.TooManyPackages;
            }
            package_count += input.model.packages.len;

            switch (input.kind) {
                .installed => {
                    installed_count += 1;
                    if (installed_count > 1) {
                        return error.MultipleInstalledRepositories;
                    }
                    if (input.installed_states.len != input.model.packages.len) {
                        return error.InstalledStateCountMismatch;
                    }
                },
                .available, .command_line => {
                    if (input.installed_states.len != 0) {
                        return error.UnexpectedInstalledState;
                    }
                },
            }
        }

        const repositories = try allocator.alloc(UniverseRepository, inputs.len);
        errdefer allocator.free(repositories);
        const packages = try allocator.alloc(UniversePackage, package_count);
        errdefer allocator.free(packages);
        const input_to_repository = try allocator.alloc(RepositoryId, inputs.len);
        errdefer allocator.free(input_to_repository);

        var repository_cursor: usize = 0;
        var package_cursor: usize = 0;
        for ([_]bool{ true, false }) |installed_pass| {
            for (inputs, 0..) |input, input_index| {
                if ((input.kind == .installed) != installed_pass) {
                    continue;
                }

                const repository_id: RepositoryId =
                    @enumFromInt(@as(u32, @intCast(repository_cursor)));
                input_to_repository[input_index] = repository_id;
                repositories[repository_cursor] = .{
                    .id = repository_id,
                    .input_index = @intCast(input_index),
                    .name = input.id,
                    .kind = input.kind,
                    .priority = input.priority,
                    .cost = input.cost,
                    .source = input.model,
                    .packages = .{
                        .start = @intCast(package_cursor),
                        .len = @intCast(input.model.packages.len),
                    },
                };

                for (input.model.packages, 0..) |*source_package, package_index| {
                    const package_id: PackageId =
                        @enumFromInt(@as(u32, @intCast(package_cursor)));
                    packages[package_cursor] = .{
                        .id = package_id,
                        .repository = repository_id,
                        .repository_package_index = @intCast(package_index),
                        .source = source_package,
                        .installed = if (input.kind == .installed)
                            input.installed_states[package_index]
                        else
                            null,
                    };
                    package_cursor += 1;
                }
                repository_cursor += 1;
            }
        }

        return .{
            .allocator = allocator,
            .repositories = repositories,
            .packages = packages,
            .input_to_repository = input_to_repository,
        };
    }

    pub fn deinit(self: *Universe) void {
        self.allocator.free(self.input_to_repository);
        self.allocator.free(self.packages);
        self.allocator.free(self.repositories);
        self.* = undefined;
    }

    pub fn repository(
        self: *const Universe,
        id: RepositoryId,
    ) ?*const UniverseRepository {
        const index: usize = @intFromEnum(id);
        if (index >= self.repositories.len) {
            return null;
        }
        return &self.repositories[index];
    }

    pub fn repositoryForInput(
        self: *const Universe,
        input_index: usize,
    ) ?*const UniverseRepository {
        if (input_index >= self.input_to_repository.len) {
            return null;
        }
        return self.repository(self.input_to_repository[input_index]);
    }

    pub fn package(
        self: *const Universe,
        id: PackageId,
    ) ?*const UniversePackage {
        const index: usize = @intFromEnum(id);
        if (index >= self.packages.len) {
            return null;
        }
        return &self.packages[index];
    }

    pub fn packagesInRepository(
        self: *const Universe,
        id: RepositoryId,
    ) ?[]const UniversePackage {
        const source_repository = self.repository(id) orelse return null;
        return source_repository.packages.slice(self.packages);
    }
};

pub const Selection = union(enum) {
    all,
    package: PackageId,
    name: []const u8,
    capability: metadata.Relation,
};

pub const JobAction = enum {
    install,
    erase,
    update,
    downgrade,
    dist_sync,
    reinstall,
    lock,
    multiversion,
    user_installed,
    allow_uninstall,
};

pub const RequestReason = enum {
    user,
    dependency,
    weak_dependency,
    cleanup,
    installonly_limit,
    policy,
};

pub const JobFlags = struct {
    clean_deps: bool = false,
    force_best: bool = false,
    targeted: bool = false,
    not_by_user: bool = false,
    weak: bool = false,
};

pub const Job = struct {
    action: JobAction,
    selection: Selection,
    flags: JobFlags = .{},
    reason: RequestReason = .user,
};

pub const Goal = struct {
    jobs: []const Job,
};

pub const ArchitecturePolicy = struct {
    native_arch: []const u8,
    force_arch: ?[]const u8 = null,
    allow_multilib: bool = true,
};

pub const SolvePolicy = struct {
    architecture: ArchitecturePolicy,
    best: bool = false,
    allow_erasing: bool = false,
    skip_broken: bool = false,
    clean_deps: bool = false,
    install_weak_deps: bool = true,
    keep_orphans: bool = true,
    installonly_limit: u32 = 0,
    protected_names: []const []const u8 = &.{},
    installonly_names: []const []const u8 = &.{},
};

pub const ActionKind = enum {
    install,
    upgrade,
    downgrade,
    erase,
    reinstall,
    obsolete,
};

pub const TransactionReason = enum {
    user,
    dependency,
    weak_dependency,
    cleanup,
    obsoletes,
    installonly_limit,
    policy,
};

pub const Action = struct {
    package: PackageId,
    priors: []const PackageId = &.{},
    kind: ActionKind,
    reason: TransactionReason,
    requested_by: ?JobId = null,
};

pub const ProblemKind = enum {
    unsatisfied_requirement,
    conflict,
    obsoletes,
    no_candidate,
    not_installable,
    protected_package,
    installonly_limit,
};

pub const Problem = struct {
    kind: ProblemKind,
    package: ?PackageId = null,
    related_package: ?PackageId = null,
    capability: ?metadata.Relation = null,
    job: ?JobId = null,
    count: u32 = 0,
};

pub const Outcome = struct {
    actions: []const Action,
    problems: []const Problem,
    skipped_jobs: []const JobId,
};

fn testPackage(name: []const u8, arch: []const u8) metadata.Package {
    return .{
        .pkg_id = name,
        .nevra = .{
            .name = name,
            .version = "1.0",
            .release = "1",
            .arch = arch,
        },
        .checksum = .{
            .kind = "sha256",
            .value = name,
            .is_pkgid = true,
        },
        .location = .{
            .href = name,
        },
    };
}

test "universe assigns installed packages first and preserves repository order" {
    var installed_packages = [_]metadata.Package{
        testPackage("installed-a", "x86_64"),
        testPackage("installed-b", "noarch"),
    };
    var available_packages = [_]metadata.Package{
        testPackage("available-a", "x86_64"),
    };
    var command_line_packages = [_]metadata.Package{
        testPackage("command-line-a", "x86_64"),
    };
    const installed_states = [_]InstalledState{
        .{ .rpmdb_hnum = 41, .reason = .user, .install_order = 10 },
        .{ .rpmdb_hnum = 42, .reason = .automatic, .install_order = 11 },
    };
    const installed_model = metadata.RepositoryModel{
        .packages = &installed_packages,
    };
    const available_model = metadata.RepositoryModel{
        .packages = &available_packages,
    };
    const command_line_model = metadata.RepositoryModel{
        .packages = &command_line_packages,
    };

    var universe = try Universe.init(std.testing.allocator, &.{
        .{
            .id = "available",
            .model = &available_model,
            .priority = 20,
            .cost = 500,
        },
        .{
            .id = "installed",
            .model = &installed_model,
            .kind = .installed,
            .installed_states = &installed_states,
        },
        .{
            .id = "command-line",
            .model = &command_line_model,
            .kind = .command_line,
        },
    });
    defer universe.deinit();

    try std.testing.expectEqual(@as(usize, 3), universe.repositories.len);
    try std.testing.expectEqualStrings("installed", universe.repositories[0].name);
    try std.testing.expectEqualStrings("available", universe.repositories[1].name);
    try std.testing.expectEqualStrings("command-line", universe.repositories[2].name);
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(universe.repositories[0].id));
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(universe.repositories[1].id));
    try std.testing.expectEqual(@as(u32, 2), @intFromEnum(universe.repositories[2].id));
    try std.testing.expectEqual(@as(u32, 1), universe.repositories[0].input_index);
    try std.testing.expectEqual(@as(u32, 0), universe.repositories[1].input_index);
    try std.testing.expectEqual(@as(u32, 2), universe.repositories[2].input_index);
    try std.testing.expectEqual(@as(u32, 0), universe.repositories[0].packages.start);
    try std.testing.expectEqual(@as(u32, 2), universe.repositories[0].packages.len);
    try std.testing.expectEqual(@as(u32, 2), universe.repositories[1].packages.start);
    try std.testing.expectEqual(@as(u32, 1), universe.repositories[1].packages.len);
    try std.testing.expectEqual(@as(u32, 3), universe.repositories[2].packages.start);
    try std.testing.expectEqual(@as(u32, 1), universe.repositories[2].packages.len);
    try std.testing.expectEqual(@as(i32, 20), universe.repositories[1].priority);
    try std.testing.expectEqual(@as(u32, 500), universe.repositories[1].cost);
    try std.testing.expectEqual(
        default_repository_priority,
        universe.repositories[2].priority,
    );

    try std.testing.expectEqual(@as(usize, 4), universe.packages.len);
    try std.testing.expectEqualStrings("installed-a", universe.packages[0].source.nevra.name);
    try std.testing.expectEqualStrings("installed-b", universe.packages[1].source.nevra.name);
    try std.testing.expectEqualStrings("available-a", universe.packages[2].source.nevra.name);
    try std.testing.expectEqualStrings("command-line-a", universe.packages[3].source.nevra.name);
    try std.testing.expectEqual(@as(u32, 41), universe.packages[0].installed.?.rpmdb_hnum);
    try std.testing.expectEqual(InstallReason.automatic, universe.packages[1].installed.?.reason);
    try std.testing.expect(universe.packages[2].installed == null);
    for (universe.packages, 0..) |package, package_index| {
        try std.testing.expectEqual(
            @as(u32, @intCast(package_index)),
            @intFromEnum(package.id),
        );
    }
    try std.testing.expectEqual(
        universe.repositories[0].id,
        universe.packages[0].repository,
    );
    try std.testing.expectEqual(
        universe.repositories[0].id,
        universe.packages[1].repository,
    );
    try std.testing.expectEqual(
        universe.repositories[1].id,
        universe.packages[2].repository,
    );
    try std.testing.expectEqual(
        universe.repositories[2].id,
        universe.packages[3].repository,
    );
    try std.testing.expectEqual(@as(u32, 0), universe.packages[0].repository_package_index);
    try std.testing.expectEqual(@as(u32, 1), universe.packages[1].repository_package_index);
    try std.testing.expectEqual(@as(u32, 0), universe.packages[2].repository_package_index);
    try std.testing.expectEqual(@as(u32, 0), universe.packages[3].repository_package_index);

    try std.testing.expectEqualStrings(
        "available",
        universe.repositoryForInput(0).?.name,
    );
    try std.testing.expectEqualStrings(
        "installed",
        universe.repositoryForInput(1).?.name,
    );
    try std.testing.expectEqual(@as(usize, 2), universe.packagesInRepository(
        universe.repositories[0].id,
    ).?.len);
}

test "universe packages borrow metadata from their own repositories" {
    var first_relations = [_]metadata.Relation{
        .{ .name = "first-capability", .comparison = .ge, .version = "2" },
    };
    var second_relations = [_]metadata.Relation{
        .{ .name = "second-capability", .comparison = .eq, .version = "3" },
    };
    var first_files = [_]metadata.FileEntry{
        .{ .path = "/usr/bin/first-tool" },
    };
    var second_files = [_]metadata.FileEntry{
        .{ .path = "/usr/bin/second-tool" },
    };
    var first_packages = [_]metadata.Package{
        testPackage("first-provider", "x86_64"),
    };
    var second_packages = [_]metadata.Package{
        testPackage("second-provider", "x86_64"),
    };
    first_packages[0].provides = .{ .start = 0, .len = first_relations.len };
    first_packages[0].files = .{ .start = 0, .len = first_files.len };
    second_packages[0].provides = .{ .start = 0, .len = second_relations.len };
    second_packages[0].files = .{ .start = 0, .len = second_files.len };
    const first_model = metadata.RepositoryModel{
        .packages = &first_packages,
        .relations = &first_relations,
        .files = &first_files,
    };
    const second_model = metadata.RepositoryModel{
        .packages = &second_packages,
        .relations = &second_relations,
        .files = &second_files,
    };

    var universe = try Universe.init(std.testing.allocator, &.{
        .{ .id = "first", .model = &first_model },
        .{ .id = "second", .model = &second_model },
    });
    defer universe.deinit();

    const first_package = universe.package(@enumFromInt(0)).?.*;
    const second_package = universe.package(@enumFromInt(1)).?.*;
    try std.testing.expectEqualStrings(
        "first-capability",
        first_package.relationEntries(&universe, .provides)[0].name,
    );
    try std.testing.expectEqualStrings(
        "/usr/bin/first-tool",
        first_package.fileEntries(&universe)[0].path,
    );
    try std.testing.expectEqualStrings(
        "second-capability",
        second_package.relationEntries(&universe, .provides)[0].name,
    );
    try std.testing.expectEqualStrings(
        "/usr/bin/second-tool",
        second_package.fileEntries(&universe)[0].path,
    );
    try std.testing.expect(universe.package(@enumFromInt(99)) == null);
    try std.testing.expect(universe.repository(@enumFromInt(99)) == null);
}

test "universe rejects ambiguous repository and installed annotations" {
    var packages = [_]metadata.Package{
        testPackage("pkg", "x86_64"),
    };
    const repository_model = metadata.RepositoryModel{
        .packages = &packages,
    };
    const installed_states = [_]InstalledState{
        .{ .rpmdb_hnum = 1 },
    };

    try std.testing.expectError(error.DuplicateRepositoryId, Universe.init(
        std.testing.allocator,
        &.{
            .{ .id = "duplicate", .model = &repository_model },
            .{ .id = "duplicate", .model = &repository_model },
        },
    ));
    try std.testing.expectError(error.MultipleInstalledRepositories, Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "installed-a",
                .model = &repository_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
            .{
                .id = "installed-b",
                .model = &repository_model,
                .kind = .installed,
                .installed_states = &installed_states,
            },
        },
    ));
    try std.testing.expectError(error.InstalledStateCountMismatch, Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "installed",
                .model = &repository_model,
                .kind = .installed,
            },
        },
    ));
    try std.testing.expectError(error.UnexpectedInstalledState, Universe.init(
        std.testing.allocator,
        &.{
            .{
                .id = "available",
                .model = &repository_model,
                .installed_states = &installed_states,
            },
        },
    ));
}
