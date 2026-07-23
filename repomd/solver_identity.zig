const std = @import("std");
const model = @import("model.zig");
const solver_model = @import("solver_model.zig");

pub const Checksum = struct {
    kind: []const u8,
    value: []const u8,
    is_pkgid: bool,
};

pub const InstalledKey = struct {
    repository: []const u8,
    rpmdb_hnum: u32,
};

pub const AvailableKey = struct {
    repository: []const u8,
    name: []const u8,
    epoch: u32,
    version: []const u8,
    release: []const u8,
    arch: []const u8,
    checksum: Checksum,
};

pub const PackageKey = union(enum) {
    installed: InstalledKey,
    available: AvailableKey,
};

pub const AvailableSelector = struct {
    repository: []const u8,
    name: []const u8,
    epoch: ?u32,
    version: []const u8,
    release: []const u8,
    arch: []const u8,
    checksum: ?Checksum = null,
};

pub const Entry = struct {
    key: PackageKey,
    package: solver_model.PackageId,
};

pub const InitError = error{
    OutOfMemory,
    UnsupportedRepositoryKind,
    UnsupportedRepositoryCost,
    InvalidPackageIdentity,
    DuplicatePackageKey,
};

pub const ResolveError = error{
    InvalidPackageSelector,
    PackageNotFound,
    AmbiguousPackageSelector,
};

/// Move-only exact-key index whose strings are owned by an arena.
pub const Index = struct {
    arena_state: std.heap.ArenaAllocator,
    universe: *const solver_model.Universe,
    entries: []const Entry,

    pub fn init(
        parent_allocator: std.mem.Allocator,
        universe: *const solver_model.Universe,
    ) InitError!Index {
        var arena_state = std.heap.ArenaAllocator.init(parent_allocator);
        errdefer arena_state.deinit();
        const arena = arena_state.allocator();
        const entries = try arena.alloc(Entry, universe.packages.len);

        for (universe.repositories) |repository| {
            switch (repository.kind) {
                .installed => {},
                .available => {
                    if (repository.cost !=
                        solver_model.default_repository_cost)
                    {
                        return error.UnsupportedRepositoryCost;
                    }
                },
                .command_line => return error.UnsupportedRepositoryKind,
            }
        }

        for (universe.packages, entries) |package, *entry| {
            const repository = universe.repository(package.repository) orelse
                unreachable;
            entry.* = .{
                .key = if (package.installed) |installed|
                    .{ .installed = .{
                        .repository = try duplicateRequired(
                            arena,
                            repository.name,
                        ),
                        .rpmdb_hnum = if (installed.rpmdb_hnum != 0)
                            installed.rpmdb_hnum
                        else
                            return error.InvalidPackageIdentity,
                    } }
                else
                    .{ .available = try cloneAvailableKey(
                        arena,
                        repository.name,
                        package.source,
                    ) },
                .package = package.id,
            };
        }

        std.mem.sort(Entry, entries, {}, entryLessThan);
        if (entries.len > 1) {
            for (entries[1..], entries[0 .. entries.len - 1]) |
                current,
                previous,
            | {
                if (compareKeys(previous.key, current.key) == .eq) {
                    return error.DuplicatePackageKey;
                }
            }
        }

        return .{
            .arena_state = arena_state,
            .universe = universe,
            .entries = entries,
        };
    }

    pub fn deinit(self: *Index) void {
        self.arena_state.deinit();
        self.* = undefined;
    }

    pub fn resolveExact(
        self: *const Index,
        key: PackageKey,
    ) ResolveError!solver_model.PackageId {
        var low: usize = 0;
        var high = self.entries.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            switch (compareKeys(self.entries[middle].key, key)) {
                .lt => low = middle + 1,
                .gt => high = middle,
                .eq => return self.entries[middle].package,
            }
        }
        return error.PackageNotFound;
    }

    pub fn resolveInstalled(
        self: *const Index,
        repository: []const u8,
        rpmdb_hnum: u32,
    ) ResolveError!solver_model.PackageId {
        if (repository.len == 0 or rpmdb_hnum == 0) {
            return error.InvalidPackageSelector;
        }
        return self.resolveExact(.{ .installed = .{
            .repository = repository,
            .rpmdb_hnum = rpmdb_hnum,
        } });
    }

    pub fn resolveInstalledNevra(
        self: *const Index,
        selector: AvailableSelector,
    ) ResolveError!solver_model.PackageId {
        try validateSelector(selector);
        if (selector.checksum != null) return error.InvalidPackageSelector;
        var match: ?solver_model.PackageId = null;
        for (self.entries) |entry| {
            const installed = switch (entry.key) {
                .installed => |value| value,
                .available => continue,
            };
            const package = self.universe.package(entry.package) orelse
                return error.PackageNotFound;
            if (!std.mem.eql(
                u8,
                installed.repository,
                selector.repository,
            ) or !matchesNevra(package.source.nevra, selector)) continue;
            if (match != null) return error.AmbiguousPackageSelector;
            match = entry.package;
        }
        return match orelse error.PackageNotFound;
    }

    pub fn resolveAvailable(
        self: *const Index,
        selector: AvailableSelector,
    ) ResolveError!solver_model.PackageId {
        try validateSelector(selector);
        var match: ?solver_model.PackageId = null;
        for (self.entries) |entry| {
            const key = switch (entry.key) {
                .installed => continue,
                .available => |available| available,
            };
            if (!matchesSelector(key, selector)) continue;
            if (match != null) return error.AmbiguousPackageSelector;
            match = entry.package;
        }
        return match orelse error.PackageNotFound;
    }
};

fn cloneAvailableKey(
    allocator: std.mem.Allocator,
    repository: []const u8,
    package: *const model.Package,
) InitError!AvailableKey {
    return .{
        .repository = try duplicateRequired(allocator, repository),
        .name = try duplicateRequired(allocator, package.nevra.name),
        .epoch = package.nevra.epoch orelse 0,
        .version = try duplicateRequired(allocator, package.nevra.version),
        .release = try duplicateRequired(allocator, package.nevra.release),
        .arch = try duplicateRequired(allocator, package.nevra.arch),
        .checksum = .{
            .kind = try duplicateRequired(
                allocator,
                package.checksum.kind,
            ),
            .value = try duplicateRequired(
                allocator,
                package.checksum.value,
            ),
            .is_pkgid = package.checksum.is_pkgid,
        },
    };
}

fn duplicateRequired(
    allocator: std.mem.Allocator,
    value: []const u8,
) InitError![]const u8 {
    if (value.len == 0) return error.InvalidPackageIdentity;
    return try allocator.dupe(u8, value);
}

fn validateSelector(selector: AvailableSelector) ResolveError!void {
    if (selector.repository.len == 0 or
        selector.name.len == 0 or
        selector.version.len == 0 or
        selector.release.len == 0 or
        selector.arch.len == 0)
    {
        return error.InvalidPackageSelector;
    }
    if (selector.checksum) |checksum| {
        if (checksum.kind.len == 0 or checksum.value.len == 0) {
            return error.InvalidPackageSelector;
        }
    }
}

fn matchesSelector(
    key: AvailableKey,
    selector: AvailableSelector,
) bool {
    if (!std.mem.eql(u8, key.repository, selector.repository) or
        !matchesNevra(.{
            .name = key.name,
            .epoch = key.epoch,
            .version = key.version,
            .release = key.release,
            .arch = key.arch,
        }, selector))
    {
        return false;
    }
    if (selector.checksum) |checksum| {
        return std.mem.eql(u8, key.checksum.kind, checksum.kind) and
            std.mem.eql(u8, key.checksum.value, checksum.value) and
            key.checksum.is_pkgid == checksum.is_pkgid;
    }
    return true;
}

fn matchesNevra(
    nevra: model.Nevra,
    selector: AvailableSelector,
) bool {
    return std.mem.eql(u8, nevra.name, selector.name) and
        (nevra.epoch orelse 0) == (selector.epoch orelse 0) and
        std.mem.eql(u8, nevra.version, selector.version) and
        std.mem.eql(u8, nevra.release, selector.release) and
        std.mem.eql(u8, nevra.arch, selector.arch);
}

fn entryLessThan(_: void, left: Entry, right: Entry) bool {
    return compareKeys(left.key, right.key) == .lt;
}

fn compareKeys(left: PackageKey, right: PackageKey) std.math.Order {
    return switch (left) {
        .installed => |left_installed| switch (right) {
            .available => .lt,
            .installed => |right_installed| compareInstalled(
                left_installed,
                right_installed,
            ),
        },
        .available => |left_available| switch (right) {
            .installed => .gt,
            .available => |right_available| compareAvailable(
                left_available,
                right_available,
            ),
        },
    };
}

fn compareInstalled(
    left: InstalledKey,
    right: InstalledKey,
) std.math.Order {
    const repository_order = std.mem.order(
        u8,
        left.repository,
        right.repository,
    );
    if (repository_order != .eq) return repository_order;
    return std.math.order(left.rpmdb_hnum, right.rpmdb_hnum);
}

fn compareAvailable(
    left: AvailableKey,
    right: AvailableKey,
) std.math.Order {
    inline for ([_]struct {
        left: []const u8,
        right: []const u8,
    }{
        .{ .left = left.repository, .right = right.repository },
        .{ .left = left.name, .right = right.name },
    }) |pair| {
        const order = std.mem.order(u8, pair.left, pair.right);
        if (order != .eq) return order;
    }
    const epoch_order = std.math.order(left.epoch, right.epoch);
    if (epoch_order != .eq) return epoch_order;
    inline for ([_]struct {
        left: []const u8,
        right: []const u8,
    }{
        .{ .left = left.version, .right = right.version },
        .{ .left = left.release, .right = right.release },
        .{ .left = left.arch, .right = right.arch },
        .{ .left = left.checksum.kind, .right = right.checksum.kind },
        .{ .left = left.checksum.value, .right = right.checksum.value },
    }) |pair| {
        const order = std.mem.order(u8, pair.left, pair.right);
        if (order != .eq) return order;
    }
    return std.math.order(
        @intFromBool(left.checksum.is_pkgid),
        @intFromBool(right.checksum.is_pkgid),
    );
}

fn testPackage(
    name: []const u8,
    epoch: ?u32,
    checksum: []const u8,
) model.Package {
    return .{
        .pkg_id = checksum,
        .nevra = .{
            .name = name,
            .epoch = epoch,
            .version = "1.0",
            .release = "1",
            .arch = "x86_64",
        },
        .checksum = .{
            .kind = "sha256",
            .value = checksum,
            .is_pkgid = true,
        },
        .location = .{},
    };
}

test "index preserves installed duplicates and rejects ambiguous available selectors" {
    var installed_packages = [_]model.Package{
        testPackage("duplicate", null, "installed"),
        testPackage("duplicate", null, "installed"),
        testPackage("unique", null, "installed-unique"),
    };
    const installed_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 41 },
        .{ .rpmdb_hnum = 73 },
        .{ .rpmdb_hnum = 91 },
    };
    var repository_a_packages = [_]model.Package{
        testPackage("candidate", null, "checksum-a"),
        testPackage("candidate", 0, "checksum-b"),
    };
    var repository_b_packages = [_]model.Package{
        testPackage("candidate", null, "checksum-a"),
    };
    const repositories = [_]solver_model.RepositoryInput{
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
        &repositories,
    );
    defer universe.deinit();
    var index = try Index.init(std.testing.allocator, &universe);
    defer index.deinit();

    const first = try index.resolveInstalled("@System", 41);
    const second = try index.resolveInstalled("@System", 73);
    try std.testing.expect(first != second);
    try std.testing.expectEqual(
        @as(u32, 41),
        universe.package(first).?.installed.?.rpmdb_hnum,
    );
    try std.testing.expectEqual(
        @as(u32, 73),
        universe.package(second).?.installed.?.rpmdb_hnum,
    );
    const installed_selector = AvailableSelector{
        .repository = "@System",
        .name = "duplicate",
        .epoch = 0,
        .version = "1.0",
        .release = "1",
        .arch = "x86_64",
    };
    try std.testing.expectError(
        error.AmbiguousPackageSelector,
        index.resolveInstalledNevra(installed_selector),
    );
    const unique = try index.resolveInstalledNevra(.{
        .repository = installed_selector.repository,
        .name = "unique",
        .epoch = installed_selector.epoch,
        .version = installed_selector.version,
        .release = installed_selector.release,
        .arch = installed_selector.arch,
    });
    try std.testing.expectEqual(
        @as(u32, 91),
        universe.package(unique).?.installed.?.rpmdb_hnum,
    );

    const selector = AvailableSelector{
        .repository = "repo-a",
        .name = "candidate",
        .epoch = null,
        .version = "1.0",
        .release = "1",
        .arch = "x86_64",
    };
    try std.testing.expectError(
        error.AmbiguousPackageSelector,
        index.resolveAvailable(selector),
    );
    const selected = try index.resolveAvailable(.{
        .repository = selector.repository,
        .name = selector.name,
        .epoch = selector.epoch,
        .version = selector.version,
        .release = selector.release,
        .arch = selector.arch,
        .checksum = .{
            .kind = "sha256",
            .value = "checksum-b",
            .is_pkgid = true,
        },
    });
    try std.testing.expectEqualStrings(
        "checksum-b",
        universe.package(selected).?.source.checksum.value,
    );
    const other_repository = try index.resolveAvailable(.{
        .repository = "repo-b",
        .name = selector.name,
        .epoch = selector.epoch,
        .version = selector.version,
        .release = selector.release,
        .arch = selector.arch,
    });
    try std.testing.expectEqualStrings(
        "repo-b",
        universe.repository(
            universe.package(other_repository).?.repository,
        ).?.name,
    );
}

test "index rejects normalized duplicates and unsupported live inputs" {
    var duplicate_packages = [_]model.Package{
        testPackage("same", null, "checksum"),
        testPackage("same", 0, "checksum"),
    };
    const duplicate_inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &duplicate_packages },
    }};
    var duplicate_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &duplicate_inputs,
    );
    defer duplicate_universe.deinit();
    try std.testing.expectError(
        error.DuplicatePackageKey,
        Index.init(std.testing.allocator, &duplicate_universe),
    );

    var package = [_]model.Package{
        testPackage("package", null, "checksum"),
    };
    const command_line_inputs = [_]solver_model.RepositoryInput{.{
        .id = "command-line",
        .model = &.{ .packages = &package },
        .kind = .command_line,
    }};
    var command_line_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &command_line_inputs,
    );
    defer command_line_universe.deinit();
    try std.testing.expectError(
        error.UnsupportedRepositoryKind,
        Index.init(std.testing.allocator, &command_line_universe),
    );

    const cost_inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &package },
        .cost = solver_model.default_repository_cost + 1,
    }};
    var cost_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &cost_inputs,
    );
    defer cost_universe.deinit();
    try std.testing.expectError(
        error.UnsupportedRepositoryCost,
        Index.init(std.testing.allocator, &cost_universe),
    );

    const invalid_states = [_]solver_model.InstalledState{
        .{ .rpmdb_hnum = 0 },
    };
    const invalid_installed_inputs = [_]solver_model.RepositoryInput{.{
        .id = "@System",
        .model = &.{ .packages = &package },
        .kind = .installed,
        .installed_states = &invalid_states,
    }};
    var invalid_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &invalid_installed_inputs,
    );
    defer invalid_universe.deinit();
    try std.testing.expectError(
        error.InvalidPackageIdentity,
        Index.init(std.testing.allocator, &invalid_universe),
    );

    var missing_checksum_package = [_]model.Package{
        testPackage("package", null, ""),
    };
    const missing_checksum_inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &missing_checksum_package },
    }};
    var missing_checksum_universe = try solver_model.Universe.init(
        std.testing.allocator,
        &missing_checksum_inputs,
    );
    defer missing_checksum_universe.deinit();
    try std.testing.expectError(
        error.InvalidPackageIdentity,
        Index.init(std.testing.allocator, &missing_checksum_universe),
    );
}

test "checksum kind and pkgid metadata remain part of available identity" {
    var packages = [_]model.Package{
        testPackage("package", null, "same-value"),
        testPackage("package", null, "same-value"),
        testPackage("package", null, "same-value"),
    };
    packages[1].checksum.kind = "sha512";
    packages[2].checksum.is_pkgid = false;
    const inputs = [_]solver_model.RepositoryInput{.{
        .id = "repo",
        .model = &.{ .packages = &packages },
    }};
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &inputs,
    );
    defer universe.deinit();
    var index = try Index.init(std.testing.allocator, &universe);
    defer index.deinit();

    const selector = AvailableSelector{
        .repository = "repo",
        .name = "package",
        .epoch = null,
        .version = "1.0",
        .release = "1",
        .arch = "x86_64",
    };
    try std.testing.expectError(
        error.AmbiguousPackageSelector,
        index.resolveAvailable(selector),
    );
    const sha512 = try index.resolveAvailable(.{
        .repository = selector.repository,
        .name = selector.name,
        .epoch = selector.epoch,
        .version = selector.version,
        .release = selector.release,
        .arch = selector.arch,
        .checksum = .{
            .kind = "sha512",
            .value = "same-value",
            .is_pkgid = true,
        },
    });
    try std.testing.expectEqualStrings(
        "sha512",
        universe.package(sha512).?.source.checksum.kind,
    );
    const not_pkgid = try index.resolveAvailable(.{
        .repository = selector.repository,
        .name = selector.name,
        .epoch = selector.epoch,
        .version = selector.version,
        .release = selector.release,
        .arch = selector.arch,
        .checksum = .{
            .kind = "sha256",
            .value = "same-value",
            .is_pkgid = false,
        },
    });
    try std.testing.expect(
        !universe.package(not_pkgid).?.source.checksum.is_pkgid,
    );
}

test "empty universe has an empty stable identity index" {
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{},
    );
    defer universe.deinit();
    var index = try Index.init(std.testing.allocator, &universe);
    defer index.deinit();
    try std.testing.expectEqual(@as(usize, 0), index.entries.len);
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    universe: *const solver_model.Universe,
) !void {
    var index = try Index.init(allocator, universe);
    defer index.deinit();
    try std.testing.expectEqual(
        universe.packages.len,
        index.entries.len,
    );
}

test "index cleans every allocation failure" {
    var packages = [_]model.Package{
        testPackage("one", null, "checksum-one"),
        testPackage("two", 2, "checksum-two"),
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
