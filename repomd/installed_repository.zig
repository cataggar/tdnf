const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");
const rpmpkg = @import("rpmpkg.zig");
const rpm_header = @import("rpm_header");
const solver_model = @import("solver_model.zig");

const sqlite = if (builtin.is_test) @import("sqlite") else struct {};

const RpmDbIter = opaque {};

extern fn tdnf_rpmdb_iter_open(
    root: ?[*:0]const u8,
) ?*RpmDbIter;
extern fn tdnf_rpmdb_iter_open_config(
    config: *const anyopaque,
) ?*RpmDbIter;
extern fn tdnf_rpmdb_iter_close(iter: ?*RpmDbIter) void;
extern fn tdnf_rpmdb_iter_next_header_blob_hnum(
    iter: ?*RpmDbIter,
    hnum_out: ?*u32,
    blob_out: ?*?[*]const u8,
    blob_len_out: ?*usize,
) i32;

pub const LoadError = error{
    OutOfMemory,
    InvalidRpmHeader,
    RpmDbOpenFailed,
    RpmDbReadFailed,
};

pub const Source = union(enum) {
    root_dir: ?[*:0]const u8,
    config: *const anyopaque,
};

pub const LoadOptions = struct {
    include_relations: bool = true,
    include_files: bool = true,
    include_changelogs: bool = false,
};

pub const InstalledState = solver_model.InstalledState;

pub const Repository = struct {
    repository: model.RepositoryModel,
    installed_states: []const InstalledState,
};

/// Move-only owner for an installed repository and its aligned state.
pub const LoadedRepository = struct {
    arena_state: std.heap.ArenaAllocator,
    repository: model.RepositoryModel,
    installed_states: []const InstalledState,

    pub fn deinit(self: *LoadedRepository) void {
        self.arena_state.deinit();
        self.* = undefined;
    }
};

pub fn load(
    parent_allocator: std.mem.Allocator,
    source: Source,
    options: LoadOptions,
) LoadError!LoadedRepository {
    var arena_state = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer arena_state.deinit();

    const loaded = try loadModel(arena_state.allocator(), source, options);
    return .{
        .arena_state = arena_state,
        .repository = loaded.repository,
        .installed_states = loaded.installed_states,
    };
}

/// The allocator owns all returned storage and must have arena lifetime.
pub fn loadModel(
    allocator: std.mem.Allocator,
    source: Source,
    options: LoadOptions,
) LoadError!Repository {
    var builder = RepositoryBuilder.init(allocator);
    defer builder.deinit();
    var installed_states = std.array_list.Managed(InstalledState).init(
        allocator,
    );
    defer installed_states.deinit();

    const iter = switch (source) {
        .root_dir => |root_dir| tdnf_rpmdb_iter_open(root_dir),
        .config => |config| tdnf_rpmdb_iter_open_config(config),
    } orelse return error.RpmDbOpenFailed;
    defer tdnf_rpmdb_iter_close(iter);

    while (true) {
        var blob_ptr: ?[*]const u8 = null;
        var blob_len: usize = 0;
        var hnum: u32 = 0;
        const rc = tdnf_rpmdb_iter_next_header_blob_hnum(
            iter,
            &hnum,
            &blob_ptr,
            &blob_len,
        );
        if (rc == 0) break;
        if (rc < 0) return error.RpmDbReadFailed;
        if (hnum == 0 or blob_ptr == null or blob_len == 0) {
            return error.InvalidRpmHeader;
        }

        const header = rpm_header.Header.parse(
            blob_ptr.?[0..blob_len],
        ) catch return error.InvalidRpmHeader;
        if (header.getString(.name)) |name| {
            if (std.mem.eql(u8, name, "gpg-pubkey")) continue;
        }

        const built = rpmpkg.buildFromHeader(allocator, header, .{
            .include_relations = options.include_relations,
            .include_files = options.include_files,
            .include_changelogs = options.include_changelogs,
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRpmHeader,
        };
        try builder.appendBuiltPackage(built);
        try installed_states.append(.{
            .rpmdb_hnum = hnum,
            .reason = .unknown,
            .install_order = 0,
        });
    }

    const repository = try builder.finish();
    const states = try installed_states.toOwnedSlice();
    if (repository.packages.len != states.len) unreachable;
    return .{
        .repository = repository,
        .installed_states = states,
    };
}

const RepositoryBuilder = struct {
    allocator: std.mem.Allocator,
    packages: std.array_list.Managed(model.Package),
    relations: std.array_list.Managed(model.Relation),
    files: std.array_list.Managed(model.FileEntry),
    changelogs: std.array_list.Managed(model.ChangelogEntry),

    fn init(allocator: std.mem.Allocator) RepositoryBuilder {
        return .{
            .allocator = allocator,
            .packages = std.array_list.Managed(model.Package).init(allocator),
            .relations = std.array_list.Managed(model.Relation).init(allocator),
            .files = std.array_list.Managed(model.FileEntry).init(allocator),
            .changelogs = std.array_list.Managed(model.ChangelogEntry).init(
                allocator,
            ),
        };
    }

    fn deinit(self: *RepositoryBuilder) void {
        self.packages.deinit();
        self.relations.deinit();
        self.files.deinit();
        self.changelogs.deinit();
    }

    fn appendBuiltPackage(
        self: *RepositoryBuilder,
        built: rpmpkg.BuiltPackage,
    ) std.mem.Allocator.Error!void {
        var pkg = built.package;
        const relation_base = self.relations.items.len;
        const file_base = self.files.items.len;
        const changelog_base = self.changelogs.items.len;

        try self.relations.appendSlice(built.relations);
        try self.files.appendSlice(built.files);
        try self.changelogs.appendSlice(built.changelogs);

        inline for (std.enums.values(model.DependencyKind)) |kind| {
            pkg.rangePtr(kind).start += relation_base;
        }
        pkg.files.start += file_base;
        pkg.changelogs.start += changelog_base;
        try self.packages.append(pkg);
    }

    fn finish(
        self: *RepositoryBuilder,
    ) std.mem.Allocator.Error!model.RepositoryModel {
        return .{
            .packages = try self.packages.toOwnedSlice(),
            .relations = try self.relations.toOwnedSlice(),
            .files = try self.files.toOwnedSlice(),
            .changelogs = try self.changelogs.toOwnedSlice(),
        };
    }
};

const FixtureRow = struct {
    hnum: u32,
    blob: []const u8,
};

const Fixture = struct {
    tmp: std.testing.TmpDir,

    fn create(rows: []const FixtureRow) !Fixture {
        var fixture = Fixture{ .tmp = std.testing.tmpDir(.{}) };
        errdefer fixture.tmp.cleanup();
        try fixture.tmp.dir.createDirPath(
            std.testing.io,
            "var/lib/rpm",
        );

        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const db = try sqlite.Database.open(.{
            .path = fixture.path(
                &path_buffer,
                "var/lib/rpm/rpmdb.sqlite",
            ),
        });
        defer db.close();
        try db.exec(
            \\CREATE TABLE Packages (
            \\    hnum INTEGER PRIMARY KEY,
            \\    blob BLOB NOT NULL
            \\)
        , .{});

        for (rows) |row| {
            const blob_hex = try hexLower(std.testing.allocator, row.blob);
            defer std.testing.allocator.free(blob_hex);
            const sql = try std.fmt.allocPrint(
                std.testing.allocator,
                "INSERT INTO Packages (hnum, blob) VALUES ({d}, x'{s}')",
                .{ row.hnum, blob_hex },
            );
            defer std.testing.allocator.free(sql);
            try db.exec(sql, .{});
        }
        return fixture;
    }

    fn cleanup(self: *Fixture) void {
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn rootPath(
        self: *const Fixture,
        buffer: *[std.Io.Dir.max_path_bytes]u8,
    ) [:0]const u8 {
        return self.path(buffer, "");
    }

    fn path(
        self: *const Fixture,
        buffer: *[std.Io.Dir.max_path_bytes]u8,
        name: []const u8,
    ) [:0]const u8 {
        return std.fmt.bufPrintZ(
            buffer,
            ".zig-cache/tmp/{s}/{s}",
            .{ &self.tmp.sub_path, name },
        ) catch @panic("fixture path too long");
    }
};

fn hexLower(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) std.mem.Allocator.Error![]u8 {
    const digits = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 0x0f];
    }
    return out;
}

test "owning loader preserves hnum order duplicate identities and state" {
    const package_blob = try rpmpkg.makeMinimalHeaderForTest(
        std.testing.allocator,
        "duplicate",
        "1.0",
        "1",
        "x86_64",
    );
    defer std.testing.allocator.free(package_blob);
    const pubkey_blob = try rpmpkg.makeMinimalHeaderForTest(
        std.testing.allocator,
        "gpg-pubkey",
        "1",
        "1",
        "noarch",
    );
    defer std.testing.allocator.free(pubkey_blob);

    var fixture = try Fixture.create(&.{
        .{ .hnum = 73, .blob = package_blob },
        .{ .hnum = 12, .blob = pubkey_blob },
        .{ .hnum = 41, .blob = package_blob },
    });
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var loaded = try load(
        std.testing.allocator,
        .{ .root_dir = fixture.rootPath(&root_buffer) },
        .{},
    );
    defer loaded.deinit();

    try std.testing.expectEqual(
        @as(usize, 2),
        loaded.repository.packages.len,
    );
    try std.testing.expectEqual(
        loaded.repository.packages.len,
        loaded.installed_states.len,
    );
    try std.testing.expectEqualStrings(
        "duplicate",
        loaded.repository.packages[0].nevra.name,
    );
    try std.testing.expectEqualStrings(
        loaded.repository.packages[0].pkg_id,
        loaded.repository.packages[1].pkg_id,
    );
    try std.testing.expectEqual(
        @as(u32, 41),
        loaded.installed_states[0].rpmdb_hnum,
    );
    try std.testing.expectEqual(
        @as(u32, 73),
        loaded.installed_states[1].rpmdb_hnum,
    );
    for (loaded.installed_states) |state| {
        try std.testing.expectEqual(
            solver_model.InstallReason.unknown,
            state.reason,
        );
        try std.testing.expectEqual(@as(u64, 0), state.install_order);
    }

    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{
            .id = "@System",
            .model = &loaded.repository,
            .kind = .installed,
            .installed_states = loaded.installed_states,
        }},
    );
    defer universe.deinit();
    try std.testing.expectEqual(
        @as(u32, 41),
        universe.packages[0].installed.?.rpmdb_hnum,
    );
    try std.testing.expectEqual(
        @as(u32, 73),
        universe.packages[1].installed.?.rpmdb_hnum,
    );
}

fn loaderAllocationFailureCase(
    allocator: std.mem.Allocator,
    source: Source,
) !void {
    var loaded = try load(allocator, source, .{});
    defer loaded.deinit();
    try std.testing.expectEqual(
        loaded.repository.packages.len,
        loaded.installed_states.len,
    );
}

test "owning loader cleans every allocation failure" {
    const package_blob = try rpmpkg.makeMinimalHeaderForTest(
        std.testing.allocator,
        "allocation",
        "1.0",
        "1",
        "noarch",
    );
    defer std.testing.allocator.free(package_blob);
    var fixture = try Fixture.create(&.{
        .{ .hnum = 19, .blob = package_blob },
    });
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const source = Source{
        .root_dir = fixture.rootPath(&root_buffer),
    };

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        loaderAllocationFailureCase,
        .{source},
    );
}

test "loader reports malformed and unreadable rpmdb input" {
    var malformed = try Fixture.create(&.{
        .{ .hnum = 1, .blob = &.{ 1, 2, 3 } },
    });
    defer malformed.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    try std.testing.expectError(
        error.InvalidRpmHeader,
        load(
            std.testing.allocator,
            .{ .root_dir = malformed.rootPath(&root_buffer) },
            .{},
        ),
    );

    var unreadable = Fixture{ .tmp = std.testing.tmpDir(.{}) };
    defer unreadable.cleanup();
    try unreadable.tmp.dir.createDirPath(
        std.testing.io,
        "var/lib/rpm",
    );
    try unreadable.tmp.dir.writeFile(
        std.testing.io,
        .{
            .sub_path = "var/lib/rpm/rpmdb.sqlite",
            .data = "not a sqlite database",
        },
    );
    var unreadable_root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    try std.testing.expectError(
        error.RpmDbOpenFailed,
        load(
            std.testing.allocator,
            .{
                .root_dir = unreadable.rootPath(
                    &unreadable_root_buffer,
                ),
            },
            .{},
        ),
    );
}

test "missing rpmdb produces an empty aligned repository" {
    var fixture = Fixture{ .tmp = std.testing.tmpDir(.{}) };
    defer fixture.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var loaded = try load(
        std.testing.allocator,
        .{ .root_dir = fixture.rootPath(&root_buffer) },
        .{},
    );
    defer loaded.deinit();

    try std.testing.expectEqual(
        @as(usize, 0),
        loaded.repository.packages.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        loaded.installed_states.len,
    );
}
