const std = @import("std");
const filelists_xml = @import("filelists.zig");
const model = @import("model.zig");
const other_xml = @import("other.zig");
const primary_xml = @import("primary.zig");
const repomd_xml = @import("repomd.zig");
const updateinfo_xml = @import("updateinfo.zig");

const max_metadata_bytes = 256 * 1024 * 1024;

const DecompressError = error{
    OutOfMemory,
    UnsupportedCompressor,
    DecompressFailed,
};

pub const LoadError = error{
    InvalidRepoMetadata,
    OutOfMemory,
    FileNotFound,
    AccessDenied,
    NameTooLong,
    BadPathName,
    NotDir,
    IsDir,
    FileTooBig,
    StreamTooLong,
    FileSystemIo,
    UnsupportedCompressor,
    DecompressFailed,
};

pub const Paths = struct {
    repomd: []const u8,
    primary: []const u8,
    filelists: ?[]const u8 = null,
    updateinfo: ?[]const u8 = null,
    other: ?[]const u8 = null,
};

/// Move-only owner for a repository model and every slice it borrows.
pub const LoadedRepository = struct {
    arena_state: std.heap.ArenaAllocator,
    repository: model.RepositoryModel,

    pub fn deinit(self: *LoadedRepository) void {
        self.arena_state.deinit();
        self.* = undefined;
    }
};

pub fn load(
    parent_allocator: std.mem.Allocator,
    paths: Paths,
) LoadError!LoadedRepository {
    var arena_state = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer arena_state.deinit();

    return .{
        .repository = try loadModel(arena_state.allocator(), paths),
        .arena_state = arena_state,
    };
}

/// The allocator owns all returned model storage and must have arena lifetime.
pub fn loadModel(
    allocator: std.mem.Allocator,
    paths: Paths,
) LoadError!model.RepositoryModel {
    const repomd_bytes = try readMetadataFile(allocator, paths.repomd);
    const parsed_repomd = repomd_xml.parse(
        allocator,
        repomd_bytes,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRepoMetadata,
    };

    const primary_bytes = try readMetadataFile(allocator, paths.primary);
    var parsed_primary = primary_xml.parse(
        allocator,
        primary_bytes,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRepoMetadata,
    };

    if (paths.filelists) |path| {
        const filelists_bytes = try readMetadataFile(allocator, path);
        filelists_xml.parseAndApply(
            allocator,
            filelists_bytes,
            &parsed_primary,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRepoMetadata,
        };
    }

    if (paths.other) |path| {
        const other_bytes = try readMetadataFile(allocator, path);
        other_xml.parseAndApply(
            allocator,
            other_bytes,
            &parsed_primary,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRepoMetadata,
        };
    }

    const parsed_updateinfo = if (paths.updateinfo) |path| blk: {
        const updateinfo_bytes = try readMetadataFile(allocator, path);
        break :blk updateinfo_xml.parse(
            allocator,
            updateinfo_bytes,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRepoMetadata,
        };
    } else model.ParsedUpdateInfo{};

    return model.repositoryModelFromParts(
        parsed_repomd,
        parsed_primary,
        parsed_updateinfo,
    );
}

fn readMetadataFile(
    allocator: std.mem.Allocator,
    path: []const u8,
) LoadError![]u8 {
    const raw = readFileAlloc(allocator, path) catch |err| {
        return mapReadError(err);
    };
    return decompressMetadata(allocator, path, raw) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnsupportedCompressor => error.UnsupportedCompressor,
        error.DecompressFailed => error.DecompressFailed,
    };
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var io_state: std.Io.Threaded = .init(allocator, .{});
    defer io_state.deinit();
    return std.Io.Dir.cwd().readFileAlloc(
        io_state.io(),
        path,
        allocator,
        .limited(max_metadata_bytes),
    );
}

fn mapReadError(err: anyerror) LoadError {
    return switch (err) {
        error.FileNotFound => error.FileNotFound,
        error.AccessDenied => error.AccessDenied,
        error.NameTooLong => error.NameTooLong,
        error.BadPathName => error.BadPathName,
        error.NotDir => error.NotDir,
        error.IsDir => error.IsDir,
        error.OutOfMemory => error.OutOfMemory,
        error.FileTooBig => error.FileTooBig,
        error.StreamTooLong => error.StreamTooLong,
        else => error.FileSystemIo,
    };
}

fn decompressMetadata(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
) DecompressError![]u8 {
    var input = std.Io.Reader.fixed(bytes);

    if (std.mem.endsWith(u8, path, ".gz")) {
        var decoder: std.compress.flate.Decompress = .init(
            &input,
            .gzip,
            &.{},
        );
        return decoder.reader.allocRemaining(
            allocator,
            .unlimited,
        ) catch error.DecompressFailed;
    }
    if (std.mem.endsWith(u8, path, ".zst") or
        std.mem.endsWith(u8, path, ".zstd"))
    {
        var decoder: std.compress.zstd.Decompress = .init(&input, &.{}, .{});
        return decoder.reader.allocRemaining(
            allocator,
            .unlimited,
        ) catch error.DecompressFailed;
    }
    if (std.mem.endsWith(u8, path, ".xz")) {
        const start_buf = allocator.alloc(u8, 0) catch
            return error.OutOfMemory;
        var decoder = std.compress.xz.Decompress.init(
            &input,
            allocator,
            start_buf,
        ) catch return error.DecompressFailed;
        defer decoder.deinit();
        return decoder.reader.allocRemaining(
            allocator,
            .unlimited,
        ) catch error.DecompressFailed;
    }

    const out = allocator.alloc(u8, bytes.len) catch
        return error.OutOfMemory;
    @memcpy(out, bytes);
    return out;
}

const fixture_repomd =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<repomd xmlns="http://linux.duke.edu/metadata/repo">
    \\  <revision>42</revision>
    \\  <data type="primary"><location href="primary.xml"/></data>
    \\  <data type="filelists"><location href="filelists.xml"/></data>
    \\  <data type="other"><location href="other.xml"/></data>
    \\  <data type="updateinfo"><location href="updateinfo.xml"/></data>
    \\</repomd>
;

const fixture_primary =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
    \\  <package type="rpm">
    \\    <name>fixture</name>
    \\    <arch>x86_64</arch>
    \\    <version epoch="1" ver="2.0" rel="3"/>
    \\    <checksum type="sha256" pkgid="YES">abcdef</checksum>
    \\    <summary>fixture summary</summary>
    \\    <location href="packages/fixture.rpm"/>
    \\  </package>
    \\</metadata>
;

const fixture_filelists =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="1">
    \\  <package pkgid="abcdef" name="fixture" arch="x86_64">
    \\    <version epoch="1" ver="2.0" rel="3"/>
    \\    <file>/usr/bin/fixture</file>
    \\  </package>
    \\</filelists>
;

const fixture_other =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<otherdata xmlns="http://linux.duke.edu/metadata/other" packages="1">
    \\  <package pkgid="abcdef" name="fixture" arch="x86_64">
    \\    <version epoch="1" ver="2.0" rel="3"/>
    \\    <changelog author="Tester" date="123">created</changelog>
    \\  </package>
    \\</otherdata>
;

const fixture_updateinfo =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<updates></updates>
;

const Fixture = struct {
    tmp: std.testing.TmpDir,

    fn create() !Fixture {
        var fixture = Fixture{ .tmp = std.testing.tmpDir(.{}) };
        errdefer fixture.tmp.cleanup();
        try fixture.tmp.dir.writeFile(
            std.testing.io,
            .{ .sub_path = "repomd.xml", .data = fixture_repomd },
        );
        try fixture.tmp.dir.writeFile(
            std.testing.io,
            .{ .sub_path = "primary.xml", .data = fixture_primary },
        );
        try fixture.tmp.dir.writeFile(
            std.testing.io,
            .{ .sub_path = "filelists.xml", .data = fixture_filelists },
        );
        try fixture.tmp.dir.writeFile(
            std.testing.io,
            .{ .sub_path = "other.xml", .data = fixture_other },
        );
        try fixture.tmp.dir.writeFile(
            std.testing.io,
            .{ .sub_path = "updateinfo.xml", .data = fixture_updateinfo },
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
        name: []const u8,
    ) [:0]const u8 {
        return std.fmt.bufPrintZ(
            buffer,
            ".zig-cache/tmp/{s}/{s}",
            .{ &self.tmp.sub_path, name },
        ) catch @panic("fixture path too long");
    }
};

test "owning loader retains primary and optional metadata" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var repomd_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var primary_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var filelists_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var other_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var updateinfo_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;

    var loaded = try load(std.testing.allocator, .{
        .repomd = fixture.path(&repomd_path_buffer, "repomd.xml"),
        .primary = fixture.path(&primary_path_buffer, "primary.xml"),
        .filelists = fixture.path(
            &filelists_path_buffer,
            "filelists.xml",
        ),
        .other = fixture.path(&other_path_buffer, "other.xml"),
        .updateinfo = fixture.path(
            &updateinfo_path_buffer,
            "updateinfo.xml",
        ),
    });
    defer loaded.deinit();

    try std.testing.expectEqual(@as(usize, 1), loaded.repository.packages.len);
    try std.testing.expectEqualStrings(
        "fixture",
        loaded.repository.packages[0].nevra.name,
    );
    try std.testing.expectEqualStrings(
        "fixture summary",
        loaded.repository.packages[0].summary.?,
    );
    try std.testing.expectEqual(@as(usize, 1), loaded.repository.files.len);
    try std.testing.expectEqualStrings(
        "/usr/bin/fixture",
        loaded.repository.files[0].path,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        loaded.repository.changelogs.len,
    );
    try std.testing.expect(loaded.repository.has_filelists);
    try std.testing.expect(loaded.repository.has_other);
    try std.testing.expect(loaded.repository.has_updateinfo);
}

test "advertised optional metadata flags do not require sidecar loading" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var repomd_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var primary_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;

    var loaded = try load(std.testing.allocator, .{
        .repomd = fixture.path(&repomd_path_buffer, "repomd.xml"),
        .primary = fixture.path(&primary_path_buffer, "primary.xml"),
    });
    defer loaded.deinit();

    try std.testing.expectEqual(@as(usize, 0), loaded.repository.files.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        loaded.repository.changelogs.len,
    );
    try std.testing.expect(loaded.repository.has_filelists);
    try std.testing.expect(loaded.repository.has_other);
    try std.testing.expect(loaded.repository.has_updateinfo);
}

fn loaderAllocationFailureCase(
    allocator: std.mem.Allocator,
    paths: Paths,
) !void {
    var loaded = try load(allocator, paths);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(usize, 1), loaded.repository.packages.len);
}

test "owning loader cleans every allocation failure" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var repomd_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var primary_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const paths = Paths{
        .repomd = fixture.path(&repomd_path_buffer, "repomd.xml"),
        .primary = fixture.path(&primary_path_buffer, "primary.xml"),
    };

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        loaderAllocationFailureCase,
        .{paths},
    );
}

test "metadata decompression supports raw gzip zstd and xz" {
    const payload = "metadata-payload";
    const gzip = [_]u8{
        31, 139, 8,  0,  0,  0,  0,   0,  0,  3,   203, 77,
        45, 73,  76, 73, 44, 73, 212, 45, 72, 172, 204, 201,
        79, 76,  1,  0,  0,  44, 40,  62, 16, 0,   0,   0,
    };
    const zstd = [_]u8{
        40,  181, 47,  253, 4,   88, 129, 0,  0,   109, 101, 116,
        97,  100, 97,  116, 97,  45, 112, 97, 121, 108, 111, 97,
        100, 163, 220, 119, 210,
    };
    const xz = [_]u8{
        253, 55,  122, 88,  90,  0,   0,   4,   230, 214, 180, 70,
        2,   0,   33,  1,   22,  0,   0,   0,   116, 47,  229, 163,
        1,   0,   15,  109, 101, 116, 97,  100, 97,  116, 97,  45,
        112, 97,  121, 108, 111, 97,  100, 0,   173, 101, 109, 110,
        15,  58,  191, 160, 0,   1,   40,  16,  229, 11,  108, 96,
        31,  182, 243, 125, 1,   0,   0,   0,   0,   4,   89,  90,
    };

    inline for (.{
        .{ "metadata.xml", payload },
        .{ "metadata.xml.gz", &gzip },
        .{ "metadata.xml.zst", &zstd },
        .{ "metadata.xml.xz", &xz },
    }) |fixture| {
        const decoded = try decompressMetadata(
            std.testing.allocator,
            fixture[0],
            fixture[1],
        );
        defer std.testing.allocator.free(decoded);
        try std.testing.expectEqualStrings(payload, decoded);
    }
}

test "loader maps missing malformed and corrupt metadata" {
    var fixture = try Fixture.create();
    defer fixture.cleanup();
    var repomd_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var primary_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var missing_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const repomd_path = fixture.path(
        &repomd_path_buffer,
        "repomd.xml",
    );
    const primary_path = fixture.path(
        &primary_path_buffer,
        "primary.xml",
    );
    const missing_path = fixture.path(
        &missing_path_buffer,
        "missing.xml",
    );

    try std.testing.expectError(error.FileNotFound, load(
        std.testing.allocator,
        .{ .repomd = repomd_path, .primary = missing_path },
    ));

    try fixture.tmp.dir.writeFile(
        std.testing.io,
        .{ .sub_path = "primary.xml", .data = "<metadata>" },
    );
    try std.testing.expectError(error.InvalidRepoMetadata, load(
        std.testing.allocator,
        .{ .repomd = repomd_path, .primary = primary_path },
    ));

    try fixture.tmp.dir.writeFile(
        std.testing.io,
        .{ .sub_path = "primary.xml.gz", .data = "not gzip" },
    );
    var corrupt_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    try std.testing.expectError(error.DecompressFailed, load(
        std.testing.allocator,
        .{
            .repomd = repomd_path,
            .primary = fixture.path(
                &corrupt_path_buffer,
                "primary.xml.gz",
            ),
        },
    ));
}
