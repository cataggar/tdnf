const std = @import("std");
const filelists_xml = @import("filelists.zig");
const metadata_integrity = @import("metadata_integrity.zig");
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

pub const CacheOptions = struct {
    include_filelists: bool = true,
    include_updateinfo: bool = false,
    include_other: bool = false,
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

    return loadResolvedModel(
        allocator,
        parsed_repomd,
        .{
            .primary = paths.primary,
            .filelists = paths.filelists,
            .updateinfo = paths.updateinfo,
            .other = paths.other,
        },
    );
}

const ResolvedPaths = struct {
    primary: []const u8,
    filelists: ?[]const u8,
    updateinfo: ?[]const u8,
    other: ?[]const u8,
};

const ResolvedBytes = struct {
    primary: []const u8,
    filelists: ?[]const u8,
    updateinfo: ?[]const u8,
    other: ?[]const u8,
};

fn loadResolvedModel(
    allocator: std.mem.Allocator,
    parsed_repomd: model.ParsedRepoMd,
    paths: ResolvedPaths,
) LoadError!model.RepositoryModel {
    const bytes = ResolvedBytes{
        .primary = try readMetadataFile(allocator, paths.primary),
        .filelists = if (paths.filelists) |path|
            try readMetadataFile(allocator, path)
        else
            null,
        .updateinfo = if (paths.updateinfo) |path|
            try readMetadataFile(allocator, path)
        else
            null,
        .other = if (paths.other) |path|
            try readMetadataFile(allocator, path)
        else
            null,
    };
    return parseResolvedModel(allocator, parsed_repomd, bytes);
}

fn parseResolvedModel(
    allocator: std.mem.Allocator,
    parsed_repomd: model.ParsedRepoMd,
    bytes: ResolvedBytes,
) LoadError!model.RepositoryModel {
    var parsed_primary = primary_xml.parse(
        allocator,
        bytes.primary,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRepoMetadata,
    };

    if (bytes.filelists) |filelists_bytes| {
        filelists_xml.parseAndApply(
            allocator,
            filelists_bytes,
            &parsed_primary,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRepoMetadata,
        };
    }

    if (bytes.other) |other_bytes| {
        other_xml.parseAndApply(
            allocator,
            other_bytes,
            &parsed_primary,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRepoMetadata,
        };
    }

    const parsed_updateinfo = if (bytes.updateinfo) |updateinfo_bytes| blk: {
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

/// Load cached metadata rooted at a repository cache directory.
/// The allocator owns all returned model storage and must have arena lifetime.
pub fn loadCacheModel(
    allocator: std.mem.Allocator,
    cache_dir: []const u8,
    options: CacheOptions,
) LoadError!model.RepositoryModel {
    var io_state: std.Io.Threaded = .init(allocator, .{});
    defer io_state.deinit();
    const io = io_state.io();
    const cache_root = std.Io.Dir.cwd().openDir(
        io,
        cache_dir,
        .{},
    ) catch |err| return mapReadError(err);
    defer cache_root.close(io);

    const repomd_bytes = try readCacheMetadataFile(
        allocator,
        cache_root,
        io,
        "repodata/repomd.xml",
        null,
    );
    const parsed_repomd = repomd_xml.parse(
        allocator,
        repomd_bytes,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRepoMetadata,
    };

    var primary_record: ?*const model.Record = null;
    var filelists_record: ?*const model.Record = null;
    var updateinfo_record: ?*const model.Record = null;
    var other_record: ?*const model.Record = null;
    for (parsed_repomd.pRecords) |*record| {
        const raw_type = model.spanZ(record.pszType) orelse continue;
        const href = model.spanZ(record.pszLocationHref) orelse continue;
        try validateCacheMetadataPath(href);
        switch (model.kindFromRawType(raw_type)) {
            .primary => if (primary_record == null) {
                primary_record = record;
            },
            .filelists => if (options.include_filelists and
                filelists_record == null)
            {
                filelists_record = record;
            },
            .updateinfo => if (options.include_updateinfo and
                updateinfo_record == null)
            {
                updateinfo_record = record;
            },
            .other => if (options.include_other and other_record == null) {
                other_record = record;
            },
            else => {},
        }
    }

    const primary = primary_record orelse
        return error.InvalidRepoMetadata;
    return parseResolvedModel(allocator, parsed_repomd, .{
        .primary = try readCacheMetadataFile(
            allocator,
            cache_root,
            io,
            model.spanZ(primary.pszLocationHref).?,
            primary,
        ),
        .filelists = if (filelists_record) |record|
            try readCacheMetadataFile(
                allocator,
                cache_root,
                io,
                model.spanZ(record.pszLocationHref).?,
                record,
            )
        else
            null,
        .updateinfo = if (updateinfo_record) |record|
            try readCacheMetadataFile(
                allocator,
                cache_root,
                io,
                model.spanZ(record.pszLocationHref).?,
                record,
            )
        else
            null,
        .other = if (other_record) |record|
            try readCacheMetadataFile(
                allocator,
                cache_root,
                io,
                model.spanZ(record.pszLocationHref).?,
                record,
            )
        else
            null,
    });
}

fn validateCacheMetadataPath(
    href: []const u8,
) LoadError!void {
    if (href.len == 0 or
        std.fs.path.isAbsolute(href) or
        std.mem.indexOfScalar(u8, href, '\\') != null)
    {
        return error.InvalidRepoMetadata;
    }
    var components = std.mem.splitScalar(u8, href, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.InvalidRepoMetadata;
        }
    }
}

fn readCacheMetadataFile(
    allocator: std.mem.Allocator,
    cache_root: std.Io.Dir,
    io: std.Io,
    path: []const u8,
    record: ?*const model.Record,
) LoadError![]u8 {
    const file = try openCacheFile(cache_root, io, path);
    defer file.close(io);
    var reader = file.reader(io, &.{});
    const raw = reader.interface.allocRemaining(
        allocator,
        .limited(max_metadata_bytes),
    ) catch |err| return switch (err) {
        error.ReadFailed => mapReadError(reader.err.?),
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.StreamTooLong,
    };
    if (record) |metadata| {
        if (metadata.nHasSize != 0 and raw.len != metadata.nSize) {
            return error.InvalidRepoMetadata;
        }
        if (!metadata_integrity.digestMatches(metadata.checksum, raw)) {
            return error.InvalidRepoMetadata;
        }
    }
    const open = decompressMetadata(
        allocator,
        path,
        raw,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnsupportedCompressor => error.UnsupportedCompressor,
        error.DecompressFailed => error.DecompressFailed,
    };
    if (record) |metadata| {
        if (metadata.nHasOpenSize != 0 and
            open.len != metadata.nOpenSize)
        {
            return error.InvalidRepoMetadata;
        }
        if ((metadata.openChecksum.pszType != null or
            metadata.openChecksum.pszValue != null) and
            !metadata_integrity.digestMatches(
                metadata.openChecksum,
                open,
            ))
        {
            return error.InvalidRepoMetadata;
        }
    }
    return open;
}

fn openCacheFile(
    cache_root: std.Io.Dir,
    io: std.Io,
    path: []const u8,
) LoadError!std.Io.File {
    try validateCacheMetadataPath(path);
    var components = std.mem.splitScalar(u8, path, '/');
    var component = components.next() orelse
        return error.InvalidRepoMetadata;
    var current = cache_root;
    var owns_current = false;
    defer if (owns_current) current.close(io);

    while (components.next()) |next| {
        const child = current.openDir(io, component, .{
            .follow_symlinks = false,
        }) catch |err| return switch (err) {
            error.NotDir, error.SymLinkLoop => error.AccessDenied,
            else => mapReadError(err),
        };
        if (owns_current) current.close(io);
        current = child;
        owns_current = true;
        component = next;
    }

    return current.openFile(io, component, .{
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch |err| return switch (err) {
        error.SymLinkLoop => error.AccessDenied,
        else => mapReadError(err),
    };
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

test "cache loader rejects metadata paths outside the cache" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "cache/repodata");
    try tmp.dir.writeFile(
        std.testing.io,
        .{
            .sub_path = "cache/repodata/repomd.xml",
            .data =
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<repomd xmlns="http://linux.duke.edu/metadata/repo">
            \\  <data type="primary">
            \\    <location href="../primary.xml"/>
            \\  </data>
            \\</repomd>
            ,
        },
    );
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cache_dir = std.fmt.bufPrint(
        &path_buffer,
        ".zig-cache/tmp/{s}/cache",
        .{&tmp.sub_path},
    ) catch @panic("cache path too long");
    var arena_state = std.heap.ArenaAllocator.init(
        std.testing.allocator,
    );
    defer arena_state.deinit();
    try std.testing.expectError(
        error.InvalidRepoMetadata,
        loadCacheModel(arena_state.allocator(), cache_dir, .{}),
    );
}

test "cache loader rejects metadata symlink escapes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "cache/repodata");
    try tmp.dir.createDir(std.testing.io, "outside", .default_dir);
    try tmp.dir.writeFile(
        std.testing.io,
        .{
            .sub_path = "cache/repodata/repomd.xml",
            .data =
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<repomd xmlns="http://linux.duke.edu/metadata/repo">
            \\  <data type="primary">
            \\    <location href="repodata/link/primary.xml"/>
            \\  </data>
            \\</repomd>
            ,
        },
    );
    try tmp.dir.writeFile(
        std.testing.io,
        .{
            .sub_path = "outside/primary.xml",
            .data = fixture_primary,
        },
    );
    try tmp.dir.symLink(
        std.testing.io,
        "../../outside",
        "cache/repodata/link",
        .{ .is_directory = true },
    );
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cache_dir = std.fmt.bufPrint(
        &path_buffer,
        ".zig-cache/tmp/{s}/cache",
        .{&tmp.sub_path},
    ) catch @panic("cache path too long");
    var arena_state = std.heap.ArenaAllocator.init(
        std.testing.allocator,
    );
    defer arena_state.deinit();
    try std.testing.expectError(
        error.AccessDenied,
        loadCacheModel(arena_state.allocator(), cache_dir, .{}),
    );
}

test "cache loader rejects unverified sidecars" {
    const documents = [_][]const u8{
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<repomd xmlns="http://linux.duke.edu/metadata/repo">
        \\  <data type="primary">
        \\    <location href="repodata/primary.xml"/>
        \\  </data>
        \\</repomd>
        ,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<repomd xmlns="http://linux.duke.edu/metadata/repo">
        \\  <data type="primary">
        \\    <checksum type="sha256">0000000000000000000000000000000000000000000000000000000000000000</checksum>
        \\    <location href="repodata/primary.xml"/>
        \\  </data>
        \\</repomd>
        ,
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for (documents, 0..) |document, index| {
        var cache_buffer: [64]u8 = undefined;
        const cache = std.fmt.bufPrint(
            &cache_buffer,
            "cache-{d}",
            .{index},
        ) catch unreachable;
        var repodata_buffer: [64]u8 = undefined;
        const repodata = std.fmt.bufPrint(
            &repodata_buffer,
            "{s}/repodata",
            .{cache},
        ) catch unreachable;
        try tmp.dir.createDirPath(std.testing.io, repodata);
        var repomd_buffer: [96]u8 = undefined;
        const repomd_path = std.fmt.bufPrint(
            &repomd_buffer,
            "{s}/repomd.xml",
            .{repodata},
        ) catch unreachable;
        try tmp.dir.writeFile(
            std.testing.io,
            .{ .sub_path = repomd_path, .data = document },
        );
        var primary_buffer: [96]u8 = undefined;
        const primary_path = std.fmt.bufPrint(
            &primary_buffer,
            "{s}/primary.xml",
            .{repodata},
        ) catch unreachable;
        try tmp.dir.writeFile(
            std.testing.io,
            .{ .sub_path = primary_path, .data = fixture_primary },
        );

        var absolute_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const cache_dir = std.fmt.bufPrint(
            &absolute_buffer,
            ".zig-cache/tmp/{s}/{s}",
            .{ &tmp.sub_path, cache },
        ) catch @panic("cache path too long");
        var arena_state = std.heap.ArenaAllocator.init(
            std.testing.allocator,
        );
        defer arena_state.deinit();
        try std.testing.expectError(
            error.InvalidRepoMetadata,
            loadCacheModel(arena_state.allocator(), cache_dir, .{}),
        );
    }
}
