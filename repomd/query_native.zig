const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("time.h");
    @cInclude("tdnferror.h");
    @cInclude("tdnf.h");
    @cInclude("tdnfrepomd.h");
    @cInclude("tdnftypes.h");
    @cInclude("rpmdb.h");
});

const model = @import("model.zig");
const pkgquery = @import("pkgquery.zig");
const query_index = @import("index.zig");
const rpmpkg = @import("rpmpkg.zig");
const rpm_header = @import("rpm_header");
const repomd_xml = @import("repomd.zig");
const solv_bridge = @import("solvbridge.zig");

extern fn TDNFUtilsFormatSize(unSize: u64, ppszFormattedSize: ?*?[*:0]u8) u32;

const system_repo_name = "@System";
const detail_list = 0;
const detail_info = 1;
const detail_changelog = 2;
const detail_sourcepkg = 3;
const detail_location = 4;

threadlocal var last_query_error_buf: [512]u8 = undefined;
threadlocal var last_query_error_len: usize = 0;

const NativeQueryError = error{
    OutOfMemory,
    InvalidParameter,
    InvalidRepoMetadata,
    InvalidRpmHeader,
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
    RpmDbOpenFailed,
    RpmDbReadFailed,
};

const DatasetKind = enum {
    installed,
    available,
};

const PackageRef = struct {
    dataset_index: usize,
    package_index: usize,
};

const AvailableLoadOptions = struct {
    need_filelists: bool = false,
    need_other: bool = false,
    need_updateinfo: bool = false,
};

const InstalledLoadOptions = struct {
    need_relations: bool = false,
    need_files: bool = false,
    need_changelogs: bool = false,
};

const AdvisoryRef = struct {
    dataset_index: usize,
    advisory_index: usize,
};

const SearchRef = union(enum) {
    package: PackageRef,
    advisory: AdvisoryRef,
};

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
            .changelogs = std.array_list.Managed(model.ChangelogEntry).init(allocator),
        };
    }

    fn deinit(self: *RepositoryBuilder) void {
        self.packages.deinit();
        self.relations.deinit();
        self.files.deinit();
        self.changelogs.deinit();
    }

    fn appendBuiltPackage(self: *RepositoryBuilder, built: rpmpkg.BuiltPackage) !void {
        var pkg = built.package;
        const relation_base = self.relations.items.len;
        const file_base = self.files.items.len;
        const changelog_base = self.changelogs.items.len;

        try self.relations.appendSlice(built.relations);
        try self.files.appendSlice(built.files);
        try self.changelogs.appendSlice(built.changelogs);

        pkg.provides.start += relation_base;
        pkg.requires.start += relation_base;
        pkg.conflicts.start += relation_base;
        pkg.obsoletes.start += relation_base;
        pkg.recommends.start += relation_base;
        pkg.suggests.start += relation_base;
        pkg.supplements.start += relation_base;
        pkg.enhances.start += relation_base;
        pkg.files.start += file_base;
        pkg.changelogs.start += changelog_base;

        try self.packages.append(pkg);
    }

    fn finish(self: *RepositoryBuilder) !model.RepositoryModel {
        return .{
            .packages = try self.packages.toOwnedSlice(),
            .relations = try self.relations.toOwnedSlice(),
            .files = try self.files.toOwnedSlice(),
            .changelogs = try self.changelogs.toOwnedSlice(),
        };
    }
};

const LoadedDataset = struct {
    kind: DatasetKind,
    repo_id: []const u8,
    arena_state: std.heap.ArenaAllocator,
    repository: model.RepositoryModel,
    index: ?query_index.RepositoryIndex = null,

    fn deinit(self: *LoadedDataset) void {
        if (self.index) |*index| {
            index.deinit();
        }
        self.arena_state.deinit();
        self.* = undefined;
    }

    fn allocator(self: *LoadedDataset) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    fn ensureIndex(self: *LoadedDataset) !*query_index.RepositoryIndex {
        if (self.index == null) {
            self.index = try query_index.RepositoryIndex.init(self.allocator(), &self.repository);
        }
        return &self.index.?;
    }
};

const NativeContext = struct {
    allocator: std.mem.Allocator,
    datasets: std.array_list.Managed(LoadedDataset),

    fn init(allocator: std.mem.Allocator) NativeContext {
        return .{
            .allocator = allocator,
            .datasets = std.array_list.Managed(LoadedDataset).init(allocator),
        };
    }

    fn deinit(self: *NativeContext) void {
        for (self.datasets.items) |*dataset| {
            dataset.deinit();
        }
        self.datasets.deinit();
    }

    fn load(
        self: *NativeContext,
        raw_repos: ?[*]const c.TDNF_REPOMD_NATIVE_REPO_INPUT,
        repo_count: u32,
        root_dir: ?[*:0]const u8,
        load_installed: bool,
        available_options: AvailableLoadOptions,
        installed_options: InstalledLoadOptions,
    ) !void {
        if (load_installed) {
            try self.datasets.append(try loadInstalledDataset(root_dir, installed_options));
        }

        const repos = if (raw_repos) |repos|
            repos[0..repo_count]
        else
            &[_]c.TDNF_REPOMD_NATIVE_REPO_INPUT{};
        for (repos) |repo| {
            try self.datasets.append(try loadAvailableDataset(repo, available_options));
        }
    }

    fn installedDatasetIndex(self: *const NativeContext) ?usize {
        for (self.datasets.items, 0..) |dataset, index| {
            if (dataset.kind == .installed) {
                return index;
            }
        }
        return null;
    }

    fn availableDatasetSlice(self: *const NativeContext) []const LoadedDataset {
        const start = if (self.installedDatasetIndex() != null) @as(usize, 1) else 0;
        return self.datasets.items[start..];
    }

    fn package(self: *const NativeContext, ref: PackageRef) model.Package {
        return self.datasets.items[ref.dataset_index].repository.packages[ref.package_index];
    }

    fn repoId(self: *const NativeContext, ref: PackageRef) []const u8 {
        return self.datasets.items[ref.dataset_index].repo_id;
    }

    fn relations(self: *const NativeContext, ref: PackageRef) []const model.Relation {
        return self.datasets.items[ref.dataset_index].repository.relations;
    }

    fn files(self: *const NativeContext, ref: PackageRef) []const model.FileEntry {
        return self.datasets.items[ref.dataset_index].repository.files;
    }

    fn changelogs(self: *const NativeContext, ref: PackageRef) []const model.ChangelogEntry {
        return self.datasets.items[ref.dataset_index].repository.changelogs;
    }
};

pub export fn TDNFRepoMdNativeQueryLastError() [*:0]const u8 {
    if (last_query_error_len >= last_query_error_buf.len) {
        last_query_error_len = last_query_error_buf.len - 1;
    }
    last_query_error_buf[last_query_error_len] = 0;
    return @ptrCast(&last_query_error_buf);
}

pub export fn TDNFRepoMdNativeList(
    raw_repos: ?[*]const c.TDNF_REPOMD_NATIVE_REPO_INPUT,
    repo_count: u32,
    root_dir: ?[*:0]const u8,
    scope_int: c_int,
    specs: [*c][*c]u8,
    detail_int: c_int,
    out_pkg_info: ?*c.PTDNF_PKG_INFO,
    out_count: ?*u32,
) u32 {
    clearError();
    if (out_pkg_info) |out| out.* = null;
    if (out_count) |out| out.* = 0;

    const out_items = out_pkg_info orelse return invalidParameter("null pkginfo output", .{});
    const out_total = out_count orelse return invalidParameter("null count output", .{});

    var ctx = NativeContext.init(std.heap.c_allocator);
    defer ctx.deinit();

    const scope: c_int = if (scope_int == c.SCOPE_NONE) c.SCOPE_ALL else scope_int;
    const need_installed = scopeNeedsInstalled(scope);
    const need_available = scopeNeedsAvailable(scope);

    ctx.load(raw_repos, repo_count, root_dir, need_installed, .{}, .{}) catch |err| {
        return mapQueryError(err);
    };
    if (!need_available and ctx.availableDatasetSlice().len != 0) {
        // Keep available data loaded if the caller passed it; selection scope
        // below will ignore it.
    }

    const has_specs = specs != null and specs[0] != null;
    const refs = selectListPackages(&ctx, scope, if (specs == null) null else specs) catch |err| {
        return mapQueryError(err);
    };
    defer std.heap.c_allocator.free(refs);

    if (refs.len == 0) {
        if (!has_specs) {
            return 0;
        }
        return c.ERROR_TDNF_NO_MATCH;
    }

    const pkg_infos = buildPackageInfoArray(&ctx, refs, detail_int, false, 0, false) catch |err| {
        return mapQueryError(err);
    };
    out_items.* = pkg_infos;
    out_total.* = @intCast(refs.len);
    return 0;
}

pub export fn TDNFRepoMdNativeSearch(
    raw_repos: ?[*]const c.TDNF_REPOMD_NATIVE_REPO_INPUT,
    repo_count: u32,
    root_dir: ?[*:0]const u8,
    search_strings: [*c][*c]u8,
    start_index: c_int,
    end_index: c_int,
    out_pkg_info: ?*c.PTDNF_PKG_INFO,
    out_count: ?*u32,
) u32 {
    clearError();
    if (out_pkg_info) |out| out.* = null;
    if (out_count) |out| out.* = 0;

    const out_items = out_pkg_info orelse return invalidParameter("null pkginfo output", .{});
    const out_total = out_count orelse return invalidParameter("null count output", .{});
    if (search_strings == null) {
        return invalidParameter("null search strings", .{});
    }
    const terms = search_strings;
    if (start_index < 0 or end_index < start_index) {
        return invalidParameter("invalid search bounds", .{});
    }

    var ctx = NativeContext.init(std.heap.c_allocator);
    defer ctx.deinit();

    ctx.load(
        raw_repos,
        repo_count,
        root_dir,
        true,
        .{ .need_updateinfo = true },
        .{},
    ) catch |err| {
        return mapQueryError(err);
    };

    const refs = searchPackages(&ctx, terms, @intCast(start_index), @intCast(end_index)) catch |err| {
        return mapQueryError(err);
    };
    defer std.heap.c_allocator.free(refs);

    if (refs.len == 0) {
        return c.ERROR_TDNF_NO_MATCH;
    }

    const pkg_infos = buildSearchInfoArray(&ctx, refs) catch |err| {
        return mapQueryError(err);
    };
    out_items.* = pkg_infos;
    out_total.* = @intCast(refs.len);
    return 0;
}

pub export fn TDNFRepoMdNativeProvides(
    raw_repos: ?[*]const c.TDNF_REPOMD_NATIVE_REPO_INPUT,
    repo_count: u32,
    root_dir: ?[*:0]const u8,
    raw_spec: ?[*:0]const u8,
    out_pkg_info: ?*c.PTDNF_PKG_INFO,
) u32 {
    clearError();
    if (out_pkg_info) |out| out.* = null;

    const out_items = out_pkg_info orelse return invalidParameter("null provides output", .{});
    const spec = spanRequired(raw_spec, "provides spec") orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var ctx = NativeContext.init(std.heap.c_allocator);
    defer ctx.deinit();

    ctx.load(
        raw_repos,
        repo_count,
        root_dir,
        true,
        .{ .need_filelists = spec.len != 0 and spec[0] == '/' },
        .{
            .need_relations = true,
            .need_files = spec.len != 0 and spec[0] == '/',
        },
    ) catch |err| {
        return mapQueryError(err);
    };

    const refs = selectProvidesPackages(&ctx, spec) catch |err| {
        return mapQueryError(err);
    };
    defer std.heap.c_allocator.free(refs);

    if (refs.len == 0) {
        return c.ERROR_TDNF_NO_MATCH;
    }

    out_items.* = buildProvidesInfoList(&ctx, refs) catch |err| {
        return mapQueryError(err);
    };
    return 0;
}

pub export fn TDNFRepoMdNativeRepoQuery(
    raw_repos: ?[*]const c.TDNF_REPOMD_NATIVE_REPO_INPUT,
    repo_count: u32,
    root_dir: ?[*:0]const u8,
    repoquery_args: ?*const c.TDNF_REPOQUERY_ARGS,
    out_pkg_info: ?*c.PTDNF_PKG_INFO,
    out_count: ?*u32,
) u32 {
    clearError();
    if (out_pkg_info) |out| out.* = null;
    if (out_count) |out| out.* = 0;

    const args = repoquery_args orelse return invalidParameter("null repoquery args", .{});
    const out_items = out_pkg_info orelse return invalidParameter("null pkginfo output", .{});
    const out_total = out_count orelse return invalidParameter("null count output", .{});

    var ctx = NativeContext.init(std.heap.c_allocator);
    defer ctx.deinit();

    const scope = repoQueryScope(args);
    ctx.load(
        raw_repos,
        repo_count,
        root_dir,
        repoQueryNeedsInstalled(args, scope),
        .{
            .need_filelists = args.nList != 0 or args.pszFile != null,
            .need_other = args.nChangeLogs != 0,
        },
        .{
            .need_relations = args.pppszWhatKeys != null or args.depKeySet != 0,
            .need_files = args.nList != 0 or args.pszFile != null,
            .need_changelogs = false,
        },
    ) catch |err| {
        return mapQueryError(err);
    };

    const refs = runRepoQuery(&ctx, args, scope) catch |err| {
        return mapQueryError(err);
    };
    defer std.heap.c_allocator.free(refs);

    if (refs.len == 0) {
        return c.ERROR_TDNF_NO_MATCH;
    }

    const fill_queryformat = args.pszQueryFormat != null;
    const detail = repoQueryDetail(args);
    const pkg_infos = buildPackageInfoArray(&ctx, refs, detail, fill_queryformat, args.depKeySet, args.nList != 0) catch |err| {
        return mapQueryError(err);
    };
    out_items.* = pkg_infos;
    out_total.* = @intCast(refs.len);
    return 0;
}

pub export fn TDNFRepoMdNativeUpdateAdvisoryIds(
    raw_repos: ?[*]const c.TDNF_REPOMD_NATIVE_REPO_INPUT,
    repo_count: u32,
    raw_name: ?[*:0]const u8,
    raw_arch: ?[*:0]const u8,
    raw_evr: ?[*:0]const u8,
    out_ids: ?*[*c][*c]u8,
    out_count: ?*u32,
) u32 {
    clearError();
    if (out_ids) |out| out.* = null;
    if (out_count) |out| out.* = 0;

    const name = spanRequired(raw_name, "package name") orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const arch = spanRequired(raw_arch, "package arch") orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const evr = spanRequired(raw_evr, "package evr") orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const ids_out = out_ids orelse return invalidParameter("null advisory id output", .{});
    const count_out = out_count orelse return invalidParameter("null advisory count output", .{});

    var ctx = NativeContext.init(std.heap.c_allocator);
    defer ctx.deinit();

    ctx.load(
        raw_repos,
        repo_count,
        null,
        false,
        .{ .need_updateinfo = true },
        .{},
    ) catch |err| {
        return mapQueryError(err);
    };

    const ids = selectUpdateAdvisoryIds(&ctx, name, arch, evr) catch |err| {
        return mapQueryError(err);
    };
    defer std.heap.c_allocator.free(ids);

    if (ids.len == 0) {
        return c.ERROR_TDNF_NO_DATA;
    }

    ids_out.* = (tryBuildCStringArray(ids) catch |err| {
        return mapQueryError(err);
    }) orelse null;
    count_out.* = @intCast(ids.len);
    return 0;
}

fn clearError() void {
    last_query_error_len = 0;
}

fn setError(comptime fmt: []const u8, args: anytype) void {
    const msg = std.fmt.bufPrint(&last_query_error_buf, fmt, args) catch blk: {
        const fallback = "(native query error truncated)";
        @memcpy(last_query_error_buf[0..fallback.len], fallback);
        break :blk last_query_error_buf[0..fallback.len];
    };
    last_query_error_len = msg.len;
}

fn setErrorDefault(comptime fmt: []const u8, args: anytype) void {
    if (last_query_error_len == 0) {
        setError(fmt, args);
    }
}

fn invalidParameter(comptime fmt: []const u8, args: anytype) u32 {
    setError(fmt, args);
    return c.ERROR_TDNF_INVALID_PARAMETER;
}

fn mapQueryError(err: anyerror) u32 {
    return switch (err) {
        error.OutOfMemory => blk: {
            setErrorDefault("out of memory", .{});
            break :blk c.ERROR_TDNF_OUT_OF_MEMORY;
        },
        error.InvalidParameter => blk: {
            setErrorDefault("invalid parameter", .{});
            break :blk c.ERROR_TDNF_INVALID_PARAMETER;
        },
        error.InvalidRepoMetadata => blk: {
            setErrorDefault("invalid repository metadata", .{});
            break :blk c.ERROR_TDNF_INVALID_REPO_FILE;
        },
        error.InvalidRpmHeader => blk: {
            setErrorDefault("invalid rpm header", .{});
            break :blk c.ERROR_TDNF_RPM_HEADER_CONVERT_FAILED;
        },
        error.FileNotFound => blk: {
            setErrorDefault("file not found", .{});
            break :blk c.ERROR_TDNF_FILE_NOT_FOUND;
        },
        error.AccessDenied => blk: {
            setErrorDefault("access denied", .{});
            break :blk c.ERROR_TDNF_ACCESS_DENIED;
        },
        error.NameTooLong => blk: {
            setErrorDefault("path too long", .{});
            break :blk c.ERROR_TDNF_NAME_TOO_LONG;
        },
        error.BadPathName => blk: {
            setErrorDefault("bad path", .{});
            break :blk c.ERROR_TDNF_INVALID_PARAMETER;
        },
        error.NotDir, error.IsDir => blk: {
            setErrorDefault("invalid directory", .{});
            break :blk c.ERROR_TDNF_INVALID_DIR;
        },
        error.FileTooBig, error.StreamTooLong => blk: {
            setErrorDefault("metadata too large", .{});
            break :blk c.ERROR_TDNF_OVERFLOW;
        },
        error.UnsupportedCompressor, error.DecompressFailed => blk: {
            setErrorDefault("failed to decompress repository metadata", .{});
            break :blk c.ERROR_TDNF_INVALID_REPO_FILE;
        },
        error.FileSystemIo => blk: {
            setErrorDefault("filesystem io error", .{});
            break :blk c.ERROR_TDNF_FILESYS_IO;
        },
        error.RpmDbOpenFailed => blk: {
            setErrorDefault("failed to open rpmdb: {s}", .{std.mem.span(c.tdnf_rpmdb_last_error())});
            break :blk c.ERROR_TDNF_RPMTS_OPENDB_FAILED;
        },
        error.RpmDbReadFailed => blk: {
            setErrorDefault("failed to read rpmdb: {s}", .{std.mem.span(c.tdnf_rpmdb_last_error())});
            break :blk c.ERROR_TDNF_SOLV_IO;
        },
        else => blk: {
            setErrorDefault("native query failure: {t}", .{err});
            break :blk c.ERROR_TDNF_SOLV_IO;
        },
    };
}

fn loadAvailableDataset(raw_repo: c.TDNF_REPOMD_NATIVE_REPO_INPUT, options: AvailableLoadOptions) !LoadedDataset {
    const repo_id = spanRequired(raw_repo.pszId, "repo id") orelse return error.InvalidParameter;
    const cache_dir = spanRequired(raw_repo.pszCacheDir, "repo cache dir") orelse return error.InvalidParameter;

    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    const repomd_path = try std.fs.path.join(arena, &.{ cache_dir, "repodata", "repomd.xml" });
    const repomd_bytes = readSmallFile(arena, repomd_path, 16 * 1024 * 1024) catch |err| {
        setError("failed to read {s}: {t}", .{ repomd_path, err });
        return err;
    };
    const parsed_repomd = repomd_xml.parse(arena, repomd_bytes) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRepoMetadata,
    };

    var primary_path: ?[]const u8 = null;
    var filelists_path: ?[]const u8 = null;
    var updateinfo_path: ?[]const u8 = null;
    var other_path: ?[]const u8 = null;

    for (parsed_repomd.pRecords) |record| {
        const raw_type = model.spanZ(record.pszType) orelse continue;
        const href = model.spanZ(record.pszLocationHref) orelse continue;
        const absolute = try std.fs.path.join(arena, &.{ cache_dir, href });
        switch (model.kindFromRawType(raw_type)) {
            .primary => {
                if (primary_path == null) primary_path = absolute;
            },
            .filelists => {
                if (options.need_filelists and filelists_path == null) filelists_path = absolute;
            },
            .updateinfo => {
                if (options.need_updateinfo and updateinfo_path == null) updateinfo_path = absolute;
            },
            .other => {
                if (options.need_other and other_path == null) other_path = absolute;
            },
            else => {},
        }
    }

    const primary = primary_path orelse return error.InvalidRepoMetadata;
    const repository = solv_bridge.loadRepositoryModel(arena, repomd_path, primary, filelists_path, updateinfo_path, other_path) catch |err| {
        setError(
            "failed to load repo '{s}' metadata: {s}",
            .{ repo_id, std.mem.span(solv_bridge.TDNFRepoMdNativeLastError()) },
        );
        return switch (err) {
            error.InvalidRepoMetadata => error.InvalidRepoMetadata,
            error.OutOfMemory => error.OutOfMemory,
            error.FileNotFound => error.FileNotFound,
            error.AccessDenied => error.AccessDenied,
            error.NameTooLong => error.NameTooLong,
            error.BadPathName => error.BadPathName,
            error.NotDir => error.NotDir,
            error.IsDir => error.IsDir,
            error.FileTooBig => error.FileTooBig,
            error.StreamTooLong => error.StreamTooLong,
            error.FileSystemIo => error.FileSystemIo,
            error.UnsupportedCompressor => error.UnsupportedCompressor,
            error.DecompressFailed => error.DecompressFailed,
        };
    };

    return .{
        .kind = .available,
        .repo_id = repo_id,
        .arena_state = arena_state,
        .repository = repository,
    };
}

fn loadInstalledDataset(root_dir: ?[*:0]const u8, options: InstalledLoadOptions) !LoadedDataset {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    const repository = try loadInstalledRepositoryModel(arena, root_dir, options);

    return .{
        .kind = .installed,
        .repo_id = system_repo_name,
        .arena_state = arena_state,
        .repository = repository,
    };
}

fn loadInstalledRepositoryModel(arena: std.mem.Allocator, root_dir: ?[*:0]const u8, options: InstalledLoadOptions) !model.RepositoryModel {
    var builder = RepositoryBuilder.init(arena);
    errdefer builder.deinit();

    const iter = c.tdnf_rpmdb_iter_open(root_dir) orelse return error.RpmDbOpenFailed;
    defer c.tdnf_rpmdb_iter_close(iter);

    while (true) {
        var blob_ptr: ?[*]const u8 = null;
        var blob_len: usize = 0;
        const rc = c.tdnf_rpmdb_iter_next_header_blob(iter, &blob_ptr, &blob_len);
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            return error.RpmDbReadFailed;
        }
        const ptr = blob_ptr orelse continue;
        if (blob_len == 0) {
            continue;
        }

        const blob = ptr[0..blob_len];
        const header = rpm_header.Header.parse(blob) catch return error.InvalidRpmHeader;
        if (header.getString(.name)) |name| {
            if (std.mem.eql(u8, name, "gpg-pubkey")) {
                continue;
            }
        }

        const built = rpmpkg.buildFromHeader(arena, header, .{
            .include_relations = options.need_relations,
            .include_files = options.need_files,
            .include_changelogs = options.need_changelogs,
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRpmHeader,
        };
        try builder.appendBuiltPackage(built);
    }

    return try builder.finish();
}

fn readSmallFile(allocator: std.mem.Allocator, path: []const u8, max_len: usize) ![]u8 {
    var io_state: std.Io.Threaded = .init(std.heap.c_allocator, .{});
    defer io_state.deinit();
    const io = io_state.io();

    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_len)) catch |err| return switch (err) {
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

fn scopeNeedsInstalled(scope: c_int) bool {
    return switch (scope) {
        c.SCOPE_AVAILABLE => false,
        else => true,
    };
}

fn scopeNeedsAvailable(scope: c_int) bool {
    return switch (scope) {
        c.SCOPE_INSTALLED => false,
        else => true,
    };
}

fn repoQueryNeedsInstalled(args: *const c.TDNF_REPOQUERY_ARGS, scope: c_int) bool {
    if (args.nExtras != 0 or args.nDuplicates != 0 or args.nUserInstalled != 0) {
        return true;
    }
    return scopeNeedsInstalled(scope);
}

fn repoQueryScope(args: *const c.TDNF_REPOQUERY_ARGS) c_int {
    if (args.nExtras != 0) {
        return c.SCOPE_ALL;
    }
    if (args.nUpgrades != 0) {
        return c.SCOPE_UPGRADES;
    }
    if (args.nDowngrades != 0) {
        return c.SCOPE_DOWNGRADES;
    }
    if (args.nInstalled == 0 or args.nAvailable != 0) {
        return c.SCOPE_AVAILABLE;
    }
    if (args.nInstalled != 0 or args.nDuplicates != 0) {
        return c.SCOPE_INSTALLED;
    }
    return c.SCOPE_ALL;
}

fn repoQueryDetail(args: *const c.TDNF_REPOQUERY_ARGS) c_int {
    if (args.nChangeLogs != 0) return detail_changelog;
    if (args.nSource != 0) return detail_sourcepkg;
    if (args.nLocation != 0) return detail_location;
    return detail_list;
}

fn selectListPackages(ctx: *NativeContext, scope: c_int, specs: ?[*c][*c]u8) ![]PackageRef {
    if (scope == c.SCOPE_UPGRADES or scope == c.SCOPE_DOWNGRADES) {
        return try selectUpDownCandidates(ctx, specs, scope == c.SCOPE_UPGRADES);
    }

    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    if (specs) |raw_specs| {
        if (raw_specs[0] != null) {
            var index_spec: usize = 0;
            while (raw_specs[index_spec] != null) : (index_spec += 1) {
                const spec = std.mem.span(raw_specs[index_spec]);
                try appendSelectionMatches(&results, ctx, scope, spec, false, true);
            }
            return try dedupeOwnedPackageRefs(try results.toOwnedSlice());
        }
    }

    try appendScopePackages(&results, ctx, scope);
    return try results.toOwnedSlice();
}

fn selectUpDownCandidates(ctx: *NativeContext, specs: ?[*c][*c]u8, up: bool) ![]PackageRef {
    var installed = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer installed.deinit();

    const installed_index = ctx.installedDatasetIndex() orelse return try std.heap.c_allocator.alloc(PackageRef, 0);
    const installed_dataset = &ctx.datasets.items[installed_index];

    if (specs) |raw_specs| {
        if (raw_specs[0] != null) {
            var spec_index: usize = 0;
            while (raw_specs[spec_index] != null) : (spec_index += 1) {
                const spec = std.mem.span(raw_specs[spec_index]);
                try appendDatasetSelectionMatches(&installed, ctx, installed_index, spec, false, true);
            }
        } else {
            for (installed_dataset.repository.packages, 0..) |_, pkg_index| {
                try installed.append(.{ .dataset_index = installed_index, .package_index = pkg_index });
            }
        }
    } else {
        for (installed_dataset.repository.packages, 0..) |_, pkg_index| {
            try installed.append(.{ .dataset_index = installed_index, .package_index = pkg_index });
        }
    }

    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    for (installed.items) |installed_ref| {
        const installed_pkg = ctx.package(installed_ref);
        for (ctx.datasets.items, 0..) |dataset, dataset_index| {
            if (dataset.kind != .available) {
                continue;
            }
            for (dataset.repository.packages, 0..) |candidate, pkg_index| {
                if (!std.mem.eql(u8, candidate.nevra.name, installed_pkg.nevra.name)) {
                    continue;
                }
                const cmp = query_index.comparePackageVersions(candidate, installed_pkg);
                if ((up and cmp > 0) or (!up and cmp < 0)) {
                    try results.append(.{ .dataset_index = dataset_index, .package_index = pkg_index });
                }
            }
        }
    }

    return try dedupeOwnedPackageRefs(try results.toOwnedSlice());
}

fn searchPackages(ctx: *NativeContext, search_strings: [*c][*c]u8, start_index: usize, end_index: usize) ![]SearchRef {
    var results = std.array_list.Managed(SearchRef).init(std.heap.c_allocator);
    defer results.deinit();

    var term_index = start_index;
    while (term_index < end_index) : (term_index += 1) {
        const raw_term = search_strings[term_index];
        if (raw_term == null) {
            continue;
        }
        const term = std.mem.span(raw_term);
        for (ctx.datasets.items, 0..) |*dataset, dataset_index| {
            const index = try dataset.ensureIndex();
            const matched = try index.searchText(dataset.allocator(), term);
            defer matched.deinit();
            for (matched.items) |pkg_index| {
                try results.append(.{ .package = .{ .dataset_index = dataset_index, .package_index = pkg_index } });
            }

            for (dataset.repository.advisories, 0..) |advisory, advisory_index| {
                if (!advisoryMatchesSearchTerm(advisory, term)) {
                    continue;
                }
                try results.append(.{ .advisory = .{ .dataset_index = dataset_index, .advisory_index = advisory_index } });
            }
        }
    }

    return try results.toOwnedSlice();
}

fn advisoryMatchesSearchTerm(advisory: model.Advisory, term: []const u8) bool {
    const trimmed = std.mem.trim(u8, term, " \t\r\n");
    if (trimmed.len == 0) {
        return false;
    }

    if (containsIgnoreCase(advisory.id, trimmed)) {
        return true;
    }
    if (advisory.title) |title| {
        if (containsIgnoreCase(title, trimmed)) {
            return true;
        }
    }
    if (advisory.description) |description| {
        if (containsIgnoreCase(description, trimmed)) {
            return true;
        }
    }
    return false;
}

fn selectProvidesPackages(ctx: *NativeContext, spec: []const u8) ![]PackageRef {
    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    for (ctx.datasets.items, 0..) |*dataset, dataset_index| {
        const refs = try selectProvidesMatchesForDataset(dataset, dataset_index, spec);
        defer std.heap.c_allocator.free(refs);
        try results.appendSlice(refs);
    }

    return try dedupeOwnedPackageRefs(try results.toOwnedSlice());
}

fn runRepoQuery(ctx: *NativeContext, args: *const c.TDNF_REPOQUERY_ARGS, scope: c_int) ![]PackageRef {
    var spec_array = [_][*c]u8{ null, null };
    const spec_ptr: ?[*c][*c]u8 = if (args.pszSpec != null) blk: {
        spec_array[0] = args.pszSpec;
        break :blk &spec_array;
    } else null;
    var refs = try selectRepoQueryPackages(ctx, scope, spec_ptr);
    errdefer std.heap.c_allocator.free(refs);

    if (args.ppszArchs != null) {
        refs = try filterByArch(ctx, refs, args.ppszArchs);
    }
    if (args.nExtras != 0) {
        refs = try filterExtras(ctx, refs);
    } else if (args.nDuplicates != 0) {
        refs = try filterDuplicates(ctx, refs);
    }

    if (args.pppszWhatKeys != null) {
        var what_key: usize = 0;
        while (what_key < c.REPOQUERY_WHAT_KEY_COUNT) : (what_key += 1) {
            if (args.pppszWhatKeys[what_key] != null) {
                refs = try filterWhatKey(ctx, refs, @intCast(what_key), args.pppszWhatKeys[what_key]);
            }
        }
    }

    if (args.pszFile != null) {
        refs = try filterByFile(ctx, refs, std.mem.span(args.pszFile));
    }

    return try dedupeOwnedPackageRefs(refs);
}

fn dedupeOwnedPackageRefs(refs: []PackageRef) ![]PackageRef {
    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    var seen = std.AutoHashMap(u64, void).init(std.heap.c_allocator);
    defer seen.deinit();

    for (refs) |ref| {
        const key = (@as(u64, @intCast(ref.dataset_index)) << 32) |
            @as(u64, @intCast(ref.package_index));
        const gop = try seen.getOrPut(key);
        if (gop.found_existing) {
            continue;
        }
        try results.append(ref);
    }

    std.heap.c_allocator.free(refs);
    return try results.toOwnedSlice();
}

fn appendScopePackages(list: *std.array_list.Managed(PackageRef), ctx: *NativeContext, scope: c_int) !void {
    for (ctx.datasets.items, 0..) |dataset, dataset_index| {
        if (!datasetInScope(dataset.kind, scope)) {
            continue;
        }
        for (dataset.repository.packages, 0..) |_, pkg_index| {
            try list.append(.{ .dataset_index = dataset_index, .package_index = pkg_index });
        }
    }
}

fn datasetInScope(kind: DatasetKind, scope: c_int) bool {
    return switch (scope) {
        c.SCOPE_INSTALLED => kind == .installed,
        c.SCOPE_AVAILABLE => kind == .available,
        else => true,
    };
}

fn selectRepoQueryPackages(ctx: *NativeContext, scope: c_int, specs: ?[*c][*c]u8) ![]PackageRef {
    if (scope == c.SCOPE_UPGRADES or scope == c.SCOPE_DOWNGRADES) {
        return try selectUpDownCandidates(ctx, specs, scope == c.SCOPE_UPGRADES);
    }

    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    if (specs) |raw_specs| {
        if (raw_specs[0] != null) {
            var index_spec: usize = 0;
            while (raw_specs[index_spec] != null) : (index_spec += 1) {
                const spec = std.mem.span(raw_specs[index_spec]);
                try appendSelectionMatches(&results, ctx, scope, spec, false, false);
            }
            return try dedupeOwnedPackageRefs(try results.toOwnedSlice());
        }
    }

    try appendScopePackages(&results, ctx, scope);
    return try results.toOwnedSlice();
}

fn appendSelectionMatches(list: *std.array_list.Managed(PackageRef), ctx: *NativeContext, scope: c_int, spec: []const u8, allow_filelist: bool, allow_provides: bool) !void {
    for (ctx.datasets.items, 0..) |dataset, dataset_index| {
        if (!datasetInScope(dataset.kind, scope)) {
            continue;
        }
        try appendDatasetSelectionMatches(list, ctx, dataset_index, spec, allow_filelist, allow_provides);
    }
}

fn appendDatasetSelectionMatches(list: *std.array_list.Managed(PackageRef), ctx: *NativeContext, dataset_index: usize, spec: []const u8, allow_filelist: bool, allow_provides: bool) !void {
    const dataset = &ctx.datasets.items[dataset_index];
    const matched = try selectPackageMatchesForDataset(dataset, dataset_index, spec, allow_filelist, allow_provides);
    defer std.heap.c_allocator.free(matched);
    try list.appendSlice(matched);
}

fn selectPackageMatchesForDataset(dataset: *LoadedDataset, dataset_index: usize, raw_spec: []const u8, allow_filelist: bool, allow_provides: bool) ![]PackageRef {
    const spec = std.mem.trim(u8, raw_spec, " \t\r\n");
    if (spec.len == 0) {
        return try std.heap.c_allocator.alloc(PackageRef, 0);
    }

    const mark_count = dataset.repository.packages.len;
    const seen = try std.heap.c_allocator.alloc(bool, mark_count);
    defer std.heap.c_allocator.free(seen);
    @memset(seen, false);

    var matched_any = false;
    matched_any = (try markSelectionMatches(dataset, spec, allow_filelist, allow_provides, false, seen)) or matched_any;
    if (!matched_any) {
        matched_any = (try markSelectionMatches(dataset, spec, false, false, true, seen)) or matched_any;
    }

    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();
    for (seen, 0..) |match, package_index| {
        if (match) {
            try results.append(.{ .dataset_index = dataset_index, .package_index = package_index });
        }
    }
    return try results.toOwnedSlice();
}

fn markSelectionMatches(dataset: *LoadedDataset, spec: []const u8, allow_filelist: bool, allow_provides: bool, ignore_case: bool, seen: []bool) !bool {
    var matched = false;
    const index = try dataset.ensureIndex();

    if (allow_filelist and spec.len != 0 and spec[0] == '/') {
        for (index.packagesProvidingFile(spec)) |pkg_index| {
            seen[pkg_index] = true;
            matched = true;
        }
    }

    const name_matches = try index.matchNamePattern(dataset.allocator(), spec, .{ .ignore_case = ignore_case });
    defer name_matches.deinit();
    for (name_matches.items) |pkg_index| {
        seen[pkg_index] = true;
        matched = true;
    }

    if (allow_provides and !containsGlobMeta(spec)) {
        const provide_matches = index.packagesProviding(dataset.allocator(), spec) catch |err| switch (err) {
            error.InvalidDependencyQuery => null,
            error.OutOfMemory => return error.OutOfMemory,
        };
        if (provide_matches) |matches| {
            defer matches.deinit();
            for (matches.items) |pkg_index| {
                seen[pkg_index] = true;
                matched = true;
            }
        }
    }

    if (query_index.DependencyQuery.parse(spec)) |query| {
        for (dataset.repository.packages, 0..) |pkg, pkg_index| {
            if (!nameEql(pkg.nevra.name, query.name, ignore_case)) {
                continue;
            }
            if (query.comparison != .none and !compareMatches(query_index.comparePackageWithQuery(pkg, query), query.comparison)) {
                continue;
            }
            seen[pkg_index] = true;
            matched = true;
        }
    } else |_| {}

    for (dataset.repository.packages, 0..) |pkg, pkg_index| {
        if (packageMatchesCanonLike(dataset.allocator(), pkg, spec, ignore_case)) {
            seen[pkg_index] = true;
            matched = true;
        }
    }

    return matched;
}

fn compareMatches(cmp: i32, op: model.CompareOp) bool {
    return switch (op) {
        .none => true,
        .eq => cmp == 0,
        .lt => cmp < 0,
        .le => cmp <= 0,
        .gt => cmp > 0,
        .ge => cmp >= 0,
    };
}

fn nameEql(left: []const u8, right: []const u8, ignore_case: bool) bool {
    return if (ignore_case) std.ascii.eqlIgnoreCase(left, right) else std.mem.eql(u8, left, right);
}

fn packageMatchesCanonLike(allocator: std.mem.Allocator, pkg: model.Package, spec: []const u8, ignore_case: bool) bool {
    const dotarch = std.fmt.allocPrint(allocator, "{s}.{s}", .{ pkg.nevra.name, pkg.nevra.arch }) catch return false;
    defer allocator.free(dotarch);
    if (stringEql(dotarch, spec, ignore_case)) {
        return true;
    }

    const nevr = pkgquery.nevrString(allocator, pkg) catch return false;
    defer allocator.free(nevr);
    if (stringEql(nevr, spec, ignore_case)) {
        return true;
    }

    const nevra = pkgquery.nevraString(allocator, pkg) catch return false;
    defer allocator.free(nevra);
    return stringEql(nevra, spec, ignore_case);
}

fn stringEql(left: []const u8, right: []const u8, ignore_case: bool) bool {
    return if (ignore_case) std.ascii.eqlIgnoreCase(left, right) else std.mem.eql(u8, left, right);
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) {
        return true;
    }
    if (needle.len > haystack.len) {
        return false;
    }

    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index .. index + needle.len], needle)) {
            return true;
        }
    }
    return false;
}

fn containsGlobMeta(pattern: []const u8) bool {
    for (pattern) |ch| {
        switch (ch) {
            '*', '?', '[', ']' => return true,
            else => {},
        }
    }
    return false;
}

fn selectProvidesMatchesForDataset(dataset: *LoadedDataset, dataset_index: usize, spec: []const u8) ![]PackageRef {
    const index = try dataset.ensureIndex();
    const mark_count = dataset.repository.packages.len;
    var seen = try std.heap.c_allocator.alloc(bool, mark_count);
    defer std.heap.c_allocator.free(seen);
    @memset(seen, false);

    if (spec.len != 0 and spec[0] == '/') {
        for (index.packagesProvidingFile(spec)) |pkg_index| {
            seen[pkg_index] = true;
        }
    }

    if (!containsGlobMeta(spec)) {
        const provide_matches = index.packagesProviding(dataset.allocator(), spec) catch |err| switch (err) {
            error.InvalidDependencyQuery => null,
            error.OutOfMemory => return error.OutOfMemory,
        };
        if (provide_matches) |matches| {
            defer matches.deinit();
            for (matches.items) |pkg_index| {
                seen[pkg_index] = true;
            }
        }
    }

    const name_matches = try index.matchNamePattern(dataset.allocator(), spec, .{ .ignore_case = false });
    defer name_matches.deinit();
    for (name_matches.items) |pkg_index| {
        seen[pkg_index] = true;
    }
    if (name_matches.items.len == 0) {
        const nocase = try index.matchNamePattern(dataset.allocator(), spec, .{ .ignore_case = true });
        defer nocase.deinit();
        for (nocase.items) |pkg_index| {
            seen[pkg_index] = true;
        }
    }

    for (dataset.repository.packages, 0..) |pkg, pkg_index| {
        if (packageMatchesCanonLike(dataset.allocator(), pkg, spec, false) or packageMatchesCanonLike(dataset.allocator(), pkg, spec, true)) {
            seen[pkg_index] = true;
        }
    }

    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();
    for (seen, 0..) |match, pkg_index| {
        if (match) {
            try results.append(.{ .dataset_index = dataset_index, .package_index = pkg_index });
        }
    }
    return try results.toOwnedSlice();
}

fn filterByArch(ctx: *NativeContext, refs: []PackageRef, raw_archs: [*c][*c]u8) ![]PackageRef {
    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    for (refs) |ref| {
        const pkg = ctx.package(ref);
        if (archInArray(pkg.nevra.arch, raw_archs)) {
            try results.append(ref);
        }
    }
    std.heap.c_allocator.free(refs);
    return try results.toOwnedSlice();
}

fn archInArray(arch: []const u8, raw_archs: [*c][*c]u8) bool {
    var index_arch: usize = 0;
    while (raw_archs[index_arch] != null) : (index_arch += 1) {
        if (std.mem.eql(u8, arch, std.mem.span(raw_archs[index_arch]))) {
            return true;
        }
    }
    return false;
}

fn filterByFile(ctx: *NativeContext, refs: []PackageRef, path: []const u8) ![]PackageRef {
    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    for (refs) |ref| {
        const pkg = ctx.package(ref);
        for (pkg.fileEntries(ctx.files(ref))) |entry| {
            if (std.mem.eql(u8, entry.path, path)) {
                try results.append(ref);
                break;
            }
        }
    }

    std.heap.c_allocator.free(refs);
    return try results.toOwnedSlice();
}

fn filterWhatKey(ctx: *NativeContext, refs: []PackageRef, what_key: usize, raw_deps: [*c][*c]u8) ![]PackageRef {
    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    for (refs) |ref| {
        if (packageMatchesWhatKey(ctx, ref, what_key, raw_deps)) {
            try results.append(ref);
        }
    }

    std.heap.c_allocator.free(refs);
    return try results.toOwnedSlice();
}

fn packageMatchesWhatKey(ctx: *NativeContext, ref: PackageRef, what_key: usize, raw_deps: [*c][*c]u8) bool {
    const pkg = ctx.package(ref);
    const relations = ctx.relations(ref);

    var dep_index: usize = 0;
    while (raw_deps[dep_index] != null) : (dep_index += 1) {
        const raw_dep = std.mem.span(raw_deps[dep_index]);
        const query = query_index.DependencyQuery.parse(raw_dep) catch continue;
        if (what_key == c.REPOQUERY_WHAT_KEY_DEPENDS) {
            const depends_kinds = [_]model.DependencyKind{ .requires, .recommends, .suggests, .supplements, .enhances };
            for (depends_kinds) |kind| {
                for (pkg.relationsFor(kind, relations)) |relation| {
                    if (query_index.relationMatchesQuery(relation, query)) {
                        return true;
                    }
                }
            }
        } else {
            const kind = relationKindForWhatKey(what_key) orelse continue;
            for (pkg.relationsFor(kind, relations)) |relation| {
                if (query_index.relationMatchesQuery(relation, query)) {
                    return true;
                }
            }
        }
    }

    return false;
}

fn relationKindForWhatKey(what_key: usize) ?model.DependencyKind {
    return switch (what_key) {
        c.REPOQUERY_WHAT_KEY_PROVIDES => .provides,
        c.REPOQUERY_WHAT_KEY_OBSOLETES => .obsoletes,
        c.REPOQUERY_WHAT_KEY_CONFLICTS => .conflicts,
        c.REPOQUERY_WHAT_KEY_REQUIRES => .requires,
        c.REPOQUERY_WHAT_KEY_RECOMMENDS => .recommends,
        c.REPOQUERY_WHAT_KEY_SUGGESTS => .suggests,
        c.REPOQUERY_WHAT_KEY_SUPPLEMENTS => .supplements,
        c.REPOQUERY_WHAT_KEY_ENHANCES => .enhances,
        else => null,
    };
}

fn filterExtras(ctx: *NativeContext, refs: []PackageRef) ![]PackageRef {
    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    for (refs, 0..) |ref, index_ref| {
        const pkg = ctx.package(ref);
        if (ctx.datasets.items[ref.dataset_index].kind != .installed) {
            continue;
        }
        var found = false;
        for (refs, 0..) |other_ref, other_index| {
            if (index_ref == other_index) {
                continue;
            }
            const other_pkg = ctx.package(other_ref);
            if (ctx.datasets.items[other_ref.dataset_index].kind == .installed) {
                continue;
            }
            if (std.mem.eql(u8, pkg.nevra.name, other_pkg.nevra.name) and
                std.mem.eql(u8, pkg.nevra.arch, other_pkg.nevra.arch) and
                query_index.comparePackageVersions(pkg, other_pkg) == 0)
            {
                found = true;
                break;
            }
        }
        if (!found) {
            try results.append(ref);
        }
    }

    std.heap.c_allocator.free(refs);
    return try results.toOwnedSlice();
}

fn filterDuplicates(ctx: *NativeContext, refs: []PackageRef) ![]PackageRef {
    var results = std.array_list.Managed(PackageRef).init(std.heap.c_allocator);
    defer results.deinit();

    for (refs, 0..) |ref, index_ref| {
        const pkg = ctx.package(ref);
        if (ctx.datasets.items[ref.dataset_index].kind != .installed) {
            continue;
        }
        var found = false;
        var other_index = index_ref + 1;
        while (other_index < refs.len) : (other_index += 1) {
            const other_ref = refs[other_index];
            if (ctx.datasets.items[other_ref.dataset_index].kind != .installed) {
                continue;
            }
            const other_pkg = ctx.package(other_ref);
            if (std.mem.eql(u8, pkg.nevra.name, other_pkg.nevra.name) and
                std.mem.eql(u8, pkg.nevra.arch, other_pkg.nevra.arch))
            {
                found = true;
                break;
            }
        }
        if (found) {
            try results.append(ref);
        }
    }

    std.heap.c_allocator.free(refs);
    return try results.toOwnedSlice();
}

fn selectUpdateAdvisoryIds(ctx: *NativeContext, name: []const u8, arch: []const u8, evr: []const u8) ![][]const u8 {
    const evr_parts = splitEvrQuery(evr);
    var results = std.array_list.Managed([]const u8).init(std.heap.c_allocator);
    defer results.deinit();

    for (ctx.datasets.items) |dataset| {
        if (dataset.kind != .available or !dataset.repository.has_updateinfo) {
            continue;
        }
        for (dataset.repository.advisories) |advisory| {
            var newer = false;
            for (advisory.packageEntries(dataset.repository.advisory_packages)) |advisory_pkg| {
                if (!std.mem.eql(u8, advisory_pkg.nevra.name, name) or !std.mem.eql(u8, advisory_pkg.nevra.arch, arch)) {
                    continue;
                }
                const cmp = query_index.compareEvr(
                    advisory_pkg.nevra.epoch,
                    advisory_pkg.nevra.version,
                    if (advisory_pkg.nevra.release.len == 0) null else advisory_pkg.nevra.release,
                    evr_parts.epoch,
                    if (evr_parts.version.len == 0) null else evr_parts.version,
                    evr_parts.release,
                );
                if (cmp > 0) {
                    newer = true;
                    break;
                }
            }
            if (newer) {
                try results.append(advisory.id);
            }
        }
    }

    return try results.toOwnedSlice();
}

const EvrQueryParts = struct {
    epoch: ?u32,
    version: []const u8,
    release: ?[]const u8,
};

fn splitEvrQuery(evr: []const u8) EvrQueryParts {
    const text = std.fmt.allocPrint(std.heap.c_allocator, "pkg = {s}", .{evr}) catch {
        return .{ .epoch = null, .version = evr, .release = null };
    };
    defer std.heap.c_allocator.free(text);

    const query = query_index.DependencyQuery.parse(text) catch {
        return .{ .epoch = null, .version = evr, .release = null };
    };
    return .{
        .epoch = query.epoch,
        .version = query.version orelse "",
        .release = query.release,
    };
}

fn tryBuildCStringArray(items: []const []const u8) !?[*c][*c]u8 {
    const raw = c.calloc(items.len + 1, @sizeOf([*c]u8)) orelse return error.OutOfMemory;
    const out: [*c][*c]u8 = @ptrCast(@alignCast(raw));
    var populated: usize = 0;
    errdefer {
        var index: usize = 0;
        while (index < populated) : (index += 1) {
            if (out[index] != null) {
                _ = c.free(out[index]);
            }
        }
        c.free(raw);
    }

    for (items, 0..) |item, index| {
        out[index] = try dupCString(item);
        populated += 1;
    }
    return out;
}

fn buildSearchInfoArray(ctx: *NativeContext, refs: []const SearchRef) !c.PTDNF_PKG_INFO {
    const raw = c.calloc(refs.len, @sizeOf(c.TDNF_PKG_INFO)) orelse return error.OutOfMemory;
    const array: c.PTDNF_PKG_INFO = @ptrCast(@alignCast(raw));
    errdefer c.TDNFFreePackageInfoArray(array, @intCast(refs.len));

    for (refs, 0..) |ref, index| {
        const item: c.PTDNF_PKG_INFO = @ptrCast(array + index);
        switch (ref) {
            .package => |pkg_ref| {
                const pkg = ctx.package(pkg_ref);
                try fillBasicPkgIdentity(item, ctx.repoId(pkg_ref), pkg, ctx.datasets.items[pkg_ref.dataset_index].kind == .available);
                item[0].pszSummary = try dupOptionalCString(pkgquery.summary(pkg));
            },
            .advisory => |adv_ref| {
                const advisory = ctx.datasets.items[adv_ref.dataset_index].repository.advisories[adv_ref.advisory_index];
                const advisory_name = try std.fmt.allocPrint(std.heap.c_allocator, "patch:{s}", .{advisory.id});
                defer std.heap.c_allocator.free(advisory_name);
                item[0].pszName = try dupCString(advisory_name);
                item[0].pszRepoName = try dupCString(ctx.datasets.items[adv_ref.dataset_index].repo_id);
                item[0].pszSummary = try dupOptionalCString(advisory.title);
            },
        }
        if (index + 1 < refs.len) {
            item[0].pNext = @ptrCast(array + index + 1);
        }
    }

    return array;
}

fn buildProvidesInfoList(ctx: *NativeContext, refs: []const PackageRef) !c.PTDNF_PKG_INFO {
    var head: c.PTDNF_PKG_INFO = null;
    errdefer c.TDNFFreePackageInfo(head);

    for (refs) |ref| {
        const node = @as(c.PTDNF_PKG_INFO, @ptrCast(@alignCast(c.calloc(1, @sizeOf(c.TDNF_PKG_INFO)) orelse return error.OutOfMemory)));
        const pkg = ctx.package(ref);
        try fillBasicPkgIdentity(node, ctx.repoId(ref), pkg, ctx.datasets.items[ref.dataset_index].kind == .available);
        node[0].pszSummary = try dupOptionalCString(pkgquery.summary(pkg));
        node[0].pNext = head;
        head = node;
    }

    return head;
}

fn buildPackageInfoArray(ctx: *NativeContext, refs: []const PackageRef, detail: c_int, fill_queryformat: bool, dep_key_set: c_uint, fill_file_list: bool) !c.PTDNF_PKG_INFO {
    const raw = c.calloc(refs.len, @sizeOf(c.TDNF_PKG_INFO)) orelse return error.OutOfMemory;
    const array: c.PTDNF_PKG_INFO = @ptrCast(@alignCast(raw));
    errdefer c.TDNFFreePackageInfoArray(array, @intCast(refs.len));

    for (refs, 0..) |ref, index| {
        const item: c.PTDNF_PKG_INFO = @ptrCast(array + index);
        const pkg = ctx.package(ref);
        const explicit_epoch = ctx.datasets.items[ref.dataset_index].kind == .available;
        try fillBasicPkgIdentity(item, ctx.repoId(ref), pkg, explicit_epoch);

        if (fill_queryformat) {
            try fillQueryFormatFields(item, ctx, ref, explicit_epoch);
        } else switch (detail) {
            detail_info => try fillInfoFields(item, pkg),
            detail_changelog => try fillChangelogFields(item, ctx, ref),
            detail_sourcepkg => try fillSourceField(item, pkg, explicit_epoch),
            detail_location => try fillLocationField(item, pkg),
            else => {},
        }

        if (fill_file_list) {
            try fillFileListField(item, ctx, ref);
        } else if (dep_key_set != 0) {
            try fillDependencyFields(item, ctx, ref, dep_key_set);
        }

        if (index + 1 < refs.len) {
            item[0].pNext = @ptrCast(array + index + 1);
        }
    }

    return array;
}

fn fillBasicPkgIdentity(item: c.PTDNF_PKG_INFO, repo_id: []const u8, pkg: model.Package, explicit_zero_epoch: bool) !void {
    item[0].dwEpoch = pkgquery.epoch(pkg) orelse 0;
    item[0].pszName = try dupCString(pkgquery.name(pkg));
    item[0].pszRepoName = try dupCString(repo_id);
    item[0].pszVersion = try dupCString(pkgquery.version(pkg));
    item[0].pszRelease = try dupCString(pkgquery.release(pkg));
    item[0].pszArch = try dupCString(pkgquery.arch(pkg));
    const evr = try pkgquery.evrString(std.heap.c_allocator, pkg);
    defer std.heap.c_allocator.free(evr);
    if (explicit_zero_epoch) {
        const explicit_evr = try ensureExplicitEpochString(std.heap.c_allocator, item[0].dwEpoch, evr);
        defer std.heap.c_allocator.free(explicit_evr);
        item[0].pszEVR = try dupCString(explicit_evr);
    } else {
        item[0].pszEVR = try dupCString(evr);
    }
}

fn fillInfoFields(item: c.PTDNF_PKG_INFO, pkg: model.Package) !void {
    try fillSizeFields(item, pkg);
    item[0].pszSummary = try dupOptionalCString(pkgquery.summary(pkg));
    item[0].pszURL = try dupOptionalCString(pkgquery.url(pkg));
    item[0].pszLicense = try dupOptionalCString(pkgquery.license(pkg));
    item[0].pszDescription = try dupOptionalCString(pkgquery.description(pkg));
}

fn fillQueryFormatFields(item: c.PTDNF_PKG_INFO, ctx: *NativeContext, ref: PackageRef, explicit_zero_epoch: bool) !void {
    const pkg = ctx.package(ref);
    try fillInfoFields(item, pkg);
    try fillSourceField(item, pkg, explicit_zero_epoch);
    try fillLocationField(item, pkg);
}

fn fillSizeFields(item: c.PTDNF_PKG_INFO, pkg: model.Package) !void {
    const install_size = pkgquery.installSize(pkg) orelse 0;
    const download_size = pkgquery.downloadSize(pkg) orelse 0;
    item[0].dwInstallSizeBytes = truncateU64ToU32(install_size);
    item[0].dwDownloadSizeBytes = truncateU64ToU32(download_size);

    if (TDNFUtilsFormatSize(install_size, &item[0].pszFormattedSize) != 0) {
        return error.OutOfMemory;
    }
    if (TDNFUtilsFormatSize(download_size, &item[0].pszFormattedDownloadSize) != 0) {
        return error.OutOfMemory;
    }
}

fn truncateU64ToU32(value: u64) u32 {
    return if (value > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(value);
}

fn fillSourceField(item: c.PTDNF_PKG_INFO, pkg: model.Package, explicit_zero_epoch: bool) !void {
    const src_name = pkgquery.sourceName(pkg) orelse return;
    const src_arch = pkgquery.sourceArch(pkg) orelse return;
    const source_evr = (try pkgquery.sourceEvrString(std.heap.c_allocator, pkg)) orelse return;
    defer std.heap.c_allocator.free(source_evr);

    const source_text = if (explicit_zero_epoch)
        try ensureExplicitEpochString(std.heap.c_allocator, pkgquery.epoch(pkg) orelse 0, source_evr)
    else
        try std.heap.c_allocator.dupe(u8, source_evr);
    defer std.heap.c_allocator.free(source_text);

    const text = try std.fmt.allocPrint(std.heap.c_allocator, "{s}-{s}.{s}", .{ src_name, source_text, src_arch });
    defer std.heap.c_allocator.free(text);
    item[0].pszSourcePkg = try dupCString(text);
}

fn fillLocationField(item: c.PTDNF_PKG_INFO, pkg: model.Package) !void {
    const href = pkgquery.locationHref(pkg);
    if (href.len == 0) {
        return;
    }
    const resolved = try pkgquery.resolvedLocation(std.heap.c_allocator, pkg);
    defer std.heap.c_allocator.free(resolved);
    item[0].pszLocation = try dupCString(resolved);
}

fn fillFileListField(item: c.PTDNF_PKG_INFO, ctx: *NativeContext, ref: PackageRef) !void {
    const pkg = ctx.package(ref);
    const files = try pkgquery.filePaths(std.heap.c_allocator, pkg, ctx.files(ref));
    defer files.deinit();
    item[0].ppszFileList = (try buildOwnedCStringArray(files.items)) orelse null;
}

fn fillDependencyFields(item: c.PTDNF_PKG_INFO, ctx: *NativeContext, ref: PackageRef, dep_key_set: c_uint) !void {
    const raw = c.calloc(c.REPOQUERY_DEP_KEY_COUNT, @sizeOf([*c][*c]u8)) orelse return error.OutOfMemory;
    item[0].pppszDependencies = @ptrCast(@alignCast(raw));

    var dep_key: usize = 0;
    while (dep_key < c.REPOQUERY_DEP_KEY_COUNT) : (dep_key += 1) {
        const mask: c_uint = @as(c_uint, 1) << @intCast(dep_key);
        if ((dep_key_set & mask) == 0) {
            continue;
        }

        const strings = try dependencyStringsForKey(ctx, ref, dep_key);
        defer strings.deinit();
        item[0].pppszDependencies[dep_key] = (try buildOwnedCStringArray(strings.items)) orelse null;
    }
}

fn fillChangelogFields(item: c.PTDNF_PKG_INFO, ctx: *NativeContext, ref: PackageRef) !void {
    const pkg = ctx.package(ref);
    const entries = pkgquery.changelogEntries(pkg, ctx.changelogs(ref));
    var head: c.PTDNF_PKG_CHANGELOG_ENTRY = null;
    var tail: c.PTDNF_PKG_CHANGELOG_ENTRY = null;

    var index: usize = entries.len;
    while (index > 0) {
        index -= 1;
        const entry = entries[index];
        const node = @as(c.PTDNF_PKG_CHANGELOG_ENTRY, @ptrCast(@alignCast(c.calloc(1, @sizeOf(c.TDNF_PKG_CHANGELOG_ENTRY)) orelse return error.OutOfMemory)));
        node[0].timeTime = @intCast(entry.timestamp);
        node[0].pszAuthor = try dupCString(entry.author);
        node[0].pszText = try dupCString(entry.text);
        if (head == null) {
            head = node;
        } else {
            tail[0].pNext = node;
        }
        tail = node;
    }

    item[0].pChangeLogEntries = head;
}

fn ensureExplicitEpochString(allocator: std.mem.Allocator, epoch: u32, evr: []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, evr, ':') != null) {
        return allocator.dupe(u8, evr);
    }
    return std.fmt.allocPrint(allocator, "{d}:{s}", .{ epoch, evr });
}

fn dependencyStringsForKey(ctx: *NativeContext, ref: PackageRef, dep_key: usize) !pkgquery.OwnedStrings {
    const pkg = ctx.package(ref);
    const relations = ctx.relations(ref);
    return switch (dep_key) {
        c.REPOQUERY_DEP_KEY_PROVIDES => pkgquery.providesStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_OBSOLETES => pkgquery.obsoletesStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_CONFLICTS => pkgquery.conflictsStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_REQUIRES => pkgquery.requiresStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_RECOMMENDS => pkgquery.recommendsStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_SUGGESTS => pkgquery.suggestsStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_SUPPLEMENTS => pkgquery.supplementsStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_ENHANCES => pkgquery.enhancesStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_DEPENDS => pkgquery.dependsStrings(std.heap.c_allocator, pkg, relations),
        c.REPOQUERY_DEP_KEY_REQUIRES_PRE => pkgquery.requiresPreStrings(std.heap.c_allocator, pkg, relations),
        else => pkgquery.OwnedStrings{ .allocator = std.heap.c_allocator, .items = try std.heap.c_allocator.alloc([]const u8, 0) },
    };
}

fn buildOwnedCStringArray(items: []const []const u8) !?[*c][*c]u8 {
    const raw = c.calloc(items.len + 1, @sizeOf([*c]u8)) orelse return error.OutOfMemory;
    const out: [*c][*c]u8 = @ptrCast(@alignCast(raw));
    var populated: usize = 0;
    errdefer {
        var index: usize = 0;
        while (index < populated) : (index += 1) {
            if (out[index] != null) {
                c.free(out[index]);
            }
        }
        c.free(raw);
    }

    for (items, 0..) |item, index| {
        out[index] = try dupCString(item);
        populated += 1;
    }
    return out;
}

fn dupCString(text: []const u8) ![*:0]u8 {
    const raw = c.calloc(text.len + 1, 1) orelse return error.OutOfMemory;
    const out: [*:0]u8 = @ptrCast(raw);
    @memcpy(out[0..text.len], text);
    out[text.len] = 0;
    return out;
}

fn dupOptionalCString(text: ?[]const u8) !?[*:0]u8 {
    if (text) |value| {
        return try dupCString(value);
    }
    return null;
}

fn spanRequired(raw: ?[*:0]const u8, comptime label: []const u8) ?[]const u8 {
    const ptr = raw orelse {
        setError("null {s}", .{label});
        return null;
    };
    const text = std.mem.span(ptr);
    if (text.len == 0) {
        setError("empty {s}", .{label});
        return null;
    }
    return text;
}
