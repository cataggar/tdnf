const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("time.h");
    @cInclude("tdnferror.h");
    @cInclude("tdnfrepomd.h");
    @cInclude("solv/chksum.h");
    @cInclude("solv/pool.h");
    @cInclude("solv/repo.h");
    @cInclude("solv/repodata.h");
    @cInclude("solv/solvable.h");
    @cInclude("solv/repo_repomdxml.h");
    @cInclude("solv/repo_rpmmd.h");
    @cInclude("solv/repo_updateinfoxml.h");
});

const model = @import("model.zig");
const repomd_xml = @import("repomd.zig");
const primary_xml = @import("primary.zig");
const filelists_xml = @import("filelists.zig");
const other_xml = @import("other.zig");
const updateinfo_xml = @import("updateinfo.zig");

const max_metadata_bytes = 256 * 1024 * 1024;

threadlocal var last_native_error_buf: [512]u8 = undefined;
threadlocal var last_native_error_len: usize = 0;

const DecompressError = error{
    OutOfMemory,
    UnsupportedCompressor,
    DecompressFailed,
};

const LoadError = error{
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

const BuildError = error{
    InvalidRepoMetadata,
    OutOfMemory,
};

pub export fn TDNFRepoMdNativeLastError() [*:0]const u8 {
    if (last_native_error_len >= last_native_error_buf.len) {
        last_native_error_len = last_native_error_buf.len - 1;
    }
    last_native_error_buf[last_native_error_len] = 0;
    return @ptrCast(&last_native_error_buf);
}

pub export fn TDNFRepoMdNativeLoadSolvRepo(
    raw_repo: ?*c.Repo,
    repomd_path: ?[*:0]const u8,
    primary_path: ?[*:0]const u8,
    filelists_path: ?[*:0]const u8,
    updateinfo_path: ?[*:0]const u8,
    other_path: ?[*:0]const u8,
) u32 {
    clearError();

    const repo = raw_repo orelse {
        setError("null repo", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    if (repo.pool == null) {
        setError("repo has no pool", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    const repomd_slice = spanRequiredPath(repomd_path, "repomd") orelse return c.ERROR_TDNF_INVALID_PARAMETER;
    const primary_slice = spanRequiredPath(primary_path, "primary") orelse return c.ERROR_TDNF_INVALID_PARAMETER;

    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const repository = loadRepositoryModel(
        arena,
        repomd_slice,
        primary_slice,
        spanOptionalPath(filelists_path),
        spanOptionalPath(updateinfo_path),
        spanOptionalPath(other_path),
    ) catch |err| {
        return mapLoadError(err, repomd_slice);
    };

    buildRepositoryIntoRepo(arena, repo, &repository) catch |err| {
        return mapBuildError(err);
    };

    return 0;
}

fn clearError() void {
    last_native_error_len = 0;
}

fn setError(comptime fmt: []const u8, args: anytype) void {
    const msg = std.fmt.bufPrint(&last_native_error_buf, fmt, args) catch blk: {
        const fallback = "(native repomd bridge error truncated)";
        @memcpy(last_native_error_buf[0..fallback.len], fallback);
        break :blk last_native_error_buf[0..fallback.len];
    };
    last_native_error_len = msg.len;
}

fn spanRequiredPath(raw_path: ?[*:0]const u8, comptime label: []const u8) ?[]const u8 {
    const path = raw_path orelse {
        setError("null {s} path", .{label});
        return null;
    };
    const slice = std.mem.span(path);
    if (slice.len == 0) {
        setError("empty {s} path", .{label});
        return null;
    }
    return slice;
}

fn spanOptionalPath(raw_path: ?[*:0]const u8) ?[]const u8 {
    const path = raw_path orelse return null;
    const slice = std.mem.span(path);
    return if (slice.len == 0) null else slice;
}

fn mapLoadError(err: LoadError, repomd_path: []const u8) u32 {
    return switch (err) {
        error.InvalidRepoMetadata => blk: {
            setError("invalid repository metadata under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_INVALID_REPO_FILE;
        },
        error.OutOfMemory => blk: {
            setError("out of memory", .{});
            break :blk c.ERROR_TDNF_OUT_OF_MEMORY;
        },
        error.FileNotFound => blk: {
            setError("file not found under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_FILE_NOT_FOUND;
        },
        error.AccessDenied => blk: {
            setError("access denied under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_ACCESS_DENIED;
        },
        error.NameTooLong => blk: {
            setError("path too long under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_NAME_TOO_LONG;
        },
        error.BadPathName => blk: {
            setError("bad path under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_INVALID_PARAMETER;
        },
        error.NotDir, error.IsDir => blk: {
            setError("invalid directory under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_INVALID_DIR;
        },
        error.FileTooBig, error.StreamTooLong => blk: {
            setError("metadata file too large under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_OVERFLOW;
        },
        error.UnsupportedCompressor, error.DecompressFailed => blk: {
            setError("failed to decompress metadata under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_INVALID_REPO_FILE;
        },
        error.FileSystemIo => blk: {
            setError("filesystem IO error under {s}", .{repomd_path});
            break :blk c.ERROR_TDNF_FILESYS_IO;
        },
    };
}

fn mapBuildError(err: BuildError) u32 {
    return switch (err) {
        error.InvalidRepoMetadata => blk: {
            setError("invalid repository metadata model", .{});
            break :blk c.ERROR_TDNF_INVALID_REPO_FILE;
        },
        error.OutOfMemory => blk: {
            setError("out of memory", .{});
            break :blk c.ERROR_TDNF_OUT_OF_MEMORY;
        },
    };
}

fn loadRepositoryModel(
    allocator: std.mem.Allocator,
    repomd_path: []const u8,
    primary_path: []const u8,
    filelists_path: ?[]const u8,
    updateinfo_path: ?[]const u8,
    other_path: ?[]const u8,
) LoadError!model.RepositoryModel {
    const repomd_bytes = try readMetadataFile(allocator, repomd_path);
    const parsed_repomd = repomd_xml.parse(allocator, repomd_bytes) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRepoMetadata,
    };

    const primary_bytes = try readMetadataFile(allocator, primary_path);
    var parsed_primary = primary_xml.parse(allocator, primary_bytes) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRepoMetadata,
    };

    if (filelists_path) |path| {
        const filelists_bytes = try readMetadataFile(allocator, path);
        filelists_xml.parseAndApply(allocator, filelists_bytes, &parsed_primary) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRepoMetadata,
        };
    }

    if (other_path) |path| {
        const other_bytes = try readMetadataFile(allocator, path);
        other_xml.parseAndApply(allocator, other_bytes, &parsed_primary) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRepoMetadata,
        };
    }

    const parsed_updateinfo = if (updateinfo_path) |path| blk: {
        const updateinfo_bytes = try readMetadataFile(allocator, path);
        break :blk updateinfo_xml.parse(allocator, updateinfo_bytes) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRepoMetadata,
        };
    } else model.ParsedUpdateInfo{};

    return model.repositoryModelFromParts(parsed_repomd, parsed_primary, parsed_updateinfo);
}

fn readMetadataFile(allocator: std.mem.Allocator, path: []const u8) LoadError![]u8 {
    const raw = readFileAlloc(allocator, path) catch |err| return mapReadError(err);
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
        var decoder: std.compress.flate.Decompress = .init(&input, .gzip, &.{});
        return decoder.reader.allocRemaining(allocator, .unlimited) catch error.DecompressFailed;
    }
    if (std.mem.endsWith(u8, path, ".zst") or std.mem.endsWith(u8, path, ".zstd")) {
        var decoder: std.compress.zstd.Decompress = .init(&input, &.{}, .{});
        return decoder.reader.allocRemaining(allocator, .unlimited) catch error.DecompressFailed;
    }
    if (std.mem.endsWith(u8, path, ".xz")) {
        const start_buf = allocator.alloc(u8, 0) catch return error.OutOfMemory;
        var decoder = std.compress.xz.Decompress.init(&input, allocator, start_buf) catch return error.DecompressFailed;
        return decoder.reader.allocRemaining(allocator, .unlimited) catch error.DecompressFailed;
    }

    const out = allocator.alloc(u8, bytes.len) catch return error.OutOfMemory;
    @memcpy(out, bytes);
    return out;
}

const SolvBuilder = struct {
    arena: std.mem.Allocator,
    repo: *c.Repo,
    pool: *c.Pool,
    repository: *const model.RepositoryModel,
    package_solvids: []c.Id,

    fn init(arena: std.mem.Allocator, repo: *c.Repo, repository: *const model.RepositoryModel) BuildError!SolvBuilder {
        const pool = repo.pool orelse return error.InvalidRepoMetadata;
        return .{
            .arena = arena,
            .repo = repo,
            .pool = pool,
            .repository = repository,
            .package_solvids = try arena.alloc(c.Id, repository.packages.len),
        };
    }

    fn build(self: *SolvBuilder) BuildError!void {
        try self.addRepomdMetadata();
        try self.addPrimary();
        if (self.repository.has_filelists) {
            try self.addFilelists();
        }
        if (self.repository.has_updateinfo) {
            try self.addUpdateinfo();
        }
        if (self.repository.has_other) {
            try self.addOther();
        }
    }

    fn addRepomdMetadata(self: *SolvBuilder) BuildError!void {
        const data = c.repo_add_repodata(self.repo, 0) orelse return error.OutOfMemory;
        var newest_timestamp: u64 = 0;

        if (self.repository.pszRevision) |revision| {
            c.repodata_set_str(data, c.SOLVID_META, c.REPOSITORY_REVISION, revision);
        }

        for (self.repository.records) |record| {
            const handle = c.repodata_new_handle(data);
            if (record.pszType) |raw_type| {
                c.repodata_set_poolstr(data, handle, c.REPOSITORY_REPOMD_TYPE, raw_type);
            }
            if (record.pszLocationHref) |href| {
                c.repodata_set_str(data, handle, c.REPOSITORY_REPOMD_LOCATION, href);
            }
            if (record.checksum.pszType != null and record.checksum.pszValue != null) {
                try setChecksumZ(data, handle, c.REPOSITORY_REPOMD_CHECKSUM, record.checksum);
            }
            if (record.openChecksum.pszType != null and record.openChecksum.pszValue != null) {
                try setChecksumZ(data, handle, c.REPOSITORY_REPOMD_OPENCHECKSUM, record.openChecksum);
            }
            if (record.nHasTimestamp != 0) {
                c.repodata_set_num(data, handle, c.REPOSITORY_REPOMD_TIMESTAMP, record.nTimestamp);
                if (record.nTimestamp > newest_timestamp) {
                    newest_timestamp = record.nTimestamp;
                }
            }
            if (record.nHasSize != 0) {
                c.repodata_set_num(data, handle, c.REPOSITORY_REPOMD_SIZE, record.nSize);
            }
            c.repodata_add_flexarray(data, c.SOLVID_META, c.REPOSITORY_REPOMD, handle);
        }

        if (newest_timestamp != 0) {
            c.repodata_set_num(data, c.SOLVID_META, c.REPOSITORY_TIMESTAMP, newest_timestamp);
        }

        c.repodata_internalize(data);
    }

    fn addPrimary(self: *SolvBuilder) BuildError!void {
        const data = c.repo_add_repodata(self.repo, 0) orelse return error.OutOfMemory;

        for (self.repository.packages, 0..) |pkg, index| {
            const solvid = c.repo_add_solvable(self.repo);
            self.package_solvids[index] = solvid;
            const solvable = c.pool_id2solvable(self.pool, solvid) orelse return error.InvalidRepoMetadata;

            solvable.*.name = c.pool_str2id(self.pool, try z(self.arena, pkg.nevra.name), 1);
            solvable.*.arch = c.pool_str2id(self.pool, try z(self.arena, pkg.nevra.arch), 1);
            solvable.*.evr = try evrId(self.arena, self.pool, pkg.nevra.epoch, pkg.nevra.version, pkg.nevra.release);
            if (pkg.rpm.vendor) |vendor| {
                solvable.*.vendor = c.pool_str2id(self.pool, try z(self.arena, vendor), 1);
            }

            if (pkg.summary) |summary| {
                c.repodata_set_str(data, solvid, c.SOLVABLE_SUMMARY, try z(self.arena, summary));
            }
            if (pkg.description) |description| {
                c.repodata_set_str(data, solvid, c.SOLVABLE_DESCRIPTION, try z(self.arena, description));
            }
            if (pkg.packager) |packager| {
                c.repodata_set_poolstr(data, solvid, c.SOLVABLE_PACKAGER, try z(self.arena, packager));
            }
            if (pkg.url) |url| {
                c.repodata_set_str(data, solvid, c.SOLVABLE_URL, try z(self.arena, url));
            }
            if (pkg.time.build) |build_time| {
                c.repodata_set_num(data, solvid, c.SOLVABLE_BUILDTIME, build_time);
            }
            if (pkg.size.installed) |installed_size| {
                c.repodata_set_num(data, solvid, c.SOLVABLE_INSTALLSIZE, installed_size);
            }
            if (pkg.size.package) |download_size| {
                c.repodata_set_num(data, solvid, c.SOLVABLE_DOWNLOADSIZE, download_size);
            }
            if (pkg.rpm.group) |group| {
                c.repodata_set_poolstr(data, solvid, c.SOLVABLE_GROUP, try z(self.arena, group));
            }
            if (pkg.rpm.license) |license| {
                c.repodata_set_poolstr(data, solvid, c.SOLVABLE_LICENSE, try z(self.arena, license));
            }
            if (pkg.rpm.buildhost) |buildhost| {
                c.repodata_set_str(data, solvid, c.SOLVABLE_BUILDHOST, try z(self.arena, buildhost));
            }
            if (pkg.rpm.source_rpm) |source_rpm| {
                c.repodata_set_sourcepkg(data, solvid, try z(self.arena, source_rpm));
            }
            if (pkg.rpm.header_range) |header_range| {
                c.repodata_set_num(data, solvid, c.SOLVABLE_HEADEREND, header_range.end);
            }
            c.repodata_set_location(data, solvid, 0, null, try z(self.arena, pkg.location.href));
            if (pkg.location.xml_base) |xml_base| {
                c.repodata_set_poolstr(data, solvid, c.SOLVABLE_MEDIABASE, try z(self.arena, xml_base));
            }
            try setChecksumSlice(self.arena, data, solvid, c.SOLVABLE_CHECKSUM, pkg.checksum.kind, pkg.checksum.value);

            inline for ([_]struct { kind: model.DependencyKind, key: c.Id }{
                .{ .kind = .provides, .key = c.SOLVABLE_PROVIDES },
                .{ .kind = .requires, .key = c.SOLVABLE_REQUIRES },
                .{ .kind = .conflicts, .key = c.SOLVABLE_CONFLICTS },
                .{ .kind = .obsoletes, .key = c.SOLVABLE_OBSOLETES },
                .{ .kind = .recommends, .key = c.SOLVABLE_RECOMMENDS },
                .{ .kind = .suggests, .key = c.SOLVABLE_SUGGESTS },
                .{ .kind = .supplements, .key = c.SOLVABLE_SUPPLEMENTS },
                .{ .kind = .enhances, .key = c.SOLVABLE_ENHANCES },
            }) |entry| {
                const relations = pkg.relationsFor(entry.kind, self.repository.relations);
                for (relations) |relation| {
                    const dep = try relationId(self.arena, self.pool, relation);
                    const marker: c.Id = if (entry.kind == .requires)
                        if (relation.pre) c.SOLVABLE_PREREQMARKER else -c.SOLVABLE_PREREQMARKER
                    else
                        0;
                    c.repo_add_deparray(self.repo, solvid, entry.key, dep, marker);
                }
            }

            if (solvable.*.name != 0 and solvable.*.arch != c.ARCH_SRC and solvable.*.arch != c.ARCH_NOSRC) {
                const self_provide = c.pool_rel2id(self.pool, solvable.*.name, solvable.*.evr, c.REL_EQ, 1);
                c.repo_add_deparray(self.repo, solvid, c.SOLVABLE_PROVIDES, self_provide, 0);
            }
        }

        if (data.*.end > data.*.start) {
            c.repodata_set_filelisttype(data, c.REPODATA_FILELIST_FILTERED);
            c.repodata_set_void(data, c.SOLVID_META, c.REPOSITORY_FILTEREDFILELIST);
        }

        c.repodata_internalize(data);
    }

    fn addFilelists(self: *SolvBuilder) BuildError!void {
        const data = c.repo_add_repodata(self.repo, c.REPO_EXTEND_SOLVABLES) orelse return error.OutOfMemory;

        for (self.repository.packages, 0..) |pkg, index| {
            const solvid = self.package_solvids[index];
            const files = pkg.fileEntries(self.repository.files);
            for (files) |file_entry| {
                var dir_buf: []const u8 = "/";
                var name_buf: []const u8 = file_entry.path;
                if (std.mem.lastIndexOfScalar(u8, file_entry.path, '/')) |separator| {
                    if (separator == 0) {
                        dir_buf = "/";
                        name_buf = file_entry.path[1..];
                    } else {
                        dir_buf = file_entry.path[0..separator];
                        name_buf = file_entry.path[separator + 1 ..];
                    }
                }
                const dir_id = c.repodata_str2dir(data, try z(self.arena, dir_buf), 1);
                c.repodata_add_dirstr(data, solvid, c.SOLVABLE_FILELIST, dir_id, try z(self.arena, name_buf));
            }
        }

        c.repodata_set_filelisttype(data, c.REPODATA_FILELIST_EXTENSION);
        c.repodata_internalize(data);
    }

    fn addUpdateinfo(self: *SolvBuilder) BuildError!void {
        const data = c.repo_add_repodata(self.repo, 0) orelse return error.OutOfMemory;

        for (self.repository.advisories) |advisory| {
            const solvid = c.repo_add_solvable(self.repo);
            const solvable = c.pool_id2solvable(self.pool, solvid) orelse return error.InvalidRepoMetadata;
            const patch_name = try fmtZ(self.arena, "patch:{s}", .{advisory.id});
            solvable.*.name = c.pool_str2id(self.pool, patch_name, 1);
            solvable.*.arch = c.ARCH_NOARCH;
            solvable.*.evr = if (advisory.version) |version|
                c.pool_str2id(self.pool, try z(self.arena, version), 1)
            else
                0;
            if (advisory.from) |from| {
                solvable.*.vendor = c.pool_str2id(self.pool, try z(self.arena, from), 1);
            }

            c.repodata_set_str(data, solvid, c.SOLVABLE_PATCHCATEGORY, try z(self.arena, advisory.raw_type));
            if (advisory.status) |status| {
                c.repodata_set_poolstr(data, solvid, c.UPDATE_STATUS, try z(self.arena, status));
            }
            if (advisory.title) |title| {
                c.repodata_set_str(data, solvid, c.SOLVABLE_SUMMARY, try z(self.arena, title));
            }
            if (advisory.severity) |severity| {
                c.repodata_set_poolstr(data, solvid, c.UPDATE_SEVERITY, try z(self.arena, severity));
            }
            if (advisory.rights) |rights| {
                c.repodata_set_poolstr(data, solvid, c.UPDATE_RIGHTS, try z(self.arena, rights));
            }
            if (advisory.description) |description| {
                c.repodata_set_str(data, solvid, c.SOLVABLE_DESCRIPTION, try z(self.arena, description));
            }
            const build_time = advisoryBuildTime(advisory);
            if (build_time != 0) {
                c.repodata_set_num(data, solvid, c.SOLVABLE_BUILDTIME, build_time);
            }
            if (advisory.reboot_suggested) {
                c.repodata_set_void(data, solvid, c.UPDATE_REBOOT);
            }

            for (advisory.referenceEntries(self.repository.advisory_references)) |reference| {
                const ref_handle = c.repodata_new_handle(data);
                if (reference.href) |href| {
                    c.repodata_set_str(data, ref_handle, c.UPDATE_REFERENCE_HREF, try z(self.arena, href));
                }
                if (reference.id) |ref_id| {
                    c.repodata_set_str(data, ref_handle, c.UPDATE_REFERENCE_ID, try z(self.arena, ref_id));
                }
                if (reference.title) |title| {
                    c.repodata_set_str(data, ref_handle, c.UPDATE_REFERENCE_TITLE, try z(self.arena, title));
                }
                if (reference.raw_type) |raw_type| {
                    c.repodata_set_poolstr(data, ref_handle, c.UPDATE_REFERENCE_TYPE, try z(self.arena, raw_type));
                }
                c.repodata_add_flexarray(data, solvid, c.UPDATE_REFERENCE, ref_handle);
            }

            var collection_started = false;
            var collection_short: ?[]const u8 = null;
            var collection_name: ?[]const u8 = null;
            var collection_handle: c.Id = 0;
            for (advisory.packageEntries(self.repository.advisory_packages)) |pkg| {
                if (!collection_started or !sameOptional(pkg.collection_short, collection_short) or !sameOptional(pkg.collection_name, collection_name)) {
                    if (collection_started) {
                        c.repodata_add_flexarray(data, solvid, c.UPDATE_COLLECTIONLIST, collection_handle);
                    }
                    collection_started = true;
                    collection_short = pkg.collection_short;
                    collection_name = pkg.collection_name;
                    collection_handle = c.repodata_new_handle(data);
                }

                const pkg_handle = c.repodata_new_handle(data);
                const name_id = c.pool_str2id(self.pool, try z(self.arena, pkg.nevra.name), 1);
                const evr_id = try evrId(self.arena, self.pool, pkg.nevra.epoch, pkg.nevra.version, pkg.nevra.release);
                const arch_id = c.pool_str2id(self.pool, try z(self.arena, pkg.nevra.arch), 1);
                c.repodata_set_id(data, pkg_handle, c.UPDATE_COLLECTION_NAME, name_id);
                c.repodata_set_id(data, pkg_handle, c.UPDATE_COLLECTION_EVR, evr_id);
                if (arch_id != 0) {
                    c.repodata_set_id(data, pkg_handle, c.UPDATE_COLLECTION_ARCH, arch_id);
                }
                if (pkg.filename) |filename| {
                    c.repodata_set_str(data, pkg_handle, c.UPDATE_COLLECTION_FILENAME, try z(self.arena, filename));
                }
                if (pkg.reboot_suggested) {
                    c.repodata_set_void(data, solvid, c.UPDATE_REBOOT);
                    c.repodata_set_void(data, pkg_handle, c.UPDATE_REBOOT);
                }
                c.repodata_add_flexarray(data, solvid, c.UPDATE_COLLECTION, pkg_handle);
                c.repodata_add_flexarray(data, collection_handle, c.UPDATE_COLLECTION, pkg_handle);
                addAdvisoryConflict(self.repo, self.pool, solvid, name_id, arch_id, evr_id);
            }
            if (collection_started) {
                c.repodata_add_flexarray(data, solvid, c.UPDATE_COLLECTIONLIST, collection_handle);
            }

            const self_provide = c.pool_rel2id(self.pool, solvable.*.name, solvable.*.evr, c.REL_EQ, 1);
            c.repo_add_deparray(self.repo, solvid, c.SOLVABLE_PROVIDES, self_provide, 0);
        }

        c.repodata_internalize(data);
    }

    fn addOther(self: *SolvBuilder) BuildError!void {
        const data = c.repo_add_repodata(self.repo, c.REPO_EXTEND_SOLVABLES) orelse return error.OutOfMemory;

        for (self.repository.packages, 0..) |pkg, index| {
            const solvid = self.package_solvids[index];
            const changelogs = pkg.changelogEntries(self.repository.changelogs);
            for (changelogs) |entry| {
                const handle = c.repodata_new_handle(data);
                c.repodata_set_num(data, handle, c.SOLVABLE_CHANGELOG_TIME, entry.timestamp);
                c.repodata_set_str(data, handle, c.SOLVABLE_CHANGELOG_AUTHOR, try z(self.arena, entry.author));
                c.repodata_set_str(data, handle, c.SOLVABLE_CHANGELOG_TEXT, try z(self.arena, entry.text));
                c.repodata_add_flexarray(data, solvid, c.SOLVABLE_CHANGELOG, handle);
            }
        }

        c.repodata_internalize(data);
    }
};

fn buildRepositoryIntoRepo(arena: std.mem.Allocator, repo: *c.Repo, repository: *const model.RepositoryModel) BuildError!void {
    var builder = try SolvBuilder.init(arena, repo, repository);
    return builder.build();
}

fn setChecksumZ(data: *c.Repodata, solvid: c.Id, keyname: c.Id, checksum: model.Checksum) BuildError!void {
    const kind = checksum.pszType orelse return error.InvalidRepoMetadata;
    const value = checksum.pszValue orelse return error.InvalidRepoMetadata;
    const chksum_type = c.solv_chksum_str2type(kind);
    if (chksum_type == 0) {
        return error.InvalidRepoMetadata;
    }
    c.repodata_set_checksum(data, solvid, keyname, chksum_type, value);
}

fn setChecksumSlice(allocator: std.mem.Allocator, data: *c.Repodata, solvid: c.Id, keyname: c.Id, kind: []const u8, value: []const u8) BuildError!void {
    const kind_z = try z(allocator, kind);
    const value_z = try z(allocator, value);
    const chksum_type = c.solv_chksum_str2type(kind_z);
    if (chksum_type == 0) {
        return error.InvalidRepoMetadata;
    }
    c.repodata_set_checksum(data, solvid, keyname, chksum_type, value_z);
}

fn z(allocator: std.mem.Allocator, value: []const u8) BuildError![*:0]const u8 {
    const duped = allocator.dupeZ(u8, value) catch return error.OutOfMemory;
    return duped.ptr;
}

fn fmtZ(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) BuildError![*:0]const u8 {
    const text = std.fmt.allocPrint(allocator, fmt, args) catch return error.OutOfMemory;
    return z(allocator, text);
}

fn evrId(
    allocator: std.mem.Allocator,
    pool: *c.Pool,
    epoch: ?u32,
    version: []const u8,
    release: []const u8,
) BuildError!c.Id {
    return evrIdOptional(
        allocator,
        pool,
        epoch,
        if (version.len == 0) null else version,
        if (release.len == 0) null else release,
    );
}

fn evrIdOptional(
    allocator: std.mem.Allocator,
    pool: *c.Pool,
    epoch: ?u32,
    version: ?[]const u8,
    release: ?[]const u8,
) BuildError!c.Id {
    if (epoch == null and version == null and release == null) {
        return 0;
    }

    const use_epoch = epoch orelse if (version) |ver|
        if (needsZeroEpoch(ver)) @as(?u32, 0) else null
    else
        null;

    const evr = try fmtZ(
        allocator,
        "{s}{s}{s}",
        .{
            if (use_epoch) |value| try std.fmt.allocPrint(allocator, "{d}:", .{value}) else "",
            version orelse "",
            if (release) |value| try std.fmt.allocPrint(allocator, "-{s}", .{value}) else "",
        },
    );
    if (std.mem.len(evr) == 0) {
        return 0;
    }
    return c.pool_str2id(pool, evr, 1);
}

fn needsZeroEpoch(version: []const u8) bool {
    var index: usize = 0;
    while (index < version.len and version[index] >= '0' and version[index] <= '9') : (index += 1) {}
    return index > 0 and index < version.len and version[index] == ':';
}

fn relationId(
    allocator: std.mem.Allocator,
    pool: *c.Pool,
    relation: model.Relation,
) BuildError!c.Id {
    const name_id = c.pool_str2id(pool, try z(allocator, relation.name), 1);
    if (relation.flags == null or relation.comparison == .none) {
        return name_id;
    }
    const evr = try evrIdOptional(allocator, pool, relation.epoch, relation.version, relation.release);
    return c.pool_rel2id(pool, name_id, evr, compareOpToSolv(relation.comparison), 1);
}

fn compareOpToSolv(op: model.CompareOp) c_int {
    return switch (op) {
        .none => 0,
        .eq => c.REL_EQ,
        .lt => c.REL_LT,
        .le => c.REL_LT | c.REL_EQ,
        .gt => c.REL_GT,
        .ge => c.REL_GT | c.REL_EQ,
    };
}

fn addAdvisoryConflict(repo: *c.Repo, pool: *c.Pool, solvid: c.Id, name_id: c.Id, arch_id: c.Id, evr_id: c.Id) void {
    var conflict: c.Id = 0;
    if (arch_id != 0 and arch_id != c.ARCH_NOARCH) {
        conflict = c.pool_rel2id(pool, name_id, arch_id, c.REL_ARCH, 1);
        conflict = c.pool_rel2id(pool, conflict, evr_id, c.REL_LT, 1);
        c.repo_add_deparray(repo, solvid, c.SOLVABLE_CONFLICTS, conflict, 0);
        conflict = c.pool_rel2id(pool, name_id, c.ARCH_NOARCH, c.REL_ARCH, 1);
        conflict = c.pool_rel2id(pool, conflict, evr_id, c.REL_LT, 1);
        c.repo_add_deparray(repo, solvid, c.SOLVABLE_CONFLICTS, conflict, 0);
    } else {
        conflict = c.pool_rel2id(pool, name_id, evr_id, c.REL_LT, 1);
        c.repo_add_deparray(repo, solvid, c.SOLVABLE_CONFLICTS, conflict, 0);
    }
}

fn advisoryBuildTime(advisory: model.Advisory) u64 {
    const issued = if (advisory.issued) |text| parseDateToTimestamp(text) else 0;
    const updated = if (advisory.updated) |text| parseDateToTimestamp(text) else 0;
    return if (updated > issued) updated else issued;
}

fn parseDateToTimestamp(text: []const u8) u64 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    var tm: c.struct_tm = std.mem.zeroes(c.struct_tm);

    if (trimmed.len == 0) {
        return 0;
    }
    const numeric = std.fmt.parseInt(u64, trimmed, 10) catch null;
    if (numeric) |value| {
        return value;
    }

    const parts = parseIsoDateTime(trimmed) orelse return 0;
    tm.tm_year = @intCast(parts.year - 1900);
    tm.tm_mon = @intCast(parts.month - 1);
    tm.tm_mday = @intCast(parts.day);
    tm.tm_hour = @intCast(parts.hour);
    tm.tm_min = @intCast(parts.minute);
    tm.tm_sec = @intCast(parts.second);

    const stamp = c.timegm(&tm);
    return if (stamp >= 0) @intCast(stamp) else 0;
}

const ParsedDateTime = struct {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
};

fn parseIsoDateTime(text: []const u8) ?ParsedDateTime {
    if (text.len != 19 or (text[10] != ' ' and text[10] != 'T')) {
        return null;
    }
    if (text[4] != '-' or text[7] != '-' or text[13] != ':' or text[16] != ':') {
        return null;
    }

    const year = std.fmt.parseInt(u32, text[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u32, text[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u32, text[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(u32, text[11..13], 10) catch return null;
    const minute = std.fmt.parseInt(u32, text[14..16], 10) catch return null;
    const second = std.fmt.parseInt(u32, text[17..19], 10) catch return null;

    if (year < 1900 or month < 1 or month > 12 or day < 1 or day > 31 or
        hour > 23 or minute > 59 or second > 60)
    {
        return null;
    }

    return .{
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
    };
}

fn sameOptional(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null and right == null) return true;
    if (left == null or right == null) return false;
    return std.mem.eql(u8, left.?, right.?);
}
