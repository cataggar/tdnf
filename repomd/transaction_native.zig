const std = @import("std");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("tdnferror.h");
    @cInclude("tdnfrepomd.h");
    @cInclude("rpmdb.h");
});

const model = @import("model.zig");
const pkgquery = @import("pkgquery.zig");
const query_index = @import("index.zig");
const rpmpkg = @import("rpmpkg.zig");
const rpm_header = @import("rpm_header");
const rpm_pkgfile = @import("rpm_pkgfile");

threadlocal var last_error_buf: [512]u8 = undefined;
threadlocal var last_error_len: usize = 0;

const sense_posttrans: u32 = 1 << 5;
const sense_prereq: u32 = 1 << 6;
const sense_pretrans: u32 = 1 << 7;
const sense_script_pre: u32 = 1 << 9;
const sense_script_post: u32 = 1 << 10;
const sense_script_preun: u32 = 1 << 11;
const sense_script_postun: u32 = 1 << 12;
const sense_script_verify: u32 = 1 << 13;
const sense_preuntrans: u32 = 1 << 20;
const sense_postuntrans: u32 = 1 << 21;
const sense_rpmlib: u32 = 1 << 24;
const sense_keyring: u32 = 1 << 26;
const sense_config: u32 = 1 << 28;
const sense_meta: u32 = 1 << 29;

const force_order_only_mask: u32 =
    sense_script_pre |
    sense_script_post |
    sense_script_preun |
    sense_script_postun;
const unordered_only_mask: u32 =
    sense_rpmlib |
    sense_config |
    sense_pretrans |
    sense_posttrans |
    sense_preuntrans |
    sense_postuntrans |
    sense_script_verify |
    sense_meta;
const special_final_check_mask: u32 =
    sense_rpmlib |
    sense_keyring |
    sense_config |
    sense_script_verify |
    sense_meta |
    sense_preuntrans |
    sense_postuntrans;

const order_dep_kinds = [_]model.DependencyKind{
    .requires,
};

const all_dep_kinds = [_]model.DependencyKind{
    .provides,
    .requires,
    .conflicts,
    .obsoletes,
    .recommends,
    .suggests,
    .supplements,
    .enhances,
};

const TransactionError = error{
    OutOfMemory,
    InvalidParameter,
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

const PackageView = struct {
    pkg: model.Package,
    relations: []const model.Relation,
    files: []const model.FileEntry,

    fn relationEntries(self: PackageView, kind: model.DependencyKind) []const model.Relation {
        return self.pkg.relationsFor(kind, self.relations);
    }

    fn fileEntries(self: PackageView) []const model.FileEntry {
        return self.pkg.fileEntries(self.files);
    }
};

const TransactionOperation = enum(u32) {
    install = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_INSTALL,
    reinstall = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_REINSTALL,
    erase = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE,
    upgrade = c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_UPGRADE,
};

const TransactionPackage = struct {
    input_index: usize,
    op: TransactionOperation,
    view: PackageView,
};

const EvrParts = struct {
    epoch: ?u32 = null,
    version: []const u8 = "",
    release: ?[]const u8 = null,
};

const EraseQuery = struct {
    name: []const u8,
    evr: EvrParts,
    arch: ?[]const u8 = null,
};

const ParsedTransaction = struct {
    added: std.array_list.Managed(TransactionPackage),
    erased: std.array_list.Managed(TransactionPackage),
    erase_mask: []bool,
    replace_mask: []bool,

    fn init(allocator: std.mem.Allocator, installed_count: usize) !ParsedTransaction {
        return .{
            .added = std.array_list.Managed(TransactionPackage).init(allocator),
            .erased = std.array_list.Managed(TransactionPackage).init(allocator),
            .erase_mask = try allocator.alloc(bool, installed_count),
            .replace_mask = try allocator.alloc(bool, installed_count),
        };
    }
};

const FinalBuildResult = struct {
    repository: model.RepositoryModel,
    installed_to_final: []?usize,
    added_to_final: []usize,
    added_base: usize,
};

const RepositoryBuilder = struct {
    allocator: std.mem.Allocator,
    packages: std.array_list.Managed(model.Package),
    relations: std.array_list.Managed(model.Relation),
    files: std.array_list.Managed(model.FileEntry),

    fn init(allocator: std.mem.Allocator) RepositoryBuilder {
        return .{
            .allocator = allocator,
            .packages = std.array_list.Managed(model.Package).init(allocator),
            .relations = std.array_list.Managed(model.Relation).init(allocator),
            .files = std.array_list.Managed(model.FileEntry).init(allocator),
        };
    }

    fn appendPackageView(self: *RepositoryBuilder, view: PackageView) !usize {
        var pkg = view.pkg;
        inline for (all_dep_kinds) |kind| {
            const entries = view.relationEntries(kind);
            pkg.rangePtr(kind).* = .{
                .start = self.relations.items.len,
                .len = entries.len,
            };
            try self.relations.appendSlice(entries);
        }

        const file_entries = view.fileEntries();
        pkg.files = .{
            .start = self.files.items.len,
            .len = file_entries.len,
        };
        try self.files.appendSlice(file_entries);

        const index = self.packages.items.len;
        try self.packages.append(pkg);
        return index;
    }

    fn finish(self: *RepositoryBuilder) !model.RepositoryModel {
        return .{
            .packages = try self.packages.toOwnedSlice(),
            .relations = try self.relations.toOwnedSlice(),
            .files = try self.files.toOwnedSlice(),
        };
    }
};

const ProblemCollector = struct {
    allocator: std.mem.Allocator,
    messages: std.array_list.Managed([]const u8),
    seen: std.StringHashMap(void),

    fn init(allocator: std.mem.Allocator) ProblemCollector {
        return .{
            .allocator = allocator,
            .messages = std.array_list.Managed([]const u8).init(allocator),
            .seen = std.StringHashMap(void).init(allocator),
        };
    }

    fn add(self: *ProblemCollector, msg: []const u8) !void {
        const gop = try self.seen.getOrPut(msg);
        if (gop.found_existing) {
            return;
        }
        try self.messages.append(msg);
    }
};

fn clearError() void {
    last_error_len = 0;
}

fn setError(comptime fmt: []const u8, args: anytype) void {
    const msg = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
        const fallback = "(rpmzig transaction error truncated)";
        @memcpy(last_error_buf[0..fallback.len], fallback);
        break :blk last_error_buf[0..fallback.len];
    };
    last_error_len = msg.len;
}

pub export fn TDNFRepoMdNativeTransactionLastError() [*:0]const u8 {
    if (last_error_len >= last_error_buf.len) {
        last_error_len = last_error_buf.len - 1;
    }
    last_error_buf[last_error_len] = 0;
    return @ptrCast(&last_error_buf);
}

pub export fn TDNFRepoMdNativeTransactionSolve(
    raw_items: ?[*]const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    item_count: u32,
    root_dir: ?[*:0]const u8,
    out_order_lines: ?*[*c][*c]u8,
    out_order_count: ?*u32,
    out_problem_lines: ?*[*c][*c]u8,
    out_problem_count: ?*u32,
) u32 {
    clearError();
    if (out_order_lines) |out| out.* = null;
    if (out_order_count) |out| out.* = 0;
    if (out_problem_lines) |out| out.* = null;
    if (out_problem_count) |out| out.* = 0;

    const order_out = out_order_lines orelse return invalidParameter("null order output", .{});
    const order_count_out = out_order_count orelse return invalidParameter("null order count output", .{});
    const problem_out = out_problem_lines orelse return invalidParameter("null problem output", .{});
    const problem_count_out = out_problem_count orelse return invalidParameter("null problem count output", .{});

    const items = if (raw_items) |ptr|
        ptr[0..item_count]
    else if (item_count == 0)
        &[_]c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM{}
    else
        return invalidParameter("null transaction input", .{});

    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const installed_repo = loadInstalledRepositoryModel(arena, root_dir) catch |err| {
        return mapTransactionError(err);
    };

    var tx = parseTransaction(arena, items, installed_repo) catch |err| {
        return mapTransactionError(err);
    };

    const final_build = buildFinalRepository(arena, installed_repo, &tx) catch |err| {
        return mapTransactionError(err);
    };

    var installed_index = query_index.RepositoryIndex.init(arena, &installed_repo) catch {
        return mapTransactionError(error.OutOfMemory);
    };
    var final_index = query_index.RepositoryIndex.init(arena, &final_build.repository) catch {
        return mapTransactionError(error.OutOfMemory);
    };

    var problems = ProblemCollector.init(arena);
    collectNativeProblems(arena, &problems, &tx, installed_repo, final_build, &installed_index, &final_index) catch |err| {
        return mapTransactionError(err);
    };

    const order = buildNativeOrder(arena, tx.added.items, tx.erased.items) catch |err| {
        return mapTransactionError(err);
    };

    const order_lines = buildIndexLines(arena, order) catch |err| {
        return mapTransactionError(err);
    };
    const problem_lines = problems.messages.toOwnedSlice() catch {
        return mapTransactionError(error.OutOfMemory);
    };

    order_out.* = (tryBuildCStringArray(order_lines) catch |err| {
        return mapTransactionError(err);
    }) orelse null;
    order_count_out.* = @intCast(order_lines.len);

    problem_out.* = (tryBuildCStringArray(problem_lines) catch |err| {
        return mapTransactionError(err);
    }) orelse null;
    problem_count_out.* = @intCast(problem_lines.len);
    return 0;
}

fn invalidParameter(comptime fmt: []const u8, args: anytype) u32 {
    setError(fmt, args);
    return c.ERROR_TDNF_INVALID_PARAMETER;
}

fn mapTransactionError(err: anyerror) u32 {
    return switch (err) {
        error.OutOfMemory => c.ERROR_TDNF_OUT_OF_MEMORY,
        error.InvalidParameter => blk: {
            if (last_error_len == 0) {
                setError("invalid transaction input", .{});
            }
            break :blk c.ERROR_TDNF_INVALID_PARAMETER;
        },
        error.InvalidRpmHeader => blk: {
            if (last_error_len == 0) {
                setError("invalid rpm header", .{});
            }
            break :blk c.ERROR_TDNF_RPM_HEADER_CONVERT_FAILED;
        },
        error.FileNotFound => blk: {
            if (last_error_len == 0) {
                setError("file not found", .{});
            }
            break :blk c.ERROR_TDNF_FILE_NOT_FOUND;
        },
        error.AccessDenied => blk: {
            if (last_error_len == 0) {
                setError("access denied", .{});
            }
            break :blk c.ERROR_TDNF_ACCESS_DENIED;
        },
        error.NameTooLong => blk: {
            if (last_error_len == 0) {
                setError("path too long", .{});
            }
            break :blk c.ERROR_TDNF_NAME_TOO_LONG;
        },
        error.BadPathName => blk: {
            if (last_error_len == 0) {
                setError("bad path", .{});
            }
            break :blk c.ERROR_TDNF_INVALID_PARAMETER;
        },
        error.NotDir, error.IsDir => blk: {
            if (last_error_len == 0) {
                setError("invalid directory", .{});
            }
            break :blk c.ERROR_TDNF_INVALID_DIR;
        },
        error.FileTooBig, error.StreamTooLong => blk: {
            if (last_error_len == 0) {
                setError("file too large", .{});
            }
            break :blk c.ERROR_TDNF_OVERFLOW;
        },
        error.UnsupportedCompressor, error.DecompressFailed => blk: {
            if (last_error_len == 0) {
                setError("failed to parse rpm payload", .{});
            }
            break :blk c.ERROR_TDNF_INVALID_REPO_FILE;
        },
        error.FileSystemIo => blk: {
            if (last_error_len == 0) {
                setError("filesystem io error", .{});
            }
            break :blk c.ERROR_TDNF_FILESYS_IO;
        },
        error.RpmDbOpenFailed => blk: {
            if (last_error_len == 0) {
                setError("failed to open rpmdb: {s}", .{std.mem.span(c.tdnf_rpmdb_last_error())});
            }
            break :blk c.ERROR_TDNF_RPMTS_OPENDB_FAILED;
        },
        error.RpmDbReadFailed => blk: {
            if (last_error_len == 0) {
                setError("failed to read rpmdb: {s}", .{std.mem.span(c.tdnf_rpmdb_last_error())});
            }
            break :blk c.ERROR_TDNF_SOLV_IO;
        },
        else => blk: {
            if (last_error_len == 0) {
                setError("native transaction failure: {t}", .{err});
            }
            break :blk c.ERROR_TDNF_SOLV_IO;
        },
    };
}

fn loadInstalledRepositoryModel(
    arena: std.mem.Allocator,
    root_dir: ?[*:0]const u8,
) TransactionError!model.RepositoryModel {
    var builder = RepositoryBuilder.init(arena);
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

        const header = rpm_header.Header.parse(ptr[0..blob_len]) catch return error.InvalidRpmHeader;
        if (header.getString(.name)) |name| {
            if (std.mem.eql(u8, name, "gpg-pubkey")) {
                continue;
            }
        }

        const built = rpmpkg.buildFromHeader(arena, header, .{
            .include_relations = true,
            .include_files = true,
            .include_changelogs = false,
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRpmHeader,
        };
        _ = try builder.appendPackageView(.{
            .pkg = built.package,
            .relations = built.relations,
            .files = built.files,
        });
    }

    return try builder.finish();
}

fn parseTransaction(
    arena: std.mem.Allocator,
    items: []const c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    installed_repo: model.RepositoryModel,
) TransactionError!ParsedTransaction {
    var tx = try ParsedTransaction.init(arena, installed_repo.packages.len);
    @memset(tx.erase_mask, false);
    @memset(tx.replace_mask, false);

    for (items, 0..) |item, input_index| {
        const op = switch (item.dwOperation) {
            c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_INSTALL => TransactionOperation.install,
            c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_REINSTALL => TransactionOperation.reinstall,
            c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_ERASE => TransactionOperation.erase,
            c.TDNF_REPOMD_NATIVE_TRANSACTION_OP_UPGRADE => TransactionOperation.upgrade,
            else => return error.InvalidParameter,
        };
        switch (op) {
            .install, .reinstall, .upgrade => {
                const path = item.pszPath orelse {
                    setError("transaction item {d} missing rpm path", .{input_index});
                    return error.InvalidParameter;
                };
                const path_text = std.mem.span(path);
                const path_z = std.heap.c_allocator.dupeZ(u8, path_text) catch return error.OutOfMemory;
                defer std.heap.c_allocator.free(path_z);

                var rpm = rpm_pkgfile.RpmFile.open(std.heap.c_allocator, path_z) catch |err| {
                    setError("failed to open rpm {s}: {t}", .{ path_text, err });
                    return switch (err) {
                        error.OutOfMemory => error.OutOfMemory,
                        error.OpenFailed, error.StatFailed, error.ReadFailed => error.FileSystemIo,
                        error.BadLeadMagic, error.HeaderParseFailed => error.InvalidRpmHeader,
                        error.UnsupportedCompressor => error.UnsupportedCompressor,
                        error.DecompressFailed => error.DecompressFailed,
                    };
                };
                defer rpm.close(std.heap.c_allocator);

                const built = rpmpkg.buildFromRpmFile(arena, &rpm, path_text) catch |err| return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.InvalidRpmHeader,
                };
                try tx.added.append(.{
                    .input_index = input_index,
                    .op = op,
                    .view = .{
                        .pkg = built.package,
                        .relations = built.relations,
                        .files = built.files,
                    },
                });
            },
            .erase => {
                const query = try parseEraseQuery(item, input_index);
                const match_index = findInstalledEraseMatch(installed_repo, query) orelse {
                    setError(
                        "failed to match erase target {s}-{s}.{s} in installed rpmdb",
                        .{
                            query.name,
                            formatEvrForError(query.evr),
                            query.arch orelse "",
                        },
                    );
                    return error.InvalidParameter;
                };
                tx.erase_mask[match_index] = true;
                try tx.erased.append(.{
                    .input_index = input_index,
                    .op = .erase,
                    .view = installedPackageView(installed_repo, match_index),
                });
            },
        }
    }

    // Two-pass replacement detection:
    //   pass 1: exact NEVRA match (reinstall or install-of-already-installed)
    //   pass 2: name+arch match against an `upgrade` op — the solver has
    //           already decided this addition supersedes the installed
    //           instance, so mark the installed row as replaced so it
    //           drops out of the "final" repository view. This is what
    //           lets the file-conflict check ignore paths that the OLD
    //           version legitimately shares with (or hands off to) the
    //           NEW version. Plain `install` op is NOT enough — the
    //           tdnf-multi multi-install case shares name+arch but must
    //           coexist, and the solver emits `install` for it.
    for (installed_repo.packages, 0..) |pkg, installed_index| {
        if (tx.erase_mask[installed_index]) {
            continue;
        }
        for (tx.added.items) |added| {
            if (sameNevra(pkg, added.view.pkg)) {
                tx.replace_mask[installed_index] = true;
                break;
            }
        }
    }
    for (installed_repo.packages, 0..) |pkg, installed_index| {
        if (tx.erase_mask[installed_index] or tx.replace_mask[installed_index]) {
            continue;
        }
        for (tx.added.items) |added| {
            if (added.op != .upgrade) {
                continue;
            }
            if (sameNameArch(pkg, added.view.pkg)) {
                tx.replace_mask[installed_index] = true;
                break;
            }
        }
    }

    return tx;
}

fn buildFinalRepository(
    arena: std.mem.Allocator,
    installed_repo: model.RepositoryModel,
    tx: *const ParsedTransaction,
) TransactionError!FinalBuildResult {
    var builder = RepositoryBuilder.init(arena);
    const installed_to_final = try arena.alloc(?usize, installed_repo.packages.len);
    const added_to_final = try arena.alloc(usize, tx.added.items.len);

    for (installed_to_final) |*entry| {
        entry.* = null;
    }

    for (installed_repo.packages, 0..) |pkg, installed_index| {
        if (tx.erase_mask[installed_index] or tx.replace_mask[installed_index]) {
            continue;
        }
        installed_to_final[installed_index] = try builder.appendPackageView(.{
            .pkg = pkg,
            .relations = installed_repo.relations,
            .files = installed_repo.files,
        });
    }

    const added_base = builder.packages.items.len;

    for (tx.added.items, 0..) |added, added_index| {
        added_to_final[added_index] = try builder.appendPackageView(added.view);
    }

    return .{
        .repository = try builder.finish(),
        .installed_to_final = installed_to_final,
        .added_to_final = added_to_final,
        .added_base = added_base,
    };
}

fn collectNativeProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    tx: *const ParsedTransaction,
    installed_repo: model.RepositoryModel,
    final_build: FinalBuildResult,
    installed_index: *const query_index.RepositoryIndex,
    final_index: *const query_index.RepositoryIndex,
) TransactionError!void {
    for (tx.added.items, 0..) |added, added_index| {
        const source_final = final_build.added_to_final[added_index];
        try collectAddedPackageProblems(
            arena,
            problems,
            added.view,
            source_final,
            installed_index,
            final_index,
            final_build.added_base,
        );
    }

    for (installed_repo.packages, 0..) |pkg, installed_index_raw| {
        if (tx.erase_mask[installed_index_raw] or tx.replace_mask[installed_index_raw]) {
            continue;
        }
        const source_final = final_build.installed_to_final[installed_index_raw] orelse continue;
        const source = PackageView{
            .pkg = pkg,
            .relations = installed_repo.relations,
            .files = installed_repo.files,
        };
        try collectRemainingPackageProblems(arena, problems, source, source_final, tx, final_index);
    }
}

fn collectAddedPackageProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    source: PackageView,
    source_final_index: usize,
    installed_index: *const query_index.RepositoryIndex,
    final_index: *const query_index.RepositoryIndex,
    added_base: usize,
) TransactionError!void {
    for (source.relationEntries(.requires)) |relation| {
        if (shouldSkipFinalRequire(relation)) {
            continue;
        }
        const active_index: *const query_index.RepositoryIndex = if ((relation.sense & sense_pretrans) != 0)
            installed_index
        else
            final_index;

        const matches = try collectMatchingPackageIndices(arena, active_index, relation, null);
        if (matches.len != 0) {
            continue;
        }

        const msg = try formatMissingRequireMessage(arena, source, relation, (relation.sense & sense_pretrans) != 0);
        try problems.add(msg);
    }

    try collectConflictStyleProblems(arena, problems, source, source_final_index, final_index, .conflicts);
    try collectConflictStyleProblems(arena, problems, source, source_final_index, final_index, .obsoletes);
    try collectFileConflictProblems(arena, problems, source, source_final_index, final_index, added_base);
}

fn collectRemainingPackageProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    source: PackageView,
    source_final_index: usize,
    tx: *const ParsedTransaction,
    final_index: *const query_index.RepositoryIndex,
) TransactionError!void {
    for (source.relationEntries(.requires)) |relation| {
        if (shouldSkipFinalRequire(relation)) {
            continue;
        }
        if (!relationMatchesAnyTransactionPackage(relation, tx.erased.items)) {
            continue;
        }

        const matches = try collectMatchingPackageIndices(arena, final_index, relation, null);
        if (matches.len != 0) {
            continue;
        }

        const msg = try formatMissingRequireMessage(arena, source, relation, false);
        try problems.add(msg);
    }

    try collectTransitionConflictProblems(arena, problems, source, source_final_index, tx.added.items, .conflicts);
    try collectTransitionConflictProblems(arena, problems, source, source_final_index, tx.added.items, .obsoletes);
}

fn collectConflictStyleProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    source: PackageView,
    source_final_index: usize,
    final_index: *const query_index.RepositoryIndex,
    kind: model.DependencyKind,
) TransactionError!void {
    for (source.relationEntries(kind)) |relation| {
        const matches = try collectMatchingPackageIndices(arena, final_index, relation, source_final_index);
        for (matches) |candidate_index| {
            const candidate = PackageView{
                .pkg = final_index.repository.packages[candidate_index],
                .relations = final_index.repository.relations,
                .files = final_index.repository.files,
            };
            if (sameNevra(source.pkg, candidate.pkg)) {
                continue;
            }
            const msg = try formatConflictStyleMessage(arena, source, candidate, kind);
            try problems.add(msg);
        }
    }
}

fn collectTransitionConflictProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    source: PackageView,
    source_final_index: usize,
    added_items: []const TransactionPackage,
    kind: model.DependencyKind,
) TransactionError!void {
    _ = source_final_index;

    for (source.relationEntries(kind)) |relation| {
        for (added_items) |added| {
            if (!relationMatchesPackage(relation, added.view)) {
                continue;
            }
            const msg = try formatConflictStyleMessage(arena, source, added.view, kind);
            try problems.add(msg);
        }
    }
}

fn collectFileConflictProblems(
    arena: std.mem.Allocator,
    problems: *ProblemCollector,
    source: PackageView,
    source_final_index: usize,
    final_index: *const query_index.RepositoryIndex,
    added_base: usize,
) TransactionError!void {
    for (source.fileEntries()) |source_file| {
        if (source_file.kind == .dir) {
            continue;
        }

        for (final_index.packagesProvidingFile(source_file.path)) |candidate_index| {
            if (candidate_index == source_final_index) {
                continue;
            }
            if (candidate_index >= added_base and candidate_index < source_final_index) {
                continue;
            }

            const candidate = PackageView{
                .pkg = final_index.repository.packages[candidate_index],
                .relations = final_index.repository.relations,
                .files = final_index.repository.files,
            };
            if (sameNevra(source.pkg, candidate.pkg)) {
                continue;
            }

            const candidate_file = findFileEntry(candidate.fileEntries(), source_file.path) orelse continue;
            if (!fileEntriesConflict(source_file, candidate_file)) {
                continue;
            }

            const msg = try formatFileConflictMessage(arena, source, candidate, source_file.path);
            try problems.add(msg);
        }
    }
}

fn buildNativeOrder(
    arena: std.mem.Allocator,
    added_items: []const TransactionPackage,
    erased_items: []const TransactionPackage,
) TransactionError![]usize {
    var results = std.array_list.Managed(usize).init(arena);

    const added_order = try topoOrderPhase(arena, added_items, false);
    try results.appendSlice(added_order);

    const erased_order = try topoOrderPhase(arena, erased_items, true);
    try results.appendSlice(erased_order);

    return try results.toOwnedSlice();
}

fn topoOrderPhase(
    arena: std.mem.Allocator,
    items: []const TransactionPackage,
    reverse: bool,
) TransactionError![]usize {
    if (items.len == 0) {
        return try arena.alloc(usize, 0);
    }

    const adjacency = try arena.alloc(std.array_list.Managed(usize), items.len);
    const indegree = try arena.alloc(usize, items.len);
    const incoming_pre = try arena.alloc(usize, items.len);
    const remaining = try arena.alloc(bool, items.len);
    const outgoing_count = try arena.alloc(usize, items.len);
    for (adjacency) |*list| {
        list.* = std.array_list.Managed(usize).init(arena);
    }
    @memset(indegree, 0);
    @memset(incoming_pre, 0);
    @memset(remaining, true);
    @memset(outgoing_count, 0);

    for (items, 0..) |consumer, consumer_index| {
        for (order_dep_kinds) |kind| {
            for (consumer.view.relationEntries(kind)) |relation| {
                if (isUnorderedReq(relation.sense)) {
                    continue;
                }
                const provider_index = findMatchingTransactionProvider(items, consumer.input_index, relation) orelse continue;

                const from = if (reverse) consumer_index else provider_index;
                const to = if (reverse) provider_index else consumer_index;
                if (from == to) {
                    continue;
                }
                if (containsIndex(adjacency[from].items, to)) {
                    continue;
                }

                try adjacency[from].append(to);
                indegree[to] += 1;
                outgoing_count[from] += 1;
                if (relation.pre) {
                    incoming_pre[to] += 1;
                }
            }
        }
    }

    var order = std.array_list.Managed(usize).init(arena);
    var scratch = std.array_list.Managed(usize).init(arena);

    while (order.items.len < items.len) {
        scratch.clearRetainingCapacity();
        for (remaining, 0..) |is_remaining, index| {
            if (is_remaining and indegree[index] == 0) {
                try scratch.append(index);
            }
        }

        if (scratch.items.len == 0) {
            const breaker = chooseCycleBreak(items, remaining, incoming_pre, outgoing_count) orelse return error.InvalidParameter;
            try scratch.append(breaker);
        } else {
            std.sort.pdq(usize, scratch.items, PhaseSortContext{
                .items = items,
                .outgoing_count = outgoing_count,
                .incoming_pre = incoming_pre,
            }, lessPhaseNode);
        }

        const next = scratch.items[0];
        remaining[next] = false;
        try order.append(items[next].input_index);

        for (adjacency[next].items) |dest| {
            if (indegree[dest] > 0) {
                indegree[dest] -= 1;
            }
        }
    }

    return try order.toOwnedSlice();
}

const PhaseSortContext = struct {
    items: []const TransactionPackage,
    outgoing_count: []const usize,
    incoming_pre: []const usize,
};

fn lessPhaseNode(ctx: PhaseSortContext, left: usize, right: usize) bool {
    if (ctx.outgoing_count[left] != ctx.outgoing_count[right]) {
        return ctx.outgoing_count[left] > ctx.outgoing_count[right];
    }
    if (ctx.incoming_pre[left] != ctx.incoming_pre[right]) {
        return ctx.incoming_pre[left] < ctx.incoming_pre[right];
    }
    return ctx.items[left].input_index < ctx.items[right].input_index;
}

fn chooseCycleBreak(
    items: []const TransactionPackage,
    remaining: []const bool,
    incoming_pre: []const usize,
    outgoing_count: []const usize,
) ?usize {
    var best: ?usize = null;

    for (remaining, 0..) |is_remaining, index| {
        if (!is_remaining) {
            continue;
        }
        if (best == null) {
            best = index;
            continue;
        }
        const current = best.?;
        if (incoming_pre[index] < incoming_pre[current] or
            (incoming_pre[index] == incoming_pre[current] and outgoing_count[index] > outgoing_count[current]) or
            (incoming_pre[index] == incoming_pre[current] and outgoing_count[index] == outgoing_count[current] and items[index].input_index < items[current].input_index))
        {
            best = index;
        }
    }

    return best;
}

fn findMatchingTransactionProvider(
    items: []const TransactionPackage,
    source_input_index: usize,
    relation: model.Relation,
) ?usize {
    var by_name: ?usize = null;
    var by_file: ?usize = null;
    var by_provide: ?usize = null;

    for (items, 0..) |candidate, index| {
        if (candidate.input_index == source_input_index) {
            continue;
        }
        if (by_name == null and relationMatchesCandidateName(relation, candidate.view.pkg.nevra.name)) {
            by_name = index;
            continue;
        }
        if (by_file == null and relationMatchesCandidateFiles(relation, candidate.view.fileEntries())) {
            by_file = index;
            continue;
        }
        if (by_provide == null and relationMatchesCandidateProvides(relation, candidate.view.relationEntries(.provides))) {
            by_provide = index;
        }
    }

    return by_name orelse by_file orelse by_provide;
}

fn collectMatchingPackageIndices(
    arena: std.mem.Allocator,
    index: *const query_index.RepositoryIndex,
    relation: model.Relation,
    skip_index: ?usize,
) TransactionError![]usize {
    var results = std.array_list.Managed(usize).init(arena);
    const seen = try arena.alloc(bool, index.repository.packages.len);
    @memset(seen, false);

    if (relationMatchesCandidateName(relation, relation.name)) {
        for (index.packagesNamed(relation.name)) |candidate_index| {
            if (skip_index != null and candidate_index == skip_index.?) {
                continue;
            }
            if (seen[candidate_index]) {
                continue;
            }
            seen[candidate_index] = true;
            try results.append(candidate_index);
        }
    }

    if (relation.name.len != 0 and relation.name[0] == '/') {
        for (index.packagesProvidingFile(relation.name)) |candidate_index| {
            if (skip_index != null and candidate_index == skip_index.?) {
                continue;
            }
            if (seen[candidate_index]) {
                continue;
            }
            seen[candidate_index] = true;
            try results.append(candidate_index);
        }
    }

    const provided = index.packagesProvidingQuery(arena, dependencyQueryFromRelation(relation)) catch return error.OutOfMemory;
    for (provided.items) |candidate_index| {
        if (skip_index != null and candidate_index == skip_index.?) {
            continue;
        }
        if (seen[candidate_index]) {
            continue;
        }
        seen[candidate_index] = true;
        try results.append(candidate_index);
    }

    return try results.toOwnedSlice();
}

fn relationMatchesAnyTransactionPackage(
    relation: model.Relation,
    items: []const TransactionPackage,
) bool {
    for (items) |item| {
        if (relationMatchesPackage(relation, item.view)) {
            return true;
        }
    }
    return false;
}

fn relationMatchesPackage(
    relation: model.Relation,
    candidate: PackageView,
) bool {
    return relationMatchesCandidateName(relation, candidate.pkg.nevra.name) or
        relationMatchesCandidateFiles(relation, candidate.fileEntries()) or
        relationMatchesCandidateProvides(relation, candidate.relationEntries(.provides));
}

fn relationMatchesCandidateName(relation: model.Relation, candidate_name: []const u8) bool {
    return std.mem.eql(u8, relation.name, candidate_name) and
        relation.comparison == .none and
        !relationHasVersion(relation);
}

fn relationMatchesCandidateFiles(relation: model.Relation, candidate_files: []const model.FileEntry) bool {
    for (candidate_files) |file_entry| {
        if (std.mem.eql(u8, relation.name, file_entry.path)) {
            return true;
        }
    }
    return false;
}

fn relationMatchesCandidateProvides(relation: model.Relation, candidate_provides: []const model.Relation) bool {
    const query = dependencyQueryFromRelation(relation);
    for (candidate_provides) |provide| {
        if (query_index.relationMatchesQuery(provide, query)) {
            return true;
        }
    }
    return false;
}

fn dependencyQueryFromRelation(relation: model.Relation) query_index.DependencyQuery {
    return .{
        .name = relation.name,
        .comparison = relation.comparison,
        .epoch = relation.epoch,
        .version = relation.version,
        .release = relation.release,
    };
}

fn relationHasVersion(relation: model.Relation) bool {
    return relation.epoch != null or
        (relation.version != null and relation.version.?.len != 0) or
        (relation.release != null and relation.release.?.len != 0);
}

fn shouldSkipFinalRequire(relation: model.Relation) bool {
    if (relation.name.len == 0) {
        return true;
    }
    if (std.mem.startsWith(u8, relation.name, "rpmlib(")) {
        return true;
    }
    return (relation.sense & special_final_check_mask) != 0;
}

fn isUnorderedReq(sense: u32) bool {
    return (sense & unordered_only_mask) != 0 and (sense & force_order_only_mask) == 0;
}

fn formatMissingRequireMessage(
    arena: std.mem.Allocator,
    source: PackageView,
    relation: model.Relation,
    pretrans_hint: bool,
) TransactionError![]const u8 {
    const source_nevra = try pkgquery.nevraString(arena, source.pkg);
    const relation_text = try pkgquery.formatRelation(arena, relation);
    if (pretrans_hint) {
        return try std.fmt.allocPrint(
            arena,
            "nothing provides {s} needed by {s}. Detected rpm pre-transaction dependency errors. Install {s} first to resolve this failure.",
            .{ relation_text, source_nevra, relation_text },
        );
    }
    return try std.fmt.allocPrint(
        arena,
        "nothing provides {s} needed by {s}",
        .{ relation_text, source_nevra },
    );
}

fn formatConflictStyleMessage(
    arena: std.mem.Allocator,
    source: PackageView,
    candidate: PackageView,
    kind: model.DependencyKind,
) TransactionError![]const u8 {
    const source_nevra = try pkgquery.nevraString(arena, source.pkg);
    const candidate_nevra = try pkgquery.nevraString(arena, candidate.pkg);
    return switch (kind) {
        .conflicts => std.fmt.allocPrint(
            arena,
            "package {s} conflicts with {s}",
            .{ source_nevra, candidate_nevra },
        ),
        .obsoletes => std.fmt.allocPrint(
            arena,
            "package {s} obsoletes {s}",
            .{ source_nevra, candidate_nevra },
        ),
        else => unreachable,
    };
}

fn formatFileConflictMessage(
    arena: std.mem.Allocator,
    source: PackageView,
    candidate: PackageView,
    path: []const u8,
) TransactionError![]const u8 {
    const source_nevra = try pkgquery.nevraString(arena, source.pkg);
    const candidate_nevra = try pkgquery.nevraString(arena, candidate.pkg);
    return try std.fmt.allocPrint(
        arena,
        "file {s} from install of {s} conflicts with file from package {s}",
        .{ path, source_nevra, candidate_nevra },
    );
}

fn buildIndexLines(arena: std.mem.Allocator, indexes: []const usize) TransactionError![][]const u8 {
    const out = try arena.alloc([]const u8, indexes.len);
    for (indexes, 0..) |value, index| {
        out[index] = try std.fmt.allocPrint(arena, "{d}", .{value});
    }
    return out;
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

fn dupCString(text: []const u8) ![*:0]u8 {
    return try std.heap.c_allocator.dupeZ(u8, text);
}

fn parseEraseQuery(
    item: c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    input_index: usize,
) TransactionError!EraseQuery {
    const name = item.pszName orelse {
        setError("transaction erase item {d} missing name", .{input_index});
        return error.InvalidParameter;
    };
    const evr_text = item.pszEVR orelse {
        setError("transaction erase item {d} missing evr", .{input_index});
        return error.InvalidParameter;
    };
    return .{
        .name = std.mem.span(name),
        .evr = splitEvr(std.mem.span(evr_text)),
        .arch = if (item.pszArch != null) std.mem.span(item.pszArch) else null,
    };
}

fn splitEvr(evr: []const u8) EvrParts {
    if (evr.len == 0) {
        return .{};
    }

    var epoch: ?u32 = null;
    var body = evr;
    if (std.mem.indexOfScalar(u8, evr, ':')) |separator| {
        if (separator != 0) {
            const candidate = evr[0..separator];
            epoch = std.fmt.parseInt(u32, candidate, 10) catch null;
            if (epoch != null) {
                body = evr[separator + 1 ..];
            }
        }
    }

    if (body.len == 0) {
        return .{ .epoch = epoch };
    }

    if (std.mem.lastIndexOfScalar(u8, body, '-')) |separator| {
        if (separator != 0 and separator + 1 < body.len) {
            return .{
                .epoch = epoch,
                .version = body[0..separator],
                .release = body[separator + 1 ..],
            };
        }
    }

    return .{
        .epoch = epoch,
        .version = body,
    };
}

fn findInstalledEraseMatch(repo: model.RepositoryModel, query: EraseQuery) ?usize {
    for (repo.packages, 0..) |pkg, index| {
        if (!std.mem.eql(u8, pkg.nevra.name, query.name)) {
            continue;
        }
        if (query.arch) |arch| {
            if (!std.mem.eql(u8, pkg.nevra.arch, arch)) {
                continue;
            }
        }
        if (query_index.compareEvr(
            pkg.nevra.epoch,
            pkg.nevra.version,
            if (pkg.nevra.release.len == 0) null else pkg.nevra.release,
            query.evr.epoch,
            query.evr.version,
            query.evr.release,
        ) == 0) {
            return index;
        }
    }
    return null;
}

fn installedPackageView(repo: model.RepositoryModel, index: usize) PackageView {
    return .{
        .pkg = repo.packages[index],
        .relations = repo.relations,
        .files = repo.files,
    };
}

fn sameNevra(left: model.Package, right: model.Package) bool {
    return std.mem.eql(u8, left.nevra.name, right.nevra.name) and
        std.mem.eql(u8, left.nevra.arch, right.nevra.arch) and
        query_index.comparePackageVersions(left, right) == 0;
}

fn sameNameArch(left: model.Package, right: model.Package) bool {
    return std.mem.eql(u8, left.nevra.name, right.nevra.name) and
        std.mem.eql(u8, left.nevra.arch, right.nevra.arch);
}

fn containsIndex(items: []const usize, wanted: usize) bool {
    for (items) |item| {
        if (item == wanted) {
            return true;
        }
    }
    return false;
}

fn findFileEntry(files: []const model.FileEntry, wanted_path: []const u8) ?model.FileEntry {
    for (files) |file_entry| {
        if (std.mem.eql(u8, file_entry.path, wanted_path)) {
            return file_entry;
        }
    }
    return null;
}

fn fileEntriesConflict(left: model.FileEntry, right: model.FileEntry) bool {
    return left.kind != .dir or right.kind != .dir;
}

fn formatEvrForError(parts: EvrParts) []const u8 {
    _ = parts;
    return "(unknown)";
}

test "native transaction order puts providers before install prereqs and consumers before erase prereqs" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const helper_file = [_]model.FileEntry{.{ .path = "/usr/bin/helper" }};
    const helper_pkg = model.Package{
        .pkg_id = "helper",
        .nevra = .{ .name = "helper", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "a" },
        .location = .{ .href = "helper.rpm" },
        .files = .{ .start = 0, .len = 1 },
    };

    const pre_rel = [_]model.Relation{.{ .name = "/usr/bin/helper", .pre = true, .sense = sense_script_pre }};
    const pre_pkg = model.Package{
        .pkg_id = "pre",
        .nevra = .{ .name = "pre", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "b" },
        .location = .{ .href = "pre.rpm" },
        .requires = .{ .start = 0, .len = 1 },
    };

    const postun_rel = [_]model.Relation{.{ .name = "/usr/bin/helper", .pre = true, .sense = sense_script_postun }};
    const postun_pkg = model.Package{
        .pkg_id = "postun",
        .nevra = .{ .name = "postun", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "c" },
        .location = .{ .href = "postun.rpm" },
        .requires = .{ .start = 0, .len = 1 },
    };

    const added = [_]TransactionPackage{
        .{ .input_index = 1, .op = .install, .view = .{ .pkg = pre_pkg, .relations = &pre_rel, .files = &[_]model.FileEntry{} } },
        .{ .input_index = 0, .op = .install, .view = .{ .pkg = helper_pkg, .relations = &[_]model.Relation{}, .files = &helper_file } },
    };
    const erased = [_]TransactionPackage{
        .{ .input_index = 2, .op = .erase, .view = .{ .pkg = postun_pkg, .relations = &postun_rel, .files = &[_]model.FileEntry{} } },
        .{ .input_index = 3, .op = .erase, .view = .{ .pkg = helper_pkg, .relations = &[_]model.Relation{}, .files = &helper_file } },
    };

    const order = try buildNativeOrder(arena, &added, &erased);
    try testing.expectEqual(@as(usize, 4), order.len);
    try testing.expectEqual(@as(usize, 0), order[0]);
    try testing.expectEqual(@as(usize, 1), order[1]);
    try testing.expectEqual(@as(usize, 2), order[2]);
    try testing.expectEqual(@as(usize, 3), order[3]);
}

test "native transaction reports unmet pretrans requirements with guidance" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source_rel = [_]model.Relation{.{
        .name = "helper",
        .comparison = .ge,
        .version = "1.0",
        .release = "1",
        .sense = sense_pretrans,
    }};
    const source_pkg = model.Package{
        .pkg_id = "consumer",
        .nevra = .{ .name = "consumer", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "x" },
        .location = .{ .href = "consumer.rpm" },
        .requires = .{ .start = 0, .len = 1 },
    };

    const repo = model.RepositoryModel{
        .packages = @constCast(&[_]model.Package{source_pkg}),
        .relations = @constCast(&source_rel),
    };
    var installed_index = try query_index.RepositoryIndex.init(arena, &model.RepositoryModel{});
    var final_index = try query_index.RepositoryIndex.init(arena, &repo);
    var problems = ProblemCollector.init(arena);

    try collectAddedPackageProblems(
        arena,
        &problems,
        .{ .pkg = source_pkg, .relations = &source_rel, .files = &[_]model.FileEntry{} },
        0,
        &installed_index,
        &final_index,
        0,
    );
    try testing.expectEqual(@as(usize, 1), problems.messages.items.len);
    try testing.expect(std.mem.containsAtLeast(u8, problems.messages.items[0], 1, "Detected rpm pre-transaction dependency errors."));
}

test "native transaction reports duplicate file ownership conflicts" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const shared_files = [_]model.FileEntry{
        .{ .path = "/usr/lib/conflict/shared", .kind = .plain },
        .{ .path = "/usr/lib/conflict/shared", .kind = .plain },
    };
    const pkg0 = model.Package{
        .pkg_id = "conflict0",
        .nevra = .{ .name = "conflict0", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "0" },
        .location = .{ .href = "conflict0.rpm" },
        .files = .{ .start = 0, .len = 1 },
    };
    const pkg1 = model.Package{
        .pkg_id = "conflict1",
        .nevra = .{ .name = "conflict1", .version = "1.0", .release = "1", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "1" },
        .location = .{ .href = "conflict1.rpm" },
        .files = .{ .start = 1, .len = 1 },
    };
    const repo = model.RepositoryModel{
        .packages = @constCast(&[_]model.Package{ pkg0, pkg1 }),
        .files = @constCast(&shared_files),
    };

    var installed_index = try query_index.RepositoryIndex.init(arena, &model.RepositoryModel{});
    var final_index = try query_index.RepositoryIndex.init(arena, &repo);
    var problems = ProblemCollector.init(arena);

    try collectAddedPackageProblems(
        arena,
        &problems,
        .{ .pkg = pkg0, .relations = &[_]model.Relation{}, .files = &shared_files },
        0,
        &installed_index,
        &final_index,
        0,
    );
    try testing.expectEqual(@as(usize, 1), problems.messages.items.len);
    try testing.expect(std.mem.containsAtLeast(
        u8,
        problems.messages.items[0],
        1,
        "file /usr/lib/conflict/shared from install of conflict0-1.0-1.noarch conflicts with file from package conflict1-1.0-1.noarch",
    ));
}
