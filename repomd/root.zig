const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("tdnferror.h");
    @cInclude("tdnfrepomd.h");
});
const model = @import("model.zig");
const repomd = @import("repomd.zig");

pub const primary_xml = @import("primary.zig");
pub const filelists_xml = @import("filelists.zig");
pub const other_xml = @import("other.zig");
pub const updateinfo_xml = @import("updateinfo.zig");
pub const available_repository_loader = @import("available_loader.zig");
pub const installed_repository_loader = @import("installed_repository.zig");
pub const metadata_cache = @import("cache.zig");
pub const metadata_model = model;
pub const package_query = @import("pkgquery.zig");
pub const query_index = @import("index.zig");
pub const rpm_package = @import("rpmpkg.zig");
pub const solv_bridge = @import("solvbridge.zig");
pub const query_native = @import("query_native.zig");
pub const transaction_native = @import("transaction_native.zig");
pub const solver_model = @import("solver_model.zig");
pub const solver_identity = @import("solver_identity.zig");
pub const solver_live = @import("solver_live.zig");
pub const solver_live_abi = @import("solver_live_abi.zig");
pub const solver_native = @import("solver_native.zig");
pub const solver_visibility = @import("solver_visibility.zig");
pub const solver_coordinator = @import("solver_coordinator.zig");
pub const solver_policy = @import("solver_policy.zig");
pub const solver_result = @import("solver_result.zig");
pub const solver_result_c = @import("solver_result_c.zig");
pub const solver_shadow = @import("solver_shadow.zig");
pub const solver_rules = @import("solver_rules.zig");
pub const solver_search = @import("solver_search.zig");

const c_header = if (builtin.is_test) @cImport({
    @cInclude("tdnfrepomd.h");
}) else struct {};

pub const TDNF_REPOMD_DOC = opaque {};
pub const TDNF_REPOMD_CHECKSUM = model.Checksum;
pub const TDNF_REPOMD_RECORD = model.Record;

const DocState = struct {
    arena_state: std.heap.ArenaAllocator,
    pszRevision: ?[*:0]const u8 = null,
    pRecords: []model.Record = &[_]model.Record{},
};

const max_repomd_bytes = 16 * 1024 * 1024;
const ProtectedNamesError = error{ OutOfMemory, InvalidInput };

threadlocal var last_error_buf: [512]u8 = undefined;
threadlocal var last_error_len: usize = 0;

fn clearError() void {
    last_error_len = 0;
}

fn setError(comptime fmt: []const u8, args: anytype) void {
    const msg = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
        const fallback = "(repomd error truncated)";
        @memcpy(last_error_buf[0..fallback.len], fallback);
        break :blk last_error_buf[0..fallback.len];
    };
    last_error_len = msg.len;
}

pub export fn TDNFRepoMdLastError() [*:0]const u8 {
    if (last_error_len >= last_error_buf.len) {
        last_error_len = last_error_buf.len - 1;
    }
    last_error_buf[last_error_len] = 0;
    return @ptrCast(&last_error_buf);
}

pub export fn TDNFRepoMdNativeSolverResultFree(
    result: ?*c.TDNF_REPOMD_NATIVE_SOLVER_RESULT,
) void {
    solver_result_c.freeOwnedResult(@ptrCast(result));
}

pub export fn TDNFRepoMdNativeSolverResultCompare(
    native: ?*const c.TDNF_REPOMD_NATIVE_SOLVER_RESULT,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    clearError();
    const output = comparison orelse {
        setError("null native solver comparison output", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    output.* = std.mem.zeroes(c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT);
    output.dwStatus = c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID;
    const native_result = native orelse {
        setError("null native solver result", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    const legacy_result = legacy orelse {
        setError("null legacy solver result", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };

    solver_shadow.compare(
        std.heap.c_allocator,
        @ptrCast(native_result),
        @ptrCast(@alignCast(legacy_result)),
        @ptrCast(output),
    ) catch |err| {
        return switch (err) {
            error.OutOfMemory => blk: {
                setError("out of memory comparing native solver result", .{});
                break :blk c.ERROR_TDNF_OUT_OF_MEMORY;
            },
            error.InvalidInput => blk: {
                setError("invalid native solver comparison input", .{});
                break :blk c.ERROR_TDNF_INVALID_PARAMETER;
            },
        };
    };
    return 0;
}

pub export fn TDNFRepoMdNativeSolverLiveCompare(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        null,
        0,
        null,
        0,
        false,
        false,
        false,
        false,
        false,
        false,
        null,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

pub export fn TDNFRepoMdNativeSolverLiveCompareV2(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        null,
        0,
        raw_hidden_available,
        hidden_available_count,
        true,
        false,
        false,
        false,
        false,
        false,
        null,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

pub export fn TDNFRepoMdNativeSolverLiveCompareV3(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    all_deps: c_int,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        null,
        0,
        raw_hidden_available,
        hidden_available_count,
        true,
        all_deps != 0,
        false,
        false,
        false,
        false,
        null,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

pub export fn TDNFRepoMdNativeSolverLiveCompareV4(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    all_deps: c_int,
    best: c_int,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        null,
        0,
        raw_hidden_available,
        hidden_available_count,
        true,
        all_deps != 0,
        best != 0,
        false,
        false,
        false,
        null,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

pub export fn TDNFRepoMdNativeSolverLiveCompareV5(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    all_deps: c_int,
    best: c_int,
    clean_deps: c_int,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        null,
        0,
        raw_hidden_available,
        hidden_available_count,
        true,
        all_deps != 0,
        best != 0,
        clean_deps != 0,
        false,
        false,
        null,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

pub export fn TDNFRepoMdNativeSolverLiveCompareV6(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    all_deps: c_int,
    best: c_int,
    clean_deps: c_int,
    skip_broken: c_int,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        null,
        0,
        raw_hidden_available,
        hidden_available_count,
        true,
        all_deps != 0,
        best != 0,
        clean_deps != 0,
        skip_broken != 0,
        false,
        null,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

pub export fn TDNFRepoMdNativeSolverLiveCompareV7(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    all_deps: c_int,
    best: c_int,
    clean_deps: c_int,
    skip_broken: c_int,
    raw_protected_names: ?[*:null]const ?[*:0]const u8,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        null,
        0,
        raw_hidden_available,
        hidden_available_count,
        true,
        all_deps != 0,
        best != 0,
        clean_deps != 0,
        skip_broken != 0,
        false,
        raw_protected_names,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

pub export fn TDNFRepoMdNativeSolverLiveCompareV8(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_erase_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    erase_job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    all_deps: c_int,
    best: c_int,
    clean_deps: c_int,
    skip_broken: c_int,
    raw_protected_names: ?[*:null]const ?[*:0]const u8,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        raw_erase_jobs,
        erase_job_count,
        raw_hidden_available,
        hidden_available_count,
        true,
        all_deps != 0,
        best != 0,
        clean_deps != 0,
        skip_broken != 0,
        false,
        raw_protected_names,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

pub export fn TDNFRepoMdNativeSolverLiveCompareV9(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_erase_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    erase_job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    all_deps: c_int,
    best: c_int,
    clean_deps: c_int,
    skip_broken: c_int,
    allow_erasing: c_int,
    raw_protected_names: ?[*:null]const ?[*:0]const u8,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    return nativeSolverLiveCompare(
        raw_repositories,
        repository_count,
        raw_jobs,
        job_count,
        raw_erase_jobs,
        erase_job_count,
        raw_hidden_available,
        hidden_available_count,
        true,
        all_deps != 0,
        best != 0,
        clean_deps != 0,
        skip_broken != 0,
        allow_erasing != 0,
        raw_protected_names,
        rpm_config,
        raw_native_arch,
        legacy,
        comparison,
    );
}

fn nativeSolverLiveCompare(
    raw_repositories: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_REPOSITORY,
    repository_count: u32,
    raw_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    job_count: u32,
    raw_erase_jobs: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    erase_job_count: u32,
    raw_hidden_available: ?[*]const c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
    hidden_available_count: u32,
    has_considered: bool,
    all_deps: bool,
    best: bool,
    clean_deps: bool,
    skip_broken: bool,
    allow_erasing: bool,
    raw_protected_names: ?[*:null]const ?[*:0]const u8,
    rpm_config: ?*const c.tdnf_rpm_config,
    raw_native_arch: ?[*:0]const u8,
    legacy: ?*const c.TDNF_SOLVED_PKG_INFO,
    comparison: ?*c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
) u32 {
    clearError();
    const output = comparison orelse {
        setError("null native live comparison output", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    output.* = std.mem.zeroes(c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT);
    output.dwStatus = c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID;
    const repositories_ptr = raw_repositories orelse {
        setError("null native live repositories", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    if (job_count != 0 and raw_jobs == null) {
        setError("null native live jobs", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }
    if (erase_job_count != 0 and raw_erase_jobs == null) {
        setError("null native live erase jobs", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }
    if (repository_count == 0 or
        (job_count == 0 and erase_job_count == 0))
    {
        setError("empty native live input", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }
    const config = rpm_config orelse {
        setError("null native live rpm configuration", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    const native_arch = if (raw_native_arch) |value|
        std.mem.span(value)
    else {
        setError("null native live architecture", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    if (native_arch.len == 0) {
        setError("empty native live architecture", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }
    const legacy_result = legacy orelse {
        setError("null native live legacy result", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };

    const allocator = std.heap.c_allocator;
    const protected_names = protectedNamesFromC(
        allocator,
        raw_protected_names,
    ) catch |err| {
        return switch (err) {
            error.OutOfMemory => blk: {
                setError(
                    "out of memory translating protected package names",
                    .{},
                );
                break :blk c.ERROR_TDNF_OUT_OF_MEMORY;
            },
            error.InvalidInput => blk: {
                setError("invalid protected package name", .{});
                break :blk c.ERROR_TDNF_INVALID_PARAMETER;
            },
        };
    };
    defer allocator.free(protected_names);
    const repositories = allocator.alloc(
        solver_live.RepositoryInput,
        repository_count,
    ) catch {
        setError("out of memory translating native live repositories", .{});
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    };
    defer allocator.free(repositories);
    for (repositories_ptr[0..repository_count], repositories) |
        raw,
        *repository,
    | {
        repository.* = .{
            .id = spanRequired(raw.pszId) orelse {
                setError("invalid native live repository id", .{});
                return c.ERROR_TDNF_INVALID_PARAMETER;
            },
            .cache_dir = spanRequired(raw.pszCacheDir) orelse {
                setError("invalid native live repository cache", .{});
                return c.ERROR_TDNF_INVALID_PARAMETER;
            },
            .snapshot_file = spanOptional(raw.pszSnapshotFile),
            .priority = raw.nPriority,
            .cost = raw.dwCost,
        };
    }
    const jobs = allocator.alloc(
        solver_live.JobInput,
        job_count,
    ) catch {
        setError("out of memory translating native live jobs", .{});
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    };
    defer allocator.free(jobs);
    if (raw_jobs) |jobs_ptr| {
        for (jobs_ptr[0..job_count], jobs) |raw, *job| {
            job.* = liveJobFromC(raw) orelse {
                setError("invalid native live job selector", .{});
                return c.ERROR_TDNF_INVALID_PARAMETER;
            };
        }
    }
    const erase_jobs = allocator.alloc(
        solver_live.EraseJobInput,
        erase_job_count,
    ) catch {
        setError("out of memory translating native live erase jobs", .{});
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    };
    defer allocator.free(erase_jobs);
    if (raw_erase_jobs) |erase_jobs_ptr| {
        for (erase_jobs_ptr[0..erase_job_count], erase_jobs) |raw, *job| {
            job.* = liveEraseJobFromC(raw) orelse {
                setError("invalid native live erase job selector", .{});
                return c.ERROR_TDNF_INVALID_PARAMETER;
            };
        }
    }
    var hidden_available: ?[]solver_live.JobInput = null;
    defer if (hidden_available) |hidden| allocator.free(hidden);
    if (has_considered) {
        if (hidden_available_count != 0 and raw_hidden_available == null) {
            setError("null native live hidden available packages", .{});
            return c.ERROR_TDNF_INVALID_PARAMETER;
        }
        const hidden = allocator.alloc(
            solver_live.JobInput,
            hidden_available_count,
        ) catch {
            setError(
                "out of memory translating native live visibility",
                .{},
            );
            return c.ERROR_TDNF_OUT_OF_MEMORY;
        };
        if (raw_hidden_available) |hidden_ptr| {
            for (hidden_ptr[0..hidden_available_count], hidden) |
                raw,
                *item,
            | {
                item.* = liveJobFromC(raw) orelse {
                    allocator.free(hidden);
                    setError(
                        "invalid native live hidden package selector",
                        .{},
                    );
                    return c.ERROR_TDNF_INVALID_PARAMETER;
                };
            }
        }
        hidden_available = hidden;
    }

    solver_live.compare(
        allocator,
        .{
            .repositories = repositories,
            .rpmdb = .{ .config = config },
            .native_arch = native_arch,
            .jobs = jobs,
            .erase_jobs = erase_jobs,
            .hidden_available = hidden_available,
            .include_installed = !all_deps,
            .best = best,
            .allow_erasing = allow_erasing,
            .clean_deps = clean_deps,
            .skip_broken = skip_broken,
            .protected_names = protected_names,
        },
        @ptrCast(@alignCast(legacy_result)),
        @ptrCast(output),
    ) catch |err| {
        setError("native live comparison unavailable: {t}", .{err});
        return if (err == error.OutOfMemory)
            c.ERROR_TDNF_OUT_OF_MEMORY
        else
            c.ERROR_TDNF_CALL_NOT_SUPPORTED;
    };
    return 0;
}

fn protectedNamesFromC(
    allocator: std.mem.Allocator,
    raw_protected_names: ?[*:null]const ?[*:0]const u8,
) ProtectedNamesError![][]const u8 {
    const raw_names = if (raw_protected_names) |names|
        std.mem.span(names)
    else
        &.{};
    const protected_names = try allocator.alloc(
        []const u8,
        raw_names.len,
    );
    errdefer allocator.free(protected_names);
    for (raw_names, protected_names) |raw, *name| {
        name.* = spanRequired(raw) orelse return error.InvalidInput;
    }
    return protected_names;
}

fn liveJobFromC(
    raw: c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
) ?solver_live.JobInput {
    const checksum = if (raw.pszChecksumType == null and
        raw.pszChecksumValue == null)
        null
    else if (spanRequired(raw.pszChecksumType)) |kind|
        if (spanRequired(raw.pszChecksumValue)) |value|
            solver_identity.Checksum{
                .kind = kind,
                .value = value,
                .is_pkgid = raw.nChecksumIsPkgId != 0,
            }
        else
            return null
    else
        return null;
    return .{ .selector = .{
        .repository = spanRequired(raw.pszRepository) orelse return null,
        .name = spanRequired(raw.pszName) orelse return null,
        .epoch = raw.dwEpoch,
        .version = spanRequired(raw.pszVersion) orelse return null,
        .release = spanRequired(raw.pszRelease) orelse return null,
        .arch = spanRequired(raw.pszArch) orelse return null,
        .checksum = checksum,
    } };
}

fn liveEraseJobFromC(
    raw: c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB,
) ?solver_live.EraseJobInput {
    const job = liveJobFromC(raw) orelse return null;
    if (job.selector.checksum != null or
        !std.mem.eql(
            u8,
            job.selector.repository,
            solver_live.system_repository_id,
        ))
    {
        return null;
    }
    return .{ .selector = job.selector };
}

fn spanRequired(value: ?[*:0]const u8) ?[]const u8 {
    const raw = value orelse return null;
    const span = std.mem.span(raw);
    return if (span.len == 0) null else span;
}

fn spanOptional(value: ?[*:0]const u8) ?[]const u8 {
    const raw = value orelse return null;
    return std.mem.span(raw);
}

pub export fn TDNFRepoMdParseBuffer(
    buf: ?[*]const u8,
    len: usize,
    out_doc: ?*?*TDNF_REPOMD_DOC,
) u32 {
    clearError();

    const doc_out = out_doc orelse {
        setError("null output document", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    doc_out.* = null;

    const data_ptr = buf orelse {
        setError("null repomd buffer", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    if (len == 0) {
        setError("empty repomd buffer", .{});
        return c.ERROR_TDNF_INVALID_REPO_FILE;
    }

    return parseIntoDoc(data_ptr[0..len], doc_out);
}

pub export fn TDNFRepoMdParseFile(
    path: ?[*:0]const u8,
    out_doc: ?*?*TDNF_REPOMD_DOC,
) u32 {
    clearError();

    const doc_out = out_doc orelse {
        setError("null output document", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    doc_out.* = null;

    const path_ptr = path orelse {
        setError("null repomd path", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    };
    const path_slice = std.mem.span(path_ptr);
    if (path_slice.len == 0) {
        setError("empty repomd path", .{});
        return c.ERROR_TDNF_INVALID_PARAMETER;
    }

    var io_state: std.Io.Threaded = .init(std.heap.c_allocator, .{});
    defer io_state.deinit();
    const io = io_state.io();

    const data = std.Io.Dir.cwd().readFileAlloc(
        io,
        path_slice,
        std.heap.c_allocator,
        .limited(max_repomd_bytes),
    ) catch |err| {
        setError("failed to read {s}: {t}", .{ path_slice, err });
        return mapFileError(err);
    };
    defer std.heap.c_allocator.free(data);

    return parseIntoDoc(data, doc_out);
}

pub export fn TDNFRepoMdFree(raw_doc: ?*TDNF_REPOMD_DOC) void {
    const doc = raw_doc orelse return;
    freeDoc(fromOpaque(doc));
}

pub export fn TDNFRepoMdGetRevision(raw_doc: ?*const TDNF_REPOMD_DOC) ?[*:0]const u8 {
    const doc = raw_doc orelse return null;
    return fromOpaqueConst(doc).pszRevision;
}

pub export fn TDNFRepoMdGetRecordCount(raw_doc: ?*const TDNF_REPOMD_DOC) u32 {
    const doc = raw_doc orelse return 0;
    return @intCast(fromOpaqueConst(doc).pRecords.len);
}

pub export fn TDNFRepoMdGetRecord(
    raw_doc: ?*const TDNF_REPOMD_DOC,
    index: u32,
) ?*const model.Record {
    const doc = raw_doc orelse return null;
    const state = fromOpaqueConst(doc);
    const record_index: usize = @intCast(index);
    if (record_index >= state.pRecords.len) {
        return null;
    }
    return &state.pRecords[record_index];
}

fn parseIntoDoc(data: []const u8, out_doc: *?*TDNF_REPOMD_DOC) u32 {
    const state = std.heap.c_allocator.create(DocState) catch {
        setError("out of memory", .{});
        return c.ERROR_TDNF_OUT_OF_MEMORY;
    };
    state.* = .{
        .arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator),
    };

    const parsed = repomd.parse(state.arena_state.allocator(), data) catch |err| {
        freeDoc(state);
        return switch (err) {
            error.InvalidRepoMd => blk: {
                setError("invalid repomd.xml", .{});
                break :blk c.ERROR_TDNF_INVALID_REPO_FILE;
            },
            error.OutOfMemory => blk: {
                setError("out of memory", .{});
                break :blk c.ERROR_TDNF_OUT_OF_MEMORY;
            },
        };
    };

    state.pszRevision = parsed.pszRevision;
    state.pRecords = parsed.pRecords;
    out_doc.* = toOpaque(state);
    return 0;
}

fn mapFileError(err: anyerror) u32 {
    return switch (err) {
        error.FileNotFound => c.ERROR_TDNF_FILE_NOT_FOUND,
        error.AccessDenied => c.ERROR_TDNF_ACCESS_DENIED,
        error.NameTooLong => c.ERROR_TDNF_NAME_TOO_LONG,
        error.BadPathName => c.ERROR_TDNF_INVALID_PARAMETER,
        error.NotDir => c.ERROR_TDNF_INVALID_DIR,
        error.IsDir => c.ERROR_TDNF_INVALID_DIR,
        error.OutOfMemory => c.ERROR_TDNF_OUT_OF_MEMORY,
        error.FileTooBig => c.ERROR_TDNF_OVERFLOW,
        error.StreamTooLong => c.ERROR_TDNF_OVERFLOW,
        else => c.ERROR_TDNF_FILESYS_IO,
    };
}

fn freeDoc(state: *DocState) void {
    state.arena_state.deinit();
    std.heap.c_allocator.destroy(state);
}

fn toOpaque(state: *DocState) *TDNF_REPOMD_DOC {
    return @ptrCast(state);
}

fn fromOpaque(doc: *TDNF_REPOMD_DOC) *DocState {
    return @ptrCast(@alignCast(doc));
}

fn fromOpaqueConst(doc: *const TDNF_REPOMD_DOC) *const DocState {
    return @ptrCast(@alignCast(doc));
}

fn expectOptionalString(expected: ?[]const u8, actual: ?[*:0]const u8) !void {
    const testing = std.testing;

    if (expected) |text| {
        const actual_text = actual orelse return error.TestExpectedEqual;
        try testing.expectEqualStrings(text, std.mem.span(actual_text));
    } else {
        try testing.expect(actual == null);
    }
}

comptime {
    _ = @import("available_loader.zig");
    _ = @import("cache.zig");
    _ = @import("filelists.zig");
    _ = @import("index.zig");
    _ = @import("other.zig");
    _ = @import("pkgquery.zig");
    _ = @import("rpmpkg.zig");
    _ = @import("solvbridge.zig");
    _ = @import("solver_coordinator.zig");
    _ = @import("solver_policy.zig");
    _ = @import("solver_result.zig");
    _ = @import("solver_result_c.zig");
    _ = @import("solver_shadow.zig");
    _ = @import("solver_rules.zig");
    _ = @import("solver_search.zig");
    _ = @import("transaction_native.zig");
    _ = @import("updateinfo.zig");
    if (!builtin.is_test) {
        _ = @import("query_native.zig");
    }
}

test "repomd header ABI matches Zig structs" {
    const testing = std.testing;

    try testing.expectEqual(@sizeOf(c_header.TDNF_REPOMD_CHECKSUM), @sizeOf(TDNF_REPOMD_CHECKSUM));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_CHECKSUM, "pszType"), @offsetOf(TDNF_REPOMD_CHECKSUM, "pszType"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_CHECKSUM, "pszValue"), @offsetOf(TDNF_REPOMD_CHECKSUM, "pszValue"));

    try testing.expectEqual(@sizeOf(c_header.TDNF_REPOMD_RECORD), @sizeOf(TDNF_REPOMD_RECORD));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "pszType"), @offsetOf(TDNF_REPOMD_RECORD, "pszType"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "dwKind"), @offsetOf(TDNF_REPOMD_RECORD, "dwKind"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "pszLocationHref"), @offsetOf(TDNF_REPOMD_RECORD, "pszLocationHref"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "checksum"), @offsetOf(TDNF_REPOMD_RECORD, "checksum"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "openChecksum"), @offsetOf(TDNF_REPOMD_RECORD, "openChecksum"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "nTimestamp"), @offsetOf(TDNF_REPOMD_RECORD, "nTimestamp"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "nSize"), @offsetOf(TDNF_REPOMD_RECORD, "nSize"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "nOpenSize"), @offsetOf(TDNF_REPOMD_RECORD, "nOpenSize"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "nDatabaseVersion"), @offsetOf(TDNF_REPOMD_RECORD, "nDatabaseVersion"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "nHasTimestamp"), @offsetOf(TDNF_REPOMD_RECORD, "nHasTimestamp"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "nHasSize"), @offsetOf(TDNF_REPOMD_RECORD, "nHasSize"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "nHasOpenSize"), @offsetOf(TDNF_REPOMD_RECORD, "nHasOpenSize"));
    try testing.expectEqual(@offsetOf(c_header.TDNF_REPOMD_RECORD, "nHasDatabaseVersion"), @offsetOf(TDNF_REPOMD_RECORD, "nHasDatabaseVersion"));
}

test "native solver comparison wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverResultCompare(
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompare(
        null,
        0,
        null,
        0,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison v2 wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompareV2(
        null,
        0,
        null,
        0,
        null,
        0,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison v3 wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompareV3(
        null,
        0,
        null,
        0,
        null,
        0,
        1,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison v4 wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompareV4(
        null,
        0,
        null,
        0,
        null,
        0,
        0,
        1,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison v5 wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompareV5(
        null,
        0,
        null,
        0,
        null,
        0,
        0,
        0,
        1,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison v6 wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompareV6(
        null,
        0,
        null,
        0,
        null,
        0,
        0,
        0,
        0,
        1,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison v7 wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompareV7(
        null,
        0,
        null,
        0,
        null,
        0,
        0,
        0,
        0,
        0,
        null,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison v8 wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompareV8(
        null,
        0,
        null,
        0,
        null,
        0,
        null,
        0,
        0,
        0,
        0,
        0,
        null,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "native live comparison v9 wrapper initializes invalid output" {
    var comparison = std.mem.zeroes(
        c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_RESULT,
    );
    const result = TDNFRepoMdNativeSolverLiveCompareV9(
        null,
        0,
        null,
        0,
        null,
        0,
        null,
        0,
        0,
        0,
        0,
        0,
        1,
        null,
        null,
        null,
        null,
        &comparison,
    );

    try std.testing.expectEqual(
        @as(u32, c.ERROR_TDNF_INVALID_PARAMETER),
        result,
    );
    try std.testing.expectEqual(
        @as(u32, c.TDNF_REPOMD_NATIVE_SOLVER_COMPARE_INVALID),
        comparison.dwStatus,
    );
}

test "translates exact installed erase selectors" {
    var raw = std.mem.zeroes(c.TDNF_REPOMD_NATIVE_SOLVER_LIVE_JOB);
    raw.pszRepository = "@System";
    raw.pszName = "installed";
    raw.pszVersion = "1";
    raw.pszRelease = "2";
    raw.pszArch = "x86_64";
    const job = liveEraseJobFromC(raw).?;

    try std.testing.expectEqualStrings("installed", job.selector.name);
    try std.testing.expectEqual(@as(?u32, 0), job.selector.epoch);
    raw.pszRepository = "available";
    try std.testing.expect(liveEraseJobFromC(raw) == null);
}

test "translates null-terminated protected package names" {
    var raw = [_:null]?[*:0]const u8{ "first", "second" };
    const names = try protectedNamesFromC(std.testing.allocator, &raw);
    defer std.testing.allocator.free(names);

    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("first", names[0]);
    try std.testing.expectEqualStrings("second", names[1]);

    var invalid = [_:null]?[*:0]const u8{""};
    try std.testing.expectError(
        error.InvalidInput,
        protectedNamesFromC(std.testing.allocator, &invalid),
    );
}

test "parses repomd records with revision checksums sizes and database versions" {
    const testing = std.testing;
    const xml =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
        \\  <revision>1729778159</revision>
        \\  <data type="primary">
        \\    <checksum type="sha256">62f84034</checksum>
        \\    <open-checksum type="sha256">fe3abdf7</open-checksum>
        \\    <location href="repodata/primary.xml.zst"/>
        \\    <timestamp>1729778159</timestamp>
        \\    <size>1234</size>
        \\    <open-size>5678</open-size>
        \\  </data>
        \\  <data type="updateinfo-1">
        \\    <checksum type="sha256">9270d81b</checksum>
        \\    <open-checksum type="sha256">1e01a83e</open-checksum>
        \\    <location href="repodata/updateinfo-1.xml.zst"/>
        \\    <timestamp>1729778160</timestamp>
        \\    <size>476</size>
        \\    <open-size>1053</open-size>
        \\  </data>
        \\  <data type="primary_db">
        \\    <checksum type="sha256">dbdb</checksum>
        \\    <location href="repodata/primary.sqlite.xz"/>
        \\    <timestamp>1729778161</timestamp>
        \\    <size>222</size>
        \\    <open-size>333</open-size>
        \\    <database_version>10</database_version>
        \\  </data>
        \\</repomd>
    ;

    var doc: ?*TDNF_REPOMD_DOC = null;
    try testing.expectEqual(@as(u32, 0), TDNFRepoMdParseBuffer(xml.ptr, xml.len, &doc));
    defer TDNFRepoMdFree(doc);

    const parsed = doc orelse return error.TestExpectedEqual;
    try expectOptionalString("1729778159", TDNFRepoMdGetRevision(parsed));
    try testing.expectEqual(@as(u32, 3), TDNFRepoMdGetRecordCount(parsed));

    const primary = TDNFRepoMdGetRecord(parsed, 0) orelse return error.TestExpectedEqual;
    try expectOptionalString("primary", primary.pszType);
    try testing.expectEqual(@as(u32, c.TDNF_REPOMD_RECORD_KIND_PRIMARY), primary.dwKind);
    try expectOptionalString("repodata/primary.xml.zst", primary.pszLocationHref);
    try expectOptionalString("sha256", primary.checksum.pszType);
    try expectOptionalString("62f84034", primary.checksum.pszValue);
    try expectOptionalString("sha256", primary.openChecksum.pszType);
    try expectOptionalString("fe3abdf7", primary.openChecksum.pszValue);
    try testing.expectEqual(@as(c_int, 1), primary.nHasTimestamp);
    try testing.expectEqual(@as(u64, 1729778159), primary.nTimestamp);
    try testing.expectEqual(@as(c_int, 1), primary.nHasSize);
    try testing.expectEqual(@as(u64, 1234), primary.nSize);
    try testing.expectEqual(@as(c_int, 1), primary.nHasOpenSize);
    try testing.expectEqual(@as(u64, 5678), primary.nOpenSize);
    try testing.expectEqual(@as(c_int, 0), primary.nHasDatabaseVersion);

    const updateinfo = TDNFRepoMdGetRecord(parsed, 1) orelse return error.TestExpectedEqual;
    try expectOptionalString("updateinfo-1", updateinfo.pszType);
    try testing.expectEqual(@as(u32, c.TDNF_REPOMD_RECORD_KIND_UPDATEINFO), updateinfo.dwKind);
    try expectOptionalString("repodata/updateinfo-1.xml.zst", updateinfo.pszLocationHref);

    const primary_db = TDNFRepoMdGetRecord(parsed, 2) orelse return error.TestExpectedEqual;
    try expectOptionalString("primary_db", primary_db.pszType);
    try testing.expectEqual(@as(u32, c.TDNF_REPOMD_RECORD_KIND_UNKNOWN), primary_db.dwKind);
    try testing.expectEqual(@as(c_int, 1), primary_db.nHasDatabaseVersion);
    try testing.expectEqual(@as(u64, 10), primary_db.nDatabaseVersion);
}

test "rejects missing required repomd fields" {
    const testing = std.testing;

    const cases = [_]struct {
        name: []const u8,
        xml: []const u8,
    }{
        .{
            .name = "data missing type",
            .xml =
            \\<repomd xmlns="http://linux.duke.edu/metadata/repo"><data><location href="repodata/primary.xml.gz"/></data></repomd>
            ,
        },
        .{
            .name = "data missing location",
            .xml =
            \\<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">abcd</checksum></data></repomd>
            ,
        },
    };

    for (cases) |case| {
        var doc: ?*TDNF_REPOMD_DOC = null;
        const rc = TDNFRepoMdParseBuffer(case.xml.ptr, case.xml.len, &doc);
        try testing.expectEqual(@as(u32, c.ERROR_TDNF_INVALID_REPO_FILE), rc);
        try testing.expect(doc == null);
    }
}

test "rejects malformed repomd xml" {
    const testing = std.testing;

    const cases = [_][]const u8{
        \\<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><location href="repodata/p.xml.gz"></repomd>
        ,
        \\<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><location href="repodata/p.xml.gz"/></dato></repomd>
        ,
    };

    for (cases) |xml| {
        var doc: ?*TDNF_REPOMD_DOC = null;
        const rc = TDNFRepoMdParseBuffer(xml.ptr, xml.len, &doc);
        try testing.expectEqual(@as(u32, c.ERROR_TDNF_INVALID_REPO_FILE), rc);
        try testing.expect(doc == null);
    }
}

test "normalizes raw updateinfo variants to advisory kind" {
    const testing = std.testing;
    const xml =
        \\<repomd xmlns="http://linux.duke.edu/metadata/repo">
        \\  <data type="updateinfo">
        \\    <location href="repodata/updateinfo.xml.gz"/>
        \\  </data>
        \\  <data type="updateinfo-2">
        \\    <location href="repodata/updateinfo-2.xml.zst"/>
        \\  </data>
        \\</repomd>
    ;

    var doc: ?*TDNF_REPOMD_DOC = null;
    try testing.expectEqual(@as(u32, 0), TDNFRepoMdParseBuffer(xml.ptr, xml.len, &doc));
    defer TDNFRepoMdFree(doc);

    const parsed = doc orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(u32, 2), TDNFRepoMdGetRecordCount(parsed));

    const first = TDNFRepoMdGetRecord(parsed, 0) orelse return error.TestExpectedEqual;
    const second = TDNFRepoMdGetRecord(parsed, 1) orelse return error.TestExpectedEqual;
    try expectOptionalString("updateinfo", first.pszType);
    try expectOptionalString("updateinfo-2", second.pszType);
    try testing.expectEqual(@as(u32, c.TDNF_REPOMD_RECORD_KIND_UPDATEINFO), first.dwKind);
    try testing.expectEqual(@as(u32, c.TDNF_REPOMD_RECORD_KIND_UPDATEINFO), second.dwKind);
}
