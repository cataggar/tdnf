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
pub const metadata_cache = @import("cache.zig");
pub const metadata_model = model;
pub const package_query = @import("pkgquery.zig");
pub const query_index = @import("index.zig");
pub const rpm_package = @import("rpmpkg.zig");
pub const solv_bridge = @import("solvbridge.zig");
pub const query_native = @import("query_native.zig");
pub const transaction_native = @import("transaction_native.zig");
pub const solver_model = @import("solver_model.zig");
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
