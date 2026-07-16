//! Native source RPM validation, planning, and extraction.
//!
//! All paths and payload metadata are validated from a retained `RpmFile`
//! before filesystem writes begin. Source packages are extracted into
//! package-scoped `_specdir`/`_sourcedir` paths and never enter the binary
//! transaction or rpmdb.

const std = @import("std");
const header = @import("rpm_header");
const pkgfile = @import("rpm_pkgfile");
const cpio = @import("cpio.zig");
const install = @import("install.zig");
const txn_config = @import("txn_config.zig");
const rpmtrans = @cImport({
    @cInclude("tdnfrpmtrans.h");
});
const c = @cImport({
    @cInclude("unistd.h");
});

const Allocator = std.mem.Allocator;
const RPMFILE_SPECFILE: u32 = 1 << 5;
const RPMFILE_GHOST: u32 = 1 << 6;
const RPMSENSE_LESS: u32 = 1 << 1;
const RPMSENSE_GREATER: u32 = 1 << 2;
const RPMSENSE_EQUAL: u32 = 1 << 3;
const RPMSENSE_SENSEMASK: u32 = 15;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

pub const SourceError = error{
    NotSourcePackage,
    InvalidSourceMetadata,
    InvalidSourcePath,
    MissingSpecFile,
    AmbiguousSpecFile,
    MissingPayloadEntry,
    UnexpectedPayloadEntry,
    GhostPayloadEntry,
    DuplicatePayloadEntry,
    ConflictingPayloadPath,
    UnsupportedPayloadFileType,
    UnsafePayloadLink,
    UnsupportedRpmlibRequirement,
};

pub const Error = Allocator.Error ||
    header.AccessError ||
    pkgfile.Error ||
    cpio.Error ||
    txn_config.InitError ||
    txn_config.SetMacroError ||
    txn_config.ResolvePathError ||
    install.Error ||
    SourceError;

const ManifestEntry = struct {
    path: []u8,
    mode: u32,
    flags: u32,
    mtime: ?u32,
    username: ?[]const u8 = null,
    groupname: ?[]const u8 = null,
};

const PlannedEntry = struct {
    relative_path: []const u8,
    data: []const u8,
    metadata: install.Metadata,
    spec: bool,
};

const Plan = struct {
    allocator: Allocator,
    payload: []u8,
    manifest: []ManifestEntry,
    entries: []PlannedEntry,
    spec_dir: []u8,
    source_dir: []u8,

    fn deinit(self: *Plan) void {
        for (self.manifest) |entry| self.allocator.free(entry.path);
        self.allocator.free(self.manifest);
        self.allocator.free(self.entries);
        self.allocator.free(self.payload);
        self.allocator.free(self.spec_dir);
        self.allocator.free(self.source_dir);
    }
};

const RpmlibFeature = struct {
    name: []const u8,
    version: []const u8,
};

const supported_rpmlib = [_]RpmlibFeature{
    .{ .name = "rpmlib(CaretInVersions)", .version = "4.15.0-1" },
    .{ .name = "rpmlib(CompressedFileNames)", .version = "3.0.4-1" },
    .{ .name = "rpmlib(DynamicBuildRequires)", .version = "4.15.0-1" },
    .{ .name = "rpmlib(FileDigests)", .version = "4.6.0-1" },
    .{ .name = "rpmlib(HeaderLoadSortsTags)", .version = "4.0.1-1" },
    .{ .name = "rpmlib(PayloadFilesHavePrefix)", .version = "4.0-1" },
    .{ .name = "rpmlib(PayloadIsLzma)", .version = "4.4.2-1" },
    .{ .name = "rpmlib(PayloadIsXz)", .version = "5.2-1" },
    .{ .name = "rpmlib(PayloadIsZstd)", .version = "5.4.18-1" },
    .{ .name = "rpmlib(RichDependencies)", .version = "4.12.0-1" },
    .{ .name = "rpmlib(TildeInVersions)", .version = "4.10.0-1" },
    .{ .name = "rpmlib(VersionedDependencies)", .version = "3.0.3-1" },
};

/// Extract a verified source RPM from its retained parsed handle.
///
/// Planning validates the complete header, payload, target paths, package
/// macro scope, and rpmlib requirements before any directory or file is
/// created. JUSTDB still performs validation but suppresses all writes.
pub fn extract(
    allocator: Allocator,
    rpm: *const pkgfile.RpmFile,
    config: *const txn_config.TxnConfig,
    trans_flags: u32,
) Error!void {
    var plan = try buildPlan(allocator, rpm, config);
    defer plan.deinit();

    if ((trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_JUSTDB) != 0) return;

    try writePlan(
        allocator,
        plan.entries,
        config.installRoot(),
        plan.spec_dir,
        plan.source_dir,
    );
}

fn buildPlan(
    allocator: Allocator,
    rpm: *const pkgfile.RpmFile,
    config: *const txn_config.TxnConfig,
) Error!Plan {
    if (rpm.packageKind() == .binary) return error.NotSourcePackage;

    const name = try requiredNonEmptyString(rpm.main, .name);
    const version = try requiredNonEmptyString(rpm.main, .version);
    const release = try requiredNonEmptyString(rpm.main, .release);
    const epoch = (try rpm.main.getU32Checked(.epoch)) orelse 0;
    try validateRpmlibRequirements(rpm.main);

    var child = try config.clone(allocator);
    defer child.deinit();
    try child.setMacroByName("name", name);
    try child.setMacroByName("version", version);
    try child.setMacroByName("release", release);
    var epoch_buf: [32]u8 = undefined;
    const epoch_text = std.fmt.bufPrint(&epoch_buf, "{d}", .{epoch}) catch
        return error.InvalidSourceMetadata;
    try child.setMacroByName("epoch", epoch_text);

    var top_buf: [std.fs.max_path_bytes]u8 = undefined;
    var spec_buf: [std.fs.max_path_bytes]u8 = undefined;
    var source_buf: [std.fs.max_path_bytes]u8 = undefined;
    const top_dir = try child.resolvePath(.topdir, &top_buf);
    const spec_dir_view = try child.resolvePath(.specdir, &spec_buf);
    const source_dir_view = try child.resolvePath(.sourcedir, &source_buf);
    try validateResolvedDirectory(config.installRoot(), top_dir);
    try validateResolvedDirectory(config.installRoot(), spec_dir_view);
    try validateResolvedDirectory(config.installRoot(), source_dir_view);

    const spec_dir = try allocator.dupe(u8, spec_dir_view);
    errdefer allocator.free(spec_dir);
    const source_dir = try allocator.dupe(u8, source_dir_view);
    errdefer allocator.free(source_dir);

    const manifest = try buildManifest(allocator, rpm.main);
    errdefer {
        for (manifest) |entry| allocator.free(entry.path);
        allocator.free(manifest);
    }
    const spec_index = try findSpecIndex(manifest);

    const payload = try rpm.decompressPayload(allocator);
    errdefer allocator.free(payload);

    const entries = try matchPayload(
        allocator,
        payload,
        manifest,
        spec_index,
        child.installRoot(),
    );
    errdefer allocator.free(entries);
    try validatePlanPaths(allocator, entries, spec_dir, source_dir);

    return .{
        .allocator = allocator,
        .payload = payload,
        .manifest = manifest,
        .entries = entries,
        .spec_dir = spec_dir,
        .source_dir = source_dir,
    };
}

fn requiredNonEmptyString(
    hdr: header.Header,
    tag: header.TagId,
) SourceError![]const u8 {
    const value = hdr.getStringChecked(tag) catch return error.InvalidSourceMetadata;
    if (value == null or value.?.len == 0) return error.InvalidSourceMetadata;
    return value.?;
}

fn validateResolvedDirectory(
    install_root: []const u8,
    resolved: []const u8,
) SourceError!void {
    if (resolved.len == 0 or resolved[0] != '/') return error.InvalidSourcePath;
    var parts = std.mem.splitScalar(u8, resolved[1..], '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return error.InvalidSourcePath;
    }

    if (std.mem.eql(u8, install_root, "/")) return;
    if (std.mem.eql(u8, resolved, install_root)) return;
    if (resolved.len <= install_root.len or
        !std.mem.eql(u8, resolved[0..install_root.len], install_root) or
        resolved[install_root.len] != '/')
    {
        return error.InvalidSourcePath;
    }
}

fn buildManifest(allocator: Allocator, hdr: header.Header) Error![]ManifestEntry {
    const count = (try hdr.stringArrayCountChecked(.basenames)) orelse
        return error.InvalidSourceMetadata;
    if (count == 0) return error.MissingSpecFile;
    if (try hdr.u32ArrayCountChecked(.filemtimes)) |mtime_count| {
        if (mtime_count != count) return error.InvalidSourceMetadata;
    }

    const manifest = try allocator.alloc(ManifestEntry, count);
    errdefer allocator.free(manifest);
    var initialized: usize = 0;
    errdefer for (manifest[0..initialized]) |entry| allocator.free(entry.path);

    var paths = std.StringHashMap(void).init(allocator);
    defer paths.deinit();

    for (0..count) |index| {
        const basename = (try hdr.stringArrayItemChecked(.basenames, index)) orelse
            return error.InvalidSourceMetadata;
        const dir_index = (try hdr.u32ArrayItemChecked(.dirindexes, index)) orelse
            return error.InvalidSourceMetadata;
        const dirname = (try hdr.stringArrayItemChecked(.dirnames, dir_index)) orelse
            return error.InvalidSourceMetadata;
        const joined = try std.fmt.allocPrint(allocator, "{s}{s}", .{
            dirname, basename,
        });
        defer allocator.free(joined);
        const path = try normalizeSourcePathOwned(allocator, joined);
        errdefer allocator.free(path);
        const result = try paths.getOrPut(path);
        if (result.found_existing) return error.InvalidSourceMetadata;

        manifest[index] = .{
            .path = path,
            .mode = (try hdr.u16ArrayItemChecked(.filemodes, index)) orelse 0,
            .flags = (try hdr.u32ArrayItemChecked(.fileflags, index)) orelse 0,
            .mtime = try hdr.u32ArrayItemChecked(.filemtimes, index),
            .username = try hdr.stringArrayItemChecked(.fileusername, index),
            .groupname = try hdr.stringArrayItemChecked(.filegroupname, index),
        };
        initialized += 1;
    }
    return manifest;
}

fn normalizeSourcePathOwned(
    allocator: Allocator,
    raw: []const u8,
) Error![]u8 {
    var path = raw;
    while (std.mem.startsWith(u8, path, "./")) path = path[2..];
    if (!install.isSafeRelativePath(path)) return error.InvalidSourcePath;
    return allocator.dupe(u8, path);
}

fn findSpecIndex(manifest: []const ManifestEntry) SourceError!usize {
    var flagged: ?usize = null;
    for (manifest, 0..) |entry, index| {
        if ((entry.flags & RPMFILE_SPECFILE) == 0) continue;
        if (flagged != null) return error.AmbiguousSpecFile;
        flagged = index;
    }
    if (flagged) |index| return index;

    var fallback: ?usize = null;
    for (manifest, 0..) |entry, index| {
        if (!std.mem.endsWith(u8, entry.path, ".spec")) continue;
        if (fallback != null) return error.AmbiguousSpecFile;
        fallback = index;
    }
    return fallback orelse error.MissingSpecFile;
}

fn matchPayload(
    allocator: Allocator,
    payload: []const u8,
    manifest: []const ManifestEntry,
    spec_index: usize,
    install_root: []const u8,
) Error![]PlannedEntry {
    var indexes = std.StringHashMap(usize).init(allocator);
    defer indexes.deinit();
    for (manifest, 0..) |entry, index| {
        try indexes.put(entry.path, index);
    }

    const processed = try allocator.alloc(bool, manifest.len);
    defer allocator.free(processed);
    @memset(processed, false);

    var planned = std.ArrayList(PlannedEntry).empty;
    errdefer planned.deinit(allocator);
    var walker = cpio.Walker.init(payload);
    while (try walker.next()) |entry| {
        const path = try normalizeSourcePathOwned(allocator, entry.name);
        defer allocator.free(path);
        const index = indexes.get(path) orelse return error.UnexpectedPayloadEntry;
        if (processed[index]) return error.DuplicatePayloadEntry;
        processed[index] = true;

        const manifest_entry = manifest[index];
        if ((manifest_entry.flags & RPMFILE_GHOST) != 0) {
            return error.GhostPayloadEntry;
        }
        const metadata = try install.resolveFileMetadata(
            allocator,
            install_root,
            manifest_entry.mode,
            manifest_entry.mtime,
            manifest_entry.username,
            manifest_entry.groupname,
            entry.mode,
            entry.mtime,
            entry.uid,
            entry.gid,
        );
        if ((metadata.mode & S_IFMT) != S_IFREG or
            (entry.mode & S_IFMT) != S_IFREG)
        {
            return error.UnsupportedPayloadFileType;
        }
        if (entry.nlink != 1) return error.UnsafePayloadLink;

        try planned.append(allocator, .{
            .relative_path = manifest_entry.path,
            .data = entry.data,
            .metadata = metadata,
            .spec = index == spec_index,
        });
    }

    if (!processed[spec_index]) return error.MissingSpecFile;
    for (processed, manifest) |seen, entry| {
        if (!seen and (entry.flags & RPMFILE_GHOST) == 0) {
            return error.MissingPayloadEntry;
        }
    }
    return planned.toOwnedSlice(allocator);
}

fn validatePlanPaths(
    allocator: Allocator,
    entries: []const PlannedEntry,
    spec_dir: []const u8,
    source_dir: []const u8,
) Error!void {
    for (entries, 0..) |left_entry, left_index| {
        const left = try plannedTargetPath(
            allocator,
            left_entry,
            spec_dir,
            source_dir,
        );
        defer allocator.free(left);

        for (entries[left_index + 1 ..]) |right_entry| {
            const right = try plannedTargetPath(
                allocator,
                right_entry,
                spec_dir,
                source_dir,
            );
            defer allocator.free(right);

            if (sameOrDescendantPath(left, right) or
                sameOrDescendantPath(right, left))
            {
                return error.ConflictingPayloadPath;
            }
        }
    }
}

fn writePlan(
    allocator: Allocator,
    entries: []const PlannedEntry,
    install_root: []const u8,
    spec_dir: []const u8,
    source_dir: []const u8,
) Error!void {
    try validatePlanPaths(allocator, entries, spec_dir, source_dir);
    for (entries) |entry| {
        try install.validateRegularFileDestinationBeneath(
            allocator,
            install_root,
            if (entry.spec) spec_dir else source_dir,
            entry.relative_path,
        );
    }
    for (entries) |entry| {
        try install.writeRegularFileBeneath(
            allocator,
            install_root,
            if (entry.spec) spec_dir else source_dir,
            entry.relative_path,
            entry.data,
            entry.metadata,
        );
    }
}

fn plannedTargetPath(
    allocator: Allocator,
    entry: PlannedEntry,
    spec_dir: []const u8,
    source_dir: []const u8,
) Error![]u8 {
    const base = if (entry.spec) spec_dir else source_dir;
    const joined = if (std.mem.endsWith(u8, base, "/"))
        try std.fmt.allocPrint(allocator, "{s}{s}", .{
            base,
            entry.relative_path,
        })
    else
        try std.fmt.allocPrint(allocator, "{s}/{s}", .{
            base,
            entry.relative_path,
        });
    defer allocator.free(joined);
    return normalizePlannedTargetPath(allocator, joined);
}

fn normalizePlannedTargetPath(
    allocator: Allocator,
    raw: []const u8,
) Error![]u8 {
    if (raw.len == 0 or raw[0] != '/') return error.InvalidSourcePath;

    var normalized = std.ArrayList(u8).empty;
    errdefer normalized.deinit(allocator);
    try normalized.append(allocator, '/');

    var wrote_component = false;
    var components = std.mem.splitScalar(u8, raw[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            return error.InvalidSourcePath;
        }
        if (wrote_component) try normalized.append(allocator, '/');
        try normalized.appendSlice(allocator, component);
        wrote_component = true;
    }
    return normalized.toOwnedSlice(allocator);
}

fn sameOrDescendantPath(parent: []const u8, candidate: []const u8) bool {
    if (std.mem.eql(u8, parent, candidate)) return true;
    return candidate.len > parent.len and
        candidate[parent.len] == '/' and
        std.mem.startsWith(u8, candidate, parent);
}

fn validateRpmlibRequirements(hdr: header.Header) SourceError!void {
    const count_optional = hdr.stringArrayCountChecked(.requirename) catch
        return error.InvalidSourceMetadata;
    const count = count_optional orelse 0;
    for (0..count) |index| {
        const name = (hdr.stringArrayItemChecked(.requirename, index) catch
            return error.InvalidSourceMetadata) orelse
            return error.InvalidSourceMetadata;
        if (!std.mem.startsWith(u8, name, "rpmlib(")) continue;
        const required_version =
            (hdr.stringArrayItemChecked(.requireversion, index) catch
                return error.InvalidSourceMetadata) orelse
            return error.InvalidSourceMetadata;
        const flags = (hdr.u32ArrayItemChecked(.requireflags, index) catch
            return error.InvalidSourceMetadata) orelse
            return error.InvalidSourceMetadata;

        try validateRpmlibRequirement(name, required_version, flags);
    }
}

fn validateRpmlibRequirement(
    name: []const u8,
    required_version: []const u8,
    flags: u32,
) SourceError!void {
    const provided_version = supportedRpmlibVersion(name) orelse
        return error.UnsupportedRpmlibRequirement;
    if (!versionSatisfies(provided_version, required_version, flags)) {
        return error.UnsupportedRpmlibRequirement;
    }
}

fn supportedRpmlibVersion(name: []const u8) ?[]const u8 {
    for (supported_rpmlib) |feature| {
        if (std.mem.eql(u8, name, feature.name)) return feature.version;
    }
    return null;
}

fn versionSatisfies(provided: []const u8, required: []const u8, flags: u32) bool {
    const sense = flags & RPMSENSE_SENSEMASK;
    if (sense == 0 or required.len == 0) return true;
    const comparison = compareRpmVersion(provided, required);
    return (comparison < 0 and (sense & RPMSENSE_LESS) != 0) or
        (comparison > 0 and (sense & RPMSENSE_GREATER) != 0) or
        (comparison == 0 and (sense & RPMSENSE_EQUAL) != 0);
}

fn compareRpmVersion(left_raw: []const u8, right_raw: []const u8) i32 {
    var left = left_raw;
    var right = right_raw;
    while (true) {
        while (left.len != 0 and !isRpmTokenByte(left[0])) left = left[1..];
        while (right.len != 0 and !isRpmTokenByte(right[0])) right = right[1..];

        if ((left.len != 0 and left[0] == '~') or
            (right.len != 0 and right[0] == '~'))
        {
            if (left.len == 0 or left[0] != '~') return 1;
            if (right.len == 0 or right[0] != '~') return -1;
            left = left[1..];
            right = right[1..];
            continue;
        }
        if ((left.len != 0 and left[0] == '^') or
            (right.len != 0 and right[0] == '^'))
        {
            if (left.len == 0) return -1;
            if (right.len == 0) return 1;
            if (left[0] != '^') return 1;
            if (right[0] != '^') return -1;
            left = left[1..];
            right = right[1..];
            continue;
        }
        if (left.len == 0 and right.len == 0) return 0;
        if (left.len == 0) return -1;
        if (right.len == 0) return 1;

        const left_digit = std.ascii.isDigit(left[0]);
        const right_digit = std.ascii.isDigit(right[0]);
        if (left_digit != right_digit) return if (left_digit) 1 else -1;

        const left_end = tokenEnd(left, left_digit);
        const right_end = tokenEnd(right, right_digit);
        var left_token = left[0..left_end];
        var right_token = right[0..right_end];
        left = left[left_end..];
        right = right[right_end..];

        if (left_digit) {
            left_token = std.mem.trimStart(u8, left_token, "0");
            right_token = std.mem.trimStart(u8, right_token, "0");
            if (left_token.len < right_token.len) return -1;
            if (left_token.len > right_token.len) return 1;
        }
        const order = std.mem.order(u8, left_token, right_token);
        if (order != .eq) return if (order == .lt) -1 else 1;
    }
}

fn isRpmTokenByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '~' or byte == '^';
}

fn tokenEnd(value: []const u8, digits: bool) usize {
    var end: usize = 0;
    while (end < value.len and
        (if (digits)
            std.ascii.isDigit(value[end])
        else
            std.ascii.isAlphabetic(value[end]))) : (end += 1)
    {}
    return end;
}

fn appendTestHex(
    output: *std.ArrayList(u8),
    allocator: Allocator,
    value: u32,
) !void {
    const digits = "0123456789abcdef";
    var shift: u5 = 28;
    while (true) {
        try output.append(allocator, digits[(value >> shift) & 0xf]);
        if (shift == 0) break;
        shift -= 4;
    }
}

fn appendTestCpioEntry(
    output: *std.ArrayList(u8),
    allocator: Allocator,
    name: []const u8,
    mode: u32,
    nlink: u32,
    data: []const u8,
) !void {
    const start = output.items.len;
    try output.appendSlice(allocator, cpio.MAGIC);
    const fields = [_]u32{
        1,
        mode,
        1001,
        1003,
        nlink,
        1234,
        @intCast(data.len),
        0,
        0,
        0,
        0,
        @intCast(name.len + 1),
        0,
    };
    for (fields) |field| try appendTestHex(output, allocator, field);
    try output.appendSlice(allocator, name);
    try output.append(allocator, 0);
    while ((output.items.len - start) % 4 != 0) try output.append(allocator, 0);
    try output.appendSlice(allocator, data);
    while ((output.items.len - start) % 4 != 0) try output.append(allocator, 0);
}

fn finishTestCpio(output: *std.ArrayList(u8), allocator: Allocator) !void {
    try appendTestCpioEntry(output, allocator, "TRAILER!!!", 0, 1, "");
}

test "source payload paths reject absolute and traversal names" {
    const allocator = std.testing.allocator;
    const invalid = [_][]const u8{
        "",
        "/absolute",
        "../escape",
        "dir/../escape",
        "dir//file",
        "dir/./file",
    };
    for (invalid) |path| {
        try std.testing.expectError(
            error.InvalidSourcePath,
            normalizeSourcePathOwned(allocator, path),
        );
    }
    const valid = try normalizeSourcePathOwned(allocator, "./dir/file");
    defer allocator.free(valid);
    try std.testing.expectEqualStrings("dir/file", valid);
}

test "source planning rejects unsafe links and mismatched payloads" {
    const allocator = std.testing.allocator;
    const manifest = [_]ManifestEntry{
        .{
            .path = @constCast("package.spec"),
            .mode = S_IFREG | 0o644,
            .flags = RPMFILE_SPECFILE,
            .mtime = 1234,
        },
    };

    const Cases = [_]struct {
        name: []const u8,
        mode: u32,
        nlink: u32,
        expected: anyerror,
    }{
        .{
            .name = "/package.spec",
            .mode = S_IFREG | 0o644,
            .nlink = 1,
            .expected = error.InvalidSourcePath,
        },
        .{
            .name = "../package.spec",
            .mode = S_IFREG | 0o644,
            .nlink = 1,
            .expected = error.InvalidSourcePath,
        },
        .{
            .name = "package.spec",
            .mode = 0o120777,
            .nlink = 1,
            .expected = error.UnsupportedPayloadFileType,
        },
        .{
            .name = "package.spec",
            .mode = S_IFREG | 0o644,
            .nlink = 2,
            .expected = error.UnsafePayloadLink,
        },
        .{
            .name = "other.spec",
            .mode = S_IFREG | 0o644,
            .nlink = 1,
            .expected = error.UnexpectedPayloadEntry,
        },
    };

    for (Cases) |case| {
        var payload = std.ArrayList(u8).empty;
        defer payload.deinit(allocator);
        try appendTestCpioEntry(
            &payload,
            allocator,
            case.name,
            case.mode,
            case.nlink,
            "content",
        );
        try finishTestCpio(&payload, allocator);
        try std.testing.expectError(
            case.expected,
            matchPayload(allocator, payload.items, &manifest, 0, "/"),
        );
    }

    var empty_payload = std.ArrayList(u8).empty;
    defer empty_payload.deinit(allocator);
    try finishTestCpio(&empty_payload, allocator);
    try std.testing.expectError(
        error.MissingSpecFile,
        matchPayload(allocator, empty_payload.items, &manifest, 0, "/"),
    );

    const missing_source_manifest = [_]ManifestEntry{
        manifest[0],
        .{
            .path = @constCast("payload.source"),
            .mode = S_IFREG | 0o644,
            .flags = 0,
            .mtime = 1234,
        },
    };
    var missing_source_payload = std.ArrayList(u8).empty;
    defer missing_source_payload.deinit(allocator);
    try appendTestCpioEntry(
        &missing_source_payload,
        allocator,
        "package.spec",
        S_IFREG | 0o644,
        1,
        "spec",
    );
    try finishTestCpio(&missing_source_payload, allocator);
    try std.testing.expectError(
        error.MissingPayloadEntry,
        matchPayload(
            allocator,
            missing_source_payload.items,
            &missing_source_manifest,
            0,
            "/",
        ),
    );

    const nosrc_manifest = [_]ManifestEntry{
        .{
            .path = @constCast("excluded.source"),
            .mode = S_IFREG | 0o644,
            .flags = RPMFILE_GHOST,
            .mtime = 1234,
        },
        manifest[0],
    };
    var nosrc_payload = std.ArrayList(u8).empty;
    defer nosrc_payload.deinit(allocator);
    try appendTestCpioEntry(
        &nosrc_payload,
        allocator,
        "package.spec",
        S_IFREG | 0o644,
        1,
        "spec",
    );
    try finishTestCpio(&nosrc_payload, allocator);
    const nosrc_plan = try matchPayload(
        allocator,
        nosrc_payload.items,
        &nosrc_manifest,
        1,
        "/",
    );
    defer allocator.free(nosrc_plan);
    try std.testing.expectEqual(@as(usize, 1), nosrc_plan.len);
    try std.testing.expect(nosrc_plan[0].spec);

    var ghost_payload = std.ArrayList(u8).empty;
    defer ghost_payload.deinit(allocator);
    try appendTestCpioEntry(
        &ghost_payload,
        allocator,
        "excluded.source",
        S_IFREG | 0o644,
        1,
        "must-not-be-extracted",
    );
    try appendTestCpioEntry(
        &ghost_payload,
        allocator,
        "package.spec",
        S_IFREG | 0o644,
        1,
        "spec",
    );
    try finishTestCpio(&ghost_payload, allocator);
    try std.testing.expectError(
        error.GhostPayloadEntry,
        matchPayload(
            allocator,
            ghost_payload.items,
            &nosrc_manifest,
            1,
            "/",
        ),
    );
}

test "source metadata distinguishes epoch-zero from absent file mtime" {
    const allocator = std.testing.allocator;
    var payload = std.ArrayList(u8).empty;
    defer payload.deinit(allocator);
    try appendTestCpioEntry(
        &payload,
        allocator,
        "package.spec",
        S_IFREG | 0o644,
        1,
        "spec",
    );
    try finishTestCpio(&payload, allocator);

    const explicit_epoch = [_]ManifestEntry{.{
        .path = @constCast("package.spec"),
        .mode = S_IFREG | 0o644,
        .flags = RPMFILE_SPECFILE,
        .mtime = 0,
    }};
    const epoch_plan = try matchPayload(
        allocator,
        payload.items,
        &explicit_epoch,
        0,
        "/",
    );
    defer allocator.free(epoch_plan);
    try std.testing.expectEqual(@as(u32, 0), epoch_plan[0].metadata.mtime);

    const absent = [_]ManifestEntry{.{
        .path = @constCast("package.spec"),
        .mode = S_IFREG | 0o644,
        .flags = RPMFILE_SPECFILE,
        .mtime = null,
    }};
    const fallback_plan = try matchPayload(
        allocator,
        payload.items,
        &absent,
        0,
        "/",
    );
    defer allocator.free(fallback_plan);
    try std.testing.expectEqual(@as(u32, 1234), fallback_plan[0].metadata.mtime);
}

test "source plan path conflicts fail before any output" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_ptr = c.getcwd(&cwd_buf, cwd_buf.len) orelse
        return error.TestUnexpectedResult;
    const cwd = std.mem.span(@as([*:0]const u8, @ptrCast(cwd_ptr)));
    const root = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ cwd, tmp.sub_path },
    );
    defer allocator.free(root);
    const base = try std.fmt.allocPrint(
        allocator,
        "{s}/extract",
        .{root},
    );
    defer allocator.free(base);

    const metadata = install.Metadata{
        .mode = S_IFREG | 0o644,
        .mtime = 1234,
        .uid = c.getuid(),
        .gid = c.getgid(),
    };
    const entries = [_]PlannedEntry{
        .{
            .relative_path = "a",
            .data = "first",
            .metadata = metadata,
            .spec = false,
        },
        .{
            .relative_path = "a/b",
            .data = "second",
            .metadata = metadata,
            .spec = false,
        },
    };

    try std.testing.expectError(
        error.ConflictingPayloadPath,
        writePlan(allocator, &entries, root, base, base),
    );

    const first_path = try std.fmt.allocPrint(allocator, "{s}/a", .{base});
    defer allocator.free(first_path);
    const first_path_z = try allocator.dupeZ(u8, first_path);
    defer allocator.free(first_path_z);
    try std.testing.expect(c.access(first_path_z.ptr, c.F_OK) != 0);
}

test "spec selection prefers flag and has strict fallback" {
    const entries = [_]ManifestEntry{
        .{ .path = @constCast("payload.tar"), .mode = S_IFREG, .flags = 0, .mtime = 0 },
        .{ .path = @constCast("package.spec"), .mode = S_IFREG, .flags = 0, .mtime = 0 },
    };
    try std.testing.expectEqual(@as(usize, 1), try findSpecIndex(&entries));

    var flagged = entries;
    flagged[0].flags = RPMFILE_SPECFILE;
    try std.testing.expectEqual(@as(usize, 0), try findSpecIndex(&flagged));

    const missing = [_]ManifestEntry{
        .{ .path = @constCast("payload.tar"), .mode = S_IFREG, .flags = 0, .mtime = 0 },
    };
    try std.testing.expectError(error.MissingSpecFile, findSpecIndex(&missing));

    const ambiguous = entries ++ [_]ManifestEntry{
        .{ .path = @constCast("other.spec"), .mode = S_IFREG, .flags = 0, .mtime = 0 },
    };
    try std.testing.expectError(error.AmbiguousSpecFile, findSpecIndex(&ambiguous));
}

test "rpmlib versions are checked against supported capabilities" {
    try std.testing.expectEqualStrings(
        "4.6.0-1",
        supportedRpmlibVersion("rpmlib(FileDigests)").?,
    );
    try std.testing.expect(
        supportedRpmlibVersion("rpmlib(NotImplemented)") == null,
    );
    try std.testing.expectError(
        error.UnsupportedRpmlibRequirement,
        validateRpmlibRequirement(
            "rpmlib(NotImplemented)",
            "1-1",
            RPMSENSE_LESS | RPMSENSE_EQUAL,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedRpmlibRequirement,
        validateRpmlibRequirement(
            "rpmlib(FileDigests)",
            "4.6.1-1",
            RPMSENSE_GREATER | RPMSENSE_EQUAL,
        ),
    );
    try std.testing.expect(versionSatisfies(
        "4.6.0-1",
        "4.6.0-1",
        RPMSENSE_LESS | RPMSENSE_EQUAL,
    ));
    try std.testing.expect(versionSatisfies(
        "4.6.0-1",
        "5.0-1",
        RPMSENSE_LESS | RPMSENSE_EQUAL,
    ));
    try std.testing.expect(!versionSatisfies(
        "4.6.0-1",
        "4.6.1-1",
        RPMSENSE_GREATER | RPMSENSE_EQUAL,
    ));
}

test "package macro child scope resolves rooted source directories" {
    var parent = try txn_config.TxnConfig.init(
        std.testing.allocator,
        "/phase6-root",
    );
    defer parent.deinit();
    try parent.setMacroByName(
        "_topdir",
        "/build/%{name}/%{version}/%{release}/%{epoch}",
    );
    try parent.setMacroByName("_specdir", "%{_topdir}/spec");
    try parent.setMacroByName("_sourcedir", "%{_topdir}/source");

    var child = try parent.clone(std.testing.allocator);
    defer child.deinit();
    try child.setMacroByName("name", "package");
    try child.setMacroByName("version", "1.2");
    try child.setMacroByName("release", "3");
    try child.setMacroByName("epoch", "7");

    var spec_buf: [std.fs.max_path_bytes]u8 = undefined;
    var source_buf: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/phase6-root/build/package/1.2/3/7/spec",
        try child.resolvePath(.specdir, &spec_buf),
    );
    try std.testing.expectEqualStrings(
        "/phase6-root/build/package/1.2/3/7/source",
        try child.resolvePath(.sourcedir, &source_buf),
    );
    try std.testing.expect(parent.rawValue("name") == null);
}
