const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");
const repomd_xml = @import("repomd.zig");
const primary_xml = @import("primary.zig");
const filelists_xml = @import("filelists.zig");
const other_xml = @import("other.zig");
const updateinfo_xml = @import("updateinfo.zig");

const c = if (builtin.is_test) @cImport({
    @cInclude("stdio.h");
    @cInclude("solv/pool.h");
    @cInclude("solv/repo.h");
    @cInclude("solv/repo_repomdxml.h");
    @cInclude("solv/repo_rpmmd.h");
    @cInclude("solv/repo_updateinfoxml.h");
    @cInclude("solv/solvable.h");
    @cInclude("solv/knownid.h");
    @cInclude("solv/queue.h");
}) else struct {};

pub const cookie_len = 32;
pub const format_version: u16 = 1;

pub const SectionKind = enum(u32) {
    strings = 1,
    repomd_records = 2,
    packages = 3,
    relations = 4,
    files = 5,
    changelogs = 6,
    advisories = 7,
    advisory_refs = 8,
    advisory_pkgs = 9,
};

pub const InvalidReason = enum {
    missing_cache,
    truncated,
    bad_magic,
    version_mismatch,
    invalid_header,
    missing_section,
    duplicate_section,
    section_bounds,
    section_size,
    string_ref,
    range_ref,
    bad_enum,
    cookie_mismatch,
    unsupported_checksum,
    unsupported_compression,
    sidecar_unavailable,
    sidecar_size_mismatch,
    sidecar_checksum_mismatch,
    sidecar_open_size_mismatch,
    sidecar_open_checksum_mismatch,
};

pub const LoadOptions = struct {
    cookie: [cookie_len]u8,
    repo_root: []const u8,
    repomd: *const model.ParsedRepoMd,
};

pub const LoadedRepository = struct {
    allocator: std.mem.Allocator,
    arena_state: std.heap.ArenaAllocator,
    backing_bytes: []u8,
    repository: model.RepositoryModel,

    pub fn deinit(self: *LoadedRepository) void {
        self.arena_state.deinit();
        self.allocator.free(self.backing_bytes);
        self.* = undefined;
    }
};

pub const LoadResult = union(enum) {
    loaded: LoadedRepository,
    invalid: InvalidReason,
};

pub const SerializeError = error{
    OutOfMemory,
    Overflow,
    InvalidRepositoryModel,
};

const magic = "TDMD";
const cookie_ident = "tdnf";
const known_feature_mask: u32 = feature_has_filelists | feature_has_other | feature_has_updateinfo;
const feature_has_filelists: u32 = 1 << 0;
const feature_has_other: u32 = 1 << 1;
const feature_has_updateinfo: u32 = 1 << 2;
const null_string_offset = std.math.maxInt(u32);
const header_size: usize = 56;
const section_entry_size: usize = 24;
const section_alignment: usize = 8;
const header_version_offset: usize = 4;
const section_len: usize = 9;

const section_order = [_]SectionKind{
    .strings,
    .repomd_records,
    .packages,
    .relations,
    .files,
    .changelogs,
    .advisories,
    .advisory_refs,
    .advisory_pkgs,
};

const StringRef = struct {
    offset: u32 = null_string_offset,
    len: u32 = 0,

    fn nullRef() StringRef {
        return .{};
    }

    fn isNull(self: StringRef) bool {
        return self.offset == null_string_offset;
    }
};

const RangeRef = struct {
    start: u32 = 0,
    len: u32 = 0,
};

const LayoutSection = struct {
    offset: usize = 0,
    len: usize = 0,
};

const Layout = struct {
    feature_bits: u32,
    revision: StringRef,
    cookie: [cookie_len]u8,
    sections: [section_len]LayoutSection,

    fn section(self: Layout, kind: SectionKind) LayoutSection {
        return self.sections[sectionIndex(kind)];
    }
};

const ParseLayoutError = error{
    Truncated,
    BadMagic,
    VersionMismatch,
    InvalidHeader,
    MissingSection,
    DuplicateSection,
    SectionBounds,
    SectionSize,
};

const DecodeError = error{
    OutOfMemory,
    Truncated,
    StringRef,
    RangeRef,
    BadEnum,
};

const DiskSection = struct {
    kind: SectionKind,
    bytes: []const u8,
    offset: usize = 0,
};

const StringTableBuilder = struct {
    allocator: std.mem.Allocator,
    bytes: std.array_list.Managed(u8),
    offsets: std.StringHashMap(StringRef),

    fn init(allocator: std.mem.Allocator) StringTableBuilder {
        return .{
            .allocator = allocator,
            .bytes = std.array_list.Managed(u8).init(allocator),
            .offsets = std.StringHashMap(StringRef).init(allocator),
        };
    }

    fn deinit(self: *StringTableBuilder) void {
        self.offsets.deinit();
        self.bytes.deinit();
    }

    fn maybeIntern(self: *StringTableBuilder, value: ?[]const u8) SerializeError!StringRef {
        const text = value orelse return StringRef.nullRef();
        return self.intern(text);
    }

    fn maybeInternZ(self: *StringTableBuilder, value: ?[*:0]const u8) SerializeError!StringRef {
        return self.maybeIntern(model.spanZ(value));
    }

    fn intern(self: *StringTableBuilder, value: []const u8) SerializeError!StringRef {
        if (self.offsets.get(value)) |existing| {
            return existing;
        }

        const offset = try toU32(self.bytes.items.len);
        self.bytes.appendSlice(value) catch return error.OutOfMemory;
        const ref = StringRef{ .offset = offset, .len = try toU32(value.len) };
        self.offsets.put(value, ref) catch return error.OutOfMemory;
        return ref;
    }
};

const Cursor = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn readInt(self: *Cursor, comptime T: type) DecodeError!T {
        if (self.offset + @sizeOf(T) > self.bytes.len) return error.Truncated;
        const value = std.mem.readInt(T, self.bytes[self.offset..][0..@sizeOf(T)], .little);
        self.offset += @sizeOf(T);
        return value;
    }

    fn readStringRef(self: *Cursor) DecodeError!StringRef {
        return .{
            .offset = try self.readInt(u32),
            .len = try self.readInt(u32),
        };
    }

    fn readRangeRef(self: *Cursor) DecodeError!RangeRef {
        return .{
            .start = try self.readInt(u32),
            .len = try self.readInt(u32),
        };
    }
};

pub fn serialize(
    allocator: std.mem.Allocator,
    repository: *const model.RepositoryModel,
    cookie: [cookie_len]u8,
) SerializeError![]u8 {
    if (repositoryValidationReason(repository)) |_| {
        return error.InvalidRepositoryModel;
    }

    var strings = StringTableBuilder.init(allocator);
    defer strings.deinit();

    var record_bytes = std.array_list.Managed(u8).init(allocator);
    defer record_bytes.deinit();
    var package_bytes = std.array_list.Managed(u8).init(allocator);
    defer package_bytes.deinit();
    var relation_bytes = std.array_list.Managed(u8).init(allocator);
    defer relation_bytes.deinit();
    var file_bytes = std.array_list.Managed(u8).init(allocator);
    defer file_bytes.deinit();
    var changelog_bytes = std.array_list.Managed(u8).init(allocator);
    defer changelog_bytes.deinit();
    var advisory_bytes = std.array_list.Managed(u8).init(allocator);
    defer advisory_bytes.deinit();
    var advisory_ref_bytes = std.array_list.Managed(u8).init(allocator);
    defer advisory_ref_bytes.deinit();
    var advisory_pkg_bytes = std.array_list.Managed(u8).init(allocator);
    defer advisory_pkg_bytes.deinit();

    const revision_ref = try strings.maybeInternZ(repository.pszRevision);
    for (repository.records) |record| {
        try serializeRecord(&record_bytes, &strings, record);
    }
    for (repository.packages) |pkg| {
        try serializePackage(&package_bytes, &strings, repository, pkg);
    }
    for (repository.relations) |relation| {
        try serializeRelation(&relation_bytes, &strings, relation);
    }
    for (repository.files) |file| {
        try serializeFile(&file_bytes, &strings, file);
    }
    for (repository.changelogs) |entry| {
        try serializeChangelog(&changelog_bytes, &strings, entry);
    }
    for (repository.advisories) |advisory| {
        try serializeAdvisory(&advisory_bytes, &strings, repository, advisory);
    }
    for (repository.advisory_references) |reference| {
        try serializeAdvisoryReference(&advisory_ref_bytes, &strings, reference);
    }
    for (repository.advisory_packages) |pkg| {
        try serializeAdvisoryPackage(&advisory_pkg_bytes, &strings, pkg);
    }

    const feature_bits = computeFeatureBits(repository.*);
    var sections = [_]DiskSection{
        .{ .kind = .strings, .bytes = strings.bytes.items },
        .{ .kind = .repomd_records, .bytes = record_bytes.items },
        .{ .kind = .packages, .bytes = package_bytes.items },
        .{ .kind = .relations, .bytes = relation_bytes.items },
        .{ .kind = .files, .bytes = file_bytes.items },
        .{ .kind = .changelogs, .bytes = changelog_bytes.items },
        .{ .kind = .advisories, .bytes = advisory_bytes.items },
        .{ .kind = .advisory_refs, .bytes = advisory_ref_bytes.items },
        .{ .kind = .advisory_pkgs, .bytes = advisory_pkg_bytes.items },
    };

    var next_offset = header_size + section_entry_size * sections.len;
    for (&sections) |*section| {
        next_offset = alignForward(next_offset, section_alignment);
        section.offset = next_offset;
        next_offset += section.bytes.len;
    }

    var out = std.array_list.Managed(u8).init(allocator);
    defer out.deinit();

    try out.appendSlice(magic);
    try appendU16(&out, format_version);
    try appendU16(&out, sections.len);
    try appendU32(&out, feature_bits);
    try appendU32(&out, 0);
    try appendStringRef(&out, revision_ref);
    out.appendSlice(&cookie) catch return error.OutOfMemory;

    for (sections) |section| {
        try appendU32(&out, @intFromEnum(section.kind));
        try appendU32(&out, 0);
        try appendU64(&out, section.offset);
        try appendU64(&out, section.bytes.len);
    }

    for (sections) |section| {
        try appendPaddingUntil(&out, section.offset);
        out.appendSlice(section.bytes) catch return error.OutOfMemory;
    }

    return out.toOwnedSlice() catch return error.OutOfMemory;
}

pub fn deserialize(
    allocator: std.mem.Allocator,
    data: []const u8,
    options: LoadOptions,
) !LoadResult {
    const layout = parseLayout(data) catch |err| {
        return .{ .invalid = mapLayoutError(err) };
    };

    if (!std.mem.eql(u8, &layout.cookie, &options.cookie)) {
        return .{ .invalid = .cookie_mismatch };
    }

    if (try validateSidecars(allocator, options)) |reason| {
        return .{ .invalid = reason };
    }

    var loaded = buildLoadedRepository(allocator, data, layout) catch |err| {
        return switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => .{ .invalid = mapDecodeError(err) },
        };
    };
    errdefer loaded.deinit();

    if (repositoryValidationReason(&loaded.repository)) |reason| {
        loaded.deinit();
        return .{ .invalid = reason };
    }

    return .{ .loaded = loaded };
}

pub fn loadFromFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    options: LoadOptions,
) !LoadResult {
    const data = readFileAlloc(allocator, path) catch return .{ .invalid = .missing_cache };
    defer allocator.free(data);
    return deserialize(allocator, data, options);
}

pub fn calculateCookieForBytes(data: []const u8) [cookie_len]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(cookie_ident);
    hasher.update(data);
    var cookie: [cookie_len]u8 = undefined;
    hasher.final(&cookie);
    return cookie;
}

pub fn calculateCookieForFile(allocator: std.mem.Allocator, path: []const u8) ![cookie_len]u8 {
    const data = try readFileAlloc(allocator, path);
    defer allocator.free(data);
    return calculateCookieForBytes(data);
}

fn serializeRecord(
    out: *std.array_list.Managed(u8),
    strings: *StringTableBuilder,
    record: model.Record,
) SerializeError!void {
    try appendStringRef(out, try strings.maybeInternZ(record.pszType));
    try appendStringRef(out, try strings.maybeInternZ(record.pszLocationHref));
    try appendStringRef(out, try strings.maybeInternZ(record.checksum.pszType));
    try appendStringRef(out, try strings.maybeInternZ(record.checksum.pszValue));
    try appendStringRef(out, try strings.maybeInternZ(record.openChecksum.pszType));
    try appendStringRef(out, try strings.maybeInternZ(record.openChecksum.pszValue));
    try appendU32(out, record.dwKind);

    var flags: u32 = 0;
    if (record.nHasTimestamp != 0) flags |= 1 << 0;
    if (record.nHasSize != 0) flags |= 1 << 1;
    if (record.nHasOpenSize != 0) flags |= 1 << 2;
    if (record.nHasDatabaseVersion != 0) flags |= 1 << 3;
    try appendU32(out, flags);
    try appendU64(out, record.nTimestamp);
    try appendU64(out, record.nSize);
    try appendU64(out, record.nOpenSize);
    try appendU64(out, record.nDatabaseVersion);
}

fn serializePackage(
    out: *std.array_list.Managed(u8),
    strings: *StringTableBuilder,
    repository: *const model.RepositoryModel,
    pkg: model.Package,
) SerializeError!void {
    try appendStringRef(out, try strings.intern(pkg.pkg_id));
    try appendStringRef(out, try strings.intern(pkg.nevra.name));
    try appendStringRef(out, try strings.intern(pkg.nevra.version));
    try appendStringRef(out, try strings.intern(pkg.nevra.release));
    try appendStringRef(out, try strings.intern(pkg.nevra.arch));
    try appendStringRef(out, try strings.intern(pkg.checksum.kind));
    try appendStringRef(out, try strings.intern(pkg.checksum.value));
    try appendStringRef(out, try strings.maybeIntern(pkg.summary));
    try appendStringRef(out, try strings.maybeIntern(pkg.description));
    try appendStringRef(out, try strings.maybeIntern(pkg.packager));
    try appendStringRef(out, try strings.maybeIntern(pkg.url));
    try appendStringRef(out, try strings.intern(pkg.location.href));
    try appendStringRef(out, try strings.maybeIntern(pkg.location.xml_base));
    try appendStringRef(out, try strings.maybeIntern(pkg.rpm.license));
    try appendStringRef(out, try strings.maybeIntern(pkg.rpm.vendor));
    try appendStringRef(out, try strings.maybeIntern(pkg.rpm.group));
    try appendStringRef(out, try strings.maybeIntern(pkg.rpm.buildhost));
    try appendStringRef(out, try strings.maybeIntern(pkg.rpm.source_rpm));
    try appendU64(out, pkg.time.file orelse 0);
    try appendU64(out, pkg.time.build orelse 0);
    try appendU64(out, pkg.size.package orelse 0);
    try appendU64(out, pkg.size.installed orelse 0);
    try appendU64(out, pkg.size.archive orelse 0);
    try appendU64(out, if (pkg.rpm.header_range) |range| range.start else 0);
    try appendU64(out, if (pkg.rpm.header_range) |range| range.end else 0);
    try appendU32(out, pkg.nevra.epoch orelse 0);

    var flags: u32 = 0;
    if (pkg.nevra.epoch != null) flags |= 1 << 0;
    if (pkg.time.file != null) flags |= 1 << 1;
    if (pkg.time.build != null) flags |= 1 << 2;
    if (pkg.size.package != null) flags |= 1 << 3;
    if (pkg.size.installed != null) flags |= 1 << 4;
    if (pkg.size.archive != null) flags |= 1 << 5;
    if (pkg.rpm.header_range != null) flags |= 1 << 6;
    if (pkg.checksum.is_pkgid) flags |= 1 << 7;
    try appendU32(out, flags);

    try appendRangeRef(out, try relationRangeRef(pkg.provides, repository.relations.len));
    try appendRangeRef(out, try relationRangeRef(pkg.requires, repository.relations.len));
    try appendRangeRef(out, try relationRangeRef(pkg.conflicts, repository.relations.len));
    try appendRangeRef(out, try relationRangeRef(pkg.obsoletes, repository.relations.len));
    try appendRangeRef(out, try relationRangeRef(pkg.recommends, repository.relations.len));
    try appendRangeRef(out, try relationRangeRef(pkg.suggests, repository.relations.len));
    try appendRangeRef(out, try relationRangeRef(pkg.supplements, repository.relations.len));
    try appendRangeRef(out, try relationRangeRef(pkg.enhances, repository.relations.len));
    try appendRangeRef(out, try fileRangeRef(pkg.files, repository.files.len));
    try appendRangeRef(out, try changelogRangeRef(pkg.changelogs, repository.changelogs.len));
}

fn serializeRelation(
    out: *std.array_list.Managed(u8),
    strings: *StringTableBuilder,
    relation: model.Relation,
) SerializeError!void {
    try appendStringRef(out, try strings.intern(relation.name));
    try appendStringRef(out, try strings.maybeIntern(relation.flags));
    try appendStringRef(out, try strings.maybeIntern(relation.version));
    try appendStringRef(out, try strings.maybeIntern(relation.release));
    try appendU32(out, relation.epoch orelse 0);
    try appendU32(out, @intFromEnum(relation.comparison));

    var flags: u32 = 0;
    if (relation.flags != null) flags |= 1 << 0;
    if (relation.epoch != null) flags |= 1 << 1;
    if (relation.version != null) flags |= 1 << 2;
    if (relation.release != null) flags |= 1 << 3;
    if (relation.pre) flags |= 1 << 4;
    try appendU32(out, flags);
}

fn serializeFile(
    out: *std.array_list.Managed(u8),
    strings: *StringTableBuilder,
    file: model.FileEntry,
) SerializeError!void {
    try appendStringRef(out, try strings.intern(file.path));
    try appendU32(out, @intFromEnum(file.kind));
}

fn serializeChangelog(
    out: *std.array_list.Managed(u8),
    strings: *StringTableBuilder,
    entry: model.ChangelogEntry,
) SerializeError!void {
    try appendStringRef(out, try strings.intern(entry.author));
    try appendStringRef(out, try strings.intern(entry.text));
    try appendU64(out, entry.timestamp);
}

fn serializeAdvisory(
    out: *std.array_list.Managed(u8),
    strings: *StringTableBuilder,
    repository: *const model.RepositoryModel,
    advisory: model.Advisory,
) SerializeError!void {
    try appendStringRef(out, try strings.intern(advisory.id));
    try appendStringRef(out, try strings.intern(advisory.raw_type));
    try appendStringRef(out, try strings.maybeIntern(advisory.from));
    try appendStringRef(out, try strings.maybeIntern(advisory.status));
    try appendStringRef(out, try strings.maybeIntern(advisory.version));
    try appendStringRef(out, try strings.maybeIntern(advisory.title));
    try appendStringRef(out, try strings.maybeIntern(advisory.severity));
    try appendStringRef(out, try strings.maybeIntern(advisory.release));
    try appendStringRef(out, try strings.maybeIntern(advisory.rights));
    try appendStringRef(out, try strings.maybeIntern(advisory.issued));
    try appendStringRef(out, try strings.maybeIntern(advisory.updated));
    try appendStringRef(out, try strings.maybeIntern(advisory.description));
    try appendU32(out, @intFromEnum(advisory.kind));
    try appendU32(out, @as(u32, if (advisory.reboot_suggested) 1 else 0));
    try appendRangeRef(out, try advisoryReferenceRangeRef(advisory.references, repository.advisory_references.len));
    try appendRangeRef(out, try advisoryPackageRangeRef(advisory.packages, repository.advisory_packages.len));
}

fn serializeAdvisoryReference(
    out: *std.array_list.Managed(u8),
    strings: *StringTableBuilder,
    reference: model.AdvisoryReference,
) SerializeError!void {
    try appendStringRef(out, try strings.maybeIntern(reference.raw_type));
    try appendStringRef(out, try strings.maybeIntern(reference.id));
    try appendStringRef(out, try strings.maybeIntern(reference.title));
    try appendStringRef(out, try strings.maybeIntern(reference.href));
    try appendU32(out, @intFromEnum(reference.kind));
}

fn serializeAdvisoryPackage(
    out: *std.array_list.Managed(u8),
    strings: *StringTableBuilder,
    pkg: model.AdvisoryPackage,
) SerializeError!void {
    try appendStringRef(out, try strings.maybeIntern(pkg.collection_short));
    try appendStringRef(out, try strings.maybeIntern(pkg.collection_name));
    try appendStringRef(out, try strings.intern(pkg.nevra.name));
    try appendStringRef(out, try strings.intern(pkg.nevra.version));
    try appendStringRef(out, try strings.intern(pkg.nevra.release));
    try appendStringRef(out, try strings.intern(pkg.nevra.arch));
    try appendStringRef(out, try strings.maybeIntern(pkg.src));
    try appendStringRef(out, try strings.maybeIntern(pkg.filename));
    try appendU32(out, pkg.nevra.epoch orelse 0);

    var flags: u32 = 0;
    if (pkg.nevra.epoch != null) flags |= 1 << 0;
    if (pkg.reboot_suggested) flags |= 1 << 1;
    try appendU32(out, flags);
}

fn buildLoadedRepository(
    allocator: std.mem.Allocator,
    data: []const u8,
    layout: Layout,
) DecodeError!LoadedRepository {
    const backing_bytes = allocator.dupe(u8, data) catch return error.OutOfMemory;
    errdefer allocator.free(backing_bytes);

    var loaded = LoadedRepository{
        .allocator = allocator,
        .arena_state = std.heap.ArenaAllocator.init(allocator),
        .backing_bytes = backing_bytes,
        .repository = .{},
    };
    errdefer loaded.arena_state.deinit();

    const arena = loaded.arena_state.allocator();
    const strings_section = backing_bytes[layout.section(.strings).offset .. layout.section(.strings).offset + layout.section(.strings).len];

    loaded.repository = .{
        .pszRevision = if (try resolveOptionalString(strings_section, layout.revision)) |text|
            (try model.dupZ(arena, text)).ptr
        else
            null,
        .records = try decodeRecords(arena, strings_section, sectionBytes(backing_bytes, layout.section(.repomd_records))),
        .relations = try decodeRelations(arena, strings_section, sectionBytes(backing_bytes, layout.section(.relations))),
        .files = try decodeFiles(arena, strings_section, sectionBytes(backing_bytes, layout.section(.files))),
        .changelogs = try decodeChangelogs(arena, strings_section, sectionBytes(backing_bytes, layout.section(.changelogs))),
        .advisory_references = try decodeAdvisoryReferences(arena, strings_section, sectionBytes(backing_bytes, layout.section(.advisory_refs))),
        .advisory_packages = try decodeAdvisoryPackages(arena, strings_section, sectionBytes(backing_bytes, layout.section(.advisory_pkgs))),
        .packages = undefined,
        .advisories = undefined,
        .has_filelists = (layout.feature_bits & feature_has_filelists) != 0,
        .has_other = (layout.feature_bits & feature_has_other) != 0,
        .has_updateinfo = (layout.feature_bits & feature_has_updateinfo) != 0,
    };

    loaded.repository.packages = try decodePackages(
        arena,
        strings_section,
        sectionBytes(backing_bytes, layout.section(.packages)),
        loaded.repository.relations.len,
        loaded.repository.files.len,
        loaded.repository.changelogs.len,
    );
    loaded.repository.advisories = try decodeAdvisories(
        arena,
        strings_section,
        sectionBytes(backing_bytes, layout.section(.advisories)),
        loaded.repository.advisory_references.len,
        loaded.repository.advisory_packages.len,
    );

    return loaded;
}

fn decodeRecords(
    allocator: std.mem.Allocator,
    strings: []const u8,
    bytes: []const u8,
) DecodeError![]model.Record {
    if (bytes.len % diskRecordSize() != 0) return error.Truncated;
    const count = bytes.len / diskRecordSize();
    const records = allocator.alloc(model.Record, count) catch return error.OutOfMemory;
    var offset: usize = 0;
    for (records) |*record| {
        var cursor = Cursor{ .bytes = bytes[offset .. offset + diskRecordSize()] };
        offset += diskRecordSize();

        const raw_type = try resolveOptionalZString(allocator, strings, try cursor.readStringRef());
        const location = try resolveOptionalZString(allocator, strings, try cursor.readStringRef());
        const checksum_type = try resolveOptionalZString(allocator, strings, try cursor.readStringRef());
        const checksum_value = try resolveOptionalZString(allocator, strings, try cursor.readStringRef());
        const open_checksum_type = try resolveOptionalZString(allocator, strings, try cursor.readStringRef());
        const open_checksum_value = try resolveOptionalZString(allocator, strings, try cursor.readStringRef());
        const kind = try cursor.readInt(u32);
        const flags = try cursor.readInt(u32);

        if (parseRecordKind(kind) == null) return error.BadEnum;

        record.* = .{
            .pszType = raw_type,
            .dwKind = kind,
            .pszLocationHref = location,
            .checksum = .{
                .pszType = checksum_type,
                .pszValue = checksum_value,
            },
            .openChecksum = .{
                .pszType = open_checksum_type,
                .pszValue = open_checksum_value,
            },
            .nTimestamp = try cursor.readInt(u64),
            .nSize = try cursor.readInt(u64),
            .nOpenSize = try cursor.readInt(u64),
            .nDatabaseVersion = try cursor.readInt(u64),
            .nHasTimestamp = boolToCInt((flags & (1 << 0)) != 0),
            .nHasSize = boolToCInt((flags & (1 << 1)) != 0),
            .nHasOpenSize = boolToCInt((flags & (1 << 2)) != 0),
            .nHasDatabaseVersion = boolToCInt((flags & (1 << 3)) != 0),
        };
    }
    return records;
}

fn decodePackages(
    allocator: std.mem.Allocator,
    strings: []const u8,
    bytes: []const u8,
    relation_count: usize,
    file_count: usize,
    changelog_count: usize,
) DecodeError![]model.Package {
    if (bytes.len % diskPackageSize() != 0) return error.Truncated;
    const count = bytes.len / diskPackageSize();
    const packages = allocator.alloc(model.Package, count) catch return error.OutOfMemory;
    var offset: usize = 0;
    for (packages) |*pkg| {
        var cursor = Cursor{ .bytes = bytes[offset .. offset + diskPackageSize()] };
        offset += diskPackageSize();

        const pkg_id = try resolveRequiredString(strings, try cursor.readStringRef());
        const name = try resolveRequiredString(strings, try cursor.readStringRef());
        const version = try resolveRequiredString(strings, try cursor.readStringRef());
        const release = try resolveRequiredString(strings, try cursor.readStringRef());
        const arch = try resolveRequiredString(strings, try cursor.readStringRef());
        const checksum_kind = try resolveRequiredString(strings, try cursor.readStringRef());
        const checksum_value = try resolveRequiredString(strings, try cursor.readStringRef());
        const summary = try resolveOptionalString(strings, try cursor.readStringRef());
        const description = try resolveOptionalString(strings, try cursor.readStringRef());
        const packager = try resolveOptionalString(strings, try cursor.readStringRef());
        const url = try resolveOptionalString(strings, try cursor.readStringRef());
        const location_href = try resolveRequiredString(strings, try cursor.readStringRef());
        const location_xml_base = try resolveOptionalString(strings, try cursor.readStringRef());
        const license = try resolveOptionalString(strings, try cursor.readStringRef());
        const vendor = try resolveOptionalString(strings, try cursor.readStringRef());
        const group = try resolveOptionalString(strings, try cursor.readStringRef());
        const buildhost = try resolveOptionalString(strings, try cursor.readStringRef());
        const source_rpm = try resolveOptionalString(strings, try cursor.readStringRef());
        const time_file = try cursor.readInt(u64);
        const time_build = try cursor.readInt(u64);
        const size_package = try cursor.readInt(u64);
        const size_installed = try cursor.readInt(u64);
        const size_archive = try cursor.readInt(u64);
        const header_start = try cursor.readInt(u64);
        const header_end = try cursor.readInt(u64);
        const epoch = try cursor.readInt(u32);
        const flags = try cursor.readInt(u32);
        const provides = try checkedRange(try cursor.readRangeRef(), relation_count);
        const requires = try checkedRange(try cursor.readRangeRef(), relation_count);
        const conflicts = try checkedRange(try cursor.readRangeRef(), relation_count);
        const obsoletes = try checkedRange(try cursor.readRangeRef(), relation_count);
        const recommends = try checkedRange(try cursor.readRangeRef(), relation_count);
        const suggests = try checkedRange(try cursor.readRangeRef(), relation_count);
        const supplements = try checkedRange(try cursor.readRangeRef(), relation_count);
        const enhances = try checkedRange(try cursor.readRangeRef(), relation_count);
        const files = try checkedRange(try cursor.readRangeRef(), file_count);
        const changelogs = try checkedRange(try cursor.readRangeRef(), changelog_count);

        pkg.* = .{
            .pkg_id = pkg_id,
            .nevra = .{
                .name = name,
                .epoch = if ((flags & (1 << 0)) != 0) epoch else null,
                .version = version,
                .release = release,
                .arch = arch,
            },
            .checksum = .{
                .kind = checksum_kind,
                .value = checksum_value,
                .is_pkgid = (flags & (1 << 7)) != 0,
            },
            .summary = summary,
            .description = description,
            .packager = packager,
            .url = url,
            .time = .{
                .file = if ((flags & (1 << 1)) != 0) time_file else null,
                .build = if ((flags & (1 << 2)) != 0) time_build else null,
            },
            .size = .{
                .package = if ((flags & (1 << 3)) != 0) size_package else null,
                .installed = if ((flags & (1 << 4)) != 0) size_installed else null,
                .archive = if ((flags & (1 << 5)) != 0) size_archive else null,
            },
            .location = .{
                .href = location_href,
                .xml_base = location_xml_base,
            },
            .rpm = .{
                .license = license,
                .vendor = vendor,
                .group = group,
                .buildhost = buildhost,
                .source_rpm = source_rpm,
                .header_range = if ((flags & (1 << 6)) != 0)
                    .{ .start = header_start, .end = header_end }
                else
                    null,
            },
            .provides = rangeToRelationRange(provides),
            .requires = rangeToRelationRange(requires),
            .conflicts = rangeToRelationRange(conflicts),
            .obsoletes = rangeToRelationRange(obsoletes),
            .recommends = rangeToRelationRange(recommends),
            .suggests = rangeToRelationRange(suggests),
            .supplements = rangeToRelationRange(supplements),
            .enhances = rangeToRelationRange(enhances),
            .files = rangeToFileRange(files),
            .changelogs = rangeToChangelogRange(changelogs),
        };
    }
    return packages;
}

fn decodeRelations(
    allocator: std.mem.Allocator,
    strings: []const u8,
    bytes: []const u8,
) DecodeError![]model.Relation {
    if (bytes.len % diskRelationSize() != 0) return error.Truncated;
    const count = bytes.len / diskRelationSize();
    const relations = allocator.alloc(model.Relation, count) catch return error.OutOfMemory;
    var offset: usize = 0;
    for (relations) |*relation| {
        var cursor = Cursor{ .bytes = bytes[offset .. offset + diskRelationSize()] };
        offset += diskRelationSize();
        const flags_bits = blk: {
            const name = try resolveRequiredString(strings, try cursor.readStringRef());
            const raw_flags = try resolveOptionalString(strings, try cursor.readStringRef());
            const version = try resolveOptionalString(strings, try cursor.readStringRef());
            const release = try resolveOptionalString(strings, try cursor.readStringRef());
            const epoch = try cursor.readInt(u32);
            const comparison_raw = try cursor.readInt(u32);
            const bits = try cursor.readInt(u32);
            relation.* = .{
                .name = name,
                .flags = raw_flags,
                .comparison = try parseCompareOp(comparison_raw),
                .epoch = if ((bits & (1 << 1)) != 0) epoch else null,
                .version = version,
                .release = release,
                .pre = (bits & (1 << 4)) != 0,
            };
            break :blk bits;
        };
        _ = flags_bits;
    }
    return relations;
}

fn decodeFiles(
    allocator: std.mem.Allocator,
    strings: []const u8,
    bytes: []const u8,
) DecodeError![]model.FileEntry {
    if (bytes.len % diskFileSize() != 0) return error.Truncated;
    const count = bytes.len / diskFileSize();
    const files = allocator.alloc(model.FileEntry, count) catch return error.OutOfMemory;
    var offset: usize = 0;
    for (files) |*file| {
        var cursor = Cursor{ .bytes = bytes[offset .. offset + diskFileSize()] };
        offset += diskFileSize();
        file.* = .{
            .path = try resolveRequiredString(strings, try cursor.readStringRef()),
            .kind = try parseFileKind(try cursor.readInt(u32)),
        };
    }
    return files;
}

fn decodeChangelogs(
    allocator: std.mem.Allocator,
    strings: []const u8,
    bytes: []const u8,
) DecodeError![]model.ChangelogEntry {
    if (bytes.len % diskChangelogSize() != 0) return error.Truncated;
    const count = bytes.len / diskChangelogSize();
    const changelogs = allocator.alloc(model.ChangelogEntry, count) catch return error.OutOfMemory;
    var offset: usize = 0;
    for (changelogs) |*entry| {
        var cursor = Cursor{ .bytes = bytes[offset .. offset + diskChangelogSize()] };
        offset += diskChangelogSize();
        entry.* = .{
            .author = try resolveRequiredString(strings, try cursor.readStringRef()),
            .text = try resolveRequiredString(strings, try cursor.readStringRef()),
            .timestamp = try cursor.readInt(u64),
        };
    }
    return changelogs;
}

fn decodeAdvisories(
    allocator: std.mem.Allocator,
    strings: []const u8,
    bytes: []const u8,
    reference_count: usize,
    package_count: usize,
) DecodeError![]model.Advisory {
    if (bytes.len % diskAdvisorySize() != 0) return error.Truncated;
    const count = bytes.len / diskAdvisorySize();
    const advisories = allocator.alloc(model.Advisory, count) catch return error.OutOfMemory;
    var offset: usize = 0;
    for (advisories) |*advisory| {
        var cursor = Cursor{ .bytes = bytes[offset .. offset + diskAdvisorySize()] };
        offset += diskAdvisorySize();
        advisory.* = .{
            .id = try resolveRequiredString(strings, try cursor.readStringRef()),
            .raw_type = try resolveRequiredString(strings, try cursor.readStringRef()),
            .from = try resolveOptionalString(strings, try cursor.readStringRef()),
            .status = try resolveOptionalString(strings, try cursor.readStringRef()),
            .version = try resolveOptionalString(strings, try cursor.readStringRef()),
            .title = try resolveOptionalString(strings, try cursor.readStringRef()),
            .severity = try resolveOptionalString(strings, try cursor.readStringRef()),
            .release = try resolveOptionalString(strings, try cursor.readStringRef()),
            .rights = try resolveOptionalString(strings, try cursor.readStringRef()),
            .issued = try resolveOptionalString(strings, try cursor.readStringRef()),
            .updated = try resolveOptionalString(strings, try cursor.readStringRef()),
            .description = try resolveOptionalString(strings, try cursor.readStringRef()),
            .kind = try parseAdvisoryKind(try cursor.readInt(u32)),
            .reboot_suggested = (try cursor.readInt(u32)) != 0,
            .references = rangeToAdvisoryReferenceRange(try checkedRange(try cursor.readRangeRef(), reference_count)),
            .packages = rangeToAdvisoryPackageRange(try checkedRange(try cursor.readRangeRef(), package_count)),
        };
    }
    return advisories;
}

fn decodeAdvisoryReferences(
    allocator: std.mem.Allocator,
    strings: []const u8,
    bytes: []const u8,
) DecodeError![]model.AdvisoryReference {
    if (bytes.len % diskAdvisoryReferenceSize() != 0) return error.Truncated;
    const count = bytes.len / diskAdvisoryReferenceSize();
    const references = allocator.alloc(model.AdvisoryReference, count) catch return error.OutOfMemory;
    var offset: usize = 0;
    for (references) |*reference| {
        var cursor = Cursor{ .bytes = bytes[offset .. offset + diskAdvisoryReferenceSize()] };
        offset += diskAdvisoryReferenceSize();
        reference.* = .{
            .raw_type = try resolveOptionalString(strings, try cursor.readStringRef()),
            .id = try resolveOptionalString(strings, try cursor.readStringRef()),
            .title = try resolveOptionalString(strings, try cursor.readStringRef()),
            .href = try resolveOptionalString(strings, try cursor.readStringRef()),
            .kind = try parseAdvisoryReferenceKind(try cursor.readInt(u32)),
        };
    }
    return references;
}

fn decodeAdvisoryPackages(
    allocator: std.mem.Allocator,
    strings: []const u8,
    bytes: []const u8,
) DecodeError![]model.AdvisoryPackage {
    if (bytes.len % diskAdvisoryPackageSize() != 0) return error.Truncated;
    const count = bytes.len / diskAdvisoryPackageSize();
    const packages = allocator.alloc(model.AdvisoryPackage, count) catch return error.OutOfMemory;
    var offset: usize = 0;
    for (packages) |*pkg| {
        var cursor = Cursor{ .bytes = bytes[offset .. offset + diskAdvisoryPackageSize()] };
        offset += diskAdvisoryPackageSize();
        const flags = blk: {
            const collection_short = try resolveOptionalString(strings, try cursor.readStringRef());
            const collection_name = try resolveOptionalString(strings, try cursor.readStringRef());
            const name = try resolveRequiredString(strings, try cursor.readStringRef());
            const version = try resolveRequiredString(strings, try cursor.readStringRef());
            const release = try resolveRequiredString(strings, try cursor.readStringRef());
            const arch = try resolveRequiredString(strings, try cursor.readStringRef());
            const src = try resolveOptionalString(strings, try cursor.readStringRef());
            const filename = try resolveOptionalString(strings, try cursor.readStringRef());
            const epoch = try cursor.readInt(u32);
            const bits = try cursor.readInt(u32);
            pkg.* = .{
                .collection_short = collection_short,
                .collection_name = collection_name,
                .nevra = .{
                    .name = name,
                    .epoch = if ((bits & (1 << 0)) != 0) epoch else null,
                    .version = version,
                    .release = release,
                    .arch = arch,
                },
                .src = src,
                .filename = filename,
                .reboot_suggested = (bits & (1 << 1)) != 0,
            };
            break :blk bits;
        };
        _ = flags;
    }
    return packages;
}

fn parseLayout(data: []const u8) ParseLayoutError!Layout {
    if (data.len < header_size + section_entry_size * section_len) return error.Truncated;
    if (!std.mem.eql(u8, data[0..magic.len], magic)) return error.BadMagic;

    const version = readU16At(data, header_version_offset) catch return error.Truncated;
    if (version != format_version) return error.VersionMismatch;

    const section_count = readU16At(data, 6) catch return error.Truncated;
    if (section_count != section_len) return error.InvalidHeader;

    const feature_bits = readU32At(data, 8) catch return error.Truncated;
    if ((feature_bits & ~known_feature_mask) != 0) return error.InvalidHeader;

    var revision = StringRef{
        .offset = readU32At(data, 16) catch return error.Truncated,
        .len = readU32At(data, 20) catch return error.Truncated,
    };

    var cookie: [cookie_len]u8 = undefined;
    @memcpy(&cookie, data[24 .. 24 + cookie_len]);

    var sections: [section_len]LayoutSection = std.mem.zeroes([section_len]LayoutSection);
    var seen: [section_len]bool = [_]bool{false} ** section_len;
    const section_table_offset = header_size;
    const section_table_end = header_size + section_entry_size * section_len;

    for (0..section_len) |index| {
        const entry_offset = section_table_offset + index * section_entry_size;
        const kind_raw = readU32At(data, entry_offset) catch return error.Truncated;
        const kind = parseSectionKind(kind_raw) orelse return error.InvalidHeader;
        const kind_index = sectionIndex(kind);
        if (seen[kind_index]) return error.DuplicateSection;
        seen[kind_index] = true;

        const offset = readU64At(data, entry_offset + 8) catch return error.Truncated;
        const len = readU64At(data, entry_offset + 16) catch return error.Truncated;
        const offset_usize = std.math.cast(usize, offset) orelse return error.SectionBounds;
        const len_usize = std.math.cast(usize, len) orelse return error.SectionBounds;
        const end = checkedAdd(offset_usize, len_usize) orelse return error.SectionBounds;
        if (offset_usize < section_table_end or end > data.len) return error.SectionBounds;
        sections[kind_index] = .{ .offset = offset_usize, .len = len_usize };
    }

    for (seen) |present| {
        if (!present) return error.MissingSection;
    }

    validateNoOverlap(sections) catch |err| return switch (err) {
        error.SectionBounds => error.SectionBounds,
        else => unreachable,
    };
    validateSectionSizes(sections) catch |err| return switch (err) {
        error.SectionSize => error.SectionSize,
        else => unreachable,
    };

    const strings_section = data[sections[sectionIndex(.strings)].offset .. sections[sectionIndex(.strings)].offset + sections[sectionIndex(.strings)].len];
    _ = resolveOptionalString(strings_section, revision) catch return error.InvalidHeader;
    if (revision.isNull() and revision.len != 0) return error.InvalidHeader;

    return .{
        .feature_bits = feature_bits,
        .revision = revision,
        .cookie = cookie,
        .sections = sections,
    };
}

fn validateNoOverlap(sections: [section_len]LayoutSection) error{SectionBounds}!void {
    for (sections, 0..) |left, left_index| {
        if (left.len == 0) continue;
        const left_end = left.offset + left.len;
        for (sections[left_index + 1 ..]) |right| {
            if (right.len == 0) continue;
            const right_end = right.offset + right.len;
            if (left.offset < right_end and right.offset < left_end) {
                return error.SectionBounds;
            }
        }
    }
}

fn validateSectionSizes(sections: [section_len]LayoutSection) error{SectionSize}!void {
    const sizes = [_]usize{
        1,
        diskRecordSize(),
        diskPackageSize(),
        diskRelationSize(),
        diskFileSize(),
        diskChangelogSize(),
        diskAdvisorySize(),
        diskAdvisoryReferenceSize(),
        diskAdvisoryPackageSize(),
    };

    for (sizes, 0..) |entry_size, index| {
        if (entry_size == 1) continue;
        if (sections[index].len % entry_size != 0) return error.SectionSize;
    }
}

fn validateSidecars(
    allocator: std.mem.Allocator,
    options: LoadOptions,
) !?InvalidReason {
    for (options.repomd.pRecords) |record| {
        const kind = parseRecordKind(record.dwKind) orelse return .bad_enum;
        switch (kind) {
            .primary, .filelists, .other, .updateinfo => {},
            else => continue,
        }

        const href = model.spanZ(record.pszLocationHref) orelse return .sidecar_unavailable;
        const sidecar_path = resolveSidecarPath(allocator, options.repo_root, href) catch return .sidecar_unavailable;
        defer allocator.free(sidecar_path);

        const sidecar_bytes = readFileAlloc(allocator, sidecar_path) catch return .sidecar_unavailable;
        defer allocator.free(sidecar_bytes);

        if (record.nHasSize != 0 and sidecar_bytes.len != record.nSize) {
            return .sidecar_size_mismatch;
        }

        if ((record.checksum.pszType != null or record.checksum.pszValue != null) and
            !digestMatches(record.checksum, sidecar_bytes))
        {
            return .sidecar_checksum_mismatch;
        }

        if (record.openChecksum.pszValue != null or record.nHasOpenSize != 0) {
            const open_bytes = decompressMetadata(allocator, href, sidecar_bytes) catch |err| return switch (err) {
                error.UnsupportedCompressor => .unsupported_compression,
                error.OutOfMemory => return error.OutOfMemory,
                else => .sidecar_open_checksum_mismatch,
            };
            defer allocator.free(open_bytes);

            if (record.nHasOpenSize != 0 and open_bytes.len != record.nOpenSize) {
                return .sidecar_open_size_mismatch;
            }
            if ((record.openChecksum.pszType != null or record.openChecksum.pszValue != null) and
                !digestMatches(record.openChecksum, open_bytes))
            {
                return .sidecar_open_checksum_mismatch;
            }
        }
    }

    return null;
}

fn digestMatches(checksum: model.Checksum, bytes: []const u8) bool {
    const checksum_type = model.spanZ(checksum.pszType) orelse return false;
    const expected = model.spanZ(checksum.pszValue) orelse return false;
    return switch (hashKind(checksum_type) orelse return false) {
        .md5 => blk: {
            var digest: [16]u8 = undefined;
            var hasher = std.crypto.hash.Md5.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
        .sha1 => blk: {
            var digest: [20]u8 = undefined;
            var hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
        .sha256 => blk: {
            var digest: [32]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
        .sha384 => blk: {
            var digest: [48]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha384.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
        .sha512 => blk: {
            var digest: [64]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha512.init(.{});
            hasher.update(bytes);
            hasher.final(&digest);
            const hex = std.fmt.bytesToHex(digest, .lower);
            break :blk std.ascii.eqlIgnoreCase(expected, &hex);
        },
    };
}

const HashKind = enum {
    md5,
    sha1,
    sha256,
    sha384,
    sha512,
};

fn hashKind(raw: []const u8) ?HashKind {
    if (std.ascii.eqlIgnoreCase(raw, "md5")) return .md5;
    if (std.ascii.eqlIgnoreCase(raw, "sha1")) return .sha1;
    if (std.ascii.eqlIgnoreCase(raw, "sha256")) return .sha256;
    if (std.ascii.eqlIgnoreCase(raw, "sha384")) return .sha384;
    if (std.ascii.eqlIgnoreCase(raw, "sha512")) return .sha512;
    return null;
}

const DecompressError = error{
    OutOfMemory,
    UnsupportedCompressor,
    DecompressFailed,
};

fn decompressMetadata(
    allocator: std.mem.Allocator,
    href: []const u8,
    bytes: []const u8,
) DecompressError![]u8 {
    var input = std.Io.Reader.fixed(bytes);

    if (std.mem.endsWith(u8, href, ".gz")) {
        var decoder: std.compress.flate.Decompress = .init(&input, .gzip, &.{});
        return decoder.reader.allocRemaining(allocator, .unlimited) catch error.DecompressFailed;
    }
    if (std.mem.endsWith(u8, href, ".zst") or std.mem.endsWith(u8, href, ".zstd")) {
        var decoder: std.compress.zstd.Decompress = .init(&input, &.{}, .{});
        return decoder.reader.allocRemaining(allocator, .unlimited) catch error.DecompressFailed;
    }
    if (std.mem.endsWith(u8, href, ".xz")) {
        const start_buf = allocator.alloc(u8, 0) catch return error.OutOfMemory;
        var decoder = std.compress.xz.Decompress.init(&input, allocator, start_buf) catch return error.DecompressFailed;
        return decoder.reader.allocRemaining(allocator, .unlimited) catch error.DecompressFailed;
    }

    const out = allocator.alloc(u8, bytes.len) catch return error.OutOfMemory;
    @memcpy(out, bytes);
    return out;
}

fn repositoryValidationReason(repository: *const model.RepositoryModel) ?InvalidReason {
    if (!containsRecordKind(repository.records, .primary)) return .invalid_header;
    if (repository.has_filelists != containsRecordKind(repository.records, .filelists)) return .invalid_header;
    if (repository.has_other != containsRecordKind(repository.records, .other)) return .invalid_header;
    if (repository.has_updateinfo != containsRecordKind(repository.records, .updateinfo)) return .invalid_header;

    if (!repository.has_filelists and repository.files.len != 0) return .invalid_header;
    if (!repository.has_other and repository.changelogs.len != 0) return .invalid_header;
    if (!repository.has_updateinfo and
        (repository.advisories.len != 0 or repository.advisory_references.len != 0 or repository.advisory_packages.len != 0))
    {
        return .invalid_header;
    }

    for (repository.packages) |pkg| {
        if (!rangeFits(pkg.provides.start, pkg.provides.len, repository.relations.len)) return .range_ref;
        if (!rangeFits(pkg.requires.start, pkg.requires.len, repository.relations.len)) return .range_ref;
        if (!rangeFits(pkg.conflicts.start, pkg.conflicts.len, repository.relations.len)) return .range_ref;
        if (!rangeFits(pkg.obsoletes.start, pkg.obsoletes.len, repository.relations.len)) return .range_ref;
        if (!rangeFits(pkg.recommends.start, pkg.recommends.len, repository.relations.len)) return .range_ref;
        if (!rangeFits(pkg.suggests.start, pkg.suggests.len, repository.relations.len)) return .range_ref;
        if (!rangeFits(pkg.supplements.start, pkg.supplements.len, repository.relations.len)) return .range_ref;
        if (!rangeFits(pkg.enhances.start, pkg.enhances.len, repository.relations.len)) return .range_ref;
        if (!rangeFits(pkg.files.start, pkg.files.len, repository.files.len)) return .range_ref;
        if (!rangeFits(pkg.changelogs.start, pkg.changelogs.len, repository.changelogs.len)) return .range_ref;
    }

    for (repository.advisories) |advisory| {
        if (!rangeFits(advisory.references.start, advisory.references.len, repository.advisory_references.len)) return .range_ref;
        if (!rangeFits(advisory.packages.start, advisory.packages.len, repository.advisory_packages.len)) return .range_ref;
    }

    return null;
}

fn computeFeatureBits(repository: model.RepositoryModel) u32 {
    var bits: u32 = 0;
    if (repository.has_filelists) bits |= feature_has_filelists;
    if (repository.has_other) bits |= feature_has_other;
    if (repository.has_updateinfo) bits |= feature_has_updateinfo;
    return bits;
}

fn containsRecordKind(records: []const model.Record, wanted: model.RecordKind) bool {
    for (records) |record| {
        if ((parseRecordKind(record.dwKind) orelse return false) == wanted) {
            return true;
        }
    }
    return false;
}

fn parseSectionKind(raw: u32) ?SectionKind {
    return switch (raw) {
        1 => .strings,
        2 => .repomd_records,
        3 => .packages,
        4 => .relations,
        5 => .files,
        6 => .changelogs,
        7 => .advisories,
        8 => .advisory_refs,
        9 => .advisory_pkgs,
        else => null,
    };
}

fn sectionIndex(kind: SectionKind) usize {
    return switch (kind) {
        .strings => 0,
        .repomd_records => 1,
        .packages => 2,
        .relations => 3,
        .files => 4,
        .changelogs => 5,
        .advisories => 6,
        .advisory_refs => 7,
        .advisory_pkgs => 8,
    };
}

fn parseRecordKind(raw: u32) ?model.RecordKind {
    return switch (raw) {
        0 => .unknown,
        1 => .primary,
        2 => .filelists,
        3 => .other,
        4 => .updateinfo,
        else => null,
    };
}

fn parseCompareOp(raw: u32) DecodeError!model.CompareOp {
    return switch (raw) {
        0 => .none,
        1 => .eq,
        2 => .lt,
        3 => .le,
        4 => .gt,
        5 => .ge,
        else => error.BadEnum,
    };
}

fn parseFileKind(raw: u32) DecodeError!model.FileKind {
    return switch (raw) {
        0 => .plain,
        1 => .dir,
        2 => .ghost,
        else => error.BadEnum,
    };
}

fn parseAdvisoryKind(raw: u32) DecodeError!model.AdvisoryKind {
    return switch (raw) {
        0 => .unknown,
        1 => .security,
        2 => .bugfix,
        3 => .enhancement,
        else => error.BadEnum,
    };
}

fn parseAdvisoryReferenceKind(raw: u32) DecodeError!model.AdvisoryReferenceKind {
    return switch (raw) {
        0 => .other,
        1 => .bugzilla,
        2 => .cve,
        3 => .vendor,
        else => error.BadEnum,
    };
}

fn resolveOptionalString(strings: []const u8, ref: StringRef) DecodeError!?[]const u8 {
    if (ref.isNull()) {
        if (ref.len != 0) return error.StringRef;
        return null;
    }

    const start: usize = ref.offset;
    const len: usize = ref.len;
    const end = checkedAdd(start, len) orelse return error.StringRef;
    if (end > strings.len) return error.StringRef;
    return strings[start..end];
}

fn resolveRequiredString(strings: []const u8, ref: StringRef) DecodeError![]const u8 {
    return try resolveOptionalString(strings, ref) orelse error.StringRef;
}

fn resolveOptionalZString(
    allocator: std.mem.Allocator,
    strings: []const u8,
    ref: StringRef,
) DecodeError!?[*:0]const u8 {
    const text = try resolveOptionalString(strings, ref) orelse return null;
    return (model.dupZ(allocator, text) catch return error.OutOfMemory).ptr;
}

fn checkedRange(ref: RangeRef, total: usize) DecodeError!RangeRef {
    const start: usize = ref.start;
    const len: usize = ref.len;
    const end = checkedAdd(start, len) orelse return error.RangeRef;
    if (end > total) return error.RangeRef;
    return ref;
}

fn rangeFits(start: usize, len: usize, total: usize) bool {
    const end = checkedAdd(start, len) orelse return false;
    return end <= total;
}

fn rangeToRelationRange(ref: RangeRef) model.RelationRange {
    return .{ .start = ref.start, .len = ref.len };
}

fn rangeToFileRange(ref: RangeRef) model.FileRange {
    return .{ .start = ref.start, .len = ref.len };
}

fn rangeToChangelogRange(ref: RangeRef) model.ChangelogRange {
    return .{ .start = ref.start, .len = ref.len };
}

fn rangeToAdvisoryReferenceRange(ref: RangeRef) model.AdvisoryReferenceRange {
    return .{ .start = ref.start, .len = ref.len };
}

fn rangeToAdvisoryPackageRange(ref: RangeRef) model.AdvisoryPackageRange {
    return .{ .start = ref.start, .len = ref.len };
}

fn relationRangeRef(range: model.RelationRange, total: usize) SerializeError!RangeRef {
    return checkedSerializeRange(range.start, range.len, total);
}

fn fileRangeRef(range: model.FileRange, total: usize) SerializeError!RangeRef {
    return checkedSerializeRange(range.start, range.len, total);
}

fn changelogRangeRef(range: model.ChangelogRange, total: usize) SerializeError!RangeRef {
    return checkedSerializeRange(range.start, range.len, total);
}

fn advisoryReferenceRangeRef(range: model.AdvisoryReferenceRange, total: usize) SerializeError!RangeRef {
    return checkedSerializeRange(range.start, range.len, total);
}

fn advisoryPackageRangeRef(range: model.AdvisoryPackageRange, total: usize) SerializeError!RangeRef {
    return checkedSerializeRange(range.start, range.len, total);
}

fn checkedSerializeRange(start: usize, len: usize, total: usize) SerializeError!RangeRef {
    if (!rangeFits(start, len, total)) return error.InvalidRepositoryModel;
    return .{
        .start = try toU32(start),
        .len = try toU32(len),
    };
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var io_state: std.Io.Threaded = .init(allocator, .{});
    defer io_state.deinit();
    return std.Io.Dir.cwd().readFileAlloc(
        io_state.io(),
        path,
        allocator,
        .limited(std.math.maxInt(usize)),
    );
}

fn resolveSidecarPath(allocator: std.mem.Allocator, repo_root: []const u8, href: []const u8) ![]u8 {
    if (std.mem.indexOf(u8, href, "://")) |_| {
        if (std.mem.startsWith(u8, href, "file://")) {
            return allocator.dupe(u8, href[7..]);
        }
        return error.UnsupportedLocation;
    }
    if (std.fs.path.isAbsolute(href)) {
        return allocator.dupe(u8, href);
    }
    return std.fs.path.join(allocator, &.{ repo_root, href });
}

fn sectionBytes(backing: []const u8, section: LayoutSection) []const u8 {
    return backing[section.offset .. section.offset + section.len];
}

fn mapLayoutError(err: ParseLayoutError) InvalidReason {
    return switch (err) {
        error.Truncated => .truncated,
        error.BadMagic => .bad_magic,
        error.VersionMismatch => .version_mismatch,
        error.InvalidHeader => .invalid_header,
        error.MissingSection => .missing_section,
        error.DuplicateSection => .duplicate_section,
        error.SectionBounds => .section_bounds,
        error.SectionSize => .section_size,
    };
}

fn mapDecodeError(err: DecodeError) InvalidReason {
    return switch (err) {
        error.Truncated => .truncated,
        error.StringRef => .string_ref,
        error.RangeRef => .range_ref,
        error.BadEnum => .bad_enum,
        error.OutOfMemory => unreachable,
    };
}

fn appendU16(out: *std.array_list.Managed(u8), value: anytype) SerializeError!void {
    const le = std.mem.nativeToLittle(u16, @intCast(value));
    out.appendSlice(std.mem.asBytes(&le)) catch return error.OutOfMemory;
}

fn appendU32(out: *std.array_list.Managed(u8), value: anytype) SerializeError!void {
    const le = std.mem.nativeToLittle(u32, @intCast(value));
    out.appendSlice(std.mem.asBytes(&le)) catch return error.OutOfMemory;
}

fn appendU64(out: *std.array_list.Managed(u8), value: anytype) SerializeError!void {
    const le = std.mem.nativeToLittle(u64, @intCast(value));
    out.appendSlice(std.mem.asBytes(&le)) catch return error.OutOfMemory;
}

fn appendStringRef(out: *std.array_list.Managed(u8), ref: StringRef) SerializeError!void {
    try appendU32(out, ref.offset);
    try appendU32(out, ref.len);
}

fn appendRangeRef(out: *std.array_list.Managed(u8), ref: RangeRef) SerializeError!void {
    try appendU32(out, ref.start);
    try appendU32(out, ref.len);
}

fn appendPaddingUntil(out: *std.array_list.Managed(u8), target_offset: usize) SerializeError!void {
    if (out.items.len > target_offset) return error.InvalidRepositoryModel;
    const zeros = [_]u8{0} ** 16;
    while (out.items.len < target_offset) {
        const remaining = target_offset - out.items.len;
        const take = @min(remaining, zeros.len);
        out.appendSlice(zeros[0..take]) catch return error.OutOfMemory;
    }
}

fn alignForward(value: usize, alignment: usize) usize {
    return (value + alignment - 1) & ~(alignment - 1);
}

fn checkedAdd(lhs: usize, rhs: usize) ?usize {
    return std.math.add(usize, lhs, rhs) catch null;
}

fn toU32(value: usize) SerializeError!u32 {
    return std.math.cast(u32, value) orelse error.Overflow;
}

fn readU16At(data: []const u8, offset: usize) ParseLayoutError!u16 {
    if (offset + @sizeOf(u16) > data.len) return error.Truncated;
    return std.mem.readInt(u16, data[offset..][0..@sizeOf(u16)], .little);
}

fn readU32At(data: []const u8, offset: usize) ParseLayoutError!u32 {
    if (offset + @sizeOf(u32) > data.len) return error.Truncated;
    return std.mem.readInt(u32, data[offset..][0..@sizeOf(u32)], .little);
}

fn readU64At(data: []const u8, offset: usize) ParseLayoutError!u64 {
    if (offset + @sizeOf(u64) > data.len) return error.Truncated;
    return std.mem.readInt(u64, data[offset..][0..@sizeOf(u64)], .little);
}

fn boolToCInt(value: bool) c_int {
    return if (value) 1 else 0;
}

fn diskRecordSize() usize {
    return 88;
}

fn diskPackageSize() usize {
    return 288;
}

fn diskRelationSize() usize {
    return 44;
}

fn diskFileSize() usize {
    return 12;
}

fn diskChangelogSize() usize {
    return 24;
}

fn diskAdvisorySize() usize {
    return 120;
}

fn diskAdvisoryReferenceSize() usize {
    return 36;
}

fn diskAdvisoryPackageSize() usize {
    return 72;
}

const fixture_primary_xml =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="3">
    \\  <package type="rpm">
    \\    <name>tdnf-repoquery-provides</name>
    \\    <arch>aarch64</arch>
    \\    <version epoch="0" ver="1.0.1" rel="2"/>
    \\    <checksum type="sha256" pkgid="YES">e880ac2df93fc378307bfb53dc719e5fb3e2cc903dadce7be8d35f776631ab8b</checksum>
    \\    <summary>Repoquery Test</summary>
    \\    <description>Part of tdnf test spec. For repoquery tests, this package will
    \\depend on tdnf-repoquery-base (or provide, ...)</description>
    \\    <packager></packager>
    \\    <url>http://www.vmware.com</url>
    \\    <time file="1783737155" build="1783737154"/>
    \\    <size package="6932" installed="0" archive="280"/>
    \\    <location xml:base="../pool" href="tdnf-repoquery-provides-1.0.1-2.aarch64.rpm"/>
    \\    <format>
    \\      <rpm:license>VMware</rpm:license>
    \\      <rpm:vendor>VMware, Inc.</rpm:vendor>
    \\      <rpm:group>Applications/tdnftest</rpm:group>
    \\      <rpm:buildhost>builder.example</rpm:buildhost>
    \\      <rpm:sourcerpm>tdnf-repoquery-provides-1.0.1-2.src.rpm</rpm:sourcerpm>
    \\      <rpm:header-range start="4504" end="6817"/>
    \\      <rpm:provides>
    \\        <rpm:entry name="tdnf-repoquery-base"/>
    \\        <rpm:entry name="tdnf-repoquery-provides" flags="EQ" epoch="0" ver="1.0.1" rel="2"/>
    \\      </rpm:provides>
    \\      <rpm:recommends>
    \\        <rpm:entry name="tdnf-repoquery-extra"/>
    \\      </rpm:recommends>
    \\    </format>
    \\  </package>
    \\  <package type="rpm">
    \\    <name>tdnf-test-pretrans-one</name>
    \\    <arch>aarch64</arch>
    \\    <version ver="1.0" rel="1"/>
    \\    <checksum type="sha256" pkgid="YES">172d8427a860f61302b59953e1c0b49b225317729adce64efa6d267b614fcde5</checksum>
    \\    <summary>Test Requires(pretrans) dependency</summary>
    \\    <description>Test Requires(pretrans) dependency</description>
    \\    <url>http://www.vmware.com</url>
    \\    <time file="1783737155" build="1783737154"/>
    \\    <size package="6305" installed="0" archive="124"/>
    \\    <location href="tdnf-test-pretrans-one-1.0-1.aarch64.rpm"/>
    \\    <format>
    \\      <rpm:license>VMware</rpm:license>
    \\      <rpm:vendor>VMware, Inc.</rpm:vendor>
    \\      <rpm:group>Applications/tdnftest</rpm:group>
    \\      <rpm:buildhost>builder.example</rpm:buildhost>
    \\      <rpm:sourcerpm>tdnf-test-pretrans-one-1.0-1.src.rpm</rpm:sourcerpm>
    \\      <rpm:header-range start="4504" end="6261"/>
    \\      <rpm:provides>
    \\        <rpm:entry name="tdnf-test-pretrans-one" flags="EQ" epoch="0" ver="1.0" rel="1"/>
    \\      </rpm:provides>
    \\      <rpm:requires>
    \\        <rpm:entry name="tdnf-dummy-pretrans" flags="GE" epoch="0" ver="1.0" rel="1" pre="1"/>
    \\        <rpm:entry name="/bin/sh"/>
    \\      </rpm:requires>
    \\      <rpm:obsoletes>
    \\        <rpm:entry name="tdnf-old-pretrans"/>
    \\      </rpm:obsoletes>
    \\    </format>
    \\  </package>
    \\  <package type="rpm">
    \\    <name>tdnf-repoquery-conflicts</name>
    \\    <arch>aarch64</arch>
    \\    <version epoch="0" ver="1.0.1" rel="2"/>
    \\    <checksum type="sha256" pkgid="YES">1b83046295a0688c767be25622daeafbbab26d73920d17ccbf72e0608662b056</checksum>
    \\    <summary>Repoquery Test</summary>
    \\    <description>Part of tdnf test spec. For repoquery tests, this package will
    \\depend on tdnf-repoquery-base (or provide, ...)</description>
    \\    <url>http://www.vmware.com</url>
    \\    <time file="1783737155" build="1783737154"/>
    \\    <size package="6984" installed="0" archive="280"/>
    \\    <location href="tdnf-repoquery-conflicts-1.0.1-2.aarch64.rpm"/>
    \\    <format>
    \\      <rpm:license>VMware</rpm:license>
    \\      <rpm:vendor>VMware, Inc.</rpm:vendor>
    \\      <rpm:group>Applications/tdnftest</rpm:group>
    \\      <rpm:buildhost>builder.example</rpm:buildhost>
    \\      <rpm:sourcerpm>tdnf-repoquery-conflicts-1.0.1-2.src.rpm</rpm:sourcerpm>
    \\      <rpm:header-range start="4504" end="6869"/>
    \\      <rpm:provides>
    \\        <rpm:entry name="tdnf-repoquery-conflicts" flags="EQ" epoch="0" ver="1.0.1" rel="2"/>
    \\      </rpm:provides>
    \\      <rpm:conflicts>
    \\        <rpm:entry name="tdnf-repoquery-base"/>
    \\      </rpm:conflicts>
    \\      <rpm:suggests>
    \\        <rpm:entry name="tdnf-repoquery-base"/>
    \\      </rpm:suggests>
    \\      <rpm:supplements>
    \\        <rpm:entry name="tdnf-repoquery-addon"/>
    \\      </rpm:supplements>
    \\      <rpm:enhances>
    \\        <rpm:entry name="tdnf-repoquery-enhanced"/>
    \\      </rpm:enhances>
    \\    </format>
    \\  </package>
    \\</metadata>
;

const fixture_filelists_xml =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="2">
    \\  <package pkgid="e880ac2df93fc378307bfb53dc719e5fb3e2cc903dadce7be8d35f776631ab8b" name="tdnf-repoquery-provides" arch="aarch64">
    \\    <version epoch="0" ver="1.0.1" rel="2"/>
    \\    <file>/usr/bin/tdnf-repoquery-provides</file>
    \\    <file type="dir">/usr/share/tdnf-repoquery-provides</file>
    \\    <file type="ghost">/var/lib/tdnf-repoquery-provides.cache</file>
    \\  </package>
    \\  <package pkgid="172d8427a860f61302b59953e1c0b49b225317729adce64efa6d267b614fcde5" name="tdnf-test-pretrans-one" arch="aarch64">
    \\    <version ver="1.0" rel="1"/>
    \\  </package>
    \\</filelists>
;

const fixture_other_xml =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<otherdata xmlns="http://linux.duke.edu/metadata/other" packages="2">
    \\  <package pkgid="e880ac2df93fc378307bfb53dc719e5fb3e2cc903dadce7be8d35f776631ab8b" name="tdnf-repoquery-provides" arch="aarch64">
    \\    <version epoch="0" ver="1.0.1" rel="2"/>
    \\    <changelog author="Jane Doe &lt;jane@example.com&gt;" date="1704067200">Initial release</changelog>
    \\    <changelog author="John Doe &lt;john@example.com&gt;" date="1704153600">Fix bug in repo sync</changelog>
    \\  </package>
    \\  <package pkgid="172d8427a860f61302b59953e1c0b49b225317729adce64efa6d267b614fcde5" name="tdnf-test-pretrans-one" arch="aarch64">
    \\    <version ver="1.0" rel="1"/>
    \\  </package>
    \\</otherdata>
;

const FixtureRepo = struct {
    arena_state: std.heap.ArenaAllocator,
    tmp: std.testing.TmpDir,
    parsed_repomd: model.ParsedRepoMd,
    repository: model.RepositoryModel,
    cookie: [cookie_len]u8,

    fn deinit(self: *FixtureRepo) void {
        self.tmp.cleanup();
        self.arena_state.deinit();
    }

    fn rootPath(self: *const FixtureRepo, buf: *[std.Io.Dir.max_path_bytes]u8) [:0]const u8 {
        return std.fmt.bufPrintZ(buf, ".zig-cache/tmp/{s}", .{&self.tmp.sub_path}) catch @panic("path too long");
    }

    fn path(self: *const FixtureRepo, buf: *[std.Io.Dir.max_path_bytes]u8, rel: []const u8) [:0]const u8 {
        return std.fmt.bufPrintZ(buf, ".zig-cache/tmp/{s}/{s}", .{ &self.tmp.sub_path, rel }) catch @panic("path too long");
    }
};

const SidecarSpec = struct {
    raw_type: []const u8,
    href: []const u8,
    data: []const u8,
    timestamp: u64,
};

fn createGoldenFixture() !FixtureRepo {
    const testing = std.testing;

    var fixture = FixtureRepo{
        .arena_state = std.heap.ArenaAllocator.init(testing.allocator),
        .tmp = std.testing.tmpDir(.{}),
        .parsed_repomd = .{},
        .repository = .{},
        .cookie = undefined,
    };
    errdefer fixture.tmp.cleanup();
    errdefer fixture.arena_state.deinit();

    const arena = fixture.arena_state.allocator();
    var repodata = try fixture.tmp.dir.createDirPathOpen(std.testing.io, "repodata", .{});
    defer repodata.close(std.testing.io);

    const updateinfo = try readFixture(arena, "pytests/repo/updateinfo-1.xml");
    try repodata.writeFile(std.testing.io, .{ .sub_path = "primary.xml", .data = fixture_primary_xml });
    try repodata.writeFile(std.testing.io, .{ .sub_path = "filelists.xml", .data = fixture_filelists_xml });
    try repodata.writeFile(std.testing.io, .{ .sub_path = "other.xml", .data = fixture_other_xml });
    try repodata.writeFile(std.testing.io, .{ .sub_path = "updateinfo-1.xml", .data = updateinfo });

    const sidecars = [_]SidecarSpec{
        .{ .raw_type = "primary", .href = "repodata/primary.xml", .data = fixture_primary_xml, .timestamp = 1729778159 },
        .{ .raw_type = "filelists", .href = "repodata/filelists.xml", .data = fixture_filelists_xml, .timestamp = 1729778160 },
        .{ .raw_type = "other", .href = "repodata/other.xml", .data = fixture_other_xml, .timestamp = 1729778161 },
        .{ .raw_type = "updateinfo-1", .href = "repodata/updateinfo-1.xml", .data = updateinfo, .timestamp = 1729778162 },
    };

    const repomd_text = try buildRepomdXml(arena, &sidecars);
    try fixture.tmp.dir.writeFile(std.testing.io, .{ .sub_path = "repomd.xml", .data = repomd_text });

    fixture.parsed_repomd = try repomd_xml.parse(arena, repomd_text);
    var parsed_primary = try primary_xml.parse(arena, fixture_primary_xml);
    try filelists_xml.parseAndApply(arena, fixture_filelists_xml, &parsed_primary);
    try other_xml.parseAndApply(arena, fixture_other_xml, &parsed_primary);
    const parsed_updateinfo = try updateinfo_xml.parse(arena, updateinfo);
    fixture.repository = model.repositoryModelFromParts(fixture.parsed_repomd, parsed_primary, parsed_updateinfo);

    var repomd_path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    fixture.cookie = try calculateCookieForFile(testing.allocator, fixture.path(&repomd_path_buf, "repomd.xml"));

    return fixture;
}

fn buildRepomdXml(allocator: std.mem.Allocator, sidecars: []const SidecarSpec) ![]const u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    defer out.deinit();

    try out.appendSlice(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<repomd xmlns="http://linux.duke.edu/metadata/repo">
        \\  <revision>1729778159</revision>
        \\
    );

    for (sidecars) |sidecar| {
        const checksum = try sha256HexDup(allocator, sidecar.data);
        const block = try std.fmt.allocPrint(allocator,
            \\  <data type="{s}">
            \\    <checksum type="sha256">{s}</checksum>
            \\    <open-checksum type="sha256">{s}</open-checksum>
            \\    <location href="{s}"/>
            \\    <timestamp>{d}</timestamp>
            \\    <size>{d}</size>
            \\    <open-size>{d}</open-size>
            \\  </data>
            \\
        , .{ sidecar.raw_type, checksum, checksum, sidecar.href, sidecar.timestamp, sidecar.data.len, sidecar.data.len });
        try out.appendSlice(block);
    }

    try out.appendSlice("</repomd>\n");
    return out.toOwnedSlice();
}

fn sha256HexDup(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    hasher.final(&digest);
    return allocator.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(std.math.maxInt(usize)),
    );
}

fn recordView(record: model.Record) struct {
    raw_type: ?[]const u8,
    kind: u32,
    location: ?[]const u8,
    checksum_type: ?[]const u8,
    checksum_value: ?[]const u8,
    open_checksum_type: ?[]const u8,
    open_checksum_value: ?[]const u8,
    timestamp: u64,
    size: u64,
    open_size: u64,
    database_version: u64,
    has_timestamp: c_int,
    has_size: c_int,
    has_open_size: c_int,
    has_database_version: c_int,
} {
    return .{
        .raw_type = model.spanZ(record.pszType),
        .kind = record.dwKind,
        .location = model.spanZ(record.pszLocationHref),
        .checksum_type = model.spanZ(record.checksum.pszType),
        .checksum_value = model.spanZ(record.checksum.pszValue),
        .open_checksum_type = model.spanZ(record.openChecksum.pszType),
        .open_checksum_value = model.spanZ(record.openChecksum.pszValue),
        .timestamp = record.nTimestamp,
        .size = record.nSize,
        .open_size = record.nOpenSize,
        .database_version = record.nDatabaseVersion,
        .has_timestamp = record.nHasTimestamp,
        .has_size = record.nHasSize,
        .has_open_size = record.nHasOpenSize,
        .has_database_version = record.nHasDatabaseVersion,
    };
}

fn expectRepositoryEqual(expected: *const model.RepositoryModel, actual: *const model.RepositoryModel) !void {
    const testing = std.testing;

    try testing.expectEqual(expected.has_filelists, actual.has_filelists);
    try testing.expectEqual(expected.has_other, actual.has_other);
    try testing.expectEqual(expected.has_updateinfo, actual.has_updateinfo);
    try testing.expectEqualDeep(model.spanZ(expected.pszRevision), model.spanZ(actual.pszRevision));
    try testing.expectEqual(expected.records.len, actual.records.len);
    for (expected.records, actual.records) |exp_record, act_record| {
        try testing.expectEqualDeep(recordView(exp_record), recordView(act_record));
    }
    try testing.expectEqualDeep(expected.packages, actual.packages);
    try testing.expectEqualDeep(expected.relations, actual.relations);
    try testing.expectEqualDeep(expected.files, actual.files);
    try testing.expectEqualDeep(expected.changelogs, actual.changelogs);
    try testing.expectEqualDeep(expected.advisories, actual.advisories);
    try testing.expectEqualDeep(expected.advisory_references, actual.advisory_references);
    try testing.expectEqualDeep(expected.advisory_packages, actual.advisory_packages);
}

fn expectMatchesLibsolv(fixture: *const FixtureRepo, repository: *const model.RepositoryModel) !void {
    const testing = std.testing;

    var repomd_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var primary_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var filelists_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var other_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var updateinfo_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;

    const pool = c.pool_create() orelse return error.OutOfMemory;
    defer c.pool_free(pool);
    const repo = c.repo_create(pool, "native-cache-golden") orelse return error.OutOfMemory;
    defer c.repo_free(repo, 1);

    try expectLibsolvOk(loadRepomd(repo, fixture.path(&repomd_buf, "repomd.xml")));
    try expectLibsolvOk(loadPrimary(repo, fixture.path(&primary_buf, "repodata/primary.xml")));
    try expectLibsolvOk(loadFilelists(repo, fixture.path(&filelists_buf, "repodata/filelists.xml")));
    try expectLibsolvOk(loadOther(repo, fixture.path(&other_buf, "repodata/other.xml")));
    try expectLibsolvOk(loadUpdateinfo(repo, fixture.path(&updateinfo_buf, "repodata/updateinfo-1.xml")));

    var package_count: usize = 0;
    var advisory_count: usize = 0;
    var found_provides = false;
    var found_pretrans = false;
    var found_advisory = false;

    var p: c.Id = repo.*.start;
    while (p < repo.*.end) : (p += 1) {
        const solvable = c.pool_id2solvable(pool, p);
        if (solvable == null) continue;
        const name = std.mem.span(c.pool_id2str(pool, solvable.*.name));
        if (std.mem.startsWith(u8, name, "patch:")) {
            advisory_count += 1;
            if (std.mem.eql(u8, name[6..], repository.advisories[0].id)) {
                found_advisory = true;
            }
            continue;
        }

        package_count += 1;
        if (std.mem.eql(u8, name, "tdnf-repoquery-provides")) {
            var checksum_type: c.Id = 0;
            const checksum = c.solvable_lookup_checksum(solvable, c.SOLVABLE_CHECKSUM, &checksum_type) orelse return error.TestExpectedEqual;
            try testing.expectEqualStrings(repository.packages[0].checksum.value, std.mem.span(checksum));
            try testing.expectEqualStrings(
                repository.packages[0].checksum.kind,
                libsolvChecksumKind(std.mem.span(c.pool_id2str(pool, checksum_type))),
            );
            try testing.expectEqualStrings(repository.packages[0].nevra.arch, std.mem.span(c.pool_id2str(pool, solvable.*.arch)));
            var provides: c.Queue = std.mem.zeroes(c.Queue);
            c.queue_init(&provides);
            defer c.queue_free(&provides);
            _ = c.solvable_lookup_deparray(solvable, c.SOLVABLE_PROVIDES, &provides, 0);
            try testing.expectEqual(@as(c_int, @intCast(repository.packages[0].relationsFor(.provides, repository.relations).len)), provides.count);
            found_provides = true;
        } else if (std.mem.eql(u8, name, "tdnf-test-pretrans-one")) {
            try testing.expectEqualStrings(repository.packages[1].nevra.arch, std.mem.span(c.pool_id2str(pool, solvable.*.arch)));
            found_pretrans = true;
        }
    }

    try testing.expectEqual(repository.packages.len, package_count);
    try testing.expectEqual(repository.advisories.len, advisory_count);
    try testing.expect(found_provides);
    try testing.expect(found_pretrans);
    try testing.expect(found_advisory);
}

fn expectLibsolvOk(rc: c_int) !void {
    try std.testing.expectEqual(@as(c_int, 0), rc);
}

fn libsolvChecksumKind(raw: []const u8) []const u8 {
    const index = std.mem.lastIndexOfScalar(u8, raw, ':') orelse return raw;
    return raw[index + 1 ..];
}

fn loadRepomd(repo: *c.Repo, path: [:0]const u8) c_int {
    const fp = c.fopen(path, "r") orelse return -1;
    defer _ = c.fclose(fp);
    return c.repo_add_repomdxml(repo, fp, 0);
}

fn loadPrimary(repo: *c.Repo, path: [:0]const u8) c_int {
    const fp = c.fopen(path, "r") orelse return -1;
    defer _ = c.fclose(fp);
    return c.repo_add_rpmmd(repo, fp, null, 0);
}

fn loadFilelists(repo: *c.Repo, path: [:0]const u8) c_int {
    const fp = c.fopen(path, "r") orelse return -1;
    defer _ = c.fclose(fp);
    return c.repo_add_rpmmd(repo, fp, "FL", c.REPO_EXTEND_SOLVABLES);
}

fn loadOther(repo: *c.Repo, path: [:0]const u8) c_int {
    const fp = c.fopen(path, "r") orelse return -1;
    defer _ = c.fclose(fp);
    return c.repo_add_rpmmd(repo, fp, null, c.REPO_EXTEND_SOLVABLES);
}

fn loadUpdateinfo(repo: *c.Repo, path: [:0]const u8) c_int {
    const fp = c.fopen(path, "r") orelse return -1;
    defer _ = c.fclose(fp);
    return c.repo_add_updateinfoxml(repo, fp, 0);
}

fn writeU16At(bytes: []u8, offset: usize, value: u16) void {
    const le = std.mem.nativeToLittle(u16, value);
    @memcpy(bytes[offset..][0..@sizeOf(u16)], std.mem.asBytes(&le));
}

fn writeU32At(bytes: []u8, offset: usize, value: u32) void {
    const le = std.mem.nativeToLittle(u32, value);
    @memcpy(bytes[offset..][0..@sizeOf(u32)], std.mem.asBytes(&le));
}

fn writeU64At(bytes: []u8, offset: usize, value: u64) void {
    const le = std.mem.nativeToLittle(u64, value);
    @memcpy(bytes[offset..][0..@sizeOf(u64)], std.mem.asBytes(&le));
}

fn expectInvalid(data: []const u8, options: LoadOptions, expected: InvalidReason) !void {
    switch (try deserialize(std.testing.allocator, data, options)) {
        .invalid => |reason| try std.testing.expectEqual(expected, reason),
        .loaded => |loaded| {
            var owned = loaded;
            defer owned.deinit();
            return error.TestUnexpectedResult;
        },
    }
}

test "native cache round-trips and matches libsolv golden fields" {
    const testing = std.testing;

    var fixture = try createGoldenFixture();
    defer fixture.deinit();

    const bytes = try serialize(testing.allocator, &fixture.repository, fixture.cookie);
    defer testing.allocator.free(bytes);

    try fixture.tmp.dir.writeFile(std.testing.io, .{ .sub_path = "native-cache.tdmd", .data = bytes });

    var cache_path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var root_path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const load_result = try loadFromFile(testing.allocator, fixture.path(&cache_path_buf, "native-cache.tdmd"), .{
        .cookie = fixture.cookie,
        .repo_root = fixture.rootPath(&root_path_buf),
        .repomd = &fixture.parsed_repomd,
    });

    switch (load_result) {
        .invalid => |reason| return std.debug.panic("unexpected invalid cache result: {s}", .{@tagName(reason)}),
        .loaded => |loaded| {
            var owned = loaded;
            defer owned.deinit();
            try expectRepositoryEqual(&fixture.repository, &owned.repository);
            try expectMatchesLibsolv(&fixture, &owned.repository);
            try testing.expectEqual(@as(usize, 3), owned.repository.packages.len);
            try testing.expectEqual(@as(usize, 1), owned.repository.advisories.len);
            try testing.expectEqualStrings("tdnf-repoquery-provides", owned.repository.packages[0].nevra.name);
            try testing.expectEqualStrings("e880ac2df93fc378307bfb53dc719e5fb3e2cc903dadce7be8d35f776631ab8b", owned.repository.packages[0].checksum.value);
            try testing.expectEqual(@as(usize, 2), owned.repository.packages[0].relationsFor(.provides, owned.repository.relations).len);
            try testing.expectEqualStrings("DISCUS-2015-5-01", owned.repository.advisories[0].id);
        },
    }
}

test "native cache gracefully rejects truncated wrong-magic version and cookie mismatches" {
    const testing = std.testing;

    var fixture = try createGoldenFixture();
    defer fixture.deinit();

    const bytes = try serialize(testing.allocator, &fixture.repository, fixture.cookie);
    defer testing.allocator.free(bytes);

    var root_path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const options = LoadOptions{
        .cookie = fixture.cookie,
        .repo_root = fixture.rootPath(&root_path_buf),
        .repomd = &fixture.parsed_repomd,
    };

    try expectInvalid(bytes[0 .. header_size + section_entry_size * section_len - 1], options, .truncated);

    var wrong_magic = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(wrong_magic);
    wrong_magic[0] = 'B';
    try expectInvalid(wrong_magic, options, .bad_magic);

    const wrong_version = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(wrong_version);
    writeU16At(wrong_version, header_version_offset, format_version + 1);
    try expectInvalid(wrong_version, options, .version_mismatch);

    var bad_cookie = fixture.cookie;
    bad_cookie[0] ^= 0xff;
    try expectInvalid(bytes, .{
        .cookie = bad_cookie,
        .repo_root = options.repo_root,
        .repomd = options.repomd,
    }, .cookie_mismatch);
}

test "native cache rejects corrupted section tables and sidecar checksum drift" {
    const testing = std.testing;

    var fixture = try createGoldenFixture();
    defer fixture.deinit();

    const bytes = try serialize(testing.allocator, &fixture.repository, fixture.cookie);
    defer testing.allocator.free(bytes);

    var root_path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const options = LoadOptions{
        .cookie = fixture.cookie,
        .repo_root = fixture.rootPath(&root_path_buf),
        .repomd = &fixture.parsed_repomd,
    };

    const bad_section = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(bad_section);
    writeU64At(bad_section, header_size + 16, std.math.maxInt(u64));
    try expectInvalid(bad_section, options, .section_bounds);

    var primary_path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const primary_path = fixture.path(&primary_path_buf, "repodata/primary.xml");
    const original_primary = try readFileAlloc(testing.allocator, primary_path);
    defer testing.allocator.free(original_primary);

    var mutated = try testing.allocator.dupe(u8, original_primary);
    defer testing.allocator.free(mutated);
    const needle = "Repoquery Test";
    const index = std.mem.indexOf(u8, mutated, needle) orelse return error.TestExpectedEqual;
    mutated[index] = 'X';
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = primary_path, .data = mutated });
    defer std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = primary_path, .data = original_primary }) catch {};

    try expectInvalid(bytes, options, .sidecar_checksum_mismatch);
}
