const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");
const rpm_header = @import("rpm_header");
const rpm_pkgfile = @import("rpm_pkgfile");

const rpmdb_test = if (builtin.is_test) @import("rpmdb_test") else struct {};
const sqlite = if (builtin.is_test) @import("sqlite") else struct {};

const dep_less: u32 = 1 << 1;
const dep_greater: u32 = 1 << 2;
const dep_equal: u32 = 1 << 3;
const dep_pre_in: u32 = (1 << 6) | (1 << 9) | (1 << 10);
const dep_pre_un: u32 = (1 << 6) | (1 << 11) | (1 << 12);
const dep_strong: u32 = 1 << 27;
const dep_compare_mask: u32 = dep_less | dep_greater | dep_equal;

const fileflag_ghost: u32 = 1 << 6;
const mode_mask: u16 = 0o170000;
const mode_dir: u16 = 0o040000;

pub const Error = error{
    InvalidRpmHeader,
    OutOfMemory,
};

pub const BuildOptions = struct {
    location: model.PackageLocation = .{},
    package_size: ?u64 = null,
    header_range: ?model.HeaderRange = null,
    include_relations: bool = true,
    include_files: bool = true,
    include_changelogs: bool = true,
};

pub const BuiltPackage = struct {
    package: model.Package,
    relations: []model.Relation = &[_]model.Relation{},
    files: []model.FileEntry = &[_]model.FileEntry{},
    changelogs: []model.ChangelogEntry = &[_]model.ChangelogEntry{},

    pub fn asParsedPrimary(
        self: BuiltPackage,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!model.ParsedPrimary {
        const packages = try allocator.alloc(model.Package, 1);
        packages[0] = self.package;
        return .{
            .declared_package_count = 1,
            .packages = packages,
            .relations = self.relations,
            .files = self.files,
            .changelogs = self.changelogs,
        };
    }
};

const RelationFlags = struct {
    text: ?[]const u8 = null,
    comparison: model.CompareOp = .none,
};

const ParsedEvr = struct {
    epoch: ?u32 = null,
    version: ?[]const u8 = null,
    release: ?[]const u8 = null,
};

const FallbackSpec = struct {
    name: rpm_header.TagId,
    version: rpm_header.TagId,
    flags: rpm_header.TagId,
    require_strong: ?bool = null,
};

const DependencySpec = struct {
    kind: model.DependencyKind,
    name: rpm_header.TagId,
    version: rpm_header.TagId,
    flags: rpm_header.TagId,
    fallback: ?FallbackSpec = null,
};

const ResolvedDependencySpec = struct {
    name: rpm_header.TagId,
    version: rpm_header.TagId,
    flags: rpm_header.TagId,
    require_strong: ?bool = null,
};

const dependency_specs = [_]DependencySpec{
    .{
        .kind = .provides,
        .name = .providename,
        .version = .provideversion,
        .flags = .provideflags,
    },
    .{
        .kind = .requires,
        .name = .requirename,
        .version = .requireversion,
        .flags = .requireflags,
    },
    .{
        .kind = .conflicts,
        .name = .conflictname,
        .version = .conflictversion,
        .flags = .conflictflags,
    },
    .{
        .kind = .obsoletes,
        .name = .obsoletename,
        .version = .obsoleteversion,
        .flags = .obsoleteflags,
    },
    .{
        .kind = .recommends,
        .name = .recommendname,
        .version = .recommendversion,
        .flags = .recommendflags,
        .fallback = .{
            .name = .oldsuggestsname,
            .version = .oldsuggestsversion,
            .flags = .oldsuggestsflags,
            .require_strong = true,
        },
    },
    .{
        .kind = .suggests,
        .name = .suggestname,
        .version = .suggestversion,
        .flags = .suggestflags,
        .fallback = .{
            .name = .oldsuggestsname,
            .version = .oldsuggestsversion,
            .flags = .oldsuggestsflags,
            .require_strong = false,
        },
    },
    .{
        .kind = .supplements,
        .name = .supplementname,
        .version = .supplementversion,
        .flags = .supplementflags,
        .fallback = .{
            .name = .oldenhancesname,
            .version = .oldenhancesversion,
            .flags = .oldenhancesflags,
            .require_strong = true,
        },
    },
    .{
        .kind = .enhances,
        .name = .enhancename,
        .version = .enhanceversion,
        .flags = .enhanceflags,
        .fallback = .{
            .name = .oldenhancesname,
            .version = .oldenhancesversion,
            .flags = .oldenhancesflags,
            .require_strong = false,
        },
    },
};

pub fn buildFromHeader(
    allocator: std.mem.Allocator,
    hdr: rpm_header.Header,
    options: BuildOptions,
) Error!BuiltPackage {
    var relations = std.array_list.Managed(model.Relation).init(allocator);
    errdefer relations.deinit();

    var files = std.array_list.Managed(model.FileEntry).init(allocator);
    errdefer files.deinit();

    var changelogs = std.array_list.Managed(model.ChangelogEntry).init(allocator);
    errdefer changelogs.deinit();

    var ranges: [dependency_specs.len]model.RelationRange = std.mem.zeroes([dependency_specs.len]model.RelationRange);
    if (options.include_relations) {
        inline for (dependency_specs, 0..) |spec, index| {
            ranges[index] = try appendRelations(allocator, hdr, spec, &relations);
        }
    }

    const file_range = if (options.include_files)
        try appendFiles(allocator, hdr, &files)
    else
        model.FileRange{};
    const changelog_range = if (options.include_changelogs)
        try appendChangelogs(allocator, hdr, &changelogs)
    else
        model.ChangelogRange{};
    const checksum = try buildChecksum(allocator, hdr);

    const package = model.Package{
        .pkg_id = checksum.value,
        .nevra = .{
            .name = try dupRequiredString(allocator, hdr, .name),
            .epoch = hdr.getU32(.epoch),
            .version = try dupRequiredString(allocator, hdr, .version),
            .release = try dupRequiredString(allocator, hdr, .release),
            .arch = try dupOptionalStringDefault(allocator, hdr.getString(.arch), ""),
        },
        .checksum = checksum,
        .summary = try dupOptionalString(allocator, hdr.getString(.summary)),
        .description = try dupOptionalString(allocator, hdr.getString(.description)),
        .packager = try dupOptionalString(allocator, hdr.getString(.packager)),
        .url = try dupOptionalString(allocator, hdr.getString(.url)),
        .time = .{
            .build = if (hdr.getU32(.build_time)) |value| value else null,
        },
        .size = .{
            .package = options.package_size,
            .installed = if (hdr.getU64(.longsize)) |value|
                value
            else if (hdr.getU32(.size)) |value|
                value
            else
                null,
            .archive = if (hdr.getU32(.archive_size)) |value| value else null,
        },
        .location = .{
            .href = try model.dup(allocator, options.location.href),
            .xml_base = if (options.location.xml_base) |value|
                try model.dup(allocator, value)
            else
                null,
        },
        .rpm = .{
            .license = try dupOptionalString(allocator, hdr.getString(.license)),
            .vendor = try dupOptionalString(allocator, hdr.getString(.vendor)),
            .group = try dupOptionalString(allocator, hdr.getString(.group)),
            .buildhost = try dupOptionalString(allocator, hdr.getString(.buildhost)),
            .source_rpm = try dupOptionalString(allocator, hdr.getString(.source_rpm)),
            .header_range = options.header_range,
        },
        .provides = rangeForKind(ranges, .provides),
        .requires = rangeForKind(ranges, .requires),
        .conflicts = rangeForKind(ranges, .conflicts),
        .obsoletes = rangeForKind(ranges, .obsoletes),
        .recommends = rangeForKind(ranges, .recommends),
        .suggests = rangeForKind(ranges, .suggests),
        .supplements = rangeForKind(ranges, .supplements),
        .enhances = rangeForKind(ranges, .enhances),
        .files = file_range,
        .changelogs = changelog_range,
    };

    const owned_relations = relations.toOwnedSlice() catch return error.OutOfMemory;
    errdefer allocator.free(owned_relations);

    const owned_files = files.toOwnedSlice() catch return error.OutOfMemory;
    errdefer allocator.free(owned_files);

    const owned_changelogs = changelogs.toOwnedSlice() catch return error.OutOfMemory;
    errdefer allocator.free(owned_changelogs);

    return .{
        .package = package,
        .relations = owned_relations,
        .files = owned_files,
        .changelogs = owned_changelogs,
    };
}

pub fn buildFromRpmFile(
    allocator: std.mem.Allocator,
    rpm: *const rpm_pkgfile.RpmFile,
    location_href: []const u8,
) Error!BuiltPackage {
    const header_end = rpm.payload_offset - 8;
    return buildFromHeader(allocator, rpm.main, .{
        .location = .{ .href = location_href },
        .package_size = rpm.bytes.len,
        .header_range = .{
            .start = rpm.main_header_offset,
            .end = header_end,
        },
    });
}

fn buildChecksum(
    allocator: std.mem.Allocator,
    hdr: rpm_header.Header,
) Error!model.PackageChecksum {
    if (hdr.getString(.sha1header)) |value| {
        if (value.len == 40) {
            return .{
                .kind = try model.dup(allocator, "sha1"),
                .value = try model.dup(allocator, value),
                .is_pkgid = true,
            };
        }
        if (value.len == 64) {
            return .{
                .kind = try model.dup(allocator, "sha256"),
                .value = try model.dup(allocator, value),
                .is_pkgid = true,
            };
        }
    }

    if (hdr.getString(.sha256header)) |value| {
        if (value.len == 64) {
            return .{
                .kind = try model.dup(allocator, "sha256"),
                .value = try model.dup(allocator, value),
                .is_pkgid = true,
            };
        }
    }

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(hdr.bytes, &digest, .{});
    return .{
        .kind = try model.dup(allocator, "sha256"),
        .value = try dupHexLower(allocator, &digest),
        .is_pkgid = true,
    };
}

fn appendRelations(
    allocator: std.mem.Allocator,
    hdr: rpm_header.Header,
    spec: DependencySpec,
    relations: *std.array_list.Managed(model.Relation),
) Error!model.RelationRange {
    const resolved = resolveDependencySpec(hdr, spec) orelse return .{};
    const count = hdr.stringArrayCount(resolved.name);
    if (count == 0) return .{};

    const version_entry = hdr.find(resolved.version) orelse return error.InvalidRpmHeader;
    const flags_entry = hdr.find(resolved.flags) orelse return error.InvalidRpmHeader;
    if (version_entry.count != count or flags_entry.count != count) {
        return error.InvalidRpmHeader;
    }

    var name_iter = (hdr.stringArrayIteratorChecked(resolved.name) catch
        return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
    var version_iter = (hdr.stringArrayIteratorChecked(resolved.version) catch
        return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;

    const start = relations.items.len;
    for (0..count) |index| {
        const name = (name_iter.next() catch
            return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
        const version = (version_iter.next() catch
            return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
        const raw_flags = hdr.u32ArrayItem(resolved.flags, index) orelse return error.InvalidRpmHeader;
        if (resolved.require_strong) |want_strong| {
            const is_strong = (raw_flags & dep_strong) != 0;
            if (is_strong != want_strong) {
                continue;
            }
        }

        if (name.len == 0) return error.InvalidRpmHeader;

        const flags = try decodeRelationFlags(raw_flags);
        const evr = try parseEvr(allocator, version);

        relations.append(.{
            .name = try model.dup(allocator, name),
            .flags = flags.text,
            .comparison = flags.comparison,
            .epoch = evr.epoch,
            .version = evr.version,
            .release = evr.release,
            .pre = spec.kind == .requires and (raw_flags & (dep_pre_in | dep_pre_un)) != 0,
            .sense = raw_flags,
        }) catch return error.OutOfMemory;
    }

    return .{
        .start = start,
        .len = relations.items.len - start,
    };
}

fn appendFiles(
    allocator: std.mem.Allocator,
    hdr: rpm_header.Header,
    files: *std.array_list.Managed(model.FileEntry),
) Error!model.FileRange {
    const basename_count = hdr.stringArrayCount(.basenames);
    if (basename_count == 0) return .{};

    const dirname_count = hdr.stringArrayCount(.dirnames);
    if (dirname_count == 0) return .{};

    const dirindex_entry = hdr.find(.dirindexes) orelse return .{};
    if (dirindex_entry.count != basename_count) return .{};

    const mode_count = if (hdr.find(.filemodes)) |entry|
        if (@as(rpm_header.TypeId, @enumFromInt(entry.typ)) == .int16) entry.count else 0
    else
        0;
    const flag_count = if (hdr.find(.fileflags)) |entry|
        if (@as(rpm_header.TypeId, @enumFromInt(entry.typ)) == .int32) entry.count else 0
    else
        0;

    const dirnames = allocator.alloc([]const u8, dirname_count) catch
        return error.OutOfMemory;
    defer allocator.free(dirnames);

    var dirname_iter = (hdr.stringArrayIteratorChecked(.dirnames) catch
        return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
    for (dirnames) |*dirname| {
        dirname.* = (dirname_iter.next() catch
            return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
    }

    var basename_iter = (hdr.stringArrayIteratorChecked(.basenames) catch
        return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;

    const start = files.items.len;
    for (0..basename_count) |index| {
        const dirname_index = hdr.u32ArrayItem(.dirindexes, index) orelse return error.InvalidRpmHeader;
        const basename_raw = (basename_iter.next() catch
            return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
        if (dirname_index >= dirname_count) continue;

        const dirname = dirnames[dirname_index];
        const basename = if (basename_raw.len != 0 and basename_raw[0] == '/') basename_raw[1..] else basename_raw;

        files.append(.{
            .path = try joinPath(allocator, dirname, basename),
            .kind = fileKindForIndex(hdr, index, mode_count, flag_count),
        }) catch return error.OutOfMemory;
    }

    return .{
        .start = start,
        .len = files.items.len - start,
    };
}

fn appendChangelogs(
    allocator: std.mem.Allocator,
    hdr: rpm_header.Header,
    changelogs: *std.array_list.Managed(model.ChangelogEntry),
) Error!model.ChangelogRange {
    const author_count = hdr.stringArrayCount(.changelogname);
    const text_count = hdr.stringArrayCount(.changelogtext);
    const time_entry = hdr.find(.changelogtime) orelse return .{};
    const time_count = time_entry.count;

    if (author_count == 0 or text_count == 0 or time_count == 0) return .{};
    if (author_count != text_count or author_count != time_count) return .{};

    var author_iter = (hdr.stringArrayIteratorChecked(.changelogname) catch
        return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
    var text_iter = (hdr.stringArrayIteratorChecked(.changelogtext) catch
        return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;

    const start = changelogs.items.len;
    for (0..author_count) |index| {
        const author = (author_iter.next() catch
            return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
        const text = (text_iter.next() catch
            return error.InvalidRpmHeader) orelse return error.InvalidRpmHeader;
        changelogs.append(.{
            .author = try model.dup(allocator, author),
            .timestamp = hdr.u32ArrayItem(.changelogtime, index) orelse return error.InvalidRpmHeader,
            .text = try model.dup(allocator, text),
        }) catch return error.OutOfMemory;
    }

    return .{
        .start = start,
        .len = changelogs.items.len - start,
    };
}

fn resolveDependencySpec(hdr: rpm_header.Header, spec: DependencySpec) ?ResolvedDependencySpec {
    if (hdr.stringArrayCount(spec.name) != 0) {
        return .{
            .name = spec.name,
            .version = spec.version,
            .flags = spec.flags,
        };
    }

    const fallback = spec.fallback orelse return null;
    if (hdr.stringArrayCount(fallback.name) == 0) return null;
    return .{
        .name = fallback.name,
        .version = fallback.version,
        .flags = fallback.flags,
        .require_strong = fallback.require_strong,
    };
}

fn decodeRelationFlags(raw_flags: u32) Error!RelationFlags {
    return switch (raw_flags & dep_compare_mask) {
        0 => .{},
        dep_equal => .{
            .text = "EQ",
            .comparison = .eq,
        },
        dep_less => .{
            .text = "LT",
            .comparison = .lt,
        },
        dep_less | dep_equal => .{
            .text = "LE",
            .comparison = .le,
        },
        dep_greater => .{
            .text = "GT",
            .comparison = .gt,
        },
        dep_greater | dep_equal => .{
            .text = "GE",
            .comparison = .ge,
        },
        else => error.InvalidRpmHeader,
    };
}

fn parseEvr(allocator: std.mem.Allocator, evr: []const u8) Error!ParsedEvr {
    if (evr.len == 0) return .{};

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

    if (body.len == 0) return .{ .epoch = epoch };

    if (std.mem.lastIndexOfScalar(u8, body, '-')) |separator| {
        if (separator != 0 and separator + 1 < body.len) {
            return .{
                .epoch = epoch,
                .version = try model.dup(allocator, body[0..separator]),
                .release = try model.dup(allocator, body[separator + 1 ..]),
            };
        }
    }

    return .{
        .epoch = epoch,
        .version = try model.dup(allocator, body),
    };
}

fn fileKindForIndex(
    hdr: rpm_header.Header,
    index: usize,
    mode_count: u32,
    flag_count: u32,
) model.FileKind {
    if (index < flagCountToUsize(flag_count)) {
        if (hdr.u32ArrayItem(.fileflags, index)) |flags| {
            if ((flags & fileflag_ghost) != 0) return .ghost;
        }
    }

    if (index < flagCountToUsize(mode_count)) {
        if (hdr.u16ArrayItem(.filemodes, index)) |mode| {
            if ((mode & mode_mask) == mode_dir) return .dir;
        }
    }

    return .plain;
}

fn joinPath(allocator: std.mem.Allocator, dirname: []const u8, basename: []const u8) Error![]const u8 {
    if (dirname.len == 0) {
        return model.dup(allocator, basename) catch error.OutOfMemory;
    }
    if (basename.len == 0) {
        return model.dup(allocator, dirname) catch error.OutOfMemory;
    }
    return std.mem.concat(allocator, u8, &.{ dirname, basename }) catch error.OutOfMemory;
}

fn rangeForKind(
    ranges: [dependency_specs.len]model.RelationRange,
    kind: model.DependencyKind,
) model.RelationRange {
    inline for (dependency_specs, 0..) |spec, index| {
        if (spec.kind == kind) return ranges[index];
    }
    return .{};
}

fn dupRequiredString(
    allocator: std.mem.Allocator,
    hdr: rpm_header.Header,
    tag: rpm_header.TagId,
) Error![]const u8 {
    const value = hdr.getString(tag) orelse return error.InvalidRpmHeader;
    if (value.len == 0) return error.InvalidRpmHeader;
    return model.dup(allocator, value) catch error.OutOfMemory;
}

fn dupOptionalStringDefault(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
    default_value: []const u8,
) Error![]const u8 {
    if (value) |text| {
        return model.dup(allocator, text) catch error.OutOfMemory;
    }
    return model.dup(allocator, default_value) catch error.OutOfMemory;
}

fn dupOptionalString(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) Error!?[]const u8 {
    const text = value orelse return null;
    if (text.len == 0) return null;
    return model.dup(allocator, text) catch error.OutOfMemory;
}

fn dupHexLower(allocator: std.mem.Allocator, bytes: []const u8) Error![]const u8 {
    const out = allocator.alloc(u8, bytes.len * 2) catch return error.OutOfMemory;
    for (bytes, 0..) |byte, index| {
        out[index * 2] = hexDigit(byte >> 4);
        out[index * 2 + 1] = hexDigit(byte & 0x0f);
    }
    return out;
}

fn hexDigit(value: u8) u8 {
    return if (value < 10) '0' + value else 'a' + (value - 10);
}

fn flagCountToUsize(count: u32) usize {
    return @intCast(count);
}

const TestEntryType = enum(u32) {
    int16 = 3,
    int32 = 4,
    int64 = 5,
    string = 6,
    bin = 7,
    string_array = 8,
    i18n_string = 9,
};

const TestHeaderEntry = union(enum) {
    string: struct {
        tag: u32,
        value: []const u8,
        typ: TestEntryType = .string,
    },
    string_array: struct {
        tag: u32,
        values: []const []const u8,
        typ: TestEntryType = .string_array,
    },
    int32: struct {
        tag: u32,
        value: u32,
    },
    int32_array: struct {
        tag: u32,
        values: []const u32,
    },
    int64: struct {
        tag: u32,
        value: u64,
    },
    int16_array: struct {
        tag: u32,
        values: []const u16,
    },
    bin: struct {
        tag: u32,
        value: []const u8,
    },
};

fn buildHeaderBlob(
    allocator: std.mem.Allocator,
    entries: []const TestHeaderEntry,
) ![]u8 {
    var data = std.array_list.Managed(u8).init(allocator);
    defer data.deinit();

    var index = std.array_list.Managed(u8).init(allocator);
    defer index.deinit();

    for (entries) |entry| {
        const alignment: usize = switch (entry) {
            .int16_array => 2,
            .int32, .int32_array => 4,
            .int64 => 8,
            else => 1,
        };
        while (data.items.len % alignment != 0) {
            try data.append(0);
        }
        const offset: u32 = @intCast(data.items.len);
        var tag: u32 = 0;
        var typ: TestEntryType = .string;
        var count: u32 = 0;

        switch (entry) {
            .string => |value| {
                tag = value.tag;
                typ = value.typ;
                count = 1;
                try data.appendSlice(value.value);
                try data.append(0);
            },
            .string_array => |value| {
                tag = value.tag;
                typ = value.typ;
                count = @intCast(value.values.len);
                for (value.values) |item| {
                    try data.appendSlice(item);
                    try data.append(0);
                }
            },
            .int32 => |value| {
                tag = value.tag;
                typ = .int32;
                count = 1;
                try appendBeU32(&data, value.value);
            },
            .int32_array => |value| {
                tag = value.tag;
                typ = .int32;
                count = @intCast(value.values.len);
                for (value.values) |item| {
                    try appendBeU32(&data, item);
                }
            },
            .int64 => |value| {
                tag = value.tag;
                typ = .int64;
                count = 1;
                try appendBeU64(&data, value.value);
            },
            .int16_array => |value| {
                tag = value.tag;
                typ = .int16;
                count = @intCast(value.values.len);
                for (value.values) |item| {
                    try appendBeU16(&data, item);
                }
            },
            .bin => |value| {
                tag = value.tag;
                typ = .bin;
                count = @intCast(value.value.len);
                try data.appendSlice(value.value);
            },
        }

        try appendBeU32(&index, tag);
        try appendBeU32(&index, @intFromEnum(typ));
        try appendBeU32(&index, offset);
        try appendBeU32(&index, count);
    }

    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    try appendBeU32(&out, @intCast(entries.len));
    try appendBeU32(&out, @intCast(data.items.len));
    try out.appendSlice(index.items);
    try out.appendSlice(data.items);
    return out.toOwnedSlice();
}

fn buildStandaloneHeader(
    allocator: std.mem.Allocator,
    header_blob: []const u8,
    region_tag: rpm_header.RegionTag,
) ![]u8 {
    const magic = [_]u8{ 0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const index_count = readBeU32(header_blob[0..4]);
    const data_size = readBeU32(header_blob[4..8]);
    const new_index_count = index_count + 1;
    const new_data_size = data_size + 16;
    const raw_len = 8 + @as(usize, new_index_count) * 16 + new_data_size;
    const standalone = try allocator.alloc(u8, magic.len + raw_len);
    @memcpy(standalone[0..magic.len], &magic);

    const raw = standalone[magic.len..];
    writeBeU32(raw[0..4], new_index_count);
    writeBeU32(raw[4..8], new_data_size);
    writeBeU32(raw[8..12], @intFromEnum(region_tag));
    writeBeU32(raw[12..16], @intFromEnum(rpm_header.TypeId.bin));
    writeBeU32(raw[16..20], data_size);
    writeBeU32(raw[20..24], 16);

    const old_index_len = @as(usize, index_count) * 16;
    @memcpy(raw[24 .. 24 + old_index_len], header_blob[8 .. 8 + old_index_len]);
    const data_start = 8 + @as(usize, new_index_count) * 16;
    @memcpy(
        raw[data_start .. data_start + data_size],
        header_blob[8 + old_index_len ..][0..data_size],
    );
    const trailer = raw[data_start + data_size ..][0..16];
    writeBeU32(trailer[0..4], @intFromEnum(region_tag));
    writeBeU32(trailer[4..8], @intFromEnum(rpm_header.TypeId.bin));
    writeBeU32(
        trailer[8..12],
        @bitCast(-@as(i32, @intCast(new_index_count * 16))),
    );
    writeBeU32(trailer[12..16], 16);
    return standalone;
}

fn buildMinimalRpmBytes(
    allocator: std.mem.Allocator,
    main_header_blob: []const u8,
) ![]u8 {
    const sig_header_blob = try buildHeaderBlob(allocator, &.{
        .{ .int32 = .{
            .tag = @intFromEnum(rpm_header.SigTagId.size),
            .value = 0,
        } },
    });
    defer allocator.free(sig_header_blob);

    const sig_standalone = try buildStandaloneHeader(
        allocator,
        sig_header_blob,
        .signatures,
    );
    defer allocator.free(sig_standalone);

    const main_standalone = try buildStandaloneHeader(
        allocator,
        main_header_blob,
        .immutable,
    );
    defer allocator.free(main_standalone);

    const sig_pad = (8 - (sig_standalone.len % 8)) % 8;
    const total = 96 + sig_standalone.len + sig_pad + main_standalone.len;
    const bytes = try allocator.alloc(u8, total);
    @memset(bytes, 0);
    bytes[0] = 0xed;
    bytes[1] = 0xab;
    bytes[2] = 0xee;
    bytes[3] = 0xdb;

    @memcpy(bytes[96 .. 96 + sig_standalone.len], sig_standalone);
    @memcpy(
        bytes[96 + sig_standalone.len + sig_pad .. 96 + sig_standalone.len + sig_pad + main_standalone.len],
        main_standalone,
    );
    return bytes;
}

fn appendBeU16(list: *std.array_list.Managed(u8), value: u16) !void {
    try list.append(@intCast((value >> 8) & 0xff));
    try list.append(@intCast(value & 0xff));
}

fn readBeU32(bytes: []const u8) u32 {
    return @as(u32, bytes[0]) << 24 |
        @as(u32, bytes[1]) << 16 |
        @as(u32, bytes[2]) << 8 |
        @as(u32, bytes[3]);
}

fn writeBeU32(bytes: []u8, value: u32) void {
    bytes[0] = @intCast((value >> 24) & 0xff);
    bytes[1] = @intCast((value >> 16) & 0xff);
    bytes[2] = @intCast((value >> 8) & 0xff);
    bytes[3] = @intCast(value & 0xff);
}

fn appendBeU32(list: *std.array_list.Managed(u8), value: u32) !void {
    try list.append(@intCast((value >> 24) & 0xff));
    try list.append(@intCast((value >> 16) & 0xff));
    try list.append(@intCast((value >> 8) & 0xff));
    try list.append(@intCast(value & 0xff));
}

fn appendBeU64(list: *std.array_list.Managed(u8), value: u64) !void {
    try list.append(@intCast((value >> 56) & 0xff));
    try list.append(@intCast((value >> 48) & 0xff));
    try list.append(@intCast((value >> 40) & 0xff));
    try list.append(@intCast((value >> 32) & 0xff));
    try list.append(@intCast((value >> 24) & 0xff));
    try list.append(@intCast((value >> 16) & 0xff));
    try list.append(@intCast((value >> 8) & 0xff));
    try list.append(@intCast(value & 0xff));
}

pub fn makeMinimalTransactionHeaderForTest(
    allocator: std.mem.Allocator,
) ![]u8 {
    const header_blob = try buildHeaderBlob(allocator, &.{
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.name), .value = "verified-package" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.version), .value = "1.0" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.release), .value = "1" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.arch), .value = "noarch" } },
    });
    defer allocator.free(header_blob);
    const standalone = try buildStandaloneHeader(
        allocator,
        header_blob,
        .immutable,
    );
    defer allocator.free(standalone);
    return allocator.dupe(u8, standalone[8..]);
}

test "builds package from rpm header tags" {
    const testing = std.testing;

    const provides_values = [_][]const u8{ "pkg-one", "/usr/bin/pkg-one" };
    const requires_values = [_][]const u8{ "dep-one", "dep-two" };
    const basename_values = [_][]const u8{ "pkg-one", "pkg-one.conf", "ghost-file" };
    const dirname_values = [_][]const u8{ "/usr/bin/", "/etc/", "/var/lib/" };
    const changelog_authors = [_][]const u8{ "Alice", "Bob" };
    const changelog_texts = [_][]const u8{ "Initial build", "Fixes" };

    const header_blob = try buildHeaderBlob(testing.allocator, &.{
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.name), .value = "pkg-one" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.version), .value = "2.3.4" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.release), .value = "5" } },
        .{ .int32 = .{ .tag = @intFromEnum(rpm_header.TagId.epoch), .value = 7 } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.arch), .value = "x86_64" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.summary), .value = "Package one" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.description), .value = "Package one description" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.packager), .value = "Pkg Builder" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.url), .value = "https://example.test/pkg-one" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.vendor), .value = "Example Co" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.license), .value = "MIT" } },
        .{ .string = .{
            .tag = @intFromEnum(rpm_header.TagId.group),
            .value = "Applications/System",
            .typ = .i18n_string,
        } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.buildhost), .value = "builder.example" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.source_rpm), .value = "pkg-one-2.3.4-5.src.rpm" } },
        .{ .int32 = .{ .tag = @intFromEnum(rpm_header.TagId.build_time), .value = 1234567890 } },
        .{ .int64 = .{ .tag = @intFromEnum(rpm_header.TagId.longsize), .value = 9876543210 } },
        .{ .int32 = .{ .tag = @intFromEnum(rpm_header.TagId.archive_size), .value = 4321 } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.sha1header), .value = "0123456789abcdef0123456789abcdef01234567" } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.providename), .values = &provides_values } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.provideversion), .values = &[_][]const u8{ "7:2.3.4-5", "" } } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.provideflags), .values = &[_]u32{ dep_equal, 0 } } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.requirename), .values = &requires_values } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.requireversion), .values = &[_][]const u8{ "1:1.0-2", "0:3.1" } } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.requireflags), .values = &[_]u32{ dep_greater | dep_equal | dep_pre_in, dep_less } } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.conflictname), .values = &[_][]const u8{"old-pkg"} } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.conflictversion), .values = &[_][]const u8{"4.0-1"} } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.conflictflags), .values = &[_]u32{dep_less} } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.obsoletename), .values = &[_][]const u8{"older-pkg"} } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.obsoleteversion), .values = &[_][]const u8{""} } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.obsoleteflags), .values = &[_]u32{0} } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.oldsuggestsname), .values = &[_][]const u8{ "strong-addon", "weak-addon" } } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.oldsuggestsversion), .values = &[_][]const u8{ "", "" } } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.oldsuggestsflags), .values = &[_]u32{ dep_strong, 0 } } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.oldenhancesname), .values = &[_][]const u8{ "strong-extra", "weak-extra" } } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.oldenhancesversion), .values = &[_][]const u8{ "", "" } } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.oldenhancesflags), .values = &[_]u32{ dep_strong, 0 } } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.basenames), .values = &basename_values } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.dirnames), .values = &dirname_values } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.dirindexes), .values = &[_]u32{ 0, 1, 2 } } },
        .{ .int16_array = .{ .tag = @intFromEnum(rpm_header.TagId.filemodes), .values = &[_]u16{ 0o100755, 0o100644, 0o040755 } } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.fileflags), .values = &[_]u32{ 0, 0, fileflag_ghost } } },
        .{ .int32_array = .{ .tag = @intFromEnum(rpm_header.TagId.changelogtime), .values = &[_]u32{ 100, 200 } } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.changelogname), .values = &changelog_authors } },
        .{ .string_array = .{ .tag = @intFromEnum(rpm_header.TagId.changelogtext), .values = &changelog_texts } },
    });
    defer testing.allocator.free(header_blob);

    const hdr = try rpm_header.Header.parse(header_blob);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const built = try buildFromHeader(arena_state.allocator(), hdr, .{});
    try testing.expectEqualStrings("pkg-one", built.package.nevra.name);
    try testing.expectEqual(@as(?u32, 7), built.package.nevra.epoch);
    try testing.expectEqualStrings("2.3.4", built.package.nevra.version);
    try testing.expectEqualStrings("5", built.package.nevra.release);
    try testing.expectEqualStrings("x86_64", built.package.nevra.arch);
    try testing.expectEqualStrings("sha1", built.package.checksum.kind);
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef01234567", built.package.checksum.value);
    try testing.expect(built.package.checksum.is_pkgid);
    try testing.expectEqualStrings(built.package.pkg_id, built.package.checksum.value);
    try testing.expectEqual(@as(?u64, 1234567890), built.package.time.build);
    try testing.expectEqual(@as(?u64, 9876543210), built.package.size.installed);
    try testing.expectEqual(@as(?u64, 4321), built.package.size.archive);
    try testing.expectEqual(@as(?u64, null), built.package.size.package);
    try testing.expectEqualStrings("", built.package.location.href);
    try testing.expectEqualStrings("Package one", built.package.summary.?);
    try testing.expectEqualStrings("Package one description", built.package.description.?);
    try testing.expectEqualStrings("Pkg Builder", built.package.packager.?);
    try testing.expectEqualStrings("https://example.test/pkg-one", built.package.url.?);
    try testing.expectEqualStrings("MIT", built.package.rpm.license.?);
    try testing.expectEqualStrings("Example Co", built.package.rpm.vendor.?);
    try testing.expectEqualStrings("Applications/System", built.package.rpm.group.?);
    try testing.expectEqualStrings("builder.example", built.package.rpm.buildhost.?);
    try testing.expectEqualStrings("pkg-one-2.3.4-5.src.rpm", built.package.rpm.source_rpm.?);

    const provides = built.package.relationsFor(.provides, built.relations);
    try testing.expectEqual(@as(usize, 2), provides.len);
    try testing.expectEqualStrings("pkg-one", provides[0].name);
    try testing.expectEqualStrings("EQ", provides[0].flags.?);
    try testing.expectEqual(model.CompareOp.eq, provides[0].comparison);
    try testing.expectEqual(@as(?u32, 7), provides[0].epoch);
    try testing.expectEqualStrings("2.3.4", provides[0].version.?);
    try testing.expectEqualStrings("5", provides[0].release.?);
    try testing.expectEqualStrings("/usr/bin/pkg-one", provides[1].name);
    try testing.expect(provides[1].flags == null);

    const requires = built.package.relationsFor(.requires, built.relations);
    try testing.expectEqual(@as(usize, 2), requires.len);
    try testing.expectEqualStrings("dep-one", requires[0].name);
    try testing.expectEqualStrings("GE", requires[0].flags.?);
    try testing.expectEqual(model.CompareOp.ge, requires[0].comparison);
    try testing.expectEqual(@as(?u32, 1), requires[0].epoch);
    try testing.expectEqualStrings("1.0", requires[0].version.?);
    try testing.expectEqualStrings("2", requires[0].release.?);
    try testing.expect(requires[0].pre);
    try testing.expectEqual(dep_greater | dep_equal | dep_pre_in, requires[0].sense);
    try testing.expectEqualStrings("dep-two", requires[1].name);
    try testing.expectEqualStrings("LT", requires[1].flags.?);
    try testing.expectEqual(model.CompareOp.lt, requires[1].comparison);
    try testing.expectEqual(@as(?u32, 0), requires[1].epoch);
    try testing.expectEqualStrings("3.1", requires[1].version.?);
    try testing.expect(requires[1].release == null);
    try testing.expect(!requires[1].pre);
    try testing.expectEqual(dep_less, requires[1].sense);

    try testing.expectEqual(@as(usize, 1), built.package.relationsFor(.recommends, built.relations).len);
    try testing.expectEqualStrings("strong-addon", built.package.relationsFor(.recommends, built.relations)[0].name);
    try testing.expectEqual(@as(usize, 1), built.package.relationsFor(.suggests, built.relations).len);
    try testing.expectEqualStrings("weak-addon", built.package.relationsFor(.suggests, built.relations)[0].name);
    try testing.expectEqual(@as(usize, 1), built.package.relationsFor(.supplements, built.relations).len);
    try testing.expectEqualStrings("strong-extra", built.package.relationsFor(.supplements, built.relations)[0].name);
    try testing.expectEqual(@as(usize, 1), built.package.relationsFor(.enhances, built.relations).len);
    try testing.expectEqualStrings("weak-extra", built.package.relationsFor(.enhances, built.relations)[0].name);

    const files = built.package.fileEntries(built.files);
    try testing.expectEqual(@as(usize, 3), files.len);
    try testing.expectEqualStrings("/usr/bin/pkg-one", files[0].path);
    try testing.expectEqual(model.FileKind.plain, files[0].kind);
    try testing.expectEqualStrings("/etc/pkg-one.conf", files[1].path);
    try testing.expectEqual(model.FileKind.plain, files[1].kind);
    try testing.expectEqualStrings("/var/lib/ghost-file", files[2].path);
    try testing.expectEqual(model.FileKind.ghost, files[2].kind);

    const changelogs = built.package.changelogEntries(built.changelogs);
    try testing.expectEqual(@as(usize, 2), changelogs.len);
    try testing.expectEqualStrings("Alice", changelogs[0].author);
    try testing.expectEqual(@as(u64, 100), changelogs[0].timestamp);
    try testing.expectEqualStrings("Initial build", changelogs[0].text);
}

test "builds packages from rpm file and rpmdb iterator" {
    const testing = std.testing;

    const header_blob = try buildHeaderBlob(testing.allocator, &.{
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.name), .value = "pkg-two" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.version), .value = "1.0" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.release), .value = "2" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.arch), .value = "noarch" } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.summary), .value = "Package two" } },
        .{ .int32 = .{ .tag = @intFromEnum(rpm_header.TagId.size), .value = 1234 } },
        .{ .string = .{ .tag = @intFromEnum(rpm_header.TagId.sha256header), .value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
    });
    defer testing.allocator.free(header_blob);

    const rpm_bytes = try buildMinimalRpmBytes(testing.allocator, header_blob);
    var rpm_file = rpm_pkgfile.RpmFile.parseBytes(rpm_bytes) catch |err| {
        testing.allocator.free(rpm_bytes);
        return err;
    };
    defer rpm_file.close(testing.allocator);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const from_file = try buildFromRpmFile(arena_state.allocator(), &rpm_file, "local/pkg-two-1.0-2.noarch.rpm");
    try testing.expectEqualStrings("pkg-two", from_file.package.nevra.name);
    try testing.expectEqual(@as(?u32, null), from_file.package.nevra.epoch);
    try testing.expectEqualStrings("sha256", from_file.package.checksum.kind);
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", from_file.package.checksum.value);
    try testing.expectEqualStrings("local/pkg-two-1.0-2.noarch.rpm", from_file.package.location.href);
    try testing.expectEqual(@as(?u64, 1234), from_file.package.size.installed);
    try testing.expectEqual(@as(?u64, rpm_bytes.len), from_file.package.size.package);
    try testing.expectEqual(@as(u64, rpm_file.main_header_offset), from_file.package.rpm.header_range.?.start);
    try testing.expectEqual(@as(u64, rpm_file.payload_offset - 8), from_file.package.rpm.header_range.?.end);
    try testing.expectEqual(@as(usize, 0), from_file.package.relationsFor(.provides, from_file.relations).len);
    try testing.expectEqual(@as(usize, 0), from_file.package.relationsFor(.requires, from_file.relations).len);

    const db_path = "rpmpkg-test-rpmdb.sqlite";
    std.Io.Dir.cwd().deleteFile(std.testing.io, db_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, db_path) catch {};

    const db = try sqlite.Database.open(.{ .path = db_path });
    defer db.close();

    try db.exec(
        \\CREATE TABLE Packages (
        \\    hnum INTEGER PRIMARY KEY,
        \\    blob BLOB NOT NULL
        \\)
    , .{});

    const blob_hex = try dupHexLower(arena_state.allocator(), header_blob);
    const insert_sql = try std.fmt.allocPrint(
        arena_state.allocator(),
        "INSERT INTO Packages (hnum, blob) VALUES (1, x'{s}')",
        .{blob_hex},
    );
    try db.exec(insert_sql, .{});

    const iter = try rpmdb_test.Iter.openAtPath(db_path);
    defer iter.close();

    const rpmdb_header = (try iter.nextHeader()) orelse return error.TestExpectedEqual;
    const from_rpmdb = try buildFromHeader(arena_state.allocator(), rpmdb_header, .{});
    try testing.expectEqualStrings("pkg-two", from_rpmdb.package.nevra.name);
    try testing.expectEqual(@as(?u32, null), from_rpmdb.package.nevra.epoch);
    try testing.expectEqualStrings("sha256", from_rpmdb.package.checksum.kind);
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", from_rpmdb.package.checksum.value);
    try testing.expectEqualStrings("", from_rpmdb.package.location.href);
    try testing.expectEqual(@as(usize, 0), from_rpmdb.package.relationsFor(.provides, from_rpmdb.relations).len);
    try testing.expectEqual(@as(usize, 0), from_rpmdb.package.relationsFor(.requires, from_rpmdb.relations).len);
}
