const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");
const primary_xml = @import("primary.zig");
const filelists_xml = @import("filelists.zig");
const other_xml = @import("other.zig");
const rpmpkg = @import("rpmpkg.zig");
const rpm_header = @import("rpm_header");
const solv_bridge = @import("solvbridge.zig");

const c = if (builtin.is_test) @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("stdio.h");
    @cInclude("solv/pool.h");
    @cInclude("solv/repo.h");
    @cInclude("solv/solvable.h");
    @cInclude("solv/knownid.h");
}) else struct {};

pub const DependencyQueryKind = enum {
    provides,
    obsoletes,
    conflicts,
    requires,
    recommends,
    suggests,
    supplements,
    enhances,
    depends,
    requires_pre,

    pub fn relationKind(self: DependencyQueryKind) ?model.DependencyKind {
        return switch (self) {
            .provides => .provides,
            .obsoletes => .obsoletes,
            .conflicts => .conflicts,
            .requires => .requires,
            .recommends => .recommends,
            .suggests => .suggests,
            .supplements => .supplements,
            .enhances => .enhances,
            .depends, .requires_pre => null,
        };
    }
};

pub const OwnedStrings = struct {
    allocator: std.mem.Allocator,
    items: [][]const u8,

    pub fn deinit(self: OwnedStrings) void {
        for (self.items) |item| {
            self.allocator.free(item);
        }
        self.allocator.free(self.items);
    }
};

const depends_kinds = [_]model.DependencyKind{
    .requires,
    .recommends,
    .suggests,
    .supplements,
    .enhances,
};

const SourceParts = struct {
    name: []const u8,
    arch: []const u8,
    epoch: ?u32,
    version: []const u8,
    release: ?[]const u8,
};

const EvrParts = struct {
    epoch: ?u32,
    version: []const u8,
    release: ?[]const u8,
};

pub fn packageId(pkg: model.Package) []const u8 {
    return pkg.pkg_id;
}

pub fn name(pkg: model.Package) []const u8 {
    return pkg.nevra.name;
}

pub fn epoch(pkg: model.Package) ?u32 {
    return pkg.nevra.epoch;
}

pub fn version(pkg: model.Package) []const u8 {
    return pkg.nevra.version;
}

pub fn release(pkg: model.Package) []const u8 {
    return pkg.nevra.release;
}

pub fn arch(pkg: model.Package) []const u8 {
    return pkg.nevra.arch;
}

pub fn checksum(pkg: model.Package) model.PackageChecksum {
    return pkg.checksum;
}

pub fn summary(pkg: model.Package) ?[]const u8 {
    return pkg.summary;
}

pub fn description(pkg: model.Package) ?[]const u8 {
    return pkg.description;
}

pub fn packager(pkg: model.Package) ?[]const u8 {
    return pkg.packager;
}

pub fn url(pkg: model.Package) ?[]const u8 {
    return pkg.url;
}

pub fn fileTime(pkg: model.Package) ?u64 {
    return pkg.time.file;
}

pub fn buildTime(pkg: model.Package) ?u64 {
    return pkg.time.build;
}

pub fn packageSize(pkg: model.Package) ?u64 {
    return pkg.size.package;
}

pub fn downloadSize(pkg: model.Package) ?u64 {
    return packageSize(pkg);
}

pub fn installedSize(pkg: model.Package) ?u64 {
    return pkg.size.installed;
}

pub fn installSize(pkg: model.Package) ?u64 {
    return installedSize(pkg);
}

pub fn archiveSize(pkg: model.Package) ?u64 {
    return pkg.size.archive;
}

pub fn location(pkg: model.Package) model.PackageLocation {
    return pkg.location;
}

pub fn locationHref(pkg: model.Package) []const u8 {
    return pkg.location.href;
}

pub fn mediaBase(pkg: model.Package) ?[]const u8 {
    return pkg.location.xml_base;
}

pub fn resolvedLocation(allocator: std.mem.Allocator, pkg: model.Package) ![]const u8 {
    return pkg.location.resolve(allocator);
}

pub fn license(pkg: model.Package) ?[]const u8 {
    return pkg.rpm.license;
}

pub fn vendor(pkg: model.Package) ?[]const u8 {
    return pkg.rpm.vendor;
}

pub fn group(pkg: model.Package) ?[]const u8 {
    return pkg.rpm.group;
}

pub fn buildhost(pkg: model.Package) ?[]const u8 {
    return pkg.rpm.buildhost;
}

pub fn sourceRpm(pkg: model.Package) ?[]const u8 {
    return pkg.rpm.source_rpm;
}

pub fn headerRange(pkg: model.Package) ?model.HeaderRange {
    return pkg.rpm.header_range;
}

pub fn evrString(allocator: std.mem.Allocator, pkg: model.Package) ![]const u8 {
    return formatPackageEvr(
        allocator,
        pkg.nevra.epoch,
        pkg.nevra.version,
        pkg.nevra.release,
    );
}

pub fn nevrString(allocator: std.mem.Allocator, pkg: model.Package) ![]const u8 {
    const evr = try evrString(allocator, pkg);
    defer allocator.free(evr);
    return std.fmt.allocPrint(allocator, "{s}-{s}", .{ pkg.nevra.name, evr });
}

pub fn nevraString(allocator: std.mem.Allocator, pkg: model.Package) ![]const u8 {
    const nevr = try nevrString(allocator, pkg);
    if (pkg.nevra.arch.len == 0) {
        return nevr;
    }
    defer allocator.free(nevr);
    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ nevr, pkg.nevra.arch });
}

pub fn sourceName(pkg: model.Package) ?[]const u8 {
    const parts = sourceParts(pkg) orelse return null;
    if (sourceMatchesBinary(pkg, parts)) {
        return pkg.nevra.name;
    }
    return parts.name;
}

pub fn sourceArch(pkg: model.Package) ?[]const u8 {
    const parts = sourceParts(pkg) orelse return null;
    return parts.arch;
}

pub fn sourceEvrString(allocator: std.mem.Allocator, pkg: model.Package) !?[]const u8 {
    const parts = sourceParts(pkg) orelse return null;
    if (sourceMatchesBinary(pkg, parts)) {
        return try evrString(allocator, pkg);
    }
    return try formatPackageEvr(allocator, parts.epoch, parts.version, parts.release orelse "");
}

pub fn sourcePackageString(allocator: std.mem.Allocator, pkg: model.Package) !?[]const u8 {
    const src_name = sourceName(pkg) orelse return null;
    const src_arch = sourceArch(pkg) orelse return null;
    const src_evr = (try sourceEvrString(allocator, pkg)) orelse return null;
    defer allocator.free(src_evr);
    return @as([]const u8, try std.fmt.allocPrint(allocator, "{s}-{s}.{s}", .{ src_name, src_evr, src_arch }));
}

pub fn relationEntries(
    pkg: model.Package,
    kind: model.DependencyKind,
    relations: []const model.Relation,
) []const model.Relation {
    return pkg.relationsFor(kind, relations);
}

pub fn formatRelation(allocator: std.mem.Allocator, relation: model.Relation) ![]const u8 {
    const evr = try formatDependencyEvr(allocator, relation.epoch, relation.version, relation.release);
    if (evr == null or relation.comparison == .none) {
        if (evr) |text| {
            allocator.free(text);
        }
        return allocator.dupe(u8, relation.name);
    }
    defer allocator.free(evr.?);
    return std.fmt.allocPrint(
        allocator,
        "{s} {s} {s}",
        .{ relation.name, compareOpText(relation.comparison), evr.? },
    );
}

pub fn dependencyStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
    kind: DependencyQueryKind,
) !OwnedStrings {
    if (kind.relationKind()) |relation_kind| {
        return formatRelationSlice(allocator, pkg.relationsFor(relation_kind, relations));
    }

    return switch (kind) {
        .depends => formatDependsStrings(allocator, pkg, relations),
        .requires_pre => formatRequiresPreStrings(allocator, pkg, relations),
        else => unreachable,
    };
}

pub fn providesStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .provides);
}

pub fn obsoletesStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .obsoletes);
}

pub fn conflictsStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .conflicts);
}

pub fn requiresStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .requires);
}

pub fn recommendsStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .recommends);
}

pub fn suggestsStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .suggests);
}

pub fn supplementsStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .supplements);
}

pub fn enhancesStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .enhances);
}

pub fn dependsStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .depends);
}

pub fn requiresPreStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    return dependencyStrings(allocator, pkg, relations, .requires_pre);
}

pub fn fileEntries(pkg: model.Package, files: []const model.FileEntry) []const model.FileEntry {
    return pkg.fileEntries(files);
}

pub fn filePaths(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    files: []const model.FileEntry,
) !OwnedStrings {
    const entries = pkg.fileEntries(files);
    const out = try allocator.alloc([]const u8, entries.len);
    errdefer allocator.free(out);

    var populated: usize = 0;
    errdefer freeStringItems(allocator, out[0..populated]);

    for (entries, 0..) |entry, index| {
        out[index] = try allocator.dupe(u8, entry.path);
        populated += 1;
    }

    return .{ .allocator = allocator, .items = out };
}

pub fn changelogEntries(
    pkg: model.Package,
    changelogs: []const model.ChangelogEntry,
) []const model.ChangelogEntry {
    return pkg.changelogEntries(changelogs);
}

fn formatRelationSlice(
    allocator: std.mem.Allocator,
    relation_slice: []const model.Relation,
) !OwnedStrings {
    const out = try allocator.alloc([]const u8, relation_slice.len);
    errdefer allocator.free(out);

    var populated: usize = 0;
    errdefer freeStringItems(allocator, out[0..populated]);

    for (relation_slice, 0..) |relation, index| {
        out[index] = try formatRelation(allocator, relation);
        populated += 1;
    }

    return .{ .allocator = allocator, .items = out };
}

fn formatDependsStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    var results = std.array_list.Managed([]const u8).init(allocator);
    defer results.deinit();
    errdefer freeStringItems(allocator, results.items);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    for (depends_kinds) |kind| {
        for (pkg.relationsFor(kind, relations)) |relation| {
            const formatted = try formatRelation(allocator, relation);
            const gop = seen.getOrPut(formatted) catch |err| {
                allocator.free(formatted);
                return err;
            };
            if (gop.found_existing) {
                allocator.free(formatted);
                continue;
            }
            results.append(formatted) catch |err| {
                allocator.free(formatted);
                return err;
            };
        }
    }

    return .{
        .allocator = allocator,
        .items = try results.toOwnedSlice(),
    };
}

fn formatRequiresPreStrings(
    allocator: std.mem.Allocator,
    pkg: model.Package,
    relations: []const model.Relation,
) !OwnedStrings {
    var results = std.array_list.Managed([]const u8).init(allocator);
    defer results.deinit();
    errdefer freeStringItems(allocator, results.items);

    for (pkg.relationsFor(.requires, relations)) |relation| {
        if (!relation.pre) {
            continue;
        }
        const formatted = try formatRelation(allocator, relation);
        try results.append(formatted);
    }

    return .{
        .allocator = allocator,
        .items = try results.toOwnedSlice(),
    };
}

fn compareOpText(op: model.CompareOp) []const u8 {
    return switch (op) {
        .none => "",
        .eq => "=",
        .lt => "<",
        .le => "<=",
        .gt => ">",
        .ge => ">=",
    };
}

fn formatPackageEvr(
    allocator: std.mem.Allocator,
    maybe_epoch: ?u32,
    pkg_version: []const u8,
    pkg_release: []const u8,
) ![]const u8 {
    const epoch_text: ?u32 = if (maybe_epoch) |value|
        if (value == 0) null else value
    else
        null;
    return formatEvrText(allocator, epoch_text, pkg_version, if (pkg_release.len == 0) null else pkg_release);
}

fn formatDependencyEvr(
    allocator: std.mem.Allocator,
    maybe_epoch: ?u32,
    maybe_version: ?[]const u8,
    maybe_release: ?[]const u8,
) !?[]const u8 {
    if (maybe_epoch == null and maybe_version == null and maybe_release == null) {
        return null;
    }
    return try formatEvrText(allocator, maybe_epoch, maybe_version, maybe_release);
}

fn formatEvrText(
    allocator: std.mem.Allocator,
    maybe_epoch: ?u32,
    maybe_version: ?[]const u8,
    maybe_release: ?[]const u8,
) ![]const u8 {
    const version_text = maybe_version orelse "";
    const release_text = maybe_release orelse "";

    if (maybe_epoch) |value| {
        if (maybe_release != null) {
            return std.fmt.allocPrint(allocator, "{d}:{s}-{s}", .{ value, version_text, release_text });
        }
        return std.fmt.allocPrint(allocator, "{d}:{s}", .{ value, version_text });
    }

    if (maybe_release != null) {
        if (maybe_version != null and version_text.len != 0) {
            return std.fmt.allocPrint(allocator, "{s}-{s}", .{ version_text, release_text });
        }
        return allocator.dupe(u8, release_text);
    }

    return allocator.dupe(u8, version_text);
}

fn sourceParts(pkg: model.Package) ?SourceParts {
    const raw = pkg.rpm.source_rpm orelse return null;
    return parseSourceRpm(raw);
}

fn parseSourceRpm(raw: []const u8) ?SourceParts {
    if (!std.mem.endsWith(u8, raw, ".rpm")) {
        return null;
    }

    const stem = raw[0 .. raw.len - 4];
    const arch_index = std.mem.lastIndexOfScalar(u8, stem, '.') orelse return null;
    if (arch_index == 0 or arch_index + 1 >= stem.len) {
        return null;
    }

    const evr_release = stem[0..arch_index];
    const arch_text = stem[arch_index + 1 ..];
    const release_index = std.mem.lastIndexOfScalar(u8, evr_release, '-') orelse return null;
    if (release_index == 0 or release_index + 1 >= evr_release.len) {
        return null;
    }

    const name_version = evr_release[0..release_index];
    const version_index = std.mem.lastIndexOfScalar(u8, name_version, '-') orelse return null;
    if (version_index == 0 or version_index + 1 >= name_version.len) {
        return null;
    }

    const parsed_evr = splitEvr(evr_release[version_index + 1 ..]);
    if (parsed_evr.version.len == 0) {
        return null;
    }

    return .{
        .name = name_version[0..version_index],
        .arch = arch_text,
        .epoch = parsed_evr.epoch,
        .version = parsed_evr.version,
        .release = parsed_evr.release,
    };
}

fn splitEvr(evr: []const u8) EvrParts {
    if (evr.len == 0) {
        return .{ .epoch = null, .version = "", .release = null };
    }

    var parsed_epoch: ?u32 = null;
    var body = evr;
    if (std.mem.indexOfScalar(u8, evr, ':')) |separator| {
        if (separator != 0) {
            const candidate = evr[0..separator];
            parsed_epoch = std.fmt.parseInt(u32, candidate, 10) catch null;
            if (parsed_epoch != null) {
                body = evr[separator + 1 ..];
            }
        }
    }

    if (body.len == 0) {
        return .{ .epoch = parsed_epoch, .version = "", .release = null };
    }

    if (std.mem.lastIndexOfScalar(u8, body, '-')) |separator| {
        if (separator != 0 and separator + 1 < body.len) {
            return .{
                .epoch = parsed_epoch,
                .version = body[0..separator],
                .release = body[separator + 1 ..],
            };
        }
    }

    return .{
        .epoch = parsed_epoch,
        .version = body,
        .release = null,
    };
}

fn sourceMatchesBinary(pkg: model.Package, parts: SourceParts) bool {
    return std.mem.eql(u8, parts.name, pkg.nevra.name) and
        std.mem.eql(u8, parts.version, pkg.nevra.version) and
        sameOptionalString(parts.release, pkg.nevra.release);
}

fn sameOptionalString(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null and right == null) {
        return true;
    }
    if (left == null or right == null) {
        return false;
    }
    return std.mem.eql(u8, left.?, right.?);
}

fn freeStringItems(allocator: std.mem.Allocator, items: []const []const u8) void {
    for (items) |item| {
        allocator.free(item);
    }
}

test "package metadata and source accessors match primary metadata" {
    const testing = std.testing;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const fixture = try parsePrimaryAccessorFixture(arena_state.allocator());

    var libsolv = try loadLibsolvFixture(arena_state.allocator(), &fixture.parsed);
    defer libsolv.deinit();

    const pkg_one = fixture.parsed.packages[0];
    try testing.expectEqualStrings("pkg-one", name(pkg_one));
    try testing.expectEqual(@as(?u32, 7), epoch(pkg_one));
    try testing.expectEqualStrings("1.2.3", version(pkg_one));
    try testing.expectEqualStrings("4", release(pkg_one));
    try testing.expectEqualStrings("x86_64", arch(pkg_one));
    try testing.expectEqualStrings(pkg_one.pkg_id, packageId(pkg_one));
    try testing.expectEqualStrings("sha256", checksum(pkg_one).kind);
    try testing.expectEqualStrings("1111111111111111111111111111111111111111111111111111111111111111", checksum(pkg_one).value);
    try testing.expect(checksum(pkg_one).is_pkgid);
    try testing.expectEqualStrings("Package one summary", summary(pkg_one).?);
    try testing.expectEqualStrings("Package one description", description(pkg_one).?);
    try testing.expectEqualStrings("Pkg Builder", packager(pkg_one).?);
    try testing.expectEqualStrings("https://example.test/pkg-one", url(pkg_one).?);
    try testing.expectEqual(@as(?u64, 111), fileTime(pkg_one));
    try testing.expectEqual(@as(?u64, 222), buildTime(pkg_one));
    try testing.expectEqual(@as(?u64, 333), packageSize(pkg_one));
    try testing.expectEqual(@as(?u64, 444), installedSize(pkg_one));
    try testing.expectEqual(@as(?u64, 555), archiveSize(pkg_one));
    try testing.expectEqualStrings("Packages/pkg-one-1.2.3-4.x86_64.rpm", locationHref(pkg_one));
    try testing.expectEqualStrings("https://example.test/repo", mediaBase(pkg_one).?);
    const resolved_location = try resolvedLocation(testing.allocator, pkg_one);
    defer testing.allocator.free(resolved_location);
    try testing.expectEqualStrings("https://example.test/repo/Packages/pkg-one-1.2.3-4.x86_64.rpm", resolved_location);
    try testing.expectEqualStrings("MIT", license(pkg_one).?);
    try testing.expectEqualStrings("Example Co", vendor(pkg_one).?);
    try testing.expectEqualStrings("Applications/Test", group(pkg_one).?);
    try testing.expectEqualStrings("builder.example", buildhost(pkg_one).?);
    try testing.expectEqualStrings("pkg-one-1.2.3-4.src.rpm", sourceRpm(pkg_one).?);
    try testing.expectEqual(@as(u64, 100), headerRange(pkg_one).?.start);
    try testing.expectEqual(@as(u64, 200), headerRange(pkg_one).?.end);

    const pkg_one_evr = try evrString(testing.allocator, pkg_one);
    defer testing.allocator.free(pkg_one_evr);
    try testing.expectEqualStrings("7:1.2.3-4", pkg_one_evr);

    const pkg_one_nevra = try nevraString(testing.allocator, pkg_one);
    defer testing.allocator.free(pkg_one_nevra);
    try testing.expectEqualStrings("pkg-one-7:1.2.3-4.x86_64", pkg_one_nevra);

    const libsolv_pkg_one = libsolv.findPackage("pkg-one") orelse return error.TestExpectedEqual;
    try testing.expectEqualStrings(
        std.mem.span(c.solvable_lookup_str(libsolv_pkg_one, c.SOLVABLE_EVR) orelse return error.TestExpectedEqual),
        pkg_one_evr,
    );
    try testing.expectEqualStrings(
        std.mem.span(c.pool_solvable2str(libsolv.pool, libsolv_pkg_one)),
        pkg_one_nevra,
    );

    try testing.expectEqualStrings("pkg-one", sourceName(pkg_one).?);
    try testing.expectEqualStrings("src", sourceArch(pkg_one).?);
    const pkg_one_source_evr = (try sourceEvrString(testing.allocator, pkg_one)) orelse return error.TestExpectedEqual;
    defer testing.allocator.free(pkg_one_source_evr);
    try testing.expectEqualStrings("7:1.2.3-4", pkg_one_source_evr);
    const pkg_one_source_pkg = (try sourcePackageString(testing.allocator, pkg_one)) orelse return error.TestExpectedEqual;
    defer testing.allocator.free(pkg_one_source_pkg);
    try testing.expectEqualStrings("pkg-one-7:1.2.3-4.src", pkg_one_source_pkg);

    const libsolv_pkg_one_source = try libsolvSourcePackageString(testing.allocator, &libsolv, libsolv_pkg_one);
    defer testing.allocator.free(libsolv_pkg_one_source);
    try testing.expectEqualStrings(libsolv_pkg_one_source, pkg_one_source_pkg);

    const pkg_sub = fixture.parsed.packages[1];
    const pkg_sub_evr = try evrString(testing.allocator, pkg_sub);
    defer testing.allocator.free(pkg_sub_evr);
    try testing.expectEqualStrings("2.0-1", pkg_sub_evr);
    try testing.expectEqualStrings("pkg-src", sourceName(pkg_sub).?);
    try testing.expectEqualStrings("src", sourceArch(pkg_sub).?);
    const pkg_sub_source_pkg = (try sourcePackageString(testing.allocator, pkg_sub)) orelse return error.TestExpectedEqual;
    defer testing.allocator.free(pkg_sub_source_pkg);
    try testing.expectEqualStrings("pkg-src-2.0-1.src", pkg_sub_source_pkg);

    const libsolv_pkg_sub = libsolv.findPackage("pkg-sub") orelse return error.TestExpectedEqual;
    const libsolv_pkg_sub_source = try libsolvSourcePackageString(testing.allocator, &libsolv, libsolv_pkg_sub);
    defer testing.allocator.free(libsolv_pkg_sub_source);
    try testing.expectEqualStrings(libsolv_pkg_sub_source, pkg_sub_source_pkg);

    const pkg_depdup = fixture.parsed.packages[2];
    try testing.expect(sourceName(pkg_depdup) == null);
    try testing.expect(sourceArch(pkg_depdup) == null);
    try testing.expect(try sourceEvrString(testing.allocator, pkg_depdup) == null);
    try testing.expect(try sourcePackageString(testing.allocator, pkg_depdup) == null);
}

test "dependency accessors match libsolv formatting and filter semantics" {
    const testing = std.testing;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const built = try buildRpmpkgAccessorFixture(arena_state.allocator());

    for (built.relations) |relation| {
        const actual = try formatRelation(testing.allocator, relation);
        defer testing.allocator.free(actual);
        const expected = try libsolvDependencyString(testing.allocator, relation);
        defer testing.allocator.free(expected);
        try testing.expectEqualStrings(expected, actual);
    }

    const provides = try providesStrings(testing.allocator, built.package, built.relations);
    defer provides.deinit();
    try expectOwnedStringsEqual(&.{ "pkg-one = 7:2.3.4-5", "/usr/bin/pkg-one" }, provides);

    const requires = try requiresStrings(testing.allocator, built.package, built.relations);
    defer requires.deinit();
    try expectOwnedStringsEqual(&.{ "dep-one >= 1:1.0-2", "dep-two < 0:3.1" }, requires);

    const conflicts = try conflictsStrings(testing.allocator, built.package, built.relations);
    defer conflicts.deinit();
    try expectOwnedStringsEqual(&.{"old-pkg < 4.0-1"}, conflicts);

    const obsoletes = try obsoletesStrings(testing.allocator, built.package, built.relations);
    defer obsoletes.deinit();
    try expectOwnedStringsEqual(&.{"older-pkg"}, obsoletes);

    const recommends = try recommendsStrings(testing.allocator, built.package, built.relations);
    defer recommends.deinit();
    try expectOwnedStringsEqual(&.{"strong-addon"}, recommends);

    const suggests = try suggestsStrings(testing.allocator, built.package, built.relations);
    defer suggests.deinit();
    try expectOwnedStringsEqual(&.{"weak-addon"}, suggests);

    const supplements = try supplementsStrings(testing.allocator, built.package, built.relations);
    defer supplements.deinit();
    try expectOwnedStringsEqual(&.{"strong-extra"}, supplements);

    const enhances = try enhancesStrings(testing.allocator, built.package, built.relations);
    defer enhances.deinit();
    try expectOwnedStringsEqual(&.{"weak-extra"}, enhances);

    const depends = try dependsStrings(testing.allocator, built.package, built.relations);
    defer depends.deinit();
    try expectOwnedStringsEqual(
        &.{
            "dep-one >= 1:1.0-2",
            "dep-two < 0:3.1",
            "strong-addon",
            "weak-addon",
            "strong-extra",
            "weak-extra",
        },
        depends,
    );

    const requires_pre = try requiresPreStrings(testing.allocator, built.package, built.relations);
    defer requires_pre.deinit();
    try expectOwnedStringsEqual(&.{"dep-one >= 1:1.0-2"}, requires_pre);

    const primary_fixture = try parsePrimaryAccessorFixture(arena_state.allocator());
    const depdup = primary_fixture.parsed.packages[2];
    const deduped = try dependsStrings(testing.allocator, depdup, primary_fixture.parsed.relations);
    defer deduped.deinit();
    try expectOwnedStringsEqual(&.{ "dep-shared", "dep-extra" }, deduped);

    const zero_enhances = try enhancesStrings(testing.allocator, primary_fixture.parsed.packages[0], primary_fixture.parsed.relations);
    defer zero_enhances.deinit();
    try testing.expectEqual(@as(usize, 0), zero_enhances.items.len);
}

test "file and changelog accessors expose native metadata slices" {
    const testing = std.testing;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const fixture = try parsePrimaryAccessorFixture(arena_state.allocator());

    const pkg_one = fixture.parsed.packages[0];
    const files = fileEntries(pkg_one, fixture.parsed.files);
    try testing.expectEqual(@as(usize, 3), files.len);
    try testing.expectEqualStrings("/usr/bin/pkg-one", files[0].path);
    try testing.expectEqual(model.FileKind.plain, files[0].kind);
    try testing.expectEqualStrings("/usr/share/pkg-one", files[1].path);
    try testing.expectEqual(model.FileKind.dir, files[1].kind);
    try testing.expectEqualStrings("/var/lib/pkg-one.cache", files[2].path);
    try testing.expectEqual(model.FileKind.ghost, files[2].kind);

    const file_paths = try filePaths(testing.allocator, pkg_one, fixture.parsed.files);
    defer file_paths.deinit();
    try expectOwnedStringsEqual(
        &.{
            "/usr/bin/pkg-one",
            "/usr/share/pkg-one",
            "/var/lib/pkg-one.cache",
        },
        file_paths,
    );

    const pkg_sub_files = try filePaths(testing.allocator, fixture.parsed.packages[1], fixture.parsed.files);
    defer pkg_sub_files.deinit();
    try testing.expectEqual(@as(usize, 0), pkg_sub_files.items.len);

    const changelogs = changelogEntries(pkg_one, fixture.parsed.changelogs);
    try testing.expectEqual(@as(usize, 2), changelogs.len);
    try testing.expectEqualStrings("Jane Doe <jane@example.com>", changelogs[0].author);
    try testing.expectEqual(@as(u64, 1704067200), changelogs[0].timestamp);
    try testing.expectEqualStrings("Initial release", changelogs[0].text);
    try testing.expectEqualStrings("John Doe <john@example.com>", changelogs[1].author);
    try testing.expectEqual(@as(u64, 1704153600), changelogs[1].timestamp);
    try testing.expectEqualStrings("Fix bug in repo sync", changelogs[1].text);

    try testing.expectEqual(
        @as(usize, 0),
        changelogEntries(fixture.parsed.packages[1], fixture.parsed.changelogs).len,
    );
}

const PrimaryAccessorFixture = struct {
    parsed: model.ParsedPrimary,
    primary_xml: []const u8,
};

fn parsePrimaryAccessorFixture(allocator: std.mem.Allocator) !PrimaryAccessorFixture {
    const primary_xml_text =
        \\<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="3">
        \\  <package type="rpm">
        \\    <name>pkg-one</name>
        \\    <arch>x86_64</arch>
        \\    <version epoch="7" ver="1.2.3" rel="4"/>
        \\    <checksum type="sha256" pkgid="YES">1111111111111111111111111111111111111111111111111111111111111111</checksum>
        \\    <summary>Package one summary</summary>
        \\    <description>Package one description</description>
        \\    <packager>Pkg Builder</packager>
        \\    <url>https://example.test/pkg-one</url>
        \\    <time file="111" build="222"/>
        \\    <size package="333" installed="444" archive="555"/>
        \\    <location xml:base="https://example.test/repo" href="Packages/pkg-one-1.2.3-4.x86_64.rpm"/>
        \\    <format>
        \\      <rpm:license>MIT</rpm:license>
        \\      <rpm:vendor>Example Co</rpm:vendor>
        \\      <rpm:group>Applications/Test</rpm:group>
        \\      <rpm:buildhost>builder.example</rpm:buildhost>
        \\      <rpm:sourcerpm>pkg-one-1.2.3-4.src.rpm</rpm:sourcerpm>
        \\      <rpm:header-range start="100" end="200"/>
        \\      <rpm:provides>
        \\        <rpm:entry name="pkg-one" flags="EQ" epoch="7" ver="1.2.3" rel="4"/>
        \\      </rpm:provides>
        \\      <rpm:requires>
        \\        <rpm:entry name="dep-one" flags="GE" epoch="1" ver="2.0" rel="3" pre="1"/>
        \\      </rpm:requires>
        \\    </format>
        \\  </package>
        \\  <package type="rpm">
        \\    <name>pkg-sub</name>
        \\    <arch>noarch</arch>
        \\    <version epoch="0" ver="2.0" rel="1"/>
        \\    <checksum type="sha256" pkgid="YES">2222222222222222222222222222222222222222222222222222222222222222</checksum>
        \\    <location href="Packages/pkg-sub-2.0-1.noarch.rpm"/>
        \\    <format>
        \\      <rpm:sourcerpm>pkg-src-2.0-1.src.rpm</rpm:sourcerpm>
        \\    </format>
        \\  </package>
        \\  <package type="rpm">
        \\    <name>pkg-depdup</name>
        \\    <arch>x86_64</arch>
        \\    <version ver="3.0" rel="1"/>
        \\    <checksum type="sha256" pkgid="YES">3333333333333333333333333333333333333333333333333333333333333333</checksum>
        \\    <location href="Packages/pkg-depdup-3.0-1.x86_64.rpm"/>
        \\    <format>
        \\      <rpm:requires>
        \\        <rpm:entry name="dep-shared"/>
        \\      </rpm:requires>
        \\      <rpm:suggests>
        \\        <rpm:entry name="dep-shared"/>
        \\      </rpm:suggests>
        \\      <rpm:enhances>
        \\        <rpm:entry name="dep-extra"/>
        \\      </rpm:enhances>
        \\    </format>
        \\  </package>
        \\</metadata>
    ;

    const filelists_xml_text =
        \\<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="1">
        \\  <package pkgid="1111111111111111111111111111111111111111111111111111111111111111" name="pkg-one" arch="x86_64">
        \\    <version epoch="7" ver="1.2.3" rel="4"/>
        \\    <file>/usr/bin/pkg-one</file>
        \\    <file type="dir">/usr/share/pkg-one</file>
        \\    <file type="ghost">/var/lib/pkg-one.cache</file>
        \\  </package>
        \\</filelists>
    ;

    const other_xml_text =
        \\<otherdata xmlns="http://linux.duke.edu/metadata/other" packages="1">
        \\  <package pkgid="1111111111111111111111111111111111111111111111111111111111111111" name="pkg-one" arch="x86_64">
        \\    <version epoch="7" ver="1.2.3" rel="4"/>
        \\    <changelog author="Jane Doe &lt;jane@example.com&gt;" date="1704067200">Initial release</changelog>
        \\    <changelog author="John Doe &lt;john@example.com&gt;" date="1704153600">Fix bug in repo sync</changelog>
        \\  </package>
        \\</otherdata>
    ;

    var parsed = try primary_xml.parse(allocator, primary_xml_text);
    try filelists_xml.parseAndApply(allocator, filelists_xml_text, &parsed);
    try other_xml.parseAndApply(allocator, other_xml_text, &parsed);

    return .{
        .parsed = parsed,
        .primary_xml = primary_xml_text,
    };
}

const LibsolvFixture = struct {
    pool: *c.Pool,
    repo: *c.Repo,

    fn deinit(self: *LibsolvFixture) void {
        c.repo_free(self.repo, 1);
        c.pool_free(self.pool);
    }

    fn findPackage(self: *const LibsolvFixture, wanted_name: []const u8) ?*c.Solvable {
        var solvid: c.Id = self.repo.*.start;
        while (solvid < self.repo.*.end) : (solvid += 1) {
            const solvable = c.pool_id2solvable(self.pool, solvid) orelse continue;
            if (std.mem.eql(u8, std.mem.span(c.pool_id2str(self.pool, solvable.*.name)), wanted_name)) {
                return solvable;
            }
        }
        return null;
    }
};

fn loadLibsolvFixture(
    allocator: std.mem.Allocator,
    primary: *const model.ParsedPrimary,
) !LibsolvFixture {
    const pool = c.pool_create() orelse return error.OutOfMemory;
    errdefer c.pool_free(pool);

    const repo = c.repo_create(pool, "pkgquery-test") orelse return error.OutOfMemory;
    errdefer c.repo_free(repo, 1);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const repository = model.RepositoryModel{
        .packages = primary.packages,
        .relations = primary.relations,
        .files = primary.files,
        .changelogs = primary.changelogs,
        .has_filelists = primary.files.len != 0,
        .has_other = primary.changelogs.len != 0,
    };
    try solv_bridge.buildRepositoryIntoRepo(arena_state.allocator(), @ptrCast(repo), &repository);

    return .{ .pool = pool, .repo = repo };
}

fn libsolvSourcePackageString(
    allocator: std.mem.Allocator,
    fixture: *const LibsolvFixture,
    solvable: *c.Solvable,
) ![]const u8 {
    const source_name = if (c.solvable_lookup_str(solvable, c.SOLVABLE_SOURCENAME)) |value|
        std.mem.span(value)
    else
        std.mem.span(c.pool_id2str(fixture.pool, solvable.*.name));
    const source_arch = c.solvable_lookup_str(solvable, c.SOLVABLE_SOURCEARCH) orelse return error.TestExpectedEqual;
    const source_evr = if (c.solvable_lookup_str(solvable, c.SOLVABLE_SOURCEEVR)) |value|
        std.mem.span(value)
    else
        std.mem.span(c.solvable_lookup_str(solvable, c.SOLVABLE_EVR) orelse return error.TestExpectedEqual);
    const normalized_source_evr = if (std.mem.startsWith(u8, source_evr, "0:"))
        source_evr[2..]
    else
        source_evr;
    return std.fmt.allocPrint(
        allocator,
        "{s}-{s}.{s}",
        .{ source_name, normalized_source_evr, std.mem.span(source_arch) },
    );
}

fn libsolvDependencyString(allocator: std.mem.Allocator, relation: model.Relation) ![]const u8 {
    const pool = c.pool_create() orelse return error.OutOfMemory;
    defer c.pool_free(pool);

    const name_z = try allocator.dupeZ(u8, relation.name);
    defer allocator.free(name_z);
    const name_id = c.pool_str2id(pool, name_z, 1);
    if (relation.comparison == .none or
        (relation.epoch == null and relation.version == null and relation.release == null))
    {
        return allocator.dupe(u8, std.mem.span(c.pool_dep2str(pool, name_id)));
    }

    const evr = try formatEvrText(allocator, relation.epoch, relation.version, relation.release);
    defer allocator.free(evr);
    const evr_z = try allocator.dupeZ(u8, evr);
    defer allocator.free(evr_z);
    const dep_id = c.pool_rel2id(pool, name_id, c.pool_str2id(pool, evr_z, 1), compareOpToSolv(relation.comparison), 1);
    return allocator.dupe(u8, std.mem.span(c.pool_dep2str(pool, dep_id)));
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

fn expectOwnedStringsEqual(expected: []const []const u8, actual: OwnedStrings) !void {
    const testing = std.testing;

    try testing.expectEqual(expected.len, actual.items.len);
    for (expected, actual.items) |exp, act| {
        try testing.expectEqualStrings(exp, act);
    }
}

fn expectLibsolvOk(rc: c_int) !void {
    try std.testing.expectEqual(@as(c_int, 0), rc);
}

const dep_less: u32 = 1 << 1;
const dep_greater: u32 = 1 << 2;
const dep_equal: u32 = 1 << 3;
const dep_pre_in: u32 = (1 << 6) | (1 << 9) | (1 << 10);
const dep_strong: u32 = 1 << 27;
const fileflag_ghost: u32 = 1 << 6;

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

fn buildRpmpkgAccessorFixture(allocator: std.mem.Allocator) !rpmpkg.BuiltPackage {
    const provides_values = [_][]const u8{ "pkg-one", "/usr/bin/pkg-one" };
    const requires_values = [_][]const u8{ "dep-one", "dep-two" };
    const basename_values = [_][]const u8{ "pkg-one", "pkg-one.conf", "ghost-file" };
    const dirname_values = [_][]const u8{ "/usr/bin/", "/etc/", "/var/lib/" };
    const changelog_authors = [_][]const u8{ "Alice", "Bob" };
    const changelog_texts = [_][]const u8{ "Initial build", "Fixes" };

    const header_blob = try buildHeaderBlob(allocator, &.{
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
    defer allocator.free(header_blob);

    const header = try rpm_header.Header.parse(header_blob);
    return rpmpkg.buildFromHeader(allocator, header, .{});
}

fn buildHeaderBlob(
    allocator: std.mem.Allocator,
    entries: []const TestHeaderEntry,
) ![]u8 {
    var data = std.array_list.Managed(u8).init(allocator);
    defer data.deinit();

    var index = std.array_list.Managed(u8).init(allocator);
    defer index.deinit();

    for (entries) |entry| {
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

fn appendBeU16(list: *std.array_list.Managed(u8), value: u16) !void {
    try list.append(@intCast((value >> 8) & 0xff));
    try list.append(@intCast(value & 0xff));
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
