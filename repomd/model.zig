const std = @import("std");

pub const RecordKind = enum(u32) {
    unknown = 0,
    primary = 1,
    filelists = 2,
    other = 3,
    updateinfo = 4,
};

pub const Checksum = extern struct {
    pszType: ?[*:0]const u8 = null,
    pszValue: ?[*:0]const u8 = null,
};

pub const Record = extern struct {
    pszType: ?[*:0]const u8 = null,
    dwKind: u32 = @intFromEnum(RecordKind.unknown),
    pszLocationHref: ?[*:0]const u8 = null,
    checksum: Checksum = .{},
    openChecksum: Checksum = .{},
    nTimestamp: u64 = 0,
    nSize: u64 = 0,
    nOpenSize: u64 = 0,
    nDatabaseVersion: u64 = 0,
    nHasTimestamp: c_int = 0,
    nHasSize: c_int = 0,
    nHasOpenSize: c_int = 0,
    nHasDatabaseVersion: c_int = 0,
};

pub const ParsedRepoMd = struct {
    pszRevision: ?[*:0]const u8 = null,
    pRecords: []Record = &[_]Record{},
};

pub const DependencyKind = enum {
    provides,
    requires,
    conflicts,
    obsoletes,
    recommends,
    suggests,
    supplements,
    enhances,
};

pub const CompareOp = enum {
    none,
    eq,
    lt,
    le,
    gt,
    ge,
};

pub const RelationRange = struct {
    start: usize = 0,
    len: usize = 0,

    pub fn slice(self: RelationRange, relations: []const Relation) []const Relation {
        return relations[self.start .. self.start + self.len];
    }
};

pub const FileKind = enum {
    plain,
    dir,
    ghost,
};

pub const FileRange = struct {
    start: usize = 0,
    len: usize = 0,

    pub fn slice(self: FileRange, files: []const FileEntry) []const FileEntry {
        return files[self.start .. self.start + self.len];
    }
};

pub const ChangelogRange = struct {
    start: usize = 0,
    len: usize = 0,

    pub fn slice(self: ChangelogRange, changelogs: []const ChangelogEntry) []const ChangelogEntry {
        return changelogs[self.start .. self.start + self.len];
    }
};

pub const AdvisoryKind = enum {
    unknown,
    security,
    bugfix,
    enhancement,
};

pub const AdvisoryReferenceKind = enum {
    other,
    bugzilla,
    cve,
    vendor,
};

pub const AdvisoryReferenceRange = struct {
    start: usize = 0,
    len: usize = 0,

    pub fn slice(self: AdvisoryReferenceRange, references: []const AdvisoryReference) []const AdvisoryReference {
        return references[self.start .. self.start + self.len];
    }
};

pub const AdvisoryPackageRange = struct {
    start: usize = 0,
    len: usize = 0,

    pub fn slice(self: AdvisoryPackageRange, packages: []const AdvisoryPackage) []const AdvisoryPackage {
        return packages[self.start .. self.start + self.len];
    }
};

pub const PackageChecksum = struct {
    kind: []const u8,
    value: []const u8,
    is_pkgid: bool = false,
};

pub const Nevra = struct {
    name: []const u8 = "",
    epoch: ?u32 = null,
    version: []const u8 = "",
    release: []const u8 = "",
    arch: []const u8 = "",
};

pub const PackageTime = struct {
    file: ?u64 = null,
    build: ?u64 = null,
};

pub const PackageSize = struct {
    package: ?u64 = null,
    installed: ?u64 = null,
    archive: ?u64 = null,
};

pub const PackageLocation = struct {
    href: []const u8 = "",
    xml_base: ?[]const u8 = null,

    pub fn resolve(self: PackageLocation, allocator: std.mem.Allocator) ![]const u8 {
        if (isAbsoluteLocation(self.href) or self.xml_base == null) {
            return allocator.dupe(u8, self.href);
        }

        const base = self.xml_base.?;
        if (base.len == 0 or self.href.len == 0) {
            return std.mem.concat(allocator, u8, &.{ base, self.href });
        }

        if (std.mem.endsWith(u8, base, "/") or std.mem.startsWith(u8, self.href, "/")) {
            return std.mem.concat(allocator, u8, &.{ base, self.href });
        }

        return std.mem.concat(allocator, u8, &.{ base, "/", self.href });
    }
};

pub const HeaderRange = struct {
    start: u64,
    end: u64,
};

pub const RpmMetadata = struct {
    license: ?[]const u8 = null,
    vendor: ?[]const u8 = null,
    group: ?[]const u8 = null,
    buildhost: ?[]const u8 = null,
    source_rpm: ?[]const u8 = null,
    header_range: ?HeaderRange = null,
};

pub const Relation = struct {
    name: []const u8,
    flags: ?[]const u8 = null,
    comparison: CompareOp = .none,
    epoch: ?u32 = null,
    version: ?[]const u8 = null,
    release: ?[]const u8 = null,
    pre: bool = false,
};

pub const FileEntry = struct {
    path: []const u8,
    kind: FileKind = .plain,
};

pub const ChangelogEntry = struct {
    author: []const u8,
    timestamp: u64,
    text: []const u8,
};

pub const AdvisoryReference = struct {
    kind: AdvisoryReferenceKind = .other,
    raw_type: ?[]const u8 = null,
    id: ?[]const u8 = null,
    title: ?[]const u8 = null,
    href: ?[]const u8 = null,
};

pub const AdvisoryPackage = struct {
    collection_short: ?[]const u8 = null,
    collection_name: ?[]const u8 = null,
    nevra: Nevra = .{},
    src: ?[]const u8 = null,
    filename: ?[]const u8 = null,
    reboot_suggested: bool = false,
};

pub const Advisory = struct {
    id: []const u8,
    raw_type: []const u8,
    kind: AdvisoryKind = .unknown,
    from: ?[]const u8 = null,
    status: ?[]const u8 = null,
    version: ?[]const u8 = null,
    title: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    release: ?[]const u8 = null,
    rights: ?[]const u8 = null,
    issued: ?[]const u8 = null,
    updated: ?[]const u8 = null,
    description: ?[]const u8 = null,
    reboot_suggested: bool = false,
    references: AdvisoryReferenceRange = .{},
    packages: AdvisoryPackageRange = .{},

    pub fn referenceEntries(self: Advisory, references: []const AdvisoryReference) []const AdvisoryReference {
        return self.references.slice(references);
    }

    pub fn packageEntries(self: Advisory, packages: []const AdvisoryPackage) []const AdvisoryPackage {
        return self.packages.slice(packages);
    }
};

pub const Package = struct {
    pkg_id: []const u8,
    nevra: Nevra,
    checksum: PackageChecksum,
    summary: ?[]const u8 = null,
    description: ?[]const u8 = null,
    packager: ?[]const u8 = null,
    url: ?[]const u8 = null,
    time: PackageTime = .{},
    size: PackageSize = .{},
    location: PackageLocation,
    rpm: RpmMetadata = .{},
    provides: RelationRange = .{},
    requires: RelationRange = .{},
    conflicts: RelationRange = .{},
    obsoletes: RelationRange = .{},
    recommends: RelationRange = .{},
    suggests: RelationRange = .{},
    supplements: RelationRange = .{},
    enhances: RelationRange = .{},
    files: FileRange = .{},
    changelogs: ChangelogRange = .{},

    pub fn range(self: Package, kind: DependencyKind) RelationRange {
        return switch (kind) {
            .provides => self.provides,
            .requires => self.requires,
            .conflicts => self.conflicts,
            .obsoletes => self.obsoletes,
            .recommends => self.recommends,
            .suggests => self.suggests,
            .supplements => self.supplements,
            .enhances => self.enhances,
        };
    }

    pub fn rangePtr(self: *Package, kind: DependencyKind) *RelationRange {
        return switch (kind) {
            .provides => &self.provides,
            .requires => &self.requires,
            .conflicts => &self.conflicts,
            .obsoletes => &self.obsoletes,
            .recommends => &self.recommends,
            .suggests => &self.suggests,
            .supplements => &self.supplements,
            .enhances => &self.enhances,
        };
    }

    pub fn relationsFor(self: Package, kind: DependencyKind, relations: []const Relation) []const Relation {
        return self.range(kind).slice(relations);
    }

    pub fn fileEntries(self: Package, files: []const FileEntry) []const FileEntry {
        return self.files.slice(files);
    }

    pub fn changelogEntries(self: Package, changelogs: []const ChangelogEntry) []const ChangelogEntry {
        return self.changelogs.slice(changelogs);
    }
};

pub const ParsedPrimary = struct {
    declared_package_count: ?u64 = null,
    packages: []Package = &[_]Package{},
    relations: []Relation = &[_]Relation{},
    files: []FileEntry = &[_]FileEntry{},
    changelogs: []ChangelogEntry = &[_]ChangelogEntry{},
};

pub const ParsedUpdateInfo = struct {
    advisories: []Advisory = &[_]Advisory{},
    references: []AdvisoryReference = &[_]AdvisoryReference{},
    packages: []AdvisoryPackage = &[_]AdvisoryPackage{},
};

pub const RepositoryModel = struct {
    pszRevision: ?[*:0]const u8 = null,
    records: []Record = &[_]Record{},
    packages: []Package = &[_]Package{},
    relations: []Relation = &[_]Relation{},
    files: []FileEntry = &[_]FileEntry{},
    changelogs: []ChangelogEntry = &[_]ChangelogEntry{},
    advisories: []Advisory = &[_]Advisory{},
    advisory_references: []AdvisoryReference = &[_]AdvisoryReference{},
    advisory_packages: []AdvisoryPackage = &[_]AdvisoryPackage{},
    has_filelists: bool = false,
    has_other: bool = false,
    has_updateinfo: bool = false,
};

pub fn repositoryModelFromParts(
    parsed_repomd: ParsedRepoMd,
    parsed_primary: ParsedPrimary,
    parsed_updateinfo: ParsedUpdateInfo,
) RepositoryModel {
    var repo = RepositoryModel{
        .pszRevision = parsed_repomd.pszRevision,
        .records = parsed_repomd.pRecords,
        .packages = parsed_primary.packages,
        .relations = parsed_primary.relations,
        .files = parsed_primary.files,
        .changelogs = parsed_primary.changelogs,
        .advisories = parsed_updateinfo.advisories,
        .advisory_references = parsed_updateinfo.references,
        .advisory_packages = parsed_updateinfo.packages,
    };

    for (parsed_repomd.pRecords) |record| {
        const raw_type = spanZ(record.pszType) orelse continue;
        switch (kindFromRawType(raw_type)) {
            .filelists => repo.has_filelists = true,
            .other => repo.has_other = true,
            .updateinfo => repo.has_updateinfo = true,
            else => {},
        }
    }

    return repo;
}

pub fn kindFromRawType(raw_type: []const u8) RecordKind {
    if (std.mem.eql(u8, raw_type, "primary")) return .primary;
    if (std.mem.eql(u8, raw_type, "filelists")) return .filelists;
    if (std.mem.eql(u8, raw_type, "other")) return .other;
    if (std.mem.startsWith(u8, raw_type, "updateinfo")) return .updateinfo;
    return .unknown;
}

pub fn advisoryKindFromType(raw_type: []const u8) AdvisoryKind {
    if (std.ascii.eqlIgnoreCase(raw_type, "security")) return .security;
    if (std.ascii.eqlIgnoreCase(raw_type, "bugfix")) return .bugfix;
    if (std.ascii.eqlIgnoreCase(raw_type, "enhancement")) return .enhancement;
    return .unknown;
}

pub fn advisoryReferenceKindFromType(raw_type: []const u8) AdvisoryReferenceKind {
    if (std.ascii.eqlIgnoreCase(raw_type, "bugzilla")) return .bugzilla;
    if (std.ascii.eqlIgnoreCase(raw_type, "cve")) return .cve;
    if (std.ascii.eqlIgnoreCase(raw_type, "vendor")) return .vendor;
    return .other;
}

pub fn dupZ(allocator: std.mem.Allocator, bytes: []const u8) ![:0]const u8 {
    const out = try allocator.allocSentinel(u8, bytes.len, 0);
    @memcpy(out[0..bytes.len], bytes);
    return out;
}

pub fn dup(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    return allocator.dupe(u8, bytes);
}

pub fn spanZ(value: ?[*:0]const u8) ?[]const u8 {
    const ptr = value orelse return null;
    return std.mem.span(ptr);
}

pub fn compareOpFromFlags(raw_flags: []const u8) ?CompareOp {
    if (std.ascii.eqlIgnoreCase(raw_flags, "EQ")) return .eq;
    if (std.ascii.eqlIgnoreCase(raw_flags, "LT")) return .lt;
    if (std.ascii.eqlIgnoreCase(raw_flags, "LE")) return .le;
    if (std.ascii.eqlIgnoreCase(raw_flags, "GT")) return .gt;
    if (std.ascii.eqlIgnoreCase(raw_flags, "GE")) return .ge;
    return null;
}

fn isAbsoluteLocation(href: []const u8) bool {
    return std.mem.indexOf(u8, href, "://") != null or std.mem.startsWith(u8, href, "/");
}
