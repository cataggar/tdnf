const std = @import("std");
const model = @import("model.zig");

pub const PackageIndex = usize;

pub const NameMatchOptions = struct {
    ignore_case: bool = false,
};

pub const OwnedPackageIndices = struct {
    allocator: std.mem.Allocator,
    items: []PackageIndex,

    pub fn deinit(self: OwnedPackageIndices) void {
        self.allocator.free(self.items);
    }
};

pub const ParseError = error{
    InvalidDependencyQuery,
};

pub const QueryError = ParseError || error{OutOfMemory};

pub const DependencyQuery = struct {
    name: []const u8,
    comparison: model.CompareOp = .none,
    epoch: ?u32 = null,
    version: ?[]const u8 = null,
    release: ?[]const u8 = null,

    pub fn parse(text: []const u8) ParseError!DependencyQuery {
        const trimmed = trimAsciiWhitespace(text);
        if (trimmed.len == 0) {
            return error.InvalidDependencyQuery;
        }

        for ([_]struct {
            token: []const u8,
            op: model.CompareOp,
        }{
            .{ .token = "<=", .op = .le },
            .{ .token = ">=", .op = .ge },
            .{ .token = "=", .op = .eq },
            .{ .token = "<", .op = .lt },
            .{ .token = ">", .op = .gt },
        }) |candidate| {
            if (std.mem.indexOf(u8, trimmed, candidate.token)) |separator| {
                const raw_name = trimAsciiWhitespace(trimmed[0..separator]);
                const raw_evr = trimAsciiWhitespace(trimmed[separator + candidate.token.len ..]);
                if (raw_name.len == 0 or raw_evr.len == 0) {
                    return error.InvalidDependencyQuery;
                }

                const parts = splitEvr(raw_evr);
                if (parts.version.len == 0 and parts.release == null) {
                    return error.InvalidDependencyQuery;
                }

                return .{
                    .name = raw_name,
                    .comparison = candidate.op,
                    .epoch = parts.epoch,
                    .version = if (parts.version.len == 0) null else parts.version,
                    .release = parts.release,
                };
            }
        }

        return .{
            .name = trimmed,
        };
    }

    pub fn hasVersion(self: DependencyQuery) bool {
        return self.epoch != null or
            (self.version != null and self.version.?.len != 0) or
            (self.release != null and self.release.?.len != 0);
    }
};

const empty_package_indices = [_]PackageIndex{};
const empty_advisory_ids = [_][]const u8{};

const ProvideEntry = struct {
    package_index: PackageIndex,
    relation_index: usize,
};

const EvrParts = struct {
    epoch: ?u32 = null,
    version: []const u8 = "",
    release: ?[]const u8 = null,
};

const Bound = struct {
    evr: EvrParts,
    inclusive: bool,
};

const VersionRange = struct {
    lower: ?Bound = null,
    upper: ?Bound = null,
};

pub const RepositoryIndex = struct {
    allocator: std.mem.Allocator,
    repository: *const model.RepositoryModel,
    names: std.StringHashMap(std.array_list.Managed(PackageIndex)),
    provides: std.StringHashMap(std.array_list.Managed(ProvideEntry)),
    files: std.StringHashMap(std.array_list.Managed(PackageIndex)),
    advisories: std.StringHashMap(std.array_list.Managed(PackageIndex)),
    package_advisory_ids: []std.array_list.Managed([]const u8),
    search_texts_lower: [][]const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        repository: *const model.RepositoryModel,
    ) error{OutOfMemory}!RepositoryIndex {
        var index = RepositoryIndex{
            .allocator = allocator,
            .repository = repository,
            .names = std.StringHashMap(std.array_list.Managed(PackageIndex)).init(allocator),
            .provides = std.StringHashMap(std.array_list.Managed(ProvideEntry)).init(allocator),
            .files = std.StringHashMap(std.array_list.Managed(PackageIndex)).init(allocator),
            .advisories = std.StringHashMap(std.array_list.Managed(PackageIndex)).init(allocator),
            .package_advisory_ids = &.{},
            .search_texts_lower = &.{},
        };
        errdefer index.deinit();

        try index.buildSearchTexts();
        try index.buildNameIndex();
        try index.buildProvidesIndex();
        try index.buildFileIndex();
        try index.buildAdvisoryIndex();

        return index;
    }

    pub fn deinit(self: *RepositoryIndex) void {
        self.deinitPackageIndexMap(&self.names);
        self.deinitProvideMap(&self.provides);
        self.deinitPackageIndexMap(&self.files);
        self.deinitPackageIndexMap(&self.advisories);

        for (self.package_advisory_ids) |list| {
            list.deinit();
        }
        if (self.package_advisory_ids.len != 0) {
            self.allocator.free(self.package_advisory_ids);
        }

        for (self.search_texts_lower) |text| {
            self.allocator.free(text);
        }
        if (self.search_texts_lower.len != 0) {
            self.allocator.free(self.search_texts_lower);
        }

        self.* = undefined;
    }

    pub fn packagesNamed(self: *const RepositoryIndex, wanted_name: []const u8) []const PackageIndex {
        if (self.names.get(wanted_name)) |indices| {
            return indices.items;
        }
        return empty_package_indices[0..];
    }

    pub fn matchNamePattern(
        self: *const RepositoryIndex,
        allocator: std.mem.Allocator,
        pattern: []const u8,
        options: NameMatchOptions,
    ) error{OutOfMemory}!OwnedPackageIndices {
        const trimmed = trimAsciiWhitespace(pattern);
        if (trimmed.len == 0) {
            return .{ .allocator = allocator, .items = try allocator.alloc(PackageIndex, 0) };
        }

        if (!options.ignore_case and !containsGlobMeta(trimmed)) {
            return duplicatePackageIndices(allocator, self.packagesNamed(trimmed));
        }

        var results = std.array_list.Managed(PackageIndex).init(allocator);
        defer results.deinit();

        for (self.repository.packages, 0..) |pkg, package_index| {
            if (nameMatchesPattern(trimmed, pkg.nevra.name, options)) {
                try results.append(package_index);
            }
        }

        return .{
            .allocator = allocator,
            .items = try results.toOwnedSlice(),
        };
    }

    pub fn packagesProviding(
        self: *const RepositoryIndex,
        allocator: std.mem.Allocator,
        query_text: []const u8,
    ) QueryError!OwnedPackageIndices {
        return self.packagesProvidingQuery(allocator, try DependencyQuery.parse(query_text));
    }

    pub fn packagesProvidingQuery(
        self: *const RepositoryIndex,
        allocator: std.mem.Allocator,
        query: DependencyQuery,
    ) error{OutOfMemory}!OwnedPackageIndices {
        var results = std.array_list.Managed(PackageIndex).init(allocator);
        defer results.deinit();

        const seen = try allocator.alloc(bool, self.repository.packages.len);
        defer allocator.free(seen);
        @memset(seen, false);

        const entries = if (self.provides.get(query.name)) |value|
            value.items
        else
            emptyProvideEntries();

        for (entries) |entry| {
            const relation = self.repository.relations[entry.relation_index];
            if (!provideMatchesQuery(relation, query)) {
                continue;
            }
            if (seen[entry.package_index]) {
                continue;
            }
            seen[entry.package_index] = true;
            try results.append(entry.package_index);
        }

        return .{
            .allocator = allocator,
            .items = try results.toOwnedSlice(),
        };
    }

    pub fn packagesProvidingFile(self: *const RepositoryIndex, path: []const u8) []const PackageIndex {
        if (self.files.get(path)) |indices| {
            return indices.items;
        }
        return empty_package_indices[0..];
    }

    pub fn packagesForAdvisory(self: *const RepositoryIndex, advisory_id: []const u8) []const PackageIndex {
        if (self.advisories.get(advisory_id)) |indices| {
            return indices.items;
        }
        return empty_package_indices[0..];
    }

    pub fn advisoryIdsForPackage(self: *const RepositoryIndex, package_index: PackageIndex) []const []const u8 {
        if (package_index >= self.package_advisory_ids.len) {
            return empty_advisory_ids[0..];
        }
        return self.package_advisory_ids[package_index].items;
    }

    pub fn searchText(
        self: *const RepositoryIndex,
        allocator: std.mem.Allocator,
        term: []const u8,
    ) error{OutOfMemory}!OwnedPackageIndices {
        const trimmed = trimAsciiWhitespace(term);
        if (trimmed.len == 0) {
            return .{ .allocator = allocator, .items = try allocator.alloc(PackageIndex, 0) };
        }

        const lowered_term = try lowerAlloc(allocator, trimmed);
        defer allocator.free(lowered_term);

        var results = std.array_list.Managed(PackageIndex).init(allocator);
        defer results.deinit();

        for (self.search_texts_lower, 0..) |search_text, package_index| {
            if (std.mem.indexOf(u8, search_text, lowered_term) != null) {
                try results.append(package_index);
            }
        }

        return .{
            .allocator = allocator,
            .items = try results.toOwnedSlice(),
        };
    }

    fn buildSearchTexts(self: *RepositoryIndex) error{OutOfMemory}!void {
        self.search_texts_lower = try self.allocator.alloc([]const u8, self.repository.packages.len);
        errdefer self.allocator.free(self.search_texts_lower);

        var populated: usize = 0;
        errdefer {
            for (self.search_texts_lower[0..populated]) |text| {
                self.allocator.free(text);
            }
        }

        for (self.repository.packages, 0..) |pkg, package_index| {
            self.search_texts_lower[package_index] = try buildSearchText(self.allocator, pkg);
            populated += 1;
        }
    }

    fn buildNameIndex(self: *RepositoryIndex) error{OutOfMemory}!void {
        for (self.repository.packages, 0..) |pkg, package_index| {
            try appendPackageIndex(&self.names, self.allocator, pkg.nevra.name, package_index);
        }
    }

    fn buildProvidesIndex(self: *RepositoryIndex) error{OutOfMemory}!void {
        for (self.repository.packages, 0..) |pkg, package_index| {
            const relations = pkg.relationsFor(.provides, self.repository.relations);
            for (relations, 0..) |relation, offset| {
                try appendProvideEntry(
                    &self.provides,
                    self.allocator,
                    relation.name,
                    .{
                        .package_index = package_index,
                        .relation_index = pkg.provides.start + offset,
                    },
                );
            }
        }
    }

    fn buildFileIndex(self: *RepositoryIndex) error{OutOfMemory}!void {
        for (self.repository.packages, 0..) |pkg, package_index| {
            for (pkg.fileEntries(self.repository.files)) |file_entry| {
                try appendUniquePackageIndex(&self.files, self.allocator, file_entry.path, package_index);
            }
        }
    }

    fn buildAdvisoryIndex(self: *RepositoryIndex) error{OutOfMemory}!void {
        self.package_advisory_ids = try self.allocator.alloc(std.array_list.Managed([]const u8), self.repository.packages.len);
        errdefer self.allocator.free(self.package_advisory_ids);

        var initialized: usize = 0;
        errdefer {
            for (self.package_advisory_ids[0..initialized]) |list| {
                list.deinit();
            }
        }

        for (self.package_advisory_ids) |*list| {
            list.* = std.array_list.Managed([]const u8).init(self.allocator);
            initialized += 1;
        }

        for (self.repository.advisories) |advisory| {
            const advisory_gop = try self.advisories.getOrPut(advisory.id);
            if (!advisory_gop.found_existing) {
                advisory_gop.value_ptr.* = std.array_list.Managed(PackageIndex).init(self.allocator);
            }

            for (advisory.packageEntries(self.repository.advisory_packages)) |advisory_pkg| {
                for (self.packagesNamed(advisory_pkg.nevra.name)) |package_index| {
                    if (!packageMatchesAdvisory(self.repository.packages[package_index], advisory_pkg)) {
                        continue;
                    }
                    try appendUniqueListPackageIndex(advisory_gop.value_ptr, package_index);
                    try appendUniqueString(&self.package_advisory_ids[package_index], advisory.id);
                }
            }
        }
    }

    fn deinitPackageIndexMap(
        self: *RepositoryIndex,
        map: *std.StringHashMap(std.array_list.Managed(PackageIndex)),
    ) void {
        var values = map.valueIterator();
        while (values.next()) |list| {
            list.deinit();
        }
        map.deinit();
        _ = self;
    }

    fn deinitProvideMap(
        self: *RepositoryIndex,
        map: *std.StringHashMap(std.array_list.Managed(ProvideEntry)),
    ) void {
        var values = map.valueIterator();
        while (values.next()) |list| {
            list.deinit();
        }
        map.deinit();
        _ = self;
    }
};

pub fn nameMatchesPattern(
    pattern: []const u8,
    name: []const u8,
    options: NameMatchOptions,
) bool {
    const trimmed = trimAsciiWhitespace(pattern);
    return if (containsGlobMeta(trimmed))
        globMatch(trimmed, name, options.ignore_case)
    else
        asciiEql(trimmed, name, options.ignore_case);
}

pub fn compareEvr(
    left_epoch: ?u32,
    left_version: ?[]const u8,
    left_release: ?[]const u8,
    right_epoch: ?u32,
    right_version: ?[]const u8,
    right_release: ?[]const u8,
) i32 {
    return compareEvrParts(
        .{
            .epoch = left_epoch,
            .version = left_version orelse "",
            .release = left_release,
        },
        .{
            .epoch = right_epoch,
            .version = right_version orelse "",
            .release = right_release,
        },
    );
}

pub fn comparePackageVersions(left: model.Package, right: model.Package) i32 {
    return compareEvr(
        left.nevra.epoch,
        left.nevra.version,
        if (left.nevra.release.len == 0) null else left.nevra.release,
        right.nevra.epoch,
        right.nevra.version,
        if (right.nevra.release.len == 0) null else right.nevra.release,
    );
}

pub fn comparePackageWithQuery(pkg: model.Package, query: DependencyQuery) i32 {
    return compareEvr(
        pkg.nevra.epoch,
        pkg.nevra.version,
        if (pkg.nevra.release.len == 0) null else pkg.nevra.release,
        query.epoch,
        query.version,
        query.release,
    );
}

pub fn relationMatchesQuery(relation: model.Relation, query: DependencyQuery) bool {
    return provideMatchesQuery(relation, query);
}

pub fn packageMatchesAdvisoryEntry(pkg: model.Package, advisory_pkg: model.AdvisoryPackage) bool {
    return packageMatchesAdvisory(pkg, advisory_pkg);
}

fn appendPackageIndex(
    map: *std.StringHashMap(std.array_list.Managed(PackageIndex)),
    allocator: std.mem.Allocator,
    key: []const u8,
    package_index: PackageIndex,
) error{OutOfMemory}!void {
    const gop = try map.getOrPut(key);
    if (!gop.found_existing) {
        gop.value_ptr.* = std.array_list.Managed(PackageIndex).init(allocator);
    }
    try gop.value_ptr.append(package_index);
}

fn appendUniquePackageIndex(
    map: *std.StringHashMap(std.array_list.Managed(PackageIndex)),
    allocator: std.mem.Allocator,
    key: []const u8,
    package_index: PackageIndex,
) error{OutOfMemory}!void {
    const gop = try map.getOrPut(key);
    if (!gop.found_existing) {
        gop.value_ptr.* = std.array_list.Managed(PackageIndex).init(allocator);
    }
    try appendUniqueListPackageIndex(gop.value_ptr, package_index);
}

fn appendProvideEntry(
    map: *std.StringHashMap(std.array_list.Managed(ProvideEntry)),
    allocator: std.mem.Allocator,
    key: []const u8,
    entry: ProvideEntry,
) error{OutOfMemory}!void {
    const gop = try map.getOrPut(key);
    if (!gop.found_existing) {
        gop.value_ptr.* = std.array_list.Managed(ProvideEntry).init(allocator);
    }
    try gop.value_ptr.append(entry);
}

fn appendUniqueListPackageIndex(
    list: *std.array_list.Managed(PackageIndex),
    package_index: PackageIndex,
) error{OutOfMemory}!void {
    for (list.items) |existing| {
        if (existing == package_index) {
            return;
        }
    }
    try list.append(package_index);
}

fn appendUniqueString(
    list: *std.array_list.Managed([]const u8),
    value: []const u8,
) error{OutOfMemory}!void {
    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, value)) {
            return;
        }
    }
    try list.append(value);
}

fn duplicatePackageIndices(
    allocator: std.mem.Allocator,
    items: []const PackageIndex,
) error{OutOfMemory}!OwnedPackageIndices {
    const out = try allocator.alloc(PackageIndex, items.len);
    @memcpy(out, items);
    return .{
        .allocator = allocator,
        .items = out,
    };
}

fn buildSearchText(
    allocator: std.mem.Allocator,
    pkg: model.Package,
) error{OutOfMemory}![]const u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    defer out.deinit();

    try appendSearchField(&out, pkg.nevra.name);
    if (pkg.summary) |summary| {
        try appendSearchField(&out, summary);
    }
    if (pkg.description) |description| {
        try appendSearchField(&out, description);
    }

    return out.toOwnedSlice();
}

fn appendSearchField(
    out: *std.array_list.Managed(u8),
    value: []const u8,
) error{OutOfMemory}!void {
    if (out.items.len != 0) {
        try out.append('\n');
    }
    for (value) |byte| {
        try out.append(std.ascii.toLower(byte));
    }
}

fn lowerAlloc(allocator: std.mem.Allocator, value: []const u8) error{OutOfMemory}![]const u8 {
    const out = try allocator.alloc(u8, value.len);
    for (value, 0..) |byte, index| {
        out[index] = std.ascii.toLower(byte);
    }
    return out;
}

fn trimAsciiWhitespace(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\r\n");
}

fn containsGlobMeta(pattern: []const u8) bool {
    for (pattern) |byte| {
        switch (byte) {
            '*', '?', '[' => return true,
            else => {},
        }
    }
    return false;
}

fn asciiEql(left: []const u8, right: []const u8, ignore_case: bool) bool {
    if (!ignore_case) {
        return std.mem.eql(u8, left, right);
    }
    if (left.len != right.len) {
        return false;
    }
    for (left, right) |lhs, rhs| {
        if (std.ascii.toLower(lhs) != std.ascii.toLower(rhs)) {
            return false;
        }
    }
    return true;
}

fn globMatch(pattern: []const u8, text: []const u8, ignore_case: bool) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;

    while (pattern_index < pattern.len) {
        switch (pattern[pattern_index]) {
            '*' => {
                while (pattern_index < pattern.len and pattern[pattern_index] == '*') {
                    pattern_index += 1;
                }
                if (pattern_index == pattern.len) {
                    return true;
                }
                while (text_index <= text.len) : (text_index += 1) {
                    if (globMatch(pattern[pattern_index..], text[text_index..], ignore_case)) {
                        return true;
                    }
                }
                return false;
            },
            '?' => {
                if (text_index == text.len) {
                    return false;
                }
                pattern_index += 1;
                text_index += 1;
            },
            '[' => {
                if (text_index == text.len) {
                    return false;
                }
                if (matchCharacterClass(pattern[pattern_index..], text[text_index], ignore_case)) |class_match| {
                    if (!class_match.matched) {
                        return false;
                    }
                    pattern_index += class_match.consumed;
                    text_index += 1;
                } else {
                    if (!asciiByteEql('[', text[text_index], ignore_case)) {
                        return false;
                    }
                    pattern_index += 1;
                    text_index += 1;
                }
            },
            else => {
                if (text_index == text.len or !asciiByteEql(pattern[pattern_index], text[text_index], ignore_case)) {
                    return false;
                }
                pattern_index += 1;
                text_index += 1;
            },
        }
    }

    return text_index == text.len;
}

const CharacterClassMatch = struct {
    matched: bool,
    consumed: usize,
};

fn matchCharacterClass(
    pattern: []const u8,
    value: u8,
    ignore_case: bool,
) ?CharacterClassMatch {
    if (pattern.len < 2 or pattern[0] != '[') {
        return null;
    }

    var index: usize = 1;
    var negated = false;
    if (index < pattern.len and (pattern[index] == '!' or pattern[index] == '^')) {
        negated = true;
        index += 1;
    }

    var matched = false;
    var found_closing = false;
    var saw_item = false;
    const folded_value = foldedAscii(value, ignore_case);

    while (index < pattern.len) {
        if (pattern[index] == ']') {
            found_closing = saw_item;
            index += 1;
            break;
        }

        saw_item = true;
        if (index + 2 < pattern.len and pattern[index + 1] == '-' and pattern[index + 2] != ']') {
            const range_start = foldedAscii(pattern[index], ignore_case);
            const range_end = foldedAscii(pattern[index + 2], ignore_case);
            const lo = @min(range_start, range_end);
            const hi = @max(range_start, range_end);
            if (folded_value >= lo and folded_value <= hi) {
                matched = true;
            }
            index += 3;
            continue;
        }

        if (foldedAscii(pattern[index], ignore_case) == folded_value) {
            matched = true;
        }
        index += 1;
    }

    if (!found_closing) {
        return null;
    }

    return .{
        .matched = if (negated) !matched else matched,
        .consumed = index,
    };
}

fn asciiByteEql(left: u8, right: u8, ignore_case: bool) bool {
    return foldedAscii(left, ignore_case) == foldedAscii(right, ignore_case);
}

fn foldedAscii(value: u8, ignore_case: bool) u8 {
    return if (ignore_case) std.ascii.toLower(value) else value;
}

fn provideMatchesQuery(relation: model.Relation, query: DependencyQuery) bool {
    if (!std.mem.eql(u8, relation.name, query.name)) {
        return false;
    }
    if (query.comparison == .none or !query.hasVersion()) {
        return true;
    }
    if (relation.comparison == .none or !relationHasVersion(relation.epoch, relation.version, relation.release)) {
        return false;
    }

    return rangesIntersect(
        rangeFromRelation(relation.comparison, relation.epoch, relation.version, relation.release),
        rangeFromRelation(query.comparison, query.epoch, query.version, query.release),
    );
}

fn packageMatchesAdvisory(pkg: model.Package, advisory_pkg: model.AdvisoryPackage) bool {
    if (!std.mem.eql(u8, pkg.nevra.name, advisory_pkg.nevra.name) or
        !std.mem.eql(u8, pkg.nevra.arch, advisory_pkg.nevra.arch))
    {
        return false;
    }

    return compareEvrParts(
        .{
            .epoch = pkg.nevra.epoch,
            .version = pkg.nevra.version,
            .release = if (pkg.nevra.release.len == 0) null else pkg.nevra.release,
        },
        .{
            .epoch = advisory_pkg.nevra.epoch,
            .version = advisory_pkg.nevra.version,
            .release = if (advisory_pkg.nevra.release.len == 0) null else advisory_pkg.nevra.release,
        },
    ) == 0;
}

fn relationHasVersion(epoch: ?u32, version: ?[]const u8, release: ?[]const u8) bool {
    return epoch != null or
        (version != null and version.?.len != 0) or
        (release != null and release.?.len != 0);
}

fn rangeFromRelation(
    comparison: model.CompareOp,
    epoch: ?u32,
    version: ?[]const u8,
    release: ?[]const u8,
) VersionRange {
    const evr = EvrParts{
        .epoch = epoch,
        .version = version orelse "",
        .release = release,
    };

    return switch (comparison) {
        .none => .{},
        .eq => .{
            .lower = .{ .evr = evr, .inclusive = true },
            .upper = .{ .evr = evr, .inclusive = true },
        },
        .lt => .{
            .upper = .{ .evr = evr, .inclusive = false },
        },
        .le => .{
            .upper = .{ .evr = evr, .inclusive = true },
        },
        .gt => .{
            .lower = .{ .evr = evr, .inclusive = false },
        },
        .ge => .{
            .lower = .{ .evr = evr, .inclusive = true },
        },
    };
}

fn rangesIntersect(left: VersionRange, right: VersionRange) bool {
    const lower = maxLowerBound(left.lower, right.lower);
    const upper = minUpperBound(left.upper, right.upper);

    if (lower == null or upper == null) {
        return true;
    }

    const cmp = compareEvrParts(lower.?.evr, upper.?.evr);
    if (cmp < 0) {
        return true;
    }
    if (cmp > 0) {
        return false;
    }

    return lower.?.inclusive and upper.?.inclusive;
}

fn maxLowerBound(left: ?Bound, right: ?Bound) ?Bound {
    if (left == null) return right;
    if (right == null) return left;

    const cmp = compareEvrParts(left.?.evr, right.?.evr);
    if (cmp > 0) return left;
    if (cmp < 0) return right;

    return .{
        .evr = left.?.evr,
        .inclusive = left.?.inclusive and right.?.inclusive,
    };
}

fn minUpperBound(left: ?Bound, right: ?Bound) ?Bound {
    if (left == null) return right;
    if (right == null) return left;

    const cmp = compareEvrParts(left.?.evr, right.?.evr);
    if (cmp < 0) return left;
    if (cmp > 0) return right;

    return .{
        .evr = left.?.evr,
        .inclusive = left.?.inclusive and right.?.inclusive,
    };
}

fn compareEvrParts(left: EvrParts, right: EvrParts) i32 {
    const left_epoch = left.epoch orelse 0;
    const right_epoch = right.epoch orelse 0;
    if (left_epoch < right_epoch) return -1;
    if (left_epoch > right_epoch) return 1;

    const version_cmp = compareRpmVersion(left.version, right.version);
    if (version_cmp != 0) return version_cmp;

    return compareRpmVersion(left.release orelse "", right.release orelse "");
}

fn compareRpmVersion(left_raw: []const u8, right_raw: []const u8) i32 {
    var left = left_raw;
    var right = right_raw;

    while (true) {
        while (left.len != 0 and !isRpmTokenByte(left[0])) {
            left = left[1..];
        }
        while (right.len != 0 and !isRpmTokenByte(right[0])) {
            right = right[1..];
        }

        if ((left.len != 0 and left[0] == '~') or (right.len != 0 and right[0] == '~')) {
            if (left.len == 0 or left[0] != '~') return 1;
            if (right.len == 0 or right[0] != '~') return -1;
            left = left[1..];
            right = right[1..];
            continue;
        }

        if ((left.len != 0 and left[0] == '^') or (right.len != 0 and right[0] == '^')) {
            if (left.len == 0) return -1;
            if (right.len == 0) return 1;
            if (left[0] != '^') return 1;
            if (right[0] != '^') return -1;
            left = left[1..];
            right = right[1..];
            continue;
        }

        if (left.len == 0 and right.len == 0) {
            return 0;
        }
        if (left.len == 0) {
            return -1;
        }
        if (right.len == 0) {
            return 1;
        }

        const left_is_digit = std.ascii.isDigit(left[0]);
        const right_is_digit = std.ascii.isDigit(right[0]);
        if (left_is_digit != right_is_digit) {
            return if (left_is_digit) 1 else -1;
        }

        if (left_is_digit) {
            const left_end = digitRunEnd(left);
            const right_end = digitRunEnd(right);

            var left_digits = left[0..left_end];
            var right_digits = right[0..right_end];
            left = left[left_end..];
            right = right[right_end..];

            left_digits = trimLeadingZeros(left_digits);
            right_digits = trimLeadingZeros(right_digits);

            if (left_digits.len < right_digits.len) return -1;
            if (left_digits.len > right_digits.len) return 1;

            const cmp = std.mem.order(u8, left_digits, right_digits);
            if (cmp != .eq) {
                return switch (cmp) {
                    .lt => -1,
                    .gt => 1,
                    .eq => unreachable,
                };
            }
            continue;
        }

        const left_end = alphaRunEnd(left);
        const right_end = alphaRunEnd(right);
        const left_alpha = left[0..left_end];
        const right_alpha = right[0..right_end];
        left = left[left_end..];
        right = right[right_end..];

        const cmp = std.mem.order(u8, left_alpha, right_alpha);
        if (cmp != .eq) {
            return switch (cmp) {
                .lt => -1,
                .gt => 1,
                .eq => unreachable,
            };
        }
    }
}

fn trimLeadingZeros(value: []const u8) []const u8 {
    var index: usize = 0;
    while (index < value.len and value[index] == '0') : (index += 1) {}
    return value[index..];
}

fn digitRunEnd(value: []const u8) usize {
    var index: usize = 0;
    while (index < value.len and std.ascii.isDigit(value[index])) : (index += 1) {}
    return index;
}

fn alphaRunEnd(value: []const u8) usize {
    var index: usize = 0;
    while (index < value.len and std.ascii.isAlphabetic(value[index])) : (index += 1) {}
    return index;
}

fn isRpmTokenByte(value: u8) bool {
    return std.ascii.isAlphanumeric(value) or value == '~' or value == '^';
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
        return .{
            .epoch = epoch,
        };
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

fn emptyProvideEntries() []const ProvideEntry {
    return &.{};
}

fn expectPackageIndices(expected: []const PackageIndex, actual: []const PackageIndex) !void {
    const testing = std.testing;

    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |exp, act| {
        try testing.expectEqual(exp, act);
    }
}

fn expectAdvisoryIds(expected: []const []const u8, actual: []const []const u8) !void {
    const testing = std.testing;

    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |exp, act| {
        try testing.expectEqualStrings(exp, act);
    }
}

test "rpm version comparison matches key ordering edge cases" {
    const testing = std.testing;

    try testing.expectEqual(@as(i32, 0), compareEvr(0, "1", "1", null, "1", "1"));
    try testing.expectEqual(@as(i32, 0), compareEvr(null, "10.0001", null, null, "10.1", null));
    try testing.expect(compareEvr(null, "2.0.1a", null, null, "2.0.1", null) > 0);
    try testing.expect(compareEvr(null, "6.0.rc1", null, null, "6.0", null) > 0);
    try testing.expect(compareEvr(null, "1.0~rc1", null, null, "1.0", null) < 0);
    try testing.expect(compareEvr(null, "1.0^git1", null, null, "1.0", null) > 0);
    try testing.expect(compareEvr(null, "1.0^git1", null, null, "1.01", null) < 0);
    try testing.expect(compareEvr(null, "1.0~rc1^git1", null, null, "1.0~rc1", null) > 0);
}

const fixture_relations = [_]model.Relation{
    .{ .name = "alpha", .comparison = .eq, .epoch = 0, .version = "1.0", .release = "1" },
    .{ .name = "libalpha", .comparison = .eq, .epoch = 2, .version = "3.1", .release = "4" },
    .{ .name = "unversioned-feature" },
    .{ .name = "alpha", .comparison = .eq, .epoch = 0, .version = "2.0", .release = "1" },
    .{ .name = "libalpha", .comparison = .eq, .epoch = 2, .version = "3.2", .release = "0" },
    .{ .name = "alpha-tools", .comparison = .eq, .epoch = 0, .version = "1.0", .release = "3" },
    .{ .name = "libalpha-tools", .comparison = .ge, .epoch = 1, .version = "5.0", .release = "0" },
    .{ .name = "beta" },
};

const fixture_files = [_]model.FileEntry{
    .{ .path = "/usr/bin/alpha" },
    .{ .path = "/usr/libexec/shared-helper" },
    .{ .path = "/usr/bin/alpha2" },
    .{ .path = "/usr/share/doc/alpha/README" },
    .{ .path = "/usr/libexec/shared-helper" },
    .{ .path = "/usr/bin/alpha-tools" },
    .{ .path = "/usr/bin/beta" },
};

const fixture_packages = [_]model.Package{
    .{
        .pkg_id = "pkg-alpha-1",
        .nevra = .{ .name = "alpha", .epoch = 0, .version = "1.0", .release = "1", .arch = "x86_64" },
        .checksum = .{ .kind = "sha256", .value = "11111111111111111111111111111111" },
        .summary = "Alpha core package",
        .description = "Base alpha runtime",
        .location = .{ .href = "Packages/alpha-1.0-1.x86_64.rpm" },
        .provides = .{ .start = 0, .len = 3 },
        .files = .{ .start = 0, .len = 2 },
    },
    .{
        .pkg_id = "pkg-alpha-2",
        .nevra = .{ .name = "alpha", .epoch = 0, .version = "2.0", .release = "1", .arch = "x86_64" },
        .checksum = .{ .kind = "sha256", .value = "22222222222222222222222222222222" },
        .summary = "Alpha second generation",
        .description = "Faster alpha runtime",
        .location = .{ .href = "Packages/alpha-2.0-1.x86_64.rpm" },
        .provides = .{ .start = 3, .len = 2 },
        .files = .{ .start = 2, .len = 2 },
    },
    .{
        .pkg_id = "pkg-alpha-tools",
        .nevra = .{ .name = "alpha-tools", .epoch = 0, .version = "1.0", .release = "3", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "33333333333333333333333333333333" },
        .summary = "Tools for alpha admins",
        .description = "Includes admin utilities",
        .location = .{ .href = "Packages/alpha-tools-1.0-3.noarch.rpm" },
        .provides = .{ .start = 5, .len = 2 },
        .files = .{ .start = 4, .len = 2 },
    },
    .{
        .pkg_id = "pkg-beta",
        .nevra = .{ .name = "beta", .version = "1.5", .release = "2", .arch = "noarch" },
        .checksum = .{ .kind = "sha256", .value = "44444444444444444444444444444444" },
        .summary = "Needle summary tool",
        .description = "General utilities",
        .location = .{ .href = "Packages/beta-1.5-2.noarch.rpm" },
        .provides = .{ .start = 7, .len = 1 },
        .files = .{ .start = 6, .len = 1 },
    },
};

const fixture_advisory_packages = [_]model.AdvisoryPackage{
    .{
        .collection_short = "ALPHA",
        .collection_name = "Alpha collection",
        .nevra = .{ .name = "alpha", .version = "2.0", .release = "1", .arch = "x86_64" },
    },
    .{
        .collection_short = "ALPHA",
        .collection_name = "Alpha collection",
        .nevra = .{ .name = "alpha-tools", .epoch = 0, .version = "1.0", .release = "3", .arch = "noarch" },
    },
    .{
        .collection_short = "BETA",
        .collection_name = "Beta collection",
        .nevra = .{ .name = "beta", .version = "1.5", .release = "2", .arch = "noarch" },
    },
};

const fixture_advisories = [_]model.Advisory{
    .{
        .id = "ADV-ALPHA-2026-0001",
        .raw_type = "security",
        .kind = .security,
        .packages = .{ .start = 0, .len = 2 },
    },
    .{
        .id = "ADV-BETA-2026-0002",
        .raw_type = "bugfix",
        .kind = .bugfix,
        .packages = .{ .start = 2, .len = 1 },
    },
};

fn fixtureRepository() model.RepositoryModel {
    return .{
        .packages = @constCast(fixture_packages[0..]),
        .relations = @constCast(fixture_relations[0..]),
        .files = @constCast(fixture_files[0..]),
        .advisories = @constCast(fixture_advisories[0..]),
        .advisory_packages = @constCast(fixture_advisory_packages[0..]),
        .has_filelists = true,
        .has_updateinfo = true,
    };
}

test "name index supports exact and glob matches" {
    const testing = std.testing;
    var repository = fixtureRepository();
    var index = try RepositoryIndex.init(testing.allocator, &repository);
    defer index.deinit();

    try expectPackageIndices(&.{ 0, 1 }, index.packagesNamed("alpha"));

    const exact = try index.matchNamePattern(testing.allocator, "alpha", .{});
    defer exact.deinit();
    try expectPackageIndices(&.{ 0, 1 }, exact.items);

    const glob = try index.matchNamePattern(testing.allocator, "alpha*", .{});
    defer glob.deinit();
    try expectPackageIndices(&.{ 0, 1, 2 }, glob.items);

    const nocase = try index.matchNamePattern(testing.allocator, "ALPHA*", .{ .ignore_case = true });
    defer nocase.deinit();
    try expectPackageIndices(&.{ 0, 1, 2 }, nocase.items);

    const missing = try index.matchNamePattern(testing.allocator, "gamma*", .{});
    defer missing.deinit();
    try testing.expectEqual(@as(usize, 0), missing.items.len);
}

test "provides index handles versioned and ranged lookups" {
    const testing = std.testing;
    var repository = fixtureRepository();
    var index = try RepositoryIndex.init(testing.allocator, &repository);
    defer index.deinit();

    const unversioned = try index.packagesProviding(testing.allocator, "libalpha");
    defer unversioned.deinit();
    try expectPackageIndices(&.{ 0, 1 }, unversioned.items);

    const ge_match = try index.packagesProviding(testing.allocator, "libalpha >= 2:3.1-5");
    defer ge_match.deinit();
    try expectPackageIndices(&.{1}, ge_match.items);

    const gt_miss = try index.packagesProviding(testing.allocator, "libalpha > 2:3.2-0");
    defer gt_miss.deinit();
    try testing.expectEqual(@as(usize, 0), gt_miss.items.len);

    const ranged_match = try index.packagesProviding(testing.allocator, "libalpha-tools<1:6.0-0");
    defer ranged_match.deinit();
    try expectPackageIndices(&.{2}, ranged_match.items);

    const ranged_miss = try index.packagesProviding(testing.allocator, "libalpha-tools < 1:5.0-0");
    defer ranged_miss.deinit();
    try testing.expectEqual(@as(usize, 0), ranged_miss.items.len);

    const unversioned_miss = try index.packagesProviding(testing.allocator, "unversioned-feature >= 1");
    defer unversioned_miss.deinit();
    try testing.expectEqual(@as(usize, 0), unversioned_miss.items.len);
}

test "file and advisory indexes map shared paths and updateinfo membership" {
    const testing = std.testing;
    var repository = fixtureRepository();
    var index = try RepositoryIndex.init(testing.allocator, &repository);
    defer index.deinit();

    try expectPackageIndices(&.{ 0, 2 }, index.packagesProvidingFile("/usr/libexec/shared-helper"));
    try expectPackageIndices(&.{ 1, 2 }, index.packagesForAdvisory("ADV-ALPHA-2026-0001"));
    try expectPackageIndices(&.{3}, index.packagesForAdvisory("ADV-BETA-2026-0002"));
    try expectAdvisoryIds(&.{}, index.advisoryIdsForPackage(0));
    try expectAdvisoryIds(&.{"ADV-ALPHA-2026-0001"}, index.advisoryIdsForPackage(1));
    try expectAdvisoryIds(&.{"ADV-ALPHA-2026-0001"}, index.advisoryIdsForPackage(2));
    try expectAdvisoryIds(&.{"ADV-BETA-2026-0002"}, index.advisoryIdsForPackage(3));
}

test "search text index matches summary and description substrings case-insensitively" {
    const testing = std.testing;
    var repository = fixtureRepository();
    var index = try RepositoryIndex.init(testing.allocator, &repository);
    defer index.deinit();

    const summary_hit = try index.searchText(testing.allocator, "NEEDLE");
    defer summary_hit.deinit();
    try expectPackageIndices(&.{3}, summary_hit.items);

    const description_hit = try index.searchText(testing.allocator, "admin util");
    defer description_hit.deinit();
    try expectPackageIndices(&.{2}, description_hit.items);
}
