const std = @import("std");
const shared_xml = @import("xml");
const sax = shared_xml.sax;
const model = @import("model.zig");

const COMMON_NS = "http://linux.duke.edu/metadata/common";
const RPM_NS = "http://linux.duke.edu/metadata/rpm";

const dependency_kinds = [_]model.DependencyKind{
    .provides,
    .requires,
    .conflicts,
    .obsoletes,
    .recommends,
    .suggests,
    .supplements,
    .enhances,
};

pub const Error = error{
    InvalidPrimary,
    OutOfMemory,
};

const ElementKind = enum {
    other,
    metadata,
    package,
    name,
    arch,
    checksum,
    summary,
    description,
    packager,
    url,
    format,
    license,
    vendor,
    group,
    buildhost,
    sourcerpm,
    dependency_container,
};

const Frame = struct {
    kind: ElementKind,
    collect_text: bool = false,
    text: std.array_list.Managed(u8),
    checksum_type: ?[]const u8 = null,
    checksum_is_pkgid: bool = false,
    dependency_kind: ?model.DependencyKind = null,

    fn init(allocator: std.mem.Allocator, kind: ElementKind) Frame {
        return .{
            .kind = kind,
            .text = std.array_list.Managed(u8).init(allocator),
        };
    }

    fn deinit(self: *Frame) void {
        self.text.deinit();
    }
};

const PackageBuilder = struct {
    allocator: std.mem.Allocator,
    package_type_is_rpm: bool = false,
    saw_version: bool = false,
    saw_checksum: bool = false,
    saw_location: bool = false,
    saw_time: bool = false,
    saw_size: bool = false,
    saw_header_range: bool = false,
    name: ?[]const u8 = null,
    arch: ?[]const u8 = null,
    epoch: ?u32 = null,
    version: ?[]const u8 = null,
    release: ?[]const u8 = null,
    checksum: ?model.PackageChecksum = null,
    summary: ?[]const u8 = null,
    description: ?[]const u8 = null,
    packager: ?[]const u8 = null,
    url: ?[]const u8 = null,
    time: model.PackageTime = .{},
    size: model.PackageSize = .{},
    location_href: ?[]const u8 = null,
    location_xml_base: ?[]const u8 = null,
    license: ?[]const u8 = null,
    vendor: ?[]const u8 = null,
    group: ?[]const u8 = null,
    buildhost: ?[]const u8 = null,
    source_rpm: ?[]const u8 = null,
    header_range: ?model.HeaderRange = null,
    relation_buckets: [dependency_kinds.len]std.array_list.Managed(model.Relation),

    fn init(allocator: std.mem.Allocator) PackageBuilder {
        var relation_buckets: [dependency_kinds.len]std.array_list.Managed(model.Relation) = undefined;
        inline for (&relation_buckets) |*relation_bucket| {
            relation_bucket.* = std.array_list.Managed(model.Relation).init(allocator);
        }

        return .{
            .allocator = allocator,
            .relation_buckets = relation_buckets,
        };
    }

    fn deinit(self: *PackageBuilder) void {
        inline for (&self.relation_buckets) |*relation_bucket| {
            relation_bucket.deinit();
        }
    }

    fn setRequiredString(self: *PackageBuilder, field: *?[]const u8, value: []const u8) Error!void {
        _ = self;
        if (field.* != null) return error.InvalidPrimary;
        field.* = value;
    }

    fn setOptionalString(self: *PackageBuilder, field: *?[]const u8, value: ?[]const u8) void {
        _ = self;
        if (value) |text| {
            field.* = text;
        }
    }

    fn relationBucket(self: *PackageBuilder, kind: model.DependencyKind) *std.array_list.Managed(model.Relation) {
        return &self.relation_buckets[@intFromEnum(kind)];
    }

    fn appendRelation(self: *PackageBuilder, kind: model.DependencyKind, relation: model.Relation) Error!void {
        self.relationBucket(kind).append(relation) catch return error.OutOfMemory;
    }

    fn build(self: *PackageBuilder, all_relations: *std.array_list.Managed(model.Relation)) Error!model.Package {
        if (!self.package_type_is_rpm or
            self.name == null or
            self.arch == null or
            self.version == null or
            self.release == null or
            self.checksum == null or
            self.location_href == null)
        {
            return error.InvalidPrimary;
        }

        const checksum = self.checksum.?;
        if (!checksum.is_pkgid) return error.InvalidPrimary;

        var package = model.Package{
            .pkg_id = checksum.value,
            .nevra = .{
                .name = self.name.?,
                .epoch = self.epoch,
                .version = self.version.?,
                .release = self.release.?,
                .arch = self.arch.?,
            },
            .checksum = checksum,
            .summary = self.summary,
            .description = self.description,
            .packager = self.packager,
            .url = self.url,
            .time = self.time,
            .size = self.size,
            .location = .{
                .href = self.location_href.?,
                .xml_base = self.location_xml_base,
            },
            .rpm = .{
                .license = self.license,
                .vendor = self.vendor,
                .group = self.group,
                .buildhost = self.buildhost,
                .source_rpm = self.source_rpm,
                .header_range = self.header_range,
            },
        };

        inline for (dependency_kinds) |kind| {
            const bucket = self.relationBucket(kind);
            const range = package.rangePtr(kind);
            range.* = .{
                .start = all_relations.items.len,
                .len = bucket.items.len,
            };
            all_relations.appendSlice(bucket.items) catch return error.OutOfMemory;
        }

        return package;
    }
};

const Parser = struct {
    allocator: std.mem.Allocator,
    frames: std.array_list.Managed(Frame),
    packages: std.array_list.Managed(model.Package),
    relations: std.array_list.Managed(model.Relation),
    current_package: PackageBuilder = undefined,
    in_package: bool = false,
    declared_package_count: ?u64 = null,
    saw_root: bool = false,

    fn init(allocator: std.mem.Allocator) Parser {
        return .{
            .allocator = allocator,
            .frames = std.array_list.Managed(Frame).init(allocator),
            .packages = std.array_list.Managed(model.Package).init(allocator),
            .relations = std.array_list.Managed(model.Relation).init(allocator),
        };
    }

    fn deinit(self: *Parser) void {
        if (self.in_package) {
            self.current_package.deinit();
        }
        for (self.frames.items) |*frame| {
            frame.deinit();
        }
        self.relations.deinit();
        self.packages.deinit();
        self.frames.deinit();
    }

    fn parse(self: *Parser, input: []const u8) Error!model.ParsedPrimary {
        var walker = sax.Walker.init(self.allocator, input);
        defer walker.deinit();

        while (true) {
            const maybe_event = walker.next() catch |err| return switch (err) {
                error.InvalidXml => error.InvalidPrimary,
                error.OutOfMemory => error.OutOfMemory,
            };

            const event = maybe_event orelse break;
            switch (event) {
                .start => |start| try self.onStartElement(start),
                .text => |text| try self.onText(text),
                .end => |end| try self.onEndElement(end),
            }
        }

        if (!self.saw_root or self.frames.items.len != 0 or self.in_package) {
            return error.InvalidPrimary;
        }

        if (self.declared_package_count) |declared_count| {
            if (declared_count != self.packages.items.len) {
                return error.InvalidPrimary;
            }
        }

        return .{
            .declared_package_count = self.declared_package_count,
            .packages = try self.packages.toOwnedSlice(),
            .relations = try self.relations.toOwnedSlice(),
        };
    }

    fn onStartElement(self: *Parser, element: sax.StartElement) Error!void {
        if (!self.saw_root) {
            if (!isCommonElement(element.name.ns_uri, element.name.local, "metadata")) {
                return error.InvalidPrimary;
            }

            self.saw_root = true;
            if (lookupAttr(element.attrs, "packages")) |package_count| {
                self.declared_package_count = try parseUnsigned(package_count);
            }
            try self.frames.append(Frame.init(self.allocator, .metadata));
            return;
        }

        if (self.frames.items.len == 0) {
            return error.InvalidPrimary;
        }

        const parent = self.frames.items[self.frames.items.len - 1];
        var frame = Frame.init(self.allocator, .other);

        if (isCommonNs(element.name.ns_uri)) {
            switch (parent.kind) {
                .metadata => {
                    if (std.mem.eql(u8, element.name.local, "package")) {
                        try self.startPackage(element);
                        frame.kind = .package;
                    }
                },
                .package => {
                    if (std.mem.eql(u8, element.name.local, "name")) {
                        frame.kind = .name;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "arch")) {
                        frame.kind = .arch;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "version")) {
                        try self.parseVersion(element.attrs);
                    } else if (std.mem.eql(u8, element.name.local, "checksum")) {
                        frame.kind = .checksum;
                        frame.collect_text = true;
                        frame.checksum_type = lookupAttr(element.attrs, "type") orelse return error.InvalidPrimary;
                        if (lookupAttr(element.attrs, "pkgid")) |pkgid_attr| {
                            frame.checksum_is_pkgid = try parseBoolean(pkgid_attr);
                        }
                    } else if (std.mem.eql(u8, element.name.local, "summary")) {
                        frame.kind = .summary;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "description")) {
                        frame.kind = .description;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "packager")) {
                        frame.kind = .packager;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "url")) {
                        frame.kind = .url;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "time")) {
                        try self.parseTime(element.attrs);
                    } else if (std.mem.eql(u8, element.name.local, "size")) {
                        try self.parseSize(element.attrs);
                    } else if (std.mem.eql(u8, element.name.local, "location")) {
                        try self.parseLocation(element.attrs);
                    } else if (std.mem.eql(u8, element.name.local, "format")) {
                        frame.kind = .format;
                    }
                },
                else => {},
            }
        } else if (isRpmNs(element.name.ns_uri)) {
            switch (parent.kind) {
                .format => {
                    if (std.mem.eql(u8, element.name.local, "license")) {
                        frame.kind = .license;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "vendor")) {
                        frame.kind = .vendor;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "group")) {
                        frame.kind = .group;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "buildhost")) {
                        frame.kind = .buildhost;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "sourcerpm")) {
                        frame.kind = .sourcerpm;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "header-range")) {
                        try self.parseHeaderRange(element.attrs);
                    } else if (dependencyKindFromLocal(element.name.local)) |kind| {
                        frame.kind = .dependency_container;
                        frame.dependency_kind = kind;
                    }
                },
                .dependency_container => {
                    if (std.mem.eql(u8, element.name.local, "entry")) {
                        const kind = parent.dependency_kind orelse return error.InvalidPrimary;
                        try self.parseDependencyEntry(kind, element.attrs);
                    }
                },
                else => {},
            }
        }

        try self.frames.append(frame);
    }

    fn onText(self: *Parser, text: []const u8) Error!void {
        if (self.frames.items.len == 0) return error.InvalidPrimary;

        const top = &self.frames.items[self.frames.items.len - 1];
        if (!top.collect_text) return;
        top.text.appendSlice(text) catch return error.OutOfMemory;
    }

    fn onEndElement(self: *Parser, element: sax.EndElement) Error!void {
        _ = element;
        if (self.frames.items.len == 0) return error.InvalidPrimary;

        try self.finishTopFrame();
        var frame = self.frames.pop() orelse return error.InvalidPrimary;
        frame.deinit();
    }

    fn finishTopFrame(self: *Parser) Error!void {
        const top = &self.frames.items[self.frames.items.len - 1];
        switch (top.kind) {
            .package => try self.finishPackage(),
            .name => try self.currentPackage().setRequiredString(&self.currentPackage().name, try copyRequiredText(self.allocator, top.text.items)),
            .arch => try self.currentPackage().setRequiredString(&self.currentPackage().arch, try copyRequiredText(self.allocator, top.text.items)),
            .checksum => try self.finishChecksum(top),
            .summary => self.currentPackage().setOptionalString(&self.currentPackage().summary, try copyOptionalText(self.allocator, top.text.items)),
            .description => self.currentPackage().setOptionalString(&self.currentPackage().description, try copyOptionalText(self.allocator, top.text.items)),
            .packager => self.currentPackage().setOptionalString(&self.currentPackage().packager, try copyOptionalText(self.allocator, top.text.items)),
            .url => self.currentPackage().setOptionalString(&self.currentPackage().url, try copyOptionalText(self.allocator, top.text.items)),
            .license => self.currentPackage().setOptionalString(&self.currentPackage().license, try copyOptionalText(self.allocator, top.text.items)),
            .vendor => self.currentPackage().setOptionalString(&self.currentPackage().vendor, try copyOptionalText(self.allocator, top.text.items)),
            .group => self.currentPackage().setOptionalString(&self.currentPackage().group, try copyOptionalText(self.allocator, top.text.items)),
            .buildhost => self.currentPackage().setOptionalString(&self.currentPackage().buildhost, try copyOptionalText(self.allocator, top.text.items)),
            .sourcerpm => self.currentPackage().setOptionalString(&self.currentPackage().source_rpm, try copyOptionalText(self.allocator, top.text.items)),
            else => {},
        }
    }

    fn startPackage(self: *Parser, element: sax.StartElement) Error!void {
        if (self.in_package) return error.InvalidPrimary;

        const package_type = lookupAttr(element.attrs, "type") orelse return error.InvalidPrimary;
        if (!std.mem.eql(u8, package_type, "rpm")) return error.InvalidPrimary;

        self.current_package = PackageBuilder.init(self.allocator);
        self.current_package.package_type_is_rpm = true;
        self.in_package = true;
    }

    fn finishPackage(self: *Parser) Error!void {
        if (!self.in_package) return error.InvalidPrimary;

        const package = try self.current_package.build(&self.relations);
        try self.packages.append(package);
        self.current_package.deinit();
        self.in_package = false;
    }

    fn currentPackage(self: *Parser) Error!*PackageBuilder {
        if (!self.in_package) return error.InvalidPrimary;
        return &self.current_package;
    }

    fn parseVersion(self: *Parser, attrs: []const sax.Attribute) Error!void {
        const builder = try self.currentPackage();
        if (builder.saw_version) return error.InvalidPrimary;

        const ver = lookupAttr(attrs, "ver") orelse return error.InvalidPrimary;
        const rel = lookupAttr(attrs, "rel") orelse return error.InvalidPrimary;
        const epoch = if (lookupAttr(attrs, "epoch")) |value|
            try parseOptionalUnsigned32(value)
        else
            null;

        builder.version = try model.dup(self.allocator, ver);
        builder.release = try model.dup(self.allocator, rel);
        builder.epoch = epoch;
        builder.saw_version = true;
    }

    fn parseTime(self: *Parser, attrs: []const sax.Attribute) Error!void {
        const builder = try self.currentPackage();
        if (builder.saw_time) return error.InvalidPrimary;

        if (lookupAttr(attrs, "file")) |file_attr| {
            builder.time.file = try parseUnsigned(file_attr);
        }
        if (lookupAttr(attrs, "build")) |build_attr| {
            builder.time.build = try parseUnsigned(build_attr);
        }

        builder.saw_time = true;
    }

    fn parseSize(self: *Parser, attrs: []const sax.Attribute) Error!void {
        const builder = try self.currentPackage();
        if (builder.saw_size) return error.InvalidPrimary;

        if (lookupAttr(attrs, "package")) |package_attr| {
            builder.size.package = try parseUnsigned(package_attr);
        }
        if (lookupAttr(attrs, "installed")) |installed_attr| {
            builder.size.installed = try parseUnsigned(installed_attr);
        }
        if (lookupAttr(attrs, "archive")) |archive_attr| {
            builder.size.archive = try parseUnsigned(archive_attr);
        }

        builder.saw_size = true;
    }

    fn parseLocation(self: *Parser, attrs: []const sax.Attribute) Error!void {
        const builder = try self.currentPackage();
        if (builder.saw_location) return error.InvalidPrimary;

        const href = lookupAttr(attrs, "href") orelse return error.InvalidPrimary;
        builder.location_href = try model.dup(self.allocator, href);
        if (lookupNsAttr(attrs, sax.XML_NS, "base")) |xml_base| {
            builder.location_xml_base = try model.dup(self.allocator, xml_base);
        }

        builder.saw_location = true;
    }

    fn parseHeaderRange(self: *Parser, attrs: []const sax.Attribute) Error!void {
        const builder = try self.currentPackage();
        if (builder.saw_header_range) return error.InvalidPrimary;

        const start = lookupAttr(attrs, "start") orelse return error.InvalidPrimary;
        const end = lookupAttr(attrs, "end") orelse return error.InvalidPrimary;
        builder.header_range = .{
            .start = try parseUnsigned(start),
            .end = try parseUnsigned(end),
        };
        builder.saw_header_range = true;
    }

    fn parseDependencyEntry(self: *Parser, kind: model.DependencyKind, attrs: []const sax.Attribute) Error!void {
        const builder = try self.currentPackage();
        const name = lookupAttr(attrs, "name") orelse return error.InvalidPrimary;
        const flags = lookupAttr(attrs, "flags");
        const relation = model.Relation{
            .name = try model.dup(self.allocator, name),
            .flags = if (flags) |value| try model.dup(self.allocator, value) else null,
            .comparison = if (flags) |value|
                model.compareOpFromFlags(value) orelse return error.InvalidPrimary
            else
                .none,
            .epoch = if (lookupAttr(attrs, "epoch")) |value|
                try parseOptionalUnsigned32(value)
            else
                null,
            .version = if (lookupAttr(attrs, "ver")) |value|
                try model.dup(self.allocator, value)
            else
                null,
            .release = if (lookupAttr(attrs, "rel")) |value|
                try model.dup(self.allocator, value)
            else
                null,
            .pre = if (lookupAttr(attrs, "pre")) |value|
                try parseBoolean(value)
            else
                false,
        };

        try builder.appendRelation(kind, relation);
    }

    fn finishChecksum(self: *Parser, top: *const Frame) Error!void {
        const builder = try self.currentPackage();
        if (builder.saw_checksum) return error.InvalidPrimary;

        const checksum_value = try copyRequiredText(self.allocator, top.text.items);
        const checksum_type = top.checksum_type orelse return error.InvalidPrimary;
        builder.checksum = .{
            .kind = try model.dup(self.allocator, checksum_type),
            .value = checksum_value,
            .is_pkgid = top.checksum_is_pkgid,
        };
        builder.saw_checksum = true;
    }
};

pub fn parse(allocator: std.mem.Allocator, input: []const u8) Error!model.ParsedPrimary {
    var parser = Parser.init(allocator);
    defer parser.deinit();
    return parser.parse(input);
}

fn dependencyKindFromLocal(local: []const u8) ?model.DependencyKind {
    if (std.mem.eql(u8, local, "provides")) return .provides;
    if (std.mem.eql(u8, local, "requires")) return .requires;
    if (std.mem.eql(u8, local, "conflicts")) return .conflicts;
    if (std.mem.eql(u8, local, "obsoletes")) return .obsoletes;
    if (std.mem.eql(u8, local, "recommends")) return .recommends;
    if (std.mem.eql(u8, local, "suggests")) return .suggests;
    if (std.mem.eql(u8, local, "supplements")) return .supplements;
    if (std.mem.eql(u8, local, "enhances")) return .enhances;
    return null;
}

fn isCommonNs(ns_uri: ?[]const u8) bool {
    const uri = ns_uri orelse return false;
    return std.mem.eql(u8, uri, COMMON_NS);
}

fn isRpmNs(ns_uri: ?[]const u8) bool {
    const uri = ns_uri orelse return false;
    return std.mem.eql(u8, uri, RPM_NS);
}

fn isCommonElement(ns_uri: ?[]const u8, local: []const u8, wanted: []const u8) bool {
    return isCommonNs(ns_uri) and std.mem.eql(u8, local, wanted);
}

fn lookupAttr(attrs: []const sax.Attribute, local: []const u8) ?[]const u8 {
    var index = attrs.len;
    while (index > 0) {
        index -= 1;
        const attr = attrs[index];
        if (attr.prefix.len == 0 and std.mem.eql(u8, attr.local, local)) {
            return attr.value;
        }
    }
    return null;
}

fn lookupNsAttr(attrs: []const sax.Attribute, ns_uri: []const u8, local: []const u8) ?[]const u8 {
    var index = attrs.len;
    while (index > 0) {
        index -= 1;
        const attr = attrs[index];
        const attr_ns = attr.ns_uri orelse continue;
        if (std.mem.eql(u8, attr_ns, ns_uri) and std.mem.eql(u8, attr.local, local)) {
            return attr.value;
        }
    }
    return null;
}

fn trimText(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, " \t\r\n");
}

fn copyRequiredText(allocator: std.mem.Allocator, text: []const u8) Error![]const u8 {
    const trimmed = trimText(text);
    if (trimmed.len == 0) return error.InvalidPrimary;
    return model.dup(allocator, trimmed) catch error.OutOfMemory;
}

fn copyOptionalText(allocator: std.mem.Allocator, text: []const u8) Error!?[]const u8 {
    const trimmed = trimText(text);
    if (trimmed.len == 0) return null;
    return model.dup(allocator, trimmed) catch error.OutOfMemory;
}

fn parseUnsigned(text: []const u8) Error!u64 {
    const trimmed = trimText(text);
    if (trimmed.len == 0) return error.InvalidPrimary;
    return std.fmt.parseInt(u64, trimmed, 10) catch error.InvalidPrimary;
}

fn parseOptionalUnsigned32(text: []const u8) Error!?u32 {
    const trimmed = trimText(text);
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(u32, trimmed, 10) catch error.InvalidPrimary;
}

fn parseBoolean(raw: []const u8) Error!bool {
    if (std.mem.eql(u8, raw, "1")) return true;
    if (std.mem.eql(u8, raw, "0")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "no")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "true")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "false")) return false;
    return error.InvalidPrimary;
}

fn expectOptionalString(expected: ?[]const u8, actual: ?[]const u8) !void {
    const testing = std.testing;

    if (expected) |text| {
        const actual_text = actual orelse return error.TestExpectedEqual;
        try testing.expectEqualStrings(text, actual_text);
    } else {
        try testing.expect(actual == null);
    }
}

test "parses primary packages with xml base scalars and dependency arrays" {
    const testing = std.testing;
    const xml =
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

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const parsed = try parse(arena_state.allocator(), xml);
    try testing.expectEqual(@as(?u64, 3), parsed.declared_package_count);
    try testing.expectEqual(@as(usize, 3), parsed.packages.len);

    const provides_pkg = parsed.packages[0];
    try testing.expectEqualStrings("tdnf-repoquery-provides", provides_pkg.nevra.name);
    try testing.expectEqual(@as(?u32, 0), provides_pkg.nevra.epoch);
    try testing.expectEqualStrings("1.0.1", provides_pkg.nevra.version);
    try testing.expectEqualStrings("2", provides_pkg.nevra.release);
    try testing.expectEqualStrings("aarch64", provides_pkg.nevra.arch);
    try testing.expectEqualStrings("sha256", provides_pkg.checksum.kind);
    try testing.expect(provides_pkg.checksum.is_pkgid);
    try testing.expectEqualStrings(provides_pkg.checksum.value, provides_pkg.pkg_id);
    try testing.expectEqualStrings("../pool", provides_pkg.location.xml_base.?);
    try testing.expectEqualStrings("tdnf-repoquery-provides-1.0.1-2.aarch64.rpm", provides_pkg.location.href);
    const resolved = try provides_pkg.location.resolve(arena_state.allocator());
    try testing.expectEqualStrings("../pool/tdnf-repoquery-provides-1.0.1-2.aarch64.rpm", resolved);
    try expectOptionalString("Repoquery Test", provides_pkg.summary);
    try expectOptionalString("VMware", provides_pkg.rpm.license);
    try expectOptionalString("VMware, Inc.", provides_pkg.rpm.vendor);
    try expectOptionalString("Applications/tdnftest", provides_pkg.rpm.group);
    try expectOptionalString("builder.example", provides_pkg.rpm.buildhost);
    try expectOptionalString("tdnf-repoquery-provides-1.0.1-2.src.rpm", provides_pkg.rpm.source_rpm);
    try testing.expectEqual(@as(?u64, 1783737155), provides_pkg.time.file);
    try testing.expectEqual(@as(?u64, 1783737154), provides_pkg.time.build);
    try testing.expectEqual(@as(?u64, 6932), provides_pkg.size.package);
    try testing.expectEqual(@as(?u64, 0), provides_pkg.size.installed);
    try testing.expectEqual(@as(?u64, 280), provides_pkg.size.archive);
    try testing.expectEqual(@as(u64, 4504), provides_pkg.rpm.header_range.?.start);
    try testing.expectEqual(@as(u64, 6817), provides_pkg.rpm.header_range.?.end);

    const provides = provides_pkg.relationsFor(.provides, parsed.relations);
    try testing.expectEqual(@as(usize, 2), provides.len);
    try testing.expectEqualStrings("tdnf-repoquery-base", provides[0].name);
    try testing.expect(provides[0].flags == null);
    try testing.expectEqual(model.CompareOp.none, provides[0].comparison);
    try testing.expectEqualStrings("tdnf-repoquery-provides", provides[1].name);
    try testing.expectEqualStrings("EQ", provides[1].flags.?);
    try testing.expectEqual(model.CompareOp.eq, provides[1].comparison);
    try testing.expectEqual(@as(?u32, 0), provides[1].epoch);
    try testing.expectEqualStrings("1.0.1", provides[1].version.?);
    try testing.expectEqualStrings("2", provides[1].release.?);
    try testing.expectEqual(@as(usize, 1), provides_pkg.relationsFor(.recommends, parsed.relations).len);

    const pretrans_pkg = parsed.packages[1];
    try testing.expect(pretrans_pkg.location.xml_base == null);
    try testing.expectEqual(@as(?u32, null), pretrans_pkg.nevra.epoch);
    const requires = pretrans_pkg.relationsFor(.requires, parsed.relations);
    try testing.expectEqual(@as(usize, 2), requires.len);
    try testing.expectEqualStrings("tdnf-dummy-pretrans", requires[0].name);
    try testing.expectEqualStrings("GE", requires[0].flags.?);
    try testing.expectEqual(model.CompareOp.ge, requires[0].comparison);
    try testing.expectEqual(@as(?u32, 0), requires[0].epoch);
    try testing.expectEqualStrings("1.0", requires[0].version.?);
    try testing.expectEqualStrings("1", requires[0].release.?);
    try testing.expect(requires[0].pre);
    try testing.expectEqualStrings("/bin/sh", requires[1].name);
    try testing.expect(!requires[1].pre);
    const obsoletes = pretrans_pkg.relationsFor(.obsoletes, parsed.relations);
    try testing.expectEqual(@as(usize, 1), obsoletes.len);
    try testing.expectEqualStrings("tdnf-old-pretrans", obsoletes[0].name);

    const conflicts_pkg = parsed.packages[2];
    const conflicts = conflicts_pkg.relationsFor(.conflicts, parsed.relations);
    try testing.expectEqual(@as(usize, 1), conflicts.len);
    try testing.expectEqualStrings("tdnf-repoquery-base", conflicts[0].name);
    try testing.expectEqual(@as(usize, 1), conflicts_pkg.relationsFor(.suggests, parsed.relations).len);
    try testing.expectEqual(@as(usize, 1), conflicts_pkg.relationsFor(.supplements, parsed.relations).len);
    try testing.expectEqual(@as(usize, 1), conflicts_pkg.relationsFor(.enhances, parsed.relations).len);
}

test "rejects missing required primary fields" {
    const testing = std.testing;

    const cases = [_][]const u8{
        \\<metadata xmlns="http://linux.duke.edu/metadata/common"><package type="rpm"><arch>aarch64</arch><version epoch="0" ver="1.0" rel="1"/><checksum type="sha256" pkgid="YES">deadbeef</checksum><location href="pkg.rpm"/></package></metadata>
        ,
        \\<metadata xmlns="http://linux.duke.edu/metadata/common"><package type="rpm"><name>pkg</name><arch>aarch64</arch><version epoch="0" ver="1.0" rel="1"/><checksum type="sha256" pkgid="YES">deadbeef</checksum></package></metadata>
        ,
        \\<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm"><package type="rpm"><name>pkg</name><arch>aarch64</arch><version epoch="0" ver="1.0" rel="1"/><checksum type="sha256" pkgid="NO">deadbeef</checksum><location href="pkg.rpm"/></package></metadata>
        ,
    };

    for (cases) |xml| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        try testing.expectError(error.InvalidPrimary, parse(arena_state.allocator(), xml));
    }
}

test "rejects malformed primary xml and invalid dependency flags" {
    const testing = std.testing;

    const malformed =
        \\<metadata xmlns="http://linux.duke.edu/metadata/common"><package type="rpm"><name>pkg</name><arch>aarch64</arch><version ver="1.0" rel="1"/><checksum type="sha256" pkgid="YES">abc</checksum><location href="pkg.rpm"></package></metadata>
    ;
    const bad_flags =
        \\<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm"><package type="rpm"><name>pkg</name><arch>aarch64</arch><version ver="1.0" rel="1"/><checksum type="sha256" pkgid="YES">abc</checksum><location href="pkg.rpm"/><format><rpm:requires><rpm:entry name="dep" flags="NE"/></rpm:requires></format></package></metadata>
    ;
    const bad_count =
        \\<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2"><package type="rpm"><name>pkg</name><arch>aarch64</arch><version ver="1.0" rel="1"/><checksum type="sha256" pkgid="YES">abc</checksum><location href="pkg.rpm"/></package></metadata>
    ;

    for ([_][]const u8{ malformed, bad_flags, bad_count }) |xml| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        try testing.expectError(error.InvalidPrimary, parse(arena_state.allocator(), xml));
    }
}
