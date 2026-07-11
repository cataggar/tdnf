const std = @import("std");
const shared_xml = @import("xml");
const sax = shared_xml.sax;
const model = @import("model.zig");

pub const Error = error{
    InvalidUpdateInfo,
    OutOfMemory,
};

const ElementKind = enum {
    other,
    root,
    update,
    id,
    title,
    severity,
    release,
    rights,
    description,
    references,
    pkglist,
    collection,
    collection_name,
    package,
    filename,
    reboot_suggested,
};

const Frame = struct {
    kind: ElementKind,
    collect_text: bool = false,
    text: std.array_list.Managed(u8),

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

const AdvisoryBuilder = struct {
    allocator: std.mem.Allocator,
    references_start: usize = 0,
    packages_start: usize = 0,
    raw_type: ?[]const u8 = null,
    kind: model.AdvisoryKind = .unknown,
    from: ?[]const u8 = null,
    status: ?[]const u8 = null,
    version: ?[]const u8 = null,
    id: ?[]const u8 = null,
    title: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    release: ?[]const u8 = null,
    rights: ?[]const u8 = null,
    issued: ?[]const u8 = null,
    updated: ?[]const u8 = null,
    description: ?[]const u8 = null,
    reboot_suggested: bool = false,

    fn init(allocator: std.mem.Allocator, references_start: usize, packages_start: usize) AdvisoryBuilder {
        return .{
            .allocator = allocator,
            .references_start = references_start,
            .packages_start = packages_start,
        };
    }

    fn setRequiredString(self: *AdvisoryBuilder, field: *?[]const u8, value: []const u8) Error!void {
        _ = self;
        if (field.* != null) return error.InvalidUpdateInfo;
        field.* = value;
    }

    fn setOptionalString(self: *AdvisoryBuilder, field: *?[]const u8, value: ?[]const u8) Error!void {
        _ = self;
        if (value) |text| {
            if (field.* != null) return error.InvalidUpdateInfo;
            field.* = text;
        }
    }

    fn build(self: *const AdvisoryBuilder, references_len: usize, packages_len: usize) Error!model.Advisory {
        return .{
            .id = self.id orelse return error.InvalidUpdateInfo,
            .raw_type = self.raw_type orelse return error.InvalidUpdateInfo,
            .kind = self.kind,
            .from = self.from,
            .status = self.status,
            .version = self.version,
            .title = self.title orelse return error.InvalidUpdateInfo,
            .severity = self.severity,
            .release = self.release,
            .rights = self.rights,
            .issued = self.issued orelse return error.InvalidUpdateInfo,
            .updated = self.updated,
            .description = self.description,
            .reboot_suggested = self.reboot_suggested,
            .references = .{
                .start = self.references_start,
                .len = references_len - self.references_start,
            },
            .packages = .{
                .start = self.packages_start,
                .len = packages_len - self.packages_start,
            },
        };
    }
};

const CollectionState = struct {
    short: ?[]const u8 = null,
    name: ?[]const u8 = null,
};

const AdvisoryPackageBuilder = struct {
    allocator: std.mem.Allocator,
    name: ?[]const u8 = null,
    arch: ?[]const u8 = null,
    epoch: ?u32 = null,
    version: ?[]const u8 = null,
    release: ?[]const u8 = null,
    src: ?[]const u8 = null,
    filename: ?[]const u8 = null,
    reboot_suggested: bool = false,

    fn init(allocator: std.mem.Allocator) AdvisoryPackageBuilder {
        return .{
            .allocator = allocator,
        };
    }

    fn setRequiredString(self: *AdvisoryPackageBuilder, field: *?[]const u8, value: []const u8) Error!void {
        _ = self;
        if (field.* != null) return error.InvalidUpdateInfo;
        field.* = value;
    }

    fn setOptionalString(self: *AdvisoryPackageBuilder, field: *?[]const u8, value: ?[]const u8) Error!void {
        _ = self;
        if (value) |text| {
            if (field.* != null) return error.InvalidUpdateInfo;
            field.* = text;
        }
    }

    fn build(self: *const AdvisoryPackageBuilder, collection: CollectionState) Error!model.AdvisoryPackage {
        return .{
            .collection_short = collection.short,
            .collection_name = collection.name,
            .nevra = .{
                .name = self.name orelse return error.InvalidUpdateInfo,
                .epoch = self.epoch,
                .version = self.version orelse return error.InvalidUpdateInfo,
                .release = self.release orelse return error.InvalidUpdateInfo,
                .arch = self.arch orelse return error.InvalidUpdateInfo,
            },
            .src = self.src,
            .filename = self.filename,
            .reboot_suggested = self.reboot_suggested,
        };
    }
};

const Parser = struct {
    allocator: std.mem.Allocator,
    frames: std.array_list.Managed(Frame),
    advisories: std.array_list.Managed(model.Advisory),
    references: std.array_list.Managed(model.AdvisoryReference),
    packages: std.array_list.Managed(model.AdvisoryPackage),
    current_advisory: AdvisoryBuilder = undefined,
    current_collection: CollectionState = .{},
    current_package: AdvisoryPackageBuilder = undefined,
    in_update: bool = false,
    in_collection: bool = false,
    in_package: bool = false,
    saw_root: bool = false,

    fn init(allocator: std.mem.Allocator) Parser {
        return .{
            .allocator = allocator,
            .frames = std.array_list.Managed(Frame).init(allocator),
            .advisories = std.array_list.Managed(model.Advisory).init(allocator),
            .references = std.array_list.Managed(model.AdvisoryReference).init(allocator),
            .packages = std.array_list.Managed(model.AdvisoryPackage).init(allocator),
        };
    }

    fn deinit(self: *Parser) void {
        for (self.frames.items) |*frame| {
            frame.deinit();
        }
        self.packages.deinit();
        self.references.deinit();
        self.advisories.deinit();
        self.frames.deinit();
    }

    fn parse(self: *Parser, input: []const u8) Error!model.ParsedUpdateInfo {
        var walker = sax.Walker.init(self.allocator, input);
        defer walker.deinit();

        while (true) {
            const maybe_event = walker.next() catch |err| return switch (err) {
                error.InvalidXml => error.InvalidUpdateInfo,
                error.OutOfMemory => error.OutOfMemory,
            };

            const event = maybe_event orelse break;
            switch (event) {
                .start => |start| try self.onStartElement(start),
                .text => |text| try self.onText(text),
                .end => |end| try self.onEndElement(end),
            }
        }

        if (!self.saw_root or self.frames.items.len != 0 or self.in_update or self.in_collection or self.in_package) {
            return error.InvalidUpdateInfo;
        }

        return .{
            .advisories = try self.advisories.toOwnedSlice(),
            .references = try self.references.toOwnedSlice(),
            .packages = try self.packages.toOwnedSlice(),
        };
    }

    fn onStartElement(self: *Parser, element: sax.StartElement) Error!void {
        if (!self.saw_root) {
            if (!isUpdateinfoElement(element.name.ns_uri, element.name.local, "updates")) {
                return error.InvalidUpdateInfo;
            }

            self.saw_root = true;
            try self.frames.append(Frame.init(self.allocator, .root));
            return;
        }

        if (self.frames.items.len == 0) {
            return error.InvalidUpdateInfo;
        }

        const parent = self.frames.items[self.frames.items.len - 1];
        var frame = Frame.init(self.allocator, .other);

        if (element.name.ns_uri == null) {
            switch (parent.kind) {
                .root => {
                    if (std.mem.eql(u8, element.name.local, "update")) {
                        try self.startAdvisory(element.attrs);
                        frame.kind = .update;
                    }
                },
                .update => {
                    if (std.mem.eql(u8, element.name.local, "id")) {
                        frame.kind = .id;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "title")) {
                        frame.kind = .title;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "severity")) {
                        frame.kind = .severity;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "release")) {
                        frame.kind = .release;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "rights")) {
                        frame.kind = .rights;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "description")) {
                        frame.kind = .description;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "issued")) {
                        try self.parseIssuedOrUpdated(element.attrs, true);
                    } else if (std.mem.eql(u8, element.name.local, "updated")) {
                        try self.parseIssuedOrUpdated(element.attrs, false);
                    } else if (std.mem.eql(u8, element.name.local, "references")) {
                        frame.kind = .references;
                    } else if (std.mem.eql(u8, element.name.local, "pkglist")) {
                        frame.kind = .pkglist;
                    }
                },
                .references => {
                    if (std.mem.eql(u8, element.name.local, "reference")) {
                        try self.parseReference(element.attrs);
                    }
                },
                .pkglist => {
                    if (std.mem.eql(u8, element.name.local, "collection")) {
                        try self.startCollection(element.attrs);
                        frame.kind = .collection;
                    }
                },
                .collection => {
                    if (std.mem.eql(u8, element.name.local, "name")) {
                        frame.kind = .collection_name;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "package")) {
                        try self.startPackage(element.attrs);
                        frame.kind = .package;
                    }
                },
                .package => {
                    if (std.mem.eql(u8, element.name.local, "filename")) {
                        frame.kind = .filename;
                        frame.collect_text = true;
                    } else if (std.mem.eql(u8, element.name.local, "reboot_suggested")) {
                        frame.kind = .reboot_suggested;
                        frame.collect_text = true;
                    }
                },
                else => {},
            }
        }

        try self.frames.append(frame);
    }

    fn onText(self: *Parser, text: []const u8) Error!void {
        if (self.frames.items.len == 0) {
            return error.InvalidUpdateInfo;
        }

        const top = &self.frames.items[self.frames.items.len - 1];
        if (!top.collect_text) return;
        top.text.appendSlice(text) catch return error.OutOfMemory;
    }

    fn onEndElement(self: *Parser, element: sax.EndElement) Error!void {
        _ = element;
        if (self.frames.items.len == 0) {
            return error.InvalidUpdateInfo;
        }

        try self.finishTopFrame();
        var frame = self.frames.pop() orelse return error.InvalidUpdateInfo;
        frame.deinit();
    }

    fn finishTopFrame(self: *Parser) Error!void {
        const top = &self.frames.items[self.frames.items.len - 1];
        switch (top.kind) {
            .update => try self.finishAdvisory(),
            .id => {
                const advisory = try self.currentAdvisory();
                try advisory.setRequiredString(&advisory.id, try copyRequiredText(self.allocator, top.text.items));
            },
            .title => {
                const advisory = try self.currentAdvisory();
                try advisory.setRequiredString(&advisory.title, try copyRequiredText(self.allocator, top.text.items));
            },
            .severity => {
                const advisory = try self.currentAdvisory();
                try advisory.setOptionalString(&advisory.severity, try copyOptionalText(self.allocator, top.text.items));
            },
            .release => {
                const advisory = try self.currentAdvisory();
                try advisory.setOptionalString(&advisory.release, try copyOptionalText(self.allocator, top.text.items));
            },
            .rights => {
                const advisory = try self.currentAdvisory();
                try advisory.setOptionalString(&advisory.rights, try copyOptionalText(self.allocator, top.text.items));
            },
            .description => {
                const advisory = try self.currentAdvisory();
                try advisory.setOptionalString(&advisory.description, try copyOptionalText(self.allocator, top.text.items));
            },
            .collection => try self.finishCollection(),
            .collection_name => {
                const collection = try self.currentCollection();
                if (collection.name != null) return error.InvalidUpdateInfo;
                collection.name = try copyRequiredText(self.allocator, top.text.items);
            },
            .package => try self.finishPackage(),
            .filename => {
                const pkg = try self.currentPackage();
                try pkg.setOptionalString(&pkg.filename, try copyOptionalText(self.allocator, top.text.items));
            },
            .reboot_suggested => {
                const pkg = try self.currentPackage();
                if (trimText(top.text.items).len == 0) return error.InvalidUpdateInfo;
                pkg.reboot_suggested = try parseBoolean(trimText(top.text.items));
            },
            else => {},
        }
    }

    fn startAdvisory(self: *Parser, attrs: []const sax.Attribute) Error!void {
        if (self.in_update or self.in_collection or self.in_package) return error.InvalidUpdateInfo;

        const raw_type = lookupAttr(attrs, "type") orelse return error.InvalidUpdateInfo;
        self.current_advisory = AdvisoryBuilder.init(self.allocator, self.references.items.len, self.packages.items.len);
        self.current_advisory.raw_type = try model.dup(self.allocator, raw_type);
        self.current_advisory.kind = model.advisoryKindFromType(raw_type);
        if (lookupAttr(attrs, "from")) |from| {
            self.current_advisory.from = try model.dup(self.allocator, from);
        }
        if (lookupAttr(attrs, "status")) |status| {
            self.current_advisory.status = try model.dup(self.allocator, status);
        }
        if (lookupAttr(attrs, "version")) |version| {
            self.current_advisory.version = try model.dup(self.allocator, version);
        }

        self.in_update = true;
    }

    fn finishAdvisory(self: *Parser) Error!void {
        if (!self.in_update or self.in_collection or self.in_package) {
            return error.InvalidUpdateInfo;
        }

        try self.advisories.append(try self.current_advisory.build(self.references.items.len, self.packages.items.len));
        self.in_update = false;
    }

    fn currentAdvisory(self: *Parser) Error!*AdvisoryBuilder {
        if (!self.in_update) return error.InvalidUpdateInfo;
        return &self.current_advisory;
    }

    fn parseIssuedOrUpdated(self: *Parser, attrs: []const sax.Attribute, issued: bool) Error!void {
        const advisory = try self.currentAdvisory();
        const date = lookupAttr(attrs, "date") orelse return error.InvalidUpdateInfo;
        const copy = try model.dup(self.allocator, date);
        if (issued) {
            if (advisory.issued != null) return error.InvalidUpdateInfo;
            advisory.issued = copy;
        } else {
            if (advisory.updated != null) return error.InvalidUpdateInfo;
            advisory.updated = copy;
        }
    }

    fn parseReference(self: *Parser, attrs: []const sax.Attribute) Error!void {
        const advisory = try self.currentAdvisory();
        _ = advisory;

        const raw_type = lookupAttr(attrs, "type");
        self.references.append(.{
            .kind = if (raw_type) |value| model.advisoryReferenceKindFromType(value) else .other,
            .raw_type = if (raw_type) |value| try model.dup(self.allocator, value) else null,
            .id = if (lookupAttr(attrs, "id")) |value| try model.dup(self.allocator, value) else null,
            .title = if (lookupAttr(attrs, "title")) |value| try model.dup(self.allocator, value) else null,
            .href = if (lookupAttr(attrs, "href")) |value| try model.dup(self.allocator, value) else null,
        }) catch return error.OutOfMemory;
    }

    fn startCollection(self: *Parser, attrs: []const sax.Attribute) Error!void {
        _ = try self.currentAdvisory();
        if (self.in_collection or self.in_package) return error.InvalidUpdateInfo;

        self.current_collection = .{};
        if (lookupAttr(attrs, "short")) |short| {
            self.current_collection.short = try model.dup(self.allocator, short);
        }
        self.in_collection = true;
    }

    fn finishCollection(self: *Parser) Error!void {
        if (!self.in_collection or self.in_package) {
            return error.InvalidUpdateInfo;
        }

        self.current_collection = .{};
        self.in_collection = false;
    }

    fn currentCollection(self: *Parser) Error!*CollectionState {
        if (!self.in_collection) return error.InvalidUpdateInfo;
        return &self.current_collection;
    }

    fn startPackage(self: *Parser, attrs: []const sax.Attribute) Error!void {
        _ = try self.currentCollection();
        if (self.in_package) return error.InvalidUpdateInfo;

        self.current_package = AdvisoryPackageBuilder.init(self.allocator);
        try self.current_package.setRequiredString(
            &self.current_package.name,
            try model.dup(self.allocator, lookupAttr(attrs, "name") orelse return error.InvalidUpdateInfo),
        );
        try self.current_package.setRequiredString(
            &self.current_package.arch,
            try model.dup(self.allocator, lookupAttr(attrs, "arch") orelse return error.InvalidUpdateInfo),
        );
        try self.current_package.setRequiredString(
            &self.current_package.version,
            try model.dup(self.allocator, lookupAttr(attrs, "version") orelse return error.InvalidUpdateInfo),
        );
        try self.current_package.setRequiredString(
            &self.current_package.release,
            try model.dup(self.allocator, lookupAttr(attrs, "release") orelse return error.InvalidUpdateInfo),
        );
        if (lookupAttr(attrs, "epoch")) |epoch| {
            self.current_package.epoch = try parseOptionalUnsigned32(epoch);
        }
        if (lookupAttr(attrs, "src")) |src| {
            self.current_package.src = try model.dup(self.allocator, src);
        }

        self.in_package = true;
    }

    fn finishPackage(self: *Parser) Error!void {
        if (!self.in_package) return error.InvalidUpdateInfo;

        const advisory = try self.currentAdvisory();
        const collection = try self.currentCollection();
        const pkg = try self.current_package.build(collection.*);
        if (pkg.reboot_suggested) {
            advisory.reboot_suggested = true;
        }

        self.packages.append(pkg) catch return error.OutOfMemory;
        self.in_package = false;
    }

    fn currentPackage(self: *Parser) Error!*AdvisoryPackageBuilder {
        if (!self.in_package) return error.InvalidUpdateInfo;
        return &self.current_package;
    }
};

pub fn parse(allocator: std.mem.Allocator, input: []const u8) Error!model.ParsedUpdateInfo {
    var parser = Parser.init(allocator);
    defer parser.deinit();
    return parser.parse(input);
}

fn isUpdateinfoElement(ns_uri: ?[]const u8, local: []const u8, wanted: []const u8) bool {
    return ns_uri == null and std.mem.eql(u8, local, wanted);
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

fn trimText(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, " \t\r\n");
}

fn copyRequiredText(allocator: std.mem.Allocator, text: []const u8) Error![]const u8 {
    const trimmed = trimText(text);
    if (trimmed.len == 0) return error.InvalidUpdateInfo;
    return model.dup(allocator, trimmed) catch error.OutOfMemory;
}

fn copyOptionalText(allocator: std.mem.Allocator, text: []const u8) Error!?[]const u8 {
    const trimmed = trimText(text);
    if (trimmed.len == 0) return null;
    return model.dup(allocator, trimmed) catch error.OutOfMemory;
}

fn parseOptionalUnsigned32(text: []const u8) Error!?u32 {
    const trimmed = trimText(text);
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(u32, trimmed, 10) catch error.InvalidUpdateInfo;
}

fn parseBoolean(raw: []const u8) Error!bool {
    if (std.mem.eql(u8, raw, "1")) return true;
    if (std.mem.eql(u8, raw, "0")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "no")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "true")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "false")) return false;
    return error.InvalidUpdateInfo;
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

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    return try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(std.math.maxInt(usize)),
    );
}

const fixture_one_path = "pytests/repo/updateinfo-1.xml";
const fixture_two_path = "pytests/repo/updateinfo-2.xml";

test "parses updateinfo fixture with references and package metadata" {
    const testing = std.testing;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const xml = try readFixture(arena_state.allocator(), fixture_one_path);
    const parsed = try parse(arena_state.allocator(), xml);

    try testing.expectEqual(@as(usize, 1), parsed.advisories.len);
    try testing.expectEqual(@as(usize, 2), parsed.references.len);
    try testing.expectEqual(@as(usize, 1), parsed.packages.len);

    const advisory = parsed.advisories[0];
    try testing.expectEqualStrings("DISCUS-2015-5-01", advisory.id);
    try testing.expectEqualStrings("bugfix", advisory.raw_type);
    try testing.expectEqual(model.AdvisoryKind.bugfix, advisory.kind);
    try expectOptionalString("discus-updates@project-discus.org", advisory.from);
    try expectOptionalString("stable", advisory.status);
    try expectOptionalString("1.0.2", advisory.version);
    try expectOptionalString("etcd", advisory.title);
    try expectOptionalString("Discus 1", advisory.release);
    try expectOptionalString("2015-05-01 12:00:00", advisory.issued);
    try testing.expect(advisory.updated == null);
    try expectOptionalString("update tdnf-test-multiversion to 1.0.2.", advisory.description);
    try testing.expect(!advisory.reboot_suggested);

    const refs = advisory.referenceEntries(parsed.references);
    try testing.expectEqual(@as(usize, 2), refs.len);
    try testing.expectEqual(model.AdvisoryReferenceKind.vendor, refs[0].kind);
    try expectOptionalString("vendor", refs[0].raw_type);
    try expectOptionalString("1", refs[0].id);
    try expectOptionalString("tdnf-test-multiversion spec file version 1.0.1", refs[0].title);
    try expectOptionalString("http://www.vmware.com", refs[0].href);
    try expectOptionalString("2", refs[1].id);
    try expectOptionalString("tdnf-test-multiversion spec file version 1.0.2", refs[1].title);

    const packages = advisory.packageEntries(parsed.packages);
    try testing.expectEqual(@as(usize, 1), packages.len);
    const pkg = packages[0];
    try expectOptionalString("DS-1", pkg.collection_short);
    try expectOptionalString("Discus 1", pkg.collection_name);
    try testing.expectEqualStrings("tdnf-test-multiversion", pkg.nevra.name);
    try testing.expectEqual(@as(?u32, 0), pkg.nevra.epoch);
    try testing.expectEqualStrings("1.0.2-1", pkg.nevra.version);
    try testing.expectEqualStrings("1.0.2", pkg.nevra.release);
    try testing.expectEqualStrings("x86_64", pkg.nevra.arch);
    try expectOptionalString(
        "file:///root/tdnf/tests/testroot/RPMS/x86_64/tdnf-test-multiversion-1.0.2-1.x86_64.rpm",
        pkg.src,
    );
    try expectOptionalString("tdnf-test-multiversion-1.0.2-1.x86_64.rpm", pkg.filename);
    try testing.expect(!pkg.reboot_suggested);
}

test "parses updateinfo fixture with severity rights updated date and reboot hint" {
    const testing = std.testing;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const xml = try readFixture(arena_state.allocator(), fixture_two_path);
    const parsed = try parse(arena_state.allocator(), xml);

    try testing.expectEqual(@as(usize, 1), parsed.advisories.len);
    try testing.expectEqual(@as(usize, 0), parsed.references.len);
    try testing.expectEqual(@as(usize, 1), parsed.packages.len);

    const advisory = parsed.advisories[0];
    try testing.expectEqualStrings("PHSA-2017-2.0-0001", advisory.id);
    try testing.expectEqualStrings("security", advisory.raw_type);
    try testing.expectEqual(model.AdvisoryKind.security, advisory.kind);
    try expectOptionalString("photonpublish@vmware.com", advisory.from);
    try expectOptionalString("stable", advisory.status);
    try expectOptionalString("1.0.2", advisory.version);
    try expectOptionalString("tdnf-test-multiversion", advisory.title);
    try expectOptionalString("7.5", advisory.severity);
    try expectOptionalString("1", advisory.release);
    try expectOptionalString("Copyright 2007 Company Inc", advisory.rights);
    try expectOptionalString("2007-12-28 16:42:30", advisory.issued);
    try expectOptionalString("2008-03-14 12:00:00", advisory.updated);
    try expectOptionalString("This update includes a fix for a denial-of-service issue.", advisory.description);
    try testing.expect(advisory.reboot_suggested);
    try testing.expectEqual(@as(usize, 0), advisory.referenceEntries(parsed.references).len);

    const packages = advisory.packageEntries(parsed.packages);
    try testing.expectEqual(@as(usize, 1), packages.len);
    const pkg = packages[0];
    try expectOptionalString("1", pkg.collection_short);
    try expectOptionalString("Photon 1", pkg.collection_name);
    try testing.expectEqualStrings("tdnf-test-multiversion", pkg.nevra.name);
    try testing.expectEqual(@as(?u32, null), pkg.nevra.epoch);
    try testing.expectEqualStrings("1.0.2", pkg.nevra.version);
    try testing.expectEqualStrings("1", pkg.nevra.release);
    try testing.expectEqualStrings("x86_64", pkg.nevra.arch);
    try testing.expect(pkg.src == null);
    try expectOptionalString("tdnf-test-multiversion-1.0.2-1.x86_64.rpm", pkg.filename);
    try testing.expect(pkg.reboot_suggested);
}

test "parses advisory with zero references and zero packages" {
    const testing = std.testing;
    const xml =
        \\<updates>
        \\  <update type="enhancement">
        \\    <id>UP-2026-0001</id>
        \\    <title>metadata-only advisory</title>
        \\    <issued date="2026-07-11 00:00:00"/>
        \\    <description/>
        \\  </update>
        \\</updates>
    ;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const parsed = try parse(arena_state.allocator(), xml);
    try testing.expectEqual(@as(usize, 1), parsed.advisories.len);
    try testing.expectEqual(@as(usize, 0), parsed.references.len);
    try testing.expectEqual(@as(usize, 0), parsed.packages.len);

    const advisory = parsed.advisories[0];
    try testing.expectEqual(model.AdvisoryKind.enhancement, advisory.kind);
    try testing.expectEqual(@as(usize, 0), advisory.referenceEntries(parsed.references).len);
    try testing.expectEqual(@as(usize, 0), advisory.packageEntries(parsed.packages).len);
    try testing.expect(advisory.description == null);
}

test "rejects malformed and incomplete updateinfo metadata" {
    const testing = std.testing;
    const cases = [_][]const u8{
        \\<updates><update type="security"><id>UP-1</id><title>x</title><issued date="2026-07-11 00:00:00"></update></updates>
        ,
        \\<updates><update><id>UP-1</id><title>x</title><issued date="2026-07-11 00:00:00"/></update></updates>
        ,
        \\<updates><update type="security"><id>UP-1</id><title>x</title><issued date="2026-07-11 00:00:00"/><pkglist><collection><package arch="x86_64" release="1" version="1.0"/></collection></pkglist></update></updates>
        ,
        \\<updates><update type="security"><id>UP-1</id><title>x</title><issued date="2026-07-11 00:00:00"/><pkglist><collection><package arch="x86_64" name="pkg" release="1" version="1.0"><reboot_suggested>maybe</reboot_suggested></package></collection></pkglist></update></updates>
        ,
    };

    for (cases) |xml| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        try testing.expectError(error.InvalidUpdateInfo, parse(arena_state.allocator(), xml));
    }
}
