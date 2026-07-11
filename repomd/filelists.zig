const std = @import("std");
const shared_xml = @import("xml");
const sax = shared_xml.sax;
const model = @import("model.zig");

const FILELISTS_NS = "http://linux.duke.edu/metadata/filelists";

pub const Error = error{
    InvalidFilelists,
    OutOfMemory,
};

const ElementKind = enum {
    other,
    root,
    package,
    file,
};

const Frame = struct {
    kind: ElementKind,
    collect_text: bool = false,
    text: std.array_list.Managed(u8),
    file_kind: model.FileKind = .plain,

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

const PackageState = struct {
    matched_index: ?usize = null,
    files_start: usize = 0,
    saw_version: bool = false,
};

const Parser = struct {
    allocator: std.mem.Allocator,
    parsed_primary: *model.ParsedPrimary,
    frames: std.array_list.Managed(Frame),
    files: std.array_list.Managed(model.FileEntry),
    package_index: std.StringHashMap(usize),
    seen_packages: []bool = &[_]bool{},
    current_package: PackageState = .{},
    in_package: bool = false,
    declared_package_count: ?u64 = null,
    seen_package_count: usize = 0,
    saw_root: bool = false,

    fn init(allocator: std.mem.Allocator, parsed_primary: *model.ParsedPrimary) Parser {
        return .{
            .allocator = allocator,
            .parsed_primary = parsed_primary,
            .frames = std.array_list.Managed(Frame).init(allocator),
            .files = std.array_list.Managed(model.FileEntry).init(allocator),
            .package_index = std.StringHashMap(usize).init(allocator),
        };
    }

    fn deinit(self: *Parser) void {
        if (self.seen_packages.len != 0) {
            self.allocator.free(self.seen_packages);
        }
        self.package_index.deinit();
        self.files.deinit();
        for (self.frames.items) |*frame| {
            frame.deinit();
        }
        self.frames.deinit();
    }

    fn parse(self: *Parser, input: []const u8) Error!void {
        try self.buildPackageIndex();

        var walker = sax.Walker.init(self.allocator, input);
        defer walker.deinit();

        while (true) {
            const maybe_event = walker.next() catch |err| return switch (err) {
                error.InvalidXml => error.InvalidFilelists,
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
            return error.InvalidFilelists;
        }

        if (self.declared_package_count) |declared_count| {
            if (declared_count != self.seen_package_count) {
                return error.InvalidFilelists;
            }
        }

        self.parsed_primary.files = try self.files.toOwnedSlice();
    }

    fn buildPackageIndex(self: *Parser) Error!void {
        try self.package_index.ensureTotalCapacity(@intCast(self.parsed_primary.packages.len));
        self.seen_packages = self.allocator.alloc(bool, self.parsed_primary.packages.len) catch
            return error.OutOfMemory;
        @memset(self.seen_packages, false);

        for (self.parsed_primary.packages, 0..) |pkg, index| {
            const gop = self.package_index.getOrPut(pkg.pkg_id) catch return error.OutOfMemory;
            if (gop.found_existing) {
                return error.InvalidFilelists;
            }
            gop.value_ptr.* = index;
        }
    }

    fn onStartElement(self: *Parser, element: sax.StartElement) Error!void {
        if (!self.saw_root) {
            if (!isFilelistsElement(element.name.ns_uri, element.name.local, "filelists")) {
                return error.InvalidFilelists;
            }

            self.saw_root = true;
            if (lookupAttr(element.attrs, "packages")) |package_count| {
                self.declared_package_count = try parseUnsigned(package_count);
            }
            try self.frames.append(Frame.init(self.allocator, .root));
            return;
        }

        if (self.frames.items.len == 0) {
            return error.InvalidFilelists;
        }

        const parent = self.frames.items[self.frames.items.len - 1];
        var frame = Frame.init(self.allocator, .other);

        if (isFilelistsNs(element.name.ns_uri)) {
            switch (parent.kind) {
                .root => {
                    if (std.mem.eql(u8, element.name.local, "package")) {
                        try self.startPackage(element.attrs);
                        frame.kind = .package;
                    }
                },
                .package => {
                    if (std.mem.eql(u8, element.name.local, "version")) {
                        try self.parseVersion(element.attrs);
                    } else if (std.mem.eql(u8, element.name.local, "file")) {
                        frame.kind = .file;
                        frame.collect_text = true;
                        frame.file_kind = try parseFileKind(lookupAttr(element.attrs, "type"));
                    }
                },
                else => {},
            }
        }

        try self.frames.append(frame);
    }

    fn onText(self: *Parser, text: []const u8) Error!void {
        if (self.frames.items.len == 0) {
            return error.InvalidFilelists;
        }

        const top = &self.frames.items[self.frames.items.len - 1];
        if (!top.collect_text) return;
        top.text.appendSlice(text) catch return error.OutOfMemory;
    }

    fn onEndElement(self: *Parser, element: sax.EndElement) Error!void {
        _ = element;
        if (self.frames.items.len == 0) {
            return error.InvalidFilelists;
        }

        try self.finishTopFrame();
        var frame = self.frames.pop() orelse return error.InvalidFilelists;
        frame.deinit();
    }

    fn finishTopFrame(self: *Parser) Error!void {
        const top = &self.frames.items[self.frames.items.len - 1];
        switch (top.kind) {
            .package => try self.finishPackage(),
            .file => try self.finishFile(top),
            else => {},
        }
    }

    fn startPackage(self: *Parser, attrs: []const sax.Attribute) Error!void {
        if (self.in_package) return error.InvalidFilelists;

        const pkg_id = lookupAttr(attrs, "pkgid") orelse return error.InvalidFilelists;
        _ = lookupAttr(attrs, "name") orelse return error.InvalidFilelists;
        _ = lookupAttr(attrs, "arch") orelse return error.InvalidFilelists;

        self.current_package = .{
            .matched_index = self.package_index.get(pkg_id),
            .files_start = self.files.items.len,
        };
        if (self.current_package.matched_index) |index| {
            if (self.seen_packages[index]) {
                return error.InvalidFilelists;
            }
            self.seen_packages[index] = true;
        }

        self.in_package = true;
        self.seen_package_count += 1;
    }

    fn finishPackage(self: *Parser) Error!void {
        if (!self.in_package or !self.current_package.saw_version) {
            return error.InvalidFilelists;
        }

        if (self.current_package.matched_index) |index| {
            const start = self.current_package.files_start;
            self.parsed_primary.packages[index].files = .{
                .start = start,
                .len = self.files.items.len - start,
            };
        }

        self.in_package = false;
    }

    fn parseVersion(self: *Parser, attrs: []const sax.Attribute) Error!void {
        if (!self.in_package or self.current_package.saw_version) {
            return error.InvalidFilelists;
        }

        _ = lookupAttr(attrs, "ver") orelse return error.InvalidFilelists;
        _ = lookupAttr(attrs, "rel") orelse return error.InvalidFilelists;
        if (lookupAttr(attrs, "epoch")) |value| {
            _ = try parseUnsigned(value);
        }

        self.current_package.saw_version = true;
    }

    fn finishFile(self: *Parser, top: *const Frame) Error!void {
        if (!self.in_package) {
            return error.InvalidFilelists;
        }

        const path = trimText(top.text.items);
        if (path.len == 0) {
            return error.InvalidFilelists;
        }

        if (self.current_package.matched_index == null) {
            return;
        }

        self.files.append(.{
            .path = try model.dup(self.allocator, path),
            .kind = top.file_kind,
        }) catch return error.OutOfMemory;
    }
};

pub fn parseAndApply(
    allocator: std.mem.Allocator,
    input: []const u8,
    parsed_primary: *model.ParsedPrimary,
) Error!void {
    var parser = Parser.init(allocator, parsed_primary);
    defer parser.deinit();
    return parser.parse(input);
}

fn isFilelistsNs(ns_uri: ?[]const u8) bool {
    const uri = ns_uri orelse return false;
    return std.mem.eql(u8, uri, FILELISTS_NS);
}

fn isFilelistsElement(ns_uri: ?[]const u8, local: []const u8, wanted: []const u8) bool {
    return isFilelistsNs(ns_uri) and std.mem.eql(u8, local, wanted);
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

fn parseUnsigned(text: []const u8) Error!u64 {
    const trimmed = trimText(text);
    if (trimmed.len == 0) {
        return error.InvalidFilelists;
    }
    return std.fmt.parseInt(u64, trimmed, 10) catch error.InvalidFilelists;
}

fn parseFileKind(raw_type: ?[]const u8) Error!model.FileKind {
    const kind = raw_type orelse return .plain;
    if (std.mem.eql(u8, kind, "file")) return .plain;
    if (std.mem.eql(u8, kind, "dir")) return .dir;
    if (std.mem.eql(u8, kind, "ghost")) return .ghost;
    return error.InvalidFilelists;
}

fn parsePrimaryFixture(allocator: std.mem.Allocator) !model.ParsedPrimary {
    const primary = @import("primary.zig");
    const xml =
        \\<metadata xmlns="http://linux.duke.edu/metadata/common" packages="3">
        \\  <package type="rpm">
        \\    <name>pkg-one</name>
        \\    <arch>aarch64</arch>
        \\    <version epoch="0" ver="1.0" rel="1"/>
        \\    <checksum type="sha256" pkgid="YES">pkgid-one</checksum>
        \\    <location href="pkg-one.rpm"/>
        \\  </package>
        \\  <package type="rpm">
        \\    <name>pkg-two</name>
        \\    <arch>aarch64</arch>
        \\    <version ver="2.0" rel="3"/>
        \\    <checksum type="sha256" pkgid="YES">pkgid-two</checksum>
        \\    <location href="pkg-two.rpm"/>
        \\  </package>
        \\  <package type="rpm">
        \\    <name>pkg-three</name>
        \\    <arch>noarch</arch>
        \\    <version ver="4.0" rel="5"/>
        \\    <checksum type="sha256" pkgid="YES">pkgid-three</checksum>
        \\    <location href="pkg-three.rpm"/>
        \\  </package>
        \\</metadata>
    ;

    return primary.parse(allocator, xml);
}

test "parses filelists entries and tolerates zero and partial coverage" {
    const testing = std.testing;
    const xml =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="2">
        \\  <package pkgid="pkgid-one" name="pkg-one" arch="aarch64">
        \\    <version epoch="0" ver="1.0" rel="1"/>
        \\    <file>/usr/bin/pkg-one</file>
        \\    <file type="dir">/usr/share/pkg-one</file>
        \\    <file type="ghost">/var/lib/pkg-one.cache</file>
        \\  </package>
        \\  <package pkgid="pkgid-two" name="pkg-two" arch="aarch64">
        \\    <version ver="2.0" rel="3"/>
        \\  </package>
        \\</filelists>
    ;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var parsed = try parsePrimaryFixture(arena_state.allocator());
    try testing.expectEqual(@as(usize, 0), parsed.files.len);

    try parseAndApply(arena_state.allocator(), xml, &parsed);
    try testing.expectEqual(@as(usize, 3), parsed.files.len);

    const first_files = parsed.packages[0].fileEntries(parsed.files);
    try testing.expectEqual(@as(usize, 3), first_files.len);
    try testing.expectEqualStrings("/usr/bin/pkg-one", first_files[0].path);
    try testing.expectEqual(model.FileKind.plain, first_files[0].kind);
    try testing.expectEqualStrings("/usr/share/pkg-one", first_files[1].path);
    try testing.expectEqual(model.FileKind.dir, first_files[1].kind);
    try testing.expectEqualStrings("/var/lib/pkg-one.cache", first_files[2].path);
    try testing.expectEqual(model.FileKind.ghost, first_files[2].kind);

    try testing.expectEqual(@as(usize, 0), parsed.packages[1].fileEntries(parsed.files).len);
    try testing.expectEqual(@as(usize, 0), parsed.packages[2].fileEntries(parsed.files).len);
}

test "rejects malformed or incomplete filelists metadata" {
    const testing = std.testing;
    const cases = [_][]const u8{
        \\<filelists xmlns="http://linux.duke.edu/metadata/filelists"><package name="pkg-one" arch="aarch64"><version ver="1.0" rel="1"/></package></filelists>
        ,
        \\<filelists xmlns="http://linux.duke.edu/metadata/filelists"><package pkgid="pkgid-one" name="pkg-one" arch="aarch64"><version ver="1.0" rel="1"/><file type="weird">/usr/bin/pkg-one</file></package></filelists>
        ,
        \\<filelists xmlns="http://linux.duke.edu/metadata/filelists"><package pkgid="pkgid-one" name="pkg-one" arch="aarch64"><version ver="1.0" rel="1"><file>/usr/bin/pkg-one</file></package></filelists>
        ,
    };

    for (cases) |xml| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();

        var parsed = try parsePrimaryFixture(arena_state.allocator());
        try testing.expectError(error.InvalidFilelists, parseAndApply(arena_state.allocator(), xml, &parsed));
    }
}
