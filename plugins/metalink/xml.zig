//! Pure-Zig metalink XML parser backed by the shared SAX core.
//!
//! This parser intentionally supports only the metalink 3.0/4.0 subset
//! that the metalink plugin consumes. It keeps the existing C ABI and
//! forward-only callback surface for file/size/hash/url records.

const std = @import("std");
const shared_xml = @import("xml");
const sax = shared_xml.sax;

pub const ERROR_TDNF_OUT_OF_MEMORY: u32 = 1612;
pub const ERROR_TDNF_INVALID_PARAMETER: u32 = 1622;
pub const ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT: u32 = 2701;
pub const ERROR_TDNF_METALINK_PARSER_INVALID_ROOT_ELEMENT: u32 = 2702;
pub const ERROR_TDNF_METALINK_PARSER_MISSING_FILE_ATTR: u32 = 2703;
pub const ERROR_TDNF_METALINK_PARSER_MISSING_HASH_ATTR: u32 = 2706;
pub const ERROR_TDNF_METALINK_PARSER_MISSING_HASH_CONTENT: u32 = 2707;
pub const ERROR_TDNF_METALINK_PARSER_MISSING_URL_ATTR: u32 = 2708;
pub const ERROR_TDNF_METALINK_PARSER_MISSING_URL_CONTENT: u32 = 2709;

const METALINK_NS_V3 = "http://www.metalinker.org/";
const METALINK_NS_V4 = "urn:ietf:params:xml:ns:metalink";
const EMPTY_TEXT = [1]u8{0};

pub const TDNF_ML_ON_FILE = *const fn (
    ctx: ?*anyopaque,
    name: [*:0]const u8,
) callconv(.c) u32;

pub const TDNF_ML_ON_SIZE = *const fn (
    ctx: ?*anyopaque,
    text: [*]const u8,
    len: usize,
) callconv(.c) u32;

pub const TDNF_ML_ON_HASH = *const fn (
    ctx: ?*anyopaque,
    hash_type: [*:0]const u8,
    text: [*]const u8,
    len: usize,
) callconv(.c) u32;

pub const TDNF_ML_ON_URL = *const fn (
    ctx: ?*anyopaque,
    protocol: ?[*:0]const u8,
    url_type: ?[*:0]const u8,
    location: ?[*:0]const u8,
    ranking_attr: ?[*:0]const u8,
    ranking_is_priority: bool,
    text: [*]const u8,
    len: usize,
) callconv(.c) u32;

pub const TDNF_METALINK_XML_CALLBACKS = extern struct {
    pfnFile: ?TDNF_ML_ON_FILE,
    pfnSize: ?TDNF_ML_ON_SIZE,
    pfnHash: ?TDNF_ML_ON_HASH,
    pfnUrl: ?TDNF_ML_ON_URL,
};

const ParseError = error{
    ParseFailed,
    OutOfMemory,
};

const Version = enum { unknown, v3, v4 };
const NamespaceKind = enum { none, v3, v4, other };
const ElementKind = enum {
    other,
    root,
    files,
    file,
    verification,
    resources,
    size,
    hash,
    url,
};

const Frame = struct {
    kind: ElementKind,
    collect_text: bool = false,
    text: std.array_list.Managed(u8),
    hash_type: ?[:0]const u8 = null,
    url_protocol: ?[:0]const u8 = null,
    url_type: ?[:0]const u8 = null,
    url_location: ?[:0]const u8 = null,
    url_ranking: ?[:0]const u8 = null,
    url_ranking_is_priority: bool = false,
};

const Parser = struct {
    allocator: std.mem.Allocator,
    callbacks: *const TDNF_METALINK_XML_CALLBACKS,
    ctx: ?*anyopaque,
    frames: std.array_list.Managed(Frame),
    version: Version = .unknown,
    saw_root: bool = false,
    error_code: u32 = 0,

    fn init(
        allocator: std.mem.Allocator,
        callbacks: *const TDNF_METALINK_XML_CALLBACKS,
        ctx: ?*anyopaque,
    ) Parser {
        return .{
            .allocator = allocator,
            .callbacks = callbacks,
            .ctx = ctx,
            .frames = std.array_list.Managed(Frame).init(allocator),
        };
    }

    fn fail(self: *Parser, code: u32) ParseError {
        self.error_code = code;
        return error.ParseFailed;
    }

    fn parse(self: *Parser, input: []const u8) ParseError!void {
        var walker = sax.Walker.init(self.allocator, input);
        defer walker.deinit();

        while (true) {
            const maybe_event = walker.next() catch |err| return switch (err) {
                error.InvalidXml => self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT),
                error.OutOfMemory => error.OutOfMemory,
            };

            const event = maybe_event orelse break;
            switch (event) {
                .start => |start| try self.onStartElement(start),
                .text => |text| try self.onText(text),
                .end => |end| try self.onEndElement(end),
            }
        }

        if (!self.saw_root or self.frames.items.len != 0) {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }
    }

    fn onStartElement(self: *Parser, element: sax.StartElement) ParseError!void {
        const ns_kind = namespaceKind(element.name.ns_uri);

        var kind: ElementKind = .other;
        if (!self.saw_root) {
            if (!std.mem.eql(u8, element.name.local, "metalink")) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_ROOT_ELEMENT);
            }
            switch (ns_kind) {
                .v3 => self.version = .v3,
                .v4 => self.version = .v4,
                else => return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_ROOT_ELEMENT),
            }
            self.saw_root = true;
            kind = .root;
        } else {
            if (self.frames.items.len == 0) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }
            kind = self.classifyElement(ns_kind, element.name.local);
        }

        var frame = Frame{
            .kind = kind,
            .text = std.array_list.Managed(u8).init(self.allocator),
        };

        switch (kind) {
            .file => {
                const name = lookupAttr(element.attrs, "name") orelse
                    return self.fail(ERROR_TDNF_METALINK_PARSER_MISSING_FILE_ATTR);
                const name_z = try self.allocZ(name);
                if (self.callbacks.pfnFile) |cb| {
                    const rc = cb(self.ctx, name_z.ptr);
                    if (rc != 0) return self.fail(rc);
                }
            },
            .size => frame.collect_text = true,
            .hash => {
                frame.collect_text = true;
                const hash_type = lookupAttr(element.attrs, "type") orelse
                    return self.fail(ERROR_TDNF_METALINK_PARSER_MISSING_HASH_ATTR);
                frame.hash_type = try self.allocZ(hash_type);
            },
            .url => {
                frame.collect_text = true;
                frame.url_protocol = try self.allocOptZ(lookupAttr(element.attrs, "protocol"));
                frame.url_type = try self.allocOptZ(lookupAttr(element.attrs, "type"));
                frame.url_location = try self.allocOptZ(lookupAttr(element.attrs, "location"));
                if (self.version == .v4) {
                    frame.url_ranking = try self.allocOptZ(lookupAttr(element.attrs, "priority"));
                    frame.url_ranking_is_priority = true;
                } else {
                    frame.url_ranking = try self.allocOptZ(lookupAttr(element.attrs, "preference"));
                }
            },
            else => {},
        }

        try self.frames.append(frame);
    }

    fn onText(self: *Parser, text: []const u8) ParseError!void {
        if (self.frames.items.len == 0) {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }

        const top = &self.frames.items[self.frames.items.len - 1];
        if (!top.collect_text) return;
        try top.text.appendSlice(text);
    }

    fn onEndElement(self: *Parser, element: sax.EndElement) ParseError!void {
        _ = element;
        if (self.frames.items.len == 0) {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }

        try self.finishTopFrame();
        self.frames.items.len -= 1;
    }

    fn finishTopFrame(self: *Parser) ParseError!void {
        const top = &self.frames.items[self.frames.items.len - 1];
        switch (top.kind) {
            .size => {
                if (self.callbacks.pfnSize) |cb| {
                    const rc = cb(self.ctx, textPtr(top.text.items), top.text.items.len);
                    if (rc != 0) return self.fail(rc);
                }
            },
            .hash => {
                if (self.callbacks.pfnHash) |cb| {
                    const rc = cb(self.ctx, top.hash_type.?.ptr, textPtr(top.text.items), top.text.items.len);
                    if (rc != 0) return self.fail(rc);
                }
            },
            .url => {
                if (self.callbacks.pfnUrl) |cb| {
                    const rc = cb(
                        self.ctx,
                        optTextPtr(top.url_protocol),
                        optTextPtr(top.url_type),
                        optTextPtr(top.url_location),
                        optTextPtr(top.url_ranking),
                        top.url_ranking_is_priority,
                        textPtr(top.text.items),
                        top.text.items.len,
                    );
                    if (rc != 0) return self.fail(rc);
                }
            },
            else => {},
        }
    }

    fn classifyElement(self: *Parser, ns_kind: NamespaceKind, local: []const u8) ElementKind {
        const wanted_ns = switch (self.version) {
            .v3 => NamespaceKind.v3,
            .v4 => NamespaceKind.v4,
            .unknown => return .other,
        };
        if (ns_kind != wanted_ns) return .other;

        const parent = self.frames.items[self.frames.items.len - 1].kind;
        return switch (self.version) {
            .v3 => switch (parent) {
                .root => if (std.mem.eql(u8, local, "files")) .files else .other,
                .files => if (std.mem.eql(u8, local, "file")) .file else .other,
                .file => blk: {
                    if (std.mem.eql(u8, local, "size")) break :blk .size;
                    if (std.mem.eql(u8, local, "verification")) break :blk .verification;
                    if (std.mem.eql(u8, local, "resources")) break :blk .resources;
                    break :blk .other;
                },
                .verification => if (std.mem.eql(u8, local, "hash")) .hash else .other,
                .resources => if (std.mem.eql(u8, local, "url")) .url else .other,
                else => .other,
            },
            .v4 => switch (parent) {
                .root => if (std.mem.eql(u8, local, "file")) .file else .other,
                .file => blk: {
                    if (std.mem.eql(u8, local, "size")) break :blk .size;
                    if (std.mem.eql(u8, local, "hash")) break :blk .hash;
                    if (std.mem.eql(u8, local, "url")) break :blk .url;
                    break :blk .other;
                },
                else => .other,
            },
            .unknown => .other,
        };
    }

    fn allocZ(self: *Parser, bytes: []const u8) ParseError![:0]const u8 {
        const out = self.allocator.allocSentinel(u8, bytes.len, 0) catch return error.OutOfMemory;
        @memcpy(out[0..bytes.len], bytes);
        return out;
    }

    fn allocOptZ(self: *Parser, bytes: ?[]const u8) ParseError!?[:0]const u8 {
        if (bytes) |value| {
            return try self.allocZ(value);
        }
        return null;
    }
};

export fn TDNFMetalinkXmlParseBuffer(
    buf: ?[*]const u8,
    len: usize,
    cbs: ?*const TDNF_METALINK_XML_CALLBACKS,
    ctx: ?*anyopaque,
) u32 {
    const callbacks = cbs orelse return ERROR_TDNF_INVALID_PARAMETER;
    const data_ptr = buf orelse return ERROR_TDNF_INVALID_PARAMETER;
    if (len == 0) return ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), callbacks, ctx);
    parser.parse(data_ptr[0..len]) catch |err| return switch (err) {
        error.ParseFailed => parser.error_code,
        error.OutOfMemory => ERROR_TDNF_OUT_OF_MEMORY,
    };
    return 0;
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

fn namespaceKind(uri: ?[]const u8) NamespaceKind {
    const ns = uri orelse return .none;
    if (ns.len == 0) return .none;
    if (std.mem.eql(u8, ns, METALINK_NS_V3)) return .v3;
    if (std.mem.eql(u8, ns, METALINK_NS_V4)) return .v4;
    return .other;
}

fn textPtr(text: []const u8) [*]const u8 {
    if (text.len == 0) {
        return @as([*]const u8, @ptrCast(&EMPTY_TEXT));
    }
    return text.ptr;
}

fn optTextPtr(text: ?[:0]const u8) ?[*:0]const u8 {
    if (text) |value| return value.ptr;
    return null;
}

const HashSeen = struct {
    hash_type: []const u8,
    value: []const u8,
};

const UrlSeen = struct {
    protocol: ?[]const u8,
    url_type: ?[]const u8,
    location: ?[]const u8,
    ranking_attr: ?[]const u8,
    ranking_is_priority: bool,
    value: []const u8,
};

const Recorder = struct {
    allocator: std.mem.Allocator,
    files: std.array_list.Managed([]const u8),
    sizes: std.array_list.Managed([]const u8),
    hashes: std.array_list.Managed(HashSeen),
    urls: std.array_list.Managed(UrlSeen),

    fn init(allocator: std.mem.Allocator) Recorder {
        return .{
            .allocator = allocator,
            .files = std.array_list.Managed([]const u8).init(allocator),
            .sizes = std.array_list.Managed([]const u8).init(allocator),
            .hashes = std.array_list.Managed(HashSeen).init(allocator),
            .urls = std.array_list.Managed(UrlSeen).init(allocator),
        };
    }

    fn recordFile(self: *Recorder, name: [*:0]const u8) u32 {
        const dup = self.allocator.dupe(u8, std.mem.span(name)) catch return ERROR_TDNF_OUT_OF_MEMORY;
        self.files.append(dup) catch return ERROR_TDNF_OUT_OF_MEMORY;
        return 0;
    }

    fn recordSize(self: *Recorder, text: [*]const u8, len: usize) u32 {
        const dup = self.allocator.dupe(u8, text[0..len]) catch return ERROR_TDNF_OUT_OF_MEMORY;
        self.sizes.append(dup) catch return ERROR_TDNF_OUT_OF_MEMORY;
        return 0;
    }

    fn recordHash(self: *Recorder, hash_type: [*:0]const u8, text: [*]const u8, len: usize) u32 {
        const type_dup = self.allocator.dupe(u8, std.mem.span(hash_type)) catch return ERROR_TDNF_OUT_OF_MEMORY;
        const value_dup = self.allocator.dupe(u8, text[0..len]) catch return ERROR_TDNF_OUT_OF_MEMORY;
        self.hashes.append(.{
            .hash_type = type_dup,
            .value = value_dup,
        }) catch return ERROR_TDNF_OUT_OF_MEMORY;
        return 0;
    }

    fn recordUrl(
        self: *Recorder,
        protocol: ?[*:0]const u8,
        url_type: ?[*:0]const u8,
        location: ?[*:0]const u8,
        ranking_attr: ?[*:0]const u8,
        ranking_is_priority: bool,
        text: [*]const u8,
        len: usize,
    ) u32 {
        const value_dup = self.allocator.dupe(u8, text[0..len]) catch return ERROR_TDNF_OUT_OF_MEMORY;
        const protocol_dup = dupOptionalCString(self.allocator, protocol) catch return ERROR_TDNF_OUT_OF_MEMORY;
        const type_dup = dupOptionalCString(self.allocator, url_type) catch return ERROR_TDNF_OUT_OF_MEMORY;
        const location_dup = dupOptionalCString(self.allocator, location) catch return ERROR_TDNF_OUT_OF_MEMORY;
        const ranking_dup = dupOptionalCString(self.allocator, ranking_attr) catch return ERROR_TDNF_OUT_OF_MEMORY;

        self.urls.append(.{
            .protocol = protocol_dup,
            .url_type = type_dup,
            .location = location_dup,
            .ranking_attr = ranking_dup,
            .ranking_is_priority = ranking_is_priority,
            .value = value_dup,
        }) catch return ERROR_TDNF_OUT_OF_MEMORY;
        return 0;
    }
};

fn dupOptionalCString(
    allocator: std.mem.Allocator,
    text: ?[*:0]const u8,
) std.mem.Allocator.Error!?[]const u8 {
    if (text) |value| {
        return try allocator.dupe(u8, std.mem.span(value));
    }
    return null;
}

fn testRecorder(ctx: ?*anyopaque) *Recorder {
    return @ptrCast(@alignCast(ctx.?));
}

fn testOnFile(ctx: ?*anyopaque, name: [*:0]const u8) callconv(.c) u32 {
    return testRecorder(ctx).recordFile(name);
}

fn testOnSize(ctx: ?*anyopaque, text: [*]const u8, len: usize) callconv(.c) u32 {
    return testRecorder(ctx).recordSize(text, len);
}

fn testOnHash(
    ctx: ?*anyopaque,
    hash_type: [*:0]const u8,
    text: [*]const u8,
    len: usize,
) callconv(.c) u32 {
    return testRecorder(ctx).recordHash(hash_type, text, len);
}

fn testOnUrl(
    ctx: ?*anyopaque,
    protocol: ?[*:0]const u8,
    url_type: ?[*:0]const u8,
    location: ?[*:0]const u8,
    ranking_attr: ?[*:0]const u8,
    ranking_is_priority: bool,
    text: [*]const u8,
    len: usize,
) callconv(.c) u32 {
    return testRecorder(ctx).recordUrl(
        protocol,
        url_type,
        location,
        ranking_attr,
        ranking_is_priority,
        text,
        len,
    );
}

fn parseWithRecorder(xml: []const u8, recorder: *Recorder) u32 {
    const callbacks = TDNF_METALINK_XML_CALLBACKS{
        .pfnFile = testOnFile,
        .pfnSize = testOnSize,
        .pfnHash = testOnHash,
        .pfnUrl = testOnUrl,
    };
    return TDNFMetalinkXmlParseBuffer(xml.ptr, xml.len, &callbacks, @ptrCast(recorder));
}

fn parseWithNullCallbacks(xml: []const u8) u32 {
    const callbacks = TDNF_METALINK_XML_CALLBACKS{
        .pfnFile = null,
        .pfnSize = null,
        .pfnHash = null,
        .pfnUrl = null,
    };
    return TDNFMetalinkXmlParseBuffer(xml.ptr, xml.len, &callbacks, null);
}

fn validateHashContent(
    ctx: ?*anyopaque,
    hash_type: [*:0]const u8,
    text: [*]const u8,
    len: usize,
) callconv(.c) u32 {
    _ = ctx;
    _ = hash_type;

    if (text[0..len].len == 0) {
        return ERROR_TDNF_METALINK_PARSER_MISSING_HASH_CONTENT;
    }

    return 0;
}

fn validateUrlContentAndRanking(
    ctx: ?*anyopaque,
    protocol: ?[*:0]const u8,
    url_type: ?[*:0]const u8,
    location: ?[*:0]const u8,
    ranking_attr: ?[*:0]const u8,
    ranking_is_priority: bool,
    text: [*]const u8,
    len: usize,
) callconv(.c) u32 {
    _ = ctx;
    _ = protocol;
    _ = url_type;
    _ = location;

    if (text[0..len].len == 0) {
        return ERROR_TDNF_METALINK_PARSER_MISSING_URL_CONTENT;
    }

    if (ranking_attr) |attr| {
        const value = std.fmt.parseInt(i64, std.mem.span(attr), 10) catch
            return ERROR_TDNF_INVALID_PARAMETER;

        if (ranking_is_priority) {
            if (value <= 0 or value >= std.math.maxInt(c_int)) {
                return ERROR_TDNF_METALINK_PARSER_MISSING_URL_ATTR;
            }
        } else if (value < 0 or value > 100) {
            return ERROR_TDNF_METALINK_PARSER_MISSING_URL_ATTR;
        }
    }

    return 0;
}

fn parseWithValidationCallbacks(xml: []const u8) u32 {
    const callbacks = TDNF_METALINK_XML_CALLBACKS{
        .pfnFile = null,
        .pfnSize = null,
        .pfnHash = validateHashContent,
        .pfnUrl = validateUrlContentAndRanking,
    };
    return TDNFMetalinkXmlParseBuffer(xml.ptr, xml.len, &callbacks, null);
}

fn expectOptionalString(expected: ?[]const u8, actual: ?[]const u8) !void {
    const testing = std.testing;

    if (expected) |want| {
        const got = actual orelse return error.TestExpectedEqual;
        try testing.expectEqualStrings(want, got);
    } else {
        try testing.expect(actual == null);
    }
}

fn readFixture(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]const u8 {
    return try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(std.math.maxInt(usize)),
    );
}

const metalink_v3_fixture_path = "pytests/fixtures/metalink/real-world-v3.xml";

const metalink_v4_fixture_path = "pytests/fixtures/metalink/priority-v4.xml";

const setup_repo_fixture_path = "pytests/fixtures/metalink/photon-setup.xml";

const entity_fixture =
    \\<metalink xmlns="urn:ietf:params:xml:ns:metalink">
    \\  <file name="repomd.xml">
    \\    <hash type="escaped">A&amp;B&lt;C&gt;D&quot;E&apos;F&#33;&#x3F;</hash>
    \\  </file>
    \\</metalink>
;

test "callbacks struct uses the C ABI pointer layout" {
    const testing = std.testing;
    const pointer_size = @sizeOf(?TDNF_ML_ON_FILE);

    try testing.expectEqual(4 * pointer_size, @sizeOf(TDNF_METALINK_XML_CALLBACKS));
    try testing.expectEqual(@as(usize, 0), @offsetOf(TDNF_METALINK_XML_CALLBACKS, "pfnFile"));
    try testing.expectEqual(pointer_size, @offsetOf(TDNF_METALINK_XML_CALLBACKS, "pfnSize"));
    try testing.expectEqual(2 * pointer_size, @offsetOf(TDNF_METALINK_XML_CALLBACKS, "pfnHash"));
    try testing.expectEqual(3 * pointer_size, @offsetOf(TDNF_METALINK_XML_CALLBACKS, "pfnUrl"));
}

test "parses metalink 3.0 fixture and ignores foreign namespaces" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const fixture = try readFixture(arena.allocator(), metalink_v3_fixture_path);

    var recorder = Recorder.init(arena.allocator());
    try testing.expectEqual(@as(u32, 0), parseWithRecorder(fixture, &recorder));

    try testing.expectEqual(@as(usize, 1), recorder.files.items.len);
    try testing.expectEqual(@as(usize, 1), recorder.sizes.items.len);
    try testing.expectEqual(@as(usize, 4), recorder.hashes.items.len);
    try testing.expectEqual(@as(usize, 3), recorder.urls.items.len);

    try testing.expectEqualStrings("repomd.xml", recorder.files.items[0]);
    try testing.expectEqualStrings("5959", recorder.sizes.items[0]);

    try testing.expectEqualStrings("md5", recorder.hashes.items[0].hash_type);
    try testing.expectEqualStrings("a103470107676577f5d80a84171aa0e5", recorder.hashes.items[0].value);
    try testing.expectEqualStrings("sha1", recorder.hashes.items[1].hash_type);
    try testing.expectEqualStrings("a0e9b164619ce0f829093b00187c1eff7e3f993b", recorder.hashes.items[1].value);
    try testing.expectEqualStrings("sha256", recorder.hashes.items[2].hash_type);
    try testing.expectEqualStrings("cccd8f40de8963c497520d50a3ddbad525f0a180dbcb3841ff892a0f64341b29", recorder.hashes.items[2].value);
    try testing.expectEqualStrings("sha512", recorder.hashes.items[3].hash_type);
    try testing.expectEqualStrings("821b280e9b5e74e693b5e239edf36ee41013c0cf888d27b893c833f6b8e361f9633e705d70ac4f6995d150749420216aeffb29610706d851b3667075c346fdb5", recorder.hashes.items[3].value);

    try expectOptionalString("https", recorder.urls.items[0].protocol);
    try expectOptionalString("https", recorder.urls.items[0].url_type);
    try expectOptionalString("UA", recorder.urls.items[0].location);
    try expectOptionalString("100", recorder.urls.items[0].ranking_attr);
    try testing.expect(!recorder.urls.items[0].ranking_is_priority);
    try testing.expectEqualStrings(
        "https://fedora-archive.ip-connect.info/fedora/linux/releases/41/Everything/x86_64/os/repodata/repomd.xml",
        recorder.urls.items[0].value,
    );

    try expectOptionalString("http", recorder.urls.items[1].protocol);
    try expectOptionalString("http", recorder.urls.items[1].url_type);
    try expectOptionalString("DE", recorder.urls.items[1].location);
    try expectOptionalString("99", recorder.urls.items[1].ranking_attr);
    try testing.expect(!recorder.urls.items[1].ranking_is_priority);
    try testing.expectEqualStrings(
        "http://ftp-stud.hs-esslingen.de/pub/Mirrors/archive.fedoraproject.org/fedora/linux/releases/41/Everything/x86_64/os/repodata/repomd.xml",
        recorder.urls.items[1].value,
    );

    try expectOptionalString("rsync", recorder.urls.items[2].protocol);
    try expectOptionalString("rsync", recorder.urls.items[2].url_type);
    try expectOptionalString("US", recorder.urls.items[2].location);
    try expectOptionalString("98", recorder.urls.items[2].ranking_attr);
    try testing.expect(!recorder.urls.items[2].ranking_is_priority);
    try testing.expectEqualStrings(
        "rsync://pubmirror1.math.uh.edu/fedora-archive/fedora/linux/releases/41/Everything/x86_64/os/repodata/repomd.xml",
        recorder.urls.items[2].value,
    );
}

test "parses metalink 4.0 fixture with priority ranking" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const fixture = try readFixture(arena.allocator(), metalink_v4_fixture_path);

    var recorder = Recorder.init(arena.allocator());
    try testing.expectEqual(@as(u32, 0), parseWithRecorder(fixture, &recorder));

    try testing.expectEqual(@as(usize, 1), recorder.files.items.len);
    try testing.expectEqual(@as(usize, 1), recorder.sizes.items.len);
    try testing.expectEqual(@as(usize, 1), recorder.hashes.items.len);
    try testing.expectEqual(@as(usize, 2), recorder.urls.items.len);

    try testing.expectEqualStrings("repomd.xml", recorder.files.items[0]);
    try testing.expectEqualStrings("4096", recorder.sizes.items[0]);
    try testing.expectEqualStrings("sha256", recorder.hashes.items[0].hash_type);
    try testing.expectEqualStrings("feed-face", recorder.hashes.items[0].value);

    try expectOptionalString("https", recorder.urls.items[0].protocol);
    try expectOptionalString("https", recorder.urls.items[0].url_type);
    try expectOptionalString("US", recorder.urls.items[0].location);
    try expectOptionalString("1", recorder.urls.items[0].ranking_attr);
    try testing.expect(recorder.urls.items[0].ranking_is_priority);
    try testing.expectEqualStrings(
        "https://cdn.example.com/repodata/repomd.xml",
        recorder.urls.items[0].value,
    );

    try expectOptionalString(null, recorder.urls.items[1].protocol);
    try expectOptionalString(null, recorder.urls.items[1].url_type);
    try expectOptionalString("JP", recorder.urls.items[1].location);
    try expectOptionalString("25", recorder.urls.items[1].ranking_attr);
    try testing.expect(recorder.urls.items[1].ranking_is_priority);
    try testing.expectEqualStrings(
        "https://mirror.example.jp/repodata/repomd.xml",
        recorder.urls.items[1].value,
    );
}

test "parses generated setup-repo metalink fixture" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const fixture = try readFixture(arena.allocator(), setup_repo_fixture_path);

    var recorder = Recorder.init(arena.allocator());
    try testing.expectEqual(@as(u32, 0), parseWithRecorder(fixture, &recorder));

    try testing.expectEqual(@as(usize, 1), recorder.files.items.len);
    try testing.expectEqual(@as(usize, 1), recorder.sizes.items.len);
    try testing.expectEqual(@as(usize, 0), recorder.hashes.items.len);
    try testing.expectEqual(@as(usize, 1), recorder.urls.items.len);

    try testing.expectEqualStrings("repomd.xml", recorder.files.items[0]);
    try testing.expectEqualStrings("1234", recorder.sizes.items[0]);
    try expectOptionalString("http", recorder.urls.items[0].protocol);
    try expectOptionalString("file", recorder.urls.items[0].url_type);
    try expectOptionalString("IN", recorder.urls.items[0].location);
    try expectOptionalString("100", recorder.urls.items[0].ranking_attr);
    try testing.expect(!recorder.urls.items[0].ranking_is_priority);
    try testing.expectEqualStrings(
        "http://localhost:8080/photon-test/repodata/repomd.xml",
        recorder.urls.items[0].value,
    );
}

test "decodes named and numeric XML entities" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var recorder = Recorder.init(arena.allocator());
    try testing.expectEqual(@as(u32, 0), parseWithRecorder(entity_fixture, &recorder));

    try testing.expectEqual(@as(usize, 1), recorder.hashes.items.len);
    try testing.expectEqualStrings("escaped", recorder.hashes.items[0].hash_type);
    try testing.expectEqualStrings("A&B<C>D\"E'F!?", recorder.hashes.items[0].value);
}

test "rejects malformed metalink documents" {
    const testing = std.testing;

    const cases = [_]struct {
        name: []const u8,
        xml: []const u8,
        expected: u32,
    }{
        .{
            .name = "truncated document",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="repomd.xml"><size>123
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT,
        },
        .{
            .name = "mismatched close tag",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="repomd.xml"></files></metalink>
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT,
        },
        .{
            .name = "bad attribute quoting",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name=repomd.xml></file></metalink>
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT,
        },
        .{
            .name = "unclosed CDATA",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="repomd.xml"><size><![CDATA[123</size></file></metalink>
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT,
        },
        .{
            .name = "file missing name attribute",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file><size>123</size></file></metalink>
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_MISSING_FILE_ATTR,
        },
        .{
            .name = "hash missing type attribute",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="repomd.xml"><hash>abcd</hash></file></metalink>
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_MISSING_HASH_ATTR,
        },
    };

    for (cases) |case| {
        const rc = parseWithNullCallbacks(case.xml);
        try testing.expectEqual(case.expected, rc);
    }
}

test "propagates callback validation failures for empty content and bad rankings" {
    const testing = std.testing;

    const cases = [_]struct {
        name: []const u8,
        xml: []const u8,
        expected: u32,
    }{
        .{
            .name = "empty hash text",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="repomd.xml"><hash type="sha256"></hash></file></metalink>
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_MISSING_HASH_CONTENT,
        },
        .{
            .name = "empty url text",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="repomd.xml"><url priority="1"></url></file></metalink>
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_MISSING_URL_CONTENT,
        },
        .{
            .name = "invalid preference value",
            .xml =
            \\<metalink xmlns="http://www.metalinker.org/"><files><file name="repomd.xml"><resources><url preference="bogus">http://mirror.example.com/repodata/repomd.xml</url></resources></file></files></metalink>
            ,
            .expected = ERROR_TDNF_INVALID_PARAMETER,
        },
        .{
            .name = "invalid priority value",
            .xml =
            \\<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="repomd.xml"><url priority="0">https://mirror.example.com/repodata/repomd.xml</url></file></metalink>
            ,
            .expected = ERROR_TDNF_METALINK_PARSER_MISSING_URL_ATTR,
        },
    };

    for (cases) |case| {
        const rc = parseWithValidationCallbacks(case.xml);
        try testing.expectEqual(case.expected, rc);
    }
}
