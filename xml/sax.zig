//! Shared SAX-style XML core.
//!
//! The walker is forward-only and namespace-aware. Start-element attribute
//! values remain valid until the next `next()` call; callers that need to keep
//! them longer must copy them.

const std = @import("std");

pub const XML_NS = "http://www.w3.org/XML/1998/namespace";

pub const Error = error{
    InvalidXml,
    OutOfMemory,
};

pub const QName = struct {
    raw: []const u8,
    prefix: []const u8,
    local: []const u8,
    ns_uri: ?[]const u8,
};

pub const NamespaceBinding = struct {
    prefix: []const u8,
    uri: []const u8,
};

pub const Attribute = struct {
    raw_name: []const u8,
    prefix: []const u8,
    local: []const u8,
    ns_uri: ?[]const u8,
    value: []const u8,
};

pub const StartElement = struct {
    name: QName,
    attrs: []const Attribute,
    ns_bindings: []const NamespaceBinding,
    empty_element: bool,
};

pub const EndElement = struct {
    name: QName,
};

pub const Event = union(enum) {
    start: StartElement,
    end: EndElement,
    text: []const u8,
};

const SplitQName = struct {
    prefix: []const u8,
    local: []const u8,
};

const ElementFrame = struct {
    name: QName,
    ns_bindings: []const NamespaceBinding,
};

pub const Walker = struct {
    allocator: std.mem.Allocator,
    arena_state: std.heap.ArenaAllocator,
    input: []const u8,
    pos: usize = 0,
    frames: std.array_list.Managed(ElementFrame),
    attrs: std.array_list.Managed(Attribute),
    local_bindings: std.array_list.Managed(NamespaceBinding),
    text_buf: std.array_list.Managed(u8),
    saw_root: bool = false,
    pending_empty_end: bool = false,

    pub fn init(allocator: std.mem.Allocator, input: []const u8) Walker {
        var walker = Walker{
            .allocator = allocator,
            .arena_state = std.heap.ArenaAllocator.init(allocator),
            .input = input,
            .frames = std.array_list.Managed(ElementFrame).init(allocator),
            .attrs = std.array_list.Managed(Attribute).init(allocator),
            .local_bindings = std.array_list.Managed(NamespaceBinding).init(allocator),
            .text_buf = std.array_list.Managed(u8).init(allocator),
        };
        walker.skipBom();
        return walker;
    }

    pub fn deinit(self: *Walker) void {
        self.text_buf.deinit();
        self.local_bindings.deinit();
        self.attrs.deinit();
        self.frames.deinit();
        self.arena_state.deinit();
    }

    pub fn next(self: *Walker) Error!?Event {
        if (self.pending_empty_end) {
            self.pending_empty_end = false;
            const frame = self.frames.pop() orelse return error.InvalidXml;
            return .{ .end = .{ .name = frame.name } };
        }

        while (self.pos < self.input.len) {
            if (self.input[self.pos] == '<') {
                if (self.hasPrefix("<!--")) {
                    try self.skipComment();
                    continue;
                }
                if (self.hasPrefix("<![CDATA[")) {
                    return .{ .text = try self.parseCData() };
                }
                if (self.hasPrefix("<?")) {
                    try self.skipProcessingInstruction();
                    continue;
                }
                if (self.hasPrefix("</")) {
                    return .{ .end = .{ .name = try self.parseEndTag() } };
                }
                if (self.hasPrefix("<!")) {
                    return error.InvalidXml;
                }
                return .{ .start = try self.parseStartTag() };
            }

            if (try self.parseText()) |text| {
                return .{ .text = text };
            }
        }

        if (!self.saw_root or self.frames.items.len != 0) {
            return error.InvalidXml;
        }

        return null;
    }

    fn parseStartTag(self: *Walker) Error!StartElement {
        std.debug.assert(self.input[self.pos] == '<');
        self.pos += 1;

        if (self.saw_root and self.frames.items.len == 0) {
            return error.InvalidXml;
        }

        const raw_qname = try self.parseNameSlice();
        const qname = try splitQName(raw_qname);

        self.local_bindings.clearRetainingCapacity();
        self.attrs.clearRetainingCapacity();
        var empty_element = false;

        while (true) {
            self.skipWhitespace();
            if (self.pos >= self.input.len) return error.InvalidXml;

            if (self.input[self.pos] == '>') {
                self.pos += 1;
                break;
            }

            if (self.input[self.pos] == '/') {
                if (self.pos + 1 >= self.input.len or self.input[self.pos + 1] != '>') {
                    return error.InvalidXml;
                }
                self.pos += 2;
                empty_element = true;
                break;
            }

            const raw_attr_name = try self.parseNameSlice();
            const attr_qname = try splitQName(raw_attr_name);

            self.skipWhitespace();
            if (self.pos >= self.input.len or self.input[self.pos] != '=') {
                return error.InvalidXml;
            }
            self.pos += 1;

            self.skipWhitespace();
            if (self.pos >= self.input.len) return error.InvalidXml;

            const quote = self.input[self.pos];
            if (quote != '"' and quote != '\'') return error.InvalidXml;
            self.pos += 1;

            const value = try self.parseAttributeValue(quote);
            if (std.mem.eql(u8, attr_qname.prefix, "xmlns")) {
                try self.local_bindings.append(.{
                    .prefix = attr_qname.local,
                    .uri = value,
                });
            } else if (attr_qname.prefix.len == 0 and std.mem.eql(u8, attr_qname.local, "xmlns")) {
                try self.local_bindings.append(.{
                    .prefix = "",
                    .uri = value,
                });
            } else {
                try self.attrs.append(.{
                    .raw_name = raw_attr_name,
                    .prefix = attr_qname.prefix,
                    .local = attr_qname.local,
                    .ns_uri = null,
                    .value = value,
                });
            }
        }

        try self.validateAttrPrefixes(self.attrs.items, self.local_bindings.items);
        for (self.attrs.items) |*attr| {
            if (attr.prefix.len != 0) {
                attr.ns_uri = self.resolvePrefixedNamespace(attr.prefix, self.local_bindings.items) orelse
                    return error.InvalidXml;
            }
        }

        const ns_uri = try self.resolveElementNamespace(qname.prefix, self.local_bindings.items);
        const name = QName{
            .raw = raw_qname,
            .prefix = qname.prefix,
            .local = qname.local,
            .ns_uri = ns_uri,
        };

        const frame = ElementFrame{
            .name = name,
            .ns_bindings = try self.dupBindings(self.local_bindings.items),
        };
        try self.frames.append(frame);
        self.saw_root = true;
        self.pending_empty_end = empty_element;

        return .{
            .name = name,
            .attrs = self.attrs.items,
            .ns_bindings = self.local_bindings.items,
            .empty_element = empty_element,
        };
    }

    fn parseEndTag(self: *Walker) Error!QName {
        if (self.frames.items.len == 0) return error.InvalidXml;

        self.pos += 2;
        const raw_qname = try self.parseNameSlice();
        self.skipWhitespace();

        if (self.pos >= self.input.len or self.input[self.pos] != '>') {
            return error.InvalidXml;
        }
        self.pos += 1;

        const top = self.frames.getLast();
        if (!std.mem.eql(u8, raw_qname, top.name.raw)) {
            return error.InvalidXml;
        }

        _ = self.frames.pop();
        return top.name;
    }

    fn parseText(self: *Walker) Error!?[]const u8 {
        const outside_root = self.frames.items.len == 0;
        var segment_start = self.pos;
        var used_buffer = false;
        self.text_buf.clearRetainingCapacity();

        while (self.pos < self.input.len and self.input[self.pos] != '<') {
            if (self.input[self.pos] == '&') {
                if (outside_root) {
                    try self.ensureWhitespaceSegment(self.input[segment_start..self.pos]);
                } else {
                    try self.text_buf.appendSlice(self.input[segment_start..self.pos]);
                    used_buffer = true;
                }

                const cp = try self.parseEntityCodepoint();
                if (outside_root) {
                    if (!isXmlWhitespaceCodepoint(cp)) return error.InvalidXml;
                } else {
                    try appendCodepoint(&self.text_buf, cp);
                    used_buffer = true;
                }

                segment_start = self.pos;
                continue;
            }

            if (self.input[self.pos] == 0) return error.InvalidXml;

            if (self.pos + 2 < self.input.len and
                self.input[self.pos] == ']' and
                self.input[self.pos + 1] == ']' and
                self.input[self.pos + 2] == '>')
            {
                return error.InvalidXml;
            }

            self.pos += 1;
        }

        const tail = self.input[segment_start..self.pos];
        if (outside_root) {
            try self.ensureWhitespaceSegment(tail);
            return null;
        }

        if (used_buffer) {
            try self.text_buf.appendSlice(tail);
            return self.text_buf.items;
        }

        return tail;
    }

    fn parseCData(self: *Walker) Error![]const u8 {
        if (self.frames.items.len == 0) return error.InvalidXml;

        self.pos += 9;
        const start = self.pos;
        while (self.pos + 2 < self.input.len) {
            if (self.input[self.pos] == ']' and
                self.input[self.pos + 1] == ']' and
                self.input[self.pos + 2] == '>')
            {
                const out = self.input[start..self.pos];
                self.pos += 3;
                return out;
            }
            self.pos += 1;
        }

        return error.InvalidXml;
    }

    fn parseAttributeValue(self: *Walker, quote: u8) Error![]const u8 {
        var out = std.array_list.Managed(u8).init(self.allocator);
        defer out.deinit();
        var segment_start = self.pos;
        var used_buffer = false;

        while (self.pos < self.input.len) {
            const ch = self.input[self.pos];
            if (ch == quote) {
                if (used_buffer) {
                    try out.appendSlice(self.input[segment_start..self.pos]);
                    self.pos += 1;
                    return try self.allocPersistent(out.items);
                }

                const value = self.input[segment_start..self.pos];
                self.pos += 1;
                return value;
            }

            if (ch == '<' or ch == 0) return error.InvalidXml;

            if (ch == '&') {
                try out.appendSlice(self.input[segment_start..self.pos]);
                const cp = try self.parseEntityCodepoint();
                try appendCodepoint(&out, cp);
                used_buffer = true;
                segment_start = self.pos;
                continue;
            }

            self.pos += 1;
        }

        return error.InvalidXml;
    }

    fn parseEntityCodepoint(self: *Walker) Error!u21 {
        std.debug.assert(self.input[self.pos] == '&');
        self.pos += 1;
        if (self.pos >= self.input.len) return error.InvalidXml;

        if (self.input[self.pos] == '#') {
            self.pos += 1;
            var base: u8 = 10;
            if (self.pos < self.input.len and (self.input[self.pos] == 'x' or self.input[self.pos] == 'X')) {
                base = 16;
                self.pos += 1;
            }

            const digits_start = self.pos;
            while (self.pos < self.input.len and isRadixDigit(self.input[self.pos], base)) {
                self.pos += 1;
            }
            if (digits_start == self.pos or self.pos >= self.input.len or self.input[self.pos] != ';') {
                return error.InvalidXml;
            }

            const digits = self.input[digits_start..self.pos];
            self.pos += 1;
            const cp = std.fmt.parseInt(u32, digits, base) catch return error.InvalidXml;
            const scalar: u21 = @intCast(cp);
            if (!isValidXmlScalar(scalar)) return error.InvalidXml;
            return scalar;
        }

        const name_start = self.pos;
        while (self.pos < self.input.len and isNameChar(self.input[self.pos])) {
            self.pos += 1;
        }
        if (name_start == self.pos or self.pos >= self.input.len or self.input[self.pos] != ';') {
            return error.InvalidXml;
        }

        const name = self.input[name_start..self.pos];
        self.pos += 1;

        if (std.mem.eql(u8, name, "amp")) return '&';
        if (std.mem.eql(u8, name, "lt")) return '<';
        if (std.mem.eql(u8, name, "gt")) return '>';
        if (std.mem.eql(u8, name, "quot")) return '"';
        if (std.mem.eql(u8, name, "apos")) return '\'';
        return error.InvalidXml;
    }

    fn parseNameSlice(self: *Walker) Error![]const u8 {
        if (self.pos >= self.input.len or !isNameStart(self.input[self.pos])) {
            return error.InvalidXml;
        }

        const start = self.pos;
        self.pos += 1;
        while (self.pos < self.input.len and isNameChar(self.input[self.pos])) {
            self.pos += 1;
        }
        return self.input[start..self.pos];
    }

    fn skipBom(self: *Walker) void {
        if (self.input.len >= 3 and
            self.input[0] == 0xEF and
            self.input[1] == 0xBB and
            self.input[2] == 0xBF)
        {
            self.pos = 3;
        }
    }

    fn skipComment(self: *Walker) Error!void {
        self.pos += 4;
        while (self.pos + 2 < self.input.len) {
            if (self.input[self.pos] == '-' and
                self.input[self.pos + 1] == '-' and
                self.input[self.pos + 2] == '>')
            {
                self.pos += 3;
                return;
            }
            self.pos += 1;
        }
        return error.InvalidXml;
    }

    fn skipProcessingInstruction(self: *Walker) Error!void {
        self.pos += 2;
        while (self.pos + 1 < self.input.len) {
            if (self.input[self.pos] == '?' and self.input[self.pos + 1] == '>') {
                self.pos += 2;
                return;
            }
            self.pos += 1;
        }
        return error.InvalidXml;
    }

    fn ensureWhitespaceSegment(self: *Walker, segment: []const u8) Error!void {
        _ = self;
        for (segment) |byte| {
            if (!isXmlWhitespaceByte(byte)) return error.InvalidXml;
        }
    }

    fn validateAttrPrefixes(
        self: *Walker,
        attrs: []const Attribute,
        local_bindings: []const NamespaceBinding,
    ) Error!void {
        for (attrs) |attr| {
            if (attr.prefix.len == 0 or std.mem.eql(u8, attr.prefix, "xml")) {
                continue;
            }
            if (self.resolvePrefixedNamespace(attr.prefix, local_bindings) == null) {
                return error.InvalidXml;
            }
        }
    }

    fn resolveElementNamespace(
        self: *Walker,
        prefix: []const u8,
        local_bindings: []const NamespaceBinding,
    ) Error!?[]const u8 {
        if (prefix.len == 0) return self.resolveDefaultNamespace(local_bindings);
        return self.resolvePrefixedNamespace(prefix, local_bindings) orelse error.InvalidXml;
    }

    fn resolveDefaultNamespace(
        self: *Walker,
        local_bindings: []const NamespaceBinding,
    ) ?[]const u8 {
        var index = local_bindings.len;
        while (index > 0) {
            index -= 1;
            if (local_bindings[index].prefix.len == 0) {
                return local_bindings[index].uri;
            }
        }

        var frame_index = self.frames.items.len;
        while (frame_index > 0) {
            frame_index -= 1;
            const bindings = self.frames.items[frame_index].ns_bindings;
            var binding_index = bindings.len;
            while (binding_index > 0) {
                binding_index -= 1;
                if (bindings[binding_index].prefix.len == 0) {
                    return bindings[binding_index].uri;
                }
            }
        }

        return null;
    }

    fn resolvePrefixedNamespace(
        self: *Walker,
        prefix: []const u8,
        local_bindings: []const NamespaceBinding,
    ) ?[]const u8 {
        if (std.mem.eql(u8, prefix, "xml")) return XML_NS;

        var index = local_bindings.len;
        while (index > 0) {
            index -= 1;
            if (std.mem.eql(u8, local_bindings[index].prefix, prefix)) {
                return local_bindings[index].uri;
            }
        }

        var frame_index = self.frames.items.len;
        while (frame_index > 0) {
            frame_index -= 1;
            const bindings = self.frames.items[frame_index].ns_bindings;
            var binding_index = bindings.len;
            while (binding_index > 0) {
                binding_index -= 1;
                if (std.mem.eql(u8, bindings[binding_index].prefix, prefix)) {
                    return bindings[binding_index].uri;
                }
            }
        }

        return null;
    }

    fn allocPersistent(self: *Walker, bytes: []const u8) Error![]const u8 {
        return self.arena_state.allocator().dupe(u8, bytes) catch error.OutOfMemory;
    }

    fn dupBindings(self: *Walker, bindings: []const NamespaceBinding) Error![]const NamespaceBinding {
        const copy = self.arena_state.allocator().alloc(NamespaceBinding, bindings.len) catch
            return error.OutOfMemory;
        @memcpy(copy, bindings);
        return copy;
    }

    fn hasPrefix(self: *Walker, prefix: []const u8) bool {
        return self.pos + prefix.len <= self.input.len and
            std.mem.eql(u8, self.input[self.pos .. self.pos + prefix.len], prefix);
    }

    fn skipWhitespace(self: *Walker) void {
        while (self.pos < self.input.len and isXmlWhitespaceByte(self.input[self.pos])) {
            self.pos += 1;
        }
    }
};

fn splitQName(raw: []const u8) Error!SplitQName {
    var colon_index: ?usize = null;
    for (raw, 0..) |byte, index| {
        if (byte != ':') continue;
        if (colon_index != null or index == 0 or index + 1 == raw.len) {
            return error.InvalidXml;
        }
        colon_index = index;
    }

    if (colon_index) |index| {
        return .{
            .prefix = raw[0..index],
            .local = raw[index + 1 ..],
        };
    }

    return .{ .prefix = "", .local = raw };
}

fn appendCodepoint(list: *std.array_list.Managed(u8), cp: u21) Error!void {
    if (!isValidXmlScalar(cp)) return error.InvalidXml;

    var buf: [4]u8 = undefined;
    const len = std.unicode.utf8Encode(cp, &buf) catch return error.InvalidXml;
    try list.appendSlice(buf[0..len]);
}

fn isValidXmlScalar(cp: u21) bool {
    return switch (cp) {
        0x9, 0xA, 0xD => true,
        0x20...0xD7FF => true,
        0xE000...0xFFFD => true,
        0x10000...0x10FFFF => true,
        else => false,
    };
}

fn isXmlWhitespaceByte(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\n' or byte == '\r';
}

fn isXmlWhitespaceCodepoint(cp: u21) bool {
    return cp == ' ' or cp == '\t' or cp == '\n' or cp == '\r';
}

fn isNameStart(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '_' or byte == ':';
}

fn isNameChar(byte: u8) bool {
    return isNameStart(byte) or std.ascii.isDigit(byte) or byte == '-' or byte == '.';
}

fn isRadixDigit(byte: u8, base: u8) bool {
    return if (base == 16) std.ascii.isHex(byte) else std.ascii.isDigit(byte);
}

fn expectQName(
    actual: QName,
    raw: []const u8,
    prefix: []const u8,
    local: []const u8,
    ns_uri: ?[]const u8,
) !void {
    const testing = std.testing;

    try testing.expectEqualStrings(raw, actual.raw);
    try testing.expectEqualStrings(prefix, actual.prefix);
    try testing.expectEqualStrings(local, actual.local);
    if (ns_uri) |expected_ns| {
        const actual_ns = actual.ns_uri orelse return error.TestExpectedEqual;
        try testing.expectEqualStrings(expected_ns, actual_ns);
    } else {
        try testing.expect(actual.ns_uri == null);
    }
}

fn expectAttr(
    actual: Attribute,
    raw_name: []const u8,
    prefix: []const u8,
    local: []const u8,
    ns_uri: ?[]const u8,
    value: []const u8,
) !void {
    const testing = std.testing;

    try testing.expectEqualStrings(raw_name, actual.raw_name);
    try testing.expectEqualStrings(prefix, actual.prefix);
    try testing.expectEqualStrings(local, actual.local);
    if (ns_uri) |expected_ns| {
        const actual_ns = actual.ns_uri orelse return error.TestExpectedEqual;
        try testing.expectEqualStrings(expected_ns, actual_ns);
    } else {
        try testing.expect(actual.ns_uri == null);
    }
    try testing.expectEqualStrings(value, actual.value);
}

fn nextEvent(walker: *Walker) !Event {
    return (try walker.next()) orelse error.TestExpectedEqual;
}

fn consumeAll(xml: []const u8) Error!void {
    var walker = Walker.init(std.testing.allocator, xml);
    defer walker.deinit();

    while (try walker.next()) |_| {}
}

test "walker parses elements text CDATA comments entities and processing instructions" {
    const testing = std.testing;
    const xml =
        \\<?xml version="1.0"?>
        \\<root xmlns="urn:root" attr="A&amp;B"><!--ignore--><child foo="bar">hi<![CDATA[ there]]>&#33;</child><?skip?></root>
    ;

    var walker = Walker.init(testing.allocator, xml);
    defer walker.deinit();

    const root = (try nextEvent(&walker)).start;
    try expectQName(root.name, "root", "", "root", "urn:root");
    try testing.expect(!root.empty_element);
    try testing.expectEqual(@as(usize, 1), root.attrs.len);
    try expectAttr(root.attrs[0], "attr", "", "attr", null, "A&B");

    const child = (try nextEvent(&walker)).start;
    try expectQName(child.name, "child", "", "child", "urn:root");
    try testing.expectEqual(@as(usize, 1), child.attrs.len);
    try expectAttr(child.attrs[0], "foo", "", "foo", null, "bar");

    const text1 = (try nextEvent(&walker)).text;
    try testing.expectEqualStrings("hi", text1);

    const text2 = (try nextEvent(&walker)).text;
    try testing.expectEqualStrings(" there", text2);

    const text3 = (try nextEvent(&walker)).text;
    try testing.expectEqualStrings("!", text3);

    const child_end = (try nextEvent(&walker)).end;
    try expectQName(child_end.name, "child", "", "child", "urn:root");

    const root_end = (try nextEvent(&walker)).end;
    try expectQName(root_end.name, "root", "", "root", "urn:root");

    try testing.expect((try walker.next()) == null);
}

test "walker resolves namespaces for elements and attributes" {
    const testing = std.testing;
    const xml =
        \\<root xmlns="urn:def" xmlns:r="urn:repo" xmlns:x="urn:extra" plain="v" r:flag="1" xml:lang="en"><r:child xmlns="urn:inner" x:name="ok"/></root>
    ;

    var walker = Walker.init(testing.allocator, xml);
    defer walker.deinit();

    const root = (try nextEvent(&walker)).start;
    try expectQName(root.name, "root", "", "root", "urn:def");
    try testing.expectEqual(@as(usize, 3), root.attrs.len);
    try testing.expectEqual(@as(usize, 3), root.ns_bindings.len);
    try expectAttr(root.attrs[0], "plain", "", "plain", null, "v");
    try expectAttr(root.attrs[1], "r:flag", "r", "flag", "urn:repo", "1");
    try expectAttr(root.attrs[2], "xml:lang", "xml", "lang", XML_NS, "en");

    const child = (try nextEvent(&walker)).start;
    try expectQName(child.name, "r:child", "r", "child", "urn:repo");
    try testing.expect(child.empty_element);
    try testing.expectEqual(@as(usize, 1), child.attrs.len);
    try testing.expectEqual(@as(usize, 1), child.ns_bindings.len);
    try expectAttr(child.attrs[0], "x:name", "x", "name", "urn:extra", "ok");

    const child_end = (try nextEvent(&walker)).end;
    try expectQName(child_end.name, "r:child", "r", "child", "urn:repo");

    const root_end = (try nextEvent(&walker)).end;
    try expectQName(root_end.name, "root", "", "root", "urn:def");

    try testing.expect((try walker.next()) == null);
}

test "walker rejects undefined namespace prefixes" {
    try std.testing.expectError(
        error.InvalidXml,
        consumeAll("<root xmlns=\"urn:def\"><x:child/></root>"),
    );
}
