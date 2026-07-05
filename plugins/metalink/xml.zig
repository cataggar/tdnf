//! Pure-Zig metalink XML walker (PR1 of issue #38).
//!
//! This parser intentionally supports only the metalink 3.0/4.0 subset
//! that the metalink plugin consumes. It provides a tiny C ABI and a
//! forward-only callback surface for file/size/hash/url records.

const std = @import("std");
const builtin = @import("builtin");

const c_xml = if (builtin.is_test) @cImport({
    @cInclude("xml.h");
}) else struct {};

pub const ERROR_TDNF_OUT_OF_MEMORY: u32 = 1612;
pub const ERROR_TDNF_INVALID_PARAMETER: u32 = 1622;
pub const ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT: u32 = 2701;
pub const ERROR_TDNF_METALINK_PARSER_INVALID_ROOT_ELEMENT: u32 = 2702;
pub const ERROR_TDNF_METALINK_PARSER_MISSING_FILE_ATTR: u32 = 2703;
pub const ERROR_TDNF_METALINK_PARSER_MISSING_HASH_ATTR: u32 = 2706;

const METALINK_NS_V3 = "http://www.metalinker.org/";
const METALINK_NS_V4 = "urn:ietf:params:xml:ns:metalink";
const XML_NS = "http://www.w3.org/XML/1998/namespace";
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

const QName = struct {
    prefix: []const u8,
    local: []const u8,
};

const NsBinding = struct {
    prefix: []const u8,
    uri: []const u8,
};

const ParsedAttr = struct {
    prefix: []const u8,
    local: []const u8,
    value: [:0]const u8,
};

const Frame = struct {
    raw_qname: []const u8,
    kind: ElementKind,
    ns_bindings: []const NsBinding,
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
    input: []const u8,
    pos: usize = 0,
    callbacks: *const TDNF_METALINK_XML_CALLBACKS,
    ctx: ?*anyopaque,
    frames: std.array_list.Managed(Frame),
    version: Version = .unknown,
    saw_root: bool = false,
    error_code: u32 = 0,

    fn init(
        allocator: std.mem.Allocator,
        input: []const u8,
        callbacks: *const TDNF_METALINK_XML_CALLBACKS,
        ctx: ?*anyopaque,
    ) Parser {
        return .{
            .allocator = allocator,
            .input = input,
            .callbacks = callbacks,
            .ctx = ctx,
            .frames = std.array_list.Managed(Frame).init(allocator),
        };
    }

    fn fail(self: *Parser, code: u32) ParseError {
        self.error_code = code;
        return error.ParseFailed;
    }

    fn parse(self: *Parser) ParseError!void {
        self.skipBom();

        while (self.pos < self.input.len) {
            if (self.input[self.pos] == '<') {
                try self.parseMarkup();
            } else {
                try self.parseText();
            }
        }

        if (!self.saw_root or self.frames.items.len != 0) {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }
    }

    fn skipBom(self: *Parser) void {
        if (self.input.len >= 3 and
            self.input[0] == 0xEF and
            self.input[1] == 0xBB and
            self.input[2] == 0xBF)
        {
            self.pos = 3;
        }
    }

    fn parseMarkup(self: *Parser) ParseError!void {
        if (self.hasPrefix("<!--")) return self.skipComment();
        if (self.hasPrefix("<![CDATA[")) return self.parseCData();
        if (self.hasPrefix("<?")) return self.skipProcessingInstruction();
        if (self.hasPrefix("</")) return self.parseEndTag();
        if (self.hasPrefix("<!")) return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        return self.parseStartTag();
    }

    fn parseText(self: *Parser) ParseError!void {
        const outside_root = self.frames.items.len == 0;
        const target = self.currentTextTarget();
        var segment_start = self.pos;

        while (self.pos < self.input.len and self.input[self.pos] != '<') {
            if (self.input[self.pos] == '&') {
                if (target) |list| {
                    try list.appendSlice(self.input[segment_start..self.pos]);
                } else if (outside_root) {
                    try self.ensureWhitespaceSegment(self.input[segment_start..self.pos]);
                }

                const cp = try self.parseEntityCodepoint();
                if (target) |list| {
                    try appendCodepoint(list, cp);
                } else if (outside_root and !isXmlWhitespaceCodepoint(cp)) {
                    return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
                }

                segment_start = self.pos;
                continue;
            }

            if (self.input[self.pos] == 0) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }

            if (self.pos + 2 < self.input.len and
                self.input[self.pos] == ']' and
                self.input[self.pos + 1] == ']' and
                self.input[self.pos + 2] == '>')
            {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }

            self.pos += 1;
        }

        if (target) |list| {
            try list.appendSlice(self.input[segment_start..self.pos]);
        } else if (outside_root) {
            try self.ensureWhitespaceSegment(self.input[segment_start..self.pos]);
        }
    }

    fn currentTextTarget(self: *Parser) ?*std.array_list.Managed(u8) {
        if (self.frames.items.len == 0) return null;
        const top = &self.frames.items[self.frames.items.len - 1];
        if (!top.collect_text) return null;
        return &top.text;
    }

    fn ensureWhitespaceSegment(self: *Parser, segment: []const u8) ParseError!void {
        for (segment) |byte| {
            if (!isXmlWhitespaceByte(byte)) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }
        }
    }

    fn parseStartTag(self: *Parser) ParseError!void {
        std.debug.assert(self.input[self.pos] == '<');
        self.pos += 1;

        const raw_qname = try self.parseNameSlice();
        const qname = try splitQName(self, raw_qname);

        var ns_bindings = std.array_list.Managed(NsBinding).init(self.allocator);
        var attrs = std.array_list.Managed(ParsedAttr).init(self.allocator);
        var empty_element = false;

        while (true) {
            self.skipWhitespace();
            if (self.pos >= self.input.len) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }

            if (self.input[self.pos] == '>') {
                self.pos += 1;
                break;
            }
            if (self.input[self.pos] == '/') {
                if (self.pos + 1 >= self.input.len or self.input[self.pos + 1] != '>') {
                    return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
                }
                self.pos += 2;
                empty_element = true;
                break;
            }

            const raw_attr_name = try self.parseNameSlice();
            const attr_qname = try splitQName(self, raw_attr_name);

            self.skipWhitespace();
            if (self.pos >= self.input.len or self.input[self.pos] != '=') {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }
            self.pos += 1;

            self.skipWhitespace();
            if (self.pos >= self.input.len) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }

            const quote = self.input[self.pos];
            if (quote != '"' and quote != '\'') {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }
            self.pos += 1;

            const value = try self.parseAttributeValue(quote);
            if (std.mem.eql(u8, attr_qname.prefix, "xmlns")) {
                try ns_bindings.append(.{ .prefix = attr_qname.local, .uri = value[0..value.len] });
            } else if (attr_qname.prefix.len == 0 and std.mem.eql(u8, attr_qname.local, "xmlns")) {
                try ns_bindings.append(.{ .prefix = "", .uri = value[0..value.len] });
            } else {
                try attrs.append(.{
                    .prefix = attr_qname.prefix,
                    .local = attr_qname.local,
                    .value = value,
                });
            }
        }

        try self.validateAttrPrefixes(attrs.items, ns_bindings.items);

        const ns_uri = try self.resolveElementNamespace(qname.prefix, ns_bindings.items);
        const ns_kind = namespaceKind(ns_uri);

        var kind: ElementKind = .other;
        if (!self.saw_root) {
            if (!std.mem.eql(u8, qname.local, "metalink")) {
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
            kind = self.classifyElement(ns_kind, qname.local);
        }

        var frame = Frame{
            .raw_qname = raw_qname,
            .kind = kind,
            .ns_bindings = ns_bindings.items,
            .text = std.array_list.Managed(u8).init(self.allocator),
        };

        switch (kind) {
            .file => {
                const name = lookupAttr(attrs.items, "name") orelse
                    return self.fail(ERROR_TDNF_METALINK_PARSER_MISSING_FILE_ATTR);
                if (self.callbacks.pfnFile) |cb| {
                    const rc = cb(self.ctx, name.ptr);
                    if (rc != 0) return self.fail(rc);
                }
            },
            .size => frame.collect_text = true,
            .hash => {
                frame.collect_text = true;
                frame.hash_type = lookupAttr(attrs.items, "type") orelse
                    return self.fail(ERROR_TDNF_METALINK_PARSER_MISSING_HASH_ATTR);
            },
            .url => {
                frame.collect_text = true;
                frame.url_protocol = lookupAttr(attrs.items, "protocol");
                frame.url_type = lookupAttr(attrs.items, "type");
                frame.url_location = lookupAttr(attrs.items, "location");
                if (self.version == .v4) {
                    frame.url_ranking = lookupAttr(attrs.items, "priority");
                    frame.url_ranking_is_priority = true;
                } else {
                    frame.url_ranking = lookupAttr(attrs.items, "preference");
                }
            },
            else => {},
        }

        try self.frames.append(frame);

        if (empty_element) {
            try self.finishTopFrame();
            self.frames.items.len -= 1;
        }
    }

    fn parseEndTag(self: *Parser) ParseError!void {
        if (self.frames.items.len == 0) {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }

        self.pos += 2;
        const raw_qname = try self.parseNameSlice();
        self.skipWhitespace();

        if (self.pos >= self.input.len or self.input[self.pos] != '>') {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }
        self.pos += 1;

        const top = &self.frames.items[self.frames.items.len - 1];
        if (!std.mem.eql(u8, raw_qname, top.raw_qname)) {
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

    fn parseAttributeValue(self: *Parser, quote: u8) ParseError![:0]const u8 {
        var out = std.array_list.Managed(u8).init(self.allocator);
        var segment_start = self.pos;

        while (self.pos < self.input.len) {
            const ch = self.input[self.pos];
            if (ch == quote) {
                try out.appendSlice(self.input[segment_start..self.pos]);
                self.pos += 1;
                return try self.allocZ(out.items);
            }
            if (ch == '<' or ch == 0) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }
            if (ch == '&') {
                try out.appendSlice(self.input[segment_start..self.pos]);
                const cp = try self.parseEntityCodepoint();
                try appendCodepoint(&out, cp);
                segment_start = self.pos;
                continue;
            }
            self.pos += 1;
        }

        return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
    }

    fn parseEntityCodepoint(self: *Parser) ParseError!u21 {
        std.debug.assert(self.input[self.pos] == '&');
        self.pos += 1;
        if (self.pos >= self.input.len) {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }

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
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }

            const digits = self.input[digits_start..self.pos];
            self.pos += 1;
            const cp = std.fmt.parseInt(u32, digits, base) catch
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            const scalar: u21 = @intCast(cp);
            if (!isValidXmlScalar(scalar)) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }
            return scalar;
        }

        const name_start = self.pos;
        while (self.pos < self.input.len and isNameChar(self.input[self.pos])) {
            self.pos += 1;
        }
        if (name_start == self.pos or self.pos >= self.input.len or self.input[self.pos] != ';') {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }

        const name = self.input[name_start..self.pos];
        self.pos += 1;

        if (std.mem.eql(u8, name, "amp")) return '&';
        if (std.mem.eql(u8, name, "lt")) return '<';
        if (std.mem.eql(u8, name, "gt")) return '>';
        if (std.mem.eql(u8, name, "quot")) return '"';
        if (std.mem.eql(u8, name, "apos")) return '\'';
        return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
    }

    fn parseNameSlice(self: *Parser) ParseError![]const u8 {
        if (self.pos >= self.input.len or !isNameStart(self.input[self.pos])) {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }

        const start = self.pos;
        self.pos += 1;
        while (self.pos < self.input.len and isNameChar(self.input[self.pos])) {
            self.pos += 1;
        }
        return self.input[start..self.pos];
    }

    fn skipComment(self: *Parser) ParseError!void {
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
        return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
    }

    fn parseCData(self: *Parser) ParseError!void {
        if (self.frames.items.len == 0) {
            return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
        }

        self.pos += 9;
        const start = self.pos;
        while (self.pos + 2 < self.input.len) {
            if (self.input[self.pos] == ']' and
                self.input[self.pos + 1] == ']' and
                self.input[self.pos + 2] == '>')
            {
                if (self.currentTextTarget()) |list| {
                    try list.appendSlice(self.input[start..self.pos]);
                }
                self.pos += 3;
                return;
            }
            self.pos += 1;
        }
        return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
    }

    fn skipProcessingInstruction(self: *Parser) ParseError!void {
        self.pos += 2;
        while (self.pos + 1 < self.input.len) {
            if (self.input[self.pos] == '?' and self.input[self.pos + 1] == '>') {
                self.pos += 2;
                return;
            }
            self.pos += 1;
        }
        return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
    }

    fn validateAttrPrefixes(self: *Parser, attrs: []const ParsedAttr, local_bindings: []const NsBinding) ParseError!void {
        for (attrs) |attr| {
            if (attr.prefix.len == 0 or std.mem.eql(u8, attr.prefix, "xml")) {
                continue;
            }
            if (self.resolvePrefixedNamespace(attr.prefix, local_bindings) == null) {
                return self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
            }
        }
    }

    fn resolveElementNamespace(self: *Parser, prefix: []const u8, local_bindings: []const NsBinding) ParseError!?[]const u8 {
        if (prefix.len == 0) return self.resolveDefaultNamespace(local_bindings);
        return self.resolvePrefixedNamespace(prefix, local_bindings) orelse
            self.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
    }

    fn resolveDefaultNamespace(self: *Parser, local_bindings: []const NsBinding) ?[]const u8 {
        var i = local_bindings.len;
        while (i > 0) {
            i -= 1;
            if (local_bindings[i].prefix.len == 0) {
                return local_bindings[i].uri;
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

    fn resolvePrefixedNamespace(self: *Parser, prefix: []const u8, local_bindings: []const NsBinding) ?[]const u8 {
        if (std.mem.eql(u8, prefix, "xml")) return XML_NS;

        var i = local_bindings.len;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, local_bindings[i].prefix, prefix)) {
                return local_bindings[i].uri;
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

    fn hasPrefix(self: *Parser, prefix: []const u8) bool {
        return self.pos + prefix.len <= self.input.len and
            std.mem.eql(u8, self.input[self.pos .. self.pos + prefix.len], prefix);
    }

    fn skipWhitespace(self: *Parser) void {
        while (self.pos < self.input.len and isXmlWhitespaceByte(self.input[self.pos])) {
            self.pos += 1;
        }
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

    var parser = Parser.init(arena.allocator(), data_ptr[0..len], callbacks, ctx);
    parser.parse() catch |err| return switch (err) {
        error.ParseFailed => parser.error_code,
        error.OutOfMemory => ERROR_TDNF_OUT_OF_MEMORY,
    };
    return 0;
}

fn splitQName(parser: *Parser, raw: []const u8) ParseError!QName {
    var colon_index: ?usize = null;
    for (raw, 0..) |byte, index| {
        if (byte != ':') continue;
        if (colon_index != null or index == 0 or index + 1 == raw.len) {
            return parser.fail(ERROR_TDNF_METALINK_PARSER_INVALID_DOC_OBJECT);
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

fn lookupAttr(attrs: []const ParsedAttr, local: []const u8) ?[:0]const u8 {
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

fn appendCodepoint(list: *std.array_list.Managed(u8), cp: u21) ParseError!void {
    if (!isValidXmlScalar(cp)) return error.ParseFailed;

    var buf: [4]u8 = undefined;
    const len = std.unicode.utf8Encode(cp, &buf) catch return error.ParseFailed;
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

fn expectOptionalString(expected: ?[]const u8, actual: ?[]const u8) !void {
    const testing = std.testing;

    if (expected) |want| {
        const got = actual orelse return error.TestExpectedEqual;
        try testing.expectEqualStrings(want, got);
    } else {
        try testing.expect(actual == null);
    }
}

const metalink_v3_fixture =
    \\<?xml version="1.0" encoding="utf-8"?>
    \\<metalink xmlns="http://www.metalinker.org/" xmlns:mm0="http://example.com/mm0" version="3.0">
    \\  <!-- metalink 3.0 fixture -->
    \\  <files>
    \\    <file name="repomd.xml">
    \\      <mm0:timestamp/>
    \\      <size>12<![CDATA[34]]>&#53;</size>
    \\      <verification>
    \\        <hash type="sha256">abc<![CDATA[123]]>&#52;</hash>
    \\        <mm0:note>ignored</mm0:note>
    \\        <hash type="sha512">def&amp;ghi</hash>
    \\      </verification>
    \\      <resources>
    \\        <url protocol="https" type="file" location="US" preference="50">https://mirror1.example.com/repodata/repomd.xml</url>
    \\        <mm0:note>skip me</mm0:note>
    \\        <url protocol="https" type="file" location="DE" preference="100">https://mirror2.example.com/repodata/repomd.xml?x=1&amp;y=2</url>
    \\      </resources>
    \\    </file>
    \\  </files>
    \\</metalink>
;

const metalink_v4_fixture =
    \\<?xml version="1.0"?>
    \\<metalink xmlns="urn:ietf:params:xml:ns:metalink">
    \\  <file name="repomd.xml">
    \\    <size><![CDATA[409]]>6</size>
    \\    <hash type="sha256">feed<![CDATA[-]]>face</hash>
    \\    <url priority="1" location="US" protocol="https" type="https">https://cdn.example.com/repodata/repomd.xml</url>
    \\    <url priority="25" location="JP">https://mirror.example.jp/repodata/repomd.xml</url>
    \\  </file>
    \\</metalink>
;

const setup_repo_fixture =
    \\<?xml version="1.0" encoding="utf-8"?>
    \\<metalink version="3.0" xmlns="http://www.metalinker.org/" type="dynamic" pubdate="Wed, 05 Feb 2020 08:14:56 GMT">
    \\ <files>
    \\  <file name="repomd.xml">
    \\   <size>1234</size>
    \\   <verification>
    \\   </verification>
    \\   <resources maxconnections="1">
    \\    <url protocol="http" type="file" location="IN" preference="100">http://localhost:8080/photon-test/repodata/repomd.xml</url>
    \\   </resources>
    \\  </file>
    \\ </files>
    \\</metalink>
;

const entity_fixture =
    \\<metalink xmlns="urn:ietf:params:xml:ns:metalink">
    \\  <file name="repomd.xml">
    \\    <hash type="escaped">A&amp;B&lt;C&gt;D&quot;E&apos;F&#33;&#x3F;</hash>
    \\  </file>
    \\</metalink>
;

test "xml header ABI matches Zig callbacks struct" {
    const testing = std.testing;

    try testing.expectEqual(@sizeOf(c_xml.TDNF_METALINK_XML_CALLBACKS), @sizeOf(TDNF_METALINK_XML_CALLBACKS));
    try testing.expectEqual(@offsetOf(c_xml.TDNF_METALINK_XML_CALLBACKS, "pfnFile"), @offsetOf(TDNF_METALINK_XML_CALLBACKS, "pfnFile"));
    try testing.expectEqual(@offsetOf(c_xml.TDNF_METALINK_XML_CALLBACKS, "pfnSize"), @offsetOf(TDNF_METALINK_XML_CALLBACKS, "pfnSize"));
    try testing.expectEqual(@offsetOf(c_xml.TDNF_METALINK_XML_CALLBACKS, "pfnHash"), @offsetOf(TDNF_METALINK_XML_CALLBACKS, "pfnHash"));
    try testing.expectEqual(@offsetOf(c_xml.TDNF_METALINK_XML_CALLBACKS, "pfnUrl"), @offsetOf(TDNF_METALINK_XML_CALLBACKS, "pfnUrl"));
}

test "parses metalink 3.0 fixture and ignores foreign namespaces" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var recorder = Recorder.init(arena.allocator());
    try testing.expectEqual(@as(u32, 0), parseWithRecorder(metalink_v3_fixture, &recorder));

    try testing.expectEqual(@as(usize, 1), recorder.files.items.len);
    try testing.expectEqual(@as(usize, 1), recorder.sizes.items.len);
    try testing.expectEqual(@as(usize, 2), recorder.hashes.items.len);
    try testing.expectEqual(@as(usize, 2), recorder.urls.items.len);

    try testing.expectEqualStrings("repomd.xml", recorder.files.items[0]);
    try testing.expectEqualStrings("12345", recorder.sizes.items[0]);

    try testing.expectEqualStrings("sha256", recorder.hashes.items[0].hash_type);
    try testing.expectEqualStrings("abc1234", recorder.hashes.items[0].value);
    try testing.expectEqualStrings("sha512", recorder.hashes.items[1].hash_type);
    try testing.expectEqualStrings("def&ghi", recorder.hashes.items[1].value);

    try expectOptionalString("https", recorder.urls.items[0].protocol);
    try expectOptionalString("file", recorder.urls.items[0].url_type);
    try expectOptionalString("US", recorder.urls.items[0].location);
    try expectOptionalString("50", recorder.urls.items[0].ranking_attr);
    try testing.expect(!recorder.urls.items[0].ranking_is_priority);
    try testing.expectEqualStrings(
        "https://mirror1.example.com/repodata/repomd.xml",
        recorder.urls.items[0].value,
    );

    try expectOptionalString("https", recorder.urls.items[1].protocol);
    try expectOptionalString("file", recorder.urls.items[1].url_type);
    try expectOptionalString("DE", recorder.urls.items[1].location);
    try expectOptionalString("100", recorder.urls.items[1].ranking_attr);
    try testing.expect(!recorder.urls.items[1].ranking_is_priority);
    try testing.expectEqualStrings(
        "https://mirror2.example.com/repodata/repomd.xml?x=1&y=2",
        recorder.urls.items[1].value,
    );
}

test "parses metalink 4.0 fixture with priority ranking" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var recorder = Recorder.init(arena.allocator());
    try testing.expectEqual(@as(u32, 0), parseWithRecorder(metalink_v4_fixture, &recorder));

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

    var recorder = Recorder.init(arena.allocator());
    try testing.expectEqual(@as(u32, 0), parseWithRecorder(setup_repo_fixture, &recorder));

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
