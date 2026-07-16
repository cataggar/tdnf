const std = @import("std");
const header = @import("rpm_header");
const txn_config = @import("txn_config.zig");
const c = @cImport({
    @cInclude("time.h");
});

const Allocator = std.mem.Allocator;
const MAX_FIELD_WIDTH: usize = 1024 * 1024;

pub const Error = Allocator.Error ||
    txn_config.ExpandError ||
    error{
        MalformedQueryFormat,
        UnknownQueryTag,
        UnsupportedQueryModifier,
        MismatchedQueryArrays,
        InvalidQueryTagData,
        QueryFieldWidthTooLarge,
    };

pub const Options = struct {
    config: ?*const txn_config.TxnConfig = null,
};

const VirtualTag = enum {
    filenames,
    evr,
    nvr,
    nevr,
    nvra,
    nevra,
};

const ResolvedTag = struct {
    id: u32,
    canonical_name: []const u8,
    virtual: ?VirtualTag = null,
};

const Modifier = enum {
    string,
    dec,
    arraysize,
    date,
    day,
    depflags,
    deptype,
    expand,
    fflags,
    fstate,
    fstatus,
    hashalgo,
    hex,
    humaniec,
    humansi,
    octal,
    perms,
    shescape,
    tagname,
    tagnum,
    triggertype,
    vflags,
    xml,
};

const Placeholder = struct {
    end: usize,
    tag_name: []const u8,
    modifier: Modifier,
    locked: bool,
    width: usize,
    left_justify: bool,
};

const Conditional = struct {
    end: usize,
    tag_name: []const u8,
    present: []const u8,
    absent: []const u8,
};

const RenderContext = struct {
    iterator_index: ?usize = null,
};

const ValueData = union(enum) {
    missing,
    string: []const u8,
    number: u64,
    blob: []const u8,
};

const Value = struct {
    data: ValueData,
    owned: ?[]u8 = null,

    fn deinit(self: Value, allocator: Allocator) void {
        if (self.owned) |bytes| allocator.free(bytes);
    }
};

const IteratorLength = struct {
    value: usize = 0,
    has_value: bool = false,

    fn add(self: *IteratorLength, count: usize) Error!void {
        if (count == 0) return;
        if (!self.has_value) {
            self.value = count;
            self.has_value = true;
            return;
        }
        if (self.value != count) return error.MismatchedQueryArrays;
    }
};

pub fn format(
    allocator: Allocator,
    hdr: header.Header,
    query: []const u8,
    options: Options,
) Error![]u8 {
    try validateSegment(hdr, query, false);

    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    try renderSegment(
        allocator,
        hdr,
        query,
        options,
        .{},
        &output,
    );
    return output.toOwnedSlice(allocator);
}

pub fn validate(
    allocator: Allocator,
    hdr: header.Header,
    query: []const u8,
    options: Options,
) Error!void {
    const rendered = try format(allocator, hdr, query, options);
    allocator.free(rendered);
}

fn validateSegment(
    hdr: header.Header,
    query: []const u8,
    in_iterator: bool,
) Error!void {
    var cursor: usize = 0;
    while (cursor < query.len) {
        switch (query[cursor]) {
            '\\' => {
                if (cursor + 1 >= query.len or query[cursor + 1] == '0') {
                    return error.MalformedQueryFormat;
                }
                cursor += 2;
            },
            '%' => {
                if (cursor + 1 < query.len and query[cursor + 1] == '%') {
                    cursor += 2;
                    continue;
                }
                if (cursor + 1 < query.len and query[cursor + 1] == '|') {
                    const conditional = try parseConditional(query, cursor);
                    _ = try resolveTag(conditional.tag_name);
                    try validateSegment(hdr, conditional.present, in_iterator);
                    try validateSegment(hdr, conditional.absent, in_iterator);
                    cursor = conditional.end;
                    continue;
                }
                const placeholder = try parsePlaceholder(query, cursor);
                _ = try resolveTag(placeholder.tag_name);
                cursor = placeholder.end;
            },
            '[' => {
                if (in_iterator) return error.MalformedQueryFormat;
                const close = try findIteratorEnd(query, cursor);
                const body = query[cursor + 1 .. close];
                try validateSegment(hdr, body, true);
                _ = try iteratorLength(hdr, body);
                cursor = close + 1;
            },
            ']', '{', '}' => return error.MalformedQueryFormat,
            else => cursor += 1,
        }
    }
}

fn renderSegment(
    allocator: Allocator,
    hdr: header.Header,
    query: []const u8,
    options: Options,
    context: RenderContext,
    output: *std.ArrayList(u8),
) Error!void {
    var cursor: usize = 0;
    while (cursor < query.len) {
        switch (query[cursor]) {
            '\\' => {
                try appendEscape(allocator, output, query[cursor + 1]);
                cursor += 2;
            },
            '%' => {
                if (query[cursor + 1] == '%') {
                    try output.append(allocator, '%');
                    cursor += 2;
                    continue;
                }
                if (query[cursor + 1] == '|') {
                    const conditional = try parseConditional(query, cursor);
                    const tag = try resolveTag(conditional.tag_name);
                    const branch = if (tagPresent(hdr, tag))
                        conditional.present
                    else
                        conditional.absent;
                    try renderSegment(
                        allocator,
                        hdr,
                        branch,
                        options,
                        context,
                        output,
                    );
                    cursor = conditional.end;
                    continue;
                }
                const placeholder = try parsePlaceholder(query, cursor);
                try renderPlaceholder(
                    allocator,
                    hdr,
                    placeholder,
                    options,
                    context,
                    output,
                );
                cursor = placeholder.end;
            },
            '[' => {
                const close = try findIteratorEnd(query, cursor);
                const body = query[cursor + 1 .. close];
                const count = try iteratorLength(hdr, body);
                for (0..count) |index| {
                    try renderSegment(
                        allocator,
                        hdr,
                        body,
                        options,
                        .{ .iterator_index = index },
                        output,
                    );
                }
                cursor = close + 1;
            },
            else => {
                try output.append(allocator, query[cursor]);
                cursor += 1;
            },
        }
    }
}

fn renderPlaceholder(
    allocator: Allocator,
    hdr: header.Header,
    placeholder: Placeholder,
    options: Options,
    context: RenderContext,
    output: *std.ArrayList(u8),
) Error!void {
    const tag = try resolveTag(placeholder.tag_name);
    const index = if (placeholder.locked)
        0
    else
        context.iterator_index orelse 0;
    const value = try tagValue(allocator, hdr, tag, index);
    defer value.deinit(allocator);
    const rendered = try formatValue(
        allocator,
        hdr,
        tag,
        value.data,
        placeholder.modifier,
        options,
    );
    defer allocator.free(rendered);

    const padding = placeholder.width -| rendered.len;
    if (!placeholder.left_justify) {
        try output.appendNTimes(allocator, ' ', padding);
    }
    try output.appendSlice(allocator, rendered);
    if (placeholder.left_justify) {
        try output.appendNTimes(allocator, ' ', padding);
    }
}

fn parsePlaceholder(query: []const u8, start: usize) Error!Placeholder {
    var cursor = start + 1;
    var left_justify = false;
    var saw_width = false;
    var width: usize = 0;

    if (cursor < query.len and query[cursor] == '-') {
        left_justify = true;
        cursor += 1;
    }
    while (cursor < query.len and std.ascii.isDigit(query[cursor])) {
        saw_width = true;
        width = std.math.mul(usize, width, 10) catch
            return error.QueryFieldWidthTooLarge;
        width = std.math.add(usize, width, query[cursor] - '0') catch
            return error.QueryFieldWidthTooLarge;
        if (width > MAX_FIELD_WIDTH) return error.QueryFieldWidthTooLarge;
        cursor += 1;
    }
    if (left_justify and !saw_width) return error.MalformedQueryFormat;
    if (cursor >= query.len or query[cursor] != '{') {
        return error.MalformedQueryFormat;
    }
    const close = std.mem.indexOfScalarPos(
        u8,
        query,
        cursor + 1,
        '}',
    ) orelse return error.MalformedQueryFormat;
    var expression = query[cursor + 1 .. close];
    if (expression.len == 0) return error.MalformedQueryFormat;

    const locked = expression[0] == '=';
    if (locked) {
        expression = expression[1..];
        if (expression.len == 0) return error.MalformedQueryFormat;
    }
    const separator = std.mem.indexOfScalar(u8, expression, ':');
    const tag_name = if (separator) |index|
        expression[0..index]
    else
        expression;
    const modifier_name = if (separator) |index|
        expression[index + 1 ..]
    else
        "string";
    if (tag_name.len == 0 or modifier_name.len == 0) {
        return error.MalformedQueryFormat;
    }

    return .{
        .end = close + 1,
        .tag_name = tag_name,
        .modifier = try parseModifier(modifier_name),
        .locked = locked,
        .width = width,
        .left_justify = left_justify,
    };
}

fn parseModifier(name: []const u8) Error!Modifier {
    inline for (std.meta.fields(Modifier)) |field| {
        if (std.mem.eql(u8, name, field.name)) {
            return @enumFromInt(field.value);
        }
    }
    return error.UnsupportedQueryModifier;
}

fn parseConditional(query: []const u8, start: usize) Error!Conditional {
    const expression_start = start + 2;
    const question = std.mem.indexOfScalarPos(
        u8,
        query,
        expression_start,
        '?',
    ) orelse return error.MalformedQueryFormat;
    const tag_name = query[expression_start..question];
    if (tag_name.len == 0 or question + 1 >= query.len or
        query[question + 1] != '{')
    {
        return error.MalformedQueryFormat;
    }

    const present_close = try findMatchingBrace(query, question + 1);
    if (present_close + 2 >= query.len or
        query[present_close + 1] != ':' or
        query[present_close + 2] != '{')
    {
        return error.MalformedQueryFormat;
    }
    const absent_open = present_close + 2;
    const absent_close = try findMatchingBrace(query, absent_open);
    if (absent_close + 1 >= query.len or query[absent_close + 1] != '|') {
        return error.MalformedQueryFormat;
    }

    return .{
        .end = absent_close + 2,
        .tag_name = tag_name,
        .present = query[question + 2 .. present_close],
        .absent = query[absent_open + 1 .. absent_close],
    };
}

fn findMatchingBrace(query: []const u8, open: usize) Error!usize {
    var depth: usize = 0;
    var cursor = open;
    while (cursor < query.len) : (cursor += 1) {
        if (query[cursor] == '\\') {
            if (cursor + 1 >= query.len) return error.MalformedQueryFormat;
            cursor += 1;
            continue;
        }
        if (query[cursor] == '{') {
            depth += 1;
        } else if (query[cursor] == '}') {
            if (depth == 0) return error.MalformedQueryFormat;
            depth -= 1;
            if (depth == 0) return cursor;
        }
    }
    return error.MalformedQueryFormat;
}

fn findIteratorEnd(query: []const u8, open: usize) Error!usize {
    var cursor = open + 1;
    while (cursor < query.len) : (cursor += 1) {
        if (query[cursor] == '\\') {
            if (cursor + 1 >= query.len) return error.MalformedQueryFormat;
            cursor += 1;
            continue;
        }
        if (query[cursor] == '[') return error.MalformedQueryFormat;
        if (query[cursor] == ']') return cursor;
    }
    return error.MalformedQueryFormat;
}

fn iteratorLength(hdr: header.Header, body: []const u8) Error!usize {
    var length = IteratorLength{};
    try collectIteratorLengths(hdr, body, &length);
    return if (length.has_value) length.value else 0;
}

fn collectIteratorLengths(
    hdr: header.Header,
    query: []const u8,
    length: *IteratorLength,
) Error!void {
    var cursor: usize = 0;
    while (cursor < query.len) {
        if (query[cursor] == '\\') {
            cursor += 2;
            continue;
        }
        if (query[cursor] != '%') {
            cursor += 1;
            continue;
        }
        if (query[cursor + 1] == '%') {
            cursor += 2;
            continue;
        }
        if (query[cursor + 1] == '|') {
            const conditional = try parseConditional(query, cursor);
            try collectIteratorLengths(hdr, conditional.present, length);
            try collectIteratorLengths(hdr, conditional.absent, length);
            cursor = conditional.end;
            continue;
        }
        const placeholder = try parsePlaceholder(query, cursor);
        if (!placeholder.locked) {
            const tag = try resolveTag(placeholder.tag_name);
            try length.add(try tagElementCount(hdr, tag));
        }
        cursor = placeholder.end;
    }
}

fn resolveTag(raw_name: []const u8) Error!ResolvedTag {
    const name = if (startsWithIgnoreCase(raw_name, "RPMTAG_"))
        raw_name["RPMTAG_".len..]
    else
        raw_name;

    const virtual_tags = [_]struct {
        name: []const u8,
        id: u32,
        value: VirtualTag,
    }{
        .{ .name = "FILENAMES", .id = 5000, .value = .filenames },
        .{ .name = "EVR", .id = 5013, .value = .evr },
        .{ .name = "NVR", .id = 5014, .value = .nvr },
        .{ .name = "NEVR", .id = 5015, .value = .nevr },
        .{ .name = "NVRA", .id = 1196, .value = .nvra },
        .{ .name = "NEVRA", .id = 5016, .value = .nevra },
    };
    for (virtual_tags) |item| {
        if (normalizedTagEqual(name, item.name)) {
            return .{
                .id = item.id,
                .canonical_name = item.name,
                .virtual = item.value,
            };
        }
    }

    inline for (std.meta.fields(header.TagId)) |field| {
        if (!std.mem.eql(u8, field.name, "_") and
            normalizedTagEqual(name, field.name))
        {
            return .{
                .id = field.value,
                .canonical_name = field.name,
            };
        }
    }
    return error.UnknownQueryTag;
}

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    return value.len >= prefix.len and
        std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix);
}

fn normalizedTagEqual(left: []const u8, right: []const u8) bool {
    var left_index: usize = 0;
    var right_index: usize = 0;
    while (true) {
        while (left_index < left.len and
            !std.ascii.isAlphanumeric(left[left_index]))
        {
            left_index += 1;
        }
        while (right_index < right.len and
            !std.ascii.isAlphanumeric(right[right_index]))
        {
            right_index += 1;
        }
        if (left_index == left.len or right_index == right.len) {
            return left_index == left.len and right_index == right.len;
        }
        if (std.ascii.toLower(left[left_index]) !=
            std.ascii.toLower(right[right_index]))
        {
            return false;
        }
        left_index += 1;
        right_index += 1;
    }
}

fn tagPresent(hdr: header.Header, tag: ResolvedTag) bool {
    if (tag.virtual) |virtual| {
        return switch (virtual) {
            .filenames => hdr.find(.basenames) != null and
                hdr.find(.dirindexes) != null and
                hdr.find(.dirnames) != null,
            .evr => hdr.getString(.version) != null and
                hdr.getString(.release) != null,
            .nvr, .nevr, .nvra, .nevra => hdr.getString(.name) != null and
                hdr.getString(.version) != null and
                hdr.getString(.release) != null,
        };
    }
    return hdr.findRaw(tag.id) != null;
}

fn tagElementCount(hdr: header.Header, tag: ResolvedTag) Error!usize {
    if (tag.virtual) |virtual| {
        return switch (virtual) {
            .filenames => hdr.stringArrayCount(.basenames),
            .evr, .nvr, .nevr, .nvra, .nevra => if (tagPresent(hdr, tag)) 1 else 0,
        };
    }
    const entry = hdr.findRaw(tag.id) orelse return 0;
    return switch (@as(header.TypeId, @enumFromInt(entry.typ))) {
        .string, .i18n_string, .bin => 1,
        .char_type, .int8, .int16, .int32, .int64, .string_array => std.math.cast(usize, entry.count) orelse
            error.InvalidQueryTagData,
        else => error.InvalidQueryTagData,
    };
}

fn tagValue(
    allocator: Allocator,
    hdr: header.Header,
    tag: ResolvedTag,
    index: usize,
) Error!Value {
    if (tag.virtual) |virtual| {
        return virtualTagValue(allocator, hdr, virtual, index);
    }
    const entry = hdr.findRaw(tag.id) orelse
        return .{ .data = .missing };
    const count = try tagElementCount(hdr, tag);
    const value_index = if (@as(header.TypeId, @enumFromInt(entry.typ)) ==
        .i18n_string) 0 else index;
    if (value_index >= count) return error.InvalidQueryTagData;

    return switch (@as(header.TypeId, @enumFromInt(entry.typ))) {
        .string, .i18n_string => .{
            .data = .{ .string = hdr.getStringRaw(tag.id) orelse
                return error.InvalidQueryTagData },
        },
        .string_array => .{
            .data = .{ .string = hdr.stringArrayItemRaw(
                tag.id,
                value_index,
            ) orelse return error.InvalidQueryTagData },
        },
        .char_type, .int8 => blk: {
            const bytes = hdr.rawEntryBytes(entry) orelse
                return error.InvalidQueryTagData;
            break :blk .{ .data = .{ .number = bytes[value_index] } };
        },
        .int16 => blk: {
            const bytes = hdr.rawEntryBytes(entry) orelse
                return error.InvalidQueryTagData;
            const offset = value_index * 2;
            break :blk .{ .data = .{ .number = readBigEndian(
                bytes[offset .. offset + 2],
            ) } };
        },
        .int32 => .{
            .data = .{ .number = hdr.u32ArrayItemRaw(
                tag.id,
                value_index,
            ) orelse return error.InvalidQueryTagData },
        },
        .int64 => blk: {
            const bytes = hdr.rawEntryBytes(entry) orelse
                return error.InvalidQueryTagData;
            const offset = value_index * 8;
            break :blk .{ .data = .{ .number = readBigEndian(
                bytes[offset .. offset + 8],
            ) } };
        },
        .bin => .{
            .data = .{ .blob = hdr.rawEntryBytes(entry) orelse
                return error.InvalidQueryTagData },
        },
        else => error.InvalidQueryTagData,
    };
}

fn virtualTagValue(
    allocator: Allocator,
    hdr: header.Header,
    tag: VirtualTag,
    index: usize,
) Error!Value {
    if (!tagPresent(hdr, .{
        .id = 0,
        .canonical_name = "",
        .virtual = tag,
    })) {
        return .{ .data = .missing };
    }
    if (tag != .filenames and index != 0) {
        return error.InvalidQueryTagData;
    }

    const bytes = switch (tag) {
        .filenames => blk: {
            const basename = hdr.stringArrayItem(.basenames, index) orelse
                return error.InvalidQueryTagData;
            const directory_index = hdr.u32ArrayItem(.dirindexes, index) orelse
                return error.InvalidQueryTagData;
            const directory = hdr.stringArrayItem(
                .dirnames,
                directory_index,
            ) orelse return error.InvalidQueryTagData;
            break :blk try std.fmt.allocPrint(
                allocator,
                "{s}{s}",
                .{ directory, basename },
            );
        },
        .evr => (try hdr.allocEvr(allocator)) orelse
            return error.InvalidQueryTagData,
        .nvr => try packageLabel(allocator, hdr, false, false),
        .nevr => try packageLabel(allocator, hdr, true, false),
        .nvra => try packageLabel(allocator, hdr, false, true),
        .nevra => (try hdr.allocNevra(allocator)) orelse
            return error.InvalidQueryTagData,
    };
    return .{
        .data = .{ .string = bytes },
        .owned = bytes,
    };
}

fn packageLabel(
    allocator: Allocator,
    hdr: header.Header,
    include_epoch: bool,
    include_arch: bool,
) Error![]u8 {
    const name = hdr.getString(.name) orelse
        return error.InvalidQueryTagData;
    const version = hdr.getString(.version) orelse
        return error.InvalidQueryTagData;
    const release = hdr.getString(.release) orelse
        return error.InvalidQueryTagData;
    const arch = hdr.getString(.arch) orelse "(none)";
    if (include_epoch) {
        if (hdr.getU32(.epoch)) |epoch| {
            if (include_arch) {
                return std.fmt.allocPrint(
                    allocator,
                    "{s}-{d}:{s}-{s}.{s}",
                    .{ name, epoch, version, release, arch },
                );
            }
            return std.fmt.allocPrint(
                allocator,
                "{s}-{d}:{s}-{s}",
                .{ name, epoch, version, release },
            );
        }
    }
    if (include_arch) {
        return std.fmt.allocPrint(
            allocator,
            "{s}-{s}-{s}.{s}",
            .{ name, version, release, arch },
        );
    }
    return std.fmt.allocPrint(
        allocator,
        "{s}-{s}-{s}",
        .{ name, version, release },
    );
}

fn readBigEndian(bytes: []const u8) u64 {
    var result: u64 = 0;
    for (bytes) |byte| {
        result = (result << 8) | byte;
    }
    return result;
}

fn formatValue(
    allocator: Allocator,
    hdr: header.Header,
    tag: ResolvedTag,
    value: ValueData,
    modifier: Modifier,
    options: Options,
) Error![]u8 {
    if (value == .missing) return allocator.dupe(u8, "(none)");

    return switch (modifier) {
        .string, .dec => defaultValue(allocator, value),
        .arraysize => std.fmt.allocPrint(
            allocator,
            "{d}",
            .{try tagElementCount(hdr, tag)},
        ),
        .date => formatDate(allocator, value, "%c"),
        .day => formatDate(allocator, value, "%a %b %d %Y"),
        .depflags => formatDepFlags(allocator, value),
        .deptype => formatDepType(allocator, value),
        .expand => blk: {
            const text = try defaultValue(allocator, value);
            defer allocator.free(text);
            const config = options.config orelse
                return error.UnsupportedQueryModifier;
            break :blk config.expandTextAlloc(allocator, text);
        },
        .fflags => formatFileFlags(allocator, value),
        .fstate => formatFileState(allocator, value),
        .fstatus, .vflags => formatVerifyFlags(allocator, value),
        .hashalgo => formatHashAlgorithm(allocator, value),
        .hex => formatNumber(allocator, value, .hex),
        .humaniec => formatHuman(allocator, value, 1024),
        .humansi => formatHuman(allocator, value, 1000),
        .octal => formatNumber(allocator, value, .octal),
        .perms => formatPermissions(allocator, value),
        .shescape => formatShellEscape(allocator, value),
        .tagname => formatTagName(allocator, tag),
        .tagnum => std.fmt.allocPrint(allocator, "{d}", .{tag.id}),
        .triggertype => formatTriggerType(allocator, value),
        .xml => formatXml(allocator, value),
    };
}

fn defaultValue(allocator: Allocator, value: ValueData) Error![]u8 {
    return switch (value) {
        .missing => allocator.dupe(u8, "(none)"),
        .string => |text| allocator.dupe(u8, text),
        .number => |number| std.fmt.allocPrint(
            allocator,
            "{d}",
            .{number},
        ),
        .blob => |bytes| formatBlobHex(allocator, bytes),
    };
}

const NumberBase = enum {
    hex,
    octal,
};

fn formatNumber(
    allocator: Allocator,
    value: ValueData,
    base: NumberBase,
) Error![]u8 {
    const number = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    return switch (base) {
        .hex => std.fmt.allocPrint(allocator, "{x}", .{number}),
        .octal => std.fmt.allocPrint(allocator, "{o}", .{number}),
    };
}

fn formatBlobHex(allocator: Allocator, bytes: []const u8) Error![]u8 {
    const result = try allocator.alloc(u8, bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        result[index * 2] = digits[byte >> 4];
        result[index * 2 + 1] = digits[byte & 0x0f];
    }
    return result;
}

fn formatDate(
    allocator: Allocator,
    value: ValueData,
    pattern: [*:0]const u8,
) Error![]u8 {
    const number = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    var timestamp: c.time_t = std.math.cast(c.time_t, number) orelse
        return allocator.dupe(u8, "(not a date)");
    var broken_down: c.struct_tm = undefined;
    if (c.localtime_r(&timestamp, &broken_down) == null) {
        return allocator.dupe(u8, "(not a date)");
    }
    var buffer: [256]u8 = undefined;
    const count = c.strftime(
        &buffer,
        buffer.len,
        pattern,
        &broken_down,
    );
    if (count == 0) return allocator.dupe(u8, "(not a date)");
    return allocator.dupe(u8, buffer[0..count]);
}

fn formatHuman(
    allocator: Allocator,
    value: ValueData,
    base: u64,
) Error![]u8 {
    const number = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    const suffixes = " KMGTPE";
    var scaled: f64 = @floatFromInt(number);
    var suffix_index: usize = 0;
    while (scaled >= @as(f64, @floatFromInt(base)) and
        suffix_index + 1 < suffixes.len)
    {
        scaled /= @floatFromInt(base);
        suffix_index += 1;
    }
    if (suffix_index == 0) {
        return std.fmt.allocPrint(allocator, "{d:.1}", .{scaled});
    }
    return std.fmt.allocPrint(
        allocator,
        "{d:.1}{c}",
        .{ scaled, suffixes[suffix_index] },
    );
}

fn formatShellEscape(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const text = try defaultValue(allocator, value);
    defer allocator.free(text);
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, '\'');
    for (text) |byte| {
        if (byte == '\'') {
            try output.appendSlice(allocator, "'\\''");
        } else {
            try output.append(allocator, byte);
        }
    }
    try output.append(allocator, '\'');
    return output.toOwnedSlice(allocator);
}

fn formatPermissions(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const mode = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    var result = [_]u8{ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' };
    result[0] = switch (mode & 0o170000) {
        0o010000 => 'p',
        0o020000 => 'c',
        0o040000 => 'd',
        0o060000 => 'b',
        0o100000 => '-',
        0o120000 => 'l',
        0o140000 => 's',
        else => '?',
    };
    const masks = [_]u64{
        0o400, 0o200, 0o100,
        0o040, 0o020, 0o010,
        0o004, 0o002, 0o001,
    };
    const chars = "rwxrwxrwx";
    for (masks, 0..) |mask, index| {
        if ((mode & mask) != 0) result[index + 1] = chars[index];
    }
    if ((mode & 0o4000) != 0) {
        result[3] = if ((mode & 0o100) != 0) 's' else 'S';
    }
    if ((mode & 0o2000) != 0) {
        result[6] = if ((mode & 0o010) != 0) 's' else 'S';
    }
    if ((mode & 0o1000) != 0) {
        result[9] = if ((mode & 0o001) != 0) 't' else 'T';
    }
    return allocator.dupe(u8, &result);
}

fn formatFileFlags(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const flags = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    const mappings = [_]struct { mask: u64, char: u8 }{
        .{ .mask = 1 << 0, .char = 'c' },
        .{ .mask = 1 << 1, .char = 'd' },
        .{ .mask = 1 << 2, .char = 'i' },
        .{ .mask = 1 << 3, .char = 'm' },
        .{ .mask = 1 << 4, .char = 'n' },
        .{ .mask = 1 << 5, .char = 's' },
        .{ .mask = 1 << 6, .char = 'g' },
        .{ .mask = 1 << 7, .char = 'l' },
        .{ .mask = 1 << 8, .char = 'r' },
        .{ .mask = 1 << 11, .char = 'p' },
        .{ .mask = 1 << 12, .char = 'a' },
    };
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    for (mappings) |mapping| {
        if ((flags & mapping.mask) != 0) {
            try output.append(allocator, mapping.char);
        }
    }
    return output.toOwnedSlice(allocator);
}

fn formatVerifyFlags(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const flags = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    const chars = "SM?D?UGTP";
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    for (chars, 0..) |char, bit| {
        if ((flags & (@as(u64, 1) << @intCast(bit))) != 0) {
            try output.append(allocator, char);
        }
    }
    return output.toOwnedSlice(allocator);
}

fn formatFileState(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const state = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    const text = switch (state) {
        0 => "normal",
        1 => "replaced",
        2 => "not installed",
        3 => "net shared",
        4 => "wrong color",
        else => "(unknown)",
    };
    return allocator.dupe(u8, text);
}

fn formatDepFlags(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const flags = switch (value) {
        .number => |item| item & 0x0f,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    const text = switch (flags) {
        2 => "<",
        4 => ">",
        8 => "=",
        10 => "<=",
        12 => ">=",
        else => "",
    };
    return allocator.dupe(u8, text);
}

fn formatDepType(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const flags = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    const mappings = [_]struct { mask: u64, text: []const u8 }{
        .{ .mask = 1 << 8, .text = "interp" },
        .{ .mask = 1 << 9, .text = "pre" },
        .{ .mask = 1 << 10, .text = "post" },
        .{ .mask = 1 << 11, .text = "preun" },
        .{ .mask = 1 << 12, .text = "postun" },
        .{ .mask = 1 << 5, .text = "posttrans" },
        .{ .mask = 1 << 14, .text = "auto" },
        .{ .mask = 1 << 24, .text = "rpmlib" },
        .{ .mask = 1 << 28, .text = "config" },
        .{ .mask = 1 << 29, .text = "meta" },
    };
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    for (mappings) |mapping| {
        if ((flags & mapping.mask) == 0) continue;
        if (output.items.len != 0) try output.append(allocator, ',');
        try output.appendSlice(allocator, mapping.text);
    }
    if (output.items.len == 0) {
        try output.appendSlice(allocator, "manual");
    }
    return output.toOwnedSlice(allocator);
}

fn formatTriggerType(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const flags = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    const text = if ((flags & (1 << 16)) != 0)
        "in"
    else if ((flags & (1 << 17)) != 0)
        "un"
    else if ((flags & (1 << 18)) != 0)
        "postun"
    else
        "";
    return allocator.dupe(u8, text);
}

fn formatHashAlgorithm(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    const algorithm = switch (value) {
        .number => |item| item,
        else => return allocator.dupe(u8, "(not a number)"),
    };
    const text = switch (algorithm) {
        0 => "unknown",
        1 => "md5",
        2 => "sha1",
        8 => "sha256",
        9 => "sha384",
        10 => "sha512",
        11 => "sha224",
        12 => "sha3-256",
        13 => "sha3-512",
        else => "unknown",
    };
    return allocator.dupe(u8, text);
}

fn formatTagName(
    allocator: Allocator,
    tag: ResolvedTag,
) Error![]u8 {
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    for (tag.canonical_name) |byte| {
        if (byte == '_') continue;
        const normalized = std.ascii.toLower(byte);
        try output.append(
            allocator,
            if (output.items.len == 0)
                std.ascii.toUpper(normalized)
            else
                normalized,
        );
    }
    return output.toOwnedSlice(allocator);
}

fn formatXml(
    allocator: Allocator,
    value: ValueData,
) Error![]u8 {
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    switch (value) {
        .string => |text| {
            try output.appendSlice(allocator, "\t<string>");
            try appendXmlEscaped(allocator, &output, text);
            try output.appendSlice(allocator, "</string>");
        },
        .number => |number| {
            try output.appendSlice(allocator, "\t<integer>");
            const text = try std.fmt.allocPrint(
                allocator,
                "{d}",
                .{number},
            );
            defer allocator.free(text);
            try output.appendSlice(allocator, text);
            try output.appendSlice(allocator, "</integer>");
        },
        .blob => return error.UnsupportedQueryModifier,
        .missing => unreachable,
    }
    return output.toOwnedSlice(allocator);
}

fn appendXmlEscaped(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    text: []const u8,
) Error!void {
    for (text) |byte| {
        const replacement: ?[]const u8 = switch (byte) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            else => null,
        };
        if (replacement) |escaped| {
            try output.appendSlice(allocator, escaped);
        } else {
            try output.append(allocator, byte);
        }
    }
}

fn appendEscape(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    escaped: u8,
) Error!void {
    const value: u8 = switch (escaped) {
        'a' => 0x07,
        'b' => 0x08,
        'f' => 0x0c,
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => 0x0b,
        else => escaped,
    };
    try output.append(allocator, value);
}
