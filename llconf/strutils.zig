// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

const c = @cImport({
    @cInclude("ctype.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("strutils.h");
});

fn duplicateBytes(bytes: []const u8) [*c]u8 {
    const raw = c.malloc(bytes.len + 1) orelse return null;
    const out: [*]u8 = @ptrCast(raw);
    @memcpy(out[0..bytes.len], bytes);
    out[bytes.len] = 0;
    return @ptrCast(out);
}

fn duplicateCString(psz: [*c]const u8) [*c]u8 {
    if (psz == null) {
        return null;
    }
    return duplicateBytes(std.mem.span(@as([*:0]const u8, @ptrCast(psz))));
}

fn cString(ptr: [*c]const u8) []const u8 {
    return std.mem.span(@as([*:0]const u8, @ptrCast(ptr)));
}

fn isSpace(ch: u8) bool {
    return c.isspace(@as(c_int, ch)) != 0;
}

fn copyLimit(n: c_int) usize {
    return if (n > 0) @as(usize, @intCast(n)) else 0;
}

export fn dup_next_word(pp: [*c][*c]const u8) [*c]u8 {
    var tmpbuf = [_:0]u8{0} ** 1024;
    _ = dup_next_word_b(pp, @ptrCast(&tmpbuf), @as(c_int, @intCast(tmpbuf.len - 1)));
    return duplicateCString(@ptrCast(&tmpbuf));
}

export fn dup_next_word_b(pp: [*c][*c]const u8, buf: [*c]u8, n: c_int) [*c]u8 {
    var p = pp[0];
    var q = buf;
    var copied: usize = 0;
    const limit = copyLimit(n);

    while (p[0] != 0 and isSpace(p[0])) {
        p += 1;
    }
    while (p[0] != 0 and !isSpace(p[0]) and copied < limit) {
        q[0] = p[0];
        q += 1;
        p += 1;
        copied += 1;
    }

    q[0] = 0;
    pp[0] = p;
    return buf;
}

export fn dup_next_quoted(pp: [*c][*c]const u8, qchar: u8) [*c]u8 {
    var tmpbuf = [_:0]u8{0} ** 1024;
    if (dup_next_quoted_b(pp, @ptrCast(&tmpbuf), @as(c_int, @intCast(tmpbuf.len - 1)), qchar) == null) {
        return null;
    }
    return duplicateCString(@ptrCast(&tmpbuf));
}

export fn dup_next_quoted_b(pp: [*c][*c]const u8, buf: [*c]u8, n: c_int, qchar: u8) [*c]u8 {
    var p = pp[0];
    var q = buf;
    var copied: usize = 0;
    const limit = copyLimit(n);
    var prev: u8 = 0;

    while (p[0] != 0 and isSpace(p[0])) {
        p += 1;
    }
    if (p[0] != qchar) {
        return null;
    }

    p += 1;
    while (p[0] != 0 and (p[0] != qchar or prev == '\\') and copied < limit) {
        q[0] = p[0];
        prev = p[0];
        q += 1;
        p += 1;
        copied += 1;
    }

    p += 1;
    q[0] = 0;
    pp[0] = p;
    return buf;
}

export fn dup_next_line(pp: [*c][*c]const u8) [*c]u8 {
    var tmpbuf = [_:0]u8{0} ** 1024;
    _ = dup_next_line_b(pp, @ptrCast(&tmpbuf), @as(c_int, @intCast(tmpbuf.len - 1)));
    return duplicateCString(@ptrCast(&tmpbuf));
}

export fn dup_next_line_b(pp: [*c][*c]const u8, buf: [*c]u8, n: c_int) [*c]u8 {
    var p = pp[0];
    var q = buf;
    var copied: usize = 0;
    const limit = copyLimit(n);

    while (p[0] != 0 and p[0] != '\n' and copied < limit) {
        q[0] = p[0];
        q += 1;
        p += 1;
        copied += 1;
    }

    q[0] = 0;
    pp[0] = p;
    return buf;
}

export fn dup_line_until(pp: [*c][*c]const u8, until: u8) [*c]u8 {
    var tmpbuf = [_:0]u8{0} ** 1024;
    _ = dup_line_until_b(pp, until, @ptrCast(&tmpbuf), @as(c_int, @intCast(tmpbuf.len - 1)));
    return duplicateCString(@ptrCast(&tmpbuf));
}

export fn dup_line_until_b(pp: [*c][*c]const u8, until: u8, buf: [*c]u8, n: c_int) [*c]u8 {
    var p = pp[0];
    var q = buf;
    var copied: usize = 0;
    const limit = copyLimit(n);

    while (p[0] != 0 and p[0] != '\n' and p[0] != until and copied < limit) {
        q[0] = p[0];
        q += 1;
        p += 1;
        copied += 1;
    }

    q[0] = 0;
    pp[0] = p;
    return buf;
}

export fn dup_quote_string(string: [*c]const u8, qchar: u8) [*c]u8 {
    const input = std.mem.span(@as([*:0]const u8, @ptrCast(string)));
    var needed: usize = 3;
    for (input) |ch| {
        if (ch == qchar) {
            needed += 1;
        }
        needed += 1;
    }

    const raw = c.malloc(needed) orelse return null;
    const out: [*]u8 = @ptrCast(raw);
    var written: usize = 0;

    out[written] = qchar;
    written += 1;
    for (input) |ch| {
        if (ch == qchar) {
            out[written] = '\\';
            written += 1;
        }
        out[written] = ch;
        written += 1;
    }
    out[written] = qchar;
    written += 1;
    out[written] = 0;

    return @ptrCast(out);
}

export fn dup_unquote_string(qstring: [*c]const u8, qchar: u8) [*c]u8 {
    const input = std.mem.span(@as([*:0]const u8, @ptrCast(qstring)));
    const raw = c.malloc(input.len + 1) orelse return null;
    const out: [*]u8 = @ptrCast(raw);
    var written: usize = 0;
    var p = qstring;

    if (p[0] == qchar) {
        p += 1;
    }

    while (p[0] != 0) {
        if (!(p[0] == '\\' and (p + 1)[0] == qchar)) {
            out[written] = p[0];
            written += 1;
            p += 1;
        } else {
            p += 1;
        }
    }

    if (written > 0 and out[written - 1] == qchar) {
        written -= 1;
    }
    out[written] = 0;
    return @ptrCast(out);
}

export fn dup_unquote_string_ifquoted(qstring: [*c]const u8, qchar: u8) [*c]u8 {
    if (qstring[0] == qchar) {
        return dup_unquote_string(qstring, qchar);
    }
    return duplicateCString(qstring);
}

export fn cp_spaces(pp: [*c][*c]const u8, pq: [*c][*c]u8, n: c_int) void {
    var p = pp[0];
    var q = pq[0];
    var copied: usize = 0;
    const limit = copyLimit(n);

    while (p[0] != 0 and isSpace(p[0]) and copied < limit) {
        q[0] = p[0];
        q += 1;
        p += 1;
        copied += 1;
    }

    pp[0] = p;
    pq[0] = q;
}

export fn cp_word(pp: [*c][*c]const u8, pq: [*c][*c]u8, n: c_int) void {
    var p = pp[0];
    var q = pq[0];
    var copied: usize = 0;
    const limit = copyLimit(n);

    while (p[0] != 0 and !isSpace(p[0]) and copied < limit) {
        q[0] = p[0];
        q += 1;
        p += 1;
        copied += 1;
    }

    pp[0] = p;
    pq[0] = q;
}

export fn cp_quoted(pp: [*c][*c]const u8, pq: [*c][*c]u8, n: c_int) void {
    var p = pp[0];
    var q = pq[0];
    var copied: usize = 0;
    const limit = copyLimit(n);
    const qchar = p[0];
    var prev = qchar;

    q[0] = p[0];
    q += 1;
    p += 1;
    copied += 1;

    while (p[0] != 0 and (p[0] != qchar or prev == '\\') and copied < limit) {
        q[0] = p[0];
        prev = p[0];
        q += 1;
        p += 1;
        copied += 1;
    }

    if (p[0] == qchar) {
        q[0] = p[0];
        q += 1;
        p += 1;
    }

    pp[0] = p;
    pq[0] = q;
}

export fn cp_quoted_ifquoted(pp: [*c][*c]const u8, pq: [*c][*c]u8, n: c_int, qchar: u8) void {
    if (pp[0][0] == qchar) {
        cp_quoted(pp, pq, n);
    } else {
        cp_word(pp, pq, n);
    }
}

export fn skip_spaces(pp: [*c][*c]const u8) void {
    var p = pp[0];
    while (p[0] != 0 and isSpace(p[0])) {
        p += 1;
    }
    pp[0] = p;
}

export fn skip_word(pp: [*c][*c]const u8) void {
    var p = pp[0];
    while (p[0] != 0 and !isSpace(p[0])) {
        p += 1;
    }
    pp[0] = p;
}

export fn skip_quoted(pp: [*c][*c]const u8) void {
    var p = pp[0];
    const qchar = p[0];
    var prev = qchar;

    p += 1;
    while (p[0] != 0 and (p[0] != qchar or prev == '\\')) {
        prev = p[0];
        p += 1;
    }

    if (p[0] == qchar) {
        p += 1;
    }

    pp[0] = p;
}

export fn skip_quoted_ifquoted(pp: [*c][*c]const u8, qchar: u8) void {
    if (pp[0][0] == qchar) {
        skip_quoted(pp);
    } else {
        skip_word(pp);
    }
}

export fn strjoin(str1: [*c]const u8, str2: [*c]const u8) [*c]u8 {
    if (str1 == null and str2 == null) {
        return null;
    }
    if (str2 == null) {
        return duplicateCString(str1);
    }
    if (str1 == null) {
        return duplicateCString(str2);
    }

    const left = cString(str1);
    const right = cString(str2);
    const raw = c.malloc(left.len + right.len + 1) orelse return null;
    const out: [*]u8 = @ptrCast(raw);
    @memcpy(out[0..left.len], left);
    @memcpy(out[left.len .. left.len + right.len], right);
    out[left.len + right.len] = 0;
    return @ptrCast(out);
}

test "dup helpers preserve tokens and escapes" {
    var p: [*c]const u8 = "  alpha beta";
    const word = dup_next_word(&p);
    if (word == null) {
        return error.TestUnexpectedNull;
    }
    defer c.free(word);
    try std.testing.expectEqualStrings("alpha", cString(word));
    try std.testing.expectEqualStrings(" beta", cString(p));

    var quoted_p: [*c]const u8 = "  \"a\\\"b\" tail";
    const quoted = dup_next_quoted(&quoted_p, '"');
    if (quoted == null) {
        return error.TestUnexpectedNull;
    }
    defer c.free(quoted);
    try std.testing.expectEqualStrings("a\\\"b", cString(quoted));
    try std.testing.expectEqualStrings(" tail", cString(quoted_p));

    const q = dup_quote_string("a\"b", '"');
    if (q == null) {
        return error.TestUnexpectedNull;
    }
    defer c.free(q);
    try std.testing.expectEqualStrings("\"a\\\"b\"", cString(q));

    const u = dup_unquote_string(q, '"');
    if (u == null) {
        return error.TestUnexpectedNull;
    }
    defer c.free(u);
    try std.testing.expectEqualStrings("a\"b", cString(u));
}

test "copy, skip, and join helpers preserve existing behavior" {
    var source: [*c]const u8 = "  key \"value here\" rest";
    var buf = [_:0]u8{0} ** 32;
    var dest: [*c]u8 = @ptrCast(&buf);

    cp_spaces(&source, &dest, 31);
    cp_word(&source, &dest, 31);
    dest[0] = 0;
    try std.testing.expectEqualStrings("  key", cString(@ptrCast(&buf)));

    skip_spaces(&source);
    var quoted_buf = [_:0]u8{0} ** 32;
    var quoted_dest: [*c]u8 = @ptrCast(&quoted_buf);
    cp_quoted_ifquoted(&source, &quoted_dest, 31, '"');
    quoted_dest[0] = 0;
    try std.testing.expectEqualStrings("\"value here\"", cString(@ptrCast(&quoted_buf)));

    skip_spaces(&source);
    skip_word(&source);
    try std.testing.expectEqualStrings("", cString(source));

    var until_p: [*c]const u8 = "value#tail\n";
    const prefix = dup_line_until(&until_p, '#');
    if (prefix == null) {
        return error.TestUnexpectedNull;
    }
    defer c.free(prefix);
    try std.testing.expectEqualStrings("value", cString(prefix));
    try std.testing.expectEqualStrings("#tail\n", cString(until_p));

    const joined = strjoin("left", "right");
    if (joined == null) {
        return error.TestUnexpectedNull;
    }
    defer c.free(joined);
    try std.testing.expectEqualStrings("leftright", cString(joined));

    const rhs = strjoin(null, "right");
    if (rhs == null) {
        return error.TestUnexpectedNull;
    }
    defer c.free(rhs);
    try std.testing.expectEqualStrings("right", cString(rhs));

    try std.testing.expect(strjoin(null, null) == null);
}
