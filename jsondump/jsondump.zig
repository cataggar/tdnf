// Copyright (C) 2022-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const libc = std.c;

const SIZE_INC: c_uint = 256;

const JsonDump = extern struct {
    buf: ?*anyopaque,
    buf_size: c_uint,
    pos: c_uint,
};

fn bufPtr(jd: *JsonDump) [*]u8 {
    return @as([*]u8, @ptrCast(jd.buf.?));
}

fn bufStr(jd: *const JsonDump) [*:0]const u8 {
    return @as([*:0]const u8, @ptrCast(jd.buf.?));
}

fn ensureCapacity(jd_opt: ?*JsonDump, add_size: c_uint) c_int {
    const jd = jd_opt orelse return -1;

    if (jd.pos +% add_size >= jd.buf_size -% 1) {
        const grow = add_size +% SIZE_INC;
        jd.buf = libc.realloc(jd.buf, @as(usize, jd.buf_size +% grow));
        if (jd.buf == null) {
            return -1;
        }
        jd.buf_size +%= grow;
    }

    return 0;
}

fn jsonifyString(str: [*:0]const u8) ?[*:0]u8 {
    const input = std.mem.span(str);
    const cap = input.len *% 2 +% 3;
    const raw = libc.calloc(cap, @sizeOf(u8)) orelse return null;
    const buf = @as([*]u8, @ptrCast(raw));

    var out: usize = 0;
    buf[out] = '"';
    out += 1;

    for (input) |ch| {
        switch (ch) {
            '"' => {
                buf[out] = '\\';
                out += 1;
                buf[out] = '"';
                out += 1;
            },
            '\\' => {
                buf[out] = '\\';
                out += 1;
                buf[out] = '\\';
                out += 1;
            },
            0x08 => {
                buf[out] = '\\';
                out += 1;
                buf[out] = 'b';
                out += 1;
            },
            0x0C => {
                buf[out] = '\\';
                out += 1;
                buf[out] = 'f';
                out += 1;
            },
            '\n' => {
                buf[out] = '\\';
                out += 1;
                buf[out] = 'n';
                out += 1;
            },
            '\r' => {
                buf[out] = '\\';
                out += 1;
                buf[out] = 'r';
                out += 1;
            },
            '\t' => {
                buf[out] = '\\';
                out += 1;
                buf[out] = 't';
                out += 1;
            },
            else => {
                buf[out] = ch;
                out += 1;
            },
        }
    }

    buf[out] = '"';
    out += 1;
    buf[out] = 0;

    return @ptrCast(buf);
}

fn mapPrepAppend(jd: *JsonDump) void {
    const buf = bufPtr(jd);

    if (jd.pos > 1) {
        var out: usize = @intCast(jd.pos);
        if (buf[out - 1] == '}') {
            out -= 1;
            jd.pos = @intCast(out);
            if (buf[out - 1] != '{') {
                buf[out] = ',';
                out += 1;
                jd.pos = @intCast(out);
            }
        }
    }
}

fn mapAddRaw(jd_opt: ?*JsonDump, key_z: [*:0]const u8, value: []const u8) c_int {
    const key = std.mem.span(key_z);
    const add_size: c_uint = @truncate(key.len +% value.len +% 5);

    if (ensureCapacity(jd_opt, add_size) != 0) {
        return -1;
    }

    const jd = jd_opt.?;
    mapPrepAppend(jd);

    const buf = bufPtr(jd);
    var out: usize = @intCast(jd.pos);

    buf[out] = '"';
    out += 1;
    @memcpy(buf[out .. out + key.len], key);
    out += key.len;
    buf[out] = '"';
    out += 1;
    buf[out] = ':';
    out += 1;
    @memcpy(buf[out .. out + value.len], value);
    out += value.len;
    buf[out] = '}';
    out += 1;
    buf[out] = 0;

    jd.pos = @intCast(out);

    return 0;
}

fn listPrepAppend(jd: *JsonDump) void {
    const buf = bufPtr(jd);

    if (jd.pos > 1) {
        var out: usize = @intCast(jd.pos);
        if (buf[out - 1] == ']') {
            out -= 1;
            jd.pos = @intCast(out);
            if (buf[out - 1] != '[') {
                buf[out] = ',';
                out += 1;
                jd.pos = @intCast(out);
            }
        }
    }
}

fn listAddRaw(jd_opt: ?*JsonDump, value: []const u8) c_int {
    const add_size: c_uint = @truncate(value.len +% 2);

    if (ensureCapacity(jd_opt, add_size) != 0) {
        return -1;
    }

    const jd = jd_opt.?;
    listPrepAppend(jd);

    const buf = bufPtr(jd);
    var out: usize = @intCast(jd.pos);

    @memcpy(buf[out .. out + value.len], value);
    out += value.len;
    buf[out] = ']';
    out += 1;
    buf[out] = 0;

    jd.pos = @intCast(out);

    return 0;
}

export fn jd_create(size: c_uint) ?*JsonDump {
    var buf_size = size;

    const jd_mem = libc.calloc(1, @sizeOf(JsonDump)) orelse return null;
    const jd: *JsonDump = @ptrCast(@alignCast(jd_mem));

    if (buf_size == 0) {
        buf_size = SIZE_INC;
    }

    jd.buf = libc.calloc(buf_size, @sizeOf(u8));
    if (jd.buf == null) {
        jd_destroy(jd);
        return null;
    }
    jd.buf_size = buf_size;

    return jd;
}

export fn jd_destroy(jd_opt: ?*JsonDump) void {
    if (jd_opt) |jd| {
        if (jd.buf) |buf| {
            libc.free(@ptrCast(buf));
        }
        libc.free(@ptrCast(jd));
    }
}

export fn jd_map_start(jd_opt: ?*JsonDump) c_int {
    if (ensureCapacity(jd_opt, 2) != 0) {
        return -1;
    }

    const jd = jd_opt.?;
    const buf = bufPtr(jd);
    var out: usize = @intCast(jd.pos);

    buf[out] = '{';
    out += 1;
    buf[out] = '}';
    out += 1;
    buf[out] = 0;

    jd.pos = @intCast(out);

    return 0;
}

export fn jd_map_add_string(jd_opt: ?*JsonDump, key: [*:0]const u8, value_opt: ?[*:0]const u8) c_int {
    const value = value_opt orelse return jd_map_add_null(jd_opt, key);
    const json_value = jsonifyString(value) orelse return -1;
    defer libc.free(@ptrCast(json_value));

    return mapAddRaw(jd_opt, key, std.mem.span(json_value));
}

export fn jd_map_add_int(jd_opt: ?*JsonDump, key: [*:0]const u8, value: c_int) c_int {
    var buf: [22]u8 = undefined;
    const formatted = std.fmt.bufPrintZ(&buf, "{d}", .{value}) catch return -1;
    return mapAddRaw(jd_opt, key, formatted);
}

export fn jd_map_add_int64(jd_opt: ?*JsonDump, key: [*:0]const u8, value: i64) c_int {
    var buf: [22]u8 = undefined;
    const formatted = std.fmt.bufPrintZ(&buf, "{d}", .{value}) catch return -1;
    return mapAddRaw(jd_opt, key, formatted);
}

export fn jd_map_add_bool(jd_opt: ?*JsonDump, key: [*:0]const u8, value: c_int) c_int {
    return mapAddRaw(jd_opt, key, if (value != 0) "true" else "false");
}

export fn jd_map_add_null(jd_opt: ?*JsonDump, key: [*:0]const u8) c_int {
    return mapAddRaw(jd_opt, key, "null");
}

export fn jd_map_add_child(jd_opt: ?*JsonDump, key: [*:0]const u8, jd_child: *const JsonDump) c_int {
    return mapAddRaw(jd_opt, key, std.mem.span(bufStr(jd_child)));
}

export fn jd_list_start(jd_opt: ?*JsonDump) c_int {
    if (ensureCapacity(jd_opt, 2) != 0) {
        return -1;
    }

    const jd = jd_opt.?;
    const buf = bufPtr(jd);
    var out: usize = @intCast(jd.pos);

    buf[out] = '[';
    out += 1;
    buf[out] = ']';
    out += 1;
    buf[out] = 0;

    jd.pos = @intCast(out);

    return 0;
}

export fn jd_list_add_string(jd_opt: ?*JsonDump, value_opt: ?[*:0]const u8) c_int {
    const value = value_opt orelse return jd_list_add_null(jd_opt);
    const json_value = jsonifyString(value) orelse return -1;
    defer libc.free(@ptrCast(json_value));

    return listAddRaw(jd_opt, std.mem.span(json_value));
}

export fn jd_list_add_int(jd_opt: ?*JsonDump, value: c_int) c_int {
    var buf: [22]u8 = undefined;
    const formatted = std.fmt.bufPrintZ(&buf, "{d}", .{value}) catch return -1;
    return listAddRaw(jd_opt, formatted);
}

export fn jd_list_add_int64(jd_opt: ?*JsonDump, value: i64) c_int {
    var buf: [22]u8 = undefined;
    const formatted = std.fmt.bufPrintZ(&buf, "{d}", .{value}) catch return -1;
    return listAddRaw(jd_opt, formatted);
}

export fn jd_list_add_bool(jd_opt: ?*JsonDump, value: c_int) c_int {
    return listAddRaw(jd_opt, if (value != 0) "true" else "false");
}

export fn jd_list_add_null(jd_opt: ?*JsonDump) c_int {
    return listAddRaw(jd_opt, "null");
}

export fn jd_list_add_child(jd_opt: ?*JsonDump, jd_child: *const JsonDump) c_int {
    return listAddRaw(jd_opt, std.mem.span(bufStr(jd_child)));
}
