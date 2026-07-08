// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("lines.h");
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

export fn create_confline(line: [*c]const u8) [*c]c.struct_confline {
    const raw = c.calloc(1, @sizeOf(c.struct_confline)) orelse return null;
    const cl: [*c]c.struct_confline = @ptrCast(@alignCast(raw));
    cl[0].line = duplicateCString(line);
    return cl;
}

export fn destroy_confline(cl: [*c]c.struct_confline) void {
    if (cl == null) {
        return;
    }

    if (cl[0].line != null) {
        c.free(cl[0].line);
    }
    c.free(cl);
}

export fn destroy_confline_list(cl_list: [*c]c.struct_confline) void {
    var cl = cl_list;
    while (cl != null) {
        const cl_next = cl[0].next;
        destroy_confline(cl);
        cl = cl_next;
    }
}

export fn append_confline(cl_list: [*c]c.struct_confline, cl: [*c]c.struct_confline) [*c]c.struct_confline {
    if (cl_list != null) {
        var pcl = &cl_list[0].next;
        while (pcl.* != null) {
            pcl = &pcl.*[0].next;
        }
        pcl.* = cl;
        return cl_list;
    }

    return cl;
}

export fn read_conflines(fptr: [*c]c.FILE) [*c]c.struct_confline {
    var line = [_:0]u8{0} ** c.MAX_CONFLINE;
    const max_chars = @as(usize, @intCast(c.MAX_CONFLINE - 2));
    var cl: [*c]c.struct_confline = null;
    var cl_root: [*c]c.struct_confline = null;

    while (true) {
        var count: usize = 0;

        while (count < max_chars) {
            const ch = c.fgetc(fptr);
            if (ch == c.EOF) {
                if (count == 0) {
                    return cl_root;
                }
                break;
            }

            line[count] = @intCast(ch);
            count += 1;
            if (@as(u8, @intCast(ch)) == '\n') {
                break;
            }
        }

        line[count] = 0;
        const cl_next = create_confline(@ptrCast(&line));
        if (cl != null) {
            cl[0].next = cl_next;
        } else {
            cl_root = cl_next;
        }
        cl = cl_next;
    }

    return cl_root;
}

test "confline helpers preserve file order" {
    const input = "alpha\nbeta\n";
    const fin = c.fmemopen(@constCast(input.ptr), input.len, "r");
    try std.testing.expect(fin != null);
    defer _ = c.fclose(fin);

    const lines = read_conflines(fin);
    if (lines == null) {
        return error.TestUnexpectedNull;
    }
    defer destroy_confline_list(lines);

    try std.testing.expectEqualStrings("alpha\n", cString(lines[0].line));
    try std.testing.expect(lines[0].next != null);
    try std.testing.expectEqualStrings("beta\n", cString(lines[0].next[0].line));

    const extra = create_confline("gamma\n");
    if (extra == null) {
        return error.TestUnexpectedNull;
    }
    try std.testing.expect(append_confline(lines, extra) == lines);
    try std.testing.expectEqualStrings("gamma\n", cString(lines[0].next[0].next[0].line));
}
