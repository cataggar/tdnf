// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("ctype.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("nodes.h");
    @cInclude("lines.h");
    @cInclude("modules.h");
    @cInclude("strutils.h");
    @cInclude("ini.h");
});

var this_module = c.struct_cnfmodule{
    .next = null,
    .name = "ini",
    .default_file = null,
    .parser = parse_ini,
    .unparser = unparse_ini,
    .opt_root = null,
};

fn isSpace(ch: u8) bool {
    return c.isspace(@as(c_int, ch)) != 0;
}

fn cString(ptr: [*c]const u8) []const u8 {
    return std.mem.span(@as([*:0]const u8, @ptrCast(ptr)));
}

fn findChild(cn: [*c]c.struct_cnfnode, name: [*:0]const u8) [*c]c.struct_cnfnode {
    if (cn == null) {
        return null;
    }
    return c.find_node(cn[0].first_child, name);
}

fn parseIniOptions(opt_root: [*c]c.struct_cnfnode, cmt_char: *c_int) c_int {
    if (opt_root == null or opt_root[0].first_child == null) {
        return -1;
    }

    var cn = opt_root[0].first_child;
    while (cn != null) : (cn = cn[0].next) {
        if (c.strcmp(@ptrCast(cn[0].name), "comment") == 0) {
            cmt_char.* = @as(c_int, cn[0].value[0]);
        }
    }

    return 0;
}

fn appendFullLineNode(parent: [*c]c.struct_cnfnode, name: [*:0]const u8, line: [*c]u8) void {
    var p: [*c]const u8 = @ptrCast(line);
    var buf = [_:0]u8{0} ** 1024;
    const cn = c.create_cnfnode(name);
    c.cnfnode_setval(cn, c.dup_next_line_b(&p, @ptrCast(&buf), @as(c_int, @intCast(buf.len - 1))));
    c.append_node(parent, cn);
}

fn parseIniSubsection(cl_root: [*c]c.struct_confline, cn: [*c]c.struct_cnfnode, cmt_char: c_int) [*c]c.struct_confline {
    const comment_char: u8 = @intCast(cmt_char);
    var cl = cl_root[0].next;

    while (cl != null) : (cl = cl[0].next) {
        var p: [*c]const u8 = @ptrCast(cl[0].line);
        while (p[0] != 0 and isSpace(p[0])) {
            p += 1;
        }

        if (p[0] == '}') {
            break;
        }

        if (p[0] == 0) {
            appendFullLineNode(cn, ".empty", cl[0].line);
        } else if (p[0] == comment_char) {
            appendFullLineNode(cn, ".comment", cl[0].line);
        } else {
            var buf = [_:0]u8{0} ** 1024;
            var key_len: usize = 0;

            while (p[0] != 0 and (!isSpace(p[0]) and p[0] != '=') and key_len < buf.len - 1) {
                buf[key_len] = p[0];
                key_len += 1;
                p += 1;
            }
            buf[key_len] = 0;

            while (p[0] != 0 and isSpace(p[0])) {
                p += 1;
            }
            if (p[0] == '=') {
                p += 1;
                while (p[0] != 0 and isSpace(p[0])) {
                    p += 1;
                }

                const cn_sub = c.create_cnfnode(@ptrCast(&buf));

                if (p[0] != '{') {
                    key_len = 0;
                    while (p[0] != 0 and key_len < buf.len - 1) {
                        buf[key_len] = p[0];
                        key_len += 1;
                        p += 1;
                    }
                    while (key_len > 0 and isSpace(buf[key_len - 1])) {
                        key_len -= 1;
                    }
                    buf[key_len] = 0;
                    c.cnfnode_setval(cn_sub, @ptrCast(&buf));
                } else {
                    p += 1;
                    while (p[0] != 0 and isSpace(p[0])) {
                        p += 1;
                    }
                    if (p[0] != '}') {
                        cl = parseIniSubsection(cl, cn_sub, cmt_char);
                    }
                }
                c.append_node(cn, cn_sub);
            } else {
                appendFullLineNode(cn, ".unparsed", cl[0].line);
            }
        }
    }

    return cl;
}

fn parseIniSection(cl_root: [*c]c.struct_confline, cn_root: [*c]c.struct_cnfnode, cmt_char: c_int) [*c]c.struct_confline {
    const comment_char: u8 = @intCast(cmt_char);
    var cl = cl_root[0].next;

    while (cl != null) {
        var p: [*c]const u8 = @ptrCast(cl[0].line);
        while (p[0] != 0 and isSpace(p[0])) {
            p += 1;
        }

        if (p[0] != 0) {
            var buf = [_:0]u8{0} ** 1024;

            if (p[0] == '[') {
                return cl;
            } else if (p[0] == comment_char) {
                appendFullLineNode(cn_root, ".comment", cl[0].line);
            } else {
                var key_len: usize = 0;

                while (p[0] != 0 and (!isSpace(p[0]) and p[0] != '=') and key_len < buf.len - 1) {
                    buf[key_len] = p[0];
                    key_len += 1;
                    p += 1;
                }
                buf[key_len] = 0;

                while (p[0] != 0 and isSpace(p[0])) {
                    p += 1;
                }
                if (p[0] == '=') {
                    p += 1;
                    while (p[0] != 0 and isSpace(p[0])) {
                        p += 1;
                    }

                    const cn_line = c.create_cnfnode(@ptrCast(&buf));

                    if (p[0] != '{') {
                        _ = c.dup_next_line_b(&p, @ptrCast(&buf), @as(c_int, @intCast(buf.len - 1)));
                        c.cnfnode_setval(cn_line, @ptrCast(&buf));
                    } else {
                        p += 1;
                        while (p[0] != 0 and isSpace(p[0])) {
                            p += 1;
                        }
                        if (p[0] != '}') {
                            cl = parseIniSubsection(cl, cn_line, cmt_char);
                        }
                    }
                    c.append_node(cn_root, cn_line);

                    while (p[0] != 0 and isSpace(p[0])) {
                        p += 1;
                    }
                    if (p[0] == comment_char) {
                        appendFullLineNode(cn_root, ".comment", cl[0].line);
                    }
                } else {
                    appendFullLineNode(cn_root, ".unparsed", cl[0].line);
                }
            }
        } else {
            const cn = c.create_cnfnode(".empty");
            c.cnfnode_setval(cn, "");
            c.append_node(cn_root, cn);
        }

        cl = cl[0].next;
    }

    return cl;
}

export fn parse_ini(cm: [*c]c.struct_cnfmodule, fptr: [*c]c.FILE) [*c]c.struct_cnfnode {
    const cl_root = c.read_conflines(fptr);
    const cn_top = c.create_cnfnode("(root)");
    var cmt_char: c_int = '#';

    if (cm != null and cm[0].opt_root != null) {
        _ = parseIniOptions(cm[0].opt_root, &cmt_char);
    }

    var cl = cl_root;
    while (cl != null) {
        var p: [*c]const u8 = @ptrCast(cl[0].line);
        var buf = [_:0]u8{0} ** 1024;

        while (p[0] != 0 and isSpace(p[0])) {
            p += 1;
        }
        if (p[0] != 0) {
            if (p[0] == '[') {
                var name_len: usize = 0;

                p += 1;
                while (p[0] != 0 and isSpace(p[0])) {
                    p += 1;
                }
                while (p[0] != 0 and p[0] != ']' and name_len < buf.len - 1) {
                    buf[name_len] = p[0];
                    name_len += 1;
                    p += 1;
                }
                buf[name_len] = 0;

                const cn = c.create_cnfnode(@ptrCast(&buf));
                c.append_node(cn_top, cn);
                cl = parseIniSection(cl, cn, cmt_char);
            } else {
                appendFullLineNode(cn_top, ".comment", cl[0].line);
                cl = cl[0].next;
            }
        } else {
            const cn = c.create_cnfnode(".empty");
            c.cnfnode_setval(cn, "");
            c.append_node(cn_top, cn);
            cl = cl[0].next;
        }
    }

    c.destroy_confline_list(cl_root);
    return cn_top;
}

fn isSyntheticLine(name: [*c]const u8) bool {
    return c.strcmp(@ptrCast(name), ".empty") == 0 or
        c.strcmp(@ptrCast(name), ".comment") == 0 or
        c.strcmp(@ptrCast(name), ".unparsed") == 0;
}

fn unparseIniSubsection(cn: [*c]c.struct_cnfnode, cl_list: [*c]c.struct_confline, level: c_uint) [*c]c.struct_confline {
    var buf = [_:0]u8{0} ** 1024;
    var ident = [_:0]u8{0} ** 256;
    var i: usize = 0;
    const indent = @as(usize, level) * 8;
    var out_list = cl_list;

    while (i < indent and i < ident.len - 1) : (i += 1) {
        ident[i] = ' ';
    }
    ident[i] = 0;

    _ = c.snprintf(@ptrCast(&buf), buf.len, "%s%s = {\n", @as([*c]const u8, @ptrCast(&ident)), cn[0].name);
    out_list = c.append_confline(out_list, c.create_confline(@ptrCast(&buf)));

    var cn_line = cn[0].first_child;
    while (cn_line != null) : (cn_line = cn_line[0].next) {
        if (cn_line[0].value != null) {
            if (isSyntheticLine(cn_line[0].name)) {
                _ = c.snprintf(@ptrCast(&buf), buf.len, "%s\n", cn_line[0].value);
            } else {
                _ = c.snprintf(@ptrCast(&buf), buf.len, "        %s%s = %s\n", @as([*c]const u8, @ptrCast(&ident)), cn_line[0].name, cn_line[0].value);
            }
            out_list = c.append_confline(out_list, c.create_confline(@ptrCast(&buf)));
        } else {
            out_list = unparseIniSubsection(cn_line, out_list, level + 1);
        }
    }

    _ = c.snprintf(@ptrCast(&buf), buf.len, "%s}\n", @as([*c]const u8, @ptrCast(&ident)));
    out_list = c.append_confline(out_list, c.create_confline(@ptrCast(&buf)));
    return out_list;
}

export fn unparse_ini(_: [*c]c.struct_cnfmodule, fptr: [*c]c.FILE, cn_root: [*c]c.struct_cnfnode) c_int {
    var cl_list: [*c]c.struct_confline = null;
    var cn_section = cn_root[0].first_child;
    var buf = [_:0]u8{0} ** 1024;

    while (cn_section != null) : (cn_section = cn_section[0].next) {
        if (cn_section[0].name[0] == '.') {
            _ = c.snprintf(@ptrCast(&buf), buf.len, "%s\n", cn_section[0].value);
            cl_list = c.append_confline(cl_list, c.create_confline(@ptrCast(&buf)));
        } else {
            _ = c.snprintf(@ptrCast(&buf), buf.len, "[%s]\n", cn_section[0].name);
            cl_list = c.append_confline(cl_list, c.create_confline(@ptrCast(&buf)));

            var cn_line = cn_section[0].first_child;
            while (cn_line != null) : (cn_line = cn_line[0].next) {
                if (isSyntheticLine(cn_line[0].name)) {
                    _ = c.snprintf(@ptrCast(&buf), buf.len, "%s\n", cn_line[0].value);
                    cl_list = c.append_confline(cl_list, c.create_confline(@ptrCast(&buf)));
                } else if (cn_line[0].value != null) {
                    _ = c.snprintf(@ptrCast(&buf), buf.len, "%s = %s\n", cn_line[0].name, cn_line[0].value);
                    cl_list = c.append_confline(cl_list, c.create_confline(@ptrCast(&buf)));
                } else {
                    cl_list = unparseIniSubsection(cn_line, cl_list, 1);
                }
            }
        }
    }

    var cl = cl_list;
    while (cl != null) : (cl = cl[0].next) {
        _ = c.fprintf(fptr, "%s", cl[0].line);
    }
    c.destroy_confline_list(cl_list);

    return 0;
}

export fn register_ini(opt_root: [*c]c.struct_cnfnode) void {
    c.register_cnfmodule(&this_module, opt_root);
}

export fn clone_cnfmodule_ini(opt_root: [*c]c.struct_cnfnode) [*c]c.struct_cnfmodule {
    return c.clone_cnfmodule(&this_module, null, null, opt_root);
}

test "ini parser preserves sections, comments, and subsection trimming" {
    const input =
        "# lead\n" ++
        "\n" ++
        "[main]\n" ++
        "enabled = 1  \n" ++
        "# section\n" ++
        "group = {\n" ++
        "        child = value   \n" ++
        "}\n" ++
        "odd line\n";

    const fin = c.fmemopen(@constCast(input.ptr), input.len, "r");
    try std.testing.expect(fin != null);
    defer _ = c.fclose(fin);

    const root = parse_ini(null, fin);
    if (root == null) {
        return error.TestUnexpectedNull;
    }
    defer c.destroy_cnftree(root);

    const top_comment = root[0].first_child;
    try std.testing.expect(top_comment != null);
    try std.testing.expectEqualStrings(".comment", cString(top_comment[0].name));
    try std.testing.expectEqualStrings("# lead", cString(top_comment[0].value));

    const top_empty = top_comment[0].next;
    try std.testing.expect(top_empty != null);
    try std.testing.expectEqualStrings(".empty", cString(top_empty[0].name));
    try std.testing.expectEqualStrings("", cString(top_empty[0].value));

    const main = top_empty[0].next;
    try std.testing.expect(main != null);
    try std.testing.expectEqualStrings("main", cString(main[0].name));

    const enabled = main[0].first_child;
    try std.testing.expect(enabled != null);
    try std.testing.expectEqualStrings("enabled", cString(enabled[0].name));
    try std.testing.expectEqualStrings("1  ", cString(enabled[0].value));

    const section_comment = enabled[0].next;
    try std.testing.expect(section_comment != null);
    try std.testing.expectEqualStrings(".comment", cString(section_comment[0].name));
    try std.testing.expectEqualStrings("# section", cString(section_comment[0].value));

    const group = section_comment[0].next;
    try std.testing.expect(group != null);
    try std.testing.expectEqualStrings("group", cString(group[0].name));
    try std.testing.expect(group[0].value == null);

    const child = findChild(group, "child");
    try std.testing.expect(child != null);
    try std.testing.expectEqualStrings("value", cString(child[0].value));

    const unparsed = group[0].next;
    try std.testing.expect(unparsed != null);
    try std.testing.expectEqualStrings(".unparsed", cString(unparsed[0].name));
    try std.testing.expectEqualStrings("odd line", cString(unparsed[0].value));

    var out_ptr: [*c]u8 = null;
    var out_len: usize = 0;
    const fout = c.open_memstream(&out_ptr, &out_len);
    try std.testing.expect(fout != null);
    try std.testing.expectEqual(@as(c_int, 0), unparse_ini(null, fout, root));
    try std.testing.expectEqual(@as(c_int, 0), c.fclose(fout));
    defer c.free(out_ptr);

    const expected =
        "# lead\n\n[main]\nenabled = 1  \n# section\n        group = {\n                child = value\n        }\nodd line\n";
    try std.testing.expectEqual(expected.len, out_len);
    try std.testing.expectEqualStrings(expected, cString(out_ptr));
}

test "ini module registration and cloning preserve ABI" {
    c.unregister_all();
    defer c.unregister_all();

    register_ini(null);
    const registered = c.find_cnfmodule("ini");
    try std.testing.expect(registered == &this_module);

    const opts = c.parse_options("comment=;");
    if (opts == null) {
        return error.TestUnexpectedNull;
    }

    const clone = clone_cnfmodule_ini(opts);
    if (clone == null) {
        c.destroy_cnftree(opts);
        return error.TestUnexpectedNull;
    }
    defer c.destroy_cnfmodule(clone);

    try std.testing.expectEqualStrings("ini", cString(@ptrCast(clone[0].name)));
    try std.testing.expect(clone[0].parser == this_module.parser);
    try std.testing.expect(clone[0].unparser == this_module.unparser);
    try std.testing.expect(clone[0].opt_root == opts);
}
