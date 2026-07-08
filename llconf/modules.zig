// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

const c = @cImport({
    @cInclude("dlfcn.h");
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("nodes.h");
    @cInclude("modules.h");
});

export var cnfmodules: [*c]c.struct_cnfmodule = null;

fn duplicateBytes(bytes: []const u8) [*c]u8 {
    const raw = c.malloc(bytes.len + 1) orelse return null;
    const out: [*]u8 = @ptrCast(raw);
    @memcpy(out[0..bytes.len], bytes);
    out[bytes.len] = 0;
    return @ptrCast(out);
}

fn duplicateCString(pszOpt: ?[*:0]const u8) [*c]u8 {
    const psz = pszOpt orelse return null;
    return duplicateBytes(std.mem.span(psz));
}

fn freeCString(psz: [*c]const u8) void {
    if (psz != null) {
        c.free(@constCast(psz));
    }
}

export fn register_cnfmodule(cm: [*c]c.struct_cnfmodule, opt_root: [*c]c.struct_cnfnode) void {
    if (cm == null) {
        return;
    }

    var prev: [*c]c.struct_cnfmodule = null;
    var current = cnfmodules;
    while (current != null and current != cm) {
        prev = current;
        current = current[0].next;
    }
    if (current == null) {
        if (prev != null) {
            prev[0].next = cm;
        } else {
            cnfmodules = cm;
        }
        cm[0].opt_root = opt_root;
        cm[0].next = null;
    }
}

export fn unregister_all() void {
    cnfmodules = null;
}

export fn destroy_cnfmodule(cm: [*c]c.struct_cnfmodule) void {
    if (cm == null) {
        return;
    }

    freeCString(cm[0].default_file);
    freeCString(cm[0].name);
    if (cm[0].opt_root != null) {
        c.destroy_cnftree(cm[0].opt_root);
    }
    c.free(cm);
}

export fn clone_cnfmodule(
    cm: [*c]c.struct_cnfmodule,
    new_name: ?[*:0]const u8,
    default_file: ?[*:0]const u8,
    opt_root: [*c]c.struct_cnfnode,
) [*c]c.struct_cnfmodule {
    if (cm == null) {
        return null;
    }

    const raw = c.calloc(1, @sizeOf(c.struct_cnfmodule)) orelse return null;
    const new_cm: [*c]c.struct_cnfmodule = @ptrCast(@alignCast(raw));

    if (new_name != null) {
        new_cm[0].name = duplicateCString(new_name);
    } else if (cm[0].name != null) {
        new_cm[0].name = duplicateCString(@ptrCast(cm[0].name));
    }

    if (default_file != null) {
        new_cm[0].default_file = duplicateCString(default_file);
    } else if (cm[0].default_file != null) {
        new_cm[0].default_file = duplicateCString(@ptrCast(cm[0].default_file));
    }

    if (opt_root != null) {
        new_cm[0].opt_root = opt_root;
    } else if (cm[0].opt_root != null) {
        new_cm[0].opt_root = cm[0].opt_root;
    }

    new_cm[0].parser = cm[0].parser;
    new_cm[0].unparser = cm[0].unparser;
    return new_cm;
}

export fn find_cnfmodule(name: ?[*:0]const u8) [*c]c.struct_cnfmodule {
    const target = name orelse return null;
    var cm = cnfmodules;
    while (cm != null) : (cm = cm[0].next) {
        if (c.strcmp(@ptrCast(cm[0].name), @ptrCast(target)) == 0) {
            return cm;
        }
    }
    return null;
}

export fn cnfmodule_setopts(cm: [*c]c.struct_cnfmodule, opt_root: [*c]c.struct_cnfnode) void {
    if (cm != null) {
        cm[0].opt_root = opt_root;
    }
}

export fn parse_options(string: ?[*:0]const u8) [*c]c.struct_cnfnode {
    const cn_top = c.create_cnfnode("(root)");
    if (cn_top == null) {
        return null;
    }

    const input = string orelse return cn_top;
    var p = input;
    while (p[0] != 0) {
        var buf = [_:0]u8{0} ** 256;
        var q_idx: usize = 0;
        var cn: [*c]c.struct_cnfnode = null;

        while (p[0] != 0 and p[0] != '=' and p[0] != ',' and q_idx < buf.len - 1) {
            buf[q_idx] = p[0];
            q_idx += 1;
            p += 1;
        }
        buf[q_idx] = 0;

        cn = c.create_cnfnode(@ptrCast(&buf));
        c.append_node(cn_top, cn);

        if (p[0] == '=') {
            p += 1;
            q_idx = 0;
            while (p[0] != 0 and p[0] != ',' and q_idx < buf.len - 1) {
                buf[q_idx] = p[0];
                q_idx += 1;
                p += 1;
            }
            buf[q_idx] = 0;
            c.cnfnode_setval(cn, @ptrCast(&buf));
        } else {
            c.cnfnode_setval(cn, "");
        }

        if (p[0] != 0) {
            p += 1;
        }
    }

    return cn_top;
}

export fn cnfmodule_parse(cm: [*c]c.struct_cnfmodule, fin: [*c]c.FILE) [*c]c.struct_cnfnode {
    if (cm == null or cm[0].parser == null) {
        return null;
    }
    return cm[0].parser.?(cm, fin);
}

export fn cnfmodule_parse_file(cm: [*c]c.struct_cnfmodule, fnameOpt: ?[*:0]const u8) [*c]c.struct_cnfnode {
    if (cm == null) {
        return null;
    }

    var fname: [*c]const u8 = if (fnameOpt) |name| @ptrCast(name) else null;
    if (fname == null) {
        fname = cm[0].default_file;
    }
    if (fname != null) {
        const fin = c.fopen(fname, "r");
        if (fin != null) {
            const cn_root = cnfmodule_parse(cm, fin);
            _ = c.fclose(fin);
            return cn_root;
        }
    }
    return null;
}

export fn cnfmodule_unparse(cm: [*c]c.struct_cnfmodule, fout: [*c]c.FILE, cn_root: [*c]c.struct_cnfnode) c_int {
    if (cm == null or cm[0].unparser == null) {
        return -1;
    }
    return cm[0].unparser.?(cm, fout, cn_root);
}

export fn cnfmodule_unparse_file(cm: [*c]c.struct_cnfmodule, fnameOpt: ?[*:0]const u8, cn_root: [*c]c.struct_cnfnode) c_int {
    if (cm == null) {
        return -1;
    }

    var ret: c_int = -1;
    var fname: [*c]const u8 = if (fnameOpt) |name| @ptrCast(name) else null;
    if (fname == null) {
        fname = cm[0].default_file;
    }
    if (fname != null) {
        const fout = c.fopen(fname, "w");
        if (fout != null) {
            ret = cnfmodule_unparse(cm, fout, cn_root);
            _ = c.fclose(fout);
        }
    }
    return ret;
}

export fn cnfmodule_register_plugin(nameOpt: ?[*:0]const u8, pathOpt: ?[*:0]const u8, opt_root: [*c]c.struct_cnfnode) c_int {
    const name = nameOpt orelse return -1;
    const path = pathOpt orelse return -1;
    const dlh = c.dlopen(@ptrCast(path), c.RTLD_LAZY);
    if (dlh == null) {
        return -1;
    }

    var fname = [_:0]u8{0} ** 256;
    _ = c.snprintf(@ptrCast(&fname), fname.len, "llconf_register_%s", name);
    _ = c.dlerror();

    const symbol = c.dlsym(dlh, @ptrCast(&fname));
    if (c.dlerror() == null and symbol != null) {
        const fe_reg_func: *const fn ([*c]c.struct_cnfnode) callconv(.c) [*c]c.struct_cnfmodule = @ptrCast(@alignCast(symbol.?));
        _ = fe_reg_func(opt_root);
        return 0;
    }

    _ = c.dlclose(dlh);
    return -2;
}

fn testParser(_: [*c]c.struct_cnfmodule, _: [*c]c.FILE) callconv(.c) [*c]c.struct_cnfnode {
    return c.create_cnfnode("(parsed)");
}

fn testUnparser(_: [*c]c.struct_cnfmodule, _: [*c]c.FILE, _: [*c]c.struct_cnfnode) callconv(.c) c_int {
    return 7;
}

test "module registry and option parsing preserve the existing ABI" {
    unregister_all();
    defer unregister_all();

    var base = std.mem.zeroes(c.struct_cnfmodule);
    base.name = "base";
    base.default_file = @constCast("base.conf");
    base.parser = testParser;
    base.unparser = testUnparser;

    register_cnfmodule(&base, null);
    try std.testing.expect(find_cnfmodule("base") == &base);
    register_cnfmodule(&base, null);
    try std.testing.expect(find_cnfmodule("base") == &base);

    const opts = parse_options("comment=#,quoted=yes,flag");
    if (opts == null) return error.TestUnexpectedNull;

    const comment = c.find_node(opts[0].first_child, "comment");
    try std.testing.expect(comment != null);
    try std.testing.expectEqualStrings("#", std.mem.span(@as([*:0]const u8, @ptrCast(c.cnfnode_getval(comment)))));

    const flag = c.find_node(opts[0].first_child, "flag");
    try std.testing.expect(flag != null);
    try std.testing.expectEqualStrings("", std.mem.span(@as([*:0]const u8, @ptrCast(c.cnfnode_getval(flag)))));

    const clone = clone_cnfmodule(&base, "copy", null, opts);
    if (clone == null) {
        c.destroy_cnftree(opts);
        return error.TestUnexpectedNull;
    }
    defer destroy_cnfmodule(clone);

    try std.testing.expectEqualStrings("copy", std.mem.span(@as([*:0]const u8, @ptrCast(clone[0].name))));
    try std.testing.expectEqualStrings("base.conf", std.mem.span(@as([*:0]const u8, @ptrCast(clone[0].default_file))));
    try std.testing.expect(clone[0].opt_root == opts);
    try std.testing.expect(clone[0].parser == base.parser);
    try std.testing.expect(clone[0].unparser == base.unparser);
}
