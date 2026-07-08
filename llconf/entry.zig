// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

const c = @cImport({
    @cInclude("ctype.h");
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("nodes.h");
    @cInclude("entry.h");
});

const FIND_ENTRY_FLAG_NOPATH: c_int = 0x01;
const FIND_ENTRY_FLAG_FIRST: c_int = 0x02;

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

fn freeCString(psz: [*c]u8) void {
    if (psz != null) {
        c.free(psz);
    }
}

fn isDigit(ch: u8) bool {
    return c.isdigit(@as(c_int, ch)) != 0;
}

fn setErrno(err: c_int) void {
    c.__errno_location().* = err;
}

fn append_cnfresult(cr_first: [*c]c.struct_cnfresult, cr: [*c]c.struct_cnfresult) void {
    var crp = &cr_first[0].next;
    while (crp.* != null) {
        crp = &crp.*[0].next;
    }
    crp.* = cr;
}

fn copyUntilNewline(src: [*:0]const u8, buf: []u8) [*:0]u8 {
    var len: usize = 0;
    while (src[len] != 0 and src[len] != '\n' and len + 1 < buf.len) : (len += 1) {
        buf[len] = src[len];
    }
    buf[len] = 0;
    return @ptrCast(buf.ptr);
}

fn cnf_find_entry_impl(
    pcr: *[*c]c.struct_cnfresult,
    cn_parent: [*c]c.struct_cnfnode,
    fullpath: [*c]const u8,
    path: [*:0]const u8,
    flags: c_int,
) void {
    if (cn_parent == null) {
        return;
    }

    const path_slice = std.mem.span(path);
    var dname = [_:0]u8{0} ** 256;
    var value: [*c]u8 = null;
    var index: c_int = -1;
    var idx: usize = 0;
    var q_idx: usize = 0;

    while (idx < path_slice.len and path_slice[idx] != '[' and
        (path_slice[idx] != '/' or (idx > 0 and path_slice[idx - 1] == '\\')) and
        q_idx < dname.len - 1)
    {
        if (path_slice[idx] == '\\') {
            idx += 1;
        } else {
            if (path_slice[idx] == '=') {
                dname[q_idx] = 0;
                q_idx += 1;
                idx += 1;
                value = @ptrCast(&dname[q_idx]);
            } else {
                dname[q_idx] = path_slice[idx];
                q_idx += 1;
                idx += 1;
            }
        }
    }
    dname[q_idx] = 0;

    if (idx < path_slice.len and path_slice[idx] == '[') {
        var tmp = [_:0]u8{0} ** 4;
        var tmp_idx: usize = 0;

        idx += 1;
        while (idx < path_slice.len and isDigit(path_slice[idx]) and tmp_idx < tmp.len - 1) {
            tmp[tmp_idx] = path_slice[idx];
            tmp_idx += 1;
            idx += 1;
        }
        tmp[tmp_idx] = 0;

        if (idx >= path_slice.len or path_slice[idx] != ']') {
            return;
        }

        index = c.atoi(@ptrCast(&tmp));
        idx += 1;
    }

    const dname_ptr: [*:0]u8 = @ptrCast(&dname);
    var cn = cn_parent[0].first_child;
    var i: c_int = 0;
    var j: c_int = 0;

    if (idx < path_slice.len and path_slice[idx] == '/' and idx + 1 < path_slice.len) {
        idx += 1;
        while (cn != null) : (cn = cn[0].next) {
            if (c.strcmp(@ptrCast(cn[0].name), dname_ptr) == 0) {
                if (value == null or (cn[0].value != null and c.strcmp(@ptrCast(cn[0].value), @ptrCast(value)) == 0)) {
                    if (index == -1 or i == index) {
                        var tmp = [_:0]u8{0} ** 1024;

                        if (fullpath != null) {
                            _ = c.snprintf(@ptrCast(&tmp), tmp.len, "%s%s[]%d]/", fullpath, dname_ptr, j);
                        }

                        cnf_find_entry_impl(pcr, cn, if (fullpath != null) @ptrCast(&tmp) else null, path + idx, flags);

                        if (index != -1) {
                            break;
                        }
                    }
                    i += 1;
                }
                j += 1;
            }
        }
    } else {
        while (cn != null) : (cn = cn[0].next) {
            if (c.strcmp(@ptrCast(cn[0].name), dname_ptr) == 0) {
                if (value == null or (cn[0].value != null and c.strcmp(@ptrCast(cn[0].value), @ptrCast(value)) == 0)) {
                    if (index == -1 or i == index) {
                        var tmp = [_:0]u8{0} ** 1024;
                        const cr = create_cnfresult(cn, blk: {
                            if (fullpath != null) {
                                _ = c.snprintf(@ptrCast(&tmp), tmp.len, "%s%s[%d]", fullpath, dname_ptr, j);
                                break :blk @as([*c]const u8, @ptrCast(&tmp));
                            }
                            break :blk null;
                        });
                        if (cr == null) {
                            return;
                        }

                        if (pcr.* != null) {
                            append_cnfresult(pcr.*, cr);
                        } else {
                            pcr.* = cr;
                        }

                        if ((flags & FIND_ENTRY_FLAG_FIRST) != 0) {
                            return;
                        }
                        if (index != -1) {
                            break;
                        }
                    }
                    i += 1;
                }
                j += 1;
            }
        }
    }
}

fn cnf_find_entry_f(cn_root: [*c]c.struct_cnfnode, path: ?[*:0]const u8, flags: c_int) [*c]c.struct_cnfresult {
    const needle = path orelse return null;
    if (cn_root == null) {
        return null;
    }

    var cnf_res: [*c]c.struct_cnfresult = null;
    var fullpath = [_:0]u8{0} ** 256;

    if (c.strcmp(@ptrCast(needle), ".") == 0) {
        cnf_res = create_cnfresult(cn_root, needle);
    } else {
        cnf_find_entry_impl(&cnf_res, cn_root, if ((flags & FIND_ENTRY_FLAG_NOPATH) != 0) null else @ptrCast(&fullpath), needle, flags);
    }

    return cnf_res;
}

export fn create_cnfresult(cn: [*c]c.struct_cnfnode, path: ?[*:0]const u8) [*c]c.struct_cnfresult {
    const raw = c.calloc(1, @sizeOf(c.struct_cnfresult)) orelse return null;
    const cr: [*c]c.struct_cnfresult = @ptrCast(@alignCast(raw));
    cr[0].cnfnode = cn;
    cr[0].path = duplicateCString(path);
    return cr;
}

export fn destroy_cnfresult(cr: [*c]c.struct_cnfresult) void {
    if (cr == null) {
        return;
    }
    freeCString(cr[0].path);
    c.free(cr);
}

export fn destroy_cnfresult_list(cr_list: [*c]c.struct_cnfresult) void {
    var cr = cr_list;
    while (cr != null) {
        const cr_next = cr[0].next;
        destroy_cnfresult(cr);
        cr = cr_next;
    }
}

export fn cnf_find_entry(cn_root: [*c]c.struct_cnfnode, path: ?[*:0]const u8) [*c]c.struct_cnfresult {
    return cnf_find_entry_f(cn_root, path, 0);
}

export fn cnf_add_branch(cn_root: [*c]c.struct_cnfnode, path: ?[*:0]const u8, do_merge: c_int) [*c]c.struct_cnfnode {
    const needle = path orelse return null;
    if (cn_root == null) {
        return null;
    }

    var cn: [*c]c.struct_cnfnode = null;
    var cn_parent = cn_root;
    var p = needle;

    while (p[0] != 0) {
        var dname = [_:0]u8{0} ** 256;
        var q_idx: usize = 0;
        var idx: usize = 0;

        while (p[idx] != 0 and ((p[idx] != '/' and p[idx] != '=') or (idx > 0 and p[idx - 1] == '\\')) and q_idx < dname.len - 1) {
            if (p[idx] == '\\') {
                idx += 1;
            } else {
                dname[q_idx] = p[idx];
                q_idx += 1;
                idx += 1;
            }
        }
        dname[q_idx] = 0;

        cn = null;
        if (do_merge != 0) {
            cn = cn_parent[0].first_child;
            while (cn != null) : (cn = cn[0].next) {
                if (c.strcmp(@ptrCast(cn[0].name), @ptrCast(&dname)) == 0) {
                    break;
                }
            }
        }
        if (cn == null) {
            cn = c.create_cnfnode(@ptrCast(&dname));
            c.append_node(cn_parent, cn);
        }
        cn_parent = cn;
        p += idx;

        if (p[0] == '=') {
            p += 1;
            if (p[0] != 0) {
                var buf = [_:0]u8{0} ** 256;
                c.cnfnode_setval(cn, copyUntilNewline(p, buf[0..]));
            } else {
                c.cnfnode_setval(cn, "");
            }
            break;
        } else if (p[0] == '/') {
            p += 1;
        } else {
            break;
        }
    }

    return cn;
}

export fn cnf_del_branch(cn_root: [*c]c.struct_cnfnode, path: ?[*:0]const u8, del_empty: c_int) c_int {
    if (cn_root == null) {
        setErrno(c.ENOENT);
        return -c.ENOENT;
    }

    const cr = cnf_find_entry_f(cn_root, path, FIND_ENTRY_FLAG_NOPATH | FIND_ENTRY_FLAG_FIRST);
    if (cr != null) {
        const cn_top = cr[0].cnfnode;
        c.unlink_node(cn_top);

        if (del_empty != 0 and cn_top != null) {
            var cn = cn_top[0].parent;
            while (cn != null and cn[0].parent != null and cn != cn_root) {
                const cn_next = cn[0].parent;
                if (cn[0].first_child == null) {
                    c.unlink_node(cn);
                    c.destroy_cnftree(cn);
                }
                cn = cn_next;
            }
        }

        c.destroy_cnftree(cn_top);
        destroy_cnfresult_list(cr);
        return 0;
    }

    setErrno(c.ENOENT);
    return -c.ENOENT;
}

export fn cnf_set_entry(cn_root: [*c]c.struct_cnfnode, path: ?[*:0]const u8, val: ?[*:0]const u8, do_create: c_int) c_int {
    if (cn_root == null) {
        return -1;
    }

    var cn: [*c]c.struct_cnfnode = null;
    const cr = cnf_find_entry_f(cn_root, path, FIND_ENTRY_FLAG_NOPATH | FIND_ENTRY_FLAG_FIRST);
    if (cr != null) {
        cn = cr[0].cnfnode;
        destroy_cnfresult_list(cr);
    } else if (do_create != 0) {
        cn = cnf_add_branch(cn_root, path, 1);
    } else {
        setErrno(c.ENOENT);
        return -1;
    }

    if (cn != null) {
        c.cnfnode_setval(cn, val);
        return 0;
    }

    return -1;
}

export fn cnf_get_entry(cn_root: [*c]c.struct_cnfnode, path: ?[*:0]const u8) [*c]const u8 {
    if (cn_root == null) {
        return null;
    }

    const cr = cnf_find_entry_f(cn_root, path, FIND_ENTRY_FLAG_NOPATH | FIND_ENTRY_FLAG_FIRST);
    if (cr != null) {
        const value = if (cr[0].cnfnode != null) cr[0].cnfnode[0].value else null;
        destroy_cnfresult_list(cr);
        return value;
    }

    setErrno(c.ENOENT);
    return null;
}

export fn cnf_get_node(cn_root: [*c]c.struct_cnfnode, path: ?[*:0]const u8) [*c]c.struct_cnfnode {
    if (cn_root == null) {
        return null;
    }

    const cr = cnf_find_entry_f(cn_root, path, FIND_ENTRY_FLAG_NOPATH | FIND_ENTRY_FLAG_FIRST);
    if (cr != null) {
        const cn = cr[0].cnfnode;
        destroy_cnfresult_list(cr);
        return cn;
    }

    setErrno(c.ENOENT);
    return null;
}

export fn strip_cnftree(cn_root: [*c]c.struct_cnfnode) void {
    if (cn_root == null) {
        return;
    }

    var cn = cn_root[0].first_child;
    while (cn != null) {
        const cn_next = cn[0].next;
        strip_cnftree(cn);

        if (cn[0].name != null and cn[0].name[0] == '.') {
            c.unlink_node(cn);
            c.destroy_cnftree(cn);
        }

        cn = cn_next;
    }
}

test "cnf entry helpers add, find, update, delete, and strip branches" {
    const root = c.create_cnfnode("(root)");
    if (root == null) return error.TestUnexpectedNull;
    defer c.destroy_cnftree(root);

    const leaf = cnf_add_branch(root, "iface/eth0/address=192.168.1.1", 1);
    if (leaf == null) return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("address", std.mem.span(@as([*:0]const u8, @ptrCast(leaf[0].name))));
    try std.testing.expectEqualStrings("192.168.1.1", std.mem.span(@as([*:0]const u8, @ptrCast(cnf_get_entry(root, "iface/eth0/address")))));

    try std.testing.expectEqual(@as(c_int, 0), cnf_set_entry(root, "iface/eth0/netmask", "255.255.255.0", 1));
    try std.testing.expectEqualStrings("255.255.255.0", std.mem.span(@as([*:0]const u8, @ptrCast(cnf_get_entry(root, "iface/eth0/netmask")))));

    const results = cnf_find_entry(root, "iface/eth0/address");
    if (results == null) return error.TestUnexpectedNull;
    defer destroy_cnfresult_list(results);
    try std.testing.expect(results[0].cnfnode == leaf);

    const comment = c.create_cnfnode(".comment");
    if (comment == null) return error.TestUnexpectedNull;
    c.cnfnode_setval(comment, "# ignored");
    c.append_node(root, comment);
    strip_cnftree(root);
    try std.testing.expect(c.find_node(root[0].first_child, ".comment") == null);

    try std.testing.expectEqual(@as(c_int, 0), cnf_del_branch(root, "iface/eth0/address", 1));
    try std.testing.expect(cnf_get_entry(root, "iface/eth0/address") == null);
}
