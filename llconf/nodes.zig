// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");

const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("nodes.h");
});

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

fn duplicateCStringPrefix(pszOpt: ?[*:0]const u8, n: usize) [*c]u8 {
    const psz = pszOpt orelse return null;
    var len: usize = 0;
    while (len < n and psz[len] != 0) : (len += 1) {}
    return duplicateBytes(psz[0..len]);
}

fn freeCString(psz: [*c]u8) void {
    if (psz != null) {
        c.free(psz);
    }
}

fn allocateNode() [*c]c.struct_cnfnode {
    const raw = c.calloc(1, @sizeOf(c.struct_cnfnode)) orelse return null;
    return @ptrCast(@alignCast(raw));
}

fn strcmpNull(s1: [*c]const u8, s2: [*c]const u8) c_int {
    if (s1 != null and s2 != null) {
        return c.strcmp(s1, s2);
    }
    if (s2 != null) return -1;
    if (s1 != null) return 1;
    return 0;
}

export fn create_cnfnode(name: ?[*:0]const u8) [*c]c.struct_cnfnode {
    const cn = allocateNode();
    if (cn == null) {
        return null;
    }
    cn[0].name = duplicateCString(name);
    return cn;
}

export fn create_cnfnode_keyval(keyval: ?[*:0]const u8) [*c]c.struct_cnfnode {
    const value = keyval orelse return null;
    const psep = c.strstr(@ptrCast(value), "=") orelse return null;
    const cn = create_cnfnode(null);
    if (cn == null) {
        return null;
    }
    cnfnode_setname_n(cn, value, @intCast(@intFromPtr(psep) - @intFromPtr(value)));
    cnfnode_setval(cn, @ptrCast(psep + 1));
    return cn;
}

export fn clone_cnfnode(cn: [*c]const c.struct_cnfnode) [*c]c.struct_cnfnode {
    if (cn == null) {
        return null;
    }

    const new_cn = allocateNode();
    if (new_cn == null) {
        return null;
    }

    new_cn[0].name = duplicateCString(@ptrCast(cn[0].name));
    new_cn[0].value = duplicateCString(@ptrCast(cn[0].value));
    return new_cn;
}

export fn compare_cnfnode(cn1: [*c]const c.struct_cnfnode, cn2: [*c]const c.struct_cnfnode) c_int {
    if (cn1 == null or cn2 == null) {
        return 0;
    }

    var ret = c.strcmp(@ptrCast(cn1[0].name), @ptrCast(cn2[0].name));
    if (ret != 0) {
        return if (ret > 0) 2 else -2;
    }

    ret = strcmpNull(@ptrCast(cn1[0].value), @ptrCast(cn2[0].value));
    if (ret != 0) {
        return if (ret > 0) 1 else -1;
    }

    return 0;
}

export fn cnfnode_getval(cn: [*c]const c.struct_cnfnode) [*c]const u8 {
    return if (cn != null) cn[0].value else null;
}

export fn cnfnode_getname(cn: [*c]const c.struct_cnfnode) [*c]const u8 {
    return if (cn != null) cn[0].name else null;
}

export fn cnfnode_setval(cn: [*c]c.struct_cnfnode, value: ?[*:0]const u8) void {
    if (cn == null) {
        return;
    }
    freeCString(cn[0].value);
    cn[0].value = duplicateCString(value);
}

export fn cnfnode_setname(cn: [*c]c.struct_cnfnode, name: ?[*:0]const u8) void {
    if (cn == null) {
        return;
    }
    freeCString(cn[0].name);
    cn[0].name = duplicateCString(name);
}

export fn cnfnode_setname_n(cn: [*c]c.struct_cnfnode, name: ?[*:0]const u8, n: usize) void {
    if (cn == null) {
        return;
    }
    freeCString(cn[0].name);
    cn[0].name = duplicateCStringPrefix(name, n);
}

export fn destroy_cnfnode(cn: [*c]c.struct_cnfnode) void {
    if (cn == null) {
        return;
    }
    freeCString(cn[0].name);
    freeCString(cn[0].value);
    c.free(cn);
}

export fn destroy_cnftree(cn_root: [*c]c.struct_cnfnode) void {
    if (cn_root == null) {
        return;
    }

    var cn = cn_root[0].first_child;
    while (cn != null) {
        const cn_next = cn[0].next;
        destroy_cnftree(cn);
        cn = cn_next;
    }
    destroy_cnfnode(cn_root);
}

export fn append_node(cn_parent: [*c]c.struct_cnfnode, cn: [*c]c.struct_cnfnode) void {
    if (cn_parent == null or cn == null) {
        return;
    }

    var cnp = &cn_parent[0].first_child;
    while (cnp.* != null) {
        cnp = &cnp.*[0].next;
    }
    cnp.* = cn;
    cn[0].parent = cn_parent;
    cn[0].next = null;
}

export fn insert_node_before(cn_before: [*c]c.struct_cnfnode, cn: [*c]c.struct_cnfnode) void {
    if (cn_before == null or cn == null or cn_before[0].parent == null) {
        return;
    }

    const cn_parent = cn_before[0].parent;
    var cnp = &cn_parent[0].first_child;
    while (cnp.* != null and cnp.* != cn_before) {
        cnp = &cnp.*[0].next;
    }

    cnp.* = cn;
    cn[0].parent = cn_parent;
    cn[0].next = cn_before;
}

export fn unlink_node(cn: [*c]c.struct_cnfnode) void {
    if (cn == null or cn[0].parent == null) {
        return;
    }

    const parent = cn[0].parent;
    var pcn = &parent[0].first_child;
    while (pcn.* != null and pcn.* != cn) {
        pcn = &pcn.*[0].next;
    }
    if (pcn.* != null) {
        pcn.* = cn[0].next;
    }
}

export fn find_node(cn_list: [*c]c.struct_cnfnode, name: ?[*:0]const u8) [*c]c.struct_cnfnode {
    const target = name orelse return null;
    var cn = cn_list;
    while (cn != null) : (cn = cn[0].next) {
        if (c.strcmp(@ptrCast(cn[0].name), @ptrCast(target)) == 0) {
            return cn;
        }
    }
    return null;
}

export fn clone_cnftree(cn_root: [*c]const c.struct_cnfnode) [*c]c.struct_cnfnode {
    if (cn_root == null) {
        return null;
    }

    const cn_root_new = clone_cnfnode(cn_root);
    if (cn_root_new == null) {
        return null;
    }

    var cn = cn_root[0].first_child;
    while (cn != null) : (cn = cn[0].next) {
        append_node(cn_root_new, clone_cnftree(cn));
    }

    return cn_root_new;
}

export fn compare_cnftree(cn_root1: [*c]const c.struct_cnfnode, cn_root2: [*c]const c.struct_cnfnode) c_int {
    if (cn_root1 != null and cn_root2 != null) {
        const ret = compare_cnfnode(cn_root1, cn_root2);
        if (ret != 0) return ret;
    } else {
        if (cn_root1 == null and cn_root2 == null) return 0;
        return if (cn_root1 == null) -3 else 3;
    }

    var cn1 = cn_root1[0].first_child;
    var cn2 = cn_root2[0].first_child;
    while (cn1 != null or cn2 != null) {
        const ret = compare_cnftree(cn1, cn2);
        if (ret != 0) return ret;
        cn1 = if (cn1 != null) cn1[0].next else null;
        cn2 = if (cn2 != null) cn2[0].next else null;
    }

    return 0;
}

export fn compare_cnftree_children(cn_root1: [*c]const c.struct_cnfnode, cn_root2: [*c]const c.struct_cnfnode) c_int {
    if (!(cn_root1 != null and cn_root2 != null)) {
        if (cn_root1 == null and cn_root2 == null) return 0;
        return if (cn_root1 == null) -3 else 3;
    }

    var cn1 = cn_root1[0].first_child;
    var cn2 = cn_root2[0].first_child;
    while (cn1 != null or cn2 != null) {
        const ret = compare_cnftree(cn1, cn2);
        if (ret != 0) return ret;
        cn1 = if (cn1 != null) cn1[0].next else null;
        cn2 = if (cn2 != null) cn2[0].next else null;
    }

    return 0;
}

export fn dump_nodes(cn_root: [*c]c.struct_cnfnode, level: c_int) void {
    if (cn_root == null) {
        return;
    }

    var i: c_int = 0;
    while (i < level) : (i += 1) {
        _ = c.putchar('\t');
    }
    _ = c.printf("%s", cn_root[0].name);
    if (cn_root[0].value != null) {
        _ = c.printf(" = '%s'", cn_root[0].value);
    }
    _ = c.putchar('\n');

    var cn = cn_root[0].first_child;
    while (cn != null) : (cn = cn[0].next) {
        dump_nodes(cn, level + 1);
    }
}

test "cnfnode tree helpers preserve tree structure" {
    const root = create_cnfnode("(root)");
    if (root == null) return error.TestUnexpectedNull;
    defer destroy_cnftree(root);

    const alpha = create_cnfnode("alpha");
    if (alpha == null) return error.TestUnexpectedNull;
    cnfnode_setval(alpha, "one");
    append_node(root, alpha);

    const beta = create_cnfnode_keyval("beta=two");
    if (beta == null) return error.TestUnexpectedNull;
    append_node(root, beta);

    const gamma = create_cnfnode("gamma");
    if (gamma == null) return error.TestUnexpectedNull;
    insert_node_before(beta, gamma);

    try std.testing.expectEqualStrings("alpha", std.mem.span(@as([*:0]const u8, @ptrCast(cnfnode_getname(alpha)))));
    try std.testing.expectEqualStrings("one", std.mem.span(@as([*:0]const u8, @ptrCast(cnfnode_getval(alpha)))));
    try std.testing.expect(find_node(root[0].first_child, "beta") == beta);
    try std.testing.expect(find_node(root[0].first_child, "gamma") == gamma);

    const clone = clone_cnftree(root);
    if (clone == null) return error.TestUnexpectedNull;
    defer destroy_cnftree(clone);

    try std.testing.expectEqual(@as(c_int, 0), compare_cnftree(root, clone));
    cnfnode_setval(clone[0].first_child, "changed");
    try std.testing.expect(compare_cnftree(root, clone) != 0);

    unlink_node(beta);
    try std.testing.expect(find_node(root[0].first_child, "beta") == null);
}
