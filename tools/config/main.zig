// Copyright (C) 2026 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU General Public License v2 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

const std = @import("std");
const c = @cImport({
    @cInclude("ctype.h");
    @cInclude("errno.h");
    @cInclude("getopt.h");
    @cInclude("glob.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");

    @cInclude("common/config.h");

    @cInclude("llconf/nodes.h");
    @cInclude("llconf/modules.h");
    @cInclude("llconf/entry.h");
    @cInclude("llconf/ini.h");

    @cInclude("jsondump/jsondump.h");
});

const ERR_CMDLINE: u8 = 1;
const ERR_SYSTEM: u8 = 2;
const ERR_NO_REPO: u8 = 3;
const ERR_NO_SETTING: u8 = 4;
const ERR_REPO_EXISTS: u8 = 5;
const ERR_JSON: u8 = 6;
const ERR_INTERNAL: u8 = 7;

var mod_ini: [*c]c.struct_cnfmodule = null;

fn cStringSlice(psz: [*c]const u8) []const u8 {
    if (psz == null) {
        return "";
    }
    return std.mem.span(psz);
}

fn getErrno() c_int {
    return c.__errno_location().*;
}

fn skipSpaces(psz: [*c]const u8) [*c]const u8 {
    var p = psz;
    while (p != null and p[0] != 0 and c.isspace(@as(c_int, p[0])) != 0) : (p += 1) {}
    return p;
}

fn findChild(cn_parent: [*c]c.struct_cnfnode, psz_name: [*c]const u8) [*c]c.struct_cnfnode {
    if (cn_parent == null) {
        return null;
    }
    return c.find_node(cn_parent[0].first_child, psz_name);
}

fn freeCString(ppsz: *[*c]u8) void {
    if (ppsz.* != null) {
        c.free(ppsz.*);
        ppsz.* = null;
    }
}

fn failf(rc: u8, comptime fmt: []const u8, args: anytype) u8 {
    std.debug.print(fmt, args);
    return rc;
}

fn setKeyValue(cn_repo: [*c]c.struct_cnfnode, psz_keyval: [*:0]const u8) ?u8 {
    var p: [*c]const u8 = psz_keyval;
    var key = [_]u8{0} ** 256;
    var key_len: usize = 0;

    while (p[0] != 0 and c.isspace(@as(c_int, p[0])) == 0 and p[0] != '=' and key_len < key.len - 1) : (p += 1) {
        key[key_len] = p[0];
        key_len += 1;
    }
    key[key_len] = 0;

    p = skipSpaces(p);
    if (p[0] != '=') {
        std.debug.print("expected '=' after key {s}\n", .{key[0..key_len]});
        return ERR_CMDLINE;
    }

    p += 1;
    p = skipSpaces(p);

    var cn_keyval = findChild(cn_repo, @ptrCast(&key));
    if (cn_keyval == null) {
        cn_keyval = c.create_cnfnode(@ptrCast(&key));
        if (cn_keyval == null) {
            return ERR_INTERNAL;
        }
        c.cnfnode_setval(cn_keyval, @ptrCast(p));
        c.append_node(cn_repo, cn_keyval);
    } else {
        c.cnfnode_setval(cn_keyval, @ptrCast(p));
    }

    return null;
}

fn setKeyValues(cn_root: [*c]c.struct_cnfnode, psz_repo: [*c]const u8, argv: [*c]?[*:0]u8) ?u8 {
    const cn_repo = findChild(cn_root, psz_repo);
    if (cn_repo == null) {
        return null;
    }

    var i: usize = 0;
    while (argv[i] != null) : (i += 1) {
        if (setKeyValue(cn_repo, argv[i].?)) |rc| {
            return rc;
        }
    }

    return null;
}

fn removeKeys(cn_root: [*c]c.struct_cnfnode, psz_repo: [*c]const u8, argv: [*c]?[*:0]u8) ?u8 {
    const cn_repo = findChild(cn_root, psz_repo);
    if (cn_repo == null) {
        std.debug.print("repo '{s}' not found\n", .{cStringSlice(psz_repo)});
        return ERR_NO_REPO;
    }

    var i: usize = 0;
    while (argv[i] != null) : (i += 1) {
        const psz_key = argv[i].?;
        const cn_keyval = findChild(cn_repo, psz_key);
        if (cn_keyval == null) {
            std.debug.print("key '{s}' not found\n", .{cStringSlice(psz_key)});
            return ERR_NO_SETTING;
        }

        c.unlink_node(cn_keyval);
        c.destroy_cnfnode(cn_keyval);
    }

    return null;
}

fn removeRepo(cn_root: [*c]c.struct_cnfnode, psz_repo: [*c]const u8) ?u8 {
    const cn_repo = findChild(cn_root, psz_repo);
    if (cn_repo == null) {
        std.debug.print("repo '{s}' not found\n", .{cStringSlice(psz_repo)});
        return ERR_NO_REPO;
    }

    c.unlink_node(cn_repo);
    c.destroy_cnftree(cn_repo);
    return null;
}

fn getRepodir(psz_main_config: [*c]const u8) [*c]u8 {
    var psz_repodir: [*c]u8 = null;
    const cn_root = c.cnfmodule_parse_file(mod_ini, psz_main_config);

    if (cn_root != null) {
        const cn_main = findChild(cn_root, "main");
        if (cn_main != null) {
            const cn_repodir = findChild(cn_main, c.TDNF_CONF_KEY_REPODIR);
            if (cn_repodir != null) {
                psz_repodir = c.strdup(c.cnfnode_getval(cn_repodir));
            }
        }
    }
    if (psz_repodir == null) {
        psz_repodir = c.strdup(c.TDNF_DEFAULT_REPO_LOCATION);
    }

    if (cn_root != null) {
        c.destroy_cnftree(cn_root);
    }

    return psz_repodir;
}

fn findRepo(psz_repodir: [*c]const u8, psz_repo: [*c]const u8, ppsz_filename: ?*[*c]u8) [*c]c.struct_cnfnode {
    var cn_root: [*c]c.struct_cnfnode = null;
    var pattern = [_]u8{0} ** 256;
    var globbuf = std.mem.zeroes(c.glob_t);

    defer c.globfree(&globbuf);

    const rc_fmt = c.snprintf(&pattern, pattern.len, "%s/*.repo", psz_repodir);
    if (rc_fmt < 0 or rc_fmt >= pattern.len) {
        return null;
    }

    const rc_glob = c.glob(@ptrCast(&pattern), 0, null, &globbuf);
    if (rc_glob != 0 and rc_glob != c.GLOB_NOMATCH) {
        return null;
    }

    if (rc_glob == 0) {
        var i: usize = 0;
        while (globbuf.gl_pathv[i] != null) : (i += 1) {
            cn_root = c.cnfmodule_parse_file(mod_ini, globbuf.gl_pathv[i]);
            if (cn_root == null) {
                return null;
            }

            if (findChild(cn_root, psz_repo) != null) {
                if (ppsz_filename) |ppsz| {
                    ppsz.* = c.strdup(globbuf.gl_pathv[i]);
                }
                return cn_root;
            }

            c.destroy_cnftree(cn_root);
            cn_root = null;
        }
    }

    return null;
}

fn writeFile(cn_root: [*c]c.struct_cnfnode, psz_filename: [*c]const u8) c_int {
    var buf = [_]u8{0} ** 256;

    const rc_fmt = c.snprintf(&buf, buf.len, "%s.tmp", psz_filename);
    if (rc_fmt < 0 or rc_fmt >= buf.len) {
        return -1;
    }

    var rc = c.cnfmodule_unparse_file(mod_ini, @ptrCast(&buf), cn_root);
    if (rc != 0) {
        _ = c.unlink(@ptrCast(&buf));
        return rc;
    }

    rc = c.rename(@ptrCast(&buf), psz_filename);
    if (rc != 0) {
        _ = c.unlink(@ptrCast(&buf));
    }
    return rc;
}

fn cnfTreeToJson(cn_root: [*c]c.struct_cnfnode) ?*c.struct_json_dump {
    const jd = c.jd_create(0) orelse return null;

    if (c.jd_map_start(jd) != 0) {
        c.jd_destroy(jd);
        return null;
    }

    if (cn_root[0].first_child != null) {
        const jd_child = cnfTreeToJson(cn_root[0].first_child) orelse {
            c.jd_destroy(jd);
            return null;
        };
        defer c.jd_destroy(jd_child);

        if (c.jd_map_add_child(jd, cn_root[0].name, jd_child) != 0) {
            c.jd_destroy(jd);
            return null;
        }
    } else {
        var cn = cn_root;
        while (cn != null) : (cn = cn[0].next) {
            if (c.jd_map_add_string(jd, cn[0].name, cn[0].value) != 0) {
                c.jd_destroy(jd);
                return null;
            }
        }
    }

    return jd;
}

fn strIsValidRepoName(psz: [*c]const u8) bool {
    var p = psz;
    if (p == null or p[0] == 0 or c.isalnum(@as(c_int, p[0])) == 0) {
        return false;
    }

    while (p[0] != 0 and
        (c.isalnum(@as(c_int, p[0])) != 0 or p[0] == '-' or p[0] == '_' or p[0] == '.')) : (p += 1)
    {}

    return p[0] == 0;
}

fn printWriteError(psz_filename: [*c]const u8) u8 {
    const n_errno = getErrno();
    return failf(
        ERR_SYSTEM,
        "failed to write file '{s}': {s} ({d})",
        .{ cStringSlice(psz_filename), cStringSlice(c.strerror(n_errno)), n_errno },
    );
}

fn printRemoveError(psz_filename: [*c]const u8) u8 {
    const n_errno = getErrno();
    return failf(
        ERR_SYSTEM,
        "failed to remove file '{s}': {s} ({d})",
        .{ cStringSlice(psz_filename), cStringSlice(c.strerror(n_errno)), n_errno },
    );
}

pub fn main(init: std.process.Init.Minimal) u8 {
    var psz_main_config: [*c]const u8 = c.TDNF_CONF_FILE;
    var psz_repo_config: [*c]const u8 = null;
    var do_json = false;

    const argv = init.args.vector;
    const argc: c_int = @intCast(argv.len);
    const argv_ptr: [*c]?[*:0]u8 = @ptrCast(@constCast(argv.ptr));

    c.optind = 1;
    c.opterr = 1;
    c.optopt = 0;
    c.optarg = null;

    while (true) {
        var long_options = [_]c.struct_option{
            .{ .name = "config", .has_arg = 1, .flag = null, .val = 'c' },
            .{ .name = "file", .has_arg = 1, .flag = null, .val = 'f' },
            .{ .name = "json", .has_arg = 1, .flag = null, .val = 'j' },
            .{ .name = null, .has_arg = 0, .flag = null, .val = 0 },
        };

        const opt = c.getopt_long(argc, @ptrCast(argv_ptr), "c:f:j", &long_options, null);
        if (opt == -1) {
            break;
        }

        switch (opt) {
            'c' => psz_main_config = c.optarg,
            'f' => psz_repo_config = c.optarg,
            'j' => do_json = true,
            '?' => return ERR_CMDLINE,
            else => return ERR_CMDLINE,
        }
    }

    c.register_ini(null);
    mod_ini = c.find_cnfmodule("ini");
    if (mod_ini == null) {
        return failf(ERR_INTERNAL, "internal error: could not find parser", .{});
    }

    if (c.optind >= argc) {
        return 0;
    }

    const optind: usize = @intCast(c.optind);
    const argcount = argv.len - optind;
    const psz_action: [*c]const u8 = argv[optind];

    if (argcount < 2) {
        return failf(ERR_CMDLINE, "expected main or repo name\n", .{});
    }

    const psz_repo: [*c]const u8 = argv[optind + 1];
    if (!strIsValidRepoName(psz_repo)) {
        return failf(ERR_CMDLINE, "'{s}' is not a valid repository name", .{cStringSlice(psz_repo)});
    }

    var psz_filename: [*c]u8 = null;
    var cn_root: [*c]c.struct_cnfnode = null;

    defer freeCString(&psz_filename);
    defer if (cn_root != null) c.destroy_cnftree(cn_root);

    if (c.strcmp(psz_action, "create") != 0) {
        if (psz_repo_config == null) {
            if (c.strcmp(psz_repo, "main") == 0) {
                cn_root = c.cnfmodule_parse_file(mod_ini, psz_main_config);
                if (cn_root == null) {
                    return failf(ERR_SYSTEM, "could not parse config file {s}\n", .{cStringSlice(psz_main_config)});
                }
                psz_filename = c.strdup(psz_main_config);
            } else {
                var psz_repodir = getRepodir(psz_main_config);
                defer freeCString(&psz_repodir);

                cn_root = findRepo(psz_repodir, psz_repo, &psz_filename);
                if (cn_root == null) {
                    return failf(ERR_NO_REPO, "repo '{s}' not found\n", .{cStringSlice(psz_repo)});
                }
            }
        } else {
            cn_root = c.cnfmodule_parse_file(mod_ini, psz_repo_config);
            if (cn_root == null) {
                return failf(ERR_SYSTEM, "could not parse repo file {s}\n", .{cStringSlice(psz_repo_config)});
            }
            psz_filename = c.strdup(psz_repo_config);
        }
    } else {
        if (c.strcmp(psz_repo, "main") == 0) {
            return failf(ERR_CMDLINE, "invalid repo name 'main'\n", .{});
        }

        var buf = [_]u8{0} ** 256;
        var psz_repodir = getRepodir(psz_main_config);
        defer freeCString(&psz_repodir);

        const existing_root = findRepo(psz_repodir, psz_repo, null);
        if (existing_root != null) {
            c.destroy_cnftree(existing_root);
            return failf(ERR_REPO_EXISTS, "repo '{s}' already exists\n", .{cStringSlice(psz_repo)});
        }

        const cn_repo = c.create_cnfnode(psz_repo);
        if (cn_repo == null) {
            return ERR_INTERNAL;
        }

        if (psz_repo_config == null) {
            cn_root = c.create_cnfnode("(root)");
            if (cn_root == null) {
                c.destroy_cnfnode(cn_repo);
                return ERR_INTERNAL;
            }

            if (c.snprintf(&buf, buf.len, "%s/%s.repo", psz_repodir, psz_repo) >= buf.len) {
                c.destroy_cnfnode(cn_repo);
                return failf(ERR_SYSTEM, "path to repo config is too long", .{});
            }
            psz_filename = c.strdup(@ptrCast(&buf));
        } else {
            cn_root = c.cnfmodule_parse_file(mod_ini, psz_repo_config);
            if (cn_root == null) {
                if (getErrno() == c.ENOENT) {
                    cn_root = c.create_cnfnode("(root)");
                } else {
                    c.destroy_cnfnode(cn_repo);
                    return failf(ERR_SYSTEM, "could not parse config file {s}\n", .{cStringSlice(psz_repo_config)});
                }
            }
            if (cn_root == null) {
                c.destroy_cnfnode(cn_repo);
                return ERR_INTERNAL;
            }
            psz_filename = c.strdup(psz_repo_config);
        }

        c.append_node(cn_root, cn_repo);
    }

    if (c.strcmp(psz_action, "edit") == 0 or c.strcmp(psz_action, "create") == 0) {
        if (argcount < 3) {
            return failf(ERR_CMDLINE, "expected at least one setting.", .{});
        }

        if (setKeyValues(cn_root, psz_repo, argv_ptr + optind + 2)) |rc| {
            return rc;
        }

        if (psz_filename != null) {
            if (writeFile(cn_root, psz_filename) != 0) {
                return printWriteError(psz_filename);
            }
            return 0;
        }

        _ = c.cnfmodule_unparse(mod_ini, c.stdout, cn_root);
        return 0;
    }

    if (c.strcmp(psz_action, "get") == 0) {
        if (argcount < 3) {
            return failf(ERR_CMDLINE, "expected one setting\n", .{});
        }

        const cn_repo = findChild(cn_root, psz_repo);
        if (cn_repo == null) {
            return failf(ERR_NO_REPO, "repo '{s}' not found\n", .{cStringSlice(psz_repo)});
        }

        const cn_keyval = findChild(cn_repo, argv[optind + 2]);
        if (cn_keyval == null) {
            return failf(
                ERR_NO_SETTING,
                "'{s}' not found in '{s}'\n",
                .{ cStringSlice(argv[optind + 2]), cStringSlice(psz_repo) },
            );
        }

        _ = c.printf("%s\n", cn_keyval[0].value);
        return 0;
    }

    if (c.strcmp(psz_action, "remove") == 0) {
        if (argcount < 3) {
            return failf(ERR_CMDLINE, "expected one setting\n", .{});
        }

        if (removeKeys(cn_root, psz_repo, argv_ptr + optind + 2)) |rc| {
            return rc;
        }

        if (psz_filename != null) {
            if (writeFile(cn_root, psz_filename) != 0) {
                return printWriteError(psz_filename);
            }
            return 0;
        }

        _ = c.cnfmodule_unparse(mod_ini, c.stdout, cn_root);
        return 0;
    }

    if (c.strcmp(psz_action, "removerepo") == 0) {
        if (removeRepo(cn_root, psz_repo)) |rc| {
            return rc;
        }

        if (psz_filename != null) {
            if (cn_root[0].first_child != null) {
                if (writeFile(cn_root, psz_filename) != 0) {
                    return printWriteError(psz_filename);
                }
            } else if (c.unlink(psz_filename) != 0) {
                return printRemoveError(psz_filename);
            }
            return 0;
        }

        _ = c.cnfmodule_unparse(mod_ini, c.stdout, cn_root);
        return 0;
    }

    if (c.strcmp(psz_action, "dump") == 0) {
        const cn_repo = findChild(cn_root, psz_repo);
        if (cn_repo == null) {
            return failf(ERR_NO_REPO, "repo '{s}' not found\n", .{cStringSlice(psz_repo)});
        }

        c.unlink_node(cn_repo);

        if (!do_json) {
            const cn_root_tmp = c.create_cnfnode("(root)");
            if (cn_root_tmp == null) {
                return ERR_INTERNAL;
            }
            c.append_node(cn_root_tmp, cn_repo);
            _ = c.cnfmodule_unparse(mod_ini, c.stdout, cn_root_tmp);
            c.destroy_cnftree(cn_root_tmp);
        } else {
            const jd = cnfTreeToJson(cn_repo) orelse {
                return failf(ERR_JSON, "failed to generate json\n", .{});
            };
            defer c.jd_destroy(jd);

            _ = c.printf("%s", jd.buf);
            c.destroy_cnftree(cn_repo);
        }

        return 0;
    }

    return failf(ERR_CMDLINE, "Unknown command '{s}'\n", .{cStringSlice(psz_action)});
}

test "repository name validation preserves current rules" {
    try std.testing.expect(strIsValidRepoName("foo"));
    try std.testing.expect(strIsValidRepoName("foo-bar_1.2"));
    try std.testing.expect(!strIsValidRepoName(""));
    try std.testing.expect(!strIsValidRepoName(" foo"));
    try std.testing.expect(!strIsValidRepoName("-foo"));
    try std.testing.expect(!strIsValidRepoName("foo/bar"));
}

test "json dump preserves repo wrapper object" {
    const cn_repo = c.create_cnfnode("foo");
    defer c.destroy_cnftree(cn_repo);

    const cn_name = c.create_cnfnode("name");
    const cn_enabled = c.create_cnfnode("enabled");
    if (cn_name == null or cn_enabled == null) return error.TestUnexpectedNull;

    c.cnfnode_setval(cn_name, "Foo");
    c.cnfnode_setval(cn_enabled, "1");
    c.append_node(cn_repo, cn_name);
    c.append_node(cn_repo, cn_enabled);

    const jd = cnfTreeToJson(cn_repo) orelse return error.TestUnexpectedNull;
    defer c.jd_destroy(jd);

    try std.testing.expectEqualStrings(
        "{\"foo\":{\"name\":\"Foo\",\"enabled\":\"1\"}}",
        std.mem.span(jd.buf),
    );
}
