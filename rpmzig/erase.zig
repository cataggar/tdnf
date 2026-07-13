const std = @import("std");
const Allocator = std.mem.Allocator;
const header = @import("rpm_header");
const install_engine = @import("install.zig");
const txn_config = @import("txn_config.zig");

const RPMTRANS_FLAG_JUSTDB: u32 = 1 << 3;

const sysc = @cImport({
    @cInclude("errno.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

pub const KeepPathFn = *const fn (ctx: ?*anyopaque, path: []const u8) i32;

pub const Options = struct {
    install_root: []const u8,
    trans_flags: u32 = 0,
    keep_path_fn: ?KeepPathFn = null,
    keep_path_ctx: ?*anyopaque = null,
};

pub const Error = install_engine.Error || error{KeepPathQueryFailed};

pub const Context = struct {
    allocator: Allocator,
    hdr: header.Header,
    options: Options,
    config: txn_config.TxnConfig,
    last_path: ?[]const u8 = null,

    pub fn init(
        allocator: Allocator,
        hdr: header.Header,
        options: Options,
    ) (Allocator.Error || txn_config.InitError)!Context {
        var cfg = try txn_config.TxnConfig.init(allocator, options.install_root);
        errdefer cfg.deinit();

        return .{
            .allocator = allocator,
            .hdr = hdr,
            .options = options,
            .config = cfg,
        };
    }

    pub fn deinit(self: *Context) void {
        self.config.deinit();
    }

    pub fn erase(self: *Context) Error!void {
        if ((self.options.trans_flags & RPMTRANS_FLAG_JUSTDB) != 0) {
            return;
        }

        var manifest = try install_engine.Manifest.init(self.allocator, self.hdr);
        defer manifest.deinit();

        var explicit_dirs: std.ArrayList(install_engine.HeaderFile) = .empty;
        defer explicit_dirs.deinit(self.allocator);

        for (manifest.files) |file| {
            self.last_path = file.path;

            if (install_engine.isGhost(file.flags)) {
                continue;
            }

            if (install_engine.isDirMode(file.mode)) {
                try explicit_dirs.append(self.allocator, file);
                continue;
            }

            const target_path = try install_engine.joinInstallRootAndPathOwned(
                self.allocator,
                self.config.installRoot(),
                file.path,
            );
            defer self.allocator.free(target_path);

            if (try self.shouldKeepPath(file.path)) {
                continue;
            }

            try self.eraseNonDirectory(file, target_path);
        }

        sortDirectoriesDeepestFirst(explicit_dirs.items);
        for (explicit_dirs.items) |file| {
            self.last_path = file.path;

            const target_path = try install_engine.joinInstallRootAndPathOwned(
                self.allocator,
                self.config.installRoot(),
                file.path,
            );
            defer self.allocator.free(target_path);

            if (try self.shouldKeepPath(file.path)) {
                continue;
            }

            try removeDirectoryIfEmpty(self.allocator, target_path);
        }
    }

    fn shouldKeepPath(self: *Context, path: []const u8) Error!bool {
        const keep_path_fn = self.options.keep_path_fn orelse return false;
        const rc = keep_path_fn(self.options.keep_path_ctx, path);
        if (rc < 0) return error.KeepPathQueryFailed;
        return rc > 0;
    }

    fn eraseNonDirectory(
        self: *Context,
        file: install_engine.HeaderFile,
        target_path: []const u8,
    ) Error!void {
        if (!install_engine.pathExists(self.allocator, target_path)) {
            return;
        }

        if (install_engine.isConfig(file.flags) and file.digest != null and try isRegularPath(self.allocator, target_path)) {
            const matches = try install_engine.fileDigestMatches(
                self.allocator,
                target_path,
                file.digest_algo,
                file.digest.?,
            );
            if (!matches) {
                const rpmsave_path = try std.fmt.allocPrint(self.allocator, "{s}.rpmsave", .{target_path});
                defer self.allocator.free(rpmsave_path);
                try install_engine.renameExistingPath(self.allocator, target_path, rpmsave_path);
                return;
            }
        }

        try install_engine.removeExistingPath(self.allocator, target_path);
    }
};

fn isRegularPath(allocator: Allocator, path: []const u8) Allocator.Error!bool {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    var st: sysc.struct_stat = undefined;
    if (sysc.lstat(path_z.ptr, &st) != 0) {
        return false;
    }

    return (st.st_mode & sysc.S_IFMT) == sysc.S_IFREG;
}

fn removeDirectoryIfEmpty(allocator: Allocator, path: []const u8) Error!void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const rc = sysc.rmdir(path_z.ptr);
    if (rc == 0) {
        return;
    }

    return switch (std.c.errno(rc)) {
        .NOENT, .NOTEMPTY => {},
        else => error.SyscallFailed,
    };
}

fn sortDirectoriesDeepestFirst(dirs: []install_engine.HeaderFile) void {
    var i: usize = 1;
    while (i < dirs.len) : (i += 1) {
        var j = i;
        while (j > 0 and directoryPathLess(dirs[j - 1].path, dirs[j].path)) : (j -= 1) {
            const tmp = dirs[j - 1];
            dirs[j - 1] = dirs[j];
            dirs[j] = tmp;
        }
    }
}

fn directoryPathLess(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) {
        return a.len < b.len;
    }
    return std.mem.order(u8, a, b) == .lt;
}

test "directory sort keeps deepest paths first" {
    var dirs = [_]install_engine.HeaderFile{
        .{ .path = @constCast("/usr/share/pkg"), .mode = 0, .flags = 0, .mtime = 0, .username = null, .groupname = null, .digest = null, .digest_algo = 0, .caps = null },
        .{ .path = @constCast("/usr/share/pkg/nested"), .mode = 0, .flags = 0, .mtime = 0, .username = null, .groupname = null, .digest = null, .digest_algo = 0, .caps = null },
        .{ .path = @constCast("/etc/pkg"), .mode = 0, .flags = 0, .mtime = 0, .username = null, .groupname = null, .digest = null, .digest_algo = 0, .caps = null },
    };

    sortDirectoriesDeepestFirst(&dirs);

    try std.testing.expectEqualStrings("/usr/share/pkg/nested", dirs[0].path);
    try std.testing.expectEqualStrings("/usr/share/pkg", dirs[1].path);
    try std.testing.expectEqualStrings("/etc/pkg", dirs[2].path);
}
