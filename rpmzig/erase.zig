const std = @import("std");
const Allocator = std.mem.Allocator;
const header = @import("rpm_header");
const install_engine = @import("install.zig");
const txn_config = @import("txn_config.zig");
const rpmtrans = @cImport({
    @cInclude("tdnfrpmtrans.h");
});

const sysc = @cImport({
    @cInclude("errno.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

pub const KeepPathFn = *const fn (ctx: ?*anyopaque, path: []const u8) i32;

pub const Options = struct {
    install_root: []const u8,
    config: ?*const txn_config.TxnConfig = null,
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
    root: install_engine.RootDir,
    last_path: ?[]const u8 = null,
    last_path_storage: [std.fs.max_path_bytes]u8 = undefined,

    pub fn init(
        allocator: Allocator,
        hdr: header.Header,
        options: Options,
    ) install_engine.Error!Context {
        var cfg = if (options.config) |config|
            try config.clone(allocator)
        else
            try txn_config.TxnConfig.init(allocator, options.install_root);
        errdefer cfg.deinit();
        var root = try install_engine.RootDir.init(
            allocator,
            cfg.installRoot(),
            null,
            null,
        );
        errdefer root.deinit();

        return .{
            .allocator = allocator,
            .hdr = hdr,
            .options = options,
            .config = cfg,
            .root = root,
        };
    }

    pub fn deinit(self: *Context) void {
        self.root.deinit();
        self.config.deinit();
    }

    fn setLastPath(self: *Context, path: []const u8) void {
        const len = @min(path.len, self.last_path_storage.len);
        @memcpy(self.last_path_storage[0..len], path[0..len]);
        self.last_path = self.last_path_storage[0..len];
    }

    pub fn erase(self: *Context) Error!void {
        if ((self.options.trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_JUSTDB) != 0) {
            return;
        }

        var manifest = try install_engine.Manifest.init(self.allocator, self.hdr);
        defer manifest.deinit();

        var explicit_dirs: std.ArrayList(install_engine.HeaderFile) = .empty;
        defer explicit_dirs.deinit(self.allocator);

        for (manifest.files) |file| {
            self.setLastPath(file.path);

            if (install_engine.isGhost(file.flags)) {
                continue;
            }

            if (install_engine.isDirMode(file.mode)) {
                try explicit_dirs.append(self.allocator, file);
                continue;
            }

            if (try self.shouldKeepPath(file.path)) {
                continue;
            }

            try self.eraseNonDirectory(file);
        }

        sortDirectoriesDeepestFirst(explicit_dirs.items);
        for (explicit_dirs.items) |file| {
            self.setLastPath(file.path);

            if (try self.shouldKeepPath(file.path)) {
                continue;
            }

            try self.root.removeEmptyDirectory(file.path);
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
    ) Error!void {
        const st = (try self.root.stat(file.path)) orelse return;
        if ((st.st_mode & sysc.S_IFMT) == sysc.S_IFDIR) {
            return;
        }

        if (install_engine.isConfig(file.flags) and
            file.digest != null and
            (st.st_mode & sysc.S_IFMT) == sysc.S_IFREG)
        {
            const matches = try self.root.fileDigestMatches(
                file.path,
                file.digest_algo,
                file.digest.?,
            );
            if (!matches) {
                const rpmsave_path = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}.rpmsave",
                    .{file.path},
                );
                defer self.allocator.free(rpmsave_path);
                try self.root.rename(file.path, rpmsave_path);
                return;
            }
        }

        try self.root.remove(file.path);
    }
};

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
