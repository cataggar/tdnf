const std = @import("std");
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const header = @import("rpm_header");
const pkgfile = @import("rpm_pkgfile");
const cpio = @import("cpio.zig");
const txn_config = @import("txn_config.zig");
const rpmtrans = @cImport({
    @cInclude("tdnfrpmtrans.h");
});

const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const AT_REMOVEDIR: c_int = 0x200;
const AT_EMPTY_PATH: u32 = 0x1000;

const c = @cImport({
    @cInclude("grp.h");
    @cInclude("pwd.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/sysmacros.h");
    @cInclude("sys/time.h");
    @cInclude("sys/types.h");
    @cInclude("unistd.h");
});

const RPMFILE_CONFIG: u32 = 1 << 0;
const RPMFILE_DOC: u32 = 1 << 1;
const RPMFILE_NOREPLACE: u32 = 1 << 4;
const RPMFILE_GHOST: u32 = 1 << 6;
const RPMFILE_LICENSE: u32 = 1 << 7;
const RPMFILE_README: u32 = 1 << 8;

const S_IFMT_U32: u32 = @intCast(c.S_IFMT);
const S_IFREG_U32: u32 = @intCast(c.S_IFREG);
const S_IFDIR_U32: u32 = @intCast(c.S_IFDIR);
const S_IFLNK_U32: u32 = @intCast(c.S_IFLNK);
const S_IFCHR_U32: u32 = @intCast(c.S_IFCHR);
const S_IFBLK_U32: u32 = @intCast(c.S_IFBLK);
const S_IFIFO_U32: u32 = @intCast(c.S_IFIFO);
const MODE_PERMS_MASK: u32 = 0o7777;

pub const InstallKind = enum(u32) {
    install = 0,
    upgrade = 1,
    reinstall = 2,
};

pub const ConflictFn = *const fn (ctx: ?*anyopaque, path: []const u8) i32;
pub const ChangedPathFn = *const fn (ctx: ?*anyopaque, path: []const u8) i32;
pub const MutationFn = *const fn (ctx: ?*anyopaque) void;

pub const Options = struct {
    install_root: []const u8,
    config: ?*const txn_config.TxnConfig = null,
    trans_flags: u32 = 0,
    install_kind: InstallKind = .install,
    prior_headers: []const header.Header = &.{},
    conflict_fn: ?ConflictFn = null,
    conflict_ctx: ?*anyopaque = null,
    changed_path_fn: ?ChangedPathFn = null,
    changed_path_ctx: ?*anyopaque = null,
    mutation_fn: ?MutationFn = null,
    mutation_ctx: ?*anyopaque = null,
};

pub const InstallError = error{
    BadHeader,
    InvalidPackagePath,
    MissingHeaderPath,
    MissingPayloadEntry,
    UnsupportedDigestAlgorithm,
    UnsupportedFileCapabilities,
    UnsupportedFileType,
    UnsupportedSourceRpm,
    FileConflict,
    ConflictQueryFailed,
    ChangedPathCallbackFailed,
    HardlinkMissingPayload,
    UnsafeExtractionPath,
    SyscallFailed,
};

pub const Error = Allocator.Error || txn_config.InitError || cpio.Error || pkgfile.Error || InstallError;

pub const Context = struct {
    allocator: Allocator,
    rpm: *const pkgfile.RpmFile,
    options: Options,
    config: txn_config.TxnConfig,
    root: RootDir,
    last_path: ?[]const u8 = null,
    last_path_storage: [std.fs.max_path_bytes]u8 = undefined,

    pub fn init(
        allocator: Allocator,
        rpm: *const pkgfile.RpmFile,
        options: Options,
    ) Error!Context {
        var cfg = if (options.config) |config|
            try config.clone(allocator)
        else
            try txn_config.TxnConfig.init(allocator, options.install_root);
        errdefer cfg.deinit();
        var root = try RootDir.init(
            allocator,
            cfg.installRoot(),
            options.mutation_fn,
            options.mutation_ctx,
        );
        errdefer root.deinit();

        return .{
            .allocator = allocator,
            .rpm = rpm,
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

    pub fn install(self: *Context) Error!void {
        if (self.isSourceRpm()) {
            return error.UnsupportedSourceRpm;
        }

        if ((self.options.trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_JUSTDB) != 0) {
            return;
        }

        var manifest = try Manifest.init(self.allocator, self.rpm.main);
        defer manifest.deinit();

        var prior_manifests: std.ArrayList(Manifest) = .empty;
        defer {
            for (prior_manifests.items) |*prior| {
                prior.deinit();
            }
            prior_manifests.deinit(self.allocator);
        }

        for (self.options.prior_headers) |prior_header| {
            const prior_manifest = try Manifest.init(self.allocator, prior_header);
            try prior_manifests.append(self.allocator, prior_manifest);
        }

        const payload = try self.rpm.decompressPayload(self.allocator);
        defer self.allocator.free(payload);

        var walker = cpio.Walker.init(payload);
        var deferred_dirs: std.ArrayList(DeferredDir) = .empty;
        defer {
            for (deferred_dirs.items) |dir| {
                self.allocator.free(dir.target_path);
            }
            deferred_dirs.deinit(self.allocator);
        }

        var hardlinks = std.AutoHashMap(HardlinkKey, HardlinkState).init(self.allocator);
        defer {
            var iterator = hardlinks.valueIterator();
            while (iterator.next()) |state| {
                state.deinit(self.allocator);
            }
            hardlinks.deinit();
        }

        while (true) {
            const maybe_entry = try walker.next();
            const entry = maybe_entry orelse break;

            const payload_path = try normalizeCpioPathOwned(self.allocator, entry.name);
            defer self.allocator.free(payload_path);

            const manifest_index = manifest.index.get(payload_path) orelse {
                self.setLastPath(payload_path);
                return error.MissingHeaderPath;
            };
            manifest.processed[manifest_index] = true;

            const file = manifest.files[manifest_index];
            self.setLastPath(file.path);

            if (shouldSkipFile(file.flags, self.options.trans_flags)) {
                continue;
            }
            if (isGhost(file.flags)) {
                continue;
            }
            if (hasCapabilities(file) and
                (self.options.trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOCAPS) == 0)
            {
                return error.UnsupportedFileCapabilities;
            }

            const target_path = file.path;

            const metadata = try self.buildMetadata(file, entry);

            if (isDirMode(metadata.mode)) {
                try self.root.ensureDirectory(target_path);
                try deferred_dirs.append(self.allocator, .{
                    .target_path = try self.allocator.dupe(u8, target_path),
                    .mode = metadata.mode,
                    .mtime = metadata.mtime,
                    .uid = metadata.uid,
                    .gid = metadata.gid,
                });
                try self.notifyChangedPath(file.path);
                continue;
            }

            const action = try self.decideAction(
                file,
                prior_manifests.items,
                target_path,
            );

            switch (action) {
                .skip => continue,
                .install => {
                    try self.installEntry(
                        entry,
                        metadata,
                        target_path,
                        &hardlinks,
                    );
                    try self.notifyChangedPath(file.path);
                },
                .rpmnew => {
                    const rpmnew_path = try std.fmt.allocPrint(self.allocator, "{s}.rpmnew", .{target_path});
                    defer self.allocator.free(rpmnew_path);
                    try self.installEntry(entry, metadata, rpmnew_path, &hardlinks);
                    try self.notifyChangedPath(file.path);
                },
                .rpmsave => {
                    const rpmsave_path = try std.fmt.allocPrint(self.allocator, "{s}.rpmsave", .{target_path});
                    defer self.allocator.free(rpmsave_path);
                    try self.root.rename(target_path, rpmsave_path);
                    try self.installEntry(entry, metadata, target_path, &hardlinks);
                    try self.notifyChangedPath(file.path);
                },
            }
        }

        try self.ensureNoMissingHardlinks(&hardlinks);
        try self.ensureNoMissingEntries(&manifest);
        try self.applyDeferredDirs(deferred_dirs.items);
    }

    fn notifyChangedPath(self: *Context, path: []const u8) InstallError!void {
        const callback = self.options.changed_path_fn orelse return;
        if (callback(self.options.changed_path_ctx, path) != 0) {
            return error.ChangedPathCallbackFailed;
        }
    }

    fn isSourceRpm(self: *const Context) bool {
        const arch = self.rpm.main.getString(.arch) orelse return false;
        return std.mem.eql(u8, arch, "src") or std.mem.eql(u8, arch, "nosrc");
    }

    fn buildMetadata(
        self: *Context,
        file: HeaderFile,
        entry: cpio.Entry,
    ) Error!Metadata {
        return resolveFileMetadata(
            self.allocator,
            self.config.installRoot(),
            file.mode,
            file.mtime,
            file.username,
            file.groupname,
            entry.mode,
            entry.mtime,
            entry.uid,
            entry.gid,
        );
    }

    fn decideAction(
        self: *Context,
        file: HeaderFile,
        prior_manifests: []const Manifest,
        target_path: []const u8,
    ) Error!ConfigAction {
        if (!(try self.root.pathExists(target_path))) {
            return .install;
        }

        const prior = findPriorFile(prior_manifests, file.path);
        if (prior == null) {
            const conflict_fn = self.options.conflict_fn orelse return .install;
            const rc = conflict_fn(self.options.conflict_ctx, file.path);
            if (rc < 0) return error.ConflictQueryFailed;
            if (rc > 0) return error.FileConflict;
            return .install;
        }

        if (!isConfig(file.flags)) {
            return .install;
        }
        if (self.options.install_kind == .install) {
            return .install;
        }

        const new_digest = file.digest orelse return .install;
        const matches_new = try self.root.fileDigestMatches(
            target_path,
            file.digest_algo,
            new_digest,
        );
        if (matches_new) {
            return .skip;
        }

        const prior_file = prior.?;
        const old_digest = prior_file.digest orelse return .install;
        const matches_old = try self.root.fileDigestMatches(
            target_path,
            prior_file.digest_algo,
            old_digest,
        );
        return chooseConfigAction(matches_old, matches_new, isNoReplace(file.flags));
    }

    fn installEntry(
        self: *Context,
        entry: cpio.Entry,
        metadata: Metadata,
        target_path: []const u8,
        hardlinks: *std.AutoHashMap(HardlinkKey, HardlinkState),
    ) Error!void {
        if (isRegularMode(metadata.mode) and entry.nlink > 1) {
            try self.installHardlinkEntry(entry, metadata, target_path, hardlinks);
            return;
        }

        try self.writeConcreteEntry(entry, metadata, target_path);
    }

    fn installHardlinkEntry(
        self: *Context,
        entry: cpio.Entry,
        metadata: Metadata,
        target_path: []const u8,
        hardlinks: *std.AutoHashMap(HardlinkKey, HardlinkState),
    ) Error!void {
        const key = HardlinkKey{
            .ino = entry.ino,
            .devmajor = entry.devmajor,
            .devminor = entry.devminor,
        };
        const gop = try hardlinks.getOrPut(key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        const state = gop.value_ptr;

        if (entry.data.len > 0) {
            if (state.canonical_path == null) {
                try self.writeConcreteEntry(entry, metadata, target_path);
                state.canonical_path = try self.allocator.dupe(u8, target_path);
                for (state.pending_paths.items) |pending_path| {
                    try self.root.hardLink(target_path, pending_path);
                }
                for (state.pending_paths.items) |pending_path| {
                    self.allocator.free(pending_path);
                }
                state.pending_paths.clearRetainingCapacity();
                return;
            }
        }

        if (state.canonical_path) |canonical_path| {
            try self.root.hardLink(canonical_path, target_path);
            return;
        }

        try state.pending_paths.append(self.allocator, try self.allocator.dupe(u8, target_path));
    }

    fn writeConcreteEntry(
        self: *Context,
        entry: cpio.Entry,
        metadata: Metadata,
        target_path: []const u8,
    ) Error!void {
        const mode_type = metadata.mode & S_IFMT_U32;
        if (mode_type == S_IFREG_U32) {
            try self.root.writeRegularFile(target_path, entry.data, metadata);
            return;
        }
        if (mode_type == S_IFLNK_U32) {
            try self.root.writeSymlink(target_path, entry.data, metadata);
            return;
        }
        if (mode_type == S_IFCHR_U32 or mode_type == S_IFBLK_U32) {
            try self.root.writeDeviceNode(
                target_path,
                metadata.mode,
                entry.rdevmajor,
                entry.rdevminor,
                metadata,
            );
            return;
        }
        if (mode_type == S_IFIFO_U32) {
            try self.root.writeFifo(
                target_path,
                metadata.mode,
                metadata,
            );
            return;
        }
        if (mode_type == S_IFDIR_U32) {
            try self.root.ensureDirectory(target_path);
            return;
        }
        return error.UnsupportedFileType;
    }

    fn ensureNoMissingHardlinks(
        self: *Context,
        hardlinks: *const std.AutoHashMap(HardlinkKey, HardlinkState),
    ) InstallError!void {
        var iterator = hardlinks.iterator();
        while (iterator.next()) |entry| {
            const state = entry.value_ptr.*;
            if (state.canonical_path == null and state.pending_paths.items.len > 0) {
                if (state.pending_paths.items.len > 0) {
                    self.setLastPath(state.pending_paths.items[0]);
                }
                return error.HardlinkMissingPayload;
            }
        }
    }

    fn ensureNoMissingEntries(self: *Context, manifest: *const Manifest) InstallError!void {
        if ((self.options.trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_JUSTDB) != 0) {
            return;
        }

        for (manifest.files, manifest.processed) |file, processed| {
            if (processed) {
                continue;
            }
            if (isGhost(file.flags) or shouldSkipFile(file.flags, self.options.trans_flags)) {
                continue;
            }
            if (isDirMode(file.mode)) {
                continue;
            }
            self.setLastPath(file.path);
            return error.MissingPayloadEntry;
        }
    }

    fn applyDeferredDirs(self: *Context, deferred_dirs: []const DeferredDir) Error!void {
        for (deferred_dirs) |dir| {
            try self.root.ensureDirectory(dir.target_path);
            try self.root.applyMetadata(
                dir.target_path,
                .{
                    .mode = dir.mode,
                    .mtime = dir.mtime,
                    .uid = dir.uid,
                    .gid = dir.gid,
                },
            );
        }
    }
};

const ConfigAction = enum {
    install,
    skip,
    rpmnew,
    rpmsave,
};

pub const Metadata = struct {
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
};

/// Resolve header ownership names under the install root, falling back to the
/// cpio numeric metadata exactly as the native binary installer does.
pub fn resolveFileMetadata(
    allocator: Allocator,
    install_root: []const u8,
    mode: u32,
    mtime: ?u32,
    username: ?[]const u8,
    groupname: ?[]const u8,
    fallback_mode: u32,
    fallback_mtime: u32,
    fallback_uid: u32,
    fallback_gid: u32,
) Error!Metadata {
    const uid = if (username) |name|
        (try lookupUserId(allocator, install_root, name)) orelse fallback_uid
    else
        fallback_uid;
    const gid = if (groupname) |name|
        (try lookupGroupId(allocator, install_root, name)) orelse fallback_gid
    else
        fallback_gid;

    return .{
        .mode = if (mode != 0) mode else fallback_mode,
        .mtime = mtime orelse fallback_mtime,
        .uid = uid,
        .gid = gid,
    };
}

const DeferredDir = struct {
    target_path: []u8,
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
};

pub const HeaderFile = struct {
    path: []u8,
    mode: u32,
    flags: u32,
    mtime: ?u32,
    username: ?[]const u8,
    groupname: ?[]const u8,
    digest: ?[]const u8,
    digest_algo: u32,
    caps: ?[]const u8,
};

fn nextOptionalString(
    iter: *?header.StringArrayIterator,
) ?[]const u8 {
    if (iter.*) |*value| {
        return value.next() catch null;
    }
    return null;
}

pub const Manifest = struct {
    allocator: Allocator,
    files: []HeaderFile,
    processed: []bool,
    index: std.StringHashMap(usize),

    pub fn init(allocator: Allocator, hdr: header.Header) Error!Manifest {
        const count = hdr.stringArrayCount(.basenames);
        if (hdr.u32ArrayCountChecked(.filemtimes) catch
            return error.BadHeader) |mtime_count|
        {
            if (mtime_count != count) return error.BadHeader;
        }
        const files = try allocator.alloc(HeaderFile, count);
        errdefer allocator.free(files);
        const processed = try allocator.alloc(bool, count);
        errdefer allocator.free(processed);
        @memset(processed, false);

        var index = std.StringHashMap(usize).init(allocator);
        errdefer index.deinit();

        const digest_algo = hdr.getU32(.filedigestalgo) orelse 0;
        const dirname_count = hdr.stringArrayCount(.dirnames);
        if (count != 0 and dirname_count == 0) return error.BadHeader;

        const dirnames = try allocator.alloc([]const u8, dirname_count);
        defer allocator.free(dirnames);
        var dirname_iter = hdr.stringArrayIterator(.dirnames);
        if (dirname_count != 0 and dirname_iter == null) {
            return error.BadHeader;
        }
        if (dirname_iter) |*iter| {
            for (dirnames) |*dirname| {
                dirname.* = (iter.next() catch return error.BadHeader) orelse
                    return error.BadHeader;
            }
        }

        var basename_iter = hdr.stringArrayIterator(.basenames);
        if (count != 0 and basename_iter == null) {
            return error.BadHeader;
        }
        var username_iter = hdr.stringArrayIterator(.fileusername);
        var groupname_iter = hdr.stringArrayIterator(.filegroupname);
        var digest_iter = hdr.stringArrayIterator(.filedigests);
        var caps_iter = hdr.stringArrayIterator(.filecaps);

        for (0..count) |i| {
            const basename = if (basename_iter) |*iter|
                (iter.next() catch return error.BadHeader) orelse
                    return error.BadHeader
            else
                return error.BadHeader;
            const dir_index = hdr.u32ArrayItem(.dirindexes, i) orelse return error.BadHeader;
            if (dir_index >= dirnames.len) return error.BadHeader;
            const dirname = dirnames[dir_index];
            const joined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ dirname, basename });
            defer allocator.free(joined);
            const normalized = try normalizeAbsolutePathOwned(allocator, joined);

            files[i] = .{
                .path = normalized,
                .mode = hdr.u16ArrayItem(.filemodes, i) orelse 0,
                .flags = hdr.u32ArrayItem(.fileflags, i) orelse 0,
                .mtime = hdr.u32ArrayItem(.filemtimes, i),
                .username = nextOptionalString(&username_iter),
                .groupname = nextOptionalString(&groupname_iter),
                .digest = nextOptionalString(&digest_iter),
                .digest_algo = digest_algo,
                .caps = nextOptionalString(&caps_iter),
            };

            const put_result = try index.getOrPut(files[i].path);
            if (put_result.found_existing) {
                return error.BadHeader;
            }
            put_result.value_ptr.* = i;
        }

        return .{
            .allocator = allocator,
            .files = files,
            .processed = processed,
            .index = index,
        };
    }

    pub fn deinit(self: *Manifest) void {
        for (self.files) |file| {
            self.allocator.free(file.path);
        }
        self.allocator.free(self.files);
        self.allocator.free(self.processed);
        self.index.deinit();
    }
};

const HardlinkKey = struct {
    ino: u32,
    devmajor: u32,
    devminor: u32,
};

const HardlinkState = struct {
    canonical_path: ?[]u8 = null,
    pending_paths: std.ArrayList([]u8) = .empty,

    fn deinit(self: *HardlinkState, allocator: Allocator) void {
        if (self.canonical_path) |path| {
            allocator.free(path);
        }
        for (self.pending_paths.items) |path| {
            allocator.free(path);
        }
        self.pending_paths.deinit(allocator);
    }
};

fn chooseConfigAction(matches_old: bool, matches_new: bool, noreplace: bool) ConfigAction {
    if (matches_new) {
        return .skip;
    }
    if (matches_old) {
        return .install;
    }
    return if (noreplace) .rpmnew else .rpmsave;
}

fn findPriorFile(prior_manifests: []const Manifest, path: []const u8) ?HeaderFile {
    for (prior_manifests) |prior| {
        if (prior.index.get(path)) |index| {
            return prior.files[index];
        }
    }
    return null;
}

fn hasCapabilities(file: HeaderFile) bool {
    const caps = file.caps orelse return false;
    return caps.len > 0;
}

pub fn shouldSkipFile(flags: u32, trans_flags: u32) bool {
    if ((trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NOCONFIGS) != 0 and isConfig(flags)) {
        return true;
    }
    if ((trans_flags & rpmtrans.TDNF_RPMTRANS_FLAG_NODOCS) != 0 and isExcludedDoc(flags)) {
        return true;
    }
    return false;
}

pub fn isConfig(flags: u32) bool {
    return (flags & RPMFILE_CONFIG) != 0;
}

pub fn isNoReplace(flags: u32) bool {
    return (flags & RPMFILE_NOREPLACE) != 0;
}

pub fn isGhost(flags: u32) bool {
    return (flags & RPMFILE_GHOST) != 0;
}

pub fn isExcludedDoc(flags: u32) bool {
    return (flags & (RPMFILE_DOC | RPMFILE_README)) != 0;
}

pub fn isRegularMode(mode: u32) bool {
    return (mode & S_IFMT_U32) == S_IFREG_U32;
}

pub fn isDirMode(mode: u32) bool {
    return (mode & S_IFMT_U32) == S_IFDIR_U32;
}

pub fn normalizeAbsolutePathOwned(allocator: Allocator, raw: []const u8) Error![]u8 {
    if (raw.len == 0 or raw[0] != '/') {
        return error.InvalidPackagePath;
    }

    const trimmed = trimTrailingSlashKeepRoot(raw);
    if (!isValidPackagePath(trimmed)) {
        return error.InvalidPackagePath;
    }
    return allocator.dupe(u8, trimmed);
}

fn normalizeCpioPathOwned(allocator: Allocator, raw: []const u8) Error![]u8 {
    var path = raw;
    if (std.mem.startsWith(u8, path, "./")) {
        path = path[2..];
    }
    while (path.len > 0 and path[0] == '/') {
        path = path[1..];
    }
    const absolute = if (path.len == 0)
        try allocator.dupe(u8, "/")
    else
        try std.fmt.allocPrint(allocator, "/{s}", .{path});
    defer allocator.free(absolute);
    return normalizeAbsolutePathOwned(allocator, absolute);
}

fn trimTrailingSlashKeepRoot(path: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, path, "/");
    if (trimmed.len == 0) {
        return "/";
    }
    return trimmed;
}

fn isValidPackagePath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') {
        return false;
    }
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) {
            continue;
        }
        if (std.mem.eql(u8, part, "..")) {
            return false;
        }
    }
    return true;
}

pub fn joinInstallRootAndPathOwned(
    allocator: Allocator,
    install_root: []const u8,
    path: []const u8,
) Allocator.Error![]u8 {
    if (std.mem.eql(u8, install_root, "/")) {
        return allocator.dupe(u8, path);
    }
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ install_root, path });
}

/// Write one regular file beneath `base_path` without following symlinks in
/// either the directory chain or the destination. Existing multiply-linked
/// files are rejected before truncation so extraction cannot modify a file
/// outside the requested tree through a hardlink.
pub fn writeRegularFileBeneath(
    allocator: Allocator,
    install_root: []const u8,
    base_path: []const u8,
    relative_path: []const u8,
    data: []const u8,
    metadata: Metadata,
) Error!void {
    if (!isSafeRelativePath(relative_path)) return error.UnsafeExtractionPath;
    var root = try RootDir.init(
        allocator,
        install_root,
        null,
        null,
    );
    defer root.deinit();
    const logical_base = try root.logicalPathFromFullOwned(
        install_root,
        base_path,
    );
    defer allocator.free(logical_base);
    const target_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ std.mem.trimEnd(u8, logical_base, "/"), relative_path },
    );
    defer allocator.free(target_path);
    try root.validateRegularTarget(target_path);
    try root.writeRegularFile(target_path, data, metadata);
}

/// Validate an extraction destination without creating or changing anything.
/// A missing directory chain or destination is safe; existing components must
/// be real directories and an existing destination must be a singly-linked
/// regular file.
pub fn validateRegularFileDestinationBeneath(
    allocator: Allocator,
    install_root: []const u8,
    base_path: []const u8,
    relative_path: []const u8,
) Error!void {
    if (!isSafeRelativePath(relative_path)) return error.UnsafeExtractionPath;
    var root = try RootDir.init(
        allocator,
        install_root,
        null,
        null,
    );
    defer root.deinit();
    const logical_base = try root.logicalPathFromFullOwned(
        install_root,
        base_path,
    );
    defer allocator.free(logical_base);
    const target_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ std.mem.trimEnd(u8, logical_base, "/"), relative_path },
    );
    defer allocator.free(target_path);
    try root.validateRegularTarget(target_path);
}

pub fn isSafeRelativePath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') {
        return false;
    }
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or
            std.mem.eql(u8, part, ".") or
            std.mem.eql(u8, part, ".."))
        {
            return false;
        }
    }
    return true;
}

const ParentDir = struct {
    fd: c_int,
    basename: []const u8,

    fn deinit(self: *ParentDir) void {
        _ = c.close(self.fd);
        self.fd = -1;
    }
};

pub const RootDir = struct {
    allocator: Allocator,
    fd: c_int,
    trusted_uid: c.uid_t,
    mutation_fn: ?MutationFn,
    mutation_ctx: ?*anyopaque,

    pub fn init(
        allocator: Allocator,
        install_root: []const u8,
        mutation_fn: ?MutationFn,
        mutation_ctx: ?*anyopaque,
    ) Error!RootDir {
        return (try initExisting(
            allocator,
            install_root,
            mutation_fn,
            mutation_ctx,
        )) orelse error.SyscallFailed;
    }

    pub fn initExisting(
        allocator: Allocator,
        install_root: []const u8,
        mutation_fn: ?MutationFn,
        mutation_ctx: ?*anyopaque,
    ) Error!?RootDir {
        const normalized = try normalizeAbsolutePathOwned(
            allocator,
            install_root,
        );
        defer allocator.free(normalized);
        const filesystem_root = std.c.open("/", .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
        });
        if (filesystem_root < 0) return error.SyscallFailed;
        defer _ = c.close(filesystem_root);
        const root_fd = (try openExistingDirectoryTree(
            filesystem_root,
            normalized[1..],
        )) orelse return null;
        return @as(
            ?RootDir,
            try initFromOwnedFd(
                allocator,
                root_fd,
                mutation_fn,
                mutation_ctx,
            ),
        );
    }

    pub fn initCreating(
        allocator: Allocator,
        install_root: []const u8,
    ) Error!RootDir {
        if (install_root.len == 0 or install_root[0] != '/') {
            const cwd_fd = std.c.open(".", .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            });
            if (cwd_fd < 0) return error.SyscallFailed;
            var cwd_root = try initFromOwnedFd(
                allocator,
                cwd_fd,
                null,
                null,
            );
            defer cwd_root.deinit();
            const logical = try std.fmt.allocPrint(
                allocator,
                "/{s}",
                .{std.mem.trim(u8, install_root, "/")},
            );
            defer allocator.free(logical);
            const root_fd = (try cwd_root.openDirectory(
                logical,
                true,
            )) orelse return error.SyscallFailed;
            return initFromOwnedFd(allocator, root_fd, null, null);
        }
        const normalized = try normalizeAbsolutePathOwned(
            allocator,
            install_root,
        );
        defer allocator.free(normalized);
        const filesystem_root = std.c.open("/", .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
        });
        if (filesystem_root < 0) return error.SyscallFailed;
        defer _ = c.close(filesystem_root);
        const root_fd = try openOrCreateDirectoryTree(
            filesystem_root,
            normalized[1..],
        );
        return initFromOwnedFd(allocator, root_fd, null, null);
    }

    pub fn initFromOwnedFd(
        allocator: Allocator,
        root_fd: c_int,
        mutation_fn: ?MutationFn,
        mutation_ctx: ?*anyopaque,
    ) Error!RootDir {
        errdefer _ = c.close(root_fd);
        var st: c.struct_stat = undefined;
        if (c.fstat(root_fd, &st) != 0 or
            (st.st_mode & c.S_IFMT) != c.S_IFDIR)
        {
            return error.UnsafeExtractionPath;
        }
        return .{
            .allocator = allocator,
            .fd = root_fd,
            .trusted_uid = st.st_uid,
            .mutation_fn = mutation_fn,
            .mutation_ctx = mutation_ctx,
        };
    }

    pub fn deinit(self: *RootDir) void {
        if (self.fd >= 0) {
            _ = c.close(self.fd);
            self.fd = -1;
        }
    }

    pub fn releaseFd(self: *RootDir) c_int {
        const fd = self.fd;
        self.fd = -1;
        return fd;
    }

    fn mutationHook(self: *const RootDir) void {
        if (self.mutation_fn) |callback| {
            callback(self.mutation_ctx);
        }
    }

    fn logicalPath(self: *const RootDir, path: []const u8) Error![]const u8 {
        _ = self;
        if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') {
            return error.InvalidPackagePath;
        }
        var components = std.mem.splitScalar(u8, path[1..], '/');
        while (components.next()) |component| {
            if (component.len == 0 or
                std.mem.eql(u8, component, ".") or
                std.mem.eql(u8, component, ".."))
            {
                return error.InvalidPackagePath;
            }
        }
        return path[1..];
    }

    pub fn logicalPathFromFullOwned(
        self: *const RootDir,
        install_root_raw: []const u8,
        full_path_raw: []const u8,
    ) Error![]u8 {
        const install_root = try normalizeAbsolutePathOwned(
            self.allocator,
            install_root_raw,
        );
        defer self.allocator.free(install_root);
        const full_path = try normalizeAbsolutePathOwned(
            self.allocator,
            full_path_raw,
        );
        defer self.allocator.free(full_path);
        const relative = try pathRelativeToInstallRoot(
            install_root,
            full_path,
        );
        if (relative.len == 0) return error.InvalidPackagePath;
        const logical = try std.fmt.allocPrint(
            self.allocator,
            "/{s}",
            .{relative},
        );
        errdefer self.allocator.free(logical);
        _ = try self.logicalPath(logical);
        return logical;
    }

    pub fn canonicalPathOwned(
        self: *const RootDir,
        path: []const u8,
    ) Error![]u8 {
        const relative = try self.logicalPath(path);
        const slash = std.mem.indexOfScalar(u8, relative, '/');
        const first = if (slash) |index| relative[0..index] else relative;
        if (!isCanonicalDirectoryAlias(first)) {
            return self.allocator.dupe(u8, path);
        }
        var name_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
        if (first.len >= name_buf.len) return error.UnsafeExtractionPath;
        @memcpy(name_buf[0..first.len], first);
        name_buf[first.len] = 0;
        const name_z: [*:0]const u8 = @ptrCast(&name_buf);
        var alias_st: c.struct_stat = undefined;
        const stat_rc = c.fstatat(
            self.fd,
            name_z,
            &alias_st,
            AT_SYMLINK_NOFOLLOW,
        );
        if (stat_rc != 0 or
            (alias_st.st_mode & c.S_IFMT) != c.S_IFLNK)
        {
            return self.allocator.dupe(u8, path);
        }
        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
        const target_len = std.c.readlinkat(
            self.fd,
            name_z,
            &target_buf,
            target_buf.len,
        );
        if (target_len < 0) return error.SyscallFailed;
        const expected = canonicalDirectoryTarget(
            first,
            target_buf[0..@intCast(target_len)],
        ) orelse return error.UnsafeExtractionPath;
        const alias_fd = try self.openTrustedAlias(self.fd, name_z, first);
        _ = c.close(alias_fd);
        const remainder = if (slash) |index| relative[index..] else "";
        return std.fmt.allocPrint(
            self.allocator,
            "/{s}{s}",
            .{ expected, remainder },
        );
    }

    fn openTrustedAlias(
        self: *const RootDir,
        parent_fd: c_int,
        name_z: [*:0]const u8,
        name: []const u8,
    ) Error!c_int {
        var link_st: c.struct_stat = undefined;
        if (c.fstatat(
            parent_fd,
            name_z,
            &link_st,
            AT_SYMLINK_NOFOLLOW,
        ) != 0 or
            (link_st.st_mode & c.S_IFMT) != c.S_IFLNK or
            link_st.st_uid != self.trusted_uid)
        {
            return error.UnsafeExtractionPath;
        }
        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
        const target_len = std.c.readlinkat(
            parent_fd,
            name_z,
            &target_buf,
            target_buf.len,
        );
        if (target_len < 0) return error.SyscallFailed;
        const target = target_buf[0..@intCast(target_len)];
        const expected = canonicalDirectoryTarget(name, target) orelse
            return error.UnsafeExtractionPath;

        var current_fd = c.dup(self.fd);
        if (current_fd < 0) return error.SyscallFailed;
        errdefer _ = c.close(current_fd);
        var components = std.mem.splitScalar(u8, expected, '/');
        while (components.next()) |component| {
            var component_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
            if (component.len == 0 or component.len >= component_buf.len) {
                return error.UnsafeExtractionPath;
            }
            @memcpy(component_buf[0..component.len], component);
            component_buf[component.len] = 0;
            const component_z: [*:0]const u8 = @ptrCast(&component_buf);
            const next_fd = std.c.openat(current_fd, component_z, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            });
            if (next_fd < 0) return error.UnsafeExtractionPath;
            var st: c.struct_stat = undefined;
            if (c.fstat(next_fd, &st) != 0 or
                (st.st_mode & c.S_IFMT) != c.S_IFDIR or
                st.st_uid != self.trusted_uid)
            {
                _ = c.close(next_fd);
                return error.UnsafeExtractionPath;
            }
            _ = c.close(current_fd);
            current_fd = next_fd;
        }
        return current_fd;
    }

    fn openDirectoryTree(
        self: *const RootDir,
        relative_path: []const u8,
        create: bool,
    ) Error!?c_int {
        var current_fd = c.dup(self.fd);
        if (current_fd < 0) return error.SyscallFailed;
        errdefer _ = c.close(current_fd);
        if (relative_path.len == 0) return current_fd;

        var component_index: usize = 0;
        var components = std.mem.splitScalar(u8, relative_path, '/');
        while (components.next()) |component| : (component_index += 1) {
            if (component.len == 0 or
                std.mem.eql(u8, component, ".") or
                std.mem.eql(u8, component, ".."))
            {
                return error.UnsafeExtractionPath;
            }
            var name_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
            if (component.len >= name_buf.len) {
                return error.UnsafeExtractionPath;
            }
            @memcpy(name_buf[0..component.len], component);
            name_buf[component.len] = 0;
            const name_z: [*:0]const u8 = @ptrCast(&name_buf);

            var next_fd = std.c.openat(current_fd, name_z, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            });
            if (next_fd < 0 and
                (std.c.errno(next_fd) == .LOOP or
                    std.c.errno(next_fd) == .NOTDIR) and
                component_index == 0)
            {
                next_fd = try self.openTrustedAlias(
                    current_fd,
                    name_z,
                    component,
                );
            } else if (next_fd < 0 and std.c.errno(next_fd) == .NOENT) {
                if (!create) {
                    _ = c.close(current_fd);
                    return null;
                }
                const mkdir_rc = c.mkdirat(current_fd, name_z, 0o755);
                if (mkdir_rc != 0 and std.c.errno(mkdir_rc) != .EXIST) {
                    return error.SyscallFailed;
                }
                next_fd = std.c.openat(current_fd, name_z, .{
                    .ACCMODE = .RDONLY,
                    .DIRECTORY = true,
                    .CLOEXEC = true,
                    .NOFOLLOW = true,
                });
            }
            if (next_fd < 0) {
                return switch (std.c.errno(next_fd)) {
                    .LOOP, .NOTDIR => error.UnsafeExtractionPath,
                    else => error.SyscallFailed,
                };
            }
            _ = c.close(current_fd);
            current_fd = next_fd;
        }
        return current_fd;
    }

    fn openParent(
        self: *const RootDir,
        path: []const u8,
        create: bool,
    ) Error!?ParentDir {
        const relative = try self.logicalPath(path);
        const slash = std.mem.lastIndexOfScalar(u8, relative, '/');
        const parent_path = if (slash) |index| relative[0..index] else "";
        const basename = if (slash) |index|
            relative[index + 1 ..]
        else
            relative;
        const parent_fd = (try self.openDirectoryTree(
            parent_path,
            create,
        )) orelse return null;
        return .{
            .fd = parent_fd,
            .basename = basename,
        };
    }

    fn basenameZ(
        self: *const RootDir,
        basename: []const u8,
    ) Error![:0]u8 {
        if (basename.len == 0 or basename.len > std.fs.max_name_bytes) {
            return error.UnsafeExtractionPath;
        }
        return self.allocator.dupeZ(u8, basename);
    }

    fn statAt(
        self: *const RootDir,
        parent: *const ParentDir,
        basename_z: [*:0]const u8,
    ) Error!?c.struct_stat {
        _ = self;
        var st: c.struct_stat = undefined;
        const rc = c.fstatat(
            parent.fd,
            basename_z,
            &st,
            AT_SYMLINK_NOFOLLOW,
        );
        if (rc == 0) return st;
        if (std.c.errno(rc) == .NOENT) return null;
        return error.SyscallFailed;
    }

    fn unlinkAt(
        self: *const RootDir,
        parent: *const ParentDir,
        basename_z: [*:0]const u8,
    ) Error!void {
        const st = (try self.statAt(parent, basename_z)) orelse return;
        const flags: c_int = if ((st.st_mode & c.S_IFMT) == c.S_IFDIR)
            AT_REMOVEDIR
        else
            0;
        if (c.unlinkat(parent.fd, basename_z, flags) != 0) {
            return error.SyscallFailed;
        }
    }

    fn applyFdMetadata(
        fd: c_int,
        metadata: Metadata,
    ) Error!void {
        if (c.fchown(fd, metadata.uid, metadata.gid) != 0 or
            c.fchmod(fd, metadata.mode & MODE_PERMS_MASK) != 0)
        {
            return error.SyscallFailed;
        }
        var times = [2]c.struct_timespec{
            .{ .tv_sec = @intCast(metadata.mtime), .tv_nsec = 0 },
            .{ .tv_sec = @intCast(metadata.mtime), .tv_nsec = 0 },
        };
        if (c.futimens(fd, &times) != 0) return error.SyscallFailed;
    }

    fn applyStableMetadata(
        fd: c_int,
        metadata: Metadata,
        symlink: bool,
    ) Error!void {
        if (std.posix.errno(linux.fchownat(
            fd,
            "",
            metadata.uid,
            metadata.gid,
            AT_EMPTY_PATH,
        )) != .SUCCESS) {
            return error.SyscallFailed;
        }
        if (!symlink and std.posix.errno(linux.fchmodat2(
            fd,
            "",
            metadata.mode & MODE_PERMS_MASK,
            AT_EMPTY_PATH,
        )) != .SUCCESS) {
            return error.SyscallFailed;
        }
        var times = [2]linux.timespec{
            .{ .sec = @intCast(metadata.mtime), .nsec = 0 },
            .{ .sec = @intCast(metadata.mtime), .nsec = 0 },
        };
        if (std.posix.errno(linux.utimensat(
            fd,
            "",
            &times,
            AT_EMPTY_PATH,
        )) != .SUCCESS) {
            return error.SyscallFailed;
        }
    }

    fn openStableObject(
        parent: *const ParentDir,
        basename_z: [*:0]const u8,
        expected_type: c.mode_t,
    ) Error!c_int {
        const fd = std.c.openat(parent.fd, basename_z, .{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .NOFOLLOW = true,
            .PATH = true,
        });
        if (fd < 0) return error.UnsafeExtractionPath;
        errdefer _ = c.close(fd);
        var st: c.struct_stat = undefined;
        if (c.fstat(fd, &st) != 0 or
            (st.st_mode & c.S_IFMT) != expected_type)
        {
            return error.UnsafeExtractionPath;
        }
        return fd;
    }

    pub fn ensureDirectory(
        self: *const RootDir,
        path: []const u8,
    ) Error!void {
        const relative = try self.logicalPath(path);
        const fd = (try self.openDirectoryTree(
            relative,
            true,
        )) orelse return error.SyscallFailed;
        _ = c.close(fd);
    }

    pub fn openDirectory(
        self: *const RootDir,
        path: []const u8,
        create: bool,
    ) Error!?c_int {
        if (std.mem.eql(u8, path, "/")) {
            const fd = c.dup(self.fd);
            if (fd < 0) return error.SyscallFailed;
            return fd;
        }
        const relative = try self.logicalPath(path);
        return self.openDirectoryTree(relative, create);
    }

    pub fn pathExists(
        self: *const RootDir,
        path: []const u8,
    ) Error!bool {
        var parent = (try self.openParent(path, false)) orelse return false;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        return (try self.statAt(&parent, basename_z.ptr)) != null;
    }

    pub fn writeRegularFile(
        self: *const RootDir,
        path: []const u8,
        data: []const u8,
        metadata: Metadata,
    ) Error!void {
        var parent = (try self.openParent(path, true)) orelse
            return error.SyscallFailed;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        self.mutationHook();
        try self.unlinkAt(&parent, basename_z.ptr);
        const fd = std.c.openat(parent.fd, basename_z.ptr, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        }, @as(std.c.mode_t, 0o600));
        if (fd < 0) {
            return if (std.c.errno(fd) == .LOOP or
                std.c.errno(fd) == .EXIST)
                error.UnsafeExtractionPath
            else
                error.SyscallFailed;
        }
        defer _ = c.close(fd);
        var st: c.struct_stat = undefined;
        if (c.fstat(fd, &st) != 0 or
            (st.st_mode & c.S_IFMT) != c.S_IFREG or
            st.st_nlink != 1)
        {
            return error.UnsafeExtractionPath;
        }
        try writeAll(fd, data);
        try applyFdMetadata(fd, metadata);
    }

    pub fn createExclusiveRegular(
        self: *const RootDir,
        path: []const u8,
        mode: u32,
    ) Error!?c_int {
        var parent = (try self.openParent(path, true)) orelse
            return error.SyscallFailed;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        self.mutationHook();
        const fd = std.c.openat(parent.fd, basename_z.ptr, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        }, @as(std.c.mode_t, @intCast(mode & MODE_PERMS_MASK)));
        if (fd >= 0) return fd;
        return switch (std.c.errno(fd)) {
            .EXIST => null,
            .LOOP => error.UnsafeExtractionPath,
            else => error.SyscallFailed,
        };
    }

    pub fn writeSymlink(
        self: *const RootDir,
        path: []const u8,
        target: []const u8,
        metadata: Metadata,
    ) Error!void {
        var parent = (try self.openParent(path, true)) orelse
            return error.SyscallFailed;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        const target_z = try self.allocator.dupeZ(u8, target);
        defer self.allocator.free(target_z);
        self.mutationHook();
        try self.unlinkAt(&parent, basename_z.ptr);
        if (c.symlinkat(target_z.ptr, parent.fd, basename_z.ptr) != 0) {
            return error.SyscallFailed;
        }
        const fd = try openStableObject(
            &parent,
            basename_z.ptr,
            c.S_IFLNK,
        );
        defer _ = c.close(fd);
        self.mutationHook();
        try applyStableMetadata(fd, metadata, true);
    }

    pub fn writeDeviceNode(
        self: *const RootDir,
        path: []const u8,
        mode: u32,
        major_id: u32,
        minor_id: u32,
        metadata: Metadata,
    ) Error!void {
        var parent = (try self.openParent(path, true)) orelse
            return error.SyscallFailed;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        self.mutationHook();
        try self.unlinkAt(&parent, basename_z.ptr);
        const dev = c.makedev(
            @as(c_uint, @intCast(major_id)),
            @as(c_uint, @intCast(minor_id)),
        );
        if (c.mknodat(parent.fd, basename_z.ptr, mode, dev) != 0) {
            return error.SyscallFailed;
        }
        const fd = try openStableObject(
            &parent,
            basename_z.ptr,
            @intCast(mode & @as(u32, @intCast(c.S_IFMT))),
        );
        defer _ = c.close(fd);
        self.mutationHook();
        try applyStableMetadata(fd, metadata, false);
    }

    pub fn writeFifo(
        self: *const RootDir,
        path: []const u8,
        mode: u32,
        metadata: Metadata,
    ) Error!void {
        var parent = (try self.openParent(path, true)) orelse
            return error.SyscallFailed;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        self.mutationHook();
        try self.unlinkAt(&parent, basename_z.ptr);
        if (c.mknodat(
            parent.fd,
            basename_z.ptr,
            @as(c.mode_t, @intCast(
                @as(u32, @intCast(c.S_IFIFO)) |
                    (mode & MODE_PERMS_MASK),
            )),
            0,
        ) != 0) {
            return error.SyscallFailed;
        }
        const fd = try openStableObject(
            &parent,
            basename_z.ptr,
            c.S_IFIFO,
        );
        defer _ = c.close(fd);
        self.mutationHook();
        try applyStableMetadata(fd, metadata, false);
    }

    pub fn applyMetadata(
        self: *const RootDir,
        path: []const u8,
        metadata: Metadata,
    ) Error!void {
        var parent = (try self.openParent(path, false)) orelse
            return error.SyscallFailed;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        const st = (try self.statAt(&parent, basename_z.ptr)) orelse
            return error.SyscallFailed;
        if ((st.st_mode & c.S_IFMT) == c.S_IFREG or
            (st.st_mode & c.S_IFMT) == c.S_IFDIR)
        {
            const fd = std.c.openat(parent.fd, basename_z.ptr, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = (st.st_mode & c.S_IFMT) == c.S_IFDIR,
                .CLOEXEC = true,
                .NOFOLLOW = true,
                .NONBLOCK = true,
            });
            if (fd < 0) return error.UnsafeExtractionPath;
            defer _ = c.close(fd);
            self.mutationHook();
            return applyFdMetadata(fd, metadata);
        }
        const fd = try openStableObject(
            &parent,
            basename_z.ptr,
            @intCast(st.st_mode & c.S_IFMT),
        );
        defer _ = c.close(fd);
        self.mutationHook();
        return applyStableMetadata(
            fd,
            metadata,
            (st.st_mode & c.S_IFMT) == c.S_IFLNK,
        );
    }

    pub fn remove(
        self: *const RootDir,
        path: []const u8,
    ) Error!void {
        var parent = (try self.openParent(path, false)) orelse return;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        self.mutationHook();
        try self.unlinkAt(&parent, basename_z.ptr);
    }

    pub fn removeEmptyDirectory(
        self: *const RootDir,
        path: []const u8,
    ) Error!void {
        var parent = (try self.openParent(path, false)) orelse return;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        self.mutationHook();
        const rc = c.unlinkat(parent.fd, basename_z.ptr, AT_REMOVEDIR);
        if (rc == 0) return;
        return switch (std.c.errno(rc)) {
            .NOENT, .NOTDIR, .NOTEMPTY => {},
            else => error.SyscallFailed,
        };
    }

    pub fn rename(
        self: *const RootDir,
        src: []const u8,
        dst: []const u8,
    ) Error!void {
        var src_parent = (try self.openParent(src, false)) orelse
            return error.SyscallFailed;
        defer src_parent.deinit();
        var dst_parent = (try self.openParent(dst, true)) orelse
            return error.SyscallFailed;
        defer dst_parent.deinit();
        const src_z = try self.basenameZ(src_parent.basename);
        defer self.allocator.free(src_z);
        const dst_z = try self.basenameZ(dst_parent.basename);
        defer self.allocator.free(dst_z);
        self.mutationHook();
        try self.unlinkAt(&dst_parent, dst_z.ptr);
        if (c.renameat(
            src_parent.fd,
            src_z.ptr,
            dst_parent.fd,
            dst_z.ptr,
        ) != 0) {
            return error.SyscallFailed;
        }
    }

    pub fn hardLink(
        self: *const RootDir,
        existing_path: []const u8,
        new_path: []const u8,
    ) Error!void {
        var src_parent = (try self.openParent(
            existing_path,
            false,
        )) orelse return error.SyscallFailed;
        defer src_parent.deinit();
        var dst_parent = (try self.openParent(
            new_path,
            true,
        )) orelse return error.SyscallFailed;
        defer dst_parent.deinit();
        const src_z = try self.basenameZ(src_parent.basename);
        defer self.allocator.free(src_z);
        const dst_z = try self.basenameZ(dst_parent.basename);
        defer self.allocator.free(dst_z);
        const source_fd = std.c.openat(src_parent.fd, src_z.ptr, .{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .NOFOLLOW = true,
            .PATH = true,
        });
        if (source_fd < 0) return error.UnsafeExtractionPath;
        defer _ = c.close(source_fd);
        var st: c.struct_stat = undefined;
        if (c.fstat(source_fd, &st) != 0 or
            (st.st_mode & c.S_IFMT) != c.S_IFREG)
        {
            return error.UnsafeExtractionPath;
        }
        self.mutationHook();
        try self.unlinkAt(&dst_parent, dst_z.ptr);
        if (c.linkat(
            src_parent.fd,
            src_z.ptr,
            dst_parent.fd,
            dst_z.ptr,
            0,
        ) != 0) {
            return error.SyscallFailed;
        }
        const linked = (try self.statAt(
            &dst_parent,
            dst_z.ptr,
        )) orelse return error.SyscallFailed;
        if (linked.st_dev != st.st_dev or linked.st_ino != st.st_ino) {
            _ = c.unlinkat(dst_parent.fd, dst_z.ptr, 0);
            return error.UnsafeExtractionPath;
        }
    }

    pub fn stat(
        self: *const RootDir,
        path: []const u8,
    ) Error!?c.struct_stat {
        var parent = (try self.openParent(path, false)) orelse return null;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        return self.statAt(&parent, basename_z.ptr);
    }

    pub fn fileDigestMatches(
        self: *const RootDir,
        path: []const u8,
        digest_algo_raw: u32,
        expected_hex: []const u8,
    ) Error!bool {
        const algo = try normalizeDigestAlgo(
            digest_algo_raw,
            expected_hex,
        );
        var parent = (try self.openParent(path, false)) orelse return false;
        defer parent.deinit();
        const basename_z = try self.basenameZ(parent.basename);
        defer self.allocator.free(basename_z);
        const fd = std.c.openat(parent.fd, basename_z.ptr, .{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        });
        if (fd < 0) return error.SyscallFailed;
        const stream_fd = c.dup(fd);
        _ = c.close(fd);
        if (stream_fd < 0) return error.SyscallFailed;
        const fp = c.fdopen(stream_fd, "rb") orelse {
            _ = c.close(stream_fd);
            return error.SyscallFailed;
        };
        defer _ = c.fclose(fp);
        var chunk: [8192]u8 = undefined;
        return switch (algo) {
            .md5 => digestStream(std.crypto.hash.Md5, fp, &chunk, expected_hex),
            .sha1 => digestStream(std.crypto.hash.Sha1, fp, &chunk, expected_hex),
            .sha224 => digestStream(std.crypto.hash.sha2.Sha224, fp, &chunk, expected_hex),
            .sha256 => digestStream(std.crypto.hash.sha2.Sha256, fp, &chunk, expected_hex),
            .sha384 => digestStream(std.crypto.hash.sha2.Sha384, fp, &chunk, expected_hex),
            .sha512 => digestStream(std.crypto.hash.sha2.Sha512, fp, &chunk, expected_hex),
        };
    }

    pub fn validateRegularTarget(
        self: *const RootDir,
        path: []const u8,
    ) Error!void {
        const st = (try self.stat(path)) orelse return;
        if ((st.st_mode & c.S_IFMT) != c.S_IFREG or st.st_nlink != 1) {
            return error.UnsafeExtractionPath;
        }
    }
};

fn openExistingDirectoryTree(
    start_fd: c_int,
    relative_path: []const u8,
) Error!?c_int {
    var current_fd = c.dup(start_fd);
    if (current_fd < 0) return error.SyscallFailed;
    errdefer _ = c.close(current_fd);

    var parts = std.mem.splitScalar(u8, relative_path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) return error.UnsafeExtractionPath;

        var name_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
        if (part.len >= name_buf.len) return error.UnsafeExtractionPath;
        @memcpy(name_buf[0..part.len], part);
        name_buf[part.len] = 0;
        const name_z: [*:0]const u8 = @ptrCast(&name_buf);

        const next_fd = std.c.openat(
            current_fd,
            name_z,
            .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            },
        );
        if (next_fd < 0) {
            switch (std.c.errno(next_fd)) {
                .NOENT => {
                    _ = c.close(current_fd);
                    return null;
                },
                .LOOP, .NOTDIR => return error.UnsafeExtractionPath,
                else => return error.SyscallFailed,
            }
        }
        _ = c.close(current_fd);
        current_fd = next_fd;
    }
    return current_fd;
}

fn openOrCreateDirectoryTree(
    start_fd: c_int,
    relative_path: []const u8,
) Error!c_int {
    var current_fd = c.dup(start_fd);
    if (current_fd < 0) return error.SyscallFailed;
    errdefer _ = c.close(current_fd);
    var parts = std.mem.splitScalar(u8, relative_path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) return error.UnsafeExtractionPath;
        var name_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
        if (part.len >= name_buf.len) return error.UnsafeExtractionPath;
        @memcpy(name_buf[0..part.len], part);
        name_buf[part.len] = 0;
        const name_z: [*:0]const u8 = @ptrCast(&name_buf);
        const mkdir_rc = c.mkdirat(current_fd, name_z, 0o755);
        if (mkdir_rc != 0 and std.c.errno(mkdir_rc) != .EXIST) {
            return error.SyscallFailed;
        }
        const next_fd = std.c.openat(current_fd, name_z, .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        });
        if (next_fd < 0) {
            return switch (std.c.errno(next_fd)) {
                .LOOP, .NOTDIR => error.UnsafeExtractionPath,
                else => error.SyscallFailed,
            };
        }
        _ = c.close(current_fd);
        current_fd = next_fd;
    }
    return current_fd;
}

fn writeAll(fd: c_int, data: []const u8) InstallError!void {
    var offset: usize = 0;
    while (offset < data.len) {
        const written = c.write(fd, data.ptr + offset, data.len - offset);
        if (written < 0) {
            if (std.c.errno(@as(c_int, @intCast(written))) == .INTR) continue;
            return error.SyscallFailed;
        }
        if (written == 0) return error.SyscallFailed;
        offset += @intCast(written);
    }
}

const CanonicalDirectoryLink = struct {
    name: []const u8,
    target: []const u8,
};

const canonical_directory_links = [_]CanonicalDirectoryLink{
    .{ .name = "bin", .target = "usr/bin" },
    .{ .name = "sbin", .target = "usr/sbin" },
    .{ .name = "lib", .target = "usr/lib" },
    .{ .name = "lib64", .target = "usr/lib64" },
};

fn isCanonicalDirectoryAlias(name: []const u8) bool {
    for (canonical_directory_links) |entry| {
        if (std.mem.eql(u8, name, entry.name)) return true;
    }
    return false;
}

fn canonicalDirectoryTarget(
    name: []const u8,
    target: []const u8,
) ?[]const u8 {
    for (canonical_directory_links) |entry| {
        if (std.mem.eql(u8, name, entry.name) and
            symlinkTargetMatches(target, entry.target))
        {
            return entry.target;
        }
    }
    if (std.mem.eql(u8, name, "lib64") and
        symlinkTargetMatches(target, "usr/lib"))
    {
        return "usr/lib";
    }
    return null;
}

fn pathRelativeToInstallRoot(
    install_root: []const u8,
    target_path: []const u8,
) InstallError![]const u8 {
    if (std.mem.eql(u8, install_root, "/")) {
        if (target_path.len < 2 or target_path[0] != '/') {
            return error.UnsafeExtractionPath;
        }
        return target_path[1..];
    }
    if (target_path.len <= install_root.len or
        !std.mem.eql(u8, target_path[0..install_root.len], install_root) or
        target_path[install_root.len] != '/')
    {
        return error.UnsafeExtractionPath;
    }
    return target_path[install_root.len + 1 ..];
}

fn symlinkTargetMatches(actual: []const u8, expected: []const u8) bool {
    return std.mem.eql(u8, actual, expected) or
        (actual.len == expected.len + 1 and
            actual[0] == '/' and
            std.mem.eql(u8, actual[1..], expected));
}

const DigestAlgo = enum(u32) {
    md5 = 1,
    sha1 = 2,
    sha256 = 8,
    sha384 = 9,
    sha512 = 10,
    sha224 = 11,
};

fn normalizeDigestAlgo(algo: u32, digest_hex: []const u8) InstallError!DigestAlgo {
    if (algo != 0) {
        return switch (algo) {
            @intFromEnum(DigestAlgo.md5) => .md5,
            @intFromEnum(DigestAlgo.sha1) => .sha1,
            @intFromEnum(DigestAlgo.sha224) => .sha224,
            @intFromEnum(DigestAlgo.sha256) => .sha256,
            @intFromEnum(DigestAlgo.sha384) => .sha384,
            @intFromEnum(DigestAlgo.sha512) => .sha512,
            else => error.UnsupportedDigestAlgorithm,
        };
    }

    return switch (digest_hex.len) {
        32 => .md5,
        40 => .sha1,
        56 => .sha224,
        64 => .sha256,
        96 => .sha384,
        128 => .sha512,
        else => error.UnsupportedDigestAlgorithm,
    };
}

fn digestStream(
    comptime Hash: type,
    fp: *c.FILE,
    chunk: []u8,
    expected_hex: []const u8,
) InstallError!bool {
    var hasher = Hash.init(.{});
    while (true) {
        const got = c.fread(chunk.ptr, 1, chunk.len, fp);
        if (got == 0) {
            break;
        }
        hasher.update(chunk[0..got]);
    }

    var digest: [Hash.digest_length]u8 = undefined;
    hasher.final(&digest);

    var actual_hex: [Hash.digest_length * 2]u8 = undefined;
    const actual = encodeHexLower(&actual_hex, &digest);
    return std.ascii.eqlIgnoreCase(actual[0..expected_hex.len], expected_hex);
}

fn encodeHexLower(buf: []u8, bytes: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    std.debug.assert(buf.len >= bytes.len * 2);

    for (bytes, 0..) |byte, i| {
        buf[i * 2] = digits[byte >> 4];
        buf[i * 2 + 1] = digits[byte & 0x0f];
    }
    return buf[0 .. bytes.len * 2];
}

fn lookupUserId(
    allocator: Allocator,
    install_root: []const u8,
    name: []const u8,
) Allocator.Error!?u32 {
    return lookupNamedId(allocator, install_root, "/etc/passwd", name, .passwd);
}

fn lookupGroupId(
    allocator: Allocator,
    install_root: []const u8,
    name: []const u8,
) Allocator.Error!?u32 {
    return lookupNamedId(allocator, install_root, "/etc/group", name, .group);
}

const LookupKind = enum {
    passwd,
    group,
};

fn lookupNamedId(
    allocator: Allocator,
    install_root: []const u8,
    relative_path: []const u8,
    name: []const u8,
    kind: LookupKind,
) Allocator.Error!?u32 {
    if (parseNumericId(name)) |numeric| {
        return numeric;
    }

    const full_path = try joinInstallRootAndPathOwned(allocator, install_root, relative_path);
    defer allocator.free(full_path);
    const contents = (try readFileOwned(allocator, full_path)) orelse return null;
    defer allocator.free(contents);

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trimEnd(u8, line_raw, "\r");
        if (line.len == 0 or line[0] == '#') {
            continue;
        }

        var fields = std.mem.splitScalar(u8, line, ':');
        const entry_name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        if (!std.mem.eql(u8, entry_name, name)) {
            continue;
        }

        const id_field = switch (kind) {
            .passwd => fields.next() orelse continue,
            .group => blk: {
                _ = fields.next() orelse continue;
                break :blk fields.next() orelse continue;
            },
        };
        return std.fmt.parseUnsigned(u32, id_field, 10) catch null;
    }

    return null;
}

fn parseNumericId(text: []const u8) ?u32 {
    return std.fmt.parseUnsigned(u32, text, 10) catch null;
}

fn readFileOwned(allocator: Allocator, path: []const u8) Allocator.Error!?[]u8 {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    var st: c.struct_stat = undefined;
    if (c.stat(path_z.ptr, &st) != 0) {
        return null;
    }

    const file_size: usize = @intCast(st.st_size);
    const fp = c.fopen(path_z.ptr, "rb") orelse return null;
    defer _ = c.fclose(fp);

    const contents = try allocator.alloc(u8, file_size);
    errdefer allocator.free(contents);

    if (file_size > 0 and c.fread(contents.ptr, 1, file_size, fp) != file_size) {
        allocator.free(contents);
        return null;
    }
    return contents;
}

const MutationSwap = struct {
    parent: [*:0]const u8,
    parked: [*:0]const u8,
    outside: [*:0]const u8,
    ran: bool = false,
    failed: bool = false,

    fn run(raw: ?*anyopaque) void {
        const self: *MutationSwap = @ptrCast(@alignCast(raw.?));
        if (self.ran) return;
        self.ran = true;
        if (c.rename(self.parent, self.parked) != 0 or
            c.symlink(self.outside, self.parent) != 0)
        {
            self.failed = true;
        }
    }
};

const ObjectSwap = struct {
    const Kind = enum {
        symlink,
        hardlink,
    };

    object: [*:0]const u8,
    replacement: [*:0]const u8,
    kind: Kind,
    calls: usize = 0,
    failed: bool = false,

    fn run(raw: ?*anyopaque) void {
        const self: *ObjectSwap = @ptrCast(@alignCast(raw.?));
        self.calls += 1;
        if (self.calls != 2) return;
        if (c.unlink(self.object) != 0) {
            self.failed = true;
            return;
        }
        const rc = switch (self.kind) {
            .symlink => c.symlink(self.replacement, self.object),
            .hardlink => c.link(self.replacement, self.object),
        };
        if (rc != 0) self.failed = true;
    }
};

test "chooseConfigAction handles noreplace" {
    try std.testing.expectEqual(ConfigAction.install, chooseConfigAction(true, false, true));
    try std.testing.expectEqual(ConfigAction.skip, chooseConfigAction(false, true, true));
    try std.testing.expectEqual(ConfigAction.rpmnew, chooseConfigAction(false, false, true));
    try std.testing.expectEqual(ConfigAction.rpmsave, chooseConfigAction(false, false, false));
}

test "special file metadata stays on pinned created object" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_ptr = c.getcwd(&cwd_buf, cwd_buf.len) orelse
        return error.TestUnexpectedResult;
    const cwd = std.mem.span(@as([*:0]const u8, @ptrCast(cwd_ptr)));
    const root_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ cwd, tmp.sub_path },
    );
    defer allocator.free(root_path);
    var root = try RootDir.init(allocator, root_path, null, null);
    defer root.deinit();
    try root.ensureDirectory("/special");
    const metadata = Metadata{
        .mode = S_IFLNK_U32 | 0o777,
        .mtime = 1234,
        .uid = c.getuid(),
        .gid = c.getgid(),
    };
    const object_path = try std.fmt.allocPrint(
        allocator,
        "{s}/special/link",
        .{root_path},
    );
    defer allocator.free(object_path);
    const outside_path = try std.fmt.allocPrint(
        allocator,
        "{s}/special/outside",
        .{root_path},
    );
    defer allocator.free(outside_path);
    const object_z = try allocator.dupeZ(u8, object_path);
    defer allocator.free(object_z);
    const outside_z = try allocator.dupeZ(u8, outside_path);
    defer allocator.free(outside_z);
    var symlink_swap = ObjectSwap{
        .object = object_z.ptr,
        .replacement = outside_z.ptr,
        .kind = .symlink,
    };
    root.mutation_fn = ObjectSwap.run;
    root.mutation_ctx = &symlink_swap;
    try root.writeSymlink("/special/link", "original", metadata);
    try std.testing.expectEqual(@as(usize, 2), symlink_swap.calls);
    try std.testing.expect(!symlink_swap.failed);
    var replaced_link: c.struct_stat = undefined;
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.lstat(object_z.ptr, &replaced_link),
    );
    try std.testing.expect(replaced_link.st_mtim.tv_sec != metadata.mtime);

    root.mutation_fn = null;
    root.mutation_ctx = null;
    const regular_metadata = Metadata{
        .mode = S_IFREG_U32 | 0o644,
        .mtime = 4321,
        .uid = c.getuid(),
        .gid = c.getgid(),
    };
    try root.writeRegularFile("/special/victim", "victim", regular_metadata);
    const fifo_path = try std.fmt.allocPrint(
        allocator,
        "{s}/special/fifo",
        .{root_path},
    );
    defer allocator.free(fifo_path);
    const victim_path = try std.fmt.allocPrint(
        allocator,
        "{s}/special/victim",
        .{root_path},
    );
    defer allocator.free(victim_path);
    const fifo_z = try allocator.dupeZ(u8, fifo_path);
    defer allocator.free(fifo_z);
    const victim_z = try allocator.dupeZ(u8, victim_path);
    defer allocator.free(victim_z);
    var fifo_swap = ObjectSwap{
        .object = fifo_z.ptr,
        .replacement = victim_z.ptr,
        .kind = .hardlink,
    };
    root.mutation_fn = ObjectSwap.run;
    root.mutation_ctx = &fifo_swap;
    try root.writeFifo("/special/fifo", S_IFIFO_U32 | 0o600, .{
        .mode = S_IFIFO_U32 | 0o600,
        .mtime = 5678,
        .uid = c.getuid(),
        .gid = c.getgid(),
    });
    try std.testing.expectEqual(@as(usize, 2), fifo_swap.calls);
    try std.testing.expect(!fifo_swap.failed);
    var victim_st: c.struct_stat = undefined;
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.stat(victim_z.ptr, &victim_st),
    );
    try std.testing.expectEqual(
        @as(c.mode_t, S_IFREG_U32 | 0o644),
        victim_st.st_mode & (c.S_IFMT | 0o777),
    );
    try std.testing.expectEqual(
        @as(@TypeOf(victim_st.st_mtim.tv_sec), regular_metadata.mtime),
        victim_st.st_mtim.tv_sec,
    );
}

test "fd rooted mutations survive intermediate symlink swaps" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_ptr = c.getcwd(&cwd_buf, cwd_buf.len) orelse
        return error.TestUnexpectedResult;
    const cwd = std.mem.span(@as([*:0]const u8, @ptrCast(cwd_ptr)));
    const root_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ cwd, tmp.sub_path },
    );
    defer allocator.free(root_path);
    var root = try RootDir.init(allocator, root_path, null, null);
    defer root.deinit();
    const metadata = Metadata{
        .mode = S_IFREG_U32 | 0o640,
        .mtime = 1234,
        .uid = c.getuid(),
        .gid = c.getgid(),
    };

    try root.ensureDirectory("/write/parent");
    try root.ensureDirectory("/write/outside");
    const write_parent = try std.fmt.allocPrint(
        allocator,
        "{s}/write/parent",
        .{root_path},
    );
    defer allocator.free(write_parent);
    const write_parked = try std.fmt.allocPrint(
        allocator,
        "{s}/write/parked",
        .{root_path},
    );
    defer allocator.free(write_parked);
    const write_outside = try std.fmt.allocPrint(
        allocator,
        "{s}/write/outside",
        .{root_path},
    );
    defer allocator.free(write_outside);
    const write_parent_z = try allocator.dupeZ(u8, write_parent);
    defer allocator.free(write_parent_z);
    const write_parked_z = try allocator.dupeZ(u8, write_parked);
    defer allocator.free(write_parked_z);
    const write_outside_z = try allocator.dupeZ(u8, write_outside);
    defer allocator.free(write_outside_z);
    var write_swap = MutationSwap{
        .parent = write_parent_z.ptr,
        .parked = write_parked_z.ptr,
        .outside = write_outside_z.ptr,
    };
    root.mutation_fn = MutationSwap.run;
    root.mutation_ctx = &write_swap;
    try root.writeRegularFile("/write/parent/file", "safe", metadata);
    try std.testing.expect(write_swap.ran and !write_swap.failed);
    const parked_file = try std.fmt.allocPrint(
        allocator,
        "{s}/file",
        .{write_parked},
    );
    defer allocator.free(parked_file);
    const outside_file = try std.fmt.allocPrint(
        allocator,
        "{s}/file",
        .{write_outside},
    );
    defer allocator.free(outside_file);
    const parked_contents = (try readFileOwned(allocator, parked_file)).?;
    defer allocator.free(parked_contents);
    try std.testing.expectEqualStrings("safe", parked_contents);
    try std.testing.expect((try readFileOwned(allocator, outside_file)) == null);

    root.mutation_fn = null;
    root.mutation_ctx = null;
    try root.ensureDirectory("/hard/src");
    try root.ensureDirectory("/hard/dst");
    try root.ensureDirectory("/hard/outside");
    try root.writeRegularFile("/hard/src/file", "linked", metadata);
    const hard_parent = try std.fmt.allocPrint(
        allocator,
        "{s}/hard/dst",
        .{root_path},
    );
    defer allocator.free(hard_parent);
    const hard_parked = try std.fmt.allocPrint(
        allocator,
        "{s}/hard/parked",
        .{root_path},
    );
    defer allocator.free(hard_parked);
    const hard_outside = try std.fmt.allocPrint(
        allocator,
        "{s}/hard/outside",
        .{root_path},
    );
    defer allocator.free(hard_outside);
    const hard_parent_z = try allocator.dupeZ(u8, hard_parent);
    defer allocator.free(hard_parent_z);
    const hard_parked_z = try allocator.dupeZ(u8, hard_parked);
    defer allocator.free(hard_parked_z);
    const hard_outside_z = try allocator.dupeZ(u8, hard_outside);
    defer allocator.free(hard_outside_z);
    var hard_swap = MutationSwap{
        .parent = hard_parent_z.ptr,
        .parked = hard_parked_z.ptr,
        .outside = hard_outside_z.ptr,
    };
    root.mutation_fn = MutationSwap.run;
    root.mutation_ctx = &hard_swap;
    try root.hardLink("/hard/src/file", "/hard/dst/link");
    try std.testing.expect(hard_swap.ran and !hard_swap.failed);
    const parked_link = try std.fmt.allocPrint(
        allocator,
        "{s}/link",
        .{hard_parked},
    );
    defer allocator.free(parked_link);
    const outside_link = try std.fmt.allocPrint(
        allocator,
        "{s}/link",
        .{hard_outside},
    );
    defer allocator.free(outside_link);
    var source_st: c.struct_stat = undefined;
    var link_st: c.struct_stat = undefined;
    const source_path = try std.fmt.allocPrint(
        allocator,
        "{s}/hard/src/file",
        .{root_path},
    );
    defer allocator.free(source_path);
    const source_z = try allocator.dupeZ(u8, source_path);
    defer allocator.free(source_z);
    const parked_link_z = try allocator.dupeZ(u8, parked_link);
    defer allocator.free(parked_link_z);
    try std.testing.expectEqual(@as(c_int, 0), c.stat(source_z.ptr, &source_st));
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.stat(parked_link_z.ptr, &link_st),
    );
    try std.testing.expectEqual(source_st.st_ino, link_st.st_ino);
    try std.testing.expect((try readFileOwned(allocator, outside_link)) == null);

    root.mutation_fn = null;
    root.mutation_ctx = null;
    try root.ensureDirectory("/remove/parent");
    try root.ensureDirectory("/remove/outside");
    try root.writeRegularFile("/remove/parent/victim", "inside", metadata);
    try root.writeRegularFile("/remove/outside/victim", "outside", metadata);
    const remove_parent = try std.fmt.allocPrint(
        allocator,
        "{s}/remove/parent",
        .{root_path},
    );
    defer allocator.free(remove_parent);
    const remove_parked = try std.fmt.allocPrint(
        allocator,
        "{s}/remove/parked",
        .{root_path},
    );
    defer allocator.free(remove_parked);
    const remove_outside = try std.fmt.allocPrint(
        allocator,
        "{s}/remove/outside",
        .{root_path},
    );
    defer allocator.free(remove_outside);
    const remove_parent_z = try allocator.dupeZ(u8, remove_parent);
    defer allocator.free(remove_parent_z);
    const remove_parked_z = try allocator.dupeZ(u8, remove_parked);
    defer allocator.free(remove_parked_z);
    const remove_outside_z = try allocator.dupeZ(u8, remove_outside);
    defer allocator.free(remove_outside_z);
    var remove_swap = MutationSwap{
        .parent = remove_parent_z.ptr,
        .parked = remove_parked_z.ptr,
        .outside = remove_outside_z.ptr,
    };
    root.mutation_fn = MutationSwap.run;
    root.mutation_ctx = &remove_swap;
    try root.remove("/remove/parent/victim");
    try std.testing.expect(remove_swap.ran and !remove_swap.failed);
    const parked_victim = try std.fmt.allocPrint(
        allocator,
        "{s}/victim",
        .{remove_parked},
    );
    defer allocator.free(parked_victim);
    const outside_victim = try std.fmt.allocPrint(
        allocator,
        "{s}/victim",
        .{remove_outside},
    );
    defer allocator.free(outside_victim);
    try std.testing.expect((try readFileOwned(
        allocator,
        parked_victim,
    )) == null);
    const outside_contents = (try readFileOwned(
        allocator,
        outside_victim,
    )).?;
    defer allocator.free(outside_contents);
    try std.testing.expectEqualStrings("outside", outside_contents);

    root.mutation_fn = null;
    root.mutation_ctx = null;
    try root.ensureDirectory("/upgrade/parent");
    try root.ensureDirectory("/upgrade/outside");
    try root.writeRegularFile("/upgrade/parent/config", "config", metadata);
    const upgrade_parent = try std.fmt.allocPrint(
        allocator,
        "{s}/upgrade/parent",
        .{root_path},
    );
    defer allocator.free(upgrade_parent);
    const upgrade_parked = try std.fmt.allocPrint(
        allocator,
        "{s}/upgrade/parked",
        .{root_path},
    );
    defer allocator.free(upgrade_parked);
    const upgrade_outside = try std.fmt.allocPrint(
        allocator,
        "{s}/upgrade/outside",
        .{root_path},
    );
    defer allocator.free(upgrade_outside);
    const upgrade_parent_z = try allocator.dupeZ(u8, upgrade_parent);
    defer allocator.free(upgrade_parent_z);
    const upgrade_parked_z = try allocator.dupeZ(u8, upgrade_parked);
    defer allocator.free(upgrade_parked_z);
    const upgrade_outside_z = try allocator.dupeZ(u8, upgrade_outside);
    defer allocator.free(upgrade_outside_z);
    var upgrade_swap = MutationSwap{
        .parent = upgrade_parent_z.ptr,
        .parked = upgrade_parked_z.ptr,
        .outside = upgrade_outside_z.ptr,
    };
    root.mutation_fn = MutationSwap.run;
    root.mutation_ctx = &upgrade_swap;
    try root.rename(
        "/upgrade/parent/config",
        "/upgrade/parent/config.rpmsave",
    );
    try std.testing.expect(upgrade_swap.ran and !upgrade_swap.failed);
    const parked_save = try std.fmt.allocPrint(
        allocator,
        "{s}/config.rpmsave",
        .{upgrade_parked},
    );
    defer allocator.free(parked_save);
    const save_contents = (try readFileOwned(allocator, parked_save)).?;
    defer allocator.free(save_contents);
    try std.testing.expectEqualStrings("config", save_contents);
}

test "normalizeCpioPathOwned strips rpm prefix" {
    const path = try normalizeCpioPathOwned(std.testing.allocator, "./usr/share/doc/");
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/usr/share/doc", path);
}

test "normalizeDigestAlgo falls back to digest length" {
    try std.testing.expectEqual(DigestAlgo.sha256, try normalizeDigestAlgo(0, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    try std.testing.expectEqual(DigestAlgo.sha512, try normalizeDigestAlgo(0, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

test "shouldSkipFile handles nodocs and noconfigs" {
    try std.testing.expect(shouldSkipFile(RPMFILE_DOC, rpmtrans.TDNF_RPMTRANS_FLAG_NODOCS));
    try std.testing.expect(!shouldSkipFile(RPMFILE_LICENSE, rpmtrans.TDNF_RPMTRANS_FLAG_NODOCS));
    try std.testing.expect(shouldSkipFile(RPMFILE_CONFIG, rpmtrans.TDNF_RPMTRANS_FLAG_NOCONFIGS));
    try std.testing.expect(!shouldSkipFile(RPMFILE_CONFIG, rpmtrans.TDNF_RPMTRANS_FLAG_NODOCS));
}

test "canonical directory symlinks stay beneath installroot" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_ptr = c.getcwd(&cwd_buf, cwd_buf.len) orelse
        return error.TestUnexpectedResult;
    const cwd = std.mem.span(@as([*:0]const u8, @ptrCast(cwd_ptr)));
    const root = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ cwd, tmp.sub_path },
    );
    defer allocator.free(root);
    const metadata = Metadata{
        .mode = S_IFREG_U32 | 0o640,
        .mtime = 1234,
        .uid = c.getuid(),
        .gid = c.getgid(),
    };
    var safe_root = try RootDir.init(allocator, root, null, null);
    defer safe_root.deinit();

    const usr_lib = try std.fmt.allocPrint(allocator, "{s}/usr/lib", .{root});
    defer allocator.free(usr_lib);
    try safe_root.ensureDirectory("/usr/lib");
    const lib = try std.fmt.allocPrint(allocator, "{s}/lib", .{root});
    defer allocator.free(lib);
    const lib_z = try allocator.dupeZ(u8, lib);
    defer allocator.free(lib_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.symlink("usr/lib", lib_z.ptr),
    );
    const lib_base = try std.fmt.allocPrint(
        allocator,
        "{s}/lib/rpm-sources",
        .{root},
    );
    defer allocator.free(lib_base);
    try writeRegularFileBeneath(
        allocator,
        root,
        lib_base,
        "pkg/source",
        "relative canonical",
        metadata,
    );
    const physical_lib_file = try std.fmt.allocPrint(
        allocator,
        "{s}/usr/lib/rpm-sources/pkg/source",
        .{root},
    );
    defer allocator.free(physical_lib_file);
    const lib_contents = (try readFileOwned(
        allocator,
        physical_lib_file,
    )).?;
    defer allocator.free(lib_contents);
    try std.testing.expectEqualStrings("relative canonical", lib_contents);
    try safe_root.writeRegularFile(
        "/usr/lib/alias-config",
        "config",
        metadata,
    );
    try safe_root.rename(
        "/lib/alias-config",
        "/lib/alias-config.rpmsave",
    );
    const saved_config = try std.fmt.allocPrint(
        allocator,
        "{s}/usr/lib/alias-config.rpmsave",
        .{root},
    );
    defer allocator.free(saved_config);
    const saved_contents = (try readFileOwned(
        allocator,
        saved_config,
    )).?;
    defer allocator.free(saved_contents);
    try std.testing.expectEqualStrings("config", saved_contents);
    try safe_root.writeRegularFile(
        "/usr/lib/alias-shared",
        "shared",
        metadata,
    );
    try safe_root.remove("/lib/alias-shared");
    const physical_shared = try std.fmt.allocPrint(
        allocator,
        "{s}/usr/lib/alias-shared",
        .{root},
    );
    defer allocator.free(physical_shared);
    try std.testing.expect((try readFileOwned(
        allocator,
        physical_shared,
    )) == null);

    const usr_bin = try std.fmt.allocPrint(allocator, "{s}/usr/bin", .{root});
    defer allocator.free(usr_bin);
    try safe_root.ensureDirectory("/usr/bin");
    const bin = try std.fmt.allocPrint(allocator, "{s}/bin", .{root});
    defer allocator.free(bin);
    const bin_z = try allocator.dupeZ(u8, bin);
    defer allocator.free(bin_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.symlink("/usr/bin", bin_z.ptr),
    );
    try safe_root.writeRegularFile(
        "/bin/tool",
        "absolute canonical",
        metadata,
    );
    const physical_bin_file = try std.fmt.allocPrint(
        allocator,
        "{s}/usr/bin/tool",
        .{root},
    );
    defer allocator.free(physical_bin_file);
    const bin_contents = (try readFileOwned(
        allocator,
        physical_bin_file,
    )).?;
    defer allocator.free(bin_contents);
    try std.testing.expectEqualStrings("absolute canonical", bin_contents);

    const outside = try std.fmt.allocPrint(
        allocator,
        "{s}/../outside-{s}",
        .{ root, tmp.sub_path },
    );
    defer allocator.free(outside);
    const outside_z = try allocator.dupeZ(u8, outside);
    defer allocator.free(outside_z);
    try std.testing.expectEqual(@as(c_int, 0), c.mkdir(outside_z.ptr, 0o755));
    defer _ = c.rmdir(outside_z.ptr);

    const sbin = try std.fmt.allocPrint(allocator, "{s}/sbin", .{root});
    defer allocator.free(sbin);
    const sbin_z = try allocator.dupeZ(u8, sbin);
    defer allocator.free(sbin_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.symlink("../../outside", sbin_z.ptr),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        safe_root.writeRegularFile(
            "/sbin/pwned",
            "bad",
            metadata,
        ),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        safe_root.canonicalPathOwned("/sbin/pwned"),
    );

    const lib64 = try std.fmt.allocPrint(allocator, "{s}/lib64", .{root});
    defer allocator.free(lib64);
    const lib64_z = try allocator.dupeZ(u8, lib64);
    defer allocator.free(lib64_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.symlink(outside_z.ptr, lib64_z.ptr),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        safe_root.writeRegularFile(
            "/lib64/pwned",
            "bad",
            metadata,
        ),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        safe_root.canonicalPathOwned("/lib64/pwned"),
    );
    try std.testing.expectEqual(@as(c_int, 0), c.unlink(lib64_z.ptr));
    try safe_root.writeRegularFile(
        "/usr/lib64",
        "not a directory",
        metadata,
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.symlink("usr/lib64", lib64_z.ptr),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        safe_root.writeRegularFile(
            "/lib64/pwned",
            "bad",
            metadata,
        ),
    );
    try std.testing.expectEqual(@as(c_int, 0), c.unlink(lib64_z.ptr));
    try safe_root.remove("/usr/lib64");
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.symlink("usr/lib", lib64_z.ptr),
    );
    const lib64_identity = try safe_root.canonicalPathOwned(
        "/lib64/loader",
    );
    defer allocator.free(lib64_identity);
    try std.testing.expectEqualStrings("/usr/lib/loader", lib64_identity);
    const escaped = try std.fmt.allocPrint(
        allocator,
        "{s}/pwned",
        .{outside},
    );
    defer allocator.free(escaped);
    try std.testing.expect((try readFileOwned(allocator, escaped)) == null);
}

test "source write helper rejects symlink escapes and hardlinked targets" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_ptr = c.getcwd(&cwd_buf, cwd_buf.len) orelse
        return error.TestUnexpectedResult;
    const cwd = std.mem.span(@as([*:0]const u8, @ptrCast(cwd_ptr)));
    const root = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ cwd, tmp.sub_path },
    );
    defer allocator.free(root);
    const base = try std.fmt.allocPrint(allocator, "{s}/extract", .{root});
    defer allocator.free(base);
    const metadata = Metadata{
        .mode = S_IFREG_U32 | 0o640,
        .mtime = 1234,
        .uid = c.getuid(),
        .gid = c.getgid(),
    };

    try writeRegularFileBeneath(
        allocator,
        root,
        base,
        "nested/file",
        "safe",
        metadata,
    );
    const safe_path = try std.fmt.allocPrint(
        allocator,
        "{s}/nested/file",
        .{base},
    );
    defer allocator.free(safe_path);
    const safe_contents = (try readFileOwned(allocator, safe_path)).?;
    defer allocator.free(safe_contents);
    try std.testing.expectEqualStrings("safe", safe_contents);

    const outside = try std.fmt.allocPrint(allocator, "{s}/outside", .{root});
    defer allocator.free(outside);
    const outside_z = try allocator.dupeZ(u8, outside);
    defer allocator.free(outside_z);
    try std.testing.expectEqual(@as(c_int, 0), c.mkdir(outside_z.ptr, 0o755));
    const link_path = try std.fmt.allocPrint(allocator, "{s}/escape", .{base});
    defer allocator.free(link_path);
    const link_z = try allocator.dupeZ(u8, link_path);
    defer allocator.free(link_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.symlink(outside_z.ptr, link_z.ptr),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        validateRegularFileDestinationBeneath(
            allocator,
            root,
            base,
            "escape/pwned",
        ),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        writeRegularFileBeneath(
            allocator,
            root,
            base,
            "escape/pwned",
            "bad",
            metadata,
        ),
    );
    const escaped = try std.fmt.allocPrint(allocator, "{s}/pwned", .{outside});
    defer allocator.free(escaped);
    try std.testing.expect((try readFileOwned(allocator, escaped)) == null);

    try writeRegularFileBeneath(
        allocator,
        root,
        base,
        "original",
        "unchanged",
        metadata,
    );
    const original = try std.fmt.allocPrint(allocator, "{s}/original", .{base});
    defer allocator.free(original);
    const hardlink = try std.fmt.allocPrint(allocator, "{s}/hardlink", .{base});
    defer allocator.free(hardlink);
    const original_z = try allocator.dupeZ(u8, original);
    defer allocator.free(original_z);
    const hardlink_z = try allocator.dupeZ(u8, hardlink);
    defer allocator.free(hardlink_z);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.link(original_z.ptr, hardlink_z.ptr),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        validateRegularFileDestinationBeneath(
            allocator,
            root,
            base,
            "hardlink",
        ),
    );
    try std.testing.expectError(
        error.UnsafeExtractionPath,
        writeRegularFileBeneath(
            allocator,
            root,
            base,
            "hardlink",
            "changed",
            metadata,
        ),
    );
    const original_contents = (try readFileOwned(allocator, original)).?;
    defer allocator.free(original_contents);
    try std.testing.expectEqualStrings("unchanged", original_contents);
}
