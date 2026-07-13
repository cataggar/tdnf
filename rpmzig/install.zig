const std = @import("std");
const Allocator = std.mem.Allocator;
const header = @import("rpm_header");
const pkgfile = @import("rpm_pkgfile");
const cpio = @import("cpio.zig");
const txn_config = @import("txn_config.zig");

const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

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

const RPMTRANS_FLAG_JUSTDB: u32 = 1 << 3;
const RPMTRANS_FLAG_NODOCS: u32 = 1 << 5;
const RPMTRANS_FLAG_NOCAPS: u32 = 1 << 9;
const RPMTRANS_FLAG_NOCONFIGS: u32 = 1 << 30;

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

pub const Options = struct {
    install_root: []const u8,
    trans_flags: u32 = 0,
    install_kind: InstallKind = .install,
    prior_headers: []const header.Header = &.{},
    conflict_fn: ?ConflictFn = null,
    conflict_ctx: ?*anyopaque = null,
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
    HardlinkMissingPayload,
    SyscallFailed,
};

pub const Error = Allocator.Error || txn_config.InitError || cpio.Error || pkgfile.Error || InstallError;

pub const Context = struct {
    allocator: Allocator,
    rpm: *const pkgfile.RpmFile,
    options: Options,
    config: txn_config.TxnConfig,
    last_path: ?[]const u8 = null,

    pub fn init(
        allocator: Allocator,
        rpm: *const pkgfile.RpmFile,
        options: Options,
    ) (Allocator.Error || txn_config.InitError)!Context {
        var cfg = try txn_config.TxnConfig.init(allocator, options.install_root);
        errdefer cfg.deinit();

        return .{
            .allocator = allocator,
            .rpm = rpm,
            .options = options,
            .config = cfg,
        };
    }

    pub fn deinit(self: *Context) void {
        self.config.deinit();
    }

    pub fn install(self: *Context) Error!void {
        if (self.isSourceRpm()) {
            return error.UnsupportedSourceRpm;
        }

        if ((self.options.trans_flags & RPMTRANS_FLAG_JUSTDB) != 0) {
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
                self.last_path = payload_path;
                return error.MissingHeaderPath;
            };
            manifest.processed[manifest_index] = true;

            const file = manifest.files[manifest_index];
            self.last_path = file.path;

            if (shouldSkipFile(file.flags, self.options.trans_flags)) {
                continue;
            }
            if (isGhost(file.flags)) {
                continue;
            }
            if (hasCapabilities(file) and (self.options.trans_flags & RPMTRANS_FLAG_NOCAPS) == 0) {
                return error.UnsupportedFileCapabilities;
            }

            const target_path = try joinInstallRootAndPathOwned(
                self.allocator,
                self.config.installRoot(),
                file.path,
            );
            defer self.allocator.free(target_path);

            const metadata = try self.buildMetadata(file, entry);

            if (isDirMode(metadata.mode)) {
                try ensureDirectoryPath(self.allocator, target_path);
                try deferred_dirs.append(self.allocator, .{
                    .target_path = try self.allocator.dupe(u8, target_path),
                    .mode = metadata.mode,
                    .mtime = metadata.mtime,
                    .uid = metadata.uid,
                    .gid = metadata.gid,
                });
                continue;
            }

            const action = try self.decideAction(
                file,
                prior_manifests.items,
                target_path,
            );

            switch (action) {
                .skip => continue,
                .install => try self.installEntry(
                    entry,
                    metadata,
                    target_path,
                    &hardlinks,
                ),
                .rpmnew => {
                    const rpmnew_path = try std.fmt.allocPrint(self.allocator, "{s}.rpmnew", .{target_path});
                    defer self.allocator.free(rpmnew_path);
                    try self.installEntry(entry, metadata, rpmnew_path, &hardlinks);
                },
                .rpmsave => {
                    const rpmsave_path = try std.fmt.allocPrint(self.allocator, "{s}.rpmsave", .{target_path});
                    defer self.allocator.free(rpmsave_path);
                    try renameExistingPath(self.allocator, target_path, rpmsave_path);
                    try self.installEntry(entry, metadata, target_path, &hardlinks);
                },
            }
        }

        try self.ensureNoMissingHardlinks(&hardlinks);
        try self.ensureNoMissingEntries(&manifest);
        try self.applyDeferredDirs(deferred_dirs.items);
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
        const uid = if (file.username) |name|
            (try lookupUserId(self.allocator, self.config.installRoot(), name)) orelse entry.uid
        else
            entry.uid;
        const gid = if (file.groupname) |name|
            (try lookupGroupId(self.allocator, self.config.installRoot(), name)) orelse entry.gid
        else
            entry.gid;

        return .{
            .mode = if (file.mode != 0) file.mode else entry.mode,
            .mtime = if (file.mtime != 0) file.mtime else entry.mtime,
            .uid = uid,
            .gid = gid,
        };
    }

    fn decideAction(
        self: *Context,
        file: HeaderFile,
        prior_manifests: []const Manifest,
        target_path: []const u8,
    ) Error!ConfigAction {
        if (!pathExists(self.allocator, target_path)) {
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
        const matches_new = try fileDigestMatches(self.allocator, target_path, file.digest_algo, new_digest);
        if (matches_new) {
            return .skip;
        }

        const prior_file = prior.?;
        const old_digest = prior_file.digest orelse return .install;
        const matches_old = try fileDigestMatches(self.allocator, target_path, prior_file.digest_algo, old_digest);
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
                    try createHardLink(self.allocator, target_path, pending_path);
                }
                for (state.pending_paths.items) |pending_path| {
                    self.allocator.free(pending_path);
                }
                state.pending_paths.clearRetainingCapacity();
                return;
            }
        }

        if (state.canonical_path) |canonical_path| {
            try createHardLink(self.allocator, canonical_path, target_path);
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
            try writeRegularFile(self.allocator, target_path, entry.data);
            try applyMetadata(self.allocator, target_path, metadata, false);
            return;
        }
        if (mode_type == S_IFLNK_U32) {
            try writeSymlink(self.allocator, target_path, entry.data);
            try applyMetadata(self.allocator, target_path, metadata, true);
            return;
        }
        if (mode_type == S_IFCHR_U32 or mode_type == S_IFBLK_U32) {
            try writeDeviceNode(self.allocator, target_path, metadata.mode, entry.rdevmajor, entry.rdevminor);
            try applyMetadata(self.allocator, target_path, metadata, false);
            return;
        }
        if (mode_type == S_IFIFO_U32) {
            try writeFifo(self.allocator, target_path, metadata.mode);
            try applyMetadata(self.allocator, target_path, metadata, false);
            return;
        }
        if (mode_type == S_IFDIR_U32) {
            try ensureDirectoryPath(self.allocator, target_path);
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
                    self.last_path = state.pending_paths.items[0];
                }
                return error.HardlinkMissingPayload;
            }
        }
    }

    fn ensureNoMissingEntries(self: *Context, manifest: *const Manifest) InstallError!void {
        if ((self.options.trans_flags & RPMTRANS_FLAG_JUSTDB) != 0) {
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
            self.last_path = file.path;
            return error.MissingPayloadEntry;
        }
    }

    fn applyDeferredDirs(self: *Context, deferred_dirs: []const DeferredDir) Error!void {
        for (deferred_dirs) |dir| {
            try ensureDirectoryPath(self.allocator, dir.target_path);
            try applyMetadata(self.allocator, dir.target_path, .{
                .mode = dir.mode,
                .mtime = dir.mtime,
                .uid = dir.uid,
                .gid = dir.gid,
            }, false);
        }
    }
};

const ConfigAction = enum {
    install,
    skip,
    rpmnew,
    rpmsave,
};

const Metadata = struct {
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
};

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
    mtime: u32,
    username: ?[]const u8,
    groupname: ?[]const u8,
    digest: ?[]const u8,
    digest_algo: u32,
    caps: ?[]const u8,
};

pub const Manifest = struct {
    allocator: Allocator,
    files: []HeaderFile,
    processed: []bool,
    index: std.StringHashMap(usize),

    pub fn init(allocator: Allocator, hdr: header.Header) Error!Manifest {
        const count = hdr.stringArrayCount(.basenames);
        const files = try allocator.alloc(HeaderFile, count);
        errdefer allocator.free(files);
        const processed = try allocator.alloc(bool, count);
        errdefer allocator.free(processed);
        @memset(processed, false);

        var index = std.StringHashMap(usize).init(allocator);
        errdefer index.deinit();

        const digest_algo = hdr.getU32(.filedigestalgo) orelse 0;

        for (0..count) |i| {
            const basename = hdr.stringArrayItem(.basenames, i) orelse return error.BadHeader;
            const dir_index = hdr.u32ArrayItem(.dirindexes, i) orelse return error.BadHeader;
            const dirname = hdr.stringArrayItem(.dirnames, dir_index) orelse return error.BadHeader;
            const joined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ dirname, basename });
            defer allocator.free(joined);
            const normalized = try normalizeAbsolutePathOwned(allocator, joined);

            files[i] = .{
                .path = normalized,
                .mode = hdr.u16ArrayItem(.filemodes, i) orelse 0,
                .flags = hdr.u32ArrayItem(.fileflags, i) orelse 0,
                .mtime = hdr.u32ArrayItem(.filemtimes, i) orelse 0,
                .username = hdr.stringArrayItem(.fileusername, i),
                .groupname = hdr.stringArrayItem(.filegroupname, i),
                .digest = hdr.stringArrayItem(.filedigests, i),
                .digest_algo = digest_algo,
                .caps = hdr.stringArrayItem(.filecaps, i),
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

fn shouldSkipFile(flags: u32, trans_flags: u32) bool {
    if ((trans_flags & RPMTRANS_FLAG_NOCONFIGS) != 0 and isConfig(flags)) {
        return true;
    }
    if ((trans_flags & RPMTRANS_FLAG_NODOCS) != 0 and isExcludedDoc(flags)) {
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

fn ensureDirectoryPath(allocator: Allocator, path: []const u8) Error!void {
    var mutable = try allocator.dupeZ(u8, path);
    defer allocator.free(mutable);

    var i: usize = 1;
    while (i < mutable.len) : (i += 1) {
        if (mutable[i] != '/') {
            continue;
        }
        mutable[i] = 0;
        try mkdirExistingOk(@ptrCast(mutable.ptr));
        mutable[i] = '/';
    }
    try mkdirExistingOk(@ptrCast(mutable.ptr));
}

fn ensureParentDirs(allocator: Allocator, path: []const u8) Error!void {
    const slash_index = std.mem.lastIndexOfScalar(u8, path, '/') orelse return;
    if (slash_index == 0) {
        return;
    }
    try ensureDirectoryPath(allocator, path[0..slash_index]);
}

fn mkdirExistingOk(path_z: [*:0]const u8) InstallError!void {
    if (c.mkdir(path_z, 0o755) == 0) {
        return;
    }
    var st: c.struct_stat = undefined;
    if (c.lstat(path_z, &st) == 0 and (st.st_mode & c.S_IFMT) == c.S_IFDIR) {
        return;
    }
    return error.SyscallFailed;
}

pub fn pathExists(allocator: Allocator, path: []const u8) bool {
    const path_z = allocator.dupeZ(u8, path) catch return false;
    defer allocator.free(path_z);
    var st: c.struct_stat = undefined;
    return c.lstat(path_z.ptr, &st) == 0;
}

pub fn removeExistingPath(allocator: Allocator, path: []const u8) Error!void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    var st: c.struct_stat = undefined;
    if (c.lstat(path_z.ptr, &st) != 0) {
        return;
    }

    if ((st.st_mode & c.S_IFMT) == c.S_IFDIR) {
        if (c.rmdir(path_z.ptr) != 0) {
            return error.SyscallFailed;
        }
        return;
    }

    if (c.unlink(path_z.ptr) != 0) {
        return error.SyscallFailed;
    }
}

pub fn renameExistingPath(allocator: Allocator, src: []const u8, dst: []const u8) Error!void {
    try ensureParentDirs(allocator, dst);
    try removeExistingPath(allocator, dst);

    const src_z = try allocator.dupeZ(u8, src);
    defer allocator.free(src_z);
    const dst_z = try allocator.dupeZ(u8, dst);
    defer allocator.free(dst_z);

    if (c.rename(src_z.ptr, dst_z.ptr) != 0) {
        return error.SyscallFailed;
    }
}

fn writeRegularFile(allocator: Allocator, path: []const u8, data: []const u8) Error!void {
    try ensureParentDirs(allocator, path);
    try removeExistingPath(allocator, path);

    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const fp = c.fopen(path_z.ptr, "wb") orelse {
        return error.SyscallFailed;
    };
    defer _ = c.fclose(fp);

    if (data.len > 0 and c.fwrite(data.ptr, 1, data.len, fp) != data.len) {
        return error.SyscallFailed;
    }
}

fn writeSymlink(allocator: Allocator, path: []const u8, target: []const u8) Error!void {
    try ensureParentDirs(allocator, path);
    try removeExistingPath(allocator, path);

    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    if (c.symlink(target_z.ptr, path_z.ptr) != 0) {
        return error.SyscallFailed;
    }
}

fn writeDeviceNode(
    allocator: Allocator,
    path: []const u8,
    mode: u32,
    major_id: u32,
    minor_id: u32,
) Error!void {
    try ensureParentDirs(allocator, path);
    try removeExistingPath(allocator, path);

    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const dev = c.makedev(
        @as(c_uint, @intCast(major_id)),
        @as(c_uint, @intCast(minor_id)),
    );
    if (c.mknod(path_z.ptr, mode, dev) != 0) {
        return error.SyscallFailed;
    }
}

fn writeFifo(allocator: Allocator, path: []const u8, mode: u32) Error!void {
    try ensureParentDirs(allocator, path);
    try removeExistingPath(allocator, path);

    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    if (c.mkfifo(path_z.ptr, mode & MODE_PERMS_MASK) != 0) {
        return error.SyscallFailed;
    }
}

fn createHardLink(allocator: Allocator, existing_path: []const u8, new_path: []const u8) Error!void {
    try ensureParentDirs(allocator, new_path);
    try removeExistingPath(allocator, new_path);

    const existing_z = try allocator.dupeZ(u8, existing_path);
    defer allocator.free(existing_z);
    const new_z = try allocator.dupeZ(u8, new_path);
    defer allocator.free(new_z);

    if (c.link(existing_z.ptr, new_z.ptr) != 0) {
        return error.SyscallFailed;
    }
}

fn applyMetadata(
    allocator: Allocator,
    path: []const u8,
    metadata: Metadata,
    is_symlink: bool,
) Error!void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    if (is_symlink) {
        if (c.lchown(path_z.ptr, metadata.uid, metadata.gid) != 0) {
            return error.SyscallFailed;
        }
    } else {
        if (c.chown(path_z.ptr, metadata.uid, metadata.gid) != 0) {
            return error.SyscallFailed;
        }
        if (c.chmod(path_z.ptr, metadata.mode & MODE_PERMS_MASK) != 0) {
            return error.SyscallFailed;
        }
    }

    var times = [2]c.struct_timespec{
        .{ .tv_sec = @intCast(metadata.mtime), .tv_nsec = 0 },
        .{ .tv_sec = @intCast(metadata.mtime), .tv_nsec = 0 },
    };
    const flags: c_int = if (is_symlink) AT_SYMLINK_NOFOLLOW else 0;
    if (c.utimensat(AT_FDCWD, path_z.ptr, &times, flags) != 0) {
        return error.SyscallFailed;
    }
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

pub fn fileDigestMatches(
    allocator: Allocator,
    path: []const u8,
    digest_algo_raw: u32,
    expected_hex: []const u8,
) Error!bool {
    const algo = try normalizeDigestAlgo(digest_algo_raw, expected_hex);
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const fp = c.fopen(path_z.ptr, "rb") orelse return error.SyscallFailed;
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

test "chooseConfigAction handles noreplace" {
    try std.testing.expectEqual(ConfigAction.install, chooseConfigAction(true, false, true));
    try std.testing.expectEqual(ConfigAction.skip, chooseConfigAction(false, true, true));
    try std.testing.expectEqual(ConfigAction.rpmnew, chooseConfigAction(false, false, true));
    try std.testing.expectEqual(ConfigAction.rpmsave, chooseConfigAction(false, false, false));
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
    try std.testing.expect(shouldSkipFile(RPMFILE_DOC, RPMTRANS_FLAG_NODOCS));
    try std.testing.expect(!shouldSkipFile(RPMFILE_LICENSE, RPMTRANS_FLAG_NODOCS));
    try std.testing.expect(shouldSkipFile(RPMFILE_CONFIG, RPMTRANS_FLAG_NOCONFIGS));
    try std.testing.expect(!shouldSkipFile(RPMFILE_CONFIG, RPMTRANS_FLAG_NODOCS));
}
