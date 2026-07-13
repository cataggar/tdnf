//! Minimal native macro/config resolution for the transaction engine.
//!
//! This intentionally models only the small librpm surface that tdnf's
//! native transaction work needs today:
//! - `%{_dbpath}` for rpmdb open/init/rebuild/verify
//! - `%{_tmppath}` for temporary transaction/script files
//! - `%{_install_script_path}` for the PATH exported to scriptlets
//!
//! Upstream librpm defaults the script interpreter itself to `/bin/sh`
//! when an RPM header does not carry an explicit `*PROG` tag. That is
//! a hard-coded runtime default, not a macro, so it is exposed here as
//! a constant for downstream consumers.

const std = @import("std");

pub const DEFAULT_INSTALL_ROOT = "/";
pub const DEFAULT_DBPATH = "/var/lib/rpm";
pub const DEFAULT_RPMDB_BASENAME = "rpmdb.sqlite";
pub const DEFAULT_TMPPATH = "/var/tmp";
pub const DEFAULT_INSTALL_SCRIPT_PATH = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/X11R6/bin";
pub const DEFAULT_SCRIPT_INTERPRETER = "/bin/sh";

pub const Macro = enum {
    dbpath,
    tmppath,
    install_script_path,

    /// Returns the rpm macro name this enum member represents.
    pub fn name(self: Macro) []const u8 {
        return switch (self) {
            .dbpath => "_dbpath",
            .tmppath => "_tmppath",
            .install_script_path => "_install_script_path",
        };
    }

    /// Returns the default librpm value for this macro.
    pub fn defaultValue(self: Macro) []const u8 {
        return switch (self) {
            .dbpath => DEFAULT_DBPATH,
            .tmppath => DEFAULT_TMPPATH,
            .install_script_path => DEFAULT_INSTALL_SCRIPT_PATH,
        };
    }

    /// Returns true when the macro resolves to an install-root-relative path.
    pub fn isInstallRootRelative(self: Macro) bool {
        return switch (self) {
            .dbpath, .tmppath => true,
            .install_script_path => false,
        };
    }
};

pub const ParsedRpmDefine = struct {
    macro: ?Macro,
    name: []const u8,
    value: []const u8,
};

pub const ParseDefineError = error{
    InvalidDefine,
};

pub const SetMacroError = error{
    InvalidMacroValue,
    OutOfMemory,
};

pub const ResolvePathError = error{
    NotPathMacro,
    PathTooLong,
};

pub const InitError = error{
    InvalidInstallRoot,
    OutOfMemory,
};

/// Returns the known macro represented by `name`, or null for a valid
/// but currently irrelevant macro.
pub fn macroFromName(name: []const u8) ?Macro {
    if (std.mem.eql(u8, name, "_dbpath")) return .dbpath;
    if (std.mem.eql(u8, name, "_tmppath")) return .tmppath;
    if (std.mem.eql(u8, name, "_install_script_path")) return .install_script_path;
    return null;
}

/// Parses a raw rpmdefine payload from either `--rpmdefine` or
/// `--setopt=rpmdefine=...`.
///
/// Accepted forms are:
/// - `_dbpath /usr/lib/sysimage/rpm`
/// - `_dbpath=/usr/lib/sysimage/rpm`
/// - `%{_dbpath}=/usr/lib/sysimage/rpm`
///
/// The returned slices alias the caller-owned `text`.
pub fn parseRpmDefine(text: []const u8) ParseDefineError!ParsedRpmDefine {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidDefine;

    const split_index = std.mem.indexOfAny(u8, trimmed, "=\t ") orelse {
        return error.InvalidDefine;
    };

    var name = std.mem.trim(u8, trimmed[0..split_index], " \t\r\n");
    var value = std.mem.trimStart(u8, trimmed[split_index..], "=\t ");
    value = std.mem.trim(u8, value, " \t\r\n");
    if (name.len == 0 or value.len == 0) return error.InvalidDefine;

    if (name[0] == '%') {
        if (name.len >= 4 and name[1] == '{' and name[name.len - 1] == '}') {
            name = name[2 .. name.len - 1];
        } else {
            name = name[1..];
        }
    }
    if (name.len == 0) return error.InvalidDefine;

    return .{
        .macro = macroFromName(name),
        .name = name,
        .value = value,
    };
}

/// Tiny transaction-engine config store backed by explicit defaults plus
/// command-line rpmdefine overrides.
pub const TxnConfig = struct {
    allocator: std.mem.Allocator,
    install_root: []u8,
    dbpath: []u8,
    tmppath: []u8,
    install_script_path: []u8,

    /// Initializes a config store rooted at `install_root`. Empty input
    /// is treated as `/`.
    pub fn init(allocator: std.mem.Allocator, install_root: []const u8) InitError!TxnConfig {
        const root = try normalizeInstallRootOwned(allocator, install_root);
        errdefer allocator.free(root);

        const dbpath = try allocator.dupe(u8, DEFAULT_DBPATH);
        errdefer allocator.free(dbpath);

        const tmppath = try allocator.dupe(u8, DEFAULT_TMPPATH);
        errdefer allocator.free(tmppath);

        const install_script_path = try allocator.dupe(u8, DEFAULT_INSTALL_SCRIPT_PATH);
        errdefer allocator.free(install_script_path);

        return .{
            .allocator = allocator,
            .install_root = root,
            .dbpath = dbpath,
            .tmppath = tmppath,
            .install_script_path = install_script_path,
        };
    }

    pub fn deinit(self: *TxnConfig) void {
        self.allocator.free(self.install_root);
        self.allocator.free(self.dbpath);
        self.allocator.free(self.tmppath);
        self.allocator.free(self.install_script_path);
    }

    pub fn installRoot(self: *const TxnConfig) []const u8 {
        return self.install_root;
    }

    /// Returns the effective value for a known macro.
    pub fn value(self: *const TxnConfig, macro_name: Macro) []const u8 {
        return switch (macro_name) {
            .dbpath => self.dbpath,
            .tmppath => self.tmppath,
            .install_script_path => self.install_script_path,
        };
    }

    /// Applies a raw rpmdefine string. Returns true when the define
    /// changes a macro currently consulted by the native engine, false
    /// for syntactically valid but currently irrelevant macros.
    pub fn applyRpmDefine(
        self: *TxnConfig,
        text: []const u8,
    ) (ParseDefineError || SetMacroError)!bool {
        const parsed = try parseRpmDefine(text);
        const macro_name = parsed.macro orelse return false;
        try self.setMacro(macro_name, parsed.value);
        return true;
    }

    /// Overrides a known macro with a caller-provided value.
    pub fn setMacro(
        self: *TxnConfig,
        macro_name: Macro,
        macro_value: []const u8,
    ) SetMacroError!void {
        switch (macro_name) {
            .dbpath => replaceOwnedString(
                self.allocator,
                &self.dbpath,
                try normalizePathMacroValueOwned(self.allocator, macro_value),
            ),
            .tmppath => replaceOwnedString(
                self.allocator,
                &self.tmppath,
                try normalizePathMacroValueOwned(self.allocator, macro_value),
            ),
            .install_script_path => replaceOwnedString(
                self.allocator,
                &self.install_script_path,
                try normalizePlainValueOwned(self.allocator, macro_value),
            ),
        }
    }

    /// Resolves a known install-root-relative macro to a concrete path.
    pub fn resolvePath(
        self: *const TxnConfig,
        macro_name: Macro,
        buf: []u8,
    ) ResolvePathError![]const u8 {
        if (!macro_name.isInstallRootRelative()) return error.NotPathMacro;
        return buildInstallRootedPath(buf, self.install_root, self.value(macro_name));
    }

    /// Resolves the sqlite rpmdb file path under the configured root.
    pub fn resolveRpmDbSqlitePath(
        self: *const TxnConfig,
        buf: []u8,
    ) error{PathTooLong}![]const u8 {
        return buildRpmDbSqlitePath(buf, self.install_root, self.dbpath);
    }
};

/// Builds an install-root-relative path for a macro such as `_dbpath`
/// or `_tmppath`.
pub fn buildInstallRootedPath(
    buf: []u8,
    install_root: []const u8,
    macro_value: []const u8,
) error{PathTooLong}![]const u8 {
    const root_prefix = trimRootPrefix(install_root);
    const relative = std.mem.trim(u8, macro_value, "/");

    if (relative.len == 0) {
        if (root_prefix.len == 0) {
            if (buf.len < 2) return error.PathTooLong;
            return std.fmt.bufPrintZ(buf, "/", .{}) catch return error.PathTooLong;
        }
        if (root_prefix.len + 1 > buf.len) return error.PathTooLong;
        return std.fmt.bufPrintZ(buf, "{s}", .{root_prefix}) catch return error.PathTooLong;
    }

    const needed = root_prefix.len + 1 + relative.len + 1;
    if (needed > buf.len) return error.PathTooLong;
    return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ root_prefix, relative }) catch return error.PathTooLong;
}

/// Builds the rooted path to the sqlite rpmdb file.
pub fn buildRpmDbSqlitePath(
    buf: []u8,
    install_root: []const u8,
    dbpath_macro: []const u8,
) error{PathTooLong}![]const u8 {
    const root_prefix = trimRootPrefix(install_root);
    const relative = std.mem.trim(u8, dbpath_macro, "/");

    if (relative.len == 0) {
        const needed = root_prefix.len + 1 + DEFAULT_RPMDB_BASENAME.len + 1;
        if (needed > buf.len) return error.PathTooLong;
        return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ root_prefix, DEFAULT_RPMDB_BASENAME }) catch return error.PathTooLong;
    }

    const needed = root_prefix.len + 1 + relative.len + 1 + DEFAULT_RPMDB_BASENAME.len + 1;
    if (needed > buf.len) return error.PathTooLong;
    return std.fmt.bufPrintZ(
        buf,
        "{s}/{s}/{s}",
        .{ root_prefix, relative, DEFAULT_RPMDB_BASENAME },
    ) catch return error.PathTooLong;
}

/// Convenience helper for the default rpmdb location.
pub fn buildDefaultRpmDbSqlitePath(
    buf: []u8,
    install_root: []const u8,
) error{PathTooLong}![]const u8 {
    return buildRpmDbSqlitePath(buf, install_root, DEFAULT_DBPATH);
}

fn normalizeInstallRootOwned(allocator: std.mem.Allocator, input: []const u8) InitError![]u8 {
    var trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) trimmed = DEFAULT_INSTALL_ROOT;
    if (trimmed[0] != '/') return error.InvalidInstallRoot;
    trimmed = trimTrailingSlashKeepRoot(trimmed);
    return allocator.dupe(u8, trimmed);
}

fn normalizePathMacroValueOwned(
    allocator: std.mem.Allocator,
    input: []const u8,
) SetMacroError![]u8 {
    var trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidMacroValue;
    trimmed = trimTrailingSlashKeepRoot(trimmed);
    return allocator.dupe(u8, trimmed);
}

fn normalizePlainValueOwned(
    allocator: std.mem.Allocator,
    input: []const u8,
) SetMacroError![]u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidMacroValue;
    return allocator.dupe(u8, trimmed);
}

fn replaceOwnedString(
    allocator: std.mem.Allocator,
    dest: *[]u8,
    replacement: []u8,
) void {
    const old = dest.*;
    dest.* = replacement;
    allocator.free(old);
}

fn trimRootPrefix(input: []const u8) []const u8 {
    const effective = if (input.len == 0) DEFAULT_INSTALL_ROOT else input;
    var trimmed = std.mem.trimEnd(u8, effective, "/");
    if (trimmed.len == 0) trimmed = "";
    return trimmed;
}

fn trimTrailingSlashKeepRoot(input: []const u8) []const u8 {
    var trimmed = std.mem.trimEnd(u8, input, "/");
    if (trimmed.len == 0) trimmed = DEFAULT_INSTALL_ROOT;
    return trimmed;
}

test "parseRpmDefine accepts whitespace form" {
    const parsed = try parseRpmDefine("_dbpath /usr/lib/sysimage/rpm/");
    try std.testing.expectEqual(Macro.dbpath, parsed.macro.?);
    try std.testing.expectEqualStrings("_dbpath", parsed.name);
    try std.testing.expectEqualStrings("/usr/lib/sysimage/rpm/", parsed.value);
}

test "parseRpmDefine accepts equals form" {
    const parsed = try parseRpmDefine("%{_tmppath}=/var/tmp/native");
    try std.testing.expectEqual(Macro.tmppath, parsed.macro.?);
    try std.testing.expectEqualStrings("_tmppath", parsed.name);
    try std.testing.expectEqualStrings("/var/tmp/native", parsed.value);
}

test "parseRpmDefine rejects missing value" {
    try std.testing.expectError(error.InvalidDefine, parseRpmDefine("_dbpath"));
}

test "TxnConfig ignores unknown rpmdefines" {
    var cfg = try TxnConfig.init(std.testing.allocator, "");
    defer cfg.deinit();

    try std.testing.expect(!(try cfg.applyRpmDefine("_foo /bar")));
    try std.testing.expectEqualStrings(DEFAULT_DBPATH, cfg.value(.dbpath));
}

test "TxnConfig resolves rooted dbpath override" {
    var cfg = try TxnConfig.init(std.testing.allocator, "/mnt/sysroot/");
    defer cfg.deinit();

    try std.testing.expect(try cfg.applyRpmDefine("_dbpath=/usr/lib/sysimage/rpm/"));

    var buf: [256]u8 = undefined;
    const db_dir = try cfg.resolvePath(.dbpath, &buf);
    try std.testing.expectEqualStrings("/mnt/sysroot/usr/lib/sysimage/rpm", db_dir);

    const db_file = try cfg.resolveRpmDbSqlitePath(&buf);
    try std.testing.expectEqualStrings("/mnt/sysroot/usr/lib/sysimage/rpm/rpmdb.sqlite", db_file);
}

test "TxnConfig resolves tmppath under installroot" {
    var cfg = try TxnConfig.init(std.testing.allocator, "/altroot");
    defer cfg.deinit();

    var buf: [256]u8 = undefined;
    const path = try cfg.resolvePath(.tmppath, &buf);
    try std.testing.expectEqualStrings("/altroot/var/tmp", path);
}

test "TxnConfig exposes install script path without rooting" {
    var cfg = try TxnConfig.init(std.testing.allocator, "/");
    defer cfg.deinit();

    try std.testing.expectEqualStrings(DEFAULT_INSTALL_SCRIPT_PATH, cfg.value(.install_script_path));
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.NotPathMacro, cfg.resolvePath(.install_script_path, &buf));
}

test "TxnConfig rejects relative installroots" {
    try std.testing.expectError(
        error.InvalidInstallRoot,
        TxnConfig.init(std.testing.allocator, "relative/root"),
    );
}

test "buildDefaultRpmDbSqlitePath keeps root slash semantics" {
    var buf: [256]u8 = undefined;
    const path = try buildDefaultRpmDbSqlitePath(&buf, "/");
    try std.testing.expectEqualStrings("/var/lib/rpm/rpmdb.sqlite", path);
}
