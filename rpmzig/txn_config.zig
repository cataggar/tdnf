//! Minimal native macro/config resolution for the transaction engine.
//!
//! This intentionally models only the small librpm surface that tdnf's
//! native transaction work needs today:
//! - `%{_dbpath}` for rpmdb open/init/rebuild/verify
//! - `%{_tmppath}` for temporary transaction/script files
//! - `%{_install_script_path}` for the PATH exported to scriptlets
//! - `%{_topdir}`, `%{_specdir}`, and `%{_sourcedir}` for source RPMs
//!
//! Upstream librpm defaults the script interpreter itself to `/bin/sh`
//! when an RPM header does not carry an explicit `*PROG` tag. That is
//! a hard-coded runtime default, not a macro, so it is exposed here as
//! a constant for downstream consumers.

const std = @import("std");
const c = @cImport({
    @cInclude("glob.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

pub const DEFAULT_INSTALL_ROOT = "/";
pub const DEFAULT_DBPATH = "/var/lib/rpm";
pub const DEFAULT_RPMDB_BASENAME = "rpmdb.sqlite";
pub const DEFAULT_TMPPATH = "/var/tmp";
pub const DEFAULT_INSTALL_SCRIPT_PATH = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/X11R6/bin";
pub const DEFAULT_TOPDIR = "%{getenv:HOME}/rpmbuild";
pub const DEFAULT_SPECDIR = "%{_topdir}/SPECS";
pub const DEFAULT_SOURCEDIR = "%{_topdir}/SOURCES";
pub const DEFAULT_SCRIPT_INTERPRETER = "/bin/sh";
const MAX_EXPANSION_DEPTH = 32;

pub const Macro = enum {
    dbpath,
    tmppath,
    install_script_path,
    topdir,
    specdir,
    sourcedir,

    /// Returns the rpm macro name this enum member represents.
    pub fn name(self: Macro) []const u8 {
        return switch (self) {
            .dbpath => "_dbpath",
            .tmppath => "_tmppath",
            .install_script_path => "_install_script_path",
            .topdir => "_topdir",
            .specdir => "_specdir",
            .sourcedir => "_sourcedir",
        };
    }

    /// Returns the default librpm value for this macro.
    pub fn defaultValue(self: Macro) []const u8 {
        return switch (self) {
            .dbpath => DEFAULT_DBPATH,
            .tmppath => DEFAULT_TMPPATH,
            .install_script_path => DEFAULT_INSTALL_SCRIPT_PATH,
            .topdir => DEFAULT_TOPDIR,
            .specdir => DEFAULT_SPECDIR,
            .sourcedir => DEFAULT_SOURCEDIR,
        };
    }

    /// Returns true when the macro resolves to an install-root-relative path.
    pub fn isInstallRootRelative(self: Macro) bool {
        return switch (self) {
            .dbpath, .tmppath, .topdir, .specdir, .sourcedir => true,
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
    InvalidMacroName,
    OutOfMemory,
};

pub const ExpandError = error{
    ExpansionCycle,
    ExpansionTooDeep,
    InvalidMacroExpression,
    UnknownMacro,
    OutOfMemory,
};

pub const ResolvePathError = ExpandError || error{
    NotPathMacro,
    PathTooLong,
};

pub const InitError = error{
    InvalidInstallRoot,
    OutOfMemory,
};

pub const LoadMacrosError = SetMacroError || error{
    GlobFailed,
    MacroFileOpenFailed,
    MacroFileReadFailed,
};

/// Returns the known macro represented by `name`, or null for a valid
/// but currently irrelevant macro.
pub fn macroFromName(name: []const u8) ?Macro {
    if (std.mem.eql(u8, name, "_dbpath")) return .dbpath;
    if (std.mem.eql(u8, name, "_tmppath")) return .tmppath;
    if (std.mem.eql(u8, name, "_install_script_path")) return .install_script_path;
    if (std.mem.eql(u8, name, "_topdir")) return .topdir;
    if (std.mem.eql(u8, name, "_specdir")) return .specdir;
    if (std.mem.eql(u8, name, "_sourcedir")) return .sourcedir;
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

const MacroEntry = struct {
    name: []u8,
    value: []u8,
};

/// Transaction-engine config store backed by explicit defaults plus arbitrary
/// command-line definitions. Values are expanded lazily so later definitions
/// affect macros that reference them, matching librpm's macro behavior.
pub const TxnConfig = struct {
    allocator: std.mem.Allocator,
    install_root: []u8,
    macros: std.ArrayList(MacroEntry),

    /// Initializes a config store rooted at `install_root`. Empty input
    /// is treated as `/`.
    pub fn init(allocator: std.mem.Allocator, install_root: []const u8) InitError!TxnConfig {
        const root = try normalizeInstallRootOwned(allocator, install_root);
        var config = TxnConfig{
            .allocator = allocator,
            .install_root = root,
            .macros = .empty,
        };
        errdefer config.deinit();

        inline for (std.meta.fields(Macro)) |field| {
            const macro_name: Macro = @enumFromInt(field.value);
            config.setMacroByName(macro_name.name(), macro_name.defaultValue()) catch |err| {
                return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.InvalidMacroName, error.InvalidMacroValue => unreachable,
                };
            };
        }

        return config;
    }

    pub fn deinit(self: *TxnConfig) void {
        self.allocator.free(self.install_root);
        for (self.macros.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.macros.deinit(self.allocator);
    }

    pub fn clone(self: *const TxnConfig, allocator: std.mem.Allocator) InitError!TxnConfig {
        const root = try allocator.dupe(u8, self.install_root);
        var copy = TxnConfig{
            .allocator = allocator,
            .install_root = root,
            .macros = .empty,
        };
        errdefer copy.deinit();

        for (self.macros.items) |entry| {
            copy.setMacroByName(entry.name, entry.value) catch |err| {
                return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.InvalidMacroName, error.InvalidMacroValue => unreachable,
                };
            };
        }
        return copy;
    }

    /// Loads the conventional system and per-user declarative macro files.
    /// Missing glob patterns are expected and ignored.
    pub fn loadConventionalMacroFiles(self: *TxnConfig) LoadMacrosError!void {
        const patterns = [_][]const u8{
            "/usr/lib/rpm/macros",
            "/usr/lib/rpm/macros.d/macros.*",
            "/usr/lib/rpm/macros.d/*.macros",
            "/etc/rpm/macros.*",
            "/etc/rpm/*.macros",
            "/etc/rpm/macros",
        };
        for (patterns) |pattern| {
            try self.loadMacroGlob(pattern);
        }

        if (c.getenv("HOME")) |home_ptr| {
            const user_path = std.fmt.allocPrint(
                self.allocator,
                "{s}/.rpmmacros",
                .{std.mem.span(home_ptr)},
            ) catch return error.OutOfMemory;
            defer self.allocator.free(user_path);
            try self.loadMacroGlob(user_path);
        }
    }

    pub fn installRoot(self: *const TxnConfig) []const u8 {
        return self.install_root;
    }

    /// Returns the effective value for a known macro.
    pub fn value(self: *const TxnConfig, macro_name: Macro) []const u8 {
        return self.rawValue(macro_name.name()).?;
    }

    /// Returns the unexpanded value of an arbitrary macro.
    pub fn rawValue(self: *const TxnConfig, name: []const u8) ?[]const u8 {
        const index = self.findMacro(name) orelse return null;
        return self.macros.items[index].value;
    }

    /// Applies a raw rpmdefine string. Arbitrary definitions are retained
    /// because native path macros may reference package- or user-defined
    /// values recursively.
    pub fn applyRpmDefine(
        self: *TxnConfig,
        text: []const u8,
    ) (ParseDefineError || SetMacroError)!bool {
        const parsed = try parseRpmDefine(text);
        try self.setMacroByName(parsed.name, parsed.value);
        return true;
    }

    /// Overrides a known macro with a caller-provided value.
    pub fn setMacro(
        self: *TxnConfig,
        macro_name: Macro,
        macro_value: []const u8,
    ) SetMacroError!void {
        try self.setMacroByName(macro_name.name(), macro_value);
    }

    /// Overrides or creates an arbitrary macro without expanding its value.
    pub fn setMacroByName(
        self: *TxnConfig,
        name: []const u8,
        macro_value: []const u8,
    ) SetMacroError!void {
        const normalized_name = std.mem.trim(u8, name, " \t\r\n");
        if (!isValidMacroName(normalized_name)) return error.InvalidMacroName;

        const normalized_value = std.mem.trim(u8, macro_value, " \t\r\n");
        if (normalized_value.len == 0) return error.InvalidMacroValue;

        const replacement = try self.allocator.dupe(u8, normalized_value);
        errdefer self.allocator.free(replacement);

        if (self.findMacro(normalized_name)) |index| {
            const old = self.macros.items[index].value;
            self.macros.items[index].value = replacement;
            self.allocator.free(old);
            return;
        }

        const owned_name = try self.allocator.dupe(u8, normalized_name);
        errdefer self.allocator.free(owned_name);
        try self.macros.append(self.allocator, .{
            .name = owned_name,
            .value = replacement,
        });
    }

    /// Applies the declarative, single-line subset used by conventional rpm
    /// macro files. Control directives and executable expressions remain
    /// unevaluated and are ignored unless a retained macro references them.
    pub fn applyMacroFileBytes(
        self: *TxnConfig,
        bytes: []const u8,
    ) SetMacroError!void {
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        var conditional_depth: usize = 0;
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len < 2 or line[0] != '%' or line[1] == '#') continue;

            var definition = line[1..];
            if (std.mem.startsWith(u8, definition, "define ") or
                std.mem.startsWith(u8, definition, "global "))
            {
                definition = definition[std.mem.indexOfScalar(u8, definition, ' ').? + 1 ..];
            } else if (definition[0] == '{') {
                continue;
            }

            if (std.mem.eql(u8, definition, "endif")) {
                conditional_depth -|= 1;
                continue;
            }

            const split = std.mem.indexOfAny(u8, definition, " \t") orelse continue;
            const name = definition[0..split];
            if (isConditionalStart(name)) {
                conditional_depth += 1;
                continue;
            }
            if (conditional_depth != 0) continue;
            if (isMacroControlDirective(name)) continue;
            const macro_value = std.mem.trim(u8, definition[split..], " \t\r");
            if (!isValidMacroName(name) or macro_value.len == 0) continue;
            try self.setMacroByName(name, macro_value);
        }
    }

    fn loadMacroGlob(self: *TxnConfig, pattern: []const u8) LoadMacrosError!void {
        const pattern_z = self.allocator.dupeZ(u8, pattern) catch return error.OutOfMemory;
        defer self.allocator.free(pattern_z);

        var matches: c.glob_t = std.mem.zeroes(c.glob_t);
        const rc = c.glob(pattern_z.ptr, 0, null, &matches);
        if (rc == c.GLOB_NOMATCH) return;
        if (rc != 0) return error.GlobFailed;
        defer c.globfree(&matches);

        for (0..matches.gl_pathc) |index| {
            try self.loadMacroFile(std.mem.span(matches.gl_pathv[index]));
        }
    }

    fn loadMacroFile(self: *TxnConfig, path: []const u8) LoadMacrosError!void {
        const path_z = self.allocator.dupeZ(u8, path) catch return error.OutOfMemory;
        defer self.allocator.free(path_z);

        const file = c.fopen(path_z.ptr, "rb") orelse return error.MacroFileOpenFailed;
        defer _ = c.fclose(file);
        if (c.fseek(file, 0, c.SEEK_END) != 0) return error.MacroFileReadFailed;
        const file_size = c.ftell(file);
        if (file_size < 0) return error.MacroFileReadFailed;
        c.rewind(file);

        const bytes = self.allocator.alloc(u8, @intCast(file_size)) catch {
            return error.OutOfMemory;
        };
        defer self.allocator.free(bytes);
        if (bytes.len != 0 and c.fread(bytes.ptr, 1, bytes.len, file) != bytes.len) {
            return error.MacroFileReadFailed;
        }
        try self.applyMacroFileBytes(bytes);
    }

    /// Expands one known macro into caller-owned memory.
    pub fn expandMacroAlloc(
        self: *const TxnConfig,
        allocator: std.mem.Allocator,
        macro_name: Macro,
    ) ExpandError![]u8 {
        return self.expandNameAlloc(allocator, macro_name.name());
    }

    /// Expands an arbitrary macro into caller-owned memory.
    pub fn expandNameAlloc(
        self: *const TxnConfig,
        allocator: std.mem.Allocator,
        name: []const u8,
    ) ExpandError![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        var stack: [MAX_EXPANSION_DEPTH][]const u8 = undefined;
        try self.appendExpandedMacro(allocator, &output, name, &stack, 0);
        return output.toOwnedSlice(allocator);
    }

    /// Expands macro expressions embedded in arbitrary caller-supplied text.
    pub fn expandTextAlloc(
        self: *const TxnConfig,
        allocator: std.mem.Allocator,
        text: []const u8,
    ) ExpandError![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        var stack: [MAX_EXPANSION_DEPTH][]const u8 = undefined;
        var cursor: usize = 0;
        while (std.mem.indexOfPos(u8, text, cursor, "%{")) |start| {
            try output.appendSlice(allocator, text[cursor..start]);
            const close = std.mem.indexOfScalarPos(u8, text, start + 2, '}') orelse {
                return error.InvalidMacroExpression;
            };
            const expression = text[start + 2 .. close];
            if (expression.len == 0) return error.InvalidMacroExpression;
            if (std.mem.startsWith(u8, expression, "getenv:")) {
                const env_name = expression["getenv:".len..];
                if (!isValidMacroName(env_name)) {
                    return error.InvalidMacroExpression;
                }
                const env_name_z = try allocator.dupeZ(u8, env_name);
                defer allocator.free(env_name_z);
                if (c.getenv(env_name_z.ptr)) |env_value| {
                    try output.appendSlice(allocator, std.mem.span(env_value));
                }
            } else if (self.rawValue(expression) == null) {
                try output.appendSlice(allocator, text[start .. close + 1]);
            } else {
                try self.appendExpandedMacro(
                    allocator,
                    &output,
                    expression,
                    &stack,
                    0,
                );
            }
            cursor = close + 1;
        }
        try output.appendSlice(allocator, text[cursor..]);
        return output.toOwnedSlice(allocator);
    }

    /// Resolves a known install-root-relative macro to a concrete path.
    pub fn resolvePath(
        self: *const TxnConfig,
        macro_name: Macro,
        buf: []u8,
    ) ResolvePathError![]const u8 {
        if (!macro_name.isInstallRootRelative()) return error.NotPathMacro;
        const expanded = try self.expandMacroAlloc(self.allocator, macro_name);
        defer self.allocator.free(expanded);
        return buildInstallRootedPath(buf, self.install_root, expanded);
    }

    /// Resolves the sqlite rpmdb file path under the configured root.
    pub fn resolveRpmDbSqlitePath(
        self: *const TxnConfig,
        buf: []u8,
    ) (ExpandError || error{PathTooLong})![]const u8 {
        const expanded = try self.expandMacroAlloc(self.allocator, .dbpath);
        defer self.allocator.free(expanded);
        return buildRpmDbSqlitePath(buf, self.install_root, expanded);
    }

    fn findMacro(self: *const TxnConfig, name: []const u8) ?usize {
        for (self.macros.items, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.name, name)) return index;
        }
        return null;
    }

    fn appendExpandedMacro(
        self: *const TxnConfig,
        allocator: std.mem.Allocator,
        output: *std.ArrayList(u8),
        name: []const u8,
        stack: *[MAX_EXPANSION_DEPTH][]const u8,
        depth: usize,
    ) ExpandError!void {
        if (depth >= MAX_EXPANSION_DEPTH) return error.ExpansionTooDeep;
        for (stack[0..depth]) |ancestor| {
            if (std.mem.eql(u8, ancestor, name)) return error.ExpansionCycle;
        }

        const raw = self.rawValue(name) orelse return error.UnknownMacro;
        stack[depth] = name;
        try self.appendExpandedText(allocator, output, raw, stack, depth + 1);
    }

    fn appendExpandedText(
        self: *const TxnConfig,
        allocator: std.mem.Allocator,
        output: *std.ArrayList(u8),
        text: []const u8,
        stack: *[MAX_EXPANSION_DEPTH][]const u8,
        depth: usize,
    ) ExpandError!void {
        var cursor: usize = 0;
        while (std.mem.indexOfPos(u8, text, cursor, "%{")) |start| {
            try output.appendSlice(allocator, text[cursor..start]);
            const close = std.mem.indexOfScalarPos(u8, text, start + 2, '}') orelse {
                return error.InvalidMacroExpression;
            };
            const expression = text[start + 2 .. close];
            if (expression.len == 0) return error.InvalidMacroExpression;

            if (std.mem.startsWith(u8, expression, "getenv:")) {
                const env_name = expression["getenv:".len..];
                if (!isValidMacroName(env_name)) return error.InvalidMacroExpression;
                const env_name_z = try allocator.dupeZ(u8, env_name);
                defer allocator.free(env_name_z);
                if (c.getenv(env_name_z.ptr)) |env_value| {
                    try output.appendSlice(allocator, std.mem.span(env_value));
                }
            } else {
                if (std.mem.indexOfScalar(u8, expression, ':') != null or
                    !isValidMacroName(expression))
                {
                    return error.InvalidMacroExpression;
                }
                try self.appendExpandedMacro(allocator, output, expression, stack, depth);
            }
            cursor = close + 1;
        }
        try output.appendSlice(allocator, text[cursor..]);
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

fn isValidMacroName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |ch| {
        if (!(std.ascii.isAlphanumeric(ch) or ch == '_')) return false;
    }
    return true;
}

fn isMacroControlDirective(name: []const u8) bool {
    const directives = [_][]const u8{
        "if",
        "ifarch",
        "ifnarch",
        "ifos",
        "ifnos",
        "else",
        "endif",
        "include",
        "load",
        "trace",
        "dump",
    };
    for (directives) |directive| {
        if (std.mem.eql(u8, name, directive)) return true;
    }
    return false;
}

fn isConditionalStart(name: []const u8) bool {
    return std.mem.eql(u8, name, "if") or
        std.mem.eql(u8, name, "ifarch") or
        std.mem.eql(u8, name, "ifnarch") or
        std.mem.eql(u8, name, "ifos") or
        std.mem.eql(u8, name, "ifnos");
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

test "TxnConfig retains arbitrary rpmdefines" {
    var cfg = try TxnConfig.init(std.testing.allocator, "");
    defer cfg.deinit();

    try std.testing.expect(try cfg.applyRpmDefine("_foo /bar"));
    try std.testing.expectEqualStrings("/bar", cfg.rawValue("_foo").?);
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

test "TxnConfig recursively expands arbitrary macros" {
    var cfg = try TxnConfig.init(std.testing.allocator, "/sysroot");
    defer cfg.deinit();

    _ = try cfg.applyRpmDefine("name demo");
    _ = try cfg.applyRpmDefine("_topdir /build/%{name}");
    _ = try cfg.applyRpmDefine("_specdir %{_topdir}/specs");

    const expanded = try cfg.expandMacroAlloc(std.testing.allocator, .specdir);
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("/build/demo/specs", expanded);

    var buf: [256]u8 = undefined;
    const rooted = try cfg.resolvePath(.specdir, &buf);
    try std.testing.expectEqualStrings("/sysroot/build/demo/specs", rooted);
}

test "TxnConfig rejects cycles and unsupported expressions" {
    var cfg = try TxnConfig.init(std.testing.allocator, "");
    defer cfg.deinit();

    _ = try cfg.applyRpmDefine("one %{two}");
    _ = try cfg.applyRpmDefine("two %{one}");
    try std.testing.expectError(
        error.ExpansionCycle,
        cfg.expandNameAlloc(std.testing.allocator, "one"),
    );

    _ = try cfg.applyRpmDefine("scripted %{lua:print('no')}");
    try std.testing.expectError(
        error.InvalidMacroExpression,
        cfg.expandNameAlloc(std.testing.allocator, "scripted"),
    );
}

test "TxnConfig parses declarative macro file entries" {
    var cfg = try TxnConfig.init(std.testing.allocator, "");
    defer cfg.deinit();

    try cfg.applyMacroFileBytes(
        \\# comment
        \\%_topdir /native/build
        \\%global package_name demo
        \\%define derived %{package_name}-value
        \\%if 0
        \\%_topdir /ignored/control
        \\%endif
        \\%_specdir /native/specs
    );

    try std.testing.expectEqualStrings("/native/build", cfg.value(.topdir));
    try std.testing.expectEqualStrings("/native/specs", cfg.value(.specdir));
    const expanded = try cfg.expandNameAlloc(std.testing.allocator, "derived");
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("demo-value", expanded);
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
