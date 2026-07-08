//! tdnf build script (replacement for the former CMake build).
//!
//! Produces the same set of artifacts the CMake build did:
//!   * static libs: common, tdnfsolv, tdnfllconf, jsondump, tdnfhistory
//!   * shared libs: libtdnf.so (SOVERSION=3), libtdnfcli.so (SOVERSION=3)
//!   * executables: tdnf, tdnf-config, tdnf-history-util, jsondumptest
//!   * plugins:     libtdnfmetalink.so, libtdnfrepogpgcheck.so
//!
//! All compilation goes through `zig cc` (clang from Zig's bundled LLVM).
//! GCC-only warnings from the former cmake/CFlags.cmake were removed; the
//! retained set is the strict subset clang accepts.

const std = @import("std");
const Build = std.Build;
const LazyPath = Build.LazyPath;
const ResolvedTarget = Build.ResolvedTarget;
const OptimizeMode = std.builtin.OptimizeMode;

const project_name = "tdnf";
const default_project_version = "4.0.0";
const default_project_semver: std.SemanticVersion = .{ .major = 4, .minor = 0, .patch = 0 };

/// Warnings + hardening flags from the former cmake/CFlags.cmake, filtered
/// to the strict set clang accepts. GCC-only warnings have been removed.
const tdnf_cflags = [_][]const u8{
    "-Wall",
    "-Wundef",
    "-Wstrict-prototypes",
    "-Wno-trigraphs",
    "-Werror-implicit-function-declaration",
    "-Wdeclaration-after-statement",
    "-Wvla",
    "-Wno-format-security",
    "-Wno-sign-compare",
    "-Wextra",
    "-Werror",
    "-Wformat=2",
    "-Wshadow",
    "-Wmissing-prototypes",
    "-Wold-style-definition",
    "-Wmissing-declarations",
    "-Wredundant-decls",
    "-Wcast-align",
    "-Wpointer-arith",
    "-Wwrite-strings",
    "-Waggregate-return",
    "-Winit-self",
    "-Wnull-dereference",
    "-Walloca",
    "-fno-strict-aliasing",
    "-fno-common",
    "-fno-delete-null-pointer-checks",
    "-fstack-protector-strong",
    "-D_XOPEN_SOURCE=500",
    "-D_DEFAULT_SOURCE",
};

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -Dversion overrides the version baked into the artifacts (libtdnf.so
    // SOVERSION, tdnf --version output, generated config.h). Used by the
    // release workflow to pin the binary's version to the git tag.
    const version_override = b.option(
        []const u8,
        "version",
        "Override project version (default: " ++ default_project_version ++ ")",
    );
    const project_version: []const u8 = version_override orelse default_project_version;
    const project_semver: std.SemanticVersion = if (version_override) |v|
        std.SemanticVersion.parse(v) catch
            std.debug.panic("invalid -Dversion='{s}' (expected semantic version)", .{v})
    else
        default_project_semver;

    const history_db_dir = b.option(
        []const u8,
        "history-db-dir",
        "Directory for tdnf history database (default: /var/lib/tdnf)",
    ) orelse "/var/lib/tdnf";
    const systemd_dir = b.option(
        []const u8,
        "systemd-dir",
        "systemd unit install directory (relative to prefix, default: lib/systemd/system)",
    ) orelse "lib/systemd/system";
    const motdgen_dir = b.option(
        []const u8,
        "motdgen-dir",
        "motd generator directory (relative to prefix, default: etc/motdgen.d)",
    ) orelse "etc/motdgen.d";
    const sysconf_dir = b.option(
        []const u8,
        "sysconfdir",
        "System configuration directory (relative to prefix, default: etc)",
    ) orelse "etc";
    const plugin_dir_rel = b.option(
        []const u8,
        "plugin-dir",
        "Plugin install directory (relative to prefix, default: lib/tdnf-plugins)",
    ) orelse "lib/tdnf-plugins";

    // Opt-in: replace librpm's signature verifier (rpmVerifySignatures)
    // with rpmzig's pure-Zig OpenPGP verifier. Compiles
    // client/gpgcheck_zig.c plus rpmzig/verify_pure.c into libtdnf.
    // Default false — does not change observable behaviour.
    const rpmzig_verify = b.option(
        bool,
        "rpmzig-verify",
        "Replace librpm signature verification with rpmzig's pure-Zig OpenPGP verifier (default false)",
    ) orelse false;

    const prefix = b.install_prefix;
    const libdir = "lib";
    const full_libdir = b.fmt("{s}/{s}", .{ prefix, libdir });
    // `b.install_prefix` is the literal `--prefix` argument (e.g. `./out`)
    // and is left relative when the caller passes a relative path — unlike
    // the default `zig-out`, which build.zig resolves to an absolute path
    // itself. pytest runs with cwd=`pytests/`, so a relative prefix baked
    // into pytests/config.json (`build_dir`, `bin_dir`, ...) would resolve
    // against the wrong directory. Make it absolute, anchored at the
    // build root (zig build is always invoked from there in practice).
    const abs_prefix = if (std.fs.path.isAbsolute(prefix))
        prefix
    else
        b.pathJoin(&.{ b.build_root.path.?, prefix });
    // Vendored sqlite backs the Zig-side history and rpmdb code paths.
    const sqlite_dep = b.dependency("sqlite", .{});

    const build_with_rpm_6x = detectRpm6(b);
    if (build_with_rpm_6x) {
        std.log.info("rpm >= 6.0 detected; enabling BUILD_WITH_RPM_6X", .{});
    }

    // ----- generated headers (written into source tree to match the CMake
    //       layout, which avoids the "two config.h" search-order problem).
    //       These files are listed in .gitignore. -----

    writeTemplate(b, "client/config.h.in", "client/config.h", &.{
        .{ .key = "PROJECT_NAME", .value = project_name },
        .{ .key = "VERSION", .value = project_version },
        .{ .key = "CMAKE_INSTALL_FULL_LIBDIR", .value = full_libdir },
    });
    writeTemplate(b, "history/config.h.in", "history/config.h", &.{
        .{ .key = "HISTORY_DB_DIR", .value = history_db_dir },
    });
    writeTemplate(b, "plugins/metalink/config.h.in", "plugins/metalink/config.h", &.{
        .{ .key = "PROJECT_NAME", .value = "tdnfmetalink" },
        .{ .key = "PROJECT_VERSION", .value = project_version },
    });
    writeTemplate(b, "plugins/repogpgcheck/config.h.in", "plugins/repogpgcheck/config.h", &.{
        .{ .key = "PROJECT_NAME", .value = "tdnfrepogpgcheck" },
        .{ .key = "PROJECT_VERSION", .value = project_version },
    });

    // pytests/mount-small-cache is referenced by tests/test_cache.py; ship a
    // ready-to-run copy in the source tree (gitignored) so `pytest -v` works
    // without an extra configure step.
    writeTemplate(b, "pytests/mount-small-cache.in", "pytests/mount-small-cache", &.{
        .{ .key = "CMAKE_CURRENT_BINARY_DIR", .value = abs_prefix },
    });

    // pytests/config.json: written directly into the source tree (gitignored,
    // like the config.h files above) via writeTemplate rather than
    // addConfigHeader, for two reasons: (1) addConfigHeader's autoconf_at
    // style prepends a "generated by ConfigHeader" comment line, which is
    // valid in a C header but makes the output invalid JSON — conftest.py's
    // `json.load()` can't parse a leading `/* ... */` comment; (2) conftest.py
    // (`TestUtils.__init__`) reads config.json from the same directory as
    // conftest.py itself (`pytests/config.json`), not from the install
    // prefix, so installing it under `<prefix>/pytests-runtime/` (the old
    // approach) left pytest unable to find it at all. `abs_prefix` (an
    // absolute form of `b.install_prefix`, the resolved `--prefix` value) is
    // used here rather than a hardcoded `zig-out` so this works with the
    // documented `--prefix ./out` build invocation, not just the default
    // `zig-out`, and resolves correctly regardless of pytest's cwd.
    writeTemplate(b, "pytests/config.json.in", "pytests/config.json", &.{
        .{ .key = "PROJECT_NAME", .value = project_name },
        .{ .key = "VERSION", .value = project_version },
        .{ .key = "CMAKE_SOURCE_DIR", .value = b.build_root.path.? },
        .{ .key = "CMAKE_CURRENT_BINARY_DIR", .value = abs_prefix },
        .{ .key = "CMAKE_BINARY_DIR", .value = abs_prefix },
        .{ .key = "PLUGIN_PATH", .value = b.fmt("{s}/{s}", .{ abs_prefix, plugin_dir_rel }) },
    });

    // ----- generated text files (autoconf_at style: @VAR@ only) ----- //
    // autoconf_at leaves `${...}` literal, which is required for .pc files.

    const tdnf_pc = b.addConfigHeader(.{
        .style = .{ .autoconf_at = b.path("client/tdnf.pc.in") },
        .include_path = "tdnf.pc",
    }, .{
        .CMAKE_INSTALL_PREFIX = prefix,
        .CMAKE_INSTALL_LIBDIR = libdir,
        .PROJECT_VERSION = project_version,
    });

    const tdnf_cli_libs_pc = b.addConfigHeader(.{
        .style = .{ .autoconf_at = b.path("tools/cli/lib/tdnf-cli-libs.pc.in") },
        .include_path = "tdnf-cli-libs.pc",
    }, .{
        .CMAKE_INSTALL_PREFIX = prefix,
        .CMAKE_INSTALL_LIBDIR = libdir,
        .PROJECT_VERSION = project_version,
    });

    const tdnf_automatic = b.addConfigHeader(.{
        .style = .{ .autoconf_at = b.path("bin/tdnf-automatic.in") },
        .include_path = "tdnf-automatic",
    }, .{
        .VERSION = project_version,
    });

    const zig_test_step = b.step("test", "Run Zig unit tests");

    // ----- static libraries ----- //

    const common_lib = blk: {
        const mod = b.createModule(.{
            .root_source_file = b.path("common/common.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("include"));
        mod.addIncludePath(b.path("common"));
        mod.addCSourceFiles(.{
            .root = b.path("common"),
            .files = &.{ "memory_printf_shim.c", "log_shim.c", "joinpath_shim.c" },
            .flags = &tdnf_cflags,
        });
        const lib = b.addLibrary(.{
            .name = "common",
            .linkage = .static,
            .root_module = mod,
        });
        break :blk lib;
    };

    const llconf_lib = staticLib(b, target, optimize, .{
        .name = "tdnfllconf",
        .root = "llconf",
        .files = &.{ "entry.c", "ini.c", "lines.c", "modules.c", "nodes.c", "strutils.c" },
    });

    const jsondump_lib = blk: {
        const mod = b.createModule(.{
            .root_source_file = b.path("jsondump/jsondump.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("include"));
        mod.addIncludePath(b.path("jsondump"));
        mod.addCSourceFiles(.{
            .root = b.path("jsondump"),
            .files = &.{"fmt_shim.c"},
            .flags = &tdnf_cflags,
        });
        const lib = b.addLibrary(.{
            .name = "jsondump",
            .linkage = .static,
            .root_module = mod,
        });
        break :blk lib;
    };

    const solv_lib = staticLib(b, target, optimize, .{
        .name = "tdnfsolv",
        .root = "solv",
        .files = &.{ "tdnfpackage.c", "tdnfpool.c", "tdnfquery.c", "tdnfrepo.c", "simplequery.c" },
    });

    const history_lib = blk: {
        const mod = b.createModule(.{
            .root_source_file = b.path("history/history_zig.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        const lib = b.addLibrary(.{
            .name = "tdnfhistory",
            .linkage = .static,
            .root_module = mod,
        });
        break :blk lib;
    };

    const history_zig_lib = history_lib;

    const cli_zig_lib = blk: {
        const mod = b.createModule(.{
            .root_source_file = b.path("tools/cli/lib/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("include"));
        mod.addIncludePath(b.path("llconf"));
        mod.addIncludePath(b.path("tools/cli"));
        mod.addIncludePath(b.path("tools/cli/lib"));
        const lib = b.addLibrary(.{
            .name = "tdnfclizig",
            .linkage = .static,
            .root_module = mod,
        });
        break :blk lib;
    };

    // ----- rpmzig (Zig-side librpm replacement, see plan-replace-librpm.md) //

    const rpmzig_lib = blk: {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/rpmdb.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        const lib = b.addLibrary(.{
            .name = "tdnfrpmzig",
            .linkage = .static,
            .root_module = mod,
        });
        break :blk lib;
    };

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("common/common.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("common"));
        test_mod.addCSourceFiles(.{
            .root = b.path("common"),
            .files = &.{ "memory_printf_shim.c", "memory_test_shim.c", "log_shim.c", "joinpath_shim.c", "utils_test_shim.c" },
            .flags = &tdnf_cflags,
        });
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    // `zig build test` runs the rpmzig Zig unit tests (currently just
    // path-building; the FFI surface is smoke-tested via
    // tdnf-rpmdb-count against a live rpmdb).
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/rpmdb.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("tools/cli/lib/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("llconf"));
        test_mod.addIncludePath(b.path("tools/cli"));
        test_mod.addIncludePath(b.path("tools/cli/lib"));
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    // Smoke-test the vendored zig-sqlite dependency in isolation.
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("history/sqlite_smoke_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    // Build and exercise the Zig history backend unit tests.
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("history/history_zig_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const history_zig_test_step = b.step(
            "history-zig-test",
            "Run standalone Zig history backend unit tests",
        );
        history_zig_test_step.dependOn(&history_zig_lib.step);
        history_zig_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&history_zig_lib.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    // tdnf-rpmdb-count: smoke-test exe for the rpmzig C ABI.
    {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("rpmzig"));
        mod.addCSourceFiles(.{
            .root = b.path("rpmzig"),
            .files = &.{"count_main.c"},
            .flags = &tdnf_cflags,
        });
        mod.linkLibrary(rpmzig_lib);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpmdb-count",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // tdnf-rpmdb-list: smoke-test exe for the rpmzig iterator.
    {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("rpmzig"));
        mod.addCSourceFiles(.{
            .root = b.path("rpmzig"),
            .files = &.{"list_main.c"},
            .flags = &tdnf_cflags,
        });
        mod.linkLibrary(rpmzig_lib);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpmdb-list",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // tdnf-rpm-info: smoke-test exe for the rpmzig `.rpm` file parser.
    {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("rpmzig"));
        mod.addCSourceFiles(.{
            .root = b.path("rpmzig"),
            .files = &.{"info_main.c"},
            .flags = &tdnf_cflags,
        });
        mod.linkLibrary(rpmzig_lib);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-info",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // tdnf-rpmdb-pubkeys: smoke-test exe for the rpmdb gpg-pubkey
    // iterator. Lists every rpm-imported public key.
    {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("rpmzig"));
        mod.addCSourceFiles(.{
            .root = b.path("rpmzig"),
            .files = &.{"pubkeys_main.c"},
            .flags = &tdnf_cflags,
        });
        mod.linkLibrary(rpmzig_lib);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpmdb-pubkeys",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // tdnf-rpm-files: smoke-test exe for the cpio walker + payload
    // decompressor.
    {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("rpmzig"));
        mod.addCSourceFiles(.{
            .root = b.path("rpmzig"),
            .files = &.{"files_main.c"},
            .flags = &tdnf_cflags,
        });
        mod.linkLibrary(rpmzig_lib);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-files",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // tdnf-rpm-verify: smoke-test exe for the pure-Zig signature
    // verifier. Builds the same in-memory --key / --rpmdb keyring
    // path libtdnf uses under -Drpmzig-verify=true.
    {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("rpmzig"));
        mod.addCSourceFiles(.{
            .root = b.path("rpmzig"),
            .files = &.{ "verify_main.c", "verify_pure.c" },
            .flags = &tdnf_cflags,
        });
        mod.linkLibrary(rpmzig_lib);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-verify",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // ----- libtdnf (shared) ----- //

    const tdnf_so_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    tdnf_so_mod.addIncludePath(b.path("include"));
    tdnf_so_mod.addIncludePath(b.path("client"));
    if (build_with_rpm_6x) tdnf_so_mod.addCMacro("BUILD_WITH_RPM_6X", "1");
    if (rpmzig_verify) {
        // TDNF_RPMZIG_VERIFY gates the rpmzig entry point
        // (TDNFRpmzigVerify) in client/gpgcheck.c. When enabled,
        // libtdnf routes package signature verification through the
        // pure-Zig rpmzig path.
        tdnf_so_mod.addCMacro("TDNF_RPMZIG_VERIFY", "1");
        tdnf_so_mod.addIncludePath(b.path("rpmzig"));
    }
    tdnf_so_mod.addCSourceFiles(.{
        .root = b.path("client"),
        .files = &.{
            "api.c",      "client.c",   "config.c",    "eventdata.c",
            "goal.c",     "gpgcheck.c", "init.c",      "packageutils.c",
            "plugins.c",  "repo.c",     "repoutils.c", "remoterepo.c",
            "repolist.c", "resolve.c",  "rpmtrans.c",  "updateinfo.c",
            "utils.c",    "history.c",  "varsdir.c",
        },
        .flags = &tdnf_cflags,
    });
    if (rpmzig_verify) {
        // gpgcheck_zig.c is the single C-side entry point into the
        // rpmzig verifier; verify_pure.c bridges into rpmzig/pgp
        // without any gpgme dependency.
        tdnf_so_mod.addCSourceFiles(.{
            .root = b.path("client"),
            .files = &.{"gpgcheck_zig.c"},
            .flags = &tdnf_cflags,
        });
        tdnf_so_mod.addCSourceFiles(.{
            .root = b.path("rpmzig"),
            .files = &.{"verify_pure.c"},
            .flags = &tdnf_cflags,
        });
    }
    tdnf_so_mod.linkLibrary(common_lib);
    tdnf_so_mod.linkLibrary(solv_lib);
    tdnf_so_mod.linkLibrary(history_lib);
    tdnf_so_mod.linkLibrary(llconf_lib);
    tdnf_so_mod.linkLibrary(rpmzig_lib);
    linkSystem(tdnf_so_mod, &.{ "rpm", "libsolv", "libsolvext", "libcurl", "sqlite3" });

    const libtdnf = b.addLibrary(.{
        .name = "tdnf",
        .linkage = .dynamic,
        .root_module = tdnf_so_mod,
        .version = project_semver,
    });
    b.installArtifact(libtdnf);

    // ----- libtdnfcli (shared) ----- //

    const cli_so_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    cli_so_mod.addIncludePath(b.path("include"));
    cli_so_mod.addIncludePath(b.path("tools/cli"));
    cli_so_mod.addCSourceFiles(.{
        .root = b.path("tools/cli/lib"),
        .files = &.{
            "api.c",               "help.c",               "installcmd.c",
            "options.c",           "output.c",             "parseargs.c",
            "updateinfocmd.c",
        },
        .flags = &tdnf_cflags,
    });
    cli_so_mod.linkLibrary(cli_zig_lib);
    cli_so_mod.linkLibrary(jsondump_lib);

    const libtdnfcli = b.addLibrary(.{
        .name = "tdnfcli",
        .linkage = .dynamic,
        .root_module = cli_so_mod,
        .version = project_semver,
    });
    b.installArtifact(libtdnfcli);

    // ----- executables ----- //

    // tdnf
    const tdnf_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    tdnf_mod.addIncludePath(b.path("include"));
    tdnf_mod.addIncludePath(b.path("tools/cli"));
    tdnf_mod.addCSourceFiles(.{
        .root = b.path("tools/cli"),
        .files = &.{"main.c"},
        .flags = &tdnf_cflags,
    });
    tdnf_mod.linkLibrary(libtdnfcli);
    tdnf_mod.linkLibrary(libtdnf);
    const tdnf_exe = b.addExecutable(.{
        .name = "tdnf",
        .root_module = tdnf_mod,
    });
    hardenExe(tdnf_exe);
    b.installArtifact(tdnf_exe);

    // tdnf-config
    const tdnf_config_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    tdnf_config_mod.addIncludePath(b.path("include"));
    tdnf_config_mod.addCSourceFiles(.{
        .root = b.path("tools/config"),
        .files = &.{"main.c"},
        .flags = &tdnf_cflags,
    });
    tdnf_config_mod.linkLibrary(llconf_lib);
    tdnf_config_mod.linkLibrary(jsondump_lib);
    linkSystem(tdnf_config_mod, &.{"dl"});
    const tdnf_config_exe = b.addExecutable(.{
        .name = "tdnf-config",
        .root_module = tdnf_config_mod,
    });
    hardenExe(tdnf_config_exe);
    b.installArtifact(tdnf_config_exe);

    // tdnf-history-util — librpm-free as of T1 PR #5; links the
    // vendored-SQLite history and rpmzig static libs.
    const history_util_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    history_util_mod.addIncludePath(b.path("include"));
    history_util_mod.addIncludePath(b.path("history"));
    history_util_mod.addCSourceFiles(.{
        .root = b.path("history"),
        .files = &.{"main.c"},
        .flags = &tdnf_cflags,
    });
    history_util_mod.linkLibrary(history_lib);
    history_util_mod.linkLibrary(rpmzig_lib);
    const history_util_exe = b.addExecutable(.{
        .name = "tdnf-history-util",
        .root_module = history_util_mod,
    });
    hardenExe(history_util_exe);
    const install_history_util = b.addInstallArtifact(history_util_exe, .{
        .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
    });
    b.getInstallStep().dependOn(&install_history_util.step);

    // jsondumptest
    const jsondump_test_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    jsondump_test_mod.addIncludePath(b.path("include"));
    jsondump_test_mod.addIncludePath(b.path("jsondump"));
    jsondump_test_mod.addCSourceFiles(.{
        .root = b.path("jsondump"),
        .files = &.{"test.c"},
        .flags = &tdnf_cflags,
    });
    jsondump_test_mod.linkLibrary(jsondump_lib);
    const jsondump_test_exe = b.addExecutable(.{
        .name = "jsondumptest",
        .root_module = jsondump_test_mod,
    });
    hardenExe(jsondump_test_exe);
    b.installArtifact(jsondump_test_exe);

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("plugins/metalink/xml.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addIncludePath(b.path("plugins/metalink"));
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    // ----- plugins ----- //

    const metalink_xml_mod = b.createModule(.{
        .root_source_file = b.path("plugins/metalink/xml.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    const metalink_xml_lib = b.addLibrary(.{
        .name = "tdnfmetalinkxml",
        .linkage = .static,
        .root_module = metalink_xml_mod,
    });

    const metalink_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    metalink_mod.addIncludePath(b.path("include"));
    metalink_mod.addIncludePath(b.path("plugins/metalink"));
    metalink_mod.addCSourceFiles(.{
        .root = b.path("plugins/metalink"),
        .files = &.{ "api.c", "metalink.c", "utils.c", "list.c" },
        .flags = &tdnf_cflags,
    });
    metalink_mod.linkLibrary(libtdnf);
    metalink_mod.linkLibrary(metalink_xml_lib);
    const metalink_plugin = b.addLibrary(.{
        .name = "tdnfmetalink",
        .linkage = .dynamic,
        .root_module = metalink_mod,
    });
    const install_metalink = b.addInstallArtifact(metalink_plugin, .{
        .dest_dir = .{ .override = .{ .custom = plugin_dir_rel } },
    });
    b.getInstallStep().dependOn(&install_metalink.step);

    const repogpgcheck_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    repogpgcheck_mod.addIncludePath(b.path("include"));
    repogpgcheck_mod.addIncludePath(b.path("plugins/repogpgcheck"));
    repogpgcheck_mod.addCSourceFiles(.{
        .root = b.path("plugins/repogpgcheck"),
        .files = &.{ "api.c", "repogpgcheck.c" },
        .flags = &tdnf_cflags,
    });
    repogpgcheck_mod.linkLibrary(libtdnf);
    linkSystem(repogpgcheck_mod, &.{"gpgme"});
    const repogpgcheck_plugin = b.addLibrary(.{
        .name = "tdnfrepogpgcheck",
        .linkage = .dynamic,
        .root_module = repogpgcheck_mod,
    });
    const install_repogpgcheck = b.addInstallArtifact(repogpgcheck_plugin, .{
        .dest_dir = .{ .override = .{ .custom = plugin_dir_rel } },
    });
    b.getInstallStep().dependOn(&install_repogpgcheck.step);

    // ----- generated text file installs ----- //

    const pkgconfig_dir: Build.InstallDir = .{ .custom = b.fmt("{s}/pkgconfig", .{libdir}) };
    b.getInstallStep().dependOn(
        &b.addInstallFileWithDir(tdnf_pc.getOutputFile(), pkgconfig_dir, "tdnf.pc").step,
    );
    b.getInstallStep().dependOn(
        &b.addInstallFileWithDir(tdnf_cli_libs_pc.getOutputFile(), pkgconfig_dir, "tdnf-cli-libs.pc").step,
    );

    const install_automatic = b.addInstallFileWithDir(tdnf_automatic.getOutputFile(), .bin, "tdnf-automatic");
    b.getInstallStep().dependOn(&install_automatic.step);
    const chmod_automatic = b.addSystemCommand(&.{ "chmod", "+x", b.getInstallPath(.bin, "tdnf-automatic") });
    chmod_automatic.step.dependOn(&install_automatic.step);
    b.getInstallStep().dependOn(&chmod_automatic.step);

    // ----- public headers ----- //

    b.installDirectory(.{
        .source_dir = b.path("include"),
        .install_dir = .header,
        .install_subdir = "tdnf",
    });

    // ----- static config files ----- //

    const tdnf_conf_dir: Build.InstallDir = .{ .custom = b.fmt("{s}/tdnf", .{sysconf_dir}) };
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(b.path("etc/tdnf/tdnf.conf"), tdnf_conf_dir, "tdnf.conf").step);
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(b.path("etc/tdnf/automatic.conf"), tdnf_conf_dir, "automatic.conf").step);

    const pluginconf_dir: Build.InstallDir = .{ .custom = b.fmt("{s}/tdnf/pluginconf.d", .{sysconf_dir}) };
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(b.path("etc/tdnf/pluginconf.d/tdnfmetalink.conf"), pluginconf_dir, "tdnfmetalink.conf").step);
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(b.path("etc/tdnf/pluginconf.d/tdnfrepogpgcheck.conf"), pluginconf_dir, "tdnfrepogpgcheck.conf").step);

    const systemd_install_dir: Build.InstallDir = .{ .custom = systemd_dir };
    for ([_][]const u8{
        "tdnf-automatic.service",
        "tdnf-automatic.timer",
        "tdnf-automatic-notifyonly.service",
        "tdnf-automatic-notifyonly.timer",
        "tdnf-automatic-install.service",
        "tdnf-automatic-install.timer",
    }) |fname| {
        b.getInstallStep().dependOn(
            &b.addInstallFileWithDir(b.path(b.fmt("etc/systemd/{s}", .{fname})), systemd_install_dir, fname).step,
        );
    }

    const motd_install_dir: Build.InstallDir = .{ .custom = motdgen_dir };
    b.getInstallStep().dependOn(
        &b.addInstallFileWithDir(b.path("etc/motdgen.d/02-tdnf-updateinfo.sh"), motd_install_dir, "02-tdnf-updateinfo.sh").step,
    );

    const completion_dir: Build.InstallDir = .{ .custom = "share/bash-completion/completions" };
    b.getInstallStep().dependOn(
        &b.addInstallFileWithDir(b.path("etc/bash_completion.d/tdnf-completion.bash"), completion_dir, "tdnf").step,
    );

    // pytests/config.json is written directly into the source tree by
    // writeTemplate() above (configure-time, like client/config.h) — no
    // install step needed; it's not an installable artifact.

    // ----- check + lint steps ----- //

    const check_step = b.step("check", "Run pytest integration tests");
    const run_pytest = b.addSystemCommand(&.{ "pytest", "-v" });
    run_pytest.setCwd(b.path("pytests"));
    run_pytest.setEnvironmentVariable(
        "LD_LIBRARY_PATH",
        b.getInstallPath(.lib, ""),
    );
    run_pytest.step.dependOn(b.getInstallStep());
    check_step.dependOn(&run_pytest.step);

    const lint_step = b.step("lint", "Run flake8 on pytests/");
    const run_flake8 = b.addSystemCommand(&.{ "flake8", "pytests" });
    run_flake8.setCwd(b.path("."));
    lint_step.dependOn(&run_flake8.step);
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

const StaticLibOpts = struct {
    name: []const u8,
    root: []const u8,
    files: []const []const u8,
};

fn staticLib(
    b: *Build,
    target: ResolvedTarget,
    optimize: OptimizeMode,
    opts: StaticLibOpts,
) *Build.Step.Compile {
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    mod.addIncludePath(b.path("include"));
    mod.addIncludePath(b.path(opts.root));
    mod.addCSourceFiles(.{
        .root = b.path(opts.root),
        .files = opts.files,
        .flags = &tdnf_cflags,
    });
    return b.addLibrary(.{
        .name = opts.name,
        .linkage = .static,
        .root_module = mod,
    });
}

fn linkSystem(mod: *Build.Module, names: []const []const u8) void {
    for (names) |n| mod.linkSystemLibrary(n, .{});
}

fn hardenExe(exe: *Build.Step.Compile) void {
    exe.pie = true;
    // link_z_relro is true by default in 0.16; -z now is not directly
    // exposed by the Compile step API, so it relies on the linker default.
    exe.link_z_relro = true;
}

/// Detect rpm >= 6.0 at configure time. Returns false if pkg-config is
/// missing, the rpm package is not registered, or the version can't be
/// parsed.
fn detectRpm6(b: *Build) bool {
    var code: u8 = undefined;
    const stdout = b.runAllowFail(
        &.{ "pkg-config", "--modversion", "rpm" },
        &code,
        .ignore,
    ) catch return false;
    const trimmed = std.mem.trim(u8, stdout, " \r\n\t");
    const v = std.SemanticVersion.parse(trimmed) catch return false;
    return v.major >= 6;
}

const TemplateVar = struct {
    key: []const u8,
    value: []const u8,
};

/// Reads a `*.in` file from `<repo>/<in_rel>`, substitutes each `@KEY@`
/// (cmake-style `@VAR@`) and `#cmakedefine FOO …` directive, and writes the
/// result to `<repo>/<out_rel>`. Output files are gitignored.
///
/// This is configure-time generation (runs every time `build.zig` is
/// evaluated). It matches the CMake build's habit of writing generated
/// `config.h` files into the source tree, which sidesteps the otherwise
/// unavoidable problem of two components both producing a header called
/// `config.h` that would shadow each other via `-I` search order.
fn writeTemplate(
    b: *Build,
    in_rel: []const u8,
    out_rel: []const u8,
    vars: []const TemplateVar,
) void {
    const io = b.graph.io;
    const root = b.build_root.handle;
    const in_bytes = root.readFileAlloc(io, in_rel, b.allocator, .limited(2 * 1024 * 1024)) catch |err|
        std.debug.panic("unable to read template '{s}': {t}", .{ in_rel, err });
    defer b.allocator.free(in_bytes);

    var out: std.array_list.Managed(u8) = .init(b.allocator);
    defer out.deinit();

    var line_it = std.mem.splitScalar(u8, in_bytes, '\n');
    var first = true;
    while (line_it.next()) |line| {
        if (!first) out.append('\n') catch @panic("OOM");
        first = false;
        renderTemplateLine(&out, line, vars);
    }

    root.writeFile(io, .{ .sub_path = out_rel, .data = out.items }) catch |err|
        std.debug.panic("unable to write generated file '{s}': {t}", .{ out_rel, err });
}

fn renderTemplateLine(
    out: *std.array_list.Managed(u8),
    line: []const u8,
    vars: []const TemplateVar,
) void {
    const trimmed = std.mem.trimStart(u8, line, " \t");
    const prefix = "#cmakedefine";
    if (std.mem.startsWith(u8, trimmed, prefix) and
        (trimmed.len == prefix.len or trimmed[prefix.len] == ' ' or trimmed[prefix.len] == '\t'))
    {
        const rest = std.mem.trim(u8, trimmed[prefix.len..], " \t");
        var name_end: usize = 0;
        while (name_end < rest.len and !std.ascii.isWhitespace(rest[name_end])) : (name_end += 1) {}
        const name = rest[0..name_end];
        const value_template = std.mem.trim(u8, rest[name_end..], " \t");

        const value = lookup(name, vars);
        if (value) |_| {
            if (value_template.len == 0) {
                appendFmt(out, "#define {s}", .{name});
            } else {
                var expanded: std.array_list.Managed(u8) = .init(out.allocator);
                defer expanded.deinit();
                substituteAtAt(&expanded, value_template, vars);
                appendFmt(out, "#define {s} {s}", .{ name, expanded.items });
            }
        } else {
            appendFmt(out, "/* #undef {s} */", .{name});
        }
        return;
    }
    substituteAtAt(out, line, vars);
}

fn appendFmt(out: *std.array_list.Managed(u8), comptime fmt: []const u8, args: anytype) void {
    const s = std.fmt.allocPrint(out.allocator, fmt, args) catch @panic("OOM");
    defer out.allocator.free(s);
    out.appendSlice(s) catch @panic("OOM");
}

fn substituteAtAt(out: *std.array_list.Managed(u8), text: []const u8, vars: []const TemplateVar) void {
    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '@') {
            if (std.mem.indexOfScalarPos(u8, text, i + 1, '@')) |end| {
                const key = text[i + 1 .. end];
                if (isValidKey(key)) {
                    if (lookup(key, vars)) |v| {
                        out.appendSlice(v) catch @panic("OOM");
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        out.append(text[i]) catch @panic("OOM");
        i += 1;
    }
}

fn isValidKey(key: []const u8) bool {
    if (key.len == 0) return false;
    for (key) |c| {
        switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '_' => {},
            else => return false,
        }
    }
    return true;
}

fn lookup(key: []const u8, vars: []const TemplateVar) ?[]const u8 {
    for (vars) |v| if (std.mem.eql(u8, v.key, key)) return v.value;
    return null;
}

comptime {
    _ = LazyPath;
}
