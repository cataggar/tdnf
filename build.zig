//! tdnf build script (replacement for the former CMake build).
//!
//! Produces the same set of artifacts the CMake build did:
//!   * static libs: common, tdnfllconf, jsondump, tdnfhistory
//!   * shared libs: libtdnf.so (SOVERSION=4), libtdnfcli.so (SOVERSION=4)
//!   * executables: tdnf, tdnf-config, tdnf-history-util, jsondumptest
//!   * built-ins:   metalink and repository-signature verification
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

/// Patch level of the vendored libsolv (see `.libsolv` in build.zig.zon).
/// Used only by the opt-in libsolv solver oracle.
const vendored_libsolv_version_patch = "39";

/// Every client/ C translation unit. libsolv has been pushed out of
/// client/'s C sources entirely (issue #39): these files must keep
/// compiling with no libsolv header anywhere in scope, which the
/// libsolv-confinement-audit step below proves by building them without
/// libsolv's include paths. There is no longer an exception --
/// packageutils.c was the last one.
const client_libsolv_free_srcs = [_][]const u8{
    "api.c",             "goal.c",
    "gpgcheck.c",        "packageutils.c",
    "querynative.c",     "plugins.c",
    "repo.c",            "repolist.c",
    "resolve.c",         "rpmtrans.c",
    "rpmtrans_native.c", "utils.c",
};

/// Warnings + hardening flags from the former cmake/CFlags.cmake, filtered
/// to the strict set clang accepts. GCC-only warnings have been removed.
const tdnf_cflags = [_][]const u8{
    // Vendored libsolv's headers are reached with -I rather than
    // -isystem, because zig cc orders /usr/include *ahead* of user
    // -isystem directories: with -isystem, a host libsolv-devel silently
    // wins and the build compiles against the host's headers while
    // linking the vendored .a. -I restores the intended precedence, and
    // this flag restores the warning suppression that -isystem used to
    // provide, without exempting any of tdnf's own sources -- every
    // libsolv header is spelled <solv/...>, and a
    // header included from a system header is itself a system header, so
    // libsolv's internal quoted includes are covered too.
    "--system-header-prefix=solv/",
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
    const enable_libsolv_oracle = b.option(
        bool,
        "libsolv-oracle",
        "Enable the opt-in vendored libsolv parity oracle",
    ) orelse false;
    const transaction_plan_mod = b.createModule(.{
        .root_source_file = b.path("client/transaction_plan.zig"),
        .target = target,
        .optimize = optimize,
    });
    const public_tdnf_mod = b.addModule("tdnf", .{
        .root_source_file = b.path("tdnf.zig"),
        .target = target,
        .optimize = optimize,
    });
    public_tdnf_mod.addImport("transaction_plan", transaction_plan_mod);

    // Zig 0.16 documents an empty Build.pkg_hash as the root package. A
    // dependency only needs the modules registered above; returning here keeps
    // private dependencies, generated source templates, and product artifacts
    // out of the consumer's build graph.
    if (b.pkg_hash.len != 0) return;

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
    const prefix = b.install_prefix;
    const libdir = "lib";
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
    const full_libdir = b.fmt("{s}/{s}", .{ abs_prefix, libdir });
    const client_config_options = b.addOptions();
    client_config_options.addOption([]const u8, "history_db_dir", history_db_dir);
    client_config_options.addOption([]const u8, "source_root", b.build_root.path.?);
    client_config_options.addOption([]const u8, "system_libdir", full_libdir);
    // Vendored sqlite backs the Zig-side history and rpmdb code paths.
    const sqlite_dep_optional = b.lazyDependency("sqlite", .{});
    const tls_dep_optional = b.lazyDependency("tls", .{});
    const zlua_dep_optional = b.lazyDependency("zlua", .{
        .target = target,
        .optimize = optimize,
    });
    if (sqlite_dep_optional == null or
        tls_dep_optional == null or
        zlua_dep_optional == null)
    {
        return;
    }
    const client_updateinfo_test_step = b.step(
        "client-updateinfo-test",
        "Run client updateinfo production-logic tests",
    );
    const sqlite_dep = sqlite_dep_optional.?;
    const tls_dep = tls_dep_optional.?;
    const zlua_mod = zlua_dep_optional.?.module("zlua");

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
        .{ .key = "NATIVE_FILE_INSTALL_BINARY", .value = b.fmt("{s}/libexec/tdnf/tdnf-rpm-install", .{abs_prefix}) },
        .{ .key = "NATIVE_FILE_ERASE_BINARY", .value = b.fmt("{s}/libexec/tdnf/tdnf-rpm-erase", .{abs_prefix}) },
        .{ .key = "HISTORY_UTIL_BINARY", .value = b.fmt("{s}/libexec/tdnf/tdnf-history-util", .{abs_prefix}) },
        .{ .key = "AUTOMATIC_SCRIPT", .value = b.fmt("{s}/bin/tdnf-automatic", .{abs_prefix}) },
    });

    // ----- generated text files (autoconf_at style: @VAR@ only) ----- //
    // autoconf_at leaves `${...}` literal, which is required for .pc files.

    const tdnf_pc = b.addConfigHeader(.{
        .style = .{ .autoconf_at = b.path("client/tdnf.pc.in") },
        .include_path = "tdnf.pc",
    }, .{
        .CMAKE_INSTALL_PREFIX = abs_prefix,
        .CMAKE_INSTALL_LIBDIR = libdir,
        .PROJECT_VERSION = project_version,
    });

    const tdnf_cli_libs_pc = b.addConfigHeader(.{
        .style = .{ .autoconf_at = b.path("tools/cli/lib/tdnf-cli-libs.pc.in") },
        .include_path = "tdnf-cli-libs.pc",
    }, .{
        .CMAKE_INSTALL_PREFIX = abs_prefix,
        .CMAKE_INSTALL_LIBDIR = libdir,
        .PROJECT_VERSION = project_version,
    });

    writeTemplateExecutable(
        b,
        "bin/tdnf-automatic.in",
        "bin/tdnf-automatic",
        &.{.{ .key = "VERSION", .value = project_version }},
    );

    const zig_test_step = b.step("test", "Run Zig unit tests");
    const migration_audit_step = b.step(
        "migration-audit",
        "Reject increases in the remaining C-to-Zig migration surface",
    );
    const run_migration_audit = b.addSystemCommand(
        &.{ "python3", "scripts/c-to-zig-audit.py" },
    );
    run_migration_audit.setCwd(b.path("."));
    migration_audit_step.dependOn(&run_migration_audit.step);
    const dead_errdefer_audit_step = b.step(
        "dead-errdefer-audit",
        "Reject errdefer in functions that cannot return an error",
    );
    const run_dead_errdefer_audit = b.addSystemCommand(
        &.{ "python3", "scripts/dead-errdefer-audit.py" },
    );
    run_dead_errdefer_audit.setCwd(b.path("."));
    dead_errdefer_audit_step.dependOn(&run_dead_errdefer_audit.step);
    const native_dependency_audit_step = b.step(
        "native-dependency-audit",
        "Reject system RPM source and ELF dependencies",
    );
    const run_native_dependency_audit = b.addSystemCommand(
        &.{
            "python3",
            "scripts/librpm-audit.py",
            "--prefix",
            b.getInstallPath(.prefix, ""),
        },
    );
    run_native_dependency_audit.setCwd(b.path("."));
    run_native_dependency_audit.step.dependOn(b.getInstallStep());
    native_dependency_audit_step.dependOn(&run_native_dependency_audit.step);
    const product_no_libsolv_fetch_audit_step = b.step(
        "product-no-libsolv-fetch-audit",
        "Build the product cleanly with fetching disabled and no libsolv",
    );
    const run_product_no_libsolv_fetch_audit = b.addSystemCommand(
        &.{
            "python3",
            "scripts/product-no-libsolv-fetch-audit.py",
            "--zig",
            b.graph.zig_exe,
        },
    );
    run_product_no_libsolv_fetch_audit.setCwd(b.path("."));
    product_no_libsolv_fetch_audit_step.dependOn(
        &run_product_no_libsolv_fetch_audit.step,
    );
    const public_api_audit_step = b.step(
        "public-api-audit",
        "Compile and link an external C consumer using installed metadata",
    );
    const run_public_api_audit = b.addSystemCommand(
        &.{
            "python3",
            "scripts/public-api-audit.py",
            "--prefix",
            b.getInstallPath(.prefix, ""),
        },
    );
    run_public_api_audit.setCwd(b.path("."));
    run_public_api_audit.step.dependOn(b.getInstallStep());
    public_api_audit_step.dependOn(&run_public_api_audit.step);
    const public_zig_api_audit_step = b.step(
        "public-zig-api-audit",
        "Build and run an external consumer of the public Zig module",
    );
    const run_public_zig_api_audit = b.addSystemCommand(
        &.{
            "python3",
            "scripts/public-zig-api-audit.py",
            "--zig",
            b.graph.zig_exe,
            "--optimize",
            @tagName(optimize),
        },
    );
    run_public_zig_api_audit.setCwd(b.path("."));
    public_zig_api_audit_step.dependOn(&run_public_zig_api_audit.step);
    const abi_audit_step = b.step(
        "abi-audit",
        "Build and compare the public C ABI with its baseline",
    );
    const run_abi_audit = b.addSystemCommand(
        &.{
            "python3",
            "scripts/abi-audit.py",
            "--prefix",
            b.getInstallPath(.prefix, ""),
        },
    );
    run_abi_audit.setCwd(b.path("."));
    run_abi_audit.step.dependOn(b.getInstallStep());
    abi_audit_step.dependOn(&run_abi_audit.step);

    const tdnf_error_mod = b.createModule(.{
        .root_source_file = b.path("abi/error_codes.zig"),
        .target = target,
        .optimize = optimize,
    });
    const client_abi_mod = b.createModule(.{
        .root_source_file = b.path("client/abi.zig"),
        .target = target,
        .optimize = optimize,
    });
    const rpmtrans_flags_mod = b.createModule(.{
        .root_source_file = b.path("rpmzig/trans_flags.zig"),
        .target = target,
        .optimize = optimize,
    });
    const client_varsdir_mod = b.createModule(.{
        .root_source_file = b.path("client/varsdir.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    client_abi_mod.addIncludePath(b.path("include"));
    client_abi_mod.addIncludePath(b.path("client"));
    client_abi_mod.addIncludePath(b.path("rpmzig"));
    client_varsdir_mod.addImport("client_abi", client_abi_mod);
    {
        const tests = b.addTest(.{ .root_module = tdnf_error_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const tests = b.addTest(.{ .root_module = public_tdnf_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/updateinfo.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_abi", client_abi_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("client"));
        test_mod.addIncludePath(b.path("rpmzig"));
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        client_updateinfo_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }
    {
        const tests = b.addTest(.{ .root_module = transaction_plan_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    const transaction_plan_capture_abi_mod = b.createModule(.{
        .root_source_file = b.path("client/transaction_plan_capture_abi.zig"),
        .target = target,
        .optimize = optimize,
    });
    const transaction_plan_request_trace_mod = b.createModule(.{
        .root_source_file = b.path(
            "client/transaction_plan_request_trace.zig",
        ),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    transaction_plan_request_trace_mod.addImport(
        "transaction_plan_capture_abi",
        transaction_plan_capture_abi_mod,
    );
    transaction_plan_request_trace_mod.addImport(
        "tdnf_error",
        tdnf_error_mod,
    );
    const transaction_plan_capture_test_step = b.step(
        "transaction-plan-capture-test",
        "Run private transaction plan capture ABI and adapter tests",
    );
    {
        const tests = b.addTest(.{
            .root_module = transaction_plan_request_trace_mod,
        });
        const run_tests = b.addRunArtifact(tests);
        transaction_plan_capture_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }
    const transaction_plan_capture_test_mod = b.createModule(.{
        .root_source_file = b.path("client/transaction_plan_capture.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    transaction_plan_capture_test_mod.addImport(
        "transaction_plan_capture_abi",
        transaction_plan_capture_abi_mod,
    );
    transaction_plan_capture_test_mod.addImport(
        "transaction_plan",
        transaction_plan_mod,
    );
    transaction_plan_capture_test_mod.addImport(
        "transaction_plan_request_trace",
        transaction_plan_request_trace_mod,
    );
    transaction_plan_capture_test_mod.addImport("tdnf_error", tdnf_error_mod);
    {
        const tests = b.addTest(.{
            .root_module = transaction_plan_capture_test_mod,
        });
        const run_tests = b.addRunArtifact(tests);
        transaction_plan_capture_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    const repomd_abi_mod = b.createModule(.{
        .root_source_file = b.path("abi/repomd_layout.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const solver_result_abi_mod = b.createModule(.{
        .root_source_file = b.path("repomd/solver_result_abi.zig"),
        .target = target,
        .optimize = optimize,
    });
    const solver_legacy_abi_mod = b.createModule(.{
        .root_source_file = b.path("repomd/solver_legacy_abi.zig"),
        .target = target,
        .optimize = optimize,
    });
    const solver_live_abi_mod = b.createModule(.{
        .root_source_file = b.path("repomd/solver_live_abi.zig"),
        .target = target,
        .optimize = optimize,
    });
    repomd_abi_mod.addImport("solver_result_abi", solver_result_abi_mod);
    repomd_abi_mod.addImport("solver_legacy_abi", solver_legacy_abi_mod);
    repomd_abi_mod.addImport("solver_live_abi", solver_live_abi_mod);
    repomd_abi_mod.addImport(
        "transaction_plan_capture_abi",
        transaction_plan_capture_abi_mod,
    );
    repomd_abi_mod.addIncludePath(b.path("include"));
    repomd_abi_mod.addIncludePath(b.path("client"));
    {
        const tests = b.addTest(.{ .root_module = repomd_abi_mod });
        const run_tests = b.addRunArtifact(tests);
        transaction_plan_capture_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    const xml_mod = b.createModule(.{
        .root_source_file = b.path("xml/xml.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const metalink_xml_mod = b.createModule(.{
        .root_source_file = b.path("plugins/metalink/xml.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    metalink_xml_mod.addImport("xml", xml_mod);
    const repository_metadata_mod = b.createModule(.{
        .root_source_file = b.path(
            "repomd/transaction_plan_repository_dependencies.zig",
        ),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    repository_metadata_mod.addImport("xml", xml_mod);
    const transaction_plan_repository_mod = b.createModule(.{
        .root_source_file = b.path("client/transaction_plan_repository.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    transaction_plan_repository_mod.addImport(
        "repository_metadata",
        repository_metadata_mod,
    );
    transaction_plan_repository_mod.addImport(
        "transaction_plan",
        transaction_plan_mod,
    );
    const transaction_plan_repository_test_step = b.step(
        "transaction-plan-repository-test",
        "Run repository transaction-plan identity capture tests",
    );
    {
        const tests = b.addTest(.{
            .root_module = transaction_plan_repository_mod,
        });
        const run_tests = b.addRunArtifact(tests);
        transaction_plan_repository_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    const rpmzig_header_mod = b.createModule(.{
        .root_source_file = b.path("rpmzig/header.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const rpmzig_pkgfile_mod = b.createModule(.{
        .root_source_file = b.path("rpmzig/pkgfile.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    rpmzig_pkgfile_mod.addImport("rpm_header", rpmzig_header_mod);

    const rpmzig_verify_mod = b.createModule(.{
        .root_source_file = b.path("rpmzig/verify.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    rpmzig_verify_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);

    const rpmzig_cpio_mod = b.createModule(.{
        .root_source_file = b.path("rpmzig/cpio.zig"),
        .target = target,
        .optimize = optimize,
    });

    const rpmzig_rpmdb_test_mod = b.createModule(.{
        .root_source_file = b.path("rpmzig/rpmdb.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
        },
    });
    rpmzig_rpmdb_test_mod.addImport("rpm_header", rpmzig_header_mod);
    rpmzig_rpmdb_test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
    configureLuaScriptletSupport(b, rpmzig_rpmdb_test_mod, zlua_mod);

    const repomd_mod = b.createModule(.{
        .root_source_file = b.path("repomd/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    repomd_mod.addImport("xml", xml_mod);
    repomd_mod.addImport("rpm_header", rpmzig_header_mod);
    repomd_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
    repomd_mod.addImport("tdnf_error", tdnf_error_mod);
    repomd_mod.addIncludePath(b.path("include"));
    repomd_mod.addIncludePath(b.path("rpmzig"));

    const transaction_plan_native_mod = b.createModule(.{
        .root_source_file = b.path("client/transaction_plan_native.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    transaction_plan_native_mod.addImport(
        "transaction_plan_capture_abi",
        transaction_plan_capture_abi_mod,
    );
    transaction_plan_native_mod.addImport("tdnf_error", tdnf_error_mod);
    transaction_plan_native_mod.addImport("repomd", repomd_mod);
    const transaction_plan_repository_integration_mod = b.createModule(.{
        .root_source_file = b.path("client/transaction_plan_repository.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    transaction_plan_repository_integration_mod.addImport(
        "repository_metadata",
        repomd_mod,
    );
    transaction_plan_repository_integration_mod.addImport(
        "transaction_plan",
        transaction_plan_mod,
    );
    const transaction_plan_integration_mod = b.createModule(.{
        .root_source_file = b.path("client/transaction_plan_integration.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    const transaction_plan_integration_options = b.addOptions();
    transaction_plan_integration_options.addOption(
        bool,
        "standalone_test",
        false,
    );
    transaction_plan_integration_mod.addOptions(
        "transaction_plan_integration_options",
        transaction_plan_integration_options,
    );
    transaction_plan_integration_mod.addImport(
        "transaction_plan_capture_abi",
        transaction_plan_capture_abi_mod,
    );
    transaction_plan_integration_mod.addImport(
        "transaction_plan_capture",
        transaction_plan_capture_test_mod,
    );
    transaction_plan_integration_mod.addImport(
        "transaction_plan_native",
        transaction_plan_native_mod,
    );
    transaction_plan_integration_mod.addImport(
        "transaction_plan_repository",
        transaction_plan_repository_integration_mod,
    );
    transaction_plan_integration_mod.addImport(
        "repository_metadata",
        repomd_mod,
    );
    transaction_plan_integration_mod.addImport(
        "transaction_plan",
        transaction_plan_mod,
    );
    transaction_plan_integration_mod.addImport(
        "transaction_plan_request_trace",
        transaction_plan_request_trace_mod,
    );
    transaction_plan_integration_mod.addImport("tdnf_error", tdnf_error_mod);

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
        mod.addImport("tdnf_error", tdnf_error_mod);
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

    const llconf_lib = blk: {
        const mod = b.createModule(.{
            .root_source_file = b.path("llconf/llconf.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addIncludePath(b.path("include"));
        mod.addIncludePath(b.path("llconf"));
        const lib = b.addLibrary(.{
            .name = "tdnfllconf",
            .linkage = .static,
            .root_module = mod,
        });
        break :blk lib;
    };

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
        const lib = b.addLibrary(.{
            .name = "jsondump",
            .linkage = .static,
            .root_module = mod,
        });
        break :blk lib;
    };

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

    // ----- rpmzig (native RPM implementation) ----- //

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
        mod.addImport("rpm_header", rpmzig_header_mod);
        mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        configureLuaScriptletSupport(b, mod, zlua_mod);
        const lib = b.addLibrary(.{
            .name = "tdnfrpmzig",
            .linkage = .static,
            .root_module = mod,
        });
        break :blk lib;
    };

    const transaction_plan_native_test_step = b.step(
        "transaction-plan-native-test",
        "Run native solver transaction plan capture tests",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/transaction_plan_native.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport(
            "transaction_plan_capture_abi",
            transaction_plan_capture_abi_mod,
        );
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        test_mod.addImport("repomd", repomd_mod);
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        transaction_plan_native_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    // `repomd/query_native.zig` is deliberately excluded from `repomd/root.zig`'s
    // test aggregation (it needs libtdnf's allocators at link time), so its unit
    // tests need a root of their own or they never run.
    const query_native_test_step = b.step(
        "query-native-test",
        "Run native repoquery/exclude line builder tests",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/query_native.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("xml", xml_mod);
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        test_mod.addImport("sqlite", sqlite_dep.module("sqlite"));
        test_mod.addImport("rpmdb_test", rpmzig_rpmdb_test_mod);
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("rpmzig"));
        test_mod.linkLibrary(common_lib);
        test_mod.linkLibrary(llconf_lib);
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        query_native_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    const client_download_mod = b.createModule(.{
        .root_source_file = b.path("client/download/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
        .imports = &.{
            .{ .name = "client_abi", .module = client_abi_mod },
            .{ .name = "tls", .module = tls_dep.module("tls") },
            .{ .name = "tdnf_error", .module = tdnf_error_mod },
        },
    });

    const client_repoutils_test_step = b.step(
        "client-repoutils-test",
        "Run client repository utility production tests",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/repoutils.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_abi", client_abi_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("client"));
        test_mod.addIncludePath(b.path("rpmzig"));
        test_mod.linkLibrary(common_lib);
        test_mod.linkLibrary(llconf_lib);
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        client_repoutils_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    const client_remoterepo_test_step = b.step(
        "client-remoterepo-test",
        "Run client remote repository production tests",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/remoterepo.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "client_abi", .module = client_abi_mod },
                .{ .name = "client_download", .module = client_download_mod },
                .{ .name = "tdnf_error", .module = tdnf_error_mod },
            },
        });
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("client"));
        test_mod.addIncludePath(b.path("rpmzig"));
        test_mod.linkLibrary(common_lib);
        test_mod.linkLibrary(llconf_lib);
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        client_remoterepo_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    const transaction_plan_integration_test_step = b.step(
        "transaction-plan-integration-test",
        "Run authoritative stored transaction plan integration tests",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(
                "client/transaction_plan_integration.zig",
            ),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport(
            "transaction_plan_capture_abi",
            transaction_plan_capture_abi_mod,
        );
        test_mod.addImport(
            "transaction_plan_capture",
            transaction_plan_capture_test_mod,
        );
        test_mod.addImport(
            "transaction_plan_native",
            transaction_plan_native_mod,
        );
        test_mod.addImport(
            "transaction_plan_repository",
            transaction_plan_repository_integration_mod,
        );
        test_mod.addImport("repository_metadata", repomd_mod);
        test_mod.addImport("transaction_plan", transaction_plan_mod);
        test_mod.addImport(
            "transaction_plan_request_trace",
            transaction_plan_request_trace_mod,
        );
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        const test_options = b.addOptions();
        test_options.addOption(bool, "standalone_test", true);
        test_mod.addOptions(
            "transaction_plan_integration_options",
            test_options,
        );
        const tests = b.addTest(.{
            .root_module = test_mod,
        });
        tests.root_module.linkLibrary(common_lib);
        tests.root_module.linkLibrary(llconf_lib);
        tests.root_module.linkLibrary(rpmzig_lib);
        const run_tests = b.addRunArtifact(tests);
        transaction_plan_integration_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("common/common.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("common"));
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        test_mod.addCSourceFiles(.{
            .root = b.path("common"),
            .files = &.{ "memory_printf_shim.c", "log_shim.c", "joinpath_shim.c" },
            .flags = &tdnf_cflags,
        });
        test_mod.linkLibrary(llconf_lib);
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const common_test_step = b.step(
            "common-test",
            "Run common Zig unit tests",
        );
        common_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("llconf/llconf.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("llconf"));
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    // `zig build test` runs the rpmzig Zig unit tests (path-building,
    // txn-config resolution, plus the pure-Zig parser/verifier submodules).
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
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        configureLuaScriptletSupport(b, test_mod, zlua_mod);
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
        test_mod.addIncludePath(b.path("jsondump"));
        test_mod.addIncludePath(b.path("llconf"));
        test_mod.addIncludePath(b.path("tools/cli"));
        test_mod.addIncludePath(b.path("tools/cli/lib"));
        test_mod.linkLibrary(common_lib);
        test_mod.linkLibrary(jsondump_lib);
        test_mod.linkLibrary(llconf_lib);
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/config.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_abi", client_abi_mod);
        test_mod.addImport("client_config_options", client_config_options.createModule());
        test_mod.addImport("client_varsdir", client_varsdir_mod);
        test_mod.addImport("rpmtrans_flags", rpmtrans_flags_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        test_mod.linkLibrary(common_lib);
        test_mod.linkLibrary(llconf_lib);
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        run_tests.argv.items.len = 1;
        run_tests.stdio = .inherit;
        const client_config_test_step = b.step(
            "client-config-test",
            "Run client configuration tests",
        );
        client_config_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/excludes.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_abi", client_abi_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        test_mod.linkLibrary(common_lib);
        test_mod.linkLibrary(llconf_lib);
        test_mod.linkLibrary(rpmzig_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const client_excludes_test_step = b.step(
            "client-excludes-test",
            "Run package exclusion collection tests",
        );
        client_excludes_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/varsdir.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_abi", client_abi_mod);
        test_mod.linkLibrary(llconf_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("tools/config/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addIncludePath(b.path("."));
        test_mod.addIncludePath(b.path("include"));
        test_mod.linkLibrary(llconf_lib);
        test_mod.linkLibrary(jsondump_lib);
        linkSystem(test_mod, &.{"dl"});
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

    const client_download_test_step = b.step(
        "client-download-test",
        "Run Zig HTTP/TLS download transport tests",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/download/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "client_abi", .module = client_abi_mod },
                .{ .name = "tls", .module = tls_dep.module("tls") },
                .{ .name = "tdnf_error", .module = tdnf_error_mod },
            },
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        client_download_test_step.dependOn(&run_tests.step);
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

    var read_tool_install_steps: [4]*std.Build.Step = undefined;

    // tdnf-rpmdb-count: smoke-test exe for the native rpmdb reader.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/count_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpmdb", rpmzig_lib.root_module);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpmdb-count",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
        read_tool_install_steps[0] = &install.step;
    }

    // tdnf-rpmdb-list: smoke-test exe for the rpmzig iterator.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/list_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpmdb", rpmzig_lib.root_module);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpmdb-list",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
        read_tool_install_steps[1] = &install.step;
    }

    // tdnf-rpm-info: smoke-test exe for the rpmzig `.rpm` file parser.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/info_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-info",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
        read_tool_install_steps[2] = &install.step;
    }

    var key_tool_install_steps: [3]*std.Build.Step = undefined;

    // tdnf-rpmdb-pubkeys: smoke-test exe for the rpmdb gpg-pubkey
    // iterator. Lists every rpm-imported public key.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/pubkeys_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpmdb", rpmzig_lib.root_module);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpmdb-pubkeys",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
        key_tool_install_steps[0] = &install.step;
    }

    // tdnf-rpmdb-import-pubkeys: smoke-test exe for atomic native
    // OpenPGP certificate import.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/pubkey_import_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpmdb", rpmzig_lib.root_module);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpmdb-import-pubkeys",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
        key_tool_install_steps[1] = &install.step;
    }

    // tdnf-rpmdb-write: smoke-test exe for the native sqlite rpmdb
    // write path.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/write_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpmdb", rpmzig_lib.root_module);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpmdb-write",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
        key_tool_install_steps[2] = &install.step;
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/key_tools_cli_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        run_tests.setEnvironmentVariable(
            "TDNF_RPMDB_PUBKEYS_TEST_BINARY",
            b.getInstallPath(
                .{ .custom = "libexec/tdnf" },
                "tdnf-rpmdb-pubkeys",
            ),
        );
        run_tests.setEnvironmentVariable(
            "TDNF_RPMDB_IMPORT_PUBKEYS_TEST_BINARY",
            b.getInstallPath(
                .{ .custom = "libexec/tdnf" },
                "tdnf-rpmdb-import-pubkeys",
            ),
        );
        run_tests.setEnvironmentVariable(
            "TDNF_RPMDB_WRITE_TEST_BINARY",
            b.getInstallPath(
                .{ .custom = "libexec/tdnf" },
                "tdnf-rpmdb-write",
            ),
        );
        run_tests.setEnvironmentVariable(
            "TDNF_RPMDB_KEY_FIXTURE",
            "rpmzig/pgp/testdata/microsoft-rpm-key.asc",
        );
        run_tests.setCwd(b.path("."));
        for (&key_tool_install_steps) |install_step| {
            run_tests.step.dependOn(install_step);
        }
        const key_tools_test_step = b.step(
            "rpmzig-key-tools-test",
            "Run rpmzig key tool CLI tests",
        );
        key_tools_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    // tdnf-rpm-files: smoke-test exe for the cpio walker + payload
    // decompressor.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/files_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpm_cpio", rpmzig_cpio_mod);
        mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-files",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
        read_tool_install_steps[3] = &install.step;
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/read_tools_cli_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const cpio_tests = b.addTest(.{ .root_module = rpmzig_cpio_mod });
        const run_cpio_tests = b.addRunArtifact(cpio_tests);
        inline for (
            .{
                "tdnf-rpmdb-count",
                "tdnf-rpmdb-list",
                "tdnf-rpm-info",
                "tdnf-rpm-files",
            },
            .{
                "TDNF_RPMDB_COUNT_TEST_BINARY",
                "TDNF_RPMDB_LIST_TEST_BINARY",
                "TDNF_RPM_INFO_TEST_BINARY",
                "TDNF_RPM_FILES_TEST_BINARY",
            },
        ) |binary, environment_name| {
            run_tests.setEnvironmentVariable(
                environment_name,
                b.getInstallPath(.{ .custom = "libexec/tdnf" }, binary),
            );
        }
        for (&read_tool_install_steps) |install_step| {
            run_tests.step.dependOn(install_step);
        }
        const read_tools_test_step = b.step(
            "rpmzig-read-tools-test",
            "Run rpmzig read-tool CLI tests",
        );
        read_tools_test_step.dependOn(&run_tests.step);
        read_tools_test_step.dependOn(&run_cpio_tests.step);
        zig_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_cpio_tests.step);
    }

    // tdnf-rpm-install: smoke-test exe for the native file-install
    // engine.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/install_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpm_header", rpmzig_header_mod);
        mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-install",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // tdnf-rpm-scriptlet: smoke-test exe for the native
    // scriptlet executor.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/scriptlet_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpm_header", rpmzig_header_mod);
        mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        configureLuaScriptletSupport(b, mod, zlua_mod);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-scriptlet",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // tdnf-rpm-trigger: smoke-test exe for the native trigger
    // executor.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/trigger_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        mod.addImport("rpm_header", rpmzig_header_mod);
        mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        configureLuaScriptletSupport(b, mod, zlua_mod);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-trigger",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // tdnf-rpm-erase: smoke-test exe for the native file-erase
    // engine.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/erase_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        mod.addImport("rpm_header", rpmzig_header_mod);
        mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-erase",
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
    // path libtdnf uses.
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/verify_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        mod.addImport("rpmdb", rpmzig_lib.root_module);
        const exe = b.addExecutable(.{
            .name = "tdnf-rpm-verify",
            .root_module = mod,
        });
        hardenExe(exe);
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "libexec/tdnf" } },
        });
        b.getInstallStep().dependOn(&install.step);

        const verify_tests = b.addTest(.{
            .root_module = rpmzig_verify_mod,
        });
        const run_verify_tests = b.addRunArtifact(verify_tests);
        const cli_test_mod = b.createModule(.{
            .root_source_file = b.path("rpmzig/verify_cli_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        const cli_tests = b.addTest(.{ .root_module = cli_test_mod });
        const run_cli_tests = b.addRunArtifact(cli_tests);
        run_cli_tests.setEnvironmentVariable(
            "TDNF_RPM_VERIFY_TEST_BINARY",
            b.getInstallPath(
                .{ .custom = "libexec/tdnf" },
                "tdnf-rpm-verify",
            ),
        );
        run_cli_tests.step.dependOn(&install.step);
        const verifier_tools_test_step = b.step(
            "rpmzig-verifier-tools-test",
            "Run rpmzig verifier bridge and CLI tests",
        );
        verifier_tools_test_step.dependOn(&run_verify_tests.step);
        verifier_tools_test_step.dependOn(&run_cli_tests.step);
        zig_test_step.dependOn(&run_verify_tests.step);
        zig_test_step.dependOn(&run_cli_tests.step);
    }

    const builtin_plugins_mod = b.createModule(.{
        .root_source_file = b.path("plugins/builtin.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    builtin_plugins_mod.addImport("metalink_xml", metalink_xml_mod);
    builtin_plugins_mod.addIncludePath(b.path("include"));
    builtin_plugins_mod.addIncludePath(b.path("client"));
    builtin_plugins_mod.addIncludePath(b.path("llconf"));
    builtin_plugins_mod.addIncludePath(b.path("rpmzig"));
    builtin_plugins_mod.addCMacro("TDNF_CLIENT_LIBSOLV_IN_SCOPE", "1");

    // ----- libtdnf (shared) ----- //

    const client_history_mod = b.createModule(.{
        .root_source_file = b.path("client/history.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    client_history_mod.addImport("client_abi", client_abi_mod);
    client_history_mod.addImport("tdnf_error", tdnf_error_mod);

    const client_updateinfo_mod = b.createModule(.{
        .root_source_file = b.path("client/updateinfo_exports.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    client_updateinfo_mod.addImport("tdnf_error", tdnf_error_mod);
    client_updateinfo_mod.addImport("client_abi", client_abi_mod);
    client_updateinfo_mod.addIncludePath(b.path("include"));
    client_updateinfo_mod.addIncludePath(b.path("client"));
    client_updateinfo_mod.addIncludePath(b.path("rpmzig"));

    const client_init_mod = b.createModule(.{
        .root_source_file = b.path("client/init.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    client_init_mod.addImport(
        "transaction_plan_capture_abi",
        transaction_plan_capture_abi_mod,
    );
    client_init_mod.addImport("client_init_abi", client_abi_mod);
    client_init_mod.addImport("tdnf_error", tdnf_error_mod);

    const tdnf_so_mod = b.createModule(.{
        .root_source_file = b.path("client/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    tdnf_so_mod.addImport(
        "transaction_plan_capture",
        transaction_plan_capture_test_mod,
    );
    tdnf_so_mod.addImport(
        "transaction_plan_integration",
        transaction_plan_integration_mod,
    );
    tdnf_so_mod.addImport("client_init", client_init_mod);
    tdnf_so_mod.addImport("repomd_client_exports", repomd_mod);
    tdnf_so_mod.addImport("builtin_plugins", builtin_plugins_mod);
    tdnf_so_mod.addImport("client_history", client_history_mod);
    tdnf_so_mod.addImport("client_abi", client_abi_mod);
    tdnf_so_mod.addImport("client_download", client_download_mod);
    tdnf_so_mod.addImport("client_config_options", client_config_options.createModule());
    tdnf_so_mod.addImport("client_varsdir", client_varsdir_mod);
    tdnf_so_mod.addImport("rpmtrans_flags", rpmtrans_flags_mod);
    tdnf_so_mod.addImport("tdnf_error", tdnf_error_mod);
    tdnf_so_mod.addImport("client_updateinfo", client_updateinfo_mod);
    tdnf_so_mod.addIncludePath(b.path("include"));
    tdnf_so_mod.addIncludePath(b.path("client"));
    tdnf_so_mod.addIncludePath(b.path("rpmzig"));
    // Native transaction ordering, dependency/conflict checks, and the
    // composed transaction executor are unconditional.
    tdnf_so_mod.addCMacro("TDNF_RPMZIG_TRANSACTION_CHECK", "1");
    // The native target may expose host headers, so this production build
    // declares only that the confinement negative control is not armed.
    tdnf_so_mod.addCMacro("TDNF_CLIENT_LIBSOLV_IN_SCOPE", "1");
    // All client C and Zig sources are production-libsolv-free.
    tdnf_so_mod.addCSourceFiles(.{
        .root = b.path("client"),
        .files = &(client_libsolv_free_srcs),
        .flags = &tdnf_cflags,
    });
    tdnf_so_mod.linkLibrary(common_lib);
    tdnf_so_mod.linkLibrary(history_lib);
    tdnf_so_mod.linkLibrary(llconf_lib);
    tdnf_so_mod.linkLibrary(rpmzig_lib);
    const libtdnf = b.addLibrary(.{
        .name = "tdnf",
        .linkage = .dynamic,
        .root_module = tdnf_so_mod,
        .version = project_semver,
    });
    libtdnf.forceUndefinedSymbol("TDNFTransactionPlanCaptureCreate");
    libtdnf.forceUndefinedSymbol("TDNFTransactionPlanCaptureDestroy");
    // Stop re-exporting vendored SQLite. See
    // client/libtdnf.map for why this is a correctness fix and not
    // housekeeping: without it libtdnf.so exports 632 third-party
    // symbols that can interpose on, or be interposed by, a real
    // libsolv.so or libsqlite3.so in the same process.
    libtdnf.setVersionScript(b.path("client/libtdnf.map"));
    b.installArtifact(libtdnf);

    // Compiler-enforced libsolv confinement (issue #39). Build every C
    // file in client/ with libsolv's headers unreachable. A regex over
    // the sources was wrong eight times; this cannot be: if any of these
    // files reaches for a libsolv type, macro or function -- with or
    // without an #include -- the build fails.
    //
    // What makes this hermetic rather than merely convenient is the
    // explicitly-spelled target:
    //
    //   * Zig only searches the host's /usr/include for a *native*
    //     target, and libsolv-devel is a normal build dependency on the
    //     distributions tdnf targets (Photon, Azure Linux). Naming the
    //     triple, even the host's own, restricts the search to Zig's
    //     bundled libc headers, so <solv/pool.h> is genuinely absent
    //     instead of accidentally so.
    //
    // A separate module is still required because include paths are
    // per-module: the audit arms client/includes.h's negative control
    // with -DTDNF_CLIENT_LIBSOLV_OUT_OF_SCOPE, which the production
    // module must not define.
    const confinement_target = b.resolveTargetQuery(.{
        .cpu_arch = target.result.cpu.arch,
        .os_tag = .linux,
        .abi = .gnu,
    });
    const client_confinement = staticLib(b, confinement_target, optimize, .{
        .name = "client-libsolv-confinement",
        .root = "client",
        .files = &client_libsolv_free_srcs,
    });
    client_confinement.root_module.addIncludePath(b.path("rpmzig"));
    client_confinement.root_module.addCMacro(
        "TDNF_RPMZIG_TRANSACTION_CHECK",
        "1",
    );
    // Arms the negative control in client/includes.h. The audit is only
    // evidence if libsolv is genuinely unreachable; if it were reachable
    // the audit would pass while proving nothing, which is the exact
    // failure mode this series keeps hitting. Compiling the check inside
    // the audited module means it sees the configuration under test by
    // construction -- it cannot drift out of step with it, and there is
    // no second compiler invocation to keep in sync.
    client_confinement.root_module.addCMacro(
        "TDNF_CLIENT_LIBSOLV_OUT_OF_SCOPE",
        "1",
    );
    const libsolv_confinement_step = b.step(
        "libsolv-confinement-audit",
        "Prove every C file in client/ builds without libsolv headers",
    );
    libsolv_confinement_step.dependOn(&client_confinement.step);
    // The -I pin is attached per module by addLibsolvIncludes, so a file
    // in a module that never calls it can still spell <solv/pool.h> and
    // resolve it from /usr/include with no version assert in scope --
    // exactly the bug the pin exists to prevent, reachable everywhere
    // outside the oracle module. Nothing in the build graph can catch
    // that, because such a file compiles cleanly; only the spelling
    // gives it away.
    const run_libsolv_include_audit = b.addSystemCommand(
        &.{ "python3", "scripts/libsolv-include-audit.py" },
    );
    run_libsolv_include_audit.setCwd(b.path("."));
    libsolv_confinement_step.dependOn(&run_libsolv_include_audit.step);

    const run_libsolv_artifact_audit = b.addSystemCommand(
        &.{
            "python3",
            "scripts/libsolv-artifact-audit.py",
            b.getInstallPath(.prefix, ""),
        },
    );
    run_libsolv_artifact_audit.setCwd(b.path("."));
    run_libsolv_artifact_audit.step.dependOn(b.getInstallStep());
    libsolv_confinement_step.dependOn(&run_libsolv_artifact_audit.step);

    const client_history_test_step = b.step(
        "client-history-test",
        "Run private client history context tests",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/history_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_history", client_history_mod);
        test_mod.addImport("client_root", tdnf_so_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        client_history_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    const transaction_plan_handle_test_step = b.step(
        "transaction-plan-handle-test",
        "Run private production handle transaction plan integration test",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(
                "client/transaction_plan_handle_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_root", tdnf_so_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        transaction_plan_handle_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    const client_init_test_step = b.step(
        "client-init-test",
        "Run private production client refresh-input tests",
    );
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/init_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_root", tdnf_so_mod);
        test_mod.addImport(
            "transaction_plan_capture_abi",
            transaction_plan_capture_abi_mod,
        );
        test_mod.addImport("client_init_abi", client_abi_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        client_init_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("client/updateinfo_export_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("client_root", tdnf_so_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        client_updateinfo_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    // ----- libtdnfcli (shared) ----- //

    const cli_so_mod = b.createModule(.{
        .root_source_file = b.path("tools/cli/lib/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    cli_so_mod.addIncludePath(b.path("include"));
    cli_so_mod.addIncludePath(b.path("jsondump"));
    cli_so_mod.addIncludePath(b.path("llconf"));
    cli_so_mod.addIncludePath(b.path("tools/cli"));
    cli_so_mod.addIncludePath(b.path("tools/cli/lib"));
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
        .root_source_file = b.path("tools/cli/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    tdnf_mod.addIncludePath(b.path("include"));
    tdnf_mod.addIncludePath(b.path("jsondump"));
    tdnf_mod.addIncludePath(b.path("tools/cli"));
    tdnf_mod.linkLibrary(jsondump_lib);
    tdnf_mod.linkLibrary(libtdnfcli);
    tdnf_mod.linkLibrary(libtdnf);
    const tdnf_exe = b.addExecutable(.{
        .name = "tdnf",
        .root_module = tdnf_mod,
    });
    hardenExe(tdnf_exe);
    b.installArtifact(tdnf_exe);

    {
        const plan_cli_test_mod = b.createModule(.{
            .root_source_file = b.path("tools/cli/plan_cli_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        const plan_cli_tests = b.addTest(.{ .root_module = plan_cli_test_mod });
        const run_plan_cli_tests = b.addRunArtifact(plan_cli_tests);
        run_plan_cli_tests.setEnvironmentVariable(
            "TDNF_CLI_TEST_PREFIX",
            b.getInstallPath(.prefix, ""),
        );
        run_plan_cli_tests.step.dependOn(b.getInstallStep());
        run_plan_cli_tests.has_side_effects = true;
        zig_test_step.dependOn(&run_plan_cli_tests.step);
    }

    // tdnf-config
    const tdnf_config_mod = b.createModule(.{
        .root_source_file = b.path("tools/config/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    tdnf_config_mod.addIncludePath(b.path("."));
    tdnf_config_mod.addIncludePath(b.path("include"));
    tdnf_config_mod.linkLibrary(llconf_lib);
    tdnf_config_mod.linkLibrary(jsondump_lib);
    linkSystem(tdnf_config_mod, &.{"dl"});
    const tdnf_config_exe = b.addExecutable(.{
        .name = "tdnf-config",
        .root_module = tdnf_config_mod,
    });
    hardenExe(tdnf_config_exe);
    b.installArtifact(tdnf_config_exe);

    // tdnf-history-util links the vendored-SQLite history and rpmzig libs.
    const history_util_options = b.addOptions();
    history_util_options.addOption([]const u8, "db_dir", history_db_dir);
    const history_util_mod = b.createModule(.{
        .root_source_file = b.path("history/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    history_util_mod.addImport("history", history_lib.root_module);
    history_util_mod.addImport(
        "history_config",
        history_util_options.createModule(),
    );
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

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("history/main_cli_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        run_tests.setEnvironmentVariable(
            "TDNF_HISTORY_UTIL_TEST_BINARY",
            b.getInstallPath(
                .{ .custom = "libexec/tdnf" },
                "tdnf-history-util",
            ),
        );
        run_tests.step.dependOn(&install_history_util.step);
        const history_util_test_step = b.step(
            "history-util-test",
            "Run tdnf-history-util CLI tests",
        );
        history_util_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    // jsondumptest
    const jsondump_test_mod = b.createModule(.{
        .root_source_file = b.path("jsondump/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    jsondump_test_mod.addImport("jsondump", jsondump_lib.root_module);
    const jsondump_test_exe = b.addExecutable(.{
        .name = "jsondumptest",
        .root_module = jsondump_test_mod,
    });
    hardenExe(jsondump_test_exe);
    b.installArtifact(jsondump_test_exe);
    {
        const tests = b.addTest(.{ .root_module = jsondump_test_mod });
        const run_tests = b.addRunArtifact(tests);
        const jsondump_test_step = b.step(
            "jsondump-test",
            "Run jsondump unit tests",
        );
        jsondump_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const tests = b.addTest(.{ .root_module = xml_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/available_loader.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("xml", xml_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/cmdline_repository.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        test_mod.addImport("rpmdb_test", rpmzig_rpmdb_test_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/directory_repository.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        test_mod.addImport("rpmdb_test", rpmzig_rpmdb_test_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/installed_repository.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        test_mod.addImport("rpmdb_test", rpmzig_rpmdb_test_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const installed_loader_test_step = b.step(
            "installed-loader-test",
            "Run the standalone installed repository loader tests",
        );
        installed_loader_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/package_context.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        test_mod.addImport("xml", xml_mod);
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        test_mod.addImport("rpmdb_test", rpmzig_rpmdb_test_mod);
        test_mod.addIncludePath(b.path("include"));
        test_mod.linkLibrary(common_lib);
        test_mod.linkLibrary(llconf_lib);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const package_context_test_step = b.step(
            "package-context-test",
            "Run native package context lifetime and stable handle tests",
        );
        package_context_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/solver_identity.zig"),
            .target = target,
            .optimize = optimize,
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const identity_test_step = b.step(
            "solver-identity-test",
            "Run stable native solver package identity tests",
        );
        identity_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/solver_visibility.zig"),
            .target = target,
            .optimize = optimize,
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const visibility_test_step = b.step(
            "solver-visibility-test",
            "Run native solver visibility projection tests",
        );
        visibility_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/solver_native.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const native_solve_test_step = b.step(
            "native-solve-test",
            "Run reusable native solver entry point tests",
        );
        native_solve_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/solver_live.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        test_mod.addImport("xml", xml_mod);
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        test_mod.addImport("rpmdb_test", rpmzig_rpmdb_test_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        const live_solve_test_step = b.step(
            "live-solve-test",
            "Run strict native live-input solve tests",
        );
        live_solve_test_step.dependOn(&run_tests.step);
        zig_test_step.dependOn(&run_tests.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        test_mod.addImport("xml", xml_mod);
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        test_mod.addImport("rpmdb_test", rpmzig_rpmdb_test_mod);
        test_mod.addImport("tdnf_error", tdnf_error_mod);
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("rpmzig"));
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    const oracle_test_step = b.step(
        "libsolv-oracle-test",
        "Run the opt-in canonical libsolv solver oracle tests",
    );
    if (enable_libsolv_oracle) {
        // libsolv's C sources intentionally rely on wraparound in a few
        // internal hash paths; match packaged libsolv's release behaviour.
        const libsolv_dep_optional = b.lazyDependency("libsolv", .{
            .target = target,
            .optimize = OptimizeMode.ReleaseFast,
            .ext = true,
            .zlib = false,
        });
        if (libsolv_dep_optional == null) return;
        const libsolv_dep = libsolv_dep_optional.?;
        const libsolv = libsolv_dep.artifact("solv");
        const libsolvext = libsolv_dep.artifact("solvext");
        const libsolv_includes = LibsolvIncludes.init(
            b,
            libsolv,
            libsolvext,
        );
        const test_mod = b.createModule(.{
            .root_source_file = b.path("repomd/solver_oracle_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sqlite", .module = sqlite_dep.module("sqlite") },
            },
        });
        test_mod.addImport("xml", xml_mod);
        test_mod.addImport("rpm_header", rpmzig_header_mod);
        test_mod.addImport("rpm_pkgfile", rpmzig_pkgfile_mod);
        test_mod.addImport("rpmdb_test", rpmzig_rpmdb_test_mod);
        test_mod.addIncludePath(b.path("include"));
        test_mod.addIncludePath(b.path("rpmzig"));
        addLibsolvIncludes(
            test_mod,
            libsolv_includes,
        );
        test_mod.addObjectFile(libsolv.getEmittedBin());
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        oracle_test_step.dependOn(&run_tests.step);
    } else {
        const disabled = b.addSystemCommand(&.{
            "sh",
            "-c",
            "echo 'error: libsolv oracle disabled; rerun with -Dlibsolv-oracle=true' >&2; exit 1",
        });
        oracle_test_step.dependOn(&disabled.step);
    }

    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("plugins/metalink/xml.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_mod.addImport("xml", xml_mod);
        const tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(tests);
        zig_test_step.dependOn(&run_tests.step);
    }

    // ----- generated text file installs ----- //

    const pkgconfig_dir: Build.InstallDir = .{ .custom = b.fmt("{s}/pkgconfig", .{libdir}) };
    b.getInstallStep().dependOn(
        &b.addInstallFileWithDir(tdnf_pc.getOutputFile(), pkgconfig_dir, "tdnf.pc").step,
    );
    b.getInstallStep().dependOn(
        &b.addInstallFileWithDir(tdnf_cli_libs_pc.getOutputFile(), pkgconfig_dir, "tdnf-cli-libs.pc").step,
    );

    const install_automatic = b.addInstallFileWithDir(
        b.path("bin/tdnf-automatic"),
        .bin,
        "tdnf-automatic",
    );
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

    // The Zig integration suite. It drives the same installed binaries as
    // `check`, but each test owns an install root instead of sharing the
    // host's, so it neither mutates the machine it runs on nor has to run
    // serially. It reuses the RPM fixtures `pytests/repo/setup-repo.sh`
    // generates. The preflight fails loudly when those fixtures or root
    // privileges are absent so an all-skipped suite is never reported as
    // success.
    const ztest_step = b.step(
        "ztest",
        "Run Zig integration tests against the installed tree",
    );
    {
        const ztest_prefix = b.getInstallPath(.prefix, "");
        const ztest_preflight_script =
            \\prefix=$1
            \\repo_script=$2
            \\repo_src=$3
            \\status=0
            \\
            \\if [ "$(id -u)" -ne 0 ]; then
            \\  echo "error: ztest must run as root (package file ownership checks require uid 0)." >&2
            \\  echo 'help: re-run with: sudo -E env "PATH=$PATH" zig build ztest --prefix ./out --summary all' >&2
            \\  status=1
            \\fi
            \\
            \\tdnf="$prefix/bin/tdnf"
            \\if [ ! -x "$tdnf" ]; then
            \\  echo "error: ztest binary missing: $tdnf" >&2
            \\  echo "help: build it first with: zig build install --prefix \"$prefix\"" >&2
            \\  echo 'help: for the documented ztest layout, use: zig build install --prefix ./out' >&2
            \\  status=1
            \\fi
            \\
            \\seed="$prefix/repo/photon-test/repodata/repomd.xml"
            \\if [ ! -f "$seed" ]; then
            \\  echo "error: ztest repo seed missing: $seed" >&2
            \\  echo "help: generate it with: bash \"$repo_script\" \"$prefix/repo\" \"$repo_src\"" >&2
            \\  echo 'help: for the documented ztest layout, generate ./out/repo and run ztest with --prefix ./out' >&2
            \\  status=1
            \\fi
            \\
            \\if [ "$status" -ne 0 ]; then
            \\  echo "error: ztest preflight failed; refusing to report an all-skipped suite as passing." >&2
            \\  exit "$status"
            \\fi
        ;
        const run_ztest_preflight = b.addSystemCommand(&.{
            "bash",
            "-eu",
            "-c",
            ztest_preflight_script,
            "ztest-preflight",
            ztest_prefix,
            b.pathJoin(&.{ b.build_root.path.?, "pytests/repo/setup-repo.sh" }),
            b.pathJoin(&.{ b.build_root.path.?, "pytests/repo" }),
        });
        run_ztest_preflight.setCwd(b.path("."));

        const ztest_install_libtdnf = b.addInstallArtifact(libtdnf, .{});
        ztest_install_libtdnf.step.dependOn(&run_ztest_preflight.step);
        const ztest_install_libtdnfcli = b.addInstallArtifact(libtdnfcli, .{});
        ztest_install_libtdnfcli.step.dependOn(&run_ztest_preflight.step);
        const ztest_install_tdnf = b.addInstallArtifact(tdnf_exe, .{});
        ztest_install_tdnf.step.dependOn(&run_ztest_preflight.step);

        const ztest_mod = b.createModule(.{
            .root_source_file = b.path("ztests/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        const ztests = b.addTest(.{ .root_module = ztest_mod });
        const run_ztests = b.addRunArtifact(ztests);
        run_ztests.setEnvironmentVariable(
            "TDNF_ZTEST_PREFIX",
            ztest_prefix,
        );
        run_ztests.setEnvironmentVariable(
            "TDNF_ZTEST_PLUGIN_DIR",
            b.getInstallPath(.{ .custom = plugin_dir_rel }, ""),
        );
        run_ztests.step.dependOn(&ztest_install_libtdnf.step);
        run_ztests.step.dependOn(&ztest_install_libtdnfcli.step);
        run_ztests.step.dependOn(&ztest_install_tdnf.step);
        run_ztests.has_side_effects = true;
        ztest_step.dependOn(&run_ztests.step);

        const plugin_ztest_step = b.step(
            "plugin-ztest",
            "Run focused built-in plugin Zig integration tests",
        );
        const plugin_ztest_mod = b.createModule(.{
            .root_source_file = b.path("ztests/plugin_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        const plugin_ztests = b.addTest(.{
            .root_module = plugin_ztest_mod,
            .filters = &.{"plugin contract:"},
        });
        const run_plugin_ztests = b.addRunArtifact(plugin_ztests);
        run_plugin_ztests.setEnvironmentVariable(
            "TDNF_ZTEST_PREFIX",
            ztest_prefix,
        );
        run_plugin_ztests.setEnvironmentVariable(
            "TDNF_ZTEST_PLUGIN_DIR",
            b.getInstallPath(.{ .custom = plugin_dir_rel }, ""),
        );
        run_plugin_ztests.step.dependOn(&ztest_install_libtdnf.step);
        run_plugin_ztests.step.dependOn(&ztest_install_libtdnfcli.step);
        run_plugin_ztests.step.dependOn(&ztest_install_tdnf.step);
        run_plugin_ztests.has_side_effects = true;
        plugin_ztest_step.dependOn(&run_plugin_ztests.step);
    }

    const lint_step = b.step("lint", "Run flake8 on pytests/");
    const run_flake8 = b.addSystemCommand(&.{ "flake8", "pytests" });
    run_flake8.setCwd(b.path("."));
    lint_step.dependOn(&run_flake8.step);
    const run_source_dependency_audit = b.addSystemCommand(
        &.{ "python3", "scripts/librpm-audit.py" },
    );
    run_source_dependency_audit.setCwd(b.path("."));
    lint_step.dependOn(&run_source_dependency_audit.step);
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

const LibsolvIncludes = struct {
    /// Emitted tree; supplies <solv/*.h>.
    core: LazyPath,
    /// The same tree's solv/ subdir. Derived in init() rather than set by
    /// the caller: as a third field it could be pointed at a different
    /// tree, or at the core root, with no diagnostic. Nothing spells a
    /// flat include today, and nothing should: --system-header-prefix
    /// matches the written spelling, so <pool.h> gets no system
    /// exemption and brings back the 18 -Wextra -Werror failures in
    /// libsolv's own headers.
    flat: LazyPath,
    /// libsolvext's tree; supplies <solv/{solv_xfopen,testcase,tools_util}.h>.
    ext: LazyPath,

    fn init(
        b: *Build,
        libsolv: *Build.Step.Compile,
        libsolvext: *Build.Step.Compile,
    ) LibsolvIncludes {
        const core = libsolv.getEmittedIncludeTree();
        return .{
            .core = core,
            .flat = core.path(b, "solv"),
            .ext = libsolvext.getEmittedIncludeTree(),
        };
    }
};

fn addLibsolvIncludes(mod: *Build.Module, trees: LibsolvIncludes) void {
    // -I, not -isystem: zig cc searches /usr/include *before* user
    // -isystem directories, so with -isystem a host libsolv-devel wins
    // and the build compiles against the host's headers while linking the
    // vendored .a. tdnf_cflags carries --system-header-prefix=solv/ to
    // keep libsolv's own warnings suppressed, and both the C and Zig
    // sides assert on TDNF_VENDORED_LIBSOLV_VERSION_PATCH below so a
    // regression here fails the build instead of passing quietly.
    //
    // Known boundary -- read this before trusting the asserts. They
    // detect "the vendored tree is not on the include path at all". They
    // are NOT a per-header leakage detector, and cannot be made into one:
    // libsolv's headers are guard-macro protected, so once any vendored
    // header has been included, a host header that wins a later lookup
    // has its own #include "pool.h" skipped by the already-defined guard.
    // LIBSOLV_VERSION_PATCH stays 39 and the asserts stay silent while
    // host declarations are in scope. Only a host header included
    // *before* every vendored one trips them.
    //
    // This matters because -I pins a header only if the vendored tree
    // emits a file of that name. The pinned set is 31: the fork installs
    // libsolv's public set from src/CMakeLists.txt (27 + generated
    // solvversion.h) plus libsolvext's 3. A distro libsolv-devel also
    // ships feature headers such as repo_rpmdb.h and pool_fileconflicts.h
    // that the fork does not build, and spelling one would resolve
    // against /usr/include silently. If the translation unit calls one of
    // the functions such a header declares, the link then fails on the
    // missing symbol; macro-, enum- or typedef-only use (RPM_ADD_*,
    // FINDFILECONFLICTS_*) produces no diagnostic anywhere. Nothing in
    // the tree spells one today. Do not add such an include without
    // first making the fork emit the header.
    mod.addIncludePath(trees.core);
    mod.addIncludePath(trees.flat);
    // The ext tree goes to every consumer, not just the ones that spell
    // an ext header today. It is <dir>/solv/{solv_xfopen,testcase,
    // tools_util}.h, so omitting it did not merely leave those three
    // unavailable -- it left them resolvable from /usr/include/solv, and
    // a host testcase.h then drags in the whole host core set through
    // includer-relative quoted lookup, without -I ordering ever being
    // consulted.
    mod.addIncludePath(trees.ext);
    mod.addCMacro(
        "TDNF_VENDORED_LIBSOLV_VERSION_PATCH",
        vendored_libsolv_version_patch,
    );
}

fn configureLuaScriptletSupport(
    b: *Build,
    mod: *Build.Module,
    zlua_mod: *Build.Module,
) void {
    mod.addIncludePath(b.path("include"));
    mod.addIncludePath(b.path("rpmzig"));
    mod.addImport("zlua", zlua_mod);
}

fn hardenExe(exe: *Build.Step.Compile) void {
    exe.pie = true;
    // link_z_relro is true by default in 0.16; -z now is not directly
    // exposed by the Compile step API, so it relies on the linker default.
    exe.link_z_relro = true;
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

fn writeTemplateExecutable(
    b: *Build,
    in_rel: []const u8,
    out_rel: []const u8,
    vars: []const TemplateVar,
) void {
    writeTemplate(b, in_rel, out_rel, vars);
    b.build_root.handle.setFilePermissions(
        b.graph.io,
        out_rel,
        .executable_file,
        .{},
    ) catch |err|
        std.debug.panic(
            "unable to mark generated file '{s}' executable: {t}",
            .{ out_rel, err },
        );
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
