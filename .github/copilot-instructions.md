# tdnf - Copilot instructions

tdnf is "tiny dandified yum" — a C implementation of a dnf/yum-compatible package
manager built on vendored `libsolv` and the native Zig RPM stack in
`rpmzig/`, with downloads handled by Zig's HTTP/TLS stack. It ships a
public C library (`libtdnf`) plus CLI binaries and has no production
dependency on system RPM libraries, headers, or development metadata.

## Build, test, lint

The build is driven by **Zig 0.16+** (no CMake — migrated to `build.zig`).
The host needs `libgpgme-dev` on Debian/Ubuntu (the equivalent
development package on other distributions). SQLite, libsolv, and the
pure-Zig Lua scriptlet runtime are vendored dependencies. Lua scriptlet
support is unconditional because real base packages use `<lua>`-tagged
scriptlets; no system Lua headers or libraries are required.

```sh
# build + install into ./out
zig build -Doptimize=ReleaseSafe install --prefix ./out

# tests only (runs `pytest -v` in pytests/, depends on install). Needs an
# rpm-aware host with rpmbuild + createrepo_c + python pytest/requests/pyOpenSSL.
zig build check

# single pytest (cwd must be pytests/ so config.json is picked up)
cd pytests && LD_LIBRARY_PATH=../out/lib \
    pytest -v tests/test_install.py::test_install_no_arg

# python lint
zig build lint    # equivalent to: flake8 pytests
```

All compilation goes through **`zig cc`** (clang from Zig's bundled LLVM).
There is no longer a separate gcc/clang CI matrix; what `zig build`
produces locally is what CI produces.

CI builds with no RPM development files, runs unit tests, lint, ABI and
migration audits, compiles an isolated public C consumer, checks all
installed ELF files, and executes every native smoke helper. The full
pytest integration suite is run by the developer on a local rpm-aware
host. There is no Docker image or RPM packaging in this repo.

The pytest harness (`pytests/conftest.py`) sets up an HTTP repo on
`localhost:8080`, generates RPMs from specs under `pytests/repo/`, and
invokes the binaries from `./out/bin/` (or wherever `zig build install`
landed). The `utils` fixture rewrites `tdnf`/`tdnf-config` commands to
point at the build tree and injects `-c <repo_path>/tdnf.conf`
automatically — use `utils.run([...])` rather than calling `subprocess`
directly. A module-scoped autouse fixture
(`check_packages_consistency`) snapshots installed packages around
every test, so tests must clean up anything they install. Use
`utils.run_memcheck(cmd)` for valgrind coverage.

`DIST` env var (`photon` or `fedora`) is read by `conftest.py` and a
handful of test files; some tests skip or branch on distro.

The default branch for PRs is **`main`** (see CONTRIBUTING.md).

## Architecture

`build.zig` composes the project from these source dirs (each used to be
its own CMake component — the source layout is unchanged):

| Component | Output | Purpose |
|---|---|---|
| `common/` | `libcommon.a` | logging (`pr_info`/`pr_err`), memory wrappers, string utils, file locking |
| `llconf/` | `libtdnfllconf.a` | vendored ini/config parser (`.repo` and `tdnf.conf`) |
| `jsondump/` | `libjsondump.a` | JSON output used by `tdnf <cmd> -j` |
| `history/` | `libtdnfhistory.a` + `tdnf-history-util` | sqlite-backed transaction history |
| `solv/` | `libtdnfsolv.a` | thin wrapper around libsolv (pool/repo/query/goal) |
| `client/` | `libtdnf.so` | the public library — implements every `TDNF*` API in `include/tdnf.h` |
| `tools/cli/` | `tdnf` + `libtdnfcli.so` | argument parsing, output formatting, subcommand dispatch |
| `tools/config/` | `tdnf-config` | read/edit `tdnf.conf` |
| `plugins/` | `tdnfmetalink.so`, `tdnfrepogpgcheck.so` | loadable `.so`s; see `plugins/README.md` |
| `bin/` | `tdnf-automatic` | systemd-driven auto-update script (generated from `.in` template) |
| `pytests/` | (test only) | pytest-based integration tests |

Dependency direction is one-way: `tools/cli` → `client` (libtdnf) →
`solv` → `common`. Plugins link against `libtdnf` and receive events
through the event-type/state machine declared in `include/tdnfplugin.h`
and `include/tdnfplugineventmap.h`.

Public headers live in `include/`. A component must **never** include a
header from another component's source folder — only headers under
`include/` are cross-component (`docs/coding-guidelines.md`). Plugins
follow this strictly: they go through `libtdnf`'s public API only.

## Generated files (configure-time, `build.zig`'s `writeTemplate`)

The following files are produced from `*.h.in` templates at the start
of every `zig build` and written **into the source tree** (gitignored).
This matches what the prior CMake `configure_file` did and avoids the
otherwise unsolvable "two `config.h` headers shadow each other" problem
that an in-cache layout would create.

- `client/config.h` — `PACKAGE_NAME`, `VERSION`, `SYSTEM_LIBDIR`
- `history/config.h` — `HISTORY_DB_DIR`
- `plugins/{metalink,repogpgcheck}/config.h` — plugin name + version

Pkg-config files and the `tdnf-automatic` script are produced via
`b.addConfigHeader(.autoconf_at, ...)` into the build cache, then
installed.

## Native RPM implementation (issue #137 complete)

`rpmzig/` is a Zig static library that owns package parsing, rpmdb
access, OpenPGP verification, configuration, pubkey import, and the
composed transaction executor.
Today it exposes (via the C ABI in `rpmzig/rpmdb.h`,
`rpmzig/verify.h`, and the install/erase/scriptlet/trigger
engines used from `client/rpmtrans_native.c`):

- **rpmdb reader** (T1): `tdnf_rpmdb_count_packages`,
  `tdnf_rpmdb_iter_*`, `tdnf_rpmdb_cookie`,
  `tdnf_rpmdb_pubkeys_*` (walks `gpg-pubkey-*` entries — the
  imported public-key keyring).
- **`.rpm` file parser** (T2): `tdnf_rpm_file_*` — opens a
  `.rpm`, parses lead + signature header + main header, walks
  the cpio payload via `std.compress.{flate,zstd,xz}`.
- **Signature verifier** (T3): `tdnf_rpmzig_verify_pure`, plus a
  libtdnf-side wrapper `TDNFRpmzigVerify` in
  `client/gpgcheck_zig.c`. Backed entirely by the pure-Zig
  OpenPGP verifier in `rpmzig/pgp/*.zig` (see
  plan-pure-zig-pgp.md, issue #14).
- **Composed native transaction executor** (T4, issue #117):
  `client/rpmtrans_native.c` composes the rpmzig install,
  rpmdb-write, file-erase, scriptlet, trigger, and pure-Zig Lua
  engines into the sole transaction path. It runs
  `%pretrans` once, then per-item in native order
  `%pre`→file-install→rpmdb-write→`%post`→`%triggerin`; for
  upgrades the old blob is torn down via
  `%triggerun`→`%preun`→file-erase-of-old→`%postun`→`%triggerpostun`
  (arg2 correctly = 1 while the new instance survives), and
  finally `%posttrans` once. Multi-instance upgrades
  (`nPriors >= 2`) are refused loudly with a clear error.

libtdnf uses the pure-Zig OpenPGP verifier unconditionally on the
package-install path. Package headers and imported keys are handled by
rpmzig. The GPGME dependency is isolated to the optional repository
metadata signature plugin.

The crosscheck-only scaffolding flags used during T4 development
(`-Drpmzig-file-install-crosscheck`, `-Drpmzig-file-erase-crosscheck`,
`-Drpmzig-transaction-check`) and the rollback-safety
`-Drpmzig-transaction-execute` flag (which briefly gated the composed
native executor after PR #132 flipped it on by default) have been
removed — their behaviours are now unconditional. Every
`tdnf install`/`erase`/`upgrade` dispatches through the native
executor in `client/rpmtrans_native.c`; there is no host implementation
fallback.

Smoke-test consumers under `libexec/tdnf/`:
`tdnf-rpmdb-count`, `tdnf-rpmdb-list`, `tdnf-rpmdb-pubkeys`,
`tdnf-rpmdb-import-pubkeys`, `tdnf-rpmdb-write`,
`tdnf-rpm-info`, `tdnf-rpm-files`, `tdnf-rpm-verify` (the last
supports `--key` and `--rpmdb [root]`, using the same pure-Zig
verification path as libtdnf), `tdnf-rpm-install`, `tdnf-rpm-erase`,
`tdnf-rpm-trigger`, `tdnf-rpm-scriptlet`.

**Zero production librpm dependency:** system RPM headers, ABI symbols,
version probes, and link declarations are forbidden by
`scripts/librpm-audit.py`. Host `rpm`, `rpmkeys`, `rpmbuild`, and
`rpmsign` remain test-only fixture tools and behavior oracles.
`TDNFInit`/`TDNFUninit` and the legacy verbosity option remain
ABI-compatible no-ops.

**Adding gpgme-using Zig code:** don't put
`mod.linkSystemLibrary("gpgme", …)` on a static-library module —
that embeds `libgpgme.so` inside the resulting `.a` and
tdnf-side consumers fail to link. Vendored
`cataggar/zig-sqlite` is safe to import from static libraries;
`history_lib` and `rpmzig_lib` now compile SQLite in-tree and do
not rely on a system `-lsqlite3` link.

## C code conventions

These are enforced by convention (and reviewed for); deviating from them
is the most common reason for review churn. The full rules are in
`docs/coding-guidelines.md`.

**Per-component file layout.** Inside each component:

- `includes.h` — the only header any `.c` file in the component
  includes; it pulls in (in order) project headers, system headers,
  dependency headers, then `defines.h`, `structs.h`, `prototypes.h`,
  `externs.h`.
- `defines.h` / `structs.h` / `prototypes.h` / `externs.h` —
  definitions, structs, private function prototypes, extern globals.
- `globals.c` — defines globals (avoid globals where possible).

**Error handling.** Functions that can fail return `uint32_t`. Use the
`BAIL_ON_TDNF_ERROR(dwError)` macro from `include/tdnf-common-defines.h`
after each fallible call, with a single `error:` label at the bottom of
the function (optionally paired with a `cleanup:` label). Allocate to
locals, transfer to out-pointers only at the end of the success path.
See `client/api.c` for the canonical pattern. Error codes are
`ERROR_TDNF_*` from `include/tdnferror.h` (range 1000–1999); CLI-only
codes are `ERROR_TDNFCLI_*` in `include/tdnfclierror.h`. Tests assert
on these numeric codes directly (e.g. `assert ret['retval'] == 1001`),
so don't renumber existing ones.

**Memory.** Allocate with `TDNFAllocateMemory` / `TDNFAllocateString` /
`TDNFAllocateStringPrintf` (from `common/`), free with `TDNFFreeMemory`
— and prefer the `TDNF_SAFE_FREE_MEMORY(p)` /
`TDNF_SAFE_FREE_STRINGARRAY(pp)` macros, which null the pointer after
free. All allocations are zero-initialized (calloc-style).

**Output / logging.** Use `pr_info`, `pr_err`, `pr_crit` (printed
regardless of `--quiet`) and `pr_json`/`pr_jsonf` — never call
`printf`/`fprintf` directly from library code.

**Naming.** Public symbols are `TDNF<PascalCase>`; types are
`TDNF_FOO` / `PTDNF_FOO` (pointer typedef). Argument prefixes follow
Hungarian notation: `pszName` (string), `pp...` (out-pointer),
`dwError`/`dwCount` (uint32). Match the surrounding style when editing
existing files (CONTRIBUTING.md explicitly says: even if it feels
weird).

**Static functions.** Declared at the top of the `.c` file in the order
they are defined; defined at the bottom of the file.

## Things that bite

- `client/config.h`, `history/config.h`, the plugin `config.h`s, and
  the `.pc` files are **generated**. Edit the `.in` files, not the
  outputs.
- Version defaults to `default_project_version = "4.0.0"` in `build.zig`
  and also appears in `build.zig.zon`. There is no `VERSION` file
  anymore. Bumping requires both edits.
- `zig build native-dependency-audit --prefix ./out` scans source,
  dynamic dependencies, and undefined symbols. `zig build
  public-api-audit --prefix ./out` compiles each installed header and
  links a consumer with isolated package metadata.
- Plugins are off by default — set `plugins=1` in `tdnf.conf` to load
  them, and CLI flags `--enableplugin=<glob>` /
  `--disableplugin=<glob>` override per-plugin config
  (`plugins/README.md`).
- GCC-only warnings (`-Wjump-misses-init`, `-Wduplicated-cond`,
  `-Wduplicated-branches`, `-Wlogical-op`, `-Walloc-zero`,
  `-Wtrampolines`) were dropped during the move to `zig cc`. If a
  GCC-only diagnostic catches a regression, prefer fixing the C code;
  do not reintroduce the flag (clang rejects it).

## Commits & PRs

- Open PRs against the `main` branch.
- Keep commits as logical units; squash fixups into the commit that
  introduced them (CONTRIBUTING.md "Updating pull requests"). One
  self-contained commit per merge is the rule of thumb.
