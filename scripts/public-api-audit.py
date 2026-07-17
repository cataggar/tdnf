#!/usr/bin/env python3

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
METADATA_TOOL = "pkg-config"
LEGACY_MODULE = "r" + "pm"


def run(argv, **kwargs):
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        **kwargs,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"{' '.join(argv)} failed ({result.returncode}): {detail}"
        )
    return result


def metadata_environment(prefix):
    environment = os.environ.copy()
    environment["PKG_CONFIG_PATH"] = ""
    environment["PKG_CONFIG_LIBDIR"] = str(prefix / "lib" / "pkgconfig")
    return environment


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Compile and link an external consumer against installed "
            "public headers and package metadata."
        )
    )
    parser.add_argument(
        "--prefix",
        type=Path,
        default=ROOT / "out",
        help="installed build prefix",
    )
    parser.add_argument(
        "--require-external-prefix",
        action="store_true",
        help="fail unless the installed prefix is outside the repository",
    )
    args = parser.parse_args()

    prefix = args.prefix.resolve()
    if (args.require_external_prefix and (
        prefix == ROOT or ROOT in prefix.parents
    )):
        print(
            f"public API audit prefix must be outside repository: {prefix}",
            file=sys.stderr,
        )
        return 1
    headers_dir = prefix / "include" / "tdnf"
    workdir = Path(tempfile.mkdtemp(prefix="tdnf-public-api-")).resolve()
    if workdir == ROOT or ROOT in workdir.parents:
        raise RuntimeError(
            f"public API audit workdir must be outside repository: {workdir}"
        )
    output = workdir / "consumer"
    environment = metadata_environment(prefix)

    try:
        if not headers_dir.is_dir():
            raise FileNotFoundError(headers_dir)

        legacy_probe = subprocess.run(
            [METADATA_TOOL, "--exists", LEGACY_MODULE],
            check=False,
            env=environment,
        )
        if legacy_probe.returncode == 0:
            raise RuntimeError(
                "legacy system package metadata is visible in the "
                "isolated consumer environment"
            )

        metadata = run(
            [METADATA_TOOL, "--cflags", "--libs", "tdnf"],
            env=environment,
            cwd=workdir,
        )
        flags = shlex.split(metadata.stdout)
        compiler = os.environ.get("CC", "cc")
        headers = sorted(path.name for path in headers_dir.glob("*.h"))
        if not headers:
            raise RuntimeError(f"{headers_dir}: no public headers found")

        standard_headers = (
            "#include <stdbool.h>\n"
            "#include <stddef.h>\n"
            "#include <stdint.h>\n"
            "#include <time.h>\n"
        )
        for header in headers:
            source = (
                standard_headers
                + f"#include <{header}>\n"
                + "int main(void) { return 0; }\n"
            )
            run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsyntax-only",
                    "-x",
                    "c",
                    "-",
                    *flags,
                ],
                input=source,
                env=environment,
                cwd=workdir,
            )

        includes = "".join(
            f"#include <{header}>\n" for header in headers
        )
        consumer = (
            standard_headers
            + includes
            + "\n"
            + "_Static_assert(sizeof(TDNF_RPMTRANS_FLAGS) == 4, "
            + '"transaction flags ABI changed");\n'
            + "int main(void) {\n"
            + "    tdnf_rpm_config *config;\n"
            + "    if (TDNFInit() != 0) return 1;\n"
            + '    config = tdnf_rpm_config_create("/");\n'
            + "    if (config == NULL) return 2;\n"
            + "    tdnf_rpm_config_destroy(config);\n"
            + "    TDNFUninit();\n"
            + "    return 0;\n"
            + "}\n"
        )
        run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-x",
                "c",
                "-",
                *flags,
                f"-Wl,-rpath,{prefix / 'lib'}",
                "-o",
                str(output),
            ],
            input=consumer,
            env=environment,
            cwd=workdir,
        )
        run([str(output)], env=environment, cwd=workdir)

        repos_dir = workdir / "repos"
        cache_path = workdir / "cache"
        repos_dir.mkdir()
        cache_path.mkdir()
        runtime_config = workdir / "tdnf.conf"
        runtime_config.write_text(
            "[main]\n"
            "plugins=1\n"
            f"pluginconfpath={prefix / 'etc' / 'tdnf' / 'pluginconf.d'}\n"
            f"repodir={repos_dir}\n"
            f"cachedir={cache_path}\n"
            "gpgcheck=0\n",
            encoding="utf-8",
        )
        runtime_environment = environment.copy()
        runtime_environment["LD_LIBRARY_PATH"] = str(prefix / "lib")
        runtime = run(
            [
                str(prefix / "bin" / "tdnf"),
                "-c",
                str(runtime_config),
                "--releasever",
                "1",
                "repolist",
            ],
            env=runtime_environment,
            cwd=workdir,
        )
        loaded = set(runtime.stdout.splitlines())
        expected_plugins = {
            "Loaded plugin: tdnfmetalink",
            "Loaded plugin: tdnfrepogpgcheck",
        }
        if not expected_plugins.issubset(loaded):
            raise RuntimeError(
                "installed tdnf did not load plugins from its absolute "
                f"default directory {prefix / 'lib' / 'tdnf-plugins'}"
            )
    except (FileNotFoundError, OSError, RuntimeError) as error:
        print(f"public API audit failed: {error}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print(
        f"Public API audit passed ({len(headers)} installed headers, "
        "isolated package metadata)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
