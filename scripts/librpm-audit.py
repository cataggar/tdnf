#!/usr/bin/env python3

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_DIRS = {
    "client",
    "common",
    "history",
    "include",
    "jsondump",
    "llconf",
    "plugins",
    "repomd",
    "rpmzig",
    "solv",
    "tools",
    "xml",
}
REPOSITORY_DIRS = PRODUCTION_DIRS | {
    ".github",
    "abi",
    "bin",
    "ci",
    "docs",
    "etc",
    "pytests",
    "scripts",
}
SOURCE_SUFFIXES = {".c", ".h", ".in", ".zig"}


def tracked_files():
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = []
    for encoded in result.stdout.split(b"\0"):
        if not encoded:
            continue
        relative = Path(encoded.decode())
        if len(relative.parts) == 1 or relative.parts[0] in REPOSITORY_DIRS:
            paths.append(ROOT / relative)
    return paths


def forbidden_repository_patterns():
    package_prefix = "rp" + "m"
    legacy_library = "lib" + package_prefix + r"(?:io)?\.so"
    lua_name = "l" + "ua"
    legacy_lua_library = "lib" + lua_name + r"[0-9.]*\.so"
    return (
        (
            re.compile(
                r"#\s*include\s*[<\"]" + package_prefix + r"/"
            ),
            "system RPM header include",
        ),
        (
            re.compile(
                r"@cInclude\s*\(\s*[\"']" + package_prefix + r"/"
            ),
            "system RPM header import",
        ),
        (
            re.compile("BUILD_WITH_" + "RPM_6X"),
            "system RPM version conditional",
        ),
        (
            re.compile(
                r"pkg-config[^\n]*\b" + package_prefix + r"\b"
            ),
            "system RPM metadata probe",
        ),
        (
            re.compile(
                r"linkSystem[^\n]*[\"']" + package_prefix + r"[\"']"
            ),
            "system RPM link declaration",
        ),
        (
            re.compile(
                r"\b(?:dlopen|dlmopen)\s*\([^;\n]*[\"'][^\"']*"
                + legacy_library,
                re.IGNORECASE,
            ),
            "runtime system RPM library load",
        ),
        (
            re.compile(
                r"#\s*include\s*[<\"]" + lua_name + r"(?:[0-9.]*/)?"
            ),
            "system Lua header include",
        ),
        (
            re.compile(
                r"@cInclude\s*\(\s*[\"']" + lua_name + r"(?:[0-9.]*/)?"
            ),
            "system Lua header import",
        ),
        (
            re.compile(
                r"linkSystem[^\n]*[\"']" + lua_name + r"[0-9.]*[\"']"
            ),
            "system Lua link declaration",
        ),
        (
            re.compile(package_prefix + "zig-" + lua_name),
            "obsolete Lua runtime build selector",
        ),
        (
            re.compile(
                r"\b(?:dlopen|dlmopen)\s*\([^;\n]*[\"'][^\"']*"
                + legacy_lua_library,
                re.IGNORECASE,
            ),
            "runtime system Lua library load",
        ),
    )


def strip_comments_and_literals(source):
    def preserve_lines(match):
        return "\n" * match.group(0).count("\n")

    source = re.sub(r"/\*.*?\*/", preserve_lines, source, flags=re.S)
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r'"(?:\\.|[^"\\])*"', '""', source)
    source = re.sub(r"'(?:\\.|[^'\\])*'", "''", source)
    return source


def forbidden_c_identifiers():
    return re.compile(
        r"\b(?:"
        r"FD_t|"
        r"F(?:open|close|read|write|seek|tell|error|ileno)|"
        r"pgp(?:Armor|ParsePkts)|"
        r"header(?:Get|Is|Free|Link|New|Reload|Copy)[A-Za-z0-9_]*|"
        r"rpm(?:ReadConfigFiles|FreeRpmrc|SetVerbosity|"
        r"Expand|GetPath|DefineMacro|LoadMacros|FreeMacros|"
        r"PushMacro|PopMacro|vercmp)|"
        r"rpm" r"ts[A-Za-z0-9_]*|"
        r"rpm" r"ds[A-Za-z0-9_]*|"
        r"rpm" r"Problem[A-Za-z0-9_]*|"
        r"RPM(?:CALLBACK|VSF|PROB|LOG|TAG)_[A-Z0-9_]+"
        r")\b"
    )


def line_number(source, offset):
    return source.count("\n", 0, offset) + 1


def source_errors(files):
    errors = []
    repository_patterns = forbidden_repository_patterns()
    c_identifiers = forbidden_c_identifiers()

    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        relative = path.relative_to(ROOT)
        for pattern, description in repository_patterns:
            for match in pattern.finditer(source):
                errors.append(
                    f"{relative}:{line_number(source, match.start())}: "
                    f"{description}"
                )

        if (
            not relative.parts
            or relative.parts[0] not in PRODUCTION_DIRS
            or path.suffix not in SOURCE_SUFFIXES
        ):
            continue
        lexical_source = strip_comments_and_literals(source)
        for match in c_identifiers.finditer(lexical_source):
            if (
                path.suffix == ".zig"
                and match.group(0).startswith("RPMTAG_")
            ):
                continue
            errors.append(
                f"{relative}:{line_number(lexical_source, match.start())}: "
                f"system RPM identifier {match.group(0)}"
            )

        if path.suffix in {".c", ".h", ".in"}:
            for match in re.finditer(
                r"#\s*include\s*<" + "rpmdb" + r"\.h>",
                lexical_source,
            ):
                errors.append(
                    f"{relative}:"
                    f"{line_number(lexical_source, match.start())}: "
                    "system RPM database header include"
                )
            for match in re.finditer(r"\bHeader\b", lexical_source):
                errors.append(
                    f"{relative}:"
                    f"{line_number(lexical_source, match.start())}: "
                    "system RPM Header type"
                )
    return errors


def is_elf(path):
    try:
        with path.open("rb") as stream:
            return stream.read(4) == b"\x7fELF"
    except OSError:
        return False


def command_output(argv):
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"{' '.join(argv)} failed ({result.returncode}): {detail}"
        )
    return result.stdout


def elf_errors(prefix):
    errors = []
    elf_paths = sorted(
        path for path in prefix.rglob("*")
        if path.is_file() and is_elf(path)
    )
    if not elf_paths:
        return [f"{prefix}: no installed ELF files found"]

    undefined_pattern = re.compile(
        r"^(?:rpm|rpmlog|header[A-Z_]|pgp[A-Z_]|F[A-Z])"
    )
    needed_pattern = re.compile(
        r"\blib(?:rpm(?:io)?|sqlite3|solv(?:ext)?|lua[0-9.]*)\.so(?:\.|])"
    )
    runtime_load_pattern = re.compile(
        r"\blib(?:" + "rpm" + r"(?:io)?|" + "lua" +
        r"[0-9.]*)\.so(?:\.[0-9]+)*\b"
    )

    for path in elf_paths:
        dynamic = command_output(["readelf", "-d", "--", str(path)])
        if needed_pattern.search(dynamic):
            errors.append(
                f"{path}: DT_NEEDED references a vendored or native backend"
            )
        dynamic_strings = command_output(
            ["readelf", "--string-dump=.dynstr", "--", str(path)]
        )
        if runtime_load_pattern.search(dynamic_strings):
            errors.append(
                f"{path}: dynamic strings reference a system RPM library"
            )

        undefined = command_output(
            ["nm", "-D", "--undefined-only", "--", str(path)]
        )
        for line in undefined.splitlines():
            fields = line.split()
            if not fields:
                continue
            symbol = fields[-1].split("@", 1)[0]
            if undefined_pattern.match(symbol):
                errors.append(
                    f"{path}: undefined system RPM symbol {symbol}"
                )
    return errors


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Reject system RPM/Lua headers, build declarations, and "
            "installed ELF dependencies."
        )
    )
    parser.add_argument(
        "--prefix",
        type=Path,
        help="also inspect every ELF below this install prefix",
    )
    args = parser.parse_args()

    try:
        errors = source_errors(tracked_files())
        if args.prefix is not None:
            prefix = args.prefix.resolve()
            if not prefix.is_dir():
                raise FileNotFoundError(prefix)
            errors.extend(elf_errors(prefix))
    except (
        FileNotFoundError,
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"native dependency audit failed: {error}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"native dependency regression: {error}", file=sys.stderr)
        return 1

    scope = "source and installed ELF files" if args.prefix else "source"
    print(f"Native dependency audit passed ({scope})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
