#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "scripts" / "c-to-zig-baseline.json"
SOURCE_ROOTS = {
    "abi",
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

METRIC_LABELS = {
    "tracked_c_files": "Tracked .c files",
    "tracked_h_files": "Tracked .h files",
    "tracked_h_in_files": "Tracked .h.in templates",
    "tracked_c_lines": "Tracked C lines",
    "zig_cimport_files": "Zig files using @cImport",
    "zig_cinclude_directives": "@cInclude directives",
    "build_add_c_source_calls": "build.zig C-source declarations",
    "build_add_system_include_calls": "build.zig system include declarations",
    "build_link_system_library_calls": "build.zig linkSystemLibrary calls",
    "build_link_system_helper_calls": "build.zig linkSystem helper calls",
    "build_pkg_config_literals": "build.zig pkg-config command literals",
}


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
        if len(relative.parts) == 1 or relative.parts[0] in SOURCE_ROOTS:
            paths.append(ROOT / relative)
    return paths


def count_lines(paths):
    return sum(path.read_bytes().count(b"\n") for path in paths)


def collect_metrics():
    files = tracked_files()
    c_files = [path for path in files if path.suffix == ".c"]
    h_files = [path for path in files if path.suffix == ".h"]
    h_in_files = [path for path in files if path.name.endswith(".h.in")]
    zig_files = [path for path in files if path.suffix == ".zig"]
    zig_sources = [path.read_text(encoding="utf-8") for path in zig_files]
    build_source = (ROOT / "build.zig").read_text(encoding="utf-8")

    return {
        "tracked_c_files": len(c_files),
        "tracked_h_files": len(h_files),
        "tracked_h_in_files": len(h_in_files),
        "tracked_c_lines": count_lines(c_files),
        "zig_cimport_files": sum(
            "@cImport" in source for source in zig_sources
        ),
        "zig_cinclude_directives": sum(
            source.count("@cInclude") for source in zig_sources
        ),
        "build_add_c_source_calls": len(
            re.findall(r"\baddCSourceFiles?\s*\(", build_source)
        ),
        "build_add_system_include_calls": len(
            re.findall(r"\baddSystemIncludePath\s*\(", build_source)
        ),
        "build_link_system_library_calls": len(
            re.findall(r"\blinkSystemLibrary\s*\(", build_source)
        ),
        "build_link_system_helper_calls": len(
            re.findall(r"\blinkSystem\s*\(", build_source)
        ),
        "build_pkg_config_literals": build_source.count('"pkg-config"'),
    }


def load_maximums(path):
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)
    maximums = data.get("maximums")
    if not isinstance(maximums, dict):
        raise ValueError(f"{path}: missing object 'maximums'")
    missing = set(METRIC_LABELS) - set(maximums)
    extra = set(maximums) - set(METRIC_LABELS)
    if missing or extra:
        raise ValueError(
            f"{path}: metric mismatch; missing={sorted(missing)}, "
            f"extra={sorted(extra)}"
        )
    return maximums


def render_table(metrics, maximums):
    lines = [
        "| Migration metric | Current | Maximum |",
        "|---|---:|---:|",
    ]
    for key, label in METRIC_LABELS.items():
        lines.append(f"| {label} | {metrics[key]} | {maximums[key]} |")
    return "\n".join(lines)


def append_github_summary(table):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as stream:
        stream.write("## C-to-Zig migration audit\n\n")
        stream.write(table)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Report C-to-Zig migration debt and reject increases above "
            "the checked-in baseline."
        )
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help="baseline JSON path",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit current metrics as JSON",
    )
    args = parser.parse_args()

    try:
        metrics = collect_metrics()
        maximums = load_maximums(args.baseline)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"c-to-zig audit failed: {error}", file=sys.stderr)
        return 2

    table = render_table(metrics, maximums)
    append_github_summary(table)
    if args.json:
        print(json.dumps(metrics, indent=2, sort_keys=True))
    else:
        print(table)

    regressions = [
        key for key in METRIC_LABELS if metrics[key] > maximums[key]
    ]
    if regressions:
        for key in regressions:
            print(
                f"migration regression: {METRIC_LABELS[key]} is "
                f"{metrics[key]}, maximum is {maximums[key]}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
