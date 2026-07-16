#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "scripts" / "abi-baseline.json"
PUBLIC_SYMBOL = re.compile(
    r"^(?:TDNF[A-Za-z0-9_]*|tdnf_rpm_config_[A-Za-z0-9_]*)$"
)
COMPATIBILITY_HEADERS = (
    ROOT / "plugins" / "metalink" / "xml.h",
)
EXPECTED_SONAMES = {
    "libtdnf": "libtdnf.so.4",
    "libtdnfcli": "libtdnfcli.so.4",
}


def artifact_paths(prefix):
    lib_dir = prefix / "lib"

    def versioned_library(stem):
        candidates = sorted(
            lib_dir.glob(f"{stem}.so.*"),
            key=lambda path: (path.name.count("."), len(path.name), path.name),
        )
        if not candidates:
            raise FileNotFoundError(f"{lib_dir}/{stem}.so.*")
        return candidates[-1]

    return {
        "libtdnf": versioned_library("libtdnf"),
        "libtdnfcli": versioned_library("libtdnfcli"),
        "libtdnfmetalink": (
            lib_dir / "tdnf-plugins" / "libtdnfmetalink.so"
        ),
        "libtdnfrepogpgcheck": (
            lib_dir / "tdnf-plugins" / "libtdnfrepogpgcheck.so"
        ),
    }


def public_symbols(path):
    result = subprocess.run(
        ["nm", "-D", "--defined-only", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    symbols = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        symbol = fields[-1].split("@", 1)[0]
        if PUBLIC_SYMBOL.fullmatch(symbol):
            symbols.add(symbol)
    return sorted(symbols)


def dynamic_soname(path):
    result = subprocess.run(
        ["readelf", "-d", "--", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    match = re.search(r"\(SONAME\).*\[([^\]]+)\]", result.stdout)
    if not match:
        raise ValueError(f"{path}: missing DT_SONAME")
    return match.group(1)


def header_hashes(headers_dir):
    headers = sorted(headers_dir.glob("*.h"))
    if not headers:
        raise FileNotFoundError(f"{headers_dir}/*.h")
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in headers
    }


def compatibility_header_hashes():
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in COMPATIBILITY_HEADERS
    }


def collect_snapshot(prefix, headers_dir):
    artifacts = artifact_paths(prefix)
    for path in artifacts.values():
        if not path.is_file():
            raise FileNotFoundError(path)
    for name, expected in EXPECTED_SONAMES.items():
        actual = dynamic_soname(artifacts[name])
        if actual != expected:
            raise ValueError(
                f"{artifacts[name]}: DT_SONAME is {actual}, "
                f"expected {expected}"
            )
    return {
        "compatibility_headers_sha256": compatibility_header_hashes(),
        "public_headers_sha256": header_hashes(headers_dir),
        "public_symbols": {
            name: public_symbols(path)
            for name, path in artifacts.items()
        },
    }


def load_snapshot(path):
    with path.open(encoding="utf-8") as stream:
        snapshot = json.load(stream)
    if set(snapshot) != {
        "compatibility_headers_sha256",
        "public_headers_sha256",
        "public_symbols",
    }:
        raise ValueError(f"{path}: invalid ABI baseline keys")
    return snapshot


def compare_maps(label, expected, actual):
    errors = []
    expected_keys = set(expected)
    actual_keys = set(actual)
    for key in sorted(expected_keys - actual_keys):
        errors.append(f"{label}: removed {key}")
    for key in sorted(actual_keys - expected_keys):
        errors.append(f"{label}: added {key}")
    for key in sorted(expected_keys & actual_keys):
        if expected[key] != actual[key]:
            errors.append(f"{label}: changed {key}")
    return errors


def compare_snapshots(expected, actual):
    errors = compare_maps(
        "compatibility header",
        expected["compatibility_headers_sha256"],
        actual["compatibility_headers_sha256"],
    )
    errors.extend(
        compare_maps(
            "public header",
            expected["public_headers_sha256"],
            actual["public_headers_sha256"],
        )
    )
    expected_symbols = expected["public_symbols"]
    actual_symbols = actual["public_symbols"]
    errors.extend(
        compare_maps("artifact", expected_symbols, actual_symbols)
    )
    for artifact in sorted(set(expected_symbols) & set(actual_symbols)):
        expected_set = set(expected_symbols[artifact])
        actual_set = set(actual_symbols[artifact])
        for symbol in sorted(expected_set - actual_set):
            errors.append(f"{artifact}: removed symbol {symbol}")
        for symbol in sorted(actual_set - expected_set):
            errors.append(f"{artifact}: added symbol {symbol}")
    return errors


def render_summary(snapshot):
    headers = len(snapshot["public_headers_sha256"])
    compatibility_headers = len(
        snapshot["compatibility_headers_sha256"]
    )
    lines = [
        "| ABI surface | Count |",
        "|---|---:|",
        f"| Public headers | {headers} |",
        f"| Internal compatibility headers | {compatibility_headers} |",
    ]
    for artifact, symbols in snapshot["public_symbols"].items():
        lines.append(f"| `{artifact}` public symbols | {len(symbols)} |")
    return "\n".join(lines)


def append_github_summary(table):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as stream:
        stream.write("## Public ABI audit\n\n")
        stream.write(table)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Compare public TDNF headers and exported symbols with the "
            "checked-in ABI baseline."
        )
    )
    parser.add_argument(
        "--prefix",
        type=Path,
        default=ROOT / "out",
        help="installed build prefix",
    )
    parser.add_argument(
        "--headers-dir",
        type=Path,
        default=ROOT / "include",
        help="directory containing public headers",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help="ABI baseline JSON path",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="replace the baseline with the current snapshot",
    )
    args = parser.parse_args()

    try:
        actual = collect_snapshot(args.prefix.resolve(), args.headers_dir)
        if args.update_baseline:
            with args.baseline.open("w", encoding="utf-8") as stream:
                json.dump(actual, stream, indent=2, sort_keys=True)
                stream.write("\n")
        expected = load_snapshot(args.baseline)
    except (
        OSError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(f"ABI audit failed: {error}", file=sys.stderr)
        return 2

    table = render_summary(actual)
    append_github_summary(table)
    print(table)

    errors = compare_snapshots(expected, actual)
    if errors:
        for error in errors:
            print(f"ABI regression: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
