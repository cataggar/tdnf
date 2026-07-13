#
# Copyright (C) 2025 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License"); you may
# not use this file except in compliance with the License. The terms of the
# License are located in the COPYING file of this distribution.
#

import platform
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest


ARCH = platform.machine()
REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "out"
SPEC_DIR = REPO_ROOT / "pytests" / "repo"
TEST_ROOT = OUT_DIR / "rpmzig-rpmdb-write-tests"
WRITE_TOOL = OUT_DIR / "libexec" / "tdnf" / "tdnf-rpmdb-write"
COUNT_TOOL = OUT_DIR / "libexec" / "tdnf" / "tdnf-rpmdb-count"
LIST_TOOL = OUT_DIR / "libexec" / "tdnf" / "tdnf-rpmdb-list"

pytestmark = pytest.mark.skipif(
    not WRITE_TOOL.exists() or
    shutil.which("rpm") is None or
    shutil.which("rpmbuild") is None or
    shutil.which("unshare") is None,
    reason="rpmzig rpmdb write crosscheck prerequisites are unavailable",
)


def run(cmd, check=True):
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            "command failed: {}\nstdout:\n{}\nstderr:\n{}".format(
                " ".join(str(part) for part in cmd),
                result.stdout,
                result.stderr,
            )
        )
    return result


def run_rpm_root(root, args, check=True):
    cmd = [
        "unshare",
        "-Ur",
        "bash",
        "-lc",
        'rpm --root "$1" "${@:2}"',
        "_",
        str(root),
        *[str(arg) for arg in args],
    ]
    return run(cmd, check=check)


def clear_tree(path):
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def build_test_rpms():
    build_root = TEST_ROOT / "rpmbuild"
    clear_tree(build_root)

    for rel in [
        "BUILD",
        "BUILDROOT",
        "RPMS",
        "SRPMS",
        "SOURCES",
        "SPECS",
    ]:
        (build_root / rel).mkdir(parents=True, exist_ok=True)

    specs = {
        "install": "tdnf-test-one.spec",
        "lower": "tdnf-test-multiversion-1.0.1.spec",
        "higher": "tdnf-test-multiversion-1.0.2.spec",
    }
    for spec in specs.values():
        run([
            "rpmbuild",
            "-D",
            "_topdir {}".format(build_root),
            "-bb",
            str(SPEC_DIR / spec),
        ])

    rpm_dir = build_root / "RPMS" / ARCH
    return {
        "install": rpm_dir / "tdnf-test-one-1.0.1-2.{}.rpm".format(ARCH),
        "lower": rpm_dir / "tdnf-test-multiversion-1.0.1-1.{}.rpm".format(ARCH),
        "higher": rpm_dir / "tdnf-test-multiversion-1.0.2-1.{}.rpm".format(ARCH),
    }


def rpmdb_path(root):
    return root / "var" / "lib" / "rpm" / "rpmdb.sqlite"


def normalize_sql(sql):
    if sql is None:
        return None
    return " ".join(sql.split()).replace(", ", ",")


def load_db_state(root):
    con = sqlite3.connect(rpmdb_path(root))
    cur = con.cursor()

    # sqlite_stat1 is planner metadata. rpm 4.18 updates it
    # opportunistically and can leave stale rows behind after erase, so
    # the semantic crosscheck focuses on the rpmdb schema proper plus
    # every logical data table, including sqlite_sequence.
    raw_schema = cur.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_master
        WHERE name != 'sqlite_stat1'
        ORDER BY type, name
        """
    ).fetchall()
    schema = [
        (row[0], row[1], row[2], normalize_sql(row[3]))
        for row in raw_schema
    ]

    tables = {}
    table_names = cur.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name != 'sqlite_stat1'
        ORDER BY name
        """
    ).fetchall()
    for (table_name,) in table_names:
        columns = [row[1] for row in cur.execute("PRAGMA table_info('{}')".format(table_name))]
        selected = ", ".join('"{}"'.format(col) for col in columns)
        ordering = ", ".join(str(idx) for idx in range(1, len(columns) + 1))
        tables[table_name] = cur.execute(
            "SELECT {} FROM '{}' ORDER BY {}".format(selected, table_name, ordering)
        ).fetchall()

    return {
        "schema": schema,
        "tables": tables,
    }


def assert_db_state_matches(native_root, real_root):
    native = load_db_state(native_root)
    real = load_db_state(real_root)
    assert native["schema"] == real["schema"]
    assert native["tables"] == real["tables"]


def rpm_query(root, package, query_format):
    return run_rpm_root(root, ["-q", "--qf", query_format, package]).stdout.strip()


def rpm_command_result(root, args):
    result = run_rpm_root(root, args, check=False)
    return {
        "retval": result.returncode,
        "stdout": result.stdout.splitlines(),
        "stderr": result.stderr.splitlines(),
    }


def assert_rpm_view_matches(native_root, real_root, package):
    commands = [
        ["-qa"],
        ["-q", package],
        ["-V", package],
    ]
    for args in commands:
        assert rpm_command_result(native_root, args) == rpm_command_result(real_root, args)


def find_hnum(root, nevra):
    result = run([str(WRITE_TOOL), "find-hnum", str(root), nevra], check=False)
    return result.returncode, result.stdout.strip(), result.stderr


@pytest.fixture(scope="module")
def rpm_fixtures():
    clear_tree(TEST_ROOT)
    return build_test_rpms()


def prepare_case(name):
    case_root = TEST_ROOT / name
    native_root = case_root / "native"
    real_root = case_root / "real"
    clear_tree(native_root)
    clear_tree(real_root)
    return native_root.resolve(), real_root.resolve()


def install_real(root, rpm_path):
    run_rpm_root(root, ["--initdb"])
    run_rpm_root(root, ["-i", "--justdb", "--nodeps", "--nosignature", str(rpm_path)])


def install_native(root, rpm_path, install_tid, install_time):
    result = run([
        str(WRITE_TOOL),
        "install",
        str(root),
        str(rpm_path),
        str(install_tid),
        str(install_time),
        "3",
    ])
    return int(result.stdout.strip())


def replace_native(root, old_hnum, rpm_path, install_tid, install_time):
    result = run([
        str(WRITE_TOOL),
        "replace",
        str(root),
        str(old_hnum),
        str(rpm_path),
        str(install_tid),
        str(install_time),
        "3",
    ])
    return int(result.stdout.strip())


def erase_native(root, hnum):
    run([str(WRITE_TOOL), "erase-hnum", str(root), str(hnum)])


def single_hnum(root):
    con = sqlite3.connect(rpmdb_path(root))
    return con.execute("SELECT hnum FROM Packages").fetchone()[0]


def single_nevra(root, package):
    return rpm_query(root, package, "%{NEVRA}\n")


def install_meta(root, package):
    out = rpm_query(root, package, "%{INSTALLTID} %{INSTALLTIME}\n")
    tid, when = out.split()
    return int(tid), int(when)


def test_rpmzig_rpmdb_write_install_matches_real_rpm(rpm_fixtures):
    native_root, real_root = prepare_case("install")
    rpm_path = rpm_fixtures["install"]
    package = "tdnf-test-one"

    install_real(real_root, rpm_path)
    install_tid, install_time = install_meta(real_root, package)
    nevra = single_nevra(real_root, package)

    assert install_native(native_root, rpm_path, install_tid, install_time) == 1
    assert run([str(COUNT_TOOL), str(native_root)]).stdout.strip() == "1"
    assert run([str(LIST_TOOL), str(native_root)]).stdout.splitlines() == [nevra]

    rc, stdout, stderr = find_hnum(native_root, nevra)
    assert rc == 0, stderr
    assert stdout == "1"

    assert_db_state_matches(native_root, real_root)
    assert_rpm_view_matches(native_root, real_root, package)


def test_rpmzig_rpmdb_write_upgrade_matches_real_rpm(rpm_fixtures):
    native_root, real_root = prepare_case("upgrade")
    lower_rpm = rpm_fixtures["lower"]
    higher_rpm = rpm_fixtures["higher"]
    package = "tdnf-test-multiversion"

    install_real(real_root, lower_rpm)
    install_tid, install_time = install_meta(real_root, package)
    old_hnum = single_hnum(real_root)
    assert install_native(native_root, lower_rpm, install_tid, install_time) == old_hnum

    run_rpm_root(real_root, ["-U", "--justdb", "--nodeps", "--nosignature", str(higher_rpm)])
    replace_tid, replace_time = install_meta(real_root, package)
    real_new_hnum = single_hnum(real_root)
    native_new_hnum = replace_native(native_root, old_hnum, higher_rpm, replace_tid, replace_time)

    assert native_new_hnum == real_new_hnum == 2
    assert_db_state_matches(native_root, real_root)
    assert_rpm_view_matches(native_root, real_root, package)


def test_rpmzig_rpmdb_write_reinstall_matches_real_rpm(rpm_fixtures):
    native_root, real_root = prepare_case("reinstall")
    rpm_path = rpm_fixtures["lower"]
    package = "tdnf-test-multiversion"

    install_real(real_root, rpm_path)
    install_tid, install_time = install_meta(real_root, package)
    old_hnum = single_hnum(real_root)
    assert install_native(native_root, rpm_path, install_tid, install_time) == old_hnum

    run_rpm_root(real_root, ["-U", "--replacepkgs", "--justdb", "--nodeps", "--nosignature", str(rpm_path)])
    replace_tid, replace_time = install_meta(real_root, package)
    real_new_hnum = single_hnum(real_root)
    native_new_hnum = replace_native(native_root, old_hnum, rpm_path, replace_tid, replace_time)

    assert native_new_hnum == real_new_hnum == 2
    assert_db_state_matches(native_root, real_root)
    assert_rpm_view_matches(native_root, real_root, package)


def test_rpmzig_rpmdb_write_erase_matches_real_rpm(rpm_fixtures):
    native_root, real_root = prepare_case("erase")
    rpm_path = rpm_fixtures["lower"]
    package = "tdnf-test-multiversion"

    install_real(real_root, rpm_path)
    install_tid, install_time = install_meta(real_root, package)
    old_hnum = single_hnum(real_root)
    assert install_native(native_root, rpm_path, install_tid, install_time) == old_hnum

    run_rpm_root(real_root, ["-e", "--justdb", "--nodeps", package])
    erase_native(native_root, old_hnum)

    assert_db_state_matches(native_root, real_root)
    assert_rpm_view_matches(native_root, real_root, package)

    rc, stdout, _ = find_hnum(native_root, "{}-1.0.1-1.{}".format(package, ARCH))
    assert rc == 3
    assert stdout == ""


def test_rpmzig_rpmdb_write_refuses_legacy_backend_markers(rpm_fixtures):
    legacy_root, _ = prepare_case("legacy-backend")
    legacy_db_dir = legacy_root / "var" / "lib" / "rpm"
    legacy_db_dir.mkdir(parents=True, exist_ok=True)
    (legacy_db_dir / "Packages").write_text("legacy backend marker", encoding="utf-8")

    result = run([
        str(WRITE_TOOL),
        "install",
        str(legacy_root),
        str(rpm_fixtures["install"]),
        "1",
        "1",
        "3",
    ], check=False)
    assert result.returncode == 1
    assert "UnsupportedBackend" in result.stderr
