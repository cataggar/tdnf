#
# Copyright (C) 2026 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#
"""
Targeted crosscheck for the composed rpmzig transaction executor.

Runs only when tdnf was built with -Drpmzig-transaction-execute=true.
When enabled, tdnf install/erase/upgrade dispatch through the composed
native executor in client/rpmtrans_native.c instead of librpm's
rpmtsRun.

Everything skips when the flag is off, so the flag-off pytest baseline
is unaffected by this file.
"""

import json
import os
import shutil
import subprocess

import pytest


HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, '..', 'config.json')
with open(CONFIG_PATH) as _cf:
    CONFIG = json.load(_cf)

REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
TDNF_BIN = os.path.join(REPO_ROOT, 'out', 'bin', 'tdnf')
TDNF_CONF = os.path.join(REPO_ROOT, 'out', 'repo', 'tdnf.conf')
LD_LIBRARY_PATH = os.path.join(REPO_ROOT, 'out', 'lib')
CASE_ROOT = os.path.join(REPO_ROOT, 'out', 'native-transaction-execute')

PKG_ONE = 'tdnf-test-one'
PKG_TWO = 'tdnf-test-two'
PKG_MULTI = 'tdnf-test-multiversion'
PKG_ORPHANS = 'tdnf-test-upgrade-orphans'
ORPHANS_ROOT_DIR = '/opt/tdnf-test-upgrade-orphans'


pytestmark = pytest.mark.skipif(
    not CONFIG.get('rpmzig_transaction_execute', False),
    reason='requires -Drpmzig-transaction-execute=true',
)


@pytest.fixture(scope='module', autouse=True)
def _skip_module_pkg_check():
    yield


@pytest.fixture(scope='module', autouse=True)
def _require_env(utils):
    if not os.path.exists(TDNF_BIN):
        pytest.skip('tdnf binary not built at {}'.format(TDNF_BIN))
    if not shutil.which('unshare'):
        pytest.skip('unshare is unavailable')
    probe = subprocess.run(
        ['unshare', '-Ur', 'true'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if probe.returncode != 0:
        pytest.skip('unshare -Ur is unavailable in this environment')
    # tdnf hardcodes /var/run/.tdnf-instance-lockfile — even with `unshare
    # -Ur` mapping our uid to root inside the namespace, the inode ACLs on
    # /var/run are enforced against our real uid. We work around this by
    # additionally creating a mount namespace (`-m`) and mounting a
    # private tmpfs on /var/run inside the wrapper. Verify that works
    # here; skip cleanly otherwise.
    lock_probe = subprocess.run(
        _unshare_wrapper() + [
            'sh', '-c',
            'touch /var/run/.tdnf-crosscheck-probe && '
            'rm -f /var/run/.tdnf-crosscheck-probe'
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if lock_probe.returncode != 0:
        pytest.skip(
            '/var/run is not writable (tdnf instance lockfile) in this '
            'environment; end-to-end tdnf crosscheck is unavailable'
        )


def _unshare_wrapper():
    """Build the wrapper that (1) fakes root and (2) mounts a private
    tmpfs on /var/run so the tdnf instance lockfile is writable.

    Uses `-Urm` (user + mount) rather than `-Urnm`, because tdnf must
    still reach the outer test HTTP server on localhost:8080 — creating
    a fresh net namespace would drop us into an empty loopback.
    """
    return [
        'unshare', '-Urm',
        'sh', '-c',
        'mount -t tmpfs tmpfs /var/run && exec "$@"',
        '--',
    ]


def _fresh_root(case):
    path = os.path.join(CASE_ROOT, case)
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.makedirs(os.path.join(path, 'var', 'lib', 'rpm'))
    return path


def _rpm_initdb(root):
    subprocess.run(
        _unshare_wrapper() + [
            'rpm', '--root', root, '--dbpath', '/var/lib/rpm', '--initdb'
        ],
        check=True,
    )


def _rpm_qa(root):
    result = subprocess.run(
        _unshare_wrapper() + [
            'rpm', '--root', root, '--dbpath', '/var/lib/rpm', '-qa'
        ],
        check=True, stdout=subprocess.PIPE, text=True,
    )
    return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())


def _run_tdnf(root, extra_args, check=True):
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = LD_LIBRARY_PATH
    cmd = _unshare_wrapper() + [
        TDNF_BIN,
        '-c', TDNF_CONF,
        '-y',
        '--installroot', root,
        '--releasever=4.0',
        '--disablerepo=*',
        '--enablerepo=photon-test-unsigned',
        '--nogpgcheck',
    ] + extra_args
    result = subprocess.run(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check:
        assert result.returncode == 0, (
            'tdnf {} failed rc={}\nstdout:\n{}\nstderr:\n{}'.format(
                ' '.join(extra_args), result.returncode,
                result.stdout, result.stderr,
            )
        )
    return result


def test_native_transaction_execute_install_and_erase(utils):
    root = _fresh_root('install-erase')
    _rpm_initdb(root)

    _run_tdnf(root, ['install', PKG_ONE])

    installed = _rpm_qa(root)
    assert any(line.startswith(PKG_ONE + '-') for line in installed), installed

    expected_file = os.path.join(
        root, 'lib', 'systemd', 'system', 'tdnf-test-one.service'
    )
    assert os.path.exists(expected_file), expected_file

    _run_tdnf(root, ['erase', PKG_ONE])

    installed_after = _rpm_qa(root)
    assert not any(line.startswith(PKG_ONE + '-') for line in installed_after), \
        installed_after
    assert not os.path.exists(expected_file), expected_file


def test_native_transaction_execute_multi_install(utils):
    root = _fresh_root('multi-install')
    _rpm_initdb(root)

    _run_tdnf(root, ['install', PKG_ONE, PKG_TWO])

    installed = _rpm_qa(root)
    assert any(line.startswith(PKG_ONE + '-') for line in installed), installed
    assert any(line.startswith(PKG_TWO + '-') for line in installed), installed


def test_native_transaction_execute_upgrade(utils):
    root = _fresh_root('upgrade')
    _rpm_initdb(root)

    _run_tdnf(root, ['install', '{}-1.0.1'.format(PKG_MULTI)])
    _run_tdnf(root, ['upgrade', PKG_MULTI])

    installed = [
        line for line in _rpm_qa(root) if line.startswith(PKG_MULTI + '-')
    ]
    assert len(installed) == 1, installed


def _paths_under(root, rel_paths):
    return {p: os.path.exists(os.path.join(root, p.lstrip('/'))) for p in rel_paths}


def test_native_transaction_execute_upgrade_removes_orphan_files(utils):
    """
    Regression check for the upgrade orphan-file cleanup gap (part of
    issue #115 / T4 gap called out on PR #129).

    The rpmzig executor previously left files unique to the OLD
    version of an upgraded package on disk as orphans. This test
    installs `tdnf-test-upgrade-orphans-1.0`, which ships:

      /opt/tdnf-test-upgrade-orphans/shared
      /opt/tdnf-test-upgrade-orphans/old-only
      /opt/tdnf-test-upgrade-orphans/nested/deep/old-only-nested

    upgrades to `-2.0` which ships:

      /opt/tdnf-test-upgrade-orphans/shared      (should stay)
      /opt/tdnf-test-upgrade-orphans/new-only    (should appear)

    and verifies that the old-only files are removed while shared
    files are preserved. Also cross-verifies against real `rpm -U`
    against a separate scratch rpmdb root to confirm behavior parity.
    """
    all_paths = [
        os.path.join(ORPHANS_ROOT_DIR, 'shared'),
        os.path.join(ORPHANS_ROOT_DIR, 'old-only'),
        os.path.join(ORPHANS_ROOT_DIR, 'nested', 'deep', 'old-only-nested'),
        os.path.join(ORPHANS_ROOT_DIR, 'new-only'),
    ]

    root = _fresh_root('upgrade-orphans')
    _rpm_initdb(root)

    _run_tdnf(root, ['install', '{}-1.0'.format(PKG_ORPHANS)])

    installed_v1 = _paths_under(root, all_paths)
    assert installed_v1[os.path.join(ORPHANS_ROOT_DIR, 'shared')], installed_v1
    assert installed_v1[os.path.join(ORPHANS_ROOT_DIR, 'old-only')], installed_v1
    assert installed_v1[
        os.path.join(ORPHANS_ROOT_DIR, 'nested', 'deep', 'old-only-nested')
    ], installed_v1
    assert not installed_v1[os.path.join(ORPHANS_ROOT_DIR, 'new-only')], installed_v1

    _run_tdnf(root, ['upgrade', PKG_ORPHANS])

    installed = [
        line for line in _rpm_qa(root) if line.startswith(PKG_ORPHANS + '-')
    ]
    assert len(installed) == 1, installed
    assert installed[0].startswith(PKG_ORPHANS + '-2.0'), installed

    after = _paths_under(root, all_paths)
    assert after[os.path.join(ORPHANS_ROOT_DIR, 'shared')], (
        'shared file must survive upgrade (owned by NEW version): {}'.format(after)
    )
    assert after[os.path.join(ORPHANS_ROOT_DIR, 'new-only')], (
        'new-only file must be installed by upgrade: {}'.format(after)
    )
    assert not after[os.path.join(ORPHANS_ROOT_DIR, 'old-only')], (
        'old-only file must be removed as an orphan on upgrade: {}'.format(after)
    )
    assert not after[
        os.path.join(ORPHANS_ROOT_DIR, 'nested', 'deep', 'old-only-nested')
    ], (
        'nested old-only file must be removed as an orphan on upgrade: {}'
        .format(after)
    )

    # Bonus: the /opt/tdnf-test-upgrade-orphans directory must still
    # exist since it contains files owned by v2 (shared, new-only).
    assert os.path.isdir(os.path.join(
        root, ORPHANS_ROOT_DIR.lstrip('/')
    )), 'v2 package root dir must still exist'

    # Cross-verify against real rpm on a separate scratch root: apply
    # the same install/upgrade using the OS `rpm` binary and confirm
    # its post-upgrade file set matches tdnf-native's.
    v1_rpms = _find_rpms('{}-1.0-1'.format(PKG_ORPHANS))
    v2_rpms = _find_rpms('{}-2.0-1'.format(PKG_ORPHANS))
    if not v1_rpms or not v2_rpms:
        pytest.skip('built RPMs for {} not found under out/repo'.format(PKG_ORPHANS))

    rpm_root = _fresh_root('upgrade-orphans-rpm-crosscheck')
    _rpm_initdb(rpm_root)
    _run_rpm(rpm_root, ['-ivh', '--nodeps', '--nosignature', v1_rpms[0]])
    _run_rpm(rpm_root, ['-Uvh', '--nodeps', '--nosignature', v2_rpms[0]])

    rpm_after = _paths_under(rpm_root, all_paths)
    assert rpm_after == after, (
        'tdnf-native upgrade file set diverges from real rpm -U:\n'
        '  tdnf: {}\n  rpm : {}'.format(after, rpm_after)
    )


def _find_rpms(name_prefix):
    """Locate built RPMs (any arch) matching a NEVRA prefix like
    'tdnf-test-upgrade-orphans-1.0-1' under out/repo/photon-test-unsigned."""
    unsigned_root = os.path.join(REPO_ROOT, 'out', 'repo', 'photon-test-unsigned', 'RPMS')
    if not os.path.isdir(unsigned_root):
        return []
    hits = []
    for arch in os.listdir(unsigned_root):
        arch_dir = os.path.join(unsigned_root, arch)
        if not os.path.isdir(arch_dir):
            continue
        for entry in os.listdir(arch_dir):
            if entry.startswith(name_prefix) and entry.endswith('.rpm'):
                hits.append(os.path.join(arch_dir, entry))
    return sorted(hits)


def _run_rpm(root, extra_args):
    result = subprocess.run(
        _unshare_wrapper() + [
            'rpm', '--root', root, '--dbpath', '/var/lib/rpm',
        ] + extra_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert result.returncode == 0, (
        'rpm {} failed rc={}\nstdout:\n{}\nstderr:\n{}'.format(
            ' '.join(extra_args), result.returncode,
            result.stdout, result.stderr,
        )
    )
    return result
