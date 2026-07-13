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
