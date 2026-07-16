#
# Copyright (C) 2019-2026 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess

import pytest


HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
OUT_DIR = os.path.join(REPO_ROOT, 'out')
TDNF_BIN = os.path.join(OUT_DIR, 'bin', 'tdnf')
TDNF_CONF = os.path.join(OUT_DIR, 'repo', 'tdnf.conf')
LD_LIBRARY_PATH = os.path.join(OUT_DIR, 'lib')
RPMDB_WRITE = os.path.join(
    OUT_DIR, 'libexec', 'tdnf', 'tdnf-rpmdb-write')
CASE_ROOT = os.path.join(OUT_DIR, 'phase7-tsflags')

PKG_ONE = 'tdnf-test-one'
PKG_VERBOSE = 'tdnf-verbose-scripts'
PKG_SCRIPTS = 'tdnf-phase7-scriptlets'
PKG_TRIGGER_OWNER = 'tdnf-phase7-trigger-owner'
PKG_TRIGGER_TARGET = 'tdnf-phase7-trigger-target'
PKG_BAD_POST = 'tdnf-phase7-bad-post'
PKG_BAD_PRE = 'tdnf-bad-pre'
PKG_PRETRANS = 'tdnf-test-pretrans-one'
PKG_PRETRANS_PROVIDER = 'tdnf-dummy-pretrans'
PKG_ORPHANS = 'tdnf-test-upgrade-orphans'
PKG_SHARED_A = 'tdnf-test-native-erase-shared-a'
PKG_SHARED_B = 'tdnf-test-native-erase-shared-b'

VERBOSE_FILE = '/lib/systemd/system/tdnf-verbose-scripts.service'
ONE_FILE = '/lib/systemd/system/tdnf-test-one.service'
SCRIPT_FILE = '/usr/share/tdnf-phase7/scriptlets'
SCRIPT_LOG = '/var/tmp/tdnf-phase7-scriptlets.log'
TRIGGER_LOG = '/var/tmp/tdnf-phase7-triggers.log'
ORPHAN_ROOT = '/opt/tdnf-test-upgrade-orphans'


def _unshare_wrapper():
    return [
        'unshare', '-Urm',
        'sh', '-c',
        'mount -t tmpfs tmpfs /var/run && exec "$@"',
        '--',
    ]


@pytest.fixture(scope='module', autouse=True)
def isolated_environment(utils):
    if not os.path.exists(TDNF_BIN):
        pytest.skip('tdnf binary is not built')
    if not shutil.which('unshare'):
        pytest.skip('unshare is unavailable')
    probe = subprocess.run(
        _unshare_wrapper() + ['true'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if probe.returncode != 0:
        pytest.skip('unshare user/mount namespaces are unavailable')
    shutil.rmtree(CASE_ROOT, ignore_errors=True)
    os.makedirs(CASE_ROOT)
    yield
    shutil.rmtree(CASE_ROOT, ignore_errors=True)


def _fresh_root(case):
    root = os.path.join(CASE_ROOT, case)
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(os.path.join(root, 'var', 'lib', 'rpm'))
    os.makedirs(os.path.join(root, 'var', 'tmp'))
    subprocess.run(
        _unshare_wrapper() + [
            'rpm', '--root', root, '--dbpath', '/var/lib/rpm', '--initdb',
        ],
        check=True,
    )
    _provision_shell(root)
    return root


def _provision_shell(root):
    for executable in ('/bin/sh', '/usr/bin/false'):
        destination = _root_path(root, executable)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copy2(executable, destination, follow_symlinks=True)
        result = subprocess.run(
            ['ldd', executable],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        for line in result.stdout.splitlines():
            for token in line.replace('=>', ' ').split():
                if not token.startswith('/') or not os.path.isfile(token):
                    continue
                library = _root_path(root, token)
                os.makedirs(os.path.dirname(library), exist_ok=True)
                shutil.copy2(token, library, follow_symlinks=True)


def _run_tdnf(root, args, check=True):
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = LD_LIBRARY_PATH
    result = subprocess.run(
        _unshare_wrapper() + [
            TDNF_BIN,
            '-c', TDNF_CONF,
            '-y',
            '--installroot', root,
            '--releasever=4.0',
            '--disablerepo=*',
            '--enablerepo=photon-test-unsigned',
            '--nogpgcheck',
        ] + args,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check:
        assert result.returncode == 0, (
            'tdnf {} failed rc={}\nstdout:\n{}\nstderr:\n{}'
            .format(' '.join(args), result.returncode,
                    result.stdout, result.stderr)
        )
    return result


def _run_rpm(root, args, check=True):
    result = subprocess.run(
        _unshare_wrapper() + [
            'rpm', '--root', root, '--dbpath', '/var/lib/rpm',
        ] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check:
        assert result.returncode == 0, result.stderr
    return result


def _installed(root, package):
    return _run_rpm(root, ['-q', package], check=False).returncode == 0


def _installed_nevras(root, package):
    result = _run_rpm(
        root,
        ['-q', '--qf', '%{NEVRA}\n', package],
        check=False,
    )
    if result.returncode != 0:
        return []
    return sorted(result.stdout.splitlines())


def _root_path(root, path):
    return os.path.join(root, path.lstrip('/'))


def _read_lines(root, path):
    rooted = _root_path(root, path)
    if not os.path.exists(rooted):
        return []
    with open(rooted, encoding='utf-8') as stream:
        return stream.read().splitlines()


def _clear_file(root, path):
    try:
        os.remove(_root_path(root, path))
    except FileNotFoundError:
        pass


def _snapshot_tree(path):
    snapshot = {}
    if not os.path.isdir(path):
        return snapshot
    for directory, _, files in os.walk(path):
        for name in sorted(files):
            if name == '.rpm.lock' or name.endswith('-shm'):
                continue
            full_path = os.path.join(directory, name)
            if name.endswith('-wal') and os.path.getsize(full_path) == 0:
                continue
            relative = os.path.relpath(full_path, path)
            with open(full_path, 'rb') as stream:
                snapshot[relative] = hashlib.sha256(stream.read()).hexdigest()
    return snapshot


def _snapshot_paths(root, paths):
    snapshot = {}
    for path in paths:
        rooted = _root_path(root, path)
        if not os.path.exists(rooted):
            snapshot[path] = None
        elif os.path.isdir(rooted):
            snapshot[path] = 'directory'
        else:
            with open(rooted, 'rb') as stream:
                snapshot[path] = hashlib.sha256(stream.read()).hexdigest()
    return snapshot


def _rpmdb_snapshot(root):
    return _snapshot_tree(os.path.join(root, 'var', 'lib', 'rpm'))


def _rpmdb_sqlite_path(root):
    path = os.path.join(root, 'var', 'lib', 'rpm', 'rpmdb.sqlite')
    assert os.path.isfile(path), path
    return path


def _rpmdb_bytes_and_sidecars(root):
    path = _rpmdb_sqlite_path(root)
    directory = os.path.dirname(path)
    basename = os.path.basename(path)
    with open(path, 'rb') as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
    sidecars = sorted(
        name for name in os.listdir(directory)
        if name.startswith(basename + '-')
    )
    return digest, sidecars


def _make_delete_journal_rpmdb_readonly(root):
    path = _rpmdb_sqlite_path(root)
    directory = os.path.dirname(path)
    lock_path = os.path.join(directory, '.rpm.lock')
    with open(lock_path, 'ab'):
        pass
    with sqlite3.connect(path) as database:
        database.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        journal_mode = database.execute(
            'PRAGMA journal_mode=DELETE'
        ).fetchone()[0]
    assert journal_mode.lower() == 'delete'

    modes = {
        path: os.stat(path).st_mode & 0o7777,
        directory: os.stat(directory).st_mode & 0o7777,
    }
    os.chmod(path, 0o444)
    os.chmod(directory, 0o555)
    return modes


def _restore_modes(modes):
    for path, mode in reversed(list(modes.items())):
        os.chmod(path, mode)


def _repo_rpm(name, evr):
    rpm_root = os.path.join(OUT_DIR, 'repo', 'build', 'RPMS')
    matches = []
    for arch in os.listdir(rpm_root):
        candidate = os.path.join(
            rpm_root, arch, '{}-{}.{}.rpm'.format(name, evr, arch))
        if os.path.isfile(candidate):
            matches.append(candidate)
    assert len(matches) == 1, matches
    return matches[0]


def _native_rpmdb_install(root, rpm_path):
    result = subprocess.run(
        [RPMDB_WRITE, 'install', root, rpm_path],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return int(result.stdout.strip())


def _seed_shell(root):
    _run_tdnf(root, ['install', 'tdnf-native-shell-provider'])


@pytest.mark.parametrize(
    'flags,db_installed,file_installed,scripts_run',
    [
        ('nodb', False, True, True),
        ('justdb', True, False, False),
        ('nodb justdb', False, False, False),
    ],
)
def test_fresh_install_database_files_and_scripts(
        flags, db_installed, file_installed, scripts_run):
    root = _fresh_root('fresh-' + flags.replace(' ', '-'))
    before = _rpmdb_snapshot(root)
    result = _run_tdnf(
        root,
        ['--setopt=tsflags=' + flags, 'install', PKG_VERBOSE],
    )
    after = _rpmdb_snapshot(root)

    if 'nodb' in flags.split():
        assert after == before
    assert _installed(root, PKG_VERBOSE) is db_installed
    assert os.path.exists(_root_path(root, VERBOSE_FILE)) is file_installed
    output = result.stdout + result.stderr
    assert ('echo from pre' in output) is scripts_run
    assert ('echo from post' in output) is scripts_run


def test_justdb_and_noscripts_suppress_failing_pre():
    for flag in ('justdb', 'noscripts'):
        root = _fresh_root('bad-pre-' + flag)
        result = _run_tdnf(
            root,
            ['--setopt=tsflags=' + flag, 'install', PKG_BAD_PRE],
        )
        assert result.returncode == 0
        assert _installed(root, PKG_BAD_PRE)


def test_dry_run_validates_without_database_file_or_script_side_effects():
    root = _fresh_root('testonly')
    db_before = _rpmdb_snapshot(root)
    tracked = [VERBOSE_FILE, '/usr/share/tdnf-native/shell-provider']
    files_before = _snapshot_paths(root, tracked)

    result = _run_tdnf(root, ['--testonly', 'install', PKG_VERBOSE])

    assert _rpmdb_snapshot(root) == db_before
    assert _snapshot_paths(root, tracked) == files_before
    assert not _installed(root, PKG_VERBOSE)
    assert 'echo from pre' not in result.stdout + result.stderr


@pytest.mark.parametrize(
    'flag,suppressed',
    [
        ('nopretrans', 'pretrans'),
        ('nopre', 'pre'),
        ('nopost', 'post'),
        ('noposttrans', 'posttrans'),
    ],
)
def test_install_phase_flags_suppress_only_requested_phase(flag, suppressed):
    root = _fresh_root('install-phase-' + flag)
    _seed_shell(root)
    _run_tdnf(
        root,
        ['--setopt=tsflags=' + flag, 'install', PKG_SCRIPTS],
    )
    phases = {
        line.split(':', 1)[0]
        for line in _read_lines(root, SCRIPT_LOG)
    }
    expected = {'pretrans', 'pre', 'post', 'posttrans'} - {suppressed}
    assert phases == expected


@pytest.mark.parametrize(
    'flag,suppressed',
    [
        ('nopreun', 'preun'),
        ('nopostun', 'postun'),
    ],
)
def test_erase_phase_flags_suppress_only_requested_phase(flag, suppressed):
    root = _fresh_root('erase-phase-' + flag)
    _seed_shell(root)
    _run_tdnf(root, ['install', PKG_SCRIPTS])
    _clear_file(root, SCRIPT_LOG)
    _run_tdnf(
        root,
        ['--setopt=tsflags=' + flag, 'erase', PKG_SCRIPTS],
    )
    phases = {
        line.split(':', 1)[0]
        for line in _read_lines(root, SCRIPT_LOG)
    }
    assert phases == {'preun', 'postun'} - {suppressed}


def test_noscripts_suppresses_package_and_transaction_phases():
    root = _fresh_root('noscripts-all-phases')
    _seed_shell(root)
    _run_tdnf(
        root,
        ['--setopt=tsflags=noscripts', 'install', PKG_SCRIPTS],
    )
    assert _read_lines(root, SCRIPT_LOG) == []
    _run_tdnf(
        root,
        ['--setopt=tsflags=noscripts', 'erase', PKG_SCRIPTS],
    )
    assert _read_lines(root, SCRIPT_LOG) == []


def _seed_trigger_owner(root):
    _run_tdnf(root, ['install', PKG_TRIGGER_OWNER])
    _clear_file(root, TRIGGER_LOG)


@pytest.mark.parametrize(
    'flag,expected',
    [
        ('notriggerin', []),
        ('notriggers', []),
        ('', ['triggerin:1:1']),
    ],
)
def test_triggerin_flags(flag, expected):
    root = _fresh_root('triggerin-' + (flag or 'normal'))
    _seed_trigger_owner(root)
    args = ['install', PKG_TRIGGER_TARGET]
    if flag:
        args.insert(0, '--setopt=tsflags=' + flag)
    _run_tdnf(root, args)
    assert _read_lines(root, TRIGGER_LOG) == expected


@pytest.mark.parametrize(
    'flag,expected_phases',
    [
        ('notriggerun', {'triggerpostun'}),
        ('notriggerpostun', {'triggerun'}),
        ('notriggers', set()),
        ('', {'triggerun', 'triggerpostun'}),
    ],
)
def test_trigger_erase_phase_flags(flag, expected_phases):
    root = _fresh_root('trigger-erase-' + (flag or 'normal'))
    _seed_trigger_owner(root)
    _run_tdnf(root, ['install', PKG_TRIGGER_TARGET])
    _clear_file(root, TRIGGER_LOG)
    args = ['erase', PKG_TRIGGER_TARGET]
    if flag:
        args.insert(0, '--setopt=tsflags=' + flag)
    _run_tdnf(root, args)
    phases = {line.split(':', 1)[0] for line in _read_lines(root, TRIGGER_LOG)}
    assert phases == expected_phases


def test_nodb_triggerin_uses_overlay_for_absent_target_row():
    root = _fresh_root('nodb-trigger-transaction-view')
    _seed_trigger_owner(root)
    db_before = _rpmdb_snapshot(root)
    _run_tdnf(
        root,
        [
            '--setopt=tsflags=nodb',
            'install',
            PKG_TRIGGER_TARGET,
        ],
    )
    assert _rpmdb_snapshot(root) == db_before
    assert not _installed(root, PKG_TRIGGER_TARGET)
    assert _read_lines(root, TRIGGER_LOG) == ['triggerin:1:1']


def test_nodb_new_trigger_owner_is_not_discovered_later():
    root = _fresh_root('nodb-trigger-owner-visibility')

    _run_tdnf(
        root,
        [
            '--setopt=tsflags=nodb',
            'install',
            PKG_TRIGGER_OWNER,
            PKG_TRIGGER_TARGET,
        ],
    )

    assert _read_lines(root, TRIGGER_LOG) == []


def test_nodb_erase_trigger_counts_ignore_unchanged_physical_row():
    root = _fresh_root('nodb-trigger-erase-view')
    _seed_trigger_owner(root)
    _run_tdnf(root, ['install', PKG_TRIGGER_TARGET])
    _clear_file(root, TRIGGER_LOG)
    db_before = _rpmdb_snapshot(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=nodb', 'erase', PKG_TRIGGER_TARGET],
    )

    assert _rpmdb_snapshot(root) == db_before
    assert _installed(root, PKG_TRIGGER_TARGET)
    assert _read_lines(root, TRIGGER_LOG) == [
        'triggerun:1:0',
        'triggerpostun:1:0',
    ]


@pytest.mark.parametrize(
    'flags,db_version,new_file,old_file',
    [
        ('nodb', '1.0', True, False),
        ('justdb', '2.0', False, True),
        ('nodb justdb', '1.0', False, True),
    ],
)
def test_upgrade_flag_matrix(flags, db_version, new_file, old_file):
    root = _fresh_root('upgrade-' + flags.replace(' ', '-'))
    _run_tdnf(root, ['install', PKG_ORPHANS + '-1.0'])
    db_before = _rpmdb_snapshot(root)
    tracked = [
        ORPHAN_ROOT + '/shared',
        ORPHAN_ROOT + '/old-only',
        ORPHAN_ROOT + '/new-only',
    ]
    files_before = _snapshot_paths(root, tracked)

    _run_tdnf(
        root,
        ['--setopt=tsflags=' + flags, 'upgrade', PKG_ORPHANS],
    )
    db_after = _rpmdb_snapshot(root)

    if 'nodb' in flags.split():
        assert db_after == db_before
    assert any(
        nevra.startswith(PKG_ORPHANS + '-' + db_version)
        for nevra in _installed_nevras(root, PKG_ORPHANS)
    )
    assert os.path.exists(_root_path(root, ORPHAN_ROOT + '/new-only')) is new_file
    assert os.path.exists(_root_path(root, ORPHAN_ROOT + '/old-only')) is old_file
    if flags == 'nodb justdb':
        assert _snapshot_paths(root, tracked) == files_before


def test_nodb_downgrade_preserves_new_install_during_old_erase():
    root = _fresh_root('nodb-downgrade-order')
    _run_tdnf(root, ['install', PKG_ORPHANS])
    db_before = _rpmdb_snapshot(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=nodb', 'downgrade', PKG_ORPHANS],
    )

    assert _rpmdb_snapshot(root) == db_before
    assert any(
        nevra.startswith(PKG_ORPHANS + '-2.0')
        for nevra in _installed_nevras(root, PKG_ORPHANS)
    )
    assert os.path.exists(_root_path(root, ORPHAN_ROOT + '/old-only'))
    assert not os.path.exists(_root_path(root, ORPHAN_ROOT + '/new-only'))
    assert os.path.exists(_root_path(root, ORPHAN_ROOT + '/shared'))


@pytest.mark.parametrize(
    'flags,db_unchanged,file_restored',
    [
        ('nodb', True, True),
        ('justdb', False, False),
        ('nodb justdb', True, False),
    ],
)
def test_reinstall_flag_matrix(flags, db_unchanged, file_restored):
    root = _fresh_root('reinstall-' + flags.replace(' ', '-'))
    _run_tdnf(root, ['install', PKG_ONE])
    os.remove(_root_path(root, ONE_FILE))
    db_before = _rpmdb_snapshot(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=' + flags, 'reinstall', PKG_ONE],
    )
    db_after = _rpmdb_snapshot(root)

    assert (db_after == db_before) is db_unchanged
    assert _installed(root, PKG_ONE)
    assert os.path.exists(_root_path(root, ONE_FILE)) is file_restored


def test_nodb_reinstall_script_counts_use_transaction_view():
    root = _fresh_root('nodb-reinstall-script-counts')
    _seed_shell(root)
    _run_tdnf(root, ['install', PKG_SCRIPTS])
    _clear_file(root, SCRIPT_LOG)
    db_before = _rpmdb_snapshot(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=nodb', 'reinstall', PKG_SCRIPTS],
    )

    assert _rpmdb_snapshot(root) == db_before
    assert _read_lines(root, SCRIPT_LOG) == [
        'pretrans:2',
        'pre:2',
        'post:2',
        'preun:1',
        'postun:1',
        'posttrans:1',
    ]


@pytest.mark.parametrize(
    'flags,db_installed,file_installed',
    [
        ('nodb', True, False),
        ('justdb', False, True),
        ('nodb justdb', True, True),
    ],
)
def test_erase_flag_matrix(flags, db_installed, file_installed):
    root = _fresh_root('erase-' + flags.replace(' ', '-'))
    _run_tdnf(root, ['install', PKG_ONE])
    db_before = _rpmdb_snapshot(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=' + flags, 'erase', PKG_ONE],
    )
    db_after = _rpmdb_snapshot(root)

    if 'nodb' in flags.split():
        assert db_after == db_before
    assert _installed(root, PKG_ONE) is db_installed
    assert os.path.exists(_root_path(root, ONE_FILE)) is file_installed


@pytest.mark.parametrize(
    'operation,flags',
    [
        ('erase', 'nodb'),
        ('erase', 'nodb justdb'),
        ('upgrade', 'nodb'),
        ('upgrade', 'nodb justdb'),
    ],
)
def test_nodb_erase_and_upgrade_do_not_open_rpmdb_writer(operation, flags):
    root = _fresh_root(
        'readonly-rpmdb-{}-{}'.format(operation, flags.replace(' ', '-'))
    )
    if operation == 'erase':
        _run_tdnf(root, ['install', PKG_ONE])
        transaction = ['erase', PKG_ONE]
    else:
        _run_tdnf(root, ['install', PKG_ORPHANS + '-1.0'])
        transaction = ['upgrade', PKG_ORPHANS]

    modes = _make_delete_journal_rpmdb_readonly(root)
    before = _rpmdb_bytes_and_sidecars(root)
    try:
        result = _run_tdnf(
            root,
            ['--setopt=tsflags=' + flags] + transaction,
            check=False,
        )
        after = _rpmdb_bytes_and_sidecars(root)
    finally:
        _restore_modes(modes)

    assert result.returncode == 0, result.stdout + result.stderr
    assert after == before


def test_nodb_shared_file_ownership_uses_transaction_view():
    root = _fresh_root('nodb-shared-owner')
    rpm_a = _repo_rpm(PKG_SHARED_A, '1.0.0-1')
    rpm_b = _repo_rpm(PKG_SHARED_B, '1.0.0-1')
    _run_rpm(
        root,
        ['-ivh', '--nodeps', '--nosignature', '--replacefiles', rpm_a, rpm_b],
    )
    db_before = _rpmdb_snapshot(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=nodb', 'erase', PKG_SHARED_A],
    )

    assert _rpmdb_snapshot(root) == db_before
    assert os.path.exists(_root_path(
        root, '/etc/tdnf-test-native-erase-shared/shared.conf'))
    assert not os.path.exists(_root_path(
        root, '/usr/share/tdnf-test-native-erase-shared/shared-dir/a.txt'))
    assert os.path.exists(_root_path(
        root, '/usr/share/tdnf-test-native-erase-shared/shared-dir/b.txt'))


def test_nodb_multi_erase_removes_path_after_last_overlay_owner():
    root = _fresh_root('nodb-shared-last-owner')
    rpm_a = _repo_rpm(PKG_SHARED_A, '1.0.0-1')
    rpm_b = _repo_rpm(PKG_SHARED_B, '1.0.0-1')
    _run_rpm(
        root,
        ['-ivh', '--nodeps', '--nosignature', '--replacefiles', rpm_a, rpm_b],
    )
    db_before = _rpmdb_snapshot(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=nodb', 'erase', PKG_SHARED_A, PKG_SHARED_B],
    )

    assert _rpmdb_snapshot(root) == db_before
    assert not os.path.exists(_root_path(
        root, '/etc/tdnf-test-native-erase-shared/shared.conf'))
    assert not os.path.exists(_root_path(
        root, '/usr/share/tdnf-test-native-erase-shared/shared-dir/a.txt'))
    assert not os.path.exists(_root_path(
        root, '/usr/share/tdnf-test-native-erase-shared/shared-dir/b.txt'))


def test_nodb_installonly_instances_share_one_ordered_overlay():
    root = _fresh_root('nodb-installonly')
    common = ['--setopt=installonlypkgs=tdnf-multi']
    _run_tdnf(
        root,
        common + ['install', 'tdnf-multi=1.0.1-4'],
    )
    db_before = _rpmdb_snapshot(root)
    _run_tdnf(
        root,
        common + [
            '--setopt=tsflags=nodb',
            'install',
            'tdnf-multi=1.0.1-1',
        ],
    )
    assert _rpmdb_snapshot(root) == db_before
    assert os.path.exists(_root_path(root, '/usr/share/multiinstall-1'))
    assert os.path.exists(_root_path(root, '/usr/share/multiinstall-4'))
    assert len(_installed_nevras(root, 'tdnf-multi')) == 1


def test_upgrade_multiplicity_prevalidation_has_no_side_effects():
    root = _fresh_root('prevalidate-multiplicity')
    _run_tdnf(root, ['install', PKG_ORPHANS + '-1.0'])
    _native_rpmdb_install(root, _repo_rpm(PKG_ORPHANS, '1.0-1'))
    tracked = [
        ORPHAN_ROOT + '/shared',
        ORPHAN_ROOT + '/old-only',
        ORPHAN_ROOT + '/new-only',
    ]
    db_before = _rpmdb_snapshot(root)
    files_before = _snapshot_paths(root, tracked)

    result = _run_tdnf(root, ['upgrade', PKG_ORPHANS], check=False)

    assert result.returncode != 0
    assert 'installed tdnf-test-upgrade-orphans instances' in (
        result.stdout + result.stderr
    )
    assert 'Error(1515)' in result.stdout + result.stderr
    assert _rpmdb_snapshot(root) == db_before
    assert _snapshot_paths(root, tracked) == files_before


def test_pretrans_problem_guidance_precedes_all_side_effects():
    root = _fresh_root('pretrans-guidance')
    db_before = _rpmdb_snapshot(root)
    result = _run_tdnf(
        root,
        ['install', PKG_PRETRANS, PKG_PRETRANS_PROVIDER],
        check=False,
    )

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert 'Detected rpm pre-transaction dependency errors.' in output
    assert 'Install tdnf-dummy-pretrans >= 1.0-1 first' in output
    assert 'Error(1515)' in output
    assert _rpmdb_snapshot(root) == db_before
    assert not _installed(root, PKG_PRETRANS)
    assert not _installed(root, PKG_PRETRANS_PROVIDER)


def test_native_file_conflict_guidance_precedes_all_side_effects():
    root = _fresh_root('file-conflict-guidance')
    db_before = _rpmdb_snapshot(root)
    conflict_path = '/usr/lib/conflict/conflicting-file'
    result = _run_tdnf(
        root,
        ['install', 'tdnf-conflict-file0', 'tdnf-conflict-file1'],
        check=False,
    )

    assert result.returncode != 0
    assert 'file {} from install of'.format(conflict_path) in (
        result.stdout + result.stderr
    )
    assert 'Error(1525)' in result.stdout + result.stderr
    assert _rpmdb_snapshot(root) == db_before
    assert not os.path.exists(_root_path(root, conflict_path))


def test_quiet_suppresses_native_progress():
    root = _fresh_root('quiet-progress')
    result = _run_tdnf(root, ['--quiet', 'install', PKG_ONE])
    output = result.stdout + result.stderr
    assert 'Running transaction (rpmzig native executor)' not in output
    assert 'Installing:' not in output


def test_json_keeps_script_output_off_stdout():
    root = _fresh_root('json-script-output')
    result = _run_tdnf(root, ['-j', 'install', PKG_VERBOSE])
    payload = json.loads(result.stdout)
    assert 'Install' in payload
    assert 'echo from pre' not in result.stdout
    assert 'echo from post' not in result.stdout
    assert 'echo from pre' in result.stderr
    assert 'echo from post' in result.stderr


def test_script_failure_severity():
    root = _fresh_root('script-failure-severity')
    critical = _run_tdnf(root, ['install', PKG_BAD_PRE], check=False)
    assert critical.returncode != 0
    assert not _installed(root, PKG_BAD_PRE)

    warning = _run_tdnf(root, ['install', PKG_BAD_POST])
    assert warning.returncode == 0
    assert _installed(root, PKG_BAD_POST)
    assert os.path.exists(_root_path(root, '/usr/share/tdnf-phase7/bad-post'))
    assert 'script warning in %post (exit 7)' in (
        warning.stdout + warning.stderr
    )


@pytest.mark.parametrize(
    'flag',
    [
        'allfiles',
        'noplugins',
        'nocontexts',
        'notriggerprein',
        'nomd5',
        'nofiledigest',
        'noartifacts',
        'deploops',
    ],
)
def test_recognized_compatibility_noop_flags_are_explicit(flag):
    root = _fresh_root('noop-' + flag)
    result = _run_tdnf(
        root,
        ['--setopt=tsflags=' + flag, 'list', PKG_ONE],
    )
    assert "tsflag '{}' is a recognized compatibility no-op".format(
        flag
    ) in result.stdout + result.stderr


def test_rpmverbosity_is_documented_compatibility_noop():
    result = subprocess.run(
        [TDNF_BIN, '--help'],
        env=dict(os.environ, LD_LIBRARY_PATH=LD_LIBRARY_PATH),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    assert '--rpmverbosity <level>' in result.stdout
    assert 'Compatibility no-op' in result.stdout
