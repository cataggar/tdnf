#
# Copyright (C) 2026 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License"); you may
# not use this file except in compliance with the License. The terms
# are located in the COPYING file of this distribution.
#

import hashlib
import os
import shutil
import sqlite3
import struct
import subprocess

import pytest


REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..'))
OUT_DIR = os.path.join(REPO_ROOT, 'out')
TDNF_BIN = os.path.join(OUT_DIR, 'bin', 'tdnf')
TDNF_CONF = os.path.join(OUT_DIR, 'repo', 'tdnf.conf')
LD_LIBRARY_PATH = os.path.join(OUT_DIR, 'lib')
CASE_ROOT = os.path.join(OUT_DIR, 'native-file-trigger-tests')

OWNER = 'tdnf-phase7-filetrigger-owner'
OWNER_SECOND = 'tdnf-phase7-filetrigger-owner-second'
FLAGS_OWNER = 'tdnf-phase7-filetrigger-flags'
BAD_QUERY_OWNER = 'tdnf-phase7-filetrigger-bad-query'
ADDED_OWNER = 'tdnf-phase7-filetrigger-added-owner'
REMOVED_OWNER = 'tdnf-phase7-filetrigger-removed-owner'
REPLACEMENT_TARGET = 'tdnf-phase7-filetarget-replacement'
TARGET = 'tdnf-phase7-filetarget'
TARGET_V1 = TARGET + '-1.0.0'
EXTRA = 'tdnf-phase7-filetarget-extra'
SHARED_A = 'tdnf-phase7-filetarget-shared-a'
SHARED_B = 'tdnf-phase7-filetarget-shared-b'
LOG = '/var/lib/tdnf-phase7-filetriggers.log'
TARGET_ROOT = '/usr/share/tdnf-phase7-filetarget'
SHARED_ROOT = '/usr/share/tdnf-phase7-shared'


@pytest.fixture(scope='module', autouse=True)
def check_packages_consistency():
    yield


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


def _unshare_wrapper():
    return [
        'unshare', '-Urm',
        'sh', '-c',
        'mount -t tmpfs tmpfs /var/run && exec "$@"',
        '--',
    ]


def _root_path(root, path):
    return os.path.join(root, path.lstrip('/'))


def _fresh_root(case):
    root = os.path.join(CASE_ROOT, case)
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(os.path.join(root, 'var', 'lib', 'rpm'))
    subprocess.run(
        _unshare_wrapper() + [
            'rpm', '--root', root, '--dbpath', '/var/lib/rpm', '--initdb',
        ],
        check=True,
    )
    _provision_shell(root)
    return root


def _provision_shell(root):
    destination = _root_path(root, '/bin/sh')
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    shutil.copy2('/bin/sh', destination, follow_symlinks=True)
    result = subprocess.run(
        ['ldd', '/bin/sh'],
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


def _read_lines(root):
    path = _root_path(root, LOG)
    if not os.path.exists(path):
        return []
    with open(path, encoding='utf-8') as stream:
        return stream.read().splitlines()


def _clear_log(root):
    try:
        os.remove(_root_path(root, LOG))
    except FileNotFoundError:
        pass


def _markers(lines, prefix):
    return [line.split(':', 1)[0] for line in lines
            if line.startswith(prefix) and '-path:' not in line]


def _paths(lines, prefix):
    marker = prefix + '-path:'
    return [line[len(marker):] for line in lines if line.startswith(marker)]


def _seed_owner(root):
    _run_tdnf(root, ['install', OWNER])
    _clear_log(root)


def _assert_install_trigger_log(lines, expected_paths):
    markers = _markers(lines, 'file-in-')
    assert markers == [
        'file-in-p200000',
        'file-in-p100000',
        'file-in-p100',
    ] * 2
    assert lines.count('file-in-p200000:1:0:unset') == 2
    assert _paths(lines, 'file-in-p200000') == expected_paths
    assert _markers(lines, 'trans-in-') == [
        'trans-in-p300000',
        'trans-in-p100',
    ]
    trans_paths = _paths(lines, 'trans-in-p300000')
    assert trans_paths == expected_paths


def test_installed_owner_install_priorities_stdin_and_transaction_scope():
    root = _fresh_root('installed-owner-install')
    _seed_owner(root)

    _run_tdnf(root, ['install', TARGET_V1, EXTRA])
    lines = _read_lines(root)
    expected = [
        TARGET_ROOT + '/extra',
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v1-only',
        TARGET_ROOT + '/common',
    ]
    _assert_install_trigger_log(lines, expected)

    high = [index for index, line in enumerate(lines)
            if line == 'file-in-p200000:1:0:unset'][1]
    middle = [index for index, line in enumerate(lines)
              if line == 'file-in-p100000:1:0:unset'][1]
    post = lines.index('target-v1-post:1')
    low = [index for index, line in enumerate(lines)
           if line == 'file-in-p100:1:0:unset'][1]
    assert high < middle < post < low
    assert lines.index('target-v1-posttrans:1') < \
        lines.index('trans-in-p300000:1:0:unset')


def test_same_transaction_trigger_owner_sees_target_overlay():
    root = _fresh_root('same-transaction-owner')

    _run_tdnf(root, ['install', OWNER, TARGET_V1])
    lines = _read_lines(root)
    assert lines.count('file-in-p200000:1:0:unset') == 1
    assert _paths(lines, 'file-in-p200000') == [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v1-only',
        TARGET_ROOT + '/common',
    ]
    assert lines.count('trans-in-p300000:1:0:unset') == 1
    assert _paths(lines, 'trans-in-p300000') == [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v1-only',
        TARGET_ROOT + '/common',
    ]


def test_erase_file_and_transaction_trigger_phases():
    root = _fresh_root('erase')
    _seed_owner(root)
    _run_tdnf(root, ['install', TARGET_V1])
    _clear_log(root)

    _run_tdnf(root, ['erase', TARGET])
    lines = _read_lines(root)
    removed = [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v1-only',
        TARGET_ROOT + '/v1-only',
    ]

    assert _paths(lines, 'trans-un-p300000') == removed
    assert _paths(lines, 'file-un-p200000') == removed
    assert _paths(lines, 'file-postun-p200000') == removed
    assert lines.count('trans-un-p300000:1:0:unset') == 1
    assert lines.count('trans-postun-p300000:1:0:unset') == 1
    assert not any(line.startswith('trans-postun-unexpected-path:')
                   for line in lines)
    assert 'target-v1-self-postun:1:0:unset' in lines
    assert _paths(lines, 'target-v1-self-postun') == [
        TARGET_ROOT + '/v1-only',
    ]
    assert lines.index('trans-un-p300000:1:0:unset') < \
        lines.index('file-un-p200000:1:0:unset')
    assert lines.index('file-un-p200000:1:0:unset') < \
        lines.index('target-v1-preun:0') < \
        lines.index('file-un-p100:1:0:unset')
    assert lines.index('file-postun-p200000:1:0:unset') < \
        lines.index('target-v1-postun:0') < \
        lines.index('file-postun-p100:1:0:unset')
    assert lines.index('target-v1-postun:0') < \
        lines.index('trans-postun-p300000:1:0:unset')


def test_upgrade_and_reinstall_changed_path_semantics():
    root = _fresh_root('upgrade-reinstall')
    _seed_owner(root)
    _run_tdnf(root, ['install', TARGET_V1])
    _clear_log(root)

    _run_tdnf(root, ['upgrade', TARGET])
    lines = _read_lines(root)
    assert _paths(lines, 'file-in-p200000') == [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v2-only',
        TARGET_ROOT + '/common',
    ]
    assert _paths(lines, 'file-un-p200000') == [
        TARGET_ROOT + '/v1-only',
        TARGET_ROOT + '/v1-only',
    ]
    assert _paths(lines, 'file-postun-p200000') == [
        TARGET_ROOT + '/v1-only',
        TARGET_ROOT + '/v1-only',
    ]
    assert _paths(lines, 'trans-un-p300000') == [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v1-only',
        TARGET_ROOT + '/v1-only',
    ]
    assert _paths(lines, 'trans-in-p300000') == [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v2-only',
        TARGET_ROOT + '/common',
    ]

    _clear_log(root)
    _run_tdnf(root, ['reinstall', TARGET])
    lines = _read_lines(root)
    assert _paths(lines, 'file-in-p200000') == [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v2-only',
        TARGET_ROOT + '/common',
    ]
    assert _paths(lines, 'file-un-p200000') == []
    assert _paths(lines, 'file-postun-p200000') == []
    assert lines.count('trans-un-p300000:1:0:unset') == 1
    assert lines.count('trans-postun-p300000:1:0:unset') == 1
    assert lines.count('trans-in-p300000:1:0:unset') == 1


@pytest.mark.parametrize('mode', ['noscripts', 'justdb', 'testonly'])
def test_script_suppression_modes(mode):
    root = _fresh_root('suppression-' + mode)
    _seed_owner(root)

    args = ['install', TARGET_V1]
    if mode == 'testonly':
        args.insert(0, '--testonly')
    else:
        args.insert(0, '--setopt=tsflags=' + mode)
    _run_tdnf(root, args)

    assert _read_lines(root) == []
    if mode == 'noscripts':
        assert _installed(root, TARGET)
        assert os.path.exists(_root_path(root, TARGET_ROOT + '/common'))
    elif mode == 'justdb':
        assert _installed(root, TARGET)
        assert not os.path.exists(_root_path(root, TARGET_ROOT + '/common'))
    else:
        assert not _installed(root, TARGET)
        assert not os.path.exists(_root_path(root, TARGET_ROOT + '/common'))


def test_dedicated_trigger_flags_suppress_only_their_phase():
    root = _fresh_root('phase-flags')
    _seed_owner(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=notriggerin', 'install', TARGET_V1],
    )
    assert not any('file-in-' in line or 'trans-in-' in line
                   for line in _read_lines(root))

    _clear_log(root)
    _run_tdnf(
        root,
        ['--setopt=tsflags=notriggerun', 'erase', TARGET],
    )
    lines = _read_lines(root)
    assert not any('file-un-' in line or 'trans-un-' in line
                   for line in lines)
    assert any(line.startswith('file-postun-') for line in lines)
    assert any(line.startswith('trans-postun-') for line in lines)

    post_root = _fresh_root('postun-phase-flag')
    _seed_owner(post_root)
    _run_tdnf(post_root, ['install', TARGET_V1])
    _clear_log(post_root)
    _run_tdnf(
        post_root,
        ['--setopt=tsflags=notriggerpostun', 'erase', TARGET],
    )
    lines = _read_lines(post_root)
    assert any(line.startswith('file-un-') for line in lines)
    assert any(line.startswith('trans-un-') for line in lines)
    assert not any('file-postun-' in line or 'trans-postun-' in line
                   for line in lines)


def test_notriggers_suppresses_file_triggers_but_not_scriptlets():
    root = _fresh_root('notriggers')
    _seed_owner(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=notriggers', 'install', TARGET_V1],
    )
    lines = _read_lines(root)
    assert 'target-v1-pre:1' in lines
    assert 'target-v1-post:1' in lines
    assert not any('file-' in line or 'trans-' in line for line in lines)


def test_nodb_separates_filesystem_paths_from_rpmdb_trigger_rows():
    install_root = _fresh_root('nodb-install')
    _seed_owner(install_root)
    _run_tdnf(
        install_root,
        ['--setopt=tsflags=nodb', 'install', TARGET_V1],
    )
    assert not _installed(install_root, TARGET)
    assert os.path.exists(
        _root_path(install_root, TARGET_ROOT + '/common'))
    install_lines = _read_lines(install_root)
    assert 'file-in-p200000:1:0:unset' in install_lines
    assert _paths(install_lines, 'file-in-p200000') == [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v1-only',
        TARGET_ROOT + '/common',
    ]
    assert not any(line.startswith('trans-in-') for line in install_lines)

    erase_root = _fresh_root('nodb-erase')
    _seed_owner(erase_root)
    _run_tdnf(erase_root, ['install', TARGET_V1])
    _clear_log(erase_root)
    _run_tdnf(
        erase_root,
        ['--setopt=tsflags=nodb', 'erase', TARGET],
    )
    assert _installed(erase_root, TARGET)
    assert not os.path.exists(
        _root_path(erase_root, TARGET_ROOT + '/common'))
    lines = _read_lines(erase_root)
    assert 'file-un-p200000:1:0:unset' in lines
    assert 'file-postun-p200000:1:0:unset' in lines
    assert 'trans-un-p300000:1:0:unset' in lines
    assert 'trans-postun-p300000:1:0:unset' in lines


def test_nodb_new_owner_is_not_discovered_by_later_package():
    root = _fresh_root('nodb-new-owner')

    _run_tdnf(
        root,
        ['--setopt=tsflags=nodb', 'install', OWNER, TARGET_V1],
    )

    lines = _read_lines(root)
    assert not any(line.startswith('file-in-') for line in lines)
    assert not any(line.startswith('trans-in-') for line in lines)


def test_nodb_owner_runs_only_its_immediate_rpmdb_matches():
    root = _fresh_root('nodb-owner-immediate')
    _run_tdnf(root, ['install', TARGET_V1])
    _clear_log(root)

    _run_tdnf(
        root,
        ['--setopt=tsflags=nodb', 'install', OWNER],
    )

    lines = _read_lines(root)
    assert not _installed(root, OWNER)
    assert 'file-in-p200000:1:0:unset' in lines
    assert 'trans-in-p300000:1:0:unset' in lines


def test_added_owner_is_visible_to_later_filetriggerun():
    root = _fresh_root('added-owner-un')
    _run_tdnf(root, ['install', TARGET_V1])
    _clear_log(root)

    _run_tdnf(root, ['install', ADDED_OWNER])

    lines = _read_lines(root)
    assert not _installed(root, TARGET)
    assert 'visibility-added-un:1:0:unset' in lines
    assert _paths(lines, 'visibility-added-un') == [
        TARGET_ROOT + '/common',
        TARGET_ROOT + '/v1-only',
    ]


def test_removed_owner_remains_visible_to_earlier_filetriggerin():
    root = _fresh_root('removed-owner-in')
    _run_tdnf(root, ['install', REMOVED_OWNER])
    _clear_log(root)

    _run_tdnf(root, ['install', REPLACEMENT_TARGET])

    lines = _read_lines(root)
    assert not _installed(root, REMOVED_OWNER)
    assert 'visibility-removed-in:1:0:unset' in lines
    assert _paths(lines, 'visibility-removed-in') == [
        '/usr/share/tdnf-phase7-filetarget-replacement/payload',
    ]


def test_file_trigger_script_flags_and_lua_arguments_match_host_rpm():
    native_root = _fresh_root('flags-native')
    host_root = _fresh_root('flags-host')
    target_rpm = _repo_rpm(TARGET, '1.0.0')
    flags_rpm = _repo_rpm(FLAGS_OWNER, '1.0.0')

    _run_tdnf(native_root, ['install', TARGET_V1])
    _clear_log(native_root)
    _run_tdnf(native_root, ['install', FLAGS_OWNER])

    host_result = _run_rpm(
        host_root,
        ['-ivh', '--nodeps', '--nosignature', target_rpm],
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot install the trigger target')
    _clear_log(host_root)
    host_result = _run_rpm(
        host_root,
        ['-ivh', '--nodeps', '--nosignature', flags_rpm],
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot execute the trigger flags fixture')

    native = [line for line in _read_lines(native_root)
              if line.startswith('flags-')]
    host = [line for line in _read_lines(host_root)
            if line.startswith('flags-')]
    assert native == host == [
        'flags-expand:/var/lib/rpm:1:0:unset',
        'flags-query:tdnf-phase7-filetrigger-flags:1.0.0:noarch:'
        '1:0',
        'flags-lua:2:0:nil',
        'flags-trans:/var/lib/rpm:tdnf-phase7-filetrigger-flags:'
        '1:0',
    ]


def test_query_format_modifiers_iterators_and_conditionals_match_host_rpm():
    native_root = _fresh_root('query-format-native')
    host_root = _fresh_root('query-format-host')
    target_rpm = _repo_rpm(TARGET, '1.0.0')
    flags_rpm = _repo_rpm(FLAGS_OWNER, '1.0.0')

    _run_tdnf(native_root, ['install', FLAGS_OWNER])
    host_result = _run_rpm(
        host_root,
        ['-ivh', '--nodeps', '--nosignature', flags_rpm],
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot install the query-format fixture')
    _clear_log(native_root)
    _clear_log(host_root)

    _run_tdnf(native_root, ['install', TARGET_V1])
    host_result = _run_rpm(
        host_root,
        ['-ivh', '--nodeps', '--nosignature', target_rpm],
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot execute the query-format fixture')

    native = [line for line in _read_lines(native_root)
              if line.startswith('qformat-')]
    host = [line for line in _read_lines(host_root)
            if line.startswith('qformat-')]
    native_without_date = [line for line in native
                           if not line.startswith('qformat-date:')]
    host_without_date = [line for line in host
                         if not line.startswith('qformat-date:')]
    assert native_without_date == host_without_date
    assert 'qformat-conditional:noepoch-{}'.format(FLAGS_OWNER) in native
    assert (
        'qformat-iterator:{}:/usr/share/{}/payload:-rw-r--r--:'
        .format(FLAGS_OWNER, FLAGS_OWNER)
    ) in native

    query = 'qformat-date:%{INSTALLTIME:date}|%{INSTALLTIME:day}'
    native_expected = _run_rpm(
        native_root,
        ['-q', '--qf', query, FLAGS_OWNER],
    ).stdout
    host_expected = _run_rpm(
        host_root,
        ['-q', '--qf', query, FLAGS_OWNER],
    ).stdout
    assert [line for line in native
            if line.startswith('qformat-date:')] == [native_expected]
    assert [line for line in host
            if line.startswith('qformat-date:')] == [host_expected]


def test_immediate_transfile_priorities_are_scoped_to_each_owner():
    root = _fresh_root('immediate-owner-order')
    _run_tdnf(root, ['install', TARGET_V1])
    _clear_log(root)

    _run_tdnf(root, ['install', OWNER, OWNER_SECOND])
    lines = _read_lines(root)
    post_order = [
        line.split(':', 1)[0]
        for line in lines
        if line.startswith(('owner-post:', 'owner-second-post:'))
    ]
    groups = {
        'owner-post': [
            'trans-in-p300000',
            'trans-in-p100',
        ],
        'owner-second-post': [
            'trans-second-in-p400000',
            'trans-second-in-p50',
        ],
    }
    expected = [
        marker
        for owner_marker in post_order
        for marker in groups[owner_marker]
    ]
    actual = [
        line.split(':', 1)[0]
        for line in lines
        if (line.startswith(('trans-in-', 'trans-second-in-')) and
            '-path:' not in line)
    ]
    assert actual == expected


def test_stable_transfile_triggers_keep_global_rpm_priority_order():
    root = _fresh_root('stable-owner-order')
    _run_tdnf(root, ['install', OWNER, OWNER_SECOND])
    _clear_log(root)

    _run_tdnf(root, ['install', TARGET_V1])
    actual = [
        line.split(':', 1)[0]
        for line in _read_lines(root)
        if (line.startswith(('trans-in-', 'trans-second-in-')) and
            '-path:' not in line)
    ]
    assert actual == [
        'trans-second-in-p400000',
        'trans-in-p300000',
        'trans-in-p100',
        'trans-second-in-p50',
    ]


def test_removed_immediate_transfile_priorities_are_per_owner():
    root = _fresh_root('removed-owner-order')
    _run_tdnf(root, ['install', TARGET_V1, OWNER, OWNER_SECOND])
    _clear_log(root)

    _run_tdnf(root, ['erase', OWNER, OWNER_SECOND])
    lines = _read_lines(root)
    erase_order = [
        line.split(':', 1)[0]
        for line in lines
        if line.startswith(('owner-preun:', 'owner-second-preun:'))
    ]
    groups = {
        'owner-preun': [
            'trans-un-p300000',
            'trans-un-p100',
        ],
        'owner-second-preun': [
            'trans-second-un-p400000',
            'trans-second-un-p50',
        ],
    }
    expected = [
        marker
        for owner_marker in erase_order
        for marker in groups[owner_marker]
    ]
    actual = [
        line.split(':', 1)[0]
        for line in lines
        if (line.startswith(('trans-un-', 'trans-second-un-')) and
            '-path:' not in line)
    ]
    assert actual == expected


def _set_first_file_state(root, package, state):
    database_path = os.path.join(
        root, 'var', 'lib', 'rpm', 'rpmdb.sqlite')
    with sqlite3.connect(database_path) as database:
        hnum = database.execute(
            "SELECT hnum FROM 'Name' WHERE key=?",
            (package,),
        ).fetchone()[0]
        blob = bytearray(database.execute(
            "SELECT blob FROM 'Packages' WHERE hnum=?",
            (hnum,),
        ).fetchone()[0])
        index_count = struct.unpack_from('>I', blob, 0)[0]
        data_start = 8 + index_count * 16
        found = False
        for index in range(index_count):
            offset = 8 + index * 16
            tag = struct.unpack_from('>I', blob, offset)[0]
            data_offset = struct.unpack_from(
                '>I', blob, offset + 8)[0]
            if tag == 1029:
                blob[data_start + data_offset] = state
                found = True
                break
        assert found
        database.execute(
            "UPDATE 'Packages' SET blob=? WHERE hnum=?",
            (bytes(blob), hnum),
        )


def test_netshared_file_state_remains_trigger_visible():
    root = _fresh_root('netshared-state')
    _run_tdnf(root, ['install', TARGET_V1])
    _set_first_file_state(root, TARGET, 3)
    _clear_log(root)

    _run_tdnf(root, ['install', OWNER])

    paths = _paths(_read_lines(root), 'file-in-p200000')
    assert TARGET_ROOT + '/common' in paths
    assert TARGET_ROOT + '/v1-only' in paths


def _corrupt_filetrigger_index_count(root):
    database_path = os.path.join(
        root, 'var', 'lib', 'rpm', 'rpmdb.sqlite')
    with sqlite3.connect(database_path) as database:
        hnum = database.execute(
            "SELECT hnum FROM 'Name' WHERE key=?",
            (OWNER,),
        ).fetchone()[0]
        blob = bytearray(database.execute(
            "SELECT blob FROM 'Packages' WHERE hnum=?",
            (hnum,),
        ).fetchone()[0])
        index_count = struct.unpack_from('>I', blob, 0)[0]
        found = False
        for index in range(index_count):
            offset = 8 + index * 16
            tag = struct.unpack_from('>I', blob, offset)[0]
            if tag == 5070:
                count = struct.unpack_from('>I', blob, offset + 12)[0]
                struct.pack_into('>I', blob, offset + 12, count + 1)
                found = True
                break
        assert found
        database.execute(
            "UPDATE 'Packages' SET blob=? WHERE hnum=?",
            (bytes(blob), hnum),
        )


def _hide_filetrigger_program_tag(root):
    database_path = os.path.join(
        root, 'var', 'lib', 'rpm', 'rpmdb.sqlite')
    with sqlite3.connect(database_path) as database:
        hnum = database.execute(
            "SELECT hnum FROM 'Name' WHERE key=?",
            (OWNER,),
        ).fetchone()[0]
        blob = bytearray(database.execute(
            "SELECT blob FROM 'Packages' WHERE hnum=?",
            (hnum,),
        ).fetchone()[0])
        index_count = struct.unpack_from('>I', blob, 0)[0]
        found = False
        for index in range(index_count):
            offset = 8 + index * 16
            tag = struct.unpack_from('>I', blob, offset)[0]
            if tag == 5067:
                struct.pack_into('>I', blob, offset, 60000)
                found = True
                break
        assert found
        database.execute(
            "UPDATE 'Packages' SET blob=? WHERE hnum=?",
            (bytes(blob), hnum),
        )


def _database_digest(path):
    digest = hashlib.sha256()
    with sqlite3.connect(path) as database:
        for statement in database.iterdump():
            digest.update(statement.encode())
            digest.update(b'\n')
    return digest.hexdigest()


def test_malformed_installed_trigger_metadata_fails_before_side_effects():
    root = _fresh_root('malformed')
    _seed_owner(root)
    _corrupt_filetrigger_index_count(root)
    database_path = os.path.join(
        root, 'var', 'lib', 'rpm', 'rpmdb.sqlite')
    database_before = _database_digest(database_path)

    result = _run_tdnf(root, ['install', TARGET_V1], check=False)

    assert result.returncode != 0
    assert not _installed(root, TARGET)
    assert not os.path.exists(_root_path(root, TARGET_ROOT + '/common'))
    assert _read_lines(root) == []
    assert _database_digest(database_path) == database_before


def test_missing_trigger_program_fails_before_side_effects():
    root = _fresh_root('missing-trigger-program')
    _seed_owner(root)
    _hide_filetrigger_program_tag(root)
    database_path = os.path.join(
        root, 'var', 'lib', 'rpm', 'rpmdb.sqlite')
    database_before = _database_digest(database_path)

    result = _run_tdnf(root, ['install', TARGET_V1], check=False)

    assert result.returncode != 0
    assert not _installed(root, TARGET)
    assert not os.path.exists(_root_path(root, TARGET_ROOT + '/common'))
    assert _read_lines(root) == []
    assert _database_digest(database_path) == database_before


def test_unsupported_trigger_query_format_fails_before_side_effects():
    root = _fresh_root('unsupported-query-format')
    database_path = os.path.join(
        root, 'var', 'lib', 'rpm', 'rpmdb.sqlite')
    database_before = _database_digest(database_path)

    result = _run_tdnf(
        root,
        ['install', BAD_QUERY_OWNER],
        check=False,
    )

    assert result.returncode != 0
    assert 'UnsupportedQueryModifier' in result.stdout + result.stderr
    assert not _installed(root, BAD_QUERY_OWNER)
    assert not os.path.exists(_root_path(
        root,
        '/usr/share/tdnf-phase7-filetrigger-bad-query/payload',
    ))
    assert _read_lines(root) == []
    assert _database_digest(database_path) == database_before


def _repo_rpm(package, version):
    directory = os.path.join(
        OUT_DIR, 'repo', 'build', 'RPMS', 'noarch')
    matches = [
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if (name.startswith('{}-{}-'.format(package, version)) and
            name.endswith('.noarch.rpm'))
    ]
    assert len(matches) == 1, matches
    return matches[0]


def test_file_trigger_paths_and_transaction_scope_match_host_rpm():
    if shutil.which('rpm') is None:
        pytest.skip('host rpm is unavailable')
    native_root = _fresh_root('host-compare-native')
    host_root = _fresh_root('host-compare-rpm')
    owner_rpm = _repo_rpm(OWNER, '1.0.0')
    target_rpm = _repo_rpm(TARGET, '1.0.0')
    extra_rpm = _repo_rpm(EXTRA, '1.0.0')

    _run_tdnf(native_root, ['install', OWNER])
    _clear_log(native_root)
    _run_tdnf(native_root, ['install', TARGET_V1, EXTRA])
    host_result = _run_rpm(
        host_root,
        ['-ivh', '--nodeps', '--nosignature', owner_rpm],
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot install the trigger owner')
    _clear_log(host_root)
    host_result = _run_rpm(
        host_root,
        [
            '-ivh', '--nodeps', '--nosignature',
            target_rpm, extra_rpm,
        ],
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot execute the fixture in this environment')

    native_lines = _read_lines(native_root)
    host_lines = _read_lines(host_root)
    assert _paths(native_lines, 'file-in-p200000') == \
        _paths(host_lines, 'file-in-p200000')
    assert [line for line in native_lines
            if line.startswith('file-in-p200000:')] == \
        [line for line in host_lines
         if line.startswith('file-in-p200000:')]
    assert list(dict.fromkeys(
        _paths(native_lines, 'trans-in-p300000'))) == \
        _paths(host_lines, 'trans-in-p300000')
    assert native_lines.count('trans-in-p300000:1:0:unset') == 1
    assert host_lines.count('trans-in-p300000:1:0:unset') == 1


def _assert_shared_path_multiplicity(lines):
    paths = _paths(lines, 'shared-in')
    shared_dir = SHARED_ROOT + '/shared-dir'
    assert len(paths) == 10
    assert paths.count(SHARED_ROOT) == 2
    assert paths.count(shared_dir) == 4
    assert paths.count(shared_dir + '/a') == 2
    assert paths.count(shared_dir + '/b') == 2
    return paths


def test_installed_shared_paths_match_host_rpm_multiplicity():
    native_root = _fresh_root('installed-shared-paths-native')
    host_root = _fresh_root('installed-shared-paths-host')
    owner_rpm = _repo_rpm(OWNER, '1.0.0')
    shared_rpms = [
        _repo_rpm(SHARED_A, '1.0.0'),
        _repo_rpm(SHARED_B, '1.0.0'),
    ]

    _run_tdnf(native_root, ['install', SHARED_A, SHARED_B])
    host_result = _run_rpm(
        host_root,
        ['-ivh', '--nodeps', '--nosignature'] + shared_rpms,
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot install shared-path fixtures')
    _clear_log(native_root)
    _clear_log(host_root)

    _run_tdnf(native_root, ['install', OWNER])
    host_result = _run_rpm(
        host_root,
        ['-ivh', '--nodeps', '--nosignature', owner_rpm],
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot execute installed shared-path fixture')

    native_paths = _assert_shared_path_multiplicity(
        _read_lines(native_root))
    host_paths = _assert_shared_path_multiplicity(_read_lines(host_root))
    assert native_paths == host_paths


def test_same_transaction_shared_paths_match_host_rpm_multiplicity():
    native_root = _fresh_root('transaction-shared-paths-native')
    host_root = _fresh_root('transaction-shared-paths-host')
    owner_rpm = _repo_rpm(OWNER, '1.0.0')
    shared_rpms = [
        _repo_rpm(SHARED_A, '1.0.0'),
        _repo_rpm(SHARED_B, '1.0.0'),
    ]

    _run_tdnf(native_root, ['install', OWNER, SHARED_A, SHARED_B])
    host_result = _run_rpm(
        host_root,
        ['-ivh', '--nodeps', '--nosignature', owner_rpm] + shared_rpms,
        check=False,
    )
    if host_result.returncode != 0:
        pytest.skip('host rpm cannot execute same-transaction shared paths')

    native_paths = _assert_shared_path_multiplicity(
        _read_lines(native_root))
    host_paths = _assert_shared_path_multiplicity(_read_lines(host_root))
    assert native_paths == host_paths
