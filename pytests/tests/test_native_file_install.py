import glob
import json
import os
import shutil
import stat

import pytest

from conftest import TestUtils as _TestUtils


CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config.json')
with open(CONFIG_PATH) as config_file:
    CONFIG = json.load(config_file)

pytestmark = pytest.mark.skipif(
    not os.path.exists(CONFIG.get('native_file_install_binary', '')),
    reason='native file-install crosscheck binary missing',
)

PKGNAME = 'tdnf-test-native-install'
V1 = '1.0.0-1'
V2 = '1.0.1-1'
CASE_ROOT = os.path.join(CONFIG['build_dir'], 'native-file-install-crosscheck')
NATIVE_BIN = CONFIG['native_file_install_binary']

PLAIN_CONFIG = f'/etc/{PKGNAME}/plain.conf'
NOREPLACE_CONFIG = f'/etc/{PKGNAME}/noreplace.conf'
PLAIN_FILE = f'/usr/share/{PKGNAME}/plain.txt'
HARDLINK_A = f'/usr/share/{PKGNAME}/hardlink-a'
HARDLINK_B = f'/usr/share/{PKGNAME}/hardlink-b'
DOC_FILE = f'/usr/share/doc/{PKGNAME}/README'
LICENSE_FILE = f'/usr/share/licenses/{PKGNAME}/LICENSE'
GHOST_FILE = f'/var/lib/{PKGNAME}/ghost.token'
RPMNEW_FILE = NOREPLACE_CONFIG + '.rpmnew'
RPMSAVE_FILE = PLAIN_CONFIG + '.rpmsave'

COMPARE_PATHS = [
    PLAIN_CONFIG,
    NOREPLACE_CONFIG,
    PLAIN_FILE,
    HARDLINK_A,
    HARDLINK_B,
    DOC_FILE,
    LICENSE_FILE,
    GHOST_FILE,
]
EXTRA_PATHS = [RPMNEW_FILE, RPMSAVE_FILE]


@pytest.fixture(scope='module')
def fixture_rpms(utils):
    pattern = os.path.join(utils.config['repo_path'], 'photon-test', 'RPMS', '*', f'{PKGNAME}-*.rpm')
    rpms = {}
    for path in glob.glob(pattern):
        filename = os.path.basename(path)
        if filename.startswith(f'{PKGNAME}-{V1}'):
            rpms['v1'] = path
        elif filename.startswith(f'{PKGNAME}-{V2}'):
            rpms['v2'] = path
    assert 'v1' in rpms, pattern
    assert 'v2' in rpms, pattern
    return rpms


@pytest.fixture(scope='module')
def utils():
    return _TestUtils()


@pytest.fixture(scope='module', autouse=True)
def check_packages_consistency():
    yield


@pytest.fixture(scope='module', autouse=True)
def check_native_runtime(utils):
    if not os.path.exists(NATIVE_BIN):
        pytest.skip(f'native install binary not built: {NATIVE_BIN}')
    ret = utils.run(['unshare', '-Ur', 'true'])
    if ret['retval'] != 0:
        pytest.skip('unshare -Ur is unavailable in this environment')


def test_native_install_matches_rpm_install(utils, fixture_rpms):
    real_root, native_root = prepare_roots('install')
    rpm_initdb(utils, real_root)

    rpm_install(utils, real_root, fixture_rpms['v1'])
    native_install(utils, native_root, fixture_rpms['v1'])

    assert_roots_match(real_root, native_root)


def test_native_install_matches_rpm_nodocs(utils, fixture_rpms):
    real_root, native_root = prepare_roots('nodocs')
    rpm_initdb(utils, real_root)

    rpm_install(utils, real_root, fixture_rpms['v1'], tsflags=['nodocs'])
    native_install(utils, native_root, fixture_rpms['v1'], tsflags=['nodocs'])

    assert_roots_match(real_root, native_root)


def test_native_upgrade_matches_rpm_config_semantics(utils, fixture_rpms):
    real_root, native_root = prepare_roots('upgrade-modified')
    rpm_initdb(utils, real_root)

    rpm_install(utils, real_root, fixture_rpms['v1'])
    native_install(utils, native_root, fixture_rpms['v1'])

    modify_file(os.path.join(real_root, PLAIN_CONFIG.lstrip('/')), b'plain-custom\n')
    modify_file(os.path.join(real_root, NOREPLACE_CONFIG.lstrip('/')), b'noreplace-custom\n')
    modify_file(os.path.join(native_root, PLAIN_CONFIG.lstrip('/')), b'plain-custom\n')
    modify_file(os.path.join(native_root, NOREPLACE_CONFIG.lstrip('/')), b'noreplace-custom\n')

    rpm_upgrade(utils, real_root, fixture_rpms['v2'])
    native_install(
        utils,
        native_root,
        fixture_rpms['v2'],
        install_kind='upgrade',
        prior=[fixture_rpms['v1']],
    )

    assert_roots_match(real_root, native_root)


def test_native_upgrade_matches_rpm_unmodified_config_replace(utils, fixture_rpms):
    real_root, native_root = prepare_roots('upgrade-unmodified')
    rpm_initdb(utils, real_root)

    rpm_install(utils, real_root, fixture_rpms['v1'])
    native_install(utils, native_root, fixture_rpms['v1'])

    rpm_upgrade(utils, real_root, fixture_rpms['v2'])
    native_install(
        utils,
        native_root,
        fixture_rpms['v2'],
        install_kind='upgrade',
        prior=[fixture_rpms['v1']],
    )

    assert_roots_match(real_root, native_root)


def prepare_roots(case_name):
    case_dir = os.path.join(CASE_ROOT, case_name)
    real_root = os.path.join(case_dir, 'rpm-root')
    native_root = os.path.join(case_dir, 'native-root')
    if os.path.isdir(case_dir):
        shutil.rmtree(case_dir)
    os.makedirs(real_root, exist_ok=True)
    os.makedirs(native_root, exist_ok=True)
    return real_root, native_root


def rpm_initdb(utils, root):
    ret = utils.run(['unshare', '-Ur', 'rpm', '--root', root, '--initdb'])
    assert ret['retval'] == 0, ret


def rpm_install(utils, root, rpm_path, tsflags=None):
    cmd = ['unshare', '-Ur', 'rpm', '-ivh', '--nodeps', '--nosignature', '--root', root]
    for flag in tsflags or []:
        if flag == 'nodocs':
            cmd.append('--excludedocs')
        else:
            raise AssertionError(flag)
    cmd.append(rpm_path)
    ret = utils.run(cmd)
    assert ret['retval'] == 0, ret


def rpm_upgrade(utils, root, rpm_path):
    cmd = ['unshare', '-Ur', 'rpm', '-Uvh', '--nodeps', '--nosignature', '--root', root, rpm_path]
    ret = utils.run(cmd)
    assert ret['retval'] == 0, ret


def native_install(utils, root, rpm_path, install_kind='install', prior=None, tsflags=None):
    cmd = ['unshare', '-Ur', NATIVE_BIN, '--root', root]
    if install_kind == 'upgrade':
        cmd.append('--upgrade')
    elif install_kind == 'reinstall':
        cmd.append('--reinstall')
    elif install_kind != 'install':
        raise AssertionError(install_kind)

    for old_rpm in prior or []:
        cmd.extend(['--prior', old_rpm])
    for flag in tsflags or []:
        cmd.extend(['--tsflag', flag])
    cmd.append(rpm_path)

    ret = utils.run(cmd)
    assert ret['retval'] == 0, ret


def modify_file(path, contents):
    with open(path, 'wb') as handle:
        handle.write(contents)
    os.utime(path, (1700100000, 1700100000))


def assert_roots_match(real_root, native_root):
    real_state = capture_state(real_root)
    native_state = capture_state(native_root)
    assert real_state == native_state
    assert hardlink_signature(real_root) == hardlink_signature(native_root)


def capture_state(root):
    state = {}
    for relpath in COMPARE_PATHS + EXTRA_PATHS:
        full_path = os.path.join(root, relpath.lstrip('/'))
        if not os.path.lexists(full_path):
            state[relpath] = None
            continue

        st = os.lstat(full_path)
        entry = {
            'mode': stat.S_IMODE(st.st_mode),
            'type': stat.S_IFMT(st.st_mode),
            'uid': st.st_uid,
            'gid': st.st_gid,
            'mtime': int(st.st_mtime),
            'nlink': st.st_nlink,
        }
        if stat.S_ISREG(st.st_mode):
            with open(full_path, 'rb') as handle:
                entry['bytes'] = handle.read()
        elif stat.S_ISLNK(st.st_mode):
            entry['target'] = os.readlink(full_path)
        elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
            entry['rdev'] = (os.major(st.st_rdev), os.minor(st.st_rdev))

        state[relpath] = entry
    return state


def hardlink_signature(root):
    path_a = os.path.join(root, HARDLINK_A.lstrip('/'))
    path_b = os.path.join(root, HARDLINK_B.lstrip('/'))
    stat_a = os.lstat(path_a)
    stat_b = os.lstat(path_b)
    return {
        'same_inode': stat_a.st_ino == stat_b.st_ino,
        'nlink_a': stat_a.st_nlink,
        'nlink_b': stat_b.st_nlink,
    }
