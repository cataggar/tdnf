import glob
import json
import os
import shutil
import sqlite3
import stat

import pytest

from conftest import TestUtils as _TestUtils


CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config.json')
with open(CONFIG_PATH) as config_file:
    CONFIG = json.load(config_file)

pytestmark = pytest.mark.skipif(
    not CONFIG.get('native_file_erase_crosscheck_enabled', False),
    reason='native file-erase crosscheck build flag is disabled',
)

CASE_ROOT = os.path.join(CONFIG['build_dir'], 'native-file-erase-crosscheck')
INSTALL_TOOL = CONFIG['native_file_install_binary']
ERASE_TOOL = CONFIG['native_file_erase_binary']
WRITE_TOOL = os.path.join(CONFIG['build_dir'], 'libexec', 'tdnf', 'tdnf-rpmdb-write')

PKGNAME = 'tdnf-test-native-install'
SHARED_A = 'tdnf-test-native-erase-shared-a'
SHARED_B = 'tdnf-test-native-erase-shared-b'

INSTALL_PREFIXES = [
    f'/etc/{PKGNAME}',
    f'/usr/share/{PKGNAME}',
    f'/usr/share/doc/{PKGNAME}',
    f'/usr/share/licenses/{PKGNAME}',
    f'/var/lib/{PKGNAME}',
]
SHARED_PREFIXES = [
    '/etc/tdnf-test-native-erase-shared',
    '/usr/share/tdnf-test-native-erase-shared',
]


@pytest.fixture(scope='module')
def fixture_rpms(utils):
    paths = {}
    for path in glob.glob(os.path.join(utils.config['repo_path'], 'photon-test', 'RPMS', '*', '*.rpm')):
        filename = os.path.basename(path)
        if filename.startswith(f'{PKGNAME}-1.0.0-1'):
            paths['install_v1'] = path
        elif filename.startswith(f'{SHARED_A}-1.0.0-1'):
            paths['shared_a'] = path
        elif filename.startswith(f'{SHARED_B}-1.0.0-1'):
            paths['shared_b'] = path
    assert 'install_v1' in paths, paths
    assert 'shared_a' in paths, paths
    assert 'shared_b' in paths, paths
    return paths


@pytest.fixture(scope='module')
def utils():
    return _TestUtils()


@pytest.fixture(scope='module', autouse=True)
def check_packages_consistency():
    yield


@pytest.fixture(scope='module', autouse=True)
def check_native_runtime(utils):
    if not os.path.exists(INSTALL_TOOL):
        pytest.skip(f'native install binary not built: {INSTALL_TOOL}')
    if not os.path.exists(ERASE_TOOL):
        pytest.skip(f'native erase binary not built: {ERASE_TOOL}')
    if not os.path.exists(WRITE_TOOL):
        pytest.skip(f'native rpmdb write binary not built: {WRITE_TOOL}')
    ret = utils.run(['unshare', '-Ur', 'true'])
    if ret['retval'] != 0:
        pytest.skip('unshare -Ur is unavailable in this environment')


def test_native_erase_matches_rpm_basic(utils, fixture_rpms):
    real_root, native_root = prepare_roots('basic')
    rpm_initdb(utils, real_root)

    hnum = mirrored_install(utils, real_root, native_root, fixture_rpms['install_v1'], PKGNAME)

    rpm_erase(utils, real_root, PKGNAME)
    native_erase(utils, native_root, hnum)

    assert_roots_match(real_root, native_root, INSTALL_PREFIXES)
    assert_db_state_matches(native_root, real_root)


def test_native_erase_matches_rpm_modified_config_and_ghost(utils, fixture_rpms):
    real_root, native_root = prepare_roots('modified-config')
    rpm_initdb(utils, real_root)

    hnum = mirrored_install(utils, real_root, native_root, fixture_rpms['install_v1'], PKGNAME)

    modify_file(os.path.join(real_root, 'etc', PKGNAME, 'plain.conf'), b'plain-custom\n')
    modify_file(os.path.join(real_root, 'etc', PKGNAME, 'noreplace.conf'), b'noreplace-custom\n')
    modify_file(os.path.join(native_root, 'etc', PKGNAME, 'plain.conf'), b'plain-custom\n')
    modify_file(os.path.join(native_root, 'etc', PKGNAME, 'noreplace.conf'), b'noreplace-custom\n')

    rpm_erase(utils, real_root, PKGNAME)
    native_erase(utils, native_root, hnum)

    assert_roots_match(real_root, native_root, INSTALL_PREFIXES)
    assert_db_state_matches(native_root, real_root)


def test_native_erase_matches_rpm_nodocs_missing_files(utils, fixture_rpms):
    real_root, native_root = prepare_roots('nodocs')
    rpm_initdb(utils, real_root)

    hnum = mirrored_install(
        utils,
        real_root,
        native_root,
        fixture_rpms['install_v1'],
        PKGNAME,
        tsflags=['nodocs'],
    )

    rpm_erase(utils, real_root, PKGNAME)
    native_erase(utils, native_root, hnum)

    assert_roots_match(real_root, native_root, INSTALL_PREFIXES)
    assert_db_state_matches(native_root, real_root)


def test_native_erase_preserves_shared_paths_until_last_owner(utils, fixture_rpms):
    real_root, native_root = prepare_roots('shared-ownership')
    rpm_initdb(utils, real_root)

    hnum_a = mirrored_install(utils, real_root, native_root, fixture_rpms['shared_a'], SHARED_A)
    hnum_b = mirrored_install(utils, real_root, native_root, fixture_rpms['shared_b'], SHARED_B)

    rpm_erase(utils, real_root, SHARED_A)
    native_erase(utils, native_root, hnum_a)

    assert_roots_match(real_root, native_root, SHARED_PREFIXES)
    assert_db_state_matches(native_root, real_root)

    rpm_erase(utils, real_root, SHARED_B)
    native_erase(utils, native_root, hnum_b)

    assert_roots_match(real_root, native_root, SHARED_PREFIXES)
    assert_db_state_matches(native_root, real_root)


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


def rpm_erase(utils, root, package):
    ret = utils.run(['unshare', '-Ur', 'rpm', '-e', '--nodeps', '--nosignature', '--root', root, package])
    assert ret['retval'] == 0, ret


def install_meta(utils, root, package):
    ret = utils.run(['unshare', '-Ur', 'rpm', '--root', root, '-q', '--qf', '%{INSTALLTID} %{INSTALLTIME}\n', package])
    assert ret['retval'] == 0, ret
    tid, when = ret['stdout'][0].split()
    return int(tid), int(when)


def native_file_install(utils, root, rpm_path, tsflags=None):
    cmd = ['unshare', '-Ur', INSTALL_TOOL, '--root', root]
    for flag in tsflags or []:
        cmd.extend(['--tsflag', flag])
    cmd.append(rpm_path)
    ret = utils.run(cmd)
    assert ret['retval'] == 0, ret


def native_db_install(utils, root, rpm_path, install_tid, install_time):
    ret = utils.run([
        WRITE_TOOL,
        'install',
        root,
        rpm_path,
        str(install_tid),
        str(install_time),
        '3',
    ])
    assert ret['retval'] == 0, ret
    return int(ret['stdout'][0])


def native_erase(utils, root, hnum):
    ret = utils.run(['unshare', '-Ur', ERASE_TOOL, '--root', root, str(hnum)])
    assert ret['retval'] == 0, ret


def mirrored_install(utils, real_root, native_root, rpm_path, package, tsflags=None):
    rpm_install(utils, real_root, rpm_path, tsflags=tsflags)
    install_tid, install_time = install_meta(utils, real_root, package)
    native_file_install(utils, native_root, rpm_path, tsflags=tsflags)
    return native_db_install(utils, native_root, rpm_path, install_tid, install_time)


def modify_file(path, contents):
    with open(path, 'wb') as handle:
        handle.write(contents)
    os.utime(path, (1700300000, 1700300000))


def normalize_sql(sql):
    if sql is None:
        return None
    return ' '.join(sql.split()).replace(', ', ',')


def rpmdb_path(root):
    return os.path.join(root, 'var', 'lib', 'rpm', 'rpmdb.sqlite')


def load_db_state(root):
    con = sqlite3.connect(rpmdb_path(root))
    cur = con.cursor()

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
        selected = ', '.join('"{}"'.format(col) for col in columns)
        ordering = ', '.join(str(idx) for idx in range(1, len(columns) + 1))
        tables[table_name] = cur.execute(
            "SELECT {} FROM '{}' ORDER BY {}".format(selected, table_name, ordering)
        ).fetchall()

    con.close()
    return {
        'schema': schema,
        'tables': tables,
    }


def assert_db_state_matches(native_root, real_root):
    native = load_db_state(native_root)
    real = load_db_state(real_root)
    assert native['schema'] == real['schema']
    assert native['tables'] == real['tables']


def capture_tree(root, prefixes):
    state = {}
    for prefix in prefixes:
        full_path = os.path.join(root, prefix.lstrip('/'))
        if not os.path.lexists(full_path):
            state[prefix] = None
            continue
        capture_path(full_path, prefix, state)
    return state


def capture_path(full_path, rel_path, state):
    st = os.lstat(full_path)
    entry = {
        'mode': stat.S_IMODE(st.st_mode),
        'type': stat.S_IFMT(st.st_mode),
        'uid': st.st_uid,
        'gid': st.st_gid,
        'mtime': int(st.st_mtime),
    }
    if stat.S_ISREG(st.st_mode):
        with open(full_path, 'rb') as handle:
            entry['bytes'] = handle.read()
    elif stat.S_ISLNK(st.st_mode):
        entry['target'] = os.readlink(full_path)
    elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
        entry['rdev'] = (os.major(st.st_rdev), os.minor(st.st_rdev))

    state[rel_path] = entry

    if stat.S_ISDIR(st.st_mode):
        for name in sorted(os.listdir(full_path)):
            child_full = os.path.join(full_path, name)
            child_rel = rel_path.rstrip('/') + '/' + name
            capture_path(child_full, child_rel, state)


def assert_roots_match(real_root, native_root, prefixes):
    assert capture_tree(real_root, prefixes) == capture_tree(native_root, prefixes)
