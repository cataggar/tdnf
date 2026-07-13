#
# Copyright (C) 2025 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License"); you may
# not use this file except in compliance with the License. The terms of the
# License are located in the COPYING file of this distribution.
#

import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / 'out'
TEST_ROOT = OUT_DIR / 'native-trigger-tests'
SCRIPTLET_TOOL = OUT_DIR / 'libexec' / 'tdnf' / 'tdnf-rpm-scriptlet'
TRIGGER_TOOL = OUT_DIR / 'libexec' / 'tdnf' / 'tdnf-rpm-trigger'
WRITE_TOOL = OUT_DIR / 'libexec' / 'tdnf' / 'tdnf-rpmdb-write'

WARNING_EXIT = 40

pytestmark = pytest.mark.skipif(
    not SCRIPTLET_TOOL.exists() or
    not TRIGGER_TOOL.exists() or
    not WRITE_TOOL.exists() or
    shutil.which('rpm') is None or
    shutil.which('rpmbuild') is None or
    shutil.which('unshare') is None,
    reason='native trigger crosscheck prerequisites are unavailable',
)


def run(cmd, check=True):
    result = subprocess.run(
        [str(part) for part in cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            'command failed: {}\nstdout:\n{}\nstderr:\n{}'.format(
                ' '.join(str(part) for part in cmd),
                result.stdout,
                result.stderr,
            )
        )
    return result


def run_as_root(cmd, check=True):
    return run(['unshare', '-Ur', *cmd], check=check)


def clear_tree(path):
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def rpm_db_dir(db_root):
    return db_root / 'var' / 'lib' / 'rpm'


def rpm_initdb(db_root):
    db_dir = rpm_db_dir(db_root)
    db_dir.mkdir(parents=True, exist_ok=True)
    run_as_root(['rpm', '--dbpath', db_dir, '--initdb'])


def rpm_installed(db_root, package_name):
    result = run(['rpm', '--dbpath', rpm_db_dir(db_root), '-q', package_name], check=False)
    return result.returncode == 0


def query_nevra(rpm_path):
    return run(['rpm', '-qp', '--qf', '%{NEVRA}\n', rpm_path]).stdout.strip()


def native_tmp_define(tmp_dir):
    return f'_tmppath {tmp_dir}'


def native_db_install(db_root, rpm_path, install_tid):
    result = run([WRITE_TOOL, 'install', db_root, rpm_path, str(install_tid), str(install_tid), '3'])
    return int(result.stdout.strip())


def native_db_replace(db_root, old_hnum, rpm_path, install_tid):
    result = run([WRITE_TOOL, 'replace', db_root, str(old_hnum), rpm_path, str(install_tid), str(install_tid), '3'])
    return int(result.stdout.strip())


def native_db_erase(db_root, hnum):
    run([WRITE_TOOL, 'erase-hnum', db_root, str(hnum)])


def native_run_scriptlet(rpm_path, phase, tmp_dir, arg1):
    return run([
        SCRIPTLET_TOOL,
        '--root', '/',
        '--phase', phase,
        '--arg1', str(arg1),
        '--rpmdefine', native_tmp_define(tmp_dir),
        rpm_path,
    ], check=False)


def native_run_trigger(rpm_path, phase, db_root, tmp_dir, arg2=None):
    cmd = [
        TRIGGER_TOOL,
        '--db-root', db_root,
        '--install-root', '/',
        '--phase', phase,
        '--rpmdefine', native_tmp_define(tmp_dir),
    ]
    if arg2 is not None:
        cmd += ['--arg2', str(arg2)]
    cmd.append(rpm_path)
    return run(cmd, check=False)


def real_install(db_root, rpm_path):
    return run_as_root(['rpm', '--dbpath', rpm_db_dir(db_root), '-ivh', '--nodeps', '--nosignature', rpm_path], check=False)


def real_upgrade(db_root, rpm_path):
    return run_as_root(['rpm', '--dbpath', rpm_db_dir(db_root), '-Uvh', '--nodeps', '--nosignature', rpm_path], check=False)


def real_erase(db_root, package_name):
    return run_as_root(['rpm', '--dbpath', rpm_db_dir(db_root), '-e', '--nodeps', package_name], check=False)


def read_log(log_path):
    if not log_path.exists():
        return []
    return log_path.read_text(encoding='utf-8').splitlines()


def build_root(path):
    clear_tree(path)
    for rel in ['BUILD', 'BUILDROOT', 'RPMS', 'SRPMS', 'SOURCES', 'SPECS']:
        (path / rel).mkdir(parents=True, exist_ok=True)


def build_rpm(build_dir, name, version, spec_text):
    build_root(build_dir)
    spec_path = build_dir / 'SPECS' / f'{name}.spec'
    spec_path.write_text(spec_text, encoding='utf-8')
    run(['rpmbuild', '-D', f'_topdir {build_dir}', '-bb', spec_path])
    return build_dir / 'RPMS' / 'noarch' / f'{name}-{version}-1.noarch.rpm'


def make_env(case_root, env_name):
    env_root = case_root / env_name
    clear_tree(env_root)
    marker_dir = env_root / 'markers'
    marker_dir.mkdir(parents=True, exist_ok=True)
    files_dir = env_root / 'files'
    files_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = env_root / 'tmp'
    tmp_dir.mkdir(parents=True, exist_ok=True)
    return {
        'root': env_root,
        'marker_dir': marker_dir,
        'files_dir': files_dir,
        'db_root': env_root / 'dbroot',
        'tmp_dir': tmp_dir,
        'build_dir': env_root / 'rpmbuild',
        'log_path': marker_dir / 'log',
    }


def make_case(name):
    case_root = TEST_ROOT / name
    clear_tree(case_root)
    return {
        'root': case_root,
        'real': make_env(case_root, 'real'),
        'native': make_env(case_root, 'native'),
    }


def log_db_state_block(prefix, db_root, package_name):
    db_dir = rpm_db_dir(db_root)
    return f'''\
echo {prefix}:$1 >> "{{log_path}}"
if rpm --dbpath "{db_dir}" -q {package_name} >/dev/null 2>&1; then
    echo {prefix}-db:present >> "{{log_path}}"
else
    echo {prefix}-db:absent >> "{{log_path}}"
fi
'''


def build_target_order_spec(name, version, payload_path, log_path, db_root, label):
    payload_parent = payload_path.parent
    return f'''Summary: Native trigger target order fixture
Name: {name}
Version: {version}
Release: 1
License: MIT
BuildArch: noarch

%description
Native trigger target order crosscheck fixture.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo payload-{label} > %{{buildroot}}{payload_path}

%pre
{log_db_state_block(f'target-{label}:%pre', db_root, name).format(log_path=log_path)}
%post
{log_db_state_block(f'target-{label}:%post', db_root, name).format(log_path=log_path)}
%preun
{log_db_state_block(f'target-{label}:%preun', db_root, name).format(log_path=log_path)}
%postun
{log_db_state_block(f'target-{label}:%postun', db_root, name).format(log_path=log_path)}
%posttrans
echo target-{label}:%posttrans:$1 >> "{log_path}"

%files
{payload_path}
'''


def build_owner_order_spec(name, target_name, payload_path, log_path, db_root):
    payload_parent = payload_path.parent

    def trigger_block(phase):
        return f'''%{phase} -- {target_name}
{log_db_state_block(f'owner:%{phase}', db_root, target_name).format(log_path=log_path)}'''

    return f'''Summary: Native trigger owner order fixture
Name: {name}
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Native trigger owner order crosscheck fixture.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo owner > %{{buildroot}}{payload_path}

{trigger_block('triggerin')}
{trigger_block('triggerun')}
{trigger_block('triggerpostun')}
%files
{payload_path}
'''


def build_fail_target_spec(name, payload_path):
    payload_parent = payload_path.parent
    return f'''Summary: Native trigger target failure fixture
Name: {name}
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Native trigger target failure fixture.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo payload > %{{buildroot}}{payload_path}

%files
{payload_path}
'''


def build_fail_owner_spec(name, target_name, payload_path, log_path, phase, code):
    payload_parent = payload_path.parent
    return f'''Summary: Native trigger failure fixture
Name: {name}
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Native trigger failure fixture.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo owner > %{{buildroot}}{payload_path}

%{phase} -- {target_name}
echo {phase}:$1:$2 >> "{log_path}"
exit {code}

%files
{payload_path}
'''


def simulate_native_install(native_env, rpm_path, install_tid):
    result = native_run_scriptlet(rpm_path, 'pre', native_env['tmp_dir'], arg1=1)
    assert result.returncode == 0, result
    hnum = native_db_install(native_env['db_root'], rpm_path, install_tid)
    result = native_run_scriptlet(rpm_path, 'post', native_env['tmp_dir'], arg1=1)
    assert result.returncode == 0, result
    result = native_run_trigger(rpm_path, 'triggerin', native_env['db_root'], native_env['tmp_dir'])
    assert result.returncode == 0, result
    result = native_run_scriptlet(rpm_path, 'posttrans', native_env['tmp_dir'], arg1=1)
    assert result.returncode == 0, result
    return hnum


def test_native_trigger_order_and_args_match_real_rpm():
    case = make_case('order-and-args')
    target_name = 'tdnf-native-trigger-target'
    owner_name = 'tdnf-native-trigger-owner'

    real_target_v1 = build_rpm(
        case['real']['build_dir'] / 'target-v1',
        target_name,
        '1.0.0',
        build_target_order_spec(
            target_name,
            '1.0.0',
            case['real']['files_dir'] / 'target.txt',
            case['real']['log_path'],
            case['real']['db_root'],
            '1.0.0',
        ),
    )
    real_target_v2 = build_rpm(
        case['real']['build_dir'] / 'target-v2',
        target_name,
        '1.1.0',
        build_target_order_spec(
            target_name,
            '1.1.0',
            case['real']['files_dir'] / 'target.txt',
            case['real']['log_path'],
            case['real']['db_root'],
            '1.1.0',
        ),
    )
    real_owner = build_rpm(
        case['real']['build_dir'] / 'owner',
        owner_name,
        '1.0.0',
        build_owner_order_spec(
            owner_name,
            target_name,
            case['real']['files_dir'] / 'owner.txt',
            case['real']['log_path'],
            case['real']['db_root'],
        ),
    )

    native_target_v1 = build_rpm(
        case['native']['build_dir'] / 'target-v1',
        target_name,
        '1.0.0',
        build_target_order_spec(
            target_name,
            '1.0.0',
            case['native']['files_dir'] / 'target.txt',
            case['native']['log_path'],
            case['native']['db_root'],
            '1.0.0',
        ),
    )
    native_target_v2 = build_rpm(
        case['native']['build_dir'] / 'target-v2',
        target_name,
        '1.1.0',
        build_target_order_spec(
            target_name,
            '1.1.0',
            case['native']['files_dir'] / 'target.txt',
            case['native']['log_path'],
            case['native']['db_root'],
            '1.1.0',
        ),
    )
    native_owner = build_rpm(
        case['native']['build_dir'] / 'owner',
        owner_name,
        '1.0.0',
        build_owner_order_spec(
            owner_name,
            target_name,
            case['native']['files_dir'] / 'owner.txt',
            case['native']['log_path'],
            case['native']['db_root'],
        ),
    )

    rpm_initdb(case['real']['db_root'])
    assert real_install(case['real']['db_root'], real_owner).returncode == 0
    assert real_install(case['real']['db_root'], real_target_v1).returncode == 0
    assert real_upgrade(case['real']['db_root'], real_target_v2).returncode == 0
    assert real_erase(case['real']['db_root'], target_name).returncode == 0

    owner_hnum = native_db_install(case['native']['db_root'], native_owner, 1)
    assert owner_hnum == 1

    target_v1_hnum = simulate_native_install(case['native'], native_target_v1, 2)

    result = native_run_scriptlet(native_target_v2, 'pre', case['native']['tmp_dir'], arg1=2)
    assert result.returncode == 0, result
    target_v2_hnum = native_db_install(case['native']['db_root'], native_target_v2, 3)
    result = native_run_scriptlet(native_target_v2, 'post', case['native']['tmp_dir'], arg1=2)
    assert result.returncode == 0, result
    result = native_run_trigger(native_target_v2, 'triggerin', case['native']['db_root'], case['native']['tmp_dir'])
    assert result.returncode == 0, result
    result = native_run_trigger(native_target_v1, 'triggerun', case['native']['db_root'], case['native']['tmp_dir'])
    assert result.returncode == 0, result
    result = native_run_scriptlet(native_target_v1, 'preun', case['native']['tmp_dir'], arg1=1)
    assert result.returncode == 0, result
    result = native_run_scriptlet(native_target_v1, 'postun', case['native']['tmp_dir'], arg1=1)
    assert result.returncode == 0, result
    result = native_run_trigger(native_target_v1, 'triggerpostun', case['native']['db_root'], case['native']['tmp_dir'])
    assert result.returncode == 0, result
    native_db_erase(case['native']['db_root'], target_v1_hnum)
    result = native_run_scriptlet(native_target_v2, 'posttrans', case['native']['tmp_dir'], arg1=2)
    assert result.returncode == 0, result

    result = native_run_trigger(native_target_v2, 'triggerun', case['native']['db_root'], case['native']['tmp_dir'])
    assert result.returncode == 0, result
    result = native_run_scriptlet(native_target_v2, 'preun', case['native']['tmp_dir'], arg1=0)
    assert result.returncode == 0, result
    result = native_run_scriptlet(native_target_v2, 'postun', case['native']['tmp_dir'], arg1=0)
    assert result.returncode == 0, result
    result = native_run_trigger(native_target_v2, 'triggerpostun', case['native']['db_root'], case['native']['tmp_dir'])
    assert result.returncode == 0, result
    native_db_erase(case['native']['db_root'], target_v2_hnum)

    assert read_log(case['real']['log_path']) == read_log(case['native']['log_path'])
    assert rpm_installed(case['real']['db_root'], owner_name)
    assert rpm_installed(case['native']['db_root'], owner_name)
    assert not rpm_installed(case['real']['db_root'], target_name)
    assert not rpm_installed(case['native']['db_root'], target_name)


@pytest.mark.parametrize('phase,code,expect_target_installed', [
    ('triggerin', 7, True),
    ('triggerun', 8, False),
    ('triggerpostun', 9, False),
])
def test_native_trigger_warning_exit_codes_match_real_rpm(phase, code, expect_target_installed):
    case = make_case(f'warning-{phase}')
    target_name = f'tdnf-native-trigger-target-{phase}'
    owner_name = f'tdnf-native-trigger-owner-{phase}'

    real_target = build_rpm(
        case['real']['build_dir'] / 'target',
        target_name,
        '1.0.0',
        build_fail_target_spec(target_name, case['real']['files_dir'] / 'target.txt'),
    )
    real_owner = build_rpm(
        case['real']['build_dir'] / 'owner',
        owner_name,
        '1.0.0',
        build_fail_owner_spec(
            owner_name,
            target_name,
            case['real']['files_dir'] / 'owner.txt',
            case['real']['log_path'],
            phase,
            code,
        ),
    )
    native_target = build_rpm(
        case['native']['build_dir'] / 'target',
        target_name,
        '1.0.0',
        build_fail_target_spec(target_name, case['native']['files_dir'] / 'target.txt'),
    )
    native_owner = build_rpm(
        case['native']['build_dir'] / 'owner',
        owner_name,
        '1.0.0',
        build_fail_owner_spec(
            owner_name,
            target_name,
            case['native']['files_dir'] / 'owner.txt',
            case['native']['log_path'],
            phase,
            code,
        ),
    )

    rpm_initdb(case['real']['db_root'])
    assert real_install(case['real']['db_root'], real_owner).returncode == 0

    owner_hnum = native_db_install(case['native']['db_root'], native_owner, 1)
    assert owner_hnum == 1

    if phase == 'triggerin':
        real_result = real_install(case['real']['db_root'], real_target)
        assert real_result.returncode == 0

        target_hnum = native_db_install(case['native']['db_root'], native_target, 2)
        native_result = native_run_trigger(native_target, phase, case['native']['db_root'], case['native']['tmp_dir'])
        assert native_result.returncode == WARNING_EXIT
        assert target_hnum == 2
    else:
        assert real_install(case['real']['db_root'], real_target).returncode == 0
        target_hnum = native_db_install(case['native']['db_root'], native_target, 2)

        real_result = real_erase(case['real']['db_root'], target_name)
        assert real_result.returncode == 0

        native_result = native_run_trigger(native_target, phase, case['native']['db_root'], case['native']['tmp_dir'])
        assert native_result.returncode == WARNING_EXIT
        native_db_erase(case['native']['db_root'], target_hnum)

    assert read_log(case['real']['log_path']) == read_log(case['native']['log_path'])
    assert rpm_installed(case['real']['db_root'], target_name) == expect_target_installed
    assert rpm_installed(case['native']['db_root'], target_name) == expect_target_installed


def build_target_upgrade_spec(name, version, payload_path):
    payload_parent = payload_path.parent
    return f'''Summary: Native trigger upgrade arg2 fixture target
Name: {name}
Version: {version}
Release: 1
License: MIT
BuildArch: noarch

%description
Native trigger upgrade arg2 fixture target.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo payload-{version} > %{{buildroot}}{payload_path}

%files
{payload_path}
'''


def build_owner_argcapture_spec(name, target_name, payload_path, log_path):
    """
    Trigger scripts that log both `$1` and `$2` for every phase.

    Used to cross-check `%triggerin/%triggerun/%triggerpostun`
    argument conventions between real rpm and the native executor
    across install -> upgrade -> erase.
    """
    payload_parent = payload_path.parent

    def trigger_block(phase):
        return (
            f'%{phase} -- {target_name}\n'
            f'echo {phase}:$1:$2 >> "{log_path}"\n'
        )

    return f'''Summary: Native trigger upgrade arg2 fixture owner
Name: {name}
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Native trigger upgrade arg2 fixture owner.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo owner > %{{buildroot}}{payload_path}

{trigger_block('triggerin')}
{trigger_block('triggerun')}
{trigger_block('triggerpostun')}

%files
{payload_path}
'''


def test_native_trigger_upgrade_arg2_matches_real_rpm():
    """
    Crosscheck: for an owner package with %triggerin/%triggerun/
    %triggerpostun on a target, the native executor must reproduce
    real rpm's `$1`/`$2` sequence across install -> upgrade -> erase.

    Real rpm's log (verified in the epic write-up):
        triggerin:1:1                 (install target v1)
        triggerin:1:2                 (upgrade v1->v2, both briefly co-installed)
        triggerun:1:1                 (upgrade cleanup, new v2 survives)
        triggerpostun:1:1             (upgrade cleanup, new v2 survives)
        triggerun:1:0                 (plain erase v2)
        triggerpostun:1:0             (plain erase v2)

    The native executor now matches this via the trigger engine's
    `arg2_override_present/value` fields wired from
    client/rpmtrans_native.c.
    """
    case = make_case('upgrade-arg2')
    target_name = 'tdnf-native-trigger-upgrade-target'
    owner_name = 'tdnf-native-trigger-upgrade-owner'

    def build_env(env):
        target_v1 = build_rpm(
            env['build_dir'] / 'target-v1',
            target_name,
            '1.0.0',
            build_target_upgrade_spec(target_name, '1.0.0', env['files_dir'] / 'target.txt'),
        )
        target_v2 = build_rpm(
            env['build_dir'] / 'target-v2',
            target_name,
            '2.0.0',
            build_target_upgrade_spec(target_name, '2.0.0', env['files_dir'] / 'target.txt'),
        )
        owner = build_rpm(
            env['build_dir'] / 'owner',
            owner_name,
            '1.0.0',
            build_owner_argcapture_spec(
                owner_name,
                target_name,
                env['files_dir'] / 'owner.txt',
                env['log_path'],
            ),
        )
        return target_v1, target_v2, owner

    real_v1, real_v2, real_owner = build_env(case['real'])
    native_v1, native_v2, native_owner = build_env(case['native'])

    # Real rpm sequence: install owner, install target v1, upgrade v1->v2, erase v2.
    rpm_initdb(case['real']['db_root'])
    assert real_install(case['real']['db_root'], real_owner).returncode == 0
    assert real_install(case['real']['db_root'], real_v1).returncode == 0
    assert real_upgrade(case['real']['db_root'], real_v2).returncode == 0
    assert real_erase(case['real']['db_root'], target_name).returncode == 0
    real_log = read_log(case['real']['log_path'])

    assert real_log == [
        'triggerin:1:1',
        'triggerin:1:2',
        'triggerun:1:1',
        'triggerpostun:1:1',
        'triggerun:1:0',
        'triggerpostun:1:0',
    ], f'unexpected real rpm log: {real_log}'

    # Native simulation. write_replace collapses the two-instance
    # state, so we drive the trigger engine using the explicit arg2
    # override for the upgrade-only phases, mirroring what
    # client/rpmtrans_native.c does in ProcessInstallItem +
    # EraseOldAfterReplace.
    owner_hnum = native_db_install(case['native']['db_root'], native_owner, 1)
    assert owner_hnum == 1

    # Install target v1 (fresh).
    v1_hnum = native_db_install(case['native']['db_root'], native_v1, 2)
    r = native_run_trigger(native_v1, 'triggerin', case['native']['db_root'], case['native']['tmp_dir'])
    assert r.returncode == 0, r

    # Upgrade target v1 -> v2 (write_replace deletes old row, inserts new
    # under a fresh hnum — the DB briefly held two rows during the
    # transaction, but at this point only the new row survives).
    v2_hnum = native_db_replace(case['native']['db_root'], v1_hnum, native_v2, 3)
    # %triggerin on new during upgrade: arg2 override = 1 + nPriors = 2.
    r = native_run_trigger(native_v2, 'triggerin', case['native']['db_root'], case['native']['tmp_dir'], arg2=2)
    assert r.returncode == 0, r
    # %triggerun on old during upgrade: arg2 override = 1.
    r = native_run_trigger(native_v1, 'triggerun', case['native']['db_root'], case['native']['tmp_dir'], arg2=1)
    assert r.returncode == 0, r
    # %triggerpostun on old during upgrade: arg2 override = 1.
    r = native_run_trigger(native_v1, 'triggerpostun', case['native']['db_root'], case['native']['tmp_dir'], arg2=1)
    assert r.returncode == 0, r

    # Plain erase v2: no override (engine computes from rpmdb).
    r = native_run_trigger(native_v2, 'triggerun', case['native']['db_root'], case['native']['tmp_dir'])
    assert r.returncode == 0, r
    native_db_erase(case['native']['db_root'], v2_hnum)
    r = native_run_trigger(native_v2, 'triggerpostun', case['native']['db_root'], case['native']['tmp_dir'])
    assert r.returncode == 0, r

    native_log = read_log(case['native']['log_path'])
    assert native_log == real_log, (
        f'native trigger arg1/arg2 sequence diverges from real rpm:\n'
        f'  real:   {real_log}\n'
        f'  native: {native_log}'
    )


@pytest.fixture(scope='module', autouse=True)
def prepare_test_root():
    clear_tree(TEST_ROOT)
    yield
    shutil.rmtree(TEST_ROOT, ignore_errors=True)
