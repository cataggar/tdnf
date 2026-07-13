import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / 'out'
TEST_ROOT = OUT_DIR / 'native-scriptlet-tests'
SCRIPTLET_TOOL = OUT_DIR / 'libexec' / 'tdnf' / 'tdnf-rpm-scriptlet'
WRITE_TOOL = OUT_DIR / 'libexec' / 'tdnf' / 'tdnf-rpmdb-write'

pytestmark = pytest.mark.skipif(
    not SCRIPTLET_TOOL.exists() or
    not WRITE_TOOL.exists() or
    shutil.which('rpm') is None or
    shutil.which('rpmbuild') is None or
    shutil.which('unshare') is None,
    reason='native scriptlet crosscheck prerequisites are unavailable',
)

CRITICAL_EXIT = 41
WARNING_EXIT = 40


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


def run_native_scriptlet(rpm_path, phase, tmp_dir, arg1=None, redirect=False):
    cmd = [
        SCRIPTLET_TOOL,
        '--root', '/',
        '--phase', phase,
        '--rpmdefine', native_tmp_define(tmp_dir),
    ]
    if arg1 is not None:
        cmd.extend(['--arg1', str(arg1)])
    if redirect:
        cmd.extend(['--script-fd', '2', '--redirect-stdout-to-stderr'])
    return run(cmd + [rpm_path], check=False)


def native_db_install(db_root, rpm_path):
    result = run([WRITE_TOOL, 'install', db_root, rpm_path, '1', '1', '3'])
    return int(result.stdout.strip())


def native_db_erase(db_root, hnum):
    run([WRITE_TOOL, 'erase-hnum', db_root, str(hnum)])


def native_find_hnum(db_root, nevra):
    result = run([WRITE_TOOL, 'find-hnum', db_root, nevra], check=False)
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return int(result.stdout.strip())


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


def script_state_block(phase, marker_dir, db_root, package_name, payload_path):
    log = marker_dir / 'log'
    db_dir = rpm_db_dir(db_root)
    return f'''%{phase}
echo {phase}:$1 >> "{log}"
if rpm --dbpath "{db_dir}" -q {package_name} >/dev/null 2>&1; then
    echo {phase}-db:present >> "{log}"
else
    echo {phase}-db:absent >> "{log}"
fi
if [ -f "{payload_path}" ]; then
    echo {phase}-file:present >> "{log}"
else
    echo {phase}-file:absent >> "{log}"
fi
'''


def build_stateful_spec(name, version, payload_path, marker_dir, db_root):
    payload_parent = Path(payload_path).parent
    sections = [
        script_state_block('pretrans', marker_dir, db_root, name, payload_path),
        script_state_block('pre', marker_dir, db_root, name, payload_path),
        script_state_block('post', marker_dir, db_root, name, payload_path),
        script_state_block('preun', marker_dir, db_root, name, payload_path),
        script_state_block('postun', marker_dir, db_root, name, payload_path),
        script_state_block('posttrans', marker_dir, db_root, name, payload_path),
    ]
    return f'''Summary: Native shell scriptlet state test package
Name: {name}
Version: {version}
Release: 1
License: MIT
BuildArch: noarch

%description
Native shell scriptlet state crosscheck fixture.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo payload-{version} > %{{buildroot}}{payload_path}

{''.join(sections)}%files
{payload_path}
'''


def build_fail_spec(name, version, payload_path, marker_dir, fail_phase, fail_code):
    payload_parent = Path(payload_path).parent
    log = marker_dir / 'log'
    sections = []
    if fail_phase == 'pre':
        sections.append(f'''%pre
echo pre:$1 >> "{log}"
exit {fail_code}
''')
    else:
        sections.append(f'''%pre
echo pre:$1 >> "{log}"
''')

    if fail_phase == 'post':
        sections.append(f'''%post
echo post:$1 >> "{log}"
exit {fail_code}
''')
    else:
        sections.append(f'''%post
echo post:$1 >> "{log}"
''')

    if fail_phase == 'preun':
        sections.append(f'''%preun
echo preun:$1 >> "{log}"
exit {fail_code}
''')
    elif fail_phase in ('postun', 'erase-ok'):
        sections.append(f'''%preun
echo preun:$1 >> "{log}"
''')

    if fail_phase == 'postun':
        sections.append(f'''%postun
echo postun:$1 >> "{log}"
exit {fail_code}
''')
    elif fail_phase in ('preun', 'erase-ok'):
        sections.append(f'''%postun
echo postun:$1 >> "{log}"
''')

    return f'''Summary: Native shell scriptlet failure fixture
Name: {name}
Version: {version}
Release: 1
License: MIT
BuildArch: noarch

%description
Native shell scriptlet failure crosscheck fixture.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo payload-{version} > %{{buildroot}}{payload_path}

{''.join(sections)}%files
{payload_path}
'''


def build_upgrade_spec(name, version, payload_path, log_path, label):
    payload_parent = Path(payload_path).parent
    return f'''Summary: Native shell scriptlet upgrade arg fixture
Name: {name}
Version: {version}
Release: 1
License: MIT
BuildArch: noarch

%description
Native shell scriptlet upgrade arg fixture.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo payload-{label} > %{{buildroot}}{payload_path}

%pretrans
echo {label}:pretrans:$1 >> "{log_path}"
%pre
echo {label}:pre:$1 >> "{log_path}"
%post
echo {label}:post:$1 >> "{log_path}"
%preun
echo {label}:preun:$1 >> "{log_path}"
%postun
echo {label}:postun:$1 >> "{log_path}"
%posttrans
echo {label}:posttrans:$1 >> "{log_path}"

%files
{payload_path}
'''


def build_verbose_spec(name, version, payload_path):
    payload_parent = Path(payload_path).parent
    return f'''Summary: Native shell scriptlet stdout/stderr fixture
Name: {name}
Version: {version}
Release: 1
License: MIT
BuildArch: noarch

%description
Native shell scriptlet stdout/stderr fixture.

%prep
%build
%install
mkdir -p %{{buildroot}}{payload_parent}
echo payload-{version} > %{{buildroot}}{payload_path}

%pre
echo stdout-from-pre
echo stderr-from-pre >&2

%files
{payload_path}
'''


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
        'payload_path': files_dir / 'payload.txt',
        'db_root': env_root / 'dbroot',
        'tmp_dir': tmp_dir,
        'build_dir': env_root / 'rpmbuild',
    }


def make_case(name):
    case_root = TEST_ROOT / name
    clear_tree(case_root)
    return {
        'root': case_root,
        'real': make_env(case_root, 'real'),
        'native': make_env(case_root, 'native'),
    }


def assert_log_match(real_env, native_env):
    assert read_log(real_env['marker_dir'] / 'log') == read_log(native_env['marker_dir'] / 'log')


def materialize_payload(payload_path, version):
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_path.write_text(f'payload-{version}\n', encoding='utf-8')


def simulate_native_install(native_env, rpm_path, version):
    for phase in ('pretrans', 'pre'):
        result = run_native_scriptlet(rpm_path, phase, native_env['tmp_dir'], arg1=1)
        assert result.returncode == 0, result
    materialize_payload(native_env['payload_path'], version)
    native_db_install(native_env['db_root'], rpm_path)
    for phase in ('post', 'posttrans'):
        result = run_native_scriptlet(rpm_path, phase, native_env['tmp_dir'], arg1=1)
        assert result.returncode == 0, result


def simulate_native_erase(native_env, rpm_path):
    package_name = run(['rpm', '-qp', '--qf', '%{NAME}\n', rpm_path]).stdout.strip()
    nevra = query_nevra(rpm_path)
    hnum = native_find_hnum(native_env['db_root'], nevra)
    result = run_native_scriptlet(rpm_path, 'preun', native_env['tmp_dir'], arg1=0)
    assert result.returncode == 0, result
    native_env['payload_path'].unlink()
    result = run_native_scriptlet(rpm_path, 'postun', native_env['tmp_dir'], arg1=0)
    assert result.returncode == 0, result
    native_db_erase(native_env['db_root'], hnum)
    assert not rpm_installed(native_env['db_root'], package_name)


@pytest.fixture(scope='module', autouse=True)
def prepare_test_root():
    clear_tree(TEST_ROOT)
    yield
    shutil.rmtree(TEST_ROOT, ignore_errors=True)


def test_native_scriptlet_install_and_erase_match_real_rpm():
    case = make_case('install-erase')
    name = 'tdnf-native-scriptlet-stateful'
    version = '1.0.0'

    real_rpm = build_rpm(
        case['real']['build_dir'],
        name,
        version,
        build_stateful_spec(name, version, case['real']['payload_path'], case['real']['marker_dir'], case['real']['db_root']),
    )
    native_rpm = build_rpm(
        case['native']['build_dir'],
        name,
        version,
        build_stateful_spec(name, version, case['native']['payload_path'], case['native']['marker_dir'], case['native']['db_root']),
    )

    rpm_initdb(case['real']['db_root'])
    rpm_initdb(case['native']['db_root'])

    real_install_result = real_install(case['real']['db_root'], real_rpm)
    assert real_install_result.returncode == 0, real_install_result.stderr
    simulate_native_install(case['native'], native_rpm, version)
    assert_log_match(case['real'], case['native'])
    assert case['real']['payload_path'].read_text(encoding='utf-8') == case['native']['payload_path'].read_text(encoding='utf-8')
    assert rpm_installed(case['real']['db_root'], name)
    assert rpm_installed(case['native']['db_root'], name)

    real_erase_result = real_erase(case['real']['db_root'], name)
    assert real_erase_result.returncode == 0, real_erase_result.stderr
    simulate_native_erase(case['native'], native_rpm)
    assert_log_match(case['real'], case['native'])
    assert not case['real']['payload_path'].exists()
    assert not case['native']['payload_path'].exists()
    assert not rpm_installed(case['real']['db_root'], name)
    assert not rpm_installed(case['native']['db_root'], name)


def test_native_upgrade_argument_convention_matches_real_rpm():
    case = make_case('upgrade-args')
    name = 'tdnf-native-scriptlet-upgrade'
    log_real = case['real']['marker_dir'] / 'log'
    log_native = case['native']['marker_dir'] / 'log'

    real_v1 = build_rpm(
        case['real']['build_dir'] / 'v1',
        name,
        '1.0.0',
        build_upgrade_spec(name, '1.0.0', case['real']['payload_path'], log_real, '1.0.0'),
    )
    real_v2 = build_rpm(
        case['real']['build_dir'] / 'v2',
        name,
        '1.1.0',
        build_upgrade_spec(name, '1.1.0', case['real']['payload_path'], log_real, '1.1.0'),
    )
    native_v1 = build_rpm(
        case['native']['build_dir'] / 'v1',
        name,
        '1.0.0',
        build_upgrade_spec(name, '1.0.0', case['native']['payload_path'], log_native, '1.0.0'),
    )
    native_v2 = build_rpm(
        case['native']['build_dir'] / 'v2',
        name,
        '1.1.0',
        build_upgrade_spec(name, '1.1.0', case['native']['payload_path'], log_native, '1.1.0'),
    )

    rpm_initdb(case['real']['db_root'])
    assert real_install(case['real']['db_root'], real_v1).returncode == 0
    assert real_upgrade(case['real']['db_root'], real_v2).returncode == 0

    for phase in ('pretrans', 'pre', 'post', 'posttrans'):
        result = run_native_scriptlet(native_v1, phase, case['native']['tmp_dir'], arg1=1)
        assert result.returncode == 0, result
    for phase in ('pretrans', 'pre', 'post'):
        result = run_native_scriptlet(native_v2, phase, case['native']['tmp_dir'], arg1=2)
        assert result.returncode == 0, result
    for phase in ('preun', 'postun'):
        result = run_native_scriptlet(native_v1, phase, case['native']['tmp_dir'], arg1=1)
        assert result.returncode == 0, result
    result = run_native_scriptlet(native_v2, 'posttrans', case['native']['tmp_dir'], arg1=2)
    assert result.returncode == 0, result

    assert read_log(log_real) == read_log(log_native)


def test_native_install_failure_severity_matches_real_rpm():
    case = make_case('install-failures')

    pre_name = 'tdnf-native-scriptlet-prefail'
    post_name = 'tdnf-native-scriptlet-postfail'
    pre_version = '1.0.0'
    post_version = '1.0.0'

    real_pre_rpm = build_rpm(
        case['real']['build_dir'] / 'prefail',
        pre_name,
        pre_version,
        build_fail_spec(pre_name, pre_version, case['real']['payload_path'], case['real']['marker_dir'], 'pre', 9),
    )
    native_pre_rpm = build_rpm(
        case['native']['build_dir'] / 'prefail',
        pre_name,
        pre_version,
        build_fail_spec(pre_name, pre_version, case['native']['payload_path'], case['native']['marker_dir'], 'pre', 9),
    )

    rpm_initdb(case['real']['db_root'])
    rpm_initdb(case['native']['db_root'])
    real_pre = real_install(case['real']['db_root'], real_pre_rpm)
    assert real_pre.returncode != 0
    native_pre = run_native_scriptlet(native_pre_rpm, 'pre', case['native']['tmp_dir'], arg1=1)
    assert native_pre.returncode == CRITICAL_EXIT
    assert not case['real']['payload_path'].exists()
    assert not case['native']['payload_path'].exists()
    assert not rpm_installed(case['real']['db_root'], pre_name)
    assert not rpm_installed(case['native']['db_root'], pre_name)

    clear_tree(case['real']['marker_dir'])
    clear_tree(case['native']['marker_dir'])
    case['real']['payload_path'].parent.mkdir(parents=True, exist_ok=True)
    case['native']['payload_path'].parent.mkdir(parents=True, exist_ok=True)

    real_post_rpm = build_rpm(
        case['real']['build_dir'] / 'postfail',
        post_name,
        post_version,
        build_fail_spec(post_name, post_version, case['real']['payload_path'], case['real']['marker_dir'], 'post', 7),
    )
    native_post_rpm = build_rpm(
        case['native']['build_dir'] / 'postfail',
        post_name,
        post_version,
        build_fail_spec(post_name, post_version, case['native']['payload_path'], case['native']['marker_dir'], 'post', 7),
    )

    clear_tree(case['real']['db_root'])
    clear_tree(case['native']['db_root'])
    rpm_initdb(case['real']['db_root'])
    rpm_initdb(case['native']['db_root'])
    real_post = real_install(case['real']['db_root'], real_post_rpm)
    assert real_post.returncode == 0

    materialize_payload(case['native']['payload_path'], post_version)
    native_db_install(case['native']['db_root'], native_post_rpm)
    native_post = run_native_scriptlet(native_post_rpm, 'post', case['native']['tmp_dir'], arg1=1)
    assert native_post.returncode == WARNING_EXIT

    assert case['real']['payload_path'].exists()
    assert case['native']['payload_path'].exists()
    assert rpm_installed(case['real']['db_root'], post_name)
    assert rpm_installed(case['native']['db_root'], post_name)


def test_native_erase_failure_severity_matches_real_rpm():
    case = make_case('erase-failures')

    preun_name = 'tdnf-native-scriptlet-preunfail'
    postun_name = 'tdnf-native-scriptlet-postunfail'
    version = '1.0.0'

    real_preun_rpm = build_rpm(
        case['real']['build_dir'] / 'preunfail',
        preun_name,
        version,
        build_fail_spec(preun_name, version, case['real']['payload_path'], case['real']['marker_dir'], 'preun', 9),
    )
    native_preun_rpm = build_rpm(
        case['native']['build_dir'] / 'preunfail',
        preun_name,
        version,
        build_fail_spec(preun_name, version, case['native']['payload_path'], case['native']['marker_dir'], 'preun', 9),
    )

    rpm_initdb(case['real']['db_root'])
    rpm_initdb(case['native']['db_root'])
    assert real_install(case['real']['db_root'], real_preun_rpm).returncode == 0
    simulate_native_install(case['native'], native_preun_rpm, version)
    real_preun = real_erase(case['real']['db_root'], preun_name)
    assert real_preun.returncode != 0
    native_preun = run_native_scriptlet(native_preun_rpm, 'preun', case['native']['tmp_dir'], arg1=0)
    assert native_preun.returncode == CRITICAL_EXIT
    assert case['real']['payload_path'].exists()
    assert case['native']['payload_path'].exists()
    assert rpm_installed(case['real']['db_root'], preun_name)
    assert rpm_installed(case['native']['db_root'], preun_name)

    clear_tree(case['real']['marker_dir'])
    clear_tree(case['native']['marker_dir'])
    case['real']['payload_path'].parent.mkdir(parents=True, exist_ok=True)
    case['native']['payload_path'].parent.mkdir(parents=True, exist_ok=True)

    real_postun_rpm = build_rpm(
        case['real']['build_dir'] / 'postunfail',
        postun_name,
        version,
        build_fail_spec(postun_name, version, case['real']['payload_path'], case['real']['marker_dir'], 'postun', 7),
    )
    native_postun_rpm = build_rpm(
        case['native']['build_dir'] / 'postunfail',
        postun_name,
        version,
        build_fail_spec(postun_name, version, case['native']['payload_path'], case['native']['marker_dir'], 'postun', 7),
    )

    clear_tree(case['real']['db_root'])
    clear_tree(case['native']['db_root'])
    rpm_initdb(case['real']['db_root'])
    rpm_initdb(case['native']['db_root'])
    assert real_install(case['real']['db_root'], real_postun_rpm).returncode == 0
    simulate_native_install(case['native'], native_postun_rpm, version)
    real_postun = real_erase(case['real']['db_root'], postun_name)
    assert real_postun.returncode == 0

    nevra = query_nevra(native_postun_rpm)
    hnum = native_find_hnum(case['native']['db_root'], nevra)
    native_preun_ok = run_native_scriptlet(native_postun_rpm, 'preun', case['native']['tmp_dir'], arg1=0)
    assert native_preun_ok.returncode == 0
    case['native']['payload_path'].unlink()
    native_postun = run_native_scriptlet(native_postun_rpm, 'postun', case['native']['tmp_dir'], arg1=0)
    assert native_postun.returncode == WARNING_EXIT
    native_db_erase(case['native']['db_root'], hnum)

    assert not case['real']['payload_path'].exists()
    assert not case['native']['payload_path'].exists()
    assert not rpm_installed(case['real']['db_root'], postun_name)
    assert not rpm_installed(case['native']['db_root'], postun_name)


def test_native_scriptlet_redirects_stdout_to_stderr_for_json_mode():
    case = make_case('json-redirect')
    name = 'tdnf-native-scriptlet-verbose'
    version = '1.0.0'

    rpm_path = build_rpm(
        case['native']['build_dir'],
        name,
        version,
        build_verbose_spec(name, version, case['native']['payload_path']),
    )

    result = run_native_scriptlet(rpm_path, 'pre', case['native']['tmp_dir'], arg1=1, redirect=True)
    assert result.returncode == 0
    assert result.stdout == ''
    assert 'stdout-from-pre' in result.stderr
    assert 'stderr-from-pre' in result.stderr
