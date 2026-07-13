#
# Copyright (C) 2026 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import ctypes
import glob
import json
import os
import shutil
import subprocess

import pytest

HELPER = 'tdnf-native-order-helper'
PRE = 'tdnf-native-order-pre'
POST = 'tdnf-native-order-post'
PREUN = 'tdnf-native-order-preun'
POSTUN = 'tdnf-native-order-postun'
SHELL_PROVIDER = 'tdnf-native-shell-provider'
PRETRANS_ONE = 'tdnf-test-pretrans-one'
PRETRANS_TWO = 'tdnf-test-pretrans-two'
PRETRANS_PROVIDER = 'tdnf-dummy-pretrans'
CONFLICT_FILE0 = 'tdnf-conflict-file0'
CONFLICT_FILE1 = 'tdnf-conflict-file1'
DUMMY_CONFLICT0 = 'tdnf-test-dummy-conflicts-0'
DUMMY_CONFLICT1 = 'tdnf-test-dummy-conflicts-1'
OBSOLETED = 'tdnf-test-dummy-obsoleted'
OBSOLETING = 'tdnf-test-dummy-obsoleting'
MULTIVERSION = 'tdnf-test-multiversion'
MULTIVERSION_LOWER = 'tdnf-test-multiversion@1.0.1-1'
MULTIVERSION_HIGHER = 'tdnf-test-multiversion@1.0.2-1'

OP_INSTALL = 1
OP_REINSTALL = 2
OP_ERASE = 3


@pytest.fixture(scope='module', autouse=True)
def check_packages_consistency():
    yield


class NativeTransactionItem(ctypes.Structure):
    _fields_ = [
        ('dwOperation', ctypes.c_uint32),
        ('pszPath', ctypes.c_char_p),
        ('pszName', ctypes.c_char_p),
        ('pszEVR', ctypes.c_char_p),
        ('pszArch', ctypes.c_char_p),
    ]


class NativeTransactionSolver(object):
    def __init__(self, build_dir):
        self.lib = ctypes.CDLL(os.path.join(build_dir, 'lib', 'libtdnf.so'))
        self.lib.TDNFRepoMdNativeTransactionSolve.argtypes = [
            ctypes.POINTER(NativeTransactionItem),
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p)),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p)),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self.lib.TDNFRepoMdNativeTransactionSolve.restype = ctypes.c_uint32
        self.lib.TDNFRepoMdNativeTransactionLastError.restype = ctypes.c_char_p
        self.lib.TDNFFreeStringArray.argtypes = [ctypes.POINTER(ctypes.c_char_p)]

    def solve(self, root, items):
        raw_items = (NativeTransactionItem * len(items))()
        for index, item in enumerate(items):
            raw_items[index].dwOperation = item['op']
            raw_items[index].pszPath = item.get('path')
            raw_items[index].pszName = item.get('name')
            raw_items[index].pszEVR = item.get('evr')
            raw_items[index].pszArch = item.get('arch')

        order_lines = ctypes.POINTER(ctypes.c_char_p)()
        order_count = ctypes.c_uint32()
        problem_lines = ctypes.POINTER(ctypes.c_char_p)()
        problem_count = ctypes.c_uint32()

        rc = self.lib.TDNFRepoMdNativeTransactionSolve(
            raw_items,
            len(items),
            root.encode(),
            ctypes.byref(order_lines),
            ctypes.byref(order_count),
            ctypes.byref(problem_lines),
            ctypes.byref(problem_count),
        )
        if rc != 0:
            last_error = self.lib.TDNFRepoMdNativeTransactionLastError().decode()
            pytest.fail(f'native transaction solve failed: rc={rc} err={last_error}')

        order = []
        problems = []
        try:
            if order_lines:
                order = [int(order_lines[index].decode()) for index in range(order_count.value)]
            if problem_lines:
                problems = [problem_lines[index].decode() for index in range(problem_count.value)]
        finally:
            if order_lines:
                self.lib.TDNFFreeStringArray(order_lines)
            if problem_lines:
                self.lib.TDNFFreeStringArray(problem_lines)
        return order, problems


def run_cmd(cmd):
    return subprocess.run(
        cmd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def load_config():
    with open(os.path.join(os.path.dirname(__file__), '..', 'config.json')) as fp:
        return json.load(fp)


def ensure_repo(repo_path, specs_dir):
    if os.path.isdir(repo_path):
        shutil.rmtree(repo_path)
    run_cmd(['bash', os.path.join(specs_dir, 'setup-repo.sh'), repo_path, specs_dir])


def find_rpm(repo_path, name):
    matches = glob.glob(os.path.join(repo_path, 'photon-test', 'RPMS', '*', f'{name}-*.rpm'))
    assert len(matches) == 1, f'expected one RPM for {name}, found {matches}'
    return matches[0]


def find_rpm_with_evr(repo_path, name, evr):
    matches = glob.glob(os.path.join(repo_path, 'photon-test', 'RPMS', '*', f'{name}-{evr}.*.rpm'))
    assert len(matches) == 1, f'expected one RPM for {name}-{evr}, found {matches}'
    return matches[0]


def query_nevra(rpm_path):
    result = run_cmd([
        'rpm',
        '-qp',
        '--queryformat',
        '%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}\n',
        rpm_path,
    ])
    name, evr, arch = result.stdout.strip().splitlines()
    return {
        'name': name,
        'evr': evr,
        'arch': arch,
    }


def nevra_text(meta):
    return f"{meta['name']}-{meta['evr']}.{meta['arch']}"


def init_local_root(work_dir):
    root = os.path.join(work_dir, 'root')
    dbpath = os.path.join(root, 'var', 'lib', 'rpm')
    os.makedirs(dbpath, exist_ok=True)
    run_cmd(['rpm', '--dbpath', dbpath, '--initdb'])
    return root, dbpath


def rpmdb_install(dbpath, rpm_paths):
    run_cmd([
        'rpm',
        '--dbpath', dbpath,
        '-ivh',
        '--justdb',
        '--nodeps',
        '--noscripts',
        *rpm_paths,
    ])


def build_install_items(*rpm_paths):
    return [{'op': OP_INSTALL, 'path': rpm_path.encode()} for rpm_path in rpm_paths]


def build_erase_items(rpm_meta):
    return [{
        'op': OP_ERASE,
        'name': meta['name'].encode(),
        'evr': meta['evr'].encode(),
        'arch': meta['arch'].encode(),
    } for meta in rpm_meta]


@pytest.fixture(scope='module')
def native_ctx():
    config = load_config()
    repo_path = os.path.join(config['build_dir'], 'native-transaction-test-repo')
    specs_dir = config['specs_dir']
    ensure_repo(repo_path, specs_dir)

    packages = {
        name: find_rpm(repo_path, name)
        for name in (
            HELPER,
            PRE,
            POST,
            PREUN,
            POSTUN,
            SHELL_PROVIDER,
            PRETRANS_ONE,
            PRETRANS_TWO,
            PRETRANS_PROVIDER,
            CONFLICT_FILE0,
            CONFLICT_FILE1,
            DUMMY_CONFLICT0,
            DUMMY_CONFLICT1,
            OBSOLETED,
            OBSOLETING,
        )
    }
    packages[MULTIVERSION_LOWER] = find_rpm_with_evr(repo_path, MULTIVERSION, config['mulversion_lower'])
    packages[MULTIVERSION_HIGHER] = find_rpm_with_evr(repo_path, MULTIVERSION, config['mulversion_higher'])
    package_meta = {
        name: query_nevra(path)
        for name, path in packages.items()
    }
    work_dir = os.path.join(config['build_dir'], 'native-transaction-work')
    if os.path.isdir(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)

    yield {
        'packages': packages,
        'package_meta': package_meta,
        'solver': NativeTransactionSolver(config['build_dir']),
        'work_dir': work_dir,
    }

    shutil.rmtree(repo_path, ignore_errors=True)
    shutil.rmtree(work_dir, ignore_errors=True)


def create_root(native_ctx, name, installed_packages):
    root_dir = os.path.join(native_ctx['work_dir'], name)
    if os.path.isdir(root_dir):
        shutil.rmtree(root_dir)
    os.makedirs(root_dir)
    root, dbpath = init_local_root(root_dir)
    if installed_packages:
        rpmdb_install(dbpath, [native_ctx['packages'][pkg] for pkg in installed_packages])
    return root


def order_names(order, names):
    return [names[index] for index in order]


def test_install_requires_pre_post_ordering(native_ctx):
    root = create_root(native_ctx, 'install-order', [SHELL_PROVIDER])
    items = build_install_items(
        native_ctx['packages'][POST],
        native_ctx['packages'][PRE],
        native_ctx['packages'][HELPER],
    )
    order, problems = native_ctx['solver'].solve(root, items)
    assert problems == []

    ordered = order_names(order, [POST, PRE, HELPER])
    assert ordered.index(HELPER) < ordered.index(PRE)
    assert ordered.index(HELPER) < ordered.index(POST)


def test_erase_requires_preun_postun_ordering(native_ctx):
    root = create_root(native_ctx, 'erase-order', [SHELL_PROVIDER, HELPER, PREUN, POSTUN])
    items = build_erase_items([
        native_ctx['package_meta'][HELPER],
        native_ctx['package_meta'][PREUN],
        native_ctx['package_meta'][POSTUN],
    ])
    order, problems = native_ctx['solver'].solve(root, items)
    assert problems == []

    ordered = order_names(order, [HELPER, PREUN, POSTUN])
    assert ordered.index(PREUN) < ordered.index(HELPER)
    assert ordered.index(POSTUN) < ordered.index(HELPER)


@pytest.mark.parametrize(
    'package_name, expected_requirement',
    [
        (PRETRANS_ONE, 'tdnf-dummy-pretrans >= 1.0-1'),
        (PRETRANS_TWO, 'tdnf-dummy-pretrans < 1.0-2'),
    ],
)
def test_pretrans_requires_missing_problem_has_guidance(native_ctx, package_name, expected_requirement):
    root = create_root(native_ctx, f'pretrans-missing-{package_name}', [SHELL_PROVIDER])
    order, problems = native_ctx['solver'].solve(
        root,
        build_install_items(native_ctx['packages'][package_name]),
    )
    assert order == [0]
    assert len(problems) == 1
    assert expected_requirement in problems[0]
    assert 'Detected rpm pre-transaction dependency errors.' in problems[0]


@pytest.mark.parametrize('package_name', [PRETRANS_ONE, PRETRANS_TWO])
def test_pretrans_requires_satisfied_by_local_rpmdb(native_ctx, package_name):
    root = create_root(native_ctx, f'pretrans-satisfied-{package_name}', [SHELL_PROVIDER, PRETRANS_PROVIDER])
    order, problems = native_ctx['solver'].solve(
        root,
        build_install_items(native_ctx['packages'][package_name]),
    )
    assert order == [0]
    assert problems == []


def test_file_conflict_atonce_detected(native_ctx):
    root = create_root(native_ctx, 'file-conflict-atonce', [SHELL_PROVIDER])
    order, problems = native_ctx['solver'].solve(
        root,
        build_install_items(
            native_ctx['packages'][CONFLICT_FILE0],
            native_ctx['packages'][CONFLICT_FILE1],
        ),
    )
    assert order == [0, 1]
    assert problems == [
        'file /usr/lib/conflict/conflicting-file from install of '
        f"{nevra_text(native_ctx['package_meta'][CONFLICT_FILE0])} "
        'conflicts with file from package '
        f"{nevra_text(native_ctx['package_meta'][CONFLICT_FILE1])}"
    ]


def test_file_conflict_against_installed_rpmdb_detected(native_ctx):
    root = create_root(native_ctx, 'file-conflict-installed', [SHELL_PROVIDER, CONFLICT_FILE0])
    order, problems = native_ctx['solver'].solve(
        root,
        build_install_items(native_ctx['packages'][CONFLICT_FILE1]),
    )
    assert order == [0]
    assert problems == [
        'file /usr/lib/conflict/conflicting-file from install of '
        f"{nevra_text(native_ctx['package_meta'][CONFLICT_FILE1])} "
        'conflicts with file from package '
        f"{nevra_text(native_ctx['package_meta'][CONFLICT_FILE0])}"
    ]


@pytest.mark.parametrize(
    'packages, expected_word',
    [
        ((DUMMY_CONFLICT0, DUMMY_CONFLICT1), ' conflicts '),
        ((OBSOLETED, OBSOLETING), ' obsoletes '),
    ],
)
def test_relation_conflicts_and_obsoletes_detected(native_ctx, packages, expected_word):
    root = create_root(native_ctx, 'relation-problems-' + '-'.join(packages), [SHELL_PROVIDER])
    order, problems = native_ctx['solver'].solve(
        root,
        build_install_items(*(native_ctx['packages'][name] for name in packages)),
    )
    assert order == [0, 1]
    assert len(problems) == 1
    assert expected_word in f' {problems[0]} '


def test_upgrade_orders_install_before_erase_same_name(native_ctx):
    root = create_root(native_ctx, 'upgrade-order', [SHELL_PROVIDER, MULTIVERSION_LOWER])
    order, problems = native_ctx['solver'].solve(
        root,
        build_install_items(native_ctx['packages'][MULTIVERSION_HIGHER]) +
        build_erase_items([native_ctx['package_meta'][MULTIVERSION_LOWER]]),
    )
    assert order == [0, 1]
    assert problems == []
