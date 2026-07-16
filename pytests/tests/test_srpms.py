#
# Copyright (C) 2019 - 2022 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import glob
import ctypes
import os
import platform
import pytest
import shutil
import subprocess

ARCH = platform.machine()

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
RPMBUILD_DIR = os.path.join(REPO_ROOT, 'out', 'srpm-extract')
SOURCE_BUILD_DIR = os.path.join(REPO_ROOT, 'out', 'srpm-build')


@pytest.fixture(scope='function', autouse=True)
def setup_test(utils):
    yield
    teardown_test(utils)


def teardown_test(utils):
    if (os.path.isdir(RPMBUILD_DIR)):
        shutil.rmtree(RPMBUILD_DIR)
    if (os.path.isdir(SOURCE_BUILD_DIR)):
        shutil.rmtree(SOURCE_BUILD_DIR)


def source_options(topdir=RPMBUILD_DIR):
    return ['--rpmdefine', '_topdir {}'.format(topdir)]


def build_source_rpm(name, nosrc=False, epoch=7):
    if os.path.isdir(SOURCE_BUILD_DIR):
        shutil.rmtree(SOURCE_BUILD_DIR)
    for directory in ['BUILD', 'BUILDROOT', 'RPMS', 'SRPMS',
                      'SOURCES', 'SPECS']:
        os.makedirs(os.path.join(SOURCE_BUILD_DIR, directory))

    source_name = '{}.source'.format(name)
    source_path = os.path.join(SOURCE_BUILD_DIR, 'SOURCES', source_name)
    with open(source_path, 'w', encoding='utf-8') as source:
        source.write('native source payload\n')

    spec_path = os.path.join(SOURCE_BUILD_DIR, 'SPECS', name + '.spec')
    no_source = 'NoSource: 0\n' if nosrc else ''
    with open(spec_path, 'w', encoding='utf-8') as spec:
        spec.write(
            'Name: {name}\n'
            'Version: 1.2\n'
            'Release: 3\n'
            'Epoch: {epoch}\n'
            'Summary: native source extraction test\n'
            'License: MIT\n'
            'Source0: {source}\n'
            '{no_source}'
            '\n'
            '%description\n'
            'native source extraction test\n'.format(
                name=name,
                epoch=epoch,
                source=source_name,
                no_source=no_source,
            )
        )
    subprocess.run([
        'rpmbuild',
        '-D', '_topdir {}'.format(SOURCE_BUILD_DIR),
        '-bs', spec_path,
    ], check=True, stdout=subprocess.DEVNULL)
    extension = '.nosrc.rpm' if nosrc else '.src.rpm'
    matches = glob.glob(os.path.join(
        SOURCE_BUILD_DIR, 'SRPMS', '*' + extension))
    assert len(matches) == 1
    return matches[0]


def get_pkg_file_path(utils, pkgname):
    dir = os.path.join(utils.config['repo_path'], 'photon-test', 'RPMS', ARCH)
    matches = glob.glob('{}/{}-*.rpm'.format(dir, pkgname))
    return matches[0]


def get_srcpkg_file_path(utils, pkgname):
    dir = os.path.join(utils.config['repo_path'], 'photon-test-src', 'SRPMS')
    matches = glob.glob('{}/{}-*.src.rpm'.format(dir, pkgname))
    return matches[0]


def test_install_srpm(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)

    ret = utils.run(
        ['tdnf', 'install', '--repoid=photon-test-src', '-y',
         '--source', '--nogpgcheck'] + source_options() + [pkgname])
    assert ret['retval'] == 0, '\n'.join(ret['stderr'])
    assert not utils.check_package(pkgname)  # source RPMs are never really installed

    assert len(glob.glob(os.path.join(RPMBUILD_DIR, 'SPECS', '*.spec'))) > 0
    utils.erase_package(pkgname)


def test_install_srpm_file_with_source_option(utils):
    pkgname = utils.config["sglversion_pkgname"]
    path = get_srcpkg_file_path(utils, pkgname)
    ret = utils.run(
        ['tdnf', 'install', '-y', '--source', '--nogpgcheck'] +
        source_options() + [path])
    assert ret['retval'] == 0, ret

    assert len(glob.glob(os.path.join(RPMBUILD_DIR, 'SPECS', '*.spec'))) > 0
    utils.erase_package(pkgname)


# test srpm install if binary is installed (issue #515)
def test_install_srpm_binary_isinstalled(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)

    ret = utils.run(['tdnf', 'install', '-y', '--nogpgcheck', pkgname])
    assert ret['retval'] == 0
    ret = utils.run(
        ['tdnf', 'install', '--repoid=photon-test-src', '-y',
         '--source', '--nogpgcheck'] + source_options() + [pkgname])
    assert ret['retval'] == 0

    assert len(glob.glob(os.path.join(RPMBUILD_DIR, 'SPECS', '*.spec'))) > 0
    utils.erase_package(pkgname)


# fail if trying to install an rpm with --source option
def test_install_rpm_file_with_source_option(utils):
    pkgname = utils.config["sglversion_pkgname"]
    path = get_pkg_file_path(utils, pkgname)
    ret = utils.run(['tdnf', 'install', '-y', '--source', '--nogpgcheck', path])
    assert ret['retval'] != 0
    utils.erase_package(pkgname)


# fail if trying to install an srpm without --source option
def test_install_srpm_file_without_source_option(utils):
    pkgname = utils.config["sglversion_pkgname"]
    path = get_srcpkg_file_path(utils, pkgname)
    ret = utils.run(['tdnf', 'install', '-y', '--nogpgcheck', path])
    assert ret['retval'] != 0
    utils.erase_package(pkgname)


@pytest.mark.parametrize('nosrc', [False, True])
def test_native_src_and_nosrc_extraction(utils, nosrc):
    name = 'tdnf-phase6-nosrc' if nosrc else 'tdnf-phase6-src'
    path = build_source_rpm(name, nosrc=nosrc)
    target = os.path.join(RPMBUILD_DIR, name)

    ret = utils.run(
        ['tdnf', 'install', '-y', '--source', '--nogpgcheck'] +
        source_options(target) + [path])
    assert ret['retval'] == 0, '\n'.join(ret['stderr'])
    specs = glob.glob(os.path.join(target, 'SPECS', '*.spec'))
    assert len(specs) == 1
    original_spec = os.path.join(SOURCE_BUILD_DIR, 'SPECS', name + '.spec')
    extracted_stat = os.stat(specs[0])
    original_stat = os.stat(original_spec)
    assert extracted_stat.st_mode & 0o7777 == original_stat.st_mode & 0o7777
    assert extracted_stat.st_uid == original_stat.st_uid
    assert extracted_stat.st_gid == original_stat.st_gid
    assert int(extracted_stat.st_mtime) == int(original_stat.st_mtime)
    sources = glob.glob(os.path.join(target, 'SOURCES', '*.source'))
    assert len(sources) == (0 if nosrc else 1)
    assert not utils.check_package(name)


def test_source_package_macro_scope_and_explicit_directories(utils):
    name = 'tdnf-phase6-macros'
    path = build_source_rpm(name, epoch=7)
    base = os.path.join(RPMBUILD_DIR, 'macros')
    topdir = os.path.join(
        base, '%{name}', '%{version}', '%{release}', '%{epoch}')
    options = [
        '--rpmdefine', '_topdir {}'.format(topdir),
        '--rpmdefine', '_specdir %{_topdir}/spec-custom',
        '--rpmdefine', '_sourcedir %{_topdir}/source-custom',
    ]

    ret = utils.run(
        ['tdnf', 'install', '-y', '--source', '--nogpgcheck'] +
        options + [path])
    assert ret['retval'] == 0
    expanded = os.path.join(base, name, '1.2', '3', '7')
    assert os.path.isfile(os.path.join(
        expanded, 'spec-custom', name + '.spec'))
    assert os.path.isfile(os.path.join(
        expanded, 'source-custom', name + '.source'))


def test_source_extraction_honors_installroot(utils):
    name = 'tdnf-phase6-installroot'
    path = build_source_rpm(name)
    installroot = os.path.join(RPMBUILD_DIR, 'installroot')
    os.makedirs(installroot)

    ret = utils.run([
        'tdnf', 'install', '-y', '--source', '--nogpgcheck',
        '--installroot', installroot,
        '--releasever=4.0',
        '--rpmdefine', '_topdir /phase6-build',
        path,
    ])
    assert ret['retval'] == 0, ret
    assert os.path.isfile(os.path.join(
        installroot, 'phase6-build', 'SPECS', name + '.spec'))
    assert os.path.isfile(os.path.join(
        installroot, 'phase6-build', 'SOURCES', name + '.source'))


def test_source_justdb_suppresses_extraction(utils):
    name = 'tdnf-phase6-justdb'
    path = build_source_rpm(name)
    target = os.path.join(RPMBUILD_DIR, 'justdb')

    ret = utils.run(
        ['tdnf', 'install', '-y', '--source', '--nogpgcheck',
         '--setopt=tsflags=justdb'] + source_options(target) + [path])
    assert ret['retval'] == 0
    assert not os.path.exists(target)
    assert not utils.check_package(name)


@pytest.mark.parametrize(
    'tsflags,extracted',
    [
        (None, True),
        ('justdb', False),
    ],
)
def test_source_only_zero_binary_transaction_succeeds(
        utils, tsflags, extracted):
    suffix = tsflags or 'normal'
    name = 'tdnf-phase7-source-only-' + suffix
    path = build_source_rpm(name)
    installroot = os.path.join(RPMBUILD_DIR, 'root-' + suffix)
    os.makedirs(installroot)
    target = '/phase7-source'
    command = [
        'tdnf', 'install', '-y', '--source', '--nogpgcheck',
        '--installroot', installroot, '--releasever=4.0',
    ]
    if tsflags:
        command.append('--setopt=tsflags=' + tsflags)
    command += source_options(target) + [path]

    ret = utils.run(command)

    assert ret['retval'] == 0, '\n'.join(ret['stderr'])
    assert not any(
        'rpmzig-transaction' in line or 'Error(' in line
        for line in ret['stderr']
    )
    spec_path = os.path.join(
        installroot, target.lstrip('/'), 'SPECS', name + '.spec'
    )
    assert os.path.isfile(spec_path) is extracted
    assert not utils.check_package(name)


def test_source_extraction_uses_retained_handle_after_path_replaced(utils):
    name = 'tdnf-phase6-retained'
    path = build_source_rpm(name)
    target = os.path.join(RPMBUILD_DIR, 'retained')
    library = ctypes.CDLL(os.path.join(REPO_ROOT, 'out', 'lib', 'libtdnf.so'))
    library.tdnf_rpm_file_open.argtypes = [ctypes.c_char_p]
    library.tdnf_rpm_file_open.restype = ctypes.c_void_p
    library.tdnf_rpm_file_close.argtypes = [ctypes.c_void_p]
    library.tdnf_rpm_config_create.argtypes = [ctypes.c_char_p]
    library.tdnf_rpm_config_create.restype = ctypes.c_void_p
    library.tdnf_rpm_config_destroy.argtypes = [ctypes.c_void_p]
    library.tdnf_rpm_config_apply_define.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    library.tdnf_rpm_file_extract_source_config.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]

    handle = library.tdnf_rpm_file_open(os.fsencode(path))
    assert handle
    config = library.tdnf_rpm_config_create(b'/')
    assert config
    try:
        define = '_topdir {}'.format(target).encode()
        assert library.tdnf_rpm_config_apply_define(config, define) == 0
        os.replace(path, path + '.verified')
        with open(path, 'wb') as replacement:
            replacement.write(b'not an rpm')

        assert library.tdnf_rpm_file_extract_source_config(
            handle, config, 0) == 0
        assert os.path.isfile(os.path.join(
            target, 'SPECS', name + '.spec'))
        assert os.path.isfile(os.path.join(
            target, 'SOURCES', name + '.source'))
    finally:
        library.tdnf_rpm_config_destroy(config)
        library.tdnf_rpm_file_close(handle)
