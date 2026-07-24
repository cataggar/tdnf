#
# Copyright (C) 2019 - 2022 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import os
import shutil

import pytest

PKGNAME_OBSED_VER = "tdnf-test-dummy-obsoleted=0.1"
PKGNAME_OBSED = "tdnf-test-dummy-obsoleted"
PKGNAME_OBSING = "tdnf-test-dummy-obsoleting"


@pytest.fixture(scope='module', autouse=True)
def setup_test(utils):
    yield
    teardown_test(utils)


def teardown_test(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.run(f"tdnf remove -y {pkgname} {PKGNAME_OBSED} {PKGNAME_OBSING}")


def test_install_no_arg(utils):
    ret = utils.run(['tdnf', 'install'])
    assert ret['retval'] == 1001


def test_install_invalid_arg(utils):
    ret = utils.run(['tdnf', 'install', 'invalid_package'])
    assert ret['retval'] == 1011


def test_install_package_with_version_suffix(utils):
    pkgname = utils.config["mulversion_pkgname"]
    pkgversion = utils.config["mulversion_lower"]
    utils.erase_package(pkgname)

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', pkgname + '-' + pkgversion])
    assert utils.check_package(pkgname)


def test_install_package_without_version_suffix(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', pkgname])
    assert utils.check_package(pkgname)


# -v (verbose) prints progress data
def test_install_package_verbose(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)
    utils.run(['tdnf', 'install', '-y', '-v', '--nogpgcheck', pkgname])
    assert utils.check_package(pkgname)


def test_dummy_requires(utils):
    pkg = utils.config["dummy_requires_pkgname"]
    ret = utils.run(['tdnf', 'install', '-y', pkg])
    assert ' nothing provides ' in ret['stderr'][0]


def test_install_testonly(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', '--testonly', pkgname])
    assert not utils.check_package(pkgname)


def test_install_debugsolver_native_shadow(utils):
    pkgname = utils.config["mulversion_pkgname"]
    pkgversion = utils.config["mulversion_lower"]
    pkghigher = utils.config["mulversion_higher"]
    hidden_installed = utils.config["sglversion_pkgname"]
    alldeps_pkg = 'tdnf-test-cleanreq-leaf1'
    alldeps_required = 'tdnf-test-cleanreq-required'
    conflict0 = 'tdnf-test-dummy-conflicts-0'
    conflict1 = 'tdnf-test-dummy-conflicts-1'
    protected_dir = os.path.join(utils.config['repo_path'], 'protected.d')
    locks_dir = os.path.join(utils.config['repo_path'], 'locks.d')
    utils.erase_package(pkgname)
    utils.erase_package(hidden_installed)
    utils.erase_package(alldeps_pkg)
    utils.erase_package(alldeps_required)
    utils.erase_package(conflict0)
    utils.erase_package(conflict1)
    utils.erase_package(PKGNAME_OBSED)
    utils.erase_package(PKGNAME_OBSING)
    utils.install_package(hidden_installed)

    try:
        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--skip-broken', pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert not utils.check_package(pkgname)
        shutil.rmtree('debugdata', ignore_errors=True)

        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', '--allowerasing', pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert not utils.check_package(pkgname)
        shutil.rmtree('debugdata', ignore_errors=True)

        utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck',
            '{}-{}'.format(pkgname, pkgversion),
        ])
        ret = utils.run([
            'tdnf', 'upgrade', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: unavailable' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(pkgname, version=pkgversion)
        shutil.rmtree('debugdata', ignore_errors=True)
        utils.erase_package(pkgname)

        utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck',
            '{}-{}'.format(pkgname, pkgversion),
        ])
        os.makedirs(locks_dir, exist_ok=True)
        with open(os.path.join(locks_dir, 'native-shadow.conf'), 'w') as f:
            f.write(pkgname)
        ret = utils.run([
            'tdnf', 'upgrade', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove',
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: unavailable' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(pkgname, version=pkgversion)

        with open(os.path.join(locks_dir, 'native-shadow.conf'), 'w') as f:
            f.write(hidden_installed)
        utils.erase_package(pkgname)
        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', '--best', pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: unavailable' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert not utils.check_package(pkgname)
        assert utils.check_package(hidden_installed)

        utils.install_package(pkgname)
        with open(os.path.join(locks_dir, 'native-shadow.conf'), 'w') as f:
            f.write('{}\nmissing-native-lock'.format(hidden_installed))
        ret = utils.run([
            'tdnf', 'erase', '-y', '--testonly', '--debugsolver',
            '--noautoremove', pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: unavailable' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(pkgname)
        assert utils.check_package(hidden_installed)
        shutil.rmtree(locks_dir)
        shutil.rmtree('debugdata', ignore_errors=True)
        utils.erase_package(pkgname)

        utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck',
            '{}-{}'.format(pkgname, pkgversion),
        ])
        ret = utils.run([
            'tdnf', 'upgrade', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove',
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: unavailable' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(pkgname, version=pkgversion)
        shutil.rmtree('debugdata', ignore_errors=True)
        utils.erase_package(pkgname)

        utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck',
            '{}-{}'.format(pkgname, pkgversion),
        ])
        ret = utils.run([
            'tdnf', 'distro-sync', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove',
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: unavailable' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(pkgname, version=pkgversion)
        shutil.rmtree('debugdata', ignore_errors=True)
        utils.erase_package(pkgname)

        utils.install_package(pkgname)
        ret = utils.run([
            'tdnf', 'downgrade', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: unavailable' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(pkgname, version=pkghigher)
        shutil.rmtree('debugdata', ignore_errors=True)
        utils.erase_package(pkgname)

        utils.install_package(conflict0)
        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', '--allowerasing', conflict1,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: unavailable' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: projected match' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(conflict0)
        assert not utils.check_package(conflict1)
        shutil.rmtree('debugdata', ignore_errors=True)

        utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', PKGNAME_OBSED_VER,
        ])
        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', '--allowerasing',
            PKGNAME_OBSING,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: unavailable' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: projected match' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(PKGNAME_OBSED)
        assert not utils.check_package(PKGNAME_OBSING)
        shutil.rmtree('debugdata', ignore_errors=True)

        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', PKGNAME_OBSING,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert 'native-solver-shadow: unavailable' not in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(PKGNAME_OBSED)
        assert not utils.check_package(PKGNAME_OBSING)
        shutil.rmtree('debugdata', ignore_errors=True)

        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', '--skip-broken',
            pkgname, 'missing',
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: unavailable' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert not utils.check_package(pkgname)
        shutil.rmtree('debugdata', ignore_errors=True)

        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', '--skip-broken',
            pkgname, 'tdnf-missing-dep',
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: unavailable' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert not utils.check_package(pkgname)
        shutil.rmtree('debugdata', ignore_errors=True)

        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', '--best', pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert not utils.check_package(pkgname)
        shutil.rmtree('debugdata', ignore_errors=True)

        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove',
            '--exclude={}'.format(hidden_installed), pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert not utils.check_package(pkgname)
        assert utils.check_package(hidden_installed)
        shutil.rmtree('debugdata', ignore_errors=True)

        ret = utils.run([
            'tdnf', 'reinstall', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', hidden_installed,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(hidden_installed)
        shutil.rmtree('debugdata', ignore_errors=True)

        ret = utils.run([
            'tdnf', 'erase', '-y', '--testonly', '--debugsolver',
            '--noautoremove', hidden_installed,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(hidden_installed)
        shutil.rmtree('debugdata', ignore_errors=True)

        os.makedirs(protected_dir, exist_ok=True)
        with open(os.path.join(protected_dir, 'native-shadow.conf'), 'w') as f:
            f.write(hidden_installed)
        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--testonly',
            '--debugsolver', '--noautoremove', pkgname,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert utils.check_package(hidden_installed)
        shutil.rmtree(protected_dir)
        shutil.rmtree('debugdata', ignore_errors=True)

        utils.install_package(alldeps_required)
        ret = utils.run([
            'tdnf', 'install', '-y', '--nogpgcheck', '--urls',
            '--debugsolver', '--noautoremove', '--alldeps', alldeps_pkg,
        ])
        assert ret['retval'] == 0
        assert 'native-solver-shadow: projected match' in \
            '\n'.join(ret['stdout'] + ret['stderr'])
        assert any(alldeps_required in line for line in ret['stdout'])
        assert not utils.check_package(alldeps_pkg)
    finally:
        shutil.rmtree(protected_dir, ignore_errors=True)
        shutil.rmtree(locks_dir, ignore_errors=True)
        shutil.rmtree('debugdata', ignore_errors=True)
        utils.erase_package(alldeps_pkg)
        utils.erase_package(alldeps_required)
        utils.erase_package(conflict0)
        utils.erase_package(conflict1)
        utils.erase_package(PKGNAME_OBSED)
        utils.erase_package(PKGNAME_OBSING)
        utils.erase_package(pkgname)
        utils.erase_package(hidden_installed)


# install multiple packages, one that doesn't exist
# expect other pkg will be installed if invoked with --skip-broken
def test_install_skip_broken_missing_pkg(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)
    pkgname_missing = "missing"

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', '--skip-broken', pkgname, pkgname_missing])
    assert utils.check_package(pkgname)


# install multiple packages, one that doesn't exist
# expect fail if invoked without --skip-broken
def test_install_missing_pkg(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)
    pkgname_missing = "missing"

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', pkgname, pkgname_missing])
    assert not utils.check_package(pkgname)


# install multiple packages, one with a missing dependency
# expect other pkg will be installed if invoked with --skip-broken
def test_install_skip_broken_missing_dep(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)
    pkgname_missing = "tdnf-missing-dep"

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', '--skip-broken', pkgname, pkgname_missing])
    assert utils.check_package(pkgname)


# install multiple packages, one with a missing dependency
# expect fail if invoked without --skip-broken
def test_install_missing_dep(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)
    pkgname_missing = "tdnf-missing-dep"

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', pkgname, pkgname_missing])
    assert not utils.check_package(pkgname)


# install an obsoleting package, expect the obsoleted package to be removed
def test_install_obsoleting(utils):
    utils.erase_package(PKGNAME_OBSING)
    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', PKGNAME_OBSED_VER])
    assert utils.check_package(PKGNAME_OBSED)

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', PKGNAME_OBSING])
    assert not utils.check_package(PKGNAME_OBSED)


# install an obsoleted package, expect the obsoleting package to be installed
# the obsoleting package must also provide the obsoleted one
def test_install_obsoletes(utils):
    utils.erase_package(PKGNAME_OBSED)
    utils.erase_package(PKGNAME_OBSING)

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', PKGNAME_OBSED])
    assert utils.check_package(PKGNAME_OBSING)


# install an obsoleted package with version - expect the obsoleted package to be installed
def test_install_obsoleted_version(utils):
    utils.erase_package(PKGNAME_OBSED_VER)
    utils.erase_package(PKGNAME_OBSING)

    ret = utils.run(['tdnf', 'install', '-y', '--nogpgcheck', PKGNAME_OBSED_VER])
    print(ret)
    assert utils.check_package(PKGNAME_OBSED)


# same as test_install_obsoletes, but the obsoleted package already installed
def test_install_obsoleted_installed(utils):
    # make sure we install the obsoleted one by using version
    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', PKGNAME_OBSED_VER])
    utils.erase_package(PKGNAME_OBSING)

    utils.run(['tdnf', 'install', '-y', '--nogpgcheck', PKGNAME_OBSED])
    assert utils.check_package(PKGNAME_OBSING)


# install a package with non-existing requirement, expect fail
def test_install_no_providers(utils):
    pkgname = utils.config['dummy_requires_pkgname']
    ret = utils.run(['tdnf', 'install', '-y', '--nogpgcheck', pkgname])
    # ERROR_TDNF_SOLV_FAILED - "Solv general runtime error"
    assert ret['retval'] == 1301
    assert "nothing provides" in '\n'.join(ret['stderr'])


def xxx_test_install_memcheck(utils):
    pkgname = utils.config["mulversion_pkgname"]
    utils.erase_package(pkgname)

    utils.run_memcheck(['tdnf', 'install', '-y', '--nogpgcheck', pkgname])
    assert utils.check_package(pkgname)
