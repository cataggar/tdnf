#
# Copyright (C) 2023 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import os
import shutil
import pytest


INSTALLROOT = '/root/installroot'
REPOFILENAME = 'photon-test.repo'


@pytest.fixture(scope='function', autouse=True)
def setup_test(utils):
    cleanup_installroot()
    yield
    cleanup_installroot()


def cleanup_installroot():
    if os.path.islink(INSTALLROOT) or (
        os.path.lexists(INSTALLROOT) and not os.path.isdir(INSTALLROOT)
    ):
        os.unlink(INSTALLROOT)
    elif os.path.isdir(INSTALLROOT):
        shutil.rmtree(INSTALLROOT)


def run_install(utils, pkgname, dbpath, define_args):
    ret = utils.run(['tdnf', 'install',
                     '-y', '--nogpgcheck',
                     '--installroot', INSTALLROOT,
                     '--releasever=5.0',
                     '--disablerepo=*',
                     '--enablerepo=photon-test-unsigned'] +
                    define_args + [pkgname])
    assert ret['retval'] == 0
    assert os.path.isdir(os.path.join(INSTALLROOT, dbpath.lstrip("/")))
    assert os.path.isfile(os.path.join(INSTALLROOT, dbpath.lstrip("/"), "rpmdb.sqlite"))

    ret = utils.run(['tdnf', 'list', 'installed',
                     '--installroot', INSTALLROOT,
                     '--releasever=5.0'] + define_args)
    assert ret['retval'] == 0
    assert any(pkgname in line for line in ret['stdout'])


@pytest.mark.parametrize("dbpath", ["/usr/lib/rpm", "/usr/lib/sysimage/rpm/"])
def test_install(utils, dbpath):
    pkgname = utils.config["mulversion_pkgname"]
    run_install(utils, pkgname, dbpath, ['--rpmdefine', f"_dbpath {dbpath}"])
    shutil.rmtree(INSTALLROOT)

    run_install(
        utils, pkgname, dbpath,
        [f'--setopt=rpmdefine=_dbpath={dbpath}'])


def test_install_recursive_dbpath(utils):
    pkgname = utils.config["mulversion_pkgname"]
    dbpath = "/usr/lib/rpm-native"
    run_install(
        utils,
        pkgname,
        dbpath,
        [
            '--rpmdefine', '_dbbase /usr/lib',
            '--rpmdefine', '_dbpath %{_dbbase}/rpm-native',
        ],
    )
