#
# Copyright (C) 2022 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import fcntl
import time
import pytest
from threading import Thread
from subprocess import Popen, PIPE

proc = None
t1_started = False
t2_started = False
t3_started = False

t1_failed = False
t2_failed = False
t3_failed = False
t2_waited = False
t3_waited = False

expected_str = 'WARNING: failed to acquire lock on: /var/run/.tdnf-instance-lockfile, retrying ...'
LOCKFILE = '/var/run/.tdnf-instance-lockfile'


def wait_for_transaction_lock():
    for _ in range(600):
        with open(LOCKFILE, 'a+') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock, fcntl.LOCK_UN)
            except BlockingIOError:
                return
        time.sleep(0.1)
    pytest.fail('install command did not acquire the transaction lock')


@pytest.fixture(scope='module', autouse=True)
def setup_test(utils):
    yield
    teardown_test(utils)


def teardown_test(utils):
    pkgname = utils.config["sglversion_pkgname"]
    utils.run(['tdnf', 'erase', '-y', pkgname])


def run_tdnf_blocking_cmd(utils, pkgname):
    try:
        cmd = ['tdnf', 'install', pkgname]
        utils._decorate_tdnf_cmd_for_test(cmd)
        print(cmd)
        global t1_started
        global proc
        proc = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE)
        t1_started = True
        proc.wait()
        out, err = proc.communicate()
        out = out.decode().strip().split('\n')
        err = err.decode().strip().split('\n')
        print('\n\n\n', out, err)
        assert 'Installing:' in out
    except Exception:
        global t1_failed
        t1_failed = True


def run_tdnf_search_cmd(utils, pkgname):
    cmd = ['tdnf', 'search', pkgname]
    utils._decorate_tdnf_cmd_for_test(cmd)
    global t2_started
    t2_started = True
    ret = utils.run(cmd)  # this gets blocked till install finishes
    try:
        global t2_waited
        t2_waited = expected_str in ret['stderr']
        assert 'tdnf-test-one : basic install test file.' in ret['stdout']
    except Exception:
        global t2_failed
        t2_failed = True


def run_tdnf_info_cmd(utils, pkgname):
    cmd = ['tdnf', 'info', pkgname]
    utils._decorate_tdnf_cmd_for_test(cmd)
    global t3_started
    t3_started = True
    ret = utils.run(cmd)  # this gets blocked till install finishes
    print(ret['stdout'])
    try:
        global t3_waited
        t3_waited = expected_str in ret['stderr']
        assert 'Name          : tdnf-test-one' in ret['stdout']
    except Exception:
        global t3_failed
        t3_failed = True


def test_lock_basic(utils):
    pkgname = utils.config["sglversion_pkgname"]
    utils.run(['tdnf', 'erase', '-y', pkgname])

    t2 = Thread(target=run_tdnf_search_cmd, args=(utils, pkgname, ))
    t3 = Thread(target=run_tdnf_info_cmd, args=(utils, pkgname, ))

    with open(LOCKFILE, 'a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        t2.start()
        t3.start()
        while not t2_started or not t3_started:
            time.sleep(0.1)
        time.sleep(1)
        assert t2.is_alive() and t3.is_alive()
        fcntl.flock(lock, fcntl.LOCK_UN)

    t2.join()
    t3.join()

    assert not t2_failed and not t3_failed
    assert t2_waited and t3_waited
