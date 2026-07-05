#
# Copyright (C) 2026 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import glob
import json
import os
import sys

import pytest

PYTESTS_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if PYTESTS_DIR not in sys.path:
    sys.path.insert(0, PYTESTS_DIR)

from cli_testlib import MinimalCliRuntime  # noqa: E402

REPO_ROOT = os.path.dirname(PYTESTS_DIR)
FIXTURE_DIR = os.path.join(PYTESTS_DIR, 'fixtures', 'cli-golden')
FIXTURE_PATHS = sorted(glob.glob(os.path.join(FIXTURE_DIR, '*.json')))
BINDIR_ENV = 'TDNF_CLI_GOLDEN_BINDIR'

pytestmark = pytest.mark.skipif(
    not FIXTURE_PATHS,
    reason='CLI golden fixtures are missing',
)


def _resolve_bindir():
    candidates = [
        os.environ.get(BINDIR_ENV),
        os.path.join(REPO_ROOT, 'out', 'bin'),
        os.path.join(REPO_ROOT, 'zig-out', 'bin'),
    ]
    for candidate in candidates:
        if candidate and os.path.isdir(candidate):
            return os.path.abspath(candidate)
    return None


@pytest.fixture(scope='module')
def cli_runtime():
    bindir = _resolve_bindir()
    if bindir is None:
        pytest.skip('built tdnf bindir not found')

    runtime = MinimalCliRuntime(
        bindir,
        os.path.join(os.path.dirname(bindir), 'cli-golden-test-runtime'),
    )
    yield runtime
    runtime.cleanup()


def _fixture_id(path):
    return os.path.splitext(os.path.basename(path))[0]


@pytest.mark.parametrize('fixture_path', FIXTURE_PATHS, ids=_fixture_id)
def test_cli_golden(cli_runtime, fixture_path):
    with open(fixture_path) as handle:
        expected = json.load(handle)

    actual = cli_runtime.capture(expected['argv'])

    assert actual['stdout'] == expected['stdout']
    assert actual['stderr'] == expected['stderr']
    assert actual['retval'] == expected['retval']
