import configparser
import os
import subprocess
import time


def test_session_repository_is_isolated(utils):
    marker = os.environ.get('TDNF_SESSION_MARKER', str(os.getpid()))
    repo_path = os.path.realpath(utils.config['repo_path'])
    seed_path = os.path.realpath(utils.config['repo_seed_path'])

    assert repo_path != seed_path
    assert repo_path.startswith(
        os.path.realpath(os.path.join(
            utils.config['build_dir'],
            'pytest-sessions',
        )) + os.sep
    )

    utils.edit_config({'session_marker': marker})
    time.sleep(2)

    session_config = configparser.ConfigParser()
    session_config.read(os.path.join(repo_path, 'tdnf.conf'))
    assert session_config['main']['session_marker'] == marker

    seed_config = configparser.ConfigParser()
    seed_config.read(os.path.join(seed_path, 'tdnf.conf'))
    assert 'session_marker' not in seed_config['main']


def test_setup_repo_preserves_caller_rpmmacros(utils, monkeypatch):
    home = os.path.join(utils.config['repo_path'], 'sentinel-home')
    os.makedirs(home)
    macros = os.path.join(home, '.rpmmacros')
    sentinel = b'caller-owned rpm macros\n%sentinel unchanged\n'
    with open(macros, 'wb') as stream:
        stream.write(sentinel)
    monkeypatch.setenv('HOME', home)

    subprocess.run(
        [
            'bash',
            os.path.join(
                utils.config['test_path'],
                'repo',
                'setup-repo.sh',
            ),
            utils.config['repo_path'],
            utils.config['specs_dir'],
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    with open(macros, 'rb') as stream:
        assert stream.read() == sentinel


def test_testutils_instances_share_session_repository(utils):
    second = type(utils)()
    assert second.config['repo_path'] == utils.config['repo_path']
    assert second.config['repo_seed_path'] == utils.config['repo_seed_path']
