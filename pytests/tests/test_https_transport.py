#
# Copyright (C) 2026 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import base64
import glob
import http.client
import os
import shutil
import socket
import time

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.server import SimpleHTTPRequestHandler
from multiprocessing import Process
from urllib.parse import urlsplit

import pytest

from conftest import TestRepoServer

SERVER_HOST = '127.0.0.1'
HTTPS_HOST = 'localhost'
HTTPS_REPO_SUBDIR = 'photon-test'
PROXY_USERNAME = 'proxy-user'
PROXY_PASSWORD = 'proxy-pass'
TIMEOUT_ERROR = 1710

PYTESTS_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
REPO_ROOT = os.path.dirname(PYTESTS_DIR)
DOWNLOAD_FIXTURE_DIR = os.path.join(
    REPO_ROOT,
    'client',
    'download',
    'fixtures',
)
CA_CERT_PATH = os.path.join(DOWNLOAD_FIXTURE_DIR, 'ca-cert.pem')
SERVER_CERT_PATH = os.path.join(DOWNLOAD_FIXTURE_DIR, 'server-cert.pem')
SERVER_KEY_PATH = os.path.join(DOWNLOAD_FIXTURE_DIR, 'server-key.pem')
CLIENT_CERT_PATH = os.path.join(DOWNLOAD_FIXTURE_DIR, 'client-cert.pem')
CLIENT_KEY_PATH = os.path.join(DOWNLOAD_FIXTURE_DIR, 'client-key.pem')

REPO_NAMES = (
    'https-custom-ca',
    'https-insecure',
    'https-mtls',
    'http-proxy',
    'slow-timeout',
    'slow-throttle',
)


def repo_file_path(utils, repo_name):
    return os.path.join(
        utils.config['repo_path'],
        'yum.repos.d',
        repo_name + '.repo',
    )


def repo_cache_dir(utils, repo_name):
    return os.path.join(
        utils.tdnf_config.get('main', 'cachedir'),
        repo_name,
    )


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((SERVER_HOST, 0))
        return sock.getsockname()[1]


def wait_for_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex((SERVER_HOST, port)) == 0:
                return
        time.sleep(0.1)
    raise AssertionError(f'server on port {port} failed to start')


@contextmanager
def running_process(target, *args, port, **kwargs):
    kwargs = dict(kwargs)
    kwargs['port'] = port
    server = Process(target=target, args=args, kwargs=kwargs)
    server.start()
    try:
        wait_for_port(port)
        yield
    finally:
        server.terminate()
        server.join()


def reset_global_transport_config(utils):
    utils.edit_config({
        'proxy': None,
        'proxy_username': None,
        'proxy_password': None,
        'connect_timeout': None,
        'sslverify': None,
    })


def clear_repo_state(utils, repo_name):
    repofile = repo_file_path(utils, repo_name)
    if os.path.isfile(repofile):
        os.remove(repofile)
    shutil.rmtree(repo_cache_dir(utils, repo_name), ignore_errors=True)


def configure_repo(utils, repo_name, baseurl, extra=None):
    clear_repo_state(utils, repo_name)
    utils.create_repoconf(repo_file_path(utils, repo_name), baseurl, repo_name)
    changes = {'metadata_expire': '0'}
    if extra:
        changes.update(extra)
    utils.edit_config(changes, repo=repo_name)


def makecache(utils, repo_name, workdir):
    return utils.run([
        'tdnf',
        '--disablerepo=*',
        f'--enablerepo={repo_name}',
        'makecache',
    ], cwd=workdir)


def downloadonly(utils, repo_name, workdir, package_name, downloaddir):
    return utils.run([
        'tdnf',
        'install',
        '-y',
        '--nogpgcheck',
        '--downloadonly',
        '--downloaddir',
        downloaddir,
        '--disablerepo=*',
        f'--enablerepo={repo_name}',
        package_name,
    ], cwd=workdir)


def repodata_download_size(utils):
    repodata_dir = os.path.join(
        utils.config['repo_path'],
        HTTPS_REPO_SUBDIR,
        'repodata',
    )
    total = 0
    for pattern in (
            'repomd.xml',
            '*primary.xml.zst',
            '*filelists.xml.zst',
            '*other.xml.zst'):
        for path in glob.glob(os.path.join(repodata_dir, pattern)):
            total += os.path.getsize(path)
    return total


def AuthProxyServer(
        port,
        interface='',
        upstream_host=SERVER_HOST,
        upstream_port=8080,
        username=PROXY_USERNAME,
        proxy_pass=PROXY_PASSWORD):
    expected = 'Basic ' + base64.b64encode(
        f'{username}:{proxy_pass}'.encode('utf-8')
    ).decode('ascii')

    class AuthProxyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get('Proxy-Authorization') != expected:
                self.send_response(407, 'Proxy Authentication Required')
                self.send_header('Proxy-Authenticate', 'Basic realm="tdnf-test"')
                self.end_headers()
                return

            parsed = urlsplit(self.path)
            path = parsed.path or '/'
            if parsed.query:
                path = f'{path}?{parsed.query}'

            conn = http.client.HTTPConnection(
                upstream_host,
                upstream_port,
                timeout=5.0,
            )
            try:
                conn.request('GET', path)
                response = conn.getresponse()
                status = response.status
                reason = response.reason
                headers = response.getheaders()
                body = response.read()
            finally:
                conn.close()

            self.send_response(status, reason)
            for header, value in headers:
                if header.lower() in {'connection', 'transfer-encoding'}:
                    continue
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    httpd = HTTPServer((interface, port), AuthProxyHandler)
    httpd.serve_forever()


def SlowRepoServer(
        root,
        port,
        interface='',
        chunk_size=256,
        chunk_delay=0.0,
        initial_delay=0.0):
    os.chdir(root)

    class SlowRepoHandler(SimpleHTTPRequestHandler):
        def copyfile(self, source, outputfile):
            if initial_delay:
                time.sleep(initial_delay)
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    break
                outputfile.write(chunk)
                outputfile.flush()
                if chunk_delay:
                    time.sleep(chunk_delay)

        def log_message(self, fmt, *args):
            return

    httpd = HTTPServer((interface, port), SlowRepoHandler)
    httpd.serve_forever()


@pytest.fixture(scope='function', autouse=True)
def setup_case(utils):
    workroot = os.path.join(utils.config['build_dir'], 'https-transport-tests')
    shutil.rmtree(workroot, ignore_errors=True)
    os.makedirs(workroot, exist_ok=True)
    reset_global_transport_config(utils)
    yield workroot
    reset_global_transport_config(utils)
    shutil.rmtree(workroot, ignore_errors=True)
    for repo_name in REPO_NAMES:
        clear_repo_state(utils, repo_name)


def test_makecache_https_with_custom_ca(utils, setup_case):
    repo_name = 'https-custom-ca'
    workdir = os.path.join(setup_case, repo_name)
    os.makedirs(workdir, exist_ok=True)

    port = reserve_port()
    certfile = os.path.join(workdir, 'selfsigned-cert.pem')
    keyfile = os.path.join(workdir, 'selfsigned-key.pem')

    with running_process(
            TestRepoServer,
            utils.config['repo_path'],
            port=port,
            interface='',
            enable_https=True,
            certfile=certfile,
            keyfile=keyfile):
        configure_repo(
            utils,
            repo_name,
            f'https://{HTTPS_HOST}:{port}/{HTTPS_REPO_SUBDIR}',
            {'sslcacert': certfile},
        )
        ret = makecache(utils, repo_name, workdir)

    assert ret['retval'] == 0
    assert os.path.isfile(certfile)


def test_makecache_https_with_sslverify_disabled(utils, setup_case):
    repo_name = 'https-insecure'
    workdir = os.path.join(setup_case, repo_name)
    os.makedirs(workdir, exist_ok=True)

    port = reserve_port()
    certfile = os.path.join(workdir, 'selfsigned-cert.pem')
    keyfile = os.path.join(workdir, 'selfsigned-key.pem')

    with running_process(
            TestRepoServer,
            utils.config['repo_path'],
            port=port,
            interface='',
            enable_https=True,
            certfile=certfile,
            keyfile=keyfile):
        configure_repo(
            utils,
            repo_name,
            f'https://{HTTPS_HOST}:{port}/{HTTPS_REPO_SUBDIR}',
            {'sslverify': '0'},
        )
        ret = makecache(utils, repo_name, workdir)

    assert ret['retval'] == 0


def test_makecache_https_with_mutual_tls(utils, setup_case):
    repo_name = 'https-mtls'
    workdir = os.path.join(setup_case, repo_name)
    os.makedirs(workdir, exist_ok=True)

    port = reserve_port()

    with running_process(
            TestRepoServer,
            utils.config['repo_path'],
            port=port,
            interface='',
            enable_https=True,
            certfile=SERVER_CERT_PATH,
            keyfile=SERVER_KEY_PATH,
            require_client_cert=True,
            client_ca_cert=CA_CERT_PATH):
        configure_repo(
            utils,
            repo_name,
            f'https://{HTTPS_HOST}:{port}/{HTTPS_REPO_SUBDIR}',
            {
                'sslcacert': CA_CERT_PATH,
                'sslclientcert': CLIENT_CERT_PATH,
                'sslclientkey': CLIENT_KEY_PATH,
            },
        )
        ret = makecache(utils, repo_name, workdir)

    assert ret['retval'] == 0


def test_makecache_with_authenticated_proxy(utils, setup_case):
    repo_name = 'http-proxy'
    workdir = os.path.join(setup_case, repo_name)
    os.makedirs(workdir, exist_ok=True)

    upstream_port = reserve_port()
    proxy_port = reserve_port()
    with running_process(
            TestRepoServer,
            utils.config['repo_path'],
            port=upstream_port,
            interface=SERVER_HOST):
        with running_process(
                AuthProxyServer,
                port=proxy_port,
                interface=SERVER_HOST,
                upstream_host=SERVER_HOST,
                upstream_port=upstream_port):
            configure_repo(
                utils,
                repo_name,
                'http://proxy-target.invalid/photon-test',
            )
            utils.edit_config({
                'proxy': f'http://{SERVER_HOST}:{proxy_port}',
                'proxy_username': PROXY_USERNAME,
                'proxy_password': PROXY_PASSWORD,
            })
            ret = makecache(utils, repo_name, workdir)

    assert ret['retval'] == 0


def test_download_timeout_with_minrate(utils, setup_case):
    repo_name = 'slow-timeout'
    workdir = os.path.join(setup_case, repo_name)
    os.makedirs(workdir, exist_ok=True)

    port = reserve_port()

    with running_process(
            SlowRepoServer,
            utils.config['repo_path'],
            port=port,
            interface=SERVER_HOST,
            chunk_size=256,
            chunk_delay=1.0):
        configure_repo(
            utils,
            repo_name,
            f'http://{SERVER_HOST}:{port}/{HTTPS_REPO_SUBDIR}',
            {
                'timeout': '3',
                'minrate': '65536',
            },
        )
        ret = makecache(utils, repo_name, workdir)

    assert ret['retval'] == TIMEOUT_ERROR
    assert 'connection timed out' in '\n'.join(ret['stderr']).lower()


def test_download_throttle_limits_speed(utils, setup_case):
    repo_name = 'slow-throttle'
    workdir = os.path.join(setup_case, repo_name)
    os.makedirs(workdir, exist_ok=True)

    port = reserve_port()
    total_bytes = repodata_download_size(utils)
    throttle_bytes_per_sec = 2048

    with running_process(
            SlowRepoServer,
            utils.config['repo_path'],
            port=port,
            interface=SERVER_HOST):
        configure_repo(
            utils,
            repo_name,
            f'http://{SERVER_HOST}:{port}/{HTTPS_REPO_SUBDIR}',
            {'throttle': str(throttle_bytes_per_sec)},
        )
        start = time.monotonic()
        ret = makecache(utils, repo_name, workdir)
        elapsed = time.monotonic() - start

    assert ret['retval'] == 0
    assert elapsed >= (total_bytes / throttle_bytes_per_sec) * 0.75
