#
# Copyright (C) 2026 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

import ctypes
import os
import shutil
import sqlite3
import struct

import pytest


RPMTAG_VERSION = 1001
RPMTAG_PROVIDENAME = 1047
RPMTAG_PROVIDEFLAGS = 1112
RPMTAG_PROVIDEVERSION = 1113
RPM_STRING_TYPE = 6
RPM_INT32_TYPE = 4
RPM_STRING_ARRAY_TYPE = 8
RPMSENSE_EQUAL = 1 << 3

ERROR_TDNF_DISTROVERPKG_NO_PROVIDERS = 1022
ERROR_TDNF_DISTROVERPKG_READ_FAILED = 1023


def _string(value):
    return value.encode() + b'\0'


def _string_array(values):
    return b''.join(_string(value) for value in values)


def _int32_array(values):
    return b''.join(struct.pack('>I', value) for value in values)


def _header_blob(package_version, names, flags, versions):
    fields = [
        (RPMTAG_VERSION, RPM_STRING_TYPE, 1, _string(package_version)),
        (RPMTAG_PROVIDENAME, RPM_STRING_ARRAY_TYPE, len(names),
         _string_array(names)),
        (RPMTAG_PROVIDEFLAGS, RPM_INT32_TYPE, len(flags),
         _int32_array(flags)),
        (RPMTAG_PROVIDEVERSION, RPM_STRING_ARRAY_TYPE, len(versions),
         _string_array(versions)),
    ]
    indexes = []
    data = bytearray()
    for tag, field_type, count, value in fields:
        if field_type == RPM_INT32_TYPE:
            data.extend(b'\0' * (-len(data) % 4))
        indexes.append((tag, field_type, len(data), count))
        data.extend(value)
    prefix = struct.pack('>II', len(indexes), len(data))
    return prefix + b''.join(struct.pack('>IIII', *entry)
                             for entry in indexes) + data


def _create_rpmdb(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB)')
    db.execute('CREATE TABLE Providename(key TEXT, hnum INTEGER, idx INTEGER)')
    return db


def _insert_provider(db, hnum, package_version, names, flags, versions):
    blob = _header_blob(package_version, names, flags, versions)
    db.execute('INSERT INTO Packages(hnum, blob) VALUES (?, ?)',
               (hnum, blob))
    for index, name in enumerate(names):
        db.execute('INSERT INTO Providename(key, hnum, idx) VALUES (?, ?, ?)',
                   (name, hnum, index))


@pytest.fixture
def distrover_case(utils, monkeypatch, request):
    base = os.path.join(utils.config['build_dir'], 'distroverpkg-tests',
                        request.node.name)
    shutil.rmtree(base, ignore_errors=True)
    root = os.path.join(base, 'installroot')
    home = os.path.join(base, 'home')
    os.makedirs(home)
    with open(os.path.join(home, '.rpmmacros'), 'w') as macros:
        macros.write('%_dbbase /native\n')
        macros.write('%_dbpath %{_dbbase}/nested\n')
    monkeypatch.setenv('HOME', home)

    dbpath = os.path.join(root, 'native', 'nested', 'rpmdb.sqlite')
    yield root, dbpath
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture(scope='module')
def release_version_api(utils):
    library = ctypes.CDLL(os.path.join(utils.config['build_dir'], 'lib',
                                       'libtdnf.so'))
    library.TDNFGetReleaseVersion.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.TDNFGetReleaseVersion.restype = ctypes.c_uint32
    library.TDNFFreeMemory.argtypes = [ctypes.c_void_p]
    library.TDNFFreeMemory.restype = None

    def resolve(root, provide_name='test-distrover'):
        value = ctypes.c_void_p()
        result = library.TDNFGetReleaseVersion(
            root.encode(), provide_name.encode(), ctypes.byref(value))
        if not value.value:
            return result, None
        try:
            return result, ctypes.string_at(value).decode()
        finally:
            library.TDNFFreeMemory(value)

    return resolve


def test_package_version_fallback(distrover_case, release_version_api):
    root, dbpath = distrover_case
    with _create_rpmdb(dbpath) as db:
        _insert_provider(db, 1, '5.2', ['test-distrover'], [0], [''])
    assert release_version_api(root) == (0, '5.2')


def test_equal_provide_uses_parallel_evr(distrover_case,
                                         release_version_api):
    root, dbpath = distrover_case
    with _create_rpmdb(dbpath) as db:
        _insert_provider(
            db, 1, '1.0',
            ['other-provide', 'test-distrover'],
            [RPMSENSE_EQUAL, RPMSENSE_EQUAL],
            ['wrong-index', '9.4-2'])
    assert release_version_api(root) == (0, '9.4-2')


def test_non_equal_provide_uses_package_version(distrover_case,
                                                release_version_api):
    root, dbpath = distrover_case
    with _create_rpmdb(dbpath) as db:
        _insert_provider(db, 1, '7.1', ['test-distrover'], [1 << 2],
                         ['99'])
    assert release_version_api(root) == (0, '7.1')


def test_first_provider_is_lowest_hnum(distrover_case,
                                       release_version_api):
    root, dbpath = distrover_case
    with _create_rpmdb(dbpath) as db:
        _insert_provider(db, 20, 'later', ['test-distrover'],
                         [RPMSENSE_EQUAL], ['20'])
        _insert_provider(db, 10, 'first', ['test-distrover'], [0], [''])
    assert release_version_api(root) == (0, 'first')


def test_no_provider_returns_exact_error(distrover_case,
                                         release_version_api):
    root, dbpath = distrover_case
    with _create_rpmdb(dbpath):
        pass
    assert release_version_api(root) == (
        ERROR_TDNF_DISTROVERPKG_NO_PROVIDERS, None)


def test_malformed_header_returns_exact_error(distrover_case,
                                              release_version_api):
    root, dbpath = distrover_case
    with _create_rpmdb(dbpath) as db:
        db.execute('INSERT INTO Packages(hnum, blob) VALUES (1, ?)',
                   (b'\0',))
        db.execute(
            'INSERT INTO Providename(key, hnum, idx) VALUES (?, 1, 0)',
            ('test-distrover',))
    assert release_version_api(root) == (
        ERROR_TDNF_DISTROVERPKG_READ_FAILED, None)


def test_mismatched_provide_arrays_return_exact_error(
        distrover_case, release_version_api):
    root, dbpath = distrover_case
    with _create_rpmdb(dbpath) as db:
        _insert_provider(db, 1, '1.0', ['test-distrover'],
                         [RPMSENSE_EQUAL], ['1.0', 'extra'])
    assert release_version_api(root) == (
        ERROR_TDNF_DISTROVERPKG_READ_FAILED, None)
