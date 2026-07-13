# rpmzig sqlite rpmdb write notes

Issue #110 adds a native write path for the rpm ≥ 6 sqlite rpmdb
backend. This document records the compatibility facts the write path
must match.

## What was verified

- Live host check:
  - `rpm --version` → `RPM version 4.18.2`
  - `rpm --eval '%{_db_backend}'` → `sqlite`
  - `rpm --eval '%{_dbpath}'` → `/var/lib/rpm`
  - live sqlite db at `/var/lib/rpm/rpmdb.sqlite`
- Upstream rpm sources cross-read:
  - `lib/backend/sqlite.cc`
  - `lib/rpmdb.cc`
  - `lib/psm.cc`
  - `lib/transaction.cc`
  - `lib/package.cc`

## Confirmed sqlite schema

Primary table:

- `Packages(hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)`

Secondary tables:

- `Name`
- `Basenames`
- `Group`
- `Requirename`
- `Providename`
- `Conflictname`
- `Obsoletename`
- `Triggername`
- `Dirnames`
- `Installtid`
- `Sigmd5`
- `Sha1header`
- `Filetriggername`
- `Transfiletriggername`
- `Recommendname`
- `Suggestname`
- `Supplementname`
- `Enhancename`

Key types matter:

- `Installtid.key` is a raw 4-byte native-endian blob
- `Sigmd5.key` is raw 16-byte binary MD5
- `Sha1header.key` is lowercase hex text
- other secondary keys are text

This is **not** just `Packages` plus views/generated columns. Real rpm
maintains real secondary tables and indexes for compatibility.

## Installed-header facts

Compared a package file header with the installed header that real rpm
writes into a scratch `--root ... --justdb` sqlite rpmdb. Real rpm adds
these main-header tags:

- `257` `SIGSIZE`
- `261` `SIGMD5`
- `269` `SHA1HEADER`
- `273` `SHA256HEADER`
- `1008` `INSTALLTIME`
- `1029` `FILESTATES`
- `1046` `ARCHIVESIZE`
- `1127` `INSTALLCOLOR`
- `1128` `INSTALLTID`

Modern headers keep `HEADERIMMUTABLE` (`63`) as the region tag; the
write path must preserve it.

## Secondary-index rules copied from rpm

- `Group` falls back to `"Unknown"` when absent
- `Requirename` skips transient/install-only requirements
- `Triggername` deduplicates duplicate trigger names
- `Filetriggername` / `Transfiletriggername` use
  `FILETRIGGERINDEX` / `TRANSFILETRIGGERINDEX` for `idx`
- rich dependencies add extra secondary rows for embedded names

## Observed row-id behavior

Scratch-root experiments with real rpm showed:

- fresh install allocates `hnum = 1`
- upgrade/reinstall allocate a **fresh** replacement `hnum`
- erase removes rows but does **not** rewind `sqlite_sequence`

The native write path mirrors this.

## Compatibility boundary

Only the sqlite rpmdb backend is supported here. Legacy Berkeley DB /
NDB layouts are intentionally rejected when legacy marker files are
present under `var/lib/rpm/`.

## Crosscheck harness

`pytests/tests/test_rpmzig_rpmdb_write.py` runs the same scratch-root
transactions through:

1. real `rpm --root ... --justdb`
2. `tdnf-rpmdb-write`

and compares:

- sqlite schema
- logical table contents, including `Packages.blob`
- `sqlite_sequence`
- real `rpm -qa`, `rpm -q`, and `rpm -V` output against the native db

`sqlite_stat1` is excluded from the logical diff. On rpm 4.18 it is
planner metadata, updated opportunistically and observed to remain stale
across erase, so it is not a correctness signal for installed-package
state.
