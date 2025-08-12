#!/bin/bash

set -e

rm -rf build
mkdir -p build
cd build || exit 1

JOBS=$(( ($(nproc)+1) / 2 ))
HIST_DB_DIR="/usr/lib/sysimage/tdnf"

mkdir -p ${HIST_DB_DIR}
cmake -DHISTORY_DB_DIR=${HIST_DB_DIR} ..
make -j${JOBS}
make check -j${JOBS}

if ! flake8 ../pytests ; then
  echo "ERROR: flake8 tests failed" >&2
  exit 1
fi
