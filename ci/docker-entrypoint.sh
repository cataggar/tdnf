#!/bin/bash

set -e

build_dir="build"
HIST_DB_DIR="/usr/lib/sysimage/tdnf"

[ -d ${build_dir} ] && rm -r ${build_dir}

mkdir -p ${build_dir} ${HIST_DB_DIR}

JOBS=$(( ($(nproc)+1) / 2 ))

cmake -S . -B ${build_dir} \
  -DHISTORY_DB_DIR=${HIST_DB_DIR}

cmake --build ${build_dir} -j${JOBS}
make -C ${build_dir} check -j${JOBS}

if ! flake8 pytests ; then
  echo "ERROR: flake8 tests failed" >&2
  exit 1
fi
