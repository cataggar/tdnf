#!/bin/bash

set -e

pkgs=(llvm-devel clang-devel)
pkgs+=(which gcc cmake make)

tdnf install -y --refresh ${pkgs[@]}

export CC="$(which clang)"
export CFLAGS="-Qunused-arguments -Wno-deprecated -Werror"

[ -d build ] && rm -rf build
mkdir -p build
cd build || exit 1

JOBS=$(( ($(nproc)+1) / 2 ))
HIST_DB_DIR="/usr/lib/sysimage/tdnf"

{
  mkdir -p ${HIST_DB_DIR}
  cmake -DHISTORY_DB_DIR=${HIST_DB_DIR} ..
  make -j${JOBS}
  make check -j${JOBS}
} || exit 1
