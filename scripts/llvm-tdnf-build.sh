#!/bin/bash

set -e

pkgs=(llvm-devel clang-devel)
pkgs+=(which gcc cmake make)

build_dir="build"
HIST_DB_DIR="/usr/lib/sysimage/tdnf"
JOBS=$(( ($(nproc)+1) / 2 ))

export CC="$(which clang)"
export CFLAGS="-Qunused-arguments -Wno-deprecated -Werror"

tdnf install -y --refresh ${pkgs[@]}

[ -d ${build_dir} ] && rm -r ${build_dir}

mkdir -p ${build_dir} ${HIST_DB_DIR}

cmake -S . -B ${build_dir} \
  -DHISTORY_DB_DIR=${HIST_DB_DIR}

cmake --build ${build_dir} -j${JOBS}
make -C ${build_dir} check -j${JOBS}
