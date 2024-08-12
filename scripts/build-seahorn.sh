#!/bin/bash
set -eu

cmake -DCMAKE_INSTALL_PREFIX=run \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_COMPILER="clang++-14" \
      -DCMAKE_C_COMPILER="clang-14" \
      -DSEA_ENABLE_LLD=ON  \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
      ../ \
      -DZ3_ROOT=/usr/lib/z3-4.8.9/bin \
      -DLLVM_DIR=/usr/lib/llvm-14/lib/cmake/llvm \
      -GNinja
ninja install
