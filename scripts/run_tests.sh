#!/bin/bash

set -eu

export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-14
export LLVM_CXX_NAME=clang-14
export LLVM_LINK_NAME=llvm-link-14
export LLVM_AR_NAME=llvm-ar-14
export WLLVM_OBJCOPY=/usr/bin/llvm-objcopy-14

pushd build
../scripts/build-seahorn.sh
SEAHORN=$PWD/run/bin/sea lit ../test/kernel/
popd
