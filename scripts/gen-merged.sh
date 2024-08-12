#!/bin/sh

set -eu

export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-14
export LLVM_CXX_NAME=clang-14
export LLVM_LINK_NAME=llvm-link-14
export LLVM_AR_NAME=llvm-ar-14
export WLLVM_OBJCOOPY=/usr/bin/llvm-objcopy-14

./scripts/merge-bitcodes.sh drvhorn-util.c kernel/vmlinux.bc kernel.bc
./scripts/merge-bitcodes.sh $1 kernel.bc merged.bc
