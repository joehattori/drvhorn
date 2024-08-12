#!/bin/bash

set -eu

export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-14
export LLVM_CXX_NAME=clang-14
export LLVM_LINK_NAME=llvm-link-14
export LLVM_AR_NAME=llvm-ar-14

make ARCH=x86_64 HOSTCC=wllvm CC=wllvm -j$(nproc)
extract-bc vmlinux
