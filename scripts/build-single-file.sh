#!/bin/sh

set -eu

FILE=$1
OUT=$2

LLVM_COMPILER=clang WLLVM_OBJCOPY=llvm-objcopy wllvm \
  --target=x86_64-unknown-linux-gnu \
  -I./kernel/arch/x86/include \
  -I./kernel/arch/x86/include/generated \
  -I./kernel/arch/x86/include/uapi \
  -I./kernel/arch/x86/include/generated/uapi \
  -I./kernel/include \
  -I./kernel/include/uapi \
  -I./kernel/include/generated/uapi \
  -include ./kernel/include/linux/compiler-version.h \
  -include ./kernel/include/linux/kconfig.h \
  -include ./kernel/include/linux/compiler_types.h \
  -D__KERNEL__ \
  -D__i386__ \
  -std=gnu11 \
  -DCC_USING_FENTRY \
  -DMODULE \
  -DKBUILD_BASENAME=seahorn \
  -DKBUILD_MODNAME=seahorn \
  -D__KBUILD_MODNAME=seahorn \
  -fshort-wchar \
  -c $FILE \
  -o $OUT
