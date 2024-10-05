#!/bin/sh

set -eu

FILE=$1
OUT=$2

KERNEL_DIR=${KERNEL_DIR:-./kernel}

clang-14 \
  --target=x86_64-unknown-linux-gnu \
  -I${KERNEL_DIR}/arch/x86/include \
  -I${KERNEL_DIR}/arch/x86/include/generated \
  -I${KERNEL_DIR}/arch/x86/include/uapi \
  -I${KERNEL_DIR}/arch/x86/include/generated/uapi \
  -I${KERNEL_DIR}/include \
  -I${KERNEL_DIR}/include/uapi \
  -I${KERNEL_DIR}/include/generated/uapi \
  -I${KERNEL_DIR}/drivers/acpi \
  -include ${KERNEL_DIR}/include/linux/compiler-version.h \
  -include ${KERNEL_DIR}/include/linux/kconfig.h \
  -include ${KERNEL_DIR}/include/linux/compiler_types.h \
  -Os \
  -D__KERNEL__ \
  -std=gnu11 \
  -DCC_USING_FENTRY \
  -DMODULE \
  -DKBUILD_BASENAME=seahorn \
  -DKBUILD_MODNAME=seahorn \
  -D__KBUILD_MODNAME=seahorn \
  -fshort-wchar \
  -emit-llvm \
  -c $FILE \
  -o $OUT.bc
