#!/bin/sh

set -eu

INPUT=$1
BASE=$2
OUT=$3
KERNEL_DIR=${4:-./kernel}
OBJNAME=$(mktemp /tmp/seahorn.XXXX.o)

wllvm \
  --target=x86_64-unknown-linux-gnu \
  -I${KERNEL_DIR}/arch/x86/include \
  -I${KERNEL_DIR}/arch/x86/include/generated \
  -I${KERNEL_DIR}/arch/x86/include/uapi \
  -I${KERNEL_DIR}/arch/x86/include/generated/uapi \
  -I${KERNEL_DIR}/include \
  -I${KERNEL_DIR}/include/uapi \
  -I${KERNEL_DIR}/include/generated/uapi \
  -I${KERNEL_DIR}/drivers \
  -I${KERNEL_DIR}/drivers/acpi \
  -I${KERNEL_DIR}/drivers/char \
  -I${KERNEL_DIR}/drivers/net \
  -I${KERNEL_DIR}/drivers/net/dsa \
  -include ${KERNEL_DIR}/include/linux/compiler-version.h \
  -include ${KERNEL_DIR}/include/linux/kconfig.h \
  -include ${KERNEL_DIR}/include/linux/compiler_types.h \
  -Os \
  -D__KERNEL__ \
  -std=gnu11 \
  -DCC_USING_FENTRY \
  -DMODULE \
  -DKBUILD_BASENAME=\"seahorn\" \
  -DKBUILD_MODNAME=\"seahorn\" \
  -D__KBUILD_MODNAME=\"seahorn\" \
  -fshort-wchar \
  -c ${INPUT} \
  -o ${OBJNAME}
extract-bc ${OBJNAME}
llvm-link-14 ${BASE} ${OBJNAME}.bc -o ${OUT}
