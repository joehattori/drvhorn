#/bin/sh

set -eu

INPUT=$1
BASE=$2
OUT=$3
OBJNAME=/tmp/seahorn-tmp

./scripts/build-single-file.sh ${INPUT} ${OBJNAME}.o
extract-bc ${OBJNAME}.o
llvm-link-14 ${BASE} ${OBJNAME}.o.bc -o ${OUT}.bc
