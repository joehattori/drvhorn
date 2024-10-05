#!/bin/sh

set -eu

./scripts/merge-bitcodes.sh drvhorn-util.c kernel/vmlinux.bc kernel.bc
./scripts/merge-bitcodes.sh $1 kernel.bc merged.bc
