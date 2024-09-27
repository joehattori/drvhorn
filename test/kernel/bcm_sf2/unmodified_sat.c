// RUN: set -e
// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --specific-function=bcm_sf2_mdio_register %t-merged.bc | OutputCheck %s
// CHECK: ^sat$
