// RUN: set -e
// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --dsa-switch-ops=qca8k_switch_ops %t-merged.bc | OutputCheck %s
// CHECK: ^sat$
