// RUN: set -eu
// RUN: %sea kernel --dsa-switch-ops=qca8k_switch_ops %kernel_bc | OutputCheck %s
// CHECK: ^sat$
