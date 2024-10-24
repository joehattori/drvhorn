// RUN: set -eu
// RUN: %sea kernel --dsa-switch-ops=qca8k_switch_ops %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
