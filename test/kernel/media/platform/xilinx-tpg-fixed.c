// RUN: set -eu
// RUN: %sea kernel --platform-driver=xtpg_driver %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
