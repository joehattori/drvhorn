// RUN: set -eu
// RUN: %sea kernel --i2c-driver=ht16k33_driver %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
