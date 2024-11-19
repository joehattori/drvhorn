// RUN: set -eu
// RUN: %sea kernel --specific-function=dtpm_cpu_setup %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
