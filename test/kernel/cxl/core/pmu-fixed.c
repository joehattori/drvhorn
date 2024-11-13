// RUN: set -eu
// RUN: %sea kernel --specific-function=devm_cxl_pmu_add %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
