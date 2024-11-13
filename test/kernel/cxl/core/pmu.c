// RUN: set -eu
// RUN: %sea kernel --specific-function=devm_cxl_pmu_add %kernel_bc | OutputCheck %s
// CHECK: ^sat$
