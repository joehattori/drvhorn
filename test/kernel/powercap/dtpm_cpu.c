// RUN: set -eu
// RUN: %sea kernel --specific-function=dtpm_cpu_setup %kernel_bc | OutputCheck %s
// CHECK: ^sat$
