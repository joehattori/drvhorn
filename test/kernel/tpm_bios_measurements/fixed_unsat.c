// RUN: set -eu
// RUN: %sea kernel --file-operations=tpm_bios_measurements_ops %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
