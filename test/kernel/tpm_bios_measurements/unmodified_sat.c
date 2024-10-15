// RUN: set -e
// RUN: %sea kernel --file-operations=tpm_bios_measurements_ops %kernel_bc | OutputCheck %s
// CHECK: ^sat$
