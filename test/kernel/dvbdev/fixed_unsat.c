// RUN: set -eu
// RUN: %sea kernel --file-operations=dvb_device_fops %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
