// RUN: set -eu
// RUN: %sea kernel --file-operations=dvb_device_fops %kernel_bc | OutputCheck %s
// CHECK: ^sat$
