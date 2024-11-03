// RUN: set -eu
// RUN: %sea kernel --specific-function=bcm_sf2_mdio_register %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
