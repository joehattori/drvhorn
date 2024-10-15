// RUN: set -e
// RUN: %sea kernel --specific-function=bcm_sf2_mdio_register %kernel_bc | OutputCheck %s
// CHECK: ^sat$
