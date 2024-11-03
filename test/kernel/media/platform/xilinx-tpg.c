// RUN: set -eu
// RUN: %sea kernel --platform-driver=xtpg_driver %kernel_bc | OutputCheck %s
// CHECK: ^sat$
