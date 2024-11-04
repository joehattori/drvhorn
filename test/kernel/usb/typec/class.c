// RUN: set -eu
// RUN: %sea kernel --specific-function=typec_port_register_altmodes %kernel_bc | OutputCheck %s
// CHECK: ^sat$
