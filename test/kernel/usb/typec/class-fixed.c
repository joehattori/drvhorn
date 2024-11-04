// RUN: set -eu
// RUN: %sea kernel --specific-function=typec_port_register_altmodes %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
