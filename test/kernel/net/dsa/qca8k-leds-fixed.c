// RUN: set -eu
// RUN: %sea kernel --specific-function=qca8k_setup_led_ctrl %fixed_kernel_bc | OutputCheck %s
// CHECK: ^unsat$
