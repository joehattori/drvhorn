// RUN: set -eu
// RUN: %sea kernel --specific-function=qca8k_setup_led_ctrl %kernel_bc | OutputCheck %s
// CHECK: ^sat$
