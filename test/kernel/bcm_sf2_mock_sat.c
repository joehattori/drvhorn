// RUN: set -e
// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --platform-driver=bcm_sf2_driver_sat %t-merged.bc | OutputCheck %s
// CHECK: ^sat$

#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_mdio.h>

extern bool nd_bool();
int bcm_sf2_sw_probe_sat(struct platform_device *pdev) {
  struct device_node *dn = of_find_compatible_node(NULL, NULL, "brcm,unimac-mdio");
  struct mii_bus *bus = of_mdio_find_bus(dn);
  if (!bus) {
    return -EPROBE_DEFER;
  }
  if (nd_bool()) {
    return -ENOMEM;
  }
  return 0;
}

struct platform_driver bcm_sf2_driver_sat = {
  .probe = bcm_sf2_sw_probe_sat,
};
