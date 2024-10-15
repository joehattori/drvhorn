// RUN: set -e
// RUN: %merge %s %kernel_bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --platform-driver=mock_platform_driver %t-merged.bc | OutputCheck %s
// CHECK: ^sat$

#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_mdio.h>

extern bool nd_bool();

static int mock_platform_driver_probe(struct platform_device *pdev) {
	struct device_node *dn = of_find_compatible_node(NULL, NULL, "brcm,unimac-mdio");
  struct mii_bus *bus = of_mdio_find_bus(dn);
  if (!bus) {
    return -1;
  }
  if (nd_bool()) {
    goto err_put_dev;
  }
  return 0;

err_put_dev:
  put_device(&bus->dev);
err_put_node:
  of_node_put(dn);
  return -1;
}

struct platform_driver mock_platform_driver = {
  .probe = mock_platform_driver_probe,
};
