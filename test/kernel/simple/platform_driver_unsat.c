// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --platform-driver=mock_platform_driver %t-merged.bc | OutputCheck %s
// CHECK: ^unsat$

#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/platform_device.h>

extern bool nd_bool();
extern struct device_node *__DRVHORN_get_device_node(struct device_node *from);
extern void __DRVHORN_setup_device(struct device *dev);

/*static int mock_platform_driver_probe(struct platform_device *pdev) {*/
/*	struct device_node *dn = of_find_compatible_node(NULL, NULL, "brcm,unimac-mdio");*/
/*  struct mii_bus *bus = of_mdio_find_bus(dn);*/
/*  if (!bus) {*/
/*    goto err_put_node;*/
/*  }*/
/*  if (nd_bool()) {*/
/*    goto err_put_dev;*/
/*  }*/
/*  return 0;*/
/**/
/*err_put_dev:*/
/*  put_device(&bus->dev);*/
/*err_put_node:*/
/*  of_node_put(dn);*/
/*  return -1;*/
/*}*/

static int mock_platform_driver_probe(struct platform_device *pdev) {
  struct device_node *dn = of_find_compatible_node(NULL, NULL, "label1");
  struct mii_bus *bus = of_mdio_find_bus(dn);
  if (!bus) {
    goto err_put_node;
  }
  of_node_get(dn);
  struct device_node *name = of_find_compatible_node(dn, NULL, "label2");
  if (!name) {
    goto err_put_dev;
  }

  of_node_put(name);
err_put_dev:
  put_device(&bus->dev);
err_put_node:
  of_node_put(dn);
  return -1;
}

struct platform_driver mock_platform_driver = {
  .probe = mock_platform_driver_probe,
};
