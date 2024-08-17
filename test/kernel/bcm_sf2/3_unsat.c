// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir &> /dev/null
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir &> /dev/null
// RUN: %sea kernel --platform-driver=bcm_sf2_driver_unsat %t-merged.bc | OutputCheck %s
// CHECK: ^unsat$

#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/phy.h>
#include <linux/phy_fixed.h>
#include <linux/phylink.h>
#include <linux/mii.h>
#include <linux/clk.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/of_net.h>
#include <linux/of_mdio.h>
#include <net/dsa.h>
#include <linux/ethtool.h>
#include <linux/if_bridge.h>
#include <linux/brcmphy.h>
#include <linux/etherdevice.h>
#include <linux/platform_data/b53.h>

#include <dsa/bcm_sf2.h>
#include <dsa/bcm_sf2_regs.h>
#include <b53/b53_priv.h>
#include <b53/b53_regs.h>

extern bool nd_bool();
static int bcm_sf2_sw_probe(struct platform_device *pdev)
{
  struct device_node *child;
  struct device_node *dn;
	struct phy_device *phydev;
  struct bcm_sf2_priv *priv = kmalloc(sizeof(*priv), GFP_KERNEL);
  int err;

  dn = of_find_compatible_node(NULL, NULL, "brcm,unimac-mdio");
	priv->master_mii_bus = of_mdio_find_bus(dn);
	if (!priv->master_mii_bus) {
		err = -EPROBE_DEFER;
		goto err_of_node_put;
	}

	priv->slave_mii_bus = mdiobus_alloc();
	if (!priv->slave_mii_bus) {
		err = -ENOMEM;
		goto err_put_master_mii_bus_dev;
	}

  phydev = of_phy_find_device(dn);
  if (phydev)
    phy_device_free(phydev);
	/*for_each_available_child_of_node(dn, child) {*/
	/*	phydev = of_phy_find_device(child);*/
	/*	if (phydev) {*/
	/*		phy_device_remove(phydev);*/
	/*		phy_device_free(phydev);*/
	/*	}*/
	/*}*/
  if (nd_bool()) {
    err = -1;
    goto err_put_master_mii_bus_dev;
  }
  of_node_put(dn);
  return 0;

err_put_master_mii_bus_dev:
	put_device(&priv->master_mii_bus->dev);
err_of_node_put:
	of_node_put(dn);
	return err;
}

struct platform_driver bcm_sf2_driver_unsat = {
  .probe = bcm_sf2_sw_probe,
};
