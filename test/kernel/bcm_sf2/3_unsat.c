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

static int bcm_sf2_sw_mdio_read(struct mii_bus *bus, int addr, int regnum)
{
  return 0;
}

static int bcm_sf2_sw_mdio_write(struct mii_bus *bus, int addr, int regnum,
				 u16 val)
{
  return 0;
}

static int bcm_sf2_sw_register(struct dsa_switch *ds)
{
  struct device_node *child;
  struct device_node *dn;
	struct phy_device *phydev;
	struct bcm_sf2_priv *priv = bcm_sf2_to_priv(ds);
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

	priv->slave_mii_bus->priv = priv;
	priv->slave_mii_bus->name = "sf2 user mii";
	priv->slave_mii_bus->read = bcm_sf2_sw_mdio_read;
	priv->slave_mii_bus->write = bcm_sf2_sw_mdio_write;

	for_each_available_child_of_node(dn, child) {
		phydev = of_phy_find_device(child);
		if (phydev) {
			phy_device_remove(phydev);
			phy_device_free(phydev);
		}
	}

  err = mdiobus_register(priv->slave_mii_bus);
  if (err)
    goto err_free_slave_mii_bus;
  of_node_put(dn);

  return 0;

err_free_slave_mii_bus:
	mdiobus_free(priv->slave_mii_bus);
err_put_master_mii_bus_dev:
	put_device(&priv->master_mii_bus->dev);
err_of_node_put:
	of_node_put(dn);
	return err;
}

static void bcm_sf2_mdio_unregister(struct bcm_sf2_priv *priv)
{
	mdiobus_unregister(priv->slave_mii_bus);
	mdiobus_free(priv->slave_mii_bus);
	put_device(&priv->master_mii_bus->dev);
}

static const struct of_device_id bcm_sf2_of_match[] = {
	{ /* sentinel */ },
};

struct bcm_sf2_of_data {
	u32 type;
	const u16 *reg_offsets;
	unsigned int core_reg_align;
	unsigned int num_cfp_rules;
	unsigned int num_crossbar_int_ports;
};

static int bcm_sf2_sw_probe(struct platform_device *pdev) {
	struct device_node *dn = pdev->dev.of_node;
  struct bcm_sf2_priv *priv;
	struct dsa_switch *ds;
	struct b53_device *dev;
	const struct of_device_id *of_id = NULL;
	const struct bcm_sf2_of_data *data;
	struct b53_platform_data *pdata;
  int ret;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	dev = b53_switch_alloc(&pdev->dev, NULL, priv);
	if (!dev)
		return -ENOMEM;
	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;
	of_id = of_match_node(bcm_sf2_of_match, dn);
	if (!of_id || !of_id->data)
		return -EINVAL;

	data = of_id->data;

	/* Set SWITCH_REG register offsets and SWITCH_CORE align factor */
	priv->type = data->type;
	priv->reg_offsets = data->reg_offsets;
	priv->core_reg_align = data->core_reg_align;
	priv->num_cfp_rules = data->num_cfp_rules;
	priv->num_crossbar_int_ports = data->num_crossbar_int_ports;

	priv->rcdev = devm_reset_control_get_optional_exclusive(&pdev->dev,
								"switch");
	if (IS_ERR(priv->rcdev))
		return PTR_ERR(priv->rcdev);

	pdata->chip_id = priv->type;
	dev->pdata = pdata;

	priv->dev = dev;
	ds = dev->ds;

  ret = bcm_sf2_sw_register(ds);
  if (ret)
    goto out_clk_mdiv;

  if (nd_bool()) {
    ret = 0;
    goto out_mdio;
  }

  return 0;

out_mdio:
	bcm_sf2_mdio_unregister(priv);
out_clk_mdiv:
	clk_disable_unprepare(priv->clk_mdiv);
out_clk:
	clk_disable_unprepare(priv->clk);
	return ret;
}

struct platform_driver bcm_sf2_driver_unsat = {
  .probe = bcm_sf2_sw_probe,
};
