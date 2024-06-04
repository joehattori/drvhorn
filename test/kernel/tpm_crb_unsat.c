// RUN: set -e
// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --acpi-driver=crb_acpi_driver_unsat --inline %t-merged.bc | OutputCheck %s
// CHECK: ^unsat$

#include <linux/acpi.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/rculist.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/tpm.h>
#include <acpi/actbl.h>
#include <acpi/actypes.h>
#include <acpica/aclocal.h>
#include <acpica/actables.h>
#include <tpm/tpm.h>

extern void __VERIFIER_error(void);
#define sassert(X) (void)((X) || (__VERIFIER_error(), 0))

extern const struct tpm_class_ops tpm_crb;

struct tpm2_crb_smc {
	u32 interrupt;
	u8 interrupt_flags;
	u8 op_flags;
	u16 reserved2;
	u32 smc_func_id;
};

struct crb_priv {
  u32 sm;
  const char *hid;
  struct crb_regs_head __iomem *regs_h;
  struct crb_regs_tail __iomem *regs_t;
  u8 __iomem *cmd;
  u8 __iomem *rsp;
  u32 cmd_size;
  u32 smc_func_id;
};

extern struct acpi_table_list acpi_gbl_root_table_list;

int acpi_device_add(struct acpi_device *device);
int crb_map_io(struct acpi_device *device, struct crb_priv *priv, struct acpi_table_tpm2 *buf);

int crb_acpi_add_unsat(struct acpi_device *device)
{
  struct acpi_table_tpm2 *buf;
  struct crb_priv *priv;
  struct tpm_chip *chip;
  struct device *dev = &device->dev;
  struct tpm2_crb_smc *crb_smc;
  acpi_status status;
  u32 sm;
  int rc;

	status = acpi_get_table(ACPI_SIG_TPM2, 1,
				(struct acpi_table_header **) &buf);
	if (ACPI_FAILURE(status)) {
	  return -EINVAL;
	}
	if (buf->header.length < sizeof(*buf)) {
	  rc = -EINVAL;
	  goto out;
	}
  
  sm = buf->start_method;
  if (sm == ACPI_TPM2_MEMORY_MAPPED) {
    rc = -ENODEV;
    goto out;
  }
  priv = devm_kzalloc(dev, sizeof(struct crb_priv), GFP_KERNEL);
  if (!priv) {
    rc = -ENOMEM;
    goto out;
  }

  if (sm == ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC) {
    if (buf->header.length < (sizeof(*buf) + sizeof(*crb_smc))) {
      dev_err(dev,
        FW_BUG "TPM2 ACPI table has wrong size %u for start method type %d\n",
        buf->header.length,
        ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC);
      rc = -EINVAL;
      goto out;
    }
    crb_smc = ACPI_ADD_PTR(struct tpm2_crb_smc, buf, sizeof(*buf));
    priv->smc_func_id = crb_smc->smc_func_id;
  }

  priv->sm = sm;
  priv->hid = acpi_device_hid(device);

  rc = crb_map_io(device, priv, buf);
  if (rc)
  	goto out;

  chip = tpmm_chip_alloc(dev, &tpm_crb);
  if (IS_ERR(chip)) {
    rc = PTR_ERR(chip);
    goto out;
  }

  dev_set_drvdata(&chip->dev, priv);
  chip->acpi_dev_handle = device->handle;
  chip->flags = TPM_CHIP_FLAG_TPM2;

  rc = tpm_chip_register(chip);
out:
	acpi_put_table((struct acpi_table_header *)buf);
	return rc;
}

static int crb_acpi_remove_unsat(struct acpi_device *device)
{
	struct device *dev = &device->dev;
	struct tpm_chip *chip = dev_get_drvdata(dev);

	tpm_chip_unregister(chip);

	return 0;
}

static const struct acpi_device_id crb_device_ids_unsat[] = {
	{"MSFT0101", 0},
	{"", 0},
};

static const struct dev_pm_ops crb_pm_unsat = {
	SET_SYSTEM_SLEEP_PM_OPS(tpm_pm_suspend, tpm_pm_resume)
};

struct acpi_driver crb_acpi_driver_unsat = {
	.name = "tpm_crb_unsat",
	.ids = crb_device_ids_unsat,
	.ops = {
		.add = crb_acpi_add_unsat,
		.remove = crb_acpi_remove_unsat,
	},
	.drv = {
		.pm = &crb_pm_unsat,
	},
};

static struct acpi_table_desc my_initial_tables[128];

extern int nd_int();
extern char nd_char();

void setup_acpi_tables(void) {
  acpi_gbl_root_table_list.current_table_count = 1;
  acpi_gbl_root_table_list.max_table_count = 128;
  acpi_gbl_root_table_list.tables = my_initial_tables;
  acpi_gbl_root_table_list.tables[0].signature.integer = nd_int();
  acpi_gbl_root_table_list.tables[0].validation_count = 0;
  acpi_gbl_root_table_list.tables[0].flags = nd_char();
}

extern int __PLACEHOLDER_acpi_driver_add(struct acpi_device *dev);

int main(void) {
	setup_acpi_tables();
	struct acpi_device *dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if  (!dev)
	  return 0;
	// int rc = acpi_device_add(dev);
	// if (rc < 0)
	// 	return 1;
	__PLACEHOLDER_acpi_driver_add(dev);
	sassert(acpi_gbl_root_table_list.tables[0].validation_count == 0);
	return 0;
}
