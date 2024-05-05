// RUN: %wllvm --target=x86_64-unknown-linux-gnu -I%kernel-dir/arch/x86/include -I%kernel-dir/arch/x86/include/generated -I%kernel-dir/arch/x86/include/uapi -I%kernel-dir/arch/x86/include/generated/uapi -I%kernel-dir/include -I%kernel-dir/include/uapi -I%kernel-dir/include/generated/uapi -include %kernel-dir/include/linux/compiler-version.h -include %kernel-dir/include/linux/kconfig.h -include %kernel-dir/include/linux/compiler_types.h -Os -D__KERNEL__ -std=gnu11 -DCC_USING_FENTRY -DMODULE -DKBUILD_BASENAME=seahorn -DKBUILD_MODNAME=seahorn -D__KBUILD_MODNAME=seahorn -fshort-wchar -c %kern-util -o %t-util.o 2> /dev/null
// RUN: %extract-bc %t-util.o
// RUN: %llvm-link %vmlinux-bc %t-util.o.bc -o %t-kernel.bc
// RUN: %wllvm --target=x86_64-unknown-linux-gnu -I%kernel-dir/arch/x86/include -I%kernel-dir/arch/x86/include/generated -I%kernel-dir/arch/x86/include/uapi -I%kernel-dir/arch/x86/include/generated/uapi -I%kernel-dir/include -I%kernel-dir/include/uapi -I%kernel-dir/include/generated/uapi -include %kernel-dir/include/linux/compiler-version.h -include %kernel-dir/include/linux/kconfig.h -include %kernel-dir/include/linux/compiler_types.h -Os -D__KERNEL__ -std=gnu11 -DCC_USING_FENTRY -DMODULE -DKBUILD_BASENAME=seahorn -DKBUILD_MODNAME=seahorn -D__KBUILD_MODNAME=seahorn -fshort-wchar -c %s -o %t.o 2> /dev/null
// RUN: %extract-bc %t.o
// RUN: %llvm-link %t-kernel.bc %t.o.bc -o %t-merged.bc
// RUN: %sea kernel --acpi-driver=crb_acpi_driver_ok --track=mem --horn-stats --externalize-addr-taken-functions --devirt-functions=types --inline "%t-merged.bc" | OutputCheck %s
// CHECK: ^unsat$

#include <linux/acpi.h>
#include <linux/highmem.h>
#include <linux/rculist.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/tpm.h>

extern const struct tpm_class_ops tpm_crb;
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

struct tpm2_crb_smc {
	u32 interrupt;
	u8 interrupt_flags;
	u8 op_flags;
	u16 reserved2;
	u32 smc_func_id;
};

extern int crb_map_io(struct acpi_device *device, struct crb_priv *priv,
		      struct acpi_table_tpm2 *buf);
extern struct tpm_chip *tpmm_chip_alloc(struct device *pdev,
				 const struct tpm_class_ops *ops);
extern int tpm_chip_register(struct tpm_chip *chip);

int crb_acpi_add_ok(struct acpi_device *device)
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
	if (ACPI_FAILURE(status) || buf->header.length < sizeof(*buf)) {
		dev_err(dev, FW_BUG "failed to get TPM2 ACPI table\n");
		rc = -ENODEV;
		goto out;
	}

	/* Should the FIFO driver handle this? */
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

static int crb_acpi_remove_ok(struct acpi_device *device)
{
	struct device *dev = &device->dev;
	struct tpm_chip *chip = dev_get_drvdata(dev);

	tpm_chip_unregister(chip);

	return 0;
}

static const struct acpi_device_id crb_device_ids_ok[] = {
	{"MSFT0101", 0},
	{"", 0},
};

static const struct dev_pm_ops crb_pm_ok = {
	SET_SYSTEM_SLEEP_PM_OPS(tpm_pm_suspend, tpm_pm_resume)
};

struct acpi_driver crb_acpi_driver_ok = {
	.name = "tpm_crb_ok",
	.ids = crb_device_ids_ok,
	.ops = {
		.add = crb_acpi_add_ok,
		.remove = crb_acpi_remove_ok,
	},
	.drv = {
		.pm = &crb_pm_ok,
	},
};
