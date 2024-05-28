// RUN: set -e
// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --acpi-driver=crb_acpi_driver --inline %t-merged.bc | OutputCheck %s
// CHECK: ^sat$

#include <linux/acpi.h>
#include <linux/slab.h>
#include <acpi/actbl.h>

extern void __VERIFIER_error(void);
#define sassert(X) (void)((X) || (__VERIFIER_error(), 0))

struct acpi_table_list {
	struct acpi_table_desc *tables;	/* Table descriptor array */
	unsigned int current_table_count;	/* Tables currently in the array */
	unsigned int max_table_count;	/* Max tables array will hold */
	unsigned char flags;
};

struct tpm2_crb_smc {
	u32 interrupt;
	u8 interrupt_flags;
	u8 op_flags;
	u16 reserved2;
	u32 smc_func_id;
};

extern struct acpi_table_list acpi_gbl_root_table_list;

static struct acpi_table_desc my_initial_tables[128];

void setup_acpi_tables(void) {
  struct acpi_table_tpm2 *tpm2;

	acpi_gbl_root_table_list.current_table_count = 1;
	acpi_gbl_root_table_list.max_table_count = 128;
	acpi_gbl_root_table_list.tables = my_initial_tables;
	acpi_gbl_root_table_list.tables[0].signature.integer = 0x324d5054;
  acpi_gbl_root_table_list.tables[0].validation_count = 0;

  tpm2 = kmalloc(sizeof(*tpm2), GFP_KERNEL);
  tpm2->header.signature[0] = 'T';
  tpm2->header.signature[1] = 'P';
  tpm2->header.signature[2] = 'M';
  tpm2->header.signature[3] = '2';
  tpm2->header.length = sizeof(*tpm2) + sizeof(struct tpm2_crb_smc);
  tpm2->start_method = 2;
  acpi_gbl_root_table_list.tables[0].pointer = (struct acpi_table_header *)tpm2;
}

extern int __PLACEHOLDER_acpi_driver_add(struct acpi_device *dev);

int main(void) {
	setup_acpi_tables();
	struct acpi_device *dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return 0;
	// int rc = acpi_device_add(dev);
	// if (rc < 0)
	// 	return 1;
	__PLACEHOLDER_acpi_driver_add(dev);
	sassert(acpi_gbl_root_table_list.tables[0].validation_count == 0);
	return 0;
}
