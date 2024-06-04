// RUN: set -e
// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --acpi-driver=acpi_battery_driver --inline %t-merged.bc | OutputCheck %s
// CHECK: ^unsat$

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

extern struct acpi_table_list acpi_gbl_root_table_list;

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
	if (!dev)
		return 0;
	// int rc = acpi_device_add(dev);
	// if (rc < 0)
	// 	return 1;
	__PLACEHOLDER_acpi_driver_add(dev);
	sassert(acpi_gbl_root_table_list.tables[0].validation_count == 0);
	return 0;
}
