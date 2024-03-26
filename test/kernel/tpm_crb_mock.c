/*
 * from Invgen test suite
 */

extern void __VERIFIER_error (void);
void assert (int v) { if (!v) __VERIFIER_error (); }


#define u32 unsigned
#define u16 unsigned short
#define u8 unsigned char

void *__kmalloc(unsigned int size, int flags);
void *kmalloc_large_node(unsigned int size, int flags, int node);

typedef struct {
	int counter;
} atomic_t;

typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;

struct kref {
    refcount_t refcount;
};

struct kobject {
    struct kref kref;
};

struct device {
    struct kobject kobj;
};

struct acpi_device {
    struct device dev;
};

union acpi_name_union {
	u32 integer;
	char ascii[4];
};

#define acpi_uintptr_t                  void *
#define ACPI_CAST_PTR(t, p)             ((t *) (acpi_uintptr_t) (p))
#define ACPI_COMPARE_NAMESEG(a,b)       (*ACPI_CAST_PTR (u32, (a)) == *ACPI_CAST_PTR (u32, (b)))

struct acpi_table_header {
    u32 signature;
};

struct acpi_table_desc {
    unsigned int length;
    struct acpi_table_header *pointer;
    u16 validation_count;
    union acpi_name_union signature;
};

struct acpi_table_list {
    struct acpi_table_desc *tables;
    u32 current_table_count;
    u32 max_table_count;
    u8 flags;
};

#define ACPI_MAX_TABLES 128
static struct acpi_table_desc initial_tables[ACPI_MAX_TABLES];
struct acpi_table_list acpi_gbl_root_table_list;

struct acpi_table_tpm2 {
	struct acpi_table_header header;	/* Common ACPI table header */
	u16 platform_class;
	u16 reserved;
	u32 start_method;
};

u32 acpi_tb_get_table(struct acpi_table_desc *table_desc, struct acpi_table_header **out_table)
{
    if (table_desc->validation_count < 0xffff) {
        table_desc->validation_count++;
    }

    *out_table = table_desc->pointer;
    return 0;
}

u32 acpi_get_table(char *signature, u32 instance, struct acpi_table_header **out_table) {
    if (!signature || !out_table)
        return 0x1001;
    u32 i, j;
    struct acpi_table_desc *table_desc;
    u32 status = 1;
    for (i = 0, j = 0; i < acpi_gbl_root_table_list.current_table_count; i++) {
        table_desc = &acpi_gbl_root_table_list.tables[i];

        if (!ACPI_COMPARE_NAMESEG(&table_desc->signature, signature)) {
            continue;
        }

        if (++j < instance) {
            continue;
        }

        status = acpi_tb_get_table(table_desc, out_table);
        break;
    }

    return status;
}

void setup() {
    acpi_gbl_root_table_list.tables = initial_tables;
    acpi_gbl_root_table_list.current_table_count = 1;
    acpi_gbl_root_table_list.max_table_count = ACPI_MAX_TABLES;

    acpi_gbl_root_table_list.tables[0].signature.integer = 0x324d5054; // 2MPT
    acpi_gbl_root_table_list.tables[0].validation_count = 0;
}

void mutex_dummy_lock() {
    // should not be called
    __VERIFIER_error();
}

int crb_acpi_add(struct acpi_device *device) {
    u32 status;
    struct acpi_table_tpm2 *buf;
    u32 *priv;

    setup();
    mutex_dummy_lock();
    status = acpi_get_table("TPM2", 1, (struct acpi_table_header **)&buf);
    if (status)
        return -1;
    priv = __kmalloc(sizeof(u32), 0);
    if (!priv)
        return -1;
    return 0;
}
